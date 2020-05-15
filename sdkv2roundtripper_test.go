package awsgosignv4_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsgosignv4 "github.com/jriquelme/awsgosigv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyRoundTripper verifies the signature in the Authorization header, returning a 200 empty response if everything
// is OK, otherwise returns 400. The expected signature is left in the field ExpectedSignature for later inspection.
type verifyRoundTripper struct {
	Key               string
	Secret            string
	Service           string
	Region            string
	ExpectedSignature string
}

func (r *verifyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()

	// check signature
	authorization := req.Header.Get("Authorization")
	if authorization == "" {
		recorder.WriteHeader(http.StatusUnauthorized)
		return recorder.Result(), nil
	}
	if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256") {
		recorder.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(recorder, "signature expected to start with AWS4-HMAC-SHA256")
		return recorder.Result(), nil
	}

	// copy request and sign it again
	req2 := req.Clone(context.Background())
	// calculate body hash
	b := []byte("")
	if req2.Body != nil {
		var err error
		b, err = ioutil.ReadAll(req2.Body)
		if err != nil {
			recorder.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(recorder, "error reading body: %s", err)
			return recorder.Result(), nil
		}
		req2.Body = ioutil.NopCloser(bytes.NewReader(b))
	}
	hash := sha256.Sum256(b)
	hexHash := hex.EncodeToString(hash[:])
	// use time of X-Amz-Date
	xAmzDate := req2.Header.Get("X-Amz-Date")
	signingTime, err := time.Parse("20060102T150405Z", xAmzDate)
	if err != nil {
		recorder.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(recorder, "error parsing X-Amz-Date=%s: %s", xAmzDate, err)
		return recorder.Result(), nil
	}
	// sign
	signer := v4.NewSigner(aws.NewStaticCredentialsProvider(r.Key, r.Secret, ""))
	err = signer.SignHTTP(context.Background(), req2, hexHash, r.Service, r.Region, signingTime)
	if err != nil {
		recorder.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(recorder, "error signing request copy: %s", err)
		return recorder.Result(), nil
	}

	// resulting signature must match Authorization header
	r.ExpectedSignature = req2.Header.Get("Authorization")
	if r.ExpectedSignature != authorization {
		recorder.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(recorder, "invalid signature")
		return recorder.Result(), nil
	}
	recorder.WriteHeader(http.StatusOK)
	return recorder.Result(), nil
}

func TestSignV4SDKV2_RoundTripOK(t *testing.T) {
	t.Parallel()
	newRoundTripper := func() (*awsgosignv4.SignV4SDKV2, *verifyRoundTripper) {
		verifier := &verifyRoundTripper{
			Key:     "jriquelme",
			Secret:  "notedigo",
			Service: "es",
			Region:  "us-east-1",
		}
		r := &awsgosignv4.SignV4SDKV2{
			RoundTripper: verifier,
			Credentials:  aws.NewStaticCredentialsProvider("jriquelme", "notedigo", ""),
			Region:       "us-east-1",
			Service:      "es",
			Now:          time.Now,
		}
		return r, verifier
	}

	t.Run("get", func(t *testing.T) {
		t.Parallel()
		request, err := http.NewRequest("GET", "http://localhost/hi", nil)
		require.Nil(t, err)
		request.Header.Set("X-API-Key", "MY-API-KEY")
		r, verifier := newRoundTripper()
		response, err := r.RoundTrip(request)
		assert.Nil(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, verifier.ExpectedSignature, request.Header.Get("Authorization"))
	})
	t.Run("getWithQueryParams", func(t *testing.T) {
		t.Parallel()
		request, err := http.NewRequest("GET", "http://localhost/hi?a=b&c=d", nil)
		require.Nil(t, err)
		request.Header.Set("X-API-Key", "MY-API-KEY")
		r, verifier := newRoundTripper()
		response, err := r.RoundTrip(request)
		assert.Nil(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, verifier.ExpectedSignature, request.Header.Get("Authorization"))
	})
	t.Run("post", func(t *testing.T) {
		t.Parallel()
		request, err := http.NewRequest("POST", "http://localhost/hi", bytes.NewReader([]byte(`{"msg":"hi"}`)))
		require.Nil(t, err)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-API-Key", "MY-API-KEY")
		r, verifier := newRoundTripper()
		response, err := r.RoundTrip(request)
		assert.Nil(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, verifier.ExpectedSignature, request.Header.Get("Authorization"))
	})
}

// mutateRequestRoundTripper applies the Mutate function to the incoming request before invoking the wrapped
// RoundTripper.
type mutateRequestRoundTripper struct {
	RoundTripper http.RoundTripper
	Mutate       func(req *http.Request)
}

func (r *mutateRequestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.Mutate(req)
	return r.RoundTripper.RoundTrip(req)
}

func TestSignV4SDKV2_RoundTripErr(t *testing.T) {
	t.Parallel()
	verifier := &verifyRoundTripper{
		Key:     "jriquelme",
		Secret:  "notedigo",
		Service: "es",
		Region:  "us-east-1",
	}
	// this chain of RoundTripper (sign -> mutate request -> sign again) should generate different signatures.
	r := &awsgosignv4.SignV4SDKV2{
		RoundTripper: &mutateRequestRoundTripper{
			RoundTripper: verifier,
			Mutate: func(req *http.Request) {
				// this header will be considered in the expected signature by the verifier, but wasn't included when
				// SignV4SDKV2 created the signature present in Authorization
				req.Header.Set("X-Oh-No", "asdf")
			},
		},
		Credentials: aws.NewStaticCredentialsProvider("jriquelme", "notedigo", ""),
		Region:      "us-east-1",
		Service:     "es",
		Now:         time.Now,
	}

	request, err := http.NewRequest("POST", "http://localhost/hi", bytes.NewReader([]byte(`{"msg":"hi"}`)))
	require.Nil(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", "MY-API-KEY")
	response, err := r.RoundTrip(request)
	assert.Nil(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.NotEqual(t, verifier.ExpectedSignature, request.Header.Get("Authorization"))
	assert.Contains(t, verifier.ExpectedSignature, ";x-oh-no")
	assert.NotContains(t, request.Header.Get("Authorization"), ";x-oh-no")
}

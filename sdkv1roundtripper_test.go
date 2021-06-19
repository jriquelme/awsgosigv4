package awsgosignv4_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	awsgosignv4 "github.com/jriquelme/awsgosigv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignV4SDKV1_RoundTripOK(t *testing.T) {
	t.Parallel()
	newRoundTripper := func() (*awsgosignv4.SignV4SDKV1, *verifyRoundTripper) {
		verifier := &verifyRoundTripper{
			Key:     "jriquelme",
			Secret:  "notedigo",
			Service: "es",
			Region:  "us-east-1",
		}
		r := &awsgosignv4.SignV4SDKV1{
			RoundTripper: verifier,
			Credentials:  credentials.NewStaticCredentials("jriquelme", "notedigo", ""),
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
		t.Skip("not working") // FIXME: issue with content-type in SignedHeaders
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

func TestSignV4SDKV1_RoundTripErr(t *testing.T) {
	t.Parallel()
	verifier := &verifyRoundTripper{
		Key:     "jriquelme",
		Secret:  "notedigo",
		Service: "es",
		Region:  "us-east-1",
	}
	// this chain of RoundTripper (sign -> mutate request -> sign again) should generate different signatures.
	r := &awsgosignv4.SignV4SDKV1{
		RoundTripper: &mutateRequestRoundTripper{
			RoundTripper: verifier,
			Mutate: func(req *http.Request) {
				// this header will be considered in the expected signature by the verifier, but wasn't included when
				// SignV4SDKV1 created the signature present in Authorization
				req.Header.Set("X-Oh-No", "asdf")
			},
		},
		Credentials: credentials.NewStaticCredentials("jriquelme", "notedigo", ""),
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

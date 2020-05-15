package awsgosignv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// SignV4SDKV2 is a http.RoundTripper to sign requests using aws-sdk-go-v2
type SignV4SDKV2 struct {
	RoundTripper http.RoundTripper
	Credentials  aws.CredentialsProvider
	Region       string
	Service      string
	Now          func() time.Time
}

func (s *SignV4SDKV2) RoundTrip(req *http.Request) (*http.Response, error) {
	signer := v4.NewSigner(s.Credentials)
	payloadHash, newReader, err := hashPayload(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = newReader
	err = signer.SignHTTP(context.Background(), req, payloadHash, s.Service, s.Region, s.Now())
	if err != nil {
		return nil, fmt.Errorf("error signing request: %w", err)
	}
	return s.RoundTripper.RoundTrip(req)
}

func hashPayload(r io.ReadCloser) (payloadHash string, newReader io.ReadCloser, err error) {
	var payload []byte
	if r == nil {
		payload = []byte("")
	} else {
		payload, err = ioutil.ReadAll(r)
		if err != nil {
			return
		}
		newReader = ioutil.NopCloser(bytes.NewReader(payload))
	}
	hash := sha256.Sum256(payload)
	payloadHash = hex.EncodeToString(hash[:])
	return
}

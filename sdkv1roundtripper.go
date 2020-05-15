package awsgosignv4

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
)

// SignV4SDKV1 is a http.RoundTripper to sign requests using aws-sdk-go
type SignV4SDKV1 struct {
	RoundTripper http.RoundTripper
	Credentials  *credentials.Credentials
	Region       string
	Service      string
	Now          func() time.Time
}

func (s *SignV4SDKV1) RoundTrip(req *http.Request) (*http.Response, error) {
	signer := v4.NewSigner(s.Credentials)
	var body io.ReadSeeker
	if req.Body != nil {
		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
		req.Body = ioutil.NopCloser(bytes.NewReader(b))
	}
	_, err := signer.Sign(req, body, s.Service, s.Region, s.Now())
	if err != nil {
		return nil, fmt.Errorf("error signing request: %w", err)
	}
	return s.RoundTripper.RoundTrip(req)
}

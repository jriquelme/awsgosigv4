package awsgosignv4_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/estransport"
	awsgosignv4 "github.com/jriquelme/awsgosigv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignV4SDKV1_RoundTrip_elastic(t *testing.T) {
	elasticEndpoint := os.Getenv("ELASTIC")
	if elasticEndpoint == "" {
		t.Skip("ELASTIC environment variable not found")
	}
	awsSession, err := session.NewSession()
	require.Nil(t, err)
	esClient, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{elasticEndpoint},
		Transport: &awsgosignv4.SignV4SDKV1{
			RoundTripper: http.DefaultTransport,
			Credentials:  awsSession.Config.Credentials,
			// set AWS_SDK_LOAD_CONFIG=1 to load the default region from ~/.aws/config, otherwise this will be empty
			Region:  *awsSession.Config.Region,
			Service: "es",
			Now:     time.Now,
		},
		Logger: &estransport.TextLogger{
			Output:             os.Stdout,
			EnableRequestBody:  true,
			EnableResponseBody: true,
		},
	})
	require.Nil(t, err)
	response, err := esClient.Info()
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestSignV4SDKV2_RoundTrip_elastic(t *testing.T) {
	elasticEndpoint := os.Getenv("ELASTIC")
	if elasticEndpoint == "" {
		t.Skip("ELASTIC environment variable not found")
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	require.Nil(t, err)
	credentials, err := cfg.Credentials.Retrieve(ctx)
	require.Nil(t, err)
	esClient, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{elasticEndpoint},
		Transport: &awsgosignv4.SignV4SDKV2{
			RoundTripper: http.DefaultTransport,
			Credentials:  credentials,
			Region:       cfg.Region,
			Service:      "es",
			Now:          time.Now,
		},
		Logger: &estransport.TextLogger{
			Output:             os.Stdout,
			EnableRequestBody:  true,
			EnableResponseBody: true,
		},
	})
	require.Nil(t, err)
	response, err := esClient.Info()
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

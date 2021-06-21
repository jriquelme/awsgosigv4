# AWS Signature V4 tests in GO

This repository contains two [http.RoundTripper](https://golang.org/pkg/net/http/#RoundTripper) implementations to sign
requests using [AWS Signature V4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html):

* SignV4SDKV1, using [aws-sdk-go](https://github.com/aws/aws-sdk-go)
* SignV4SDKV2, using [aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2)

The tests `TestSignV4SDKV1_RoundTrip_elastic` and `TestSignV4SDKV1_RoundTrip_elastic` (in `elasticexample_test.go`) show
how to use `SignV4SDKV1` and `SignV4SDKV2` with the [Elastic client](https://github.com/elastic/go-elasticsearch). The
tests get information from an Elastic cluster running in AWS, printing the request and its output. To run the examples
you need:

* An Elastic cluster running in [AWS Elasticsearch Service](https://aws.amazon.com/elasticsearch-service/).
* User credentials in `~/.aws/credentials` with access to the Elastic cluster.

Get your Elastic cluster endpoint and run:

```shell
ELASTIC="https://your-elastic-endpoint.us-east-1.es.amazonaws.com" AWS_SDK_LOAD_CONFIG=1 go test -v -run TestSignV4SDKV1_RoundTrip_elastic
```

or:

```shell
ELASTIC="https://your-elastic-endpoint.us-east-1.es.amazonaws.com" go test -v -run TestSignV4SDKV2_RoundTrip_elastic
```

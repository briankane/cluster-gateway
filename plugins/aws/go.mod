module github.com/oam-dev/cluster-gateway/plugins/aws

go 1.24

require (
	cuelang.org/go v0.14.1
	github.com/aws/aws-sdk-go-v2 v1.47.1
	github.com/aws/aws-sdk-go-v2/config v1.33.6
	github.com/aws/aws-sdk-go-v2/credentials v1.20.6
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.1
	github.com/aws/smithy-go v1.28.2
	github.com/oam-dev/cluster-gateway v0.0.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.1 // indirect
	github.com/cockroachdb/apd/v3 v3.2.1 // indirect
	github.com/emicklei/proto v1.14.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/protocolbuffers/txtpbfmt v0.0.0-20250627152318-f293424e46b5 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// The plugin builds against the protocol packages in this repository.
replace github.com/oam-dev/cluster-gateway => ../..

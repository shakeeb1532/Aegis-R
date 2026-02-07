package inventory

import (
	"fmt"
)

type Adapter interface {
	Name() string
	Load(cfg AdapterConfig) (Inventory, error)
}

type AdapterConfig struct {
	AWS   AWSConfig
	Okta  OktaConfig
	Azure AzureConfig
	GCP   GCPConfig
}

type AWSConfig struct {
	Region   string `json:"region"`
	Profile  string `json:"profile"`
	RoleARN  string `json:"role_arn"`
	External string `json:"external_id"`
}

type OktaConfig struct {
	OrgURL string `json:"org_url"`
	Token  string `json:"token"`
}

type AzureConfig struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Subscription string `json:"subscription"`
}

type GCPConfig struct {
	ProjectID   string `json:"project_id"`
	CredsFile   string `json:"creds_file"`
	CredsJSON   string `json:"creds_json"`
	Impersonate string `json:"impersonate"`
}

func NewAdapter(name string) (Adapter, error) {
	switch name {
	case "aws":
		return AWSAdapter{}, nil
	case "okta":
		return OktaAdapter{}, nil
	case "azure":
		return AzureAdapter{}, nil
	case "gcp":
		return GCPAdapter{}, nil
	default:
		return nil, fmt.Errorf("unknown adapter: %s", name)
	}
}

type AWSAdapter struct{}

func (AWSAdapter) Name() string { return "aws" }

type OktaAdapter struct{}

func (OktaAdapter) Name() string { return "okta" }

type AzureAdapter struct{}

func (AzureAdapter) Name() string { return "azure" }

type GCPAdapter struct{}

func (GCPAdapter) Name() string { return "gcp" }

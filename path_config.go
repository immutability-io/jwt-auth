// Copyright © 2018 Immutability, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"role_claim": &framework.FieldSchema{
					Default:     "group",
					Type:        framework.TypeString,
					Description: `Name of the claim (key) which will be used to map roles to policies.`,
				},
				"subject_claim": &framework.FieldSchema{
					Default:     "sub",
					Type:        framework.TypeString,
					Description: `Name of the claim (key) which will be used to map the user's identity.`,
				},
				"jwt_signer": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The public key used to validate the JWT signature.`,
				},
				"jwt_algorithm": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "RS256",
					Description: `The algorithm used to generate the signer's private key.`,
				},
				"oauth_resource": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The resource that is the audience of this JWT. Only used when authenticating with user/pass.`,
				},
				"oauth_endpoint": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The URL to authenticate to retrieve a JWT. Only used when authenticating with user/pass.`,
				},
				"oauth_cacert": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The CA Certificate used to sign the OAuth endpoint certificate.`,
				},
				"oauth_client_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The client ID to retrieve a JWT. Only used when authenticating with user/pass.`,
				},
				"oauth_client_secret": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The shared secret to retrieve a JWT. Only used when authenticating with user/pass.`,
				},
				"ad_domain": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The AD domain for the user.`,
				},
				"ttl": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `Duration after which authentication will be expired`,
				},
				"max_ttl": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `Maximum duration after which authentication will be expired`,
				},
				"bound_cidr_list": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: `Comma separated string or list of CIDR blocks. If set, specifies the blocks of
IP addresses which can perform the login operation.`,
				},
				"trustee_list": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: `Comma separated string or list of trustee addresses. If set, specifies that only delegated
authentication by one of these trustees is allowed.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathConfigWrite,
				logical.UpdateOperation: b.pathConfigWrite,
				logical.ReadOperation:   b.pathConfigRead,
			},
		},
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleClaim := data.Get("role_claim").(string)
	subjectClaim := data.Get("subject_claim").(string)
	jwtSigner := data.Get("jwt_signer").(string)
	jwtAlgorithm := data.Get("jwt_algorithm").(string)
	oauthResource := data.Get("oauth_resource").(string)
	oauthEndpoint := data.Get("oauth_endpoint").(string)
	oauthCACert := data.Get("oauth_cacert").(string)
	oauthClientID := data.Get("oauth_client_id").(string)
	oauthClientSecret := data.Get("oauth_client_secret").(string)
	adDomain := data.Get("ad_domain").(string)

	var ttl time.Duration
	var err error
	ttlRaw, ok := data.GetOk("ttl")
	if !ok || len(ttlRaw.(string)) == 0 {
		ttl = 0
	} else {
		ttl, err = time.ParseDuration(ttlRaw.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Invalid 'ttl':%s", err)), nil
		}
	}

	var maxTTL time.Duration
	maxTTLRaw, ok := data.GetOk("max_ttl")
	if !ok || len(maxTTLRaw.(string)) == 0 {
		maxTTL = 0
	} else {
		maxTTL, err = time.ParseDuration(maxTTLRaw.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Invalid 'max_ttl':%s", err)), nil
		}
	}
	var boundCIDRList []string
	if boundCIDRListRaw, ok := data.GetOk("bound_cidr_list"); ok {
		boundCIDRList = boundCIDRListRaw.([]string)
	}

	var trusteeList []string
	if trusteeListRaw, ok := data.GetOk("trustee_list"); ok {
		trusteeList = trusteeListRaw.([]string)
	}
	configBundle := config{
		RoleClaim:         roleClaim,
		SubjectClaim:      subjectClaim,
		JWTSigner:         jwtSigner,
		JWTAlgorithm:      jwtAlgorithm,
		OauthResource:     oauthResource,
		OauthEndpoint:     oauthEndpoint,
		OauthCACert:       oauthCACert,
		OauthClientID:     oauthClientID,
		OauthClientSecret: oauthClientSecret,
		ADDomain:          adDomain,
		TTL:               ttl,
		MaxTTL:            maxTTL,
		BoundCIDRList:     boundCIDRList,
		TrusteeList:       trusteeList,
	}
	entry, err := logical.StorageEntryJSON("config", configBundle)

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("configuration object not found")
	}

	config.TTL /= time.Second
	config.MaxTTL /= time.Second

	resp := &logical.Response{
		Data: map[string]interface{}{
			"role_claim":          config.RoleClaim,
			"subject_claim":       config.SubjectClaim,
			"jwt_signer":          config.JWTSigner,
			"jwt_algorithm":       config.JWTAlgorithm,
			"oauth_resource":      config.OauthResource,
			"oauth_endpoint":      config.OauthEndpoint,
			"oauth_cacert":        config.OauthCACert,
			"oauth_client_id":     config.OauthClientID,
			"oauth_client_secret": config.OauthClientSecret,
			"oauth_ad_domain":     config.ADDomain,
			"ttl":                 config.TTL,
			"max_ttl":             config.MaxTTL,
			"bound_cidr_list":     config.BoundCIDRList,
			"trustee_list":        config.TrusteeList,
		},
	}
	return resp, nil
}

// Config returns the configuration for this backend.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	var result config
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, fmt.Errorf("error reading configuration: %s", err)
		}
	}

	return &result, nil
}

type config struct {
	RoleClaim         string        `json:"role_claim" structs:"role_claim" mapstructure:"role_claim"`
	SubjectClaim      string        `json:"subject_claim" structs:"subject_claim" mapstructure:"subject_claim"`
	JWTSigner         string        `json:"jwt_signer" structs:"jwt_signer" mapstructure:"jwt_signer"`
	JWTAlgorithm      string        `json:"jwt_algorithm" structs:"jwt_algorithm" mapstructure:"jwt_algorithm"`
	OauthResource     string        `json:"oauth_resource" structs:"oauth_resource" mapstructure:"oauth_resource"`
	OauthEndpoint     string        `json:"oauth_endpoint" structs:"oauth_endpoint" mapstructure:"oauth_endpoint"`
	OauthCACert       string        `json:"oauth_cacert" structs:"oauth_cacert" mapstructure:"oauth_cacert"`
	OauthClientID     string        `json:"oauth_client_id" structs:"oauth_client_id" mapstructure:"oauth_client_id"`
	OauthClientSecret string        `json:"oauth_client_secret" structs:"oauth_client_secret" mapstructure:"oauth_client_secret"`
	ADDomain          string        `json:"ad_domain" structs:"ad_domain" mapstructure:"ad_domain"`
	TTL               time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL            time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	BoundCIDRList     []string      `json:"bound_cidr_list_list" structs:"bound_cidr_list" mapstructure:"bound_cidr_list"`
	TrusteeList       []string      `json:"trustee_list" structs:"trustee_list" mapstructure:"trustee_list"`
}

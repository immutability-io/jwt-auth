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
					Default:     "groups",
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

	entry, err := logical.StorageEntryJSON("config", config{
		RoleClaim:     roleClaim,
		SubjectClaim:  subjectClaim,
		JWTSigner:     jwtSigner,
		JWTAlgorithm:  jwtAlgorithm,
		TTL:           ttl,
		MaxTTL:        maxTTL,
		BoundCIDRList: boundCIDRList,
	})

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
			"role_claim":      config.RoleClaim,
			"subject_claim":   config.SubjectClaim,
			"jwt_signer":      config.JWTSigner,
			"jwt_algorithm":   config.JWTAlgorithm,
			"ttl":             config.TTL,
			"max_ttl":         config.MaxTTL,
			"bound_cidr_list": config.BoundCIDRList,
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
	RoleClaim     string        `json:"role_claim" structs:"role_claim" mapstructure:"role_claim"`
	SubjectClaim  string        `json:"subject_claim" structs:"subject_claim" mapstructure:"subject_claim"`
	JWTSigner     string        `json:"jwt_signer" structs:"jwt_signer" mapstructure:"jwt_signer"`
	JWTAlgorithm  string        `json:"jwt_algorithm" structs:"jwt_algorithm" mapstructure:"jwt_algorithm"`
	TTL           time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL        time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	BoundCIDRList []string      `json:"bound_cidr_list_list" structs:"bound_cidr_list" mapstructure:"bound_cidr_list"`
}

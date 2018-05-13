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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/cidrutil"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	jwt "github.com/immutability-io/jwt-go"
)

// JWTMappings is returned after successful authentication. This
// struct contains the list of policies to which this identity is entitled
// and the claims in the JWT as well.
type JWTMappings struct {
	Claims   jwt.MapClaims
	Policies []string
}

// ClaimsList returns this list of claims as strings
func (jwt *JWTMappings) ClaimsList(name string) []string {
	var claimsList []string
	listSlice, ok := jwt.Claims[name].([]interface{})
	if ok {
		for _, v := range listSlice {
			item, ok := v.(string)
			if ok {
				claimsList = append(claimsList, item)
			}
		}
	} else {
		stringBean, ok := jwt.Claims[name].(string)
		if ok {
			claimsList = append(claimsList, stringBean)
		}
	}
	return claimsList
}

func pathLogin(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "login",
			Fields: map[string]*framework.FieldSchema{
				"token": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "This is the JWT token in base64 encoded form.",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation:         b.pathLogin,
				logical.CreateOperation:         b.pathLogin,
				logical.AliasLookaheadOperation: b.pathLoginAliasLookahead,
			},
		},
	}
}

func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	token := data.Get("token").(string)
	var jwtMappings *JWTMappings
	if jwtMappingsResp, resp, err := b.validateJWT(ctx, req, token); err != nil {
		return nil, err
	} else if resp != nil {
		return resp, nil
	} else {
		jwtMappings = jwtMappingsResp
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: jwtMappings.Claims[config.SubjectClaim].(string),
			},
		},
	}, nil
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	token := data.Get("token").(string)
	var jwtMappings *JWTMappings

	if jwtMappingsResp, resp, err := b.validateJWT(ctx, req, token); err != nil {
		return nil, err
	} else if resp != nil {
		return resp, nil
	} else {
		jwtMappings = jwtMappingsResp
	}

	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	resp := &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"token": token,
			},
			DisplayName: jwtMappings.Claims[config.SubjectClaim].(string),
			Policies:    jwtMappings.Policies,
			Metadata: map[string]string{
				"username": jwtMappings.Claims[config.SubjectClaim].(string),
				"claims":   fmt.Sprintf("%v", jwtMappings.Claims[config.RoleClaim]),
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       config.TTL,
				Renewable: true,
			},
			Alias: &logical.Alias{
				Name: jwtMappings.Claims[config.SubjectClaim].(string),
			},
		},
	}
	listSlice := jwtMappings.ClaimsList(config.RoleClaim)
	for _, item := range listSlice {
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: item,
		})
	}

	return resp, nil
}

func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, fmt.Errorf("there is no authentication information in this request")
	}

	tokenRaw, ok := req.Auth.InternalData["token"]
	if !ok {
		return nil, fmt.Errorf("token created in previous version of Vault cannot be validated properly at renewal time")
	}
	token := tokenRaw.(string)

	var jwtMappings *JWTMappings
	if jwtMappingsResp, validateResp, err := b.validateJWT(ctx, req, token); err != nil {
		return nil, err
	} else if validateResp != nil {
		return validateResp, nil
	} else {
		jwtMappings = jwtMappingsResp
	}
	if !policyutil.EquivalentPolicies(jwtMappings.Policies, req.Auth.Policies) {
		return nil, fmt.Errorf("policies are not equivalent")
	}

	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	resp, err := framework.LeaseExtend(config.TTL, config.MaxTTL, b.System())(ctx, req, d)
	if err != nil {
		return nil, err
	}

	resp.Auth.GroupAliases = nil
	roles := jwtMappings.Claims[config.RoleClaim].([]string)
	for _, role := range roles {
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: role,
		})
	}

	return resp, nil
}

func (b *backend) parseJWT(ctx context.Context, token string, algorithm string, publicKey []byte) (jwt.MapClaims, error) {
	tokenWithoutWhitespace := regexp.MustCompile(`\s*$`).ReplaceAll([]byte(token), []byte{})
	var err error
	if parsed, err := jwt.Parse(string(tokenWithoutWhitespace), func(t *jwt.Token) (interface{}, error) {
		if strings.HasPrefix(algorithm, "ES") {
			return jwt.ParseECPublicKeyFromPEM(publicKey)
		} else if strings.HasPrefix(algorithm, "RS") {
			return jwt.ParseRSAPublicKeyFromPEM(publicKey)
		}
		return publicKey, nil
	}); err == nil {
		claims := parsed.Claims.(jwt.MapClaims)
		return claims, claims.Valid()
	}
	return nil, err
}

// PrettyPrint prints an indented JSON payload. This is used for development debugging.
func PrettyPrint(v interface{}) string {
	jsonString, _ := json.Marshal(v)
	var out bytes.Buffer
	json.Indent(&out, jsonString, "", "  ")
	return out.String()
}

func (b *backend) validateJWT(ctx context.Context, req *logical.Request, token string) (*JWTMappings, *logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, nil, err
	}
	publicKey := []byte(config.JWTSigner)
	claims, err := b.parseJWT(ctx, token, config.JWTAlgorithm, publicKey)

	if err != nil {
		return nil, nil, err
	}
	if validConnection, err := b.validIPConstraints(ctx, req); !validConnection {
		return nil, nil, err
	}
	jwtMappings := &JWTMappings{
		Claims: claims,
	}
	claimPoliciesList, err := b.RoleMap.Policies(ctx, req.Storage, jwtMappings.ClaimsList(config.RoleClaim)...)

	if err != nil {
		return nil, nil, err
	}

	userPoliciesList, err := b.UserMap.Policies(ctx, req.Storage, jwtMappings.ClaimsList(config.SubjectClaim)...)

	if err != nil {
		return nil, nil, err
	}

	return &JWTMappings{
		Claims:   claims,
		Policies: append(claimPoliciesList, userPoliciesList...),
	}, nil, nil
}

func (b *backend) validIPConstraints(ctx context.Context, req *logical.Request) (bool, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	if len(config.BoundCIDRList) != 0 {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return false, fmt.Errorf("failed to get connection information")
		}

		belongs, err := cidrutil.IPBelongsToCIDRBlocksSlice(req.Connection.RemoteAddr, config.BoundCIDRList)
		if err != nil {
			return false, errwrap.Wrapf("failed to verify the CIDR restrictions set on the role: {{err}}", err)
		}
		if !belongs {
			return false, fmt.Errorf("source address %q unauthorized through CIDR restrictions on the role", req.Connection.RemoteAddr)
		}
	}
	return true, nil
}

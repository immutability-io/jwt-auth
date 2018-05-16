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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/cidrutil"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	jwt "github.com/immutability-io/jwt-go"
	"github.com/sethgrid/pester"
)

// JWTMappings is returned after successful authentication. This
// struct contains the list of policies to which this identity is entitled
// and the claims in the JWT as well.
type JWTMappings struct {
	Claims   jwt.MapClaims
	Policies []string
}

// TokenResponse is the response from the OAuth server
type TokenResponse struct {
	AccessToken           string `json:"access_token" structs:"access_token" mapstructure:"access_token"`
	TokenType             string `json:"token_type" structs:"token_type" mapstructure:"token_type"`
	ExpiresIn             int    `json:"expires_in" structs:"expires_in" mapstructure:"expires_in"`
	Resource              string `json:"resource" structs:"resource" mapstructure:"resource"`
	RefreshToken          string `json:"refresh_token" structs:"refresh_token" mapstructure:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in" structs:"refresh_token_expires_in" mapstructure:"refresh_token_expires_in"`
	IDToken               string `json:"id_token" structs:"id_token" mapstructure:"id_token"`
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
				"username": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "User name for authenticating to an endpoint to retrieve a JWT - overrides token auth.",
				},
				"password": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The password for the username above.",
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

func (b *backend) makeOauthRequest(ctx context.Context, req *logical.Request, data url.Values) (*TokenResponse, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config.OauthEndpoint == "" || config.OauthClientID == "" || config.OauthResource == "" || config.OauthClientSecret == "" || config.OauthCACert == "" {
		return nil, fmt.Errorf("missing configuration elements")
	}

	caCert, err := ioutil.ReadFile(config.OauthCACert)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	httpClient := pester.New()

	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}

	data.Add("client_id", config.OauthClientID)
	data.Add("client_secret", config.OauthClientSecret)
	if config.OauthResource != "" {
		data.Add("resource", config.OauthResource)
	}
	encoded := []byte(data.Encode())

	request, err := http.NewRequest("POST", config.OauthEndpoint, bytes.NewBuffer(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "x-www-form-urlencoded")

	resp, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("OAuth endpoint failed to return a response")
	}
	var htmlData []byte
	htmlData, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var payload TokenResponse
	err = json.Unmarshal(htmlData, &payload)
	if err != nil {
		return nil, err
	}

	return &payload, nil

}

func (b *backend) getJWTFromOauthPasswordGrant(ctx context.Context, req *logical.Request, username, password string) (*TokenResponse, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Add("grant_type", "password")
	if config.ADDomain != "" {
		data.Add("username", fmt.Sprintf("%s\\%s", config.ADDomain, username))
	} else {
		data.Add("username", username)
	}
	data.Add("password", password)
	return b.makeOauthRequest(ctx, req, data)
}

func (b *backend) getJWTFromOauthRefresh(ctx context.Context, req *logical.Request, refreshToken string) (*TokenResponse, error) {
	data := url.Values{}
	data.Add("grant_type", "refresh_token")
	data.Add("refresh_token", refreshToken)
	return b.makeOauthRequest(ctx, req, data)
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
	if jwtMappings == nil {
		return nil, fmt.Errorf("unable to map claims")
	}
	subject, ok := jwtMappings.Claims[config.SubjectClaim]
	if !ok {
		return nil, fmt.Errorf("unable to find subject")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: subject.(string),
			},
		},
	}, nil
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	token := data.Get("token").(string)
	username := data.Get("username").(string)
	password := data.Get("password").(string)

	refreshToken := ""

	if username != "" && password != "" {
		tokenResponse, err := b.getJWTFromOauthPasswordGrant(ctx, req, username, password)

		if err != nil {
			return nil, err
		}
		token = tokenResponse.AccessToken
		refreshToken = tokenResponse.RefreshToken
	}
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
	if jwtMappings == nil {
		return nil, fmt.Errorf("unable to map claims")
	}
	subject, ok := jwtMappings.Claims[config.SubjectClaim]
	if !ok {
		return nil, fmt.Errorf("unable to find subject")
	}

	claims, ok := jwtMappings.Claims[config.RoleClaim]
	if !ok {
		return nil, fmt.Errorf("unable to find roles")
	}
	resp := &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"token":         token,
				"refresh_token": refreshToken,
			},
			DisplayName: subject.(string),
			Policies:    jwtMappings.Policies,
			Metadata: map[string]string{
				"username": subject.(string),
				"jwt":      token,
				"roles":    fmt.Sprintf("%v", claims),
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       config.TTL,
				Renewable: true,
			},
			Alias: &logical.Alias{
				Name: subject.(string),
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
	token := ""
	refreshToken, ok := req.Auth.InternalData["refresh_token"]
	if ok && refreshToken != "" {
		tokenResponse, err := b.getJWTFromOauthRefresh(ctx, req, refreshToken.(string))

		if err != nil {
			tokenRaw, ok := req.Auth.InternalData["token"]
			if !ok {
				return nil, fmt.Errorf("token created in previous version of Vault cannot be validated properly at renewal time")
			}
			token = tokenRaw.(string)
		} else {
			token = tokenResponse.AccessToken
		}
	}

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
	if jwtMappings == nil {
		return nil, fmt.Errorf("unable to map claims")
	}

	claims, ok := jwtMappings.Claims[config.RoleClaim].([]interface{})
	if !ok {
		roleName, ok := jwtMappings.Claims[config.RoleClaim].(string)
		if !ok {
			return nil, fmt.Errorf("unable to find roles")
		}
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: roleName,
		})
	} else {
		for _, role := range claims {
			roleName := role.(string)
			resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
				Name: roleName,
			})
		}
	}

	return resp, nil
}

func (b *backend) parseJWT(ctx context.Context, token string, algorithm string, publicKey []byte) (jwt.MapClaims, error) {
	tokenWithoutWhitespace := regexp.MustCompile(`\s*$`).ReplaceAll([]byte(token), []byte{})
	parsed, err := jwt.Parse(string(tokenWithoutWhitespace), func(t *jwt.Token) (interface{}, error) {
		if strings.HasPrefix(algorithm, "ES") {
			return jwt.ParseECPublicKeyFromPEM(publicKey)
		} else if strings.HasPrefix(algorithm, "RS") {
			return jwt.ParseRSAPublicKeyFromPEM(publicKey)
		}
		return publicKey, nil
	})
	if err == nil {
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
	if claims == nil {
		return nil, nil, fmt.Errorf("unable to parse claims - likely a time sync issue")
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

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

	"github.com/hashicorp/vault/helper/mfa"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Factory creates the Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// FactoryType returns the Factory
func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := Backend()
		b.BackendType = backendType
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// Backend is the implementation of the JWT Auth backend
func Backend() *backend {
	var b backend
	b.RoleMap = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "claims",
		},
		DefaultKey: "default",
	}

	b.UserMap = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "users",
		},
		DefaultKey: "default",
	}

	b.Backend = &framework.Backend{
		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Root: mfa.MFARootPaths(),
			Unauthenticated: []string{
				"login",
			},
		},

		Paths: framework.PathAppend(
			pathConfig(&b),
			b.RoleMap.Paths(),
			b.UserMap.Paths(),
			mfa.MFAPaths(b.Backend, pathLogin(&b)[0]),
		),
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
	}

	return &b
}

type backend struct {
	*framework.Backend

	RoleMap *framework.PolicyMap
	UserMap *framework.PolicyMap
}

const backendHelp = `
The JWT Auth credential provider allows authentication via JWT.

The JWT Auth backend is configured by mapping claims in the JWT 
to the policies that should be allowed for those claims. The name of
claim to use is configurable via the config path.
`

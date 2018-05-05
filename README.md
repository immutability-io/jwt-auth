JWT-Auth: A generic, and simplistic, authentication plugin for Vault
---------------

JWTs are all the rage. They provide a simple way of transmitting claims made by a trusted entity to another. So, if Vault trusts the signer of a JWT, why shouldn't Vault allow that signer to assert claims about an identity? JWTs are bearer tokens, so if the JWT gets compromised then an attacker could use it to gain access to Vault. While this attack vector is something to protect against, it is no different than the compromise of a GitHub personal access token or even a person's LDAP credentials. A nice aspect to JWTs is that they *usually* have short TTLs, so they are intrinsically safer than GitHub personal access tokens or LDAP credentials (which typically are long lived.)

This plugin is just another tool in the chest for a Vaulter: if you wish to provide access to Vault based upon the bearer of a JWT, then here is your tool. Context is everything, and since Vault gives you choices about how to manage context, this plugin gives you another choice in how to navigate that context.

## Build/Install

Building is typically golang: 

```sh
$ go get github.com/immutability-io/jwt-auth
```

This will drop the executable in your `$GOPATH/bin` directory. Alternatively, you can download the latest release from this GitHub repo. If you do this, you should verify the release like this (assuming your current directory is where the files `SHA256SUMS.sig` and `SHA256SUMS` reside.)

```sh
$ keybase pgp verify -d ./SHA256SUMS.sig -i ./SHA256SUMS
```

## Installation

If you download the release, the zipfile contains a file called `SHA265SUM`. This is what I got for `shasum -a 256` on my build. You will need this value to install the plugin. You can export it into your environment:

```sh
$ export SHA256=$(cat SHA265SUM) 
```

Alternatively, if you built the plugin, and it is in the `$GOPATH/bin` directory do this:

```sh
$ export SHA256=$(shasum -a 256 "$GOPATH/bin/jwt-auth" | cut -d' ' -f1)
```

I assume that you are using TLS to connect to Vault. I assume this because I respect you. Let's say that your Vault configuration resides in: `$HOME/etc/vault.d/`

A very simple Vault configuration - a laptop special - might look like this:

```
"default_lease_ttl" = "24h"

"ui" = "true"
"max_lease_ttl" = "24h"
"disable_mlock" = "true"
"backend" "file" {
  "path" = "/Users/immutability/etc/vault.d/data"
}

"api_addr" = "https://localhost:8200"

"listener" "tcp" {
  "address" = "localhost:8200"

  "tls_cert_file" = "/Users/immutability/etc/vault.d/vault.crt"
  "tls_client_ca_file" = "/immutability/tssbi08/etc/vault.d/root.crt"
  "tls_key_file" = "/Users/immutability/etc/vault.d/vault.key"
}

"plugin_directory" = "/Users/immutability/etc/vault.d/vault_plugins"
```

Note: `"api_addr" = "https://localhost:8200"`. [This is important for plugins](https://www.vaultproject.io/docs/configuration/index.html#api_addr).

Assuming this configuration - yours may be different, so the following commands may need to be tweaked -the following will install the plugin:

```sh
$ mv $GOPATH/bin/jwt-auth $HOME/etc/vault.d/vault_plugins
$ vault write sys/plugins/catalog/jwt-auth \
      sha_256="${SHA256}" \
      command="jwt-auth --ca-cert=$HOME/etc/vault.d/root.crt --client-cert=$HOME/etc/vault.d/vault.crt --client-key=$HOME/etc/vault.d/vault.key"
$ vault auth enable -path=jwt-auth -plugin-name=jwt-auth -description="JWT authentication plugin" plugin
```

Assuming that worked, you should see something like this when you list your auth endpoints:

```sh
$ vault auth list
Path         Type      Description
----         ----      -----------
jwt-auth/    plugin    JWT authentication plugin
token/       token     token based credentials
```

## Configuration

There are 4 main configuration *options* with this plugin:

1. Configure the trust - associate the signer key and algorithm with the authentication endpoint.
2. Configure the claims - choose which claims map to policies.
3. Configure the IP contraints: choose which IP ranges are allowed to authenticate.
4. Map policies to claims.

The first 3 options are configured via the `config` endpoint. Assuming you used the path exemplified above (you can mount this plugin at a variety of paths - this is not a singleton) you configure as follows:

### Trust 

```sh
$ vault write auth/jwt-auth/config jwt_signer=@jwtRS256.key.pub ttl=60m max_ttl=300m
```

This will establish trust with whatever entity has the private key corresponding to the `jwtRS256.key.pub` public key. 

### Claims

The above will use the default claims `groups` and `sub` for claim and subject mapping. Since you are probably confused, and example JWT is probably useful now. Consider the following JWT:

![Very silly JWT](/doc/jwt.png?raw=true "Silly JWT")

This JWT has 2 claims: `groups` and `sub`. The `sub` claim identifies the subject of the JWT - about whom the claims are made. The `groups` is an statement about attributes of the subject: `goober` belongs to the `test` group.

If this is not your JWT schema, then you can change the names of the claims that you want to use to map policies. For example, consider an ADFS JWT:

![ADFS JWT](/doc/adfs.png?raw=true "ADFS JWT")

In this case, you would want to point to different claims - probably `groupsid` and `upn`. You would do this thusly:

```sh
$ vault write auth/jwt-auth/config jwt_signer=@adfs.key.pub role_claim=groupsid subject_claim=upn ttl=60m max_ttl=300m
```

### Configure IP Constraints

Suppose you only want certain machines to authenticate using this JWT. In that case, you can restrict authentication to a set of CIDR blocks. For example:

```sh
$ vault write auth/jwt-auth/config jwt_signer=@adfs.key.pub role_claim=groupsid subject_claim=upn bound_cidr_list="10.23.14.0/22,10.45.12.0/22" ttl=60m max_ttl=300m
```

Now, when anything tries to authenticate - with a valid JWT token - from an IP address outside of that range it will fail.

**Note: IP restrictions are helpful - to some extent - but not really awesome in a containerized world. Stay tuned - I will be merging ideas from my Ethereum plugin with this plugin in the near future. This will address that limitation.**

### Map policies to claims

Suppose you have 2 policies in Vault:

1. A user policy called `developer`; and,
2. A policy called `admin` that requires some entitlement (aka, claim in a JWT)

To map the `developer` policy to a user named `goober` do the following. (Note: the name `goober` is identified in the JWT by the subject claim. See #2 above):

```sh
$ vault write auth/jwt-auth/map/users/goober value=developer
```

To map the `admin` policy to all users that are part of the `admin` group do the following. (Note: the name `admin` is identified in the JWT by the role claim. See #2 above):

```sh
$ vault write auth/jwt-auth/map/claims/admin value=admin
```

## Usage

Once configured, authentication proceeds as follows:

```sh
$ vault write -format=json auth/jwt-auth/login token=@jwt.json
{
  "request_id": "13d0f04e-882f-f83c-7b5a-71807a948feb",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": null,
  "warnings": null,
  "auth": {
    "client_token": "782b473e-b79a-10bc-50a3-61a44b3937f3",
    "accessor": "ce6611a0-5055-fdc9-8ee4-3e324050d4ec",
    "policies": [
      "default",
      "goober",
      "admin"
    ],
    "metadata": {
      "claims": "[test]",
      "username": "goober"
    },
    "lease_duration": 3600,
    "renewable": true
  }
}
```

## Have fun

And let me know what you like or hate... but be kind, I am very sensitive. :) Note: much of this code was based on the Vault GitHub plugin. I used the same code that I contributed to that plugin for MFA here. 

Also, I will be delivering a secrets plugin that allows the creation of JWTs in the near future. This will include some capabilities that should be fun.

Cheers!
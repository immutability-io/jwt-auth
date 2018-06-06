A design for delegated authentication using Vault
--------

I have built 2 Vault plugins - [the trustee plugin](https://github.com/immutability-io/trustee) and [the jwt-auth plugin](https://github.com/immutability-io/jwt-auth) - which when used together can provide a delegated authentication mechanism for web services.


# Some Delegated Authentication Use Cases

There are a handful of ways the Trustee plugin can be used effectively in conjunction with the JWT-Auth plugin. I will start with a very simple use case: 

## Governance by Proxy

Imagine that you have an identity in Active Directory: You have a user ID and you are the member of a handful of Active Directory groups. One of these groups is `pay-master-group`. Your membership in this group means that you are allowed to cut checks from a bank account (`123412341234`) that holds millions of dollars.

Accessing this bank account (`123412341234`) requires a credential - for simplicity's sake, let's call it a password - so, we want to use Vault to secure this password. We put the password in Vault at the following path: `secret/bank/123412341234`

### Protecting the Credential with RBAC Is Not Enough!!!

A simple solution to securing this bank account password might be to use the JWT-Auth plugin as follows:

1. Create a policy that allows this path to be read:

```sh

$ cat pay-master.hcl

path "secret/bank/123412341234" {
    policy = "read"
}

$ vault policy write pay-master-policy pay-master.hcl
```

2. Map this policy to the `pay-master` group:

```sh
$ vault write auth/jwt-auth/map/claims/pay-master-group value=pay-master-policy
```

Now when you, the pay-master, authenticate to the `auth/jwt-auth/login` Vault endpoint you get a token you can use to read the password, and all is great:

```sh
$ read -s PASSWORD; vault write -format=json auth/jwt-auth/login username=cypherhat password=$PASSWORD | jq ; unset PASSWORD
{
  "request_id": "1bced3ff-acc7-14b0-99c8-f50c28e3b83c",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": null,
  "warnings": null,
  "auth": {
    "client_token": "5d72d7200-602f-3451-e19a-d9860fc05a63",
    "accessor": "953e1412-bb92-e81c-70bf-0aa6e7262238",
    "policies": [
      "default",
      "pay-master-policy"
    ],
    "metadata": {
      "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJncm91cCI6WyJwYXktbWFzdGVyLWdyb3VwIl0sInN1YiI6ImN5cGhlcmhhdCJ9.kNrzfOxcALrGXQPbYkSnoBJ_LjiRfPmQXjCOv5l2uUeuM3H6GCdqnQY5kvnZtJuj4ztR3Us_uDI5cxhDJ45OQEHz4zRipYJX28rKHfO04rK1ieP95KNRxlQ1YCnufWmHHmPJgh3aK-a9zGdy2ZaXlmpVbDEOxNyUm7gNuJ1AFkYqN0S_LnNx_alU5zzoxTkKGMpTLVGzPqVKrhXRuEZwK1duKlAS4YIvq4BzYJm7lMyAafdxEkeqPb1VptQEvJzyIU2xkZMBBlhbxj6qZUEiiKloPzgAs6z1pLYDCpJL6SZ50ozyDM3tqocqY6Qqaxl3Rk0WARC17z7UFIuiOERMfUafvKC5v8aA7Wzr_3BoM91qNI3IyqFl-GEYToDZ4TD922hvNaVpdKciKIJMUUZjNXvXD9xhGWWUqwvHMPkYYJDnC5uRDdlgzgXVIGD0ABPk3a6ULLMw9PxF_RpjQzUkqVfywsUvaUOj0jPx1SVeS3CQdjFcPLwYQuub5H3HzjGUWSFLetktGrbdG_YnW6lFAz-wMzI_BYOSBtwiq9IhrxDL0x2E6PYnU1k5C0-DmYV3yDb_cMNul0KZLq4e0tC6i8YeteAlqCfoWOc3WgWPuqVulBsPGIkbmuRNYOWEpxlseWaX41On_BSskfL7NK02YHHFIZH91njGSDHo_Md0h6Y",
      "roles": "[pay-master-group]",
      "username": "tssbi08"
    },
    "lease_duration": 3600,
    "renewable": true
  }
}

$ vault login 5d72d7200-602f-3451-e19a-d9860fc05a63

Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                Value
---                -----
token              d72d7200-602f-3451-e19a-d9860fc05a63
token_accessor     953e1412-bb92-e81c-70bf-0aa6e7262238
token_duration     30m
token_renewable    false
token_policies     [default pay-master-policy]

$ vault read secret/bank/123412341234
Key                 Value
---                 -----
refresh_interval    24h
password            pa49881word
```

### Necessity and Sufficiency and Context

Protecting the password to the bank account with an access control as described above is **necessary** to prevent unauthorized access to the password; however, it is not **sufficient** to prevent unauthorized access to the password. Most likely, this password should never be accessed by an end user's machine. Furthermore, there are typically many aspects of governance that are required to happen before this password can be used in a legitimate context. That governance is often manifested as a software process - trusted code that has to execute before and after accessing and using the password. Let's call this code a `service`.

To make this use case realistic and interesting, let's say that this `service` also performs tasks that are less sensitive - in addition to debiting the bank account; it sends non-account information to the bank. 

Let's posit the following as a **sufficient** access control:

1. The actor that accesses the password must be in the `pay-master-group`;
2. The actor cannot access the password except within the context of the trusted code described above;
2. The password can **not** be accessed by the above service unless it is acting on behalf of the actor in #1. 

### In Which Context is Everything

Before we talk about the `service`, let's talk about the network context where the password is used. One might say: we could use IP constraints to add an additional authentication factor to the Vault JWT-Auth plugin. (This plugin **does** support IP constraints.) Though this is certainly possible; in our new world of containers as functions and micro-services, IP addresses are pretty hard to pin down with the kind of resolution that is necessary to make trust decisions. We rarely know the IP address ahead of time, so we are left with broad CIDR block ranges.  

Furthermore, IP addresses have always been problematic as an authentication factor: they only works well if you have "true" IP - the protocols used by proxies are insecure as X-Forwarded-For can be tampered with; and, it isn't realistic to expect a packet to be relayed without some form of network address translation. 

Wouldn't it be awesome if there was a functional equivalent of the IP address for the modern Internet? Well, as is evidenced by the Trustee Vault plugin, [we can extend the IP Metaphor with Ethereum Addreses](https://github.com/immutability-io/trustee#extending-the-ip-metaphor-with-ethereum-addreses).

With the Trustee plugin, we can tighten up trust to effect what we describe as **sufficient** above. Follows is how we do that:

#### Establish a Trustee

A trustee is essentially a well-known Ethereum address - we trust that only the actor that possesses the private key associated with an Ethereum address can make valid claims on behalf of that Ethereum address. So, the first thing we have to do is establish a trustee. This doesn't have to be done using the Vault Trustee plugin, but since it **does** have to be done using a private key, Vault is a good choice for securing this key.

To establish the `bank-account-service` trustee using the Vault Trustee plugin, we do the following (assuming the plugin has been successfully installed.):

```sh
## The Trustee plugin is mounted using:

$ vault secrets enable -path=trust -plugin-name=trustee plugin 
$ vault write -f trust/trustees/bank-account-service
Key          Value
---          -----
address      0x90f9321a3615fCFB4F0Fe8C1E45986D85251F5FE
blacklist    <nil>
chain_id     1977
whitelist    <nil>

```

The above address is the Ethereum address. The critical element of the trust equation here is to give the **legitimate** `bank-account-service` write access to the path `trust/trustees/bank-account-service/claim`. This can be done in several ways using Vault; but, all of these amount to creating an authentication mechanism for the `bank-account-service` so that it has a policy that includes:

```

$ cat bank-account-service.hcl

path "trust/trustees/bank-account-service/claim" {
    policy = "write"
}

```

#### Trust the Trustee

So, now we have a trustee, aka, an Ethereum address. Now, we have to trust it to authenticate as the `pay-master's` behalf. What this means is that we will add the trustee (address) to the jwt-auth mechanism described above.

```sh
$ vault write auth/jwt-auth/config jwt_signer=@jwtRS256.key.pub trustee_list="0x90f9321a3615fCFB4F0Fe8C1E45986D85251F5FE" ttl=60m max_ttl=300m
```

Note: The file `jwtRS256.key.pub` is the public key that corresponds to the private key that Active Directory used to sign a JWT token. 

Now just to test, let's authenticate to Active Directory and get a JWT token. (I won't show this here.) If we capture this token in a file named `delegate.json` we can try to authenticate to Vault with the token:

```sh
$ vault write -format=json auth/jwt-auth/login token=@delegate.json | jq .
Error writing data to auth/test/jwt/login: Error making API request.

URL: PUT https://vault.awesomesauce.com:8200/v1/auth/jwt-auth/login
Code: 500. Errors:

* we don't trust this issuer: http://fs.awesomesauce.com/adfs/services/trust
```

Authentication fails, as it should - we are not the `bank-account-service`! We are just the `pay-master` and we are trying to get secrets **out of the bounds of a legitimate context**. 

#### Delegated Authentication

So, we have deployed our `bank-account-service` to a Kubernetes cluster. This service is used by a `bank-account-application` which we login to using an OAuth2 ceremony with ADFS. This application propagates our JWT token to our trustee - the `bank-account-service`. This JWT is a base64 encoded string that the `bank-account-service` adds to a JSON structure that constitutes the claims it wants to make. This JWT **must be** the `delegate` claim:

```sh

$ cat claims.json
{
  "service": "bank-account-service",
  "delegate": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJncm91cCI6WyJwYXktbWFzdGVyLWdyb3VwIl0sInN1YiI6ImN5cGhlcmhhdCJ9.kNrzfOxcALrGXQPbYkSnoBJ_LjiRfPmQXjCOv5l2uUeuM3H6GCdqnQY5kvnZtJuj4ztR3Us_uDI5cxhDJ45OQEHz4zRipYJX28rKHfO04rK1ieP95KNRxlQ1YCnufWmHHmPJgh3aK-a9zGdy2ZaXlmpVbDEOxNyUm7gNuJ1AFkYqN0S_LnNx_alU5zzoxTkKGMpTLVGzPqVKrhXRuEZwK1duKlAS4YIvq4BzYJm7lMyAafdxEkeqPb1VptQEvJzyIU2xkZMBBlhbxj6qZUEiiKloPzgAs6z1pLYDCpJL6SZ50ozyDM3tqocqY6Qqaxl3Rk0WARC17z7UFIuiOERMfUafvKC5v8aA7Wzr_3BoM91qNI3IyqFl-GEYToDZ4TD922hvNaVpdKciKIJMUUZjNXvXD9xhGWWUqwvHMPkYYJDnC5uRDdlgzgXVIGD0ABPk3a6ULLMw9PxF_RpjQzUkqVfywsUvaUOj0jPx1SVeS3CQdjFcPLwYQuub5H3HzjGUWSFLetktGrbdG_YnW6lFAz-wMzI_BYOSBtwiq9IhrxDL0x2E6PYnU1k5C0-DmYV3yDb_cMNul0KZLq4e0tC6i8YeteAlqCfoWOc3WgWPuqVulBsPGIkbmuRNYOWEpxlseWaX41On_BSskfL7NK02YHHFIZH91njGSDHo_Md0h6Y"
}

```

First, we call the Vault Trustee plugin to create a `claim`. This `claim` takes the form of a JWT token that is signed with the private key used to generate the Trustee's Ethereum address:

```sh
$ vault write -format=json trust/trustees/bank-account-service/claim  claims=@claim.json
{
  "request_id": "2aefacbf-152f-322b-3c32-468b98d6af37",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "delegate": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJncm91cCI6WyJwYXktbWFzdGVyLWdyb3VwIl0sInN1YiI6ImN5cGhlcmhhdCJ9.kNrzfOxcALrGXQPbYkSnoBJ_LjiRfPmQXjCOv5l2uUeuM3H6GCdqnQY5kvnZtJuj4ztR3Us_uDI5cxhDJ45OQEHz4zRipYJX28rKHfO04rK1ieP95KNRxlQ1YCnufWmHHmPJgh3aK-a9zGdy2ZaXlmpVbDEOxNyUm7gNuJ1AFkYqN0S_LnNx_alU5zzoxTkKGMpTLVGzPqVKrhXRuEZwK1duKlAS4YIvq4BzYJm7lMyAafdxEkeqPb1VptQEvJzyIU2xkZMBBlhbxj6qZUEiiKloPzgAs6z1pLYDCpJL6SZ50ozyDM3tqocqY6Qqaxl3Rk0WARC17z7UFIuiOERMfUafvKC5v8aA7Wzr_3BoM91qNI3IyqFl-GEYToDZ4TD922hvNaVpdKciKIJMUUZjNXvXD9xhGWWUqwvHMPkYYJDnC5uRDdlgzgXVIGD0ABPk3a6ULLMw9PxF_RpjQzUkqVfywsUvaUOj0jPx1SVeS3CQdjFcPLwYQuub5H3HzjGUWSFLetktGrbdG_YnW6lFAz-wMzI_BYOSBtwiq9IhrxDL0x2E6PYnU1k5C0-DmYV3yDb_cMNul0KZLq4e0tC6i8YeteAlqCfoWOc3WgWPuqVulBsPGIkbmuRNYOWEpxlseWaX41On_BSskfL7NK02YHHFIZH91njGSDHo_Md0h6Y",
    "eth": "0x0f2c5c77d6f0d7318653ceb68288d94463bee72265e9c38e0e12437bcbf10ef144596a5fbef9d4db833cdcdf9092031d30ea805939019cb9fc3ac33e718ece8601",
    "exp": "1528317525",
    "iss": "0x90f9321a3615fCFB4F0Fe8C1E45986D85251F5FE",
    "jti": "8bb409f3-2ccb-48f2-b3d6-d7beaea7f97b",
    "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJkZWxlZ2F0ZSI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpuY205MWNDSTZXeUp3WVhrdGJXRnpkR1Z5TFdkeWIzVndJbDBzSW5OMVlpSTZJbU41Y0dobGNtaGhkQ0o5LmtOcnpmT3hjQUxyR1hRUGJZa1Nub0JKX0xqaVJmUG1RWGpDT3Y1bDJ1VWV1TTNINkdDZHFuUVk1a3ZuWnRKdWo0enRSM1VzX3VESTVjeGhESjQ1T1FFSHo0elJpcFlKWDI4cktIZk8wNHJLMWllUDk1S05SeGxRMVlDbnVmV21ISG1QSmdoM2FLLWE5ekdkeTJaYVhsbXBWYkRFT3hOeVVtN2dOdUoxQUZrWXFOMFNfTG5OeF9hbFU1enpveFRrS0dNcFRMVkd6UHFWS3JoWFJ1RVp3SzFkdUtsQVM0WUl2cTRCellKbTdsTXlBYWZkeEVrZXFQYjFWcHRRRXZKenlJVTJ4a1pNQkJsaGJ4ajZxWlVFaWlLbG9QemdBczZ6MXBMWURDcEpMNlNaNTBvenlETTN0cW9jcVk2UXFheGwzUmswV0FSQzE3ejdVRkl1aU9FUk1mVWFmdktDNXY4YUE3V3pyXzNCb005MXFOSTNJeXFGbC1HRVlUb0RaNFREOTIyaHZOYVZwZEtjaUtJSk1VVVpqTlh2WEQ5eGhHV1dVcXd2SE1Qa1lZSkRuQzV1UkRkbGd6Z1hWSUdEMEFCUGszYTZVTExNdzlQeEZfUnBqUXpVa3FWZnl3c1V2YVVPajBqUHgxU1ZlUzNDUWRqRmNQTHdZUXV1YjVIM0h6akdVV1NGTGV0a3RHcmJkR19Zblc2bEZBei13TXpJX0JZT1NCdHdpcTlJaHJ4REwweDJFNlBZblUxazVDMC1EbVlWM3lEYl9jTU51bDBLWkxxNGUwdEM2aThZZXRlQWxxQ2ZvV09jM1dnV1B1cVZ1bEJzUEdJa2JtdVJOWU9XRXB4bHNlV2FYNDFPbl9CU3NrZkw3TkswMllISEZJWkg5MW5qR1NESG9fTWQwaDZZIiwiZXRoIjoiMHgwZjJjNWM3N2Q2ZjBkNzMxODY1M2NlYjY4Mjg4ZDk0NDYzYmVlNzIyNjVlOWMzOGUwZTEyNDM3YmNiZjEwZWYxNDQ1OTZhNWZiZWY5ZDRkYjgzM2NkY2RmOTA5MjAzMWQzMGVhODA1OTM5MDE5Y2I5ZmMzYWMzM2U3MThlY2U4NjAxIiwiZXhwIjoiMTUyODMxNzUyNSIsImlzcyI6IjB4OTBmOTMyMWEzNjE1ZkNGQjRGMEZlOEMxRTQ1OTg2RDg1MjUxRjVGRSIsImp0aSI6IjhiYjQwOWYzLTJjY2ItNDhmMi1iM2Q2LWQ3YmVhZWE3Zjk3YiIsIm5iZiI6IjE1MjgzMTM5MjUiLCJzZXJ2aWNlIjoiYmFuay1hY2NvdW50LXNlcnZpY2UiLCJzdWIiOiIweDkwZjkzMjFhMzYxNWZDRkI0RjBGZThDMUU0NTk4NkQ4NTI1MUY1RkUifQ.AwDFFg8V0bDQVJYpzqsucU6g2fIwiXlftHbx-7Yb3ymNo2OmgsqtbV-Qv5o0X0byma3yWhhMItvIdWMu3BgBZw",
    "nbf": "1528313925",
    "service": "bank-account-service",
    "sub": "0x90f9321a3615fCFB4F0Fe8C1E45986D85251F5FE"
  },
  "warnings": null
}
```

The JWT that is returned is captured in a file named `service.json` and then sent to the jwt-auth endpoint to perform delegated authentication.

```sh
$ vault write -format=json auth/jwt-auth/login token=@service.json | jq .
{
  "request_id": "532cc2cd-05e8-4704-b853-7fd5cd1dec5b",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": null,
  "warnings": null,
  "auth": {
    "client_token": "04302161-36af-6e96-54bf-319a8cf1aa73",
    "accessor": "92a422f4-ea74-6241-923f-00473345ba42",
    "policies": [
      "default"
    ],
    "metadata": {
      "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJncm91cCI6WyJwYXktbWFzdGVyLWdyb3VwIl0sInN1YiI6ImN5cGhlcmhhdCJ9.kNrzfOxcALrGXQPbYkSnoBJ_LjiRfPmQXjCOv5l2uUeuM3H6GCdqnQY5kvnZtJuj4ztR3Us_uDI5cxhDJ45OQEHz4zRipYJX28rKHfO04rK1ieP95KNRxlQ1YCnufWmHHmPJgh3aK-a9zGdy2ZaXlmpVbDEOxNyUm7gNuJ1AFkYqN0S_LnNx_alU5zzoxTkKGMpTLVGzPqVKrhXRuEZwK1duKlAS4YIvq4BzYJm7lMyAafdxEkeqPb1VptQEvJzyIU2xkZMBBlhbxj6qZUEiiKloPzgAs6z1pLYDCpJL6SZ50ozyDM3tqocqY6Qqaxl3Rk0WARC17z7UFIuiOERMfUafvKC5v8aA7Wzr_3BoM91qNI3IyqFl-GEYToDZ4TD922hvNaVpdKciKIJMUUZjNXvXD9xhGWWUqwvHMPkYYJDnC5uRDdlgzgXVIGD0ABPk3a6ULLMw9PxF_RpjQzUkqVfywsUvaUOj0jPx1SVeS3CQdjFcPLwYQuub5H3HzjGUWSFLetktGrbdG_YnW6lFAz-wMzI_BYOSBtwiq9IhrxDL0x2E6PYnU1k5C0-DmYV3yDb_cMNul0KZLq4e0tC6i8YeteAlqCfoWOc3WgWPuqVulBsPGIkbmuRNYOWEpxlseWaX41On_BSskfL7NK02YHHFIZH91njGSDHo_Md0h6Y",
      "roles": "[pay-master-group]",
      "username": "cypherhat"
    },
    "lease_duration": 3600,
    "renewable": true
  }
}

$ vault login 04302161-36af-6e96-54bf-319a8cf1aa73
$ vault read secret/bank/123412341234
Key                 Value
---                 -----
refresh_interval    24h
password            pa49881word

```

### FIN
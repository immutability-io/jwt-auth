#!/usr/bin/env bats

setup() {
  if [ ! -f jwtRS256.key ]; then
    ssh-keygen -t rsa -b 4096 -P "" -f jwtRS256.key
    openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
    echo {\"sub\":\"goober\",\"groups\": [\"test\"]} | jwt -key jwtRS256.key -alg RS256 -sign - > jwt.json
  fi
}

@test "test configure jwt-auth" {
  run vault write auth/jwt-auth/config jwt_signer=@jwtRS256.key.pub ttl=60m max_ttl=300m
    [ "$status" -eq 0 ]
}

@test "test map policies to role" {
  run vault policy write test test.hcl
    [ "$status" -eq 0 ]
  run vault write auth/jwt-auth/map/claims/test value=test
    [ "$status" -eq 0 ]
  run vault write auth/jwt-auth/map/users/goober value=goober
    [ "$status" -eq 0 ]
}


@test "test auth as goober" {
  results=$(vault write -format=json auth/jwt-auth/login token=@jwt.json | jq .auth)
  username=$(echo $results | jq .metadata.username | tr -d '"')
    [ "$username" == "goober" ]
}

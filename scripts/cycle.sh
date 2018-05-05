# !/usr/bash

vault auth disable jwt-auth
vault delete sys/plugins/catalog/jwt-auth
cd ..
go build
mv jwt-auth $HOME/etc/vault.d/vault_plugins
export SHA256=$(shasum -a 256 "$HOME/etc/vault.d/vault_plugins/jwt-auth" | cut -d' ' -f1)
vault write sys/plugins/catalog/jwt-auth \
      sha_256="${SHA256}" \
      command="jwt-auth --ca-cert=$HOME/etc/vault.d/root.crt --client-cert=$HOME/etc/vault.d/vault.crt --client-key=$HOME/etc/vault.d/vault.key"
vault auth enable -path=jwt-auth -plugin-name=jwt-auth -description="JWT authentication plugin" plugin

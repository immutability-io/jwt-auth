#!/bin/bash
function print_help {
    echo "Usage: bash mfa.sh ARGUMENTS"
    echo -e "\nARGUMENTS:"
    echo -e "  [Duo API Hostname]"
    echo -e "  [Duo Integration Key]"
    echo -e "  [Duo Secret Key]"
}

if [ -z "$3" ]; then
    print_help
    exit 0
else
    DUO_API_HOSTNAME=$1
    DUO_INTEGRATION_KEY=$2
    DUO_SECRET_KEY=$3
fi

vault write auth/jwt-auth/mfa_config type=duo
vault write auth/jwt-auth/duo/access \
    host=$DUO_API_HOSTNAME \
    ikey=$DUO_INTEGRATION_KEY \
    skey=$DUO_SECRET_KEY

vault write auth/jwt-auth/duo/config \
    user_agent="" \
    username_format="%s-jwt-auth"

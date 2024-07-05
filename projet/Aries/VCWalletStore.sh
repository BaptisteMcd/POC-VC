#!/bin/bash

# Script to store a SD JWT vc to waltid wallet

# Retrieve the user's Access token
# USER_ACCESS_TOKEN=$(curl -X 'POST'   'https://wallet.walt.id/wallet-api/auth/keycloak/login'   -H 'accept: */*'   -H 'Content-Type: application/json'   -d '{
# 		"type": "keycloak",
# 		"username": "toto",
# 		"password": "toto"
# 		}' | jq -r '.token' )

USER_ACCESS_TOKEN=$(curl -X 'POST' 'https://wallet.walt.id/wallet-api/auth/login' \
		-H 'accept: */*' \
		-H 'Content-Type: application/json' \
		-d '{
		"type": "email",
		"email": "titi@titi.net",
		"password": "titi"
		}' | jq -r '.token' )

echo "User access token : " $USER_ACCESS_TOKEN


# Retrieve the user's Wallet
USER_WALLET=$(curl -X 'GET' \
		'https://wallet.walt.id/wallet-api/wallet/accounts/wallets' \
		-H 'accept: application/json' \
		-H 'Authorization: Bearer '$USER_ACCESS_TOKEN | jq -r '.wallets[0].id' )
echo "User s wallet : $USER_WALLET " 

curl -X 'PUT' \
	     'https://wallet.walt.id/wallet-api/wallet/'$USER_WALLET'/credentials' \
	     -H 'accept: */*' \
	     -H 'Authorization: Bearer '$USER_ACCESS_TOKEN \
	     -d @sd_jwt_example_full

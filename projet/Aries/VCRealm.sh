#!/bin/bash

#Scirpt to create a working Verifiable Credentials Realm on an already running keycloak (inside docker here) with the right feature enabled.


# For now it is only available in an experimentail feature of keycloak but this command will change
# Temporary command is 
# docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:nightly start-dev --log-level=DEBUG --features="oid4vc-vci"


# Master variables
MASTER_USERNAME=admin
MASTER_PASSWORD=admin
REALM_NAME=verifiable-credentials
CLIENT_NAME=oidc-client

# Get the URL of the master token from .well-known endpoint
MASTER_TOKEN_URL=$(curl --location --request GET 'http://localhost:8080/realms/master/.well-known/openid-configuration' | jq -r '.token_endpoint')

#Get the Master Token
MASTER_TOKEN=$(curl --location --request POST "$MASTER_TOKEN_URL" \
	--header 'Content-Type: application/x-www-form-urlencoded' \
	--data-urlencode 'client_id=admin-cli' \
	--data-urlencode 'username='$MASTER_USERNAME \
	--data-urlencode 'password='$MASTER_PASSWORD \
	--data-urlencode 'grant_type=password' | jq -r '.access_token')
	# echo 'MASTER_TOKEN = '$MASTER_TOKEN

# Post the Realm from the already configured file
curl -v  --location --request POST  'http://localhost:8080/admin/realms' -H "Authorization: Bearer "$MASTER_TOKEN -H "Content-Type: application/json" -d @verifiable-credentials-realm.json
#curl -v  --location --request POST  'http://localhost:8080/admin/realms' -H "Authorization: Bearer "$MASTER_TOKEN -H "Content-Type: application/json" -d @realm-export.json

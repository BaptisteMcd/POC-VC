#!/bin/bash

# Script to request a VC from the previously created Verifiable Credential Realm

# Retrieve the user's Access token
USER_ACCESS_TOKEN=$(curl --location --request POST  'http://localhost:8080/realms/verifiable-credentials/protocol/openid-connect/token' -d 'grant_type=password' -d 'username=toto' -d 'password=toto' -d 'client_id=oidc-client' -d 'scope=openid' | jq -r '.access_token')


# Retrieve the VC of a Natural Person form 
#

USER_VC_NP=$(curl --location --request POST  'http://localhost:8080/realms/verifiable-credentials/protocol/oid4vc/credential' --header 'Authorization: Bearer '$USER_ACCESS_TOKEN --header 'Content-Type: application/json' --data '
	{
		"credential_identifier":"natural-person",
		"format":"ldp_vc"
	}
' ) #| jq -r '.credential')

echo "User s credentials in base64: $USER_VC_NP "
echo "User s credentials decoded : $(echo $USER_VC_NP | jq -R 'split(".") | .[0],.[1],.[0] | @base64d | fromjson')"

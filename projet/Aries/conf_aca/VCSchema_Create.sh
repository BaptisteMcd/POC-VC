#!/bin/bash
# Post a Schema to accept a credential
# Ledger needs to be available

curl -X 'POST' \
  'http://127.0.0.1:9100/schemas' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "attributes": [
    "roles",
"email"
  ],
  "schema_name": "NP_cred",
  "schema_version": "1.0"
}'

# Envoie la définition du crédential
#curl -X 'POST' \
#  'http://127.0.0.1:9100/credential-definitions' \
#  -H 'accept: application/json' \
#  -H 'Content-Type: application/json' \
#  -d '{
#  "schema_id": "PLEVLDPJQMJvPLyX3LgB6S:2:NP_cred:1.0",
#  "support_revocation": false,
#  "tag": "default"
#}'

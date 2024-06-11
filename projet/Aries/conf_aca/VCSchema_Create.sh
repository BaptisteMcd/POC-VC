#!/bin/bash
# Post a Schema to accept a credential
# Ledger needs to be available

curl -X POST http://127.0.0.1:8031/schemas \
  -H 'Content-Type: application/json' \
  -d '{
    "attributes": [
      "roles",
      "email"
    ],
    "schema_name": "NP",
    "schema_version": "1.0"
}'
> {
  "schema_id": "M6HJ1MQHKr98nuxobuzJJg:2:my-schema:1.0",
  "schema": {
    "ver": "1.0",
    "id": "M6HJ1MQHKr98nuxobuzJJg:2:my-schema:1.0",
    "name": "my-schema",
    "version": "1.0",
    "attrNames": [
      "roles",
      "email"
    ],
    "seqNo": 1006
  }
}


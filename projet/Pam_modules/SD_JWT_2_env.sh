#!/bin/bash

# Check if the token is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <SD_JWT_TOKEN>"
  exit 1
fi

# Input token from the first argument
TOKEN="$1"

# Split the token by '~' to separate the JWT and selective disclosures
IFS='~' read -ra PARTS <<< "$TOKEN"

# JWT part
JWT=${PARTS[0]}

# Split the JWT by '.' to get header, payload, and signature
IFS='.' read -r HEADER PAYLOAD SIGNATURE <<< "$JWT"

# Export JWT parts as environment variables
export JWT_HEADER="$HEADER"
export JWT_PAYLOAD="$PAYLOAD"
export JWT_SIGNATURE="$SIGNATURE"

# Process and export selective disclosures
for i in "${!PARTS[@]}"; do
  if [ $i -gt 0 ]; then
    export "DISCLOSURE_$i"="${PARTS[$i]}"
  fi
done

echo -e "\nDone, have a look at your newly set env variables :"
env | grep -E 'JWT|DISCLOSURE'


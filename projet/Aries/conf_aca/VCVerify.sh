#!/bin/bash


# Script to check against Aries cloud agent if a credential is valid

curl --noproxy "*" -X 'POST' \
	     'http://127.0.0.1:8031/vc/credentials/verify' \
	     -H 'accept: application/json' \
	     -H 'Content-Type: application/json' \
	     -d @VC_example.json

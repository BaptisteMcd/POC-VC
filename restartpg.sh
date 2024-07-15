#!/bin/bash

# Needs to be on ./POC-VC
# Rebuild and rerun pg_client image
docker stop pg_client
docker rm pg_client
docker build -t client_image -f ./installation/VC_Client/Dockerfile .
docker run -it -d --name pg_client client_image

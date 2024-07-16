#!/bin/bash

# Needs to be on ./POC-VC
# Rebuild and rerun pg_client image
docker stop pg_client
docker rm pg_client
docker build -t client_image -f ./installation/VC_Client/Dockerfile .
docker run -it -d --name pg_client client_image
sleep 2
docker exec -it pg_client psql -U postgres -f /docker-entrypoint-initdb.d/init.sql

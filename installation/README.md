# Container install 

Run the Keycloak server container running with a persistant volume, in Server_Keycloak directory :

    docker compose up -d 


Build the preconfigured PostgreSQL client container : 

    docker build --build-arg -t client -f ./installation/Client_PostgreSQL/Dockerfile .

Run the built container :

    docker run -it -d client

Get its ip using inspect and ssh into it using the firstuser.

    ssh firstuser@172.17.0.2

Keycloak passowrd : test 


You are now using Keycloak IDP to connect !

Login in PostgreSQL using your tokens (stored in /tmp/.tokens for now)

    psql


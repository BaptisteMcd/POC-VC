# Installation and configuration of the POC


Before anything, you'll need to create a network.


Run the Keycloak server container running with a persistant volume :

    docker compose up -d 


Build the PostgreSQL client container preconfigured : 

    docker build --build-arg -t client_testing -f ./installation/Client_PostgreSQL/Dockerfile .

Run the build container :

    docker run -it -d client_testing


Get it ip 

docker inspect \
  -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' [container-name]
You can access it now using ssh 
You can access now at PostgreSQL using psql 


Note : Pour se connecter à postgreSQL en local les utilisateurs doievent avoir le droit de se login.
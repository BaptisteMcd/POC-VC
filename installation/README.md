# Container install 

Run the Keycloak server container running with a persistant volume, in Server_Keycloak directory :

    docker compose up -d 

Check the container's IP and edit the Keycloak server's IP in kc_auth.conf if necessary.

Build the preconfigured PostgreSQL client container : 

    docker build -t client_image -f ./installation/Client_PostgreSQL/Dockerfile .

Run the built container :

    docker run -it -d --name pg_client client_image

The only user not connecting to PostgreSQL via an access_token is postgres

# Example

Execute the example init script

    docker exec -it <container_name> psql -U postgres -f /docker-entrypoint-initdb.d/init.sql
Input postgres's password :  postgres for now.


Get its ip using inspect and ssh into it as firstuser.

    ssh firstuser@<container_ip>

You are now using Keycloak IDP to connect !
Keycloak passoword : test 

In this example, we assigned in keycloak, a corresponding PostgresSQL role : admin1.
admin1 own the database admindb1 having a table table1;

firstuser has the role admin1 in Keycloak.
The PAM module automatically creates and assign corresponding users and his roles in PostgresSQL.

Login in PostgreSQL and connect to the admin1's database using your tokens, your access corresponds to your resssource access in your Keycloak Token :

    psql --dbname=admindb1

You can query the databases owned by the role you are member of.

    admindb1=> SELECT * FROM table1 ;
    id | name 
    ----+------
    1 | toto
    2 | titi
    (2 rows)


Please note that users will not inherit their rights from newly created tables, even if they have the role of the owner.
To fix this run the following command (while connected to the right database) after creating a table :

    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin1 ;

You can still temporarly inpersonate admin1 as you have the right role :

    SET ROLE admin1 ;
# Notes pour PostgreSQl

Pas d'auth de base avec un jeton dans PGSQL
Une apparition de jeton exterieur lors de l'utilisation de PostgREST API ([Lien](https://postgrest.org/en/v12/references/auth.html)).
Cette méthode vérifie le claim "role" du jeton et usurpe l'identité de du role.
Reproduisible facilement mais est-ce que cela correspond à ce que l'on le souhaite

Obj module PAM

Vérif token -> 
    authent si token valide
    Vérifier si le role de l'utilisateur (KC et linux existe sur pg) 
    Attribuer les roles de perms si ils ne les possèdent pas déjà

select 'admin' from information_schema.role_table_grants WHERE grantee='firstuser';
chema de vérification si un utilisateur possède le role admin

Donner un role admin à un utilisateur : 

    GRANT admin1 TO firstuser;


Permissions 

    SELECT * FROM pg_roles WHERE rolname='firstuser';


Les roles d'un utilisateur firstuser : 

    SELECT rolname FROM pg_roles WHERE pg_has_role('firstuser',oid,'member');


Connaitre l'utilisateur courant :

    SELECT CURRENT_USER;


Attention : 

Tel que spécifié [ici](https://www.postgresql.org/docs/current/role-membership.html), les attributs : LOGIN, SUPERUSER, CREATEDB et CREATEROLE ne s'héritent pas.
Les utilisteurs héritent justent des BBDs qui appartiennent au role. 

sudo dnf install libpq-devel.x86_64

gcc -fPIC -Wall -shared -o pam_cpgsql.so -Wl,-soname,pam_cpgsql.sqo main_pg.c -lcurl -ljwt
sudo cp pam_cpgsql.so /lib64/security/pam_cpgsql.so


Utilisateur BDD correspond aux utilisateurs Keycloak : (dont dev et password)

SELECT * FROM pg_catalog.pg_user;
## PAM MODULE

Ecriture d'un module PAM (Pluggable Authentication Modules) pour réaliser proprement une authentification, (en c).

### PAM : infos à savoir : 
Regles pour chaque façon de login : /etc/pam.d/<nom>
Chaque application/service s'appuie sur des modules .so

On retrouve les modules dans :
/lib/security ou /lib64/security ou DEB (/lib/x86_64-linux-gnu/security/) : 


Les changemeents sur les fichiers de configurations /etc/pam.d/ ainsi que sur les modules sont effectifs instantannéments.
    - Faire très attention à la configuration et à SELinux en général.

http://www.fifi.org/doc/libpam-doc/html/pam_modules.html




Compilation du fichier : (! ATTENTION PAS DE STACK PROTECTOR !)

    gcc -fPIC -fno-stack-protector -c main.c -lcurl

Ajout biblio : 

    sudo ld -lcurl -x --shared -o /lib64/security/pam_custom.so main.o

<!-- Idée : authent en curl good
curl -X POST -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Content-Length: 134' -H 'Content-Type: application/x-www-form-urlencoded' -H 'User-Agent: python-requests/2.31.0' -d 'client_id=Client-test&client_secret=gf5V17TzXFDFWqnxOjPY4px4dw6KPHNQ&username=firstuser&password=test&grant_type=password&scope=openid' http://172.26.142.2:8080/realms/DevRealm/protocol/openid-connect/token -->


Problème d'une simple utilisatio de PAM : 
Le système vérifie à l'aide de réglès NSS  si l'utilisateur est déjà créé ou non et n'appelle même pas mon module PAM si l'utilisateur n'existe pas dans le système.
Plusieurs solutions s'offrent à nous : 
- Executer un script à l'aide de pam_sscript avant l'execution du module d'authentification afin de créer un utilisateur
- Modifier les règles NSS, là encore 2 solution
  - Se référer à un annuaire tel que LDAP
  - Créer notre module PAM et requêter KC lorsque l'utilisateur n'est pas connu pour le créer


Plan de route PAM : 
- logout


Suite avec les VCs une fois le module crée
Exemple authentification avec un QR code similaire pam google, l'avantage c'est que le module est fait maison.

## NSS MODULE 

Module NSS : 
inspiré pour l'instant du module nss_pool :

Compilation :

    gcc -fPIC -Wall -shared -o libnss_pool.so -Wl,-soname,libnss_pool.sqo libnss_pool.c
    or
    gcc -fPIC -Wall -shared -o libnss_pool.so -Wl,-soname,libnss_pool.so libnss_pool.c

Copie dans /usr/lib64/ avec le nom en .so.2 : shared object 2.

    sudo cp ./libnss_pool.so /usr/lib64/libnss_pool.so.2


Ajouter l'entré qui correspond à la librairie dans /etc/nsswitch.conf 


    passwd:     files pool sss systemd
    shadow:     files pool
    group:      files pool sss systemd

Le changement de nss est effectif après un redémarrage ou une déconnexion session mais le changement d'objet partagé est effectif immédiatent.

TODO : changer le nom pour un truc custom !

Si utilisation d'une distribution RedHat vérifier que authselect ne décide pas de la configuration, auxquel cas :

    authselect opt-out

Dans NSS
Dev le module en soit maintenant qu'il marche : 
Pourquoi pas dev une librairie en C avec quelques fonction histoire d'avoir les requetes sur l'API Rest KC.

Questionnement : 
Où mettre les paramètres d'authenth KC ?
Est-ce que cela vaut la peine de faire une autre github avec les modules KC traditionnels ?


Dev futur ATTENTION à : https://github.com/FIWARE/keycloak-vc-issuer/issues/36
<!-- non -->
<!-- gcc -fPIC -c libnss_pool.c -lcurl
sudo ld -lcurl -x --shared -o /usr/lib64/libnss_pool.so.2 libnss_pool.o -->

problèmes : nss doit être extremement rapide mutex ? Que se passe-t-il ?
https://github.com/donapieppo/libnss-ato
un seul utilisateur type ? et des clones de cet utilisateur
PAM fonctionne toujours en vérifiant username/login
Inconvénient : pas de homme directory pas de session à part 


https://github.com/cinek810/libnss-pool
Un pool d'utilisateurs types ?


Je crois que LDAP est bien pour le nss mais pas pour le pam
http://www.minetti.org/wiki/Linux:Configuration_de_NSS/PAM_pour_une_authentification_via_un_LDAP

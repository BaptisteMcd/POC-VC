# 15/03 - 25/03
* Finir d'installer les environnements :
   * Monter une machine de dev (avec IDE)
   * Pour les 3 machines ( dev + 2 "serveurs") s'assurer la connectivté entre chacun + l'accès à internet
   * Monter sur Serveur "Keycloak" un keycloak 22.x en conteneur.
   * Développer un client keycloak openidconnect en utilisant le framework Flask. (/!\ le logout doit fonctionner).
   * L'application doit dumper le contenu des jetons échangés avec Keycloak :
   *   Id token
   *   access token courrant
   *   user-infos 
 Pour le développement, enrôler un client CONFIDENTIEL dans keycloak et en suivre la documentation.


Travaux futurs:
*  Installer le plugin https://github.com/FIWARE/keycloak-vc-issuer?tab=readme-ov-file
*  Suivre la documentation et y installer également https://github.com/walt-id/waltid-ssikit
Objectif pour le 25 : déterminer de quoi a t on besoin sur le serveur "client" pour agir comment client keycloak en mode "vc". 

# 25/03 - 05/04

## reliquats
  * déchiffrer les jetons (decode b64)
  * debugger le logout
  * mettre la conf du client SFTP dans le projet
  * Démoniser le client flask (systemd) et débarasser du setup.sh (utiliser l'objet app).
  * le client flask et son démon doivent êter allumés par un compte de service dédié (eg: client-flask).

## A faire
  * Lier via un PAM (éventuellement avec la librairie ci-dessous) une session UNIX à une session keycloak => logout quand sortie de la session
  * Installer un PGSQL 14.X et y créer 1 base de donner avec 3 tables (exemple1, exemple2, exemple3).
  * Etudier la liaison entre la session PAM et l'ouverture d'une session PGSQL.
  * Cela fait, etudier si différence entre pgsql containeurisé, et pgsql "bare-metal", si oui l'implémenter
  
## Reproducibilité
  * L'installation de chaque partie de notre environnement doit être réinstallable automatique par dockerfile ET/OU Ansible. (SAUF AUTORISATION PAS DE MODULES SHELL/COMMAND) => ne pas sous estimer la tâche.
  * Pour les conteneurs (eg: pgsql, keycloak, dockerfiles gités).

## Travaux futurs
 * Lier un rôle à des droits postgresql dans keycloak
 * Rendre capable Postgresql de les consommer => créer un rôle admin1 capable d'écrire et lire sur la table exemple1 et uniquement de lire sur les tables 2 et 3.
 *  Installer le plugin https://github.com/FIWARE/keycloak-vc-issuer?tab=readme-ov-file
 *  Suivre la documentation et y installer également https://github.com/walt-id/waltid-ssikit
Objectif pour le 25 : déterminer de quoi a t on besoin sur le serveur "client" pour agir comment client keycloak en mode "vc". 


* https://github.com/Ralnoc/pam-python


* Bonus
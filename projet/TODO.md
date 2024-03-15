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

#ifndef KC_AUTH_H
#define KC_AUTH_H

/** Fonction qui essaie d'authentifier un utilisateur contre le serveur Keycloak
 * @param user le nom de l'utilisateur
 * @param pass le mot de passe de l'utilisateur
 * 
 * @return true si l'authentification est réussie, false sinon
 */
bool authentification_utilisateur(const char *user, const char *pass);

/**
 * Récupère le jeton d'authentification et de rafraichissement du client
 * @param scope char * le scope de l'authentification
 * @param access_token pointeur sur char * : le scope de l'authentification
 * @param id_token pointeur sur char * : le scope de l'authentification
 * @return true si l'authentification est réussie, false sinon
 * Modifie les valeurs des pointeurs access_token et id_token
*/
const bool jeton_client(char *scope, char ** access_token, char ** id_token);

#endif /* KC_AUTH_H */

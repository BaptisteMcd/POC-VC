#ifndef KC_AUTH_H
#define KC_AUTH_H

/** Fonction qui essaie d'authentifier un utilisateur contre le serveur Keycloak
 * @param user le nom de l'utilisateur
 * @param pass le mot de passe de l'utilisateur
 * @param access_token pointeur sur char * : le jeton d'accès
 * @param refresh_token pointeur sur char * : le jeton de rafraîchissement
 * @param id_token pointeur sur char * : le jeton d'identification
 * @return true si l'authentification est réussie, false sinon
 * Modifie les valeurs des pointeurs access_token, refresh_token et id_token qui devront être free après utilisation
 */
bool authentification_utilisateur(const char *user, const char *pass, char **access_token, char **refresh_token, char **id_token);

/**
 * Fonction qui récupère le jeton d'authentification et d'identification du client
 * @param scope char * le scope de l'authentification
 * @param access_token pointeur sur char * : le scope de l'authentification
 * @param id_token pointeur sur char * : le scope de l'authentification
 * @return true si l'authentification est réussie, false sinon
 * Modifie les valeurs des pointeurs access_token et id_token qui devront être free après utilisation
 */
const bool jeton_client(char *scope, char **access_token, char **id_token);

/**
 * Fonction qui vérifie si un utilisateur existe dans le serveur Keycloak
 * @param nom_utilisateur le nom de l'utilisateur recherché
 * @param access_token le jeton d'accès du client administrateur utilisé pour la recherche
 * @return true si l'utilisateur existe, false sinon
 */
const bool verif_existance_utilisateur(const char *nom_utilisateur, const char **access_token);

/**
 * Fonction qui déconnecte un utilisateur du serveur Keycloak
 * @param p_access_token pointeur sur char * : le jeton d'accès de l'utilisateur
 * @param p_id_token pointeur sur char * : le jeton d'identification de l'utilisateur
 * @return true si la déconnexion est réussie, false sinon
 */
const bool deconnection(const char **p_access_token, const char **p_id_token);

/**
 * Fonction to get the public key of the keycloak server
 * @param p_public_key pointer on char * : pubkey variable
 * @return true if succeeded, false otherwise
 * Will modify the values of p_public_key.
 * Public key is written in PEM format.
 */
const bool getpubkey(char **p_public_key);

/**
 * Fonction to validate a JWT token using jwt.h library
 * @param p_token
 * @param p_public_key
 * @param p_ressource_claims pointer on char * representing the ressource claim to check,
 * @return true if token is valid false otherwise
 * @return The claim will be replaced by the value of the claim itself, null if it doesn't exist
 */
const bool validate_token(const char **p_token, const char **p_public_key, char **p_ressource_claims, char *username_in_token);

/**
 * Fonction to parse role claims from an origin
 * @param p_claims
 * @param origin
 * @param p_retVal pointer on the return value, an array of char *. Each string contains a diffrent role
 * @param nretVal pointer on the number of values in the array of char *
 * @return true if succeeded, false otherwise
 * Clean with cleanupArray
 */
const bool parse_role_claims(const char **p_claims, const char *origin, char ***p_retVal, int *nretVal);

void cleanupArray(char **array, int n);
#endif /* KC_AUTH_H */
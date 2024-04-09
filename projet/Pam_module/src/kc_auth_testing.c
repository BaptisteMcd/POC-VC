#include <curl/curl.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "../include/kc_auth.h"
#include "../include/jsmn.h"
#include "../src/logger.c"
#include "../src/kc_auth.c"
#define CONFIG_FILE "../kc_auth.conf" // Don't forget to include define config file

int main()
{

    bool reponse;
    char *access_token;
    char *refresh_token;
    char *id_token;

    FILE *f = fopen(CONFIG_FILE, "r");
    if (f == NULL)
    {
        printf("Erreur lors de l'ouverture du fichier de configuration\n");
        logger("test", "Erreur lors de l'ouverture du fichier de configuration");
        return 1;
    }
    char * ip = read_conf(f, "KEYCLOAK_IP");
    printf("IP : %s\n", ip);
    char * port = read_conf(f, "KEYCLOAK_PORT");
    printf("PORT : %s\n", port);


    reponse = jeton_client("openid", &access_token, &id_token);
    if (reponse)
    {
        printf("Jeton client executé obtenu avec succès\n");
        logger("test", "jeton client obtenu avec succès");
        printf("access_token : %s\n\n", access_token);
        printf("refresh_token : %s\n\n", id_token);
    }
    else
    {
        logger("test", "jeton client non obtenu");
    }

    bool valid = verif_existance_utilisateur("firstuser",(const char **) &access_token);
    if (valid)
    {
        printf("Utilisateur trouvé\n");
        logger("test", "verif user fonctionnelle");
    }
    else
    {
        printf("Utilisateur non trouvé\n");
        logger("test", "verif user non fonctionnelle");
    }
    free(access_token);
    free(id_token);

    bool auth = authentification_utilisateur("firstuser", "test",&access_token, &refresh_token, &id_token);
    if (auth)
    {
        printf("Authentification réussie\n");
        logger("test", "authentification réussie");
    }
    else
    {
        printf("Authentification échouée\n");
        logger("test", "authentification échouée");
    }

    bool deco = deconnection((const char **)&access_token, (const char **) &refresh_token);
    if(deco){
        printf("Déconnexion réussie\n");
        logger("test", "déconnexion réussie");
    }
    else{
        printf("Déconnexion échouée\n");
        logger("test", "déconnexion échouée");
    }
    free(access_token);
    free(id_token);
    free(refresh_token);
    return valid;
}

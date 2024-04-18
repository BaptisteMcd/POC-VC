#include <curl/curl.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "../include/kc_auth.h"
#include "../include/jsmn.h"
#include "../lib/logger.c"
#include "../src/kc_auth.c"
// #include <libpq-dev.h>

// #define CONFIG_FILE "../kc_auth.conf" // Don't forget to include define config file

int main()
{

    bool reponse;
    char *access_token;
    char *refresh_token;
    char *id_token;

    FILE *f = fopen("/etc/kc_auth.conf", "r");
    if (f == NULL)
    {
        printf("Erreur lors de l'ouverture du fichier de configuration\n");
        logger("test", "Erreur lors de l'ouverture du fichier de configuration");
        return 1;
    }
    char *ip = read_conf(f, "KEYCLOAK_IP");
    printf("IP : %s\n", ip);
    char *port = read_conf(f, "KEYCLOAK_PORT");
    printf("PORT : %s\n", port);

    reponse = jeton_client("openid", &access_token, &id_token);
    if (reponse)
    {
        printf("Jeton client executé obtenu avec succès\n");
        logger("test", "jeton client obtenu avec succès");
        // printf("access_token : %s\n\n", access_token);
        // printf("refresh_token : %s\n\n", id_token);
    }
    else
    {
        logger("test", "jeton client non obtenu");
    }

    bool valid = verif_existance_utilisateur("firstuser", (const char **)&access_token);
    // attention aux roles du client
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
    // free(access_token);
    // free(id_token);

    bool auth = authentification_utilisateur("firstuser", "test", &access_token, &refresh_token, &id_token);
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
    printf("tokens before writing them to conf file\n");
    printf("access_token : %s\n", access_token);
    printf("id_token : %s\n", id_token);
    printf("refresh_token : %s\n", refresh_token);

    write_tokens("/tmp/.tokens_test", access_token, id_token, refresh_token);
    bool deco = deconnection((const char **)&access_token, (const char **)&refresh_token);
    if (deco)
    {
        printf("Déconnexion réussie\n");
        logger("test", "déconnexion réussie");
    }
    else
    {
        printf("Déconnexion échouée\n");
        logger("test", "déconnexion échouée");
    }

    char path_tokens[512];
    // sprintf(path_tokens, "/home/%s/.tokens", username);
    sprintf(path_tokens, "/tmp/.tokens_test"); // testing

    // FILE *pConfigFile = fopen(path_tokens, "r");
    FILE *pTokensFile = fopen(path_tokens, "r"); // testing
    if (pTokensFile == NULL)
    {
        printf("Erreur lors de l'ouverture du fichier .tokens\n");
        logger("test", "Erreur lors de l'ouverture du fichier .tokens");
        return 0;
    }
    logger("pam_sm_authenticate pTokensFile", "pTokensFile");
    char *access_token2;
    char *id_token2;
    char *refresh_token2;
    read_tokens("/tmp/.tokens_test", &access_token2, &id_token2, &refresh_token2);
    fclose(pTokensFile);

    printf("token access %s \n", access_token2);
    printf("token id %s \n", id_token2);
    printf("token %s \n", refresh_token2);
    if (access_token2 == NULL || id_token2 == NULL || refresh_token2 == NULL)
    {
        printf("Erreur lors de la lecture des tokens\n");
    }
    printf("Les jetons on été tous lu avec success\n");

    char *pubkey;
    bool success_getting_pk = getpubkey(&pubkey);
    if (success_getting_pk)
    {
        printf("Clé publique récupérée dans le main\n");
        // printf("La clée publique juste là %s \n", pubkey);
    }
    else
    {
        printf("Clé publique non récupérée\n");
        logger("test", "clé publique non récupérée");
    }
    char *claim = "resource_access";
    char *token_user;
    bool succes_token_validation = validate_token((const char **)&access_token2, (const char **)&pubkey, &claim, &token_user);
    if (succes_token_validation)
    {
        printf("Jeton validé avec success\n");
        printf("The token user is %s\n", token_user);
        if (claim != NULL)
        {
            printf("The claim searched %s \n", claim);
            char **list_roles;
            int nroles;
            printf("Parsing roles claims\n");
            bool success_parse = parse_role_claims((const char **)&claim, (const char *)CLIENT_ID, &list_roles, &nroles);
            if (success_parse)
            {
                printf("sucess parsing answers");
                for (int i = 0; i < nroles; i = i + 1)
                {
                    printf("Role n %d: %s\n", i, list_roles[i]);
                }
                cleanupArray(list_roles, nroles);
            }else{
                printf("No corresponding claims found\n");
            }
        }
    }
    else
    {
        printf("Erreur dans la validation du jeton donné");
    }
    free(access_token);
    free(id_token);
    free(refresh_token);
    free(pubkey);
    return valid;
}
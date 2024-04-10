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
#include <jwt.h>

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
    char *ip = read_conf(f, "KEYCLOAK_IP");
    printf("IP : %s\n", ip);
    char *port = read_conf(f, "KEYCLOAK_PORT");
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

    bool valid = verif_existance_utilisateur("firstuser", (const char **)&access_token);
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

    char *pubkey;
    bool success_getting_pk = getpubkey(&pubkey);
    if (success_getting_pk)
    {
        printf("Clé publique récupérée dans le main\n");
        printf("La clée publique juste là %s \n", pubkey);
        asprintf(&pubkey, "%s", pubkey);
        // "-----BEGIN PUBLIC KEY-----\n"+r_json['public_key']+"\n-----END PUBLIC KEY-----"
        // concat begin and end of pubkey to PEM format
        char *begin = "-----BEGIN PUBLIC KEY-----\n";
        char *end = "\n-----END PUBLIC KEY-----";
        char *tmp = malloc(strlen(pubkey) + strlen(begin) + strlen(end) + 1);
        strcpy(tmp, begin);
        strcat(tmp, pubkey);
        strcat(tmp, end);
        free(pubkey);
        pubkey = tmp;
        
    }
    else
    {
        printf("Clé publique non récupérée\n");
        logger("test", "clé publique non récupérée");
    }

    printf("\n\n");
    int exit_status = 0;
    // Validate access_token
    jwt_t *jwt = NULL;
    jwt_alg_t opt_alg = JWT_ALG_RS256;
    jwt_valid_t *jwt_valid;
    int ret = 0;

    /* Setup validation */
    ret = jwt_valid_new(&jwt_valid, opt_alg);
    if (ret != 0 || jwt_valid == NULL)
    {
        fprintf(stderr, "failed to allocate jwt_valid\n");
        goto finish_valid;
    }

    jwt_valid_set_headers(jwt_valid, 1);
    jwt_valid_set_now(jwt_valid, time(NULL));

    /* Decode access_token */
    ret = jwt_decode(&jwt, access_token, pubkey, strlen(pubkey));
    if (ret != 0 || jwt == NULL)
    {
        fprintf(stderr, "invalid access_token\n");
        exit_status = 1;
        goto finish;
    }

    fprintf(stderr, "access_token decoded successfully!\n");

    if (jwt_validate(jwt, jwt_valid) != 0)
    {
        jwt_dump_fp(jwt, stderr, 1);
        exit_status = 1;
        goto finish;
    }

    fprintf(stderr, "access_token is authentic! sub: %s\n", jwt_get_grant(jwt, "sub"));
    printf("access_token is authentic! sub: %s\n", jwt_get_grant(jwt, "sub"));
    jwt_dump_fp(jwt, stdout, 1);

finish:
    jwt_free(jwt);
finish_valid:
    jwt_valid_free(jwt_valid);

    free(pubkey);
    free(access_token);
    free(id_token);
    free(refresh_token);
    return valid;
}
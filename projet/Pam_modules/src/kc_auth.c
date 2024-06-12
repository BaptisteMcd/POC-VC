#define _GNU_SOURCE
#include <curl/curl.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "../include/logger.h"
#include "../include/kc_auth.h"
#include "../include/jsmn.h"
// #include "kc_auth.h"
#define CONFIG_FILE "/etc/kc_auth.conf"
#include "../lib/jansson.h"
#include "../lib/jwt.h"
#include <libpq-fe.h>

// config
static char *KEYCLOAK_IP;
static char *KEYCLOAK_PORT;
static char *REALM_NAME;
static char *CLIENT_ID;
static char *CLIENT_SECRET;

struct MemoryStruct
{
    char *memory;
    size_t size;
};

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0)
    {
        return 0;
    }
    return -1;
}

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr)
    {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

__attribute__((constructor)) void init(void)
{
    logger("kc_auth", "init");
    FILE *pConfigFile = fopen(CONFIG_FILE, "r");
    if (pConfigFile == NULL)
    {
        printf("Erreur lors de l'ouverture du fichier de configuration kc_auth\n");
        logger("test", "Erreur lors de l'ouverture du fichier de configuration kc_auth");
        return;
    }
    KEYCLOAK_IP = read_conf(pConfigFile, "KEYCLOAK_IP");
    KEYCLOAK_PORT = read_conf(pConfigFile, "KEYCLOAK_PORT");
    REALM_NAME = read_conf(pConfigFile, "REALM_NAME");
    CLIENT_ID = read_conf(pConfigFile, "CLIENT_ID");
    CLIENT_SECRET = read_conf(pConfigFile, "CLIENT_SECRET");
    fclose(pConfigFile);
    return;
}
__attribute__((destructor)) void fini(void)
{
    logger("kc_auth", "fini");
    free(KEYCLOAK_IP);
    free(KEYCLOAK_PORT);
    free(REALM_NAME);
    free(CLIENT_ID);
    return;
}

char *read_conf(FILE *file, char const *desired_name)
{
    char name[128];
    char val[128];
    while (fscanf(file, "%127[^=]=%127[^\n]%*[\n]", name, val) == 2)
    {
        if (strcmp(name, desired_name) == 0)
        {
            return strdup(val);
        }
    }
    if (feof(file))
    {
        fprintf(stderr, "Error: Token '%s' not found in configuration file.\n", desired_name);
        logger("read_conf", "Token not found in configuration file");
    }
    else if (ferror(file))
    {
        perror("Error reading configuration file");
        logger("read_conf", "Error reading configuration file");
    }
    logger("read_conf", "Error reading configuration file (unknown error)");
    return NULL;
}

const bool write_tokens(const char *filename, const char *access_token, const char *refresh_token, const char *id_token)
{
    // Open the file in write mode, which will delete all existing content
    FILE *file;
    file = fopen(filename, "w");
    if (file == NULL)
    {
        printf("Error opening file for writing\n");
        logger("write_tokens", "Error opening file for writing");
        return false;
    }
    fprintf(file, "access_token=%s\n", access_token);
    fprintf(file, "refresh_token=%s\n", refresh_token);
    fprintf(file, "id_token=%s\n", id_token);

    fclose(file);
    return true;
}

const bool read_tokens(const char *filename, char **access_token, char **refresh_token, char **id_token)
{
    FILE *file;
    file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Error opening file for reading\n");
        logger("read_tokens", "Error opening file for reading");
        return false;
    }

    char name[128];
    char val[2048];
    while (fscanf(file, "%127[^=]=%2047[^\n]%*[\n]", name, val) == 2)
    {
        if (strcmp(name, "access_token") == 0)
        {
            *access_token = strdup(val);
        }
        else if (strcmp(name, "refresh_token") == 0)
        {
            *refresh_token = strdup(val);
        }
        else if (strcmp(name, "id_token") == 0)
        {
            *id_token = strdup(val);
        }
    }
    fclose(file);
    return true;
}

bool authentification_utilisateur(const char *user, const char *pass, char **p_access_token, char **p_refresh_token, char **p_id_token)
{
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();

    struct MemoryStruct chunk;
    chunk.memory = malloc(1); /* grown as needed by the realloc above */
    chunk.size = 0;           /* no data at this point */
    bool success = false;
    if (curl)
    {
        char *url;
        asprintf(&url, "http://%s:%s/realms/%s/protocol/openid-connect/token", KEYCLOAK_IP, KEYCLOAK_PORT, REALM_NAME);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        char *data;
        asprintf(&data, "client_id=%s&client_secret=%s&username=%s&password=%s&grant_type=password&scope=openid", CLIENT_ID, CLIENT_SECRET, user, pass);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        res = curl_easy_perform(curl); // PERFORM REQUEST
        curl_slist_free_all(headers);
        free(data);
        free(url);
    }
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    // printf((int) response_code);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        logger("Authentification utilisateur", "curl_easy_perform() failed");
        return false;
    }
    else
    {
        if (response_code == 200)
        { // Succeeded
            jsmn_parser p;
            jsmntok_t t[128];
            jsmn_init(&p);
            int r = jsmn_parse(&p, chunk.memory, chunk.size, t, sizeof(t) / sizeof(t[0]));
            if (r < 0)
            { // Parsing failed
                printf("Failed to parse JSON performing request for Client token : %d\n", r);
                printf("%s\n", chunk.memory);
                logger("Jeton client", "Failed to parse JSON");
            }
            else
            { // Good parsing
                for (int i = 1; i < r; i++)
                {
                    if (jsoneq(chunk.memory, &t[i], "access_token") == 0)
                    {
                        asprintf(p_access_token, "%.*s", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
                        i += 1;
                    }
                    else if (jsoneq(chunk.memory, &t[i], "id_token") == 0)
                    {
                        asprintf(p_id_token, "%.*s", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
                        i += 1;
                    }
                    else if (jsoneq(chunk.memory, &t[i], "refresh_token") == 0)
                    {
                        asprintf(p_refresh_token, "%.*s", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
                        i += 1;
                    }
                }
                logger("Authentification utilisateur", "Succeeded");
                success = true;
            }
        }
        else
        { // Failed
            logger("Authentification utilisateur", "Failed : got wrong response code");
            logger("Authentification utilisateur", chunk.memory);
            printf("Wrong username/password, got response : %ld from server\n", response_code);
        }
    }
    free(chunk.memory);
    return success;
}

const bool jeton_client(char *scope, char **p_access_token, char **p_id_token)
{
    // TODO : Ajouter la gestion des erreurs
    // Déterminer les paramètres vraiment nécessaire

    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1); /* grown as needed by the realloc above */
    chunk.size = 0;           /* no data at this point */
    bool success = false;
    curl = curl_easy_init();
    if (curl)
    {
        char *url;
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        asprintf(&url, "http://%s:%s/realms/%s/protocol/openid-connect/token", KEYCLOAK_IP, KEYCLOAK_PORT, REALM_NAME);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        char *data;
        asprintf(&data, "client_id=%s&client_secret=%s&scope=%s&grant_type=client_credentials", CLIENT_ID, CLIENT_SECRET, scope);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl); // PERFORM REQUEST

        // CLEANUP
        curl_slist_free_all(headers);
        free(url);
        free(data);
    }
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (res != CURLE_OK)
    { // Bad response
        logger("Jeton client", "curl_easy_perform() failed");
    }
    else
    { // Good response
        jsmn_parser p;
        jsmntok_t t[128];
        jsmn_init(&p);
        int r = jsmn_parse(&p, chunk.memory, chunk.size, t, sizeof(t) / sizeof(t[0]));
        if (r < 0)
        { // Parsing failed
            printf("Failed to parse JSON performing request for Client token : %d\n", r);
            printf("%s\n", chunk.memory);
            logger("Jeton client", "Failed to parse JSON");
        }
        else
        { // Good parsing
            for (int i = 1; i < r; i++)
            {
                if (jsoneq(chunk.memory, &t[i], "access_token") == 0)
                {
                    asprintf(p_access_token, "%.*s", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
                    i += 1;
                }
                else if (jsoneq(chunk.memory, &t[i], "id_token") == 0)
                {
                    asprintf(p_id_token, "%.*s", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
                    i += 1;
                }
            }
            logger("Jeton client", "Succeeded");
            success = true;
        }
    }
    free(chunk.memory);
    return success;
}

const bool verif_existance_utilisateur(const char *nom_utilisateur, const char **p_access_token)
{
    CURL *curl;
    CURLcode res;
    char *header_bearer = NULL;
    char *request_url = NULL;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1); /* grown as needed by the realloc above */
    chunk.size = 0;           /* no data at this point */
    bool found = false;
    curl = curl_easy_init();

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        asprintf(&request_url, "http://%s:%s/admin/realms/%s/users?exact=true&username=%s", KEYCLOAK_IP, KEYCLOAK_PORT, REALM_NAME, nom_utilisateur);
        curl_easy_setopt(curl, CURLOPT_URL, request_url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        asprintf(&header_bearer, "authorization: Bearer %s", *p_access_token);
        headers = curl_slist_append(headers, header_bearer);
        headers = curl_slist_append(headers, "content-type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        const char *data = "";
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl); // PERFORM REQUEST

        // CLEANUP
        curl_slist_free_all(headers);
        free(header_bearer);
        free(request_url);
    }
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (res != CURLE_OK)
    { // Bad response
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        printf("Failed to perform request checking user existance, got code : %lu \n", response_code);
        logger("Existance utilisateur", "curl_easy_perform() failed");
        return false;
    }
    else
    { // Good response but it doesn't mean the user is found
        printf("Response code : %lu \n", response_code);
        if (response_code == 200)
        { // Good response, parsing ...
            logger("Existance utilisateur", "Good response");
            char *result_username = NULL;
            jsmn_parser p;
            jsmntok_t t[128]; /* We expect no more than 128 JSON tokens */
            jsmn_init(&p);
            int r = jsmn_parse(&p, chunk.memory, chunk.size, t, sizeof(t) / sizeof(t[0]));

            if (r < 0)
            {
                printf("Failed to parse JSON performing request to check user existance : %d\n", r);
                logger("Existance utilisateur", "Failed to parse JSON");
            }
            else
            { // Parsing JSON
                for (int i = 1; i < r; i++)
                {
                    if (jsoneq(chunk.memory, &t[i], "username") == 0)
                    { // Found username
                        asprintf(&result_username, "%.*s", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
                        i += 1;
                    }
                }

                printf("%lu :", response_code);
                printf("%s\n", chunk.memory);
                if (result_username == NULL)
                { // No username found
                    logger("Existance utilisateur", "user not found");
                }
                if (strcmp(result_username, nom_utilisateur) == 0 && t[0].size == 1)
                { // It's the right and only user
                    found = true;
                    logger("Existance utilisateur", "user found");
                    free(result_username);
                }
            }
        }
    }
    free(chunk.memory);
    return found;
}

const bool deconnection(const char **p_access_token, const char **p_refresh_token)
{
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        char *url;
        asprintf(&url, "http://%s:%s/realms/%s/protocol/openid-connect/logout", KEYCLOAK_IP, KEYCLOAK_PORT, REALM_NAME);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        char *data;
        asprintf(&data, "client_id=%s&client_secret=%s&Authorization=Bearer %s&refresh_token=%s", CLIENT_ID, CLIENT_SECRET, *p_access_token, *p_refresh_token);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        res = curl_easy_perform(curl);

        // Cleanup
        free(data);
        free(url);
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (res != CURLE_OK)
    { // Bad response
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        printf("Failed to perform request to disconnect user got code : %lu \n", response_code);
        logger("Déconnexion", "wrong response");
        return false;
    }
    else
    { // Good response but it doesn't mean the user is found
        if (response_code != 204)
        { // Failed
            printf("Failed to disconnect user got code : %lu \n", response_code);
            logger("Déconnexion", "Failed");
            return false;
        }
        return true;
        logger("Déconnexion", "Succeeded");
    }
}

const bool getpubkey(char **p_public_key)
{
    CURL *curl;
    CURLcode res;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1); /* grown as needed by the realloc above */
    chunk.size = 0;
    bool success = false;
    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        char *url;
        asprintf(&url, "http://%s:%s/realms/%s", KEYCLOAK_IP, KEYCLOAK_PORT, REALM_NAME);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;

        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (res != CURLE_OK)
    { // Bad response
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        printf("Failed to perform request checking user existance, got code : %lu \n", response_code);
        return false;
    }
    else
    { // Good response but it doesn't mean the user is found
        jsmn_parser p;
        jsmntok_t t[128]; /* We expect no more than 128 JSON tokens */
        jsmn_init(&p);
        int r = jsmn_parse(&p, chunk.memory, chunk.size, t, sizeof(t) / sizeof(t[0]));

        if (r < 0)
        {
            printf("Failed to parse JSON performing request to check user existance : %d\n", r);
            logger("Existance utilisateur", "Failed to parse JSON");
        }
        else
        { // Parsing JSON
            for (int i = 1; i < r; i++)
            {
                if (jsoneq(chunk.memory, &t[i], "public_key") == 0)
                { // Found pubkey
                    asprintf(p_public_key, "-----BEGIN PUBLIC KEY-----\n%.*s\n-----END PUBLIC KEY-----", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
                    success = true;
                    break;
                }
            }
        }
    }
    free(chunk.memory);
    return success;
}

const bool validate_token(const char **p_token, const char **p_public_key, char **claim, char **p_username_in_token)
{
    logger("token validation", "start");
    bool success = 0;
    // Validate access_token
    jwt_t *jwt = NULL;
    jwt_alg_t opt_alg = JWT_ALG_RS256;
    jwt_valid_t *jwt_valid;
    int ret = 0;

    /* Setup validation */
    logger("token validation", "entering validation");
    ret = jwt_valid_new(&jwt_valid, opt_alg);
    logger("token validation", "validation set");
    if (ret != 0 || jwt_valid == NULL)
    {
        fprintf(stderr, "failed to allocate jwt_valid\n");
        goto finish_valid;
    }

    jwt_valid_set_headers(jwt_valid, 1);
    jwt_valid_set_now(jwt_valid, time(NULL));
    logger("token validation", "decoding now ...");
    /* Decode access_token */
    ret = jwt_decode(&jwt, *p_token, *p_public_key, strlen(*p_public_key));
    logger("token validation", "decoding done");
    if (ret != 0 || jwt == NULL)
    { // working access and id but not refresh
        logger("token validation", "invalid access_token");
        fprintf(stderr, "invalid access_token\n");
        goto finish;
    }
    logger("token validation", "valid access_token");

    // fprintf(stderr, "access_token decoded successfully!\n");
    logger("token validation", "validating");

    if (jwt_validate(jwt, jwt_valid) != 0)
    {
        jwt_dump_fp(jwt, stderr, 1);
        goto finish;
    }

    logger("token validation", "getting username");
    asprintf(p_username_in_token, "%s", jwt_get_grant(jwt, "preferred_username"));
    // printf("username of the token user %s \n", *p_username_in_token);
    // jwt_dump_fp(jwt, stdout, 1);
    char *jwt_str = jwt_dump_str(jwt, 0);
    printf("%s", jwt_str);
    free(jwt_str);
    success = 1;
    *claim = jwt_get_grants_json(jwt, *claim);
    logger("token validation", "end of validation");
finish:
    jwt_free(jwt);
finish_valid:
    jwt_valid_free(jwt_valid);
    logger("token validation", "end");
    return success;
}

const bool parse_role_claims(const char **p_claims, const char *origin, char ***p_retVal, int *nretVal)
{
    jsmn_parser p;
    jsmntok_t t[64];
    jsmn_init(&p);
    int r = jsmn_parse(&p, *p_claims, strlen(*p_claims), t, sizeof(t) / sizeof(t[0]));
    bool success = false;
    if (r < 0)
    {
        printf("Failed to parse JSON performing request to check user existance : %d\n", r);
        logger("Existance utilisateur", "Failed to parse JSON");
    }
    else
    { // Parsing JSON
        for (int i = 1; i < r; i++)
        {
            if (jsoneq(*p_claims, &t[i], "roles") == 0)
            { // Found Role identifier
                if (t[i + 1].type != JSMN_ARRAY || jsoneq(*p_claims, &t[i - 2], CLIENT_ID) != 0)
                { // wrong place or not the targeted origin
                    printf("Wrong place or not the targeted origin\n");
                    continue;
                }
                printf("Found the right place\n");
                success = true;
                *nretVal = t[i + 1].size;
                *p_retVal = (char **)malloc(sizeof(char *) * (*nretVal)); // Allocate the array of pointers of chars
                for (int j = 0; j < *nretVal; j++)
                {
                    jsmntok_t *g = &t[i + j + 2];
                    printf(" *%.*s\n", g->end - g->start, *p_claims + g->start);
                    // allocate and put in the array of pointer a pointer to the allocated array of char
                    asprintf(&(*p_retVal)[j], "%.*s", g->end - g->start, *p_claims + g->start);
                }
                success = true;
                break; // one and only one source of role at a time
            }
        }
    }
    return success;
}

void cleanupArray(char **array, int n)
{
    for (int i = 0; i < n; i++)
    {
        free(array[i]);
    }
    free(array);
}
void exit_nicely(PGconn *conn)
{
    PQfinish(conn);
    exit(1);
}

bool getUserRoles(PGconn *conn, const char *username, char ***p_retVal, int *nretVal)
{
    PGresult *res;
    char *query;
    asprintf(&query, "SELECT rolname FROM pg_roles WHERE pg_has_role('%s',oid,'member');", username);
    res = PQexec(conn, query);
    free(query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {

        fprintf(stderr, "Select current user failed : %s", PQerrorMessage(conn));
        PQclear(res);
        exit_nicely(conn);
    }

    *nretVal = PQntuples(res);                                // The number of rows
    *p_retVal = (char **)malloc(sizeof(char *) * (*nretVal)); // Allocate the array of pointers of chars
    for (int j = 0; j < *nretVal; j++)
    {
    }
    printf("Number of rows: %d\n", *nretVal);
    // Print all the rows and columns
    for (int i = 0; i < *nretVal; i++)
    {
        printf("%s\t", PQgetvalue(res, i, 0));
        asprintf(&(*p_retVal)[i], "%s", PQgetvalue(res, i, 0));
    }
    PQclear(res);
    return true;
}

bool assignRole2User(PGconn *conn, const char *role, const char *username)
{
    PGresult *res;
    char *query;
    asprintf(&query, "GRANT %s TO %s;", role, username);
    res = PQexec(conn, query);
    free(query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
        fprintf(stderr, "Assign role to user failed : %s", PQerrorMessage(conn));
        PQclear(res);
        exit_nicely(conn);
    }
    PQclear(res);
    return true;
}
// check if role exist in the db, if it exists in DB
bool roleExists(PGconn *conn, const char *role)
{
    PGresult *res;
    char *query;
    asprintf(&query, "SELECT 1 FROM pg_roles WHERE rolname = '%s';", role);
    res = PQexec(conn, query);
    free(query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "Select role failed : %s", PQerrorMessage(conn));
        PQclear(res);
        exit_nicely(conn);
    }
    int rows = PQntuples(res); // The number of rows
    PQclear(res);
    return rows == 1;
}
bool InitSearchPath(PGconn *conn)
{ /* Initialise un search path sûr, pour qu'un utilisateur
malveillant ne puisse prendre le contrôle. */
    PGresult *res;
    res = PQexec(conn, "SELECT pg_catalog.set_config('search_path', '', false)");
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "SET failed: %s", PQerrorMessage(conn));
        PQclear(res);
        exit_nicely(conn);
    }
    PQclear(res);
    return true;
}

void assignAuthorizedRoles(PGconn *conn, const char **rolesDB, const int nrolesDB, const char **rolesKC, const int nrolesKC)
{
    for (int i = 0; i < nrolesKC; i = i + 1)
    {
        printf("Role n %d: %s\n", i, rolesKC[i]);
        // Check if the role is in the list of roles from the DB
        bool found = false;
        for (int j = 0; j < nrolesDB; j = j + 1)
        {
            if (strcmp(rolesKC[i], rolesDB[j]) == 0)
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            printf("    Role %s NOT ASSIGNED in Postgres\n", rolesKC[i]);

            if (roleExists(conn, rolesKC[i]))
            {
                printf("        Role %s EXIST in Postgres .. Assigning role \n", rolesKC[i]);
                assignRole2User(conn, rolesKC[i], "firstuser");
                logger("Role assignation", rolesKC[i]);
            }
            else
            {
                printf("        Role %s DOES NOT EXIST in Postgres .. Not assigning role \n", rolesKC[i]);
            }
        }
        else
        {
            printf("    Role %s ASSIGNED in Postgres\n", rolesKC[i]);
        }
    }
}

bool checkUserDB(PGconn *conn, const char *username)
{
    PGresult *res;
    char *query;
    asprintf(&query, "SELECT 1 FROM pg_roles WHERE rolname = '%s';", username);
    res = PQexec(conn, query);
    free(query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
        fprintf(stderr, "Select role failed : %s", PQerrorMessage(conn));
        PQclear(res);
        exit_nicely(conn);
    }
    int rows = PQntuples(res); // The number of rows
    PQclear(res);
    return 1 == rows;
}
bool createUserDB(PGconn *conn, const char *username)
{
    PGresult *res;
    char *query;
    asprintf(&query, "CREATE ROLE %s LOGIN INHERIT;", username);
    res = PQexec(conn, query);
    free(query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
    {
        fprintf(stderr, "Select role failed : %s", PQerrorMessage(conn));
        PQclear(res);
        exit_nicely(conn);
    }
    PQclear(res);
    return true;
}

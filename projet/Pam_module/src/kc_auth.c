#include <curl/curl.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "../include/logger.h"
#include "../include/kc_auth.h"
#include "../include/jsmn.h"
#define CONFIG_FILE "/etc/kc_auth.conf"

// #include <libconfig.h> ?
//  TODO : AJOUTER UN FICHIER DE CONFIG KC DANS ETC
//  TODO PLUS TARD UTILISER TRUSTSYSTEM REDHAT
//  CHECK ASPRINTF

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

char *read_conf(FILE *file, char const *desired_name)
{
    char name[128];
    char val[128];
    while (fscanf(file, "%127[^=]=%127[^\n]%*c", name, val) == 2)
    {
        if (0 == strcmp(name, desired_name))
        {
            return strdup(val);
        }
    }
    return NULL;
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

bool authentification_utilisateur(const char *user, const char *pass, char **access_token, char **refresh_token)
{
    // TODO : Ajout retour tokens access et refresh si nécessaire
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    FILE *devnull = fopen("/dev/null", "w+");

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
        headers = curl_slist_append(headers, "User-Agent: python-requests/2.31.0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        // char *data;// = "client_id=Client-test&client_secret=gf5V17TzXFDFWqnxOjPY4px4dw6KPHNQ&username=firstuser&password=test&grant_type=password&scope=openid";
        char *data;
        asprintf(&data, "client_id=%s&client_secret=%s&username=%s&password=%s&grant_type=password&scope=openid", CLIENT_ID, CLIENT_SECRET, user, pass);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, devnull);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        // curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        free(data);
        free(url);
    }

    fclose(devnull);
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    // printf((int) response_code);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        return false;
    }
    if (response_code == 200)
    {
        // Succeeded

        return 1;
    }
    else
    {
        printf("Wrong authentification, got response : %ld\n", response_code);
        // Failed
        return 0;
    }
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
        headers = curl_slist_append(headers, "User-Agent: python-requests/2.31.0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        char *data;
        asprintf(&data, "client_id=%s&client_secret=%s&scope=%s&grant_type=client_credentials", CLIENT_ID, CLIENT_SECRET, scope);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        /* send all data to this function  */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

        /* we pass our 'chunk' struct to the callback function */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        free(url);
        free(data);
    }
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(chunk.memory);
        return false;
    }
    else
    {
        jsmn_parser p;
        jsmntok_t t[128];
        jsmn_init(&p);
        int r = jsmn_parse(&p, chunk.memory, chunk.size, t, sizeof(t) / sizeof(t[0]));
        if (r < 0)
        {
            printf("Failed to parse JSON performing request for Client token : %d\n", r);
            printf("%s\n", chunk.memory);
            return false;
        }
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
            i++;
        }
        free(chunk.memory);
        return true;
    }
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
        headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0");
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
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        printf("%lu \n", response_code);
        free(chunk.memory);
        return false;
    }
    else
    { // Good response but it doesn't mean the user is found
        char *result_username = NULL;
        jsmn_parser p;
        jsmntok_t t[128]; /* We expect no more than 128 JSON tokens */
        jsmn_init(&p);
        int r = jsmn_parse(&p, chunk.memory, chunk.size, t, sizeof(t) / sizeof(t[0]));

        if (r < 0)
        {
            printf("Failed to parse JSON performing request to check user existance : %d\n", r);
            return false;
        }
        for (int i = 1; i < r; i++)
        {
            if (jsoneq(chunk.memory, &t[i], "username") == 0)
            {
                printf("Found username\n");
                asprintf(&result_username, "%.*s", t[i + 1].end - t[i + 1].start, chunk.memory + t[i + 1].start);
            }
        }

        printf("%lu :", response_code);
        printf("%s\n", chunk.memory);
        if (result_username == NULL)
        { // No username found
            found = false;
        }
        if (strcmp(result_username, nom_utilisateur) == 0 && t[0].size == 1)
        { // It's the right and only user
            found = true;
            logger("Existance utilisateur", "user found");
        }
        free(result_username);
        free(chunk.memory);
        return found;
    }
}
#include <curl/curl.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
// #include "logger.c"
#include "kc_auth.h"
#include "jsmn.h"

// #include <libconfig.h> ?
//  TODO : AJOUTER UN FICHIER DE CONFIG KC DANS ETC
//  TODO PLUS TARD UTILISER TRUSTSYSTEM REDHAT
//  CHECK ASPRINTF

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

char *read_conf(FILE *file, char const *desired_name) { 
    char name[128];
    char val[128];

    while (fscanf(file, "%127[^=]=%127[^\n]%*c", name, val) == 2) {
        if (0 == strcmp(name, desired_name)) {
            return strdup(val);
        }
    }
    return NULL;
}


bool authentification_utilisateur(const char *user, const char *pass)
{
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    FILE *devnull = fopen("/dev/null", "w+");

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, "http://172.30.6.16:8080/realms/DevRealm/protocol/openid-connect/token");
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
        asprintf(&data, "client_id=Client-test&client_secret=Z717yEXBXJMD490AckHFYSrY7PPSp8ym&username=%s&password=%s&grant_type=password&scope=openid", user, pass);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, devnull);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        // curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        free(data);

    }

    fclose(devnull);
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    // printf((int) response_code);
    printf("%ld :", response_code);
    if (response_code == 200)
    {
        // Succeeded
        return 1;
    }
    else
    {
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
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, "http://172.30.6.16:8080/realms/DevRealm/protocol/openid-connect/token");
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        headers = curl_slist_append(headers, "User-Agent: python-requests/2.31.0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        const char *data = "client_id=Client-test&client_secret=Z717yEXBXJMD490AckHFYSrY7PPSp8ym&scope=openid&grant_type=client_credentials";
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        /* send all data to this function  */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

        /* we pass our 'chunk' struct to the callback function */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    // printf((int) response_code);
    /* check for errors */
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        free(chunk.memory);
        return false;
    }
    else
    {
        /*
         * Now, our chunk.memory points to a memory block that is chunk.size
         * bytes big and contains the remote file.
         *
         * Do something nice with it!
         */
        jsmn_parser p;
        jsmntok_t t[128]; /* We expect no more than 128 JSON tokens */
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
                /* We may use strndup() to fetch string value */
                asprintf(p_access_token, "%.*s", t[i + 1].end - t[i + 1].start,
                         chunk.memory + t[i + 1].start);
            }
            else if (jsoneq(chunk.memory, &t[i], "id_token") == 0)
            {
                /* We may use strndup() to fetch string value */
                asprintf(p_id_token, "%.*s", t[i + 1].end - t[i + 1].start,
                         chunk.memory + t[i + 1].start);
            }
            else
            {
                // printf("Other entry: %.*s\n", t[i + 1].end - t[i + 1].start,
                //        chunk.memory + t[i + 1].start);
            }
            i++;
        }
        // printf("%lu :", response_code);
        // printf("%s\n", chunk.memory);
        // printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
        free(chunk.memory);
        return true;
    }
}

const bool verif_existance_utilisateur(const char *nom_utilisateur, const char **access_token)
{

    CURL *curl;
    CURLcode res;
    char *header_bearer = NULL;
    char *request_url= NULL;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1); /* grown as needed by the realloc above */
    chunk.size = 0;           /* no data at this point */
    bool found  = false;
    curl = curl_easy_init();
    //Setup des headers
    asprintf(&header_bearer, "authorization: Bearer %s", *access_token);
    asprintf(&request_url, "http://172.30.6.16:8080/admin/realms/DevRealm/users?exact=true&username=%s", nom_utilisateur);

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl, CURLOPT_URL, request_url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0");
        headers = curl_slist_append(headers, header_bearer);
        headers = curl_slist_append(headers, "content-type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        const char *data = "";
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    free(header_bearer);
    free(request_url);
    printf(CURLE_OK);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        printf("%lu \n", response_code);
        free(chunk.memory);
        return false;
    }
    else
    {
        char * result_username = NULL;

        // Bon code de réponse mais ça ne signifie pas que l'utilisateur existe !
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
                /* We may use strndup() to fetch string value */
                asprintf(&result_username, "%.*s", t[i + 1].end - t[i + 1].start,
                         chunk.memory + t[i + 1].start);
                
            }
            else
            {
                // printf("Other entry: %.*s\n", t[i + 1].end - t[i + 1].start,
                //        chunk.memory + t[i + 1].start);
            }
            // i++;
        }
        
        printf("%lu :", response_code);
        printf("%s\n", chunk.memory);
        if(result_username == NULL){
            free(chunk.memory);
            return false;
        }
        if(strcmp(result_username, nom_utilisateur) == 0 && t[0].size == 1){
            found = true;
            logger("test", "user found");
        }
        free(result_username); // cas ou mauvais utilisateur
        free(chunk.memory);
        return found;
    }
} 
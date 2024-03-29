#include <curl/curl.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "logger.c"
#include "kc_auth.h"
#include "jsmn.h"

// TODO : AJOUTER UN FICHIER DE CONFIG KC

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

int main()
{

    bool reponse;
    char *access_token;
    char *id_token;

    reponse = jeton_client("openid", &access_token, &id_token);
    if (reponse)
    {
        printf("Jeton client executé avec succès obtenu avec succès\n");
        logger("test", "jeton client obtenu avec succès");
        printf("access_token : %s\n\n", access_token);
        printf("refresh_token : %s\n\n", id_token);
    }
    else
    {
        logger("test", "jeton client non obtenu");
    }

    bool valid = authentification_utilisateur("firstuser", "test");
    if (valid)
    {
        logger("test", "authentification fonctionnelle");
        return 1;
    }
    else
    {
        logger("test", "authentification non fonctionnelle");
        return 0;
    }
}

bool authentification_utilisateur(const char *user, const char *pass)
{

    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    char *response;
    FILE *devnull = fopen("/dev/null", "w+");

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, "http://172.26.142.2:8080/realms/DevRealm/protocol/openid-connect/token");
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
        asprintf(&data, "client_id=Client-test&client_secret=gf5V17TzXFDFWqnxOjPY4px4dw6KPHNQ&username=%s&password=%s&grant_type=password&scope=openid", user, pass);

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, devnull);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        // curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
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

const bool jeton_client(char *scope, char **access_token, char **id_token)
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
        curl_easy_setopt(curl, CURLOPT_URL, "http://172.26.142.2:8080/realms/DevRealm/protocol/openid-connect/token");
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        headers = curl_slist_append(headers, "User-Agent: python-requests/2.31.0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        const char *data = "client_id=Client-test&client_secret=gf5V17TzXFDFWqnxOjPY4px4dw6KPHNQ&scope=openid&grant_type=client_credentials";
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
            printf("Failed to parse JSON: %d\n", r);
            return NULL;
        }
        for (int i = 1; i < r; i++)
        {
            if (jsoneq(chunk.memory, &t[i], "access_token") == 0)
            {
                /* We may use strndup() to fetch string value */
                asprintf(access_token, "%.*s", t[i + 1].end - t[i + 1].start,
                         chunk.memory + t[i + 1].start);
            }
            else if (jsoneq(chunk.memory, &t[i], "id_token") == 0)
            {
                /* We may use strndup() to fetch string value */
                asprintf(id_token, "%.*s", t[i + 1].end - t[i + 1].start,
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
        return true;
    }
}

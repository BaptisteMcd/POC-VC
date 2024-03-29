#include <curl/curl.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include "logger.c"

// only for testing purposes do not use
bool KC_auth(const char *user, const char *pass)
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
    printf("%ld :",response_code);
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

int main()
{
    bool valid = KC_auth("firstuser", "test");
    if (valid)
    {
        logger("test","authentification fonctionnelle");
        printf("authent fonctionnelle");
        return 1;
    }
    else
    {
        logger("test","authentification fonctionnelle");
        printf("non valide");
        return 0;
    }
}
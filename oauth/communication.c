#include "communication.h"
#include <string.h>


#ifdef _WIN32
#include <C:\Users\JustMe\Desktop\curl-7.40.0-devel-mingw32\include\curl\curl.h>
#endif

#ifdef __linux__
#include <curl/curl.h>
#endif

#define PEER_VERIFICATION
#define HOST_VERIFICATION

size_t callback(void *contents, size_t size, size_t nmemb, void *userp) {

    size_t realsize = size * nmemb;
    struct Response *mem = (struct Response *)userp;

    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if(mem->data == NULL) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

cJSON* json_parser(struct Response* res) {

    if(res->size == 0) {
        return NULL;
    }

    cJSON* json = NULL;
    json = cJSON_Parse(res->data);
    return json;
}

struct Response curl_post(const char* url, const char* d_post){

    CURLcode res;
    CURL* curl;

    struct Response response;
    response.data = malloc(1);
    if(response.data == NULL) {
        puts("Error during malloc");
        // čištění
    }
    response.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "Couldn't initialize the CURL\n");
    }

    // set curl to POST (default 0 = GET)
    curl_easy_setopt(curl, CURLOPT_POST, 1);

    // set curls endpoint to https://accounts.google.com/o/oauth2/device/code
    curl_easy_setopt(curl, CURLOPT_URL, url);

#ifdef PEER_VERIFICATION
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 1);
    #ifdef _WIN32
    curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
    #endif
#endif

#ifndef PEER_VERIFICATION
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 0);
#endif

#ifdef PEER_VERIFICATION
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST , 2L);
    #ifdef _WIN32
    curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
    #endif
#endif

#ifndef PEER_VERIFICATION
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST , 0);
#endif

    // set POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, d_post);

    // set function in which we
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);

    // set variable to which we want save data
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    // perform curl call
    res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        free(response.data);
        response.size = 0;
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return response;
}

struct Response curl_header(const char* url, const char* header){

    CURL *curl;
    CURLcode res;

    struct Response response;
    response.data = malloc(1);
    response.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "Couldn't initialize the CURL\n");
    }

    struct curl_slist* list = NULL;

    list = curl_slist_append(list, header);

    // set curls endpoint to
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // set curls header to "Authora"
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

#ifdef PEER_VERIFICATION
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 1);
    #ifdef _WIN32
    curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
    #endif
#endif

#ifndef PEER_VERIFICATION
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 0);
#endif

    // set function in which we
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);

    // set variable to which we want save data
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    // perform curl call
    res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        free(response.data);
        response.size = 0;
    }

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return response;
}

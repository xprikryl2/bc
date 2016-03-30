#include <curl/curl.h>
#include <string.h>
#include <libxml2/libxml/tree.h>
#include <libxml2/libxml/parser.h>

#define PEER_VERIFICATION
#define HOST_VERIFICATION

struct Response {
  char* data;
  size_t size;
};

typedef enum operation{ List, Sign} operation;

size_t callback(void *contents, size_t size, size_t nmemb, void *userp) {

    size_t realsize = size * nmemb;
    struct Response *mem = (struct Response *)userp;

    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if(mem->data == NULL) {
        // cannot alocate memory
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

struct Response curl_post_with_header(const char* url, const char* d_post, const char* header) {

    CURLcode res;
    CURL* curl;

    struct Response response = {0};
    response.data = malloc(1);
    if(response.data == NULL) {
        puts("Error during malloc");
        return response;
    }
    response.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "Couldn't initialize the CURL\n");
    }

    struct curl_slist* list = NULL;
    list = curl_slist_append(list, header);

    // set curls header to "Authora"
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

    // set curls endpoint to https://accounts.google.com/o/oauth2/device/code
    curl_easy_setopt(curl, CURLOPT_URL, url);

    #ifdef PEER_VERIFICATION
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 1);
    #endif

    #ifndef PEER_VERIFICATION
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 0);
    #endif

    #ifdef HOST_VERIFICATION
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST , 1);
    #endif

    #ifndef HOST_VERIFICATION
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST , 0);
    #endif
    if(d_post != NULL) {
        // set curl to POST (default 0 = GET)
        curl_easy_setopt(curl, CURLOPT_POST, 1);

        // set POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, d_post);
    }

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
        response.data = NULL;
        curl_slist_free_all(list);
        return response;
    }

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return response;
}


char* remsig_comm(char* accessToken, operation type) {

    const char* sign = "https://remsig.ics.muni.cz/remsig/sign";
    const char* list = "https://remsig.ics.muni.cz/remsig/listCertificates";
    const char* bearer = "Authorization: Bearer ";
    struct Response res = {0};
    char* header = NULL;

    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));

    strcpy(header, bearer);
    strcat(header, accessToken);
    strcat(header, "\0");

    if(type == List) {
        res = curl_post_with_header(list, NULL, header);
        //parse
    }
    else if(type == Sign) {
        char* data = NULL;
        res = curl_post_with_header(sign, data, header);
    }
    else {
        return NULL;
    }

    return NULL;
}

/*
 * The MIT License
 *
 * Copyright (c) 2016 Institute of Computer Science, Masaryk University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <curl/curl.h>
#endif

#ifdef _WIN32
    #include <winsock2.h>
    #include "curl/include/curl/curl.h"
#endif

#include "loging.c"
#include "communication.h"


/*
 * If you want to connect to a site who isn't using a certificate that is
 * signed by one of the certs in the CA bundle you have, you can skip the
 * verification of the server's certificate. This makes the connection
 * A LOT LESS SECURE. For skiping disable PEER_VERIFICATION
 */
#define PEER_VERIFICATION

/*
 * If the site you're connecting to uses a different host name that what
 * they have mentioned in their server certificate's commonName (or
 * subjectAltName) fields, libcurl will refuse to connect. You can skip
 * this check, but this will make the connection less secure.
 * For skiping disable HOST_VERIFICATION
 */
#define HOST_VERIFICATION

size_t callback(void *contents, size_t size, size_t nmemb, void *userp) {

    // this function can receive more then 1 chunk of the response

    // computes size of the chunk
    size_t realsize = size * nmemb;
    // get handle to the userp structure
    struct Response *mem = (struct Response *)userp;

    // reallocates space, space already used + space needed for new chunk
    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if(mem->data == NULL) {
        makeLog(2, "Error during memory alloc.");
        return 0;
    }

    // adds new chunk to the end of the string
    memcpy(&(mem->data[mem->size]), contents, realsize);
    // modifies to actual new size
    mem->size += realsize;
    // adds '\0' to the end of the string
    mem->data[mem->size] = 0;

    return realsize;
}

cJSON* json_parser(struct Response* res) {

    // checks if the string isn't empty
    if(res->size == 0) {
        return NULL;
    }

    cJSON* json = NULL;
    // parse string to json structure
    json = cJSON_Parse(res->data);
    return json;
}

struct Response curl_post(const char* url, const char* d_post){

    CURLcode res;
    CURL* curl;

    // creates response structure
    struct Response response;
    response.data = malloc(1);
    if(response.data == NULL) {
        makeLog(2, "Error during memory alloc.");
        goto cleanup;
    }
    response.size = 0;

    // initializes curl
    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        makeLog(2, "Couldn't initialize the CURL.");
        goto cleanup;
    }

    // sets curl to POST (default 0 = GET)
    res = curl_easy_setopt(curl, CURLOPT_POST, 1);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // sets curls endpoint
    res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

#ifdef PEER_VERIFICATION
    res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 1);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }
    #ifdef _WIN32
        res = curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
        if(res != CURLE_OK) {
            makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto cleanup;
        }
    #endif
#endif

#ifndef PEER_VERIFICATION
    res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 0);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }
#endif

#ifdef PEER_VERIFICATION
    res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST , 2L);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }
    #ifdef _WIN32
        res = curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
        if(res != CURLE_OK) {
            makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto cleanup;
        }
    #endif
#endif

#ifndef HOST_VERIFICATION
    res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST , 0);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }
#endif

    // sets POST data
    res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, d_post);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // sets function in which we proccess received chunks
    res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // sets variable to which we want save data
    res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // performs curl call
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return response;

    cleanup:
    free(response.data);
    response.size = 0;
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return response;
}

struct Response curl_header(const char* url, const char* header){

    CURL *curl;
    CURLcode res;

    // creates response structure
    struct Response response;
    response.data = malloc(1);
    if(response.data == NULL) {
        makeLog(2, "Error during memory alloc.");
        goto cleanup;
    }
    response.size = 0;

    // initializes curl
    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        makeLog(2, "Couldn't initialize the CURL.");
        goto cleanup;
    }

    struct curl_slist* list = NULL;
    list = curl_slist_append(list, header);

    // sets curls endpoint
    res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // sets curls header
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

#ifdef PEER_VERIFICATION
    res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 1);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }
    #ifdef _WIN32
        res = curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
        if(res != CURLE_OK) {
            makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto cleanup;
        }
    #endif
#endif

#ifndef PEER_VERIFICATION
    res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 0);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }
#endif

    // set function in which we proccess received chunks
    res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // sets variable to which we want save data
    res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // performs curl call
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        makeLog(2, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto cleanup;
    }

    // cleanup
    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return response;

    cleanup:
    free(response.data);
    response.size = 0;
    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return response;
}

void plusToSpace(char* string) {
    // checks if the string is valid
    if(string == NULL) {
        return;
    }
    int i = 0;
    // changes all '+' in string to ' '
    while(string[i] != '\0'){
        if(string[i] == '+') {
            string[i] = ' ';
        }
        i++;
    }
}

char* process(char* state, char* string) {

    char error_m[4096] = "Error: ";
    char* p = NULL;
    char state_get[4096] = "state=";
    char* code = NULL;

    // checks if the string is valid
    if(string == NULL) {
        makeLog(2, "String is not present.");
        return NULL;
    }

    p = strtok(string, "?");
    p = strtok(NULL, "=");

    // parse response parametrs, template ?name1=value1&name2=value2....
    while( p != NULL) {

        if( strcmp(p, "state") == 0) {
            p = strtok(NULL, "  &");
            plusToSpace(p);
            strcat(state_get, p);
            strcat(state_get, "\0");
        }

        else if( strcmp(p, "code") == 0) {
            p = strtok(NULL, "  &");
            code = malloc((strlen(p) + 5 + 1) * sizeof(char));
            strcpy(code, "code=");
            strcat(code, p);
            strcat(code, "\0");
        }

        else if( strcmp(p, "error") == 0) {
            p = strtok(NULL, "  &");
            strcat(error_m, p);
            makeLog(2, error_m);
            return NULL;
        }

        else if( strcmp(p, "error_description") == 0) {
            p = strtok(NULL, "  &");
            strcat(error_m, p);
            makeLog(2, error_m);
            return NULL;
        }

        else if( strcmp(p, "error_uri") == 0) {
            p = strtok(NULL, "  &");
            strcat(error_m, p);
            makeLog(2, error_m);
            return NULL;
        }
        p = strtok(NULL, "=");
    }

    // checks if the authorization code was present
    if(code == NULL) {
        makeLog(2, "Error: Missing code.\n");
        return NULL;
    }

    // checks if the states are identical
    if((state != NULL && state_get == NULL)||(state == NULL && state_get != NULL)) {
        makeLog(2, "Error: Missing state.\n");
        return NULL;
    }

    if(state != NULL && state_get != NULL) {
        if(strcmp(state, state_get) != 0) {
            makeLog(2, "Error: Different states.\n");
            return NULL;
        }
    }

    makeLog(0, "Code extracted.");
    return code;
}

char* server(int port, char* state) {

    #ifdef _WIN32
        WSADATA wsa;
        SOCKET s, new_socket;
        int c;
    #endif

    #ifdef __linux__
        int s, new_socket;
        unsigned int c;
    #endif

    struct sockaddr_in server, client;
    char buffer[20] = {0};
    char* data = NULL;
    char* code = NULL;
    int bytes_read;
    int total = 1;

    //printf("Creating localhost server on port %d.\n", port);
    //printf("---------------------------------------\n");

    #ifdef _WIN32
        // Initialising
        makeLog(0, "Initialising Winsock...");
        if (WSAStartup(MAKEWORD(2,2),&wsa) != 0) {
            makeLog(2, "Failed. Error Code : %d.\n",WSAGetLastError());
            goto error_clenup_0;
        }
        //printf("Initialised.\n");
    #endif


    // Creating a socket
    #ifdef _WIN32
        if((s = socket(AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET) {
            makeLog(2, "Could not create socket : %d.\n" , WSAGetLastError());
            goto error_clenup_1;
        }
    #endif
    #ifdef __linux__
        if((s = socket(AF_INET , SOCK_STREAM , 0 )) < 0) {
            makeLog(2, "Could not create socket.\n");
            goto error_clenup_1;
        }
    #endif
    //printf("Socket created.\n");

    // Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(port);

    // Binding
    #ifdef _WIN32
        if( bind(s ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR) {
            makeLog(2, "Bind failed with error code : %d.\n" , WSAGetLastError());
            goto error_clenup_1;
        }
    #endif
    #ifdef __linux__
        if( bind(s ,(struct sockaddr *)&server , sizeof(server)) < 0) {
            makeLog(2, "Bind failed.\n");
            makeLog(2, "Port already in use.\n");
            goto error_clenup_1;
        }
    #endif
    //puts("Bind done.");

    // Listening to incoming connections
    #ifdef _WIN32
        if(listen(s , 5) == SOCKET_ERROR) {
            makeLog(2, "Listening failed with error code : %d.\n" , WSAGetLastError());
            goto error_clenup_1;
        }
    #endif
    #ifdef __linux__
        if(listen(s , 5) < 0 ) {
            makeLog(2, "Listening failed.\n");
            goto error_clenup_1;
        }
    #endif

    // Accept and incoming connection
    //puts("Waiting for incoming connections...");

    c = sizeof(client);
    new_socket = accept(s , (struct sockaddr *)&client, &c);
    #ifdef _WIN32
        if (new_socket == INVALID_SOCKET) {
            makeLog(2, "Accept failed with error code : %d" , WSAGetLastError());
            goto error_clenup;
        }
    #endif
    #ifdef __linux__
        if (new_socket < 0) {
            makeLog(2, "Accept failed.\n");
            goto error_clenup;
        }
    #endif
    //puts("Connection accepted.");

    // Read data
    data = malloc(sizeof(char));
    if(data == NULL) {
        makeLog(2, "Error during memory alloc. Not enought space.");
        free(data);
        goto error_clenup;
    }
    strcpy(data, "\0");
    do{
        bytes_read = 0;
        bytes_read = recv(new_socket, buffer, sizeof(buffer) - 1, 0);
        strcat(buffer, "\0");
        #ifdef _WIN32
            if(bytes_read == SOCKET_ERROR) {
                makeLog(2, "Receive failed with error code : %d.\n" , WSAGetLastError());
                free(data);
                goto error_clenup;
            }
        #endif
        #ifdef __linux__
            if(bytes_read < 0) {
                makeLog(2, "Receive failed.\n");
                free(data);
                goto error_clenup;
            }
        #endif
        if(bytes_read > 0) {
             total = total + bytes_read + 1;
             data = realloc(data, total * sizeof(char));
             if(data == NULL) {
                 makeLog(2, "Error (re)allocating memory");
                 free(data);
                 goto error_clenup;
             }
             strcat(data, buffer);
        }
    }while (bytes_read >= 19);
    strcat(data, "\0");
    //printf("Read: %d bytes.\n", total);

    // Sending answer
    char* msg = "<html><head><title>Response</title></head><body>You have been successfully logged in. You can return to your application.</body></html>";
    #ifdef _WIN32
        if (send(new_socket, msg, strlen(msg), 0) == SOCKET_ERROR) {
            makeLog(2, "Send failed with error code : %d" , WSAGetLastError());
            free(data);
            goto error_clenup;
        }
    #endif
    #ifdef __linux__
        if (send(new_socket, msg, strlen(msg), 0) < 0) {
            makeLog(2, "Send failed.");
            free(data);
            goto error_clenup;
        }
    #endif

    // Process data
    code = process(state, data);

    if(code == NULL){
        makeLog(2, "Bad response.");
        free(data);
        goto error_clenup;
    }


    // Cleanup sockets
    #ifdef _WIN32
        closesocket(new_socket);
        closesocket(s);
        WSACleanup();
    #endif
    #ifdef __linux__
        close(new_socket);
        close(s);
    #endif

    free(data);
    return code;

    #ifdef _WIN32
        error_clenup_0:
            WSACleanup();
            return NULL;
    #endif

    error_clenup_1:
        #ifdef _WIN32
            closesocket(s);
            WSACleanup();
        #endif
        #ifdef __linux__
            close(s);
        #endif
        return NULL;


    error_clenup:
        #ifdef _WIN32
            closesocket(new_socket);
            closesocket(s);
            WSACleanup();
        #endif
        #ifdef __linux__
            close(new_socket);
            close(s);
        #endif
        return NULL;
}

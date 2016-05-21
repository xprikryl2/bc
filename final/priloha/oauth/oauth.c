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
#include <errno.h>
#include <sys/stat.h>
#include "communication.c"
#include "oauth.h"
#include "config.h"

#ifdef __linux__
    #include <unistd.h>
    #include <sys/types.h>
    #include <pwd.h>
#endif

#ifdef _WIN32
    #include <direct.h>
#endif

void oauth(const char* state) {

    // creates token
    struct OAuth_Object token = {0};

    // initializes token structure
    initialize(&token, state);

    // checks if OAuth was already performed, 1 - no, 0 - yes
    if(getRefreshToken(&token) == 1) {

        // first part of OAuth flow
        if(authorization(&token) == 1) {
            makeLog(2, "Error occurred - authorization!");
            destroy(&token);
            exit(EXIT_FAILURE);
        }

        // second part of OAuth flow
        if(token_request(&token) == 1) {
            makeLog(2, "Error occurred - token request!");
            destroy(&token);
            exit(EXIT_FAILURE);
        }

    }
    else {
        // refreshes token if the OAuth was already performed
        if(refresh_token(&token) == 1) {
            makeLog(2, "Error occurred - refresh token!");
            destroy(&token);
            destroyFile();
            exit(EXIT_FAILURE);
        }
    }

    // saves recent tokens to the file
    makeFile(&token);

    // destroys token structure
    destroy(&token);
}

void initialize(struct OAuth_Object* token, const char* state) {

    // alocates memory and initializes structure
    token->client_id = malloc((strlen(client_id) + 1) * sizeof(char));
    if(token->client_id == NULL) {
        goto cleanup;
    }
    strcpy(token->client_id, client_id);
    strcat(token->client_id, "\0");

    token->client_secret = malloc((strlen(client_secret) + 1) * sizeof(char));
    if(token->client_secret == NULL) {
        goto cleanup;
    }
    strcpy(token->client_secret, client_secret);
    strcat(token->client_secret, "\0");

    if(state != NULL) {
        token->state = malloc(sizeof(char) * (strlen(state) + 7));
        if(token->state == NULL) {
            goto cleanup;
        }
        strcpy(token->state, "state=");
        strcat(token->state, state);
        strcat(token->state, "\0");
    }

    #ifdef redirect
        token->redirect_uri = malloc((strlen(redirect) + 1) * sizeof(char));
        if(token->redirect_uri == NULL) {
            goto cleanup;
        }
        strcpy(token->redirect_uri, redirect);
        strcat(token->redirect_uri, "\0");
    #endif

    #ifdef port_num
        token->port = malloc((strlen(port_num) + 1) * sizeof(char));
        if(token->port == NULL) {
            goto cleanup;
        }
        strcpy(token->port, port_num);
        strcat(token->port, "\0");
    #endif

    #ifdef scopes
        token->scope = malloc((strlen(scopes) + 1) * sizeof(char));
        if(token->scope == NULL) {
            goto cleanup;
        }
        strcpy(token->scope, scopes);
        strcat(token->scope, "\0");
    #endif

    #ifdef login
        token->login_hint = malloc((strlen(login) + 1) * sizeof(char));
        if(token->login_hint == NULL) {
            goto cleanup;
        }
        strcpy(token->login_hint, login);
        strcat(token->login_hint, "\0");
    #endif

    //checks if required parametrs are set
    if(token->client_id == NULL || token->client_secret == NULL) {
        makeLog(2, "Client ID or client secret are not set. Those parameters are requeired.");
        destroy(token);
        exit(EXIT_FAILURE);
    }

    //checks if required parametrs are set
    if(token->redirect_uri == NULL || token->port == NULL) {

        makeLog(2, "Redirect_uri and port are missing. Those parameters are requeired for our flow.");
        destroy(token);
        exit(EXIT_FAILURE);
    }

    makeLog(0, "Initialised.");
    return;

    // error cleanup
    cleanup:

    makeLog(2, "Problem with memory alloc.");
    destroy(token);
    exit(EXIT_FAILURE);
}

void destroy(struct OAuth_Object* token) {

    // frees the structure

    makeLog(0,"Destroying token");

    if(token->client_id != NULL) {
        free(token->client_id);
    }

    if(token->client_secret != NULL) {
        free(token->client_secret);
    }

    if(token->redirect_uri != NULL) {
        free(token->redirect_uri);
    }

    if(token->port != NULL) {
        free(token->port);
    }

    if(token->state != NULL) {
        free(token->state);
    }

    if(token->state_get != NULL) {
        free(token->state_get);
    }

    if(token->authorizationCode != NULL) {
        free(token->authorizationCode);
    }

    if(token->scope != NULL) {
        free(token->scope);
    }

    if(token->login_hint != NULL) {
        free(token->login_hint);
    }

    if(token->accessToken != NULL) {
        free(token->accessToken);
    }

    if(token->refreshToken != NULL) {
        free(token->refreshToken);
    }

    if(token->tokenType != NULL) {
        free(token->tokenType);
    }

    makeLog(0, "Destroyed.\n");
}

void makeFile(struct OAuth_Object *token) {

    char path[120] = {0};
    struct stat st = {0};

    // gets enviroment path /home/[user]/.remsig
    #ifdef __linux__
        struct passwd *pw = getpwuid(getuid());
        const char *homedir = pw->pw_dir;
        strcpy(path, homedir);
        strcat(path, "/.remsig");
    #endif

    // gets enviroment path C:\users\[user]\appdata\roaming\remsig
    #ifdef _WIN32
        strcpy(path, getenv("APPDATA"));
        strcat(path, "\\RemSig");
    #endif

    // checks if folder already exists, if not, creates the folder
    if (stat( path, &st) == -1) {
        #ifdef _WIN32
            _mkdir(path);
        #endif
        #ifdef __linux__
            mkdir(path, 0777);
        #endif
    }

    // name of the file
    #ifdef __linux__
        strcat(path, "/access");
    #endif

    #ifdef _WIN32
        strcat(path, "\\access");
    #endif

    char error_m[1024] = "Cannot make file: ";
    char suc_m[1024] = "Token saved to: ";
    FILE* file = NULL;

    // creates/overwrite file
    file = fopen(path, "w");
    if (file == NULL)
      {
        //printf("%d\n", errno);
        strcat(error_m, path);
        makeLog(2, error_m);
        return;
      }

    // copies access token to the file
    fputs(token->accessToken, file);
    fputs("\n", file);

    // checks if refresh token is supported
    if(token->refreshToken != NULL) {
        // copies refresh token to the file
        fputs(token->refreshToken, file);
        fputs("\n", file);
    }

    // log
    strcat(suc_m, path);
    makeLog(0, suc_m);

    // cleanup
    fclose (file);
}

int getRefreshToken(struct OAuth_Object* token) {

    char path[120] = {0};
    FILE* file = NULL;
    char* buffer = NULL;
    char* p = NULL;
    int length = 0;

    // gets enviroment path C:\users\[user]\appdata\roaming\remsig\access
    #ifdef _WIN32
        strcpy(path, getenv("APPDATA"));
        strcat(path, "\\RemSig");
        strcat(path, "\\access");
    #endif

    // gets enviroment path /home/[user]/.remsig/access
    #ifdef __linux__
        struct passwd *pw = getpwuid(getuid());
        const char *homedir = pw->pw_dir;
        strcpy(path, homedir);
        strcat(path, "/.remsig");
        strcat(path, "/access");
    #endif

    // opens file on location specified above, read-only
    file = fopen(path, "r");
    if (file == NULL)
        return 1;

    // gets file size
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    rewind(file);

    // allocates memory
    buffer = malloc(sizeof(char) * (length + 1));
    if(buffer == NULL) {
        goto error_cleanup;
    }

    // reads first line of the file
    if(fgets(buffer, length, file) == NULL) {
        goto error_cleanup;
    }

    // parses first line, looking for access token
    p = strtok(buffer, "\n");
    if( p == NULL) {
        goto error_cleanup;
    }
    else {
        token->accessToken = malloc(sizeof(char) * (strlen(p) + 1));
        if(token->accessToken == NULL) {
            makeLog(2, "Error during memory alloc.");
            goto error_cleanup;
        }
        strcpy(token->accessToken, p);
        strcat(token->accessToken, "\0");
    }

    // reads second line of the file
    if(fgets(buffer, length, file) == NULL) {
        goto error_cleanup;
    }

    // parses second line, looking for refresh token
    p = strtok(buffer, "\n");
    if( p == NULL) {
        goto error_cleanup;
    }
    else {
        token->refreshToken = malloc(sizeof(char) * (strlen(p) + 1));
        if(token->refreshToken == NULL) {
            makeLog(2, "Error during memory alloc.");
            goto error_cleanup;
        }
        strcpy(token->refreshToken, p);
        strcat(token->refreshToken, "\0");
    }

    //cleanup
    free(buffer);
    fclose (file);
    return 0;

    // error cleanup
    error_cleanup:
    free(buffer);
    fclose(file);
    return 1;
}

void destroyFile() {

    // this function is used, when error occurs
    char path[120] = {0};

    // gets enviroment path C:\users\[user]\appdata\roaming\remsig\access
    #ifdef _WIN32
        strcpy(path, getenv("APPDATA"));
        strcat(path, "\\remsig");
        strcat(path, "\\access");
    #endif

    // gets enviroment path /home/[user]/.remsig/access
    #ifdef __linux__
        struct passwd *pw = getpwuid(getuid());
        const char *homedir = pw->pw_dir;
        strcpy(path, homedir);
        strcat(path, "/.remsig");
        strcat(path, "/access");
    #endif

    // removes file in location above
    if(remove(path) == 0) {
        char suc_m[1024] = "File removed: ";
        strcat(suc_m, path);
        makeLog(0, suc_m);
    }
    else {
        char error_m[1024] = "Cannot remove file: ";
        strcat(error_m, path);
        makeLog(2, error_m);
    }
}

int authorization(struct OAuth_Object* token) {

    const char* response_type = "response_type=code";
    char* parametrs = NULL;
    char* command = NULL;
    char* response = NULL;
    int par_size = 0;

    makeLog(0, "First part - Authentication");

    // computes size which is neeeded for malloc
    par_size +=  strlen(response_type) + strlen(token->client_id) + 2;
    par_size += strlen(token->redirect_uri) + strlen(token->port) + 2;

    // optional size
    if(token->scope != NULL) {
        par_size += strlen(token->scope) + 1;
    }

    // optional size
    if(token->login_hint != NULL) {
        par_size += strlen(token->login_hint) + 1;
    }

    // optional size
    if(token->state != NULL) {
        par_size += strlen(token->state) + 1;
    }

    // Allocating
    parametrs = malloc(par_size * sizeof(char));
    if(parametrs == NULL) {
        makeLog(2, "Error during memory alloc.");
        return 1;
    }
    memset(parametrs, 0, par_size);

    // Required (response type and client id)
    strcpy(parametrs, response_type);
    strcat(parametrs, "&");
    strcat(parametrs, token->client_id);

    // Required: adding redirect_uri and port
    strcat(parametrs, "&");
    strcat(parametrs, token->redirect_uri);
    strcat(parametrs, ":");
    strcat(parametrs, token->port);

    // Optional: adding login_hint
    if(token->login_hint != NULL) {
        strcat(parametrs, "&");
        strcat(parametrs, token->login_hint);
    }

    // Optional: adding scope
    if(token->scope != NULL) {
        strcat(parametrs, "&");
        strcat(parametrs, token->scope);
    }

    // Optional: adding state
    if(token->state != NULL) {
        strcat(parametrs, "&");
        strcat(parametrs, token->state);
    }
    strcat(parametrs, "\0");

    // creates command
    command = malloc(sizeof(char) * (13 + 1 + strlen(google_auth_endpoint) + 1 + strlen(parametrs) + 2));
    if(command == NULL) {
        makeLog(2, "Error during memory alloc. Not enought space.");
        free(parametrs);
        return 1;
    }

    // adding default browser
    #ifdef __linux__
        strcpy(command, "xdg-open ");
    #endif

    #ifdef _WIN32
        strcpy(command, "start \"link\" ");
    #endif

    // copies parametrs to command
    strcat(command, "\"");
    strcat(command, google_auth_endpoint);
    strcat(command, "?");
    strcat(command, parametrs);
    strcat(command, "\"");
    strcat(command, "\0");

    // start user-agent
    system(command);

    // receives response
    response = server(atoi(token->port), token->state);
    if(response == NULL) {
        // cleanup
        free(parametrs);
        free(command);
        return 1;
    }

    // copies authorization code to token structure
    token->authorizationCode = response;

    makeLog(0, "Authentication successful.");

    //cleanup
    free(parametrs);
    free(command);
    return 0;
}

int token_request(struct OAuth_Object* token) {

    char* parametrs = NULL;
    int par_size;
    const char* grant_type = "grant_type=authorization_code";

    makeLog(0, "Second part - TOKEN REQUEST");

    // computes size which is needed for malloc
    par_size = strlen(token->client_id) + 1 + strlen(token->client_secret) + 1 + strlen(token->authorizationCode) + 1;
    par_size += strlen(token->redirect_uri) + 1 + strlen(token->port) + 1 + strlen(grant_type) + 1;

    // allocates memory
    parametrs = malloc(par_size * sizeof(char));
    if(parametrs == NULL) {
        makeLog(2, "Error during memory alloc.");
        return 1;
    }
    memset(parametrs, 0, par_size);

    // sets parametrs needed for request
    strcpy(parametrs,token->client_id);
    strcat(parametrs, "&");
    strcat(parametrs, token->client_secret);
    strcat(parametrs, "&");
    strcat(parametrs, token->authorizationCode);
    strcat(parametrs, "&");
    strcat(parametrs, grant_type);
    strcat(parametrs, "&");
    strcat(parametrs, token->redirect_uri);
    strcat(parametrs, ":");
    strcat(parametrs, token->port);
    strcat(parametrs, "\0");

    // performs requests
    struct Response res = curl_post(google_token_endpoint, parametrs);

    // parses string to json structure
    cJSON* json = json_parser(&res);
    if(json == NULL) {
        res.size = 0;
        free(res.data);
        free(parametrs);
        return 1;
    }

    // looking for access token in json structure
    if(!cJSON_GetObjectItem(json, "access_token")) {
        makeLog(2, "Bad response.");
        goto cleanup;
    }

    // allocates memory for access token and copies access token to token structure
    token->accessToken = malloc(sizeof(char) * (strlen(cJSON_GetObjectItem(json, "access_token")->valuestring) + 1));
    if(token->accessToken == NULL) {
        makeLog(2, "Error during malloc.");
        goto cleanup;
    }
    strcpy(token->accessToken,cJSON_GetObjectItem(json, "access_token")->valuestring);
    strcat(token->accessToken, "\0");

    // looking for token type in json structure
    if(!cJSON_GetObjectItem(json, "token_type")) {
        makeLog(2, "Bad response.");
        goto cleanup;
    }

    // allocates memory for token type and copies it to token structure
    token->tokenType = malloc(sizeof(char) * (strlen(cJSON_GetObjectItem(json, "token_type")->valuestring) + 1));
    if(token->tokenType == NULL) {
        makeLog(2, "Error during malloc.");
        goto cleanup;
    }
    strcpy(token->tokenType, cJSON_GetObjectItem(json, "token_type")->valuestring);
    strcat(token->tokenType, "\0");

    // optional - looking for a new refresh token
    if(cJSON_GetObjectItem(json, "refresh_token")) {

        // allocates memory for refresh token and copies it to token structure
        token->refreshToken = malloc(sizeof(char) * (strlen(cJSON_GetObjectItem(json, "refresh_token")->valuestring) + 1));
        if(token->refreshToken == NULL) {
            makeLog(2, "Error during malloc.");
            goto cleanup;
        }
        strcpy(token->refreshToken, cJSON_GetObjectItem(json, "refresh_token")->valuestring);
        strcat(token->refreshToken,"\0");
    }

    makeLog(0, "Token obtained.");

    // cleanup
    cJSON_Delete(json);
    res.size = 0;
    free(res.data);
    free(parametrs);
    return 0;

    // error cleanup
    cleanup:
    cJSON_Delete(json);
    res.size = 0;
    free(res.data);
    free(parametrs);
    return 1;
}

int refresh_token(struct OAuth_Object* token) {

    char* parametrs = NULL;
    int par_size = 0;
    const char* grant_type = "grant_type=refresh_token";

    makeLog(0, "Optional - REFRESH TOKEN");

    // checks if refresh token is supported
    if(token->refreshToken == NULL) {
        makeLog(0, "Optional - refresh token is not available.");
        return 1;
    }

    // computes size which is needed for malloc
    par_size +=  strlen(token->client_id) + strlen(token->client_secret) + strlen(grant_type) + 3;
    par_size +=  strlen(token->refreshToken) + 15;

    // allocates memory
    parametrs = malloc(par_size * sizeof(char));
    if(parametrs == NULL) {
        makeLog(2, "Error during memory alloc.");
        return 1;
    }
    memset(parametrs, 0, par_size);

    // sets parametrs needed for request
    strcpy(parametrs, token->client_id);
    strcat(parametrs, "&");
    strcat(parametrs, token->client_secret);
    strcat(parametrs, "&");
    strcat(parametrs, "refresh_token=");
    strcat(parametrs, token->refreshToken);
    strcat(parametrs, "&");
    strcat(parametrs, grant_type);
    strcat(parametrs, "\0");

    // performs requests
    struct Response res = curl_post(google_token_endpoint, parametrs);

    // parses string to json structure
    cJSON* json = json_parser(&res);
    if(json == NULL) {
        res.size = 0;
        free(res.data);
        free(parametrs);
        return 1;
    }

    // looking for access token in json structure
    if(!cJSON_GetObjectItem(json, "access_token")) {
        makeLog(2, "Error: Bad response.");
        goto cleanup;
    }

    // allocates memory for access token and copies access token to token structure
    token->accessToken = realloc(token->accessToken, sizeof(char) * (strlen(cJSON_GetObjectItem(json, "access_token")->valuestring) + 1));
    if(token->accessToken == NULL) {
        makeLog(2, "Error during reallocating.");
        goto cleanup;
    }
    strcpy(token->accessToken,cJSON_GetObjectItem(json, "access_token")->valuestring);
    strcat(token->accessToken,"\0");

    // allocates memory for token type and copies it to token structure
    token->tokenType = realloc(token->tokenType, sizeof(char) * (strlen(cJSON_GetObjectItem(json, "token_type")->valuestring) + 1));
    if(token->tokenType == NULL) {
        makeLog(2, "Error during reallocating.");
        goto cleanup;
    }
    strcpy(token->tokenType, cJSON_GetObjectItem(json, "token_type")->valuestring);
    strcat(token->tokenType,"\0");

    // optional - looking for a new refresh token
    if(cJSON_GetObjectItem(json, "refresh_token")) {

        // allocates memory for refresh token and copies it to token structure
        token->refreshToken = realloc(token->refreshToken, sizeof(char) * (strlen(cJSON_GetObjectItem(json, "refresh_token")->valuestring) + 1));
        if(token->refreshToken == NULL) {
            makeLog(2, "Error during reallocating.");
            goto cleanup;
        }
        strcpy(token->refreshToken, cJSON_GetObjectItem(json, "refresh_token")->valuestring);
        strcat(token->refreshToken,"\0");
    }

    makeLog(0, "Refreshing successful.");

    // cleanup
    cJSON_Delete(json);
    res.size = 0;
    free(res.data);
    free(parametrs);
    return 0;

    // error_cleanup
    cleanup:
    cJSON_Delete(json);
    res.size = 0;
    free(res.data);
    free(parametrs);
    return 1;
}

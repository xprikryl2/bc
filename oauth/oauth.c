#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "communication.h"
#include "server.c"
#include "oauth.h"

const char* path = "aaaa.txt";

// Required:
const char* client_id = "client_id=157665463979-a7m5opdjnqfkdvcr7isppbn69afk6acq.apps.googleusercontent.com";
const char* client_secret = "client_secret=4Te40AOGwc8PUUOGMlIjx8jA";
const char* response_type = "response_type=code";
// Required for our flow:
#define redirect "redirect_uri=http://127.0.0.1"
#define port_num "6501"

// Optional:
#define scopes "scope=profile"
#define login "login_hint=prikryl.ond@gmail.com"
// state is given in main

// Endpoints:
const char* google_auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
const char* google_token_endpoint = "https://www.googleapis.com/oauth2/v4/token";
const char* google_data_endpoint = "https://www.googleapis.com/userinfo/v2/me";


void oauth(const char* state) {

    struct OAuth_Object token = {0};

    initialize(&token, state);

    if(token.status == None) {
        if(authorization(&token) == 1) {
            makeLog(2, "Error occurred - authorization!");
            destroy(&token);
            exit(EXIT_FAILURE);
        }

        if(token_request(&token) == 1) {
            makeLog(2, "Error occurred - token request!");
            destroy(&token);
            exit(EXIT_FAILURE);
        }
    }

    // refresh_token call testing
    token.status = Expired;

    if(token.status == Expired) {
        if(refresh_token(&token) == 1) {
            makeLog(2, "Error occurred - refresh token!");
            destroy(&token);
            exit(EXIT_FAILURE);
        }
    }

    makeFile(&token);

    destroy(&token);
}

void initialize(struct OAuth_Object* token, const char* state) {

    token->client_id = malloc((strlen(client_id) + 1) * sizeof(char));
    strcpy(token->client_id, client_id);
    strcat(token->client_id, "\0");

    token->client_secret = malloc((strlen(client_secret) + 1) * sizeof(char));
    strcpy(token->client_secret, client_secret);
    strcat(token->client_secret, "\0");

    token->response_type = malloc((strlen(response_type) + 1) * sizeof(char));
    strcpy(token->response_type, response_type);
    strcat(token->response_type, "\0");

    token->status = None;

    if(state != NULL) {
        token->state = malloc(sizeof(char) * (strlen(state) + 7));
        strcpy(token->state, "state=");
        strcat(token->state, state);
        strcat(token->state, "\0");
    }

    #ifdef redirect
        token->redirect_uri = malloc((strlen(redirect) + 1) * sizeof(char));
        strcpy(token->redirect_uri, redirect);
        strcat(token->redirect_uri, "\0");
    #endif

    #ifdef port_num
        token->port = malloc((strlen(port_num) + 1) * sizeof(char));
        strcpy(token->port, port_num);
        strcat(token->port, "\0");
    #endif

    #ifdef scopes
        token->scope = malloc((strlen(scopes) + 1) * sizeof(char));
        strcpy(token->scope, scopes);
        strcat(token->scope, "\0");
    #endif

    #ifdef login
        token->login_hint = malloc((strlen(login) + 1) * sizeof(char));
        strcpy(token->login_hint, login);
        strcat(token->login_hint, "\0");
    #endif

    if(token->response_type == NULL || token->client_id == NULL || token->client_secret == NULL) {
        makeLog(2, "Client ID, client secret or response type are not all set. Those parameters are requeired.");
        destroy(token);
        exit(EXIT_FAILURE);
    }
    if(token->redirect_uri == NULL || token->port == NULL) {

        makeLog(2, "Redirect_uri and port are missing. Those parameters are requeired for our flow.");
        destroy(token);
        exit(EXIT_FAILURE);
    }

    makeLog(0, "Initialised.");
}

void destroy(struct OAuth_Object* token) {

    makeLog(0,"Destroying token");

    if(token->client_id != NULL) {
        free(token->client_id);
    }

    if(token->client_secret != NULL) {
        free(token->client_secret);
    }

    if(token->response_type != NULL) {
        free(token->response_type);
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

    if(token->data_Link != NULL) {
        free(token->data_Link);
    }

    if(token->data_Name != NULL) {
        free(token->data_Name);
    }

    makeLog(0, "Destroyed.");
}

void makeFile(struct OAuth_Object *token) {

    char error_m[1024] = "Cannot make file at: ";
    FILE* file = NULL;

    file = fopen(path, "w");
    if (file == NULL)
      {
        strcat(error_m, path);
        makeLog(2, error_m);
        return;
      }

    fputs(token->accessToken, file);
    fputs("\n", file);
    fputs(token->refreshToken, file);
    fputs("\n", file);

    fclose (file);
}

int authorization(struct OAuth_Object* token) {

    char* parametrs = NULL;
    char* command = NULL;
    char* response = NULL;
    int par_size = 0;

    makeLog(0, "First part - Authentication");

    par_size +=  strlen(token->response_type) + strlen(token->client_id) + 2;
    par_size += strlen(token->redirect_uri) + strlen(token->port) + 2;

    if(token->scope != NULL) {
        par_size += strlen(token->scope) + 1;
    }

    if(token->login_hint != NULL) {
        par_size += strlen(token->login_hint) + 1;
    }

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
    strcpy(parametrs, token->response_type);
    strcat(parametrs, "&");
    strcat(parametrs, token->client_id);

    // Optional: adding redirect_uri and port
    if(token->redirect_uri != NULL) {
        strcat(parametrs, "&");
        strcat(parametrs, token->redirect_uri);
        if(token->port != NULL) {
            strcat(parametrs, ":");
            strcat(parametrs, token->port);
        }
    }

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


    command = malloc(sizeof(char) * (9 + 1 + strlen(google_auth_endpoint) + 1 + strlen(parametrs) + 2));
    if(command == NULL) {
        makeLog(2, "Error during memory alloc. Not enought space.");
        free(parametrs);
        return 1;
    }
    #ifdef __linux__
        strcpy(command, "xdg-open ");
    #endif

    #ifdef _WIN32
        strcpy(command, "explorer ");
    #endif

    strcat(command, "\"");
    strcat(command, google_auth_endpoint);
    strcat(command, "?");
    strcat(command, parametrs);
    strcat(command, "\"");
    strcat(command, "\0");

    system(command);

    response = server(atoi(token->port), token->state);
    if(response == NULL) {
        free(parametrs);
        free(command);
        return 1;
    }

    token->authorizationCode = response;

    makeLog(0, "Authentication successful.");
    free(parametrs);
    free(command);
    return 0;
}

int token_request(struct OAuth_Object* token) {

    char* parametrs = NULL;
    int par_size = 0;
    const char* grant_type = "grant_type=authorization_code";

    makeLog(0, "Second part - TOKEN REQUEST");

    par_size = strlen(token->client_id) + 1 + strlen(token->client_secret) + 1 + strlen(token->authorizationCode) + 1;
    par_size += strlen(token->redirect_uri) + 1 + strlen(token->port) + 1 + strlen(grant_type) + 1;

    parametrs = malloc(par_size * sizeof(char));
    if(parametrs == NULL) {
        makeLog(2, "Error during memory alloc.");
        return 1;
    }
    memset(parametrs, 0, par_size);

    strcpy(parametrs,token->client_id);
    strcat(parametrs, "&");
    strcat(parametrs, token->client_secret);
    strcat(parametrs, "&");
    strcat(parametrs, token->authorizationCode);
    strcat(parametrs, "&");
    strcat(parametrs, grant_type);

    if(token->redirect_uri != NULL) {
        strcat(parametrs, "&");
        strcat(parametrs, token->redirect_uri);
        if(token->port != NULL) {
            strcat(parametrs, ":");
            strcat(parametrs, token->port);
        }
    }
    strcat(parametrs, "\0");

    struct Response res = curl_post(google_token_endpoint, parametrs);
    cJSON* json = json_parser(&res);
    if(json == NULL) {
        res.size = 0;
        free(res.data);
        free(parametrs);
        return 1;
    }

    if(!cJSON_GetObjectItem(json, "access_token")) {
        makeLog(2, "Bad response.");
        goto cleanup;
    }

    token->accessToken = malloc(sizeof(char) * (strlen(cJSON_GetObjectItem(json, "access_token")->valuestring) + 1));
    if(token->accessToken == NULL) {
        makeLog(2, "Error during malloc.");
        goto cleanup;
    }
    strcpy(token->accessToken,cJSON_GetObjectItem(json, "access_token")->valuestring);
    strcat(token->accessToken, "\0");

    token->refreshToken = malloc(sizeof(char) * (strlen(cJSON_GetObjectItem(json, "refresh_token")->valuestring) + 1));
    if(token->refreshToken == NULL) {
        makeLog(2, "Error during malloc.");
        goto cleanup;
    }
    strcpy(token->refreshToken, cJSON_GetObjectItem(json, "refresh_token")->valuestring);
    strcat(token->refreshToken, "\0");

    token->tokenType = malloc(sizeof(char) * (strlen(cJSON_GetObjectItem(json, "token_type")->valuestring) + 1));
    if(token->tokenType == NULL) {
        makeLog(2, "Error during malloc.");
        goto cleanup;
    }
    strcpy(token->tokenType, cJSON_GetObjectItem(json, "token_type")->valuestring);
    strcat(token->tokenType, "\0");

    token->status = Done;

    cJSON_Delete(json);
    res.size = 0;
    free(res.data);
    free(parametrs);

    makeLog(0, "Token obtained.\n");
    return 0;

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

    par_size +=  strlen(token->client_id) + strlen(token->client_secret) + strlen(grant_type) + 3;
    par_size +=  strlen(token->refreshToken) + 15;

    parametrs = malloc(par_size * sizeof(char));
    if(parametrs == NULL) {
        makeLog(2, "Error during memory alloc.");
        return 1;
    }
    memset(parametrs, 0, par_size);

    strcpy(parametrs, token->client_id);
    strcat(parametrs, "&");
    strcat(parametrs, token->client_secret);
    strcat(parametrs, "&");
    strcat(parametrs, "refresh_token=");
    strcat(parametrs, token->refreshToken);
    strcat(parametrs, "&");
    strcat(parametrs, grant_type);
    strcat(parametrs, "\0");

    struct Response res = curl_post(google_token_endpoint, parametrs);
    cJSON* json = json_parser(&res);

    if(json == NULL) {
        res.size = 0;
        free(res.data);
        free(parametrs);
        return 1;
    }
    if(!cJSON_GetObjectItem(json, "access_token")) {
        makeLog(2, "Error: Bad response.");
        goto cleanup;
    }

    token->accessToken = realloc(token->accessToken, sizeof(char) * (strlen(cJSON_GetObjectItem(json, "access_token")->valuestring) + 1));
    if(token->accessToken == NULL) {
        makeLog(2, "Error during reallocating.");
        goto cleanup;
    }
    strcpy(token->accessToken,cJSON_GetObjectItem(json, "access_token")->valuestring);
    strcat(token->accessToken,"\0");

    token->tokenType = realloc(token->tokenType, sizeof(char) * (strlen(cJSON_GetObjectItem(json, "token_type")->valuestring) + 1));
    if(token->tokenType == NULL) {
        makeLog(2, "Error during reallocating.");
        goto cleanup;
    }
    strcpy(token->tokenType, cJSON_GetObjectItem(json, "token_type")->valuestring);
    strcat(token->tokenType,"\0");

    token->status = Done;

    makeLog(0, "Refreshing successful.\n");

    cJSON_Delete(json);
    res.size = 0;
    free(res.data);
    free(parametrs);
    return 0;

    cleanup:

    cJSON_Delete(json);
    res.size = 0;
    free(res.data);
    free(parametrs);
    return 1;
}

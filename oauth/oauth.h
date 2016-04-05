#ifndef OAUTH_H
#define OAUTH_H

typedef enum A {None, Done, Expired, Error} State;

struct OAuth_Object {
    State status;
    char* client_id;
    char* client_secret;
    char* response_type;
    char* redirect_uri;
    char* port;
    char* scope;
    char* login_hint;
    char* state;
    char* state_get;
    char* authorizationCode;
    char* refreshToken;
    char* accessToken;
    char* tokenType;
    char* data_Name;
    char* data_Link;
};

void oauth(const char* state);

void initialize(struct OAuth_Object* token, const char* state);

void destroy(struct OAuth_Object* token);

int authorization(struct OAuth_Object* token);

int token_request(struct OAuth_Object* token);

int refresh_token(struct OAuth_Object* token);

void makeFile(struct OAuth_Object* token);


#endif // OAUTH_H


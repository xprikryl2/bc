/*
 * The MIT License
 *
 * Copyright (c) 2014 Institute of Computer Science, Masaryk University.
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

#ifndef OAUTH_H
#define OAUTH_H

struct OAuth_Object {
    char* client_id;            // Required - client id credential
    char* client_secret;        // Required - client password credential
    char* redirect_uri;         // Required - client redirect uri - is set to lacalhost
    char* port;                 // Required - client port
    char* scope;                // Optional - Scopes to which client wants permission
    char* login_hint;           // Optional - if supported, this function fills client login credentials
    char* state;                // Optional - original session state
    char* state_get;            // Optional - received session state, must be exactly the same as original
    char* authorizationCode;    // Authorization code received in the first part of the flow
    char* refreshToken;         // Refresh token - OAuth 2.0 refresh token
    char* accessToken;          // Access token - OAuth 2.0 access token
    char* tokenType;            // Must be set to - Bearer
};

/**
 * @brief General function, which performs OAuth 2.0 authorization code grant
 * @param state - session state, this param can be NULL
 */
void oauth(const char* state);

/**
 * @brief Initializes structure
 * @param token - pointer to the token, which should be initialized
 * @param state - session state, this param can be NULL
 */
void initialize(struct OAuth_Object* token, const char* state);

/**
 * @brief Frees structure
 * @param token - pointer to the token, which should be freed
 */
void destroy(struct OAuth_Object* token);

/**
 * @brief First part of the authorization code grant, uses user-agent to redirect user to authentization
 *        endpoint, receives authorization code and saves him to the token structure.
 * @param token - pointer to the token, which obtains flow informations
 * @return returns 0 on sucess, 1 otherwise.
 */
int authorization(struct OAuth_Object* token);

/**
 * @brief Second part of the authorization code grant, uses authorization code to obtain access and refresh tokens.
 * @param token - pointer to the token, which obtains flow information
 * @return returns 0 on sucess, 1 otherwise.
 */
int token_request(struct OAuth_Object* token);

/**
 * @brief This function is called, when the OAuth 2.0 flow was already performed and the access token expired.
 *        It uses refresh token to obtain a new pair of valid access and refresh tokens.
 * @param token - pointer to the token, which obtains flow informations
 * @return returns 0 on sucess, 1 otherwise.
 */
int refresh_token(struct OAuth_Object* token);

/**
 * @brief This function saves access and refresh tokens to the file. If tokens cannot be saved, the whole procedure
 *        have to be repeated.
 * @param token - pointer to the token, which obtains flow informations
 */
void makeFile(struct OAuth_Object* token);

/**
 * @brief This function checks if the OAuth 2.0 flow was already performed
 *        and if access and refresh tokens can be obtained from file
 * @param token - pointer to the token, which obtains flow informations
 * @return returns 0 on sucess, 1 otherwise.
 */
int getRefreshToken(struct OAuth_Object* token);

/**
 * @brief This function destroy file which contains tokens
 */
void destroyFile();

#endif // OAUTH_H


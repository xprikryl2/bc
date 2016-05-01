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

#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include "cJson/cJSON.h"

// curl response structure
struct Response {
  char* data;       // contains data
  size_t size;      // data length
};

/**
 * @brief This callback function gets called by libcurl as soon as there is data received that needs to be saved.
 *        It allocates memory and saves data.
 * @param contents - points to the delivered data
 * @param size - number of members
 * @param nmemb - size of one member
 * @param userp - points to the location, which receive already processed data
 * @return return the number of bytes actually taken care of
 */
size_t callback(void *contents, size_t size, size_t nmemb, void *userp);

/**
 * @brief Performs request to the given url with data, which are send by HTTP POST method, used technologies CURL
 * @param url - string, which represents endpoint url
 * @param d_post - parametrs of the request
 * @return returns response structure which contains data on succes, otherwise is empty
 */
struct Response curl_post(const char* url, const char* d_post);

/**
 * @brief Performs request to the given url with header, which contains access token, used technologies CURL
 * @param url - string, which represents endpoint url
 * @param header - header data, contains access token
 * @returns returns response structure which contains data on succes, otherwise is empty
 */
struct Response curl_header(const char* url, const char* header);

/**
 * @brief This function parse string and creates json object, this object must be freed by function cJSON_Delete
 * @param res - structure, which contains string to be parsed
 * @return returns json object on sucess, NULL otherwise
 */
cJSON* json_parser(struct Response* res);

/**
 * @brief This function replace all chars '+' to ' '
 * @param string - string which should be modified
 */
void plusToSpace(char* string);

/**
 * @brief This function parses authorization code from string, if state was given, the response has to contain identical session state
 * @param state - original session state, recieved session state has to be identical, this param can be NULL
 * @param string - string which should be parsed
 * @return returns string which contains authorization code on succes, NULL otherwise
 */
char* process(char* state, char* string);

/**
 * @brief This function is listening on localhost, on port which we specified, it receives string which contains authorization code
 *        and calls function process to parse the code.
 * @param port - port on which we are listening
 * @param state - original session state which is given to function process, this param can be NULL
 * @return returns string which contains authorization code on succes, NULL otherwise
 */
char* server(int port, char* state);

#endif // COMMUNICATION_H

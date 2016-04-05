#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <stdlib.h>
#include "cJSON.h"


struct Response {
  char* data;
  size_t size;
};

size_t callback(void *contents, size_t size, size_t nmemb, void *userp);

struct Response curl_post(const char* url, const char* d_post);

struct Response curl_header(const char* url, const char* header);

cJSON* json_parser(struct Response* res);

#endif // COMMUNICATION_H

/*
 * Copyright (c) 2010, Masaryk university
 * (Masaryk university, Faculty of informatics, Brno, Czech republic)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the university nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#ifdef __linux__
    #include <curl/curl.h>
    #include <libxml2/libxml/tree.h>
    #include <libxml2/libxml/parser.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <pwd.h>
#endif

#ifdef _WIN32
    #include <libxml/tree.h>
    #include <libxml/parser.h>
    #include "curl/include/curl/curl.h"
#endif

#include "ref/pkcs11u.h"
#include "ref/pkcs11.h"

#define SIMULATE
//#define PEER_VERIFICATION

#define MAX_PIN_LENGTH              32
#define MAX_NUM_SESSIONS            10
#define MAX_NUM_SESSIONS_PER_TOKEN  5
#define MAX_NUM_TOKENS              2

static struct remsig_token {

  int app_error_fatal;
  FILE* logfile;
  int cryptoki_initialized;

  int open_sessions;
  struct session_state {
    CK_SESSION_HANDLE session_handle;

        CK_STATE state_session; //PKCS11 state
        CK_FLAGS flags;
        CK_VOID_PTR application;
        CK_NOTIFY notify;

        CK_SLOT_ID slot;

        int find_init_done;
        CK_ATTRIBUTE_PTR templ;
        int template_count;

        int sign_init_done;

  } sessions[MAX_NUM_SESSIONS];

  int num_tokens;
  struct token_info{
    struct {
    int hardware_slot;
    int login_user;
        int conn_up;
    } flags;

    int sessions_open;
    char *DN;
    char *serial;
    char* issuer;
    char* pin;
    int qualified;
    char* cert;

  } tokens[MAX_NUM_TOKENS];

} remsig_token;

static void
st_logf(const char *fmt, ...)
{
    va_list ap;
    if (remsig_token.logfile == NULL)
    return;
    va_start(ap, fmt);
    vfprintf(remsig_token.logfile, fmt, ap);
    va_end(ap);
    fflush(remsig_token.logfile);
}

static char* getToken() {

    char path[120] = {0};
    FILE* file = NULL;
    char* buffer = NULL;
    char* p = NULL;
    char* output = NULL;
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
    if (file == NULL) return NULL;

    // gets file size
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    rewind(file);

    // allocates memory
    buffer = malloc(sizeof(char) * (length + 1));
    memset(buffer, 0, sizeof(char) * (length + 1));
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
        output = malloc(sizeof(char) * (strlen(p) + 1));
        if(output == NULL) {
            st_logf("Error during memory alloc.\n");
            goto error_cleanup;
        }
        strcpy(output, p);
        strcat(output, "\0");
    }

    //cleanup
    free(buffer);
    fclose (file);
    return output;

    // error cleanup
    error_cleanup:
    free(buffer);
    fclose(file);
    return NULL;
}

CK_BYTE*
toBase64(CK_BYTE* str, int len) {
    BIO *bio = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bufferPtr = NULL;
    CK_BYTE* output = NULL;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, str, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    output = (CK_BYTE*)(*bufferPtr).data;
    return output;
}

CK_BYTE*
decode64(CK_BYTE* input, int len) {
  BIO *b64 = NULL;
  BIO *bio = NULL;

  CK_BYTE *buffer = malloc(len + 1);
  memset(buffer, 0, len);

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(input, len);
  bio = BIO_push(b64, bio);

  BIO_read(bio, buffer, len);

  BIO_free_all(bio);

  return buffer;
}

static void
snprintf_fill(char *str, size_t size, char fillchar, const char *fmt, ...)
{
    int len;
    va_list ap;
    len = vsnprintf(str, size, fmt, ap);
    va_end(ap);
    if (len < 0 || len > size)
    return;
    while(len < size)
    str[len++] = fillchar;
}

/******************************************
 *
 *               Communication
 *
 * ***************************************/

struct Response {
  char* data;
  size_t size;
};

static size_t
callback(void *contents, size_t size, size_t nmemb, void *userp) {

    // this function can receive more then 1 chunk of the response

    // computes size of the chunk
    size_t realsize = size * nmemb;
    // get handle to the userp structure
    struct Response *mem = (struct Response *)userp;

    // reallocates space, space already used + space needed for new chunk
    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if(mem->data == NULL) {
        st_logf("CURL - Error during memory alloc.\n");
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

static struct Response
curl_post_with_header(const char* url, const char* d_post, const char* header) {

    CURLcode res;
    CURL* curl;

    // allocating data memory
    struct Response response = {0};
    response.data = malloc(1);
    if (response.data == NULL) {
        st_logf("Error during malloc.\n");
        return response;
    }

    // initializes curl
    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        st_logf("Couldn't initialize the CURL\n");
        free(response.data);
        response.data = NULL;
        return response;
    }

    // sets authorization header
    struct curl_slist* list = NULL;
    list = curl_slist_append(list, header);

    // sets curls header
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    if(res != CURLE_OK) {
        st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

    // sets curls endpoint
    res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if(res != CURLE_OK) {
        st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

#ifdef PEER_VERIFICATION
    res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 1);
    if(res != CURLE_OK) {
        st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }
    #ifdef _WIN32
        res = curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
        if(res != CURLE_OK) {
            st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto error_cleanup;
        }
    #endif
#endif

#ifndef PEER_VERIFICATION
    res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 0);
    if(res != CURLE_OK) {
        st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }
#endif

    // sets post data if available
    if(d_post != NULL) {

        // sets curl to POST (default 0 = GET)
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        if(res != CURLE_OK) {
            st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto error_cleanup;
        }

        // sets POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, d_post);
        if(res != CURLE_OK) {
            st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto error_cleanup;
        }
    }

    // sets function in which we
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    if(res != CURLE_OK) {
        st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

    // sets variable to which we want save data
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    if(res != CURLE_OK) {
        st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

    // performs curl call
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

    // cleanup
    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return response;

    // error cleanup
    error_cleanup:
    free(response.data);
    response.size = 0;
    response.data = NULL;

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return response;
}

/******************************************
 *
 *      Listing and setting tokens
 *
 * ***************************************/

static void
set_tokens(const char *xml)
{

    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;
    int i = 0;

    st_logf("Setting virtual slots.\n");

    // create xml from string
    doc = xmlReadMemory(xml, strlen(xml), NULL, NULL, 0);
    if (doc == NULL) {
        st_logf("Error during reading xml response.\n");
        return;
    }
    // getting remsig root element
    root_element = xmlDocGetRootElement(doc);

    // setting local tokens
    for (xmlNode *cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
        if ((cur_node->type == XML_ELEMENT_NODE)&&(strcmp((char*)cur_node->name, "certificate") == 0)) {
            if(i == MAX_NUM_TOKENS) {
                st_logf("Error: max number of tokens.\n");
                goto cleanup;
            }
            st_logf("%d. token found.\n", i+1);
            remsig_token.tokens[i].DN = strdup((char*)cur_node->children->children->content);
            remsig_token.tokens[i].issuer = strdup((char*)cur_node->children->next->children->content);
            remsig_token.tokens[i].serial = strdup((char*)cur_node->children->next->next->children->content);
            remsig_token.tokens[i].qualified = atoi((char*)cur_node->children->next->next->next->next->children->content);
            remsig_token.tokens[i].cert = strdup((char*)cur_node->children->next->next->next->next->next->children->content);
            remsig_token.tokens[i].sessions_open = 0;
            remsig_token.tokens[i].flags.conn_up = 1;
            remsig_token.tokens[i].flags.login_user = -1;
            remsig_token.tokens[i].flags.hardware_slot = i;         
            i++;
        }
    }

    if (i == 0) {
        st_logf("Error during loading tokens.\n");
    }

    // number of leaded tokens
    remsig_token.num_tokens = i;

    // cleanup
    cleanup:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();
}

static void
load_tokens()
{

    st_logf("Loading tokens from Remsig.\n");

    #ifdef SIMULATE

        // alternative
        char* xml = "<?xml version=\"1.0\"?><remsig><certificate id=\"1\"><dn>/C=CZ/O=Masaryk University/CN=Jan Novak</dn><issuer>/C=CZ/O=PostSignum QCA</issuer><serialNumber>1234</serialNumber><expiration>12345789</expiration><qualified>0</qualified><certificatePEM>­­­­BEGIN CERTIFICATE­­­­ ...</certificatePEM><chainPEM>­­­­BEGIN CERTIFICATE­­­­ ...</chainPEM></certificate><operationId>1111</operationId></remsig>";
        set_tokens(xml);
        return;

    #endif

    const char* list = "https://remsig.ics.muni.cz/remsig/listCertificates";
    const char* bearer = "Authorization: Bearer ";
    struct Response res = {0};
    char* header = NULL;
    char* accessToken = NULL;

    // get access token from file
    accessToken = getToken();
    if(accessToken == NULL) {
        st_logf("Access Token not found.\n");
        return;
    }

    // set authentization header
    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));
    if(header == NULL) {
        st_logf("Error during memory alloc.\n");
        free(accessToken);
        return;
    }
    strcpy(header, bearer);
    strcat(header, accessToken);
    strcat(header, "\0");

    // perform server request
    res = curl_post_with_header(list, NULL, header);

    if(res.data != NULL && res.size != 0) {
        // parse response and set tokens info
        set_tokens(res.data);
    }

    // cleanup
    free(res.data);
    res.size = 0;
    free(header);
    free(accessToken);
}

/******************************************
 *
 *             Check password
 *
 * ***************************************/

static int
check_password(xmlNode * a_node)
{
    xmlNode *cur_node = NULL;

    for (cur_node = a_node->children; cur_node; cur_node = cur_node->next) {

        if ((cur_node->type == XML_ELEMENT_NODE)&&(strcmp((char*)cur_node->name, "returnType") == 0)) {
            if(strcmp((char*)cur_node->children->content, "OK") == 0) {
                return 1;
            }
            else {
                st_logf("Check_password error: %s.\n", (char*)cur_node->children->content);
                return 0;
            }
        }
    }

    return 0;
}

static int
remsig_checkPassword(unsigned certID, char* password) {

    st_logf("Checking password.\n");

    #ifdef SIMULATE

        // Password is correct
        return 1;

    #endif

    const char* sign = "https://remsig.ics.muni.cz/remsig/checkPassword";
    const char* bearer = "Authorization: Bearer ";
    struct Response res = {0};
    char* header = NULL;
    char* accessToken = NULL;

    xmlNodePtr certificateIdElem;
    xmlNodePtr passwordElem;
    xmlDocPtr doc;
    xmlNodePtr root_node;
    xmlChar *xmlbuff;
    int buffersize;

    xmlDoc *answ = NULL;
    xmlNode *root_element = NULL;

    // get access token from file
    accessToken = getToken();
    if(accessToken == NULL) {
        st_logf("Access Token not found.\n");
        return -1;
    }

    // set authentization header
    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));
    if(header == NULL) {
        st_logf("Error during memory alloc.\n");
        free(accessToken);
        return -1;
    }
    strcpy(header, bearer);
    strcat(header, accessToken);
    strcat(header, "\0");

    // create new xml document
    doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        st_logf("Cannot create xml document.\n");
        free(accessToken);
        free(header);
        return -1;
    }

    // create new remsig root node
    root_node = xmlNewNode(NULL, BAD_CAST "remsig");
    xmlDocSetRootElement(doc, root_node);

    if (root_node == NULL) {
        goto xml_Error;
    }

    // add data to xml
    certificateIdElem = xmlNewChild(root_node, NULL, BAD_CAST "certificateId", BAD_CAST certID);
    if (certificateIdElem == NULL) {
        goto xml_Error;
    }
    passwordElem = xmlNewChild(root_node, NULL, BAD_CAST "password", BAD_CAST password);
    if (passwordElem == NULL) {
        goto xml_Error;
    }

    // dump data to buffer
    xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

    // xml cleanup
    if (doc != NULL)  xmlFreeDoc(doc);
    xmlCleanupParser();

    // perform server request
    res = curl_post_with_header(sign, (char*) xmlbuff, header);

    // checking response size
    if (res.size == 0 || res.data == NULL)
        goto xml_Error;

    // create xml from string
    answ = xmlReadMemory(res.data, res.size, NULL, NULL, 0);
    if (answ == NULL) {
        st_logf("Invalid xml document.\n");
        goto xml_Error;
    }

    // get root element of xml
    root_element = xmlDocGetRootElement(answ);
    if (root_element == NULL) {
        st_logf("Cannot find xml root.\n");
        goto xml_Error;
    }

    // cleanup
    free(accessToken);
    free(header);

    if(check_password(root_element) == 1) {
        // password was correct
        free(res.data);
        res.size = 0;
        if (doc != NULL)  xmlFreeDoc(doc);
        if (answ != NULL)  xmlFreeDoc(doc);
        xmlCleanupParser();
        return 1;
    }
    else {
        // invalid password
        free(res.data);
        res.size = 0;
        if (doc != NULL)  xmlFreeDoc(doc);
        if (answ != NULL)  xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }


    // cleanup
    xml_Error:
    free(accessToken);
    free(header);
    free(res.data);
    res.size = 0;
    if (doc != NULL)  xmlFreeDoc(doc);
    if (answ != NULL)  xmlFreeDoc(doc);
    xmlCleanupParser();
    return -1;
}


/******************************************
 *
 *               Signing
 *
 * ***************************************/

CK_BYTE*
find_signature(xmlNode * a_node)
{
    xmlNode *cur_node = NULL;

    // searching nodes for signature value
    for (cur_node = a_node->children; cur_node; cur_node = cur_node->next) {

        if ((cur_node->type == XML_ELEMENT_NODE)&&(strcmp((char*)cur_node->name, "returnType") == 0)) {
            if(strcmp((char*)cur_node->children->content, "OK") == 0) {
                continue;
            }
            else {
                st_logf("Signature error: %s.\n", (char*)cur_node->children->content);
                return NULL;
            }
        }

        if ((cur_node->type == XML_ELEMENT_NODE)&&(strcmp((char*)cur_node->name, "signature") == 0)) {
            return cur_node->children->content;
        }
    }

    return NULL;
}

CK_BYTE*
xml_sign_parse(char* xml, int size) {

    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;
    CK_BYTE* tmp = NULL;
    CK_BYTE* signature = NULL;

    // checking if the parameters are valid
    if (size == 0 || xml == NULL)
        return NULL;

    // create xml from string
    doc = xmlReadMemory(xml, size, NULL, NULL, 0);
    if (doc == NULL) {
        st_logf("Invalid xml document.\n");
        return NULL;
    }

    // get root element of xml
    root_element = xmlDocGetRootElement(doc);
    if (root_element == NULL) {
        st_logf("Cannot find xml root.\n");
        goto cleanup;
    }

    // looking for signature
    tmp = find_signature(root_element);

    // get signature from xml structure
    signature = malloc((strlen((char*)tmp) + 1) * sizeof(char));
    if (signature == NULL) {
        st_logf("Error during memory alloc.\n");
        goto cleanup;
    }

    strcpy((char*)signature, (char*)tmp);
    strcat((char*)signature, "\0");

    // cleanup
    cleanup:
    tmp = NULL;
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();

    return signature;
}

CK_BYTE*
remsig_sign(unsigned certID, char* password, CK_BYTE* data, unsigned data_len) {

    #ifdef SIMULATE

        return data;

    #endif

    const char* sign = "https://remsig.ics.muni.cz/remsig/sign";
    const char* bearer = "Authorization: Bearer ";
    struct Response res = {0};
    char* header = NULL;
    CK_BYTE* signature = NULL;
    CK_BYTE* decodedSig = NULL;
    char* accessToken = NULL;
    char* qualified = NULL;

    xmlNodePtr certificateIdElem;
    xmlNodePtr timestampElem;
    xmlNodePtr passwordElem;
    xmlNodePtr dataElem;
    xmlDocPtr doc;
    xmlNodePtr root_node;
    xmlChar *xmlbuff;
    int buffersize;

    // checks if the data are valid
    if(data == NULL) {
        return NULL;
    }

    // get access token from file
    accessToken = getToken();
    if(accessToken == NULL) {
        st_logf("Access Token not found.\n");
        return NULL;
    }

    // set authentization header
    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));
    if(header == NULL) {
        st_logf("Error during memory alloc.\n");
        free(accessToken);
        return NULL;
    }

    strcpy(header, bearer);
    strcat(header, accessToken);
    strcat(header, "\0");

    // create new xml document
    doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        st_logf("Cannot create xml document.\n");
        free(accessToken);
        free(header);
        return NULL;
    }

    // set remsig root node
    root_node = xmlNewNode(NULL, BAD_CAST "remsig");
    xmlDocSetRootElement(doc, root_node);

    if (root_node == NULL) {
        goto xml_Error;
    }

    // check certificate status
    if(remsig_token.tokens[certID].qualified == 1) {
        qualified = "QUALIFIED";
    }
    else {
        qualified = "NONQUALIFIED";
    }

    // add data to xml
    certificateIdElem = xmlNewChild(root_node, NULL, BAD_CAST "certificateId", BAD_CAST certID);
    if (certificateIdElem == NULL) {
        goto xml_Error;
    }
    passwordElem = xmlNewChild(root_node, NULL, BAD_CAST "password", BAD_CAST password);
    if (passwordElem == NULL) {
        goto xml_Error;
    }
    timestampElem = xmlNewChild(root_node, NULL, BAD_CAST "timestamp", BAD_CAST qualified);
    if (timestampElem == NULL) {
        goto xml_Error;
    }
    dataElem = xmlNewChild(root_node, NULL, BAD_CAST "data", BAD_CAST toBase64(data, data_len));
    if (dataElem == NULL) {
        goto xml_Error;
    }

    // dump xml to buffer
    xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

    // xml cleanup
    if (doc != NULL)  xmlFreeDoc(doc);
    xmlCleanupParser();

    // perform server request
    res = curl_post_with_header(sign, (char*) xmlbuff, header);

    // parse response, get base64 coded signature
    signature = xml_sign_parse(res.data, res.size);
    if(signature != NULL) {
        // decoding
        decodedSig = decode64(signature, strlen((char*)signature));
    }

    // cleanup
    free(accessToken);
    free(header);
    free(signature);
    free(res.data);
    res.size = 0;

    return decodedSig;

    // error cleanup
    xml_Error:
    free(accessToken);
    free(header);
    if (doc != NULL)  xmlFreeDoc(doc);
    xmlCleanupParser();
    return NULL;
}

/******************************************
 *
 *               PKCS#11
 *
 * ***************************************/

static void
application_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (remsig_token.app_error_fatal)
    abort();
}

static CK_RV
verify_session_handle(CK_SESSION_HANDLE hSession,
              struct session_state **state)
{
    int i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++){
    if (remsig_token.sessions[i].session_handle == hSession)
        break;
    }
    if (i == MAX_NUM_SESSIONS) {
    application_error("use of invalid handle: 0x%08lx\n",
              (unsigned long)hSession);
    return CKR_SESSION_HANDLE_INVALID;
    }
    if (state)
    *state = &remsig_token.sessions[i];
    return CKR_OK;
}

static void
close_session(struct session_state *state)
{
    state->session_handle = CK_INVALID_HANDLE;
    state->application = NULL_PTR;
    state->notify = NULL_PTR;
}

static void
remsig_token_close_session(struct session_state *state)
{
    CK_SLOT_ID slot;

    slot = state->slot;
    close_session(state);
    remsig_token.open_sessions--;
    remsig_token.tokens[(int)slot].sessions_open--;

    if (remsig_token.tokens[(int)slot].sessions_open == 0 && (remsig_token.tokens[(int)slot].flags.login_user == CKU_SO ||
        remsig_token.tokens[(int)slot].flags.login_user == CKU_USER))
    {
      remsig_token.tokens[(int)slot].flags.login_user = -1;
    }
}

static CK_SLOT_ID
get_sess_slot(CK_SESSION_HANDLE hSession)
{
    int i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++){
    if (remsig_token.sessions[i].session_handle == hSession)
        break;
    }
     if (i == MAX_NUM_SESSIONS) {
    application_error("use of invalid handle: 0x%08lx\n",
              (unsigned long)hSession);
    return CKR_SESSION_HANDLE_INVALID;
    }

    return remsig_token.sessions[i].slot;

}



static CK_RV
func_not_supported(void)
{
    // prints not supported function
    st_logf("function not supported\n");
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_Initialize(CK_VOID_PTR a)
{
    CK_C_INITIALIZE_ARGS_PTR args = a;

    int i;
    char path[120] = {0};

    // sets logging
    remsig_token.logfile = NULL;

#if __WIN32
    strcpy(path, getenv("APPDATA"));
    strcat(path, "\\RemSig");
    strcat(path, "\\pkcs11log.txt");
#endif

#ifdef __linux__
    struct passwd *pw = getpwuid(getuid());
    const char *homedir = pw->pw_dir;
    strcpy(path, homedir);
    strcat(path, "/.remsig");
    strcat(path, "/pkcs11log.txt");
#endif

    remsig_token.logfile = fopen(path, "a");
    if(remsig_token.logfile == NULL) {
        return CKR_FUNCTION_FAILED;
    }

    st_logf("Initialize.\n");

    // checks if the module was already initialized
    if (remsig_token.cryptoki_initialized == 1)
    {
      return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    // checks if the Multithreading is off
    if (a != NULL_PTR) {
    st_logf("\tCreateMutex:\t%p\n", args->CreateMutex);
    st_logf("\tDestroyMutext\t%p\n", args->DestroyMutex);
    st_logf("\tLockMutext\t%p\n", args->LockMutex);
    st_logf("\tUnlockMutext\t%p\n", args->UnlockMutex);
    st_logf("\tFlags\t%04x\n", (unsigned int)args->flags);
        st_logf("\tCK_C_INITIALIZE_ARGS are not supported\n");
        return CKR_ARGUMENTS_BAD;
    }

    // sets default values to plugin context
    remsig_token.app_error_fatal = 0;
    remsig_token.cryptoki_initialized = 0;

    remsig_token.open_sessions = 0;
    for(i=0;i<MAX_NUM_SESSIONS;i++) {
      remsig_token.sessions[i].templ = NULL;
      remsig_token.sessions[i].template_count = 0;
      remsig_token.sessions[i].session_handle = CK_INVALID_HANDLE;
      remsig_token.sessions[i].state_session = -1;
      remsig_token.sessions[i].flags = -1;
      remsig_token.sessions[i].application = NULL;
      remsig_token.sessions[i].notify = NULL;
      remsig_token.sessions[i].slot = -1;
    }

    remsig_token.num_tokens = 0;
    for(i=0;i<MAX_NUM_TOKENS;i++) {
      remsig_token.tokens[i].flags.hardware_slot = -1;
      remsig_token.tokens[i].flags.login_user = -1;
      remsig_token.tokens[i].flags.conn_up = 0;

      remsig_token.tokens[i].sessions_open = 0;
      remsig_token.tokens[i].qualified = 0;
      remsig_token.tokens[i].DN = NULL;
      remsig_token.tokens[i].serial = NULL;
      remsig_token.tokens[i].issuer = NULL;
      remsig_token.tokens[i].pin = NULL;
      remsig_token.tokens[i].cert = NULL;
    }

    // load tokens
    load_tokens();

    // sets token info as initialized
    remsig_token.cryptoki_initialized = 1;
    st_logf("Module initialized.\n");
    return CKR_OK;
}

CK_RV
C_Finalize(CK_VOID_PTR args)
{
    int i;
    st_logf("Finalize. \n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (args != NULL )
    {
       st_logf("- pReserved is not NULL\n");
       return CKR_ARGUMENTS_BAD;
    }

    // close log file
    fclose(remsig_token.logfile);

    // cleanup context
    remsig_token.open_sessions = 0;
    for(i=0;i<MAX_NUM_SESSIONS;i++) {
      remsig_token.sessions[i].session_handle = CK_INVALID_HANDLE;
      remsig_token.sessions[i].state_session = -1;
      remsig_token.sessions[i].flags = -1;
      remsig_token.sessions[i].application = NULL;
      remsig_token.sessions[i].notify = NULL;
      remsig_token.sessions[i].slot = -1;
      free(remsig_token.sessions[i].templ);
      remsig_token.sessions[i].templ = NULL;
    }

    remsig_token.num_tokens = 0;
    for(i=0;i<MAX_NUM_TOKENS;i++) {
      remsig_token.tokens[i].flags.hardware_slot = -1;
      remsig_token.tokens[i].flags.login_user = -1;
      remsig_token.tokens[i].flags.conn_up = 0;

      remsig_token.tokens[i].sessions_open = 0;
      free(remsig_token.tokens[i].DN);
      remsig_token.tokens[i].DN = NULL;
      free(remsig_token.tokens[i].serial);
      remsig_token.tokens[i].serial = NULL;
      free(remsig_token.tokens[i].issuer);
      remsig_token.tokens[i].issuer = NULL;
      free(remsig_token.tokens[i].pin);
      remsig_token.tokens[i].pin = NULL;
      free(remsig_token.tokens[i].cert);
      remsig_token.tokens[i].cert = NULL;
    }

    remsig_token.cryptoki_initialized = 0;

    return CKR_OK;
}

CK_RV
C_GetInfo(CK_INFO_PTR args)
{
    st_logf("GetInfo ");

    // checks if the module is already initialized
    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // sets static Cryptoki info
    memset(args, 17, sizeof(*args));
    args->cryptokiVersion.major = 2;
    args->cryptokiVersion.minor = 20;
    snprintf_fill((char *)args->manufacturerID,
                  sizeof(args->manufacturerID),
                  ' ',
                  "OndrejPrikryl");
    snprintf_fill((char *)args->libraryDescription,
                  sizeof(args->libraryDescription),
                  ' ',
                  "RemSigToken");
    args->libraryVersion.major = 1;
    args->libraryVersion.minor = 0;

    st_logf("- OK\n");
    return CKR_OK;
}

// list of supported functions
extern CK_FUNCTION_LIST funcs;

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    *ppFunctionList = &funcs;
    return CKR_OK;
}

CK_RV
C_GetSlotList(CK_BBOOL tokenPresent,
          CK_SLOT_ID_PTR pSlotList,
          CK_ULONG_PTR   pulCount)
{
    // obtains list of slots currently used in module
    int i, idx = 0, conn_tokens = 0;

    // if tokenPresent is true, list cointains only slots, where token is present
    st_logf("GetSlotList: %s\n",
        tokenPresent ? "tokenPresent" : "token not Present");

    if (remsig_token.cryptoki_initialized != 1)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // returns only tokens with opened connection to server
    if(tokenPresent == CK_TRUE)
    {
      for (i=0;i<remsig_token.num_tokens;i++) {
        if(remsig_token.tokens[i].flags.conn_up == 1)
        {
          conn_tokens++;
          // if pSlotList is null, function returns just number of tokens and then is called again with already allocated
          // space in pSlotList
          if (pSlotList)
          {
            pSlotList[idx] = i;
            idx++;
          }
        }
      }

      *pulCount = conn_tokens;
    }
    else
    {
       // prints all slots
       *pulCount = MAX_NUM_TOKENS;
       // if pSlotList is null, function returns just number of tokens and then is called again with already allocated
       // space in pSlotList
       if (pSlotList)
         for(i=0;i<MAX_NUM_TOKENS;i++)
           pSlotList[i] = i;
    }

    return CKR_OK;
}


CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID,
          CK_SLOT_INFO_PTR pInfo)
{
    st_logf("GetSlotInfo: slot: %d - ", (int)slotID);

    if (remsig_token.cryptoki_initialized != 1)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // sets static slot info
    memset(pInfo, 18, sizeof(*pInfo));

    if (slotID < 0 || slotID >= MAX_NUM_TOKENS)
        return CKR_SLOT_ID_INVALID;

    snprintf_fill((char *)pInfo->slotDescription,
          sizeof(pInfo->slotDescription),
                 ' ',
                 "RemsigToken slot");
    snprintf_fill((char *)pInfo->manufacturerID,
                  sizeof(pInfo->manufacturerID),
                  ' ',
                  "OndrejPrikryl");

    if(remsig_token.tokens[(int)slotID].flags.conn_up == 1) {
        pInfo->flags = CKF_TOKEN_PRESENT;
        st_logf("Token present: slot: %d ", (int)slotID);
    }
    else {
        st_logf("Token not present: slot: %d ", (int)slotID);
    }

    // sets versions
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    st_logf("- OK\n");
    return CKR_OK;
}

CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID,
           CK_TOKEN_INFO_PTR pInfo)
{
    char* p = NULL;

    st_logf("GetTokenInfo");

    if (remsig_token.cryptoki_initialized != 1)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID < 0 || slotID >= MAX_NUM_TOKENS) {
        return CKR_SLOT_ID_INVALID;
    }

    if(remsig_token.tokens[(int)slotID].flags.conn_up != 1) {
        return CKR_TOKEN_NOT_PRESENT;
    }

    // sets info about token, in our case, RemSig certificate which is in the slot
    memset(pInfo, 19, sizeof(*pInfo));

    // get CN parameter from DN
    p = strstr(remsig_token.tokens[(int)slotID].DN, "CN=");


    snprintf_fill((char *)pInfo->label,
                  sizeof(pInfo->label),
                  ' ',
                  p);

    // get O parameter from issuer
    p = strstr(remsig_token.tokens[(int)slotID].issuer, "O=");


    snprintf_fill((char *)pInfo->manufacturerID,
                  sizeof(pInfo->manufacturerID),
                  ' ',
                  p);

    snprintf_fill((char *)pInfo->model,
                  sizeof(pInfo->model),
                  ' ',
                  "1.0");

    snprintf_fill((char *)pInfo->serialNumber,
                  sizeof(pInfo->serialNumber),
                  ' ',
                  remsig_token.tokens[(int)slotID].serial);

    pInfo->flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED |
                   CKF_SO_PIN_LOCKED ;

    pInfo->ulMaxSessionCount = MAX_NUM_SESSIONS_PER_TOKEN;
    pInfo->ulSessionCount = remsig_token.tokens[(int)slotID].sessions_open;
    pInfo->ulMaxRwSessionCount = MAX_NUM_SESSIONS_PER_TOKEN;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = MAX_PIN_LENGTH;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    //strcpy(pInfo->utcTime,"0000000000000000");

    st_logf(" - OK\n");
    return CKR_OK;
}


CK_RV
C_GetMechanismList(CK_SLOT_ID slotID,
                   CK_MECHANISM_TYPE_PTR pMechanismList,
                   CK_ULONG_PTR pulCount)
{
    st_logf("GetMechanismList od slot %d", slotID);

    if (remsig_token.cryptoki_initialized != 1)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID < 0 || slotID >= MAX_NUM_TOKENS) {
        return CKR_SLOT_ID_INVALID;
    }

    if(remsig_token.tokens[(int)slotID].flags.conn_up != 1) {
        return CKR_TOKEN_NOT_PRESENT;
    }

    // number of mechanism returned
    *pulCount = 1;

    // if the mechanism is already allocated, returns the values
    if (pMechanismList != NULL_PTR) {
        pMechanismList[0] =  CKM_SHA256_RSA_PKCS;
    }

    st_logf(" - OK\n");
    return CKR_OK;
}

CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID,
                   CK_MECHANISM_TYPE type,
                   CK_MECHANISM_INFO_PTR pInfo)
{
    st_logf("GetMechanismInfo od slot %d", slotID);

    if (remsig_token.cryptoki_initialized != 1)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID < 0 || slotID >= MAX_NUM_TOKENS) {
        return CKR_SLOT_ID_INVALID;
    }

    if(remsig_token.tokens[(int)slotID].flags.conn_up != 1) {
        return CKR_TOKEN_NOT_PRESENT;
    }

    if(type != CKM_SHA256_RSA_PKCS) {
        return CKR_MECHANISM_INVALID;
    }

    pInfo->flags = CKF_SIGN | CKF_HW;

    return CKR_OK;
}

CK_RV
C_OpenSession(CK_SLOT_ID slotID,
          CK_FLAGS flags,
          CK_VOID_PTR pApplication,
          CK_NOTIFY Notify,
          CK_SESSION_HANDLE_PTR phSession)
{
    int i;

    st_logf("OpenSession: slot: %d\n", (int)slotID);
    st_logf("GetSlotList: %s - ",
        (flags & CKF_SERIAL_SESSION) ? "CKF_SERIAL_SESSION" : "not CKF_SERIAL_SESSION");
    st_logf("GetSlotList: %s - ",
        (flags & CKF_RW_SESSION) ? "CKF_RW_SESSION" : "not CKF_RW_SESSION");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // tests for various input conditions
    if (slotID < 0 || slotID >= MAX_NUM_TOKENS)
      return CKR_SLOT_ID_INVALID;

    if(remsig_token.tokens[(int)slotID].flags.conn_up != 1)
      return CKR_TOKEN_NOT_PRESENT;

    if (!(flags & CKF_SERIAL_SESSION))
    {
      return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    if (flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION))
    {
      return CKR_ARGUMENTS_BAD;
    }

    if (!(flags & CKF_RW_SESSION) && (remsig_token.tokens[(int)slotID].flags.login_user == CKU_SO))
    {
      return CKR_SESSION_READ_WRITE_SO_EXISTS;
    }

    if (remsig_token.tokens[(int)slotID].sessions_open == MAX_NUM_SESSIONS_PER_TOKEN)
    {
      return CKR_SESSION_COUNT;
    }

    if (remsig_token.open_sessions == MAX_NUM_SESSIONS)
    {
      return CKR_SESSION_COUNT;
    }

    for (i = 0; i < MAX_NUM_SESSIONS; i++)
    if (remsig_token.sessions[i].session_handle == CK_INVALID_HANDLE)
        break;
    if (i == MAX_NUM_SESSIONS)
        return CKR_SESSION_COUNT;

    remsig_token.sessions[i].session_handle = (CK_SESSION_HANDLE)(rand() & 0xfffff);
    remsig_token.sessions[i].flags = flags;
    remsig_token.sessions[i].application = pApplication;
    remsig_token.sessions[i].notify = Notify;
    remsig_token.sessions[i].slot = slotID;

    remsig_token.sessions[i].find_init_done = 0;
    remsig_token.sessions[i].sign_init_done = 0;


    // updates sessions' state
    if (flags & CKF_RW_SESSION)
    {
      if (remsig_token.tokens[(int)slotID].flags.login_user == CKU_SO)
      {
        remsig_token.sessions[i].state_session = CKS_RW_SO_FUNCTIONS;
      }
      if (remsig_token.tokens[(int)slotID].flags.login_user == CKU_USER)
      {
        remsig_token.sessions[i].state_session = CKS_RW_USER_FUNCTIONS;
      }
      if (remsig_token.tokens[(int)slotID].flags.login_user == -1)
      {
        remsig_token.sessions[i].state_session = CKS_RW_PUBLIC_SESSION;
      }
    }
    else
    {
      if (remsig_token.tokens[(int)slotID].flags.login_user == CKU_USER)
      {
        remsig_token.sessions[i].state_session = CKS_RO_USER_FUNCTIONS;
      }
      if (remsig_token.tokens[(int)slotID].flags.login_user == -1)
      {
        remsig_token.sessions[i].state_session = CKS_RO_PUBLIC_SESSION;
      }
    }

    remsig_token.open_sessions++;
    remsig_token.tokens[(int)slotID].sessions_open++;
    *phSession = remsig_token.sessions[i].session_handle;

    st_logf("Number of opened sessions:%d\n", remsig_token.open_sessions);

    return CKR_OK;
}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
    struct session_state *state;

    st_logf("CloseSession\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, &state) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    remsig_token_close_session(state);

    return CKR_OK;
}

CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{
    int i;

    st_logf("CloseAllSessions\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID < 0 || slotID >= MAX_NUM_TOKENS)
        return CKR_SLOT_ID_INVALID;

    if(remsig_token.tokens[(int)slotID].flags.conn_up != 1)
        return CKR_TOKEN_NOT_PRESENT;

    for (i = 0; i < MAX_NUM_SESSIONS; i++)
        if (remsig_token.sessions[i].session_handle != CK_INVALID_HANDLE)
          if(remsig_token.sessions[i].slot == slotID)
            remsig_token_close_session(&remsig_token.sessions[i]);

    return CKR_OK;
}

CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession,
         CK_SESSION_INFO_PTR pInfo)
{
    struct session_state *state;

    st_logf("GetSessionInfo\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, &state) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if (pInfo == NULL)
    {
      return CKR_ARGUMENTS_BAD;
    }

    memset(pInfo, 20, sizeof(*pInfo));

    // setting session info
    pInfo->slotID = state->slot;
    pInfo->state = state->state_session;
    pInfo->flags = state->flags;
    pInfo->ulDeviceError = 0;

    return CKR_OK;
}

CK_RV
C_Login(CK_SESSION_HANDLE hSession,
    CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{
    int i;
    CK_SLOT_ID slotID;

    st_logf("Login\n");
    st_logf("userType login - ");
    if(userType == CKU_USER) {
        st_logf("user\n");
    }
    if(userType == CKU_SO) {
        st_logf("so\n");
    }

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, NULL) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if (userType != CKU_USER && userType != CKU_SO)
    {
      return CKR_USER_TYPE_INVALID;
    }

    slotID = get_sess_slot(hSession);

    if (remsig_token.tokens[(int)slotID].flags.login_user == CKU_SO || remsig_token.tokens[(int)slotID].flags.login_user == CKU_USER)
    {
      return CKR_USER_ALREADY_LOGGED_IN;
    }

    if (userType == CKU_SO)
    {
      for (i = 0; i < MAX_NUM_SESSIONS; i++)
      {
        if(remsig_token.sessions[i].session_handle != CK_INVALID_HANDLE)
        {
          if (remsig_token.sessions[i].slot == slotID)
          {
            if (remsig_token.sessions[i].state_session == CKS_RO_PUBLIC_SESSION)
              return CKR_SESSION_READ_ONLY_EXISTS;
          }
        }
      }
    }

    int res = remsig_checkPassword(slotID, (char*) pPin);
    if (res == 0) {
        st_logf("Pin is incorect.\n");
        return CKR_PIN_INCORRECT;
    }
    if (res == -1) {
        st_logf("Error during pin.\n");
        return CKR_DEVICE_ERROR;
    }

    if (pPin != NULL_PTR && ulPinLen != 0) {
        // saves pin to the token context
        remsig_token.tokens[(int)slotID].pin = strdup((char*)pPin);
    }

    // updates session states
    for (i = 0; i < MAX_NUM_SESSIONS; i++)
    {
      if(remsig_token.sessions[i].session_handle != CK_INVALID_HANDLE)
      {
        if (remsig_token.sessions[i].slot == slotID)
        {
          if (remsig_token.sessions[i].state_session == CKS_RO_PUBLIC_SESSION &&
              userType == CKU_USER)
              remsig_token.sessions[i].state_session = CKS_RO_USER_FUNCTIONS;

          if (remsig_token.sessions[i].state_session == CKS_RW_PUBLIC_SESSION &&
              userType == CKU_USER)
              remsig_token.sessions[i].state_session = CKS_RW_USER_FUNCTIONS;

          if (remsig_token.sessions[i].state_session == CKS_RW_PUBLIC_SESSION &&
              userType == CKU_SO)
              remsig_token.sessions[i].state_session = CKS_RW_SO_FUNCTIONS;
        }
      }
    }

    // sets user role
    if (userType == CKU_USER)
    {
      remsig_token.tokens[(int)slotID].flags.login_user = CKU_USER;
    }

    if (userType == CKU_SO)
    {
      remsig_token.tokens[(int)slotID].flags.login_user = CKU_SO;
    }

    return CKR_OK;
}

CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{
    int i;
    CK_SLOT_ID slotID;

    st_logf("Logout\n");

    if (verify_session_handle(hSession, NULL) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    slotID = get_sess_slot(hSession);

    if (remsig_token.tokens[(int)slotID].flags.login_user != CKU_SO && remsig_token.tokens[(int)slotID].flags.login_user != CKU_USER)
    {
      return CKR_USER_NOT_LOGGED_IN;
    }

    // updates session states
    for (i = 0; i < MAX_NUM_SESSIONS; i++)
    {
      if(remsig_token.sessions[i].session_handle != CK_INVALID_HANDLE)
      {
        if (remsig_token.sessions[i].slot == (unsigned)slotID)
        {
          if (remsig_token.sessions[i].state_session == CKS_RO_USER_FUNCTIONS)
              remsig_token.sessions[i].state_session = CKS_RO_PUBLIC_SESSION;

          if (remsig_token.sessions[i].state_session == CKS_RW_USER_FUNCTIONS ||
              remsig_token.sessions[i].state_session == CKS_RW_SO_FUNCTIONS)
              remsig_token.sessions[i].state_session = CKS_RW_PUBLIC_SESSION;


          remsig_token.sessions[i].sign_init_done = 0;

        }
      }
    }

    // frees the pin from the token context
    free(remsig_token.tokens[(int)slotID].pin);
    remsig_token.tokens[(int)slotID].pin = NULL;
    remsig_token.tokens[(int)slotID].flags.login_user = -1;

    return CKR_OK;
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession,
          CK_ATTRIBUTE_PTR pTemplate,
          CK_ULONG ulCount)
{
    struct session_state *state;

    st_logf("FindObjectsInit with pTemplate : \n");


    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, &state) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if ( (pTemplate == NULL_PTR && ulCount != 0) || (ulCount == 0 && pTemplate != NULL_PTR) )
    {
      return CKR_ARGUMENTS_BAD;
    }

    if(state->find_init_done != 0)
    {
      return CKR_OPERATION_ACTIVE;
    }

    // Objects are searched by label, issuer, serial number or ID

    for(unsigned i = 0; i < ulCount; i++) {
        if(pTemplate[i].type == CKA_CLASS) {
            if(*(unsigned*)(pTemplate[i].pValue) == CKO_CERTIFICATE) {
                st_logf("looking for certificate object \n");
            }
            else if(*(unsigned*)(pTemplate[i].pValue) == CKO_DATA) {
                st_logf("looking for data object\n");
            }
            else if(*(unsigned*)(pTemplate[i].pValue) == CKO_PRIVATE_KEY) {
                st_logf("looking for private key object\n");
            }
            else if(*(unsigned*)(pTemplate[i].pValue) == CKO_SECRET_KEY) {
                st_logf("looking for secret key object\n");
            }
            else if(*(unsigned*)(pTemplate[i].pValue) == CKO_PUBLIC_KEY) {
                st_logf("looking for public key object\n");
            }
            else if(*(unsigned*)(pTemplate[i].pValue) == CKO_MECHANISM) {
                st_logf("looking for mechanism object\n");
            }
            else if(*(unsigned*)(pTemplate[i].pValue) == CKO_VENDOR_DEFINED) {
                st_logf("looking for vendor definied object\n");
            }
            else if(*(unsigned*)(pTemplate[i].pValue) == CKO_DOMAIN_PARAMETERS) {
                st_logf("looking for vendor definied object\n");
            }
            else if(*(unsigned*)(pTemplate[i].pValue) == CKO_HW_FEATURE) {
                st_logf("looking for vendor definied object\n");
            }
            else {
                st_logf("CKA_CLASS error %x\n", *(unsigned*)(pTemplate[i].pValue));
            }
        }
        else if(pTemplate[i].type == CKA_TOKEN) {
             if(*(CK_BBOOL*)(pTemplate[i].pValue) == CK_TRUE) {
                 st_logf("looking for token object\n");
             }
             else if(*(CK_BBOOL*)(pTemplate[i].pValue) == CK_FALSE) {
                 st_logf("looking for session object\n");
             }
             else {
                 st_logf("CKA_TOKEN error\n");
             }
        }
        else if(pTemplate[i].type == CKA_SERIAL_NUMBER) {
             st_logf("looking for serial %llu\n", pTemplate[i].pValue);
        }
        else if(pTemplate[i].type == CKA_ISSUER) {
             st_logf("looking for issuer %s\n", pTemplate[i].pValue);
        }
        else if(pTemplate[i].type == CKA_SUBJECT) {
             st_logf("looking for subject %s\n", pTemplate[i].pValue);
        }
        else if(pTemplate[i].type == CKA_ID) {
             st_logf("looking for id %d\n", pTemplate[i].pValue);
        }
        else {
            st_logf("looking for %x %u\n", pTemplate[i].type, pTemplate[i].pValue);
        }
    }


    // looking for objects, if the ulCount == 0, all objects are required
    if(ulCount != 0) {
        // saves template to session context
        state->templ = pTemplate;
        state->template_count = (int)ulCount;
    }
    else {
        state->templ = NULL;
    }

    state->find_init_done = 1;
    return CKR_OK;
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession,
          CK_OBJECT_HANDLE_PTR phObject,
          CK_ULONG ulMaxObjectCount,
          CK_ULONG_PTR pulObjectCount)
{

    struct session_state *state;
    CK_ATTRIBUTE_PTR pTemplate = NULL;
    CK_SLOT_ID slotID;
    int objects = 3;
    char* label = NULL;

    st_logf("FindObjects\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, &state) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if(state->find_init_done != 1)
    {
      return CKR_OPERATION_NOT_INITIALIZED;
    }

    if ( state->state_session != CKS_RW_USER_FUNCTIONS && state->state_session != CKS_RO_USER_FUNCTIONS)
    {
      st_logf("Public session - cannot find objects!.\n");
      *pulObjectCount = 0;
      return CKR_OK;
    }

    if ( ulMaxObjectCount < 1)
    {
      return CKR_ARGUMENTS_BAD;
    }

    slotID = state->slot;

    // looking for objects
    pTemplate = state->templ;
    if(pTemplate == NULL) {
        st_logf("Looking for all objects.\n");
        objects = 3;
        goto set;
    }
    else {

        for(int i = 0; i < state->template_count; i++) {

            switch(pTemplate[i].type) {

                case CKA_TOKEN:
                    if(*(CK_BBOOL*)pTemplate[i].pValue == CK_FALSE) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_PRIVATE:
                    if(*(CK_BBOOL*)pTemplate[i].pValue == CK_FALSE) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_MODIFIABLE:
                    if(*(CK_BBOOL*)pTemplate[i].pValue == CK_TRUE) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_LABEL:
                    label = strstr(remsig_token.tokens[slotID].DN, "CN=");
                    if(strcmp(label, pTemplate[i].pValue) != 0) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_ID:
                    if(*(CK_ULONG*)pTemplate[i].pValue != slotID) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_SUBJECT:
                    if(strcmp(remsig_token.tokens[i].DN, pTemplate[i].pValue) != 0) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_CLASS:
                    if(*(CK_ULONG*)pTemplate[i].pValue == CKO_CERTIFICATE) {
                        objects = 2;
                    }
                    else if (*(CK_ULONG*)pTemplate[i].pValue == CKO_PRIVATE_KEY) {
                        objects = 1;
                    }
                    else {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_TRUSTED:
                    objects = 2;
                    if(*(CK_BBOOL*)pTemplate[i].pValue != CK_TRUE) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_ISSUER:
                    objects = 2;
                    // DER ENCODING
                    if(strcmp(pTemplate[i].pValue, remsig_token.tokens[slotID].issuer) != 0) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_SERIAL_NUMBER:
                    objects = 2;
                    // DER ENCODING
                    if(strcmp(pTemplate[i].pValue, remsig_token.tokens[slotID].serial) != 0) {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_CERTIFICATE_TYPE:
                    if(*(CK_ULONG*)pTemplate[i].pValue == CKC_X_509) {
                        objects = 2;
                    }
                    else {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_CERTIFICATE_CATEGORY:
                    if(*(CK_ULONG*)pTemplate[i].pValue == 1) {
                        objects = 2;
                    }
                    else {
                        objects = 0;
                        goto set;
                    }
                break;
                case CKA_SIGN:
                    if(*(CK_BBOOL*)pTemplate[i].pValue == CK_TRUE) {
                        objects = 1;
                    }
                    else {
                        objects = 0;
                        goto set;
                    }
                break;

            default:
                objects = 0;
                *pulObjectCount = 0;
            break;
            }
        }
    }

    set:
    if(objects == 3) {

        // returns private key and certificate, if the memory is allocated, if not, returns just certificate

        if(ulMaxObjectCount >= 2) {
            phObject[0] = 0;
            phObject[1] = 1;
            *pulObjectCount = 2;
        }
        else {
            phObject[0] = 1;
            *pulObjectCount = 1;
            st_logf("Not enought memory - 1 object returned.\n");
        }
    }
    else if (objects == 2) {
        // returns certificate object
        phObject[0] = 1;
        *pulObjectCount = 1;
    }
    else if (objects == 1) {
        // return private key object
        phObject[0] = 0;
        *pulObjectCount = 1;
    }
    else {
        // bad template, object was not found
        *pulObjectCount = 0;
    }

    st_logf("Number of objects found - %d\n", *pulObjectCount);

    return CKR_OK;
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    struct session_state *state;

    st_logf("FindObjectsFinal\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, &state) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if(state->find_init_done != 1)
    {
      return CKR_OPERATION_NOT_INITIALIZED;
    }

    // frees the template
    state->templ = NULL;
    state->template_count = 0;
    state->find_init_done = 0;
    return CKR_OK;
}



CK_RV
C_SignInit(CK_SESSION_HANDLE hSession,
       CK_MECHANISM_PTR pMechanism,
       CK_OBJECT_HANDLE hKey)
{
    struct session_state *state;

    st_logf("SignInit\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, &state) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if ( state->state_session != CKS_RW_USER_FUNCTIONS && state->state_session != CKS_RO_USER_FUNCTIONS)
    {
      return CKR_USER_NOT_LOGGED_IN;
    }

    if(state->sign_init_done != 0)
    {
      return CKR_OPERATION_ACTIVE;
    }

    if(hKey != 0) {
        st_logf("Bad object for signing.\n");
        return CKR_KEY_HANDLE_INVALID;
    }

    if(pMechanism->mechanism != CKM_SHA256_RSA_PKCS) {
        st_logf("Bad signing mechanism.\n");
        return CKR_MECHANISM_INVALID;
    }

    state->sign_init_done = 1;
    return CKR_OK;
}

CK_RV
C_Sign(CK_SESSION_HANDLE hSession,
       CK_BYTE_PTR pData,
       CK_ULONG ulDataLen,
       CK_BYTE_PTR pSignature,
       CK_ULONG_PTR pulSignatureLen)
{
    CK_SLOT_ID ID;
    struct session_state *state;

    st_logf("Sign\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, &state) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if ( state->state_session != CKS_RW_USER_FUNCTIONS && state->state_session != CKS_RO_USER_FUNCTIONS)
    {
      return CKR_USER_NOT_LOGGED_IN;
    }

    if(state->sign_init_done != 1)
    {
      return CKR_OPERATION_NOT_INITIALIZED;
    }

    if (pulSignatureLen == NULL) {
    st_logf("pulSignatureLen NULL\n");
    return CKR_ARGUMENTS_BAD;
    }

    if (pData == NULL_PTR) {
    st_logf("data NULL\n");
    return CKR_ARGUMENTS_BAD;
    }

    ID = state->slot;

    char* buf = (char*) remsig_sign(ID, remsig_token.tokens[ID].pin, pData, ulDataLen);

    if (pSignature != NULL_PTR && buf != NULL) {
        memcpy(pSignature, buf, strlen(buf));
        *pulSignatureLen = (CK_ULONG) strlen(buf);
    }
    else {
        st_logf("Error during signing.\n");
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                    CK_OBJECT_HANDLE hObject,
                    CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount)
{

    struct session_state *state;
    CK_SLOT_ID slotID;
    CK_ULONG err = CKR_OK;
    char* label = NULL;

    st_logf("GetAttributeValue - count %d\n", ulCount);

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, &state) != CKR_OK)
    {
      return CKR_SESSION_HANDLE_INVALID;
    }

    if(hObject != 0 || hObject != 1)
    {
        return CKR_ARGUMENTS_BAD;
    }

    slotID = state->slot;

    if(hObject == 0) {

        for (unsigned i = 0; i < ulCount; i++) {

            // gets value of atribute
            switch(pTemplate[i].type) {

                case CKA_TOKEN:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_PRIVATE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_MODIFIABLE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_LABEL:

                    label = strstr(remsig_token.tokens[slotID].DN, "CN=");

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = strlen(label);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= strlen(label)) {
                            memcpy(pTemplate[i].pValue, label, strlen(label));
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_KEY_TYPE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_KEY_TYPE)) {
                            *(CK_KEY_TYPE*)pTemplate[i].pValue = CKK_RSA;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_ID:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BYTE);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BYTE)) {
                            *(CK_BYTE*)pTemplate[i].pValue = slotID;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_START_DATE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = 0;
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_DATE)) {
                            pTemplate[i].ulValueLen = 0;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_END_DATE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = 0;
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_DATE)) {
                            pTemplate[i].ulValueLen = 0;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_DERIVE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_LOCAL:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_KEY_GEN_MECHANISM:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_LONG);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_LONG)) {
                            *(CK_LONG*)pTemplate[i].pValue = CK_UNAVAILABLE_INFORMATION;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_SUBJECT:

                    // DER ENCODING OF CERTIFICATE SUBJECT NAME
                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(strlen(remsig_token.tokens[i].DN));
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(strlen(remsig_token.tokens[i].DN))) {
                            memcpy(pTemplate[i].pValue, remsig_token.tokens[i].DN, strlen(remsig_token.tokens[i].DN));
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_SENSITIVE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_DECRYPT:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_SIGN:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_SIGN_RECOVER:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_UNWRAP:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_EXTRACTABLE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_ALWAYS_SENSITIVE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_NEVER_EXTRACTABLE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_WRAP_WITH_TRUSTED:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_UNWRAP_TEMPLATE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_ALWAYS_AUTHENTICATE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }
                break;

                default:

                    pTemplate[i].ulValueLen = -1;
                    err = CKR_ATTRIBUTE_TYPE_INVALID;

                break;
            }
        }

    }
    else {

        for(unsigned i = 0; i < ulCount; i++) {

            switch(pTemplate[i].type) {

                case CKA_TOKEN:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_PRIVATE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_MODIFIABLE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_FALSE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_LABEL:

                    label = strstr(remsig_token.tokens[slotID].DN, "CN=");

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = strlen(label);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= strlen(label)) {
                            memcpy(pTemplate[i].pValue, label, strlen(label));
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_CERTIFICATE_TYPE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_CERTIFICATE_TYPE);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_CERTIFICATE_TYPE)) {
                            *(CK_CERTIFICATE_TYPE*)pTemplate[i].pValue = CKC_X_509;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_TRUSTED:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_CERTIFICATE_CATEGORY:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_ULONG);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_ULONG)) {
                            *(CK_ULONG*)pTemplate[i].pValue = 1;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_START_DATE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = 0;
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_DATE)) {
                            pTemplate[i].ulValueLen = 0;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_END_DATE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = 0;
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_DATE)) {
                            pTemplate[i].ulValueLen = 0;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;


                case CKA_SUBJECT:

                    // DER ENCODING OF CERTIFICATE SUBJECT NAME
                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(strlen(remsig_token.tokens[i].DN));
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(strlen(remsig_token.tokens[i].DN))) {
                            memcpy(pTemplate[i].pValue, remsig_token.tokens[i].DN, strlen(remsig_token.tokens[i].DN));
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_ID:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_BYTE);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BYTE)) {
                            *(CK_BYTE*)pTemplate[i].pValue = slotID;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_ISSUER:

                    // DER ENCODING OF CERTIFICATE ISSUER
                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(strlen(remsig_token.tokens[i].issuer));
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(strlen(remsig_token.tokens[i].issuer))) {
                            memcpy(pTemplate[i].pValue, remsig_token.tokens[i].issuer, strlen(remsig_token.tokens[i].issuer));
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_SERIAL_NUMBER:

                    // DER ENCODING OF SERIAL NUMBER

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(strlen(remsig_token.tokens[i].serial));
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(strlen(remsig_token.tokens[i].serial))) {
                            memcpy(pTemplate[i].pValue, remsig_token.tokens[i].serial, strlen(remsig_token.tokens[i].serial));
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_VALUE:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(strlen(remsig_token.tokens[i].cert));
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(strlen(remsig_token.tokens[i].cert))) {
                            memcpy(pTemplate[i].pValue, remsig_token.tokens[i].cert, strlen(remsig_token.tokens[i].cert));
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_URL:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = 0;
                    }
                    else {
                        if(pTemplate[i].ulValueLen > 0) {
                            pTemplate[i].ulValueLen = 0;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = 0;
                    }
                    else {
                        if(pTemplate[i].ulValueLen > 0) {
                            pTemplate[i].ulValueLen = 0;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_HASH_OF_ISSUER_PUBLIC_KEY:

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = 0;
                    }
                    else {
                        if(pTemplate[i].ulValueLen > 0) {
                            pTemplate[i].ulValueLen = 0;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                case CKA_JAVA_MIDP_SECURITY_DOMAIN :

                    if(pTemplate[i].pValue == NULL) {
                        pTemplate[i].ulValueLen = sizeof(CK_ULONG);
                    }
                    else {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_ULONG)) {
                            *(CK_ULONG*)pTemplate[i].pValue = 3;
                        }
                        else {
                            pTemplate[i].ulValueLen = -1;
                            err = CKR_BUFFER_TOO_SMALL;
                        }
                    }

                break;

                default:

                    pTemplate[i].ulValueLen = -1;
                    err = CKR_ATTRIBUTE_TYPE_INVALID;

                break;
            }
        }
    }

    return err;
}

CK_RV
C_WaitForSlotEvent(CK_FLAGS flags,
                   CK_SLOT_ID_PTR pSlot,
                   CK_VOID_PTR pReserved)
{
    st_logf("C_WaitForSlotEvent - %x %d %d\n", flags, pSlot, pReserved);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

// function list
CK_FUNCTION_LIST funcs = {
    { 2, 11 },
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    (void *)func_not_supported, /* C_InitToken, */
    (void *)func_not_supported, /* C_InitPIN,*/
    (void *)func_not_supported, /* C_SetPIN,*/
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    (void *)func_not_supported, /* C_GetOperationState, */
    (void *)func_not_supported, /* C_SetOperationState, */
    C_Login,
    C_Logout,
    (void *)func_not_supported, /* C_CreateObject,*/
    (void *)func_not_supported, /* C_CopyObject,*/
    (void *)func_not_supported, /* C_DestroyObject,*/
    (void *)func_not_supported, /* C_GetObjectSize,*/
    C_GetAttributeValue,
    (void *)func_not_supported, /* C_SetAttributeValue,*/
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    (void *)func_not_supported, /* C_EncryptInit */
    (void *)func_not_supported, /* C_Encrypt */
    (void *)func_not_supported, /* C_EncryptUpdate */
    (void *)func_not_supported, /* C_EncryptFinal */
    (void *)func_not_supported, /* C_DecryptInit */
    (void *)func_not_supported, /* C_Decrypt */
    (void *)func_not_supported, /* C_DecryptUpdate */
    (void *)func_not_supported, /* C_DecryptFinal */
    (void *)func_not_supported, /* C_DigestInit */
    (void *)func_not_supported, /* C_Digest */
    (void *)func_not_supported, /* C_DigestUpdate */
    (void *)func_not_supported, /* C_DigestKey */
    (void *)func_not_supported, /* C_DigestFinal */
    C_SignInit,
    C_Sign,
    (void *)func_not_supported, /* C_SignUpdate */
    (void *)func_not_supported, /* C_SignFinal */
    (void *)func_not_supported, /* C_SignRecoverInit */
    (void *)func_not_supported, /* C_SignRecover */
    (void *)func_not_supported, /* C_VerifyInit */
    (void *)func_not_supported, /* C_Verify */
    (void *)func_not_supported, /* C_VerifyUpdate */
    (void *)func_not_supported, /* C_VerifyFinal*/
    (void *)func_not_supported, /* C_VerifyRecoverInit */
    (void *)func_not_supported, /* C_VerifyRecover */
    (void *)func_not_supported, /* C_DigestEncryptUpdate */
    (void *)func_not_supported, /* C_DecryptDigestUpdate */
    (void *)func_not_supported, /* C_SignEncryptUpdate */
    (void *)func_not_supported, /* C_DecryptVerifyUpdate */
    (void *)func_not_supported, /* C_GenerateKey */
    (void *)func_not_supported, /* C_GenerateKeyPair */
    (void *)func_not_supported, /* C_WrapKey */
    (void *)func_not_supported, /* C_UnwrapKey */
    (void *)func_not_supported, /* C_DeriveKey */
    (void *)func_not_supported, /* C_Seedrandom */
    (void *)func_not_supported, /* C_Generaterandom */
    (void *)func_not_supported, /* C_GetFunctionStatus, */
    (void *)func_not_supported, /* C_CancelFunction, */
    C_WaitForSlotEvent,
};

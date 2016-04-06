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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <curl/curl.h>
#include <libxml2/libxml/tree.h>
#include <libxml2/libxml/parser.h>

#include "ref/pkcs11u.h"
#include "ref/pkcs11.h"

#define MAX_NUM_SESSIONS           5
#define MAX_NUM_SESSIONS_PER_TOKEN 5
#define MAX_NUM_TOKENS             5

static struct remsig_token {

  int app_error_fatal;
  FILE* logfile;
  int cryptoki_initialized;
  char* access_token;
  char* uco;

  int open_sessions;
  struct session_state {
    CK_SESSION_HANDLE session_handle;

        CK_STATE state_session; //PKCS11 state
        CK_FLAGS flags;
        CK_VOID_PTR application;
        CK_NOTIFY notify;

        CK_SLOT_ID slot;
        int find_init_done;
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

  } tokens[MAX_NUM_TOKENS];

} remsig_token;

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

char* toBase64(char* str, int len) {
    BIO *bio = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bufferPtr = NULL;
    char* output = NULL;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, str, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    output = (*bufferPtr).data;
    return output;
}

char *decode64(char *input, int len) {
  BIO *b64 = NULL;
  BIO *bio = NULL;

  char *buffer = malloc(len + 1);
  memset(buffer, 0, len);

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(input, len);
  bio = BIO_push(b64, bio);

  BIO_read(bio, buffer, len);

  BIO_free_all(bio);

  return buffer;
}

struct Response {
  char* data;
  size_t size;
};

static size_t
callback(void *contents, size_t size, size_t nmemb, void *userp) {

    size_t realsize = size * nmemb;
    struct Response *mem = (struct Response *)userp;

    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if(mem->data == NULL) {
        // cannot alocate memory
        st_logf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

static struct Response
curl_post_with_header(const char* url, const char* d_post, const char* header) {

    CURLcode res;
    CURL* curl;

    struct Response response = {0};
    response.data = malloc(1);
    if(response.data == NULL) {
        st_logf("Error during malloc.\n");
        return response;
    }
    response.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        st_logf("Couldn't initialize the CURL\n");
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
        st_logf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
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

static void
set_tokens(const char *xml)
{
    xmlDoc *doc = NULL; /* the resulting document tree */
    xmlNode *root_element = NULL;
    int i = 0;

    doc = xmlReadMemory(xml, strlen(xml), NULL, NULL, 0);

    root_element = xmlDocGetRootElement(doc);

    for (xmlNode *cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
        if ((cur_node->type == XML_ELEMENT_NODE)&&(strcmp((char*)cur_node->name, "certificate") == 0)) {
            if(i == MAX_NUM_TOKENS) {
                st_logf("Error: max number of tokens.\n");
                goto cleanup;
            }
            remsig_token.tokens[i].DN = strdup((char*)cur_node->children->children->content);
            remsig_token.tokens[i].issuer = strdup((char*)cur_node->children->next->children->content);
            remsig_token.tokens[i].serial = strdup((char*)cur_node->children->next->next->children->content);
            remsig_token.tokens[i].sessions_open = 0;
            remsig_token.tokens[i].flags.conn_up = 1;
            remsig_token.tokens[i].flags.login_user = -1;
            remsig_token.tokens[i].flags.hardware_slot = i;
        }
        else {
            st_logf("Error during loading tokens.\n");
            goto cleanup;
        }
        i++;
    }
    remsig_token.num_tokens = i;

    cleanup:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();
}

static void
load_tokens()
{
    const char* list = "https://remsig.ics.muni.cz/remsig/listCertificates";
    const char* bearer = "Authorization: Bearer ";
    struct Response res = {0};
    char* header = NULL;
    xmlNodePtr personElem;
    xmlNodePtr userIdElem;
    xmlNodePtr root_node;
    xmlDocPtr doc;
    xmlChar* xmlbuff;
    int buffersize;

    header = malloc((strlen(bearer) + strlen(remsig_token.access_token) + 1) * sizeof(char));

    strcpy(header, bearer);
    strcat(header, remsig_token.access_token);
    strcat(header, "\0");

    doc = xmlNewDoc(BAD_CAST "1.0");
    //setting root node: remsig
    root_node = xmlNewNode(NULL, BAD_CAST "remsig");
    xmlDocSetRootElement(doc, root_node);

    root_node = xmlDocGetRootElement(doc);
    if (root_node == NULL) {
            goto xml_Error;
    }

    personElem = xmlNewChild(root_node, NULL, BAD_CAST "person", NULL);
    if (personElem == NULL) {
            goto xml_Error;
    }

    userIdElem = xmlNewChild(personElem, NULL, BAD_CAST "uco", BAD_CAST remsig_token.uco);
    if (userIdElem == NULL) {
            goto xml_Error;
    }

    xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

    res = curl_post_with_header(list, (char*) xmlbuff, header);

    set_tokens(res.data);

    xml_Error:

    if (doc != NULL)  xmlFreeDoc(doc);
    xmlCleanupParser();
}

char* find_signature(xmlNode * a_node)
{
    if(a_node == NULL) {
        return NULL;
    }

    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if(strcmp((char *) cur_node->name, "signature") == 0) {
                printf("node type: Element, name: %s - ", cur_node->name);
                return (char*) cur_node->children->content;
            }
        }

        char* temp = find_signature(cur_node->children);
        if(temp != NULL) {
            return temp;
        }
    }
    return NULL;
}

char* xml_sign_parse(char* xml, int size) {

    xmlDoc *doc = NULL; /* the resulting document tree */
    xmlNode *root_element = NULL;
    char* tmp = NULL;
    char* signature = NULL;

    doc = xmlReadMemory(xml, size, NULL, NULL, 0);

    root_element = xmlDocGetRootElement(doc);

    tmp = find_signature(root_element);

    signature = malloc(strlen(tmp) * sizeof(char));

    strcpy(signature, tmp);

    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();

    return signature;
}

char* remsig_sign(char* accessToken, unsigned certID,char* password, char* uco, char* data) {

    const char* sign = "https://remsig.ics.muni.cz/remsig/sign";
    const char* bearer = "Authorization: Bearer ";
    struct Response res = {0};
    char* header = NULL;
    xmlNodePtr personElem;
    xmlNodePtr userIdElem;
    xmlNodePtr certificateIdElem;
    xmlNodePtr timestampElem;
    xmlNodePtr passwordElem;
    xmlNodePtr dataElem;
    xmlDocPtr doc;
    xmlNodePtr root_node;
    xmlChar *xmlbuff;
    int buffersize;
    char* signature;
    char* decodedSig = NULL;

    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));

    strcpy(header, bearer);
    strcat(header, accessToken);
    strcat(header, "\0");

    doc = xmlNewDoc(BAD_CAST "1.0");
    //setting root node: remsig
    root_node = xmlNewNode(NULL, BAD_CAST "remsig");
    xmlDocSetRootElement(doc, root_node);

    if (root_node == NULL) {
        goto xml_Error;
    }

    personElem = xmlNewChild(root_node, NULL, BAD_CAST "person", NULL);
    if (personElem == NULL) {
        goto xml_Error;
    }
    userIdElem = xmlNewChild(personElem, NULL, BAD_CAST "uco", BAD_CAST uco);
    if (userIdElem == NULL) {
        goto xml_Error;
    }
    certificateIdElem = xmlNewChild(root_node, NULL, BAD_CAST "certificateId", BAD_CAST certID);
    if (certificateIdElem == NULL) {
        goto xml_Error;
    }
    passwordElem = xmlNewChild(root_node, NULL, BAD_CAST "password", BAD_CAST password);
    if (passwordElem == NULL) {
        goto xml_Error;
    }
    timestampElem = xmlNewChild(root_node, NULL, BAD_CAST "timestamp", BAD_CAST "QUALIFIED");
    if (timestampElem == NULL) {
        goto xml_Error;
    }
    dataElem = xmlNewChild(root_node, NULL, BAD_CAST "data", BAD_CAST toBase64(data,strlen(data)));
    if (dataElem == NULL) {
        goto xml_Error;
    }

    xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

    res = curl_post_with_header(sign, (char*) xmlbuff, header);

    signature = xml_sign_parse(res.data, res.size);
    if(signature != NULL) {
        decodedSig = decode64(signature, strlen(signature));
    }

    xml_Error:
    if (doc != NULL)  xmlFreeDoc(doc);
    xmlCleanupParser();
    return decodedSig;
}

static CK_RV
func_not_supported(void)
{
    st_logf("function not supported\n");
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_Initialize(CK_VOID_PTR a)
{
    CK_C_INITIALIZE_ARGS_PTR args = a;

    int i;

    // sets logging
#if 0
    remsig_token.logfile = NULL;
#endif
#if 1
    remsig_token.logfile = stdout;
#endif
#if 0
    remsig_token.logfile = fopen("~/log-pkcs11.txt", "a");
#endif

    st_logf("Initialize\n");

    if (remsig_token.cryptoki_initialized == 1)
    {
      return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

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
      remsig_token.tokens[i].DN = NULL;
      remsig_token.tokens[i].serial = NULL;
      remsig_token.tokens[i].issuer = NULL;
      remsig_token.tokens[i].pin = NULL;
    }

    // load tokens
    load_tokens();

    remsig_token.cryptoki_initialized = 1;

    return CKR_OK;
}

CK_RV
C_Finalize(CK_VOID_PTR args)
{

    st_logf("Finalize\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (args != NULL )
    {
       st_logf("\tpReserved is not NULL\n");
       return CKR_ARGUMENTS_BAD;
    }

    // free remsig_token struct

    remsig_token.cryptoki_initialized = 0;

    return CKR_OK;
}

CK_RV
C_GetInfo(CK_INFO_PTR args)
{
    st_logf("GetInfo\n");

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

    return CKR_OK;
}

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
    int i, idx = 0, conn_tokens = 0;

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
      *pulCount = MAX_NUM_TOKENS;
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
    st_logf("GetSlotInfo: slot: %d\n", (int)slotID);

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
                  "OndrejPrikryl (slot)");

    if(remsig_token.tokens[(int)slotID].flags.conn_up == 1)
      pInfo->flags = CKF_TOKEN_PRESENT;

    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID,
           CK_TOKEN_INFO_PTR pInfo)
{

    st_logf("GetTokenInfo\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID < 0 || slotID >= MAX_NUM_TOKENS)
        return CKR_SLOT_ID_INVALID;

    if(remsig_token.tokens[(int)slotID].flags.conn_up != 1)
      return CKR_TOKEN_NOT_PRESENT;

    memset(pInfo, 19, sizeof(*pInfo));

    snprintf_fill((char *)pInfo->label,
                  sizeof(pInfo->label),
                  ' ',
                  remsig_token.tokens[(int)slotID].DN);

    snprintf_fill((char *)pInfo->manufacturerID,
                  sizeof(pInfo->manufacturerID),
                  ' ',
                  remsig_token.tokens[(int)slotID].issuer);

    snprintf_fill((char *)pInfo->model,
                  sizeof(pInfo->model),
                  ' ',
                  "1.0");

    snprintf_fill((char *)pInfo->serialNumber,
                  sizeof(pInfo->serialNumber),
                  ' ',
                  remsig_token.tokens[(int)slotID].serial);

    pInfo->flags = CKF_WRITE_PROTECTED;

    pInfo->ulMaxSessionCount = MAX_NUM_SESSIONS_PER_TOKEN;
    pInfo->ulSessionCount = remsig_token.tokens[(int)slotID].sessions_open;
    pInfo->ulMaxRwSessionCount = 0;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = 50;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = 0;
    pInfo->ulFreePublicMemory = 0;
    pInfo->ulTotalPrivateMemory = 0;
    pInfo->ulFreePrivateMemory = 0;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    //strcpy(pInfo->utcTime,"0000000000000000");

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

    remsig_token.sessions[i].session_handle = (CK_SESSION_HANDLE)(random() & 0xfffff);
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

    if (pPin != NULL_PTR && ulPinLen != 0) {
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
        if (remsig_token.sessions[i].slot == (int)slotID)
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
    int i;
    struct session_state *state;

    st_logf("FindObjectsInit\n");

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


    for(i=0;i<ulCount;i++)
    {
      if(pTemplate[i].type & CKA_VENDOR_DEFINED)
        return CKR_ATTRIBUTE_TYPE_INVALID;
      if(*(CK_ULONG*)pTemplate[i].pValue & CKO_VENDOR_DEFINED)
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if ( state->state_session != CKS_RW_USER_FUNCTIONS && state->state_session != CKS_RO_USER_FUNCTIONS)
    {
      state->find_init_done = 1;
      return CKR_OK;
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
      *pulObjectCount = 0;
      return CKR_OK;
    }

    if ( ulMaxObjectCount < 1)
    {
      return CKR_ARGUMENTS_BAD;
    }


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

    if ( state->state_session != CKS_RW_USER_FUNCTIONS && state->state_session != CKS_RO_USER_FUNCTIONS)
    {
      state->find_init_done = 0;
      return CKR_OK;
    }

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

    char* buf = (char*) remsig_sign(remsig_token.access_token, ID,remsig_token.tokens[ID].pin, remsig_token.uco, (char*) pData);

    if (pSignature != NULL_PTR)
    memcpy(pSignature, buf, strlen(buf));
    *pulSignatureLen = (CK_ULONG) strlen(buf);

    free(buf);

    return CKR_OK;
}

CK_FUNCTION_LIST funcs = {
    { 2, 11 },
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    (void *)func_not_supported, /* C_GetMechanismList */
    (void *)func_not_supported, /* C_GetMechanismInfo */
    (void *)func_not_supported, /* C_InitToken */
    (void *)func_not_supported, /* C_InitPIN */
    (void *)func_not_supported, /* C_SetPIN */
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    (void *)func_not_supported, /* C_GetOperationState */
    (void *)func_not_supported, /* C_SetOperationState */
    C_Login,
    C_Logout,
    (void *)func_not_supported, /* C_CreateObject */
    (void *)func_not_supported, /* C_CopyObject */
    (void *)func_not_supported, /* C_DestroyObject */
    (void *)func_not_supported, /* C_GetObjectSize */
    (void *)func_not_supported, /* C_GetAttributeValue */
    (void *)func_not_supported, /* C_SetAttributeValue */
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
    (void *)func_not_supported, /* C_SeedRandom */
    (void *)func_not_supported, /*C_GenerateRandom */
    (void *)func_not_supported, /* C_GetFunctionStatus */
    (void *)func_not_supported, /* C_CancelFunction */
    (void *)func_not_supported  /* C_WaitForSlotEvent */
};


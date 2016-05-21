#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "config.h"
#include "cardmod.h"
#include "curl/include/curl/curl.h"

#define PEER_VERIFICATION
#define SIMULATE
#define MINIMUM_VERSION_SUPPORTED 4
#define GUID_SIZE 16

#define UNUSED(x) (void)(x)

// store the instance given at DllMain when attached to access internal resources
HINSTANCE inst;

// hKey300 guid - must be generated later
BYTE iKey_guid[] = {0x50, 0xdd, 0x52, 0x30, 0xba, 0x8a, 0x11, 0xd1, 0xbf, 0x5d, 0x00, 0x00, 0xf8, 0x05, 0xf5, 0x30};

typedef struct token{

    // card info
    int authenticated;
    BYTE guid[GUID_SIZE];
    unsigned certID;

    // remsig info
    int qualified;
    char* serial;
    char* pin;
    char* DN;
    char* issuer;
    char* certPem;
    unsigned char* cert;

    // loading status
    unsigned state;

} remsig_token;

void
logprintf(const char* format, ...)
{
    va_list arg;
    char path[120] = {0};
    FILE* lldebugfp = NULL;

    strcpy(path, getenv("APPDATA"));
    strcat(path, "\\RemSig");
    strcat(path, "\\minidriverlog.txt");

    lldebugfp = fopen(path,"a+");
    if (lldebugfp)   {
        va_start(arg, format);
        vfprintf(lldebugfp, format, arg);
        va_end(arg);
        fflush(lldebugfp);
        fclose(lldebugfp);
    }
}

static char*
getToken() {

    char path[120] = {0};
    FILE* file = NULL;
    char* buffer = NULL;
    char* p = NULL;
    char* output = NULL;
    int length = 0;

    // gets enviroment path C:\users\[user]\appdata\roaming\remsig\access
    strcpy(path, getenv("APPDATA"));
    strcat(path, "\\RemSig");
    strcat(path, "\\access");


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
            logprintf("Error during memory alloc.\n");
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

static BYTE*
toBase64(BYTE* str, int len) {
    BIO *bio = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bufferPtr = NULL;
    BYTE* output = NULL;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, str, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    output = (BYTE*)(*bufferPtr).data;
    return output;
}

static BYTE*
decode64(BYTE* input, int len) {
  BIO *b64 = NULL;
  BIO *bio = NULL;

  BYTE *buffer = malloc(len + 1);
  memset(buffer, 0, len);

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(input, len);
  bio = BIO_push(b64, bio);

  BIO_read(bio, buffer, len);

  BIO_free_all(bio);

  return buffer;
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
        logprintf("CURL - Error during memory alloc.\n");
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
        logprintf("Error during malloc.\n");
        return response;
    }

    // initializes curl
    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        logprintf("Couldn't initialize the CURL\n");
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
        logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

    // sets curls endpoint
    res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if(res != CURLE_OK) {
        logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

    #ifdef PEER_VERIFICATION
        // we must set path to the ca_bundle
        res = curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
        if(res != CURLE_OK) {
            logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto error_cleanup;
        }
    #endif

    #ifndef PEER_VERIFICATION
        res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 0);
        if(res != CURLE_OK) {
            logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto error_cleanup;
        }
    #endif

    // sets post data if available
    if(d_post != NULL) {

        // sets curl to POST (default 0 = GET)
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        if(res != CURLE_OK) {
            logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto error_cleanup;
        }

        // sets POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, d_post);
        if(res != CURLE_OK) {
            logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            goto error_cleanup;
        }
    }

    // sets function in which we
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    if(res != CURLE_OK) {
        logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

    // sets variable to which we want save data
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    if(res != CURLE_OK) {
        logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        goto error_cleanup;
    }

    // performs curl call
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        logprintf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
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
set_token(remsig_token* card_context, const char *xml)
{
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;
    int i = 0;
    unsigned length = 0;
    BIO *mem = NULL;
    X509* pem = NULL;

    logprintf("Setting virtual slots.\n");

    // create xml from string
    doc = xmlReadMemory(xml, strlen(xml), NULL, NULL, 0);
    if (doc == NULL) {
        logprintf("Error during reading xml response.\n");
        return;
    }
    // getting remsig root element
    root_element = xmlDocGetRootElement(doc);

    // setting local tokens
    for (xmlNode *cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
        if ((cur_node->type == XML_ELEMENT_NODE)&&(strcmp((char*)cur_node->name, "certificate") == 0)) {
            if(i == 0) {
                card_context->certID = i;
                card_context->DN = strdup((char*)cur_node->children->children->content);
                card_context->issuer = strdup((char*)cur_node->children->next->children->content);
                card_context->serial = strdup((char*)cur_node->children->next->next->children->content);
                card_context->qualified = atoi((char*)cur_node->children->next->next->next->next->children->content);
                card_context->certPem = strdup((char*)cur_node->children->next->next->next->next->next->children->content);
                card_context->pin = NULL;
                card_context->authenticated = 0;
                memcpy(card_context->guid, iKey_guid, GUID_SIZE);

                break;
            }
        }
    }

    if (i == 0)
        logprintf("Error during loading token.\n");

    #ifdef SIMULATE
        char certPath[120] = {0};
        // gets enviroment path C:\users\[user]\appdata\roaming\remsig\access
        strcpy(certPath, getenv("APPDATA"));
        strcat(certPath, "\\RemSig");
        strcat(certPath, "\\cert.der");

        FILE* cert = fopen(certPath, "r");
        if(!cert) {
            logprintf("Cannot open certificate file.\n");
            card_context->state = 0;
            goto cleanup;
        }
        i = 0;
        int p;

        // gets file size
        fseek(cert, 0, SEEK_END);
        size_t size = ftell(cert);
        rewind(cert);

        card_context->cert = malloc(size + 1);
        memset(card_context->cert, 0, size + 1);
        if(!card_context) {
            logprintf("Cannot read certificate file.\n");
            card_context->state = 0;
            fclose(cert);
            goto cleanup;
        }

        do {
            p = fgetc(cert);
            card_context->cert[i] = p;
            i++;
        } while(p != EOF);

        fclose(cert);
        card_context->state = 1;
        goto cleanup;
    #endif

    // parse PEM to DER
    mem = BIO_new(BIO_s_mem());
    BIO_puts(mem, card_context->certPem);
    pem = PEM_read_bio_X509(mem, NULL, 0, NULL);

    length = i2d_X509(pem, NULL);
    card_context->cert = malloc(length);
    if(!card_context->cert){
        logprintf("Error during memory alloc, pem to der convertion.\n");
        card_context->state = 0;
        goto bio_cleanup;
    }

    i2d_X509(pem, &card_context->cert);
    card_context->state = 1;

    bio_cleanup:
    BIO_free(mem);
    X509_free(pem);

    // cleanup
    cleanup:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();
}

static void
load_token(remsig_token* card_context)
{

    logprintf("Loading tokens from Remsig.\n");

    #ifdef SIMULATE

        // alternative
        char* xml = "<?xml version=\"1.0\"?><remsig><certificate id=\"1\"><dn>/C=CZ/O=Masaryk University/CN=Jan Novak</dn><issuer>/C=CZ/O=PostSignum QCA</issuer><serialNumber>1234</serialNumber><expiration>12345789</expiration><qualified>0</qualified><certificatePEM>­­­­BEGIN CERTIFICATE­­­­ ...</certificatePEM><chainPEM>­­­­BEGIN CERTIFICATE­­­­ ...</chainPEM></certificate><operationId>1111</operationId></remsig>";
        set_token(card_context, xml);
        return;

    #endif

    const char* bearer = "Authorization: Bearer ";
    struct Response res = {0};
    char* header = NULL;
    char* accessToken = NULL;

    // get access token from file
    accessToken = getToken();
    if(accessToken == NULL) {
        logprintf("Access Token not found.\n");
        return;
    }

    // set authentization header
    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));
    if(header == NULL) {
        logprintf("Error during memory alloc.\n");
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
        set_token(card_context, res.data);
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
                logprintf("Check_password error: %s.\n", (char*)cur_node->children->content);
                return 0;
            }
        }
    }

    return 0;
}

static int
remsig_checkPassword(unsigned certID, char* password) {

    logprintf("Checking password.\n");

    #ifdef SIMULATE

        // Password is correct
        return 1;

    #endif

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
        logprintf("Access Token not found.\n");
        return -1;
    }

    // set authentization header
    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));
    if(header == NULL) {
        logprintf("Error during memory alloc.\n");
        free(accessToken);
        return -1;
    }
    strcpy(header, bearer);
    strcat(header, accessToken);
    strcat(header, "\0");

    // create new xml document
    doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        logprintf("Cannot create xml document.\n");
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
    res = curl_post_with_header(checkpassword, (char*) xmlbuff, header);

    // checking response size
    if (res.size == 0 || res.data == NULL)
        goto xml_Error;

    // create xml from string
    answ = xmlReadMemory(res.data, res.size, NULL, NULL, 0);
    if (answ == NULL) {
        logprintf("Invalid xml document.\n");
        goto xml_Error;
    }

    // get root element of xml
    root_element = xmlDocGetRootElement(answ);
    if (root_element == NULL) {
        logprintf("Cannot find xml root.\n");
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

BYTE*
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
                logprintf("Signature error: %s.\n", (char*)cur_node->children->content);
                return NULL;
            }
        }

        if ((cur_node->type == XML_ELEMENT_NODE)&&(strcmp((char*)cur_node->name, "signature") == 0)) {
            return cur_node->children->content;
        }
    }

    return NULL;
}

BYTE*
xml_sign_parse(char* xml, int size) {

    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;
    BYTE* tmp = NULL;
    BYTE* signature = NULL;

    // checking if the parameters are valid
    if (size == 0 || xml == NULL)
        return NULL;

    // create xml from string
    doc = xmlReadMemory(xml, size, NULL, NULL, 0);
    if (doc == NULL) {
        logprintf("Invalid xml document.\n");
        return NULL;
    }

    // get root element of xml
    root_element = xmlDocGetRootElement(doc);
    if (root_element == NULL) {
        logprintf("Cannot find xml root.\n");
        goto cleanup;
    }

    // looking for signature
    tmp = find_signature(root_element);

    // get signature from xml structure
    signature = malloc((strlen((char*)tmp) + 1) * sizeof(char));
    if (signature == NULL) {
        logprintf("Error during memory alloc.\n");
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

BYTE*
remsig_sign(remsig_token* card_context, BYTE* data, unsigned data_len) {

    #ifdef SIMULATE

        return data;

    #endif

    const char* bearer = "Authorization: Bearer ";
    struct Response res = {0};
    char* header = NULL;
    BYTE* signature = NULL;
    BYTE* decodedSig = NULL;
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
        logprintf("Access Token not found.\n");
        return NULL;
    }

    // set authentization header
    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));
    if(header == NULL) {
        logprintf("Error during memory alloc.\n");
        free(accessToken);
        return NULL;
    }

    strcpy(header, bearer);
    strcat(header, accessToken);
    strcat(header, "\0");

    // create new xml document
    doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        logprintf("Cannot create xml document.\n");
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
    if(card_context->qualified == 1) {
        qualified = "QUALIFIED";
    }
    else {
        qualified = "NONQUALIFIED";
    }

    // add data to xml
    certificateIdElem = xmlNewChild(root_node, NULL, BAD_CAST "certificateId", BAD_CAST card_context->certID);
    if (certificateIdElem == NULL) {
        goto xml_Error;
    }
    passwordElem = xmlNewChild(root_node, NULL, BAD_CAST "password", BAD_CAST card_context->pin);
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

/**************************************
 *
 *          Minidriver
 *
 *************************************/


/***************************************************
 * READ - ONLY CARDS
 * NO
 *
 * Those operations must not be implemented.
 * Entry point must exist and must return
 * SCARD_E_UNSUPPORTED_FEATURE
 **************************************************/

DWORD WINAPI
CardCreateDirectory(
    __in    PCARD_DATA                      pCardData,
    __in    LPSTR                           pszDirectoryName,
    __in    CARD_DIRECTORY_ACCESS_CONDITION AccessCondition)
{
    UNUSED (pCardData);
    UNUSED (pszDirectoryName);
    UNUSED (AccessCondition);
    logprintf("CardCreateDirectory unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardDeleteDirectory(
    __in    PCARD_DATA  pCardData,
    __in    LPSTR       pszDirectoryName)
{
    UNUSED (pCardData);
    UNUSED (pszDirectoryName);
    logprintf("CardDeleteDirectory unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardCreateFile(
    __in        PCARD_DATA                  pCardData,
    __in_opt    LPSTR                       pszDirectoryName,
    __in        LPSTR                       pszFileName,
    __in        DWORD                       cbInitialCreationSize,
    __in        CARD_FILE_ACCESS_CONDITION  AccessCondition)
{
    UNUSED (pCardData);
    UNUSED (pszDirectoryName);
    UNUSED (pszFileName);
    UNUSED (cbInitialCreationSize);
    UNUSED (AccessCondition);
    logprintf("CardCreateFile unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardWriteFile(
    __in                     PCARD_DATA  pCardData,
    __in_opt                 LPSTR       pszDirectoryName,
    __in                     LPSTR       pszFileName,
    __in                     DWORD       dwFlags,
    __in_bcount(cbData)      PBYTE       pbData,
    __in                     DWORD       cbData)
{
    UNUSED (pCardData);
    UNUSED (pszDirectoryName);
    UNUSED (pszFileName);
    UNUSED (dwFlags);
    UNUSED (pbData);
    UNUSED (cbData);
    logprintf("CardWriteFile unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardDeleteFile(
    __in        PCARD_DATA  pCardData,
    __in_opt    LPSTR       pszDirectoryName,
    __in        LPSTR       pszFileName,
    __in        DWORD       dwFlags)
{
    UNUSED (pCardData);
    UNUSED (pszDirectoryName);
    UNUSED (pszFileName);
    UNUSED (dwFlags);
    logprintf("CardDeleteFile unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardCreateContainer(
    __in    PCARD_DATA  pCardData,
    __in    BYTE        bContainerIndex,
    __in    DWORD       dwFlags,
    __in    DWORD       dwKeySpec,
    __in    DWORD       dwKeySize,
    __in    PBYTE       pbKeyData)
{
    UNUSED (pCardData);
    UNUSED (bContainerIndex);
    UNUSED (dwFlags);
    UNUSED (dwKeySize);
    UNUSED (dwKeySpec);
    UNUSED (pbKeyData);
    logprintf("CardCreateContainer unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD
WINAPI
CardDeleteContainer(
    __in    PCARD_DATA  pCardData,
    __in    BYTE        bContainerIndex,
    __in    DWORD       dwReserved)
{
    UNUSED (pCardData);
    UNUSED (bContainerIndex);
    UNUSED (dwReserved);
    logprintf("CardDeleteContainer unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD
WINAPI
CardSetContainerProperty(
    __in                    PCARD_DATA  pCardData,
    __in                    BYTE        bContainerIndex,
    __in                    LPCWSTR     wszProperty,
    __in_bcount(cbDataLen)  PBYTE       pbData,
    __in                    DWORD       cbDataLen,
    __in                    DWORD       dwFlags)
{
    UNUSED (pCardData);
    UNUSED (bContainerIndex);
    UNUSED (wszProperty);
    UNUSED (pbData);
    UNUSED (cbDataLen);
    UNUSED (dwFlags);
    logprintf("CardSetContainerProperty unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

/***************************************************
 * READ - ONLY CARDS
 * NO - OPTIONAL
 *
 * Those operations are not required to be supported
 * for a read-only card, but may be implemented if
 * the card supports the operation. If not supported,
 * the entry point must return
 * SCARD_E_UNSUPPORTED_FEATURE.
 **************************************************/

DWORD WINAPI
CardGetChallenge(
    __in                                    PCARD_DATA  pCardData,
    __deref_out_bcount(*pcbChallengeData)   PBYTE       *ppbChallengeData,
    __out                                   PDWORD      pcbChallengeData)
{
    UNUSED (pCardData);
    UNUSED (ppbChallengeData);
    UNUSED (pcbChallengeData);
    logprintf("CardGetChalenge unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardAuthenticateChallenge(
    __in                             PCARD_DATA pCardData,
    __in_bcount(cbResponseData)      PBYTE      pbResponseData,
    __in                             DWORD      cbResponseData,
    __out_opt                        PDWORD     pcAttemptsRemaining)
{
    UNUSED (pCardData);
    UNUSED (pbResponseData);
    UNUSED (cbResponseData);
    UNUSED (pcAttemptsRemaining);
    logprintf("CardAuthenticateChalenge unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardUnblockPin(
    __in                               PCARD_DATA  pCardData,
    __in                               LPWSTR      pwszUserId,
    __in_bcount(cbAuthenticationData)  PBYTE       pbAuthenticationData,
    __in                               DWORD       cbAuthenticationData,
    __in_bcount(cbNewPinData)          PBYTE       pbNewPinData,
    __in                               DWORD       cbNewPinData,
    __in                               DWORD       cRetryCount,
    __in                               DWORD       dwFlags)
{
    UNUSED (pCardData);
    UNUSED (pwszUserId);
    UNUSED (pbAuthenticationData);
    UNUSED (cbAuthenticationData);
    UNUSED (pbNewPinData);
    UNUSED (cbNewPinData);
    UNUSED (cRetryCount);
    UNUSED (dwFlags);
    logprintf("CardUnblockPin unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardChangeAuthenticator(
    __in                                 PCARD_DATA  pCardData,
    __in                                 LPWSTR      pwszUserId,
    __in_bcount(cbCurrentAuthenticator)  PBYTE       pbCurrentAuthenticator,
    __in                                 DWORD       cbCurrentAuthenticator,
    __in_bcount(cbNewAuthenticator)      PBYTE       pbNewAuthenticator,
    __in                                 DWORD       cbNewAuthenticator,
    __in                                 DWORD       cRetryCount,
    __in                                 DWORD       dwFlags,
    __out_opt                            PDWORD      pcAttemptsRemaining)
{
    UNUSED (pCardData);
    UNUSED (pwszUserId);
    UNUSED (pbCurrentAuthenticator);
    UNUSED (cbCurrentAuthenticator);
    UNUSED (pbNewAuthenticator);
    UNUSED (cbNewAuthenticator);
    UNUSED (cRetryCount);
    UNUSED (dwFlags);
    UNUSED (pcAttemptsRemaining);
    logprintf("CardChangeAuthenticator unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardCreateContainerEx(
    __in    PCARD_DATA  pCardData,
    __in    BYTE        bContainerIndex,
    __in    DWORD       dwFlags,
    __in    DWORD       dwKeySpec,
    __in    DWORD       dwKeySize,
    __in    PBYTE       pbKeyData,
    __in    PIN_ID      PinId)
{
    UNUSED (pCardData);
    UNUSED (bContainerIndex);
    UNUSED (dwFlags);
    UNUSED (dwKeySpec);
    UNUSED (dwKeySize);
    UNUSED (pbKeyData);
    UNUSED (PinId);
    logprintf("CardCreateContainerEx unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardChangeAuthenticatorEx(
    __in                                    PCARD_DATA  pCardData,
    __in                                    DWORD       dwFlags,
    __in                                    PIN_ID      dwAuthenticatingPinId,
    __in_bcount(cbAuthenticatingPinData)    PBYTE       pbAuthenticatingPinData,
    __in                                    DWORD       cbAuthenticatingPinData,
    __in                                    PIN_ID      dwTargetPinId,
    __in_bcount(cbTargetData)               PBYTE       pbTargetData,
    __in                                    DWORD       cbTargetData,
    __in                                    DWORD       cRetryCount,
    __out_opt                               PDWORD      pcAttemptsRemaining)
{
    UNUSED (pCardData);
    UNUSED (dwFlags);
    UNUSED (dwAuthenticatingPinId);
    UNUSED (pbAuthenticatingPinData);
    UNUSED (cbAuthenticatingPinData);
    UNUSED (dwTargetPinId);
    UNUSED (pbTargetData);
    UNUSED (cbTargetData);
    UNUSED (cRetryCount);
    UNUSED (pcAttemptsRemaining);
    logprintf("CardChangeAuthenticatorEx unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardGetChallengeEx(
    __in                                    PCARD_DATA  pCardData,
    __in                                    PIN_ID      PinId,
    __deref_out_bcount(*pcbChallengeData)   PBYTE       *ppbChallengeData,
    __out                                   PDWORD      pcbChallengeData,
    __in                                    DWORD       dwFlags)
{
    UNUSED (pCardData);
    UNUSED (PinId);
    UNUSED (ppbChallengeData);
    UNUSED (pcbChallengeData);
    UNUSED (dwFlags);
    logprintf("CardGetChallengeEx unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
MDImportSessionKey(
    __in                    PCARD_DATA          pCardData,
    __in                    LPCWSTR             pwszBlobType,
    __in                    LPCWSTR             pwszAlgId,
    __out                   PCARD_KEY_HANDLE    phKey,
    __in_bcount(cbInput)    PBYTE               pbInput,
    __in                    DWORD               cbInput)
{
    UNUSED (pCardData);
    UNUSED (pwszBlobType);
    UNUSED (pwszAlgId);
    UNUSED (phKey);
    UNUSED (pbInput);
    UNUSED (cbInput);
    logprintf("MDImportSessionKey unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
MDEncryptData(
    __in                                    PCARD_DATA              pCardData,
    __in                                    CARD_KEY_HANDLE         hKey,
    __in                                    LPCWSTR                 pwszSecureFunction,
    __in_bcount(cbInput)                    PBYTE                   pbInput,
    __in                                    DWORD                   cbInput,
    __in                                    DWORD                   dwFlags,
    __deref_out_ecount(*pcEncryptedData)    PCARD_ENCRYPTED_DATA    *ppEncryptedData,
    __out                                   PDWORD                  pcEncryptedData)
{
    UNUSED (pCardData);
    UNUSED (hKey);
    UNUSED (pwszSecureFunction);
    UNUSED (pbInput);
    UNUSED (cbInput);
    UNUSED (dwFlags);
    UNUSED (ppEncryptedData);
    UNUSED (pcEncryptedData);
    logprintf("MDEncryptData unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardImportSessionKey(
    __in                    PCARD_DATA          pCardData,
    __in                    BYTE                bContainerIndex,
    __in                    LPVOID              pPaddingInfo,
    __in                    LPCWSTR             pwszBlobType,
    __in                    LPCWSTR             pwszAlgId,
    __out                   PCARD_KEY_HANDLE    phKey,
    __in_bcount(cbInput)    PBYTE               pbInput,
    __in                    DWORD               cbInput,
    __in                    DWORD               dwFlags)
{
    UNUSED (pCardData);
    UNUSED (bContainerIndex);
    UNUSED (pPaddingInfo);
    UNUSED (pwszBlobType);
    UNUSED (pwszAlgId);
    UNUSED (phKey);
    UNUSED (pbInput);
    UNUSED (cbInput);
    UNUSED (dwFlags);
    logprintf("CardImportSessionKey unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardGetSharedKeyHandle(
    __in                                PCARD_DATA          pCardData,
    __in_bcount(cbInput)                PBYTE               pbInput,
    __in                                DWORD               cbInput,
    __deref_opt_out_bcount(*pcbOutput)  PBYTE               *ppbOutput,
    __out_opt                           PDWORD              pcbOutput,
    __out                               PCARD_KEY_HANDLE    phKey)
{
    UNUSED (pCardData);
    UNUSED (pbInput);
    UNUSED (cbInput);
    UNUSED (ppbOutput);
    UNUSED (pcbOutput);
    UNUSED (phKey);
    logprintf("CardGetSharedKeyHandle unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardGetAlgorithmProperty(
    __in                                        PCARD_DATA  pCardData,
    __in                                        LPCWSTR     pwszAlgId,
    __in                                        LPCWSTR     pwszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen)  PBYTE       pbData,
    __in                                        DWORD       cbData,
    __out                                       PDWORD      pdwDataLen,
    __in                                        DWORD       dwFlags)
{
    UNUSED (pCardData);
    UNUSED (pwszAlgId);
    UNUSED (pwszProperty);
    UNUSED (pbData);
    UNUSED (cbData);
    UNUSED (pdwDataLen);
    UNUSED (dwFlags);
    logprintf("CardGetAlgorithmProperty unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardGetKeyProperty(
    __in                                        PCARD_DATA      pCardData,
    __in                                        CARD_KEY_HANDLE hKey,
    __in                                        LPCWSTR         pwszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen)  PBYTE           pbData,
    __in                                        DWORD           cbData,
    __out                                       PDWORD          pdwDataLen,
    __in                                        DWORD           dwFlags)
{
    UNUSED (pCardData);
    UNUSED (hKey);
    UNUSED (pwszProperty);
    UNUSED (pbData);
    UNUSED (cbData);
    UNUSED (pdwDataLen);
    UNUSED (dwFlags);
    logprintf("CardGetKeyProperty unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardSetKeyProperty(
    __in                    PCARD_DATA      pCardData,
    __in                    CARD_KEY_HANDLE hKey,
    __in                    LPCWSTR         pwszProperty,
    __in_bcount(cbInput)    PBYTE           pbInput,
    __in                    DWORD           cbInput,
    __in                    DWORD           dwFlags)
{
    UNUSED (pCardData);
    UNUSED (hKey);
    UNUSED (pwszProperty);
    UNUSED (pbInput);
    UNUSED (cbInput);
    UNUSED (dwFlags);
    logprintf("CardSetKeyProperty unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardDestroyKey(
    __in    PCARD_DATA      pCardData,
    __in    CARD_KEY_HANDLE hKey)
{
    UNUSED (pCardData);
    UNUSED (hKey);
    logprintf("CardDestroyKey unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardProcessEncryptedData(
    __in                                            PCARD_DATA              pCardData,
    __in                                            CARD_KEY_HANDLE         hKey,
    __in                                            LPCWSTR                 pwszSecureFunction,
    __in_ecount(cEncryptedData)                     PCARD_ENCRYPTED_DATA    pEncryptedData,
    __in                                            DWORD                   cEncryptedData,
    __out_bcount_part_opt(cbOutput, *pdwOutputLen)  PBYTE                   pbOutput,
    __in                                            DWORD                   cbOutput,
    __out_opt                                       PDWORD                  pdwOutputLen,
    __in                                            DWORD                   dwFlags)
{
    UNUSED (pCardData);
    UNUSED (hKey);
    UNUSED (pwszSecureFunction);
    UNUSED (pEncryptedData);
    UNUSED (cEncryptedData);
    UNUSED (pbOutput);
    UNUSED (cbOutput);
    UNUSED (pdwOutputLen);
    UNUSED (dwFlags);
    logprintf("CardProcessEncryptedData unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

/***************************************************
 * READ - ONLY CARDS
 * YES - OPTIONAL
 *
 * This function SHOULD be implemented according to
 * its definition in this specification, regardless
 * of whether the card is read-only.
 **************************************************/

DWORD WINAPI
CardRSADecrypt(
    __in    PCARD_DATA              pCardData,
    __inout PCARD_RSA_DECRYPT_INFO  pInfo)
{
    UNUSED (pCardData);
    UNUSED (pInfo);
    logprintf("CardRSADecrypt unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardDestroyDHAgreement(
    __in PCARD_DATA pCardData,
    __in BYTE       bSecretAgreementIndex,
    __in DWORD      dwFlags)
{
    UNUSED (pCardData);
    UNUSED (bSecretAgreementIndex);
    UNUSED (dwFlags);
    logprintf("CardDestroyDHAgreement unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardDeriveKey(
    __in    PCARD_DATA pCardData,
    __inout PCARD_DERIVE_KEY pAgreementInfo)
{
    UNUSED (pCardData);
    UNUSED (pAgreementInfo);
    logprintf("CardDeriveKey unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI
CardConstructDHAgreement(
    __in    PCARD_DATA pCardData,
    __inout PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
    UNUSED (pCardData);
    UNUSED (pAgreementInfo);
    logprintf("CardConstructDHAgreement unsuported.\n");
    return SCARD_E_UNSUPPORTED_FEATURE;
}

/***************************************************
 * READ - ONLY CARDS
 * YES
 *
 * This function MUST be implemented according to
 * its definition in this specification, regardless
 * of whether the card is read-only.
 **************************************************/

BOOL WINAPI DllMain(
    __in HANDLE hinstDLL,
    __in DWORD dwReason,
    __in LPVOID lpvReserved)
{
    logprintf("DllMain called - reason: ");

    switch(dwReason) {

        case DLL_PROCESS_ATTACH:
            logprintf("DLL_PROCESS_ATTACH - ");
            if(lpvReserved == NULL) {
                logprintf("dynamic.\n");
            }
            else {
                logprintf("static.\n");
            }
            inst = hinstDLL;
        break;

        case DLL_PROCESS_DETACH:
            logprintf("DLL_PROCESS_DETACH.\n");
            // maybe call CardDeleteContext
        break;

        case DLL_THREAD_ATTACH:
            logprintf("DLL_THREAD_ATTACH.\n");
        break;

        case DLL_THREAD_DETACH:
            logprintf("DLL_THREAD_DETACH.\n");
        break;
    }

    return TRUE;
}

DWORD WINAPI
CardDeleteContext(PCARD_DATA pCardData)
{
    logprintf("CardDeleteContext.\n");

    if (!pCardData) return SCARD_E_INVALID_PARAMETER;

    if (pCardData->pvVendorSpecific)
        pCardData->pfnCspFree(pCardData->pvVendorSpecific);

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardAuthenticatePin(
    __in                   PCARD_DATA   pCardData,
    __in                   LPWSTR       pwszUserId,
    __in_bcount(cbPin)     PBYTE        pbPin,
    __in                   DWORD        cbPin,
    __out_opt              PDWORD       pcAttemptsRemaining)
{
    logprintf("CardAuthenticateEx.\n");

    PIN_ID pinId = 0;

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if (wcscmp(pwszUserId, wszCARD_USER_USER) == 0)	{
        pinId = ROLE_USER;
    }
    else if (wcscmp(pwszUserId, wszCARD_USER_ADMIN) == 0) {
        pinId = ROLE_ADMIN;
    }
    else {
        return SCARD_E_INVALID_PARAMETER;
    }

    if (pbPin == NULL)
        return SCARD_E_INVALID_PARAMETER;

    return CardAuthenticateEx(pCardData, pinId, 0, pbPin, cbPin, NULL, NULL, pcAttemptsRemaining);
}

DWORD WINAPI
CardAuthenticateEx(
    __in                                    PCARD_DATA  pCardData,
    __in                                    PIN_ID      PinId,
    __in                                    DWORD       dwFlags,
    __in_bcount(cbPinData)                  PBYTE       pbPinData,
    __in                                    DWORD       cbPinData,
    __deref_opt_out_bcount(*pcbSessionPin)  PBYTE       *ppbSessionPin,
    __out_opt                               PDWORD      pcbSessionPin,
    __out_opt                               PDWORD      pcAttemptsRemaining)
{
    remsig_token* vendor;
    logprintf("CardAuthenticateEx\n");

    if (!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    logprintf("CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s\n",
        PinId, dwFlags, cbPinData, pcAttemptsRemaining ? "YES" : "NO");

    if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN || dwFlags == CARD_AUTHENTICATE_SESSION_PIN)
        return SCARD_E_UNSUPPORTED_FEATURE;

    if(ppbSessionPin != NULL || pcbSessionPin != NULL)
        return SCARD_E_INVALID_PARAMETER;

    if (dwFlags & ~(CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN | CARD_PIN_SILENT_CONTEXT))
        return SCARD_E_INVALID_PARAMETER;

    if (PinId != ROLE_USER)
        return SCARD_E_INVALID_PARAMETER;

    vendor = pCardData->pvVendorSpecific;
    // -1 means unlimited
    if(pcAttemptsRemaining)
        (*pcAttemptsRemaining) = (DWORD) -1;

    int result = remsig_checkPassword(vendor->certID, (char*)pbPinData);
    // checkPassword
    if(result == 1) {
        // copies pin into the structure
        vendor->pin = malloc(cbPinData);
        memcpy(vendor, pbPinData, cbPinData);
        vendor->authenticated = 1;
    }
    else if (result == -1) {
        return SCARD_E_UNEXPECTED;
    }
    else {
        logprintf("Bad pin.\n");
        return SCARD_W_WRONG_CHV;
    }

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardDeauthenticate(
    __in    PCARD_DATA  pCardData,
    __in    LPWSTR      pwszUserId,
    __in    DWORD       dwFlags)
{
    logprintf("CardDeauthenticate.\n");
    remsig_token* vendor;

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    if (wcscmp(pwszUserId, wszCARD_USER_USER) == 0) {
        vendor = pCardData->pvVendorSpecific;
        free(vendor->pin);
        vendor->pin = NULL;
        vendor->authenticated = 0;
    }

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardDeauthenticateEx(
    __in    PCARD_DATA   pCardData,
    __in    PIN_SET      PinId,
    __in    DWORD        dwFlags)
{

    logprintf("CardDeauthenticateEx : Pin_set = %d\n", PinId);

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    return CardDeauthenticate(pCardData, wszCARD_USER_USER, 0);
}

DWORD WINAPI
CardReadFile(
    __in                            PCARD_DATA  pCardData,
    __in_opt                        LPSTR       pszDirectoryName,
    __in                            LPSTR       pszFileName,
    __in                            DWORD       dwFlags,
    __deref_out_bcount_opt(*pcbData)    PBYTE       *ppbData,
    __out                           PDWORD      pcbData)
{
    remsig_token* vendor;
    logprintf("Reading file %s in %s folder.\n", pszFileName, pszDirectoryName);

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    // root folder
    if(pszDirectoryName == NULL) {
        // reading cardif file, which contains 16 Bytes logn GUID
        if(strcmp(pszFileName, "cardid") == 0){

            *ppbData = pCardData->pfnCspAlloc(GUID_SIZE);
            if(!*ppbData)
                return ERROR_NOT_ENOUGH_MEMORY;

            vendor = pCardData->pvVendorSpecific;
            *pcbData = (DWORD) GUID_SIZE;
            CopyMemory(*ppbData, vendor->guid, GUID_SIZE);
        }
        // reading cardapps file, which contains the name of the application folder
        else if(strcmp(pszFileName, "cardapps") == 0){

            char cardapps[8] = {'m','s','c','p', 0, 0, 0, 0};

            *ppbData = pCardData->pfnCspAlloc(8);
            if(!*ppbData)
                return ERROR_NOT_ENOUGH_MEMORY;

            *pcbData = (DWORD) 8;
            CopyMemory(*ppbData, cardapps, 8);
        }
        // reading card cache file, because the flag CP_CACHE_MODE_NO_CACHE is set, this file is empty
        else if(strcmp(pszFileName, "cardcf") == 0){

            *ppbData = pCardData->pfnCspAlloc(sizeof(CARD_CACHE_FILE_FORMAT));
            if(!*ppbData)
                return ERROR_NOT_ENOUGH_MEMORY;

            *pcbData = sizeof(CARD_CACHE_FILE_FORMAT);
            memset(*ppbData, 0, sizeof(CARD_CACHE_FILE_FORMAT));
        }
        else {
            logprintf("Read-file - file %s not found in root folder.\n", pszFileName);
            return SCARD_E_FILE_NOT_FOUND;
        }
    }
    // mscp folder defined in /cardapps file
    else if(strcmp(pszFileName, "mscp") == 0) {
        // container map file, BaseCSP/KSP works with this file
        if(strcmp(pszFileName, "cmapfile") == 0){
            vendor = pCardData->pvVendorSpecific;
            CONTAINER_MAP_RECORD map;
            memset(&map, 0, sizeof(CONTAINER_MAP_RECORD));

            *ppbData = pCardData->pfnCspAlloc(sizeof(CONTAINER_MAP_RECORD));
            if(!*ppbData)
                return ERROR_NOT_ENOUGH_MEMORY;

            int iReturn = MultiByteToWideChar(CP_UTF8, 0, (char*)vendor->guid, strlen((char*)vendor->guid), map.wszGuid, MAX_CONTAINER_NAME_LEN);
            if (iReturn == 0) {
                logprintf("Error MultiByteToWideChar\n");
                return SCARD_E_UNEXPECTED;
            }

            map.bFlags = CONTAINER_MAP_VALID_CONTAINER | CONTAINER_MAP_DEFAULT_CONTAINER;
            map.bReserved = 0;
            map.wSigKeySizeBits = 2018;
            map.wKeyExchangeKeySizeBits = 0;

            *pcbData = sizeof(CONTAINER_MAP_RECORD);
            CopyMemory(*ppbData, &map, sizeof(CONTAINER_MAP_RECORD));
        }
        // key signature cert 0 - file
        else if(strcmp(pszFileName, "ksc00") == 0){

            vendor = pCardData->pvVendorSpecific;
            *ppbData = pCardData->pfnCspAlloc(strlen((char*)vendor->cert));
            if(!*ppbData)
                return ERROR_NOT_ENOUGH_MEMORY;

            *pcbData = strlen((char*)vendor->cert);
            CopyMemory(*ppbData, vendor->cert, strlen((char*)vendor->cert));
        }
        else {
            logprintf("Read-file - file %s not found in mscp folder.\n", pszFileName);
            return SCARD_E_FILE_NOT_FOUND;
        }
    }
    else {
        logprintf("Read-file - dir %s not found.\n", pszDirectoryName);
        return SCARD_E_DIR_NOT_FOUND;
    }

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardEnumFiles(
    __in                                PCARD_DATA  pCardData,
    __in_opt                            LPSTR       pszDirectoryName,
    __deref_out_ecount(*pdwcbFileName)  LPSTR      *pmszFileNames,
    __out                               LPDWORD     pdwcbFileName,
    __in                                DWORD       dwFlags)
{
    logprintf("CardEnumFiles.\n");
    char output[100] = {0};
    int size = 0;

    if (!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if (dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    if (pszDirectoryName == NULL) {
        strcpy(output, "cardid");
        size += strlen("cardid");
        strcat(output, "\0");
        size += 1;
        strcat(output, "cardcf");
        size += strlen("cardcf");
        strcat(output, "\0");
        size += 1;
        strcat(output, "cardapps");
        size += strlen("cardapps");
        strcat(output, "\0");
        size += 1;
        strcat(output, "\0");
        size += 1;
    }
    else if (strcmp(pszDirectoryName, "mscp") == 0){
        strcpy(output, "cmapfile");
        size += strlen("cmapfile");
        strcat(output, "\0");
        size += 1;
        strcat(output, "ksc00");
        size += strlen("ksc00");
        strcat(output, "\0");
        size += 1;
        strcat(output, "\0");
        size += 1;
    }
    else {
        return SCARD_E_DIR_NOT_FOUND;
    }

    *pmszFileNames = (LPSTR)pCardData->pfnCspAlloc(size);
    if (*pmszFileNames == NULL)
        return SCARD_E_NO_MEMORY;

    CopyMemory(*pmszFileNames, output, size);
    *pdwcbFileName = (DWORD) size;

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardGetFileInfo(
    __in        PCARD_DATA      pCardData,
    __in_opt    LPSTR           pszDirectoryName,
    __in        LPSTR           pszFileName,
    __inout     PCARD_FILE_INFO pCardFileInfo)
{
    logprintf("CardGetFileInfo - file %s in %s folder.\n", pszDirectoryName, pszFileName);

    if (!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(!pszFileName)
        return SCARD_E_INVALID_PARAMETER;

    if(!pCardFileInfo)
        return SCARD_E_INVALID_PARAMETER;

    if(pCardFileInfo->dwVersion != CARD_FILE_INFO_CURRENT_VERSION || pCardFileInfo->dwVersion != 0)
        return ERROR_REVISION_MISMATCH;

    if (pszDirectoryName == NULL) {
        if(strcmp(pszFileName, "cardid") == 0){
            pCardFileInfo->cbFileSize = GUID_SIZE;
        }
        else if(strcmp(pszFileName, "cardapps") == 0){
            pCardFileInfo->cbFileSize = 8;
        }
        else if(strcmp(pszFileName, "cardcf") == 0){
            pCardFileInfo->cbFileSize = sizeof(CARD_CACHE_FILE_FORMAT);
        }
        else {
            return SCARD_E_FILE_NOT_FOUND;
        }
    }
    else if (strcmp(pszDirectoryName, "mscp") == 0) {
        if(strcmp(pszFileName, "cmapfile") == 0){
            pCardFileInfo->cbFileSize = sizeof(CONTAINER_MAP_RECORD);
        }
        else if(strcmp(pszFileName, "ksc00") == 0){
            pCardFileInfo->cbFileSize = sizeof(PCONTAINER_INFO);  // check this valueeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
        }
        else {
            return SCARD_E_FILE_NOT_FOUND;
        }
    }
    else {
        return SCARD_E_DIR_NOT_FOUND;
    }

    pCardFileInfo->AccessCondition = EveryoneReadAdminWriteAc;
    pCardFileInfo->dwVersion = CARD_FILE_INFO_CURRENT_VERSION;

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardGetContainerProperty(
    __in                                        PCARD_DATA  pCardData,
    __in                                        BYTE        bContainerIndex,
    __in                                        LPCWSTR     wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen)  PBYTE       pbData,
    __in                                        DWORD       cbData,
    __out                                       PDWORD      pdwDataLen,
    __in                                        DWORD       dwFlags)
{
    logprintf("CardGetContainerProperty - container number %d.\n", bContainerIndex);

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(bContainerIndex != 0)
        return SCARD_E_NO_KEY_CONTAINER;

    if(dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    if(!pbData)
        return SCARD_E_INVALID_PARAMETER;

    if(!pdwDataLen)
         return SCARD_E_INVALID_PARAMETER;

    if(!wszProperty)
         return SCARD_E_INVALID_PARAMETER;

    if(wcscmp(CCP_CONTAINER_INFO,wszProperty) == 0) {

        PCONTAINER_INFO p = (PCONTAINER_INFO) pbData;
        if (pdwDataLen)
            *pdwDataLen = sizeof(*p);

        if (cbData >= sizeof(DWORD))
            if (p->dwVersion != CONTAINER_INFO_CURRENT_VERSION && p->dwVersion != 0 )
                return ERROR_REVISION_MISMATCH;
        if (cbData < sizeof(*p))
            return ERROR_INSUFFICIENT_BUFFER;

        return CardGetContainerInfo(pCardData, bContainerIndex, 0, p);
    }
    else if (wcscmp(CCP_PIN_IDENTIFIER,wszProperty)  == 0) {
        PPIN_ID p = (PPIN_ID) pbData;
        if (pdwDataLen)
            *pdwDataLen = sizeof(*p);

        if (cbData < sizeof(*p))
            return ERROR_INSUFFICIENT_BUFFER;

        *p = ROLE_USER;
    }
    else if (wcscmp(CCP_ASSOCIATED_ECDH_KEY,wszProperty)  == 0) {
        logprintf("Unsupported property - ccp_associated_ecdh_key.\n");
        return SCARD_E_INVALID_PARAMETER;
    }
    else {
        logprintf("Unsupported property.\n");
        return SCARD_E_INVALID_PARAMETER;
    }

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardGetContainerInfo(
    __in    PCARD_DATA      pCardData,
    __in    BYTE            bContainerIndex,
    __in    DWORD           dwFlags,
    __inout PCONTAINER_INFO pContainerInfo)
{
    remsig_token* vendor;
    logprintf("CardGetContainerInfo - container number %d.\n", bContainerIndex);

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    if(bContainerIndex != 0)
        return  SCARD_E_NO_KEY_CONTAINER;

    if(!pContainerInfo)
        return SCARD_E_INVALID_PARAMETER;

    if(pContainerInfo->dwVersion != CONTAINER_INFO_CURRENT_VERSION)
        return ERROR_REVISION_MISMATCH;

    vendor = pCardData->pvVendorSpecific;
    pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;
    pContainerInfo->dwReserved = 0;
    // pointer to the certificate
    pContainerInfo->pbSigPublicKey = vendor->cert;
    pContainerInfo->cbSigPublicKey = strlen((char*)vendor->cert);
    // key exchange key is empty
    pContainerInfo->pbKeyExPublicKey = NULL;
    pContainerInfo->cbKeyExPublicKey = 0;

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardQueryCapabilities(
    __in      PCARD_DATA          pCardData,
    __inout   PCARD_CAPABILITIES  pCardCapabilities)
{
    logprintf("QueryFreeSpace was called.\n");

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(!pCardCapabilities)
        return SCARD_E_INVALID_PARAMETER;

    if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION && pCardCapabilities->dwVersion != 0)
            return ERROR_REVISION_MISMATCH;

    // Token cannot generate keys,  token implements its own compression of certificates, no BaseCSP compression
    pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
    pCardCapabilities->fCertificateCompression = TRUE;
    pCardCapabilities->fKeyGen = FALSE;

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardQueryFreeSpace(
    __in    PCARD_DATA              pCardData,
    __in    DWORD                   dwFlags,
    __inout PCARD_FREE_SPACE_INFO   pCardFreeSpaceInfo)
{
    logprintf("QueryFreeSpace was called.\n");

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    if(!pCardFreeSpaceInfo)
        return SCARD_E_INVALID_PARAMETER;

    if(pCardFreeSpaceInfo->dwVersion != CARD_FREE_SPACE_INFO_CURRENT_VERSION && pCardFreeSpaceInfo->dwVersion != 0)
        return ERROR_REVISION_MISMATCH;

    // token owns only 1 container, no free space left - read-only property
    pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
    pCardFreeSpaceInfo->dwBytesAvailable = 0;
    pCardFreeSpaceInfo->dwKeyContainersAvailable = 0;
    pCardFreeSpaceInfo->dwMaxKeyContainers = 1;

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardQueryKeySizes(
    __in    PCARD_DATA      pCardData,
    __in    DWORD           dwKeySpec,
    __in    DWORD           dwFlags,
    __inout PCARD_KEY_SIZES pKeySizes)
{
    logprintf("CardQueryKeySizes was called - %d.\n", dwKeySpec);

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    if(!pKeySizes)
        return SCARD_E_INVALID_PARAMETER;

    if(dwKeySpec != AT_SIGNATURE)
        return SCARD_E_INVALID_PARAMETER;

    if(pKeySizes->dwVersion != CARD_KEY_SIZES_CURRENT_VERSION && pKeySizes->dwVersion != 0)
        return ERROR_REVISION_MISMATCH;

    pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
    pKeySizes->dwMinimumBitlen = minBitlen;
    pKeySizes->dwMaximumBitlen = maxBitlen;
    pKeySizes->dwDefaultBitlen = defaultBitLen;
    pKeySizes->dwIncrementalBitlen = incrBitLen;

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardSignData(
    __in    PCARD_DATA          pCardData,
    __inout PCARD_SIGNING_INFO  pInfo)
{
    BYTE* signature = NULL;
    remsig_token* vendor = NULL;

    logprintf("Signing data.\n");

    if(!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if(!pInfo)
        return SCARD_E_INVALID_PARAMETER;

    if(!pInfo->pbData)
        return SCARD_E_INVALID_PARAMETER;

    if(pInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION || pInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION)
        return ERROR_REVISION_MISMATCH;

    if(pInfo->bContainerIndex != 0)
        return SCARD_E_NO_KEY_CONTAINER;

    if(!pInfo->dwKeySpec)
        return SCARD_E_INVALID_PARAMETER;

    if(pInfo->dwKeySpec != AT_SIGNATURE)
        return SCARD_E_UNSUPPORTED_FEATURE;

    if(pInfo->aiHashAlg != CALG_SHA_256)
        return SCARD_E_UNSUPPORTED_FEATURE;

    vendor = pCardData->pvVendorSpecific;

    if(vendor->authenticated != 1)
        return SCARD_W_SECURITY_VIOLATION;

    // performs remsig signing
    signature = remsig_sign(vendor, pInfo->pbData, pInfo->cbData);
    if(signature == NULL)
        return SCARD_E_UNEXPECTED;

    // copies signature to the structure
    pInfo->cbSignedData = strlen((char*)signature);
    pInfo->pbSignedData = pCardData->pfnCspAlloc(pInfo->cbSignedData);
    CopyMemory(pInfo->pbSignedData, signature, pInfo->cbSignedData);
    free(signature);

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardGetProperty(
    __in                                        PCARD_DATA  pCardData,
    __in                                        LPCWSTR     wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen)  PBYTE       pbData,
    __in                                        DWORD       cbData,
    __out                                       PDWORD      pdwDataLen,
    __in                                        DWORD       dwFlags)
{
    remsig_token* vendor;
    logprintf("CardGetProperty.\n");

    if (!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if (!wszProperty)
        return SCARD_E_INVALID_PARAMETER;

    if (!pbData)
        return SCARD_E_INVALID_PARAMETER;

    if (!pdwDataLen)
        return SCARD_E_INVALID_PARAMETER;

    if (dwFlags && ((wcscmp(CP_CARD_PIN_STRENGTH_VERIFY,wszProperty) != 0)
        || (wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0)
        || (wcscmp(CP_CARD_KEYSIZES,wszProperty) == 0)))
            return SCARD_E_INVALID_PARAMETER;

    vendor = pCardData->pvVendorSpecific;

    if (wcscmp(CP_CARD_FREE_SPACE,wszProperty) == 0) {
        // CARD FREE SPACE INFO
        if (pdwDataLen)
            *pdwDataLen = sizeof(PCARD_FREE_SPACE_INFO);

        if (cbData < sizeof(PCARD_FREE_SPACE_INFO))
            return ERROR_INSUFFICIENT_BUFFER;

        return CardQueryFreeSpace(pCardData, 0, (PCARD_FREE_SPACE_INFO) pbData);
    }
    else if (wcscmp(CP_CARD_CAPABILITIES, wszProperty) == 0) {
        // CARD CAPABALITIES INFO
        if (pdwDataLen)
            *pdwDataLen = sizeof(PCARD_CAPABILITIES);

        if (cbData < sizeof(PCARD_CAPABILITIES))
            return ERROR_INSUFFICIENT_BUFFER;


        return CardQueryCapabilities(pCardData, (PCARD_CAPABILITIES) pbData);
    }
    else if (wcscmp(CP_CARD_KEYSIZES,wszProperty) == 0) {
        // CARD KEY SIZE INFO
        if (pdwDataLen)
            *pdwDataLen = sizeof(PCARD_KEY_SIZES);

        if (cbData < sizeof(PCARD_KEY_SIZES))
            return ERROR_INSUFFICIENT_BUFFER;       

        return CardQueryKeySizes(pCardData, dwFlags, 0, (PCARD_KEY_SIZES) pbData);
    }
    else if (wcscmp(CP_CARD_READ_ONLY, wszProperty) == 0) {
        // READ-ONLY INFO
        BOOL *p = (BOOL *)pbData;

        if (pdwDataLen)
            *pdwDataLen = sizeof(BOOL);

        if (cbData < sizeof(BOOL))
            return ERROR_INSUFFICIENT_BUFFER;

        *p = TRUE;
    }
    else if (wcscmp(CP_CARD_CACHE_MODE, wszProperty) == 0) {
        // CARD CACHE MODE INFO
        DWORD *p = (DWORD *)pbData;

        if (pdwDataLen)
            *pdwDataLen = sizeof(DWORD);

        if (cbData < sizeof(DWORD))
            return ERROR_INSUFFICIENT_BUFFER;

        *p = CP_CACHE_MODE_NO_CACHE;
    }
    else if (wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT, wszProperty) == 0) {
        // X509 ENROLLMENT INFO
        BOOL *p = (BOOL*)pbData;

        if (pdwDataLen)
            *pdwDataLen = sizeof(BOOL);

        if (cbData < sizeof(BOOL))
            return ERROR_INSUFFICIENT_BUFFER;

        *p = FALSE;
    }
    else if (wcscmp(CP_CARD_GUID, wszProperty) == 0)   {
        // GUID INFO
        if (pdwDataLen)
            *pdwDataLen = (DWORD) GUID_SIZE;

        if (cbData < GUID_SIZE)
            return ERROR_INSUFFICIENT_BUFFER;

        CopyMemory(pbData, vendor->guid, GUID_SIZE);
    }
    else if (wcscmp(CP_CARD_SERIAL_NO, wszProperty) == 0)   {
        // CARD SERIAL NUMBER - same as remsig certificate serial number
        size_t buf_len = strlen((char*)vendor->serial);

        if (pdwDataLen)
            *pdwDataLen = (DWORD) buf_len;

        if (cbData < buf_len)
            return ERROR_INSUFFICIENT_BUFFER;

        CopyMemory(pbData, vendor->serial, buf_len);
    }
    else if (wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0)   {
        // CARD PIN INFO
        PPIN_INFO p = (PPIN_INFO) pbData;

        if (pdwDataLen)
            *pdwDataLen = sizeof(PIN_INFO);

        if (cbData < sizeof(PIN_INFO))
            return ERROR_INSUFFICIENT_BUFFER;

        if (p->dwVersion != PIN_INFO_CURRENT_VERSION)
            return ERROR_REVISION_MISMATCH;

        p->PinType = AlphaNumericPinType;
        p->dwFlags = 0;
        switch (dwFlags) {
            case ROLE_USER:
                logprintf("returning info on PIN ROLE_USER ( Auth ) [%u]\n",dwFlags);
                p->PinPurpose = DigitalSignaturePin;
                p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
                p->PinCachePolicy.dwPinCachePolicyInfo = 0;
                p->PinCachePolicy.PinCachePolicyType = PinCacheNormal; // pin_no_cache
                p->dwChangePermission = CREATE_PIN_SET(ROLE_USER);
                p->dwUnblockPermission = CREATE_PIN_SET(ROLE_ADMIN);
                break;
            case ROLE_ADMIN:
                logprintf("returning info on PIN ROLE_ADMIN ( Unblock ) [%u]\n",dwFlags);
                p->PinPurpose = UnblockOnlyPin;
                p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
                p->PinCachePolicy.dwPinCachePolicyInfo = 0;
                p->PinCachePolicy.PinCachePolicyType = PinCacheNormal; // pin_no_cache
                p->dwChangePermission = CREATE_PIN_SET(ROLE_ADMIN);
                p->dwUnblockPermission = 0;
                break;
            default:
                logprintf("Invalid Pin number %u requested\n",dwFlags);
                return SCARD_E_INVALID_PARAMETER;
        }
    }
    else if (wcscmp(CP_CARD_LIST_PINS,wszProperty) == 0)   {
        // LIST PINS
        PPIN_SET p = (PPIN_SET) pbData;

        if (pdwDataLen)
            *pdwDataLen = sizeof(*p);

        if (cbData < sizeof(*p))
            return ERROR_INSUFFICIENT_BUFFER;     

        SET_PIN(*p, ROLE_USER);
    }
    else if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY,wszProperty) == 0)   {
        // PIN STRENGHT
        DWORD *p = (DWORD *)pbData;

        if (dwFlags != ROLE_USER)
            return SCARD_E_INVALID_PARAMETER;

        if (pdwDataLen)
            *pdwDataLen = sizeof(DWORD);

        if (cbData < sizeof(DWORD))
            return ERROR_INSUFFICIENT_BUFFER;


        *p = CARD_PIN_STRENGTH_PLAINTEXT;
    }
    else if (wcscmp(CP_KEY_IMPORT_SUPPORT, wszProperty) == 0)   {
        // KEY IMPORT
        DWORD *p = (DWORD *)pbData;

        if (pdwDataLen)
            *pdwDataLen = sizeof(DWORD);

        if (cbData < sizeof(DWORD))
            return ERROR_INSUFFICIENT_BUFFER;

        *p = 0;
    }
    else {
       logprintf("Unsupported property '%S'\n", wszProperty);
       return SCARD_E_INVALID_PARAMETER;
    }

    return SCARD_S_SUCCESS;
}

DWORD WINAPI
CardSetProperty(
    __in                    PCARD_DATA  pCardData,
    __in                    LPCWSTR     wszProperty,
    __in_bcount(cbDataLen)  PBYTE       pbData,
    __in                    DWORD       cbDataLen,
    __in                    DWORD       dwFlags)
{
    remsig_token* vendor;
    logprintf("CardSetProperty.\n");
    logprintf("Property %s - value %s, size %d.\n", wszProperty, pbData, cbDataLen);

    if (!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if (dwFlags)
        return SCARD_E_INVALID_PARAMETER;

    if (wcscmp(wszProperty, CP_CARD_FREE_SPACE) == 0 ||             // always read-only, cannot be set
        wcscmp(wszProperty, CP_CARD_CAPABILITIES) == 0 ||           // .
        wcscmp(wszProperty, CP_CARD_KEYSIZES) == 0 ||               // .
        wcscmp(wszProperty, CP_CARD_LIST_PINS) == 0 ||              // .
        wcscmp(wszProperty, CP_CARD_AUTHENTICATED_STATE) == 0 ||    // .
        wcscmp(wszProperty, CP_KEY_IMPORT_SUPPORT) == 0 ||          // .
        wcscmp(wszProperty, CP_ENUM_ALGORITHMS) == 0 ||             // .
        wcscmp(wszProperty, CP_PADDING_SCHEMES) == 0 ||             // .
        wcscmp(wszProperty, CP_CHAINING_MODES) == 0)                // always read-only
            return SCARD_E_UNSUPPORTED_FEATURE;

    else if (wcscmp(wszProperty, CP_CARD_CACHE_MODE) == 0 ||            // for read-only cards, cannot be set
        wcscmp(wszProperty, CP_SUPPORTS_WIN_X509_ENROLLMENT) == 0 ||    // .
        wcscmp(wszProperty, CP_CARD_GUID) == 0 ||                       // .
        wcscmp(wszProperty, CP_CARD_PIN_INFO) == 0 ||                   // .
        wcscmp(wszProperty, CP_PARENT_WINDOW) == 0 ||                   // .
        wcscmp(wszProperty, CP_PIN_CONTEXT_STRING) == 0 ||              // .
        wcscmp(wszProperty, CP_CARD_PIN_STRENGTH_VERIFY) == 0 ||        // .
        wcscmp(wszProperty, CP_CARD_PIN_STRENGTH_CHANGE) == 0 ||        // .
        wcscmp(wszProperty, CP_CARD_PIN_STRENGTH_UNBLOCK) == 0 ||       // .
        wcscmp(wszProperty, CP_CARD_SERIAL_NO) == 0)                    // for read-only cards, cannot be set
            return SCARD_W_SECURITY_VIOLATION;

    else if (wcscmp(wszProperty, CP_CARD_READ_ONLY) == 0) {
        logprintf("Changing read-only state - unsupported.\n");
        vendor = pCardData->pvVendorSpecific;
        // checks if admin is logged in
        if(vendor->authenticated != 2)
            return SCARD_W_SECURITY_VIOLATION;

        // cannot be changed
        return SCARD_E_UNSUPPORTED_FEATURE;
    }
    else {
        return SCARD_E_INVALID_PARAMETER;
    }
}


DWORD WINAPI
CardAcquireContext(
    __inout     PCARD_DATA  pCardData,
    __in        DWORD       dwFlags)
{
    logprintf("CardAcquireContext called.\n");
    DWORD suppliedVersion = 0;
    remsig_token* vendor;

    if (!pCardData)
        return SCARD_E_INVALID_PARAMETER;

    if (dwFlags)
        return SCARD_E_UNSUPPORTED_FEATURE;

    if (!(dwFlags & CARD_SECURE_KEY_INJECTION_NO_CARD_MODE)) {
        if( pCardData->hSCardCtx == 0) {
            logprintf("Invalide handle.\n");
            return SCARD_E_INVALID_HANDLE;
        }
        if( pCardData->hScard == 0) {
            logprintf("Invalide handle.\n");
            return SCARD_E_INVALID_HANDLE;
        }
    }
    else {
        // secure key injection not supported
        return SCARD_E_UNSUPPORTED_FEATURE;
    }

    if (!pCardData->pbAtr)
        return SCARD_E_INVALID_PARAMETER;
    if (!pCardData->pwszCardName)
        return SCARD_E_INVALID_PARAMETER;

//    /* <2 lenght or >=0x22 are not ISO compliant */
//    if (pCardData->cbAtr >= 0x22 || pCardData->cbAtr <= 0x2)
//        return SCARD_E_INVALID_PARAMETER;
//    /* ATR beginning by 0x00 or 0xFF are not ISO compliant */
//    if (pCardData->pbAtr[0] == 0xFF || pCardData->pbAtr[0] == 0x00)
//        return SCARD_E_UNKNOWN_CARD;

    // Memory management functions
    if (( pCardData->pfnCspAlloc   == NULL ) ||
        ( pCardData->pfnCspReAlloc == NULL ) ||
        ( pCardData->pfnCspFree    == NULL ))
            return SCARD_E_INVALID_PARAMETER;

    // The lowest supported version is 4 - current is 7.
    if (pCardData->dwVersion < MINIMUM_VERSION_SUPPORTED)
        return ERROR_REVISION_MISMATCH;

    suppliedVersion = pCardData->dwVersion;

    // sets remsig vendor specific informations
    vendor = malloc(sizeof(remsig_token));
    pCardData->pvVendorSpecific = vendor;
    vendor->state = 0;
    load_token(vendor);
    // checks loading status, 1 is OK, otherwise 0
    if(vendor->state != 1)
        return SCARD_E_UNEXPECTED;

    // functions with NULL comment aren't implemented
    pCardData->pfnCardDeleteContext = CardDeleteContext;
    pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
    pCardData->pfnCardDeleteContainer = CardDeleteContainer; // NULL
    pCardData->pfnCardCreateContainer = CardCreateContainer; // NULL
    pCardData->pfnCardGetContainerInfo = CardGetContainerInfo;
    pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;
    pCardData->pfnCardGetChallenge = CardGetChallenge; // NULL
    pCardData->pfnCardAuthenticateChallenge = CardAuthenticateChallenge; // NULL
    pCardData->pfnCardUnblockPin = CardUnblockPin; // NULL
    pCardData->pfnCardChangeAuthenticator = CardChangeAuthenticator; // NULL
    pCardData->pfnCardDeauthenticate = CardDeauthenticate;
    pCardData->pfnCardCreateDirectory = CardCreateDirectory; // NULL
    pCardData->pfnCardDeleteDirectory = CardDeleteDirectory; // NULL
    pCardData->pvUnused3 = NULL;
    pCardData->pvUnused4 = NULL;
    pCardData->pfnCardCreateFile = CardCreateFile; // NULL
    pCardData->pfnCardReadFile = CardReadFile;
    pCardData->pfnCardWriteFile = CardWriteFile; // NULL
    pCardData->pfnCardDeleteFile = CardDeleteFile; // NULL
    pCardData->pfnCardEnumFiles = CardEnumFiles;
    pCardData->pfnCardGetFileInfo = CardGetFileInfo;
    pCardData->pfnCardQueryFreeSpace = CardQueryFreeSpace;
    pCardData->pfnCardQueryKeySizes = CardQueryKeySizes;
    pCardData->pfnCardSignData = CardSignData;
    pCardData->pfnCardRSADecrypt = CardRSADecrypt; // NULL
    pCardData->pfnCardConstructDHAgreement = CardConstructDHAgreement; // NULL

    logprintf("Supplied version %u - version used %u.\n", suppliedVersion, pCardData->dwVersion);

    if (pCardData->dwVersion >= CARD_DATA_VERSION_FIVE) {
        pCardData->pfnCardDeriveKey = CardDeriveKey; // NULL
        pCardData->pfnCardDestroyDHAgreement = CardDestroyDHAgreement; // NULL

        if (pCardData->dwVersion >= CARD_DATA_VERSION_SIX) {
            pCardData->pfnCardGetChallengeEx = CardGetChallengeEx; // NULL
            pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
            pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx; // NULL
            pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
            pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
            pCardData->pfnCardSetContainerProperty = CardSetContainerProperty; // NULL
            pCardData->pfnCardGetProperty = CardGetProperty;
            pCardData->pfnCardSetProperty = CardSetProperty;

            if (pCardData->dwVersion >= CARD_DATA_VERSION_SEVEN) {
                pCardData->pfnMDImportSessionKey         = MDImportSessionKey; // NULL
                pCardData->pfnMDEncryptData              = MDEncryptData; // NULL
                pCardData->pfnCardImportSessionKey       = CardImportSessionKey; // NULL
                pCardData->pfnCardGetSharedKeyHandle     = CardGetSharedKeyHandle; // NULL
                pCardData->pfnCardGetAlgorithmProperty   = CardGetAlgorithmProperty; // NULL
                pCardData->pfnCardGetKeyProperty         = CardGetKeyProperty; // NULL
                pCardData->pfnCardSetKeyProperty         = CardSetKeyProperty; // NULL
                pCardData->pfnCardProcessEncryptedData   = CardProcessEncryptedData; // NULL
                pCardData->pfnCardDestroyKey             = CardDestroyKey; // NULL
                pCardData->pfnCardCreateContainerEx      = CardCreateContainerEx; // NULL
            }
        }
    }

    return SCARD_S_SUCCESS;
}

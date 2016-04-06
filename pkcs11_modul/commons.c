#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <libxml2/libxml/tree.h>
#include <libxml2/libxml/parser.h>

#define PEER_VERIFICATION
#define HOST_VERIFICATION

struct Response {
  char* data;
  size_t size;
};

struct Certificate {
    int id;
    char dn[2048];
    char serial[2048];
    char issuer[2048];
};

size_t callback(void *contents, size_t size, size_t nmemb, void *userp) {

    size_t realsize = size * nmemb;
    struct Response *mem = (struct Response *)userp;

    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if(mem->data == NULL) {
        // cannot alocate memory
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

struct Response curl_post_with_header(const char* url, const char* d_post, const char* header) {

    CURLcode res;
    CURL* curl;

    struct Response response = {0};
    response.data = malloc(1);
    if(response.data == NULL) {
        puts("Error during malloc");
        return response;
    }
    response.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "Couldn't initialize the CURL\n");
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
        fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
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

        return find_signature(cur_node->children);
    }
    return NULL;
}

xmlDocPtr createRemsigDocument() {

    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;
    //creating new document
    doc = xmlNewDoc(BAD_CAST "1.0");
    //setting root node: remsig
    root_node = xmlNewNode(NULL, BAD_CAST "remsig");
    xmlDocSetRootElement(doc, root_node);

    return doc;
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

int numbOfObjects(char* xml, int size) {

    xmlDoc *doc = NULL; /* the resulting document tree */
    xmlNode *root_element = NULL;
    int count = 0;

    doc = xmlReadMemory(xml, size, NULL, NULL, 0);

    root_element = xmlDocGetRootElement(doc);

    for (xmlNode *cur_node = root_element->children; cur_node; cur_node = cur_node->next) {
        if ((cur_node->type == XML_ELEMENT_NODE)&&(strcmp((char*)cur_node->name, "certificate") == 0)) {
            count++;
        }
        else {
            xmlFreeDoc(doc);
            xmlCleanupParser();
            xmlMemoryDump();
            return -1;
        }
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();

    return count;
}

void xml_list_parse(char* xml, int size) {

}

char* remsig_list(char* accessToken, char* uco) {

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

    header = malloc((strlen(bearer) + strlen(accessToken) + 1) * sizeof(char));

    strcpy(header, bearer);
    strcat(header, accessToken);
    strcat(header, "\0");

    doc = createRemsigDocument();

    root_node = xmlDocGetRootElement(doc);
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

    xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

    res = curl_post_with_header(list, (char*) xmlbuff, header);

    xml_list_parse(res.data, res.size);


    return NULL;

    xml_Error:

    if (doc != NULL)  xmlFreeDoc(doc);
    xmlCleanupParser();
    return NULL;
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

    doc = createRemsigDocument(); /* document pointer */
    root_node = xmlDocGetRootElement(doc);
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


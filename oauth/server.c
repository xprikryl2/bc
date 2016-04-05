#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "loging.c"

#ifdef __linux__
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
#endif

#ifdef _WIN32
    #include <winsock2.h>
#endif

void plusToSpace(char* string) {
    if(string == NULL) {
        return;
    }
    int i = 0;
    while(string[i] != '\0'){
        if(string[i] == '+') {
            string[i] = ' ';
        }
        i++;
    }
}

char* process(char* state, char* string) {

    char error_m[4096] = "Error: ";
    char* p = NULL;
    char state_get[4096] = "state=";
    char* code = NULL;
    p = strtok(string, "?");
    p = strtok(NULL, "=");

    while( p != NULL) {

        if( strcmp(p, "state") == 0) {
            p = strtok(NULL, "  &");
            plusToSpace(p);
            strcat(state_get, p);
            strcat(state_get, "\0");
        }

        else if( strcmp(p, "code") == 0) {
            p = strtok(NULL, "  &");
            code = malloc((strlen(p) + 5 + 1) * sizeof(char));
            strcpy(code, "code=");
            strcat(code, p);
            strcat(code, "\0");
        }

        else if( strcmp(p, "error") == 0) {
            p = strtok(NULL, "  &");
            strcat(error_m, p);
            makeLog(2, error_m);
            return NULL;
        }

        else if( strcmp(p, "error_description") == 0) {
            p = strtok(NULL, "  &");
            strcat(error_m, p);
            makeLog(2, error_m);
            return NULL;
        }

        else if( strcmp(p, "error_uri") == 0) {
            p = strtok(NULL, "  &");
            strcat(error_m, p);
            makeLog(2, error_m);
            return NULL;
        }
        p = strtok(NULL, "=");
    }

    if(code == NULL) {
        makeLog(2, "Error: Missing code.\n");
        return NULL;
    }

    if((state != NULL && state_get == NULL)||(state == NULL && state_get != NULL)) {
        makeLog(2, "Error: Missing state.\n");
        return NULL;
    }

    if(state != NULL && state_get != NULL) {
        if(strcmp(state, state_get) != 0) {
            makeLog(2, "Error: Different states.\n");
            return NULL;
        }
    }

    makeLog(0, "Code extracted.\n");
    return code;
}

char* server(int port, char* state) {

    #ifdef _WIN32
        WSADATA wsa;
        SOCKET s, new_socket;
        int c;
    #endif

    #ifdef __linux__
        int s, new_socket;
        unsigned int c;
    #endif

    struct sockaddr_in server, client;
    char buffer[20] = {0};
    char* data = NULL;
    char* code = NULL;
    int bytes_read;
    int total = 1;

    //printf("Creating localhost server on port %d.\n", port);
    //printf("---------------------------------------\n");

    #ifdef _WIN32
        // Initialising
        makeLog(2, "Initialising Winsock...");
        if (WSAStartup(MAKEWORD(2,2),&wsa) != 0) {
            makeLog(2, "Failed. Error Code : %d.\n",WSAGetLastError());
            goto error_clenup_0;
        }
        //printf("Initialised.\n");
    #endif


    // Create a socket
    #ifdef _WIN32
        if((s = socket(AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET) {
            makeLog(2, "Could not create socket : %d.\n" , WSAGetLastError());
            goto error_clenup_1;
        }
    #endif
    #ifdef __linux__
        if((s = socket(AF_INET , SOCK_STREAM , 0 )) < 0) {
            makeLog(2, "Could not create socket.\n");
            goto error_clenup_1;
        }
    #endif
    //printf("Socket created.\n");

    // Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(port);

    // Bind
    #ifdef _WIN32
        if( bind(s ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR) {
            makeLog(2, "Bind failed with error code : %d.\n" , WSAGetLastError());
            goto error_clenup_1;
        }
    #endif
    #ifdef __linux__
        if( bind(s ,(struct sockaddr *)&server , sizeof(server)) < 0) {
            makeLog(2, "Bind failed.\n");
            makeLog(2, "Port already in use.\n");
            goto error_clenup_1;
        }
    #endif
    //puts("Bind done.");

    // Listen to incoming connections
    #ifdef _WIN32
        if(listen(s , 5) == SOCKET_ERROR) {
            makeLog(2, "Listening failed with error code : %d.\n" , WSAGetLastError());
            goto error_clenup_1;
        }
    #endif
    #ifdef __linux__
        if(listen(s , 5) < 0 ) {
            makeLog(2, "Listening failed.\n");
            goto error_clenup_1;
        }
    #endif

    // Accept and incoming connection
    //puts("Waiting for incoming connections...");

    c = sizeof(client);
    new_socket = accept(s , (struct sockaddr *)&client, &c);
    #ifdef _WIN32
        if (new_socket == INVALID_SOCKET) {
            makeLog(2, "Accept failed with error code : %d" , WSAGetLastError());
            goto error_clenup;
        }
    #endif
    #ifdef __linux__
        if (new_socket < 0) {
            makeLog(2, "Accept failed.\n");
            goto error_clenup;
        }
    #endif
    //puts("Connection accepted.");

    // Read data
    data = malloc(sizeof(char));
    if(data == NULL) {
        makeLog(2, "Error during memory alloc. Not enought space.");
        free(data);
        goto error_clenup;
    }
    strcpy(data, "\0");
    do{
        bytes_read = 0;
        bytes_read = recv(new_socket, buffer, sizeof(buffer) - 1, 0);
        strcat(buffer, "\0");
        #ifdef _WIN32
            if(bytes_read == SOCKET_ERROR) {
                makeLog(2, "Receive failed with error code : %d.\n" , WSAGetLastError());
                free(data);
                goto error_clenup;
            }
        #endif
        #ifdef __linux__
            if(bytes_read < 0) {
                makeLog(2, "Receive failed.\n");
                free(data);
                goto error_clenup;
            }
        #endif
        if(bytes_read > 0) {
             total = total + bytes_read + 1;
             data = realloc(data, total * sizeof(char));
             if(data == NULL) {
                 makeLog(2, "Error (re)allocating memory");
                 free(data);
                 goto error_clenup;
             }
             strcat(data, buffer);
        }
    }while (bytes_read >= 19);
    strcat(data, "\0");
    //printf("Read: %d bytes.\n", total);

    // Sending answer
    char* msg = "<html><head><title>Response</title></head><body>You have been successfully logged in. You can return to your application.</body></html>";
    #ifdef _WIN32
        if (send(new_socket, msg, strlen(msg), 0) == SOCKET_ERROR) {
            makeLog(2, "Send failed with error code : %d" , WSAGetLastError());
            free(data);
            goto error_clenup;
        }
    #endif
    #ifdef __linux__
        if (send(new_socket, msg, strlen(msg), 0) < 0) {
            makeLog(2, "Send failed.");
            free(data);
            goto error_clenup;
        }
    #endif

    // Process data
    code = process(state, data);

    if(code == NULL){
        makeLog(2, "Bad response.");
        free(data);
        goto error_clenup;
    }


    // Cleanup sockets
    #ifdef _WIN32
        closesocket(new_socket);
        closesocket(s);
        WSACleanup();
    #endif
    #ifdef __linux__
        close(new_socket);
        close(s);
    #endif

    free(data);
    return code;

    #ifdef _WIN32
        error_clenup_0:
            WSACleanup();
            return NULL;
    #endif

    error_clenup_1:
        #ifdef _WIN32
            closesocket(s);
            WSACleanup();
        #endif
        #ifdef __linux__
            close(s);
        #endif
        return NULL;


    error_clenup:
        #ifdef _WIN32
            closesocket(new_socket);
            closesocket(s);
            WSACleanup();
        #endif
        #ifdef __linux__
            close(new_socket);
            close(s);
        #endif
        return NULL;
}

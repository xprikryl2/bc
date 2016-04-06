#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <ref/pkcs11u.h>
#include <ref/pkcs11.h>
#include "commons.c"

#define MAX_NUM_SESSIONS 20
#define MAX_NUM_SESSIONS_PER_TOKEN 20
#define MAX_NUM_TOKENS 1

static struct remsig_token {

  char* access_token;
  char* uco;
  int cryptoki_initialized;

  int open_sessions;
  struct session_state {
        CK_SESSION_HANDLE session_handle;

        CK_STATE state_session; //PKCS11 state
        CK_FLAGS flags;
        CK_VOID_PTR application;
        CK_NOTIFY notify;
        CK_SLOT_ID slot;
        CK_ATTRIBUTE_PTR pTemplate;
        CK_MECHANISM_PTR mechanism;


        int find_init_done;
        int sign_init_done;
        long unsigned password;

  } sessions[MAX_NUM_SESSIONS];

  int hardware_slot;
  int login_user;
  int conn_up;

} remsig_token;

static int loadAccessToken(){
    // dodělat, zjistit umístění a tak
    return 0;
}

static void snprintf_fill(char *str, size_t size, char fillchar, const char *fmt)
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

static CK_RV verify_session_handle(CK_SESSION_HANDLE hSession, struct session_state **state)
{
    int i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++){
    if (remsig_token.sessions[i].session_handle == hSession)
        break;
    }
    if (i == MAX_NUM_SESSIONS) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (state)
    *state = &remsig_token.sessions[i];
    return CKR_OK;
}

CK_RV C_Initialize(CK_VOID_PTR a)
{
    // structure containing information on how the library should deal with multi-threaded access, NULL_PTR = no multi-thread access
    CK_C_INITIALIZE_ARGS_PTR args = a;

    if (remsig_token.cryptoki_initialized == 1)
    {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    if (a != NULL_PTR) {
        printf("\tCreateMutex:\t%p\n", args->CreateMutex);
        printf("\tDestroyMutext\t%p\n", args->DestroyMutex);
        printf("\tLockMutext\t%p\n", args->LockMutex);
        printf("\tUnlockMutext\t%p\n", args->UnlockMutex);
        printf("\tFlags\t%04x\n", (unsigned int)args->flags);
        printf("\tCK_C_INITIALIZE_ARGS are not supported\n");
        return CKR_ARGUMENTS_BAD;
    }

    if (loadAccessToken() != 0){
        return CKR_DEVICE_REMOVED;
    }

    remsig_token.conn_up = 1;
    remsig_token.open_sessions = 0;

    for(int i = 0; i < MAX_NUM_SESSIONS; i++) {
        remsig_token.sessions[i].session_handle = CK_INVALID_HANDLE;
        remsig_token.sessions[i].state_session = -1;
        remsig_token.sessions[i].flags = -1;
        remsig_token.sessions[i].application = NULL;
        remsig_token.sessions[i].notify = NULL;
        remsig_token.sessions[i].slot = -1;
        remsig_token.sessions[i].pTemplate = NULL;
        remsig_token.sessions[i].password = 0;
    }

    remsig_token.login_user = -1;
    remsig_token.hardware_slot = 0;

    remsig_token.cryptoki_initialized = 1;

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR args)
{

    printf("Finalize\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (args != NULL_PTR )
    {
       printf("\tpReserved is not NULL\n");
       return CKR_ARGUMENTS_BAD;
    }

    remsig_token.cryptoki_initialized = 0;

    return CKR_OK;
}

extern CK_FUNCTION_LIST funcs;

CK_RV C_GetInfo(CK_INFO_PTR args)
{
    printf("GetInfo\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // sets static Cryptoki info
    memset(args, 17, sizeof(*args));
    args->cryptokiVersion.major = 2;
    args->cryptokiVersion.minor = 20;
    snprintf_fill((char *)args->manufacturerID, sizeof(args->manufacturerID), ' ', "OndrejPrikryl");
    snprintf_fill((char *)args->libraryDescription, sizeof(args->manufacturerID), ' ', "PKCS11Module");
    args->libraryVersion.major = 1;
    args->libraryVersion.minor = 0;

    return CKR_OK;
}


CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR   pulCount)
{
    int conn_tokens = 0;

    printf("GetSlotList: %s\n",
        tokenPresent ? "tokenPresent" : "token not Present");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // returns only tokens with opened connection to server
    if(tokenPresent == CK_TRUE)
    {
        if(remsig_token.conn_up == 1)
        {
          conn_tokens = 1;
          if (pSlotList)
          {
            pSlotList[0] = 0;
          }
        }
        *pulCount = conn_tokens;
    }
    else
    {
      *pulCount = MAX_NUM_TOKENS;
       if (pSlotList)
       {
            pSlotList[0] = 0;
       }
    }

    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    printf("GetSlotInfo: slot: %d\n", (int)slotID);

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // sets static slot info
    memset(pInfo, 18, sizeof(*pInfo));

    if (slotID < 0 || slotID >= MAX_NUM_TOKENS)
    return CKR_SLOT_ID_INVALID;

    snprintf_fill((char *)pInfo->slotDescription, sizeof(pInfo->slotDescription), ' ', "RemSig token slot");
    snprintf_fill((char *)pInfo->manufacturerID, sizeof(pInfo->manufacturerID), ' ', "OndrejPrikryl (slot)");

    if(remsig_token.conn_up == 1)
      pInfo->flags = CKF_TOKEN_PRESENT;

    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    printf("GetTokenInfo\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID < 0 || slotID >= MAX_NUM_TOKENS)
        return CKR_SLOT_ID_INVALID;

    if(remsig_token.conn_up != 1)
      return CKR_TOKEN_NOT_PRESENT;

    memset(pInfo, 19, sizeof(*pInfo));

    snprintf_fill((char *)pInfo->label, sizeof(pInfo->label), ' ', "VirtualRemSig");

    snprintf_fill((char *)pInfo->manufacturerID, sizeof(pInfo->manufacturerID), ' ', "RemSig");

    snprintf_fill((char *)pInfo->model, sizeof(pInfo->model),' ', "1.0");

    snprintf_fill((char *)pInfo->serialNumber,sizeof(pInfo->serialNumber),' ', "0");

    pInfo->flags = CKF_WRITE_PROTECTED | CKF_SECONDARY_AUTHENTICATION;

    pInfo->ulMaxSessionCount = MAX_NUM_SESSIONS;
    pInfo->ulSessionCount = remsig_token.open_sessions;
    pInfo->ulMaxRwSessionCount = 0;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = 0;
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

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    *ppFunctionList = &funcs;
    return CKR_OK;
}

static CK_RV func_not_supported(void)
{
    printf("function not supported\n");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    int i;

    printf("OpenSession: slot: %d\n", (int)slotID);

    if (remsig_token.cryptoki_initialized != 1)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // tests for various input conditions
    if (slotID < 0 || slotID >= MAX_NUM_TOKENS)
    {
        return CKR_SLOT_ID_INVALID;
    }

    if(remsig_token.conn_up != 1)
    {
        return CKR_TOKEN_NOT_PRESENT;
    }

    if (!(flags & CKF_SERIAL_SESSION))
    {
      return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    if (flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION))
    {
      return CKR_ARGUMENTS_BAD;
    }

    if (!(flags & CKF_RW_SESSION) && (remsig_token.login_user == CKU_SO))
    {
      return CKR_SESSION_READ_WRITE_SO_EXISTS;
    }

    if (remsig_token.open_sessions == MAX_NUM_SESSIONS)
    {
      return CKR_SESSION_COUNT;
    }

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (remsig_token.sessions[i].session_handle == CK_INVALID_HANDLE)
            break;
    }
    if (i == MAX_NUM_SESSIONS) {
        return CKR_SESSION_COUNT;
    }

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
      if (remsig_token.login_user == CKU_SO)
      {
         remsig_token.sessions[i].state_session = CKS_RW_SO_FUNCTIONS;
      }
      if (remsig_token.login_user == CKU_USER)
      {
         remsig_token.sessions[i].state_session = CKS_RW_USER_FUNCTIONS;
      }
      if (remsig_token.login_user == -1)
      {
         remsig_token.sessions[i].state_session = CKS_RW_PUBLIC_SESSION;
      }
    }
    else
    {
      if (remsig_token.login_user == CKU_USER)
      {
        remsig_token.sessions[i].state_session = CKS_RO_USER_FUNCTIONS;
      }
      if (remsig_token.login_user == -1)
      {
        remsig_token.sessions[i].state_session = CKS_RO_PUBLIC_SESSION;
      }
    }

    remsig_token.open_sessions++;
    *phSession = remsig_token.sessions[i].session_handle;

    printf("Number of opened sessions:%d\n", remsig_token.open_sessions);

    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    int i;

    printf("CloseSession\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    for( i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (remsig_token.sessions[i].session_handle == hSession)
        {
            break;
        }
    }
    if(remsig_token.sessions[i].session_handle != hSession) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    remsig_token.sessions[i].session_handle = CK_INVALID_HANDLE;
    remsig_token.sessions[i].state_session = -1;
    remsig_token.sessions[i].flags = -1;
    remsig_token.sessions[i].application = NULL;
    remsig_token.sessions[i].notify = NULL;
    remsig_token.sessions[i].slot = -1;

    remsig_token.open_sessions--;

    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    printf("CloseAllSessions\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (slotID != 0)
    {
        return CKR_SLOT_ID_INVALID;
    }

    if(remsig_token.conn_up != 1)
      return CKR_TOKEN_NOT_PRESENT;

    for(int i = 0; i < MAX_NUM_SESSIONS; i++) {
        remsig_token.sessions[i].session_handle = CK_INVALID_HANDLE;
        remsig_token.sessions[i].state_session = -1;
        remsig_token.sessions[i].flags = -1;
        remsig_token.sessions[i].application = NULL;
        remsig_token.sessions[i].notify = NULL;
        remsig_token.sessions[i].slot = -1;
    }
    remsig_token.open_sessions = 0;

    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    struct session_state *state;

    printf("GetSessionInfo\n");

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

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    unsigned i;

    printf("GetAttributeValue\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    for( i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (remsig_token.sessions[i].session_handle == hSession)
        {
            break;
        }
    }
    if(remsig_token.sessions[i].session_handle != hSession) {
        return CKR_SESSION_HANDLE_INVALID;
    }


    // sends number of requested attributes and object id
    for(i = 0; i < ulCount; i++) {
        pTemplate[i].ulValueLen = -1;
    }

    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    int i;

    printf("Login\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    for( i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (remsig_token.sessions[i].session_handle == hSession)
        {
            break;
        }
    }
    if(remsig_token.sessions[i].session_handle != hSession) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (userType != CKU_USER && userType != CKU_SO)
    {
      return CKR_USER_TYPE_INVALID;
    }


    if (remsig_token.login_user == CKU_SO || remsig_token.login_user == CKU_USER)
    {
      return CKR_USER_ALREADY_LOGGED_IN;
    }

    if (userType == CKU_SO)
    {
        if (remsig_token.sessions[i].state_session == CKS_RO_PUBLIC_SESSION)
        {
              return CKR_SESSION_READ_ONLY_EXISTS;
        }
    }

    if (pPin != NULL_PTR) {
        // doplnit jak je to s pinem
    }



    if (remsig_token.sessions[i].state_session == CKS_RO_PUBLIC_SESSION && userType == CKU_USER)
    {
        remsig_token.sessions[i].state_session = CKS_RO_USER_FUNCTIONS;
    }

    if (remsig_token.sessions[i].state_session == CKS_RW_PUBLIC_SESSION && userType == CKU_USER)
    {
        remsig_token.sessions[i].state_session = CKS_RW_USER_FUNCTIONS;
    }

     if (remsig_token.sessions[i].state_session == CKS_RW_PUBLIC_SESSION && userType == CKU_SO)
     {
        remsig_token.sessions[i].state_session = CKS_RW_SO_FUNCTIONS;
     }


    if (userType == CKU_USER)
    {
      remsig_token.login_user = CKU_USER;
    }

    if (userType == CKU_SO)
    {
      remsig_token.login_user = CKU_SO;
    }

    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{

    printf("Logout\n");

    if (remsig_token.cryptoki_initialized != 1)
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (verify_session_handle(hSession, NULL) != CKR_OK)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (remsig_token.login_user == CKU_SO || remsig_token.login_user == CKU_USER)
    {
      return CKR_USER_ALREADY_LOGGED_IN;
    }

    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    struct session_state *state;

    printf("FindObjectsInit\n");

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

    if ( state->state_session != CKS_RW_USER_FUNCTIONS && state->state_session != CKS_RO_USER_FUNCTIONS)
    {
      state->find_init_done = 1;
      return CKR_OK;
    }

    if(ulCount)
    {
        state->pTemplate = malloc(ulCount * sizeof(CK_ATTRIBUTE_PTR));
        state->pTemplate = pTemplate;
    }

    state->find_init_done = 1;

    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    char temp[128], *s;
    struct session_state *state;
    int i;
    CK_OBJECT_HANDLE h;

    printf("FindObjects\n");

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




    /*
    *pulObjectCount = atoi(myproxy_token.tokens[(int)slotID].server_response->data_string2);
    if(*pulObjectCount > 0)
    {
      s = NULL;
      h = atoi(strtok_r(myproxy_token.tokens[(int)slotID].server_response->data_string, ";",&s));
      *(phObject) = h;
      for(i=1;i<*pulObjectCount;i++)
      {
        h = atoi(strtok_r(NULL,";",&s));
        *(++phObject) = h;
      }
    }
    */
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    struct session_state *state;

    printf("FindObjectsFinal\n");

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

    if(state->pTemplate != NULL) {
        free(state->pTemplate);
        state->pTemplate = NULL;
    }

    state->find_init_done = 0;
    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    struct session_state *state;

    printf("SignInit\n");

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

    state->password = hKey;
    state->mechanism = pMechanism;

    state->sign_init_done = 1;
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    struct session_state *state;

    printf("Sign\n");

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

    if (pData == NULL_PTR) {
        printf("data NULL\n");
        return CKR_ARGUMENTS_BAD;
    }

    if (ulDataLen == 0) {
        printf("data NULL\n");
        return CKR_ARGUMENTS_BAD;
    }


    char* buf = (char*)remsig_sign(remsig_token.access_token, 1, state->password, remsig_token.uco, (char*) pData);

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
    C_GetAttributeValue,
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


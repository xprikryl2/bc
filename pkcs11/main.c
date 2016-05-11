#include "pkcs11.c"

int main() {

    // Tests
    CK_RV ret;
    CK_ULONG num_slots;
    CK_SLOT_ID_PTR slot_ids;
    CK_SLOT_ID slot;

    CK_SESSION_HANDLE session1;
    CK_UTF8CHAR_PTR pin = (unsigned char*) "pinpinpin";

    CK_OBJECT_CLASS keyClassPriv = CKO_PRIVATE_KEY, certificateClass = CKO_CERTIFICATE;
    CK_KEY_TYPE keyType = CKK_RSA;

    CK_ULONG mechanismcount = 1;
    CK_MECHANISM mechanism;

    CK_OBJECT_HANDLE hObjectPub, hObjectPriv;
    CK_ULONG ulObjectCount;

    CK_ATTRIBUTE_PTR certTemplate = malloc(2 * sizeof(CK_ATTRIBUTE));
    certTemplate[0].type = CKA_CLASS;
    certTemplate[0].pValue = &certificateClass;
    certTemplate[0].ulValueLen = sizeof(certificateClass);

    CK_ATTRIBUTE_PTR keyTemplatePriv = malloc(2 * sizeof(CK_ATTRIBUTE));
    keyTemplatePriv[0].type = CKA_CLASS;
    keyTemplatePriv[0].pValue = &keyClassPriv;
    keyTemplatePriv[0].ulValueLen = sizeof(keyClassPriv);
    keyTemplatePriv[1].type = CKA_KEY_TYPE;
    keyTemplatePriv[1].pValue = &keyType;
    keyTemplatePriv[1].ulValueLen = sizeof(keyType);

    CK_ULONG sizein = 4;
    CK_ULONG sizeout;
    CK_BYTE* textout;
    CK_BYTE textin[] = {'t', 'e', 's', 't'};

    // initializes module
    C_Initialize(NULL_PTR);

    // get number of slots in which token is present
    ret = C_GetSlotList(TRUE, NULL, &num_slots);
    if (ret)
        goto end;

    if (num_slots == 0)
        goto end;

    // allocates memory for number which we get above
    if ((slot_ids = calloc(1, num_slots * sizeof(*slot_ids))) == NULL)
        goto end;

    // get array of slots
    ret = C_GetSlotList(TRUE, slot_ids, &num_slots);
    if (ret)
        goto end;

    // we want to work with first slot
    slot = slot_ids[0];

    // open session on this slot
    ret = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session1);
    if (ret != CKR_OK)
        goto end;

    // login to the token
    ret = C_Login(session1, CKU_USER, pin, sizeof(pin));
    if (ret != CKR_OK)
        goto end;

    // looking for an object which mathces given template
    ret = C_FindObjectsInit(session1, certTemplate, 1);
    if (ret != CKR_OK)
        goto end;
    C_FindObjects(session1, &hObjectPub, 1, &ulObjectCount);
    if (ret != CKR_OK)
        goto end;

    printf("founded handle:%lu\n", hObjectPub);

    ret = C_FindObjectsFinal(session1);
    if (ret != CKR_OK)
        goto end;

    // looking for an object which mathces given template
    ret = C_FindObjectsInit(session1, keyTemplatePriv, 1);
    if (ret != CKR_OK)
        goto end;
    C_FindObjects(session1, &hObjectPriv, 1, &ulObjectCount);
    if (ret != CKR_OK)
        goto end;

    printf("founded handle:%lu\n", hObjectPriv);

    ret = C_FindObjectsFinal(session1);
    if (ret != CKR_OK)
        goto end;

    // listing token mechanisms
    memset(&mechanism, 0, sizeof(mechanism));
    ret = C_GetMechanismList(slot, &mechanism.mechanism, &mechanismcount);
    if (ret != CKR_OK)
      goto end;

    // signing operation
    ret = C_SignInit(session1, &mechanism, hObjectPriv);
    if (ret != CKR_OK)
      goto end;

    // allocate output memory
    textout = malloc(128);
    memset(textout, 0, 128);

    ret = C_Sign(session1, (CK_BYTE *)textin, sizein,
                 (CK_BYTE *)textout, &sizeout);
    if (ret != CKR_OK) {
      printf("message: %lu\n", ret);
      goto end;
    }
    printf("message: %s\n", textout);

    // logout user
    ret = C_Logout(session1);
        if (ret != CKR_OK)
        goto end;

        ret = C_CloseAllSessions(slot);
        if (ret != CKR_OK)
        goto end;

    end:
        // module shutdown
        C_Finalize(NULL_PTR);

    return 0;
}

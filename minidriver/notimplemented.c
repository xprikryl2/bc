#include <stdio.h>
#include "minidriver.c"

#define UNUSED(x) (void)(x)

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
 * This function should be implemented according to
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

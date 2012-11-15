#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <curl/curl.h>

#include "cJSON.h"
#include "pkcs11.h"
#include "https.h"
#include "common.h"

#define CONFIG_FILE "~/.iPKCS11.url"

#ifdef DEBUG
#define debug(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while(0);
#else
#define debug(...) /* swallow */
#endif

const char *read_config(void)
{
    FILE *file = myopen(CONFIG_FILE, "r");
    if(!file)
        return NULL;

    static char buf[128];
    char *ret = fgets(buf, 128, file);
    fclose(file);

    return (const char *) ret;
}


#define NULLFUN(x) CK_RV NULL_##x(void){fprintf(stderr, "FATAL: %s not implemented\n", #x);  return CKR_GENERAL_ERROR; }

NULLFUN(C_GetSlotInfo);
NULLFUN(C_GetMechanismList);
NULLFUN(C_GetMechanismInfo);
NULLFUN(C_InitToken);
NULLFUN(C_InitPIN);
NULLFUN(C_SetPIN);
NULLFUN(C_CloseAllSessions);
NULLFUN(C_GetSessionInfo);
NULLFUN(C_GetOperationState);
NULLFUN(C_SetOperationState);
NULLFUN(C_Logout);
NULLFUN(C_CreateObject);
NULLFUN(C_CopyObject);
NULLFUN(C_DestroyObject);
NULLFUN(C_GetObjectSize);
NULLFUN(C_SetAttributeValue);
NULLFUN(C_EncryptInit);
NULLFUN(C_Encrypt);
NULLFUN(C_EncryptUpdate);
NULLFUN(C_EncryptFinal);
NULLFUN(C_DecryptInit);
NULLFUN(C_Decrypt);
NULLFUN(C_DecryptUpdate);
NULLFUN(C_DecryptFinal);
NULLFUN(C_DigestInit);
NULLFUN(C_Digest);
NULLFUN(C_DigestUpdate);
NULLFUN(C_DigestKey);
NULLFUN(C_DigestFinal);
NULLFUN(C_SignUpdate);
NULLFUN(C_SignFinal);
NULLFUN(C_SignRecoverInit);
NULLFUN(C_SignRecover);
NULLFUN(C_VerifyInit);
NULLFUN(C_Verify);
NULLFUN(C_VerifyUpdate);
NULLFUN(C_VerifyFinal);
NULLFUN(C_VerifyRecoverInit);
NULLFUN(C_VerifyRecover);
NULLFUN(C_DigestEncryptUpdate);
NULLFUN(C_DecryptDigestUpdate);
NULLFUN(C_SignEncryptUpdate);
NULLFUN(C_DecryptVerifyUpdate);
NULLFUN(C_GenerateKey);
NULLFUN(C_GenerateKeyPair);
NULLFUN(C_WrapKey);
NULLFUN(C_UnwrapKey);
NULLFUN(C_DeriveKey);
NULLFUN(C_SeedRandom);
NULLFUN(C_GenerateRandom);
NULLFUN(C_GetFunctionStatus);
NULLFUN(C_CancelFunction);
NULLFUN(C_WaitForSlotEvent);

CK_FUNCTION_LIST pkcs11_function_list = {
	{ 2, 11 }, 
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	(void *)NULL_C_GetSlotInfo,
	C_GetTokenInfo,
	(void *)NULL_C_GetMechanismList,
	(void *)NULL_C_GetMechanismInfo,
	(void *)NULL_C_InitToken,
	(void *)NULL_C_InitPIN,
	(void *)NULL_C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	(void *)NULL_C_CloseAllSessions,
	(void *)NULL_C_GetSessionInfo,
	(void *)NULL_C_GetOperationState,
	(void *)NULL_C_SetOperationState,
	C_Login,
	(void *)NULL_C_Logout,
	(void *)NULL_C_CreateObject,
	(void *)NULL_C_CopyObject,
	(void *)NULL_C_DestroyObject,
	(void *)NULL_C_GetObjectSize,
	C_GetAttributeValue,
	(void *)NULL_C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	(void *)NULL_C_EncryptInit,
	(void *)NULL_C_Encrypt,
	(void *)NULL_C_EncryptUpdate,
	(void *)NULL_C_EncryptFinal,
	(void *)NULL_C_DecryptInit,
	(void *)NULL_C_Decrypt,
	(void *)NULL_C_DecryptUpdate,
	(void *)NULL_C_DecryptFinal,
	(void *)NULL_C_DigestInit,
	(void *)NULL_C_Digest,
	(void *)NULL_C_DigestUpdate,
	(void *)NULL_C_DigestKey,
	(void *)NULL_C_DigestFinal,
	C_SignInit,
	C_Sign,
	(void *)NULL_C_SignUpdate,
	(void *)NULL_C_SignFinal,
	(void *)NULL_C_SignRecoverInit,
	(void *)NULL_C_SignRecover,
	(void *)NULL_C_VerifyInit,
	(void *)NULL_C_Verify,
	(void *)NULL_C_VerifyUpdate,
	(void *)NULL_C_VerifyFinal,
	(void *)NULL_C_VerifyRecoverInit,
	(void *)NULL_C_VerifyRecover,
	(void *)NULL_C_DigestEncryptUpdate,
	(void *)NULL_C_DecryptDigestUpdate,
	(void *)NULL_C_SignEncryptUpdate,
	(void *)NULL_C_DecryptVerifyUpdate,
	(void *)NULL_C_GenerateKey,
	(void *)NULL_C_GenerateKeyPair,
	(void *)NULL_C_WrapKey,
	(void *)NULL_C_UnwrapKey,
	(void *)NULL_C_DeriveKey,
	(void *)NULL_C_SeedRandom,
	(void *)NULL_C_GenerateRandom,
	(void *)NULL_C_GetFunctionStatus,
	(void *)NULL_C_CancelFunction,
	(void *)NULL_C_WaitForSlotEvent,
};

cJSON *pkcs_query(const char *method, const char *format, ...)
{
    cJSON *root   = cJSON_CreateObject();  
    cJSON *params = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "method", cJSON_CreateString(method));
    cJSON_AddItemToObject(root, "params", params);

    va_list list_ptr;
    va_start(list_ptr, format);
    while(1)
    {
	char *param = va_arg(list_ptr, char *);
	if(param==NULL)
	    break;
        int type = *format++;

        int valueint;
        char *valuestring;
        switch(type)
        {
            case 'd': 
                valueint = va_arg(list_ptr, int);
                cJSON_AddNumberToObject(params, param, valueint);
                break;
            case 's': 
                valuestring = va_arg(list_ptr, char *);
                cJSON_AddStringToObject(params, param, valuestring);
                break;
            default:
                fprintf(stderr, "bad format: %s", format);
                
        }

    }
    va_end(list_ptr);

    char *payload = cJSON_Print(root);
    cJSON_Delete(root);

    char  *replyString = send_string(payload);
    free(payload);

    cJSON *reply;
    if(replyString)
    {
        //printf("REPLY: %s\n\n", replyString);
        reply = cJSON_Parse(replyString);
        free(replyString);
    }
    else
        reply = NULL;

    return reply;
}

int get_return_code(cJSON *root)
{
    cJSON *object = cJSON_GetObjectItem(root, "returnCode");
    if(object)
        return object->valueint;
    else
        return CKR_GENERAL_ERROR;
}

/*
int main(void)
{
    printf("%s\n", JSONPayload("hello", "arg1", "val1", 0));
    printf("%s\n", JSONPayload("hello", "arg1", "val1", "arg2", "val2", 0));

    return 0;
}
*/


CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    debug("DEBUG: at line %d: GetFunctionList\n", __LINE__);
    if (ppFunctionList == NULL_PTR)
	return CKR_ARGUMENTS_BAD;

    *ppFunctionList = &pkcs11_function_list;
    return CKR_OK;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    debug("DEBUG: at line %d: Initialize\n", __LINE__);
    const char *url = read_config();
    if(url == NULL)
        return CKR_GENERAL_ERROR;

    ssl_link_init(url);
    
    return CKR_OK;
}


CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    debug("DEBUG: at line %d: GetInfo\n", __LINE__);

    cJSON *reply = pkcs_query("C_GetInfo", NULL, NULL);
    if(!reply)
        return CKR_GENERAL_ERROR;

    cJSON *object;

    object = cJSON_GetObjectItem(reply, "libraryDescription");
    if(object)
        memcpy(pInfo->libraryDescription, object->valuestring, 32);

    object = cJSON_GetObjectItem(reply, "manufacturerID");
    if(object)
        memcpy(pInfo->manufacturerID, object->valuestring, 32);

    object = cJSON_GetObjectItem(reply, "flags");
    if(object)
        pInfo->flags = object->valueint;

    object = cJSON_GetObjectItem(reply, "cryptokiVersion");
    if(object)
    {
        cJSON *version;
        version = cJSON_GetObjectItem(object, "major");
        if(version)
            pInfo->cryptokiVersion.major = version->valueint;

        version = cJSON_GetObjectItem(object, "minor");
        if(version)
            pInfo->cryptokiVersion.minor = version->valueint;
    }

    object = cJSON_GetObjectItem(reply, "libraryVersion");
    if(object)
    {
        cJSON *version;
        version = cJSON_GetObjectItem(object, "major");
        if(version)
            pInfo->libraryVersion.major = version->valueint;

        version = cJSON_GetObjectItem(object, "minor");
        if(version)
            pInfo->libraryVersion.minor = version->valueint;
    }

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    debug("DEBUG: at line %d: GetSlotList, pSlotList=%p\n", __LINE__, pSlotList);

    static cJSON *reply = NULL;
    static int ret;

    if (pulCount == NULL_PTR)
	return CKR_ARGUMENTS_BAD;

    if (pSlotList == NULL_PTR)
    {
        reply = pkcs_query("C_GetSlotList", NULL, NULL);
        if(!reply)
            return CKR_GENERAL_ERROR;

        cJSON *list = cJSON_GetObjectItem(reply, "slotList");
        cJSON *child;
        if(list)
            child = list->child;
        else
            child = NULL;

        int count = 0;
        while(child)
        {
            count++;
            child = child->next;
        }

        ret = get_return_code(reply);
        *pulCount = count;
    }
    else
    {
        if(!reply)
            return CKR_GENERAL_ERROR;

        cJSON *list = cJSON_GetObjectItem(reply, "slotList");
        cJSON *child;
        if(list)
            child = list->child;
        else
            child = NULL;

        while(child)
        {
            *pSlotList++ = child->valueint;
            debug("valueint %d\n", child->valueint);
            child = child->next;
        }

        cJSON_Delete(reply);
        reply = NULL;

    }

    return ret;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    debug("DEBUG: at line %d: GetTokenInfo, slotID=%d, pInfo=%p\n", __LINE__, slotID, pInfo);
    if (pInfo == NULL_PTR)
	return CKR_ARGUMENTS_BAD;

    cJSON *reply = pkcs_query("C_GetTokenInfo", "d", "slotID", slotID, NULL);

    if(!reply)
        return CKR_GENERAL_ERROR;

    cJSON *object;

    object = cJSON_GetObjectItem(reply, "label");
    if(object)
        memcpy(pInfo->label, object->valuestring, 32);

    object = cJSON_GetObjectItem(reply, "manufacturerID");
    if(object)
        memcpy(pInfo->manufacturerID, object->valuestring, 32);

    object = cJSON_GetObjectItem(reply, "model");
    if(object)
        memcpy(pInfo->model, object->valuestring, 16);

    object = cJSON_GetObjectItem(reply, "serialNumber");
    if(object)
        memcpy(pInfo->serialNumber, object->valuestring, 16);

    object = cJSON_GetObjectItem(reply, "flags");
    if(object)
        pInfo->flags = object->valueint;

    object = cJSON_GetObjectItem(reply, "ulMaxSessionCount");
    if(object)
        pInfo->ulMaxSessionCount = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "ulSessionCount");
    if(object)
        pInfo->ulSessionCount = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "ulMaxRwSessionCount");
    if(object)
        pInfo->ulMaxRwSessionCount = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "ulRwSessionCount");
    if(object)
        pInfo->ulRwSessionCount = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "ulMaxPinLen");
    if(object)
        pInfo->ulMaxPinLen = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "ulMinPinLen");
    if(object)
        pInfo->ulMinPinLen = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "ulTotalPublicMemory");
    if(object)
        pInfo->ulTotalPublicMemory = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "ulFreePublicMemory");
    if(object)
        pInfo->ulFreePublicMemory = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "ulTotalPrivateMemory");
    if(object)
        pInfo->ulTotalPrivateMemory = object->valueint;
   
    object = cJSON_GetObjectItem(reply, "ulFreePrivateMemory");
    if(object)
        pInfo->ulFreePrivateMemory = object->valueint;
    
    object = cJSON_GetObjectItem(reply, "hardwareVersion");
    if(object)
    {
        cJSON *version;
        version = cJSON_GetObjectItem(object, "major");
        if(version)
            pInfo->hardwareVersion.major = version->valueint;

        version = cJSON_GetObjectItem(object, "minor");
        if(version)
            pInfo->hardwareVersion.minor = version->valueint;
    }

    object = cJSON_GetObjectItem(reply, "firmwareVersion");
    if(object)
    {
        cJSON *version;
        version = cJSON_GetObjectItem(object, "major");
        if(version)
            pInfo->firmwareVersion.major = version->valueint;

        version = cJSON_GetObjectItem(object, "minor");
        if(version)
            pInfo->firmwareVersion.minor = version->valueint;
    }

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    debug("DEBUG: at line %d: OpenSession\n", __LINE__);

    cJSON *reply = pkcs_query("C_OpenSession", "d", "slotID", slotID, NULL);

    if(!reply)
        return CKR_GENERAL_ERROR;

    int ret = get_return_code(reply);
    cJSON *object = cJSON_GetObjectItem(reply, "hSession");
    if(object)
        *phSession = object->valueint;
    else
    {
        *phSession = 0xb0bdead;
        if(ret == CKR_OK)
            ret = CKR_GENERAL_ERROR;
    }

    cJSON_Delete(reply);
    return ret;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    debug("DEBUG: at line %d: FindObjectsInit\n", __LINE__);

    cJSON *reply = pkcs_query("C_FindObjectsInit", "d", "hSession", hSession, NULL);
    if(!reply)
        return CKR_GENERAL_ERROR;

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    debug("DEBUG: at line %d: FindObjects\n", __LINE__);

    cJSON *reply = pkcs_query("C_FindObjects", "d", "hSession", hSession, NULL);
    if(!reply)
        return CKR_GENERAL_ERROR;

    cJSON *object;

    object = cJSON_GetObjectItem(reply, "ulObjectCount");
    if(object)
        *pulObjectCount = object->valueint;

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    debug("DEBUG: at line %d: FindOjectsFinal\n", __LINE__);
    cJSON *reply = pkcs_query("C_FindObjectsFinal", "d", "hSession", hSession, NULL);
    if(!reply)
        return CKR_GENERAL_ERROR;

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    
    debug("DEBUG: at line %d: GetAttributeValue, ulCount=%d, pTemplate[0,1,2]=%d,%d,%d\n", __LINE__, ulCount,pTemplate[0].ulValueLen,pTemplate[1].ulValueLen,pTemplate[2].ulValueLen);
    if (pTemplate == NULL_PTR || ulCount == 0)
	return CKR_ARGUMENTS_BAD;

    int isSizeRequest = ((*pTemplate).pValue == NULL)? 1 : 0;

    static cJSON *reply;
    if(isSizeRequest)
        reply = pkcs_query("C_GetAttributeValue", "dd", "ulCount", ulCount, "hSession", hSession, NULL);

    if(!reply)
        return CKR_GENERAL_ERROR;

    int ret = get_return_code(reply);
    if(ret != CKR_OK)
    {
        cJSON_Delete(reply);
        return ret;
    }

    cJSON *jTemplate = cJSON_GetObjectItem(reply, "template");
    if(!jTemplate)
        return CKR_GENERAL_ERROR;

    for(cJSON *jElement = jTemplate->child; jElement; jElement = jElement->next)
    {
        cJSON *jType     = cJSON_GetObjectItem(jElement, "type");
        cJSON *jValue    = cJSON_GetObjectItem(jElement, "value");
        if(!jType || !jValue)
            return CKR_GENERAL_ERROR;

        switch(jType->valueint)
        {
            case CKA_ID:
                (*pTemplate).type = CKA_ID;
                if(isSizeRequest)
                    (*pTemplate).ulValueLen = 1;
                else
                {
                    int *id_ptr = (int *)((*pTemplate).pValue);
                    *id_ptr = jValue->valueint;
                }
                break;

            case CKA_MODULUS:
                if(isSizeRequest)
                {
                    char *hexstr = jValue->valuestring;
                    (*pTemplate).ulValueLen = strlen(hexstr) >> 1;
                    (*pTemplate).type = CKA_MODULUS;
                }
                else
                {
                    char *hexstr   = jValue->valuestring;
                    int   hexlen   = strlen(hexstr);

                    for(int i=0; i<hexlen; i+=2)
                    {
                        unsigned char byte;
                        char tmp = hexstr[i+2];
                        hexstr[i+2] = 0;
                        sscanf(&hexstr[i], "%x", (unsigned int *) &byte);
                        hexstr[i+2] = tmp;

                        char *buf = (char *)((*pTemplate).pValue);
                        buf[i>>1] = byte;
                    }
                }
                break;
            case CKA_PUBLIC_EXPONENT:
                if(isSizeRequest)
                {
                    (*pTemplate).type = CKA_PUBLIC_EXPONENT;
                    (*pTemplate).ulValueLen = 3;
                }
                else
                {
                    int *exp_ptr = (int *)((*pTemplate).pValue);
                    *exp_ptr = jValue->valueint;
                }
                break;
            default:
                return CKR_GENERAL_ERROR;
        }
        pTemplate++;
    }


    if(!isSizeRequest)
    {
        cJSON_Delete(reply);
        reply = NULL;
    }
    return ret;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    debug("DEBUG: at line %d: Login: you typed: %s\n", __LINE__, pPin);

    cJSON *reply = pkcs_query("C_Login", "ds", "hSession", hSession, "pin", pPin, NULL);
    if(!reply)
        return CKR_GENERAL_ERROR;

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    debug("DEBUG: at line %d: SignInit\n", __LINE__);

    cJSON *reply = pkcs_query("C_SignInit", "d", "hSession", hSession, NULL);
    if(!reply)
        return CKR_GENERAL_ERROR;

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}


CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    debug("DEBUG: at line %d: Sign\n", __LINE__);

    char *toBeSigned = (char *) malloc(sizeof(char) * ulDataLen * 2 + 1);
    for(int i=0; i<ulDataLen; i++)
        sprintf(&toBeSigned[2*i], "%02X", pData[i]);

    cJSON *reply = pkcs_query("C_Sign", "ds", "hSession", hSession, "data", toBeSigned, NULL);
    free(toBeSigned);

    if(!reply)
        return CKR_GENERAL_ERROR;

    cJSON *object;
    char *hexstr = NULL;

    object = cJSON_GetObjectItem(reply, "signature");
    if(object)
        hexstr = object->valuestring;

    int hexlen = strlen(hexstr);

    for(int i=0; i<hexlen; i+=2)
    {
        unsigned char byte;
        char tmp = hexstr[i+2];
        hexstr[i+2] = 0;
        sscanf(&hexstr[i], "%x", (unsigned int *) &byte);
        hexstr[i+2] = tmp;
        pSignature[i>>1] = byte;
    }

    *pulSignatureLen = hexlen >> 1;

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE session)
{
    debug("DEBUG: at line %d: CloseSession\n", __LINE__);
    cJSON *reply = pkcs_query("C_CloseSession", "d", "hSession", session, NULL);
    if(!reply)
        return CKR_GENERAL_ERROR;

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    debug("DEBUG: at line %d: Finalize\n", __LINE__);

    cJSON *reply = pkcs_query("C_Finalize", NULL, NULL);
    if(!reply)
        return CKR_GENERAL_ERROR;

    int ret = get_return_code(reply);
    cJSON_Delete(reply);
    return ret;

    ssl_link_cleanup();
}


/*
 * include/haproxy/pkcs11-spec.h
 * PKCS#11 module definition.
 *
 * Copyright (C) 2025 Chris Staite - christopher.staite@menlosecurity.com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

 #ifndef _HAPROXY_PKCS11_SPEC_H
 #define _HAPROXY_PKCS11_SPEC_H

/* specification taken from
 * https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959679
 */

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long int CK_ULONG;
typedef long int CK_LONG;

typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_NOTIFICATION;
typedef CK_ULONG CK_OBJECT_CLASS;

typedef void* CK_VOID_PTR;
typedef CK_VOID_PTR* CK_VOID_PTR_PTR;

typedef struct CK_VERSION {
	CK_BYTE major;
	CK_BYTE minor;
} CK_VERSION;

typedef CK_RV(*CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV(*CK_CREATEMUTEX)(CK_VOID_PTR_PTR ppMutex);
typedef CK_RV(*CK_DESTROYMUTEX)(CK_VOID_PTR ppMutex);
typedef CK_RV(*CK_UNLOCKMUTEX)(CK_VOID_PTR ppMutex);

typedef struct CK_C_INITIALIZE_ARGS {
	CK_CREATEMUTEX CreateMutex;
	CK_DESTROYMUTEX DestroyMutex;
	CK_LOCKMUTEX LockMutex;
	CK_UNLOCKMUTEX UnlockMutex;
	CK_FLAGS flags;
	CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

typedef struct CK_INFO {
	CK_VERSION cryptokiVersion;
	CK_UTF8CHAR manufacturerID[32];
	CK_FLAGS flags;
	CK_UTF8CHAR libraryDescription[32];
	CK_VERSION libraryVersion;
} CK_INFO;

typedef struct CK_ATTRIBUTE {
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct CK_MECHANISM {
	CK_MECHANISM_TYPE mechanism;
	CK_VOID_PTR pParameter;
	CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef struct CK_SLOT_INFO {
	CK_UTF8CHAR slotDescription[64];
	CK_UTF8CHAR manufacturerID[32];
	CK_FLAGS flags;
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef struct CK_TOKEN_INFO {
	CK_UTF8CHAR label[32];
	CK_UTF8CHAR manufacturerID[32];
	CK_UTF8CHAR model[16];
	CK_CHAR serialNumber[16];
	CK_FLAGS flags;
	CK_ULONG ulMaxSessionCount;
	CK_ULONG ulSessionCount;
	CK_ULONG ulMaxRwSessionCount;
	CK_ULONG ulRwSessionCount;
	CK_ULONG ulMaxPinLen;
	CK_ULONG ulMinPinLen;
	CK_ULONG ulTotalPublicMemory;
	CK_ULONG ulFreePublicMemory;
	CK_ULONG ulTotalPrivateMemory;
	CK_ULONG ulFreePrivateMemory;
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
	CK_CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_MECHANISM_INFO {
   CK_ULONG ulMinKeySize;
   CK_ULONG ulMaxKeySize;
   CK_FLAGS flags;
} CK_MECHANISM_INFO;

typedef struct CK_FUNCTION_LIST* CK_FUNCTION_LIST_PTR;

typedef CK_RV(*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

typedef CK_RV(*CK_C_Initialize)(CK_C_INITIALIZE_ARGS* pInitArgs);
typedef CK_RV(*CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV(*CK_C_GetInfo)(CK_INFO* pInfo);
typedef CK_RV(*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR* ppFunctionList);
typedef CK_RV(*CK_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount);
typedef CK_RV(*CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo);
typedef CK_RV(*CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo);
typedef CK_RV(*CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE *phSession);
typedef CK_RV(*CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV(*CK_C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE *pMechanismList, CK_ULONG *pulCount);
typedef CK_RV(*CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR *pPin, CK_ULONG ulPinLen);
typedef CK_RV(*CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);
typedef CK_RV(*CK_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject, CK_ULONG ulMaxObjectCount, CK_ULONG *pulObjectCount);
typedef CK_RV(*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV(*CK_C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV(*CK_C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE *pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE *pData, CK_ULONG *pulDataLen);
typedef CK_RV(*CK_C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV(*CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);

/* unused functions are simply defined as CK_VOID_PTR to avoid extra unused
 * definitions.
 */
typedef struct CK_FUNCTION_LIST {
	CK_VERSION version;
	CK_C_Initialize C_Initialize;
	CK_C_Finalize C_Finalize;
	CK_C_GetInfo C_GetInfo;
	CK_C_GetFunctionList C_GetFunctionList;
	CK_C_GetSlotList C_GetSlotList;
	CK_C_GetSlotInfo C_GetSlotInfo;
	CK_C_GetTokenInfo C_GetTokenInfo;
	CK_C_GetMechanismList C_GetMechanismList;
	CK_VOID_PTR C_GetMechanismInfo;
	CK_VOID_PTR C_InitToken;
	CK_VOID_PTR C_InitPIN;
	CK_VOID_PTR C_SetPIN;
	CK_C_OpenSession C_OpenSession;
	CK_C_CloseSession C_CloseSession;
	CK_VOID_PTR C_CloseAllSessions;
	CK_VOID_PTR C_GetSessionInfo;
	CK_VOID_PTR C_GetOperationState;
	CK_VOID_PTR C_SetOperationState;
	CK_C_Login C_Login;
	CK_VOID_PTR C_Logout;
	CK_VOID_PTR C_CreateObject;
	CK_VOID_PTR C_CopyObject;
	CK_VOID_PTR C_DestroyObject;
	CK_VOID_PTR C_GetObjectSize;
	CK_VOID_PTR C_GetAttributeValue;
	CK_VOID_PTR C_SetAttributeValue;
	CK_C_FindObjectsInit C_FindObjectsInit;
	CK_C_FindObjects C_FindObjects;
	CK_C_FindObjectsFinal C_FindObjectsFinal;
	CK_VOID_PTR C_EncryptInit;
	CK_VOID_PTR C_Encrypt;
	CK_VOID_PTR C_EncryptUpdate;
	CK_VOID_PTR C_EncryptFinal;
	CK_C_DecryptInit C_DecryptInit;
	CK_C_Decrypt C_Decrypt;
	CK_VOID_PTR C_DecryptUpdate;
	CK_VOID_PTR C_DecryptFinal;
	CK_VOID_PTR C_DigestInit;
	CK_VOID_PTR C_Digest;
	CK_VOID_PTR C_DigestUpdate;
	CK_VOID_PTR C_DigestKey;
	CK_VOID_PTR C_DigestFinal;
	CK_C_SignInit C_SignInit;
	CK_C_Sign C_Sign;
	CK_VOID_PTR C_SignUpdate;
	CK_VOID_PTR C_SignFinal;
	CK_VOID_PTR C_SignRecoverInit;
	CK_VOID_PTR C_SignRecover;
	CK_VOID_PTR C_VerifyInit;
	CK_VOID_PTR C_Verify;
	CK_VOID_PTR C_VerifyUpdate;
	CK_VOID_PTR C_VerifyFinal;
	CK_VOID_PTR C_VerifyRecoverInit;
	CK_VOID_PTR C_VerifyRecover;
	CK_VOID_PTR C_DigestEncryptUpdate;
	CK_VOID_PTR C_DecryptDigestUpdate;
	CK_VOID_PTR C_SignEncryptUpdate;
	CK_VOID_PTR C_DecryptVerifyUpdate;
	CK_VOID_PTR C_GenerateKey;
	CK_VOID_PTR C_GenerateKeyPair;
	CK_VOID_PTR C_WrapKey;
	CK_VOID_PTR C_UnwrapKey;
	CK_VOID_PTR C_DeriveKey;
	CK_VOID_PTR C_SeedRandom;
	CK_VOID_PTR C_GenerateRandom;
	CK_VOID_PTR C_GetFunctionStatus;
	CK_VOID_PTR C_CancelFunction;
	CK_VOID_PTR C_WaitForSlotEvent;
 } CK_FUNCTION_LIST;

#define CKR_OK  0x00000000UL

/* valid values that are used for CK_MECHANISM_TYPE */
#define CKM_RSA_X_509            0x00000003UL
#define CKM_SHA1_RSA_PKCS        0x00000006UL
#define CKM_SHA256_RSA_PKCS      0x00000040UL
#define CKM_SHA384_RSA_PKCS      0x00000041UL
#define CKM_SHA512_RSA_PKCS      0x00000042UL
#define CKM_ECDSA_SHA1           0x00001042UL
#define CKM_ECDSA_SHA256         0x00001044UL
#define CKM_ECDSA_SHA384         0x00001045UL
#define CKM_ECDSA_SHA512         0x00001046UL
#define CKM_SHA256_RSA_PKCS_PSS  0x00000043UL
#define CKM_SHA384_RSA_PKCS_PSS  0x00000044UL
#define CKM_SHA512_RSA_PKCS_PSS  0x00000045UL
#define CKM_EDDSA                0x00001057UL

#define CK_INVALID_HANDLE				0UL

#define CKF_TOKEN_PRESENT	0x00000001UL

#define CK_TRUE   1
#define CK_FALSE  0

#define CKU_USER  1UL

#define CKA_CLASS  0x00000000UL
#define CKA_LABEL  0x00000003UL
#define CKA_ID     0x00000102UL

#define CKO_PRIVATE_KEY  0x00000003UL

#define CKF_SERIAL_SESSION  0x00000004UL

#endif  /* _HAPROXY_PKCS11_SPEC_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */

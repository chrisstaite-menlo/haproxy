/*
 * Copyright (C) 2025 Chris Staite <christopher.staite@menlosecurity.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <haproxy/openssl-compat.h>
#include <haproxy/pkcs11-spec.h>

#include <stdlib.h>
#include <string.h>

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR* ppFunctionList);

struct session {
    char* pem_file;
    EVP_PKEY_CTX* ctx;
    size_t key_list_len;
    EVP_PKEY** key_list;
};

CK_RV C_Initialize(CK_C_INITIALIZE_ARGS* pInitArgs) {
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO* pInfo) {
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount) {
    *pulCount = 1;
    if (pSlotList) {
        *pSlotList = 0;
    }
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo) {
    if (slotID != 0) {
        return !CKR_OK;
    }
    pInfo->flags = CKF_TOKEN_PRESENT;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo) {
    if (slotID != 0) {
        return !CKR_OK;
    }
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE *phSession) {
    if (slotID != 0 || flags != CKF_SERIAL_SESSION) {
        return !CKR_OK;
    }
    *phSession = (CK_SESSION_HANDLE) calloc(1, sizeof(struct session));
    return phSession ? CKR_OK : !CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    struct session* session = (struct session*) hSession;
    size_t i;
    if (session->pem_file) {
        free(session->pem_file);
    }
    for (i = 0; i < session->key_list_len; ++i) {
        EVP_PKEY_free(session->key_list[i]);
    }
    if (session->key_list) {
        free(session->key_list);
    }
    free(session);
    return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE *pMechanismList, CK_ULONG *pulCount) {
    *pulCount = 13;
    if (pMechanismList == NULL)
        goto out;
    *pMechanismList++ = CKM_RSA_X_509;
    *pMechanismList++ = CKM_SHA1_RSA_PKCS;
    *pMechanismList++ = CKM_SHA256_RSA_PKCS;
    *pMechanismList++ = CKM_SHA384_RSA_PKCS;
    *pMechanismList++ = CKM_SHA512_RSA_PKCS;
    *pMechanismList++ = CKM_ECDSA_SHA1;
    *pMechanismList++ = CKM_ECDSA_SHA256;
    *pMechanismList++ = CKM_ECDSA_SHA384;
    *pMechanismList++ = CKM_ECDSA_SHA512;
    *pMechanismList++ = CKM_SHA256_RSA_PKCS_PSS;
    *pMechanismList++ = CKM_SHA384_RSA_PKCS_PSS;
    *pMechanismList++ = CKM_SHA512_RSA_PKCS_PSS;
    *pMechanismList++ = CKM_EDDSA;
out:
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR *pPin, CK_ULONG ulPinLen) {
    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount) {
    struct session *session = (struct session *) hSession;
    char *dummy_path = getenv("DUMMY_PATH");
    char *ptr;
    size_t dummy_len, path_len;
    CK_ULONG i;
    for (i = 0; i < ulCount; ++i) {
        if (pTemplate[i].type == CKA_ID) {
            path_len = pTemplate[i].ulValueLen + 1;
            if (dummy_path && ((char *) pTemplate[i].pValue)[0] != '/') {
                dummy_len = strlen(dummy_path);
                path_len += dummy_len + 1;
            }
            ptr = session->pem_file = malloc(path_len);
            if (session->pem_file == NULL)
                goto out;
            if (path_len > pTemplate[i].ulValueLen + 1) {
                memcpy(ptr, dummy_path, dummy_len);
                ptr += dummy_len - 1;
                /* ensure that there's a slash to join the paths. */
                if (*ptr++ != '/')
                    *ptr++ = '/';
            }
            memcpy(ptr, pTemplate[i].pValue, pTemplate[i].ulValueLen);
            ptr += pTemplate[i].ulValueLen;
            *ptr = '\0';
        }
    }

out:
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject, CK_ULONG ulMaxObjectCount, CK_ULONG *pulObjectCount) {
	BIO *in;
	EVP_PKEY *key = NULL;
	EVP_PKEY **key_list;
    struct session* session = (struct session*) hSession;
    if (!session->pem_file || ulMaxObjectCount < 1)
        goto end;
    in = BIO_new(BIO_s_file());
    if (in == NULL)
        goto end;

    if (BIO_read_filename(in, session->pem_file) <= 0) {
        printf("Could not find key in file %s\n", session->pem_file);
        goto end;
    }

    key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (!key)
        goto end;

    if (session->key_list) {
        key_list = realloc(session->key_list, sizeof(EVP_PKEY*) * (session->key_list_len + 1));
        if (key_list == NULL) {
            EVP_PKEY_free(key);
            key = NULL;
            goto end;
        } else {
            session->key_list = key_list;
        }
    } else {
        session->key_list = malloc(sizeof(EVP_PKEY*) * (session->key_list_len + 1));
    }
    if (!session->key_list) {
        session->key_list_len = 0;
        EVP_PKEY_free(key);
        key = NULL;
        goto end;
    }
    session->key_list[session->key_list_len++] = key;

end:
    if (key) {
        *phObject = (CK_OBJECT_HANDLE) key;
        *pulObjectCount = 1;
    } else if (pulObjectCount)
        *pulObjectCount = 0;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    struct session* session = (struct session*) hSession;
    if (session->pem_file) {
        free(session->pem_file);
        session->pem_file = NULL;
    }
    return CKR_OK;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
    struct session* session = (struct session*) hSession;
    if (session->ctx) {
        printf("Duplicate decrypt sessions\n");
        return !CKR_OK;
    }
    printf("Decrypt init\n");

    if (pMechanism == NULL || pMechanism->mechanism != CKM_RSA_X_509) {
        printf("Decrypt mechanism error\n");
        goto end;
    }

    session->ctx = EVP_PKEY_CTX_new((EVP_PKEY*) hKey, NULL);
    if (!session->ctx) {
        printf("Create context error\n");
        goto end;
    }

    if (EVP_PKEY_decrypt_init(session->ctx) <= 0) {
        printf("Decrypt init error\n");
        goto err;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(session->ctx, RSA_NO_PADDING) <= 0) {
        printf("Decrypt set padding error\n");
        goto err;
    }

    printf("Decrypt init success\n");
    goto end;

err:
    EVP_PKEY_CTX_free(session->ctx);
    session->ctx = NULL;

end:
    return session->ctx ? CKR_OK : !CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE *pData, CK_ULONG *pulDataLen) {
    struct session* session = (struct session*) hSession;
    CK_RV ret = CKR_OK;

    if (!session->ctx) {
        printf("Decrypt called without init\n");
        return !CKR_OK;
    }

    if (EVP_PKEY_decrypt(session->ctx, pData, pulDataLen, pEncryptedData, ulEncryptedDataLen) <= 0) {
        printf("Error decrypting\n");
        ret = !CKR_OK;
    }

    EVP_PKEY_CTX_free(session->ctx);
    session->ctx = NULL;
    return ret;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
    struct session* session = (struct session*) hSession;
    if (session->ctx) {
        printf("Duplicate sign sessions\n");
        return !CKR_OK;
    }

    if (pMechanism == NULL) {
        printf("No mechanism specified'n");
        goto end;
    }

    session->ctx = EVP_PKEY_CTX_new((EVP_PKEY*) hKey, NULL);
    if (!session->ctx) {
        printf("Sign context init failure\n");
        goto end;
    }

    if (EVP_PKEY_sign_init(session->ctx) <= 0) {
        printf("Sign init failure\n");
        goto err;
    }

    switch (pMechanism->mechanism) {
    case CKM_SHA1_RSA_PKCS:
        if (EVP_PKEY_CTX_set_rsa_padding(session->ctx, RSA_PKCS1_PADDING) <= 0) {
            printf("Set padding failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha1()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_SHA256_RSA_PKCS:
        if (EVP_PKEY_CTX_set_rsa_padding(session->ctx, RSA_PKCS1_PADDING) <= 0) {
            printf("Set padding failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha256()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_SHA384_RSA_PKCS:
        if (EVP_PKEY_CTX_set_rsa_padding(session->ctx, RSA_PKCS1_PADDING) <= 0) {
            printf("Set padding failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha384()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_SHA512_RSA_PKCS:
        if (EVP_PKEY_CTX_set_rsa_padding(session->ctx, RSA_PKCS1_PADDING) <= 0) {
            printf("Set padding failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha512()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_ECDSA_SHA1:
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha1()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_ECDSA_SHA256:
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha256()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_ECDSA_SHA384:
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha384()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_ECDSA_SHA512:
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha512()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_SHA256_RSA_PKCS_PSS:
        if (EVP_PKEY_CTX_set_rsa_padding(session->ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            printf("Set padding failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(session->ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            printf("Set salt length failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha256()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_SHA384_RSA_PKCS_PSS:
        if (EVP_PKEY_CTX_set_rsa_padding(session->ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            printf("Set padding failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(session->ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            printf("Set salt length failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha384()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_SHA512_RSA_PKCS_PSS:
        if (EVP_PKEY_CTX_set_rsa_padding(session->ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            printf("Set padding failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(session->ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            printf("Set salt length failure %s\n", ERR_reason_error_string(ERR_get_error()));
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(session->ctx, EVP_sha512()) <= 0) {
            printf("Set md failure\n");
            goto err;
        }
        break;
    case CKM_EDDSA:
        break;
    default:
        goto err;
    }

    goto end;

err:
    EVP_PKEY_CTX_free(session->ctx);
    session->ctx = NULL;

end:
    return session->ctx ? CKR_OK : !CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen) {
    struct session* session = (struct session*) hSession;
    CK_RV ret = !CKR_OK;
    const EVP_MD *md = NULL;
    CK_BYTE data[64];
    unsigned int data_len = sizeof(data);

    if (!session->ctx)
        return !CKR_OK;

    if (EVP_PKEY_CTX_get_signature_md(session->ctx, &md) <= 0) {
        printf("Error getting digest algorithm %s\n", ERR_reason_error_string(ERR_get_error()));
        goto out;
    }

    if (md) {
        if (EVP_Digest(pData, ulDataLen, data, &data_len, md, NULL) <= 0)
            goto out;
        pData = data;
        ulDataLen = data_len;
    }

    if (EVP_PKEY_sign(session->ctx, pSignature, pulSignatureLen, pData, ulDataLen) <= 0) {
        printf("Error signing %s\n", ERR_reason_error_string(ERR_get_error()));
        goto out;
    }

    ret = CKR_OK;

out:
    EVP_PKEY_CTX_free(session->ctx);
    session->ctx = NULL;
    return ret;
}

static CK_FUNCTION_LIST g_func_list = {
    .C_Initialize = &C_Initialize,
	.C_Finalize = &C_Finalize,
	.C_GetInfo = &C_GetInfo,
	.C_GetFunctionList = &C_GetFunctionList,
	.C_GetSlotList = &C_GetSlotList,
	.C_GetSlotInfo = &C_GetSlotInfo,
	.C_GetTokenInfo = &C_GetTokenInfo,
	.C_GetMechanismList = &C_GetMechanismList,
	.C_OpenSession = &C_OpenSession,
	.C_CloseSession = &C_CloseSession,
	.C_Login = &C_Login,
	.C_FindObjectsInit = &C_FindObjectsInit,
	.C_FindObjects = &C_FindObjects,
	.C_FindObjectsFinal = &C_FindObjectsFinal,
	.C_DecryptInit = &C_DecryptInit,
	.C_Decrypt = &C_Decrypt,
	.C_SignInit = &C_SignInit,
	.C_Sign = &C_Sign,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR* ppFunctionList) {
    *ppFunctionList = &g_func_list;
    return CKR_OK;
}

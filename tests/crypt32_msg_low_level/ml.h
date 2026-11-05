/* crypt32 CryptMsg* low-level message tests: shared helpers. */
#ifndef ML_H
#define ML_H
#define CMSG_ENVELOPED_ENCODE_INFO_HAS_CMS_FIELDS 1
#include "t.h"
#include <wincrypt.h>
#include "vectors.h"

#ifndef CMSG_ENCODED_SIGNER
#define CMSG_ENCODED_SIGNER 28
#endif
#ifndef CMSG_ENCODED_MESSAGE
#define CMSG_ENCODED_MESSAGE 29
#endif
#ifndef CMSG_VERSION_PARAM
#define CMSG_VERSION_PARAM 30
#endif
#ifndef CRYPT_E_STREAM_MSG_NOT_READY
#define CRYPT_E_STREAM_MSG_NOT_READY ((LONG)0x80091010)
#endif
#ifndef CRYPT_E_HASH_VALUE
#define CRYPT_E_HASH_VALUE ((LONG)0x80091007)
#endif
#ifndef CRYPT_E_INVALID_MSG_TYPE
#define CRYPT_E_INVALID_MSG_TYPE ((LONG)0x80091004)
#endif
#ifndef CRYPT_E_SIGNER_NOT_FOUND
#define CRYPT_E_SIGNER_NOT_FOUND ((LONG)0x8009100E)
#endif
#ifndef CRYPT_E_UNEXPECTED_MSG_TYPE
#define CRYPT_E_UNEXPECTED_MSG_TYPE ((LONG)0x80091008)
#endif
#ifndef CRYPT_E_NOT_FOUND
#define CRYPT_E_NOT_FOUND ((LONG)0x80092004)
#endif
#ifndef CRYPT_E_MSG_ERROR
#define CRYPT_E_MSG_ERROR ((LONG)0x80091001)
#endif
#ifndef CRYPT_E_UNKNOWN_ALGO
#define CRYPT_E_UNKNOWN_ALGO ((LONG)0x80091002)
#endif
#ifndef CRYPT_E_INVALID_INDEX
#define CRYPT_E_INVALID_INDEX ((LONG)0x80092005)
#endif
#ifndef CRYPT_E_NO_DECRYPT_CERT
#define CRYPT_E_NO_DECRYPT_CERT ((LONG)0x8009200C)
#endif
#ifndef CRYPT_E_BAD_MSG
#define CRYPT_E_BAD_MSG ((LONG)0x8009200D)
#endif

#define ENC PKCS_7_ASN_ENCODING
#define OID_SHA1   "1.3.14.3.2.26"
#define OID_SHA256 "2.16.840.1.101.3.4.2.1"
#define OID_MD5    "1.2.840.113549.2.5"
#define OID_AES128 "2.16.840.1.101.3.4.1.2"
#define OID_AES256 "2.16.840.1.101.3.4.1.42"
#define OID_3DES   "1.2.840.113549.3.7"
#define OID_RSA    "1.2.840.113549.1.1.1"
#define OID_DATA   "1.2.840.113549.1.7.1"

#define REQ_MSG() do { REQUIRE(t_proc_in("crypt32.dll", "CryptMsgOpenToEncode")); REQUIRE(t_proc_in("crypt32.dll", "CryptMsgOpenToDecode")); \
    REQUIRE(t_proc_in("crypt32.dll", "CryptMsgUpdate")); REQUIRE(t_proc_in("crypt32.dll", "CryptMsgGetParam")); \
    REQUIRE(t_proc_in("crypt32.dll", "CryptMsgControl")); REQUIRE(t_proc_in("crypt32.dll", "CryptMsgClose")); } while (0)

#define mOpenEnc() UIN("crypt32.dll", CryptMsgOpenToEncode)
#define mOpenDec() UIN("crypt32.dll", CryptMsgOpenToDecode)
#define mUpdate() UIN("crypt32.dll", CryptMsgUpdate)
#define mGetParam() UIN("crypt32.dll", CryptMsgGetParam)
#define mControl() UIN("crypt32.dll", CryptMsgControl)
#define mClose() UIN("crypt32.dll", CryptMsgClose)
#define mDup() UIN("crypt32.dll", CryptMsgDuplicate)
#define mCalcLen() UIN("crypt32.dll", CryptMsgCalculateEncodedLength)

/* ---- helpers (ml_util.c) ---- */
const BYTE *ml_memmem(const BYTE *h, size_t hn, const BYTE *n, size_t nn);
HCRYPTPROV ml_prov(const BYTE *keyblob, DWORD cb);        /* VERIFYCONTEXT provider with the private key imported (0 on failure) */
void ml_prov_release(HCRYPTPROV p);
PCCERT_CONTEXT ml_cert(const BYTE *der, DWORD cb);        /* CertCreateCertificateContext */
void ml_cert_free(PCCERT_CONTEXT c);
/* CryptMsgGetParam wrapper: size query then fetch. Returns LocalAlloc'd buffer (NULL on failure, last error preserved). */
BYTE *ml_param(HCRYPTMSG m, DWORD pt, DWORD idx, DWORD *cb);
void ml_free(void *p);
BOOL ml_param_dword(HCRYPTMSG m, DWORD pt, DWORD idx, DWORD *out);
/* Encode helpers: return final encoded message via CMSG_CONTENT_PARAM (LocalAlloc'd). */
BYTE *ml_encode_data(DWORD flags, const BYTE *data, DWORD cb, DWORD *out_cb);
/* Decode a complete message with one final update; type 0 = autodetect. */
HCRYPTMSG ml_decode(const BYTE *der, DWORD cb, DWORD type, DWORD flags);
/* Signed message encoder. */
typedef struct {
    HCRYPTPROV prov; PCCERT_CONTEXT cert; PCCERT_CONTEXT cert2; HCRYPTPROV prov2;
    CMSG_SIGNER_ENCODE_INFO si[2]; CMSG_SIGNED_ENCODE_INFO se;
    CERT_BLOB certblob[2]; CRYPT_ATTRIBUTE attr; CRYPT_ATTR_BLOB attrval;
} ml_signer_t;
BOOL ml_signer_init(ml_signer_t *s, const char *hash_oid);   /* signer 1 only; cert not embedded */
void ml_signer_done(ml_signer_t *s);
/* Sign `data` with signer 1; returns encoded message (LocalAlloc'd) */
BYTE *ml_sign(ml_signer_t *s, DWORD flags, const char *hash_oid, const BYTE *data, DWORD cb, DWORD *out_cb);
#endif

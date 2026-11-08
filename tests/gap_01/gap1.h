/* Shared helpers for the gap_01 area. Every call into the DLLs under test goes through U()/UIN()/UN(). */
#ifndef GAP1_H
#define GAP1_H
/* the CMS fields of CMSG_SIGNER_ENCODE_INFO (SignerId, HashEncryptionAlgorithm) are part of the documented struct */
#define CMSG_SIGNER_ENCODE_INFO_HAS_CMS_FIELDS
#include "t.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include "bcrypt_handles.h"
#include <ncrypt.h>
#include <stdlib.h>
#include "vectors.h"

#define ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define ST_INVALID_HANDLE     ((NTSTATUS)0xC0000008)
#define ST_INVALID_PARAMETER  ((NTSTATUS)0xC000000D)
#define ST_BUFFER_TOO_SMALL   ((NTSTATUS)0xC0000023)
#define ST_NOT_SUPPORTED      ((NTSTATUS)0xC00000BB)
#define ST_NOT_FOUND          ((NTSTATUS)0xC0000225)
#define ST_INVALID_SIGNATURE  ((NTSTATUS)0xC000A000)
#define ST_AUTH_TAG_MISMATCH  ((NTSTATUS)0xC000A002)
#define E_INVALIDARG_         ((DWORD)0x80070057)
#define NTE_BAD_SIGNATURE_    ((DWORD)0x80090006)
#define CRYPT_E_INVALID_MSG_TYPE_  ((DWORD)0x80091004)
#define CRYPT_E_AUTH_ATTR_MISSING_ ((DWORD)0x80091006)
#define CRYPT_E_ATTRIBUTES_MISSING_ ((DWORD)0x8009100F)
#define CRYPT_E_MSG_ERROR_    ((DWORD)0x80091001)
#define CRYPT_E_HASH_VALUE_   ((DWORD)0x80091007)
#define CRYPT_E_INVALID_INDEX_ ((DWORD)0x80091008)
#define CRYPT_E_UNEXPECTED_MSG_TYPE_ ((DWORD)0x8009200A)
#define CRYPT_E_NO_SIGNER_    ((DWORD)0x8009200E)
#define CRYPT_E_ASN1_ANY(e)   (((e) & 0xFFFFFF00u) == 0x80093100u)
#define TRUST_E_SUBJECT_FORM_UNKNOWN_ ((DWORD)0x800B0003)
#define OID_SHA1   "1.3.14.3.2.26"
#define OID_SHA256 "2.16.840.1.101.3.4.2.1"
#define OID_SHA512 "2.16.840.1.101.3.4.2.3"
#define OID_MD5    "1.2.840.113549.2.5"
#define BLOB(x) x, (DWORD)sizeof(x)

/* identity A/B: ephemeral CAPI provider with the private key imported, cert contexts without a key */
typedef struct { PCCERT_CONTEXT cert; HCRYPTPROV prov; } g1_id;
extern g1_id g1_A, g1_B;
NCRYPT_KEY_HANDLE g1_cng_key(const BYTE *capi_privblob);   /* ephemeral CNG copy of a legacy RSA private key blob, 0 on failure */
int g1_init(void);                  /* 1 on success, else t_skip + 0 */
#define G1_INIT() do { if (!g1_init()) return; } while (0)

#define NOWINE_STUB() do { if (t_is_wine()) { t_skip("export is an unimplemented stub in the emulator"); return; } } while (0)
/* DER helpers */
DWORD g1_der_hdr(const BYTE *p, DWORD cb);
DWORD g1_der_total(const BYTE *p, DWORD cb);
int g1_has(const BYTE *hay, DWORD n, const void *needle, DWORD m);
#define G1_HAS(b, n, lit) g1_has((b), (n), (lit), sizeof(lit) - 1)
#endif

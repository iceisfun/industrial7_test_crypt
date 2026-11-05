/* Shared helpers for crypt32_asn_keys_pkcs_misc: DER vector based encode/decode checks.
 * Every call goes through GetProcAddress (U()); CryptEncodeObject(Ex)/CryptDecodeObject(Ex) are
 * resolved from crypt32.dll. LocalFree/GetLastError are trivial scaffolding. */
#ifndef KP_H
#define KP_H
#include "t.h"
#include <wincrypt.h>

#define KP_ENC X509_ASN_ENCODING
#define KP_ENC_P7 (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#ifndef CRYPT_E_ASN1_EOD
#define CRYPT_E_ASN1_EOD 0x80093102
#endif
#define KP_E_EOD      ((DWORD)0x80093102)
#define KP_E_CORRUPT  ((DWORD)0x80093103)
/* truncated input: the ASN.1 layer reports either EOD or CORRUPT depending on where the cut falls */
#define KP_E_TRUNC    ((DWORD)1)
#define KP_E_LARGE    ((DWORD)0x80093104)
#define KP_E_BADTAG   ((DWORD)0x8009310B)
#define KP_E_INVALIDARG ((DWORD)0x80070057)

/* Bytes literal: V(1,2,3) expands to two arguments (pointer, length). */
#define V(...) ((const BYTE[]){__VA_ARGS__}), sizeof((const BYTE[]){__VA_ARGS__})

#define KP_OID_STR(x) ((LPCSTR)(ULONG_PTR)(x))

/* Encode with CRYPT_ENCODE_ALLOC_FLAG; returns buffer (free with kp_free) or NULL. */
BYTE *kp_enc_alloc(LPCSTR type, const void *info, DWORD flags, DWORD *cb);
void  kp_free(void *p);
/* Decode with CRYPT_DECODE_ALLOC_FLAG; returns struct (free with kp_free) or NULL; *cb = size. */
void *kp_dec_alloc(LPCSTR type, const BYTE *der, size_t n, DWORD flags, DWORD *cb);

/* Full encode-side contract: Ex alloc, Ex into exact buffer, size query, buffer too small, plain CryptEncodeObject. */
void kp_check_enc(const char *file, int line, LPCSTR type, const void *info, const BYTE *want, size_t n);
/* encode must fail with last error err (checked for both Ex and plain APIs). */
void kp_check_enc_fail(const char *file, int line, LPCSTR type, const void *info, DWORD err);
/* decode must fail with last error err (0 = only check failure). */
void kp_check_dec_fail(const char *file, int line, LPCSTR type, const BYTE *der, size_t n, DWORD err);
/* decode success; returns struct (free with kp_free), also exercises the size protocol. */
void *kp_check_dec(const char *file, int line, LPCSTR type, const BYTE *der, size_t n, DWORD flags);

#define ENC_EQ(type, info, ...)   kp_check_enc(__FILE__, __LINE__, type, info, __VA_ARGS__)
#define ENC_FAIL(type, info, err) kp_check_enc_fail(__FILE__, __LINE__, type, info, err)
#define DEC_FAIL_(type, p, n, err) kp_check_dec_fail(__FILE__, __LINE__, type, p, n, err)
#define DEC_FAIL(type, ...)       DEC_FAIL_(type, __VA_ARGS__)
#define DEC_FAILV(type, err, ...) kp_check_dec_fail(__FILE__, __LINE__, type, V(__VA_ARGS__), err)
#define DEC_OK_(type, p, n, fl)   kp_check_dec(__FILE__, __LINE__, type, p, n, fl)
#define DEC_OK(type, ...)         DEC_OK_(type, __VA_ARGS__)

/* blob equality helpers */
#define BLOB_IS(b, ...) kp_blob_is(__FILE__, __LINE__, #b, (b).cbData, (b).pbData, V(__VA_ARGS__))
void kp_blob_is(const char *file, int line, const char *what, DWORD cb, const BYTE *pb, const BYTE *want, size_t n);
/* Under an emulator that lacks a codec the dependent tests are skipped; on Windows a missing codec is a failure. */
int kp_type_known(LPCSTR type);
#define REQ_TYPE(t) do { REQUIRE(t_proc_in("crypt32.dll", "CryptEncodeObjectEx")); REQUIRE(t_proc_in("crypt32.dll", "CryptDecodeObjectEx")); \
    REQUIRE(t_proc_in("crypt32.dll", "CryptEncodeObject")); REQUIRE(t_proc_in("crypt32.dll", "CryptDecodeObject")); \
    if (t_is_wine() && !kp_type_known(t)) { t_skip("codec not provided by the emulator"); return; } } while (0)
#endif

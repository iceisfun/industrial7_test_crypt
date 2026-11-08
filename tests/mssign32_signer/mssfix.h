/* Shared declarations and fixtures for the mssign32_signer area.
 * mssign32.dll has no SDK header: every structure and prototype is declared here from the
 * documented / observed layouts. All calls into the DLLs under test go through GetProcAddress. */
#ifndef MSSFIX_H
#define MSSFIX_H
#include "t.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include "bcrypt_handles.h"
#include <stdint.h>

/* The tested exports are all stubs that abort the process under Wine: REQUIRE also skips there.
 * Fixture self-tests (fixtures.c) use CHECK-only guards and do run everywhere. */
#undef REQUIRE
#define REQUIRE(ptr) do { if (!(ptr)) { t_skip("missing export: " #ptr); return; } \
    if (t_is_wine()) { t_skip("mssign32 exports are stubs under Wine"); return; } } while (0)

/* ---- structures (x64 layouts) ---- */
typedef struct { DWORD cbSize; DWORD *pdwIndex; DWORD dwSubjectChoice; void *pInfo; } SG_SUBJECT;            /* 32 */
typedef struct { DWORD cbSize; LPCWSTR pwszFileName; HANDLE hFile; } SG_FILE;                              /* 24 */
typedef struct { DWORD cbSize; GUID *pGuidSubject; DWORD cbBlob; BYTE *pbBlob; LPCWSTR pwszDisplayName; } SG_BLOB; /* 40 */
typedef struct { DWORD cbSize; DWORD dwCertChoice; void *pInfo; HWND hwnd; } SG_CERT;                      /* 24 */
typedef struct { DWORD cbSize; PCCERT_CONTEXT pSigningCert; DWORD dwCertPolicy; HCERTSTORE hCertStore; } SG_CERTSTORE; /* 32 */
typedef struct { DWORD cbSize; LPCWSTR pwszSpcFile; DWORD dwCertPolicy; HCERTSTORE hCertStore; } SG_SPCCHAIN;  /* 32 */
typedef struct { DWORD cbSize; DWORD fCommercial; DWORD fIndividual; LPCWSTR pwszName; LPCWSTR pwszInfo; } SG_AUTHCODE; /* 32 */
typedef struct { DWORD cbSize; DWORD algId; DWORD dwAttrChoice; void *pAttrAuthcode; PCRYPT_ATTRIBUTES psAuthenticated; PCRYPT_ATTRIBUTES psUnauthenticated; } SG_SIGINFO; /* 40 */
typedef struct { DWORD cbSize; LPCWSTR pwszProviderName; DWORD dwProviderType; DWORD dwKeySpec; DWORD dwPvkChoice; void *pInfo; } SG_PROV; /* 40 */
typedef struct { DWORD cbSize; DWORD cbBlob; BYTE *pbBlob; } SG_CTX;                                       /* 16 */

#define SG_SUBJECT_FILE 1
#define SG_SUBJECT_BLOB 2
#define SG_CERT_SPC_FILE 1
#define SG_CERT_STORE 2
#define SG_CERT_SPC_CHAIN 3
#define SG_NO_ATTR 0
#define SG_AUTHCODE_ATTR 1
#define SG_PVK_FILE 1
#define SG_PVK_CONTAINER 2

#define HR_INVALIDARG    0x80070057u
#define HR_FILE_NOT_FOUND 0x80070002u
#define HR_PATH_NOT_FOUND 0x80070003u
#define HR_NO_PROVIDER   0x80092006u  /* CRYPT_E_NO_PROVIDER */
#define HR_NO_MATCH      0x80092009u  /* CRYPT_E_NO_MATCH */
#define HR_NO_KEY_PROP   0x8009200Bu  /* CRYPT_E_NO_KEY_PROPERTY */
#define PVK_E_BADFILE    0x80097002u
#define PVK_E_WRONGTYPE  0x80097003u
#define PVK_E_NOPASSWORD 0x80097004u

/* ---- prototypes (no SDK header) ---- */
UDECL(HRESULT, SignerSign, (SG_SUBJECT*, SG_CERT*, SG_SIGINFO*, SG_PROV*, PCWSTR, PCRYPT_ATTRIBUTES, PVOID));
UDECL(HRESULT, SignerSignEx, (DWORD, SG_SUBJECT*, SG_CERT*, SG_SIGINFO*, SG_PROV*, PCWSTR, PCRYPT_ATTRIBUTES, PVOID, SG_CTX**));
UDECL(HRESULT, SignerSignEx2, (DWORD, SG_SUBJECT*, SG_CERT*, SG_SIGINFO*, SG_PROV*, DWORD, PCSTR, PCWSTR, PCRYPT_ATTRIBUTES, PVOID, SG_CTX**, PVOID, PVOID));
UDECL(HRESULT, SignerSignEx3, (DWORD, SG_SUBJECT*, SG_CERT*, SG_SIGINFO*, SG_PROV*, DWORD, PCSTR, PCWSTR, PCRYPT_ATTRIBUTES, PVOID, SG_CTX**, PVOID, PVOID, PVOID));
UDECL(HRESULT, SignerFreeSignerContext, (SG_CTX*));
UDECL(HRESULT, SignerTimeStamp, (SG_SUBJECT*, PCWSTR, PCRYPT_ATTRIBUTES, PVOID));
UDECL(HRESULT, SignerTimeStampEx, (DWORD, SG_SUBJECT*, PCWSTR, PCRYPT_ATTRIBUTES, PVOID, SG_CTX**));
UDECL(HRESULT, SignerTimeStampEx2, (DWORD, SG_SUBJECT*, PCWSTR, PCSTR, PCRYPT_ATTRIBUTES, PVOID, SG_CTX**));
UDECL(HRESULT, SignerTimeStampEx3, (DWORD, DWORD, SG_SUBJECT*, PCWSTR, PCSTR, PCRYPT_ATTRIBUTES, PVOID, SG_CTX**, PVOID, PVOID));
UDECL(HRESULT, SignerCreateTimeStampRequest, (SG_SUBJECT*, PCRYPT_ATTRIBUTES, PVOID, PBYTE, DWORD*));
UDECL(HRESULT, SignerAddTimeStampResponse, (SG_SUBJECT*, PBYTE, DWORD, PVOID));
UDECL(HRESULT, SignerAddTimeStampResponseEx, (DWORD, SG_SUBJECT*, PBYTE, DWORD, PVOID, SG_CTX**));
UDECL(DWORD,   SignError, (void));
UDECL(LONG,    SpcGetCertFromKey, (DWORD, HCERTSTORE, HCRYPTPROV, DWORD, PCCERT_CONTEXT*));
UDECL(BOOL, GetCryptProvFromCert, (HWND, PCCERT_CONTEXT, HCRYPTPROV*, DWORD*, BOOL*, LPWSTR*, LPWSTR*, DWORD*));
UDECL(BOOL, GetCryptProvFromCertEx, (HWND, PCCERT_CONTEXT, HCRYPTPROV*, DWORD*, BOOL*, LPWSTR*, LPWSTR*, DWORD*));
UDECL(void, FreeCryptProvFromCert, (BOOL, HCRYPTPROV, LPWSTR, DWORD, LPWSTR));
UDECL(void, FreeCryptProvFromCertEx, (BOOL, HCRYPTPROV, DWORD, LPWSTR, DWORD, LPWSTR));
/* Pvk API (wide) */
UDECL(BOOL, PvkPrivateKeySave, (HCRYPTPROV, HANDLE, DWORD, HWND, LPWSTR, DWORD));
UDECL(BOOL, PvkPrivateKeyLoad, (HCRYPTPROV, HANDLE, HWND, LPWSTR, DWORD, DWORD*));
UDECL(BOOL, PvkPrivateKeyAcquireContext, (LPCWSTR, DWORD, HANDLE, HWND, LPWSTR, DWORD*, HCRYPTPROV*, LPWSTR*));
UDECL(BOOL, PvkPrivateKeyAcquireContextFromMemory, (LPCWSTR, DWORD, PBYTE, DWORD, HWND, LPWSTR, DWORD*, HCRYPTPROV*, LPWSTR*));
UDECL(BOOL, PvkPrivateKeyLoadFromMemory, (HCRYPTPROV, PBYTE, DWORD, HWND, LPWSTR, DWORD, DWORD*));
UDECL(BOOL, PvkPrivateKeySaveToMemory, (HCRYPTPROV, DWORD, HWND, LPWSTR, DWORD, PBYTE, DWORD*));
UDECL(BOOL, PvkPrivateKeyReleaseContext, (HCRYPTPROV, LPCWSTR, DWORD, LPWSTR));
/* Pvk API (ansi) */
UDECL(BOOL, PvkPrivateKeySaveA, (HCRYPTPROV, HANDLE, DWORD, HWND, LPSTR, DWORD));
UDECL(BOOL, PvkPrivateKeyLoadA, (HCRYPTPROV, HANDLE, HWND, LPSTR, DWORD, DWORD*));
UDECL(BOOL, PvkPrivateKeyAcquireContextA, (LPCSTR, DWORD, HANDLE, HWND, LPSTR, DWORD*, HCRYPTPROV*, LPSTR*));
UDECL(BOOL, PvkPrivateKeyAcquireContextFromMemoryA, (LPCSTR, DWORD, PBYTE, DWORD, HWND, LPSTR, DWORD*, HCRYPTPROV*, LPSTR*));
UDECL(BOOL, PvkPrivateKeyLoadFromMemoryA, (HCRYPTPROV, PBYTE, DWORD, HWND, LPSTR, DWORD, DWORD*));
UDECL(BOOL, PvkPrivateKeySaveToMemoryA, (HCRYPTPROV, DWORD, HWND, LPSTR, DWORD, PBYTE, DWORD*));
UDECL(BOOL, PvkPrivateKeyReleaseContextA, (HCRYPTPROV, LPCSTR, DWORD, LPSTR));
UDECL(DWORD, PvkGetCryptProv, (HWND, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD*, LPWSTR*, HCRYPTPROV*));
UDECL(void, PvkFreeCryptProv, (HCRYPTPROV, LPCWSTR, DWORD, LPWSTR));

/* ---- fixtures ---- */
enum { FX_A = 0, FX_B = 1 };
const BYTE *fx_cert_der(int which, DWORD *cb);
/* PRIVATEKEYBLOB for key `which`, algid patched to CALG_RSA_KEYX (keyspec 1) or CALG_RSA_SIGN (2). */
DWORD fx_keyblob(int which, int keyspec, BYTE *out, DWORD cap);
/* PVK image: 24-byte header + blob. hdr fields are explicit so tests can corrupt each one. */
DWORD fx_pvk(int which, int keyspec, DWORD encrypt, DWORD saltlen, BYTE *out, DWORD cap);
void fx_pvk_hdr(BYTE *out, DWORD magic, DWORD reserved, DWORD keytype, DWORD encrypt, DWORD saltlen, DWORD keylen);
const BYTE *fx_sig_sha1_abc(DWORD *cb);

typedef struct {
    HCRYPTPROV hProv;
    int persisted;            /* named container holding the key */
    WCHAR name[64];
    int which, keyspec;
    PCCERT_CONTEXT cert;      /* certificate with CERT_KEY_CONTEXT_PROP_ID -> hProv (after fx_cert_attach) */
} FX;
/* Open an RSA_AES context holding key `which` as `keyspec` in a uniquely named container (deleted by fx_close;
 * SHA-2 signing needs a persisted key). Returns 1 on success. */
int  fx_open(FX *f, int which, int keyspec);
/* Open an empty ephemeral (CRYPT_VERIFYCONTEXT) context without a key. */
int  fx_open_empty(FX *f);
int  fx_cert_attach(FX *f);   /* create cert context, set CERT_KEY_CONTEXT_PROP_ID */
void fx_close(FX *f);

/* PE */
#define FX_PE_SIZE 0x400
void  fx_pe_image(BYTE *b);
int   fx_write_file(const char *path, const void *p, DWORD n);
BYTE *fx_read_file(const char *path, DWORD *n);   /* free() */
LPWSTR fx_w(const char *s);                       /* malloc'd */
int   fx_pe_secdir(const BYTE *b, DWORD n, DWORD *off, DWORD *size);
void  fx_pe_new(char *path, size_t cap, const char *leaf);   /* writes a fresh unsigned PE */
/* Authenticode hash of the signed or unsigned PE image (headers+section, no cert table). */
int   fx_pe_authhash(const BYTE *b, DWORD n, LPCWSTR alg, BYTE *out, DWORD *cbout);
/* sign the PE at path using fixture f (store-info cert, no attr) */
HRESULT fx_sign(FX *f, const char *path, DWORD algid, DWORD flags, SG_CTX **ctx);
/* CryptQueryObject on the PE's embedded signature; returns HCRYPTMSG (caller closes) or NULL */
HCRYPTMSG fx_query_pe(const char *path, HCERTSTORE *store);
DWORD fx_signer_count(HCRYPTMSG m);
/* OID string of the digest algorithm of signer 0 (malloc'd) */
char *fx_signer_digest_oid(HCRYPTMSG m);
HRESULT fx_verify_trust(const char *path);
#endif

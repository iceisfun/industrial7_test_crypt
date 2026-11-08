/* Shared helpers for the bcrypt_hash_hmac area. Everything under test is reached via LoadLibrary +
 * GetProcAddress (U()); nothing here links against the DLL. */
#ifndef HH_H
#define HH_H
#include "t.h"
#include <bcrypt.h>
#include "bcrypt_handles.h"
#include <stdlib.h>
#include <wchar.h>

#define NS_OK               ((NTSTATUS)0x00000000)
#define NS_INVALID_HANDLE   ((NTSTATUS)0xC0000008)
#define NS_INVALID_PARAM    ((NTSTATUS)0xC000000D)
#define NS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define NS_NOT_SUPPORTED    ((NTSTATUS)0xC00000BB)
#define NS_INVALID_BUFFER_SIZE ((NTSTATUS)0xC0000206)
#define NS_GMAC_IV_STATE    ((NTSTATUS)0xC000042A)

#ifndef BCRYPT_HASH_REUSABLE_FLAG
#define BCRYPT_HASH_REUSABLE_FLAG 0x20
#endif
#ifndef BCRYPT_ALG_HANDLE_HMAC_FLAG
#define BCRYPT_ALG_HANDLE_HMAC_FLAG 0x8
#endif
#ifndef BCRYPT_OBJECT_LENGTH
#define BCRYPT_OBJECT_LENGTH L"ObjectLength"
#endif
#ifndef BCRYPT_HASH_LENGTH
#define BCRYPT_HASH_LENGTH L"HashDigestLength"
#endif
#ifndef BCRYPT_HASH_BLOCK_LENGTH
#define BCRYPT_HASH_BLOCK_LENGTH L"HashBlockLength"
#endif
#ifndef BCRYPT_ALGORITHM_NAME
#define BCRYPT_ALGORITHM_NAME L"AlgorithmName"
#endif
/* evaluates its first argument exactly once (EXPECT_EQ evaluates its arguments twice) */
#define EXPECT_ST(call, want) do { NTSTATUS st_ = (call); NTSTATUS w_ = (NTSTATUS)(want); \
    t_check(st_ == w_, __FILE__, __LINE__, #call " == " #want, "got 0x%08lx want 0x%08lx", (unsigned long)st_, (unsigned long)w_); } while (0)
#define HH_P_OPEN() U(BCryptOpenAlgorithmProvider)
#define HH_P_CLOSE() U(BCryptCloseAlgorithmProvider)
#define HH_P_GETPROP() U(BCryptGetProperty)
#define HH_P_SETPROP() U(BCryptSetProperty)
#define HH_P_CREATE() U(BCryptCreateHash)
#define HH_P_DATA() U(BCryptHashData)
#define HH_P_FINISH() U(BCryptFinishHash)
#define HH_P_DESTROY() U(BCryptDestroyHash)
#define HH_P_DUP() U(BCryptDuplicateHash)
#define HH_P_HASH() U(BCryptHash)
#define HH_P_CMULTI() U(BCryptCreateMultiHash)
#define HH_P_PMULTI() U(BCryptProcessMultiOperations)

/* ---- vector tables (generated at authoring time; see hh_vectors*.c) ----- */
struct hh_spec { char kind; ULONG len; int a, b; const char *hex; };   /* 'p': (i*a+b)&255, 'r': repeat byte a, 'l': hex literal */
struct hh_hvec { const char *alg; struct hh_spec in; const char *hex; };
struct hh_mvec { const char *alg; struct hh_spec key, msg; const char *hex; };
struct hh_cvec { struct hh_spec key, msg; const char *hex; };
struct hh_gvec { struct hh_spec key, iv, aad; const char *hex; };
struct hh_rfcvec { const char *name, *alg, *keyhex, *datahex, *mac; };
extern const struct hh_rfcvec hh_rfcvecs[]; extern const unsigned hh_nrfcvecs;
extern const struct hh_hvec hh_hvecs[]; extern const unsigned hh_nhvecs;
extern const struct hh_mvec hh_mvecs[]; extern const unsigned hh_nmvecs;
extern const struct hh_cvec hh_cvecs[]; extern const unsigned hh_ncvecs;
extern const struct hh_gvec hh_gvecs[]; extern const unsigned hh_ngvecs;

/* ---- algorithm table ---------------------------------------------------- */
struct hh_alg {
    const char *name; const WCHAR *wname; ULONG digest, block;
    BCRYPT_ALG_HANDLE pseudo, hmac_pseudo;      /* hmac_pseudo may be NULL */
};
extern const struct hh_alg hh_algs[]; extern const unsigned hh_nalgs;   /* MD2 MD4 MD5 SHA1 SHA256 SHA384 SHA512 */
const struct hh_alg *hh_find(const char *name);

/* ---- helpers ------------------------------------------------------------ */
BYTE *hh_spec_new(const struct hh_spec *s, ULONG *len);                 /* malloc'd, never NULL (min 1 byte) */
ULONG hh_unhex(const char *hex, BYTE *out);
void  hh_tohex(const BYTE *p, ULONG n, char *out);
int   hh_eqhex(const BYTE *p, ULONG n, const char *hex);               /* digest == hex string */
BCRYPT_ALG_HANDLE hh_open(const WCHAR *name, ULONG flags);             /* NULL (and a failed CHECK) on error */
void  hh_close(BCRYPT_ALG_HANDLE h);
ULONG hh_prop_ulong(void *h, const WCHAR *prop, int *ok);
ULONG hh_objlen(BCRYPT_ALG_HANDLE h);
/* mode: 0 heap object (NULL buffer), 1 caller buffer sized by ObjectLength, 2 heap + REUSABLE flag.
 * chunk 0 = one HashData call. Returns the status of the first failing call. */
NTSTATUS hh_compute(BCRYPT_ALG_HANDLE a, const BYTE *key, ULONG kl, const BYTE *d, ULONG n, ULONG chunk, int mode, BYTE *out, ULONG outlen);
void  hh_lcg_fill(BYTE *p, ULONG n, ULONG seed);
#endif

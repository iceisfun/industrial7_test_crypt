/* Shared helpers for the bcrypt_symmetric_ciphers area.
 * Everything under test is reached through GetProcAddress (U()). */
#ifndef BSC_H
#define BSC_H
#include "t.h"
#include <bcrypt.h>
#include <stdlib.h>
#include <wchar.h>

/* NTSTATUS values (own names: the SDK macro set differs between header versions) */
#define NS_OK            0x00000000L
#define NS_INVALID_HANDLE ((NTSTATUS)0xC0000008)
#define NS_INVALID_PARAM  ((NTSTATUS)0xC000000D)
#define NS_NO_MEMORY      ((NTSTATUS)0xC0000017)
#define NS_ACCESS_DENIED  ((NTSTATUS)0xC0000022)
#define NS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define NS_NOT_FOUND      ((NTSTATUS)0xC0000225)
#define NS_NOT_SUPPORTED  ((NTSTATUS)0xC00000BB)
#define NS_INVALID_BUFFER_SIZE ((NTSTATUS)0xC0000206)
#define NS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002)
#define NS_DATA_ERROR     ((NTSTATUS)0xC000003E)

#ifndef BCRYPT_XTS_AES_ALGORITHM
#define BCRYPT_XTS_AES_ALGORITHM L"XTS-AES"
#endif
#ifndef BCRYPT_CHAIN_MODE_CCM
#define BCRYPT_CHAIN_MODE_CCM L"ChainingModeCCM"
#endif

/* The harness EXPECT_EQ evaluates its arguments twice (once for the test, once for the message), which is wrong
 * for calls with side effects. Re-define it to evaluate once. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { unsigned long long a_ = (unsigned long long)(ULONG_PTR)(a), b_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)

#define P_Open    U(BCryptOpenAlgorithmProvider)
#define P_Close   U(BCryptCloseAlgorithmProvider)
#define P_GetProp U(BCryptGetProperty)
#define P_SetProp U(BCryptSetProperty)
#define P_GenKey  U(BCryptGenerateSymmetricKey)
#define P_Destroy U(BCryptDestroyKey)
#define P_Dup     U(BCryptDuplicateKey)
#define P_Enc     U(BCryptEncrypt)
#define P_Dec     U(BCryptDecrypt)
#define P_Imp     U(BCryptImportKey)
#define P_Exp     U(BCryptExportKey)

/* Wine's bcrypt lacks some ciphers/modes; skip those there (no-op on Windows). */
#define WINE_UNSUP(st) (t_is_wine() && ((NTSTATUS)(st) == (NTSTATUS)0xC00000BB || (NTSTATUS)(st) == (NTSTATUS)0xC0000002 || (NTSTATUS)(st) == (NTSTATUS)0xC0000225))

static size_t hx(const char *s, BYTE *o) {
    size_t n = 0;
    for (; s[0] && s[1]; s += 2) { unsigned v; sscanf(s, "%2x", &v); o[n++] = (BYTE)v; }
    return n;
}
static int same(const BYTE *a, const BYTE *b, size_t n) { return memcmp(a, b, n) == 0; }
static void hexs(const BYTE *a, size_t n, char *o) { for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", a[i]); o[2 * n] = 0; }
/* compare buffer with hex string; reports a diff on failure */
#define CHECK_HEX(buf, n, hexstr) do { BYTE e_[4096]; size_t el_ = hx(hexstr, e_); \
    CHECKF(el_ == (size_t)(n) && same((buf), e_, el_), "len %u/%u want %s", (unsigned)(n), (unsigned)el_, hexstr); } while (0)

/* An algorithm handle with optional chaining mode. */
static BCRYPT_ALG_HANDLE bsc_open(const wchar_t *alg, const wchar_t *mode) {
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS st = P_Open(&h, alg, NULL, 0);
    if (st != 0) return NULL;
    if (mode) {
        st = P_SetProp(h, BCRYPT_CHAINING_MODE, (PUCHAR)mode, (ULONG)((wcslen(mode) + 1) * 2), 0);
        if (st != 0) { P_Close(h, 0); return NULL; }
    }
    return h;
}
static void bsc_close(BCRYPT_ALG_HANDLE h) { if (h) P_Close(h, 0); }

/* A key with caller-provided key object (so the memory outlives BCryptDestroyKey and stays inspectable). */
typedef struct { BCRYPT_KEY_HANDLE h; BYTE *obj; ULONG cb; } bkey;
static ULONG bsc_objlen(BCRYPT_ALG_HANDLE a) {
    ULONG v = 0, r = 0;
    P_GetProp(a, BCRYPT_OBJECT_LENGTH, (PUCHAR)&v, 4, &r, 0);
    return v;
}
static NTSTATUS bsc_gen(BCRYPT_ALG_HANDLE a, bkey *k, const BYTE *secret, ULONG cb) {
    memset(k, 0, sizeof *k);
    k->cb = bsc_objlen(a);
    k->obj = (BYTE *)calloc(1, k->cb ? k->cb : 1);
    return P_GenKey(a, &k->h, k->obj, k->cb, (PUCHAR)secret, cb, 0);
}
static NTSTATUS bsc_genhex(BCRYPT_ALG_HANDLE a, bkey *k, const char *hexkey) {
    BYTE s[128]; size_t n = hx(hexkey, s);
    return bsc_gen(a, k, s, (ULONG)n);
}
static void bsc_free(bkey *k) { if (k->h) P_Destroy(k->h); k->h = NULL; free(k->obj); k->obj = NULL; }

/* One-shot encrypt/decrypt helpers returning status; out gets *n bytes. */
static NTSTATUS enc(BCRYPT_KEY_HANDLE k, const BYTE *in, ULONG nin, BYTE *iv, ULONG niv, BYTE *out, ULONG cbout, ULONG *nout, ULONG fl) {
    return P_Enc(k, (PUCHAR)in, nin, NULL, iv, niv, out, cbout, nout, fl);
}
static NTSTATUS dec(BCRYPT_KEY_HANDLE k, const BYTE *in, ULONG nin, BYTE *iv, ULONG niv, BYTE *out, ULONG cbout, ULONG *nout, ULONG fl) {
    return P_Dec(k, (PUCHAR)in, nin, NULL, iv, niv, out, cbout, nout, fl);
}

static const wchar_t *const ALGW_AES = L"AES";

#endif

/* Shared helpers for the capi_symmetric_keys area. Every CryptoAPI call goes through
 * GetProcAddress (U()); only trivial scaffolding is direct. */
#ifndef CK_H
#define CK_H
#include "t.h"
#include <wincrypt.h>
#include "vectors.h"
#include "vectors2.h"

#define NTE_BAD_UID_ 0x80090001L
#define NTE_BAD_KEY_ 0x80090003L
#define NTE_BAD_LEN_ 0x80090004L
#define NTE_BAD_DATA_ 0x80090005L
#define NTE_BAD_ALGID_ 0x80090008L
#define NTE_BAD_FLAGS_ 0x80090009L
#define NTE_BAD_TYPE_ 0x8009000AL
#define NTE_BAD_KEY_STATE_ 0x8009000BL
#define NTE_NO_KEY_ 0x8009000DL

#define KP_NAME_ 0
#define SIZEOFA(a) (sizeof(a)/sizeof((a)[0]))

typedef struct { BLOBHEADER h; DWORD cb; BYTE key[64]; } ck_plainblob;

/* Provider helpers: all contexts are ephemeral (CRYPT_VERIFYCONTEXT). */
static HCRYPTPROV ck_acquire(const char *name, DWORD type) {
    HCRYPTPROV p = 0;
    if (!U(CryptAcquireContextA)) return 0;
    if (!U(CryptAcquireContextA)(&p, NULL, name, type, CRYPT_VERIFYCONTEXT)) return 0;
    return p;
}
static HCRYPTPROV ck_aes(void)  { return ck_acquire(MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES); }
static HCRYPTPROV ck_enh(void)  { return ck_acquire(MS_ENHANCED_PROV_A, PROV_RSA_FULL); }
static HCRYPTPROV ck_base(void) { return ck_acquire(MS_DEF_PROV_A, PROV_RSA_FULL); }
static void ck_release(HCRYPTPROV p) { if (p) U(CryptReleaseContext)(p, 0); }

static BOOL ck_import_plain(HCRYPTPROV p, ALG_ID alg, const void *key, DWORD len, DWORD flags, HCRYPTKEY *out) {
    ck_plainblob b; memset(&b, 0, sizeof b);
    b.h.bType = PLAINTEXTKEYBLOB; b.h.bVersion = CUR_BLOB_VERSION; b.h.aiKeyAlg = alg; b.cb = len;
    memcpy(b.key, key, len);
    *out = 0;
    return U(CryptImportKey)(p, (BYTE *)&b, (DWORD)(offsetof(ck_plainblob, key) + len), 0, flags, out);
}
static HCRYPTKEY ck_key(HCRYPTPROV p, ALG_ID alg, const void *key, DWORD len) {
    HCRYPTKEY k = 0;
    if (!ck_import_plain(p, alg, key, len, CRYPT_EXPORTABLE | CRYPT_NO_SALT, &k)) return 0;
    return k;
}
static DWORD ck_param_dw(HCRYPTKEY k, DWORD kp, BOOL *ok) {
    DWORD v = 0xCCCCCCCC, n = 4; BOOL r = U(CryptGetKeyParam)(k, kp, (BYTE *)&v, &n, 0);
    if (ok) *ok = r; return v;
}
static BOOL ck_set_mode(HCRYPTKEY k, DWORD mode) { return U(CryptSetKeyParam)(k, KP_MODE, (BYTE *)&mode, 0); }
static BOOL ck_set_iv(HCRYPTKEY k, const void *iv) { return U(CryptSetKeyParam)(k, KP_IV, (const BYTE *)iv, 0); }
static BOOL ck_set_pad(HCRYPTKEY k, DWORD pad) { return U(CryptSetKeyParam)(k, KP_PADDING, (BYTE *)&pad, 0); }

/* One-shot encrypt with Final=TRUE. Returns resulting length via *len, FALSE on failure. */
static BOOL ck_enc(HCRYPTKEY k, const void *in, DWORD inlen, BYTE *out, DWORD cap, DWORD *len) {
    DWORD n = inlen; memcpy(out, in, inlen);
    BOOL r = U(CryptEncrypt)(k, 0, TRUE, 0, out, &n, cap); *len = n; return r;
}
static BOOL ck_dec(HCRYPTKEY k, const void *in, DWORD inlen, BYTE *out, DWORD *len) {
    DWORD n = inlen; memcpy(out, in, inlen);
    BOOL r = U(CryptDecrypt)(k, 0, TRUE, 0, out, &n); *len = n; return r;
}
static void ck_hex(char *dst, const BYTE *b, DWORD n) { for (DWORD i = 0; i < n; i++) sprintf(dst + 2 * i, "%02x", b[i]); }
#define CHECK_BYTES(got, want, n) do { \
    if (memcmp((got), (want), (n))) { char g_[200], w_[200]; DWORD m_ = (n) > 96 ? 96 : (n); \
        ck_hex(g_, (const BYTE *)(got), m_); ck_hex(w_, (const BYTE *)(want), m_); \
        t_check(0, __FILE__, __LINE__, "bytes " #got " == " #want, "got %s want %s", g_, w_); } \
    else t_check(1, __FILE__, __LINE__, "", NULL); } while (0)

#define NEED_CRYPT() do { REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptGenKey)); REQUIRE(U(CryptImportKey)); \
    REQUIRE(U(CryptEncrypt)); REQUIRE(U(CryptDecrypt)); REQUIRE(U(CryptGetKeyParam)); REQUIRE(U(CryptSetKeyParam)); \
    REQUIRE(U(CryptDestroyKey)); REQUIRE(U(CryptExportKey)); REQUIRE(U(CryptReleaseContext)); } while (0)
#define NEED_PROV(var) HCRYPTPROV var = ck_aes(); if (!var) { t_skip("AES provider unavailable (err %lu)", GetLastError()); return; }
#endif

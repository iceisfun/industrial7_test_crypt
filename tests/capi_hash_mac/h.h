/* Shared helpers for the capi_hash_mac area (CryptoAPI v1 hashing, MAC/HMAC, sign/verify). */
#ifndef CHM_H
#define CHM_H
#include "t.h"
#include <wincrypt.h>

#ifndef NTE_BAD_UID
#define NTE_BAD_UID 0x80090001L
#endif
#define E_NTE_BAD_UID        ((DWORD)0x80090001)
#define E_NTE_BAD_HASH       ((DWORD)0x80090002)
#define E_NTE_BAD_KEY        ((DWORD)0x80090003)
#define E_NTE_BAD_LEN        ((DWORD)0x80090004)
#define E_NTE_BAD_DATA       ((DWORD)0x80090005)
#define E_NTE_BAD_SIGNATURE  ((DWORD)0x80090006)
#define E_NTE_BAD_ALGID      ((DWORD)0x80090008)
#define E_NTE_BAD_FLAGS      ((DWORD)0x80090009)
#define E_NTE_BAD_TYPE       ((DWORD)0x8009000A)
#define E_NTE_BAD_HASH_STATE ((DWORD)0x8009000C)
#define E_NTE_NO_KEY         ((DWORD)0x8009000D)
#define E_NTE_BAD_KEYSET     ((DWORD)0x80090016)

#define PROVNAME_AES "Microsoft Enhanced RSA and AES Cryptographic Provider"
#define PROVNAME_ENH "Microsoft Enhanced Cryptographic Provider v1.0"
#define PROVNAME_BASE "Microsoft Base Cryptographic Provider v1.0"

static int h_hex2bin(const char *s, BYTE *out, size_t cap) {
    size_t n = strlen(s) / 2, i;
    if (n > cap) return -1;
    for (i = 0; i < n; i++) {
        unsigned v; char b[3] = { s[2*i], s[2*i+1], 0 };
        sscanf(b, "%02x", &v); out[i] = (BYTE)v;
    }
    return (int)n;
}
static void h_bin2hex(const BYTE *b, size_t n, char *out) {
    size_t i; for (i = 0; i < n; i++) sprintf(out + 2*i, "%02x", b[i]); out[2*n] = 0;
}
static void h_rev(BYTE *b, size_t n) { size_t i; for (i = 0; i < n/2; i++) { BYTE t = b[i]; b[i] = b[n-1-i]; b[n-1-i] = t; } }

/* ephemeral (VERIFYCONTEXT) provider; 0 on failure */
static HCRYPTPROV h_acq(DWORD type, const char *name) {
    HCRYPTPROV p = 0;
    if (!U(CryptAcquireContextA)(&p, NULL, name, type, CRYPT_VERIFYCONTEXT)) { t_note("acquire %s type %lu failed: %lu", name ? name : "(default)", type, GetLastError()); return 0; }
    return p;
}
static HCRYPTPROV h_acq_aes(void) { return h_acq(PROV_RSA_AES, PROVNAME_AES); }
static void h_rel(HCRYPTPROV p) { if (p) U(CryptReleaseContext)(p, 0); }

/* one-shot hash of data -> out/outlen; returns TRUE on success */
static BOOL h_hash(HCRYPTPROV p, ALG_ID alg, const BYTE *d, DWORD n, BYTE *out, DWORD *outlen) {
    HCRYPTHASH h = 0; BOOL ok = FALSE;
    if (!U(CryptCreateHash)(p, alg, 0, 0, &h)) return FALSE;
    if (n && !U(CryptHashData)(h, d, n, 0)) goto done;
    ok = U(CryptGetHashParam)(h, HP_HASHVAL, out, outlen, 0);
done:
    U(CryptDestroyHash)(h);
    return ok;
}
/* import a plaintext session key blob (raw key bytes) */
static HCRYPTKEY h_plainkey(HCRYPTPROV p, ALG_ID alg, const BYTE *key, DWORD len, DWORD flags) {
    BYTE blob[600]; BLOBHEADER *bh = (BLOBHEADER *)blob; HCRYPTKEY k = 0;
    bh->bType = PLAINTEXTKEYBLOB; bh->bVersion = CUR_BLOB_VERSION; bh->reserved = 0; bh->aiKeyAlg = alg;
    *(DWORD *)(blob + sizeof *bh) = len;
    memcpy(blob + sizeof *bh + 4, key, len);
    if (!U(CryptImportKey)(p, blob, (DWORD)(sizeof *bh + 4 + len), 0, flags, &k)) {
        t_note("import plaintext key alg 0x%lx len %lu flags 0x%lx failed: 0x%lx", alg, len, flags, GetLastError()); return 0; }
    return k;
}
static DWORD h_digest_len(ALG_ID a) {
    switch (a) { case CALG_MD2: case CALG_MD4: case CALG_MD5: return 16; case CALG_SHA1: return 20;
        case CALG_SHA_256: return 32; case CALG_SHA_384: return 48; case CALG_SHA_512: return 64; case CALG_SSL3_SHAMD5: return 36; }
    return 0;
}
#define EXPECT_HEX(bin, n, hexs) do { BYTE e_[256]; int en_ = h_hex2bin((hexs), e_, sizeof e_); \
    t_check(en_ == (int)(n) && !memcmp((bin), e_, (size_t)en_ > 0 ? (size_t)en_ : 0), __FILE__, __LINE__, #bin " == " #hexs, "digest mismatch"); } while (0)
#endif

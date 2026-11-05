/* capi_asymmetric_blobs: shared helpers. Every CryptoAPI call goes through U() (GetProcAddress). */
#ifndef CAB_H
#define CAB_H
#include "t.h"
#include <wincrypt.h>
#include "vectors.h"

#define CAB_NTE_BAD_UID         0x80090001L
#define CAB_NTE_BAD_HASH        0x80090002L
#define CAB_NTE_BAD_KEY         0x80090003L
#define CAB_NTE_BAD_LEN         0x80090004L
#define CAB_NTE_BAD_DATA        0x80090005L
#define CAB_NTE_BAD_SIGNATURE   0x80090006L
#define CAB_NTE_BAD_VER         0x80090007L
#define CAB_NTE_BAD_ALGID       0x80090008L
#define CAB_NTE_BAD_FLAGS       0x80090009L
#define CAB_NTE_BAD_TYPE        0x8009000AL
#define CAB_NTE_BAD_KEY_STATE   0x8009000BL
#define CAB_NTE_NO_KEY          0x8009000DL
#define CAB_NTE_NOT_FOUND       0x80090011L
#define CAB_NTE_BAD_PUBLIC_KEY  0x80090015L
#define CAB_NTE_KEYSET_NOT_DEF  0x80090016L
#define CAB_NTE_BAD_PROV_TYPE   0x80090014L

#define MAGIC_RSA1 0x31415352u
#define MAGIC_RSA2 0x32415352u
#define MAGIC_DSS1 0x31535344u
#define MAGIC_DSS2 0x32535344u
#define MAGIC_DH1  0x31484400u
#define MAGIC_DH2  0x32484400u

#define CAB_NEED() do { if (!U(CryptAcquireContextW) || !U(CryptReleaseContext) || !U(CryptImportKey) || \
    !U(CryptExportKey) || !U(CryptGetKeyParam) || !U(CryptDestroyKey) || !U(CryptCreateHash) || \
    !U(CryptHashData) || !U(CryptDestroyHash) || !U(CryptSignHashW) || !U(CryptVerifySignatureW) || \
    !U(CryptEncrypt) || !U(CryptDecrypt) || !U(CryptGenKey) || !U(CryptSetKeyParam)) { \
    t_skip("missing CryptoAPI export"); return; } } while (0)

typedef struct { const WCHAR *name; DWORD type; const char *tag; } cab_prov_t;
static const cab_prov_t CAB_RSA[] = {
    { MS_ENHANCED_PROV_W,    PROV_RSA_FULL, "enh" },
    { MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,  "aes" },
    { MS_STRONG_PROV_W,      PROV_RSA_FULL, "strong" },
};
#define CAB_NRSA 3

static HCRYPTPROV cab_acq(const WCHAR *name, DWORD type) {
    HCRYPTPROV p = 0;
    if (!U(CryptAcquireContextW)(&p, NULL, name, type, CRYPT_VERIFYCONTEXT)) return 0;
    return p;
}
static void cab_rel(HCRYPTPROV p) { if (p) U(CryptReleaseContext)(p, 0); }
static HCRYPTPROV cab_enh(void) { return cab_acq(MS_ENHANCED_PROV_W, PROV_RSA_FULL); }
static HCRYPTPROV cab_aes(void) { return cab_acq(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES); }
static HCRYPTPROV cab_dss(void) { return cab_acq(MS_DEF_DSS_PROV_W, PROV_DSS); }
static HCRYPTPROV cab_dsdh(void) { return cab_acq(MS_ENH_DSS_DH_PROV_W, PROV_DSS_DH); }

/* import helper: returns key or 0 and leaves last error alone on success */
static HCRYPTKEY cab_imp(HCRYPTPROV p, const void *b, DWORD n, DWORD fl) {
    HCRYPTKEY k = 0;
    if (!U(CryptImportKey)(p, (const BYTE *)b, n, 0, fl, &k)) return 0;
    return k;
}
static void cab_kd(HCRYPTKEY k) { if (k) U(CryptDestroyKey)(k); }
static DWORD cab_kp(HCRYPTKEY k, DWORD param, int *ok) {
    DWORD v = 0xDEADBEEF, n = 4;
    BOOL r = U(CryptGetKeyParam)(k, param, (BYTE *)&v, &n, 0);
    if (ok) *ok = r && n == 4;
    return v;
}
static DWORD cab_keylen(HCRYPTKEY k) { return cab_kp(k, KP_KEYLEN, NULL); }
static DWORD cab_algid(HCRYPTKEY k) { return cab_kp(k, KP_ALGID, NULL); }

/* hash MSG with algorithm; caller destroys */
static HCRYPTHASH cab_hash(HCRYPTPROV p, ALG_ID alg, const void *d, DWORD n) {
    HCRYPTHASH h = 0;
    if (!U(CryptCreateHash)(p, alg, 0, 0, &h)) return 0;
    if (n && !U(CryptHashData)(h, (const BYTE *)d, n, 0)) { U(CryptDestroyHash)(h); return 0; }
    return h;
}
static void cab_hd(HCRYPTHASH h) { if (h) U(CryptDestroyHash)(h); }

/* patch the aiKeyAlg of a blob copy */
static void cab_setalg(BYTE *b, DWORD alg) { memcpy(b + 4, &alg, 4); }
static void cab_setmagic(BYTE *b, DWORD magic) { memcpy(b + 8, &magic, 4); }

typedef struct { const char *name; const unsigned char *prv; size_t prvn; const unsigned char *pub; size_t pubn; DWORD bits; } cab_rsakey_t;
#define CAB_RK(nm, b) { nm, rsa##b##_prv, sizeof rsa##b##_prv, rsa##b##_pub, sizeof rsa##b##_pub, b }
static const cab_rsakey_t CAB_RKS[] = { CAB_RK("rsa512", 512), CAB_RK("rsa1024", 1024), CAB_RK("rsa2048", 2048) };
#define CAB_NRK 3
#endif

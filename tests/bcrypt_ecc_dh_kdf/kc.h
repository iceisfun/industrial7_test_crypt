/* Shared helpers for the bcrypt_ecc_dh_kdf area. Every CNG call goes through U() (GetProcAddress). */
#ifndef KC_H
#define KC_H
#include "t.h"
#include <bcrypt.h>
#include "bcrypt_handles.h"
#include "vectors.h"

#define NS_INVALID_PARAMETER  ((NTSTATUS)0xC000000D)
#define NS_INVALID_HANDLE     ((NTSTATUS)0xC0000008)
#define NS_NOT_SUPPORTED      ((NTSTATUS)0xC00000BB)
#define NS_BUFFER_TOO_SMALL   ((NTSTATUS)0xC0000023)
#define NS_INVALID_SIGNATURE  ((NTSTATUS)0xC000A000)
#define NS_UNSUCCESSFUL       ((NTSTATUS)0xC0000001)
#define NS_NOT_FOUND          ((NTSTATUS)0xC0000225)
#define NS_OK                 ((NTSTATUS)0)
#define NT_OK(s) ((LONG)(s) >= 0)

#define KC_ECDH_GENERIC   L"ECDH"
#define KC_ECDSA_GENERIC  L"ECDSA"
#define KC_CURVE_NAME     L"ECCCurveName"

/* CHECK an NTSTATUS exactly, printing both values. */
#define CHECK_NS(got, want) do { NTSTATUS g_ = (got); t_check(g_ == (NTSTATUS)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%08lx want 0x%08lx", (unsigned long)g_, (unsigned long)(NTSTATUS)(want)); } while (0)
#define CHECK_MEM(a, b, n) t_check(memcmp((a), (b), (n)) == 0, __FILE__, __LINE__, "memcmp(" #a "," #b ")", "bytes differ (%lu)", (unsigned long)(n))

/* Are the core exports there? */
static int kc_core(void) {
    return U(BCryptOpenAlgorithmProvider) && U(BCryptCloseAlgorithmProvider) && U(BCryptGenerateKeyPair) &&
           U(BCryptFinalizeKeyPair) && U(BCryptImportKeyPair) && U(BCryptExportKey) && U(BCryptDestroyKey) &&
           U(BCryptSecretAgreement) && U(BCryptDeriveKey) && U(BCryptDestroySecret) && U(BCryptSignHash) &&
           U(BCryptVerifySignature) && U(BCryptGetProperty) && U(BCryptSetProperty);
}
/* a missing export is a failure on Windows 10; only the emulator may lack them */
#define KC_MISSING(msg) do { if (t_is_wine()) t_skip(msg); else CHECKF(0, "%s", msg); } while (0)
#define NEED_CORE() do { if (!kc_core()) { KC_MISSING("missing core bcrypt exports"); return; } } while (0)

static BCRYPT_ALG_HANDLE kc_open(const WCHAR *name, ULONG flags) {
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = U(BCryptOpenAlgorithmProvider)(&h, name, NULL, flags);
    return NT_OK(s) ? h : NULL;
}
static void kc_close(BCRYPT_ALG_HANDLE h) { if (h) U(BCryptCloseAlgorithmProvider)(h, 0); }

/* ---- curves ------------------------------------------------------------ */
typedef struct {
    const char *name;
    const WCHAR *dsa, *dh, *hashalg, *curve;
    BCRYPT_ALG_HANDLE pdsa, pdh;     /* pseudo handles */
    ULONG bits, cb, dsa_pub, dsa_prv, dh_pub, dh_prv, hashlen;
    const unsigned char *dA, *xA, *yA, *dB, *xB, *yB, *z, *hash, *sig;
} curve_t;

static const curve_t g_curves[3] = {
 { "P256", L"ECDSA_P256", L"ECDH_P256", L"SHA256", L"nistP256", BCRYPT_ECDSA_P256_ALG_HANDLE, BCRYPT_ECDH_P256_ALG_HANDLE, 256, 32,
   BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECDSA_PRIVATE_P256_MAGIC, BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECDH_PRIVATE_P256_MAGIC, 32,
   EC_P256_A_D, EC_P256_A_X, EC_P256_A_Y, EC_P256_B_D, EC_P256_B_X, EC_P256_B_Y, EC_P256_Z, EC_P256_HASH, EC_P256_SIG },
 { "P384", L"ECDSA_P384", L"ECDH_P384", L"SHA384", L"nistP384", BCRYPT_ECDSA_P384_ALG_HANDLE, BCRYPT_ECDH_P384_ALG_HANDLE, 384, 48,
   BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECDSA_PRIVATE_P384_MAGIC, BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECDH_PRIVATE_P384_MAGIC, 48,
   EC_P384_A_D, EC_P384_A_X, EC_P384_A_Y, EC_P384_B_D, EC_P384_B_X, EC_P384_B_Y, EC_P384_Z, EC_P384_HASH, EC_P384_SIG },
 { "P521", L"ECDSA_P521", L"ECDH_P521", L"SHA512", L"nistP521", BCRYPT_ECDSA_P521_ALG_HANDLE, BCRYPT_ECDH_P521_ALG_HANDLE, 521, 66,
   BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_ECDSA_PRIVATE_P521_MAGIC, BCRYPT_ECDH_PUBLIC_P521_MAGIC, BCRYPT_ECDH_PRIVATE_P521_MAGIC, 64,
   EC_P521_A_D, EC_P521_A_X, EC_P521_A_Y, EC_P521_B_D, EC_P521_B_X, EC_P521_B_Y, EC_P521_Z, EC_P521_HASH, EC_P521_SIG },
};

/* Build BCRYPT_ECCKEY_BLOB: header + X + Y [+ d]. Returns size. */
static ULONG kc_eccblob(unsigned char *out, ULONG magic, ULONG cb, const unsigned char *x, const unsigned char *y, const unsigned char *d) {
    BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)out;
    h->dwMagic = magic; h->cbKey = cb;
    unsigned char *p = out + sizeof(*h);
    if (x) memcpy(p, x, cb); else memset(p, 0, cb); p += cb;
    if (y) memcpy(p, y, cb); else memset(p, 0, cb); p += cb;
    if (d) { memcpy(p, d, cb); p += cb; }
    return (ULONG)(p - out);
}

/* On Windows 10 all three curves exist; an emulator may lack P-521. */
static int kc_curve_ok(const curve_t *c) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0), b = kc_open(c->dh, 0);
    int ok = a && b;
    if (ok && t_is_wine()) { BCRYPT_KEY_HANDLE k = NULL; ok = NT_OK(U(BCryptGenerateKeyPair)(a, &k, c->bits, 0)) && NT_OK(U(BCryptFinalizeKeyPair)(k, 0)); if (k) U(BCryptDestroyKey)(k); }
    if (ok && t_is_wine()) { unsigned char bb[300]; ULONG nn = kc_eccblob(bb, c->dsa_prv, c->cb, c->xA, c->yA, c->dA); BCRYPT_KEY_HANDLE k = NULL; ok = NT_OK(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPRIVATE_BLOB, &k, bb, nn, 0)); if (k) U(BCryptDestroyKey)(k); }
    if (ok && t_is_wine()) { unsigned char bb[300]; ULONG nn = kc_eccblob(bb, c->dsa_prv, c->cb, c->xA, c->yA, c->dA); BCRYPT_KEY_HANDLE k = NULL; ok = NT_OK(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPRIVATE_BLOB, &k, bb, nn, 0)); if (k) U(BCryptDestroyKey)(k); }
    kc_close(a); kc_close(b);
    if (!ok && t_is_wine()) { t_skip("curve %s not available in this emulator", c->name); return 0; }
    return 1;
}

/* Run a per-curve body as three TESTs (area_name_p256 ...). */
#define CURVE_TESTS(nm) \
    static void nm##_impl(const curve_t *c); \
    TEST(nm##_p256) { NEED_CORE(); if (!kc_curve_ok(&g_curves[0])) return; nm##_impl(&g_curves[0]); } \
    TEST(nm##_p384) { NEED_CORE(); if (!kc_curve_ok(&g_curves[1])) return; nm##_impl(&g_curves[1]); } \
    TEST(nm##_p521) { NEED_CORE(); if (!kc_curve_ok(&g_curves[2])) return; nm##_impl(&g_curves[2]); } \
    static void nm##_impl(const curve_t *c)

static NTSTATUS kc_import(BCRYPT_ALG_HANDLE a, const WCHAR *type, const void *blob, ULONG len, ULONG flags, BCRYPT_KEY_HANDLE *out) {
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = U(BCryptImportKeyPair)(a, NULL, type, &k, (PUCHAR)blob, len, flags);
    if (NT_OK(s)) *out = k; else *out = NULL;
    return s;
}
static void kc_destroy(BCRYPT_KEY_HANDLE k) { if (k) U(BCryptDestroyKey)(k); }

/* Import key A or B of a curve as DSA/DH, private or public. */
static BCRYPT_KEY_HANDLE kc_key(BCRYPT_ALG_HANDLE a, const curve_t *c, int dh, int which_b, int priv) {
    unsigned char buf[512];
    const unsigned char *x = which_b ? c->xB : c->xA, *y = which_b ? c->yB : c->yA, *d = which_b ? c->dB : c->dA;
    ULONG magic = dh ? (priv ? c->dh_prv : c->dh_pub) : (priv ? c->dsa_prv : c->dsa_pub);
    ULONG n = kc_eccblob(buf, magic, c->cb, x, y, priv ? d : NULL);
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = kc_import(a, priv ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_ECCPUBLIC_BLOB, buf, n, 0, &k);
    return NT_OK(s) ? k : NULL;
}

static NTSTATUS kc_export(BCRYPT_KEY_HANDLE k, const WCHAR *type, unsigned char *out, ULONG cap, ULONG *len) {
    ULONG r = 0;
    NTSTATUS s = U(BCryptExportKey)(k, NULL, type, out, cap, &r, 0);
    if (len) *len = r;
    return s;
}

static BCRYPT_KEY_HANDLE kc_gen(BCRYPT_ALG_HANDLE a, ULONG bits, int finalize) {
    BCRYPT_KEY_HANDLE k = NULL;
    if (!NT_OK(U(BCryptGenerateKeyPair)(a, &k, bits, 0))) return NULL;
    if (finalize && !NT_OK(U(BCryptFinalizeKeyPair)(k, 0))) { U(BCryptDestroyKey)(k); return NULL; }
    return k;
}

static void kc_rev(unsigned char *d, const unsigned char *s, ULONG n) { for (ULONG i = 0; i < n; i++) d[i] = s[n - 1 - i]; }

/* Build a BCryptBufferDesc from up to 8 buffers. */
typedef struct { BCryptBufferDesc d; BCryptBuffer b[10]; } kc_desc;
static void kc_desc_init(kc_desc *x) { memset(x, 0, sizeof(*x)); x->d.ulVersion = BCRYPTBUFFER_VERSION; x->d.pBuffers = x->b; }
static void kc_desc_add(kc_desc *x, ULONG type, const void *p, ULONG cb) {
    x->b[x->d.cBuffers].BufferType = type; x->b[x->d.cBuffers].pvBuffer = (PVOID)p; x->b[x->d.cBuffers].cbBuffer = cb; x->d.cBuffers++;
}
static void kc_desc_wstr(kc_desc *x, ULONG type, const WCHAR *s) { kc_desc_add(x, type, s, (ULONG)((lstrlenW(s) + 1) * 2)); }

/* Agree a secret between two imported ECDH keys. */
static BCRYPT_SECRET_HANDLE kc_agree(BCRYPT_KEY_HANDLE priv, BCRYPT_KEY_HANDLE pub, NTSTATUS *st) {
    BCRYPT_SECRET_HANDLE s = NULL;
    NTSTATUS r = U(BCryptSecretAgreement)(priv, pub, &s, 0);
    if (st) *st = r;
    return NT_OK(r) ? s : NULL;
}
/* Derive with a KDF; returns status, fills out/len. */
static NTSTATUS kc_derive(BCRYPT_SECRET_HANDLE s, const WCHAR *kdf, kc_desc *d, unsigned char *out, ULONG cap, ULONG *len, ULONG flags) {
    ULONG r = 0;
    NTSTATUS st = U(BCryptDeriveKey)(s, kdf, d ? &d->d : NULL, out, cap, &r, flags);
    if (len) *len = r;
    return st;
}
static const WCHAR *const kc_hash_names[] = { L"SHA1", L"SHA256", L"SHA384", L"SHA512", L"MD5" };
#endif

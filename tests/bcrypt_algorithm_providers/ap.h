/* Shared helpers for the bcrypt_algorithm_providers area.
 * Everything under test is reached through LoadLibrary/GetProcAddress (U() / UIN()). */
#ifndef AP_H
#define AP_H
#include "t.h"
#include <bcrypt.h>
#include "bcrypt_handles.h"

/* NTSTATUS values used by the tests (own names, independent of header availability) */
#define AP_OK            ((NTSTATUS)0x00000000L)
#define AP_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#define AP_INVALID_PARAM ((NTSTATUS)0xC000000DL)
#define AP_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define AP_BUF_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define AP_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#define AP_NOT_FOUND     ((NTSTATUS)0xC0000225L)

#define NT_EQ(a, b) do { NTSTATUS a_ = (NTSTATUS)(a); NTSTATUS b_ = (NTSTATUS)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%08lx want 0x%08lx", (unsigned long)a_, (unsigned long)b_); } while (0)
#define NT_OK(a)    NT_EQ(a, AP_OK)
#define NT_FAILED(a) do { NTSTATUS a_ = (NTSTATUS)(a); t_check(a_ < 0, __FILE__, __LINE__, #a " fails", "got 0x%08lx", (unsigned long)a_); } while (0)

/* All entry points the area uses; REQUIRE them once at the top of a test. */
#define NEED_CORE() do { REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider)); \
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptSetProperty)); } while (0)

#define AP_OPEN(ph, id, impl, fl) U(BCryptOpenAlgorithmProvider)((ph), (id), (impl), (fl))
#define AP_CLOSE(h)               U(BCryptCloseAlgorithmProvider)((h), 0)
#define AP_GET(h, p, b, cb, pres) U(BCryptGetProperty)((h), (p), (PUCHAR)(b), (cb), (pres), 0)
#define AP_SET(h, p, b, cb)       U(BCryptSetProperty)((h), (p), (PUCHAR)(b), (cb), 0)

static inline NTSTATUS ap_getdw(BCRYPT_HANDLE h, LPCWSTR prop, ULONG *out, ULONG *cb) {
    ULONG c = 0xdeadbeef; ULONG v = 0xdeadbeef;
    NTSTATUS s = AP_GET(h, prop, &v, sizeof(v), &c);
    if (out) *out = v;
    if (cb) *cb = c;
    return s;
}
/* property as wide string (bounded) */
static inline NTSTATUS ap_getstr(BCRYPT_HANDLE h, LPCWSTR prop, WCHAR *buf, ULONG cch, ULONG *cb) {
    ULONG c = 0xdeadbeef;
    memset(buf, 0, cch * sizeof(WCHAR));
    NTSTATUS s = AP_GET(h, prop, buf, cch * sizeof(WCHAR), &c);
    if (cb) *cb = c;
    return s;
}

#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME L"ECCCurveName"
#define BCRYPT_ECC_CURVE_NAME_LIST L"ECCCurveNameList"
#define BCRYPT_ECC_PARAMETERS L"ECCParameters"
#endif

/* Chaining-mode bits */
#define M_ECB 1
#define M_CBC 2
#define M_CFB 4
#define M_CCM 8
#define M_GCM 16
#define M_ALL 31
static const WCHAR *const ap_mode_names[5] = { L"ChainingModeECB", L"ChainingModeCBC", L"ChainingModeCFB", L"ChainingModeCCM", L"ChainingModeGCM" };

enum fam { F_SYM, F_HASH, F_RSA, F_RSASIGN, F_DSA, F_DH, F_ECDSA, F_ECDH, F_RNG, F_KD };

struct algd {
    const char *tag;
    const WCHAR *id;
    int cls;       /* expected PrimitiveType (BCRYPT_*_INTERFACE value), -1 = do not check */
    enum fam fam;
    int hard;      /* 1 = Win10 22H2 opens it with the default provider (true for every listed algorithm, probed) */
    int blk;       /* BlockLength for ciphers, -1 unchecked */
    int hlen, hblk;/* HashDigestLength / HashBlockLength for hashes */
    int kmin, kmax, kinc; /* KeyLengths (bits), kmin == -1 unchecked */
    int mok, mbad; /* chaining modes that must / must not be settable */
    int curvebits; /* ECC: field size in bits, 0 otherwise */
    const WCHAR *curve;
};

#define ALG_LIST(X) \
 /* tag      id                  cls fam      hard blk hlen hblk kmin kmax kinc mok          mbad            cbits curve */ \
 X(aes,      L"AES",              1, F_SYM,    1,  16,  0,  0,   128, 256, 64, M_ALL,        0,              0, NULL) \
 X(des,      L"DES",              1, F_SYM,    1,   8,  0,  0,    64,  64,  0, 7,            M_CCM|M_GCM,    0, NULL) \
 X(des3,     L"3DES",             1, F_SYM,    1,   8,  0,  0,   192, 192,  0, 7,            M_CCM|M_GCM,    0, NULL) \
 X(des3_112, L"3DES_112",         1, F_SYM,    1,   8,  0,  0,   128, 128,  0, 7,            M_CCM|M_GCM,    0, NULL) \
 X(desx,     L"DESX",             1, F_SYM,    1,   8,  0,  0,   192, 192,  0, 7,            M_CCM|M_GCM,    0, NULL) \
 X(rc2,      L"RC2",              1, F_SYM,    1,   8,  0,  0,    -1,  -1, -1, M_ECB|M_CBC,  M_CCM|M_GCM,    0, NULL) \
 X(rc4,      L"RC4",              1, F_SYM,    1,  -1,  0,  0,    -1,  -1, -1, 0,            M_ALL,          0, NULL) \
 X(xts,      L"XTS-AES",          1, F_SYM,    1,  16,  0,  0,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(md2,      L"MD2",              2, F_HASH,   1,  -1, 16, 16,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(md4,      L"MD4",              2, F_HASH,   1,  -1, 16, 64,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(md5,      L"MD5",              2, F_HASH,   1,  -1, 16, 64,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(sha1,     L"SHA1",             2, F_HASH,   1,  -1, 20, 64,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(sha256,   L"SHA256",           2, F_HASH,   1,  -1, 32, 64,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(sha384,   L"SHA384",           2, F_HASH,   1,  -1, 48,128,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(sha512,   L"SHA512",           2, F_HASH,   1,  -1, 64,128,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(rsa,      L"RSA",             -1, F_RSA,    1,  -1,  0,  0,   512,16384,  8, 0,            0,              0, NULL) \
 X(rsasign,  L"RSA_SIGN",        -1, F_RSASIGN,1,  -1,  0,  0,   512,16384,  8, 0,            0,              0, NULL) \
 X(dsa,      L"DSA",             -1, F_DSA,    1,  -1,  0,  0,   512, 3072, 64, 0,            0,              0, NULL) \
 X(dh,       L"DH",              -1, F_DH,     1,  -1,  0,  0,   512, 4096,  8, 0,            0,              0, NULL) \
 X(ecdsa256, L"ECDSA_P256",      -1, F_ECDSA,  1,  -1,  0,  0,   256,  256,  0, 0,            0,            256, L"nistP256") \
 X(ecdsa384, L"ECDSA_P384",      -1, F_ECDSA,  1,  -1,  0,  0,   384,  384,  0, 0,            0,            384, L"nistP384") \
 X(ecdsa521, L"ECDSA_P521",      -1, F_ECDSA,  1,  -1,  0,  0,   521,  521,  0, 0,            0,            521, L"nistP521") \
 X(ecdh256,  L"ECDH_P256",       -1, F_ECDH,   1,  -1,  0,  0,   256,  256,  0, 0,            0,            256, L"nistP256") \
 X(ecdh384,  L"ECDH_P384",       -1, F_ECDH,   1,  -1,  0,  0,   384,  384,  0, 0,            0,            384, L"nistP384") \
 X(ecdh521,  L"ECDH_P521",       -1, F_ECDH,   1,  -1,  0,  0,   521,  521,  0, 0,            0,            521, L"nistP521") \
 X(rng,      L"RNG",              6, F_RNG,    1,  -1,  0,  0,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(fips186,  L"FIPS186DSARNG",    6, F_RNG,    1,  -1,  0,  0,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(dualec,   L"DUALECRNG",        6, F_RNG,    1,  -1,  0,  0,    -1,  -1, -1, 0,            0,              0, NULL) \
 X(sp800108, L"SP800_108_CTR_HMAC",7, F_KD,     1,  -1,  0,  0,     0,16384,  8, 0,            0,              0, NULL) \
 X(sp80056a, L"SP800_56A_CONCAT", 7, F_KD,     1,  -1,  0,  0,     0,16384,  8, 0,            0,              0, NULL) \
 X(pbkdf2,   L"PBKDF2",           7, F_KD,     1,  -1,  0,  0,     0,16384,  8, 0,            0,              0, NULL) \
 X(capikdf,  L"CAPI_KDF",         7, F_KD,     1,  -1,  0,  0,     0,16384,  8, 0,            0,              0, NULL) \
 X(hkdf,     L"HKDF",             7, F_KD,     1,  -1,  0,  0,     0,16384,  8, 0,            0,              0, NULL) \
 X(tls11,    L"TLS1_1_KDF",       7, F_KD,     1,  -1,  0,  0,     0,16384,  8, 0,            0,              0, NULL) \
 X(tls12,    L"TLS1_2_KDF",       7, F_KD,     1,  -1,  0,  0,     0,16384,  8, 0,            0,              0, NULL)

#define X_ENUM(tag, ...) A_##tag,
enum { ALG_LIST(X_ENUM) A_COUNT };
#define X_ROW(tag, id, cls, fam, hard, blk, hlen, hblk, kmin, kmax, kinc, mok, mbad, cbits, curve) \
    { #tag, id, cls, fam, hard, blk, hlen, hblk, kmin, kmax, kinc, mok, mbad, cbits, curve },
static const struct algd g_algs[] = { ALG_LIST(X_ROW) };

static inline int ap_is_asym(const struct algd *a) { return a->fam >= F_RSA && a->fam <= F_ECDH; }

/* Open helper: returns status, skips noting when the algorithm is not mandatory */
static inline NTSTATUS ap_open_alg(const struct algd *a, BCRYPT_ALG_HANDLE *h, ULONG flags) {
    *h = NULL;
    return AP_OPEN(h, a->id, NULL, flags);
}
#endif

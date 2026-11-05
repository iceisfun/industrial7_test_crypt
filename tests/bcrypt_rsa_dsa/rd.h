/* Shared helpers for the bcrypt_rsa_dsa area. Every DLL call goes through U() (GetProcAddress). */
#ifndef RD_H
#define RD_H
#include "t.h"
#include <bcrypt.h>
#include <stdlib.h>
#include "vectors.h"

/* t.h's EXPECT_EQ evaluates its arguments twice; calls with side effects must be evaluated once. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)a_, (unsigned long long)b_); } while (0)

#define ST_SUCCESS            ((NTSTATUS)0x00000000)
#define ST_INVALID_HANDLE     ((NTSTATUS)0xC0000008)
#define ST_INVALID_PARAMETER  ((NTSTATUS)0xC000000D)
#define ST_NO_MEMORY          ((NTSTATUS)0xC0000017)
#define ST_NOT_SUPPORTED      ((NTSTATUS)0xC00000BB)
#define ST_BUFFER_TOO_SMALL   ((NTSTATUS)0xC0000023)
#define ST_NOT_FOUND          ((NTSTATUS)0xC0000225)
#define ST_INVALID_SIGNATURE  ((NTSTATUS)0xC000A000)
#define ST_INVALID_BUFFER_SIZE ((NTSTATUS)0xC0000206)
#define ST_AUTH_TAG_MISMATCH  ((NTSTATUS)0xC000A002)
#define ST_DATA_ERROR         ((NTSTATUS)0xC000003E)

#ifndef LEGACY_RSAPRIVATE_BLOB
#define LEGACY_RSAPRIVATE_BLOB L"CAPIPRIVATEBLOB"
#endif
#ifndef LEGACY_DSA_V2_PRIVATE_BLOB
#define LEGACY_DSA_V2_PRIVATE_BLOB L"V2CAPIDSAPRIVATEBLOB"
#endif
#ifndef LEGACY_DSA_V2_PUBLIC_BLOB
#define LEGACY_DSA_V2_PUBLIC_BLOB L"V2CAPIDSAPUBLICBLOB"
#endif
#ifndef BCRYPT_DSA_PUBLIC_MAGIC_V2
#define BCRYPT_DSA_PUBLIC_MAGIC_V2  0x32425044
#define BCRYPT_DSA_PRIVATE_MAGIC_V2 0x32565044
#endif

#define NEED_BCRYPT() do { \
    if (!U(BCryptOpenAlgorithmProvider) || !U(BCryptCloseAlgorithmProvider) || !U(BCryptGenerateKeyPair) || \
        !U(BCryptFinalizeKeyPair) || !U(BCryptImportKeyPair) || !U(BCryptExportKey) || !U(BCryptDestroyKey) || \
        !U(BCryptSignHash) || !U(BCryptVerifySignature) || !U(BCryptEncrypt) || !U(BCryptDecrypt) || \
        !U(BCryptGetProperty) || !U(BCryptSetProperty)) { t_skip("missing bcrypt export"); return; } } while (0)

#define ARR(a) a, (ULONG)sizeof(a)

/* ---- thin wrappers (all resolve through U) ---- */
static BCRYPT_ALG_HANDLE rd_alg(LPCWSTR id) {
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = U(BCryptOpenAlgorithmProvider)(&h, id, NULL, 0);
    return s == 0 ? h : NULL;
}
static void rd_closealg(BCRYPT_ALG_HANDLE h) { if (h) U(BCryptCloseAlgorithmProvider)(h, 0); }
static void rd_destroy(BCRYPT_KEY_HANDLE k) { if (k) U(BCryptDestroyKey)(k); }
static BCRYPT_KEY_HANDLE rd_gen(BCRYPT_ALG_HANDLE a, ULONG bits) {
    BCRYPT_KEY_HANDLE k = NULL;
    if (U(BCryptGenerateKeyPair)(a, &k, bits, 0) != 0) return NULL;
    if (U(BCryptFinalizeKeyPair)(k, 0) != 0) { U(BCryptDestroyKey)(k); return NULL; }
    return k;
}
/* export into malloc'd buffer; returns status */
static NTSTATUS rd_export(BCRYPT_KEY_HANDLE k, LPCWSTR type, UCHAR **out, ULONG *len) {
    ULONG n = 0; *out = NULL; *len = 0;
    NTSTATUS s = U(BCryptExportKey)(k, NULL, type, NULL, 0, &n, 0);
    if (s != 0) return s;
    UCHAR *b = (UCHAR *)calloc(1, n + 1);
    s = U(BCryptExportKey)(k, NULL, type, b, n, &n, 0);
    if (s != 0) { free(b); return s; }
    *out = b; *len = n; return 0;
}
static NTSTATUS rd_import(BCRYPT_ALG_HANDLE a, LPCWSTR type, const void *b, ULONG n, BCRYPT_KEY_HANDLE *k) {
    *k = NULL;
    return U(BCryptImportKeyPair)(a, NULL, type, k, (PUCHAR)b, n, 0);
}
static ULONG rd_getdw(BCRYPT_KEY_HANDLE h, LPCWSTR prop, NTSTATUS *st) {
    ULONG v = 0xdeadbeef, n = 0;
    NTSTATUS s = U(BCryptGetProperty)(h, prop, (PUCHAR)&v, sizeof v, &n, 0);
    if (st) *st = s;
    return v;
}

/* ---- blob builders ---- */
static ULONG rd_be32(const UCHAR *p) { return ((ULONG)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }
/* RSA header (little-endian struct) followed by fields; returns total length */
static ULONG rd_rsa_blob(UCHAR *out, ULONG magic, int full) {
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)out;
    UCHAR *p = out + sizeof *h;
    h->Magic = magic; h->BitLength = 1024; h->cbPublicExp = sizeof kRsaE; h->cbModulus = sizeof kRsaN;
    h->cbPrime1 = magic == BCRYPT_RSAPUBLIC_MAGIC ? 0 : sizeof kRsaP;
    h->cbPrime2 = magic == BCRYPT_RSAPUBLIC_MAGIC ? 0 : sizeof kRsaQ;
    memcpy(p, kRsaE, sizeof kRsaE); p += sizeof kRsaE;
    memcpy(p, kRsaN, sizeof kRsaN); p += sizeof kRsaN;
    if (magic != BCRYPT_RSAPUBLIC_MAGIC) {
        memcpy(p, kRsaP, sizeof kRsaP); p += sizeof kRsaP;
        memcpy(p, kRsaQ, sizeof kRsaQ); p += sizeof kRsaQ;
    }
    if (magic == BCRYPT_RSAFULLPRIVATE_MAGIC) {
        memcpy(p, kRsaDP, 64); p += 64; memcpy(p, kRsaDQ, 64); p += 64; memcpy(p, kRsaIQ, 64); p += 64;
        memcpy(p, kRsaD, 128); p += 128;
    }
    return (ULONG)(p - out);
}
#define RD_RSA_BLOB_MAX 1024

/* fixed 1024-bit key fixtures */
static BCRYPT_KEY_HANDLE rd_fixed_rsa(BCRYPT_ALG_HANDLE a, ULONG magic) {
    UCHAR b[RD_RSA_BLOB_MAX]; ULONG n = rd_rsa_blob(b, magic, 0); BCRYPT_KEY_HANDLE k;
    LPCWSTR t = magic == BCRYPT_RSAPUBLIC_MAGIC ? BCRYPT_RSAPUBLIC_BLOB :
                magic == BCRYPT_RSAPRIVATE_MAGIC ? BCRYPT_RSAPRIVATE_BLOB : BCRYPT_RSAFULLPRIVATE_BLOB;
    return rd_import(a, t, b, n, &k) == 0 ? k : NULL;
}

/* DSA v1 (1024/160 uses BCRYPT_DSA_KEY_BLOB, key size 128 bytes): header + Count[4] Seed[20] q[20]; then P G Y (X) */
static ULONG rd_dsa1_blob(UCHAR *out, int priv) {
    BCRYPT_DSA_KEY_BLOB *h = (BCRYPT_DSA_KEY_BLOB *)out;
    UCHAR *p = out + sizeof *h;
    memset(out, 0, sizeof *h);
    h->dwMagic = priv ? BCRYPT_DSA_PRIVATE_MAGIC : BCRYPT_DSA_PUBLIC_MAGIC;
    h->cbKey = 128;
    memset(h->Count, 0xff, 4); /* any */
    memset(h->Seed, 0x5a, 20);
    memcpy(h->q, kDsa1_Q, 20);
    memcpy(p, kDsa1_P, 128); p += 128;
    memcpy(p, kDsa1_G, 128); p += 128;
    memcpy(p, kDsa1_Y, 128); p += 128;
    if (priv) { memset(p, 0, 108); memcpy(p + 108, kDsa1_X, 20); p += 128; }
    return (ULONG)(p - out);
}
/* DSA v2 header: BCRYPT_DSA_KEY_BLOB_V2 {dwMagic, cbKey, hashAlgorithm, standardVersion, cbSeedLength, cbGroupSize, Count[4]}
   then Seed, Group(q), P, G, Y, (X). */
static ULONG rd_dsa2_blob(UCHAR *out, int priv, DWORD hashalg) {
    BCRYPT_DSA_KEY_BLOB_V2 *h = (BCRYPT_DSA_KEY_BLOB_V2 *)out;
    UCHAR *p = out + sizeof *h;
    memset(out, 0, sizeof *h);
    h->dwMagic = priv ? BCRYPT_DSA_PRIVATE_MAGIC_V2 : BCRYPT_DSA_PUBLIC_MAGIC_V2;
    h->cbKey = 256; h->hashAlgorithm = hashalg; h->standardVersion = DSA_FIPS186_3;
    h->cbSeedLength = 32; h->cbGroupSize = 32;
    memset(h->Count, 0xff, 4);
    memset(p, 0x33, 32); p += 32;
    memcpy(p, kDsa2_Q, 32); p += 32;
    memcpy(p, kDsa2_P, 256); p += 256;
    memcpy(p, kDsa2_G, 256); p += 256;
    memcpy(p, kDsa2_Y, 256); p += 256;
    if (priv) { memcpy(p, kDsa2_X, 32); p += 32; }
    return (ULONG)(p - out);
}

static int rd_nonzero(const UCHAR *p, ULONG n) { while (n--) if (*p++) return 1; return 0; }
#endif

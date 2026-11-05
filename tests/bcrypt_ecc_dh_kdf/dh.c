/* Diffie-Hellman: DH parameters, blobs, agreement. Fixed group: 2048-bit MODP group (g = 2). */
#include "kc.h"

#define DHB 256       /* key length in bytes */

typedef struct { BCRYPT_DH_PARAMETER_HEADER h; unsigned char pg[2 * DHB]; } dhparams_t;

static ULONG dh_params(dhparams_t *p) {
    p->h.cbLength = sizeof(p->h) + 2 * DHB;
    p->h.dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
    p->h.cbKeyLength = DHB;
    memcpy(p->pg, DH_P2048, DHB);
    memcpy(p->pg + DHB, DH_G2048, DHB);
    return p->h.cbLength;
}

/* DH key blob: header, P, G, Y [, X] */
static ULONG dh_blob(unsigned char *out, ULONG magic, const unsigned char *y, const unsigned char *x) {
    BCRYPT_DH_KEY_BLOB *h = (BCRYPT_DH_KEY_BLOB *)out;
    h->dwMagic = magic; h->cbKey = DHB;
    unsigned char *p = out + sizeof(*h);
    memcpy(p, DH_P2048, DHB); p += DHB;
    memcpy(p, DH_G2048, DHB); p += DHB;
    memcpy(p, y, DHB); p += DHB;
    if (x) { memcpy(p, x, DHB); p += DHB; }
    return (ULONG)(p - out);
}

static int dh_ok(void) {
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    if (!a) { if (t_is_wine()) { t_skip("DH not available in this emulator"); return 0; } return 1; }
    kc_close(a);
    return 1;
}
#define DH_BEGIN() do { NEED_CORE(); if (!dh_ok()) return; } while (0)

static BCRYPT_KEY_HANDLE dh_import(BCRYPT_ALG_HANDLE a, int b, int priv, NTSTATUS *st) {
    unsigned char blob[8 + 4 * DHB];
    ULONG n = dh_blob(blob, priv ? BCRYPT_DH_PRIVATE_MAGIC : BCRYPT_DH_PUBLIC_MAGIC, b ? DH_B_Y : DH_A_Y, priv ? (b ? DH_B_X : DH_A_X) : NULL);
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = kc_import(a, priv ? BCRYPT_DH_PRIVATE_BLOB : BCRYPT_DH_PUBLIC_BLOB, blob, n, 0, &k);
    if (st) *st = s;
    return k;
}

TEST(bcdh_alg_open_properties) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    CHECK(a != NULL);
    WCHAR name[32] = {0}; ULONG r = 0;
    CHECK_NS(U(BCryptGetProperty)(a, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof(name), &r, 0), 0);
    EXPECT_WSTR(name, L"DH");
    BCRYPT_KEY_LENGTHS_STRUCT kl; memset(&kl, 0, sizeof(kl));
    NTSTATUS s = U(BCryptGetProperty)(a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof(kl), &r, 0);
    CHECK_NS(s, 0);
    if (NT_OK(s)) {
        t_note("DH key lengths min=%lu max=%lu inc=%lu", (unsigned long)kl.dwMinLength, (unsigned long)kl.dwMaxLength, (unsigned long)kl.dwIncrement);
        EXPECT_EQ(kl.dwMinLength, 512); EXPECT_EQ(kl.dwMaxLength, 4096); EXPECT_EQ(kl.dwIncrement, 64);
    }
    kc_close(a);
}

TEST(bcdh_pseudo_handle_name) {
    DH_BEGIN();
    WCHAR name[32] = {0}; ULONG r = 0;
    CHECK_NS(U(BCryptGetProperty)(BCRYPT_DH_ALG_HANDLE, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof(name), &r, 0), 0);
    EXPECT_WSTR(name, L"DH");
}

TEST(bcdh_generate_invalid_lengths) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    static const ULONG bad[] = { 1, 64, 256, 504, 511, 513, 4097, 4104, 4160, 8192, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = U(BCryptGenerateKeyPair)(a, &k, bad[i], 0);
        CHECKF(s == NS_INVALID_PARAMETER, "DH length %lu -> 0x%08lx", (unsigned long)bad[i], (unsigned long)s);
        kc_destroy(k);
    }
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0x1), NS_INVALID_PARAMETER);
    kc_destroy(k);
    kc_close(a);
}

TEST(bcdh_generate_without_parameters_2048) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    unsigned char pub[8 + 3 * DHB]; ULONG n = 0;
    CHECK_NS(kc_export(k, BCRYPT_DH_PUBLIC_BLOB, pub, sizeof(pub), &n), 0);
    EXPECT_EQ(n, 8 + 3 * DHB);
    BCRYPT_DH_KEY_BLOB *h = (BCRYPT_DH_KEY_BLOB *)pub;
    EXPECT_EQ(h->dwMagic, BCRYPT_DH_PUBLIC_MAGIC);
    EXPECT_EQ(h->cbKey, DHB);
    t_note("DH 2048 default group %s the RFC 3526 group 14 prime", !memcmp(pub + 8, DH_P2048, DHB) ? "is" : "is not");
    CHECK(pub[8] & 0x80);                                  /* modulus is a full 2048-bit number */
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_set_parameters_generate_export) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    dhparams_t p; ULONG pn = dh_params(&p);
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    unsigned char pub[8 + 3 * DHB], prv[8 + 4 * DHB]; ULONG n = 0;
    CHECK_NS(kc_export(k, BCRYPT_DH_PUBLIC_BLOB, NULL, 0, &n), 0);
    EXPECT_EQ(n, 8 + 3 * DHB);
    CHECK_NS(kc_export(k, BCRYPT_DH_PUBLIC_BLOB, pub, sizeof(pub), &n), 0);
    EXPECT_EQ(n, 8 + 3 * DHB);
    CHECK_MEM(pub + 8, DH_P2048, DHB);
    CHECK_MEM(pub + 8 + DHB, DH_G2048, DHB);
    CHECK_NS(kc_export(k, BCRYPT_DH_PRIVATE_BLOB, prv, sizeof(prv), &n), 0);
    EXPECT_EQ(n, 8 + 4 * DHB);
    EXPECT_EQ(((BCRYPT_DH_KEY_BLOB *)prv)->dwMagic, BCRYPT_DH_PRIVATE_MAGIC);
    EXPECT_EQ(((BCRYPT_DH_KEY_BLOB *)prv)->cbKey, DHB);
    CHECK_MEM(prv + 8, pub + 8, 3 * DHB);                  /* P, G, Y identical in both blobs */
    unsigned char zero[DHB] = {0};
    CHECK(memcmp(prv + 8 + 3 * DHB, zero, DHB) != 0);
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_export_size_protocol) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = dh_import(a, 0, 1, NULL);
    CHECK(k != NULL);
    unsigned char buf[8 + 4 * DHB]; ULONG n;
    ULONG need = 8 + 3 * DHB;
    n = 0; CHECK_NS(kc_export(k, BCRYPT_DH_PUBLIC_BLOB, buf, need - 1, &n), NS_BUFFER_TOO_SMALL); EXPECT_EQ(n, need);
    n = 0; CHECK_NS(kc_export(k, BCRYPT_DH_PUBLIC_BLOB, buf, 0, &n), NS_BUFFER_TOO_SMALL); EXPECT_EQ(n, need);
    n = 0; CHECK_NS(kc_export(k, BCRYPT_DH_PUBLIC_BLOB, buf, need, &n), 0); EXPECT_EQ(n, need);
    need = 8 + 4 * DHB;
    n = 0; CHECK_NS(kc_export(k, BCRYPT_DH_PRIVATE_BLOB, buf, need - 1, &n), NS_BUFFER_TOO_SMALL); EXPECT_EQ(n, need);
    n = 0; CHECK_NS(kc_export(k, BCRYPT_DH_PRIVATE_BLOB, NULL, 0, &n), 0); EXPECT_EQ(n, need);
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_import_roundtrip) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    NTSTATUS s;
    BCRYPT_KEY_HANDLE kp = dh_import(a, 0, 1, &s);
    CHECK_NS(s, 0);
    unsigned char want[8 + 4 * DHB], got[8 + 4 * DHB]; ULONG n = 0;
    ULONG wn = dh_blob(want, BCRYPT_DH_PRIVATE_MAGIC, DH_A_Y, DH_A_X);
    if (kp) {
        CHECK_NS(kc_export(kp, BCRYPT_DH_PRIVATE_BLOB, got, sizeof(got), &n), 0);
        EXPECT_EQ(n, wn);
        if (n == wn) CHECK_MEM(got, want, wn);
        wn = dh_blob(want, BCRYPT_DH_PUBLIC_MAGIC, DH_A_Y, NULL);
        CHECK_NS(kc_export(kp, BCRYPT_DH_PUBLIC_BLOB, got, sizeof(got), &n), 0);
        EXPECT_EQ(n, wn);
        if (n == wn) CHECK_MEM(got, want, wn);
    }
    BCRYPT_KEY_HANDLE kq = dh_import(a, 1, 0, &s);
    CHECK_NS(s, 0);
    if (kq) {
        wn = dh_blob(want, BCRYPT_DH_PUBLIC_MAGIC, DH_B_Y, NULL);
        CHECK_NS(kc_export(kq, BCRYPT_DH_PUBLIC_BLOB, got, sizeof(got), &n), 0);
        if (n == wn) CHECK_MEM(got, want, wn);
        CHECK_NS_FAIL(kc_export(kq, BCRYPT_DH_PRIVATE_BLOB, got, sizeof(got), &n));
    }
    kc_destroy(kp); kc_destroy(kq); kc_close(a);
}

TEST(bcdh_agree_kat) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE ap = dh_import(a, 0, 1, NULL), bp = dh_import(a, 1, 1, NULL), apub = dh_import(a, 0, 0, NULL), bpub = dh_import(a, 1, 0, NULL);
    NTSTATUS s1, s2;
    BCRYPT_SECRET_HANDLE x = kc_agree(ap, bpub, &s1), y = kc_agree(bp, apub, &s2);
    CHECK_NS(s1, 0); CHECK_NS(s2, 0);
    unsigned char r1[DHB] = {0}, r2[DHB] = {1}, rev[DHB]; ULONG n1 = 0, n2 = 0;
    if (x && y) {
        CHECK_NS(kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof(r1), &n1, 0), 0);
        CHECK_NS(kc_derive(y, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof(r2), &n2, 0), 0);
        EXPECT_EQ(n1, DHB); EXPECT_EQ(n2, DHB);
        CHECK_MEM(r1, r2, DHB);
        kc_rev(rev, DH_Z, DHB);
        t_note("DH raw secret %s", !memcmp(r1, rev, DHB) ? "is the reversed (little-endian) shared value" : (!memcmp(r1, DH_Z, DHB) ? "is the big-endian shared value" : "differs from both orders"));
    }
    if (x) U(BCryptDestroySecret)(x);
    if (y) U(BCryptDestroySecret)(y);
    kc_destroy(ap); kc_destroy(bp); kc_destroy(apub); kc_destroy(bpub); kc_close(a);
}

TEST(bcdh_agree_kat_raw_is_little_endian) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE ap = dh_import(a, 0, 1, NULL), bpub = dh_import(a, 1, 0, NULL);
    NTSTATUS s1;
    BCRYPT_SECRET_HANDLE x = kc_agree(ap, bpub, &s1);
    CHECK_NS(s1, 0);
    unsigned char r1[DHB] = {0}, rev[DHB]; ULONG n1 = 0;
    if (x) {
        CHECK_NS(kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof(r1), &n1, 0), 0);
        kc_rev(rev, DH_Z, DHB);
        CHECK_MEM(r1, rev, DHB);
        U(BCryptDestroySecret)(x);
    }
    kc_destroy(ap); kc_destroy(bpub); kc_close(a);
}

TEST(bcdh_agree_generated) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    dhparams_t p; ULONG pn = dh_params(&p);
    BCRYPT_KEY_HANDLE k1 = NULL, k2 = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k1, 2048, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k1, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k1, 0), 0);
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k2, 2048, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k2, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k2, 0), 0);
    /* pass the public halves through blobs, as two parties would */
    unsigned char b1[8 + 3 * DHB], b2[8 + 3 * DHB]; ULONG n1 = 0, n2 = 0;
    CHECK_NS(kc_export(k1, BCRYPT_DH_PUBLIC_BLOB, b1, sizeof(b1), &n1), 0);
    CHECK_NS(kc_export(k2, BCRYPT_DH_PUBLIC_BLOB, b2, sizeof(b2), &n2), 0);
    BCRYPT_KEY_HANDLE p1 = NULL, p2 = NULL;
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, b1, n1, 0, &p1), 0);
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, b2, n2, 0, &p2), 0);
    NTSTATUS s1, s2;
    BCRYPT_SECRET_HANDLE x = kc_agree(k1, p2, &s1), y = kc_agree(k2, p1, &s2);
    CHECK_NS(s1, 0); CHECK_NS(s2, 0);
    if (x && y) {
        unsigned char r1[DHB] = {0}, r2[DHB] = {1}; ULONG m1 = 0, m2 = 0;
        CHECK_NS(kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof(r1), &m1, 0), 0);
        CHECK_NS(kc_derive(y, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof(r2), &m2, 0), 0);
        EXPECT_EQ(m1, DHB); EXPECT_EQ(m1, m2);
        CHECK_MEM(r1, r2, DHB);
    }
    if (x) U(BCryptDestroySecret)(x);
    if (y) U(BCryptDestroySecret)(y);
    kc_destroy(p1); kc_destroy(p2); kc_destroy(k1); kc_destroy(k2); kc_close(a);
}

TEST(bcdh_agree_bad_args) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE ap = dh_import(a, 0, 1, NULL), bpub = dh_import(a, 1, 0, NULL);
    BCRYPT_SECRET_HANDLE s = NULL;
    CHECK_NS(U(BCryptSecretAgreement)(NULL, bpub, &s, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSecretAgreement)(ap, NULL, &s, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSecretAgreement)(ap, bpub, NULL, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptSecretAgreement)(ap, bpub, &s, 1), NS_INVALID_PARAMETER);
    CHECK(s == NULL);
    kc_destroy(ap); kc_destroy(bpub); kc_close(a);
}

TEST(bcdh_agree_dh_with_ecdh_key) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0), e = kc_open(L"ECDH_P256", 0);
    BCRYPT_KEY_HANDLE ap = dh_import(a, 0, 1, NULL), ek = kc_gen(e, 256, 1);
    BCRYPT_SECRET_HANDLE s = NULL;
    NTSTATUS st = U(BCryptSecretAgreement)(ap, ek, &s, 0);
    CHECK(!NT_OK(st)); t_note("DH priv + ECDH pub -> 0x%08lx", (unsigned long)st);
    if (s) U(BCryptDestroySecret)(s);
    st = U(BCryptSecretAgreement)(ek, ap, &s, 0);
    CHECK(!NT_OK(st)); t_note("ECDH priv + DH pub -> 0x%08lx", (unsigned long)st);
    if (s) U(BCryptDestroySecret)(s);
    kc_destroy(ap); kc_destroy(ek); kc_close(a); kc_close(e);
}

TEST(bcdh_agree_public_only_private_arg) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE apub = dh_import(a, 0, 0, NULL), bpub = dh_import(a, 1, 0, NULL);
    BCRYPT_SECRET_HANDLE s = NULL;
    CHECK_NS(U(BCryptSecretAgreement)(apub, bpub, &s, 0), NS_INVALID_PARAMETER);
    CHECK(s == NULL);
    kc_destroy(apub); kc_destroy(bpub); kc_close(a);
}

/* ---- DH parameters property ----------------------------------------------------------------------------------- */
TEST(bcdh_set_parameters_bad_magic) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    dhparams_t p; ULONG pn = dh_params(&p);
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0), 0);
    p.h.dwMagic = 0x41414141;
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), NS_INVALID_PARAMETER);
    p.h.dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
    p.h.cbKeyLength = DHB / 2;
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), NS_INVALID_PARAMETER);
    p.h.cbKeyLength = DHB + 8;
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), NS_INVALID_PARAMETER);
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_set_parameters_short_buffer) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    dhparams_t p; ULONG pn = dh_params(&p);
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn - 1, 0), NS_BUFFER_TOO_SMALL);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, 12, 0), NS_BUFFER_TOO_SMALL);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, 0, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), 0);
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_set_parameters_bad_group) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    dhparams_t p; ULONG pn = dh_params(&p);
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0), 0);
    p.pg[DHB - 1] &= ~1;                     /* even modulus */
    NTSTATUS s = U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0);
    CHECK(!NT_OK(s)); t_note("even DH modulus -> 0x%08lx", (unsigned long)s);
    dh_params(&p);
    memset(p.pg + DHB, 0, DHB);              /* generator 0 */
    s = U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0);
    CHECK(!NT_OK(s)); t_note("DH generator 0 -> 0x%08lx", (unsigned long)s);
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_set_unknown_property) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0), 0);
    DWORD v = 1;
    CHECK_NS(U(BCryptSetProperty)(k, L"NoSuchProperty", (PUCHAR)&v, 4, 0), NS_NOT_SUPPORTED);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, NULL, 0, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&v, 4, 0), NS_BUFFER_TOO_SMALL);
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_finalize_twice_and_flags) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    dhparams_t p; ULONG pn = dh_params(&p);
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 4), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), NS_INVALID_HANDLE);
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_unfinalized_unusable) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL, pub = dh_import(a, 1, 0, NULL);
    dhparams_t p; ULONG pn = dh_params(&p);
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 2048, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), 0);
    unsigned char buf[8 + 4 * DHB]; ULONG n = 0;
    CHECK_NS_FAIL(kc_export(k, BCRYPT_DH_PUBLIC_BLOB, buf, sizeof(buf), &n));
    kc_destroy(k); kc_destroy(pub); kc_close(a);
}

TEST(bcdh_set_key_length_before_finalize) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    dhparams_t p; ULONG pn = dh_params(&p);
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 1024, 0), 0);
    DWORD bits = 2048;
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&bits, 4, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_DH_PARAMETERS, (PUCHAR)&p, pn, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    DWORD got = 0; ULONG r = 0;
    CHECK_NS(U(BCryptGetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&got, 4, &r, 0), 0);
    EXPECT_EQ(got, 2048);
    bits = 4096;
    NTSTATUS s = U(BCryptSetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&bits, 4, 0);
    CHECK_NS(s, NS_NOT_SUPPORTED);                          /* key length is read-only after finalize */
    kc_destroy(k); kc_close(a);
}

/* ---- DH import validation ------------------------------------------------------------------------------------------ */
TEST(bcdh_import_truncated_and_magic) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    unsigned char blob[8 + 4 * DHB];
    BCRYPT_KEY_HANDLE k = NULL;
    ULONG n = dh_blob(blob, BCRYPT_DH_PUBLIC_MAGIC, DH_A_Y, NULL);
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n - 1, 0, &k), NS_INVALID_PARAMETER);
    memset(blob + n, 0, 16);
    CHECK_NS_FAIL(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n + 1, 0, &k));   /* oversize blob: exact status unverified */
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, 4, 0, &k), NS_INVALID_PARAMETER);
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, 0, 0, &k), NS_INVALID_PARAMETER);
    CHECK_NS(kc_import(a, BCRYPT_DH_PRIVATE_BLOB, blob, n, 0, &k), NS_INVALID_PARAMETER);    /* public magic, private type (also wrong size) */
    n = dh_blob(blob, BCRYPT_DH_PRIVATE_MAGIC, DH_A_Y, DH_A_X);
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0, &k), NS_INVALID_PARAMETER);     /* private magic, public type */
    CHECK_NS(kc_import(a, BCRYPT_DH_PRIVATE_BLOB, blob, n - 1, 0, &k), NS_INVALID_PARAMETER);
    ((BCRYPT_DH_KEY_BLOB *)blob)->dwMagic = 0x12345678;
    CHECK_NS(kc_import(a, BCRYPT_DH_PRIVATE_BLOB, blob, n, 0, &k), NS_INVALID_PARAMETER);
    CHECK(k == NULL);
    kc_close(a);
}

TEST(bcdh_import_bad_public_values) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    unsigned char blob[8 + 4 * DHB], bad[DHB];
    BCRYPT_KEY_HANDLE k = NULL;
    /* Y = 0, Y = 1, Y = P-1, Y = P, Y > P are all invalid public values */
    memset(bad, 0, DHB);
    ULONG n = dh_blob(blob, BCRYPT_DH_PUBLIC_MAGIC, bad, NULL);
    NTSTATUS s = kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0, &k);
    CHECK(!NT_OK(s)); t_note("Y=0 -> 0x%08lx", (unsigned long)s); kc_destroy(k); k = NULL;
    bad[DHB - 1] = 1;
    n = dh_blob(blob, BCRYPT_DH_PUBLIC_MAGIC, bad, NULL);
    s = kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0, &k);
    t_note("Y=1 -> 0x%08lx", (unsigned long)s); kc_destroy(k); k = NULL;
    memcpy(bad, DH_P2048, DHB);
    n = dh_blob(blob, BCRYPT_DH_PUBLIC_MAGIC, bad, NULL);
    s = kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0, &k);
    CHECK(!NT_OK(s)); t_note("Y=P -> 0x%08lx", (unsigned long)s); kc_destroy(k); k = NULL;
    bad[DHB - 1] ^= 1;                                    /* P-1 */
    n = dh_blob(blob, BCRYPT_DH_PUBLIC_MAGIC, bad, NULL);
    s = kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0, &k);
    t_note("Y=P-1 -> 0x%08lx", (unsigned long)s); kc_destroy(k); k = NULL;
    memset(bad, 0xFF, DHB);
    n = dh_blob(blob, BCRYPT_DH_PUBLIC_MAGIC, bad, NULL);
    s = kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0, &k);
    CHECK(!NT_OK(s)); t_note("Y=2^2048-1 -> 0x%08lx", (unsigned long)s); kc_destroy(k);
    kc_close(a);
}

TEST(bcdh_import_cbkey_invalid) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    unsigned char blob[8 + 4 * DHB];
    BCRYPT_KEY_HANDLE k = NULL;
    ULONG n = dh_blob(blob, BCRYPT_DH_PUBLIC_MAGIC, DH_A_Y, NULL);
    static const ULONG cbs[] = { 0, 1, 32, 63, 513, 0x10000000, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof(cbs) / sizeof(cbs[0]); i++) {
        ((BCRYPT_DH_KEY_BLOB *)blob)->cbKey = cbs[i];
        NTSTATUS s = kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0, &k);
        CHECKF(s == NS_INVALID_PARAMETER, "cbKey %lu -> 0x%08lx", (unsigned long)cbs[i], (unsigned long)s);
        kc_destroy(k); k = NULL;
    }
    kc_close(a);
}

TEST(bcdh_import_flags_and_unknown_type) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    unsigned char blob[8 + 4 * DHB];
    BCRYPT_KEY_HANDLE k = NULL;
    ULONG n = dh_blob(blob, BCRYPT_DH_PUBLIC_MAGIC, DH_A_Y, NULL);
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0x1, &k), NS_INVALID_PARAMETER);
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0x2, &k), NS_INVALID_PARAMETER);
    CHECK_NS(kc_import(a, BCRYPT_DH_PUBLIC_BLOB, blob, n, 0x40, &k), NS_INVALID_PARAMETER);
    CHECK_NS(kc_import(a, L"FOOBLOB", blob, n, 0, &k), NS_INVALID_PARAMETER);
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, blob, n, 0, &k), NS_INVALID_PARAMETER);
    CHECK_NS(kc_import(a, L"", blob, n, 0, &k), NS_INVALID_PARAMETER);
    BCRYPT_KEY_HANDLE other = dh_import(a, 1, 0, NULL);
    CHECK_NS(U(BCryptImportKeyPair)(a, other, BCRYPT_DH_PUBLIC_BLOB, &k, blob, n, 0), NS_NOT_SUPPORTED);
    kc_destroy(other); kc_close(a);
}

TEST(bcdh_export_wrong_type) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = dh_import(a, 0, 1, NULL);
    unsigned char buf[8 + 4 * DHB]; ULONG n = 0;
    CHECK_NS_FAIL(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n));
    CHECK_NS_FAIL(kc_export(k, L"FOOBLOB", buf, sizeof(buf), &n));
    CHECK_NS_FAIL(kc_export(k, BCRYPT_RSAPUBLIC_BLOB, buf, sizeof(buf), &n));
    CHECK_NS_FAIL(kc_export(k, BCRYPT_ECCPRIVATE_BLOB, buf, sizeof(buf), &n));
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_legacy_blob_note) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = dh_import(a, 0, 1, NULL);
    unsigned char buf[2048]; ULONG n = 0;
    NTSTATUS s = kc_export(k, LEGACY_DH_PUBLIC_BLOB, buf, sizeof(buf), &n);
    t_note("CAPIDHPUBLICBLOB export -> 0x%08lx size=%lu", (unsigned long)s, (unsigned long)n);
    s = kc_export(k, LEGACY_DH_PRIVATE_BLOB, buf, sizeof(buf), &n);
    t_note("CAPIDHPRIVATEBLOB export -> 0x%08lx size=%lu", (unsigned long)s, (unsigned long)n);
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_key_properties) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE k = dh_import(a, 0, 1, NULL);
    DWORD v = 0; ULONG r = 0;
    CHECK_NS(U(BCryptGetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, &r, 0), 0);
    EXPECT_EQ(v, 2048);
    v = 0;
    NTSTATUS s = U(BCryptGetProperty)(k, BCRYPT_KEY_STRENGTH, (PUCHAR)&v, 4, &r, 0);
    CHECK_NS(s, 0);
    t_note("DH key strength property %lu", (unsigned long)v);
    unsigned char buf[12 + 2 * DHB]; r = 0;
    s = U(BCryptGetProperty)(k, BCRYPT_DH_PARAMETERS, buf, sizeof(buf), &r, 0);
    t_note("DH key DHParameters get -> 0x%08lx size=%lu", (unsigned long)s, (unsigned long)r);
    if (NT_OK(s)) {
        BCRYPT_DH_PARAMETER_HEADER *h = (BCRYPT_DH_PARAMETER_HEADER *)buf;
        EXPECT_EQ(h->dwMagic, BCRYPT_DH_PARAMETERS_MAGIC);
        EXPECT_EQ(h->cbKeyLength, DHB);
        EXPECT_EQ(r, sizeof(*h) + 2 * DHB);
        CHECK_MEM(buf + sizeof(*h), DH_P2048, DHB);
        CHECK_MEM(buf + sizeof(*h) + DHB, DH_G2048, DHB);
    }
    kc_destroy(k); kc_close(a);
}

TEST(bcdh_secret_kdf_sizes) {
    DH_BEGIN();
    BCRYPT_ALG_HANDLE a = kc_open(BCRYPT_DH_ALGORITHM, 0);
    BCRYPT_KEY_HANDLE ap = dh_import(a, 0, 1, NULL), bpub = dh_import(a, 1, 0, NULL);
    NTSTATUS st;
    BCRYPT_SECRET_HANDLE x = kc_agree(ap, bpub, &st);
    CHECK_NS(st, 0);
    if (x) {
        ULONG n = 0;
        CHECK_NS(kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &n, 0), 0);
        EXPECT_EQ(n, DHB);
        kc_desc d; kc_desc_init(&d); kc_desc_wstr(&d, KDF_HASH_ALGORITHM, L"SHA256");
        CHECK_NS(kc_derive(x, BCRYPT_KDF_HASH, &d, NULL, 0, &n, 0), 0);
        EXPECT_EQ(n, 32);
        unsigned char h[32]; ULONG hn = 0;
        CHECK_NS(kc_derive(x, BCRYPT_KDF_HASH, &d, h, 32, &hn, 0), 0);
        EXPECT_EQ(hn, 32);
        unsigned char be[DHB], rev[DHB];
        memcpy(be, DH_Z, DHB); kc_rev(rev, DH_Z, DHB);
        t_note("DH SHA256(secret) KDF computed");
        U(BCryptDestroySecret)(x);
    }
    kc_destroy(ap); kc_destroy(bpub); kc_close(a);
}

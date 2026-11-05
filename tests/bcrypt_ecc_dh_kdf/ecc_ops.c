/* ECDSA sign/verify (raw r||s) and ECDH secret agreement. */
#include "kc.h"

static BCRYPT_KEY_HANDLE dsa_priv(const curve_t *c, BCRYPT_ALG_HANDLE a) { return kc_key(a, c, 0, 0, 1); }
static BCRYPT_KEY_HANDLE dsa_pub(const curve_t *c, BCRYPT_ALG_HANDLE a) { return kc_key(a, c, 0, 0, 0); }

/* ---- verify: known answers ------------------------------------------------------------------------------ */
CURVE_TESTS(bcecdsa_verify_kat) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE pub = dsa_pub(c, a), prv = dsa_priv(c, a);
    CHECK(pub != NULL && prv != NULL);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), 0);
    CHECK_NS(U(BCryptVerifySignature)(prv, NULL, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), 0);
    kc_destroy(pub); kc_destroy(prv); kc_close(a);
}

CURVE_TESTS(bcecdsa_verify_flipped_signature_bits) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE pub = dsa_pub(c, a);
    unsigned char sig[200];
    for (ULONG pos = 0; pos < 2 * c->cb; pos += (c->cb / 2 + 1)) {
        memcpy(sig, c->sig, 2 * c->cb);
        sig[pos] ^= 0x01;
        NTSTATUS s = U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, 2 * c->cb, 0);
        CHECKF(s == NS_INVALID_SIGNATURE, "flip byte %lu -> 0x%08lx", (unsigned long)pos, (unsigned long)s);
    }
    memcpy(sig, c->sig, 2 * c->cb);
    sig[2 * c->cb - 1] ^= 0x80;
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, 2 * c->cb, 0), NS_INVALID_SIGNATURE);
    kc_destroy(pub); kc_close(a);
}

CURVE_TESTS(bcecdsa_verify_flipped_hash) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE pub = dsa_pub(c, a);
    unsigned char h[80];
    memcpy(h, c->hash, c->hashlen);
    h[0] ^= 0x80;
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, h, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_INVALID_SIGNATURE);
    memcpy(h, c->hash, c->hashlen);
    h[c->hashlen - 1] ^= 0x01;
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, h, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_INVALID_SIGNATURE);
    kc_destroy(pub); kc_close(a);
}

CURVE_TESTS(bcecdsa_verify_wrong_key) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE other = kc_key(a, c, 0, 1, 0);       /* key B's public part */
    CHECK_NS(U(BCryptVerifySignature)(other, NULL, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_INVALID_SIGNATURE);
    kc_destroy(other); kc_close(a);
}

CURVE_TESTS(bcecdsa_verify_signature_length) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE pub = dsa_pub(c, a);
    unsigned char sig[300];
    memset(sig, 0, sizeof(sig));
    memcpy(sig, c->sig, 2 * c->cb);
    static const int deltas[] = { -2 * 66, -1, 1, 2, 8 };
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, 0, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, c->cb, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, 2 * c->cb - 1, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, 2 * c->cb + 1, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, 2 * c->cb + 8, 0), NS_INVALID_PARAMETER);
    (void)deltas;
    kc_destroy(pub); kc_close(a);
}

CURVE_TESTS(bcecdsa_verify_zero_signature) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE pub = dsa_pub(c, a);
    unsigned char sig[200] = {0};
    NTSTATUS s = U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, 2 * c->cb, 0);
    CHECK_NS(s, NS_INVALID_SIGNATURE);
    memset(sig, 0xFF, sizeof(sig));
    s = U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, 2 * c->cb, 0);
    CHECK_NS(s, NS_INVALID_SIGNATURE);
    kc_destroy(pub); kc_close(a);
}

CURVE_TESTS(bcecdsa_verify_bad_args) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE pub = dsa_pub(c, a);
    CHECK_NS(U(BCryptVerifySignature)(NULL, NULL, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptVerifySignature)((BCRYPT_KEY_HANDLE)a, NULL, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, NULL, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, NULL, 2 * c->cb, 0), NS_INVALID_PARAMETER);
    int pad = 1;
    CHECK_NS(U(BCryptVerifySignature)(pub, &pad, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_INVALID_PARAMETER);
    static const ULONG badflags[] = { 1, 4, 0x10, 0x80, 0x100 };
    for (unsigned i = 0; i < sizeof(badflags) / sizeof(badflags[0]); i++)
        CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, badflags[i]), NS_INVALID_PARAMETER);
    kc_destroy(pub); kc_close(a);
}

CURVE_TESTS(bcecdsa_verify_hash_length_variants) {
    /* A different hash length is a different message digest: the signature made over the standard digest does not verify. */
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE pub = dsa_pub(c, a);
    for (ULONG n = 1; n < c->hashlen; n += 5) {
        NTSTATUS s = U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, n, (PUCHAR)c->sig, 2 * c->cb, 0);
        CHECKF(s == NS_INVALID_SIGNATURE, "truncated hash len %lu -> 0x%08lx", (unsigned long)n, (unsigned long)s);
    }
    kc_destroy(pub); kc_close(a);
}

/* ---- sign: protocol ---------------------------------------------------------------------------------------- */
CURVE_TESTS(bcecdsa_sign_size_query) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    ULONG r = 0xCAFE;
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, NULL, 0, &r, 0), 0);
    EXPECT_EQ(r, 2 * c->cb);
    r = 0xCAFE;
    unsigned char sig[200];
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, NULL, 77, &r, 0), 0);
    EXPECT_EQ(r, 2 * c->cb);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecdsa_sign_buffer_sizes) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char sig[300];
    ULONG need = 2 * c->cb, r;
    for (ULONG cap = 0; cap < need; cap += (cap < 3 ? 1 : need / 4)) {
        r = 0xCAFE;
        memset(sig, 0xA5, sizeof(sig));
        NTSTATUS s = U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, cap, &r, 0);
        CHECKF(s == NS_BUFFER_TOO_SMALL, "cap %lu -> 0x%08lx", (unsigned long)cap, (unsigned long)s);
        EXPECT_EQ(r, need);
        EXPECT_EQ(sig[0], 0xA5);
    }
    r = 0; memset(sig, 0xA5, sizeof(sig));
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, need - 1, &r, 0), NS_BUFFER_TOO_SMALL);
    EXPECT_EQ(r, need);
    r = 0;
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, need, &r, 0), 0);
    EXPECT_EQ(r, need);
    r = 0; memset(sig, 0xA5, sizeof(sig));
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, need + 20, &r, 0), 0);
    EXPECT_EQ(r, need);
    EXPECT_EQ(sig[need], 0xA5);      /* only 2*cbKey bytes are written */
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecdsa_sign_verify_roundtrip) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char sig[200]; ULONG r = 0;
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), 0);
    EXPECT_EQ(r, 2 * c->cb);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, r, 0), 0);
    /* export the public half and verify with it */
    unsigned char blob[512]; ULONG n = 0; BCRYPT_KEY_HANDLE pub = NULL;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &n), 0);
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, blob, n, 0, &pub), 0);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, r, 0), 0);
    sig[5] ^= 4;
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, r, 0), NS_INVALID_SIGNATURE);
    kc_destroy(pub); kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecdsa_sign_known_key_verifies) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE prv = dsa_priv(c, a), pub = dsa_pub(c, a);
    unsigned char sig[200]; ULONG r = 0;
    CHECK_NS(U(BCryptSignHash)(prv, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), 0);
    CHECK_NS(U(BCryptVerifySignature)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, r, 0), 0);
    kc_destroy(prv); kc_destroy(pub); kc_close(a);
}

CURVE_TESTS(bcecdsa_sign_is_randomized) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char s1[200], s2[200]; ULONG r1 = 0, r2 = 0;
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, s1, sizeof(s1), &r1, 0), 0);
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, s2, sizeof(s2), &r2, 0), 0);
    CHECK(memcmp(s1, s2, r1) != 0);                       /* a fresh nonce per signature */
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, (PUCHAR)c->hash, c->hashlen, s1, r1, 0), 0);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, (PUCHAR)c->hash, c->hashlen, s2, r2, 0), 0);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecdsa_sign_hash_lengths) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char digest[200], sig[200];
    for (int i = 0; i < 200; i++) digest[i] = (unsigned char)(i * 7 + 3);
    static const ULONG lens[] = { 1, 16, 20, 28, 32, 48, 64, 66, 100, 200 };
    for (unsigned i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        ULONG r = 0;
        NTSTATUS s = U(BCryptSignHash)(k, NULL, digest, lens[i], sig, sizeof(sig), &r, 0);
        CHECKF(s == 0, "sign hash length %lu -> 0x%08lx", (unsigned long)lens[i], (unsigned long)s);
        if (NT_OK(s)) {
            EXPECT_EQ(r, 2 * c->cb);
            s = U(BCryptVerifySignature)(k, NULL, digest, lens[i], sig, r, 0);
            CHECKF(s == 0, "verify hash length %lu -> 0x%08lx", (unsigned long)lens[i], (unsigned long)s);
        }
    }
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecdsa_sign_bad_args) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char sig[200]; ULONG r = 0;
    CHECK_NS(U(BCryptSignHash)(NULL, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSignHash)((BCRYPT_KEY_HANDLE)a, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), NULL, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptSignHash)(k, NULL, NULL, c->hashlen, sig, sizeof(sig), &r, 0), NS_INVALID_PARAMETER);
    int pad = 0;
    CHECK_NS(U(BCryptSignHash)(k, &pad, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), NS_INVALID_PARAMETER);
    static const ULONG badflags[] = { 1, 4, 0x10, 0x80, 0x100 };
    for (unsigned i = 0; i < sizeof(badflags) / sizeof(badflags[0]); i++)
        CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, badflags[i]), NS_INVALID_PARAMETER);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecdsa_sign_public_only_key) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE pub = dsa_pub(c, a);
    unsigned char sig[200]; ULONG r = 0;
    CHECK_NS(U(BCryptSignHash)(pub, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), NS_INVALID_PARAMETER);
    kc_destroy(pub); kc_close(a);
}

CURVE_TESTS(bcecdsa_sign_with_ecdh_key) {
    /* ECDH keys belong to the key-agreement class: signing and verifying are not supported */
    BCRYPT_ALG_HANDLE b = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(b, c->bits, 1);
    unsigned char sig[200]; ULONG r = 0;
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), NS_NOT_SUPPORTED);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_NOT_SUPPORTED);
    kc_destroy(k); kc_close(b);
}

CURVE_TESTS(bcecdsa_cross_curve_signature) {
    /* a signature from this curve's key checked against the next curve's key: length mismatch -> parameter error */
    const curve_t *o = &g_curves[(c - g_curves + 1) % 3];
    BCRYPT_ALG_HANDLE a = kc_open(o->dsa, 0);
    if (!a) { kc_close(a); return; }
    BCRYPT_KEY_HANDLE k = dsa_pub(o, a);
    if (k) {
        CHECK_NS(U(BCryptVerifySignature)(k, NULL, (PUCHAR)c->hash, c->hashlen, (PUCHAR)c->sig, 2 * c->cb, 0), NS_INVALID_PARAMETER);
    }
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecdsa_pseudo_handle_roundtrip) {
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(c->pdsa, &k, 0, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    unsigned char sig[200]; ULONG r = 0;
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), 0);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, r, 0), 0);
    kc_destroy(k);
}

TEST(bcecdsa_sign_default_hash_alg_independent) {
    NEED_CORE();
    /* the signing input is an opaque digest: a SHA-1 sized and a SHA-512 sized digest both work on a P-256 key */
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDSA_P256", 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, 256, 1);
    unsigned char d[64] = {1,2,3,4,5,6,7,8,9}, sig[64]; ULONG r;
    CHECK_NS(U(BCryptSignHash)(k, NULL, d, 20, sig, 64, &r, 0), 0);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, d, 20, sig, 64, 0), 0);
    CHECK_NS(U(BCryptSignHash)(k, NULL, d, 64, sig, 64, &r, 0), 0);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, d, 64, sig, 64, 0), 0);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, d, 20, sig, 64, 0), NS_INVALID_SIGNATURE);
    kc_destroy(k); kc_close(a);
}

/* ---- ECDH secret agreement ------------------------------------------------------------------------------------ */
CURVE_TESTS(bcecdh_agree_kat) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE ap = kc_key(a, c, 1, 0, 1), bp = kc_key(a, c, 1, 1, 1), apub = kc_key(a, c, 1, 0, 0), bpub = kc_key(a, c, 1, 1, 0);
    NTSTATUS s1, s2;
    BCRYPT_SECRET_HANDLE x = kc_agree(ap, bpub, &s1), y = kc_agree(bp, apub, &s2);
    CHECK_NS(s1, 0); CHECK_NS(s2, 0);
    unsigned char r1[80] = {0}, r2[80] = {0}, want[80]; ULONG n1 = 0, n2 = 0;
    if (x) CHECK_NS(kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof(r1), &n1, 0), 0);
    if (y) CHECK_NS(kc_derive(y, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof(r2), &n2, 0), 0);
    EXPECT_EQ(n1, c->cb); EXPECT_EQ(n2, c->cb);
    kc_rev(want, c->z, c->cb);                         /* raw secret is the x coordinate in little-endian order */
    CHECK_MEM(r1, want, c->cb);
    CHECK_MEM(r2, want, c->cb);
    if (x) U(BCryptDestroySecret)(x);
    if (y) U(BCryptDestroySecret)(y);
    kc_destroy(ap); kc_destroy(bp); kc_destroy(apub); kc_destroy(bpub); kc_close(a);
}

CURVE_TESTS(bcecdh_agree_private_as_public) {
    /* the second argument may be a key pair; only its public point is used */
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE ap = kc_key(a, c, 1, 0, 1), bp = kc_key(a, c, 1, 1, 1);
    NTSTATUS s;
    BCRYPT_SECRET_HANDLE x = kc_agree(ap, bp, &s);
    CHECK_NS(s, 0);
    unsigned char r1[80] = {0}, want[80]; ULONG n1 = 0;
    if (x) {
        CHECK_NS(kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof(r1), &n1, 0), 0);
        kc_rev(want, c->z, c->cb);
        CHECK_MEM(r1, want, c->cb);
        U(BCryptDestroySecret)(x);
    }
    kc_destroy(ap); kc_destroy(bp); kc_close(a);
}

CURVE_TESTS(bcecdh_agree_generated_keys) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k1 = kc_gen(a, c->bits, 1), k2 = kc_gen(a, c->bits, 1);
    NTSTATUS s1, s2;
    BCRYPT_SECRET_HANDLE x = kc_agree(k1, k2, &s1), y = kc_agree(k2, k1, &s2);
    CHECK_NS(s1, 0); CHECK_NS(s2, 0);
    unsigned char r1[80] = {0}, r2[80] = {0}; ULONG n1 = 0, n2 = 0;
    if (x && y) {
        CHECK_NS(kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof(r1), &n1, 0), 0);
        CHECK_NS(kc_derive(y, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof(r2), &n2, 0), 0);
        EXPECT_EQ(n1, c->cb); EXPECT_EQ(n1, n2);
        CHECK_MEM(r1, r2, n1);
    }
    /* a self-agreement differs from a cross agreement */
    BCRYPT_SECRET_HANDLE z = kc_agree(k1, k1, &s1);
    CHECK_NS(s1, 0);
    if (z && x) {
        unsigned char r3[80] = {0}; ULONG n3 = 0;
        kc_derive(z, BCRYPT_KDF_RAW_SECRET, NULL, r3, sizeof(r3), &n3, 0);
        CHECK(memcmp(r1, r3, c->cb) != 0);
    }
    if (x) U(BCryptDestroySecret)(x);
    if (y) U(BCryptDestroySecret)(y);
    if (z) U(BCryptDestroySecret)(z);
    kc_destroy(k1); kc_destroy(k2); kc_close(a);
}

CURVE_TESTS(bcecdh_agree_bad_args) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE ap = kc_key(a, c, 1, 0, 1), bpub = kc_key(a, c, 1, 1, 0);
    BCRYPT_SECRET_HANDLE s = NULL;
    CHECK_NS(U(BCryptSecretAgreement)(NULL, bpub, &s, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSecretAgreement)(ap, NULL, &s, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSecretAgreement)(NULL, NULL, &s, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSecretAgreement)((BCRYPT_KEY_HANDLE)a, bpub, &s, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSecretAgreement)(ap, (BCRYPT_KEY_HANDLE)a, &s, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSecretAgreement)(ap, bpub, NULL, 0), NS_INVALID_PARAMETER);
    static const ULONG flags[] = { 1, 2, 8, 0x80000000 };
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        CHECK_NS(U(BCryptSecretAgreement)(ap, bpub, &s, flags[i]), NS_INVALID_PARAMETER);
        if (s) { U(BCryptDestroySecret)(s); s = NULL; }
    }
    CHECK(s == NULL);
    kc_destroy(ap); kc_destroy(bpub); kc_close(a);
}

CURVE_TESTS(bcecdh_agree_public_only_private_arg) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE apub = kc_key(a, c, 1, 0, 0), bpub = kc_key(a, c, 1, 1, 0);
    BCRYPT_SECRET_HANDLE s = NULL;
    /* Win10 does not check that the first key holds a private part: bcrypt faults */
    T_EXPECT_FAULT(U(BCryptSecretAgreement)(apub, bpub, &s, 0));
    kc_destroy(apub); kc_destroy(bpub); kc_close(a);
}

CURVE_TESTS(bcecdh_agree_ecdsa_key_private) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0), b = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE sk = kc_gen(a, c->bits, 1), pub = kc_key(b, c, 1, 1, 0);
    BCRYPT_SECRET_HANDLE s = NULL;
    CHECK_NS(U(BCryptSecretAgreement)(sk, pub, &s, 0), NS_NOT_SUPPORTED);   /* ECDSA is a signature-class algorithm */
    CHECK(s == NULL);
    kc_destroy(sk); kc_destroy(pub); kc_close(a); kc_close(b);
}

CURVE_TESTS(bcecdh_agree_ecdsa_key_public) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0), b = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE sk = kc_key(a, c, 0, 1, 0), prv = kc_key(b, c, 1, 0, 1);
    BCRYPT_SECRET_HANDLE s = NULL;
    NTSTATUS st = U(BCryptSecretAgreement)(prv, sk, &s, 0);
    CHECK_NS(st, NS_INVALID_PARAMETER);
    if (s) U(BCryptDestroySecret)(s);
    kc_destroy(sk); kc_destroy(prv); kc_close(a); kc_close(b);
}

TEST(bcecdh_agree_mixed_curves) {
    NEED_CORE();
    for (int i = 0; i < 3; i++) for (int j = 0; j < 3; j++) {
        if (i == j) continue;
        const curve_t *p = &g_curves[i], *q = &g_curves[j];
        BCRYPT_ALG_HANDLE a = kc_open(p->dh, 0), b = kc_open(q->dh, 0);
        if (!a || !b) { kc_close(a); kc_close(b); continue; }
        BCRYPT_KEY_HANDLE kp = kc_key(a, p, 1, 0, 1), kq = kc_key(b, q, 1, 1, 0);
        if (kp && kq) {
            BCRYPT_SECRET_HANDLE s = NULL;
            NTSTATUS st = U(BCryptSecretAgreement)(kp, kq, &s, 0);
            t_label("%s priv + %s pub", p->name, q->name); CHECK_NS(st, NS_INVALID_PARAMETER);
            if (s) U(BCryptDestroySecret)(s);
        }
        kc_destroy(kp); kc_destroy(kq); kc_close(a); kc_close(b);
    }
}

TEST(bcecdh_agree_with_rsa_key_note) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE r = kc_open(L"RSA", 0), b = kc_open(L"ECDH_P256", 0);
    if (!r) { t_skip("RSA missing"); kc_close(b); return; }
    BCRYPT_KEY_HANDLE rk = NULL, ek = kc_gen(b, 256, 1);
    if (NT_OK(U(BCryptGenerateKeyPair)(r, &rk, 1024, 0)) && NT_OK(U(BCryptFinalizeKeyPair)(rk, 0))) {
        BCRYPT_SECRET_HANDLE s = NULL;
        NTSTATUS st = U(BCryptSecretAgreement)(rk, ek, &s, 0);
        CHECK_NS(st, NS_NOT_SUPPORTED);            /* RSA is not a key-agreement algorithm */
        st = U(BCryptSecretAgreement)(ek, rk, &s, 0);
        CHECK_NS(st, NS_INVALID_PARAMETER);
        if (s) U(BCryptDestroySecret)(s);
    }
    kc_destroy(rk); kc_destroy(ek); kc_close(r); kc_close(b);
}

/* ---- secret handle lifetime ------------------------------------------------------------------------------------------- */
TEST(bcecdh_destroy_secret_bad_handles) {
    NEED_CORE();
    CHECK_NS(U(BCryptDestroySecret)(NULL), NS_INVALID_HANDLE);
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDH_P256", 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, 256, 1);
    CHECK_NS(U(BCryptDestroySecret)((BCRYPT_SECRET_HANDLE)k), NS_INVALID_HANDLE);        /* key handle is not a secret */
    CHECK_NS(U(BCryptDestroySecret)((BCRYPT_SECRET_HANDLE)a), NS_INVALID_HANDLE);        /* alg handle is not a secret */
    CHECK_NS(U(BCryptDestroyKey)((BCRYPT_KEY_HANDLE)NULL), NS_INVALID_HANDLE);
    BCRYPT_SECRET_HANDLE s = NULL;
    NTSTATUS st;
    s = kc_agree(k, k, &st);
    CHECK_NS(st, 0);
    CHECK_NS(U(BCryptDestroyKey)((BCRYPT_KEY_HANDLE)s), NS_INVALID_HANDLE);             /* secret handle is not a key */
    CHECK_NS(U(BCryptDestroySecret)(s), 0);
    kc_destroy(k); kc_close(a);
}

TEST(bcecdh_secret_outlives_keys_and_alg) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDH_P256", 0);
    BCRYPT_KEY_HANDLE k1 = kc_key(a, &g_curves[0], 1, 0, 1), k2 = kc_key(a, &g_curves[0], 1, 1, 0);
    NTSTATUS st;
    BCRYPT_SECRET_HANDLE s = kc_agree(k1, k2, &st);
    CHECK_NS(st, 0);
    kc_destroy(k1); kc_destroy(k2); kc_close(a);
    unsigned char out[32]; ULONG n = 0;
    CHECK_NS(kc_derive(s, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof(out), &n, 0), 0);
    unsigned char want[32]; kc_rev(want, g_curves[0].z, 32);
    CHECK_MEM(out, want, 32);
    CHECK_NS(U(BCryptDestroySecret)(s), 0);
}

TEST(bcecdh_multiple_secrets_from_one_pair) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDH_P256", 0);
    BCRYPT_KEY_HANDLE k1 = kc_key(a, &g_curves[0], 1, 0, 1), k2 = kc_key(a, &g_curves[0], 1, 1, 0);
    NTSTATUS st;
    BCRYPT_SECRET_HANDLE s1 = kc_agree(k1, k2, &st), s2 = kc_agree(k1, k2, &st);
    CHECK(s1 && s2 && s1 != s2);
    unsigned char o1[32], o2[32]; ULONG n;
    CHECK_NS(kc_derive(s1, BCRYPT_KDF_RAW_SECRET, NULL, o1, 32, &n, 0), 0);
    CHECK_NS(U(BCryptDestroySecret)(s1), 0);
    CHECK_NS(kc_derive(s2, BCRYPT_KDF_RAW_SECRET, NULL, o2, 32, &n, 0), 0);
    CHECK_MEM(o1, o2, 32);
    CHECK_NS(U(BCryptDestroySecret)(s2), 0);
    kc_destroy(k1); kc_destroy(k2); kc_close(a);
}

TEST(bcecdh_agree_loop_stress) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDH_P256", 0);
    for (int i = 0; i < 40; i++) {
        BCRYPT_KEY_HANDLE k1 = kc_gen(a, 256, 1), k2 = kc_gen(a, 256, 1);
        NTSTATUS s1, s2;
        BCRYPT_SECRET_HANDLE x = kc_agree(k1, k2, &s1), y = kc_agree(k2, k1, &s2);
        unsigned char r1[32] = {0}, r2[32] = {1}; ULONG n;
        if (x && y) {
            kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, r1, 32, &n, 0);
            kc_derive(y, BCRYPT_KDF_RAW_SECRET, NULL, r2, 32, &n, 0);
        }
        CHECKF(x && y && !memcmp(r1, r2, 32), "iteration %d", i);
        if (x) U(BCryptDestroySecret)(x);
        if (y) U(BCryptDestroySecret)(y);
        kc_destroy(k1); kc_destroy(k2);
    }
    kc_close(a);
}

CURVE_TESTS(bcecdh_agree_generic_vs_fixed_roundtrip_export) {
    /* export both keys' private blobs, re-import and check the agreed secret is unchanged */
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k1 = kc_gen(a, c->bits, 1), k2 = kc_gen(a, c->bits, 1), r1 = NULL;
    unsigned char blob[512]; ULONG n = 0;
    CHECK_NS(kc_export(k1, BCRYPT_ECCPRIVATE_BLOB, blob, sizeof(blob), &n), 0);
    CHECK_NS(kc_import(a, BCRYPT_ECCPRIVATE_BLOB, blob, n, 0, &r1), 0);
    NTSTATUS s1, s2;
    BCRYPT_SECRET_HANDLE x = kc_agree(k1, k2, &s1), y = kc_agree(r1, k2, &s2);
    unsigned char o1[80] = {0}, o2[80] = {1}; ULONG m;
    if (x && y) {
        kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, o1, sizeof(o1), &m, 0);
        kc_derive(y, BCRYPT_KDF_RAW_SECRET, NULL, o2, sizeof(o2), &m, 0);
        CHECK_MEM(o1, o2, c->cb);
    } else CHECK(x && y);
    if (x) U(BCryptDestroySecret)(x);
    if (y) U(BCryptDestroySecret)(y);
    kc_destroy(k1); kc_destroy(k2); kc_destroy(r1); kc_close(a);
}

/* ECC key generation, blobs, import/export validation for ECDSA_P* / ECDH_P* / generic ECDH. */
#include "kc.h"

/* ---- algorithm handles and properties ------------------------------------ */
CURVE_TESTS(bcecc_alg_open) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0), b = kc_open(c->dh, 0);
    CHECK(a != NULL); CHECK(b != NULL);
    WCHAR name[64] = {0}; ULONG r = 0;
    if (a) {
        CHECK_NS(U(BCryptGetProperty)(a, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof(name), &r, 0), 0);
        EXPECT_WSTR(name, c->dsa);
        EXPECT_EQ(r, (lstrlenW(c->dsa) + 1) * 2);
    }
    if (b) {
        memset(name, 0, sizeof(name));
        CHECK_NS(U(BCryptGetProperty)(b, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof(name), &r, 0), 0);
        EXPECT_WSTR(name, c->dh);
    }
    kc_close(a); kc_close(b);
}

CURVE_TESTS(bcecc_pseudo_name) {
    WCHAR name[64] = {0}; ULONG r = 0;
    CHECK_NS(U(BCryptGetProperty)(c->pdsa, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof(name), &r, 0), 0);
    EXPECT_WSTR(name, c->dsa);
    memset(name, 0, sizeof(name));
    CHECK_NS(U(BCryptGetProperty)(c->pdh, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof(name), &r, 0), 0);
    EXPECT_WSTR(name, c->dh);
}

TEST(bcecc_alg_open_bad_flags) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234;
    NTSTATUS s = U(BCryptOpenAlgorithmProvider)(&h, L"ECDSA_P256", NULL, 0x80);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    if (NT_OK(s)) kc_close(h);
    h = NULL;
    s = U(BCryptOpenAlgorithmProvider)(&h, L"ECDSA_P256", NULL, BCRYPT_PROV_DISPATCH);
    CHECK_NS(s, NS_INVALID_PARAMETER);   /* BCRYPT_PROV_DISPATCH is not valid for ECDSA_P256 */
    kc_close(h);
}

TEST(bcecc_alg_open_unknown) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    CHECK_NS(U(BCryptOpenAlgorithmProvider)(&h, L"ECDSA_P257", NULL, 0), NS_NOT_FOUND);
    h = NULL;
    NTSTATUS s = U(BCryptOpenAlgorithmProvider)(&h, L"ecdsa_p256", NULL, 0);
    CHECK_NS(s, NS_NOT_SUPPORTED);
    kc_close(h);
}

CURVE_TESTS(bcecc_prop_keylength) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    if (!a) { CHECK(a != NULL); return; }
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    CHECK(k != NULL);
    if (k) {
        DWORD len = 0; ULONG r = 0;
        NTSTATUS s = U(BCryptGetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&len, 4, &r, 0);
        CHECK_NS(s, 0);
        EXPECT_EQ(r, 4);
        EXPECT_EQ(len, c->bits);
        kc_destroy(k);
    }
    kc_close(a);
}

/* ---- generation -------------------------------------------------------------- */
CURVE_TESTS(bcecc_gen_basic) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0), b = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k1 = NULL, k2 = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k1, c->bits, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k1, 0), 0);
    CHECK_NS(U(BCryptGenerateKeyPair)(b, &k2, c->bits, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k2, 0), 0);
    CHECK(k1 != NULL && k2 != NULL && k1 != k2);
    kc_destroy(k1); kc_destroy(k2); kc_close(a); kc_close(b);
}

CURVE_TESTS(bcecc_gen_length_zero) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 0, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_gen_wrong_length) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    static const ULONG bad[] = { 1, 128, 255, 257, 512, 1024, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (bad[i] == c->bits) continue;
        BCRYPT_KEY_HANDLE k = (BCRYPT_KEY_HANDLE)(ULONG_PTR)1;
        NTSTATUS s = U(BCryptGenerateKeyPair)(a, &k, bad[i], 0);
        CHECKF(s == NS_INVALID_PARAMETER, "length %lu -> 0x%08lx", (unsigned long)bad[i], (unsigned long)s);
        if (NT_OK(s)) kc_destroy(k);
    }
    kc_close(a);
}

CURVE_TESTS(bcecc_gen_bad_flags) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    static const ULONG flags[] = { 1, 2, 4, 8, 0x10, 0x80000000 };
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = U(BCryptGenerateKeyPair)(a, &k, c->bits, flags[i]);
        CHECKF(s == NS_INVALID_PARAMETER, "flags 0x%lx -> 0x%08lx", (unsigned long)flags[i], (unsigned long)s);
        if (NT_OK(s)) kc_destroy(k);
    }
    kc_close(a);
}

TEST(bcecc_gen_null_args) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDSA_P256", 0);
    BCRYPT_KEY_HANDLE k = NULL;
    if (!t_is_wine()) CHECK_NS(U(BCryptGenerateKeyPair)(a, NULL, 256, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptGenerateKeyPair)(NULL, &k, 256, 0), NS_INVALID_HANDLE);
    CHECK(k == NULL);
    kc_close(a);
}

TEST(bcecc_gen_wrong_class) {
    NEED_CORE();
    /* hash, symmetric and RNG algorithms are not key-pair algorithms */
    static const WCHAR *const algs[] = { L"SHA256", L"AES", L"RNG" };
    for (unsigned i = 0; i < 3; i++) {
        BCRYPT_ALG_HANDLE a = kc_open(algs[i], 0);
        if (!a) continue;
        BCRYPT_KEY_HANDLE k = NULL;
        CHECK_NS(U(BCryptGenerateKeyPair)(a, &k, 256, 0), NS_NOT_SUPPORTED);
        kc_close(a);
    }
}

CURVE_TESTS(bcecc_gen_pseudo_handles) {
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(c->pdsa, &k, c->bits, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    unsigned char buf[512]; ULONG n = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n), 0);
    EXPECT_EQ(n, 8 + 2 * c->cb);
    EXPECT_EQ(((BCRYPT_ECCKEY_BLOB *)buf)->dwMagic, c->dsa_pub);
    kc_destroy(k);
    k = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(c->pdh, &k, c->bits, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n), 0);
    EXPECT_EQ(((BCRYPT_ECCKEY_BLOB *)buf)->dwMagic, c->dh_pub);
    kc_destroy(k);
}

/* ---- finalize ------------------------------------------------------------------ */
CURVE_TESTS(bcecc_finalize_twice) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    CHECK(k != NULL);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), NS_INVALID_HANDLE);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_finalize_bad_flags) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 0);
    CHECK(k != NULL);
    static const ULONG flags[] = { 1, 2, 4, 8, 0x10, 0x20 };
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); i++)
        CHECK_NS(U(BCryptFinalizeKeyPair)(k, flags[i]), NS_INVALID_PARAMETER);
    /* the key is still unfinalized and finalizes with flags 0 */
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    kc_destroy(k); kc_close(a);
}

TEST(bcecc_finalize_bad_handles) {
    NEED_CORE();
    CHECK_NS(U(BCryptFinalizeKeyPair)(NULL, 0), NS_INVALID_HANDLE);
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDSA_P256", 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)((BCRYPT_KEY_HANDLE)a, 0), NS_INVALID_HANDLE);   /* algorithm handle as key */
    kc_close(a);
}

TEST(bcecc_finalize_symmetric_key_not_supported) {
    NEED_CORE();
    if (!U(BCryptGenerateSymmetricKey)) { KC_MISSING("no BCryptGenerateSymmetricKey"); return; }
    BCRYPT_ALG_HANDLE a = kc_open(L"AES", 0);
    BCRYPT_KEY_HANDLE k = NULL;
    unsigned char key[16] = {0};
    CHECK_NS(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, key, 16, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), NS_NOT_SUPPORTED);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_unfinalized_unusable) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0), b = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 0), kd = kc_gen(b, c->bits, 0);
    unsigned char buf[512], sig[200]; ULONG n = 0, r = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n), NS_INVALID_HANDLE);
    CHECK_NS(kc_export(k, BCRYPT_ECCPRIVATE_BLOB, buf, sizeof(buf), &n), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), NS_INVALID_PARAMETER);
    BCRYPT_KEY_HANDLE good = kc_key(b, c, 1, 1, 0);
    BCRYPT_SECRET_HANDLE sec = NULL;
    /* Win10 does not check that the private key is finalized: bcrypt faults */
    T_EXPECT_FAULT(U(BCryptSecretAgreement)(kd, good, &sec, 0));
    kc_destroy(good); kc_destroy(k); kc_destroy(kd); kc_close(a); kc_close(b);
}

/* ---- export sizes and layout ------------------------------------------------------- */
CURVE_TESTS(bcecc_export_public_layout) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char buf[512]; ULONG n = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &n), 0);
    EXPECT_EQ(n, 8 + 2 * c->cb);
    memset(buf, 0xCC, sizeof(buf));
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n), 0);
    EXPECT_EQ(n, 8 + 2 * c->cb);
    BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)buf;
    EXPECT_EQ(h->dwMagic, c->dsa_pub);
    EXPECT_EQ(h->cbKey, c->cb);
    EXPECT_EQ(buf[n], 0xCC);                       /* nothing written past the reported size */
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_export_private_layout) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char buf[512]; ULONG n = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &n), 0);
    EXPECT_EQ(n, 8 + 3 * c->cb);
    CHECK_NS(kc_export(k, BCRYPT_ECCPRIVATE_BLOB, buf, sizeof(buf), &n), 0);
    EXPECT_EQ(n, 8 + 3 * c->cb);
    EXPECT_EQ(((BCRYPT_ECCKEY_BLOB *)buf)->dwMagic, c->dh_prv);
    EXPECT_EQ(((BCRYPT_ECCKEY_BLOB *)buf)->cbKey, c->cb);
    unsigned char zero[80] = {0};
    CHECK(memcmp(buf + 8 + 2 * c->cb, zero, c->cb) != 0);   /* d is not zero */
    /* the public part of a private export equals the public export */
    unsigned char pub[512]; ULONG pn = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, pub, sizeof(pub), &pn), 0);
    CHECK_MEM(buf + 8, pub + 8, 2 * c->cb);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_export_size_protocol) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char buf[512]; ULONG n = 0;
    ULONG need = 8 + 2 * c->cb;
    memset(buf, 0xAB, sizeof(buf));
    for (ULONG sz = 0; sz < need; sz += (sz < 12 ? 1 : need / 3)) {
        n = 0xFEEDFACE;
        NTSTATUS s = kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, sz, &n);
        CHECKF(s == NS_BUFFER_TOO_SMALL, "cap %lu -> 0x%08lx", (unsigned long)sz, (unsigned long)s);
        EXPECT_EQ(n, need);
    }
    n = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, need - 1, &n), NS_BUFFER_TOO_SMALL);
    EXPECT_EQ(n, need);
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, need, &n), 0);
    EXPECT_EQ(n, need);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_export_unknown_type) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char buf[512]; ULONG n = 0;
    static const WCHAR *const types[] = { L"FOOBLOB", L"", L"RSAPUBLICBLOB", L"DHPUBLICBLOB", L"eccpublicblob", BCRYPT_KEY_DATA_BLOB };
    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        NTSTATUS s = kc_export(k, types[i], buf, sizeof(buf), &n);
        t_label("type %u", i); CHECK_NS(s, NS_NOT_SUPPORTED);
    }
    kc_destroy(k); kc_close(a);
}

TEST(bcecc_export_bad_args) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDSA_P256", 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, 256, 1);
    unsigned char buf[256]; ULONG n = 0;
    CHECK_NS(U(BCryptExportKey)(NULL, NULL, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), NULL, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n, 0x8), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptExportKey)(k, NULL, NULL, buf, sizeof(buf), &n, 0), NS_INVALID_PARAMETER);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_export_full_public) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char buf[1024]; ULONG n = 0;
    NTSTATUS s = kc_export(k, BCRYPT_ECCFULLPUBLIC_BLOB, buf, sizeof(buf), &n);
    CHECK_NS(s, 0);
    if (!NT_OK(s)) { kc_destroy(k); kc_close(a); return; }
    BCRYPT_ECCFULLKEY_BLOB *h = (BCRYPT_ECCFULLKEY_BLOB *)buf;
    EXPECT_EQ(h->dwVersion, BCRYPT_ECC_FULLKEY_BLOB_V1);
    EXPECT_EQ(h->dwCurveType, BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE);
    EXPECT_EQ(h->dwCurveGenerationAlgId, BCRYPT_NO_CURVE_GENERATION_ALG_ID);
    EXPECT_EQ(h->cbFieldLength, c->cb);
    EXPECT_EQ(h->cbSubgroupOrder, c->cb);
    /* prime, a, b, Gx, Gy, order, cofactor, seed, then Px, Py */
    ULONG want = sizeof(*h) + 5 * h->cbFieldLength + h->cbSubgroupOrder + h->cbCofactor + h->cbSeed + 2 * h->cbFieldLength;
    EXPECT_EQ(n, want);
    EXPECT_EQ(h->dwMagic, c->dh_pub == BCRYPT_ECDH_PUBLIC_P256_MAGIC ? 0x314b4345u : c->dh_pub == BCRYPT_ECDH_PUBLIC_P384_MAGIC ? 0x334b4345u : 0x354b4345u);
    EXPECT_EQ(h->cbCofactor, 1); EXPECT_EQ(h->cbSeed, 0);
    /* the public point at the tail equals the ECCPUBLICBLOB point */
    unsigned char pub[512]; ULONG pn = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, pub, sizeof(pub), &pn), 0);
    CHECK_MEM(buf + n - 2 * c->cb, pub + 8, 2 * c->cb);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_export_full_private) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char buf[1024], pub[1024], prv[512]; ULONG n = 0, pn = 0, rn = 0;
    NTSTATUS s = kc_export(k, BCRYPT_ECCFULLPRIVATE_BLOB, buf, sizeof(buf), &n);
    CHECK_NS(s, 0);
    if (!NT_OK(s)) { kc_destroy(k); kc_close(a); return; }
    BCRYPT_ECCFULLKEY_BLOB *h = (BCRYPT_ECCFULLKEY_BLOB *)buf;
    CHECK_NS(kc_export(k, BCRYPT_ECCFULLPUBLIC_BLOB, pub, sizeof(pub), &pn), 0);
    EXPECT_EQ(n, pn + h->cbSubgroupOrder);
    CHECK_NS(kc_export(k, BCRYPT_ECCPRIVATE_BLOB, prv, sizeof(prv), &rn), 0);
    CHECK_MEM(buf + n - c->cb, prv + 8 + 2 * c->cb, c->cb);        /* trailing d */
    CHECK_MEM(buf + sizeof(*h), pub + sizeof(*h), n - sizeof(*h) - c->cb);   /* domain params + point */
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_export_full_roundtrip) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1), k2 = NULL;
    unsigned char buf[1024], again[1024]; ULONG n = 0, m = 0;
    NTSTATUS s = kc_export(k, BCRYPT_ECCFULLPRIVATE_BLOB, buf, sizeof(buf), &n);
    CHECK_NS(s, 0);
    if (!NT_OK(s)) { kc_destroy(k); kc_close(a); return; }
    s = kc_import(a, BCRYPT_ECCFULLPRIVATE_BLOB, buf, n, 0, &k2);
    CHECK_NS(s, 0);
    if (k2) {
        CHECK_NS(kc_export(k2, BCRYPT_ECCFULLPRIVATE_BLOB, again, sizeof(again), &m), 0);
        EXPECT_EQ(m, n);
        if (m == n) CHECK_MEM(buf, again, n);
    }
    kc_destroy(k2); kc_destroy(k); kc_close(a);
}

/* ---- import: known keys ---------------------------------------------------------------- */
CURVE_TESTS(bcecc_import_private_roundtrip) {
    unsigned char in[512], out[512]; ULONG n, m = 0;
    for (int dh = 0; dh < 2; dh++) {
        BCRYPT_ALG_HANDLE a = kc_open(dh ? c->dh : c->dsa, 0);
        n = kc_eccblob(in, dh ? c->dh_prv : c->dsa_prv, c->cb, c->xA, c->yA, c->dA);
        BCRYPT_KEY_HANDLE k = NULL;
        CHECK_NS(kc_import(a, BCRYPT_ECCPRIVATE_BLOB, in, n, 0, &k), 0);
        if (k) {
            CHECK_NS(kc_export(k, BCRYPT_ECCPRIVATE_BLOB, out, sizeof(out), &m), 0);
            EXPECT_EQ(m, n);
            if (m == n) CHECK_MEM(in, out, n);
            CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, out, sizeof(out), &m), 0);
            EXPECT_EQ(m, 8 + 2 * c->cb);
            CHECK_MEM(out + 8, c->xA, c->cb);
            CHECK_MEM(out + 8 + c->cb, c->yA, c->cb);
            EXPECT_EQ(((BCRYPT_ECCKEY_BLOB *)out)->dwMagic, dh ? c->dh_pub : c->dsa_pub);
            kc_destroy(k);
        }
        kc_close(a);
    }
}

CURVE_TESTS(bcecc_import_public_roundtrip) {
    unsigned char in[512], out[512]; ULONG n, m = 0;
    for (int dh = 0; dh < 2; dh++) {
        BCRYPT_ALG_HANDLE a = kc_open(dh ? c->dh : c->dsa, 0);
        n = kc_eccblob(in, dh ? c->dh_pub : c->dsa_pub, c->cb, c->xB, c->yB, NULL);
        BCRYPT_KEY_HANDLE k = NULL;
        CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), 0);
        if (k) {
            CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, out, sizeof(out), &m), 0);
            EXPECT_EQ(m, n);
            if (m == n) CHECK_MEM(in, out, n);
            /* a public-only key cannot export a private blob */
            CHECK_NS(kc_export(k, BCRYPT_ECCPRIVATE_BLOB, out, sizeof(out), &m), NS_INVALID_PARAMETER);
            kc_destroy(k);
        }
        kc_close(a);
    }
}

CURVE_TESTS(bcecc_import_private_derives_public) {
    unsigned char in[512], out[512]; ULONG n, m = 0;
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    n = kc_eccblob(in, c->dsa_prv, c->cb, NULL, NULL, c->dA);   /* X and Y all zero: public point is computed */
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(kc_import(a, BCRYPT_ECCPRIVATE_BLOB, in, n, 0, &k), 0);
    if (k) {
        CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, out, sizeof(out), &m), 0);
        EXPECT_EQ(m, 8 + 2 * c->cb);
        CHECK_MEM(out + 8, c->xA, c->cb);
        CHECK_MEM(out + 8 + c->cb, c->yA, c->cb);
        kc_destroy(k);
    }
    kc_close(a);
}

CURVE_TESTS(bcecc_import_pseudo_handle) {
    unsigned char in[512];
    ULONG n = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, c->yA, NULL);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(kc_import(c->pdsa, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), 0);
    kc_destroy(k);
}

CURVE_TESTS(bcecc_import_trailing_bytes) {
    unsigned char in[600];
    memset(in, 0x5A, sizeof(in));
    ULONG n = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, c->yA, NULL);
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n + 7, 0, &k), 0);     /* longer than needed is accepted */
    kc_destroy(k); kc_close(a);
}

/* ---- import: malformed -------------------------------------------------------------------- */
CURVE_TESTS(bcecc_import_truncated) {
    unsigned char in[512];
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    ULONG npub = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, c->yA, NULL);
    for (ULONG sz = 0; sz < npub; sz += (sz < 10 ? 1 : 7)) {
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, sz, 0, &k);
        CHECKF(s == NS_INVALID_PARAMETER, "public blob size %lu -> 0x%08lx", (unsigned long)sz, (unsigned long)s);
        kc_destroy(k);
    }
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, npub - 1, 0, &k), NS_INVALID_PARAMETER);
    ULONG npriv = kc_eccblob(in, c->dsa_prv, c->cb, c->xA, c->yA, c->dA);
    CHECK_NS(kc_import(a, BCRYPT_ECCPRIVATE_BLOB, in, npriv - 1, 0, &k), NS_INVALID_PARAMETER);
    CHECK_NS(kc_import(a, BCRYPT_ECCPRIVATE_BLOB, in, npub, 0, &k), NS_INVALID_PARAMETER);
    kc_close(a);
}

CURVE_TESTS(bcecc_import_wrong_magic) {
    unsigned char in[512];
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0), b = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    ULONG n = kc_eccblob(in, c->dh_pub, c->cb, c->xA, c->yA, NULL);          /* ECDH magic into ECDSA */
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    n = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, c->yA, NULL);               /* ECDSA magic into ECDH */
    CHECK_NS(kc_import(b, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    n = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, c->yA, c->dA);              /* public magic with a private blob type */
    CHECK_NS(kc_import(a, BCRYPT_ECCPRIVATE_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    n = kc_eccblob(in, c->dsa_prv, c->cb, c->xA, c->yA, c->dA);              /* private magic with a public blob type */
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    n = kc_eccblob(in, 0x41414141, c->cb, c->xA, c->yA, NULL);
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    n = kc_eccblob(in, 0, c->cb, c->xA, c->yA, NULL);
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    kc_close(a); kc_close(b);
}

TEST(bcecc_import_wrong_curve) {
    NEED_CORE();
    unsigned char in[512];
    for (int ai = 0; ai < 3; ai++) for (int bi = 0; bi < 3; bi++) {
        if (ai == bi) continue;
        const curve_t *alg = &g_curves[ai], *blob = &g_curves[bi];
        BCRYPT_ALG_HANDLE a = kc_open(alg->dsa, 0);
        BCRYPT_KEY_HANDLE k = NULL;
        ULONG n = kc_eccblob(in, blob->dsa_pub, blob->cb, blob->xA, blob->yA, NULL);
        NTSTATUS s = kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k);
        CHECKF(s == NS_INVALID_PARAMETER, "%s blob into %s -> 0x%08lx", blob->name, alg->name, (unsigned long)s);
        /* correct magic for the algorithm but cbKey of another curve */
        n = kc_eccblob(in, alg->dsa_pub, blob->cb, blob->xA, blob->yA, NULL);
        s = kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k);
        CHECKF(s == NS_INVALID_PARAMETER, "%s cbKey into %s -> 0x%08lx", blob->name, alg->name, (unsigned long)s);
        kc_close(a);
    }
}

CURVE_TESTS(bcecc_import_cbkey_wrong) {
    unsigned char in[600];
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    static const ULONG cbs[] = { 0, 1, 31, 33, 47, 49, 65, 67, 0x10000000, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof(cbs) / sizeof(cbs[0]); i++) {
        if (cbs[i] == c->cb) continue;
        memset(in, 0x11, sizeof(in));
        BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)in;
        h->dwMagic = c->dsa_pub; h->cbKey = cbs[i];
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, 8 + 2 * c->cb, 0, &k);
        CHECKF(s == NS_INVALID_PARAMETER, "cbKey %lu -> 0x%08lx", (unsigned long)cbs[i], (unsigned long)s);
        kc_destroy(k);
    }
    kc_close(a);
}

TEST(bcecc_import_unknown_blob_type) {
    NEED_CORE();
    unsigned char in[256];
    const curve_t *c = &g_curves[0];
    ULONG n = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, c->yA, NULL);
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    static const WCHAR *const types[] = { L"FOOBLOB", L"", L"RSAPUBLICBLOB", L"DHPUBLICBLOB", L"eccpublicblob", L"KeyDataBlob" };
    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        NTSTATUS s = kc_import(a, types[i], in, n, 0, &k);
        CHECKF(s == NS_NOT_SUPPORTED, "type %u -> 0x%08lx", i, (unsigned long)s);
        kc_destroy(k);
    }
    kc_close(a);
}

TEST(bcecc_import_bad_args) {
    NEED_CORE();
    unsigned char in[256];
    const curve_t *c = &g_curves[0];
    ULONG n = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, c->yA, NULL);
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, in, n, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptImportKeyPair)(a, NULL, NULL, &k, in, n, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, NULL, n, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, in, 0, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptImportKeyPair)(NULL, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, in, n, 0), NS_INVALID_HANDLE);
    CHECK(k == NULL);
    /* flags outside the validation bits are rejected */
    CHECK_NS(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, in, n, 0x1), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, in, n, 0x2), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, in, n, 0x4), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, in, n, 0x40), NS_INVALID_PARAMETER);
    /* hImportKey must be NULL for ECC */
    BCRYPT_KEY_HANDLE other = kc_gen(a, 256, 1);
    CHECK_NS(U(BCryptImportKeyPair)(a, other, BCRYPT_ECCPUBLIC_BLOB, &k, in, n, 0), NS_INVALID_HANDLE);
    kc_destroy(other); kc_close(a);
}

/* ---- import: invalid key material --------------------------------------------------------------- */
CURVE_TESTS(bcecc_import_point_not_on_curve) {
    unsigned char in[512], y[80];
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0), b = kc_open(c->dh, 0);
    memcpy(y, c->yA, c->cb);
    y[c->cb - 1] ^= 1;
    ULONG n = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, y, NULL);
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    kc_destroy(k);
    n = kc_eccblob(in, c->dh_pub, c->cb, c->xA, y, NULL);
    s = kc_import(b, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    kc_destroy(k);
    /* the same point inside a private blob */
    n = kc_eccblob(in, c->dh_prv, c->cb, c->xA, y, c->dA);
    s = kc_import(b, BCRYPT_ECCPRIVATE_BLOB, in, n, 0, &k);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    kc_destroy(k);
    /* X and Y swapped is (with overwhelming probability) not on the curve either */
    n = kc_eccblob(in, c->dh_pub, c->cb, c->yA, c->xA, NULL);
    s = kc_import(b, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    kc_destroy(k);
    kc_close(a); kc_close(b);
}

CURVE_TESTS(bcecc_import_coordinate_out_of_range) {
    unsigned char in[512], big[80];
    BCRYPT_ALG_HANDLE b = kc_open(c->dh, 0);
    memset(big, 0xFF, sizeof(big));
    BCRYPT_KEY_HANDLE k = NULL;
    if (c->cb == 66) big[0] = 0x01;   /* P-521 coordinates are 521 bits: 0x01FF.. is 2^521-1 which is the field prime -> still invalid */
    ULONG n = kc_eccblob(in, c->dh_pub, c->cb, big, c->yA, NULL);
    CHECK_NS(kc_import(b, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    kc_destroy(k);
    n = kc_eccblob(in, c->dh_pub, c->cb, c->xA, big, NULL);
    CHECK_NS(kc_import(b, BCRYPT_ECCPUBLIC_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    kc_destroy(k);
    kc_close(b);
}

CURVE_TESTS(bcecc_import_private_out_of_range) {
    unsigned char in[512], big[80], zero[80] = {0};
    BCRYPT_ALG_HANDLE b = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    memset(big, 0xFF, sizeof(big));
    if (c->cb == 66) big[0] = 0x01;
    /* d >= group order */
    ULONG n = kc_eccblob(in, c->dh_prv, c->cb, NULL, NULL, big);
    NTSTATUS s = kc_import(b, BCRYPT_ECCPRIVATE_BLOB, in, n, 0, &k);
    CHECK_NS(s, 0);                      /* the scalar is not range-checked on import */
    kc_destroy(k);
    /* d = 0 with a valid public point */
    n = kc_eccblob(in, c->dh_prv, c->cb, c->xA, c->yA, zero);
    s = kc_import(b, BCRYPT_ECCPRIVATE_BLOB, in, n, 0, &k);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    kc_destroy(k);
    /* all zero private blob */
    n = kc_eccblob(in, c->dh_prv, c->cb, NULL, NULL, zero);
    CHECK_NS(kc_import(b, BCRYPT_ECCPRIVATE_BLOB, in, n, 0, &k), NS_INVALID_PARAMETER);
    kc_destroy(k);
    kc_close(b);
}

CURVE_TESTS(bcecc_import_private_mismatched_public) {
    /* d of A with the public point of B: the public/private pair is inconsistent */
    unsigned char in[512];
    BCRYPT_ALG_HANDLE b = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    ULONG n = kc_eccblob(in, c->dh_prv, c->cb, c->xB, c->yB, c->dA);
    NTSTATUS s = kc_import(b, BCRYPT_ECCPRIVATE_BLOB, in, n, 0, &k);
    CHECK_NS(s, 0);   /* Win10 does not check that Q matches d on import */
    kc_destroy(k);
    kc_close(b);
}

CURVE_TESTS(bcecc_import_no_key_validation_flag) {
    /* BCRYPT_NO_KEY_VALIDATION must not break a valid import */
    unsigned char in[512];
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    ULONG n = kc_eccblob(in, c->dsa_prv, c->cb, c->xA, c->yA, c->dA);
    NTSTATUS s = kc_import(a, BCRYPT_ECCPRIVATE_BLOB, in, n, BCRYPT_NO_KEY_VALIDATION, &k);
    CHECK_NS(s, 0);
    kc_destroy(k); k = NULL;
    unsigned char y[80];
    memcpy(y, c->yA, c->cb); y[c->cb - 1] ^= 1;
    n = kc_eccblob(in, c->dsa_pub, c->cb, c->xA, y, NULL);
    s = kc_import(a, BCRYPT_ECCPUBLIC_BLOB, in, n, BCRYPT_NO_KEY_VALIDATION, &k);
    CHECK_NS(s, 0);   /* validation skipped: the off-curve point is accepted */
    kc_destroy(k);
    kc_close(a);
}

/* ---- key handle lifetime ------------------------------------------------------------------------------ */
TEST(bcecc_destroy_key_bad_handles) {
    NEED_CORE();
    CHECK_NS(U(BCryptDestroyKey)(NULL), NS_INVALID_HANDLE);
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDSA_P256", 0);
    CHECK_NS(U(BCryptDestroyKey)((BCRYPT_KEY_HANDLE)a), NS_INVALID_HANDLE);      /* an algorithm handle is not a key */
    kc_close(a);
}

TEST(bcecc_close_alg_before_key) {
    NEED_CORE();
    const curve_t *c = &g_curves[0];
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, 256, 1);
    CHECK_NS(U(BCryptCloseAlgorithmProvider)(a, 0), 0);
    /* keys hold a reference on their algorithm object */
    unsigned char sig[128]; ULONG r = 0;
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig, sizeof(sig), &r, 0), 0);
    EXPECT_EQ(r, 64);
    CHECK_NS(U(BCryptDestroyKey)(k), 0);
}

CURVE_TESTS(bcecc_two_keys_independent) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k1 = kc_gen(a, c->bits, 1), k2 = kc_gen(a, c->bits, 1);
    unsigned char p1[512], p2[512]; ULONG n1 = 0, n2 = 0;
    CHECK_NS(kc_export(k1, BCRYPT_ECCPUBLIC_BLOB, p1, sizeof(p1), &n1), 0);
    CHECK_NS(kc_export(k2, BCRYPT_ECCPUBLIC_BLOB, p2, sizeof(p2), &n2), 0);
    EXPECT_EQ(n1, n2);
    CHECK(memcmp(p1, p2, n1) != 0);
    kc_destroy(k1); kc_destroy(k2); kc_close(a);
}

CURVE_TESTS(bcecc_public_point_not_zero) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    unsigned char p[512], zero[80] = {0}; ULONG n = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, p, sizeof(p), &n), 0);
    CHECK(memcmp(p + 8, zero, c->cb) != 0);
    CHECK(memcmp(p + 8 + c->cb, zero, c->cb) != 0);
    if (c->bits == 521) CHECK((p[8] & 0xFE) == 0);        /* a 521-bit coordinate has at most one bit in its top byte */
    kc_destroy(k); kc_close(a);
}

/* ---- generic ECDH / ECDSA with named curves ------------------------------------------------------------- */
CURVE_TESTS(bcecc_generic_named_curve) {
    BCRYPT_ALG_HANDLE g = kc_open(KC_ECDH_GENERIC, 0);
    REQUIRE_NOTNULL(g);
    NTSTATUS s = U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)c->curve, (lstrlenW(c->curve) + 1) * 2, 0);
    CHECK_NS(s, 0);
    WCHAR name[64] = {0}; ULONG r = 0;
    s = U(BCryptGetProperty)(g, KC_CURVE_NAME, (PUCHAR)name, sizeof(name), &r, 0);
    CHECK_NS(s, 0);
    EXPECT_WSTR(name, c->curve);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptGenerateKeyPair)(g, &k, 0, 0), 0);
    CHECK_NS(U(BCryptFinalizeKeyPair)(k, 0), 0);
    unsigned char buf[512]; ULONG n = 0;
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n), 0);
    EXPECT_EQ(n, 8 + 2 * c->cb);
    EXPECT_EQ(((BCRYPT_ECCKEY_BLOB *)buf)->cbKey, c->cb);
    EXPECT_EQ(((BCRYPT_ECCKEY_BLOB *)buf)->dwMagic, c->dh_pub);
    kc_destroy(k); kc_close(g);
}

CURVE_TESTS(bcecc_generic_matches_fixed_curve) {
    /* A key built on the generic algorithm agrees with the same curve's fixed algorithm. */
    BCRYPT_ALG_HANDLE g = kc_open(KC_ECDH_GENERIC, 0), f = kc_open(c->dh, 0);
    if (!g) { CHECKF(0, "generic ECDH not available"); kc_close(f); return; }
    CHECK_NS(U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)c->curve, (lstrlenW(c->curve) + 1) * 2, 0), 0);
    BCRYPT_KEY_HANDLE kg = kc_gen(g, 0, 1), kf = kc_key(f, c, 1, 1, 1);
    BCRYPT_KEY_HANDLE pubf = kc_key(f, c, 1, 1, 0);
    unsigned char buf[512]; ULONG n = 0;
    BCRYPT_KEY_HANDLE kgpub = NULL;
    if (kg && NT_OK(kc_export(kg, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n))) {
        CHECK_NS(kc_import(f, BCRYPT_ECCPUBLIC_BLOB, buf, n, 0, &kgpub), 0);
        NTSTATUS s1, s2;
        BCRYPT_SECRET_HANDLE x = kc_agree(kf, kgpub, &s1);
        BCRYPT_SECRET_HANDLE y = kc_agree(kg, pubf, &s2);
        CHECK_NS(s1, 0); CHECK_NS(s2, 0);
        if (x) U(BCryptDestroySecret)(x);
        if (y) U(BCryptDestroySecret)(y);
    }
    kc_destroy(kgpub); kc_destroy(kg); kc_destroy(kf); kc_destroy(pubf); kc_close(g); kc_close(f);
}

TEST(bcecc_generic_curve_name_errors) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE g = kc_open(KC_ECDH_GENERIC, 0);
    if (!g) { CHECKF(0, "generic ECDH not available"); return; }
    NTSTATUS s;
    s = U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)L"nistP999", 18, 0);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    /* the name must be NUL terminated inside the buffer */
    s = U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)L"nistP256", 16, 0);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    s = U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)L"nistP256", 0, 0);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    s = U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)L"nistP256", 18, 0);
    CHECK_NS(s, 0);
    /* generating with a mismatching explicit length is rejected, 0 or the curve size is accepted */
    BCRYPT_KEY_HANDLE k = NULL;
    s = U(BCryptGenerateKeyPair)(g, &k, 384, 0);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    kc_destroy(k); k = NULL;
    s = U(BCryptGenerateKeyPair)(g, &k, 256, 0);
    CHECK_NS(s, 0);
    kc_destroy(k);
    kc_close(g);
}

TEST(bcecc_generic_without_curve) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE g = kc_open(KC_ECDH_GENERIC, 0);
    if (!g) { CHECKF(0, "generic ECDH not available"); return; }
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = U(BCryptGenerateKeyPair)(g, &k, 0, 0);
    CHECK_NS(s, 0);   /* the key object is created without a curve ... */
    REQUIRE_NOTNULL(k);
    s = U(BCryptFinalizeKeyPair)(k, 0);
    CHECK_NS(s, NS_INVALID_PARAMETER);   /* ... but cannot be finalized */
    kc_destroy(k);
    kc_close(g);
}

TEST(bcecc_generic_supported_curves) {
    NEED_CORE();
    static const WCHAR *const names[] = { L"nistP256", L"nistP384", L"nistP521", L"curve25519", L"brainpoolP160r1", L"brainpoolP192r1",
        L"brainpoolP224r1", L"brainpoolP256r1", L"brainpoolP320r1", L"brainpoolP384r1", L"brainpoolP512r1", L"secP256k1", L"brainpoolP256t1", L"nistP192" };
    /* coordinate size in bytes of each curve */
    static const ULONG sizes[] = { 32, 48, 66, 32, 20, 24, 28, 32, 40, 48, 64, 32, 32, 24 };
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        /* the curve name can be set once per algorithm handle, so every curve gets its own handle */
        BCRYPT_ALG_HANDLE g = kc_open(KC_ECDH_GENERIC, 0);
        if (!g) { CHECKF(0, "generic ECDH not available"); return; }
        NTSTATUS s = U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)names[i], (lstrlenW(names[i]) + 1) * 2, 0);
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS g2 = !NT_OK(s) ? s : U(BCryptGenerateKeyPair)(g, &k, 0, 0);
        NTSTATUS f2 = NT_OK(g2) ? U(BCryptFinalizeKeyPair)(k, 0) : g2;
        unsigned char buf[600]; ULONG n = 0; NTSTATUS e = NT_OK(f2) ? kc_export(k, BCRYPT_ECCPUBLIC_BLOB, buf, sizeof(buf), &n) : f2;
        t_label("curve %ls", names[i]);
        CHECK_NS(s, 0); CHECK_NS(g2, 0); CHECK_NS(f2, 0); CHECK_NS(e, 0);
        EXPECT_EQ(n, 8 + 2 * sizes[i]);
        kc_destroy(k);
        kc_close(g);
    }
}

TEST(bcecc_generic_curve_agreement_all) {
    NEED_CORE();
    static const WCHAR *const names[] = { L"nistP256", L"nistP384", L"nistP521", L"curve25519", L"brainpoolP256r1", L"brainpoolP384r1", L"brainpoolP512r1", L"secP256k1" };
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        BCRYPT_ALG_HANDLE g = kc_open(KC_ECDH_GENERIC, 0);
        if (!g) { CHECKF(0, "generic ECDH not available"); return; }
        NTSTATUS s = U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)names[i], (lstrlenW(names[i]) + 1) * 2, 0);
        t_label("curve %ls", names[i]);
        CHECK_NS(s, 0);
        if (!NT_OK(s)) { kc_close(g); continue; }
        BCRYPT_KEY_HANDLE a = kc_gen(g, 0, 1), b = kc_gen(g, 0, 1);
        CHECKF(a && b, "keygen on %ls", names[i]);
        NTSTATUS s1 = 1, s2 = 1;
        BCRYPT_SECRET_HANDLE x = a && b ? kc_agree(a, b, &s1) : NULL, y = a && b ? kc_agree(b, a, &s2) : NULL;
        CHECKF(x && y, "agree on %ls: 0x%08lx 0x%08lx", names[i], (unsigned long)s1, (unsigned long)s2);
        if (x && y) {
            unsigned char r1[80] = {0}, r2[80] = {0}; ULONG n1 = 0, n2 = 0;
            NTSTATUS d1 = kc_derive(x, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof(r1), &n1, 0);
            NTSTATUS d2 = kc_derive(y, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof(r2), &n2, 0);
            CHECK_NS(d1, 0); CHECK_NS(d2, 0);
            EXPECT_EQ(n1, n2);
            CHECK_MEM(r1, r2, n1);
            CHECK(n1 >= 20 && n1 <= 66);
        }
        if (x) U(BCryptDestroySecret)(x);
        if (y) U(BCryptDestroySecret)(y);
        kc_destroy(a); kc_destroy(b); kc_close(g);
    }
}

TEST(bcecc_curve25519_rfc7748) {
    NEED_CORE();
    /* RFC 7748 section 6.1 vector. Win10 imports only a clamped (little-endian) scalar for curve25519. */
    static const unsigned char alice_d[32] = { 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a };
    static const unsigned char bob_pub[32] = { 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f };
    static const unsigned char shared[32] = { 0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42 };
    BCRYPT_ALG_HANDLE g = kc_open(KC_ECDH_GENERIC, 0);
    if (!g) { CHECKF(0, "generic ECDH not available"); return; }
    CHECK_NS(U(BCryptSetProperty)(g, KC_CURVE_NAME, (PUCHAR)L"curve25519", 22, 0), 0);
    unsigned char blob[8 + 32 * 3];
    static const unsigned char alice_pub[32] = { 0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a };
    unsigned char dc[32];
    memcpy(dc, alice_d, 32); dc[0] &= 248; dc[31] &= 127; dc[31] |= 64;     /* Win10 only imports a clamped scalar */
    BCRYPT_KEY_HANDLE kp = NULL, kq = NULL, kr = NULL;
    ULONG n = kc_eccblob(blob, BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC, 32, NULL, NULL, alice_d);
    CHECK_NS(kc_import(g, BCRYPT_ECCPRIVATE_BLOB, blob, n, 0, &kr), NS_INVALID_PARAMETER);   /* the RFC scalar is not clamped */
    kc_destroy(kr);
    n = kc_eccblob(blob, BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC, 32, alice_pub, NULL, dc);
    CHECK_NS(kc_import(g, BCRYPT_ECCPRIVATE_BLOB, blob, n, 0, &kp), 0);
    n = kc_eccblob(blob, BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, 32, bob_pub, NULL, NULL);
    CHECK_NS(kc_import(g, BCRYPT_ECCPUBLIC_BLOB, blob, n, 0, &kq), 0);
    if (kp && kq) {
        NTSTATUS as; BCRYPT_SECRET_HANDLE sec = kc_agree(kp, kq, &as);
        CHECK_NS(as, 0);
        if (sec) {
            unsigned char out[32]; ULONG r = 0;
            CHECK_NS(kc_derive(sec, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, &r, 0), 0);
            EXPECT_EQ(r, 32);
            unsigned char rv[32]; for (int i = 0; i < 32; i++) rv[i] = shared[31 - i];
            CHECK_MEM(out, rv, 32);                          /* the raw secret is the RFC value byte-reversed */
            U(BCryptDestroySecret)(sec);
        }
    }
    kc_destroy(kp); kc_destroy(kq); kc_close(g);
}

/* ---- properties of ECC algorithm and key objects ------------------------------------------------------ */
CURVE_TESTS(bcecc_prop_signature_length) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    DWORD v = 0; ULONG r = 0;
    NTSTATUS s = U(BCryptGetProperty)(k, BCRYPT_SIGNATURE_LENGTH, (PUCHAR)&v, 4, &r, 0);
    CHECK_NS(s, 0);
    if (NT_OK(s)) { EXPECT_EQ(r, 4); EXPECT_EQ(v, 2 * c->cb); }
    /* size protocol of a fixed-size property */
    r = 0;
    CHECK_NS(U(BCryptGetProperty)(k, BCRYPT_SIGNATURE_LENGTH, NULL, 0, &r, 0), 0);
    EXPECT_EQ(r, 4);
    r = 0;
    CHECK_NS(U(BCryptGetProperty)(k, BCRYPT_SIGNATURE_LENGTH, (PUCHAR)&v, 3, &r, 0), NS_BUFFER_TOO_SMALL);
    EXPECT_EQ(r, 4);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_prop_key_strength_and_length) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    DWORD v = 0; ULONG r = 0;
    CHECK_NS(U(BCryptGetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, &r, 0), 0);
    EXPECT_EQ(v, c->bits);
    v = 0;
    CHECK_NS(U(BCryptGetProperty)(k, BCRYPT_KEY_STRENGTH, (PUCHAR)&v, 4, &r, 0), 0);
    EXPECT_EQ(v, c->bits);
    kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcecc_prop_alg_keylengths) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_LENGTHS_STRUCT kl; ULONG r = 0;
    memset(&kl, 0xEE, sizeof(kl));
    NTSTATUS s = U(BCryptGetProperty)(a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof(kl), &r, 0);
    CHECK_NS(s, 0);
    if (NT_OK(s)) { EXPECT_EQ(r, sizeof(kl)); EXPECT_EQ(kl.dwMinLength, c->bits); EXPECT_EQ(kl.dwMaxLength, c->bits); EXPECT_EQ(kl.dwIncrement, 0); }
    kc_close(a);
}

CURVE_TESTS(bcecc_prop_alg_curvename_note) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    WCHAR name[64] = {0}; ULONG r = 0;
    NTSTATUS s = U(BCryptGetProperty)(a, KC_CURVE_NAME, (PUCHAR)name, sizeof(name), &r, 0);
    CHECK_NS(s, 0); EXPECT_WSTR(name, c->curve);
    memset(name, 0, sizeof(name));
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    s = U(BCryptGetProperty)(k, KC_CURVE_NAME, (PUCHAR)name, sizeof(name), &r, 0);
    CHECK_NS(s, 0); EXPECT_WSTR(name, c->curve);
    kc_destroy(k); kc_close(a);
}

TEST(bcecc_prop_unknown_property) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE a = kc_open(L"ECDSA_P256", 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, 256, 1);
    DWORD v; ULONG r = 0;
    CHECK_NS(U(BCryptGetProperty)(k, L"NoSuchProperty", (PUCHAR)&v, 4, &r, 0), NS_NOT_SUPPORTED);
    CHECK_NS(U(BCryptGetProperty)(a, L"NoSuchProperty", (PUCHAR)&v, 4, &r, 0), NS_NOT_SUPPORTED);
    CHECK_NS(U(BCryptGetProperty)(k, NULL, (PUCHAR)&v, 4, &r, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptGetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, NULL, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptGetProperty)(NULL, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, &r, 0), NS_INVALID_HANDLE);
    kc_destroy(k); kc_close(a);
}

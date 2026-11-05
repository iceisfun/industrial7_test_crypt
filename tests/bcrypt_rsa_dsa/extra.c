/* Additional BCrypt RSA/DSA coverage: BCryptDuplicateKey, constants, determinism, hash/padding matrix. */
#include "rd.h"

static BCRYPT_ALG_HANDLE g_a;
#define BEGIN() NEED_BCRYPT(); g_a = rd_alg(BCRYPT_RSA_ALGORITHM); if (!g_a) { t_skip("no RSA provider"); return; }
#define END() rd_closealg(g_a); g_a = NULL

TEST(rsa_extra_magic_constants) {
    EXPECT_EQ(BCRYPT_RSAPUBLIC_MAGIC, 0x31415352);
    EXPECT_EQ(BCRYPT_RSAPRIVATE_MAGIC, 0x32415352);
    EXPECT_EQ(BCRYPT_RSAFULLPRIVATE_MAGIC, 0x33415352);
    EXPECT_EQ(BCRYPT_DSA_PUBLIC_MAGIC, 0x42505344);
    EXPECT_EQ(BCRYPT_DSA_PRIVATE_MAGIC, 0x56505344);
    EXPECT_EQ(BCRYPT_DSA_PUBLIC_MAGIC_V2, 0x32425044);
    EXPECT_EQ(BCRYPT_DSA_PRIVATE_MAGIC_V2, 0x32565044);
    EXPECT_EQ(sizeof(BCRYPT_RSAKEY_BLOB), 24);
    EXPECT_EQ(sizeof(BCRYPT_DSA_KEY_BLOB), 52);
    EXPECT_EQ(sizeof(BCRYPT_DSA_KEY_BLOB_V2), 28);
}
TEST(rsa_extra_fixed_key_public_header) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_fixed_rsa(g_a, BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    if (k) {
        UCHAR *b; ULONG l;
        EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &b, &l), ST_SUCCESS);
        if (b) {
            const BCRYPT_RSAKEY_BLOB *h = (const BCRYPT_RSAKEY_BLOB *)b;
            EXPECT_EQ(h->Magic, BCRYPT_RSAPUBLIC_MAGIC);
            EXPECT_EQ(h->BitLength, 1024);
            EXPECT_EQ(h->cbPublicExp, sizeof kRsaE);
            EXPECT_EQ(h->cbModulus, 128);
            CHECK(!memcmp(b + 24, kRsaE, sizeof kRsaE));
            CHECK(!memcmp(b + 24 + sizeof kRsaE, kRsaN, 128));
            free(b);
        }
        rd_destroy(k);
    }
    END();
}
TEST(rsa_extra_pkcs1_sign_deterministic) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_fixed_rsa(g_a, BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    if (k) {
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        UCHAR a[128], b[128]; ULONG n = 0;
        for (int i = 0; i < 3; i++) {
            EXPECT_EQ(U(BCryptSignHash)(k, &pi, (PUCHAR)kHash_sha256, 32, i == 1 ? b : a, 128, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
        }
        CHECK(!memcmp(a, b, 128));
        rd_destroy(k);
    }
    END();
}
TEST(rsa_extra_duplicate_key) {
    BEGIN();
    if (!U(BCryptDuplicateKey)) { t_skip("no BCryptDuplicateKey"); END(); return; }
    BCRYPT_KEY_HANDLE k = rd_fixed_rsa(g_a, BCRYPT_RSAPRIVATE_MAGIC), d = NULL; CHECK(k);
    if (k) {
        NTSTATUS s = U(BCryptDuplicateKey)(k, &d, NULL, 0, 0);
        t_note("BCryptDuplicateKey(RSA) = 0x%lx", (unsigned long)s);
        if (s == 0 && d) {
            CHECK(d != k);
            rd_destroy(k); k = NULL;
            BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
            UCHAR sig[128]; ULONG n = 0;
            EXPECT_EQ(U(BCryptSignHash)(d, &pi, (PUCHAR)kHash_sha256, 32, sig, 128, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
            CHECK(!memcmp(sig, kSigPkcs1_sha256, 128));
            rd_destroy(d);
        } else if (s != 0) {
            t_note("duplicate not supported for asymmetric keys on this build");
        }
        rd_destroy(k);
    }
    END();
}
TEST(rsa_extra_duplicate_key_invalid_handles) {
    BEGIN();
    if (!U(BCryptDuplicateKey)) { t_skip("no BCryptDuplicateKey"); END(); return; }
    BCRYPT_KEY_HANDLE d = NULL;
    EXPECT_EQ(U(BCryptDuplicateKey)(NULL, &d, NULL, 0, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(U(BCryptDuplicateKey)((BCRYPT_KEY_HANDLE)g_a, &d, NULL, 0, 0), ST_INVALID_HANDLE);
    END();
}
TEST(rsa_extra_pss_all_hashes_roundtrip) {
    BEGIN();
    BCRYPT_KEY_HANDLE prv = rd_fixed_rsa(g_a, BCRYPT_RSAPRIVATE_MAGIC), pub = rd_fixed_rsa(g_a, BCRYPT_RSAPUBLIC_MAGIC);
    CHECK(prv && pub);
    struct { LPCWSTR alg; const UCHAR *h; ULONG hl; } t[] = {
        { BCRYPT_SHA1_ALGORITHM, kHash_sha1, 20 }, { BCRYPT_SHA256_ALGORITHM, kHash_sha256, 32 },
        { BCRYPT_SHA384_ALGORITHM, kHash_sha384, 48 }, { BCRYPT_SHA512_ALGORITHM, kHash_sha512, 64 } };
    for (int i = 0; prv && pub && i < 4; i++) {
        /* 1024-bit key: emLen 128, so the salt is at most 128 - hLen - 2 (SHA-512 cannot use a 64-byte salt: 0xc000000d) */
        ULONG salt = t[i].hl <= 48 ? t[i].hl : 128 - t[i].hl - 2;
        BCRYPT_PSS_PADDING_INFO p = { t[i].alg, salt };
        UCHAR sig[128]; ULONG n = 0;
        NTSTATUS s = U(BCryptSignHash)(prv, &p, (PUCHAR)t[i].h, t[i].hl, sig, 128, &n, BCRYPT_PAD_PSS);
        CHECKF(s == 0, "%ls PSS sign 0x%lx", t[i].alg, (unsigned long)s);
        if (s) continue;
        EXPECT_EQ(U(BCryptVerifySignature)(pub, &p, (PUCHAR)t[i].h, t[i].hl, sig, 128, BCRYPT_PAD_PSS), ST_SUCCESS);
        /* a PSS signature is not a valid PKCS#1 signature */
        BCRYPT_PKCS1_PADDING_INFO pk = { t[i].alg };
        CHECK(U(BCryptVerifySignature)(pub, &pk, (PUCHAR)t[i].h, t[i].hl, sig, 128, BCRYPT_PAD_PKCS1) != 0);
    }
    rd_destroy(prv); rd_destroy(pub); END();
}
TEST(rsa_extra_key_survives_alg_close_sign) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_fixed_rsa(g_a, BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    rd_closealg(g_a); g_a = NULL;
    if (k) {
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        UCHAR sig[128]; ULONG n = 0;
        NTSTATUS s = U(BCryptSignHash)(k, &pi, (PUCHAR)kHash_sha256, 32, sig, 128, &n, BCRYPT_PAD_PKCS1);
        t_note("sign after algorithm handle closed: 0x%lx", (unsigned long)s);
        if (s == 0) CHECK(!memcmp(sig, kSigPkcs1_sha256, 128));
        rd_destroy(k);
    }
}
TEST(rsa_extra_rsa_sign_alg_encrypt) {
    BEGIN();
    BCRYPT_ALG_HANDLE as = rd_alg(BCRYPT_RSA_SIGN_ALGORITHM);
    BCRYPT_KEY_HANDLE k = as ? rd_fixed_rsa(as, BCRYPT_RSAPUBLIC_MAGIC) : NULL;
    if (k) {
        UCHAR out[128]; ULONG n = 0;
        NTSTATUS s = U(BCryptEncrypt)(k, (PUCHAR)kPlain, sizeof kPlain, NULL, NULL, 0, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
        t_note("encrypt with RSA_SIGN-provider key: 0x%lx", (unsigned long)s);
        rd_destroy(k);
    }
    rd_closealg(as); END();
}
TEST(rsa_extra_sign_concurrent_threads) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_fixed_rsa(g_a, BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    if (k) {
        struct ctx { BCRYPT_KEY_HANDLE k; NTSTATUS s; UCHAR sig[128]; } c[4];
        HANDLE th[4];
        DWORD WINAPI w(LPVOID p) {
            struct ctx *x = p; BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM }; ULONG n = 0;
            x->s = U(BCryptSignHash)(x->k, &pi, (PUCHAR)kHash_sha1, 20, x->sig, 128, &n, BCRYPT_PAD_PKCS1);
            return 0;
        }
        for (int i = 0; i < 4; i++) { c[i].k = k; c[i].s = 1; th[i] = CreateThread(NULL, 0, w, &c[i], 0, NULL); CHECK(th[i] != NULL); }
        for (int i = 0; i < 4; i++) if (th[i]) { CHECK(WaitForSingleObject(th[i], 15000) == WAIT_OBJECT_0); CloseHandle(th[i]); }
        for (int i = 0; i < 4; i++) { EXPECT_EQ(c[i].s, ST_SUCCESS); CHECK(!memcmp(c[i].sig, kSigPkcs1_sha1, 128)); }
        rd_destroy(k);
    }
    END();
}
TEST(rsa_extra_import_wrong_blob_for_alg_type) {
    BEGIN();
    /* a DSA blob type name given to the RSA provider */
    UCHAR b[RD_RSA_BLOB_MAX]; ULONG n = rd_rsa_blob(b, BCRYPT_RSAPUBLIC_MAGIC, 0); BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k);
    CHECK(s != 0); t_note("RSA provider, DSAPUBLICBLOB type: 0x%lx", (unsigned long)s);
    if (!s) rd_destroy(k);
    s = rd_import(g_a, L"NoSuchBlobTypeXyz", b, n, &k);
    CHECK(s != 0); t_note("RSA provider, unknown blob type: 0x%lx", (unsigned long)s);
    if (!s) rd_destroy(k);
    END();
}
TEST(dsa_extra_duplicate_key) {
    NEED_BCRYPT();
    if (!U(BCryptDuplicateKey)) { t_skip("no BCryptDuplicateKey"); return; }
    g_a = rd_alg(BCRYPT_DSA_ALGORITHM); if (!g_a) { t_skip("no DSA"); return; }
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 1); BCRYPT_KEY_HANDLE k = NULL, d = NULL;
    if (rd_import(g_a, BCRYPT_DSA_PRIVATE_BLOB, b, n, &k) == 0) {
        NTSTATUS s = U(BCryptDuplicateKey)(k, &d, NULL, 0, 0);
        t_note("BCryptDuplicateKey(DSA) = 0x%lx", (unsigned long)s);
        if (s == 0 && d) {
            UCHAR sig[40]; ULONG m = 0;
            EXPECT_EQ(U(BCryptSignHash)(d, NULL, (PUCHAR)kHash_sha1, 20, sig, 40, &m, 0), ST_SUCCESS);
            EXPECT_EQ(U(BCryptVerifySignature)(k, NULL, (PUCHAR)kHash_sha1, 20, sig, 40, 0), ST_SUCCESS);
            rd_destroy(d);
        }
        rd_destroy(k);
    }
    END();
}
TEST(dsa_extra_verify_known_answer_hash_mismatch) {
    NEED_BCRYPT();
    g_a = rd_alg(BCRYPT_DSA_ALGORITHM); if (!g_a) { t_skip("no DSA"); return; }
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 0); BCRYPT_KEY_HANDLE k = NULL;
    if (rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k) == 0) {
        NTSTATUS s = U(BCryptVerifySignature)(k, NULL, (PUCHAR)kHash_sha256, 32, (PUCHAR)kDsa1_Sig, 40, 0);
        CHECK(s != 0); t_note("1024/160 key verifying a 32-byte hash: 0x%lx", (unsigned long)s);
        rd_destroy(k);
    }
    END();
}

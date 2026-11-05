/* BCrypt DSA: generation, v1/v2 blobs, raw r||s signatures. */
#include "rd.h"

static BCRYPT_ALG_HANDLE g_a;
#define BEGIN() NEED_BCRYPT(); g_a = rd_alg(BCRYPT_DSA_ALGORITHM); if (!g_a) { t_skip("no DSA provider"); return; }
#define END() rd_closealg(g_a); g_a = NULL

#define SIGFAIL(e) do { NTSTATUS sf_ = (e); CHECKF(sf_ == (NTSTATUS)ST_INVALID_SIGNATURE || sf_ == (NTSTATUS)ST_INVALID_PARAMETER, "bad signature gave 0x%lx", (unsigned long)sf_); } while (0)
static BCRYPT_KEY_HANDLE fx1(int priv) {
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, priv); BCRYPT_KEY_HANDLE k;
    return rd_import(g_a, priv ? BCRYPT_DSA_PRIVATE_BLOB : BCRYPT_DSA_PUBLIC_BLOB, b, n, &k) == 0 ? k : NULL;
}
static BCRYPT_KEY_HANDLE fx2(int priv) {
    UCHAR b[2048]; ULONG n = rd_dsa2_blob(b, priv, DSA_HASH_ALGORITHM_SHA256); BCRYPT_KEY_HANDLE k;
    return rd_import(g_a, priv ? BCRYPT_DSA_PRIVATE_BLOB : BCRYPT_DSA_PUBLIC_BLOB, b, n, &k) == 0 ? k : NULL;
}
static NTSTATUS sign(BCRYPT_KEY_HANDLE k, const UCHAR *h, ULONG hl, UCHAR *out, ULONG cb, ULONG *n, ULONG fl) {
    return U(BCryptSignHash)(k, NULL, (PUCHAR)h, hl, out, cb, n, fl);
}
static NTSTATUS verify(BCRYPT_KEY_HANDLE k, const UCHAR *h, ULONG hl, const UCHAR *s, ULONG sl, ULONG fl) {
    return U(BCryptVerifySignature)(k, NULL, (PUCHAR)h, hl, (PUCHAR)s, sl, fl);
}

/* ---------- provider ---------- */
TEST(dsa_provider_key_lengths) {
    BEGIN();
    BCRYPT_KEY_LENGTHS_STRUCT kl = {0}; ULONG n = 0;
    EXPECT_EQ(U(BCryptGetProperty)(g_a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof kl, &n, 0), ST_SUCCESS);
    EXPECT_EQ(kl.dwMinLength, 512);
    EXPECT_EQ(kl.dwMaxLength, 3072);
    t_note("DSA KeyLengths min=%lu max=%lu inc=%lu", kl.dwMinLength, kl.dwMaxLength, kl.dwIncrement);
    END();
}
TEST(dsa_provider_gen_wrong_alg_types) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(NULL, &k, 512, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(U(BCryptGenerateKeyPair)(g_a, NULL, 512, 0), ST_INVALID_PARAMETER);
    BCRYPT_ALG_HANDLE h = rd_alg(BCRYPT_SHA1_ALGORITHM);
    if (h) { EXPECT_EQ(U(BCryptGenerateKeyPair)(h, &k, 512, 0), ST_NOT_SUPPORTED); rd_closealg(h); }
    END();
}

/* ---------- generation ---------- */
TEST(dsa_gen_valid_512_1024) {
    BEGIN();
    static const ULONG sizes[] = { 512, 576, 768, 1024 };
    for (int i = 0; i < 4; i++) {
        BCRYPT_KEY_HANDLE k = rd_gen(g_a, sizes[i]);
        CHECKF(k != NULL, "DSA %lu failed", sizes[i]);
        if (!k) continue;
        NTSTATUS ps;
        EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), sizes[i]); EXPECT_EQ(ps, 0);
        EXPECT_EQ(rd_getdw(k, BCRYPT_SIGNATURE_LENGTH, &ps), 40); EXPECT_EQ(ps, 0);
        rd_destroy(k);
    }
    END();
}
TEST(dsa_gen_2048_fips186_3) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 2048);
    CHECK(k != NULL);
    if (k) {
        NTSTATUS ps;
        EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 2048);
        ULONG sl = rd_getdw(k, BCRYPT_SIGNATURE_LENGTH, &ps);
        t_note("DSA-2048 signature length %lu", sl);
        CHECK(sl == 64);
        UCHAR *b; ULONG l;
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PUBLIC_BLOB, &b, &l), ST_SUCCESS);
        if (b) {
            const BCRYPT_DSA_KEY_BLOB_V2 *h = (const BCRYPT_DSA_KEY_BLOB_V2 *)b;
            EXPECT_EQ(h->dwMagic, BCRYPT_DSA_PUBLIC_MAGIC_V2);
            EXPECT_EQ(h->cbKey, 256);
            EXPECT_EQ(h->cbGroupSize, 32);
            EXPECT_EQ(h->standardVersion, DSA_FIPS186_3);
            EXPECT_EQ(l, sizeof *h + h->cbSeedLength + h->cbGroupSize + 3 * 256);
            t_note("v2 hash alg=%lu seed len=%lu", (unsigned long)h->hashAlgorithm, h->cbSeedLength);
            free(b);
        }
        rd_destroy(k);
    }
    END();
}
TEST(dsa_gen_invalid_lengths_fail) {
    BEGIN();
    /* 0 selects the default length and 1088/1536 are valid (increment 64): see dsa_gen_default_and_valid_odd_lengths */
    static const ULONG bad[] = { 1, 256, 448, 511, 513, 3073, 4096 };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS sg = U(BCryptGenerateKeyPair)(g_a, &k, bad[i], 0), sf = 0;
        if (sg == 0) sf = U(BCryptFinalizeKeyPair)(k, 0);
        EXPECT_EQ(sg, ST_INVALID_PARAMETER);
        t_note("DSA bits=%lu gen=0x%lx fin=0x%lx", bad[i], (unsigned long)sg, (unsigned long)sf);
        if (sg == 0) rd_destroy(k);
    }
    END();
}
TEST(dsa_gen_default_and_valid_odd_lengths) {
    BEGIN();
    static const ULONG ok[] = { 0, 1088, 1536 };
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        EXPECT_EQ(U(BCryptGenerateKeyPair)(g_a, &k, ok[i], 0), ST_SUCCESS);
        if (k) {
            EXPECT_EQ(U(BCryptFinalizeKeyPair)(k, 0), ST_SUCCESS);
            NTSTATUS ps; ULONG kl = rd_getdw(k, BCRYPT_KEY_LENGTH, &ps);
            t_note("DSA gen %lu -> KeyLength %lu (st 0x%lx) sig %lu", ok[i], kl, (unsigned long)ps, rd_getdw(k, BCRYPT_SIGNATURE_LENGTH, &ps));
            rd_destroy(k);
        }
    }
    END();
}
TEST(dsa_gen_unfinalized_unusable) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(g_a, &k, 512, 0), ST_SUCCESS); CHECK(k);
    if (k) {
        UCHAR sig[64], h[20] = {1}; ULONG n = 0;
        /* BCryptSignHash on an unfinalized DSA key dereferences a null key body inside the provider on Win10 (access
           violation), so it is deliberately not called here; export reports STATUS_UNSUCCESSFUL. */
        (void)sig; (void)h; (void)n;
        UCHAR *b = NULL; ULONG l = 0;
        NTSTATUS s = rd_export(k, BCRYPT_DSA_PUBLIC_BLOB, &b, &l);
        EXPECT_EQ(s, 0xC0000001); if (!s) free(b);
        rd_destroy(k);
    }
    END();
}
TEST(dsa_gen_two_keys_differ) {
    BEGIN();
    BCRYPT_KEY_HANDLE a = rd_gen(g_a, 512), b = rd_gen(g_a, 512); CHECK(a && b);
    UCHAR *x = NULL, *y = NULL; ULONG lx = 0, ly = 0;
    if (a && b) {
        rd_export(a, BCRYPT_DSA_PUBLIC_BLOB, &x, &lx); rd_export(b, BCRYPT_DSA_PUBLIC_BLOB, &y, &ly);
        CHECK(lx == ly && x && y && memcmp(x, y, lx) != 0);
    }
    free(x); free(y); rd_destroy(a); rd_destroy(b); END();
}

/* ---------- blob layout of generated keys ---------- */
TEST(dsa_export_public_v1_layout) {
    BEGIN();
    static const ULONG sizes[] = { 512, 1024 };
    for (int i = 0; i < 2; i++) {
        BCRYPT_KEY_HANDLE k = rd_gen(g_a, sizes[i]); CHECK(k); if (!k) continue;
        UCHAR *b; ULONG l; ULONG cb = sizes[i] / 8;
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PUBLIC_BLOB, &b, &l), ST_SUCCESS);
        if (b) {
            const BCRYPT_DSA_KEY_BLOB *h = (const BCRYPT_DSA_KEY_BLOB *)b;
            EXPECT_EQ(sizeof *h, 52);
            EXPECT_EQ(h->dwMagic, BCRYPT_DSA_PUBLIC_MAGIC);
            EXPECT_EQ(h->cbKey, cb);
            EXPECT_EQ(l, sizeof *h + 3 * cb);
            CHECK(rd_nonzero(h->q, 20) && (h->q[0] & 0x80));   /* 160-bit subprime, top bit set */
            CHECK(b[sizeof *h] & 0x80);                       /* P: full-length prime, big-endian */
            free(b);
        }
        rd_destroy(k);
    }
    END();
}
TEST(dsa_export_private_v1_layout) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 512); CHECK(k); if (!k) { END(); return; }
    UCHAR *b; ULONG l;
    EXPECT_EQ(rd_export(k, BCRYPT_DSA_PRIVATE_BLOB, &b, &l), ST_SUCCESS);
    if (b) {
        const BCRYPT_DSA_KEY_BLOB *h = (const BCRYPT_DSA_KEY_BLOB *)b;
        EXPECT_EQ(h->dwMagic, BCRYPT_DSA_PRIVATE_MAGIC);
        EXPECT_EQ(h->cbKey, 64);
        EXPECT_EQ(l, sizeof *h + 3 * 64 + 20);
        CHECK(rd_nonzero(b + l - 20, 20));
        free(b);
    }
    k = k;
    rd_destroy(k); END();
}
TEST(dsa_export_generic_blob_types) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 512); CHECK(k); if (!k) { END(); return; }
    UCHAR *b1, *b2; ULONG l1 = 0, l2 = 0;
    NTSTATUS s = rd_export(k, BCRYPT_PUBLIC_KEY_BLOB, &b1, &l1);
    EXPECT_EQ(s, ST_SUCCESS);
    if (!s) {
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PUBLIC_BLOB, &b2, &l2), ST_SUCCESS);
        CHECK(l1 == l2 && !memcmp(b1, b2, l1)); free(b1); free(b2);
    }
    s = rd_export(k, BCRYPT_PRIVATE_KEY_BLOB, &b1, &l1);
    EXPECT_EQ(s, ST_SUCCESS);
    if (!s) {
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PRIVATE_BLOB, &b2, &l2), ST_SUCCESS);
        CHECK(l1 == l2); free(b1); free(b2);
    }
    rd_destroy(k); END();
}
TEST(dsa_export_size_protocol) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 512); CHECK(k); if (!k) { END(); return; }
    LPCWSTR types[] = { BCRYPT_DSA_PUBLIC_BLOB, BCRYPT_DSA_PRIVATE_BLOB };
    for (int i = 0; i < 2; i++) {
        ULONG need = 0, n = 0; UCHAR buf[1024];
        EXPECT_EQ(U(BCryptExportKey)(k, NULL, types[i], NULL, 0, &need, 0), ST_SUCCESS);
        CHECK(need > 0 && need < sizeof buf); if (!need || need >= sizeof buf) continue;
        EXPECT_EQ(U(BCryptExportKey)(k, NULL, types[i], buf, need - 1, &n, 0), ST_BUFFER_TOO_SMALL);
        EXPECT_EQ(n, need);
        n = 0;
        EXPECT_EQ(U(BCryptExportKey)(k, NULL, types[i], buf, need, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, need);
    }
    rd_destroy(k); END();
}
TEST(dsa_export_rsa_blob_type_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 512); CHECK(k); if (!k) { END(); return; }
    UCHAR buf[1024]; ULONG n = 0;
    NTSTATUS s = U(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, buf, sizeof buf, &n, 0);
    CHECK(s != 0); t_note("RSA blob type from DSA key: 0x%lx", (unsigned long)s);
    rd_destroy(k); END();
}

/* ---------- import: fixed v1 key ---------- */
TEST(dsa_import_v1_public) {
    BEGIN();
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 0); BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k), ST_SUCCESS); CHECK(k);
    if (k) {
        NTSTATUS ps;
        EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 1024);
        UCHAR *o; ULONG ol;
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PUBLIC_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == n);
        if (o && ol == n) {
            CHECK(!memcmp(o, b, 8));                         /* magic, cbKey */
            CHECK(!memcmp(o + 32, b + 32, 20));              /* q */
            CHECK(!memcmp(o + 52, b + 52, 3 * 128));         /* P, G, Y */
            if (memcmp(o, b, n)) t_note("public export differs from input in Count/Seed");
        }
        free(o);
        rd_destroy(k);
    }
    END();
}
TEST(dsa_import_v1_public_as_generic_type) {
    BEGIN();
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 0); BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(g_a, BCRYPT_PUBLIC_KEY_BLOB, b, n, &k), ST_SUCCESS);
    rd_destroy(k); END();
}
TEST(dsa_import_v1_private_exports) {
    BEGIN();
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 1); BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(g_a, BCRYPT_DSA_PRIVATE_BLOB, b, n, &k), ST_SUCCESS); CHECK(k);
    if (k) {
        UCHAR *o; ULONG ol;
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PRIVATE_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == 52 + 3 * 128 + 20);
        if (o && ol == 52 + 3 * 128 + 20) CHECK(!memcmp(o + 52, b + 52, 3 * 128) && !memcmp(o + ol - 20, kDsa1_X, 20));
        free(o);
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PUBLIC_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == 52 + 3 * 128);
        free(o);
        rd_destroy(k);
    }
    END();
}
TEST(dsa_import_public_key_cannot_export_private) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx1(0); CHECK(k);
    UCHAR buf[1024]; ULONG n = 0;
    if (k) {
        NTSTATUS s = U(BCryptExportKey)(k, NULL, BCRYPT_DSA_PRIVATE_BLOB, buf, sizeof buf, &n, 0);
        CHECK(s != 0); t_note("public-only DSA key private export: 0x%lx", (unsigned long)s);
        rd_destroy(k);
    }
    END();
}
TEST(dsa_import_param_validation) {
    BEGIN();
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 0); BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptImportKeyPair)(NULL, NULL, BCRYPT_DSA_PUBLIC_BLOB, &k, b, n, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(U(BCryptImportKeyPair)(g_a, NULL, BCRYPT_DSA_PUBLIC_BLOB, NULL, b, n, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptImportKeyPair)(g_a, NULL, NULL, &k, b, n, 0), ST_INVALID_PARAMETER);
    END();
}
TEST(dsa_import_truncated_fails) {
    BEGIN();
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 0);
    ULONG cuts[] = { 0, 4, 8, 51, 52, 100, 180, n - 1 };
    for (size_t i = 0; i < sizeof cuts / sizeof *cuts; i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, cuts[i], &k);
        CHECKF(s != 0, "public blob cut to %lu imported", cuts[i]);
        if (!s) rd_destroy(k);
    }
    n = rd_dsa1_blob(b, 1);
    for (size_t i = 0; i < sizeof cuts / sizeof *cuts; i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = rd_import(g_a, BCRYPT_DSA_PRIVATE_BLOB, b, cuts[i], &k);
        CHECKF(s != 0, "private blob cut to %lu imported", cuts[i]);
        if (!s) rd_destroy(k);
    }
    n = n - 1;
    { BCRYPT_KEY_HANDLE k = NULL; NTSTATUS s = rd_import(g_a, BCRYPT_DSA_PRIVATE_BLOB, b, n, &k); CHECK(s != 0); if (!s) rd_destroy(k); }
    END();
}
TEST(dsa_import_wrong_magic_fails) {
    BEGIN();
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 0); BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = rd_import(g_a, BCRYPT_DSA_PRIVATE_BLOB, b, n, &k);   /* public magic under the private type */
    CHECK(s != 0); if (!s) rd_destroy(k);
    ((BCRYPT_DSA_KEY_BLOB *)b)->dwMagic = 0x41424344;
    s = rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k);
    CHECK(s != 0); if (!s) rd_destroy(k);
    END();
}
TEST(dsa_import_rsa_blob_fails) {
    BEGIN();
    UCHAR b[RD_RSA_BLOB_MAX]; ULONG n = rd_rsa_blob(b, BCRYPT_RSAPUBLIC_MAGIC, 0); BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = rd_import(g_a, BCRYPT_RSAPUBLIC_BLOB, b, n, &k);
    CHECK(s != 0); if (!s) rd_destroy(k);
    s = rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k);
    CHECK(s != 0); if (!s) rd_destroy(k);
    END();
}
TEST(dsa_import_into_rsa_provider_fails) {
    BEGIN();
    BCRYPT_ALG_HANDLE r = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(r);
    UCHAR b[1024]; ULONG n = rd_dsa1_blob(b, 0); BCRYPT_KEY_HANDLE k = NULL;
    if (r) { NTSTATUS s = rd_import(r, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k); CHECK(s != 0); if (!s) rd_destroy(k); rd_closealg(r); }
    END();
}

/* ---------- v2 blobs ---------- */
TEST(dsa_import_v2_public_and_layout) {
    BEGIN();
    UCHAR b[2048]; ULONG n = rd_dsa2_blob(b, 0, DSA_HASH_ALGORITHM_SHA256); BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k), ST_SUCCESS); CHECK(k);
    if (k) {
        NTSTATUS ps;
        EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 2048);
        UCHAR *o; ULONG ol;
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PUBLIC_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == n);
        if (o && ol >= sizeof(BCRYPT_DSA_KEY_BLOB_V2)) {
            const BCRYPT_DSA_KEY_BLOB_V2 *h = (const BCRYPT_DSA_KEY_BLOB_V2 *)o;
            EXPECT_EQ(sizeof *h, 28);
            EXPECT_EQ(h->dwMagic, BCRYPT_DSA_PUBLIC_MAGIC_V2);
            EXPECT_EQ(h->cbKey, 256);
            EXPECT_EQ(h->cbGroupSize, 32);
            EXPECT_EQ(h->hashAlgorithm, DSA_HASH_ALGORITHM_SHA256);
            EXPECT_EQ(h->standardVersion, DSA_FIPS186_3);
            if (ol == n) {
                const ULONG off = 28 + h->cbSeedLength;
                CHECK(!memcmp(o + off, kDsa2_Q, 32));
                CHECK(!memcmp(o + off + 32, kDsa2_P, 256));
                CHECK(!memcmp(o + off + 32 + 256, kDsa2_G, 256));
                CHECK(!memcmp(o + off + 32 + 512, kDsa2_Y, 256));
            }
        }
        free(o);
        rd_destroy(k);
    }
    END();
}
TEST(dsa_import_v2_private) {
    BEGIN();
    UCHAR b[2048]; ULONG n = rd_dsa2_blob(b, 1, DSA_HASH_ALGORITHM_SHA256); BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(g_a, BCRYPT_DSA_PRIVATE_BLOB, b, n, &k), ST_SUCCESS); CHECK(k);
    if (k) {
        UCHAR *o; ULONG ol;
        EXPECT_EQ(rd_export(k, BCRYPT_DSA_PRIVATE_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == n);
        if (o && ol == n) {
            const BCRYPT_DSA_KEY_BLOB_V2 *h = (const BCRYPT_DSA_KEY_BLOB_V2 *)o;
            EXPECT_EQ(h->dwMagic, BCRYPT_DSA_PRIVATE_MAGIC_V2);
            CHECK(!memcmp(o + ol - 32, kDsa2_X, 32));
        }
        free(o);
        rd_destroy(k);
    }
    END();
}
TEST(dsa_import_v2_hash_alg_variants) {
    BEGIN();
    DWORD algs[] = { DSA_HASH_ALGORITHM_SHA1, DSA_HASH_ALGORITHM_SHA256, DSA_HASH_ALGORITHM_SHA512 };
    for (int i = 0; i < 3; i++) {
        UCHAR b[2048]; ULONG n = rd_dsa2_blob(b, 0, algs[i]); BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k);
        t_note("v2 public import with hashAlgorithm=%lu: 0x%lx", (unsigned long)algs[i], (unsigned long)s);
        if (algs[i] == DSA_HASH_ALGORITHM_SHA256) CHECK(s == 0);
        if (!s) rd_destroy(k);
    }
    DWORD bad = 77; UCHAR b[2048]; ULONG n = rd_dsa2_blob(b, 0, bad); BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, n, &k);
    t_note("v2 import with invalid hashAlgorithm 77: 0x%lx", (unsigned long)s);
    if (!s) rd_destroy(k);
    END();
}
TEST(dsa_import_v2_truncated_fails) {
    BEGIN();
    UCHAR b[2048]; ULONG n = rd_dsa2_blob(b, 0, DSA_HASH_ALGORITHM_SHA256);
    ULONG cuts[] = { 0, 8, 27, 28, 60, 300, n - 1 };
    for (size_t i = 0; i < sizeof cuts / sizeof *cuts; i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, cuts[i], &k);
        CHECKF(s != 0, "v2 blob cut to %lu imported", cuts[i]);
        if (!s) rd_destroy(k);
    }
    END();
}

/* ---------- legacy CAPI DSA blobs ---------- */
TEST(dsa_legacy_public_export_header) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx1(0); CHECK(k);
    if (k) {
        UCHAR *o; ULONG ol;
        NTSTATUS s = rd_export(k, LEGACY_DSA_PUBLIC_BLOB, &o, &ol);
        if (s) t_note("legacy DSA public export: 0x%lx", (unsigned long)s);
        if (!s) {
            EXPECT_EQ(o[0], 6); EXPECT_EQ(o[1], 3);      /* version 3 blob */
            EXPECT_EQ(*(DWORD *)(o + 4), 0x2200);        /* CALG_DSS_SIGN */
            EXPECT_EQ(*(DWORD *)(o + 8), 0x33535344);    /* "DSS3" */
            EXPECT_EQ(*(DWORD *)(o + 12), 1024);   /* bitlenP */
            EXPECT_EQ(*(DWORD *)(o + 16), 160);    /* bitlenQ */
            EXPECT_EQ(*(DWORD *)(o + 20), 0);      /* bitlenJ */
            EXPECT_EQ(*(DWORD *)(o + 24), 0xffffffff);   /* seed counter as imported */
            EXPECT_EQ(ol, 452);
            if (ol == 452) { CHECK(o[48] == kDsa1_P[127]); CHECK(o[48 + 127] == kDsa1_P[0]); }
            free(o);
        }
        rd_destroy(k);
    }
    END();
}
TEST(dsa_legacy_private_export_header) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx1(1); CHECK(k);
    if (k) {
        UCHAR *o; ULONG ol;
        NTSTATUS s = rd_export(k, LEGACY_DSA_PRIVATE_BLOB, &o, &ol);
        if (s) t_note("legacy DSA private export: 0x%lx", (unsigned long)s);
        if (!s) {
            EXPECT_EQ(o[0], 7); EXPECT_EQ(o[1], 3);      /* version 3 blob */
            EXPECT_EQ(*(DWORD *)(o + 4), 0x2200);
            EXPECT_EQ(*(DWORD *)(o + 8), 0x34535344);    /* "DSS4" */
            EXPECT_EQ(*(DWORD *)(o + 12), 1024);   /* bitlenP */
            EXPECT_EQ(*(DWORD *)(o + 16), 160);    /* bitlenQ */
            EXPECT_EQ(*(DWORD *)(o + 20), 0);      /* bitlenJ */
            EXPECT_EQ(*(DWORD *)(o + 24), 160);    /* bitlenX */
            EXPECT_EQ(*(DWORD *)(o + 28), 0xffffffff);   /* seed counter as imported */
            CHECK(o[32] == 0x5a && o[51] == 0x5a);       /* seed as imported */
            EXPECT_EQ(ol, 476);
            /* P is little-endian and follows the 24-byte seed */
            if (ol == 476) { CHECK(o[52] == kDsa1_P[127]); CHECK(o[52 + 127] == kDsa1_P[0]); }
            free(o);
        }
        rd_destroy(k);
    }
    END();
}

/* ---------- signing / verifying ---------- */
TEST(dsa_verify_known_answer_1024_160) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx1(0), prv = fx1(1); CHECK(pub && prv);
    if (pub) EXPECT_EQ(verify(pub, kHash_sha1, 20, kDsa1_Sig, 40, 0), ST_SUCCESS);
    if (prv) EXPECT_EQ(verify(prv, kHash_sha1, 20, kDsa1_Sig, 40, 0), ST_SUCCESS);
    rd_destroy(pub); rd_destroy(prv); END();
}
TEST(dsa_verify_known_answer_2048_256) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx2(0), prv = fx2(1); CHECK(pub && prv);
    if (pub) EXPECT_EQ(verify(pub, kHash_sha256, 32, kDsa2_Sig_sha256, 64, 0), ST_SUCCESS);
    if (prv) EXPECT_EQ(verify(prv, kHash_sha256, 32, kDsa2_Sig_sha256, 64, 0), ST_SUCCESS);
    rd_destroy(pub); rd_destroy(prv); END();
}
TEST(dsa_verify_tamper_1024) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx1(0); CHECK(pub);
    if (pub) {
        for (int i = 0; i < 40; i += 13) {
            UCHAR s[40]; memcpy(s, kDsa1_Sig, 40); s[i] ^= 1;
            SIGFAIL(verify(pub, kHash_sha1, 20, s, 40, 0));
        }
        for (int i = 0; i < 20; i += 7) {
            UCHAR h[20]; memcpy(h, kHash_sha1, 20); h[i] ^= 0x10;
            SIGFAIL(verify(pub, h, 20, kDsa1_Sig, 40, 0));
        }
        /* r and s swapped */
        UCHAR sw[40]; memcpy(sw, kDsa1_Sig + 20, 20); memcpy(sw + 20, kDsa1_Sig, 20);
        SIGFAIL(verify(pub, kHash_sha1, 20, sw, 40, 0));
    }
    rd_destroy(pub); END();
}
TEST(dsa_verify_degenerate_signatures) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx1(0); CHECK(pub);
    if (pub) {
        UCHAR z[40]; memset(z, 0, 40);
        SIGFAIL(verify(pub, kHash_sha1, 20, z, 40, 0));   /* r = s = 0 */
        UCHAR f[40]; memset(f, 0xff, 40);
        SIGFAIL(verify(pub, kHash_sha1, 20, f, 40, 0));   /* r, s >= q */
        UCHAR rz[40]; memcpy(rz, kDsa1_Sig, 40); memset(rz, 0, 20);
        SIGFAIL(verify(pub, kHash_sha1, 20, rz, 40, 0));
        UCHAR sz[40]; memcpy(sz, kDsa1_Sig, 40); memset(sz + 20, 0, 20);
        SIGFAIL(verify(pub, kHash_sha1, 20, sz, 40, 0));
    }
    rd_destroy(pub); END();
}
TEST(dsa_verify_signature_length) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx1(0); CHECK(pub);
    if (pub) {
        UCHAR big[80]; memset(big, 0, sizeof big); memcpy(big, kDsa1_Sig, 40);
        ULONG lens[] = { 0, 1, 20, 39, 41, 64, 80 };
        for (int i = 0; i < 7; i++) {
            NTSTATUS s = verify(pub, kHash_sha1, 20, big, lens[i], 0);
            if (lens[i] < 40) CHECKF(s != 0, "signature length %lu verified", lens[i]);
            t_note("DSA verify with signature length %lu: 0x%lx", lens[i], (unsigned long)s);
        }
    }
    rd_destroy(pub); END();
}
TEST(dsa_verify_null_args) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx1(0); CHECK(pub);
    EXPECT_EQ(verify(NULL, kHash_sha1, 20, kDsa1_Sig, 40, 0), ST_INVALID_HANDLE);
    if (pub) {
        EXPECT_EQ(verify(pub, NULL, 20, kDsa1_Sig, 40, 0), ST_INVALID_PARAMETER);
        EXPECT_EQ(verify(pub, kHash_sha1, 20, NULL, 40, 0), ST_INVALID_PARAMETER);
        EXPECT_EQ(verify((BCRYPT_KEY_HANDLE)g_a, kHash_sha1, 20, kDsa1_Sig, 40, 0), ST_INVALID_HANDLE);
    }
    rd_destroy(pub); END();
}
TEST(dsa_verify_with_other_key_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE other = rd_gen(g_a, 1024); CHECK(other);
    if (other) EXPECT_EQ(verify(other, kHash_sha1, 20, kDsa1_Sig, 40, 0), ST_INVALID_SIGNATURE);
    rd_destroy(other); END();
}
TEST(dsa_sign_roundtrip_fixed_key_1024) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx1(0), prv = fx1(1); CHECK(pub && prv);
    if (pub && prv) {
        UCHAR s1[40], s2[40]; ULONG n = 0;
        EXPECT_EQ(sign(prv, kHash_sha1, 20, s1, sizeof s1, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, 40);
        EXPECT_EQ(verify(pub, kHash_sha1, 20, s1, 40, 0), ST_SUCCESS);
        EXPECT_EQ(sign(prv, kHash_sha1, 20, s2, sizeof s2, &n, 0), ST_SUCCESS);
        CHECK(memcmp(s1, s2, 40) != 0);               /* per-signature random nonce */
        EXPECT_EQ(verify(pub, kHash_sha1, 20, s2, 40, 0), ST_SUCCESS);
        CHECK(rd_nonzero(s1, 20) && rd_nonzero(s1 + 20, 20));
    }
    rd_destroy(pub); rd_destroy(prv); END();
}
TEST(dsa_sign_roundtrip_fixed_key_2048) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx2(0), prv = fx2(1); CHECK(pub && prv);
    if (pub && prv) {
        UCHAR s1[64]; ULONG n = 0;
        EXPECT_EQ(sign(prv, kHash_sha256, 32, s1, sizeof s1, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, 64);
        EXPECT_EQ(verify(pub, kHash_sha256, 32, s1, 64, 0), ST_SUCCESS);
        s1[40] ^= 1;
        EXPECT_EQ(verify(pub, kHash_sha256, 32, s1, 64, 0), ST_INVALID_SIGNATURE);
        UCHAR sh[64];
        NTSTATUS s = sign(prv, kHash_sha1, 20, sh, sizeof sh, &n, 0);
        t_note("2048/256 key signing a 20-byte hash: 0x%lx n=%lu", (unsigned long)s, n);
        s = sign(prv, kHash_sha512, 64, sh, sizeof sh, &n, 0);
        t_note("2048/256 key signing a 64-byte hash: 0x%lx n=%lu", (unsigned long)s, n);
    }
    rd_destroy(pub); rd_destroy(prv); END();
}
TEST(dsa_sign_size_protocol) {
    BEGIN();
    BCRYPT_KEY_HANDLE prv = fx1(1); CHECK(prv);
    if (prv) {
        UCHAR sig[128]; ULONG n = 0xdead;
        EXPECT_EQ(sign(prv, kHash_sha1, 20, NULL, 0, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, 40);
        ULONG small[] = { 0, 1, 20, 39 };
        for (int i = 0; i < 4; i++) {
            n = 0;
            NTSTATUS s = sign(prv, kHash_sha1, 20, sig, small[i], &n, 0);
            CHECKF(s == (NTSTATUS)ST_BUFFER_TOO_SMALL, "cb=%lu -> 0x%lx", small[i], (unsigned long)s);
            EXPECT_EQ(n, 40);
        }
        memset(sig, 0xcc, sizeof sig);
        EXPECT_EQ(sign(prv, kHash_sha1, 20, sig, 40, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, 40); CHECK(sig[40] == 0xcc);
        memset(sig, 0xcc, sizeof sig);
        EXPECT_EQ(sign(prv, kHash_sha1, 20, sig, 128, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, 40); CHECK(sig[40] == 0xcc);
        EXPECT_EQ(sign(prv, kHash_sha1, 20, sig, 128, NULL, 0), ST_INVALID_PARAMETER);
    }
    rd_destroy(prv); END();
}
TEST(dsa_sign_public_only_key_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx1(0); CHECK(pub);
    if (pub) {
        UCHAR sig[64]; ULONG n = 0;
        NTSTATUS s = sign(pub, kHash_sha1, 20, sig, sizeof sig, &n, 0);
        CHECK(s != 0); t_note("DSA sign with public-only key: 0x%lx", (unsigned long)s);
    }
    rd_destroy(pub); END();
}
TEST(dsa_sign_hash_lengths_v1) {
    BEGIN();
    BCRYPT_KEY_HANDLE prv = fx1(1), pub = fx1(0); CHECK(prv && pub);
    if (prv && pub) {
        UCHAR h[64], sig[64]; ULONG n = 0;
        for (int i = 0; i < 64; i++) h[i] = (UCHAR)(i * 11 + 5);
        ULONG lens[] = { 0, 1, 16, 19, 20, 21, 32, 64 };
        for (int i = 0; i < 8; i++) {
            NTSTATUS s = sign(prv, h, lens[i], sig, sizeof sig, &n, 0);
            t_note("DSA-1024/160 sign hash length %lu: 0x%lx", lens[i], (unsigned long)s);
            if (lens[i] == 20) CHECK(s == 0);
            if (s == 0) { NTSTATUS v = verify(pub, h, lens[i], sig, n, 0); CHECK(v == 0); }
        }
    }
    rd_destroy(prv); rd_destroy(pub); END();
}
TEST(dsa_sign_generated_keys_table) {
    BEGIN();
    static const ULONG sizes[] = { 512, 640, 1024 };
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = rd_gen(g_a, sizes[i]); CHECK(k); if (!k) continue;
        UCHAR sig[64]; ULONG n = 0;
        EXPECT_EQ(sign(k, kHash_sha1, 20, sig, sizeof sig, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, 40);
        EXPECT_EQ(verify(k, kHash_sha1, 20, sig, n, 0), ST_SUCCESS);
        UCHAR *b; ULONG bl; BCRYPT_KEY_HANDLE pub = NULL;
        if (rd_export(k, BCRYPT_DSA_PUBLIC_BLOB, &b, &bl) == 0) {
            EXPECT_EQ(rd_import(g_a, BCRYPT_DSA_PUBLIC_BLOB, b, bl, &pub), ST_SUCCESS);
            if (pub) { EXPECT_EQ(verify(pub, kHash_sha1, 20, sig, n, 0), ST_SUCCESS); rd_destroy(pub); }
            free(b);
        }
        rd_destroy(k);
    }
    END();
}
TEST(dsa_sign_generated_2048_roundtrip) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 2048); CHECK(k);
    if (k) {
        UCHAR sig[128]; ULONG n = 0;
        NTSTATUS s = sign(k, kHash_sha256, 32, sig, sizeof sig, &n, 0);
        EXPECT_EQ(s, ST_SUCCESS);
        EXPECT_EQ(n, 64);
        if (!s) EXPECT_EQ(verify(k, kHash_sha256, 32, sig, n, 0), ST_SUCCESS);
        UCHAR *b; ULONG bl; BCRYPT_KEY_HANDLE k2 = NULL;
        if (rd_export(k, BCRYPT_DSA_PRIVATE_BLOB, &b, &bl) == 0) {
            EXPECT_EQ(rd_import(g_a, BCRYPT_DSA_PRIVATE_BLOB, b, bl, &k2), ST_SUCCESS);
            if (k2) { if (!s) EXPECT_EQ(verify(k2, kHash_sha256, 32, sig, n, 0), ST_SUCCESS); rd_destroy(k2); }
            free(b);
        }
        rd_destroy(k);
    }
    END();
}
TEST(dsa_sign_flags_and_padding_info) {
    BEGIN();
    BCRYPT_KEY_HANDLE prv = fx1(1); CHECK(prv);
    if (prv) {
        UCHAR sig[64]; ULONG n = 0;
        ULONG fl[] = { BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PAD_NONE, 0x80000000 };
        for (int i = 0; i < 4; i++) {
            NTSTATUS s = sign(prv, kHash_sha1, 20, sig, sizeof sig, &n, fl[i]);
            t_note("DSA sign with flags 0x%lx: 0x%lx", fl[i], (unsigned long)s);
        }
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM };
        NTSTATUS s = U(BCryptSignHash)(prv, &pi, (PUCHAR)kHash_sha1, 20, sig, sizeof sig, &n, 0);
        t_note("DSA sign with padding info and flags 0: 0x%lx", (unsigned long)s);
    }
    rd_destroy(prv); END();
}
TEST(dsa_encrypt_not_supported) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx1(0); CHECK(pub);
    if (pub) {
        UCHAR in[8] = { 1 }, out[256]; ULONG n = 0;
        NTSTATUS s = U(BCryptEncrypt)(pub, in, sizeof in, NULL, NULL, 0, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
        CHECK(s != 0); t_note("DSA BCryptEncrypt: 0x%lx", (unsigned long)s);
        s = U(BCryptDecrypt)(pub, in, sizeof in, NULL, NULL, 0, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
        CHECK(s != 0);
    }
    rd_destroy(pub); END();
}
TEST(dsa_key_properties) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx1(0); CHECK(k);
    if (k) {
        NTSTATUS ps;
        EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 1024); EXPECT_EQ(ps, 0);
        { ULONG ks = rd_getdw(k, BCRYPT_KEY_STRENGTH, &ps); t_note("DSA KeyStrength=%lu st=0x%lx", ks, (unsigned long)ps); }
        WCHAR name[32] = {0}; ULONG n = 0;
        EXPECT_EQ(U(BCryptGetProperty)(k, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof name, &n, 0), ST_SUCCESS);
        EXPECT_WSTR(name, L"DSA");
        rd_destroy(k);
    }
    END();
}
TEST(dsa_destroy_semantics) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx1(0); CHECK(k);
    if (k) EXPECT_EQ(U(BCryptDestroyKey)(k), ST_SUCCESS);
    EXPECT_EQ(U(BCryptDestroyKey)(NULL), ST_INVALID_HANDLE);
    EXPECT_EQ(U(BCryptDestroyKey)((BCRYPT_KEY_HANDLE)g_a), ST_INVALID_HANDLE);
    END();
}

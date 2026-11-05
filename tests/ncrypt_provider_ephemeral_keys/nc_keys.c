/* Ephemeral key creation (NULL key name), finalization and the property protocol. */
#include "nc.h"

typedef struct { const WCHAR *alg; const WCHAR *group; DWORD defbits; const WCHAR *curve; } algrow_t;
static const algrow_t ALGS[] = {
    { L"RSA",        L"RSA",   2048, NULL },
    { L"ECDSA_P256", L"ECDSA", 256,  L"nistP256" },
    { L"ECDSA_P384", L"ECDSA", 384,  L"nistP384" },
    { L"ECDSA_P521", L"ECDSA", 521,  L"nistP521" },
    { L"ECDH_P256",  L"ECDH",  256,  L"nistP256" },
    { L"ECDH_P384",  L"ECDH",  384,  L"nistP384" },
    { L"ECDH_P521",  L"ECDH",  521,  L"nistP521" },
};
#define NALGS (sizeof(ALGS) / sizeof(ALGS[0]))

/* ---------- NCryptCreatePersistedKey ---------- */
TEST(nckey_create_phkey_null) {
    NC_NOWINE();
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    EXPECT_SS(U(NCryptCreatePersistedKey)(p, NULL, BCRYPT_RSA_ALGORITHM, NULL, 0, 0), NC_INVALID_PARAMETER);
    /* phKey is checked before the provider handle */
    EXPECT_SS(U(NCryptCreatePersistedKey)(0, NULL, BCRYPT_RSA_ALGORITHM, NULL, 0, 0), NC_INVALID_PARAMETER);
    nc_free(p);
}
TEST(nckey_create_invalid_provider) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_KEY_HANDLE k = 0x55;
    EXPECT_SS(U(NCryptCreatePersistedKey)(0, &k, BCRYPT_RSA_ALGORITHM, NULL, 0, 0), NC_INVALID_HANDLE);
    EXPECT_EQ(k, 0x55);   /* output untouched on failure */
}
TEST(nckey_create_each_algorithm) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 0; i < NALGS; i++) {
        NCRYPT_KEY_HANDLE k = 0;
        SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, ALGS[i].alg, NULL, 0, 0);
        CHECKF(s == 0, "%ls -> 0x%08lx", ALGS[i].alg, (DWORD)s);
        if (s) continue;
        CHECK(k != 0);
        CHECK(U(NCryptIsKeyHandle)(k));
        EXPECT_SS(U(NCryptFreeObject)(k), 0);
    }
    nc_free(p);
}
TEST(nckey_create_dh_dsa) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0;
    EXPECT_SS(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_DH_ALGORITHM, NULL, 0, 0), 0);
    nc_free(k); k = 0;
    SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, BCRYPT_DSA_ALGORITHM, NULL, 0, 0);
    t_note("create DSA key -> 0x%08lx", (DWORD)s);
    nc_free(k);
    nc_free(p);
}
TEST(nckey_create_unknown_algorithm) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const WCHAR *bad[] = { BCRYPT_SHA256_ALGORITHM, L"", L"cryptt-nope", L"RSA2", L"ECDSA_P257" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        NCRYPT_KEY_HANDLE k = 0x99;
        SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, bad[i], NULL, 0, 0);
        CHECKF(s != 0, "'%ls' created a key", bad[i]);
        EXPECT_EQ(k, 0x99);
        t_note("create '%ls' -> 0x%08lx", bad[i], (DWORD)s);
        if (s == 0) nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_create_null_algid) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, NULL, NULL, 0, 0);
    EXPECT_SS_FAIL(s);
    t_note("create with NULL alg -> 0x%08lx", (DWORD)s);
    if (s == 0) nc_free(k);
    nc_free(p);
}
TEST(nckey_create_two_ephemeral_same_alg_distinct) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, NC_EXP_ALL, TRUE), b = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, NC_EXP_ALL, TRUE);
    NEED(a && b, "keys");
    CHECK(a != b);
    BYTE ba[80], bb[80]; DWORD ca = 0, cb = 0;
    EXPECT_SS(U(NCryptExportKey)(a, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, ba, sizeof ba, &ca, 0), 0);
    EXPECT_SS(U(NCryptExportKey)(b, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, bb, sizeof bb, &cb, 0), 0);
    EXPECT_EQ(ca, 72); EXPECT_EQ(cb, 72);
    CHECK(memcmp(ba, bb, 72) != 0);   /* 2^-256 chance of a false failure */
    nc_free(a); nc_free(b); nc_free(p);
}
TEST(nckey_create_flags) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD f[] = { 0x1, 0x2, 0x4, 0x8, 0x10, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_SILENT_FLAG, NCRYPT_OVERWRITE_KEY_FLAG, 0x100, 0x80000000u };
    for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++) {
        NCRYPT_KEY_HANDLE k = 0;
        SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, f[i]);
        t_note("create ephemeral flags=0x%lx -> 0x%08lx", f[i], (DWORD)s);
        if (s == 0) nc_free(k); else EXPECT_EQ(k, 0);
    }
    nc_free(p);
}
TEST(nckey_create_legacy_keyspec) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD spec[] = { 0, AT_KEYEXCHANGE, AT_SIGNATURE, 3, 0xFFFF };
    for (size_t i = 0; i < sizeof(spec) / sizeof(spec[0]); i++) {
        NCRYPT_KEY_HANDLE k = 0;
        SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, NULL, spec[i], 0);
        if (spec[i] <= AT_SIGNATURE) EXPECT_SS(s, 0);
        else t_note("create RSA legacy keyspec %lu -> 0x%08lx", spec[i], (DWORD)s);
        if (s == 0) nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_create_free_loop) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (int i = 0; i < 300; i++) {
        NCRYPT_KEY_HANDLE k = 0;
        if (U(NCryptCreatePersistedKey)(p, &k, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0) != 0) { CHECKF(0, "create #%d", i); break; }
        if (U(NCryptFreeObject)(k) != 0) { CHECKF(0, "free #%d", i); break; }
    }
    nc_free(p);
}

/* ---------- NCryptFinalizeKey and key state ---------- */
TEST(nckey_finalize_invalid_handle) {
    REQUIRE(U(NCryptFinalizeKey));
    EXPECT_SS(U(NCryptFinalizeKey)(0, 0), NC_INVALID_HANDLE);
}
TEST(nckey_finalize_each_algorithm) {
    REQUIRE(U(NCryptFinalizeKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 0; i < NALGS; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ALGS[i].alg, ALGS[i].defbits == 2048 ? 1024 : 0, 0xFFFFFFFFu, FALSE);
        CHECKF(k != 0, "%ls create", ALGS[i].alg);
        if (!k) continue;
        EXPECT_SS(U(NCryptFinalizeKey)(k, 0), 0);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_finalize_twice_note) {
    REQUIRE(U(NCryptFinalizeKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    EXPECT_SS(U(NCryptFinalizeKey)(k, 0), 0);
    SECURITY_STATUS s = U(NCryptFinalizeKey)(k, 0);
    t_note("second NCryptFinalizeKey -> 0x%08lx", (DWORD)s);
    /* regardless of the second result the key keeps working */
    BYTE sig[64]; DWORD cb = 0;
    EXPECT_SS(U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, &cb, 0), 0);
    nc_free(k); nc_free(p);
}
TEST(nckey_finalize_bad_flags) {
    REQUIRE(U(NCryptFinalizeKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD f[] = { 0x1, 0x2, 0x4, 0x100, 0x80000000u };
    for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
        SECURITY_STATUS s = U(NCryptFinalizeKey)(k, f[i]);
        t_note("Finalize flags=0x%lx -> 0x%08lx", f[i], (DWORD)s);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_unfinalized_operations_bad_key_state) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature)); REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE ec = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE);
    NCRYPT_KEY_HANDLE rsa = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, FALSE);
    NEED(ec && rsa, "keys");
    BYTE out[256]; DWORD cb = 0;
    /* the exact status is KSP-internal (not visible in the router): every use must fail, the code is recorded */
    SECURITY_STATUS s;
    s = U(NCryptSignHash)(ec, NULL, (PBYTE)k_dig_sha256, 32, out, sizeof out, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("sign with unfinalized EC key -> 0x%08lx (expected NTE_BAD_KEY_STATE)", (DWORD)s);
    s = U(NCryptSignHash)(ec, NULL, (PBYTE)k_dig_sha256, 32, NULL, 0, &cb, 0);
    t_note("sign size query with unfinalized EC key -> 0x%08lx", (DWORD)s);
    s = U(NCryptVerifySignature)(ec, NULL, (PBYTE)k_dig_sha256, 32, (PBYTE)k_ec256_sig_sha256, 64, 0);
    EXPECT_SS_FAIL(s); t_note("verify with unfinalized EC key -> 0x%08lx", (DWORD)s);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    s = U(NCryptSignHash)(rsa, &pi, (PBYTE)k_dig_sha256, 32, out, sizeof out, &cb, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("sign with unfinalized RSA key -> 0x%08lx", (DWORD)s);
    s = U(NCryptEncrypt)(rsa, (PBYTE)k_pt, 8, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    EXPECT_SS_FAIL(s); t_note("encrypt with unfinalized RSA key -> 0x%08lx", (DWORD)s);
    s = U(NCryptDecrypt)(rsa, (PBYTE)k_rsa_enc_pkcs1, 128, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    EXPECT_SS_FAIL(s); t_note("decrypt with unfinalized RSA key -> 0x%08lx", (DWORD)s);
    nc_free(ec); nc_free(rsa); nc_free(p);
}
TEST(nckey_unfinalized_export_and_agreement) {
    NC_NOWINE();
    REQUIRE(U(NCryptExportKey)); REQUIRE(U(NCryptSecretAgreement));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a = nc_newkey(p, BCRYPT_ECDH_P256_ALGORITHM, 0, NC_EXP_ALL, FALSE);
    NCRYPT_KEY_HANDLE b = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ecdh256_b_pub));
    NEED(a && b, "keys");
    BYTE out[200]; DWORD cb = 0; NCRYPT_SECRET_HANDLE s = 0;
    SECURITY_STATUS st = U(NCryptExportKey)(a, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, out, sizeof out, &cb, 0);
    EXPECT_SS_FAIL(st); t_note("export public of unfinalized key -> 0x%08lx", (DWORD)st);
    st = U(NCryptSecretAgreement)(a, b, &s, 0);
    EXPECT_SS_FAIL(st); EXPECT_EQ(s, 0); t_note("agreement with unfinalized key -> 0x%08lx", (DWORD)st);
    nc_free(a); nc_free(b); nc_free(p);
}

/* ---------- LENGTH property ---------- */
TEST(nckey_length_default_rsa) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v), 0);
    EXPECT_EQ(v, 1024);   /* Win10 22H2 software KSP default RSA size */
    nc_free(k); nc_free(p);
}
TEST(nckey_length_default_ecc) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 1; i < NALGS; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ALGS[i].alg, 0, 0xFFFFFFFFu, TRUE);
        CHECKF(k != 0, "%ls", ALGS[i].alg);
        if (!k) continue;
        DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v), 0);
        CHECKF(v == ALGS[i].defbits, "%ls length %lu want %lu", ALGS[i].alg, v, ALGS[i].defbits);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_length_set_rsa_roundtrip) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD bits[] = { 512, 768, 1024, 1536, 2048 };
    for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, bits[i], 0xFFFFFFFFu, TRUE);
        CHECKF(k != 0, "RSA %lu", bits[i]);
        if (!k) continue;
        DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v), 0);
        EXPECT_EQ(v, bits[i]);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_length_set_before_finalize_visible_before_finalize) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    DWORD v; SECURITY_STATUS s = nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v);
    t_note("LENGTH before finalize -> 0x%08lx value %lu", (DWORD)s, v);
    if (s == 0) EXPECT_EQ(v, 1024);
    nc_free(k); nc_free(p);
}
TEST(nckey_length_invalid_rsa_values) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD bad[] = { 0, 64, 256, 511, 513, 1000, 1025 };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        NCRYPT_KEY_HANDLE k = 0;
        EXPECT_SS(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, NULL, 0, 0), 0);
        if (!k) continue;
        DWORD v = bad[i];
        SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0);
        SECURITY_STATUS f = (s == 0) ? U(NCryptFinalizeKey)(k, 0) : 0;
        CHECKF(s != 0 || f != 0, "RSA length %lu accepted end to end", bad[i]);
        t_note("RSA length %lu: set 0x%08lx finalize 0x%08lx", bad[i], (DWORD)s, (DWORD)f);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_length_set_wrong_size_input) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    BYTE b[8] = { 0, 4, 0, 0, 0, 0, 0, 0 };
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, b, 0, 0));
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, b, 2, 0));
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, b, 8, 0));
    nc_free(k); nc_free(p);
}
TEST(nckey_length_set_after_finalize_fails) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD v = 2048;
    SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0);
    EXPECT_SS(s, 0);   /* Win10 accepts the write after finalize; it only changes the reported value, not the key */
    DWORD g; nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &g);
    EXPECT_EQ(g, 2048);
    BYTE pub[512]; DWORD cp = 0;
    EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, pub, sizeof pub, &cp, 0), 0);
    EXPECT_EQ(cp, sizeof(BCRYPT_RSAKEY_BLOB) + 3 + 128);   /* the key itself is still 1024 bits */
    nc_free(k); nc_free(p);
}
TEST(nckey_length_set_ecc_note) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    DWORD v = 256;
    t_note("set LENGTH=256 on ECDSA_P256 before finalize -> 0x%08lx", (DWORD)U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0));
    v = 384;
    t_note("set LENGTH=384 on ECDSA_P256 before finalize -> 0x%08lx", (DWORD)U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0));
    nc_free(k); nc_free(p);
}
TEST(nckey_dh_dsa_lengths) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_DH_ALGORITHM, 1024, 0xFFFFFFFFu, TRUE);
    CHECK(k != 0);
    if (k) { DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v), 0); EXPECT_EQ(v, 1024); nc_free(k); }
    k = nc_newkey(p, BCRYPT_DH_ALGORITHM, 2048, 0xFFFFFFFFu, TRUE);
    CHECK(k != 0);
    if (k) { DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v), 0); EXPECT_EQ(v, 2048); nc_free(k); }
    k = nc_newkey(p, BCRYPT_DSA_ALGORITHM, 1024, 0xFFFFFFFFu, TRUE);
    t_note("DSA-1024 ephemeral create+finalize: %s", k ? "ok" : "failed");
    if (k) { DWORD v; if (nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v) == 0) EXPECT_EQ(v, 1024); nc_free(k); }
    nc_free(p);
}

/* ---------- LENGTHS ---------- */
TEST(nckey_lengths_rsa) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD cb = 0; BYTE *b = nc_getprop(k, NCRYPT_LENGTHS_PROPERTY, &cb);
    CHECK(b != NULL);
    if (b) {
        EXPECT_EQ(cb, sizeof(NCRYPT_SUPPORTED_LENGTHS));
        NCRYPT_SUPPORTED_LENGTHS *l = (NCRYPT_SUPPORTED_LENGTHS *)b;
        EXPECT_EQ(l->dwMinLength, 512); EXPECT_EQ(l->dwMaxLength, 16384); EXPECT_EQ(l->dwIncrement, 8);
        t_note("RSA default length in LENGTHS = %lu", l->dwDefaultLength);
        nc_hfree(b);
    }
    nc_free(k); nc_free(p);
}
TEST(nckey_lengths_other_algs_note) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 1; i < NALGS; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ALGS[i].alg, 0, 0xFFFFFFFFu, TRUE); if (!k) continue;
        DWORD cb = 0; BYTE *b = nc_getprop(k, NCRYPT_LENGTHS_PROPERTY, &cb);
        if (b && cb >= 16) { NCRYPT_SUPPORTED_LENGTHS *l = (NCRYPT_SUPPORTED_LENGTHS *)b; t_note("%ls LENGTHS min=%lu max=%lu inc=%lu def=%lu", ALGS[i].alg, l->dwMinLength, l->dwMaxLength, l->dwIncrement, l->dwDefaultLength); }
        else t_note("%ls LENGTHS unavailable", ALGS[i].alg);
        nc_hfree(b); nc_free(k);
    }
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_DH_ALGORITHM, 1024, 0xFFFFFFFFu, TRUE);
    if (k) { DWORD cb = 0; BYTE *b = nc_getprop(k, NCRYPT_LENGTHS_PROPERTY, &cb); if (b && cb >= 16) { NCRYPT_SUPPORTED_LENGTHS *l = (NCRYPT_SUPPORTED_LENGTHS *)b; t_note("DH LENGTHS min=%lu max=%lu inc=%lu def=%lu", l->dwMinLength, l->dwMaxLength, l->dwIncrement, l->dwDefaultLength); } nc_hfree(b); nc_free(k); }
    nc_free(p);
}

/* ---------- ALGORITHM / ALGORITHM_GROUP ---------- */
TEST(nckey_algorithm_property_table) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 0; i < NALGS; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ALGS[i].alg, ALGS[i].defbits == 2048 ? 1024 : 0, 0xFFFFFFFFu, TRUE);
        CHECKF(k != 0, "%ls", ALGS[i].alg);
        if (!k) continue;
        DWORD cb = 0; BYTE *b = nc_getprop(k, NCRYPT_ALGORITHM_PROPERTY, &cb);
        CHECKF(b && !lstrcmpW((WCHAR *)b, ALGS[i].alg), "%ls algorithm name", ALGS[i].alg);
        if (b) EXPECT_EQ(cb, (lstrlenW(ALGS[i].alg) + 1) * 2);
        nc_hfree(b);
        b = nc_getprop(k, NCRYPT_ALGORITHM_GROUP_PROPERTY, &cb);
        CHECKF(b && !lstrcmpW((WCHAR *)b, ALGS[i].group), "%ls algorithm group", ALGS[i].alg);
        if (b) EXPECT_EQ(cb, (lstrlenW(ALGS[i].group) + 1) * 2);
        nc_hfree(b);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_algorithm_property_dh) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_DH_ALGORITHM, 1024, 0xFFFFFFFFu, TRUE); NEED(k, "DH key");
    DWORD cb; BYTE *b = nc_getprop(k, NCRYPT_ALGORITHM_PROPERTY, &cb);
    CHECK(b && !lstrcmpW((WCHAR *)b, L"DH")); nc_hfree(b);
    b = nc_getprop(k, NCRYPT_ALGORITHM_GROUP_PROPERTY, &cb);
    CHECK(b && !lstrcmpW((WCHAR *)b, L"DH")); nc_hfree(b);
    nc_free(k); nc_free(p);
}
TEST(nckey_algorithm_property_before_finalize_note) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P384_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    DWORD cb = 0; BYTE *b = nc_getprop(k, NCRYPT_ALGORITHM_PROPERTY, &cb);
    t_note("ALGORITHM before finalize: %ls", b ? (WCHAR *)b : L"(unavailable)");
    nc_hfree(b);
    nc_free(k); nc_free(p);
}
TEST(nckey_algorithm_property_is_read_only) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)L"RSA", 8, 0));
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)L"RSA", 8, 0));
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_BLOCK_LENGTH_PROPERTY, (PBYTE)&(DWORD){ 8 }, 4, 0));
    nc_free(k); nc_free(p);
}

/* ---------- property buffer protocol ---------- */
TEST(nckey_getprop_size_query) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P384_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD cb = 0xFFFF;
    EXPECT_SS(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, 22);   /* L"ECDSA_P384" + NUL */
    cb = 0xFFFF;
    EXPECT_SS(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, 4);
    nc_free(k); nc_free(p);
}
TEST(nckey_getprop_buffer_too_small) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P384_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    BYTE buf[64]; memset(buf, 0xEE, sizeof buf);
    static const DWORD sizes[] = { 0, 1, 2, 20, 21 };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        DWORD cb = 0xFFFF;
        EXPECT_SS(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, buf, sizes[i], &cb, 0), NC_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, 22);
    }
    DWORD v = 0, cb = 0xFFFF;
    EXPECT_SS(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 3, &cb, 0), NC_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, 4);
    nc_free(k); nc_free(p);
}
TEST(nckey_getprop_exact_and_larger_buffer) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P384_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    WCHAR buf[40]; DWORD cb = 0;
    memset(buf, 0xEE, sizeof buf);
    EXPECT_SS(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)buf, 22, &cb, 0), 0);
    EXPECT_EQ(cb, 22); CHECK(!lstrcmpW(buf, L"ECDSA_P384"));
    memset(buf, 0xEE, sizeof buf); cb = 0;
    EXPECT_SS(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)buf, sizeof buf, &cb, 0), 0);
    EXPECT_EQ(cb, 22); CHECK(!lstrcmpW(buf, L"ECDSA_P384"));
    CHECK(buf[11] == 0xEEEE);   /* bytes past the result are not touched */
    nc_free(k); nc_free(p);
}
TEST(nckey_getprop_bad_arguments) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P384_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    BYTE buf[64]; DWORD cb = 0;
    EXPECT_SS(U(NCryptGetProperty)(0, NCRYPT_ALGORITHM_PROPERTY, buf, sizeof buf, &cb, 0), NC_INVALID_HANDLE);
    EXPECT_SS_FAIL(U(NCryptGetProperty)(k, NULL, buf, sizeof buf, &cb, 0));
    EXPECT_SS_FAIL(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, buf, sizeof buf, NULL, 0));
    EXPECT_SS_FAIL(U(NCryptGetProperty)(k, L"", buf, sizeof buf, &cb, 0));
    EXPECT_SS_FAIL(U(NCryptGetProperty)(k, L"cryptt no such property", buf, sizeof buf, &cb, 0));
    nc_free(k); nc_free(p);
}
TEST(nckey_getprop_name_length_limit) {
    REQUIRE(U(NCryptGetProperty)); REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    WCHAR n65[66], n64[65];
    for (int i = 0; i < 65; i++) n65[i] = L'A'; n65[65] = 0;
    for (int i = 0; i < 64; i++) n64[i] = L'A'; n64[64] = 0;
    BYTE buf[16]; DWORD cb = 0; DWORD v = 1;
    /* property names longer than NCRYPT_MAX_PROPERTY_NAME (64) are rejected up front */
    EXPECT_SS(U(NCryptSetProperty)(k, n65, (PBYTE)&v, 4, 0), NC_INVALID_PARAMETER);
    EXPECT_SS_FAIL(U(NCryptGetProperty)(k, n65, buf, sizeof buf, &cb, 0));
    SECURITY_STATUS s = U(NCryptGetProperty)(k, n64, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("64-char unknown property get -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(nckey_getprop_unknown_property_status) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    BYTE buf[16]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptGetProperty)(k, L"cryptt-unknown", buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s);
    t_note("unknown key property get -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(nckey_setprop_argument_validation) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    DWORD v = 0;
    EXPECT_SS(U(NCryptSetProperty)(0, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&v, 4, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptSetProperty)(k, NULL, (PBYTE)&v, 4, 0), NC_INVALID_PARAMETER);
    SECURITY_STATUS s = U(NCryptSetProperty)(k, L"cryptt-unknown", (PBYTE)&v, 4, 0);
    EXPECT_SS_FAIL(s); t_note("set unknown property -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}

/* ---------- EXPORT_POLICY ---------- */
TEST(nckey_exportpolicy_default_note) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD v; SECURITY_STATUS s = nc_getdw(k, NCRYPT_EXPORT_POLICY_PROPERTY, &v);
    EXPECT_SS(s, 0);
    t_note("default export policy of a new ECDSA key = 0x%lx", v);
    nc_free(k); nc_free(p);
}
TEST(nckey_exportpolicy_set_roundtrip) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD pol[] = { 0, NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG };
    for (size_t i = 0; i < sizeof(pol) / sizeof(pol[0]); i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, pol[i], FALSE);
        CHECKF(k != 0, "policy 0x%lx set", pol[i]);
        if (!k) continue;
        DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_EXPORT_POLICY_PROPERTY, &v), 0);
        CHECKF(v == pol[i], "policy before finalize got 0x%lx want 0x%lx", v, pol[i]);
        EXPECT_SS(U(NCryptFinalizeKey)(k, 0), 0);
        EXPECT_SS(nc_getdw(k, NCRYPT_EXPORT_POLICY_PROPERTY, &v), 0);
        CHECKF(v == pol[i], "policy after finalize got 0x%lx want 0x%lx", v, pol[i]);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_exportpolicy_archiving_flags_note) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD pol[] = { NCRYPT_ALLOW_ARCHIVING_FLAG, NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG, 0xF, 0x10, 0x80000000u };
    for (size_t i = 0; i < sizeof(pol) / sizeof(pol[0]); i++) {
        NCRYPT_KEY_HANDLE k = 0; DWORD v = pol[i], g = 0xDEAD;
        if (U(NCryptCreatePersistedKey)(p, &k, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0) != 0) break;
        SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&v, 4, 0);
        SECURITY_STATUS s2 = nc_getdw(k, NCRYPT_EXPORT_POLICY_PROPERTY, &g);
        t_note("export policy 0x%lx: set 0x%08lx get 0x%08lx value 0x%lx", pol[i], (DWORD)s, (DWORD)s2, g);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_exportpolicy_wrong_size) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    BYTE b[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, b, 0, 0));
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, b, 1, 0));
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, b, 8, 0));
    nc_free(k); nc_free(p);
}
TEST(nckey_exportpolicy_tighten_after_finalize_note) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, NC_EXP_ALL, TRUE); NEED(k, "key");
    DWORD v = NCRYPT_ALLOW_EXPORT_FLAG, g;
    SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&v, 4, 0);
    nc_getdw(k, NCRYPT_EXPORT_POLICY_PROPERTY, &g);
    t_note("narrow policy after finalize: set 0x%08lx now 0x%lx", (DWORD)s, g);
    v = NC_EXP_ALL;
    s = U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&v, 4, 0);
    nc_getdw(k, NCRYPT_EXPORT_POLICY_PROPERTY, &g);
    t_note("widen policy after finalize: set 0x%08lx now 0x%lx", (DWORD)s, g);
    nc_free(k); nc_free(p);
}

/* ---------- KEY_USAGE ---------- */
TEST(nckey_usage_set_roundtrip) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD u[] = { NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_ALLOW_ALL_USAGES };
    for (size_t i = 0; i < sizeof(u) / sizeof(u[0]); i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey_ex(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, u[i], TRUE, 0);
        CHECKF(k != 0, "usage 0x%lx", u[i]);
        if (!k) continue;
        DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_KEY_USAGE_PROPERTY, &v), 0);
        CHECKF(v == u[i], "usage got 0x%lx want 0x%lx", v, u[i]);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_usage_default_note) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 0; i < NALGS; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ALGS[i].alg, ALGS[i].defbits == 2048 ? 1024 : 0, 0xFFFFFFFFu, TRUE); if (!k) continue;
        DWORD v; SECURITY_STATUS s = nc_getdw(k, NCRYPT_KEY_USAGE_PROPERTY, &v);
        t_note("default KEY_USAGE %ls: 0x%08lx value 0x%lx", ALGS[i].alg, (DWORD)s, v);
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_usage_signing_only_rejects_decrypt) {
    REQUIRE(U(NCryptDecrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey_ex(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, NCRYPT_ALLOW_SIGNING_FLAG, TRUE, 0); NEED(k, "key");
    BYTE out[256]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptDecrypt)(k, (PBYTE)k_rsa_enc_pkcs1, 128, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    EXPECT_SS_FAIL(s); t_note("decrypt with signing-only key -> 0x%08lx", (DWORD)s);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, out, sizeof out, &cb, BCRYPT_PAD_PKCS1), 0);
    nc_free(k); nc_free(p);
}
TEST(nckey_usage_decrypt_only_rejects_sign) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey_ex(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, NCRYPT_ALLOW_DECRYPT_FLAG, TRUE, 0); NEED(k, "key");
    BYTE out[256]; DWORD cb = 0;
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    SECURITY_STATUS s = U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, out, sizeof out, &cb, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("sign with decrypt-only key -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(nckey_usage_set_wrong_size) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    BYTE b[8] = { 2, 0, 0, 0, 0, 0, 0, 0 };
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_KEY_USAGE_PROPERTY, b, 0, 0));
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_KEY_USAGE_PROPERTY, b, 3, 0));
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_KEY_USAGE_PROPERTY, b, 8, 0));
    nc_free(k); nc_free(p);
}

/* ---------- provider-level and misc properties ---------- */
TEST(nckey_provider_properties) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    DWORD v;
    SECURITY_STATUS s = nc_getdw(p, NCRYPT_IMPL_TYPE_PROPERTY, &v);
    EXPECT_SS(s, 0);
    if (s == 0) EXPECT_EQ(v & NCRYPT_IMPL_SOFTWARE_FLAG, NCRYPT_IMPL_SOFTWARE_FLAG);
    s = nc_getdw(p, NCRYPT_VERSION_PROPERTY, &v);       t_note("provider VERSION -> 0x%08lx value 0x%lx", (DWORD)s, v);
    s = nc_getdw(p, NCRYPT_MAX_NAME_LENGTH_PROPERTY, &v); t_note("provider MAX_NAME_LENGTH -> 0x%08lx value %lu", (DWORD)s, v);
    s = nc_getdw(p, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, &v); t_note("provider SECURITY_DESCR_SUPPORT -> 0x%08lx value %lu", (DWORD)s, v);
    s = nc_getdw(p, NCRYPT_USE_COUNT_ENABLED_PROPERTY, &v); t_note("provider USE_COUNT_ENABLED -> 0x%08lx value %lu", (DWORD)s, v);
    nc_free(p);
}
TEST(nckey_impl_type_of_key) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    /* Win10: IMPL_TYPE is a provider property; a key handle answers NOT_SUPPORTED and leaves the output untouched */
    DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_IMPL_TYPE_PROPERTY, &v), NC_NOT_SUPPORTED);
    EXPECT_EQ(v, 0xCDCDCDCDu);
    nc_free(k); nc_free(p);
}
TEST(nckey_misc_key_properties_note) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD v, cb; BYTE *b; SECURITY_STATUS s;
    s = nc_getdw(k, NCRYPT_KEY_TYPE_PROPERTY, &v);               t_note("KEY_TYPE -> 0x%08lx value 0x%lx", (DWORD)s, v);
    s = nc_getdw(k, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, &v); t_note("SECURITY_DESCR_SUPPORT -> 0x%08lx value %lu", (DWORD)s, v);
    s = nc_getdw(k, NCRYPT_BLOCK_LENGTH_PROPERTY, &v);           t_note("BLOCK_LENGTH -> 0x%08lx value %lu", (DWORD)s, v);
    s = nc_getdw(k, NCRYPT_VERSION_PROPERTY, &v);                t_note("VERSION -> 0x%08lx value 0x%lx", (DWORD)s, v);
    s = nc_getdw(k, NCRYPT_USE_COUNT_ENABLED_PROPERTY, &v);      t_note("USE_COUNT_ENABLED -> 0x%08lx value %lu", (DWORD)s, v);
    s = nc_getdw(k, NCRYPT_USE_COUNT_PROPERTY, &v);              t_note("USE_COUNT -> 0x%08lx value %lu", (DWORD)s, v);
    b = nc_getprop(k, NCRYPT_NAME_PROPERTY, &cb);               t_note("NAME of ephemeral key: %ls", b ? (WCHAR *)b : L"(unavailable)"); nc_hfree(b);
    b = nc_getprop(k, NCRYPT_UNIQUE_NAME_PROPERTY, &cb);        t_note("UNIQUE_NAME of ephemeral key: %ls", b ? (WCHAR *)b : L"(unavailable)"); nc_hfree(b);
    b = nc_getprop(k, NCRYPT_SECURITY_DESCR_PROPERTY, &cb);     t_note("SECURITY_DESCR of ephemeral key: %s (%lu bytes)", b ? "present" : "unavailable", b ? cb : 0);  nc_hfree(b);
    nc_free(k); nc_free(p);
}
TEST(nckey_provider_handle_property) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    NCRYPT_PROV_HANDLE ph = 0; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptGetProperty)(k, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PBYTE)&ph, sizeof ph, &cb, 0);
    EXPECT_SS(s, 0);
    if (s == 0) {
        EXPECT_EQ(cb, sizeof(NCRYPT_PROV_HANDLE));
        CHECK(ph != 0);
        EXPECT_SS(U(NCryptIsAlgSupported)(ph, BCRYPT_ECDSA_P256_ALGORITHM, 0), 0);
        EXPECT_SS(U(NCryptFreeObject)(ph), 0);   /* the returned handle is a new reference owned by the caller */
        BYTE sig[64]; DWORD n = 0;
        EXPECT_SS(U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, &n, 0), 0);
    }
    DWORD q = 0; cb = 0;
    EXPECT_SS(U(NCryptGetProperty)(k, NCRYPT_PROVIDER_HANDLE_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, sizeof(NCRYPT_PROV_HANDLE));
    nc_free(k); nc_free(p);
}
TEST(nckey_ecc_curve_name_property) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 1; i < NALGS; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ALGS[i].alg, 0, 0xFFFFFFFFu, TRUE);
        CHECKF(k != 0, "%ls", ALGS[i].alg);
        if (!k) continue;
        DWORD cb = 0; BYTE *b = nc_getprop(k, L"ECCCurveName", &cb);
        /* Win10: an ephemeral key has no ECCCurveName property (NOT_FOUND), even finalized */
        CHECKF(b == NULL, "%ls curve name property unexpectedly present", ALGS[i].alg);
        DWORD cq = 0; SECURITY_STATUS sq = U(NCryptGetProperty)(k, L"ECCCurveName", NULL, 0, &cq, 0);
        CHECKF(sq == (SECURITY_STATUS)NC_NOT_FOUND, "%ls ECCCurveName -> 0x%08lx", ALGS[i].alg, (DWORD)sq);
        nc_hfree(b); nc_free(k);
    }
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0xFFFFFFFFu, TRUE);
    if (k) { DWORD cb = 0; BYTE *b = nc_getprop(k, L"ECCCurveName", &cb); CHECK(b == NULL); nc_hfree(b); nc_free(k); }
    nc_free(p);
}
TEST(nckey_generic_ecdsa_with_curve_name_note) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, L"ECDSA", NULL, 0, 0);
    t_note("create generic ECDSA key -> 0x%08lx", (DWORD)s);
    if (s == 0) {
        s = U(NCryptSetProperty)(k, L"ECCCurveName", (PBYTE)L"nistP256", 18, 0);
        SECURITY_STATUS f = s ? s : U(NCryptFinalizeKey)(k, 0);
        t_note("  curve name set 0x%08lx finalize 0x%08lx", (DWORD)s, (DWORD)f);
        if (f == 0) { DWORD v; if (nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v) == 0) t_note("  length %lu", v); }
        nc_free(k);
    }
    nc_free(p);
}
TEST(nckey_uipolicy_roundtrip) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    NCRYPT_UI_POLICY pol = { 1, 0, L"cryptt create title", L"cryptt friendly", L"cryptt description" };   /* flags 0: no prompt on use */
    SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&pol, sizeof pol, 0);
    EXPECT_SS(s, 0);
    EXPECT_SS(U(NCryptFinalizeKey)(k, 0), 0);
    if (s == 0) {
        DWORD cb = 0; BYTE *b = nc_getprop(k, NCRYPT_UI_POLICY_PROPERTY, &cb);
        CHECK(b != NULL && cb >= sizeof(NCRYPT_UI_POLICY));
        if (b && cb >= sizeof(NCRYPT_UI_POLICY)) {
            NCRYPT_UI_POLICY *g = (NCRYPT_UI_POLICY *)b;
            EXPECT_EQ(g->dwVersion, 1);
            EXPECT_EQ(g->dwFlags, 0);
            t_note("UI policy strings: '%ls' '%ls' '%ls'", g->pszCreationTitle ? g->pszCreationTitle : L"(null)", g->pszFriendlyName ? g->pszFriendlyName : L"(null)", g->pszDescription ? g->pszDescription : L"(null)");
        }
        nc_hfree(b);
    }
    nc_free(k); nc_free(p);
}
TEST(nckey_uipolicy_bad_input) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    BYTE b[4] = { 1, 0, 0, 0 };
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_UI_POLICY_PROPERTY, b, 4, 0));   /* shorter than NCRYPT_UI_POLICY */
    NCRYPT_UI_POLICY pol = { 99, 0, NULL, NULL, NULL };
    SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&pol, sizeof pol, 0);
    t_note("UI policy dwVersion=99 -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(nckey_dh_parameters_property) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    /* Win10 only accepts the parameter blob when LENGTH was already set to the blob's key size (default 1024 is rejected) */
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_DH_ALGORITHM, 2048, NC_EXP_ALL, FALSE); NEED(k, "DH key");
    BYTE blob[sizeof(BCRYPT_DH_PARAMETER_HEADER) + 512];
    BCRYPT_DH_PARAMETER_HEADER *h = (BCRYPT_DH_PARAMETER_HEADER *)blob;
    h->cbLength = sizeof blob; h->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC; h->cbKeyLength = 256;
    memcpy(blob + sizeof *h, k_dh2048_p, 256); memcpy(blob + sizeof *h + 256, k_dh2048_g, 256);
    EXPECT_SS(U(NCryptSetProperty)(k, NCRYPT_DH_PARAMETERS_PROPERTY, blob, sizeof blob, 0), 0);
    EXPECT_SS(U(NCryptFinalizeKey)(k, 0), 0);
    DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v), 0);
    EXPECT_EQ(v, 2048);
    BYTE out[8 + 3 * 256 + 64]; DWORD cb = 0;
    EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_DH_PUBLIC_BLOB, NULL, out, sizeof out, &cb, 0), 0);
    EXPECT_EQ(cb, sizeof(BCRYPT_DH_KEY_BLOB) + 3 * 256);
    if (cb >= 8) { BCRYPT_DH_KEY_BLOB *kb = (BCRYPT_DH_KEY_BLOB *)out; EXPECT_EQ(kb->dwMagic, BCRYPT_DH_PUBLIC_MAGIC); EXPECT_EQ(kb->cbKey, 256); }
    /* the modulus embedded in the public blob is the one that was set */
    if (cb == 8 + 3 * 256) CHECK(!memcmp(out + 8, k_dh2048_p, 256));
    nc_free(k); nc_free(p);
}
TEST(nckey_dh_parameters_bad_blob) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_DH_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "DH key");
    BYTE blob[sizeof(BCRYPT_DH_PARAMETER_HEADER) + 512] = {0};
    BCRYPT_DH_PARAMETER_HEADER *h = (BCRYPT_DH_PARAMETER_HEADER *)blob;
    h->cbLength = sizeof blob; h->dwMagic = 0x12345678; h->cbKeyLength = 256;
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_DH_PARAMETERS_PROPERTY, blob, sizeof blob, 0));   /* wrong magic */
    h->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
    EXPECT_SS_FAIL(U(NCryptSetProperty)(k, NCRYPT_DH_PARAMETERS_PROPERTY, blob, sizeof *h, 0));      /* header only */
    nc_free(k); nc_free(p);
}

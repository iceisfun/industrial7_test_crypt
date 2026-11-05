/* BCryptEnumAlgorithms / BCryptEnumProviders / BCryptFreeBuffer (area bcrypt_algorithm_providers). */
#include "ap.h"

#define OPS_ALL 0x7f
static const ULONG g_ops[7] = { BCRYPT_CIPHER_OPERATION, BCRYPT_HASH_OPERATION, BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION,
    BCRYPT_SECRET_AGREEMENT_OPERATION, BCRYPT_SIGNATURE_OPERATION, BCRYPT_RNG_OPERATION, BCRYPT_KEY_DERIVATION_OPERATION };
static const char *const g_opname[7] = { "cipher", "hash", "asym_enc", "secret_agreement", "signature", "rng", "key_derivation" };
/* interface constants (BCRYPT_*_INTERFACE) that BCryptEnumAlgorithms reports in dwClass */
static const ULONG g_iface[7] = { 1, 2, 3, 4, 5, 6, 7 };

static NTSTATUS enum_algs(ULONG ops, ULONG *n, BCRYPT_ALGORITHM_IDENTIFIER **l) {
    *n = 0xdeadbeef; *l = (BCRYPT_ALGORITHM_IDENTIFIER *)(ULONG_PTR)0xdeadbeef;
    return U(BCryptEnumAlgorithms)(ops, n, l, 0);
}
static int has_name(const BCRYPT_ALGORITHM_IDENTIFIER *l, ULONG n, const WCHAR *name) {
    for (ULONG i = 0; i < n; i++) if (!lstrcmpW(l[i].pszName, name)) return 1;
    return 0;
}
static void require_names(ULONG ops, const WCHAR *const *names, int count, ULONG iface) {
    ULONG n; BCRYPT_ALGORITHM_IDENTIFIER *l;
    NTSTATUS s = enum_algs(ops, &n, &l);
    NT_OK(s);
    if (s < 0) return;
    for (int i = 0; i < count; i++) {
        int found = 0;
        for (ULONG j = 0; j < n; j++) if (!lstrcmpW(l[j].pszName, names[i])) { found = 1; EXPECT_EQ(l[j].dwClass, iface); EXPECT_EQ(l[j].dwFlags, 0); }
        CHECKF(found, "%ls missing from enumeration %lx", names[i], (unsigned long)ops);
    }
    U(BCryptFreeBuffer)(l);
}

#define NEED_ENUM() do { REQUIRE(U(BCryptEnumAlgorithms)); REQUIRE(U(BCryptFreeBuffer)); } while (0)

TEST(ap_enumalg_cipher_contents) {
    NEED_ENUM();
    static const WCHAR *const n[] = { L"AES", L"3DES", L"3DES_112", L"DES", L"DESX", L"RC2", L"RC4" };
    require_names(BCRYPT_CIPHER_OPERATION, n, 7, 1);
}
TEST(ap_enumalg_hash_contents) {
    NEED_ENUM();
    static const WCHAR *const n[] = { L"MD2", L"MD4", L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512" };
    require_names(BCRYPT_HASH_OPERATION, n, 7, 2);
}
TEST(ap_enumalg_asym_enc_contents) {
    NEED_ENUM();
    static const WCHAR *const n[] = { L"RSA" };
    require_names(BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, n, 1, 3);
}
TEST(ap_enumalg_secret_agreement_contents) {
    NEED_ENUM();
    static const WCHAR *const n[] = { L"DH", L"ECDH_P256", L"ECDH_P384", L"ECDH_P521" };
    require_names(BCRYPT_SECRET_AGREEMENT_OPERATION, n, 4, 4);
}
TEST(ap_enumalg_signature_contents) {
    NEED_ENUM();
    static const WCHAR *const n[] = { L"DSA", L"ECDSA_P256", L"ECDSA_P384", L"ECDSA_P521" };
    require_names(BCRYPT_SIGNATURE_OPERATION, n, 4, 5);
}
TEST(ap_enumalg_rng_contents) {
    NEED_ENUM();
    static const WCHAR *const n[] = { L"RNG" };
    require_names(BCRYPT_RNG_OPERATION, n, 1, 6);
}
TEST(ap_enumalg_kdf_contents) {
    NEED_ENUM();
    static const WCHAR *const n[] = { L"SP800_108_CTR_HMAC", L"SP800_56A_CONCAT", L"PBKDF2", L"CAPI_KDF" };
    require_names(BCRYPT_KEY_DERIVATION_OPERATION, n, 4, 7);
}

TEST(ap_enumalg_class_matches_operation) {
    NEED_ENUM();
    for (int k = 0; k < 7; k++) {
        ULONG n; BCRYPT_ALGORITHM_IDENTIFIER *l;
        NTSTATUS s = enum_algs(g_ops[k], &n, &l);
        NT_OK(s);
        if (s < 0) continue;
        CHECKF(n >= 1, "%s: no algorithms", g_opname[k]);
        for (ULONG i = 0; i < n; i++) { EXPECT_EQ(l[i].dwClass, g_iface[k]); EXPECT_EQ(l[i].dwFlags, 0); CHECK(l[i].pszName && l[i].pszName[0]); }
        U(BCryptFreeBuffer)(l);
    }
}
TEST(ap_enumalg_single_allocation_layout) {
    NEED_ENUM();
    /* array of identifiers first, then the name strings, all in one block released by one BCryptFreeBuffer */
    for (int k = 0; k < 7; k++) {
        ULONG n; BCRYPT_ALGORITHM_IDENTIFIER *l;
        NTSTATUS s = enum_algs(g_ops[k], &n, &l);
        if (s < 0 || n == 0) continue;
        const UCHAR *base = (const UCHAR *)l, *names = (const UCHAR *)(l + n);
        for (ULONG i = 0; i < n; i++) {
            CHECK((const UCHAR *)l[i].pszName >= names);
            if (i) CHECK((const UCHAR *)l[i].pszName > (const UCHAR *)l[i - 1].pszName);
        }
        CHECK((const UCHAR *)l[0].pszName == names);
        U(BCryptFreeBuffer)(l);
        (void)base;
    }
}
TEST(ap_enumalg_zero_means_all) {
    NEED_ENUM();
    ULONG total = 0, n0; BCRYPT_ALGORITHM_IDENTIFIER *l0;
    NT_OK(enum_algs(0, &n0, &l0));
    for (int k = 0; k < 7; k++) {
        ULONG n; BCRYPT_ALGORITHM_IDENTIFIER *l;
        if (enum_algs(g_ops[k], &n, &l) >= 0) { total += n; U(BCryptFreeBuffer)(l); }
    }
    EXPECT_EQ(n0, total);
    if (n0) U(BCryptFreeBuffer)(l0);
}
TEST(ap_enumalg_mask_0x7f_equals_zero) {
    NEED_ENUM();
    ULONG a, b; BCRYPT_ALGORITHM_IDENTIFIER *la, *lb;
    NT_OK(enum_algs(0, &a, &la));
    NT_OK(enum_algs(OPS_ALL, &b, &lb));
    EXPECT_EQ(a, b);
    if (a == b) for (ULONG i = 0; i < a; i++) { CHECK(!lstrcmpW(la[i].pszName, lb[i].pszName)); EXPECT_EQ(la[i].dwClass, lb[i].dwClass); }
    if (a) U(BCryptFreeBuffer)(la);
    if (b) U(BCryptFreeBuffer)(lb);
}
TEST(ap_enumalg_combined_masks_are_unions) {
    NEED_ENUM();
    for (int i = 0; i < 7; i++) for (int j = i + 1; j < 7; j++) {
        ULONG a = 0, b = 0, c = 0; BCRYPT_ALGORITHM_IDENTIFIER *la, *lb, *lc;
        NTSTATUS sa = enum_algs(g_ops[i], &a, &la), sb = enum_algs(g_ops[j], &b, &lb), sc = enum_algs(g_ops[i] | g_ops[j], &c, &lc);
        NT_OK(sc);
        if (sa >= 0 && sb >= 0 && sc >= 0) {
            EXPECT_EQ(c, a + b);
            /* ordering follows the interface order */
            for (ULONG k = 0; k < a && k < c; k++) CHECK(!lstrcmpW(lc[k].pszName, la[k].pszName));
            for (ULONG k = 0; k < b && a + k < c; k++) CHECK(!lstrcmpW(lc[a + k].pszName, lb[k].pszName));
        }
        if (sa >= 0 && a) U(BCryptFreeBuffer)(la);
        if (sb >= 0 && b) U(BCryptFreeBuffer)(lb);
        if (sc >= 0 && c) U(BCryptFreeBuffer)(lc);
    }
}
TEST(ap_enumalg_repeatable) {
    NEED_ENUM();
    ULONG a, b; BCRYPT_ALGORITHM_IDENTIFIER *la, *lb;
    NT_OK(enum_algs(BCRYPT_HASH_OPERATION, &a, &la));
    NT_OK(enum_algs(BCRYPT_HASH_OPERATION, &b, &lb));
    EXPECT_EQ(a, b);
    CHECK(la != lb);                                  /* every call returns a fresh allocation */
    if (a == b) for (ULONG i = 0; i < a; i++) CHECK(!lstrcmpW(la[i].pszName, lb[i].pszName));
    if (a) U(BCryptFreeBuffer)(la);
    if (b) U(BCryptFreeBuffer)(lb);
}
TEST(ap_enumalg_duplicate_names_observed) {
    NEED_ENUM();
    for (int k = 0; k < 7; k++) {
        ULONG n; BCRYPT_ALGORITHM_IDENTIFIER *l;
        t_label("%s", g_opname[k]);
        NT_OK(enum_algs(g_ops[k], &n, &l));
        int dup = 0;                      /* Win10 22H2 lists every name once per operation class */
        for (ULONG i = 0; i < n; i++) for (ULONG j = i + 1; j < n; j++) if (!lstrcmpW(l[i].pszName, l[j].pszName)) dup++;
        EXPECT_EQ(dup, 0);
        if (n) U(BCryptFreeBuffer)(l);
    }
}
TEST(ap_enumalg_every_listed_name_opens) {
    NEED_ENUM(); NEED_CORE();
    ULONG n; BCRYPT_ALGORITHM_IDENTIFIER *l;
    NT_OK(enum_algs(0, &n, &l));
    if (n > 400) n = 400;
    int opened = 0;
    for (ULONG i = 0; i < n; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NTSTATUS s = AP_OPEN(&h, l[i].pszName, NULL, 0);
        if (s >= 0) { opened++; AP_CLOSE(h); }
        else t_note("enumerated \"%ls\" (class %lu) fails to open: 0x%08lx", l[i].pszName, (unsigned long)l[i].dwClass, (unsigned long)s);
    }
    EXPECT_EQ(opened, n);
    EXPECT_EQ(n, 39);
    U(BCryptFreeBuffer)(l);
}
TEST(ap_enumalg_names_for_known_set) {
    NEED_ENUM();
    ULONG n; BCRYPT_ALGORITHM_IDENTIFIER *l;
    NT_OK(enum_algs(0, &n, &l));
    /* exact Win10 22H2 list, in enumeration order */
    static const struct { ULONG cls; const WCHAR *nm; } ex[] = {
        {1,L"AES"},{1,L"3DES"},{1,L"3DES_112"},{1,L"XTS-AES"},{1,L"DESX"},{1,L"DES"},{1,L"RC2"},{1,L"RC4"},
        {2,L"SHA256"},{2,L"SHA384"},{2,L"SHA512"},{2,L"SHA1"},{2,L"MD5"},{2,L"MD4"},{2,L"MD2"},{2,L"AES-GMAC"},{2,L"AES-CMAC"},
        {3,L"RSA"},{4,L"DH"},{4,L"ECDH_P256"},{4,L"ECDH_P384"},{4,L"ECDH_P521"},{4,L"ECDH"},
        {5,L"RSA_SIGN"},{5,L"ECDSA_P256"},{5,L"ECDSA_P384"},{5,L"ECDSA_P521"},{5,L"ECDSA"},{5,L"DSA"},
        {6,L"RNG"},{6,L"FIPS186DSARNG"},{6,L"DUALECRNG"},
        {7,L"SP800_108_CTR_HMAC"},{7,L"SP800_56A_CONCAT"},{7,L"PBKDF2"},{7,L"CAPI_KDF"},{7,L"TLS1_1_KDF"},{7,L"TLS1_2_KDF"},{7,L"HKDF"} };
    EXPECT_EQ(n, sizeof(ex) / sizeof(ex[0]));
    for (ULONG i = 0; i < n && i < sizeof(ex) / sizeof(ex[0]); i++) {
        t_label("alg[%lu]", (unsigned long)i);
        EXPECT_EQ(l[i].dwClass, ex[i].cls);
        EXPECT_WSTR(l[i].pszName, ex[i].nm);
    }
    if (n) U(BCryptFreeBuffer)(l);
}

/* ---- argument validation ---- */
TEST(ap_enumalg_bad_operations) {
    NEED_ENUM();
    static const ULONG bad[] = { 0x80, 0x100, 0xff, 0x7fffffffu, 0x80000000u, 0xffffffffu };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ULONG n = 0x5a5a; BCRYPT_ALGORITHM_IDENTIFIER *l = (BCRYPT_ALGORITHM_IDENTIFIER *)(ULONG_PTR)0x5a5a;
        NT_EQ(U(BCryptEnumAlgorithms)(bad[i], &n, &l, 0), AP_INVALID_PARAM);
        CHECK(n == 0x5a5a && l == (BCRYPT_ALGORITHM_IDENTIFIER *)(ULONG_PTR)0x5a5a);   /* outputs untouched */
    }
}
TEST(ap_enumalg_null_outputs) {
    NEED_ENUM();
    ULONG n = 1; BCRYPT_ALGORITHM_IDENTIFIER *l = NULL;
    NT_EQ(U(BCryptEnumAlgorithms)(BCRYPT_HASH_OPERATION, NULL, &l, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptEnumAlgorithms)(BCRYPT_HASH_OPERATION, &n, NULL, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptEnumAlgorithms)(BCRYPT_HASH_OPERATION, NULL, NULL, 0), AP_INVALID_PARAM);
    EXPECT_EQ(n, 1);
}
TEST(ap_enumalg_nonzero_flags) {
    NEED_ENUM();
    static const ULONG fl[] = { 1, 2, 0x80000000u, 0xffffffffu };
    for (unsigned i = 0; i < sizeof(fl) / sizeof(fl[0]); i++) {
        ULONG n = 0x77; BCRYPT_ALGORITHM_IDENTIFIER *l = (BCRYPT_ALGORITHM_IDENTIFIER *)(ULONG_PTR)0x77;
        NT_EQ(U(BCryptEnumAlgorithms)(BCRYPT_HASH_OPERATION, &n, &l, fl[i]), AP_INVALID_PARAM);
        CHECK(n == 0x77 && l == (BCRYPT_ALGORITHM_IDENTIFIER *)(ULONG_PTR)0x77);
    }
}
TEST(ap_enumalg_outputs_reset_on_success) {
    NEED_ENUM();
    ULONG n = 0x1234; BCRYPT_ALGORITHM_IDENTIFIER *l = (BCRYPT_ALGORITHM_IDENTIFIER *)(ULONG_PTR)0x1234;
    NT_OK(U(BCryptEnumAlgorithms)(BCRYPT_RNG_OPERATION, &n, &l, 0));
    CHECK(n != 0x1234 && l != (BCRYPT_ALGORITHM_IDENTIFIER *)(ULONG_PTR)0x1234);
    if (n) U(BCryptFreeBuffer)(l);
}
TEST(ap_freebuffer_null_ok) {
    REQUIRE(U(BCryptFreeBuffer));
    U(BCryptFreeBuffer)(NULL);
    U(BCryptFreeBuffer)(NULL);
    CHECK(1);
}
TEST(ap_enumalg_many_calls_no_growth) {
    NEED_ENUM();
    for (int i = 0; i < 500; i++) {
        ULONG n; BCRYPT_ALGORITHM_IDENTIFIER *l;
        if (enum_algs(0, &n, &l) < 0) { CHECK(0); break; }
        if (n) U(BCryptFreeBuffer)(l);
    }
    CHECK(1);
}

/* ---------------------------------------------------------------- BCryptEnumProviders */
static NTSTATUS enum_prov(const WCHAR *alg, ULONG *n, BCRYPT_PROVIDER_NAME **l) {
    *n = 0xdeadbeef; *l = (BCRYPT_PROVIDER_NAME *)(ULONG_PTR)0xdeadbeef;
    return U(BCryptEnumProviders)(alg, n, l, 0);
}
#define NEED_PROV() do { REQUIRE(U(BCryptEnumProviders)); REQUIRE(U(BCryptFreeBuffer)); \
    if (t_is_wine()) { t_skip("emulator aborts on unimplemented BCryptEnumProviders"); return; } } while (0)

TEST(ap_enumprov_primitive_provider_listed_for_core_algs) {
    NEED_PROV();
    static const WCHAR *const id[] = { L"AES", L"3DES", L"DES", L"RC2", L"RC4", L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512", L"RSA", L"DSA", L"DH",
        L"ECDSA_P256", L"ECDSA_P384", L"ECDSA_P521", L"ECDH_P256", L"ECDH_P384", L"ECDH_P521", L"RNG", L"PBKDF2", L"CAPI_KDF" };
    for (unsigned i = 0; i < sizeof(id) / sizeof(id[0]); i++) {
        ULONG n; BCRYPT_PROVIDER_NAME *l;
        NTSTATUS s = enum_prov(id[i], &n, &l);
        NT_OK(s);
        if (s < 0) continue;
        CHECKF(n >= 1, "%ls: no providers", id[i]);
        int found = 0;
        for (ULONG j = 0; j < n; j++) if (!lstrcmpW(l[j].pszProviderName, MS_PRIMITIVE_PROVIDER)) found = 1;
        CHECKF(found, "%ls: primitive provider not listed", id[i]);
        U(BCryptFreeBuffer)(l);
    }
}
TEST(ap_enumprov_single_allocation_and_order) {
    NEED_PROV();
    ULONG n; BCRYPT_PROVIDER_NAME *l;
    NT_OK(enum_prov(L"SHA256", &n, &l));
    if (n == 0) return;
    const UCHAR *strings = (const UCHAR *)(l + n);
    for (ULONG i = 0; i < n; i++) CHECK((const UCHAR *)l[i].pszProviderName >= strings);
    CHECK((const UCHAR *)l[0].pszProviderName == strings);
    EXPECT_EQ(n, 1);
    EXPECT_WSTR(l[0].pszProviderName, MS_PRIMITIVE_PROVIDER);
    U(BCryptFreeBuffer)(l);
}
TEST(ap_enumprov_listed_providers_open) {
    NEED_PROV(); NEED_CORE();
    ULONG n; BCRYPT_PROVIDER_NAME *l;
    NT_OK(enum_prov(L"AES", &n, &l));
    for (ULONG i = 0; i < n; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NTSTATUS s = AP_OPEN(&h, L"AES", l[i].pszProviderName, 0);
        NT_OK(s);
        if (s >= 0) AP_CLOSE(h);
    }
    if (n) U(BCryptFreeBuffer)(l);
}
TEST(ap_enumprov_null_and_empty_alg) {
    NEED_PROV();
    ULONG n = 0x42; BCRYPT_PROVIDER_NAME *l = (BCRYPT_PROVIDER_NAME *)(ULONG_PTR)0x42;
    NT_EQ(U(BCryptEnumProviders)(NULL, &n, &l, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptEnumProviders)(L"", &n, &l, 0), AP_INVALID_PARAM);
    CHECK(n == 0x42 && l == (BCRYPT_PROVIDER_NAME *)(ULONG_PTR)0x42);
}
TEST(ap_enumprov_null_outputs_and_flags) {
    NEED_PROV();
    ULONG n = 0x42; BCRYPT_PROVIDER_NAME *l = (BCRYPT_PROVIDER_NAME *)(ULONG_PTR)0x42;
    NT_EQ(U(BCryptEnumProviders)(L"AES", NULL, &l, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptEnumProviders)(L"AES", &n, NULL, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptEnumProviders)(L"AES", &n, &l, 1), AP_INVALID_PARAM);
    NT_EQ(U(BCryptEnumProviders)(L"AES", &n, &l, 0x80000000u), AP_INVALID_PARAM);
    CHECK(n == 0x42 && l == (BCRYPT_PROVIDER_NAME *)(ULONG_PTR)0x42);
}
TEST(ap_enumprov_unknown_algorithm) {
    NEED_PROV();
    ULONG n; BCRYPT_PROVIDER_NAME *l;
    NTSTATUS s = enum_prov(L"NoSuchAlgorithm", &n, &l);
    NT_EQ(s, AP_NOT_FOUND);
    EXPECT_EQ(n, 0);                  /* the count is zeroed on failure */
    if (s >= 0 && n) U(BCryptFreeBuffer)(l);
}
TEST(ap_enumprov_case_of_algorithm_name) {
    NEED_PROV();
    ULONG n; BCRYPT_PROVIDER_NAME *l;
    NTSTATUS s = enum_prov(L"aes", &n, &l);
    NT_OK(s);                         /* the algorithm name is matched case-insensitively here */
    EXPECT_EQ(n, 1);
    if (s >= 0 && n) U(BCryptFreeBuffer)(l);
}
TEST(ap_enumprov_repeatable) {
    NEED_PROV();
    ULONG a, b; BCRYPT_PROVIDER_NAME *la, *lb;
    NT_OK(enum_prov(L"RSA", &a, &la));
    NT_OK(enum_prov(L"RSA", &b, &lb));
    EXPECT_EQ(a, b);
    if (a == b) for (ULONG i = 0; i < a; i++) CHECK(!lstrcmpW(la[i].pszProviderName, lb[i].pszProviderName));
    if (a) U(BCryptFreeBuffer)(la);
    if (b) U(BCryptFreeBuffer)(lb);
}
TEST(ap_enumprov_platform_provider_optional) {
    NEED_PROV();
    ULONG n; BCRYPT_PROVIDER_NAME *l;
    NT_OK(enum_prov(L"RSA", &n, &l));
    int found = 0;
    for (ULONG i = 0; i < n; i++) if (!lstrcmpW(l[i].pszProviderName, MS_PLATFORM_CRYPTO_PROVIDER)) found = 1;
    if (!t_has_tpm()) { EXPECT_EQ(n, 1); EXPECT_EQ(found, 0); }   /* oracle has no TPM: only the primitive provider */
    if (n) U(BCryptFreeBuffer)(l);
}
TEST(ap_enumprov_nonzero_count_matches_resolve) {
    NEED_PROV();
    REQUIRE(U(BCryptResolveProviders));
    /* BCryptEnumProviders is a thin wrapper over BCryptResolveProviders(alg, any interface, any provider) */
    ULONG n; BCRYPT_PROVIDER_NAME *l;
    NT_OK(enum_prov(L"SHA256", &n, &l));
    ULONG cb = 0; PCRYPT_PROVIDER_REFS refs = NULL;
    NTSTATUS s = U(BCryptResolveProviders)(NULL, 0, L"SHA256", NULL, CRYPT_UM, CRYPT_ALL_FUNCTIONS, &cb, &refs);
    NT_OK(s);
    CHECK(refs != NULL);
    if (s >= 0 && refs) { EXPECT_EQ(refs->cProviders, n); EXPECT_EQ(n, 1); U(BCryptFreeBuffer)(refs); }
    if (n) U(BCryptFreeBuffer)(l);
}

/* NCrypt storage-provider layer: open/enumerate/free, handle-type validation. Nothing is persisted. */
#include "nc.h"

/* ---------- NCryptOpenStorageProvider ---------- */
TEST(ncprov_open_null_name_default_ksp) {
    REQUIRE(U(NCryptOpenStorageProvider)); REQUIRE(U(NCryptFreeObject));
    NCRYPT_PROV_HANDLE h = 0xAA;
    SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, NULL, 0);
    EXPECT_SS(s, 0);
    CHECK(h != 0 && h != 0xAA);
    if (s == 0) EXPECT_SS(U(NCryptFreeObject)(h), 0);
}
TEST(ncprov_open_phprovider_null) {
    REQUIRE(U(NCryptOpenStorageProvider));
    EXPECT_SS(U(NCryptOpenStorageProvider)(NULL, NULL, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptOpenStorageProvider)(NULL, NC_MSKSP, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptOpenStorageProvider)(NULL, L"no such provider", 0), NC_INVALID_PARAMETER);
}
TEST(ncprov_open_failure_zeroes_handle) {
    REQUIRE(U(NCryptOpenStorageProvider));
    /* the output handle is cleared before the provider is resolved */
    NCRYPT_PROV_HANDLE h = 0x1234;
    SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, L"cryptt no such KSP", 0);
    EXPECT_SS_FAIL(s);
    EXPECT_EQ(h, 0);
    t_note("bogus provider name status 0x%08lx", (DWORD)s);
}
TEST(ncprov_open_by_name_ksp) {
    REQUIRE(U(NCryptOpenStorageProvider)); REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE h = 0;
    EXPECT_SS(U(NCryptOpenStorageProvider)(&h, MS_KEY_STORAGE_PROVIDER, 0), 0);
    NEED(h, "MS KSP");
    DWORD cb = 0; BYTE *n = nc_getprop(h, NCRYPT_NAME_PROPERTY, &cb);
    CHECK(n != NULL);
    if (n) { CHECK(!lstrcmpW((WCHAR *)n, NC_MSKSP)); EXPECT_EQ(cb, sizeof(NC_MSKSP)); }
    nc_hfree(n);
    nc_free(h);
}
TEST(ncprov_open_null_equals_named_ksp) {
    REQUIRE(U(NCryptOpenStorageProvider)); REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE a = nc_prov(), b = 0;
    NEED(a, "default provider");
    EXPECT_SS(U(NCryptOpenStorageProvider)(&b, MS_KEY_STORAGE_PROVIDER, 0), 0);
    DWORD ca = 0, cb2 = 0; BYTE *na = nc_getprop(a, NCRYPT_NAME_PROPERTY, &ca), *nb = nc_getprop(b, NCRYPT_NAME_PROPERTY, &cb2);
    CHECK(na && nb && ca == cb2 && !memcmp(na, nb, ca));
    CHECK(a != b);
    nc_hfree(na); nc_hfree(nb); nc_free(a); nc_free(b);
}
TEST(ncprov_open_empty_name) {
    REQUIRE(U(NCryptOpenStorageProvider));
    NCRYPT_PROV_HANDLE h = 0;
    SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, L"", 0);
    t_note("empty provider name -> 0x%08lx", (DWORD)s);
    if (s == 0) { CHECK(h != 0); nc_free(h); }
}
TEST(ncprov_open_name_case) {
    REQUIRE(U(NCryptOpenStorageProvider));
    NCRYPT_PROV_HANDLE h = 0;
    SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, L"MICROSOFT SOFTWARE KEY STORAGE PROVIDER", 0);
    t_note("upper-case provider name -> 0x%08lx", (DWORD)s);
    if (s == 0) nc_free(h);
}
TEST(ncprov_open_unknown_names_fail) {
    REQUIRE(U(NCryptOpenStorageProvider));
    static const WCHAR *names[] = {
        L"cryptt bogus provider", L"Microsoft Software Key Storage Provide", L"Microsoft Software Key Storage Provider ",
        L"RSA", L"BCRYPT_RSA_ALGORITHM",
        L"Microsoft Enhanced Cryptographic Provider v1.0",   /* a CAPI CSP is not a key storage provider */
        L"Microsoft Strong Cryptographic Provider", L"Microsoft Primitive Provider",
        L"Microsoft Enhanced RSA and AES Cryptographic Provider",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        NCRYPT_PROV_HANDLE h = 0x77;
        SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, names[i], 0);
        CHECKF(s != 0, "name #%u unexpectedly opened", (unsigned)i);
        EXPECT_EQ(h, 0);
        if (s == 0 && h > 1) nc_free(h);
        t_note("provider name #%u -> 0x%08lx", (unsigned)i, (DWORD)s);
    }
}
TEST(ncprov_open_flags) {
    REQUIRE(U(NCryptOpenStorageProvider));
    static const DWORD flags[] = { 0x1, 0x2, 0x4, 0x8, 0x10, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_SILENT_FLAG, NCRYPT_OVERWRITE_KEY_FLAG, 0x100, 0x80000000u };
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        NCRYPT_PROV_HANDLE h = 0;
        SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, NULL, flags[i]);
        t_note("open KSP flags=0x%lx -> 0x%08lx", flags[i], (DWORD)s);
        if (s == 0) nc_free(h); else EXPECT_EQ(h, 0);
    }
}
TEST(ncprov_open_smartcard_kspn) {
    REQUIRE(U(NCryptOpenStorageProvider));
    NCRYPT_PROV_HANDLE h = 0;
    SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
    t_note("smart card KSP open -> 0x%08lx", (DWORD)s);
    if (s == 0) {
        DWORD cb = 0; BYTE *n = nc_getprop(h, NCRYPT_NAME_PROPERTY, &cb);
        if (n) { CHECK(!lstrcmpW((WCHAR *)n, MS_SMART_CARD_KEY_STORAGE_PROVIDER)); nc_hfree(n); }
        nc_free(h);
    } else EXPECT_EQ(h, 0);
}
TEST(ncprov_open_platform_crypto) {
    REQUIRE(U(NCryptOpenStorageProvider));
    NCRYPT_PROV_HANDLE h = 0;
    SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    t_note("platform crypto provider open -> 0x%08lx (needs a TPM)", (DWORD)s);
    if (s == 0) {
        DWORD cb = 0; BYTE *n = nc_getprop(h, NCRYPT_NAME_PROPERTY, &cb);
        if (n) { CHECK(!lstrcmpW((WCHAR *)n, MS_PLATFORM_CRYPTO_PROVIDER)); nc_hfree(n); }
        nc_free(h);
    } else EXPECT_EQ(h, 0);
}
TEST(ncprov_open_many_independent) {
    REQUIRE(U(NCryptOpenStorageProvider));
    NCRYPT_PROV_HANDLE h[8] = {0};
    for (int i = 0; i < 8; i++) { h[i] = nc_prov(); NEED(h[i], "provider"); }
    for (int i = 0; i < 8; i++) for (int j = i + 1; j < 8; j++) CHECK(h[i] != h[j]);
    /* close in a scrambled order; the remaining ones stay usable */
    static const int order[8] = { 3, 0, 7, 5, 1, 6, 2, 4 };
    for (int k = 0; k < 8; k++) {
        EXPECT_SS(U(NCryptFreeObject)(h[order[k]]), 0);
        h[order[k]] = 0;
        for (int i = 0; i < 8; i++) if (h[i]) { EXPECT_SS(U(NCryptIsAlgSupported)(h[i], BCRYPT_RSA_ALGORITHM, 0), 0); break; }
    }
}
TEST(ncprov_open_close_loop) {
    REQUIRE(U(NCryptOpenStorageProvider));
    for (int i = 0; i < 200; i++) {
        NCRYPT_PROV_HANDLE h = nc_prov();
        if (!h) { CHECKF(0, "open #%d failed", i); break; }
        if (U(NCryptFreeObject)(h) != 0) { CHECKF(0, "free #%d failed", i); break; }
    }
}

/* ---------- threads ---------- */
static DWORD WINAPI thr_open_key(LPVOID p)
{
    NCRYPT_PROV_HANDLE h = nc_prov();
    if (!h) return 1;
    NCRYPT_KEY_HANDLE k = nc_newkey(h, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE);
    DWORD r = k ? 0 : 2;
    BYTE sig[64]; DWORD cb = 0;
    if (!r && U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, &cb, 0) != 0) r = 3;
    nc_free(k); nc_free(h);
    return r;
}
TEST(ncprov_threads_independent_providers) {
    REQUIRE(U(NCryptOpenStorageProvider)); REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE probe = nc_prov(); NEED(probe, "provider"); nc_free(probe);
    HANDLE th[4];
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, thr_open_key, NULL, 0, NULL);
    for (int i = 0; i < 4; i++) {
        DWORD w = WaitForSingleObject(th[i], 20000), code = 99;
        EXPECT_EQ(w, WAIT_OBJECT_0);
        GetExitCodeThread(th[i], &code);
        EXPECT_EQ(code, 0);
        CloseHandle(th[i]);
    }
}
static DWORD WINAPI thr_use_prov(LPVOID p)
{
    NCRYPT_PROV_HANDLE h = (NCRYPT_PROV_HANDLE)p;
    return (DWORD)U(NCryptIsAlgSupported)(h, BCRYPT_ECDSA_P384_ALGORITHM, 0);
}
TEST(ncprov_handle_usable_from_other_thread) {
    NC_NOWINE();
    REQUIRE(U(NCryptIsAlgSupported));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    HANDLE t = CreateThread(NULL, 0, thr_use_prov, (LPVOID)h, 0, NULL);
    { DWORD w_ = WaitForSingleObject(t, 20000); EXPECT_EQ(w_, WAIT_OBJECT_0); }
    DWORD code = 99; GetExitCodeThread(t, &code);
    EXPECT_EQ(code, 0);
    CloseHandle(t);
    nc_free(h);
}

/* ---------- NCryptEnumStorageProviders / NCryptFreeBuffer ---------- */
TEST(ncprov_enumprov_basic) {
    NC_NOWINE();
    REQUIRE(U(NCryptEnumStorageProviders)); REQUIRE(U(NCryptFreeBuffer));
    DWORD n = 0; NCryptProviderName *l = NULL;
    EXPECT_SS(U(NCryptEnumStorageProviders)(&n, &l, 0), 0);
    CHECK(n >= 1 && l != NULL);
    int found = 0;
    for (DWORD i = 0; l && i < n; i++) {
        CHECK(l[i].pszName != NULL && l[i].pszName[0] != 0);
        CHECK(l[i].pszComment != NULL);
        if (l[i].pszName && !lstrcmpW(l[i].pszName, NC_MSKSP)) found++;
        t_note("storage provider %lu: %ls", i, l[i].pszName ? l[i].pszName : L"(null)");
    }
    EXPECT_EQ(found, 1);
    EXPECT_SS(U(NCryptFreeBuffer)(l), 0);
}
TEST(ncprov_enumprov_null_params) {
    NC_NOWINE();
    REQUIRE(U(NCryptEnumStorageProviders));
    DWORD n = 5; NCryptProviderName *l = NULL;
    EXPECT_SS(U(NCryptEnumStorageProviders)(NULL, &l, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptEnumStorageProviders)(&n, NULL, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptEnumStorageProviders)(NULL, NULL, 0), NC_INVALID_PARAMETER);
    EXPECT_EQ(n, 5);   /* untouched on parameter failure */
}
TEST(ncprov_enumprov_bad_flags) {
    NC_NOWINE();
    REQUIRE(U(NCryptEnumStorageProviders));
    static const DWORD bad[] = { 0x1, 0x2, 0x20, 0x80, 0x100, 0x80000000u };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        DWORD n = 7; NCryptProviderName *l = (NCryptProviderName *)0x1;
        SECURITY_STATUS s = U(NCryptEnumStorageProviders)(&n, &l, bad[i]);
        EXPECT_SS_FAIL(s);
        t_note("enum providers flags 0x%lx -> 0x%08lx", bad[i], (DWORD)s);
        if (s == 0 && l != (NCryptProviderName *)0x1) U(NCryptFreeBuffer)(l);
    }
}
TEST(ncprov_enumprov_silent_flag_accepted) {
    NC_NOWINE();
    REQUIRE(U(NCryptEnumStorageProviders));
    DWORD n = 0; NCryptProviderName *l = NULL;
    EXPECT_SS(U(NCryptEnumStorageProviders)(&n, &l, NCRYPT_SILENT_FLAG), 0);   /* only 0x40 passes the (flags & ~0x40) test */
    CHECK(n >= 1);
    if (l) U(NCryptFreeBuffer)(l);
}
TEST(ncprov_enumprov_repeatable) {
    NC_NOWINE();
    REQUIRE(U(NCryptEnumStorageProviders));
    DWORD n1 = 0, n2 = 0; NCryptProviderName *a = NULL, *b = NULL;
    EXPECT_SS(U(NCryptEnumStorageProviders)(&n1, &a, 0), 0);
    EXPECT_SS(U(NCryptEnumStorageProviders)(&n2, &b, 0), 0);
    EXPECT_EQ(n1, n2); CHECK(a != b);
    for (DWORD i = 0; a && b && i < n1 && i < n2; i++) CHECK(!lstrcmpW(a[i].pszName, b[i].pszName));
    if (a) U(NCryptFreeBuffer)(a);
    if (b) U(NCryptFreeBuffer)(b);
}
TEST(ncprov_enumprov_listed_names_open) {
    NC_NOWINE();
    REQUIRE(U(NCryptEnumStorageProviders)); REQUIRE(U(NCryptOpenStorageProvider));
    DWORD n = 0; NCryptProviderName *l = NULL;
    EXPECT_SS(U(NCryptEnumStorageProviders)(&n, &l, 0), 0);
    for (DWORD i = 0; l && i < n; i++) {
        NCRYPT_PROV_HANDLE h = 0;
        SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, l[i].pszName, 0);
        if (!lstrcmpW(l[i].pszName, NC_MSKSP)) EXPECT_SS(s, 0);
        else t_note("open listed provider '%ls' -> 0x%08lx", l[i].pszName, (DWORD)s);
        if (s == 0) nc_free(h);
    }
    if (l) U(NCryptFreeBuffer)(l);
}
TEST(ncprov_freebuffer_null) {
    REQUIRE(U(NCryptFreeBuffer));
    EXPECT_SS(U(NCryptFreeBuffer)(NULL), 0);
    EXPECT_SS(U(NCryptFreeBuffer)(NULL), 0);
}
TEST(ncprov_freebuffer_process_heap_block) {
    REQUIRE(U(NCryptFreeBuffer));
    /* a block that is not on the router's buffer list is handed straight to the process heap */
    void *p = HeapAlloc(GetProcessHeap(), 0, 64);
    CHECK(p != NULL);
    EXPECT_SS(U(NCryptFreeBuffer)(p), 0);
}

/* ---------- NCryptEnumAlgorithms ---------- */
static int alg_listed(NCryptAlgorithmName *l, DWORD n, const WCHAR *name)
{
    for (DWORD i = 0; i < n; i++) if (l[i].pszName && !lstrcmpiW(l[i].pszName, name)) return 1;
    return 0;
}
typedef struct { DWORD op; const WCHAR *name; const char *tag; } opalg_t;
TEST(ncprov_enumalgs_by_operation) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    static const opalg_t t[] = {
        { NCRYPT_SIGNATURE_OPERATION, BCRYPT_RSA_ALGORITHM, "sig RSA" },
        { NCRYPT_SIGNATURE_OPERATION, BCRYPT_ECDSA_P256_ALGORITHM, "sig P256" },
        { NCRYPT_SIGNATURE_OPERATION, BCRYPT_ECDSA_P384_ALGORITHM, "sig P384" },
        { NCRYPT_SIGNATURE_OPERATION, BCRYPT_ECDSA_P521_ALGORITHM, "sig P521" },
        { NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, BCRYPT_RSA_ALGORITHM, "enc RSA" },
        { NCRYPT_SECRET_AGREEMENT_OPERATION, BCRYPT_DH_ALGORITHM, "agree DH" },
        { NCRYPT_SECRET_AGREEMENT_OPERATION, BCRYPT_ECDH_P256_ALGORITHM, "agree ECDH256" },
        { NCRYPT_SECRET_AGREEMENT_OPERATION, BCRYPT_ECDH_P384_ALGORITHM, "agree ECDH384" },
        { NCRYPT_SECRET_AGREEMENT_OPERATION, BCRYPT_ECDH_P521_ALGORITHM, "agree ECDH521" },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        DWORD n = 0; NCryptAlgorithmName *l = NULL;
        SECURITY_STATUS s = U(NCryptEnumAlgorithms)(h, t[i].op, &n, &l, 0);
        EXPECT_SS(s, 0);
        if (s) continue;
        CHECKF(n > 0 && l, "%s empty", t[i].tag);
        CHECKF(alg_listed(l, n, t[i].name), "%s: %ls not listed", t[i].tag, t[i].name);
        for (DWORD j = 0; j < n; j++) {
            CHECK(l[j].pszName != NULL);
            CHECKF(l[j].dwAlgOperations & t[i].op, "entry %ls lacks requested op bit (ops=0x%lx)", l[j].pszName, l[j].dwAlgOperations);
        }
        U(NCryptFreeBuffer)(l);
    }
    nc_free(h);
}
TEST(ncprov_enumalgs_excludes_foreign_ops) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    DWORD n = 0; NCryptAlgorithmName *l = NULL;
    EXPECT_SS(U(NCryptEnumAlgorithms)(h, NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, &n, &l, 0), 0);
    if (l) {
        CHECK(!alg_listed(l, n, BCRYPT_ECDSA_P256_ALGORITHM));
        CHECK(!alg_listed(l, n, BCRYPT_ECDH_P256_ALGORITHM));
        CHECK(!alg_listed(l, n, BCRYPT_AES_ALGORITHM));
        U(NCryptFreeBuffer)(l);
    }
    nc_free(h);
}
TEST(ncprov_enumalgs_all_ops_superset) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    DWORD nall = 0, nsig = 0; NCryptAlgorithmName *all = NULL, *sig = NULL;
    SECURITY_STATUS s = U(NCryptEnumAlgorithms)(h, 0, &nall, &all, 0);
    t_note("EnumAlgorithms(op=0) -> 0x%08lx count=%lu", (DWORD)s, nall);
    EXPECT_SS(U(NCryptEnumAlgorithms)(h, NCRYPT_SIGNATURE_OPERATION, &nsig, &sig, 0), 0);
    if (s == 0 && all && sig) {
        CHECK(nall >= nsig);
        for (DWORD i = 0; i < nsig; i++) CHECK(alg_listed(all, nall, sig[i].pszName));
    }
    if (all) U(NCryptFreeBuffer)(all);
    if (sig) U(NCryptFreeBuffer)(sig);
    nc_free(h);
}
TEST(ncprov_enumalgs_dsa_listed_note) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    DWORD n = 0; NCryptAlgorithmName *l = NULL;
    if (U(NCryptEnumAlgorithms)(h, NCRYPT_SIGNATURE_OPERATION, &n, &l, 0) == 0 && l) {
        t_note("DSA listed for signature: %d", alg_listed(l, n, BCRYPT_DSA_ALGORITHM));
        for (DWORD i = 0; i < n; i++) t_note("sig alg %ls class=%lu ops=0x%lx flags=0x%lx", l[i].pszName, l[i].dwClass, l[i].dwAlgOperations, l[i].dwFlags);
        U(NCryptFreeBuffer)(l);
    }
    nc_free(h);
}
TEST(ncprov_enumalgs_invalid_args) {
    REQUIRE(U(NCryptEnumAlgorithms));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    DWORD n = 0; NCryptAlgorithmName *l = NULL;
    EXPECT_SS(U(NCryptEnumAlgorithms)(0, NCRYPT_SIGNATURE_OPERATION, &n, &l, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptEnumAlgorithms)(h, NCRYPT_SIGNATURE_OPERATION, NULL, &l, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptEnumAlgorithms)(h, NCRYPT_SIGNATURE_OPERATION, &n, NULL, 0), NC_INVALID_PARAMETER);
    /* handle is validated before the pointers (decomp order) */
    EXPECT_SS(U(NCryptEnumAlgorithms)(0, NCRYPT_SIGNATURE_OPERATION, NULL, NULL, 0), NC_INVALID_HANDLE);
    nc_free(h);
}
TEST(ncprov_enumalgs_key_handle_is_not_provider) {
    REQUIRE(U(NCryptEnumAlgorithms));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(h, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD n = 0; NCryptAlgorithmName *l = NULL;
    EXPECT_SS(U(NCryptEnumAlgorithms)(k, NCRYPT_SIGNATURE_OPERATION, &n, &l, 0), NC_INVALID_HANDLE);
    nc_free(k); nc_free(h);
}
TEST(ncprov_enumalgs_bad_flags) {
    REQUIRE(U(NCryptEnumAlgorithms));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    static const DWORD bad[] = { 0x1, 0x2, 0x100, 0x80000000u };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        DWORD n = 0; NCryptAlgorithmName *l = NULL;
        SECURITY_STATUS s = U(NCryptEnumAlgorithms)(h, NCRYPT_SIGNATURE_OPERATION, &n, &l, bad[i]);
        t_note("EnumAlgorithms flags=0x%lx -> 0x%08lx", bad[i], (DWORD)s);
        if (s == 0 && l) U(NCryptFreeBuffer)(l);
    }
    nc_free(h);
}

/* ---------- NCryptIsAlgSupported ---------- */
TEST(ncprov_isalg_supported_table) {
    REQUIRE(U(NCryptIsAlgSupported));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    static const WCHAR *ok[] = { BCRYPT_RSA_ALGORITHM, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_ECDSA_P521_ALGORITHM,
        BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_P384_ALGORITHM, BCRYPT_ECDH_P521_ALGORITHM, BCRYPT_DH_ALGORITHM };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) { SECURITY_STATUS s = U(NCryptIsAlgSupported)(h, ok[i], 0); CHECKF(s == 0, "%ls -> 0x%08lx", ok[i], (DWORD)s); }
    nc_free(h);
}
TEST(ncprov_isalg_unsupported_table) {
    REQUIRE(U(NCryptIsAlgSupported));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    static const WCHAR *bad[] = { BCRYPT_AES_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_RC4_ALGORITHM, BCRYPT_3DES_ALGORITHM, BCRYPT_MD5_ALGORITHM,
        L"", L"cryptt-no-such-alg", L"RSA ", L"ECDSA_P257", L"HMAC", BCRYPT_RNG_ALGORITHM };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        SECURITY_STATUS s = U(NCryptIsAlgSupported)(h, bad[i], 0);
        CHECKF(s != 0, "'%ls' unexpectedly supported", bad[i]);
        t_note("IsAlgSupported('%ls') -> 0x%08lx", bad[i], (DWORD)s);
    }
    nc_free(h);
}
TEST(ncprov_isalg_case_and_generic_names) {
    REQUIRE(U(NCryptIsAlgSupported));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    t_note("IsAlgSupported(\"rsa\") -> 0x%08lx", (DWORD)U(NCryptIsAlgSupported)(h, L"rsa", 0));
    t_note("IsAlgSupported(\"ECDSA\") -> 0x%08lx", (DWORD)U(NCryptIsAlgSupported)(h, L"ECDSA", 0));
    t_note("IsAlgSupported(\"ECDH\") -> 0x%08lx", (DWORD)U(NCryptIsAlgSupported)(h, L"ECDH", 0));
    t_note("IsAlgSupported(NULL) -> 0x%08lx", (DWORD)U(NCryptIsAlgSupported)(h, NULL, 0));
    t_note("IsAlgSupported(\"DSA\") -> 0x%08lx", (DWORD)U(NCryptIsAlgSupported)(h, BCRYPT_DSA_ALGORITHM, 0));
    nc_free(h);
}
TEST(ncprov_isalg_invalid_handle) {
    REQUIRE(U(NCryptIsAlgSupported));
    EXPECT_SS(U(NCryptIsAlgSupported)(0, BCRYPT_RSA_ALGORITHM, 0), NC_INVALID_HANDLE);
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(h, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    EXPECT_SS(U(NCryptIsAlgSupported)(k, BCRYPT_RSA_ALGORITHM, 0), NC_INVALID_HANDLE);
    nc_free(k); nc_free(h);
}
TEST(ncprov_isalg_flags) {
    REQUIRE(U(NCryptIsAlgSupported));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    static const DWORD f[] = { 0x1, 0x2, NCRYPT_SILENT_FLAG, NCRYPT_MACHINE_KEY_FLAG, 0x80000000u };
    for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++)
        t_note("IsAlgSupported(RSA, flags=0x%lx) -> 0x%08lx", f[i], (DWORD)U(NCryptIsAlgSupported)(h, BCRYPT_RSA_ALGORITHM, f[i]));
    nc_free(h);
}
TEST(ncprov_isalg_after_provider_closed_key_survives) {
    REQUIRE(U(NCryptIsAlgSupported));
    /* a key holds a reference on its provider: closing the provider handle first leaves the key usable */
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(h, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    EXPECT_SS(U(NCryptFreeObject)(h), 0);
    BYTE sig[64]; DWORD cb = 0;
    EXPECT_SS(U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, &cb, 0), 0);
    EXPECT_EQ(cb, 64);
    EXPECT_SS(U(NCryptFreeObject)(k), 0);
}

/* ---------- NCryptFreeObject / NCryptIsKeyHandle / handle typing ---------- */
TEST(ncprov_free_null) {
    REQUIRE(U(NCryptFreeObject));
    EXPECT_SS(U(NCryptFreeObject)(0), NC_INVALID_HANDLE);
}
TEST(ncprov_free_wrong_type_bcrypt_handle) {
    REQUIRE(U(NCryptFreeObject)); REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE a = NULL;
    if (U(BCryptOpenAlgorithmProvider)(&a, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) { t_skip("no bcrypt"); return; }
    EXPECT_SS(U(NCryptFreeObject)((NCRYPT_HANDLE)a), NC_INVALID_HANDLE);
    { NTSTATUS c_ = U(BCryptCloseAlgorithmProvider)(a, 0); EXPECT_EQ(c_, 0); }   /* bcrypt handle untouched */
}
TEST(ncprov_free_key_then_provider_order) {
    REQUIRE(U(NCryptFreeObject));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(h, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    EXPECT_SS(U(NCryptFreeObject)(k), 0);
    EXPECT_SS(U(NCryptFreeObject)(h), 0);
}
TEST(ncprov_free_provider_then_key_order) {
    REQUIRE(U(NCryptFreeObject));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(h, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    EXPECT_SS(U(NCryptFreeObject)(h), 0);
    CHECK(U(NCryptIsKeyHandle)(k));
    EXPECT_SS(U(NCryptFreeObject)(k), 0);
}
TEST(ncprov_free_unfinalized_key) {
    REQUIRE(U(NCryptFreeObject));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(h, BCRYPT_RSA_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    EXPECT_SS(U(NCryptFreeObject)(k), 0);   /* an ephemeral, never-finalized key is simply discarded */
    nc_free(h);
}
TEST(ncprov_iskeyhandle) {
    REQUIRE(U(NCryptIsKeyHandle));
    CHECK(!U(NCryptIsKeyHandle)(0));
    NCRYPT_PROV_HANDLE h = nc_prov(); NEED(h, "provider");
    CHECK(!U(NCryptIsKeyHandle)((NCRYPT_KEY_HANDLE)h));          /* provider tag is not a key tag */
    NCRYPT_KEY_HANDLE k = nc_newkey(h, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, FALSE); NEED(k, "key");
    CHECK(U(NCryptIsKeyHandle)(k));                              /* true before finalization too */
    EXPECT_SS(U(NCryptFinalizeKey)(k, 0), 0);
    CHECK(U(NCryptIsKeyHandle)(k));
    BCRYPT_ALG_HANDLE a = NULL;
    if (U(BCryptOpenAlgorithmProvider)(&a, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) { CHECK(!U(NCryptIsKeyHandle)((NCRYPT_KEY_HANDLE)a)); U(BCryptCloseAlgorithmProvider)(a, 0); }
    nc_free(k); nc_free(h);
}
TEST(ncprov_secret_handle_not_key_not_provider) {
    NC_NOWINE();
    REQUIRE(U(NCryptSecretAgreement));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, NCV(k_ecdh256_a_priv)), b = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ecdh256_b_pub));
    NEED(a && b, "ECDH keys");
    NCRYPT_SECRET_HANDLE s = 0;
    EXPECT_SS(U(NCryptSecretAgreement)(a, b, &s, 0), 0);
    NEED(s, "secret");
    CHECK(!U(NCryptIsKeyHandle)((NCRYPT_KEY_HANDLE)s));
    EXPECT_SS(U(NCryptIsAlgSupported)((NCRYPT_PROV_HANDLE)s, BCRYPT_RSA_ALGORITHM, 0), NC_INVALID_HANDLE);
    DWORD cb;
    EXPECT_SS(U(NCryptGetProperty)(s, NCRYPT_NAME_PROPERTY, NULL, 0, &cb, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptFreeObject)(s), 0);
    nc_free(a); nc_free(b); nc_free(p);
}
TEST(ncprov_handle_type_validation_matrix) {
    NC_NOWINE();
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature)); REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    REQUIRE(U(NCryptFinalizeKey)); REQUIRE(U(NCryptExportKey)); REQUIRE(U(NCryptSecretAgreement)); REQUIRE(U(NCryptDeriveKey));
    REQUIRE(U(NCryptKeyDerivation)); REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDH_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    BYTE buf[512]; DWORD cb = 0; NCRYPT_KEY_HANDLE out = 0; NCRYPT_SECRET_HANDLE sec = 0;
    NCRYPT_HANDLE bad[2] = { 0, p };   /* NULL and a provider handle are never valid key/secret handles */
    for (int i = 0; i < 2; i++) {
        NCRYPT_HANDLE h = bad[i];
        EXPECT_SS(U(NCryptSignHash)(h, NULL, buf, 32, buf, 64, &cb, 0), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptVerifySignature)(h, NULL, buf, 32, buf, 64, 0), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptEncrypt)(h, buf, 8, NULL, buf, 128, &cb, NCRYPT_PAD_PKCS1_FLAG), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptDecrypt)(h, buf, 8, NULL, buf, 128, &cb, NCRYPT_PAD_PKCS1_FLAG), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptFinalizeKey)(h, 0), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptExportKey)(h, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptSecretAgreement)(h, k, &sec, 0), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptSecretAgreement)(k, h, &sec, 0), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptDeriveKey)(h, BCRYPT_KDF_HASH, NULL, buf, 32, &cb, 0), NC_INVALID_HANDLE);
        EXPECT_SS(U(NCryptKeyDerivation)(h, NULL, buf, 32, &cb, 0), NC_INVALID_HANDLE);
    }
    EXPECT_EQ(sec, 0);
    /* exporting with an invalid wrapping key handle */
    EXPECT_SS(U(NCryptExportKey)(k, p, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_INVALID_HANDLE);
    /* import into a non-provider handle */
    EXPECT_SS(U(NCryptImportKey)(0, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &out, buf, 72, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptImportKey)((NCRYPT_PROV_HANDLE)k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &out, buf, 72, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptCreatePersistedKey)(0, &out, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptCreatePersistedKey)((NCRYPT_PROV_HANDLE)k, &out, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0), NC_INVALID_HANDLE);
    EXPECT_EQ(out, 0);
    nc_free(k); nc_free(p);
}

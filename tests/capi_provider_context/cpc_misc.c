#include "cpc.h"
/* CryptGenRandom, CryptGetUserKey on keyless contexts, and the advapi32 -> cryptsp forwarding in both directions. */

static int acqv(int i, HCRYPTPROV *h) {
    *h = 0;
    if (cpc_provs[i].dss && t_is_wine()) { t_skip("dssenh provider entry points are unimplemented in this emulator"); return 0; }
    if (!cpc_acq(h, cpc_provs[i].a, cpc_provs[i].type, X_VERIFY)) {
        t_check(0, __FILE__, __LINE__, "acquire", "%s err 0x%lx", cpc_provs[i].a, GetLastError());
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------ CryptGenRandom */
static void gr_basic(int i) {
    REQUIRE(U(CryptGenRandom));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    BYTE b[64], z[64] = {0};
    DWORD sizes[] = { 1, 2, 7, 8, 16, 31, 32, 33, 64 };
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        memset(b, 0xCC, sizeof b);
        BOOL ok = U(CryptGenRandom)(h, sizes[k], b);
        t_check(ok, __FILE__, __LINE__, "genrandom", "len %lu err 0x%lx", sizes[k], GetLastError());
        /* guard bytes after the request stay untouched */
        for (DWORD g = sizes[k]; g < sizeof b; g++) if (b[g] != 0xCC) { t_check(0, __FILE__, __LINE__, "overrun", "len %lu byte %lu", sizes[k], g); break; }
    }
    /* zero length is a successful no-op */
    memset(b, 0xCC, sizeof b);
    CHECK(U(CryptGenRandom)(h, 0, b));
    CHECK(!memcmp(b, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", 8));
    /* two 32-byte draws differ and are not all zero */
    BYTE x[32], y[32];
    CHECK(U(CryptGenRandom)(h, 32, x)); CHECK(U(CryptGenRandom)(h, 32, y));
    CHECK(memcmp(x, y, 32) != 0);
    CHECK(memcmp(x, z, 32) != 0);
    cpc_rel(h);
}
PERPROV(cpc_genrandom_basic, gr_basic)

static void gr_null(int i) {
    REQUIRE(U(CryptGenRandom));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    SET_ERR(0);
    CHECK(!U(CryptGenRandom)(h, 16, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!U(CryptGenRandom)(h, 0, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    cpc_rel(h);
}
PERPROV(cpc_genrandom_null_buffer, gr_null)

static void gr_large(int i) {
    REQUIRE(U(CryptGenRandom));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    enum { N = 65536 };
    BYTE *b = HeapAlloc(GetProcessHeap(), 0, N + 16);
    if (!b) { t_skip("alloc"); cpc_rel(h); return; }
    memset(b, 0xCC, N + 16);
    BOOL ok = U(CryptGenRandom)(h, N, b);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        for (int k = 0; k < 16; k++) if (b[N + k] != 0xCC) { CHECK(0); break; }
        /* bit balance of 64 KiB: expected 262144 +- 362 (1 sigma); +-6000 is > 16 sigma */
        long ones = 0;
        for (int k = 0; k < N; k++) ones += __builtin_popcount(b[k]);
        CHECKF(ones > 262144 - 6000 && ones < 262144 + 6000, "ones=%ld", ones);
        /* every byte value shows up (probability of a missing value ~ 256*e^-256) */
        int seen[256] = {0}, miss = 0;
        for (int k = 0; k < N; k++) seen[b[k]] = 1;
        for (int k = 0; k < 256; k++) if (!seen[k]) miss++;
        CHECK(miss == 0);
        /* first half and second half differ */
        CHECK(memcmp(b, b + N / 2, N / 2) != 0);
    }
    HeapFree(GetProcessHeap(), 0, b);
    cpc_rel(h);
}
PERPROV(cpc_genrandom_large, gr_large)

TEST(cpc_genrandom_unaligned_buffer) {
    REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h; if (!acqv(0, &h)) return;
    BYTE raw[80];
    for (int off = 0; off < 8; off++) {
        memset(raw, 0xCC, sizeof raw);
        CHECK(U(CryptGenRandom)(h, 40, raw + off));
        CHECK(raw[off + 40] == 0xCC);
        if (off) CHECK(raw[off - 1] == 0xCC);
    }
    cpc_rel(h);
}
TEST(cpc_genrandom_after_addref_and_two_contexts) {
    REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptContextAddRef));
    HCRYPTPROV a, b; if (!acqv(0, &a)) return; if (!acqv(3, &b)) { cpc_rel(a); return; }
    BYTE x[16], y[16];
    CHECK(U(CryptContextAddRef)(a, NULL, 0));
    CHECK(U(CryptGenRandom)(a, 16, x)); CHECK(U(CryptGenRandom)(b, 16, y));
    CHECK(memcmp(x, y, 16) != 0);
    cpc_rel(a); cpc_rel(a); cpc_rel(b);
}
TEST(cpc_genrandom_threads) {
    REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h; if (!acqv(3, &h)) return;
    struct S { HCRYPTPROV h; BYTE out[32]; BOOL ok; } s[4];
    HANDLE th[4];
    DWORD WINAPI worker(LPVOID p) {
        struct S *q = p;
        __typeof__(&CryptGenRandom) gr = (__typeof__(&CryptGenRandom))t_proc("CryptGenRandom");
        q->ok = TRUE;
        for (int k = 0; k < 200; k++) if (!gr(q->h, 32, q->out)) q->ok = FALSE;
        return 0;
    }
    int made = 0;
    for (int k = 0; k < 4; k++) { s[k].h = h; s[k].ok = FALSE; memset(s[k].out, 0, 32); th[k] = CreateThread(NULL, 0, worker, &s[k], 0, NULL); if (th[k]) made++; }
    for (int k = 0; k < 4; k++) if (th[k]) { CHECK(WaitForSingleObject(th[k], 20000) == WAIT_OBJECT_0); CloseHandle(th[k]); }
    EXPECT_EQ(made, 4);
    for (int k = 0; k < 4; k++) CHECK(s[k].ok);
    for (int a = 0; a < 4; a++) for (int b2 = a + 1; b2 < 4; b2++) CHECK(memcmp(s[a].out, s[b2].out, 32) != 0);
    cpc_rel(h);
}
TEST(cpc_genrandom_forwarded_both_ways) {
    REQUIRE(UIN("advapi32.dll", CryptGenRandom)); REQUIRE(UIN("cryptsp.dll", CryptGenRandom));
    HCRYPTPROV h; if (!acqv(0, &h)) return;
    BYTE a[24], b[24];
    CHECK(UIN("advapi32.dll", CryptGenRandom)(h, 24, a));
    CHECK(UIN("cryptsp.dll", CryptGenRandom)(h, 24, b));
    CHECK(memcmp(a, b, 24) != 0);
    if (t_is_wine()) { t_skip("NULL buffer faults in this emulator"); cpc_rel(h); return; }
    SET_ERR(0);
    CHECK(!UIN("advapi32.dll", CryptGenRandom)(h, 24, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!UIN("cryptsp.dll", CryptGenRandom)(h, 24, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    cpc_rel(h);
}

/* ------------------------------------------------------------ CryptGetUserKey */
static void guk_rsa(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    HCRYPTKEY k;
    int exch_ok = (P->type == 1 || P->type == 24);   /* providers that can hold an exchange key */
    /* VERIFYCONTEXT has no persisted keys */
    k = 0x4242; SET_ERR(0);
    BOOL ok = U(CryptGetUserKey)(h, AT_SIGNATURE, &k);
    CHECK(!ok);
    if (P->type == 2 || exch_ok || P->type == 12 || P->type == 3 || P->type == 13) EXPECT_ERR(X_NTE_NO_KEY);
    if (ok) U(CryptDestroyKey)(k);
    EXPECT_EQ(k, 0x4242);
    if (exch_ok) {
        k = 0x4242; SET_ERR(0);
        CHECK(!U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
        EXPECT_EQ(k, 0x4242);
    }
    cpc_rel(h);
}
PERPROV(cpc_getuserkey_verifyctx, guk_rsa)

static void guk_badspec(int i) {
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    DWORD bad[] = { 0, 3, 4, 0x10, 0xff, 0x100, 0x7fffffff };
    for (unsigned k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        HCRYPTKEY key = 0x4242; SET_ERR(0);
        BOOL ok = U(CryptGetUserKey)(h, bad[k], &key);
        t_check(!ok && GetLastError() == X_NTE_BAD_KEY, __FILE__, __LINE__, "bad keyspec", "spec 0x%lx ok=%d err 0x%lx", bad[k], ok, GetLastError());
        EXPECT_EQ(key, 0x4242);
    }
    cpc_rel(h);
}
PERPROV(cpc_getuserkey_bad_keyspec, guk_badspec)

TEST(cpc_getuserkey_dss_exchange_spec) {
    /* DSS (type 3) has no key-exchange algorithm; DH types simply have no key */
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h; HCRYPTKEY k = 0x4242;
    if (acqv(6, &h)) {
        SET_ERR(0); CHECK(!U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &k)); EXPECT_ERR(X_NTE_BAD_ALGID);
        SET_ERR(0); CHECK(!U(CryptGetUserKey)(h, AT_SIGNATURE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
        cpc_rel(h);
    }
    if (acqv(7, &h)) {
        SET_ERR(0); CHECK(!U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
        SET_ERR(0); CHECK(!U(CryptGetUserKey)(h, AT_SIGNATURE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
        cpc_rel(h);
    }
}
TEST(cpc_getuserkey_forwarded_both_ways) {
    REQUIRE(UIN("advapi32.dll", CryptGetUserKey)); REQUIRE(UIN("cryptsp.dll", CryptGetUserKey));
    HCRYPTPROV h; if (!acqv(0, &h)) return;
    HCRYPTKEY k = 1;
    SET_ERR(0); CHECK(!UIN("advapi32.dll", CryptGetUserKey)(h, AT_KEYEXCHANGE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
    SET_ERR(0); CHECK(!UIN("cryptsp.dll", CryptGetUserKey)(h, AT_KEYEXCHANGE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
    cpc_rel(h);
}

/* ------------------------------------------------------------ advapi32 <-> cryptsp mixing */
static const char *fnames[] = { "CryptAcquireContextA", "CryptAcquireContextW", "CryptReleaseContext", "CryptContextAddRef",
    "CryptGetProvParam", "CryptSetProvParam", "CryptEnumProvidersA", "CryptEnumProvidersW", "CryptEnumProviderTypesA",
    "CryptEnumProviderTypesW", "CryptGetDefaultProviderA", "CryptGetDefaultProviderW", "CryptGenRandom", "CryptGetUserKey",
    "CryptSetProviderA", "CryptSetProviderW", "CryptSetProviderExA", "CryptSetProviderExW", "CryptCreateHash", "CryptDestroyHash",
    "CryptDestroyKey", "CryptGenKey", "CryptHashData", "CryptGetHashParam", "CryptEncrypt", "CryptDecrypt" };

TEST(cpc_fwd_exports_in_both_modules) {
    for (unsigned k = 0; k < sizeof fnames / sizeof fnames[0]; k++) {
        t_check(GetProcAddress(t_module("advapi32.dll"), fnames[k]) != NULL, __FILE__, __LINE__, "advapi32 export", "%s", fnames[k]);
        t_check(GetProcAddress(t_module("cryptsp.dll"), fnames[k]) != NULL, __FILE__, __LINE__, "cryptsp export", "%s", fnames[k]);
    }
}
TEST(cpc_fwd_export_addresses_note) {
    for (unsigned k = 0; k < sizeof fnames / sizeof fnames[0]; k++) {
        FARPROC a = GetProcAddress(t_module("advapi32.dll"), fnames[k]), c = GetProcAddress(t_module("cryptsp.dll"), fnames[k]);
        if (a && c && a == c) t_note("%s: advapi32 export resolves to the cryptsp address", fnames[k]);
    }
}
TEST(cpc_fwd_acquire_adv_use_csp_release_adv) {
    REQUIRE(UIN("advapi32.dll", CryptAcquireContextA)); REQUIRE(UIN("cryptsp.dll", CryptGetProvParam)); REQUIRE(UIN("advapi32.dll", CryptReleaseContext));
    HCRYPTPROV h = 0;
    CHECK(UIN("advapi32.dll", CryptAcquireContextA)(&h, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, X_VERIFY));
    DWORD v = 0, n = 4;
    CHECK(UIN("cryptsp.dll", CryptGetProvParam)(h, PP_PROVTYPE, (BYTE *)&v, &n, 0)); EXPECT_EQ(v, 24);
    CHECK(UIN("advapi32.dll", CryptReleaseContext)(h, 0));
}
TEST(cpc_fwd_acquire_csp_use_adv_release_csp) {
    REQUIRE(UIN("cryptsp.dll", CryptAcquireContextA)); REQUIRE(UIN("advapi32.dll", CryptGetProvParam)); REQUIRE(UIN("cryptsp.dll", CryptReleaseContext));
    if (t_is_wine()) { t_skip("dssenh CPGetProvParam unimplemented in this emulator"); return; }
    HCRYPTPROV h = 0;
    CHECK(UIN("cryptsp.dll", CryptAcquireContextA)(&h, NULL, MS_DEF_DSS_PROV_A, PROV_DSS, X_VERIFY));
    DWORD v = 0, n = 4;
    CHECK(UIN("advapi32.dll", CryptGetProvParam)(h, PP_PROVTYPE, (BYTE *)&v, &n, 0)); EXPECT_EQ(v, 3);
    CHECK(UIN("cryptsp.dll", CryptReleaseContext)(h, 0));
}
TEST(cpc_fwd_addref_and_release_mixed) {
    REQUIRE(UIN("advapi32.dll", CryptContextAddRef)); REQUIRE(UIN("cryptsp.dll", CryptReleaseContext)); REQUIRE(UIN("advapi32.dll", CryptReleaseContext));
    REQUIRE(UIN("cryptsp.dll", CryptAcquireContextW));
    HCRYPTPROV h = 0;
    CHECK(UIN("cryptsp.dll", CryptAcquireContextW)(&h, NULL, MS_DEF_PROV_W, PROV_RSA_FULL, X_VERIFY));
    CHECK(UIN("advapi32.dll", CryptContextAddRef)(h, NULL, 0));
    CHECK(UIN("cryptsp.dll", CryptReleaseContext)(h, 0));
    DWORD v, n = 4;
    CHECK(UIN("advapi32.dll", CryptGetProvParam)(h, PP_PROVTYPE, (BYTE *)&v, &n, 0));
    CHECK(UIN("advapi32.dll", CryptReleaseContext)(h, 0));
}
TEST(cpc_fwd_acquire_errors_identical) {
    REQUIRE(UIN("advapi32.dll", CryptAcquireContextA)); REQUIRE(UIN("cryptsp.dll", CryptAcquireContextA));
    HCRYPTPROV h = 0;
    struct { const char *prov; DWORD type, flags, err; } c[] = {
        { NULL, 0, X_VERIFY, X_NTE_BAD_PROV_TYPE }, { NULL, 1000, X_VERIFY, X_NTE_BAD_PROV_TYPE },
        { "cpc no such provider", 1, X_VERIFY, X_NTE_KEYSET_NOT_DEF }, { MS_DEF_PROV_A, PROV_DSS, X_VERIFY, X_NTE_PROV_TYPE_NO_MATCH },
        { NULL, 999, X_VERIFY, X_NTE_PROV_TYPE_NOT_DEF }, { MS_DEF_PROV_A, 1, X_VERIFY | 1, X_NTE_BAD_FLAGS } };
    for (unsigned k = 0; k < sizeof c / sizeof c[0]; k++) {
        SET_ERR(0);
        BOOL a = UIN("advapi32.dll", CryptAcquireContextA)(&h, NULL, c[k].prov, c[k].type, c[k].flags); DWORD ea = GetLastError();
        SET_ERR(0);
        BOOL b = UIN("cryptsp.dll", CryptAcquireContextA)(&h, NULL, c[k].prov, c[k].type, c[k].flags); DWORD eb = GetLastError();
        t_check(!a && !b && ea == c[k].err && eb == c[k].err, __FILE__, __LINE__, "forward errors", "case %u: a=%d/0x%lx b=%d/0x%lx want 0x%lx", k, a, ea, b, eb, c[k].err);
    }
}
TEST(cpc_fwd_acquire_w_errors_identical) {
    REQUIRE(UIN("advapi32.dll", CryptAcquireContextW)); REQUIRE(UIN("cryptsp.dll", CryptAcquireContextW));
    HCRYPTPROV h = 0;
    SET_ERR(0);
    CHECK(!UIN("advapi32.dll", CryptAcquireContextW)(&h, NULL, L"cpc no such provider", 1, X_VERIFY)); EXPECT_ERR(X_NTE_KEYSET_NOT_DEF);
    SET_ERR(0);
    CHECK(!UIN("cryptsp.dll", CryptAcquireContextW)(&h, NULL, NULL, 0, X_VERIFY)); EXPECT_ERR(X_NTE_BAD_PROV_TYPE);
    SET_ERR(0);
    CHECK(!UIN("advapi32.dll", CryptAcquireContextW)(&h, L"cpc_x", MS_DEF_PROV_W, 1, X_VERIFY)); EXPECT_ERR(X_NTE_BAD_FLAGS);
}
TEST(cpc_fwd_setprovparam_mixed) {
    REQUIRE(UIN("advapi32.dll", CryptSetProvParam)); REQUIRE(UIN("cryptsp.dll", CryptSetProvParam));
    HCRYPTPROV h; if (!acqv(0, &h)) return;
    SET_ERR(0);
    CHECK(!UIN("advapi32.dll", CryptSetProvParam)(h, 0x7777, NULL, 0)); EXPECT_ERR(X_NTE_BAD_TYPE);
    SET_ERR(0);
    CHECK(!UIN("cryptsp.dll", CryptSetProvParam)(h, 0x7777, NULL, 0)); EXPECT_ERR(X_NTE_BAD_TYPE);
    cpc_rel(h);
}
TEST(cpc_fwd_setprovider_ex_args_note) {
    /* registration is covered elsewhere; here only argument validation that never writes the registry */
    REQUIRE(U(CryptSetProviderExA));
    DWORD res = 0;
    SET_ERR(0);
    BOOL ok = U(CryptSetProviderExA)("cpc no such provider", PROV_RSA_FULL, &res, CRYPT_USER_DEFAULT);
    CHECK(!ok);
    t_note("CryptSetProviderExA(unknown provider, reserved!=NULL) error 0x%lx", GetLastError());
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

/* contexts are per-process objects: exercise them from several threads concurrently */
TEST(cpc_threads_acquire_release_loop) {
    REQUIRE(U(CryptAcquireContextA));
    struct S { int ok; } s[4];
    HANDLE th[4];
    DWORD WINAPI worker(LPVOID p) {
        struct S *q = p;
        __typeof__(&CryptAcquireContextA) acq = (__typeof__(&CryptAcquireContextA))t_proc("CryptAcquireContextA");
        __typeof__(&CryptReleaseContext) rel = (__typeof__(&CryptReleaseContext))t_proc("CryptReleaseContext");
        q->ok = 1;
        for (int k = 0; k < 50; k++) {
            HCRYPTPROV h = 0;
            if (!acq(&h, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, X_VERIFY)) { q->ok = 0; break; }
            BYTE b[8];
            __typeof__(&CryptGenRandom) gr = (__typeof__(&CryptGenRandom))t_proc("CryptGenRandom");
            if (!gr(h, 8, b)) q->ok = 0;
            if (!rel(h, 0)) q->ok = 0;
        }
        return 0;
    }
    for (int k = 0; k < 4; k++) { s[k].ok = 0; th[k] = CreateThread(NULL, 0, worker, &s[k], 0, NULL); }
    for (int k = 0; k < 4; k++) if (th[k]) { CHECK(WaitForSingleObject(th[k], 30000) == WAIT_OBJECT_0); CloseHandle(th[k]); CHECK(s[k].ok); }
}

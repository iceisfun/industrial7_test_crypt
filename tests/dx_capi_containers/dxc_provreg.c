#include "dxc.h"
/* CryptSetProviderA/W, CryptSetProviderExA/W, CryptGetDefaultProviderA/W, CryptEnumProviders*,
 * CryptEnumProviderTypes*. State-changing parts register a TEST provider type (977) and a test
 * provider name under HKLM (elevation required, skipped otherwise) and restore everything.
 * Pinned from cryptsp: CryptSetProviderExA validates (type 1..999, name, reserved NULL, flags
 * subset of {1,2,4} with 1|2 forbidden), requires the provider to be registered under
 * Defaults\Provider\<name> with a matching Type value, writes Defaults\Provider Types\Type NNN\Name
 * for CRYPT_MACHINE_DEFAULT and deletes that value for CRYPT_MACHINE_DEFAULT|CRYPT_DELETE_DEFAULT.
 * CRYPT_USER_DEFAULT only verifies that the machine default is already that provider (CryptSetProviderA). */

#define TTYPE 977
#define K_PROV  "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"
#define K_TYPES "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider Types"
#define K_TYPE  K_TYPES "\\Type 977"
#define K_UTYPE "SOFTWARE\\Microsoft\\Cryptography\\Providers\\Type 977"

static const char *tprov(void) {
    static char b[96];
    snprintf(b, sizeof b, "%s_prov_%lu", T_TMP_PREFIX, GetCurrentProcessId());
    return b;
}
static void tprov_key(char *out, size_t n) { snprintf(out, n, "%s\\%s", K_PROV, tprov()); }

static int reg_set_dw(HKEY root, const char *key, const char *name, DWORD v) {
    HKEY k; if (RegCreateKeyExA(root, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL)) return 0;
    LONG r = RegSetValueExA(k, name, 0, REG_DWORD, (BYTE *)&v, 4); RegCloseKey(k); return r == 0;
}
static int reg_set_sz(HKEY root, const char *key, const char *name, const char *v) {
    HKEY k; if (RegCreateKeyExA(root, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL)) return 0;
    LONG r = RegSetValueExA(k, name, 0, REG_SZ, (const BYTE *)v, (DWORD)strlen(v) + 1); RegCloseKey(k); return r == 0;
}
static int reg_get_sz(HKEY root, const char *key, const char *name, char *out, DWORD cap) {
    HKEY k; if (RegOpenKeyExA(root, key, 0, KEY_READ, &k)) return 0;
    DWORD n = cap, ty = 0; LONG r = RegQueryValueExA(k, name, NULL, &ty, (BYTE *)out, &n); RegCloseKey(k);
    return r == 0 && ty == REG_SZ;
}
static int reg_key_exists(HKEY root, const char *key) {
    HKEY k; if (RegOpenKeyExA(root, key, 0, KEY_READ, &k)) return 0; RegCloseKey(k); return 1;
}
static void unreg_all(void) {
    char k[300]; tprov_key(k, sizeof k);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, k);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, K_TYPE);
    RegDeleteKeyA(HKEY_CURRENT_USER, K_UTYPE);
}
/* remove stale entries of earlier runs of this corpus */
static void sweep_old(void) {
    HKEY k; char nm[300];
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, K_PROV, 0, KEY_READ | KEY_WRITE, &k) == 0) {
        for (DWORD i = 0;;) {
            DWORD n = sizeof nm;
            if (RegEnumKeyExA(k, i, nm, &n, NULL, NULL, NULL, NULL)) break;
            if (!strncmp(nm, T_TMP_PREFIX "_prov_", sizeof(T_TMP_PREFIX) + 5)) RegDeleteKeyA(k, nm); else i++;
        }
        RegCloseKey(k);
    }
    char tn[100];
    if (reg_get_sz(HKEY_LOCAL_MACHINE, K_TYPE, "TypeName", tn, sizeof tn) && !strncmp(tn, T_TMP_PREFIX, 6))
        RegDeleteKeyA(HKEY_LOCAL_MACHINE, K_TYPE);
}
/* gate: elevated + HKLM writable; registers type 977 and the test provider */
static int setup_reg(void) {
    if (!U(CryptSetProviderExA) || !U(CryptGetDefaultProviderA)) { t_skip("missing export"); return 0; }
    if (t_is_wine()) { t_skip("emulator keeps CSP registration elsewhere"); return 0; }
    if (!dxc_is_admin()) { t_skip("not elevated"); return 0; }
    sweep_old();
    char k[300]; tprov_key(k, sizeof k);
    if (!reg_set_dw(HKEY_LOCAL_MACHINE, k, "Type", TTYPE)) { t_skip("HKLM not writable"); return 0; }
    reg_set_sz(HKEY_LOCAL_MACHINE, k, "Image Path", "rsaenh.dll");
    reg_set_dw(HKEY_LOCAL_MACHINE, k, "SigInFile", 0);
    if (!reg_set_sz(HKEY_LOCAL_MACHINE, K_TYPE, "TypeName", T_TMP_PREFIX " test provider type")) {
        unreg_all(); t_skip("HKLM not writable"); return 0;
    }
    return 1;
}

/* --------------------------------------------------------------- argument validation (no state change) */
TEST(dxc_provreg_setex_invalid_args) {
    REQUIRE(U(CryptSetProviderExA));
    DWORD res = 0;
    const char *p = MS_ENH_RSA_AES_PROV_A;
    SET_ERR(0); CHECK(!U(CryptSetProviderExA)(NULL, PROV_RSA_AES, NULL, CRYPT_MACHINE_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSetProviderExA)(p, 0, NULL, CRYPT_MACHINE_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSetProviderExA)(p, 1000, NULL, CRYPT_MACHINE_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSetProviderExA)(p, 0xffffffff, NULL, CRYPT_MACHINE_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSetProviderExA)(p, PROV_RSA_AES, &res, CRYPT_MACHINE_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(dxc_provreg_setex_invalid_flags) {
    REQUIRE(U(CryptSetProviderExA));
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    static const DWORD bad[] = { 3, 7, 8, 0x10, 0x100, 0x80000000, 0xfffffff8 };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        SET_ERR(0);
        BOOL ok = U(CryptSetProviderExA)(MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, NULL, bad[i]);
        CHECKF(!ok, "flags 0x%lx", bad[i]);
        EXPECT_ERR(X_NTE_BAD_FLAGS);
    }
}

TEST(dxc_provreg_setex_unregistered_provider) {
    REQUIRE(U(CryptSetProviderExA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    char nm[100]; snprintf(nm, sizeof nm, "%s_noprov_%lu", T_TMP_PREFIX, GetCurrentProcessId());
    SET_ERR(0);
    CHECK(!U(CryptSetProviderExA)(nm, TTYPE, NULL, CRYPT_MACHINE_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!U(CryptSetProviderExA)(nm, PROV_RSA_FULL, NULL, CRYPT_USER_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(dxc_provreg_setex_type_mismatch) {
    REQUIRE(U(CryptSetProviderExA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    /* registered as type 24, requested as 1 */
    SET_ERR(0);
    CHECK(!U(CryptSetProviderExA)(MS_ENH_RSA_AES_PROV_A, PROV_RSA_FULL, NULL, CRYPT_MACHINE_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!U(CryptSetProviderExA)(MS_DEF_DSS_PROV_A, PROV_RSA_AES, NULL, CRYPT_MACHINE_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(dxc_provreg_setex_flags_zero_fails) {
    REQUIRE(U(CryptSetProviderExA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    /* a registered provider but no default scope requested: nothing to write, the call fails */
    SET_ERR(0);
    BOOL ok = U(CryptSetProviderExA)(MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, NULL, 0);
    CHECK(!ok);
    t_note("SetProviderEx flags 0: err 0x%lx", GetLastError());
    SET_ERR(0);
    ok = U(CryptSetProviderExA)(MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, NULL, CRYPT_DELETE_DEFAULT);
    CHECK(!ok);
}

TEST(dxc_provreg_setprovider_invalid_args) {
    REQUIRE(U(CryptSetProviderA));
    SET_ERR(0); CHECK(!U(CryptSetProviderA)(NULL, PROV_RSA_AES)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSetProviderA)(MS_ENH_RSA_AES_PROV_A, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSetProviderA)(MS_ENH_RSA_AES_PROV_A, 1000)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    REQUIRE(U(CryptSetProviderW));
    SET_ERR(0); CHECK(!U(CryptSetProviderW)(NULL, PROV_RSA_AES)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);   /* observed: 120 for a NULL name */
    SET_ERR(0); CHECK(!U(CryptSetProviderW)(L"x", 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(dxc_provreg_setprovider_verifies_current_default) {
    REQUIRE(U(CryptSetProviderA)); REQUIRE(U(CryptGetDefaultProviderA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    /* CryptSetProvider(name, type) succeeds exactly when `name` already is the machine default for type */
    static const DWORD types[] = { PROV_RSA_FULL, PROV_RSA_AES, PROV_DSS, PROV_DSS_DH };
    for (unsigned i = 0; i < sizeof types / sizeof *types; i++) {
        char def[200]; DWORD n = sizeof def;
        if (!U(CryptGetDefaultProviderA)(types[i], NULL, CRYPT_MACHINE_DEFAULT, def, &n)) { t_note("type %lu: no default", types[i]); continue; }
        SET_ERR(0);
        CHECKF(U(CryptSetProviderA)(def, types[i]), "type %lu '%s' err 0x%lx", types[i], def, GetLastError());
        char other[200]; snprintf(other, sizeof other, "%s", def);
        other[strlen(other) - 1] ^= 1;     /* a different (unregistered) name */
        SET_ERR(0);
        CHECK(!U(CryptSetProviderA)(other, types[i])); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    }
}

TEST(dxc_provreg_setprovider_w_parity) {
    REQUIRE(U(CryptSetProviderW)); REQUIRE(U(CryptGetDefaultProviderW));
    if (t_is_wine()) { t_skip("emulator"); return; }
    WCHAR def[200]; DWORD n = sizeof def;   /* bytes */
    if (!U(CryptGetDefaultProviderW)(PROV_RSA_AES, NULL, CRYPT_MACHINE_DEFAULT, def, &n)) { t_skip("no default for type 24"); return; }
    CHECK(U(CryptSetProviderW)(def, PROV_RSA_AES));
    CHECK(U(CryptSetProviderExW)(def, PROV_RSA_AES, NULL, CRYPT_USER_DEFAULT));
    DWORD res = 0;
    SET_ERR(0); CHECK(!U(CryptSetProviderExW)(def, PROV_RSA_AES, &res, CRYPT_USER_DEFAULT)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSetProviderExW)(NULL == 0 ? def : def, PROV_RSA_AES, NULL, 3)); EXPECT_ERR(X_NTE_BAD_FLAGS);
}

/* --------------------------------------------------------------- GetDefaultProvider */
TEST(dxc_provreg_getdefault_invalid_args) {
    REQUIRE(U(CryptGetDefaultProviderA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    char b[200]; DWORD n = sizeof b, res = 0;
    SET_ERR(0); CHECK(!U(CryptGetDefaultProviderA)(0, NULL, CRYPT_MACHINE_DEFAULT, b, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = sizeof b; SET_ERR(0); CHECK(!U(CryptGetDefaultProviderA)(1000, NULL, CRYPT_MACHINE_DEFAULT, b, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = sizeof b; SET_ERR(0); CHECK(!U(CryptGetDefaultProviderA)(PROV_RSA_AES, &res, CRYPT_MACHINE_DEFAULT, b, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = sizeof b; SET_ERR(0); CHECK(!U(CryptGetDefaultProviderA)(PROV_RSA_AES, NULL, 3, b, &n)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof b; SET_ERR(0); CHECK(!U(CryptGetDefaultProviderA)(PROV_RSA_AES, NULL, 4, b, &n)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof b; SET_ERR(0); CHECK(!U(CryptGetDefaultProviderA)(PROV_RSA_AES, NULL, 0x80000001, b, &n)); EXPECT_ERR(X_NTE_BAD_FLAGS);
}

TEST(dxc_provreg_getdefault_type_not_defined) {
    REQUIRE(U(CryptGetDefaultProviderA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    if (reg_key_exists(HKEY_LOCAL_MACHINE, K_TYPE)) { t_skip("test type present"); return; }
    char b[200]; DWORD n = sizeof b;
    SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderA)(TTYPE, NULL, CRYPT_MACHINE_DEFAULT, b, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

static void gd_size_protocol(DWORD type) {
    if (!U(CryptGetDefaultProviderA) || !U(CryptGetDefaultProviderW)) { t_skip("missing export"); return; }
    if (t_is_wine()) { t_skip("emulator"); return; }
    char b[300]; DWORD need = 0, n = sizeof b;
    if (!U(CryptGetDefaultProviderA)(type, NULL, CRYPT_MACHINE_DEFAULT, b, &n)) { t_skip("no default for type %lu (err 0x%lx)", type, GetLastError()); return; }
    EXPECT_EQ(n, strlen(b) + 1);
    CHECK(strlen(b) > 5);
    /* the name is a registered provider of that type: opening a verify context with it works */
    HCRYPTPROV h = 0;
    CHECKF(U(CryptAcquireContextA)(&h, NULL, b, type, CRYPT_VERIFYCONTEXT), "acquire '%s' err 0x%lx", b, GetLastError());
    dxc_rel(h);
    SET_ERR(0);
    CHECK(U(CryptGetDefaultProviderA)(type, NULL, CRYPT_MACHINE_DEFAULT, NULL, &need));
    EXPECT_EQ(need, n);
    char small[300]; memset(small, 'X', sizeof small);
    DWORD sn = n - 1; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderA)(type, NULL, CRYPT_MACHINE_DEFAULT, small, &sn)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(sn, n);
    sn = 0; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderA)(type, NULL, CRYPT_MACHINE_DEFAULT, small, &sn)); EXPECT_ERR(ERROR_MORE_DATA);
    sn = n; memset(small, 0, sizeof small);
    CHECK(U(CryptGetDefaultProviderA)(type, NULL, CRYPT_MACHINE_DEFAULT, small, &sn));
    EXPECT_EQ(sn, n); EXPECT_STR(small, b);
    sn = sizeof small;
    CHECK(U(CryptGetDefaultProviderA)(type, NULL, CRYPT_MACHINE_DEFAULT, small, &sn));
    EXPECT_EQ(sn, n);
    /* wide variant: same name, length in characters */
    /* the wide variant counts BYTES: (strlen + 1) * 2 */
    WCHAR w[300]; DWORD wn = sizeof w;
    CHECK(U(CryptGetDefaultProviderW)(type, NULL, CRYPT_MACHINE_DEFAULT, w, &wn));
    EXPECT_EQ(wn, n * 2);
    char conv[300]; WideCharToMultiByte(CP_ACP, 0, w, -1, conv, sizeof conv, NULL, NULL);
    EXPECT_STR(conv, b);
    wn = 0; SET_ERR(0);
    CHECK(U(CryptGetDefaultProviderW)(type, NULL, CRYPT_MACHINE_DEFAULT, NULL, &wn));
    EXPECT_EQ(wn, n * 2);
    wn = n * 2 - 1; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderW)(type, NULL, CRYPT_MACHINE_DEFAULT, w, &wn)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(wn, n * 2);
    /* user default flag reads the same registered name here */
    char ub[300]; DWORD un = sizeof ub;
    if (U(CryptGetDefaultProviderA)(type, NULL, CRYPT_USER_DEFAULT, ub, &un)) t_note("user default for %lu: '%s'", type, ub);
}
TEST(dxc_provreg_getdefault_rsa_full) { gd_size_protocol(PROV_RSA_FULL); }
TEST(dxc_provreg_getdefault_rsa_aes) { gd_size_protocol(PROV_RSA_AES); }
TEST(dxc_provreg_getdefault_dss) { gd_size_protocol(PROV_DSS); }
TEST(dxc_provreg_getdefault_dss_dh) { gd_size_protocol(PROV_DSS_DH); }

static void acq_default_matches(DWORD type) {
    if (!U(CryptGetDefaultProviderA) || !U(CryptAcquireContextA)) { t_skip("missing export"); return; }
    if (t_is_wine()) { t_skip("emulator"); return; }
    char def[300]; DWORD n = sizeof def;
    if (!U(CryptGetDefaultProviderA)(type, NULL, CRYPT_MACHINE_DEFAULT, def, &n)) { t_skip("no default"); return; }
    HCRYPTPROV h = 0;
    BOOL ok = U(CryptAcquireContextA)(&h, NULL, NULL, type, CRYPT_VERIFYCONTEXT);   /* NULL provider => default */
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (!ok) return;
    char nm[300]; DWORD l = sizeof nm;
    CHECK(dxc_gpp(h, PP_NAME, nm, &l, 0));
    EXPECT_STR(nm, def);
    dxc_rel(h);
}
TEST(dxc_provreg_acquire_default_type_1) { acq_default_matches(PROV_RSA_FULL); }
TEST(dxc_provreg_acquire_default_type_24) { acq_default_matches(PROV_RSA_AES); }
TEST(dxc_provreg_acquire_default_type_3) { acq_default_matches(PROV_DSS); }
TEST(dxc_provreg_acquire_default_type_13) { acq_default_matches(PROV_DSS_DH); }

TEST(dxc_provreg_acquire_default_container_on_default_provider) {
    /* NULL provider + persisted container uses the type's default provider */
    REQUIRE(U(CryptAcquireContextA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    dxc_prepare(3, 0);
    const char *c = dxc_name("pdc"); dxc_del(c, 3, 0);
    HCRYPTPROV h = 0;
    BOOL ok = U(CryptAcquireContextA)(&h, c, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET);
    CHECKF(ok, "err 0x%lx", GetLastError());
    dxc_rel(h);
    if (ok) {
        HCRYPTPROV h2 = 0;
        char def[300]; DWORD n = sizeof def;
        if (U(CryptGetDefaultProviderA)(PROV_RSA_AES, NULL, CRYPT_MACHINE_DEFAULT, def, &n)) {
            ok = U(CryptAcquireContextA)(&h2, c, def, PROV_RSA_AES, 0);
            CHECKF(ok, "open via default name err 0x%lx", GetLastError());
            dxc_rel(h2);
        }
    }
    U(CryptAcquireContextA)(&h, c, NULL, PROV_RSA_AES, CRYPT_DELETEKEYSET);
    dxc_del(c, 3, 0);
}

/* --------------------------------------------------------------- enumeration */
TEST(dxc_provreg_enum_providers_args) {
    REQUIRE(U(CryptEnumProvidersA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    char nm[300]; DWORD n = sizeof nm, ty = 0, res = 0;
    SET_ERR(0); CHECK(!U(CryptEnumProvidersA)(0, &res, 0, &ty, nm, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = sizeof nm; SET_ERR(0); CHECK(!U(CryptEnumProvidersA)(0, NULL, 1, &ty, nm, &n)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof nm; SET_ERR(0); CHECK(!U(CryptEnumProvidersA)(0, NULL, 0x80000000, &ty, nm, &n)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof nm; SET_ERR(0); CHECK(!U(CryptEnumProvidersA)(0x7fffffff, NULL, 0, &ty, nm, &n)); EXPECT_ERR(ERROR_NO_MORE_ITEMS);
}

TEST(dxc_provreg_enum_providers_standard_present) {
    REQUIRE(U(CryptEnumProvidersA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    int seen[8] = {0}; int count = 0;
    for (DWORD i = 0; i < 200; i++) {
        char nm[300]; DWORD n = sizeof nm, ty = 0;
        if (!U(CryptEnumProvidersA)(i, NULL, 0, &ty, nm, &n)) { EXPECT_ERR(ERROR_NO_MORE_ITEMS); break; }
        count++;
        EXPECT_EQ(n, strlen(nm) + 1);
        for (int p = 0; p < 7; p++) if (!strcmp(nm, dxc_provs[p].a)) { seen[p]++; EXPECT_EQ(ty, dxc_provs[p].type); }
        /* size query for the same index */
        DWORD q = 0, ty2 = 0;
        CHECK(U(CryptEnumProvidersA)(i, NULL, 0, &ty2, NULL, &q));
        EXPECT_EQ(q, n); EXPECT_EQ(ty2, ty);
    }
    CHECK(count >= 7);
    for (int p = 0; p < 7; p++) CHECKF(seen[p] == 1, "provider %s seen %d times", dxc_provs[p].a, seen[p]);
}

TEST(dxc_provreg_enum_providers_w_parity) {
    REQUIRE(U(CryptEnumProvidersA)); REQUIRE(U(CryptEnumProvidersW));
    if (t_is_wine()) { t_skip("emulator"); return; }
    for (DWORD i = 0; i < 6; i++) {
        char a[300]; WCHAR w[300]; DWORD na = sizeof a, nw = 300, ta = 0, tw = 0;
        BOOL oa = U(CryptEnumProvidersA)(i, NULL, 0, &ta, a, &na);
        BOOL ow = U(CryptEnumProvidersW)(i, NULL, 0, &tw, w, &nw);
        EXPECT_EQ(oa, ow);
        if (!oa || !ow) break;
        char conv[300]; WideCharToMultiByte(CP_ACP, 0, w, -1, conv, sizeof conv, NULL, NULL);
        EXPECT_STR(conv, a); EXPECT_EQ(ta, tw); EXPECT_EQ(nw, na * 2);   /* the W form reports bytes, the A form characters-with-NUL */
    }
}

TEST(dxc_provreg_enum_types_args) {
    REQUIRE(U(CryptEnumProviderTypesA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    char nm[300]; DWORD n = sizeof nm, ty = 0, res = 0;
    SET_ERR(0); CHECK(!U(CryptEnumProviderTypesA)(0, &res, 0, &ty, nm, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = sizeof nm; SET_ERR(0); CHECK(!U(CryptEnumProviderTypesA)(0, NULL, 1, &ty, nm, &n)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof nm; SET_ERR(0); CHECK(!U(CryptEnumProviderTypesA)(0x7fffffff, NULL, 0, &ty, nm, &n)); EXPECT_ERR(ERROR_NO_MORE_ITEMS);
}

TEST(dxc_provreg_enum_types_standard_present) {
    REQUIRE(U(CryptEnumProviderTypesA));
    if (t_is_wine()) { t_skip("emulator"); return; }
    int has1 = 0, has3 = 0, has13 = 0, has24 = 0; int count = 0;
    for (DWORD i = 0; i < 400; i++) {
        char nm[300]; DWORD n = sizeof nm, ty = 0;
        if (!U(CryptEnumProviderTypesA)(i, NULL, 0, &ty, nm, &n)) { EXPECT_ERR(ERROR_NO_MORE_ITEMS); break; }
        count++;
        CHECK(ty >= 1 && ty < 1000);
        if (ty == 1) has1++; if (ty == 3) has3++; if (ty == 13) has13++; if (ty == 24) has24++;
        DWORD q = 0, t2 = 0;
        CHECK(U(CryptEnumProviderTypesA)(i, NULL, 0, &t2, NULL, &q));
        EXPECT_EQ(t2, ty); EXPECT_EQ(q, n);
    }
    CHECK(has1 == 1 && has3 == 1 && has13 == 1 && has24 == 1);
    CHECK(count >= 4);
}

/* --------------------------------------------------------------- state-changing: test type + provider */
TEST(dxc_provreg_machine_default_set_get_delete) {
    if (!setup_reg()) return;
    const char *nm = tprov();
    SET_ERR(0);
    BOOL ok = U(CryptSetProviderExA)(nm, TTYPE, NULL, CRYPT_MACHINE_DEFAULT);
    CHECKF(ok, "set err 0x%lx", GetLastError());
    if (ok) {
        char got[300]; DWORD n = sizeof got;
        CHECK(U(CryptGetDefaultProviderA)(TTYPE, NULL, CRYPT_MACHINE_DEFAULT, got, &n));
        EXPECT_STR(got, nm);
        /* CryptSetProviderEx stores the name with cbData = strlen (no terminator) */
        CHECK(n == strlen(nm) || n == strlen(nm) + 1);
        t_note("default name size %lu for %zu chars", n, strlen(nm));
        char rv[300];
        CHECK(reg_get_sz(HKEY_LOCAL_MACHINE, K_TYPE, "Name", rv, sizeof rv));
        EXPECT_STR(rv, nm);
        /* CryptSetProvider (user default) now verifies */
        SET_ERR(0);
        CHECKF(U(CryptSetProviderA)(nm, TTYPE), "SetProviderA err 0x%lx", GetLastError());
        CHECKF(U(CryptSetProviderExA)(nm, TTYPE, NULL, CRYPT_USER_DEFAULT), "err 0x%lx", GetLastError());
        /* delete the machine default: the Name value goes away, the type key stays */
        ok = U(CryptSetProviderExA)(nm, TTYPE, NULL, CRYPT_MACHINE_DEFAULT | CRYPT_DELETE_DEFAULT);
        CHECKF(ok, "delete err 0x%lx", GetLastError());
        CHECK(!reg_get_sz(HKEY_LOCAL_MACHINE, K_TYPE, "Name", rv, sizeof rv));
        CHECK(reg_key_exists(HKEY_LOCAL_MACHINE, K_TYPE));
        SET_ERR(0);
        CHECK(!U(CryptGetDefaultProviderA)(TTYPE, NULL, CRYPT_MACHINE_DEFAULT, got, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0);
        CHECK(!U(CryptSetProviderExA)(nm, TTYPE, NULL, CRYPT_MACHINE_DEFAULT | CRYPT_DELETE_DEFAULT));   /* nothing left to delete */
        t_note("second delete err 0x%lx", GetLastError());
        SET_ERR(0);
        CHECK(!U(CryptSetProviderA)(nm, TTYPE));    /* no default any more */
    }
    unreg_all();
    CHECK(!reg_key_exists(HKEY_LOCAL_MACHINE, K_TYPE));
}

TEST(dxc_provreg_machine_default_replace) {
    if (!setup_reg()) return;
    const char *nm = tprov();
    char k2[300]; snprintf(k2, sizeof k2, "%s\\%s_b", K_PROV, nm);
    reg_set_dw(HKEY_LOCAL_MACHINE, k2, "Type", TTYPE);
    reg_set_sz(HKEY_LOCAL_MACHINE, k2, "Image Path", "rsaenh.dll");
    char nm2[120]; snprintf(nm2, sizeof nm2, "%s_b", nm);
    CHECK(U(CryptSetProviderExA)(nm, TTYPE, NULL, CRYPT_MACHINE_DEFAULT));
    CHECK(U(CryptSetProviderExA)(nm2, TTYPE, NULL, CRYPT_MACHINE_DEFAULT));    /* replaces */
    char got[300]; DWORD n = sizeof got;
    CHECK(U(CryptGetDefaultProviderA)(TTYPE, NULL, CRYPT_MACHINE_DEFAULT, got, &n));
    EXPECT_STR(got, nm2);
    SET_ERR(0);
    CHECK(!U(CryptSetProviderA)(nm, TTYPE)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);   /* mismatch with machine default */
    CHECK(U(CryptSetProviderA)(nm2, TTYPE));
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, k2);
    unreg_all();
}

TEST(dxc_provreg_machine_default_wide) {
    if (!setup_reg()) return;
    if (!U(CryptSetProviderExW) || !U(CryptGetDefaultProviderW) || !U(CryptSetProviderW)) { unreg_all(); t_skip("missing W export"); return; }
    WCHAR w[120]; MultiByteToWideChar(CP_ACP, 0, tprov(), -1, w, 120);
    BOOL ok = U(CryptSetProviderExW)(w, TTYPE, NULL, CRYPT_MACHINE_DEFAULT);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        WCHAR got[200]; DWORD n = sizeof got;
        CHECK(U(CryptGetDefaultProviderW)(TTYPE, NULL, CRYPT_MACHINE_DEFAULT, got, &n));
        EXPECT_WSTR(got, w);
        CHECK(U(CryptSetProviderW)(w, TTYPE));
        CHECK(U(CryptSetProviderExW)(w, TTYPE, NULL, CRYPT_MACHINE_DEFAULT | CRYPT_DELETE_DEFAULT));
        n = sizeof got; SET_ERR(0);
        CHECK(!U(CryptGetDefaultProviderW)(TTYPE, NULL, CRYPT_MACHINE_DEFAULT, got, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    unreg_all();
}

TEST(dxc_provreg_user_default_delete_key) {
    if (!setup_reg()) return;
    const char *nm = tprov();
    /* CRYPT_USER_DEFAULT|CRYPT_DELETE_DEFAULT removes HKCU\...\Providers\Type 977 */
    SET_ERR(0);
    CHECK(!U(CryptSetProviderExA)(nm, TTYPE, NULL, CRYPT_USER_DEFAULT | CRYPT_DELETE_DEFAULT));
    t_note("delete of absent user default: err 0x%lx", GetLastError());
    CHECK(reg_set_sz(HKEY_CURRENT_USER, K_UTYPE, "Name", nm));
    BOOL ok = U(CryptSetProviderExA)(nm, TTYPE, NULL, CRYPT_USER_DEFAULT | CRYPT_DELETE_DEFAULT);
    CHECKF(ok, "err 0x%lx", GetLastError());
    CHECK(!reg_key_exists(HKEY_CURRENT_USER, K_UTYPE));
    unreg_all();
}

TEST(dxc_provreg_registered_provider_enumerated) {
    if (!setup_reg()) return;
    const char *nm = tprov();
    int found = 0, tfound = 0;
    for (DWORD i = 0; i < 400; i++) {
        char b[300]; DWORD n = sizeof b, ty = 0;
        if (!U(CryptEnumProvidersA)(i, NULL, 0, &ty, b, &n)) break;
        if (!strcmp(b, nm)) { found++; EXPECT_EQ(ty, TTYPE); }
    }
    EXPECT_EQ(found, 1);
    for (DWORD i = 0; i < 400; i++) {
        char b[300]; DWORD n = sizeof b, ty = 0;
        if (!U(CryptEnumProviderTypesA)(i, NULL, 0, &ty, b, &n)) break;
        if (ty == TTYPE) { tfound++; EXPECT_EQ(n, strlen(b) + 1); CHECK(!strncmp(b, T_TMP_PREFIX, 6)); }
    }
    EXPECT_EQ(tfound, 1);
    unreg_all();
    found = 0;
    for (DWORD i = 0; i < 400; i++) {
        char b[300]; DWORD n = sizeof b, ty = 0;
        if (!U(CryptEnumProvidersA)(i, NULL, 0, &ty, b, &n)) break;
        if (!strcmp(b, nm)) found++;
    }
    EXPECT_EQ(found, 0);
}

TEST(dxc_provreg_acquire_registered_test_provider) {
    if (!setup_reg()) return;
    /* the registry lookup succeeds; what the CSP DLL then does with an unknown type is its business */
    HCRYPTPROV h = 0; SET_ERR(0);
    BOOL ok = U(CryptAcquireContextA)(&h, NULL, tprov(), TTYPE, CRYPT_VERIFYCONTEXT);
    t_note("acquire test provider (rsaenh image, type %d): ok=%d err 0x%lx", TTYPE, ok, GetLastError());
    dxc_rel(h);
    /* wrong type for the registered name is a mismatch */
    SET_ERR(0);
    CHECK(!U(CryptAcquireContextA)(&h, NULL, tprov(), PROV_RSA_FULL, CRYPT_VERIFYCONTEXT));
    t_note("acquire test provider with type 1: err 0x%lx", GetLastError());
    unreg_all();
    SET_ERR(0);
    CHECK(!U(CryptAcquireContextA)(&h, NULL, tprov(), TTYPE, CRYPT_VERIFYCONTEXT));
    EXPECT_ERR(X_NTE_KEYSET_NOT_DEF);
}

TEST(dxc_provreg_acquire_with_registered_default_type) {
    if (!setup_reg()) return;
    HCRYPTPROV h = 0; SET_ERR(0);
    /* type 977 has no default yet: NULL provider name cannot be resolved */
    BOOL ok = U(CryptAcquireContextA)(&h, NULL, NULL, TTYPE, CRYPT_VERIFYCONTEXT);
    CHECK(!ok);
    t_note("acquire NULL provider for undefined default: err 0x%lx", GetLastError());
    dxc_rel(h);
    unreg_all();
}

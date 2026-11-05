#include "oidreg.h"
/* CryptGetOIDFunctionAddress with registered and installed functions, CryptFreeOIDFunctionAddress,
 * CryptInstallOIDFunctionAddress and CryptEnumOIDFunction.
 * Registered functions live at  EncodingType <n>\<set>\<oid>  with values Dll (+ optional FuncName).
 * A function set reads the registry once, at its first use in the process, so every test uses its own set name. */

#define SETUP(fn) REQUIRE(U(fn)); if (!oidr_begin()) return
#define K32 GetModuleHandleA("kernel32.dll")

static BOOL regf(DWORD enc, const char *set, const char *oid, const wchar_t *dll, const char *ov) {
    return U(CryptRegisterOIDFunction)(enc, set, oid, dll, ov);
}
static BOOL getaddr(HCRYPTOIDFUNCSET hs, DWORD enc, const char *oid, DWORD fl, void **pv, HCRYPTOIDFUNCADDR *ha) {
    return U(CryptGetOIDFunctionAddress)(hs, enc, oid, fl, pv, ha);
}

TEST(oidreg_addr_registered_function_resolved_and_called) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], oid[64]; oidr_set(set, sizeof set, "a1"); oidr_oid(oid, sizeof oid, 1);
    CHECK(regf(1, set, oid, L"kernel32.dll", "GetCurrentProcessId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    SET_ERR(0);
    CHECK(getaddr(hs, 1, oid, 0, &pv, &ha));
    EXPECT_EQ(pv, GetProcAddress(K32, "GetCurrentProcessId"));
    CHECK(ha != NULL);
    typedef DWORD (WINAPI *fn_t)(void);
    if (pv) EXPECT_EQ(((fn_t)pv)(), GetCurrentProcessId());
    CHECK(U(CryptFreeOIDFunctionAddress)(ha, 0));
    oidr_end();
}
TEST(oidreg_addr_function_name_defaults_to_set_name) {
    SETUP(CryptGetOIDFunctionAddress);
    char oid[64]; oidr_oid(oid, sizeof oid, 2);
    CHECK(regf(777, "GetCurrentThreadId", oid, L"kernel32.dll", NULL));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)("GetCurrentThreadId", 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(getaddr(hs, 777, oid, 0, &pv, &ha));
    EXPECT_EQ(pv, GetProcAddress(K32, "GetCurrentThreadId"));
    U(CryptFreeOIDFunctionAddress)(ha, 0);
    oidr_end();
}
TEST(oidreg_addr_two_oids_two_functions) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], o1[64], o2[64]; oidr_set(set, sizeof set, "a3"); oidr_oid(o1, sizeof o1, 1); oidr_oid(o2, sizeof o2, 2);
    CHECK(regf(1, set, o1, L"kernel32.dll", "GetCurrentProcessId"));
    CHECK(regf(1, set, o2, L"kernel32.dll", "GetCurrentThreadId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *p1 = NULL, *p2 = NULL; HCRYPTOIDFUNCADDR h1 = NULL, h2 = NULL;
    CHECK(getaddr(hs, 1, o1, 0, &p1, &h1)); CHECK(getaddr(hs, 1, o2, 0, &p2, &h2));
    EXPECT_EQ(p1, GetProcAddress(K32, "GetCurrentProcessId"));
    EXPECT_EQ(p2, GetProcAddress(K32, "GetCurrentThreadId"));
    U(CryptFreeOIDFunctionAddress)(h1, 0); U(CryptFreeOIDFunctionAddress)(h2, 0);
    oidr_end();
}
TEST(oidreg_addr_oid_match_is_case_insensitive) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100]; oidr_set(set, sizeof set, "a4");
    CHECK(regf(1, set, "Cryptt.Mixed.Case.Oid", L"kernel32.dll", "GetTickCount"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(getaddr(hs, 1, "CRYPTT.MIXED.CASE.OID", 0, &pv, &ha));
    EXPECT_EQ(pv, GetProcAddress(K32, "GetTickCount"));
    U(CryptFreeOIDFunctionAddress)(ha, 0);
    oidr_end();
}
TEST(oidreg_addr_unregistered_oid_not_found_outputs_cleared) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], oid[64], other[64]; oidr_set(set, sizeof set, "a5"); oidr_oid(oid, sizeof oid, 1); oidr_oid(other, sizeof other, 2);
    CHECK(regf(1, set, oid, L"kernel32.dll", "GetCurrentProcessId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = (void *)1;
    SET_ERR(0);
    CHECK(!getaddr(hs, 1, other, 0, &pv, &ha)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    WINE_DIFF { EXPECT_EQ(pv, 0); EXPECT_EQ(ha, 0); }
    oidr_end();
}
TEST(oidreg_addr_wrong_encoding_not_found) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], oid[64]; oidr_set(set, sizeof set, "a6"); oidr_oid(oid, sizeof oid, 1);
    CHECK(regf(1, set, oid, L"kernel32.dll", "GetCurrentProcessId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    SET_ERR(0);
    CHECK(!getaddr(hs, 2, oid, 0, &pv, &ha)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_addr_encoding_high_word_selects_registration) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], oid[64]; oidr_set(set, sizeof set, "a7"); oidr_oid(oid, sizeof oid, 1);
    CHECK(regf(1, set, oid, L"kernel32.dll", "GetCurrentProcessId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    BOOL ok = getaddr(hs, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, oid, 0, &pv, &ha);
    CHECK(ok); U(CryptFreeOIDFunctionAddress)(ha, 0);
    pv = NULL; ha = NULL;
    WINE_DIFF {
        CHECK(getaddr(hs, PKCS_7_ASN_ENCODING, oid, 0, &pv, &ha));   /* low word 0 -> high word 1 */
        U(CryptFreeOIDFunctionAddress)(ha, 0);
    }
    oidr_end();
}
TEST(oidreg_addr_missing_export_fails_file_not_found) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], oid[64]; oidr_set(set, sizeof set, "a8"); oidr_oid(oid, sizeof oid, 1);
    CHECK(regf(1, set, oid, L"kernel32.dll", "CrypttNoSuchExport_xyz"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = (void *)1;
    SET_ERR(0);
    CHECK(!getaddr(hs, 1, oid, 0, &pv, &ha));
    WINE_DIFF { EXPECT_ERR(ERROR_FILE_NOT_FOUND); EXPECT_EQ(pv, 0); EXPECT_EQ(ha, 0); }   /* observed: 2, not 127 */
    oidr_end();
}
TEST(oidreg_addr_missing_dll_fails) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], oid[64]; wchar_t dll[80]; oidr_set(set, sizeof set, "a9"); oidr_oid(oid, sizeof oid, 1);
    _snwprintf(dll, 80, L"cryptt_nodll_%lu.dll", GetCurrentProcessId());
    CHECK(regf(1, set, oid, dll, "GetTickCount"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = (void *)1;
    SET_ERR(0);
    CHECK(!getaddr(hs, 1, oid, 0, &pv, &ha));
    t_note("missing registered DLL: last error %lu", (unsigned long)GetLastError());
    WINE_DIFF { EXPECT_EQ(pv, 0); }
    oidr_end();
}
TEST(oidreg_addr_registration_without_dll_value_not_usable) {
    SETUP(CryptGetOIDFunctionAddress);
    if (t_is_wine()) { t_skip("emulator cannot create the key through CryptSetOIDFunctionValue"); oidr_end(); return; }
    char set[100], oid[64]; oidr_set(set, sizeof set, "a10"); oidr_oid(oid, sizeof oid, 1);
    CHECK(U(CryptSetOIDFunctionValue)(1, set, oid, L"FuncName", REG_SZ, (BYTE *)L"GetTickCount", 26));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = (void *)1;
    CHECK(!getaddr(hs, 1, oid, 0, &pv, &ha));
    oidr_end();
}
TEST(oidreg_addr_installed_only_flag_skips_registry) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], oid[64]; oidr_set(set, sizeof set, "a11"); oidr_oid(oid, sizeof oid, 1);
    CHECK(regf(1, set, oid, L"kernel32.dll", "GetCurrentProcessId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = (void *)1;
    SET_ERR(0);
    WINE_DIFF CHECK(!getaddr(hs, 1, oid, CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pv, &ha)); WINE_DIFF EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_addr_registry_read_once_per_set) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], o1[64], o2[64]; oidr_set(set, sizeof set, "a12"); oidr_oid(o1, sizeof o1, 1); oidr_oid(o2, sizeof o2, 2);
    CHECK(regf(1, set, o1, L"kernel32.dll", "GetCurrentProcessId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(getaddr(hs, 1, o1, 0, &pv, &ha)); U(CryptFreeOIDFunctionAddress)(ha, 0);   /* loads the registry view */
    CHECK(regf(1, set, o2, L"kernel32.dll", "GetCurrentThreadId"));                  /* registered afterwards */
    pv = NULL; ha = NULL;
    WINE_DIFF {
        SET_ERR(0);
        CHECK(!getaddr(hs, 1, o2, 0, &pv, &ha)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    }
    oidr_end();
}
TEST(oidreg_addr_free_null_handle_succeeds) {
    REQUIRE(U(CryptFreeOIDFunctionAddress));
    SET_ERR(0x1234);
    CHECK(U(CryptFreeOIDFunctionAddress)(NULL, 0));
    WINE_DIFF EXPECT_ERR(0x1234);
}
TEST(oidreg_addr_free_preserves_last_error) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100], oid[64]; oidr_set(set, sizeof set, "a13"); oidr_oid(oid, sizeof oid, 1);
    CHECK(regf(1, set, oid, L"kernel32.dll", "GetCurrentProcessId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(getaddr(hs, 1, oid, 0, &pv, &ha));
    SET_ERR(0x4321);
    CHECK(U(CryptFreeOIDFunctionAddress)(ha, 0));
    WINE_DIFF EXPECT_ERR(0x4321);
    oidr_end();
}
TEST(oidreg_addr_numeric_oid_registration) {
    SETUP(CryptGetOIDFunctionAddress);
    char set[100]; oidr_set(set, sizeof set, "a14");
    CHECK(regf(1, set, (LPCSTR)(ULONG_PTR)31337, L"kernel32.dll", "GetCurrentProcessId"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    BOOL ok = getaddr(hs, 1, (LPCSTR)(ULONG_PTR)31337, 0, &pv, &ha);
    CHECK(ok);
    if (ok) { EXPECT_EQ(pv, GetProcAddress(K32, "GetCurrentProcessId")); U(CryptFreeOIDFunctionAddress)(ha, 0); }
    oidr_end();
}

/* ---- installed functions (memory only) ---------------------------------------------------------------- */
static DWORD WINAPI inst_fn_a(void) { return 0xA; }
static DWORD WINAPI inst_fn_b(void) { return 0xB; }

TEST(oidreg_inst_install_and_lookup_string_oid) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    char set[100], o1[64], o2[64]; oidr_set(set, sizeof set, "i1"); oidr_oid(o1, sizeof o1, 1); oidr_oid(o2, sizeof o2, 2);
    CRYPT_OID_FUNC_ENTRY e[2] = { { o1, (void *)inst_fn_a }, { o2, (void *)inst_fn_b } };
    SET_ERR(0);
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, set, 2, e, 0));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(getaddr(hs, 1, o2, 0, &pv, &ha)); EXPECT_EQ(pv, inst_fn_b);
    WINE_DIFF CHECK(ha != NULL);
    U(CryptFreeOIDFunctionAddress)(ha, 0);
    WINE_DIFF {
        CHECK(getaddr(hs, 1, o1, CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pv, &ha)); EXPECT_EQ(pv, inst_fn_a);
        U(CryptFreeOIDFunctionAddress)(ha, 0);
    }
}
TEST(oidreg_inst_lookup_is_case_insensitive_and_encoding_specific) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    char set[100]; oidr_set(set, sizeof set, "i2");
    CRYPT_OID_FUNC_ENTRY e[1] = { { "Cryptt.Inst.OID", (void *)inst_fn_a } };
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, set, 1, e, 0));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(getaddr(hs, 1, "CRYPTT.INST.OID", 0, &pv, &ha)); EXPECT_EQ(pv, inst_fn_a); U(CryptFreeOIDFunctionAddress)(ha, 0);
    SET_ERR(0);
    CHECK(!getaddr(hs, 2, "Cryptt.Inst.OID", 0, &pv, &ha)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    SET_ERR(0);
    CHECK(!getaddr(hs, 1, "Cryptt.Inst.Other", 0, &pv, &ha)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(oidreg_inst_numeric_oid_entries) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    char set[100]; oidr_set(set, sizeof set, "i3");
    CRYPT_OID_FUNC_ENTRY e[2] = { { (LPCSTR)(ULONG_PTR)100, (void *)inst_fn_a }, { (LPCSTR)(ULONG_PTR)101, (void *)inst_fn_b } };
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, set, 2, e, 0));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(getaddr(hs, 1, (LPCSTR)(ULONG_PTR)101, 0, &pv, &ha)); EXPECT_EQ(pv, inst_fn_b); U(CryptFreeOIDFunctionAddress)(ha, 0);
    CHECK(getaddr(hs, 1, (LPCSTR)(ULONG_PTR)100, 0, &pv, &ha)); EXPECT_EQ(pv, inst_fn_a); U(CryptFreeOIDFunctionAddress)(ha, 0);
    SET_ERR(0);
    CHECK(!getaddr(hs, 1, (LPCSTR)(ULONG_PTR)102, 0, &pv, &ha)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(oidreg_inst_registry_takes_priority_over_installed) {
    SETUP(CryptGetOIDFunctionAddress);
    REQUIRE(U(CryptInstallOIDFunctionAddress));
    char set[100], oid[64]; oidr_set(set, sizeof set, "i4"); oidr_oid(oid, sizeof oid, 1);
    CHECK(regf(1, set, oid, L"kernel32.dll", "GetCurrentProcessId"));
    CRYPT_OID_FUNC_ENTRY e[1] = { { oid, (void *)inst_fn_a } };
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, set, 1, e, 0));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(getaddr(hs, 1, oid, 0, &pv, &ha));
    WINE_DIFF EXPECT_EQ(pv, inst_fn_a);       /* an installed function is found before the registered one */
    U(CryptFreeOIDFunctionAddress)(ha, 0);
    WINE_DIFF {
        CHECK(getaddr(hs, 1, oid, CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pv, &ha));
        EXPECT_EQ(pv, inst_fn_a);                                        /* flag => installed only */
        U(CryptFreeOIDFunctionAddress)(ha, 0);
    }
    oidr_end();
}

/* ---- CryptEnumOIDFunction -------------------------------------------------------------------------- */
typedef struct { DWORD enc; char fn[128]; char oid[128]; DWORD cv; DWORD types[8]; wchar_t names[8][32]; DWORD cbs[8]; BYTE data[8][160]; } erec;
typedef struct { int n; erec r[64]; const char *prefix; int stop_first; } ectx;

static BOOL WINAPI enum_cb(DWORD enc, LPCSTR fn, LPCSTR oid, DWORD cv, const DWORD types[], LPCWSTR const names[],
                           const BYTE *const data[], const DWORD cbs[], void *arg) {
    ectx *c = (ectx *)arg;
    if (c->prefix && (!fn || strncmp(fn, c->prefix, strlen(c->prefix)))) return TRUE;
    if (c->n < 64) {
        erec *r = &c->r[c->n];
        memset(r, 0, sizeof *r);
        r->enc = enc;
        if (fn) strncpy(r->fn, fn, 127);
        if (oid) strncpy(r->oid, oid, 127);
        r->cv = cv;
        for (DWORD i = 0; i < cv && i < 8; i++) {
            r->types[i] = types[i]; wcsncpy(r->names[i], names[i], 31); r->cbs[i] = cbs[i];
            memcpy(r->data[i], data[i], cbs[i] < 160 ? cbs[i] : 160);
        }
    }
    c->n++;
    return !c->stop_first;
}
static const erec *find_rec(const ectx *c, const char *oid) {
    for (int i = 0; i < c->n && i < 64; i++) if (!_stricmp(c->r[i].oid, oid)) return &c->r[i];
    return NULL;
}
static const wchar_t *rec_val(const erec *r, const wchar_t *name, DWORD *type) {
    for (DWORD i = 0; i < r->cv && i < 8; i++) if (!lstrcmpiW(r->names[i], name)) { if (type) *type = r->types[i]; return (const wchar_t *)r->data[i]; }
    return NULL;
}

TEST(oidreg_enum_sees_registered_entries_with_values) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100], o[3][64]; oidr_set(set, sizeof set, "e1");
    for (int i = 0; i < 3; i++) { oidr_oid(o[i], 64, 10 + i); CHECK(regf(1, set, o[i], L"kernel32.dll", i == 1 ? NULL : "GetTickCount")); }
    ectx c = { 0 };
    SET_ERR(0);
    CHECK(U(CryptEnumOIDFunction)(1, set, NULL, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 3);
    for (int i = 0; i < 3; i++) {
        const erec *r = find_rec(&c, o[i]);
        CHECKF(r != NULL, "oid %s not enumerated", o[i]);
        if (!r) continue;
        EXPECT_EQ(r->enc, 1);
        CHECK(!_stricmp(r->fn, set));
        EXPECT_EQ(r->cv, i == 1 ? 1 : 2);
        DWORD t = 0; const wchar_t *dll = rec_val(r, L"Dll", &t);
        CHECK(dll && !lstrcmpW(dll, L"kernel32.dll")); EXPECT_EQ(t, REG_SZ);
        const wchar_t *fn = rec_val(r, L"FuncName", &t);
        if (i == 1) CHECK(fn == NULL); else { CHECK(fn && !lstrcmpW(fn, L"GetTickCount")); EXPECT_EQ(t, REG_SZ); }
    }
    oidr_end();
}
TEST(oidreg_enum_filter_by_oid) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100], o1[64], o2[64]; oidr_set(set, sizeof set, "e2"); oidr_oid(o1, 64, 1); oidr_oid(o2, 64, 2);
    CHECK(regf(1, set, o1, L"a.dll", NULL)); CHECK(regf(1, set, o2, L"b.dll", NULL));
    ectx c = { 0 };
    CHECK(U(CryptEnumOIDFunction)(1, set, o2, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 1);
    if (c.n == 1) CHECK(!_stricmp(c.r[0].oid, o2));
    ectx d = { 0 };
    CHECK(U(CryptEnumOIDFunction)(1, set, "2.999.1347.0.0", 0, &d, enum_cb));   /* no such OID */
    EXPECT_EQ(d.n, 0);
    oidr_end();
}
TEST(oidreg_enum_filter_by_numeric_oid) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100]; oidr_set(set, sizeof set, "e3");
    CHECK(regf(1, set, (LPCSTR)(ULONG_PTR)55, L"a.dll", NULL)); CHECK(regf(1, set, (LPCSTR)(ULONG_PTR)56, L"b.dll", NULL));
    ectx c = { 0 };
    CHECK(U(CryptEnumOIDFunction)(1, set, (LPCSTR)(ULONG_PTR)56, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 1);
    if (c.n == 1) CHECK(!strcmp(c.r[0].oid, "#56"));
    ectx all = { 0 };
    CHECK(U(CryptEnumOIDFunction)(1, set, NULL, 0, &all, enum_cb));
    EXPECT_EQ(all.n, 2);
    CHECK(find_rec(&all, "#55") != NULL);
    oidr_end();
}
TEST(oidreg_enum_empty_and_unknown_set_succeed_with_no_callbacks) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100]; oidr_set(set, sizeof set, "e4");
    ectx c = { 0 };
    SET_ERR(0);
    CHECK(U(CryptEnumOIDFunction)(1, set, NULL, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 0);
    CHECK(U(CryptEnumOIDFunction)(12345, set, NULL, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 0);
    oidr_end();
}
TEST(oidreg_enum_encoding_type_filter) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100], o1[64], o2[64]; oidr_set(set, sizeof set, "e5"); oidr_oid(o1, 64, 1); oidr_oid(o2, 64, 2);
    CHECK(regf(1, set, o1, L"a.dll", NULL)); CHECK(regf(0, set, o2, L"b.dll", NULL));
    ectx c1 = { 0 }, c0 = { 0 }, ca = { 0 };
    CHECK(U(CryptEnumOIDFunction)(1, set, NULL, 0, &c1, enum_cb));
    EXPECT_EQ(c1.n, 1);
    CHECK(U(CryptEnumOIDFunction)(0, set, NULL, 0, &c0, enum_cb));
    EXPECT_EQ(c0.n, 1);
    if (c0.n == 1) { CHECK(!_stricmp(c0.r[0].oid, o2)); EXPECT_EQ(c0.r[0].enc, 0); }
    CHECK(U(CryptEnumOIDFunction)(CRYPT_ASN_ENCODING == 0 ? 0xffffffff : 0xffffffff, set, NULL, 0, &ca, enum_cb));
    EXPECT_EQ(ca.n, 2);                      /* 0xffffffff = every encoding type */
    oidr_end();
}
TEST(oidreg_enum_all_encodings_includes_private_type) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char oid[64]; oidr_oid(oid, 64, 1);
    CHECK(regf(777, "GetTickCount", oid, L"kernel32.dll", NULL));
    ectx c = { 0 }; c.prefix = "GetTickCount";
    CHECK(U(CryptEnumOIDFunction)(0xffffffff, "GetTickCount", NULL, 0, &c, enum_cb));
    const erec *r = find_rec(&c, oid);
    CHECK(r != NULL);
    if (r) EXPECT_EQ(r->enc, 777);
    oidr_end();
}
TEST(oidreg_enum_enc_report_uses_low_word) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100], oid[64]; oidr_set(set, sizeof set, "e7"); oidr_oid(oid, 64, 1);
    CHECK(regf(1, set, oid, L"a.dll", NULL));
    ectx c = { 0 };
    CHECK(U(CryptEnumOIDFunction)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, set, NULL, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 1);
    if (c.n == 1) EXPECT_EQ(c.r[0].enc, 1);
    oidr_end();
}
TEST(oidreg_enum_unregistered_entry_disappears) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100], o1[64], o2[64]; oidr_set(set, sizeof set, "e8"); oidr_oid(o1, 64, 1); oidr_oid(o2, 64, 2);
    CHECK(regf(1, set, o1, L"a.dll", NULL)); CHECK(regf(1, set, o2, L"b.dll", NULL));
    CHECK(U(CryptUnregisterOIDFunction)(1, set, o1));
    ectx c = { 0 };
    CHECK(U(CryptEnumOIDFunction)(1, set, NULL, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 1);
    CHECK(find_rec(&c, o2) != NULL);
    oidr_end();
}
TEST(oidreg_enum_default_list_reported_as_default_oid_multi_sz) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100]; oidr_set(set, sizeof set, "e9");
    CHECK(U(CryptRegisterDefaultOIDFunction)(1, set, 0, L"a.dll"));
    CHECK(U(CryptRegisterDefaultOIDFunction)(1, set, 1, L"b.dll"));
    ectx c = { 0 };
    CHECK(U(CryptEnumOIDFunction)(1, set, NULL, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 1);
    const erec *r = find_rec(&c, "DEFAULT");
    CHECK(r != NULL);
    if (r) {
        DWORD t = 0; const wchar_t *d = rec_val(r, L"Dll", &t);
        EXPECT_EQ(t, REG_MULTI_SZ);
        CHECK(d && !lstrcmpW(d, L"a.dll") && !lstrcmpW(d + 6, L"b.dll"));
    }
    oidr_end();
}
TEST(oidreg_enum_func_name_null_walks_all_sets_and_finds_ours) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char s1[100], s2[100], o1[64], o2[64]; oidr_set(s1, sizeof s1, "e10a"); oidr_set(s2, sizeof s2, "e10b"); oidr_oid(o1, 64, 1); oidr_oid(o2, 64, 2);
    CHECK(regf(1, s1, o1, L"a.dll", NULL)); CHECK(regf(1, s2, o2, L"b.dll", NULL));
    ectx c = { 0 }; c.prefix = "cryptt_oidreg_";
    CHECK(U(CryptEnumOIDFunction)(1, NULL, NULL, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 2);
    const erec *r1 = find_rec(&c, o1), *r2 = find_rec(&c, o2);
    CHECK(r1 && !_stricmp(r1->fn, s1)); CHECK(r2 && !_stricmp(r2->fn, s2));
    oidr_end();
}
TEST(oidreg_enum_callback_stop_request_observed) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100], o[64]; oidr_set(set, sizeof set, "e11");
    for (unsigned i = 1; i <= 3; i++) { oidr_oid(o, 64, i); CHECK(regf(1, set, o, L"a.dll", NULL)); }
    ectx c = { 0 }; c.stop_first = 1;
    BOOL ok = U(CryptEnumOIDFunction)(1, set, NULL, 0, &c, enum_cb);
    t_note("callback returning FALSE: enumeration returned %d after %d callback(s)", ok, c.n);
    CHECK(c.n >= 1);
    oidr_end();
}
TEST(oidreg_enum_value_cb_matches_registry_sizes) {
    SETUP(CryptEnumOIDFunction); if (t_is_wine()) { t_skip("emulator does not implement CryptEnumOIDFunction"); oidr_end(); return; }
    char set[100], oid[64]; oidr_set(set, sizeof set, "e12"); oidr_oid(oid, 64, 1);
    DWORD d = 0x1234; BYTE bin[5] = { 1, 2, 3, 4, 5 };
    CHECK(U(CryptSetOIDFunctionValue)(1, set, oid, L"Num", REG_DWORD, (BYTE *)&d, 4));
    CHECK(U(CryptSetOIDFunctionValue)(1, set, oid, L"Bin", REG_BINARY, bin, 5));
    ectx c = { 0 };
    CHECK(U(CryptEnumOIDFunction)(1, set, NULL, 0, &c, enum_cb));
    EXPECT_EQ(c.n, 1);
    if (c.n == 1) {
        const erec *r = &c.r[0]; EXPECT_EQ(r->cv, 2);
        for (DWORD i = 0; i < r->cv; i++) {
            if (!lstrcmpiW(r->names[i], L"Num")) { EXPECT_EQ(r->types[i], REG_DWORD); EXPECT_EQ(r->cbs[i], 4); EXPECT_EQ(*(DWORD *)r->data[i], 0x1234); }
            else if (!lstrcmpiW(r->names[i], L"Bin")) { EXPECT_EQ(r->types[i], REG_BINARY); EXPECT_EQ(r->cbs[i], 5); CHECK(!memcmp(r->data[i], bin, 5)); }
            else CHECKF(0, "unexpected value %ls", r->names[i]);
        }
    }
    oidr_end();
}

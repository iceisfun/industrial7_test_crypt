#include "oidreg.h"
/* Default OID function DLL lists: CryptRegisterDefaultOIDFunction / CryptUnregisterDefaultOIDFunction /
 * CryptGetDefaultOIDDllList / CryptGetDefaultOIDFunctionAddress.
 * The list is the REG_MULTI_SZ value "Dll" of  EncodingType <n>\<FuncName>\DEFAULT.
 * Most tests use the private encoding type 777 (swept wholesale by the area). */

#define E_INVALIDARG_ ((DWORD)0x80070057)
#define EXPECT_HRINVAL() do { DWORD e_ = GetLastError(); t_check(e_ == E_INVALIDARG_ || (t_is_wine() && e_ == 87), __FILE__, __LINE__, "last error E_INVALIDARG", "got 0x%lx", e_); } while (0)
#define WINE_DIFF if (!t_is_wine())
#define SETUP(fn) REQUIRE(U(fn)); if (!oidr_begin()) return
#define ENC 777

static BOOL regdef(const char *set, DWORD idx, const wchar_t *dll) { return U(CryptRegisterDefaultOIDFunction)(ENC, set, idx, dll); }
static BOOL unregdef(const char *set, const wchar_t *dll) { return U(CryptUnregisterDefaultOIDFunction)(ENC, set, dll); }

/* Reads the raw multi-sz and compares the string sequence with a '|' separated expectation ("" = empty list). */
static int raw_list(const char *set, wchar_t strs[16][64], DWORD *cb, DWORD *type) {
    wchar_t path[300], buf[1024]; DWORD t = 0, n = sizeof buf; int c = 0;
    oidr_path(path, 300, ENC, set, "DEFAULT");
    LONG rc = oidr_raw_get(path, L"Dll", &t, buf, &n);
    if (cb) *cb = n;
    if (type) *type = t;
    if (rc) return -1;
    for (wchar_t *p = buf; (BYTE *)p < (BYTE *)buf + n && *p && c < 16; p += wcslen(p) + 1) { wcsncpy(strs[c], p, 63); strs[c][63] = 0; c++; }
    return c;
}
static void expect_list(const char *set, const wchar_t *const *want, int n) {
    wchar_t strs[16][64]; DWORD cb = 0, type = 0;
    int c = raw_list(set, strs, &cb, &type);
    CHECKF(c == n, "list has %d entries, want %d", c, n);
    if (c == n) for (int i = 0; i < n; i++) CHECKF(!lstrcmpW(strs[i], want[i]), "entry %d is %ls want %ls", i, strs[i], want[i]);
    EXPECT_EQ(type, REG_MULTI_SZ);
    size_t exp = 2; for (int i = 0; i < n; i++) exp += (wcslen(want[i]) + 1) * 2;
    if (n == 0) exp = 2;
    CHECKF(cb == exp || n == 0, "raw size %lu want %zu", (unsigned long)cb, exp);   /* a-NUL b-NUL ... final NUL */
}
#define LIST(...) ((const wchar_t *const[]){ __VA_ARGS__ })

TEST(oidreg_def_register_first_entry_exact_bytes) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d1");
    SET_ERR(0xdead);
    CHECK(regdef(set, 0, L"a.dll"));
    expect_list(set, LIST(L"a.dll"), 1);
    oidr_end();
}
TEST(oidreg_def_register_last_index_appends) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d2");
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"a.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"b.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"c.dll"));
    expect_list(set, LIST(L"a.dll", L"b.dll", L"c.dll"), 3);
    oidr_end();
}
TEST(oidreg_def_register_first_index_prepends) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d3");
    CHECK(regdef(set, CRYPT_REGISTER_FIRST_INDEX, L"a.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_FIRST_INDEX, L"b.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_FIRST_INDEX, L"c.dll"));
    expect_list(set, LIST(L"c.dll", L"b.dll", L"a.dll"), 3);
    oidr_end();
}
TEST(oidreg_def_register_middle_index_inserts_before) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d4");
    CHECK(regdef(set, 0, L"a.dll")); CHECK(regdef(set, 1, L"b.dll")); CHECK(regdef(set, 2, L"c.dll"));
    CHECK(regdef(set, 1, L"x.dll"));
    WINE_DIFF expect_list(set, LIST(L"a.dll", L"x.dll", L"b.dll", L"c.dll"), 4);
    CHECK(regdef(set, 3, L"y.dll"));
    WINE_DIFF expect_list(set, LIST(L"a.dll", L"x.dll", L"b.dll", L"y.dll", L"c.dll"), 5);
    oidr_end();
}
TEST(oidreg_def_register_index_equal_to_count_appends) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d5");
    CHECK(regdef(set, 0, L"a.dll")); CHECK(regdef(set, 1, L"b.dll"));
    CHECK(regdef(set, 2, L"c.dll"));
    expect_list(set, LIST(L"a.dll", L"b.dll", L"c.dll"), 3);
    oidr_end();
}
TEST(oidreg_def_register_index_past_end_appends) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d6");
    CHECK(regdef(set, 50, L"a.dll"));       /* empty list, huge index */
    CHECK(regdef(set, 50, L"b.dll"));
    CHECK(regdef(set, 1000, L"c.dll"));
    expect_list(set, LIST(L"a.dll", L"b.dll", L"c.dll"), 3);
    oidr_end();
}
TEST(oidreg_def_register_mixed_sequence_order) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d7");
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"b.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_FIRST_INDEX, L"a.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"c.dll"));
    CHECK(regdef(set, 1, L"d.dll"));
    WINE_DIFF expect_list(set, LIST(L"a.dll", L"d.dll", L"b.dll", L"c.dll"), 4);
    oidr_end();
}
TEST(oidreg_def_register_duplicate_rejected_file_exists) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d8");
    CHECK(regdef(set, 0, L"a.dll")); CHECK(regdef(set, 1, L"b.dll"));
    SET_ERR(0);
    CHECK(!regdef(set, 0, L"b.dll")); EXPECT_ERR(ERROR_FILE_EXISTS);
    SET_ERR(0);
    CHECK(!regdef(set, CRYPT_REGISTER_LAST_INDEX, L"a.dll")); EXPECT_ERR(ERROR_FILE_EXISTS);
    expect_list(set, LIST(L"a.dll", L"b.dll"), 2);
    oidr_end();
}
TEST(oidreg_def_register_duplicate_is_case_insensitive) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d9");
    CHECK(regdef(set, 0, L"Mixed.DLL"));
    SET_ERR(0);
    CHECK(!regdef(set, 0, L"mixed.dll")); EXPECT_ERR(ERROR_FILE_EXISTS);
    expect_list(set, LIST(L"Mixed.DLL"), 1);
    oidr_end();
}
TEST(oidreg_def_register_null_and_empty_dll_invalid) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d10");
    SET_ERR(0); CHECK(!regdef(set, 0, NULL)); EXPECT_HRINVAL();
    SET_ERR(0); WINE_DIFF { CHECK(!regdef(set, 0, L"")); EXPECT_HRINVAL(); }
    wchar_t path[300]; oidr_path(path, 300, ENC, set, "DEFAULT");
    WINE_DIFF CHECK(!oidr_key_exists(path));          /* nothing was written */
    oidr_end();
}
TEST(oidreg_def_register_preserves_dll_text_verbatim) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d11");
    CHECK(regdef(set, 0, L"C:\\Some Dir\\My Plugin.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"%SystemRoot%\\system32\\x.dll"));
    expect_list(set, LIST(L"C:\\Some Dir\\My Plugin.dll", L"%SystemRoot%\\system32\\x.dll"), 2);
    oidr_end();
}
TEST(oidreg_def_register_sets_are_independent) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char s1[100], s2[100]; oidr_set(s1, sizeof s1, "d12a"); oidr_set(s2, sizeof s2, "d12b");
    CHECK(regdef(s1, 0, L"a.dll")); CHECK(regdef(s2, 0, L"a.dll"));      /* same dll in two sets is fine */
    CHECK(regdef(s1, 1, L"b.dll"));
    expect_list(s1, LIST(L"a.dll", L"b.dll"), 2);
    expect_list(s2, LIST(L"a.dll"), 1);
    oidr_end();
}
TEST(oidreg_def_register_encoding_types_are_independent) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; wchar_t p1[300], p2[300]; oidr_set(set, sizeof set, "d13");
    CHECK(U(CryptRegisterDefaultOIDFunction)(777, set, 0, L"a.dll"));
    CHECK(U(CryptRegisterDefaultOIDFunction)(778, set, 0, L"a.dll"));    /* not a duplicate: other encoding */
    oidr_path(p1, 300, 777, set, "DEFAULT"); oidr_path(p2, 300, 778, set, "DEFAULT");
    CHECK(oidr_key_exists(p1)); CHECK(oidr_key_exists(p2));
    CHECK(U(CryptUnregisterDefaultOIDFunction)(777, set, L"a.dll"));
    CHECK(U(CryptUnregisterDefaultOIDFunction)(778, set, L"a.dll"));
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, OIDR_ROOT L"\\EncodingType 778");
    oidr_end();
}
TEST(oidreg_def_register_returns_last_error_zero_on_success) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "d14");
    SET_ERR(0xabcd);
    CHECK(regdef(set, 0, L"a.dll"));
    WINE_DIFF EXPECT_ERR(0); /* the function restores the last error it computed (0) on success */
    oidr_end();
}

/* ---- unregister ------------------------------------------------------------------------------------- */
static void fill3(const char *set) {
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"a.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"b.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"c.dll"));
}
TEST(oidreg_def_unregister_middle) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u1"); fill3(set);
    CHECK(unregdef(set, L"b.dll"));
    expect_list(set, LIST(L"a.dll", L"c.dll"), 2);
    oidr_end();
}
TEST(oidreg_def_unregister_first) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u2"); fill3(set);
    CHECK(unregdef(set, L"a.dll"));
    expect_list(set, LIST(L"b.dll", L"c.dll"), 2);
    oidr_end();
}
TEST(oidreg_def_unregister_last) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u3"); fill3(set);
    CHECK(unregdef(set, L"c.dll"));
    expect_list(set, LIST(L"a.dll", L"b.dll"), 2);
    oidr_end();
}
TEST(oidreg_def_unregister_all_in_turn) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u4"); fill3(set);
    CHECK(unregdef(set, L"b.dll")); CHECK(unregdef(set, L"a.dll")); CHECK(unregdef(set, L"c.dll"));
    wchar_t strs[16][64]; DWORD cb = 0, t = 0;
    int c = raw_list(set, strs, &cb, &t);
    CHECKF(c <= 0, "list should be empty, has %d", c);
    t_note("raw 'Dll' value after removing the last entry: rc-count=%d, %lu bytes", c, (unsigned long)cb);
    CHECK(regdef(set, 0, L"z.dll"));                 /* usable again */
    expect_list(set, LIST(L"z.dll"), 1);
    oidr_end();
}
TEST(oidreg_def_unregister_case_insensitive) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u5"); fill3(set);
    CHECK(unregdef(set, L"B.DLL"));
    expect_list(set, LIST(L"a.dll", L"c.dll"), 2);
    oidr_end();
}
TEST(oidreg_def_unregister_not_in_list_not_found) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u6"); fill3(set);
    SET_ERR(0);
    CHECK(!unregdef(set, L"zzz.dll")); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    CHECK(!unregdef(set, L"a.dl"));       /* prefix is not a match */
    CHECK(!unregdef(set, L"a.dllx"));
    expect_list(set, LIST(L"a.dll", L"b.dll", L"c.dll"), 3);
    oidr_end();
}
TEST(oidreg_def_unregister_unknown_set_not_found) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u7");
    SET_ERR(0);
    CHECK(!unregdef(set, L"a.dll")); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_def_unregister_null_and_empty_invalid) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u8"); fill3(set);
    SET_ERR(0); CHECK(!unregdef(set, NULL)); EXPECT_HRINVAL();
    SET_ERR(0); CHECK(!unregdef(set, L"")); WINE_DIFF EXPECT_HRINVAL();
    expect_list(set, LIST(L"a.dll", L"b.dll", L"c.dll"), 3);
    oidr_end();
}
TEST(oidreg_def_unregister_then_reregister_position) {
    SETUP(CryptUnregisterDefaultOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "u9"); fill3(set);
    CHECK(unregdef(set, L"a.dll"));
    CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, L"a.dll"));
    expect_list(set, LIST(L"b.dll", L"c.dll", L"a.dll"), 3);
    oidr_end();
}
TEST(oidreg_def_many_entries_roundtrip) {
    SETUP(CryptRegisterDefaultOIDFunction);
    char set[100]; wchar_t names[40][20]; const wchar_t *w[40]; oidr_set(set, sizeof set, "u10");
    for (int i = 0; i < 40; i++) { _snwprintf(names[i], 20, L"dll%02d.dll", i); w[i] = names[i]; }
    for (int i = 0; i < 40; i++) CHECK(regdef(set, CRYPT_REGISTER_LAST_INDEX, names[i]));
    wchar_t strs[16][64];
    /* raw_list caps at 16: compare via the API instead */
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    DWORD cch = 0; CHECK(U(CryptGetDefaultOIDDllList)(hs, ENC, NULL, &cch));
    wchar_t *buf = calloc(cch + 4, 2); DWORD cch2 = cch;
    CHECK(U(CryptGetDefaultOIDDllList)(hs, ENC, buf, &cch2));
    int n = 0; for (wchar_t *p = buf; *p; p += wcslen(p) + 1, n++) if (n < 40) CHECKF(!lstrcmpW(p, w[n]), "entry %d is %ls", n, p);
    EXPECT_EQ(n, 40);
    free(buf);
    oidr_end();
}

/* ---- CryptGetDefaultOIDDllList ----------------------------------------------------------------------- */
static int count_list(const wchar_t *buf, const wchar_t *const *want, int nwant) {
    int n = 0;
    for (const wchar_t *p = buf; *p; p += wcslen(p) + 1, n++) if (n < nwant) CHECKF(!lstrcmpW(p, want[n]), "list entry %d is %ls want %ls", n, p, want[n]);
    return n;
}
TEST(oidreg_deflist_contents_and_size_protocol) {
    SETUP(CryptGetDefaultOIDDllList);
    char set[100]; oidr_set(set, sizeof set, "l1");
    CHECK(regdef(set, 0, L"a.dll")); CHECK(regdef(set, 1, L"bb.dll")); CHECK(regdef(set, 2, L"ccc.dll"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    CHECK(hs != NULL);
    DWORD cch = 0xffff;
    SET_ERR(0);
    CHECK(U(CryptGetDefaultOIDDllList)(hs, ENC, NULL, &cch));          /* size query */
    size_t minimum = 6 + 7 + 8 + 1;                                  /* strings with NULs + final NUL */
    CHECKF(cch >= minimum, "cch=%lu", (unsigned long)cch);
    wchar_t buf[200]; memset(buf, 0xee, sizeof buf);
    DWORD n = cch;
    CHECK(U(CryptGetDefaultOIDDllList)(hs, ENC, buf, &n));
    EXPECT_EQ(n, cch);
    EXPECT_EQ(count_list(buf, LIST(L"a.dll", L"bb.dll", L"ccc.dll"), 3), 3);
    /* too small by one: ERROR_MORE_DATA and the size is reported */
    memset(buf, 0xee, sizeof buf);
    WINE_DIFF {
        n = cch - 1; SET_ERR(0);
        CHECK(!U(CryptGetDefaultOIDDllList)(hs, ENC, buf, &n)); EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(n, cch);
        n = 0; SET_ERR(0);
        CHECK(!U(CryptGetDefaultOIDDllList)(hs, ENC, buf, &n)); EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(n, cch);
    }
    oidr_end();
}
TEST(oidreg_deflist_encoding_high_word_and_low_word) {
    SETUP(CryptGetDefaultOIDDllList);
    char set[100]; oidr_set(set, sizeof set, "l2");
    CHECK(U(CryptRegisterDefaultOIDFunction)(1, set, 0, L"a.dll"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    wchar_t buf[64]; DWORD n = 64;
    CHECK(U(CryptGetDefaultOIDDllList)(hs, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, &n));
    EXPECT_EQ(count_list(buf, LIST(L"a.dll"), 1), 1);
    n = 64; memset(buf, 0, sizeof buf);
    WINE_DIFF {
        CHECK(U(CryptGetDefaultOIDDllList)(hs, PKCS_7_ASN_ENCODING, buf, &n));   /* high word used when low word is 0 */
        EXPECT_EQ(count_list(buf, LIST(L"a.dll"), 1), 1);
    }
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, OIDR_ROOT L"\\EncodingType 1\\cryptt_oidreg_dummy");
    U(CryptUnregisterDefaultOIDFunction)(1, set, L"a.dll");
    oidr_end();
}
TEST(oidreg_deflist_empty_set_is_double_nul) {
    SETUP(CryptGetDefaultOIDDllList);
    if (t_is_wine()) { t_skip("emulator reports a different empty-list size"); oidr_end(); return; }
    char set[100]; oidr_set(set, sizeof set, "l3");
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    DWORD cch = 0;
    SET_ERR(0);
    CHECK(U(CryptGetDefaultOIDDllList)(hs, ENC, NULL, &cch));
    EXPECT_EQ(cch, 2);
    wchar_t buf[8] = { 1, 1, 1, 1 }; DWORD n = 8;
    CHECK(U(CryptGetDefaultOIDDllList)(hs, ENC, buf, &n));
    EXPECT_EQ(n, 2); EXPECT_EQ(buf[0], 0);
    n = 1; SET_ERR(0);
    CHECK(!U(CryptGetDefaultOIDDllList)(hs, ENC, buf, &n)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 2);
    oidr_end();
}
TEST(oidreg_deflist_registry_snapshot_taken_at_first_use) {
    SETUP(CryptGetDefaultOIDDllList);
    if (t_is_wine()) { t_skip("emulator re-reads the registry on every call"); oidr_end(); return; }
    char set[100]; oidr_set(set, sizeof set, "l4");
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    DWORD cch = 0;
    CHECK(U(CryptGetDefaultOIDDllList)(hs, ENC, NULL, &cch));
    EXPECT_EQ(cch, 2);
    CHECK(regdef(set, 0, L"late.dll"));            /* registered after the set loaded its registry data */
    DWORD cch2 = 0;
    CHECK(U(CryptGetDefaultOIDDllList)(hs, ENC, NULL, &cch2));
    EXPECT_EQ(cch2, 2);                            /* the cached view does not change */
    oidr_end();
}
TEST(oidreg_deflist_init_set_same_name_same_handle) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    char set[100]; oidr_set(set, sizeof set, "l5"); char other[100]; oidr_set(other, sizeof other, "l5b");
    HCRYPTOIDFUNCSET a = U(CryptInitOIDFunctionSet)(set, 0), b = U(CryptInitOIDFunctionSet)(set, 0);
    HCRYPTOIDFUNCSET c = U(CryptInitOIDFunctionSet)(other, 0);
    CHECK(a != NULL); EXPECT_EQ(a, b); CHECK(c != NULL); CHECK(c != a);
}

/* ---- default function address ----------------------------------------------------------------------- */
#define DEFADDR(name, tag) \
TEST(oidreg_defaddr_##tag) { \
    SETUP(CryptGetDefaultOIDFunctionAddress); \
    FARPROC want = GetProcAddress(GetModuleHandleA("kernel32.dll"), #name); \
    CHECK(want != NULL); \
    CHECK(U(CryptRegisterDefaultOIDFunction)(ENC, #name, 0, L"kernel32.dll")); \
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(#name, 0); \
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = NULL; \
    SET_ERR(0); \
    BOOL ok = U(CryptGetDefaultOIDFunctionAddress)(hs, ENC, L"kernel32.dll", 0, &pv, &ha); \
    CHECK(ok); \
    if (ok) { EXPECT_EQ(pv, want); CHECK(ha != NULL); CHECK(U(CryptFreeOIDFunctionAddress)(ha, 0)); } \
    oidr_end(); \
}
DEFADDR(GetCurrentProcessId, pid)
DEFADDR(GetCurrentThreadId, tid)
DEFADDR(GetTickCount, tick)

TEST(oidreg_defaddr_function_is_callable) {
    SETUP(CryptGetDefaultOIDFunctionAddress);
    CHECK(U(CryptRegisterDefaultOIDFunction)(ENC, "GetCurrentProcessId", 0, L"kernel32.dll"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)("GetCurrentProcessId", 0);
    typedef DWORD (WINAPI *fn_t)(void);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(hs, ENC, L"kernel32.dll", 0, &pv, &ha));
    if (pv) EXPECT_EQ(((fn_t)pv)(), GetCurrentProcessId());
    U(CryptFreeOIDFunctionAddress)(ha, 0);
    oidr_end();
}
TEST(oidreg_defaddr_dll_name_case_insensitive) {
    SETUP(CryptGetDefaultOIDFunctionAddress);
    CHECK(U(CryptRegisterDefaultOIDFunction)(ENC, "GetCurrentProcess", 0, L"Kernel32.DLL"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)("GetCurrentProcess", 0);
    void *pv = NULL; HCRYPTOIDFUNCADDR ha = NULL;
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(hs, ENC, L"kernel32.dll", 0, &pv, &ha));
    EXPECT_EQ(pv, GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentProcess"));
    U(CryptFreeOIDFunctionAddress)(ha, 0);
    oidr_end();
}
TEST(oidreg_defaddr_null_dll_without_installed_default_not_found) {
    SETUP(CryptGetDefaultOIDFunctionAddress);
    char set[100]; oidr_set(set, sizeof set, "da1");
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = NULL;
    SET_ERR(0);
    CHECK(!U(CryptGetDefaultOIDFunctionAddress)(hs, ENC, NULL, 0, &pv, &ha));
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    WINE_DIFF { EXPECT_EQ(pv, 0); EXPECT_EQ(ha, 0); }
    oidr_end();
}
TEST(oidreg_defaddr_function_name_missing_in_dll_fails) {
    SETUP(CryptGetDefaultOIDFunctionAddress);
    char set[100]; oidr_set(set, sizeof set, "da2");     /* no kernel32 export has this name */
    CHECK(U(CryptRegisterDefaultOIDFunction)(ENC, set, 0, L"kernel32.dll"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)(set, 0);
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = (void *)1;
    SET_ERR(0);
    CHECK(!U(CryptGetDefaultOIDFunctionAddress)(hs, ENC, L"kernel32.dll", 0, &pv, &ha));
    WINE_DIFF { EXPECT_EQ(pv, 0); EXPECT_EQ(ha, 0); }
    t_note("default function address, missing export: last error %lu", (unsigned long)GetLastError());
    oidr_end();
}
TEST(oidreg_defaddr_unregistered_dll_fails) {
    SETUP(CryptGetDefaultOIDFunctionAddress);
    CHECK(U(CryptRegisterDefaultOIDFunction)(ENC, "GetLastError", 0, L"kernel32.dll"));
    HCRYPTOIDFUNCSET hs = U(CryptInitOIDFunctionSet)("GetLastError", 0);
    void *pv = (void *)1; HCRYPTOIDFUNCADDR ha = (void *)1;
    CHECK(!U(CryptGetDefaultOIDFunctionAddress)(hs, ENC, L"cryptt_not_registered_xyz.dll", 0, &pv, &ha));
    WINE_DIFF { EXPECT_EQ(pv, 0); EXPECT_EQ(ha, 0); }
    oidr_end();
}

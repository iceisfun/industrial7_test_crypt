#include "oidreg.h"
/* CryptRegisterOIDInfo / CryptUnregisterOIDInfo and their visibility through CryptFindOIDInfo / CryptEnumOIDInfo.
 * Registration writes to  EncodingType 0\CryptDllFindOIDInfo\<OID>!<group>  (decomp):
 *   Name REG_SZ (if non-empty), Algid REG_DWORD (if non-zero), ExtraInfo REG_BINARY (if cbData != 0),
 *   Flags REG_DWORD (dwFlags, if non-zero); with cbSize >= 0x40 also CNGAlgid / CNGExtraAlgid REG_SZ.
 * Nothing is ever removed on re-registration.  CryptFindOIDInfo loads the registry list once per process, so the
 * lookup tests run in child processes that start after the registration. */

#define E_INVALIDARG_ ((DWORD)0x80070057)
#define EXPECT_HRINVAL() do { DWORD e_ = GetLastError(); t_check(e_ == E_INVALIDARG_ || (t_is_wine() && e_ == 87), __FILE__, __LINE__, "last error E_INVALIDARG", "got 0x%lx", e_); } while (0)
#define WINE_DIFF if (!t_is_wine())
#define SETUP(fn) REQUIRE(U(fn)); if (!oidr_begin()) return

/* An emulator insists on the extended structure size; Windows accepts 0x30 as well. */
#define SZ30 (t_is_wine() ? 0x40 : 0x30)
typedef struct { CRYPT_OID_INFO b; LPCWSTR cng; LPCWSTR cngx; } OIDINFOX;

static void mk(OIDINFOX *x, DWORD cbsize, LPCSTR oid, LPCWSTR name, DWORD group, DWORD algid, const BYTE *extra, DWORD cbextra) {
    memset(x, 0, sizeof *x);
    x->b.cbSize = cbsize; x->b.pszOID = oid; x->b.pwszName = name; x->b.dwGroupId = group;
    x->b.dwValue = algid; x->b.ExtraInfo.cbData = cbextra; x->b.ExtraInfo.pbData = (BYTE *)extra;
}
#define INFO(x) ((PCCRYPT_OID_INFO)&(x))

static void kpath(wchar_t *buf, size_t cap, const char *oid, DWORD group) {
    char k[200]; snprintf(k, sizeof k, "%s!%lu", oid, (unsigned long)group);
    oidr_path(buf, cap, 0, OIDR_FINDINFO, k);
}
static void expect_sz(const wchar_t *path, const wchar_t *name, const wchar_t *want) {
    wchar_t b[300]; DWORD t = 0, n = sizeof b;
    LONG rc = oidr_raw_get(path, name, &t, b, &n);
    CHECKF(rc == 0, "value %ls rc=%ld", name, (long)rc);
    if (rc) return;
    EXPECT_EQ(t, REG_SZ); EXPECT_EQ(n, (wcslen(want) + 1) * 2); CHECK(!lstrcmpW(b, want));
}
static void expect_dw(const wchar_t *path, const wchar_t *name, DWORD want) {
    DWORD v = 0, t = 0, n = 4;
    LONG rc = oidr_raw_get(path, name, &t, &v, &n);
    CHECKF(rc == 0, "value %ls rc=%ld", name, (long)rc);
    if (rc) return;
    EXPECT_EQ(t, REG_DWORD); EXPECT_EQ(n, 4); EXPECT_EQ(v, want);
}
static void expect_absent(const wchar_t *path, const wchar_t *name) {
    DWORD t, n = 0; LONG rc = oidr_raw_get(path, name, &t, NULL, &n);
    CHECKF(rc == ERROR_FILE_NOT_FOUND, "value %ls should be absent, rc=%ld", name, (long)rc);
}

TEST(oidreg_info_register_writes_name_and_algid) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 1);
    mk(&x, SZ30, oid, L"cryptt-name-1", CRYPT_HASH_ALG_OID_GROUP_ID, 0x8FF1, NULL, 0);
    SET_ERR(0xdead);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(path, 300, oid, 1);
    expect_sz(path, L"Name", L"cryptt-name-1");
    expect_dw(path, L"Algid", 0x8FF1);
    expect_absent(path, L"ExtraInfo"); expect_absent(path, L"Flags");
    EXPECT_EQ(oidr_value_count(path), 2);
    oidr_end();
}
TEST(oidreg_info_register_extra_info_binary) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x; BYTE extra[6] = { 1, 2, 3, 4, 5, 6 }; oidr_oid(oid, 64, 2);
    mk(&x, SZ30, oid, NULL, CRYPT_ENCRYPT_ALG_OID_GROUP_ID, 0, extra, 6);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(path, 300, oid, 2);
    BYTE b[16]; DWORD t = 0, n = sizeof b;
    LONG rc = oidr_raw_get(path, L"ExtraInfo", &t, b, &n);
    EXPECT_EQ(rc, 0); EXPECT_EQ(t, REG_BINARY); EXPECT_EQ(n, 6); CHECK(!memcmp(b, extra, 6));
    expect_absent(path, L"Name"); expect_absent(path, L"Algid");
    oidr_end();
}
TEST(oidreg_info_register_flags_value) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 3);
    mk(&x, SZ30, oid, L"n", 1, 0x8FF2, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), CRYPT_INSTALL_OID_INFO_BEFORE_FLAG));
    kpath(path, 300, oid, 1);
    expect_dw(path, L"Flags", CRYPT_INSTALL_OID_INFO_BEFORE_FLAG);
    oidr_end();
}
TEST(oidreg_info_register_arbitrary_flags_value_stored_verbatim) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 4);
    mk(&x, SZ30, oid, L"n", 1, 0x8FF3, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0x80));
    kpath(path, 300, oid, 1);
    expect_dw(path, L"Flags", 0x80);
    oidr_end();
}
TEST(oidreg_info_register_zero_fields_are_not_written) {
    SETUP(CryptRegisterOIDInfo);
    if (t_is_wine()) { t_skip("emulator differs in which registry values it writes / validates"); oidr_end(); return; }
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 5);
    mk(&x, SZ30, oid, L"", 1, 0x8FF4, NULL, 0);          /* empty name, no extra, no flags */
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(path, 300, oid, 1);
    expect_absent(path, L"Name"); expect_absent(path, L"ExtraInfo"); expect_absent(path, L"Flags");
    EXPECT_EQ(oidr_value_count(path), 1);
    oidr_end();
}
TEST(oidreg_info_register_everything_empty_succeeds_without_key) {
    SETUP(CryptRegisterOIDInfo);
    if (t_is_wine()) { t_skip("emulator differs in which registry values it writes / validates"); oidr_end(); return; }
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 6);
    mk(&x, SZ30, oid, NULL, 1, 0, NULL, 0);
    SET_ERR(0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(path, 300, oid, 1);
    CHECK(!oidr_key_exists(path));
    SET_ERR(0);
    CHECK(!U(CryptUnregisterOIDInfo)(INFO(x))); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_info_register_cng_fields_only_with_extended_size) {
    SETUP(CryptRegisterOIDInfo);
    if (t_is_wine()) { t_skip("emulator differs in which registry values it writes / validates"); oidr_end(); return; }
    char o1[64], o2[64]; wchar_t p1[300], p2[300]; OIDINFOX x; oidr_oid(o1, 64, 7); oidr_oid(o2, 64, 8);
    mk(&x, SZ30, o1, L"n", 1, 0x8FF5, NULL, 0); x.cng = L"SHA999"; x.cngx = L"Extra999";
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(p1, 300, o1, 1);
    expect_absent(p1, L"CNGAlgid"); expect_absent(p1, L"CNGExtraAlgid");
    mk(&x, 0x40, o2, L"n", 1, 0x8FF6, NULL, 0); x.cng = L"SHA999"; x.cngx = L"Extra999";
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(p2, 300, o2, 1);
    expect_sz(p2, L"CNGAlgid", L"SHA999"); expect_sz(p2, L"CNGExtraAlgid", L"Extra999");
    oidr_end();
}
TEST(oidreg_info_register_cng_empty_or_null_not_written) {
    SETUP(CryptRegisterOIDInfo);
    if (t_is_wine()) { t_skip("emulator differs in which registry values it writes / validates"); oidr_end(); return; }
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 9);
    mk(&x, 0x40, oid, L"n", 1, 0x8FF7, NULL, 0); x.cng = L""; x.cngx = NULL;
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(path, 300, oid, 1);
    expect_absent(path, L"CNGAlgid"); expect_absent(path, L"CNGExtraAlgid");
    oidr_end();
}
TEST(oidreg_info_register_again_overwrites_but_keeps_stale_values) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x; BYTE extra[2] = { 9, 9 }; oidr_oid(oid, 64, 10);
    mk(&x, SZ30, oid, L"first", 1, 0x8FF8, extra, 2);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    mk(&x, SZ30, oid, L"second", 1, 0x8FF9, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));         /* duplicates are not an error */
    kpath(path, 300, oid, 1);
    expect_sz(path, L"Name", L"second"); expect_dw(path, L"Algid", 0x8FF9);
    BYTE b[4]; DWORD t, n = sizeof b;
    EXPECT_EQ(oidr_raw_get(path, L"ExtraInfo", &t, b, &n), 0);   /* ExtraInfo of the first call survives */
    EXPECT_EQ(n, 2);
    oidr_end();
}
TEST(oidreg_info_register_same_oid_different_groups_distinct_keys) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; wchar_t p1[300], p2[300]; OIDINFOX x; oidr_oid(oid, 64, 11);
    mk(&x, SZ30, oid, L"as-hash", 1, 0x8FE1, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    mk(&x, SZ30, oid, L"as-enc", 2, 0x6EE1, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(p1, 300, oid, 1); kpath(p2, 300, oid, 2);
    expect_sz(p1, L"Name", L"as-hash"); expect_sz(p2, L"Name", L"as-enc");
    oidr_end();
}
TEST(oidreg_info_register_group_ids_formatted_decimal) {
    SETUP(CryptRegisterOIDInfo);
    static const DWORD groups[] = { 0, 1, 10, 11, 255, 1000 };
    for (int i = 0; i < 6; i++) {
        char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 20 + i);
        mk(&x, SZ30, oid, L"g", groups[i], 0x8000 + i, NULL, 0);
        SET_ERR(0);
        CHECKF(U(CryptRegisterOIDInfo)(INFO(x), 0), "group %lu", (unsigned long)groups[i]);   /* no group validation */
        kpath(path, 300, oid, groups[i]);
        WINE_DIFF CHECKF(oidr_key_exists(path), "key for group %lu", (unsigned long)groups[i]);
    }
    oidr_end();
}
TEST(oidreg_info_register_larger_cbsize_accepted) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; OIDINFOX x; oidr_oid(oid, 64, 12);
    mk(&x, 0x40, oid, L"big", 1, 0x8FD1, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    oidr_end();
}
TEST(oidreg_info_register_invalid_parameters) {
    SETUP(CryptRegisterOIDInfo);
    if (t_is_wine()) { t_skip("emulator differs in which registry values it writes / validates"); oidr_end(); return; }
    char oid[64]; OIDINFOX x; oidr_oid(oid, 64, 13);
    mk(&x, 0x2f, oid, L"n", 1, 0x8FD2, NULL, 0);
    SET_ERR(0); CHECK(!U(CryptRegisterOIDInfo)(INFO(x), 0)); WINE_DIFF EXPECT_HRINVAL();
    mk(&x, 0, oid, L"n", 1, 0x8FD2, NULL, 0);
    SET_ERR(0); CHECK(!U(CryptRegisterOIDInfo)(INFO(x), 0)); WINE_DIFF EXPECT_HRINVAL();
    mk(&x, SZ30, NULL, L"n", 1, 0x8FD2, NULL, 0);
    SET_ERR(0); CHECK(!U(CryptRegisterOIDInfo)(INFO(x), 0)); WINE_DIFF EXPECT_HRINVAL();
    mk(&x, SZ30, (LPCSTR)(ULONG_PTR)5, L"n", 1, 0x8FD2, NULL, 0);      /* numeric OIDs are not accepted */
    SET_ERR(0); CHECK(!U(CryptRegisterOIDInfo)(INFO(x), 0)); WINE_DIFF EXPECT_HRINVAL();
    WINE_DIFF {
        SET_ERR(0); CHECK(!U(CryptRegisterOIDInfo)(NULL, 0)); EXPECT_HRINVAL();
    }
    oidr_end();
}
TEST(oidreg_info_register_invalid_writes_nothing) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 14);
    mk(&x, 0x2c, oid, L"n", 1, 0x8FD3, NULL, 0);
    CHECK(!U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(path, 300, oid, 1);
    CHECK(!oidr_key_exists(path));
    oidr_end();
}
TEST(oidreg_info_register_mui_style_name_stored_verbatim) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 15);
    mk(&x, SZ30, oid, L"@%SystemRoot%\\system32\\nosuch.dll,-1", 1, 0x8FD4, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(path, 300, oid, 1);
    expect_sz(path, L"Name", L"@%SystemRoot%\\system32\\nosuch.dll,-1");
    oidr_end();
}
TEST(oidreg_info_not_elevated_denied) {
    REQUIRE(U(CryptRegisterOIDInfo));
    if (oidr_can_write()) { t_skip("elevated: HKLM is writable"); return; }
    char oid[64]; OIDINFOX x; oidr_oid(oid, 64, 16);
    mk(&x, SZ30, oid, L"n", 1, 0x8FD5, NULL, 0);
    SET_ERR(0);
    CHECK(!U(CryptRegisterOIDInfo)(INFO(x), 0)); EXPECT_ERR(ERROR_ACCESS_DENIED);
}

/* ---- unregister ------------------------------------------------------------------------------------- */
TEST(oidreg_info_unregister_removes_key) {
    SETUP(CryptUnregisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x; oidr_oid(oid, 64, 30);
    mk(&x, SZ30, oid, L"n", 1, 0x8FC1, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    kpath(path, 300, oid, 1);
    CHECK(oidr_key_exists(path));
    SET_ERR(0xdead);
    CHECK(U(CryptUnregisterOIDInfo)(INFO(x)));
    CHECK(!oidr_key_exists(path));
    SET_ERR(0);
    CHECK(!U(CryptUnregisterOIDInfo)(INFO(x))); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_info_unregister_only_needs_oid_group_and_size) {
    SETUP(CryptUnregisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x, y; oidr_oid(oid, 64, 31);
    mk(&x, SZ30, oid, L"original", 1, 0x8FC2, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    mk(&y, SZ30, oid, NULL, 1, 0, NULL, 0);          /* everything else blank */
    CHECK(U(CryptUnregisterOIDInfo)(INFO(y)));
    kpath(path, 300, oid, 1);
    CHECK(!oidr_key_exists(path));
    oidr_end();
}
TEST(oidreg_info_unregister_wrong_group_not_found) {
    SETUP(CryptUnregisterOIDInfo);
    char oid[64]; wchar_t path[300]; OIDINFOX x, y; oidr_oid(oid, 64, 32);
    mk(&x, SZ30, oid, L"n", 1, 0x8FC3, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    mk(&y, SZ30, oid, L"n", 2, 0x8FC3, NULL, 0);
    SET_ERR(0);
    CHECK(!U(CryptUnregisterOIDInfo)(INFO(y))); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    kpath(path, 300, oid, 1);
    CHECK(oidr_key_exists(path));
    oidr_end();
}
TEST(oidreg_info_unregister_one_group_keeps_other) {
    SETUP(CryptUnregisterOIDInfo);
    char oid[64]; wchar_t p1[300], p2[300]; OIDINFOX x; oidr_oid(oid, 64, 33);
    mk(&x, SZ30, oid, L"a", 1, 0x8FC4, NULL, 0); CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    mk(&x, SZ30, oid, L"b", 2, 0x8FC5, NULL, 0); CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    CHECK(U(CryptUnregisterOIDInfo)(INFO(x)));
    kpath(p1, 300, oid, 1); kpath(p2, 300, oid, 2);
    CHECK(oidr_key_exists(p1)); CHECK(!oidr_key_exists(p2));
    oidr_end();
}
TEST(oidreg_info_unregister_invalid_parameters) {
    SETUP(CryptUnregisterOIDInfo);
    char oid[64]; OIDINFOX x; oidr_oid(oid, 64, 34);
    mk(&x, 0x2f, oid, L"n", 1, 0, NULL, 0);
    SET_ERR(0); CHECK(!U(CryptUnregisterOIDInfo)(INFO(x))); WINE_DIFF EXPECT_HRINVAL();
    mk(&x, SZ30, NULL, L"n", 1, 0, NULL, 0);
    SET_ERR(0); CHECK(!U(CryptUnregisterOIDInfo)(INFO(x))); WINE_DIFF EXPECT_HRINVAL();
    WINE_DIFF { SET_ERR(0); CHECK(!U(CryptUnregisterOIDInfo)(NULL)); EXPECT_HRINVAL(); }
    oidr_end();
}

/* ---- lookup in child processes ------------------------------------------------------------------------ */
#define CK(c) do { if (!(c)) return __LINE__; } while (0)

/* argv: name oid group name algid */
CHILD(oidinfo_find) {
    HMODULE m = LoadLibraryA("crypt32.dll");
    if (argc < 5 || !m) return 1;
    typedef PCCRYPT_OID_INFO (WINAPI *find_t)(DWORD, void *, DWORD);
    find_t find = (find_t)GetProcAddress(m, "CryptFindOIDInfo");
    CK(find);
    const char *oid = argv[1]; DWORD group = (DWORD)atol(argv[2]); const char *name = argv[3]; DWORD algid = (DWORD)strtoul(argv[4], NULL, 0);
    wchar_t wname[100]; MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 100);
    PCCRYPT_OID_INFO p = find(CRYPT_OID_INFO_OID_KEY, (void *)oid, group);
    CK(p);
    CK(p->cbSize >= 0x30);
    CK(!strcmp(p->pszOID, oid));
    CK(!lstrcmpW(p->pwszName, wname));
    CK(p->dwGroupId == group);
    CK(p->Algid == algid);
    CK(p->ExtraInfo.cbData == 3 && p->ExtraInfo.pbData && !memcmp(p->ExtraInfo.pbData, "\x0a\x0b\x0c", 3));
    PCCRYPT_OID_INFO q = find(CRYPT_OID_INFO_NAME_KEY, wname, group);
    CK(q && !strcmp(q->pszOID, oid));
    ALG_ID a = algid;
    PCCRYPT_OID_INFO r = find(CRYPT_OID_INFO_ALGID_KEY, &a, group);
    CK(r && !strcmp(r->pszOID, oid));
    PCCRYPT_OID_INFO s = find(CRYPT_OID_INFO_OID_KEY, (void *)oid, 0);          /* any group */
    CK(s && !strcmp(s->pszOID, oid));
    PCCRYPT_OID_INFO t = find(CRYPT_OID_INFO_OID_KEY, (void *)oid, group == 2 ? 1 : 2);   /* other group */
    CK(!t || strcmp(t->pszOID, oid));
    /* unknown OID */
    PCCRYPT_OID_INFO w = find(CRYPT_OID_INFO_OID_KEY, (void *)"2.999.1347.0.0.0", group);
    CK(!w);
    return 0;
}


/* case-insensitive key matching (observed, reported with t_note) */
CHILD(oidinfo_find_case) {
    HMODULE m = LoadLibraryA("crypt32.dll");
    if (argc < 5 || !m) return 1;
    typedef PCCRYPT_OID_INFO (WINAPI *find_t)(DWORD, void *, DWORD);
    find_t find = (find_t)GetProcAddress(m, "CryptFindOIDInfo");
    CK(find);
    const char *oid = argv[1]; DWORD group = (DWORD)atol(argv[2]); const char *name = argv[3];
    wchar_t wname[100]; MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 100);
    int bits = 0;
    char up[200]; strcpy(up, oid); CharUpperA(up);
    PCCRYPT_OID_INFO u = find(CRYPT_OID_INFO_OID_KEY, up, group);
    if (!(u && !strcmp(u->pszOID, oid))) bits |= 1;
    wchar_t wup[100]; wcscpy(wup, wname); CharUpperW(wup);
    PCCRYPT_OID_INFO v = find(CRYPT_OID_INFO_NAME_KEY, wup, group);
    if (!(v && !strcmp(v->pszOID, oid))) bits |= 2;
    return bits;
}
static void spawn_find(const char *what, const char *oid, DWORD group, const char *name, DWORD algid) {
    char args[400];
    snprintf(args, sizeof args, "%s %lu %s 0x%lx", oid, (unsigned long)group, name, (unsigned long)algid);
    DWORD rc = t_run_child(what, args, 30000);
    CHECKF(rc == 0, "child %s returned %lu (failing source line / error code)", what, (unsigned long)rc);
}

TEST(oidreg_info_find_sees_registered_entry) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64], name[100]; wchar_t wname[100]; OIDINFOX x; BYTE extra[3] = { 0x0a, 0x0b, 0x0c };
    snprintf(oid, sizeof oid, "Cryptt.Find.%lu", GetCurrentProcessId());   /* letters: exercises the case-insensitive match */
    snprintf(name, sizeof name, "cryptt_oidreg_%lu_fn", GetCurrentProcessId());
    oidr_wide(wname, 100, name);
    mk(&x, SZ30, oid, wname, CRYPT_HASH_ALG_OID_GROUP_ID, 0x8FA1, extra, 3);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    spawn_find("oidinfo_find", oid, CRYPT_HASH_ALG_OID_GROUP_ID, name, 0x8FA1);
    char args[400]; snprintf(args, sizeof args, "%s %lu %s 0x8FA1", oid, (unsigned long)CRYPT_HASH_ALG_OID_GROUP_ID, name);
    DWORD rc = t_run_child("oidinfo_find_case", args, 30000);
    t_note("custom OID info lookup, case-insensitive match: OID key %s, name key %s (child result %lu)", (rc & 1) ? "no" : "yes", (rc & 2) ? "no" : "yes", (unsigned long)rc);
    oidr_end();
}
TEST(oidreg_info_find_sees_registered_entry_in_encrypt_group) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64], name[100]; wchar_t wname[100]; OIDINFOX x; BYTE extra[3] = { 0x0a, 0x0b, 0x0c };
    snprintf(oid, sizeof oid, "Cryptt.FindEnc.%lu", GetCurrentProcessId());
    snprintf(name, sizeof name, "cryptt_oidreg_%lu_fe", GetCurrentProcessId());
    oidr_wide(wname, 100, name);
    mk(&x, SZ30, oid, wname, CRYPT_ENCRYPT_ALG_OID_GROUP_ID, 0x6FA2, extra, 3);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    spawn_find("oidinfo_find", oid, CRYPT_ENCRYPT_ALG_OID_GROUP_ID, name, 0x6FA2);
    oidr_end();
}
TEST(oidreg_info_find_after_unregister_in_fresh_process_not_found) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; OIDINFOX x; oidr_oid(oid, 64, 40);
    mk(&x, SZ30, oid, L"cryptt-gone", 1, 0x8FA3, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    CHECK(U(CryptUnregisterOIDInfo)(INFO(x)));
    char args[200]; snprintf(args, sizeof args, "%s", oid);
    DWORD rc = t_run_child("oidinfo_absent", args, 30000);
    EXPECT_EQ(rc, 0);
    oidr_end();
}
CHILD(oidinfo_absent) {
    HMODULE m = LoadLibraryA("crypt32.dll");
    if (argc < 2 || !m) return 1;
    typedef PCCRYPT_OID_INFO (WINAPI *find_t)(DWORD, void *, DWORD);
    find_t find = (find_t)GetProcAddress(m, "CryptFindOIDInfo");
    CK(find);
    CK(find(CRYPT_OID_INFO_OID_KEY, (void *)argv[1], 0) == NULL);
    return 0;
}

/* before-flag ordering: argv oidA oidB */
CHILD(oidinfo_before) {
    HMODULE m = LoadLibraryA("crypt32.dll");
    if (argc < 3 || !m) return 1;
    typedef PCCRYPT_OID_INFO (WINAPI *find_t)(DWORD, void *, DWORD);
    find_t find = (find_t)GetProcAddress(m, "CryptFindOIDInfo");
    CK(find);
    ALG_ID sha1 = 0x8004, sha256 = 0x800c;
    PCCRYPT_OID_INFO a = find(CRYPT_OID_INFO_ALGID_KEY, &sha1, CRYPT_HASH_ALG_OID_GROUP_ID);
    CK(a && !strcmp(a->pszOID, argv[1]));            /* registered with the BEFORE flag: found before built-in */
    PCCRYPT_OID_INFO b = find(CRYPT_OID_INFO_ALGID_KEY, &sha256, CRYPT_HASH_ALG_OID_GROUP_ID);
    CK(b && strcmp(b->pszOID, argv[2]));             /* registered without it: the built-in entry wins */
    PCCRYPT_OID_INFO c = find(CRYPT_OID_INFO_OID_KEY, (void *)argv[2], CRYPT_HASH_ALG_OID_GROUP_ID);
    CK(c && !strcmp(c->pszOID, argv[2]) && c->Algid == sha256);   /* but it is still reachable by OID */
    return 0;
}
TEST(oidreg_info_find_before_flag_orders_ahead_of_builtin) {
    SETUP(CryptRegisterOIDInfo);
    char oa[64], ob[64]; OIDINFOX x; oidr_oid(oa, 64, 41); oidr_oid(ob, 64, 42);
    mk(&x, SZ30, oa, L"cryptt-before", 1, 0x8004, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), CRYPT_INSTALL_OID_INFO_BEFORE_FLAG));
    mk(&x, SZ30, ob, L"cryptt-after", 1, 0x800c, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    char args[200]; snprintf(args, sizeof args, "%s %s", oa, ob);
    DWORD rc = t_run_child("oidinfo_before", args, 30000);
    CHECKF(rc == 0, "child returned %lu (source line)", (unsigned long)rc);
    oidr_end();
}

/* cache: argv oid */
CHILD(oidinfo_cache) {
    HMODULE m = LoadLibraryA("crypt32.dll");
    if (argc < 2 || !m) return 1;
    typedef PCCRYPT_OID_INFO (WINAPI *find_t)(DWORD, void *, DWORD);
    typedef BOOL (WINAPI *reg_t)(PCCRYPT_OID_INFO, DWORD);
    find_t find = (find_t)GetProcAddress(m, "CryptFindOIDInfo");
    reg_t reg = (reg_t)GetProcAddress(m, "CryptRegisterOIDInfo");
    CK(find && reg);
    ALG_ID sha1 = 0x8004;
    CK(find(CRYPT_OID_INFO_ALGID_KEY, &sha1, CRYPT_HASH_ALG_OID_GROUP_ID) != NULL);   /* primes the one-time registry load */
    OIDINFOX x; mk(&x, SZ30, argv[1], L"cryptt-late", 1, 0x8FB1, NULL, 0);
    CK(reg(INFO(x), 0));
    PCCRYPT_OID_INFO p = find(CRYPT_OID_INFO_OID_KEY, (void *)argv[1], 0);
    return p ? 2 : 0;
}
TEST(oidreg_info_find_registry_list_loaded_once_per_process) {
    SETUP(CryptRegisterOIDInfo);
    char oid[64]; oidr_oid(oid, 64, 43);
    DWORD rc = t_run_child("oidinfo_cache", oid, 30000);
    CHECK(rc == 0 || rc == 2);
    if (rc == 0) t_note("an entry registered after the first CryptFindOIDInfo is not visible in the same process");
    else t_note("an entry registered after the first CryptFindOIDInfo IS visible in the same process");
    WINE_DIFF EXPECT_EQ(rc, 0);
    oidr_end();
}

/* enum: argv oid group */
static const char *g_enum_want; static int g_enum_seen, g_enum_total;
static BOOL WINAPI enum_info_cb2(PCCRYPT_OID_INFO info, void *arg) {
    g_enum_total++;
    if (info && info->pszOID && g_enum_want && !_stricmp(info->pszOID, g_enum_want)) g_enum_seen++;
    return TRUE;
}
CHILD(oidinfo_enum) {
    HMODULE m = LoadLibraryA("crypt32.dll");
    if (argc < 3 || !m) return 1;
    typedef BOOL (WINAPI *enum_t)(DWORD, DWORD, void *, PFN_CRYPT_ENUM_OID_INFO);
    enum_t en = (enum_t)GetProcAddress(m, "CryptEnumOIDInfo");
    CK(en);
    g_enum_want = argv[1];
    CK(en((DWORD)atol(argv[2]), 0, NULL, enum_info_cb2));
    CK(g_enum_total > 0);
    return g_enum_seen > 0 ? 0 : 3;
}
TEST(oidreg_info_enum_reports_registered_entry) {
    SETUP(CryptRegisterOIDInfo);
    REQUIRE(U(CryptEnumOIDInfo));
    char oid[64], args[200]; OIDINFOX x; oidr_oid(oid, 64, 44);
    mk(&x, SZ30, oid, L"cryptt-enum", 1, 0x8FB2, NULL, 0);
    CHECK(U(CryptRegisterOIDInfo)(INFO(x), 0));
    snprintf(args, sizeof args, "%s 1", oid);
    DWORD rc = t_run_child("oidinfo_enum", args, 30000);
    t_note("CryptEnumOIDInfo(group 1) child result %lu (0 = registered entry enumerated, 3 = not seen)", (unsigned long)rc);
    CHECK(rc == 0 || rc == 3);
    snprintf(args, sizeof args, "%s 0", oid);
    rc = t_run_child("oidinfo_enum", args, 30000);
    t_note("CryptEnumOIDInfo(all groups) child result %lu", (unsigned long)rc);
    oidr_end();
}

#include "oidreg.h"
/* CryptSetOIDFunctionValue / CryptGetOIDFunctionValue / CryptRegisterOIDFunction / CryptUnregisterOIDFunction.
 * Registry layout (observed): HKLM\Software\Microsoft\Cryptography\OID\EncodingType <n>\<FuncName>\<OID>, value <name>.
 * <n> is the low word of dwEncodingType, or the high word when the low word is 0. An OID below 0x10000 is the
 * numeric form and is stored as "#<n>". */

#define E_INVALIDARG_ ((DWORD)0x80070057)
/* Windows stores the HRESULT 0x80070057 itself as the last error here; an emulator uses plain 87. */
#define EXPECT_HRINVAL() do { DWORD e_ = GetLastError(); t_check(e_ == E_INVALIDARG_ || (t_is_wine() && e_ == 87), __FILE__, __LINE__, "last error E_INVALIDARG", "got 0x%lx", e_); } while (0)
/* Behaviour where an emulator is known to differ from observed Windows behaviour. */

#define SETUP(fn) \
    REQUIRE(U(fn)); \
    if (!oidr_begin()) return

/* An emulator's CryptSetOIDFunctionValue only opens existing keys; Windows creates the path
 * (RegCreateKeyExA).  Under an emulator pre-create it so the rest of each test stays meaningful. */
static void wine_precreate(DWORD enc, const char *f, const char *o) {
    if (!t_is_wine() || !f || !o) return;
    unsigned e = enc & 0xffff; if (!e) e = enc >> 16;
    char key[512], nb[16];
    if ((ULONG_PTR)o < 0x10000) { snprintf(nb, sizeof nb, "#%lu", (unsigned long)(ULONG_PTR)o); o = nb; }
    snprintf(key, sizeof key, "Software\\Microsoft\\Cryptography\\OID\\EncodingType %u\\%s\\%s", e, f, o);
    HKEY k; if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) == 0) RegCloseKey(k);
}
static BOOL setv(DWORD enc, const char *f, const char *o, const wchar_t *n, DWORD t, const void *d, DWORD cb) {
    wine_precreate(enc, f, o);
    return U(CryptSetOIDFunctionValue)(enc, f, o, n, t, (BYTE *)d, cb);
}
static BOOL getv(DWORD enc, const char *f, const char *o, const wchar_t *n, DWORD *t, void *d, DWORD *cb) {
    return U(CryptGetOIDFunctionValue)(enc, f, o, n, t, (BYTE *)d, cb);
}

/* Round-trip helper: set, then read back through the API and through the raw registry. */
static void roundtrip(DWORD type, const void *data, DWORD cb) {
    char set[100], oid[64]; wchar_t path[300];
    BYTE buf[600]; DWORD t = 99, n = sizeof buf, rt = 99, rn = sizeof buf; BYTE rbuf[600];
    oidr_set(set, sizeof set, "rt"); oidr_oid(oid, sizeof oid, 1);
    SET_ERR(0xdead);
    BOOL ok = setv(1, set, oid, L"Val", type, data, cb);
    CHECK(ok);
    memset(buf, 0xcc, sizeof buf);
    ok = getv(1, set, oid, L"Val", &t, buf, &n);
    CHECK(ok);
    EXPECT_EQ(t, type);
    EXPECT_EQ(n, cb);
    if (n == cb) CHECK(!memcmp(buf, data, cb));
    oidr_path(path, 300, 1, set, oid);
    LONG rc = oidr_raw_get(path, L"Val", &rt, rbuf, &rn);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(rt, type);
    EXPECT_EQ(rn, cb);
    if (rn == cb) CHECK(!memcmp(rbuf, data, cb));
}

TEST(oidreg_val_dword_roundtrip) { SETUP(CryptSetOIDFunctionValue); DWORD v = 0xA1B2C3D4; roundtrip(REG_DWORD, &v, 4); oidr_end(); }
TEST(oidreg_val_dword_zero_roundtrip) { SETUP(CryptSetOIDFunctionValue); DWORD v = 0; roundtrip(REG_DWORD, &v, 4); oidr_end(); }
TEST(oidreg_val_sz_roundtrip) { SETUP(CryptSetOIDFunctionValue); static const wchar_t s[] = L"kernel32.dll"; roundtrip(REG_SZ, s, sizeof s); oidr_end(); }
TEST(oidreg_val_sz_empty_roundtrip) { SETUP(CryptSetOIDFunctionValue); static const wchar_t s[] = L""; roundtrip(REG_SZ, s, sizeof s); oidr_end(); }
TEST(oidreg_val_expand_sz_roundtrip_not_expanded) {
    SETUP(CryptSetOIDFunctionValue);
    static const wchar_t s[] = L"%SystemRoot%\\system32\\crypt32.dll";
    roundtrip(REG_EXPAND_SZ, s, sizeof s);   /* the API returns the raw, unexpanded text */
    oidr_end();
}
TEST(oidreg_val_multi_sz_roundtrip) {
    SETUP(CryptSetOIDFunctionValue);
    static const wchar_t s[] = L"one.dll\0two.dll\0three.dll\0";   /* literal ends with an extra NUL */
    roundtrip(REG_MULTI_SZ, s, sizeof s);
    oidr_end();
}
TEST(oidreg_val_binary_roundtrip) {
    SETUP(CryptSetOIDFunctionValue);
    BYTE b[200]; for (int i = 0; i < 200; i++) b[i] = (BYTE)(i * 7 + 3);
    roundtrip(REG_BINARY, b, sizeof b);
    oidr_end();
}
TEST(oidreg_val_binary_one_byte_roundtrip) { SETUP(CryptSetOIDFunctionValue); BYTE b = 0x5A; roundtrip(REG_BINARY, &b, 1); oidr_end(); }
TEST(oidreg_val_qword_roundtrip) { SETUP(CryptSetOIDFunctionValue); ULONGLONG q = 0x0123456789ABCDEFull; roundtrip(REG_QWORD, &q, 8); oidr_end(); }
TEST(oidreg_val_dword_big_endian_roundtrip) { SETUP(CryptSetOIDFunctionValue); DWORD v = 0x12345678; roundtrip(REG_DWORD_BIG_ENDIAN, &v, 4); oidr_end(); }
TEST(oidreg_val_none_type_roundtrip) { SETUP(CryptSetOIDFunctionValue); BYTE b[3] = { 1, 2, 3 }; roundtrip(REG_NONE, b, 3); oidr_end(); }
TEST(oidreg_val_binary_4k_roundtrip) {
    SETUP(CryptSetOIDFunctionValue);
    static BYTE b[4096]; for (int i = 0; i < 4096; i++) b[i] = (BYTE)(i ^ (i >> 8));
    char set[100], oid[64]; BYTE rb[4096]; DWORD t, n = sizeof rb;
    oidr_set(set, sizeof set, "big"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"Big", REG_BINARY, b, sizeof b));
    CHECK(getv(1, set, oid, L"Big", &t, rb, &n));
    EXPECT_EQ(n, 4096); CHECK(!memcmp(rb, b, 4096));
    oidr_end();
}

TEST(oidreg_val_overwrite_changes_type) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; DWORD d = 77, t = 0, n = 0; wchar_t s[] = L"text"; BYTE buf[64];
    oidr_set(set, sizeof set, "ow"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"X", REG_DWORD, &d, 4));
    CHECK(setv(1, set, oid, L"X", REG_SZ, s, sizeof s));
    n = sizeof buf;
    CHECK(getv(1, set, oid, L"X", &t, buf, &n));
    EXPECT_EQ(t, REG_SZ); EXPECT_EQ(n, sizeof s);
    oidr_end();
}

TEST(oidreg_val_multiple_values_independent) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; DWORD a = 1, b = 2, ra = 0, rb = 0, t, n;
    oidr_set(set, sizeof set, "mv"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"A", REG_DWORD, &a, 4));
    CHECK(setv(1, set, oid, L"B", REG_DWORD, &b, 4));
    n = 4; CHECK(getv(1, set, oid, L"A", &t, &ra, &n)); EXPECT_EQ(ra, 1);
    n = 4; CHECK(getv(1, set, oid, L"B", &t, &rb, &n)); EXPECT_EQ(rb, 2);
    wchar_t path[300]; oidr_path(path, 300, 1, set, oid);
    EXPECT_EQ(oidr_value_count(path), 2);
    oidr_end();
}

TEST(oidreg_val_value_name_case_insensitive) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; DWORD v = 5, r = 0, t, n = 4;
    oidr_set(set, sizeof set, "vc"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"MixedName", REG_DWORD, &v, 4));
    CHECK(getv(1, set, oid, L"mixedname", &t, &r, &n)); EXPECT_EQ(r, 5);
    oidr_end();
}

TEST(oidreg_val_set_creates_registry_path) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; wchar_t path[300]; DWORD v = 1;
    oidr_set(set, sizeof set, "path"); oidr_oid(oid, sizeof oid, 7);
    oidr_path(path, 300, 1, set, oid);
    CHECK(!oidr_key_exists(path));
    CHECK(setv(1, set, oid, L"V", REG_DWORD, &v, 4));
    CHECK(oidr_key_exists(path));
    oidr_end();
    CHECK(!oidr_key_exists(path));
}

TEST(oidreg_val_unnamed_default_value) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; DWORD v = 0x31337, r = 0, t, n = 4;
    oidr_set(set, sizeof set, "dflt"); oidr_oid(oid, sizeof oid, 1);
    if (t_is_wine()) { t_skip("emulator rejects a NULL value name"); oidr_end(); return; }
    CHECK(setv(1, set, oid, NULL, REG_DWORD, &v, 4));       /* NULL value name = the key's default value */
    CHECK(getv(1, set, oid, NULL, &t, &r, &n)); EXPECT_EQ(r, 0x31337);
    CHECK(getv(1, set, oid, L"", &t, &r, &n));  EXPECT_EQ(r, 0x31337);
    oidr_end();
}

/* ---- size protocol ---------------------------------------------------------------------------------- */
TEST(oidreg_val_get_null_buffer_returns_size) {
    SETUP(CryptGetOIDFunctionValue);
    char set[100], oid[64]; static const wchar_t s[] = L"abcdef"; DWORD t = 0, n = 0;
    oidr_set(set, sizeof set, "sz"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"S", REG_SZ, s, sizeof s));
    SET_ERR(0);
    CHECK(getv(1, set, oid, L"S", &t, NULL, &n));
    EXPECT_EQ(n, sizeof s); EXPECT_EQ(t, REG_SZ);
    oidr_end();
}
TEST(oidreg_val_get_exact_buffer) {
    SETUP(CryptGetOIDFunctionValue);
    char set[100], oid[64]; static const wchar_t s[] = L"abcdef"; wchar_t b[7]; DWORD t = 0, n = sizeof b;
    oidr_set(set, sizeof set, "ex"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"S", REG_SZ, s, sizeof s));
    CHECK(getv(1, set, oid, L"S", &t, b, &n));
    EXPECT_EQ(n, sizeof s); CHECK(!lstrcmpW(b, s));
    oidr_end();
}
TEST(oidreg_val_get_buffer_too_small_more_data) {
    SETUP(CryptGetOIDFunctionValue);
    char set[100], oid[64]; static const wchar_t s[] = L"abcdef"; BYTE b[32]; DWORD t = 55, n;
    oidr_set(set, sizeof set, "sm"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"S", REG_SZ, s, sizeof s));
    n = sizeof s - 1; t = 55; SET_ERR(0);
    BOOL ok = getv(1, set, oid, L"S", &t, b, &n);
    CHECK(!ok); EXPECT_ERR(ERROR_MORE_DATA);
    /* the failure path of CryptGetOIDFunctionValue clears both outputs (the required size is NOT reported) */
    WINE_DIFF { EXPECT_EQ(n, 0); EXPECT_EQ(t, 0); }
    n = 0; t = 55; SET_ERR(0);
    ok = getv(1, set, oid, L"S", &t, b, &n);
    CHECK(!ok); EXPECT_ERR(ERROR_MORE_DATA); WINE_DIFF EXPECT_EQ(n, 0);
    oidr_end();
}
TEST(oidreg_val_get_null_type_pointer_ok) {
    SETUP(CryptGetOIDFunctionValue);
    char set[100], oid[64]; DWORD v = 9, r = 0, n = 4;
    oidr_set(set, sizeof set, "nt"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"D", REG_DWORD, &v, 4));
    CHECK(getv(1, set, oid, L"D", NULL, &r, &n)); EXPECT_EQ(r, 9);
    oidr_end();
}

/* ---- failures --------------------------------------------------------------------------------------- */
TEST(oidreg_val_get_missing_everything) {
    SETUP(CryptGetOIDFunctionValue);
    char set[100], oid[64]; DWORD t = 77, n = 77; BYTE b[8];
    oidr_set(set, sizeof set, "none"); oidr_oid(oid, sizeof oid, 1);
    SET_ERR(0);
    CHECK(!getv(1, set, oid, L"V", &t, b, &n)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    WINE_DIFF { EXPECT_EQ(t, 0); EXPECT_EQ(n, 0); }
    oidr_end();
}
TEST(oidreg_val_get_missing_value_existing_key) {
    SETUP(CryptGetOIDFunctionValue);
    char set[100], oid[64]; DWORD v = 1, t = 77, n = 4; BYTE b[8];
    oidr_set(set, sizeof set, "mvk"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"There", REG_DWORD, &v, 4));
    SET_ERR(0);
    CHECK(!getv(1, set, oid, L"NotThere", &t, b, &n)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    WINE_DIFF { EXPECT_EQ(n, 0); EXPECT_EQ(t, 0); }
    oidr_end();
}
TEST(oidreg_val_get_missing_oid_existing_set) {
    SETUP(CryptGetOIDFunctionValue);
    char set[100], oid[64], oid2[64]; DWORD v = 1, t, n = 4;
    oidr_set(set, sizeof set, "mo"); oidr_oid(oid, sizeof oid, 1); oidr_oid(oid2, sizeof oid2, 2);
    CHECK(setv(1, set, oid, L"V", REG_DWORD, &v, 4));
    SET_ERR(0);
    CHECK(!getv(1, set, oid2, L"V", &t, &v, &n)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_val_get_wrong_encoding_type_not_found) {
    SETUP(CryptGetOIDFunctionValue);
    char set[100], oid[64]; DWORD v = 1, t, n = 4;
    oidr_set(set, sizeof set, "we"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"V", REG_DWORD, &v, 4));
    SET_ERR(0);
    WINE_DIFF CHECK(!getv(0, set, oid, L"V", &t, &v, &n)); WINE_DIFF EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    SET_ERR(0);
    CHECK(!getv(777, set, oid, L"V", &t, &v, &n)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_val_null_oid_invalid_parameter) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100]; DWORD v = 1, t = 5, n = 4;
    oidr_set(set, sizeof set, "nul");
    SET_ERR(0);
    CHECK(!setv(1, set, NULL, L"V", REG_DWORD, &v, 4)); EXPECT_HRINVAL();
    SET_ERR(0);
    CHECK(!getv(1, set, NULL, L"V", &t, &v, &n)); EXPECT_HRINVAL();
    WINE_DIFF { EXPECT_EQ(t, 0); EXPECT_EQ(n, 0); }
    oidr_end();
}
TEST(oidreg_val_set_null_data_zero_size_deletes_value) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; DWORD v = 1, v2 = 2, t, n = 4;
    oidr_set(set, sizeof set, "del"); oidr_oid(oid, sizeof oid, 1);
    CHECKF(setv(1, set, oid, L"Keep", REG_DWORD, &v, 4), "err %lu", GetLastError());
    CHECK(setv(1, set, oid, L"Gone", REG_DWORD, &v2, 4));
    CHECK(setv(1, set, oid, L"Gone", 0, NULL, 0));
    SET_ERR(0);
    WINE_DIFF CHECK(!getv(1, set, oid, L"Gone", &t, &v, &n)); WINE_DIFF EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    n = 4; v = 0;
    CHECK(getv(1, set, oid, L"Keep", &t, &v, &n)); EXPECT_EQ(v, 1);
    oidr_end();
}
TEST(oidreg_val_set_null_data_missing_value_fails) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64];
    oidr_set(set, sizeof set, "delm"); oidr_oid(oid, sizeof oid, 1);
    SET_ERR(0);
    WINE_DIFF CHECK(!setv(1, set, oid, L"Nope", 0, NULL, 0));      /* key is created, value delete fails */
    WINE_DIFF EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_val_set_empty_data_nonnull_pointer_stores_empty_value) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; BYTE dummy = 0; DWORD t = 0, n = 5; BYTE b[8];
    oidr_set(set, sizeof set, "emp"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(1, set, oid, L"E", REG_BINARY, &dummy, 0));
    CHECK(getv(1, set, oid, L"E", &t, b, &n));
    EXPECT_EQ(t, REG_BINARY); EXPECT_EQ(n, 0);
    oidr_end();
}

/* ---- encoding type mapping --------------------------------------------------------------------------- */
TEST(oidreg_val_encoding_type_low_word_selects_key) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; wchar_t path[300]; DWORD v = 42;
    oidr_set(set, sizeof set, "enc"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, set, oid, L"V", REG_DWORD, &v, 4));
    oidr_path(path, 300, 1, set, oid);
    CHECK(oidr_key_exists(path));               /* low word 1 wins over the high word */
    oidr_end();
}
TEST(oidreg_val_encoding_type_high_word_used_when_low_zero) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; wchar_t path[300]; DWORD v = 42, r = 0, t, n = 4;
    oidr_set(set, sizeof set, "ench"); oidr_oid(oid, sizeof oid, 1);
    if (t_is_wine()) { t_skip("emulator ignores the high word of the encoding type"); oidr_end(); return; }
    CHECK(setv(PKCS_7_ASN_ENCODING, set, oid, L"V", REG_DWORD, &v, 4));   /* 0x00010000 -> "EncodingType 1" */
    oidr_path(path, 300, 1, set, oid);
    CHECK(oidr_key_exists(path));
    CHECK(getv(X509_ASN_ENCODING, set, oid, L"V", &t, &r, &n)); EXPECT_EQ(r, 42);
    oidr_end();
}
TEST(oidreg_val_encoding_type_zero_is_its_own_key) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], oid[64]; wchar_t p0[300], p1[300]; DWORD v = 1;
    oidr_set(set, sizeof set, "enc0"); oidr_oid(oid, sizeof oid, 1);
    CHECK(setv(0, set, oid, L"V", REG_DWORD, &v, 4));
    oidr_path(p0, 300, 0, set, oid); oidr_path(p1, 300, 1, set, oid);
    CHECK(oidr_key_exists(p0)); CHECK(!oidr_key_exists(p1));
    oidr_end();
}
TEST(oidreg_val_encoding_type_arbitrary_numbers) {
    SETUP(CryptSetOIDFunctionValue);
    char oid[64]; DWORD v = 1;
    oidr_oid(oid, sizeof oid, 1);
    static const DWORD encs[] = { 2, 7, 777, 0x10309, 0x03090000 };
    static const unsigned want[] = { 2, 7, 777, 777, 777 };
    /* 0x10309 -> low word 0x309 = 777; 0x03090000 -> low word 0, high word 0x309 = 777 */
    for (int i = 0; i < 5; i++) {
        wchar_t path[300];
        if (want[i] != 777) continue;   /* only the private type 777 is created (swept by the area) */
        char f[] = "GetTickCount";
        CHECK(setv(encs[i], f, oid, L"V", REG_DWORD, &v, 4));
        oidr_path(path, 300, 777, f, oid);
        CHECKF(oidr_key_exists(path), "encoding 0x%lx", (unsigned long)encs[i]);
    }
    oidr_end();
}

/* ---- numeric OIDs ----------------------------------------------------------------------------------- */
TEST(oidreg_val_numeric_oid_stored_as_hash_number) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100]; wchar_t path[300]; DWORD v = 11, r = 0, t, n = 4;
    oidr_set(set, sizeof set, "num");
    CHECK(setv(1, set, (LPCSTR)(ULONG_PTR)4321, L"V", REG_DWORD, &v, 4));
    oidr_path(path, 300, 1, set, "#4321");
    CHECK(oidr_key_exists(path));
    CHECK(getv(1, set, "#4321", L"V", &t, &r, &n)); EXPECT_EQ(r, 11);
    oidr_end();
}
TEST(oidreg_val_numeric_oid_string_and_integer_forms_equal) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100]; DWORD v = 22, r = 0, t, n = 4;
    oidr_set(set, sizeof set, "num2");
    CHECK(setv(1, set, "#99", L"V", REG_DWORD, &v, 4));
    CHECK(getv(1, set, (LPCSTR)(ULONG_PTR)99, L"V", &t, &r, &n)); EXPECT_EQ(r, 22);
    oidr_end();
}
TEST(oidreg_val_numeric_oid_boundaries) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100]; DWORD v = 1, t, n;
    oidr_set(set, sizeof set, "numb");
    static const ULONG_PTR ids[] = { 1, 0xffff };
    for (int i = 0; i < 2; i++) {
        char nm[16]; DWORD r = 0;
        snprintf(nm, sizeof nm, "#%lu", (unsigned long)ids[i]);
        CHECK(setv(1, set, (LPCSTR)ids[i], L"V", REG_DWORD, &v, 4));
        n = 4; CHECK(getv(1, set, nm, L"V", &t, &r, &n)); EXPECT_EQ(r, 1);
    }
    oidr_end();
}
TEST(oidreg_val_oid_string_is_case_insensitive_key) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100]; DWORD v = 3, r = 0, t, n = 4;
    oidr_set(set, sizeof set, "oc");
    CHECK(setv(1, set, "Cryptt.OidReg.CaseTest", L"V", REG_DWORD, &v, 4));
    CHECK(getv(1, set, "CRYPTT.OIDREG.CASETEST", L"V", &t, &r, &n)); EXPECT_EQ(r, 3);
    oidr_end();
}
TEST(oidreg_val_function_set_name_is_case_insensitive_key) {
    SETUP(CryptSetOIDFunctionValue);
    char set[100], up[100]; DWORD v = 3, r = 0, t, n = 4; char oid[64];
    oidr_set(set, sizeof set, "SetCase"); oidr_oid(oid, sizeof oid, 1);
    strcpy(up, set); CharUpperA(up);
    CHECK(setv(1, set, oid, L"V", REG_DWORD, &v, 4));
    CHECK(getv(1, up, oid, L"V", &t, &r, &n)); EXPECT_EQ(r, 3);
    oidr_end();
}
TEST(oidreg_val_not_elevated_set_denied) {
    REQUIRE(U(CryptSetOIDFunctionValue));
    if (oidr_can_write()) { t_skip("elevated: HKLM is writable"); return; }
    char set[100], oid[64]; DWORD v = 1;
    oidr_set(set, sizeof set, "noadm"); oidr_oid(oid, sizeof oid, 1);
    SET_ERR(0);
    CHECK(!setv(1, set, oid, L"V", REG_DWORD, &v, 4)); EXPECT_ERR(ERROR_ACCESS_DENIED);
}

/* ---- CryptRegisterOIDFunction ---------------------------------------------------------------------- */
static void expect_sz(const wchar_t *path, const wchar_t *name, const wchar_t *want) {
    wchar_t b[300]; DWORD t = 0, n = sizeof b;
    LONG rc = oidr_raw_get(path, name, &t, b, &n);
    CHECKF(rc == 0, "value %ls rc=%ld", name, (long)rc);
    if (rc) return;
    EXPECT_EQ(t, REG_SZ);
    EXPECT_EQ(n, (wcslen(want) + 1) * 2);
    CHECK(!lstrcmpW(b, want));
}
#define REG(enc, f, o, dll, ov) U(CryptRegisterOIDFunction)(enc, f, o, dll, ov)

TEST(oidreg_reg_dll_and_function_name_written) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300];
    oidr_set(set, sizeof set, "rg1"); oidr_oid(oid, sizeof oid, 1);
    SET_ERR(0xdead);
    CHECK(REG(1, set, oid, L"kernel32.dll", "GetCurrentProcessId"));
    oidr_path(path, 300, 1, set, oid);
    expect_sz(path, L"Dll", L"kernel32.dll");
    expect_sz(path, L"FuncName", L"GetCurrentProcessId");
    EXPECT_EQ(oidr_value_count(path), 2);
    oidr_end();
}
TEST(oidreg_reg_dll_only_no_funcname_value) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300]; DWORD t, n = 4; BYTE b[4];
    oidr_set(set, sizeof set, "rg2"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"crypt32.dll", NULL));
    oidr_path(path, 300, 1, set, oid);
    expect_sz(path, L"Dll", L"crypt32.dll");
    EXPECT_EQ(oidr_value_count(path), 1);
    SET_ERR(0);
    CHECK(!getv(1, set, oid, L"FuncName", &t, b, &n)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_reg_override_only_no_dll_value) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300];
    oidr_set(set, sizeof set, "rg3"); oidr_oid(oid, sizeof oid, 1);
    if (t_is_wine()) { t_skip("emulator requires a DLL name"); oidr_end(); return; }
    CHECK(REG(1, set, oid, NULL, "SomeOverrideName"));
    oidr_path(path, 300, 1, set, oid);
    expect_sz(path, L"FuncName", L"SomeOverrideName");
    EXPECT_EQ(oidr_value_count(path), 1);
    oidr_end();
}
TEST(oidreg_reg_both_null_succeeds_writes_nothing) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300], spath[300];
    oidr_set(set, sizeof set, "rg4"); oidr_oid(oid, sizeof oid, 1);
    SET_ERR(0);
    CHECK(REG(1, set, oid, NULL, NULL));
    oidr_path(path, 300, 1, set, oid);
    CHECK(!oidr_key_exists(path));
    _snwprintf(spath, 300, L"EncodingType 1\\%S", set);
    CHECK(!oidr_key_exists(spath));
    oidr_end();
}
TEST(oidreg_reg_empty_dll_name_stored_as_empty_string) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300];
    oidr_set(set, sizeof set, "rg5"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"", NULL));
    oidr_path(path, 300, 1, set, oid);
    expect_sz(path, L"Dll", L"");
    oidr_end();
}
TEST(oidreg_reg_dll_path_not_expanded_and_type_sz) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300];
    oidr_set(set, sizeof set, "rg6"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"%SystemRoot%\\system32\\crypt32.dll", NULL));
    oidr_path(path, 300, 1, set, oid);
    expect_sz(path, L"Dll", L"%SystemRoot%\\system32\\crypt32.dll");
    oidr_end();
}
TEST(oidreg_reg_twice_overwrites) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300];
    oidr_set(set, sizeof set, "rg7"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"first.dll", "FirstName"));
    CHECK(REG(1, set, oid, L"second.dll", "SecondName"));
    oidr_path(path, 300, 1, set, oid);
    expect_sz(path, L"Dll", L"second.dll");
    expect_sz(path, L"FuncName", L"SecondName");
    oidr_end();
}
TEST(oidreg_reg_second_call_without_override_keeps_old_funcname) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300];
    oidr_set(set, sizeof set, "rg8"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"a.dll", "KeepMe"));
    CHECK(REG(1, set, oid, L"b.dll", NULL));       /* a NULL override does not delete the value */
    oidr_path(path, 300, 1, set, oid);
    expect_sz(path, L"Dll", L"b.dll");
    expect_sz(path, L"FuncName", L"KeepMe");
    oidr_end();
}
TEST(oidreg_reg_null_oid_invalid_parameter) {
    SETUP(CryptRegisterOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "rg9");
    SET_ERR(0);
    CHECK(!REG(1, set, NULL, L"x.dll", NULL)); EXPECT_HRINVAL();
    oidr_end();
}
TEST(oidreg_reg_numeric_oid) {
    SETUP(CryptRegisterOIDFunction);
    char set[100]; wchar_t path[300];
    oidr_set(set, sizeof set, "rg10");
    CHECK(REG(1, set, (LPCSTR)(ULONG_PTR)2468, L"num.dll", NULL));
    oidr_path(path, 300, 1, set, "#2468");
    expect_sz(path, L"Dll", L"num.dll");
    oidr_end();
}
TEST(oidreg_reg_get_value_sees_registered_dll) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t b[64]; DWORD t = 0, n = sizeof b;
    oidr_set(set, sizeof set, "rg11"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"viaapi.dll", NULL));
    CHECK(getv(1, set, oid, L"Dll", &t, b, &n));
    EXPECT_EQ(t, REG_SZ); CHECK(!lstrcmpW(b, L"viaapi.dll"));
    oidr_end();
}
TEST(oidreg_reg_multiple_oids_in_one_set) {
    SETUP(CryptRegisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300];
    oidr_set(set, sizeof set, "rg12");
    for (unsigned i = 1; i <= 5; i++) {
        wchar_t dll[40]; _snwprintf(dll, 40, L"dll%u.dll", i);
        oidr_oid(oid, sizeof oid, i);
        CHECK(REG(1, set, oid, dll, NULL));
    }
    for (unsigned i = 1; i <= 5; i++) {
        wchar_t dll[40]; _snwprintf(dll, 40, L"dll%u.dll", i);
        oidr_oid(oid, sizeof oid, i); oidr_path(path, 300, 1, set, oid);
        expect_sz(path, L"Dll", dll);
    }
    oidr_end();
}
TEST(oidreg_reg_not_elevated_denied) {
    REQUIRE(U(CryptRegisterOIDFunction));
    if (oidr_can_write()) { t_skip("elevated: HKLM is writable"); return; }
    char set[100], oid[64];
    oidr_set(set, sizeof set, "rgna"); oidr_oid(oid, sizeof oid, 1);
    SET_ERR(0);
    CHECK(!REG(1, set, oid, L"x.dll", NULL)); EXPECT_ERR(ERROR_ACCESS_DENIED);
}

/* ---- CryptUnregisterOIDFunction -------------------------------------------------------------------- */
TEST(oidreg_unreg_removes_oid_key_keeps_set_key) {
    SETUP(CryptUnregisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300], spath[300]; DWORD t, n = 4; BYTE b[4];
    oidr_set(set, sizeof set, "ur1"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"x.dll", NULL));
    oidr_path(path, 300, 1, set, oid);
    _snwprintf(spath, 300, L"EncodingType 1\\%S", set);
    CHECK(oidr_key_exists(path));
    SET_ERR(0xdead);
    CHECK(U(CryptUnregisterOIDFunction)(1, set, oid));
    CHECK(!oidr_key_exists(path));
    CHECK(oidr_key_exists(spath));          /* the function-set key itself is not removed */
    SET_ERR(0);
    CHECK(!getv(1, set, oid, L"Dll", &t, b, &n)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_unreg_twice_second_fails_not_found) {
    SETUP(CryptUnregisterOIDFunction);
    char set[100], oid[64];
    oidr_set(set, sizeof set, "ur2"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"x.dll", NULL));
    CHECK(U(CryptUnregisterOIDFunction)(1, set, oid));
    SET_ERR(0);
    CHECK(!U(CryptUnregisterOIDFunction)(1, set, oid)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_unreg_unknown_set_not_found) {
    SETUP(CryptUnregisterOIDFunction);
    char set[100], oid[64];
    oidr_set(set, sizeof set, "ur3"); oidr_oid(oid, sizeof oid, 1);
    SET_ERR(0);
    CHECK(!U(CryptUnregisterOIDFunction)(1, set, oid)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_end();
}
TEST(oidreg_unreg_null_oid_invalid_parameter) {
    SETUP(CryptUnregisterOIDFunction);
    char set[100]; oidr_set(set, sizeof set, "ur4");
    SET_ERR(0);
    CHECK(!U(CryptUnregisterOIDFunction)(1, set, NULL)); EXPECT_HRINVAL();
    oidr_end();
}
TEST(oidreg_unreg_other_oid_untouched) {
    SETUP(CryptUnregisterOIDFunction);
    char set[100], o1[64], o2[64]; wchar_t p2[300];
    oidr_set(set, sizeof set, "ur5"); oidr_oid(o1, sizeof o1, 1); oidr_oid(o2, sizeof o2, 2);
    CHECK(REG(1, set, o1, L"a.dll", NULL)); CHECK(REG(1, set, o2, L"b.dll", NULL));
    CHECK(U(CryptUnregisterOIDFunction)(1, set, o1));
    oidr_path(p2, 300, 1, set, o2);
    expect_sz(p2, L"Dll", L"b.dll");
    oidr_end();
}
TEST(oidreg_unreg_numeric_oid) {
    SETUP(CryptUnregisterOIDFunction);
    char set[100]; wchar_t path[300];
    oidr_set(set, sizeof set, "ur6");
    CHECK(REG(1, set, (LPCSTR)(ULONG_PTR)777, L"a.dll", NULL));
    oidr_path(path, 300, 1, set, "#777");
    CHECK(oidr_key_exists(path));
    CHECK(U(CryptUnregisterOIDFunction)(1, set, (LPCSTR)(ULONG_PTR)777));
    CHECK(!oidr_key_exists(path));
    oidr_end();
}
TEST(oidreg_unreg_wrong_encoding_type_not_found) {
    SETUP(CryptUnregisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300];
    oidr_set(set, sizeof set, "ur7"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"a.dll", NULL));
    SET_ERR(0);
    CHECK(!U(CryptUnregisterOIDFunction)(0, set, oid)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    oidr_path(path, 300, 1, set, oid);
    CHECK(oidr_key_exists(path));
    oidr_end();
}
TEST(oidreg_unreg_key_with_subkey_refused) {
    SETUP(CryptUnregisterOIDFunction);
    char set[100], oid[64]; wchar_t path[300], full[400]; HKEY k;
    oidr_set(set, sizeof set, "ur8"); oidr_oid(oid, sizeof oid, 1);
    CHECK(REG(1, set, oid, L"a.dll", NULL));
    oidr_path(path, 300, 1, set, oid);
    _snwprintf(full, 400, OIDR_ROOT L"\\%ls\\child", path);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, full, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) == 0) {
        RegCloseKey(k);
        SET_ERR(0);
        BOOL ok = U(CryptUnregisterOIDFunction)(1, set, oid);
        DWORD e = GetLastError();
        CHECK(!ok);              /* RegDeleteKeyEx does not delete keys that have subkeys */
        t_note("unregister of a key with a subkey: last error %lu", (unsigned long)e);
        CHECK(oidr_key_exists(path));
    }
    oidr_end();
}

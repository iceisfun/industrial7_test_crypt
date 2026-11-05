/* certcli utility exports: wide/ansi base64 & hex wrappers, hex integer parser, GUID helpers, OID hashing,
 * period translation, version string, error text and HRESULT utilities. */
#include "cct.h"

static void freel(void *p) { if (p) LocalFree(p); }

/* ---- myCryptBinaryToString(W/A) ---------------------------------------- */
static const BYTE k_123[3] = { 1, 2, 3 };

TEST(cct_b2s_base64_wide)
{
    REQUIRE(CCLI(myCryptBinaryToString));
    LPWSTR s = NULL;
    HRESULT hr = CCLI(myCryptBinaryToString)(k_123, 3, CRYPT_STRING_BASE64, &s);
    CHECK(hr == 0); CHECK(s != NULL);
    if (s) { CHECK(!lstrcmpW(s, L"AQID\r\n")); freel(s); }
}

TEST(cct_b2s_base64_ansi)
{
    REQUIRE(CCLI(myCryptBinaryToStringA));
    LPSTR s = NULL;
    HRESULT hr = CCLI(myCryptBinaryToStringA)(k_123, 3, CRYPT_STRING_BASE64, &s);
    CHECK(hr == 0); CHECK(s != NULL);
    if (s) { CHECK(!strcmp(s, "AQID\r\n")); freel(s); }
}

TEST(cct_b2s_nocrlf)
{
    REQUIRE(CCLI(myCryptBinaryToString)); REQUIRE(CCLI(myCryptBinaryToStringA));
    LPWSTR w = NULL; LPSTR a = NULL;
    CHECK(CCLI(myCryptBinaryToString)(k_123, 3, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &w) == 0);
    CHECK(CCLI(myCryptBinaryToStringA)(k_123, 3, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &a) == 0);
    if (w) { CHECK(!lstrcmpW(w, L"AQID")); freel(w); }
    if (a) { CHECK(!strcmp(a, "AQID")); freel(a); }
}

TEST(cct_b2s_base64_header)
{
    REQUIRE(CCLI(myCryptBinaryToStringA));
    LPSTR a = NULL;
    CHECK(CCLI(myCryptBinaryToStringA)(k_123, 3, CRYPT_STRING_BASE64HEADER, &a) == 0);
    if (a) { CHECK(!strcmp(a, "-----BEGIN CERTIFICATE-----\r\nAQID\r\n-----END CERTIFICATE-----\r\n")); freel(a); }
    a = NULL;
    CHECK(CCLI(myCryptBinaryToStringA)(k_123, 3, CRYPT_STRING_BASE64REQUESTHEADER, &a) == 0);
    if (a) { CHECK(!strcmp(a, "-----BEGIN NEW CERTIFICATE REQUEST-----\r\nAQID\r\n-----END NEW CERTIFICATE REQUEST-----\r\n")); freel(a); }
    a = NULL;
    CHECK(CCLI(myCryptBinaryToStringA)(k_123, 3, CRYPT_STRING_BASE64X509CRLHEADER, &a) == 0);
    if (a) { CHECK(!strcmp(a, "-----BEGIN X509 CRL-----\r\nAQID\r\n-----END X509 CRL-----\r\n")); freel(a); }
}

TEST(cct_b2s_hexraw)
{
    REQUIRE(CCLI(myCryptBinaryToString));
    LPWSTR w = NULL;
    BYTE d[4] = { 0x00, 0xab, 0xCD, 0xff };
    CHECK(CCLI(myCryptBinaryToString)(d, 4, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, &w) == 0);
    if (w) { CHECK(!lstrcmpiW(w, L"00abcdff")); freel(w); }
}

TEST(cct_b2s_base64_padding_variants)
{
    REQUIRE(CCLI(myCryptBinaryToStringA));
    static const struct { int n; const char *s; } v[] = { {1, "AQ=="}, {2, "AQI="}, {3, "AQID"} };
    BYTE d[3] = { 1, 2, 3 };
    for (int i = 0; i < 3; i++) {
        LPSTR a = NULL;
        CHECK(CCLI(myCryptBinaryToStringA)(d, v[i].n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &a) == 0);
        if (a) { CHECKF(!strcmp(a, v[i].s), "%d: %s", v[i].n, a); freel(a); }
    }
}

TEST(cct_b2s_long_input_line_wrapping)
{
    REQUIRE(CCLI(myCryptBinaryToStringA));
    BYTE d[100]; for (int i = 0; i < 100; i++) d[i] = (BYTE)i;
    LPSTR a = NULL;
    CHECK(CCLI(myCryptBinaryToStringA)(d, 100, CRYPT_STRING_BASE64, &a) == 0);
    if (a) {
        /* 100 bytes -> 136 base64 characters, wrapped at 64 columns with CRLF */
        const char *p = strstr(a, "\r\n");
        CHECK(p && (p - a) == 64);
        CHECK(strlen(a) == 136 + 3 * 2);
        freel(a);
    }
}

TEST(cct_b2s_invalid_flags_fail)
{
    REQUIRE(CCLI(myCryptBinaryToString)); REQUIRE(CCLI(myCryptBinaryToStringA));
    LPWSTR w = (LPWSTR)(ULONG_PTR)1; LPSTR a = (LPSTR)(ULONG_PTR)1;
    HRESULT hr = CCLI(myCryptBinaryToString)(k_123, 3, 0x7f, &w);
    CHECK(FAILED(hr)); t_note("W invalid format -> 0x%lx", (long)hr);
    hr = CCLI(myCryptBinaryToStringA)(k_123, 3, 0x7f, &a);
    CHECK(FAILED(hr));
    CHECK(w == (LPWSTR)(ULONG_PTR)1);   /* out untouched on failure */
    CHECK(a == (LPSTR)(ULONG_PTR)1);
}

/* ---- myCryptStringToBinary(W/A) ----------------------------------------- */
TEST(cct_s2b_base64_wide)
{
    REQUIRE(CCLI(myCryptStringToBinary));
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(myCryptStringToBinary)(L"AQID", 0, CRYPT_STRING_BASE64, &b, &cb, NULL, NULL);
    CHECK(hr == 0); CHECK(cb == 3);
    if (b) { CHECK(!memcmp(b, k_123, 3)); freel(b); }
}

TEST(cct_s2b_base64_ansi)
{
    REQUIRE(CCLI(myCryptStringToBinaryA));
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(myCryptStringToBinaryA)("AQID\r\n", 0, CRYPT_STRING_BASE64, &b, &cb, NULL, NULL);
    CHECK(hr == 0); CHECK(cb == 3);
    if (b) { CHECK(!memcmp(b, k_123, 3)); freel(b); }
}

TEST(cct_s2b_explicit_length)
{
    REQUIRE(CCLI(myCryptStringToBinaryA));
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(myCryptStringToBinaryA)("AQIDAQID", 4, CRYPT_STRING_BASE64, &b, &cb, NULL, NULL);
    CHECK(hr == 0); CHECK(cb == 3);
    if (b) { CHECK(!memcmp(b, k_123, 3)); freel(b); }
}

TEST(cct_s2b_header_forms)
{
    REQUIRE(CCLI(myCryptStringToBinary));
    static const WCHAR txt[] = L"-----BEGIN CERTIFICATE-----\r\nAQID\r\n-----END CERTIFICATE-----\r\n";
    BYTE *b = NULL; DWORD cb = 0, skip = 99, fl = 99;
    HRESULT hr = CCLI(myCryptStringToBinary)(txt, 0, CRYPT_STRING_BASE64HEADER, &b, &cb, &skip, &fl);
    CHECK(hr == 0); CHECK(cb == 3);
    if (b) { CHECK(!memcmp(b, k_123, 3)); freel(b); }
    t_note("header parse: skip=%lu flags=%lu", skip, fl);
    b = NULL; cb = 0;
    hr = CCLI(myCryptStringToBinary)(txt, 0, CRYPT_STRING_BASE64_ANY, &b, &cb, NULL, NULL);
    CHECK(hr == 0); CHECK(cb == 3);
    freel(b);
}

TEST(cct_s2b_hexraw_and_hex)
{
    REQUIRE(CCLI(myCryptStringToBinaryA));
    BYTE *b = NULL; DWORD cb = 0;
    CHECK(CCLI(myCryptStringToBinaryA)("010203", 0, CRYPT_STRING_HEXRAW, &b, &cb, NULL, NULL) == 0);
    CHECK(cb == 3);
    if (b) { CHECK(!memcmp(b, k_123, 3)); freel(b); }
    b = NULL; cb = 0;
    CHECK(CCLI(myCryptStringToBinaryA)("01 02 03\r\n", 0, CRYPT_STRING_HEX, &b, &cb, NULL, NULL) == 0);
    CHECK(cb == 3);
    if (b) { CHECK(!memcmp(b, k_123, 3)); freel(b); }
}

TEST(cct_s2b_wide_format_any_rejected_before_decoding)
{
    REQUIRE(CCLI(myCryptStringToBinary));
    BYTE *b = (BYTE *)(ULONG_PTR)1; DWORD cb = 7;
    HRESULT hr = CCLI(myCryptStringToBinary)(L"AQID", 0, CRYPT_STRING_ANY, &b, &cb, NULL, NULL);
    CHECK(hr == (HRESULT)0x80092001);
    CHECK(b == (BYTE *)(ULONG_PTR)1); CHECK(cb == 7);
}

TEST(cct_s2b_invalid_text_fails)
{
    REQUIRE(CCLI(myCryptStringToBinary)); REQUIRE(CCLI(myCryptStringToBinaryA));
    BYTE *b = (BYTE *)(ULONG_PTR)1; DWORD cb = 0;
    HRESULT hr = CCLI(myCryptStringToBinary)(L"!!!!", 0, CRYPT_STRING_BASE64, &b, &cb, NULL, NULL);
    CHECK(FAILED(hr)); t_note("W invalid base64 -> 0x%lx", (long)hr);
    hr = CCLI(myCryptStringToBinaryA)("!!!!", 0, CRYPT_STRING_BASE64, &b, &cb, NULL, NULL);
    CHECK(FAILED(hr)); t_note("A invalid base64 -> 0x%lx", (long)hr);
    CHECK(b == (BYTE *)(ULONG_PTR)1);
}

TEST(cct_s2b_roundtrip_binary_sizes)
{
    REQUIRE(CCLI(myCryptBinaryToStringA)); REQUIRE(CCLI(myCryptStringToBinaryA));
    for (DWORD n = 1; n <= 200; n += 7) {
        BYTE d[200]; for (DWORD i = 0; i < n; i++) d[i] = (BYTE)(i * 37 + n);
        LPSTR s = NULL; BYTE *b = NULL; DWORD cb = 0;
        CHECKF(CCLI(myCryptBinaryToStringA)(d, n, CRYPT_STRING_BASE64, &s) == 0 && s, "n=%lu", n);
        if (!s) continue;
        CHECKF(CCLI(myCryptStringToBinaryA)(s, 0, CRYPT_STRING_BASE64, &b, &cb, NULL, NULL) == 0, "n=%lu", n);
        CHECKF(cb == n && b && !memcmp(b, d, n), "n=%lu cb=%lu", n, cb);
        freel(s); freel(b);
    }
}

/* ---- WszToMultiByteInteger(Buf) ----------------------------------------- */
static void check_mb(DWORD flag, const WCHAR *in, const BYTE *want, DWORD n)
{
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(WszToMultiByteInteger)(flag, in, &cb, &b);
    CHECKF(hr == 0, "%ls flag=%lu hr=0x%lx", in, flag, (long)hr);
    if (hr != 0) return;
    CHECKF(cb == n && b && !memcmp(b, want, n), "%ls flag=%lu cb=%lu", in, flag, cb);
    freel(b);
}

TEST(cct_hexint_forward_order)
{
    REQUIRE(CCLI(WszToMultiByteInteger));
    static const BYTE a[] = { 1, 2, 3 }, b[] = { 0xde, 0xad, 0xbe, 0xef }, c[] = { 0x0a };
    check_mb(1, L"010203", a, 3);
    check_mb(1, L"deadBEEF", b, 4);
    check_mb(1, L"0A", c, 1);
    check_mb(7, L"010203", a, 3);        /* any non-zero first argument selects forward order */
}

TEST(cct_hexint_reverse_order_when_flag_zero)
{
    REQUIRE(CCLI(WszToMultiByteInteger));
    static const BYTE a[] = { 3, 2, 1 }, b[] = { 0xef, 0xbe, 0xad, 0xde };
    check_mb(0, L"010203", a, 3);
    check_mb(0, L"deadbeef", b, 4);
}

TEST(cct_hexint_skips_space_and_tab)
{
    REQUIRE(CCLI(WszToMultiByteInteger));
    static const BYTE a[] = { 1, 2, 3 }, r[] = { 3, 2, 1 };
    check_mb(1, L"01 02\t03", a, 3);
    check_mb(1, L" 01 02 03 ", a, 3);
    check_mb(1, L"0 1 0 2 0 3", a, 3);
    check_mb(0, L"01 02 03", r, 3);
}

TEST(cct_hexint_invalid_digits)
{
    REQUIRE(CCLI(WszToMultiByteInteger));
    static const WCHAR *bad[] = { L"0g", L"zz", L"01-02", L"0x01", L"01,02", L"01\r\n02" };
    for (int f = 0; f < 2; f++)
        for (int i = 0; i < 6; i++) {
            BYTE *b = (BYTE *)(ULONG_PTR)1; DWORD cb = 5;
            HRESULT hr = CCLI(WszToMultiByteInteger)(f, bad[i], &cb, &b);
            CHECKF(hr == E_BADARG, "%ls f=%d hr=0x%lx", bad[i], f, (long)hr);
            CHECK(b == NULL);
        }
}

TEST(cct_hexint_odd_digit_count)
{
    REQUIRE(CCLI(WszToMultiByteInteger));
    static const WCHAR *odd[] = { L"1", L"012", L"01020", L"abc" };
    for (int f = 0; f < 2; f++)
        for (int i = 0; i < 4; i++) {
            BYTE *b = NULL; DWORD cb = 0;
            HRESULT hr = CCLI(WszToMultiByteInteger)(f, odd[i], &cb, &b);
            CHECKF(hr == E_BADARG, "%ls f=%d hr=0x%lx", odd[i], f, (long)hr);
        }
}

TEST(cct_hexint_buf_size_query)
{
    REQUIRE(CCLI(WszToMultiByteIntegerBuf));
    DWORD cb = 0;
    HRESULT hr = CCLI(WszToMultiByteIntegerBuf)(1, L"0102030405", &cb, NULL);
    CHECK(hr == 0); CHECK(cb == 5);
    cb = 99;
    hr = CCLI(WszToMultiByteIntegerBuf)(0, L"", &cb, NULL);
    CHECK(hr == 0); CHECK(cb == 0);
}

TEST(cct_hexint_buf_fill_and_capacity)
{
    REQUIRE(CCLI(WszToMultiByteIntegerBuf));
    BYTE buf[8]; DWORD cb = 8;
    memset(buf, 0xee, sizeof buf);
    HRESULT hr = CCLI(WszToMultiByteIntegerBuf)(1, L"0a0B0c", &cb, buf);
    CHECK(hr == 0); CHECK(cb == 3);
    CHECK(buf[0] == 0x0a && buf[1] == 0x0b && buf[2] == 0x0c && buf[3] == 0xee);
    cb = 3;
    hr = CCLI(WszToMultiByteIntegerBuf)(1, L"0a0B0c", &cb, buf);   /* exact capacity */
    CHECK(hr == 0); CHECK(cb == 3);
}

TEST(cct_hexint_buf_too_small)
{
    REQUIRE(CCLI(WszToMultiByteIntegerBuf));
    for (DWORD f = 0; f < 2; f++) {
        BYTE buf[8]; DWORD cb = 2;
        memset(buf, 0xee, sizeof buf);
        HRESULT hr = CCLI(WszToMultiByteIntegerBuf)(f, L"0a0b0c", &cb, buf);
        CHECKF(hr == (HRESULT)0x80028016, "f=%lu hr=0x%lx", f, (long)hr);
        CHECK(cb == 2);
        cb = 0;
        hr = CCLI(WszToMultiByteIntegerBuf)(f, L"0a", &cb, buf);
        CHECKF(hr == (HRESULT)0x80028016, "f=%lu zero capacity hr=0x%lx", f, (long)hr);
    }
}

/* ---- GUID helpers -------------------------------------------------------- */
static int is_guid_text(const WCHAR *s)
{
    if (lstrlenW(s) != 36) return 0;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != L'-') return 0; }
        else if (!((s[i] >= L'0' && s[i] <= L'9') || (s[i] >= L'a' && s[i] <= L'f'))) return 0;
    }
    return 1;
}

TEST(cct_guid_string_format)
{
    REQUIRE(CCLI(myGenerateGuidString));
    for (int i = 0; i < 20; i++) {
        LPWSTR s = NULL;
        HRESULT hr = CCLI(myGenerateGuidString)(&s);
        CHECK(hr == 0); CHECK(s != NULL);
        if (s) { CHECKF(is_guid_text(s), "%ls", s); freel(s); }
    }
}

TEST(cct_guid_string_unique)
{
    REQUIRE(CCLI(myGenerateGuidString));
    LPWSTR a = NULL, b = NULL;
    CHECK(CCLI(myGenerateGuidString)(&a) == 0);
    CHECK(CCLI(myGenerateGuidString)(&b) == 0);
    CHECK(a && b && lstrcmpW(a, b) != 0);
    freel(a); freel(b);
}

TEST(cct_guid_string_null_out)
{
    REQUIRE(CCLI(myGenerateGuidString));
    CHECK(CCLI(myGenerateGuidString)(NULL) == E_PTR);
}

TEST(cct_guid_serial_number_shape)
{
    REQUIRE(CCLI(myGenerateGuidSerialNumber));
    for (int i = 0; i < 500; i++) {
        GUID g; memset(&g, 0, sizeof g);
        CCLI(myGenerateGuidSerialNumber)(&g);
        BYTE top = g.Data4[7];
        CHECKF((top & 0x80) == 0, "bit 7 set: %02x", top);   /* serial stays positive as a little-endian integer */
        CHECKF(top != 0, "top byte zero");
        CHECKF((top & 0xf0) != 0, "top nibble zero: %02x", top);
    }
}

TEST(cct_guid_serial_number_unique)
{
    REQUIRE(CCLI(myGenerateGuidSerialNumber));
    GUID a, b;
    CCLI(myGenerateGuidSerialNumber)(&a);
    CCLI(myGenerateGuidSerialNumber)(&b);
    CHECK(memcmp(&a, &b, sizeof a) != 0);
}

/* ---- mylstrcmpiL ---------------------------------------------------------- */
TEST(cct_lstrcmpiL_ordering)
{
    REQUIRE(CCLI(mylstrcmpiL));
    CHECK(CCLI(mylstrcmpiL)(L"abc", L"ABC") == 0);
    CHECK(CCLI(mylstrcmpiL)(L"abc", L"abc") == 0);
    CHECK(CCLI(mylstrcmpiL)(L"a", L"b") == -1);
    CHECK(CCLI(mylstrcmpiL)(L"b", L"A") == 1);
    CHECK(CCLI(mylstrcmpiL)(L"", L"a") == -1);
    CHECK(CCLI(mylstrcmpiL)(L"a", L"") == 1);
    CHECK(CCLI(mylstrcmpiL)(L"", L"") == 0);
    CHECK(CCLI(mylstrcmpiL)(L"abc", L"abcd") == -1);
    CHECK(CCLI(mylstrcmpiL)(L"Zeta", L"alpha") == 1);
}

TEST(cct_lstrcmpiL_locale_invariant_case)
{
    REQUIRE(CCLI(mylstrcmpiL));
    CHECK(CCLI(mylstrcmpiL)(L"\x00e9", L"\x00c9") == 0);       /* e-acute vs E-acute */
    CHECK(CCLI(mylstrcmpiL)(L"I", L"i") == 0);                 /* invariant locale: no Turkish dotless i */
    CHECK(CCLI(mylstrcmpiL)(L"STRASSE", L"strasse") == 0);
}

/* ---- OID hashing ------------------------------------------------------------ */
static void check_oidhash(const WCHAR *oid, const WCHAR *want)
{
    LPWSTR s = NULL;
    HRESULT hr = CCLI(myOIDHashOIDToString)(oid, &s);
    CHECKF(hr == 0 && s, "%ls hr=0x%lx", oid, (long)hr);
    if (s) { CHECKF(!lstrcmpW(s, want), "%ls -> %ls", oid, s); freel(s); }
}

TEST(cct_oidhash_vectors)
{
    REQUIRE(CCLI(myOIDHashOIDToString));
    /* <last arc>.<uppercase MD5 of the UTF-16LE OID text> */
    check_oidhash(L"1.2.3.4", L"4.91E10DA3AE4EBF18F07C4AA026C469A4");
    check_oidhash(L"1.3.6.1.4.1.311.21.7", L"7.760F3746DA22D8E5970A09D41052969B");
    check_oidhash(L"2.5.29.15", L"15.6E7D057C731A6572D393E16A42EDB20B");
}

TEST(cct_oidhash_null_arguments)
{
    REQUIRE(CCLI(myOIDHashOIDToString));
    LPWSTR s = (LPWSTR)(ULONG_PTR)3;
    CHECK(CCLI(myOIDHashOIDToString)(NULL, &s) == E_BADARG);
    CHECK(CCLI(myOIDHashOIDToString)(L"1.2.3", NULL) == E_BADARG);
}

TEST(cct_oidhash_invalid_oid_text)
{
    REQUIRE(CCLI(myOIDHashOIDToString));
    static const WCHAR *bad[] = { L"", L"abc", L"1", L"1.", L".1.2", L"1..2", L"3.5.7", L"1.2.x" };
    for (int i = 0; i < 8; i++) {
        LPWSTR s = (LPWSTR)(ULONG_PTR)3;
        HRESULT hr = CCLI(myOIDHashOIDToString)(bad[i], &s);
        if (SUCCEEDED(hr)) t_note("OID text \"%ls\" accepted", bad[i]);
        t_note("hash of \"%ls\": hr=0x%lx", bad[i], (long)hr);
        if (SUCCEEDED(hr)) freel(s);
    }
    LPWSTR s = NULL;
    CHECK(FAILED(CCLI(myOIDHashOIDToString)(L"abc", &s)));
}

/* ---- caTranslateFileTimePeriodToPeriodUnits ------------------------------------ */
typedef struct { int count; int unit; } pu;
enum { U_SEC = 0, U_MIN, U_HOUR, U_DAY, U_WEEK, U_MONTH, U_YEAR };

static void check_period(LONGLONG secs, DWORD flags, int n, const pu *want)
{
    LONGLONG ft = -(secs * 10000000LL);
    DWORD cnt = 0; void *units = NULL;
    HRESULT hr = CCLI(caTranslateFileTimePeriodToPeriodUnits)(&ft, flags, &cnt, &units);
    CHECKF(hr == 0, "secs=%lld flags=%lu hr=0x%lx", secs, flags, (long)hr);
    if (hr != 0) return;
    CHECKF((int)cnt == n, "secs=%lld flags=%lu count=%lu want %d", secs, flags, cnt, n);
    if ((int)cnt == n && units) {
        const pu *g = (const pu *)units;
        for (int i = 0; i < n; i++)
            CHECKF(g[i].count == want[i].count && g[i].unit == want[i].unit,
                   "secs=%lld flags=%lu [%d] got %d/%d want %d/%d", secs, flags, i, g[i].count, g[i].unit, want[i].count, want[i].unit);
    }
    freel(units);
}

TEST(cct_period_whole_years_months_weeks)
{
    REQUIRE(CCLI(caTranslateFileTimePeriodToPeriodUnits));
    const LONGLONG D = 86400;
    { pu w[] = { {1, U_YEAR} };  check_period(365 * D, 0, 1, w); }
    { pu w[] = { {2, U_YEAR} };  check_period(730 * D, 0, 1, w); }
    { pu w[] = { {1, U_MONTH} }; check_period(30 * D, 0, 1, w); }
    { pu w[] = { {2, U_MONTH} }; check_period(60 * D, 0, 1, w); }
    { pu w[] = { {1, U_WEEK} };  check_period(7 * D, 0, 1, w); }
    { pu w[] = { {2, U_WEEK} };  check_period(14 * D, 0, 1, w); }
}

TEST(cct_period_days_and_hours)
{
    REQUIRE(CCLI(caTranslateFileTimePeriodToPeriodUnits));
    const LONGLONG D = 86400;
    { pu w[] = { {1, U_DAY} };                 check_period(1 * D, 0, 1, w); }
    { pu w[] = { {5, U_DAY} };                 check_period(5 * D, 0, 1, w); }
    { pu w[] = { {8, U_DAY} };                 check_period(8 * D, 0, 1, w); }
    { pu w[] = { {400, U_DAY} };               check_period(400 * D, 0, 1, w); }
    { pu w[] = { {2, U_DAY}, {3, U_HOUR} };    check_period(2 * D + 3 * 3600, 0, 2, w); }
    { pu w[] = { {1, U_HOUR} };                check_period(3600, 0, 1, w); }
    { pu w[] = { {12, U_HOUR} };               check_period(12 * 3600, 0, 1, w); }
}

TEST(cct_period_minutes_and_seconds)
{
    REQUIRE(CCLI(caTranslateFileTimePeriodToPeriodUnits));
    { pu w[] = { {1, U_HOUR}, {30, U_MIN} };   check_period(5400, 0, 2, w); }
    { pu w[] = { {45, U_SEC} };                check_period(45, 0, 1, w); }
    { pu w[] = { {1, U_MIN}, {1, U_SEC} };     check_period(61, 0, 2, w); }
    { pu w[] = { {2, U_MIN} };                 check_period(120, 0, 1, w); }
    { pu w[] = { {1, U_SEC} };                 check_period(1, 0, 1, w); }
}

TEST(cct_period_all_units_flag)
{
    REQUIRE(CCLI(caTranslateFileTimePeriodToPeriodUnits));
    { pu w[] = { {1, U_DAY}, {1, U_HOUR}, {1, U_MIN}, {1, U_SEC} };
      check_period(86400 + 3600 + 60 + 1, 1, 4, w); }
    { pu w[] = { {5, U_DAY}, {7, U_HOUR} };
      check_period(5 * 86400 + 7 * 3600, 1, 2, w); }
}

TEST(cct_period_subsecond_truncated)
{
    REQUIRE(CCLI(caTranslateFileTimePeriodToPeriodUnits));
    LONGLONG ft = -(30LL * 10000000LL + 9999999LL);   /* 30.9999999 s */
    DWORD cnt = 0; void *u = NULL;
    HRESULT hr = CCLI(caTranslateFileTimePeriodToPeriodUnits)(&ft, 0, &cnt, &u);
    CHECK(hr == 0); CHECK(cnt == 1);
    if (u) { CHECK(((pu *)u)[0].count == 30 && ((pu *)u)[0].unit == U_SEC); freel(u); }
}

TEST(cct_period_zero_requires_flag_2)
{
    REQUIRE(CCLI(caTranslateFileTimePeriodToPeriodUnits));
    LONGLONG zero = 0;
    DWORD cnt = 77; void *u = (void *)(ULONG_PTR)5;
    HRESULT hr = CCLI(caTranslateFileTimePeriodToPeriodUnits)(&zero, 0, &cnt, &u);
    CHECK(hr == E_BADARG); CHECK(cnt == 77); CHECK(u == (void *)(ULONG_PTR)5);
    hr = CCLI(caTranslateFileTimePeriodToPeriodUnits)(&zero, 2, &cnt, &u);
    CHECK(hr == 0); CHECK(cnt == 1);
    if (hr == 0 && u) { CHECK(((pu *)u)[0].count == 0 && ((pu *)u)[0].unit == U_SEC); freel(u); }
}

TEST(cct_period_positive_rejected)
{
    REQUIRE(CCLI(caTranslateFileTimePeriodToPeriodUnits));
    LONGLONG pos = 10000000LL * 60;
    DWORD cnt = 77; void *u = (void *)(ULONG_PTR)5;
    CHECK(CCLI(caTranslateFileTimePeriodToPeriodUnits)(&pos, 0, &cnt, &u) == E_BADARG);
    CHECK(CCLI(caTranslateFileTimePeriodToPeriodUnits)(&pos, 2, &cnt, &u) == E_BADARG);
    CHECK(cnt == 77 && u == (void *)(ULONG_PTR)5);
}

/* ---- version string ----------------------------------------------------------- */
TEST(cct_version_string_format)
{
    REQUIRE(CCLI(CertcliGetDetailedCertcliVersionString));
    LPCWSTR v = NULL;
    HRESULT hr = CCLI(CertcliGetDetailedCertcliVersionString)(&v);
    CHECK(hr == 0); CHECK(v != NULL);
    if (!v) return;
    int n = lstrlenW(v);
    CHECK(n > 8);
    CHECK(n > 7 && !lstrcmpW(v + n - 7, L" retail"));    /* "<file version> retail" */
    t_note("certca version string: %ls", v);
    if (wcsncmp(v, L"10.0.", 5)) t_note("version does not start with 10.0.");
    LocalFree((HLOCAL)v);
}

TEST(cct_version_string_stable_between_calls)
{
    REQUIRE(CCLI(CertcliGetDetailedCertcliVersionString));
    LPCWSTR a = NULL, b = NULL;
    CHECK(CCLI(CertcliGetDetailedCertcliVersionString)(&a) == 0);
    CHECK(CCLI(CertcliGetDetailedCertcliVersionString)(&b) == 0);
    CHECK(a && b && a != b && !lstrcmpW(a, b));
    if (a) LocalFree((HLOCAL)a);
    if (b) LocalFree((HLOCAL)b);
}

/* ---- HRESULT utilities ----------------------------------------------------------- */
TEST(cct_hr_hgetlasterror_mapping)
{
    REQUIRE(CCLI(myHGetLastError));
    static const struct { DWORD in; LONG want; } v[] = {
        { 0, 0 }, { 5, (LONG)0x80070005 }, { 2, (LONG)0x80070002 }, { 0x1234, (LONG)0x80071234 },
        { 0x80090010, (LONG)0x80090010 }, { 0xC0000005, (LONG)0xC0000005 },
        { 0x00010005, (LONG)0x80070005 }, { 0x10000, (LONG)0x8000FFFF }, { 0x80070005, (LONG)0x80070005 },
    };
    myHGetLastError_pfn fn = CCLI(myHGetLastError);
    for (int i = 0; i < 9; i++) {
        SET_ERR(v[i].in);
        LONG r = fn();
        CHECKF(r == v[i].want, "err 0x%lx -> 0x%lx want 0x%lx", v[i].in, (long)r, (long)v[i].want);
    }
}

TEST(cct_hr_delayload_detection)
{
    REQUIRE(CCLI(myIsDelayLoadHResult));
    CHECK(CCLI(myIsDelayLoadHResult)((LONG)0x8007007E) == 1);     /* HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND) */
    CHECK(CCLI(myIsDelayLoadHResult)((LONG)0x8007007F) == 1);     /* ERROR_PROC_NOT_FOUND */
    CHECK(CCLI(myIsDelayLoadHResult)((LONG)0xC06D007E) == 1);     /* VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND) */
    CHECK(CCLI(myIsDelayLoadHResult)((LONG)0xC06D007F) == 1);
    CHECK(CCLI(myIsDelayLoadHResult)(0) == 0);
    CHECK(CCLI(myIsDelayLoadHResult)((LONG)0x8007007D) == 0);
    CHECK(CCLI(myIsDelayLoadHResult)((LONG)0x80070080) == 0);
    CHECK(CCLI(myIsDelayLoadHResult)((LONG)0xC06D007D) == 0);
    CHECK(CCLI(myIsDelayLoadHResult)((LONG)0x80004005) == 0);
    CHECK(CCLI(myIsDelayLoadHResult)(0x7E) == 0);
}

TEST(cct_hr_jet_hresult)
{
    REQUIRE(CCLI(myJetHResult));
    CHECK(CCLI(myJetHResult)(0) == 0);
    CHECK(CCLI(myJetHResult)(1) == 1);
    CHECK(CCLI(myJetHResult)(5) == 1);                           /* positive warnings collapse to 1 */
    CHECK(CCLI(myJetHResult)(-1) == (LONG)0xC8000001);           /* JET error codes -N -> 0xC8000000 | N */
    CHECK(CCLI(myJetHResult)(-1811) == (LONG)(0xC8000000u | 1811));
    CHECK(CCLI(myJetHResult)((LONG)0x80070005) == (LONG)0x80070005);   /* ordinary failure HRESULTs pass through */
    CHECK(CCLI(myJetHResult)((LONG)0x80004005) == (LONG)0x80004005);
}

TEST(cct_hr_exception_code)
{
    REQUIRE(CCLI(myHExceptionCode));
    EXCEPTION_POINTERS ep; EXCEPTION_RECORD er;
    memset(&er, 0, sizeof er);
    ep.ExceptionRecord = NULL; ep.ContextRecord = NULL;
    CHECK(CCLI(myHExceptionCode)(&ep) == (LONG)0x80004005);
    ep.ExceptionRecord = &er;
    er.ExceptionCode = 0xC0000005;
    CHECK(CCLI(myHExceptionCode)(&ep) == (LONG)0xC0000005);
    er.ExceptionCode = 0x80000002;                  /* datatype misalignment is reported as NTE_BAD_ALGID-class 0x80094010 */
    CHECK(CCLI(myHExceptionCode)(&ep) == (LONG)0x80094010);
    er.ExceptionCode = 5;
    CHECK(CCLI(myHExceptionCode)(&ep) == (LONG)0x80070005);
    er.ExceptionCode = 0xE06D7363;
    CHECK(CCLI(myHExceptionCode)(&ep) == (LONG)0xE06D7363);
}

TEST(cct_error_message_text_basic)
{
    REQUIRE(CCLI(myGetErrorMessageText));
    static const LONG codes[] = { (LONG)0x80070002, (LONG)0x80070005, (LONG)0x80070057, (LONG)0x80092004, (LONG)0x80090008 };
    for (int i = 0; i < 5; i++) {
        LPWSTR t = CCLI(myGetErrorMessageText)(codes[i], FALSE);
        CHECKF(t != NULL && lstrlenW(t) > 0, "0x%lx", (long)codes[i]);
        if (t) {
            WCHAR hex[16]; wsprintfW(hex, L"%08x", (unsigned)codes[i]);
            if (!wcsstr(t, hex)) t_note("text for 0x%lx has no hex code: %ls", (long)codes[i], t);
            freel(t);
        }
    }
}

TEST(cct_error_message_text_with_insert)
{
    REQUIRE(CCLI(myGetErrorMessageText1));
    LPWSTR t = CCLI(myGetErrorMessageText1)((LONG)0x80070002, FALSE, L"somefile.cer");
    CHECK(t != NULL && lstrlenW(t) > 0);
    if (t) { t_note("insert text: %ls", t); freel(t); }
    t = CCLI(myGetErrorMessageText1)((LONG)0x80070002, FALSE, NULL);
    CHECK(t != NULL);
    freel(t);
}

TEST(cct_error_message_text_unknown_code_still_has_text)
{
    REQUIRE(CCLI(myGetErrorMessageText));
    LPWSTR t = CCLI(myGetErrorMessageText)((LONG)0x8abc1234, FALSE);
    CHECK(t != NULL && lstrlenW(t) > 0);
    if (t) { t_note("unknown code text: %ls", t); freel(t); }
}

/* ---- myCAPropGetDisplayName / myCAPropInfoLookup -------------------------------------- */
TEST(cct_capropinfo_lookup_table)
{
    REQUIRE(CCLI(myCAPropInfoLookup));
    struct ent { int id; int pad; const char *p; } tab[3] = { { 10, 0, "ten" }, { 20, 0, "twenty" }, { 30, 0, "thirty" } };
    const void *r = (const void *)(ULONG_PTR)1;
    CHECK(CCLI(myCAPropInfoLookup)(tab, 3, 20, &r) == 0);
    CHECK(r == &tab[1]);
    CHECK(CCLI(myCAPropInfoLookup)(tab, 3, 10, &r) == 0);
    CHECK(r == &tab[0]);
    CHECK(CCLI(myCAPropInfoLookup)(tab, 3, 30, &r) == 0);
    CHECK(r == &tab[2]);
    r = (const void *)(ULONG_PTR)1;
    CHECK(CCLI(myCAPropInfoLookup)(tab, 3, 99, &r) == HR_NOT_FOUND_FILE);
    CHECK(r == NULL);
    r = (const void *)(ULONG_PTR)1;
    CHECK(CCLI(myCAPropInfoLookup)(tab, 2, 30, &r) == HR_NOT_FOUND_FILE);   /* count limits the search */
    CHECK(CCLI(myCAPropInfoLookup)(tab, 0, 10, &r) == HR_NOT_FOUND_FILE);
    CHECK(CCLI(myCAPropInfoLookup)(tab, 3, 10, NULL) == E_PTR);
}

TEST(cct_capropinfo_first_match_wins)
{
    REQUIRE(CCLI(myCAPropInfoLookup));
    struct ent { int id; int pad; const char *p; } tab[3] = { { 7, 0, "a" }, { 7, 0, "b" }, { 8, 0, "c" } };
    const void *r = NULL;
    CHECK(CCLI(myCAPropInfoLookup)(tab, 3, 7, &r) == 0);
    CHECK(r == &tab[0]);
}

TEST(cct_capropname_invalid_id)
{
    REQUIRE(CCLI(myCAPropGetDisplayName));
    LPCWSTR n = (LPCWSTR)(ULONG_PTR)1;
    HRESULT hr = CCLI(myCAPropGetDisplayName)(0x7ffffff0, &n);
    CHECK(FAILED(hr)); CHECK(n == NULL);
    t_note("unknown CA property id -> 0x%lx", (long)hr);
}

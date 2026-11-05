#pragma GCC diagnostic ignored "-Wmisleading-indentation"
/* certcli name helpers: mySanitizeName / myRevertSanitizeName / mySanitizedNameToShortName / DSName / SplitConfigString */
#include "cct.h"

static void freel(void *p) { if (p) LocalFree(p); }

/* characters that are escaped as !XXXX besides everything outside U+0020..U+007E */
static const WCHAR k_bad[] = L"<>\"/\\:|?*#\"&<>[]^`{}|!%()=\'\"`,;+";
static int is_bad(WCHAR c) { for (const WCHAR *p = k_bad; *p; p++) if (*p == c) return 1; return 0; }

typedef struct { const WCHAR *in, *out; } vec;

static void run_sanitize(const vec *v, int n)
{
    for (int i = 0; i < n; i++) {
        LPWSTR out = (LPWSTR)(ULONG_PTR)1;
        HRESULT hr = CCLI(mySanitizeName)(v[i].in, &out);
        CHECKF(hr == 0, "vec %d hr=0x%lx", i, (long)hr);
        if (hr == 0 && out > (LPWSTR)1) {
            CHECKF(!lstrcmpW(out, v[i].out), "vec %d got %ls want %ls", i, out, v[i].out);
            freel(out);
        }
    }
}

TEST(cct_sanitize_plain_names_unchanged)
{
    REQUIRE(CCLI(mySanitizeName));
    static const vec v[] = {
        { L"Simple", L"Simple" }, { L"Simple CA", L"Simple CA" }, { L"a.b-c_d", L"a.b-c_d" },
        { L"$dollar@at~tilde", L"$dollar@at~tilde" }, { L"0123456789", L"0123456789" },
        { L"UPPER lower", L"UPPER lower" }, { L" leading and trailing ", L" leading and trailing " },
    };
    run_sanitize(v, (int)(sizeof v / sizeof v[0]));
}

TEST(cct_sanitize_escapes_special_ascii)
{
    REQUIRE(CCLI(mySanitizeName));
    static const vec v[] = {
        { L"A/B", L"A!002fB" }, { L"A\\B", L"A!005cB" }, { L"a#b", L"a!0023b" }, { L"x!y", L"x!0021y" },
        { L"100%", L"100!0025" }, { L"My CA (Root)", L"My CA !0028Root!0029" },
        { L"a,b;c+d=e", L"a!002cb!003bc!002bd!003de" }, { L"<tag>", L"!003ctag!003e" },
        { L"q\"r", L"q!0022r" }, { L"it's", L"it!0027s" }, { L"a:b|c?d*e", L"a!003ab!007cc!003fd!002ae" },
        { L"[x]^`{y}&", L"!005bx!005d!005e!0060!007by!007d!0026" },
    };
    run_sanitize(v, (int)(sizeof v / sizeof v[0]));
}

TEST(cct_sanitize_escapes_non_ascii_and_control)
{
    REQUIRE(CCLI(mySanitizeName));
    static const vec v[] = {
        { L"caf\x00e9", L"caf!00e9" }, { L"\x20ac", L"!20ac" }, { L"a\x01z", L"a!0001z" }, { L"\x7f", L"!007f" },
        { L"tab\there", L"tab!0009here" }, { L"\x4e2d\x6587", L"!4e2d!6587" }, { L"\xff", L"!00ff" },
    };
    run_sanitize(v, (int)(sizeof v / sizeof v[0]));
}

TEST(cct_sanitize_printable_ascii_table)
{
    REQUIRE(CCLI(mySanitizeName));
    for (WCHAR c = 0x20; c <= 0x7e; c++) {
        WCHAR in[2] = { c, 0 }, want[8];
        if (is_bad(c)) wsprintfW(want, L"!%04x", (unsigned)c); else { want[0] = c; want[1] = 0; }
        LPWSTR out = NULL;
        HRESULT hr = CCLI(mySanitizeName)(in, &out);
        CHECKF(hr == 0 && out, "char 0x%x hr=0x%lx", c, (long)hr);
        if (out) { CHECKF(!lstrcmpW(out, want), "char 0x%x got %ls want %ls", c, out, want); freel(out); }
    }
}

TEST(cct_sanitize_empty_string)
{
    REQUIRE(CCLI(mySanitizeName));
    LPWSTR out = NULL;
    HRESULT hr = CCLI(mySanitizeName)(L"", &out);
    CHECK(hr == 0); CHECK(out != NULL);
    if (out) { CHECK(out[0] == 0); freel(out); }
}

TEST(cct_sanitize_null_input)
{
    REQUIRE(CCLI(mySanitizeName));
    LPWSTR out = (LPWSTR)(ULONG_PTR)0x1234;
    HRESULT hr = CCLI(mySanitizeName)(NULL, &out);
    CHECK(hr == E_PTR);
    CHECK(out == NULL);          /* the out parameter is cleared before validation */
}

TEST(cct_sanitize_long_name_no_truncation)
{
    REQUIRE(CCLI(mySanitizeName));
    WCHAR in[301], want[301 * 5];
    for (int i = 0; i < 300; i++) in[i] = (i % 7 == 3) ? L'/' : L'k';
    in[300] = 0;
    want[0] = 0;
    for (int i = 0; i < 300; i++) lstrcatW(want, (i % 7 == 3) ? L"!002f" : L"k");
    LPWSTR out = NULL;
    HRESULT hr = CCLI(mySanitizeName)(in, &out);
    CHECK(hr == 0);
    if (out) { CHECK(!lstrcmpW(out, want)); freel(out); }
}

TEST(cct_revert_sanitize_basic)
{
    REQUIRE(CCLI(myRevertSanitizeName));
    static const vec v[] = {
        { L"A!002fB", L"A/B" }, { L"My CA !0028Root!0029", L"My CA (Root)" }, { L"caf!00e9", L"caf\x00e9" },
        { L"!00E9", L"\x00e9" }, { L"!20AC!20ac", L"\x20ac\x20ac" }, { L"plain", L"plain" }, { L"", L"" },
    };
    for (int i = 0; i < (int)(sizeof v / sizeof v[0]); i++) {
        LPWSTR out = NULL;
        HRESULT hr = CCLI(myRevertSanitizeName)(v[i].in, &out);
        CHECKF(hr == 0 && out, "vec %d", i);
        if (out) { CHECKF(!lstrcmpW(out, v[i].out), "vec %d got %ls", i, out); freel(out); }
    }
}

TEST(cct_revert_sanitize_malformed_escapes_kept_literal)
{
    REQUIRE(CCLI(myRevertSanitizeName));
    static const WCHAR *k[] = { L"!", L"!1", L"!12", L"!123", L"!zzzz", L"!00g1", L"a!", L"x!12 y", L"!!0041" };
    static const WCHAR *w[] = { L"!", L"!1", L"!12", L"!123", L"!zzzz", L"!00g1", L"a!", L"x!12 y", L"!A" };
    for (int i = 0; i < 9; i++) {
        LPWSTR out = NULL;
        HRESULT hr = CCLI(myRevertSanitizeName)(k[i], &out);
        CHECKF(hr == 0 && out, "%ls", k[i]);
        if (out) { CHECKF(!lstrcmpW(out, w[i]), "%ls -> %ls want %ls", k[i], out, w[i]); freel(out); }
    }
}

TEST(cct_sanitize_revert_roundtrip_all_bmp)
{
    REQUIRE(CCLI(mySanitizeName)); REQUIRE(CCLI(myRevertSanitizeName));
    int bad = 0;
    for (unsigned c = 1; c <= 0xffff; c++) {
        WCHAR in[3] = { L'k', (WCHAR)c, 0 };
        LPWSTR s = NULL, r = NULL;
        if (CCLI(mySanitizeName)(in, &s) != 0 || !s) { bad++; continue; }
        if (CCLI(myRevertSanitizeName)(s, &r) != 0 || !r || lstrcmpW(r, in)) bad++;
        freel(s); freel(r);
    }
    CHECKF(bad == 0, "%d code units failed the round trip", bad);
}

TEST(cct_sanitize_output_only_safe_characters)
{
    REQUIRE(CCLI(mySanitizeName));
    WCHAR in[0x100]; int n = 0;
    for (WCHAR c = 1; c < 0xff; c++) in[n++] = c;
    in[n] = 0;
    LPWSTR out = NULL;
    HRESULT hr = CCLI(mySanitizeName)(in, &out);
    CHECK(hr == 0);
    if (out) {
        for (const WCHAR *p = out; *p; p++) {
            CHECKF(*p >= 0x20 && *p <= 0x7e, "unsafe output char 0x%x", *p);
            CHECKF(!(*p != L'!' && is_bad(*p)), "unescaped special 0x%x", *p);
        }
        freel(out);
    }
}

/* ---- short names -------------------------------------------------------- */
static void check_short(const WCHAR *in, const WCHAR *want, int flag)
{
    LPWSTR out = NULL;
    HRESULT hr = CCLI(mySanitizedNameToShortName)(in, flag, &out);
    CHECKF(hr == 0 && out, "hr=0x%lx", (long)hr);
    if (out) { CHECKF(!lstrcmpW(out, want), "got %ls want %ls", out, want); freel(out); }
}

TEST(cct_shortname_short_input_unchanged)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    check_short(L"Short", L"Short", 0);
    check_short(L"Short", L"Short", 1);
    check_short(L"", L"", 0);
    check_short(L"With!0028escape", L"With!0028escape", 1);
    /* exactly 51 characters is still passed through */
    WCHAR a51[52]; for (int i = 0; i < 51; i++) a51[i] = L'a'; a51[51] = 0;
    check_short(a51, a51, 0);
}

TEST(cct_shortname_52_chars_hashed)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[53], want[64];
    for (int i = 0; i < 52; i++) in[i] = L'a'; in[52] = 0;
    for (int i = 0; i < 51; i++) want[i] = L'a'; want[51] = 0;
    lstrcatW(want, L"-00097");
    check_short(in, want, 0);
}

TEST(cct_shortname_60_chars_hashed_vectors)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[64], want[64];
    int i;
    for (i = 0; i < 60; i++) in[i] = L'a'; in[60] = 0;
    for (i = 0; i < 51; i++) want[i] = L'a'; want[51] = 0; lstrcatW(want, L"-49567");
    check_short(in, want, 0);
}

TEST(cct_shortname_hash_depends_on_cut_tail)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[64], want[64];
    int i;
    for (i = 0; i < 51; i++) in[i] = L'a'; for (; i < 60; i++) in[i] = L'b'; in[60] = 0;
    for (i = 0; i < 51; i++) want[i] = L'a'; want[51] = 0; lstrcatW(want, L"-50078");
    check_short(in, want, 0);
}

TEST(cct_shortname_100_chars_vector)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[101], want[64];
    int i;
    for (i = 0; i < 100; i++) in[i] = L'Z'; in[100] = 0;
    for (i = 0; i < 51; i++) want[i] = L'Z'; want[51] = 0; lstrcatW(want, L"-00087");
    check_short(in, want, 1);
}

TEST(cct_shortname_pattern_vector)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[81], want[64];
    int i;
    for (i = 0; i < 80; i++) in[i] = (i & 1) ? L'b' : L'a'; in[80] = 0;
    for (i = 0; i < 51; i++) want[i] = (i & 1) ? L'b' : L'a'; want[51] = 0; lstrcatW(want, L"-35413");
    check_short(in, want, 0);
}

/* an escape (!XXXX) cut by the 51 character limit by fewer than 5 characters is removed before hashing */
TEST(cct_shortname_cut_escape_removed)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[64], want[80]; int i;
    for (i = 0; i < 47; i++) in[i] = L'x';
    in[i] = 0; lstrcatW(in, L"!0041yyyyyyy");
    for (i = 0; i < 47; i++) want[i] = L'x'; want[47] = 0; lstrcatW(want, L"-45193");
    check_short(in, want, 0);
}

TEST(cct_shortname_complete_escape_kept)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[64], want[80]; int i;
    for (i = 0; i < 46; i++) in[i] = L'x';
    in[i] = 0; lstrcatW(in, L"!0041yyyyyyy");
    for (i = 0; i < 46; i++) want[i] = L'x'; want[46] = 0; lstrcatW(want, L"!0041-15367");
    check_short(in, want, 0);
}

TEST(cct_shortname_escape_in_middle_kept)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[80], want[80]; int i;
    for (i = 0; i < 40; i++) in[i] = L'A'; in[i] = 0;
    lstrcatW(in, L"!0028BBBBBBBBBBBBBBBBBBBB");
    for (i = 0; i < 40; i++) want[i] = L'A'; want[40] = 0; lstrcatW(want, L"!0028BBBBBB-32718");
    check_short(in, want, 0);
}

TEST(cct_shortname_null_arguments)
{
    REQUIRE(CCLI(mySanitizedNameToShortName));
    LPWSTR out = (LPWSTR)(ULONG_PTR)0x77;
    CHECK(CCLI(mySanitizedNameToShortName)(NULL, 0, &out) == E_PTR);
    CHECK(out == NULL);
    CHECK(CCLI(mySanitizedNameToShortName)(L"x", 0, NULL) == E_PTR);
}

TEST(cct_dsname_matches_shortname)
{
    REQUIRE(CCLI(mySanitizedNameToDSName)); REQUIRE(CCLI(mySanitizedNameToShortName));
    WCHAR in[90]; int i;
    for (i = 0; i < 70; i++) in[i] = L'a' + (i % 13); in[70] = 0;
    LPWSTR a = NULL, b = NULL;
    CHECK(CCLI(mySanitizedNameToDSName)(in, &a) == 0);
    CHECK(CCLI(mySanitizedNameToShortName)(in, 1, &b) == 0);
    CHECK(a && b && !lstrcmpW(a, b));
    freel(a); freel(b);
    a = (LPWSTR)(ULONG_PTR)9;
    CHECK(CCLI(mySanitizedNameToDSName)(NULL, &a) == E_PTR);
    CHECK(a == NULL);
    CHECK(CCLI(mySanitizedNameToDSName)(L"ok", &a) == 0);
    if (a) { CHECK(!lstrcmpW(a, L"ok")); freel(a); }
}

TEST(cct_shortname_sanitize_pipeline)
{
    REQUIRE(CCLI(mySanitizeName)); REQUIRE(CCLI(mySanitizedNameToShortName));
    /* a CA common name with many special characters, sanitized then shortened for use as a DS RDN */
    WCHAR in[120]; int n = 0;
    for (int i = 0; i < 30; i++) { in[n++] = L'('; in[n++] = L'x'; }
    in[n] = 0;
    LPWSTR s = NULL, sh = NULL;
    CHECK(CCLI(mySanitizeName)(in, &s) == 0 && s);
    CHECK(s && lstrlenW(s) == 30 * 6);
    CHECK(CCLI(mySanitizedNameToShortName)(s, 0, &sh) == 0 && sh);
    CHECK(sh && lstrlenW(sh) <= 57);
    CHECK(sh && lstrlenW(sh) >= 46);
    freel(s); freel(sh);
}

/* ---- SplitConfigString --------------------------------------------------- */
static void check_split(const WCHAR *in, const WCHAR *a, const WCHAR *b)
{
    LPWSTR x = (LPWSTR)(ULONG_PTR)1, y = (LPWSTR)(ULONG_PTR)1;
    HRESULT hr = CCLI(SplitConfigString)(in, &x, &y);
    CHECKF(hr == 0, "%ls hr=0x%lx", in, (long)hr);
    if (hr != 0) return;
    CHECKF(x != NULL && !lstrcmpW(x, a), "%ls: first=%ls", in, x ? x : L"(null)");
    if (b) CHECKF(y != NULL && !lstrcmpW(y, b), "%ls: second=%ls", in, y ? y : L"(null)");
    else CHECKF(y == NULL, "%ls: second not NULL", in);
    freel(x); freel(y);
}

TEST(cct_split_config_server_and_ca)
{
    REQUIRE(CCLI(SplitConfigString));
    check_split(L"server\\My CA", L"server", L"My CA");
    check_split(L"host.example.test\\Root-CA", L"host.example.test", L"Root-CA");
    check_split(L"a\\b", L"a", L"b");
}

TEST(cct_split_config_no_separator)
{
    REQUIRE(CCLI(SplitConfigString));
    check_split(L"serveronly", L"serveronly", NULL);
    check_split(L"x", L"x", NULL);
}

TEST(cct_split_config_leading_backslashes_skipped)
{
    REQUIRE(CCLI(SplitConfigString));
    check_split(L"\\server\\ca", L"server", L"ca");
    check_split(L"\\\\server\\ca", L"server", L"ca");
    check_split(L"\\\\\\only", L"only", NULL);
}

TEST(cct_split_config_extra_separators_stay_in_second)
{
    REQUIRE(CCLI(SplitConfigString));
    check_split(L"srv\\ca\\sub", L"srv", L"ca\\sub");
    check_split(L"srv\\\\ca", L"srv", L"\\ca");
}

TEST(cct_split_config_trailing_separator)
{
    REQUIRE(CCLI(SplitConfigString));
    check_split(L"srv\\", L"srv", L"");
}

TEST(cct_split_config_empty_string)
{
    REQUIRE(CCLI(SplitConfigString));
    check_split(L"", L"", NULL);
}

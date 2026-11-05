/* CertRDNValueToStrA/W: conversion of decoded RDN values. */
#include "sf.h"

#define REQ_RV() \
    DWORD (WINAPI *fa)(DWORD, PCERT_RDN_VALUE_BLOB, LPSTR, DWORD) = (void*)t_proc("CertRDNValueToStrA"); \
    DWORD (WINAPI *fw)(DWORD, PCERT_RDN_VALUE_BLOB, LPWSTR, DWORD) = (void*)t_proc("CertRDNValueToStrW"); \
    REQUIRE(fa); REQUIRE(fw); (void)fa; (void)fw

typedef struct { DWORD type; const BYTE *v; DWORD n; const WCHAR *exp; } rv_case;

static DWORD rv_w(DWORD type, const void *v, DWORD n, LPWSTR out, DWORD csz)
{
    DWORD (WINAPI *fw)(DWORD, PCERT_RDN_VALUE_BLOB, LPWSTR, DWORD) = (void*)t_proc("CertRDNValueToStrW");
    CERT_RDN_VALUE_BLOB b; b.cbData = n; b.pbData = (BYTE*)v;
    return fw(type, &b, out, csz);
}
static DWORD rv_a(DWORD type, const void *v, DWORD n, LPSTR out, DWORD csz)
{
    DWORD (WINAPI *fa)(DWORD, PCERT_RDN_VALUE_BLOB, LPSTR, DWORD) = (void*)t_proc("CertRDNValueToStrA");
    CERT_RDN_VALUE_BLOB b; b.cbData = n; b.pbData = (BYTE*)v;
    return fa(type, &b, out, csz);
}

/* full protocol for a W conversion that should yield exactly exp */
static void chk_rv(const char *file, int line, DWORD type, const void *v, DWORD n, const WCHAR *exp)
{
    size_t el = lstrlenW(exp); WCHAR out[256]; DWORD r; int wide_type = ((type & 0xff) >= 11 && (type & 0xff) <= 13);
    r = rv_w(type, v, n, NULL, 0);
    t_check(r == el + 1, file, line, "W size query", "type %#lx got %lu want %zu", type, r, el + 1);
    memset(out, 0xcc, sizeof out);
    r = rv_w(type, v, n, out, 256);
    t_check(r == el + 1 && !lstrcmpW(out, exp), file, line, "W conversion", "type %#lx r=%lu want %zu", type, r, el + 1);
    memset(out, 0xcc, sizeof out);
    r = rv_w(type, v, n, out, (DWORD)el + 1);
    t_check(r == el + 1 && !lstrcmpW(out, exp), file, line, "W exact buffer", "type %#lx r=%lu", type, r);
    if (el > 1) {
        memset(out, 0xcc, sizeof out);
        r = rv_w(type, v, n, out, (DWORD)el);
        if (wide_type) t_check(r == el && out[el - 1] == 0 && !wcsncmp(out, exp, el - 1), file, line, "W truncation (wide types copy a prefix)", "type %#lx r=%lu", type, r);
        else t_check(r == 1 && out[0] == 0, file, line, "W truncation (narrow types yield empty)", "type %#lx r=%lu first=%#x", type, r, out[0]);
    }
    memset(out, 0xcc, sizeof out);
    r = rv_w(type, v, n, out, 1);
    t_check(r == 1 && out[0] == 0, file, line, "W cch=1", "type %#lx r=%lu", type, r);
    memset(out, 0xcc, sizeof out);
    r = rv_w(type, v, n, out, 0);
    t_check(r == el + 1 && out[0] == 0xcccc, file, line, "W cch=0 with buffer is a size query", "type %#lx r=%lu", type, r);
}
#define RV(type, v, n, exp) chk_rv(__FILE__, __LINE__, (type), (v), (n), (exp))

TEST(sf_rv_ascii_string_types) {
    REQ_RV();
    RV(CERT_RDN_PRINTABLE_STRING, "Hello", 5, L"Hello");
    RV(CERT_RDN_IA5_STRING, "a@b.c", 5, L"a@b.c");
    RV(CERT_RDN_NUMERIC_STRING, "0123", 4, L"0123");
    RV(CERT_RDN_VISIBLE_STRING, "vis", 3, L"vis");
    RV(CERT_RDN_TELETEX_STRING, "tele", 4, L"tele");
    RV(CERT_RDN_VIDEOTEX_STRING, "vid", 3, L"vid");
    RV(CERT_RDN_GRAPHIC_STRING, "gra", 3, L"gra");
    RV(CERT_RDN_GENERAL_STRING, "gen", 3, L"gen");
}
TEST(sf_rv_octet_and_encoded_blob_widen_bytes) {
    REQ_RV();
    RV(CERT_RDN_OCTET_STRING, "AB", 2, L"AB");
    RV(CERT_RDN_ENCODED_BLOB, "xy", 2, L"xy");
}
TEST(sf_rv_any_type_zero) {
    REQ_RV();
    RV(CERT_RDN_ANY_TYPE, "any", 3, L"any");
}
TEST(sf_rv_empty_value) {
    REQ_RV(); WCHAR out[4] = { 0x77, 0x77 }; DWORD r;
    r = rv_w(CERT_RDN_PRINTABLE_STRING, "", 0, out, 4); EXPECT_EQ(r, 1); EXPECT_EQ(out[0], 0);
    r = rv_w(CERT_RDN_PRINTABLE_STRING, "", 0, NULL, 0); EXPECT_EQ(r, 1);
    static const BYTE none[2] = { 0 };
    r = rv_w(CERT_RDN_BMP_STRING, none, 0, out, 4); EXPECT_EQ(r, 1); EXPECT_EQ(out[0], 0);
    r = rv_w(CERT_RDN_UNIVERSAL_STRING, none, 0, out, 4); EXPECT_EQ(r, 1); EXPECT_EQ(out[0], 0);
    char a[4] = { 0x77 }; r = rv_a(CERT_RDN_PRINTABLE_STRING, "", 0, a, 4); EXPECT_EQ(r, 1); EXPECT_EQ(a[0], 0);
}
TEST(sf_rv_high_bytes_widen_one_to_one) {
    REQ_RV(); static const BYTE b[] = { 0xe9, 0xff, 0x80 };
    RV(CERT_RDN_PRINTABLE_STRING, b, 3, L"\x00e9\x00ff\x0080");
    RV(CERT_RDN_IA5_STRING, b, 3, L"\x00e9\x00ff\x0080");
    RV(CERT_RDN_OCTET_STRING, b, 3, L"\x00e9\x00ff\x0080");
}
TEST(sf_rv_printable_utf8_sequences_are_not_decoded) {
    REQ_RV(); static const BYTE b[] = { 0xc3, 0xa9 };
    RV(CERT_RDN_PRINTABLE_STRING, b, 2, L"\x00c3\x00a9");
    RV(CERT_RDN_IA5_STRING, b, 2, L"\x00c3\x00a9");
}
TEST(sf_rv_teletex_valid_utf8_is_decoded) {
    REQ_RV(); static const BYTE b[] = { 0xc3, 0xa9 };
    RV(CERT_RDN_TELETEX_STRING, b, 2, L"\x00e9");
}
TEST(sf_rv_teletex_disable_ie4_utf8_flag) {
    REQ_RV(); static const BYTE b[] = { 0xc3, 0xa9 };
    RV(CERT_RDN_TELETEX_STRING | CERT_RDN_DISABLE_IE4_UTF8_FLAG, b, 2, L"\x00c3\x00a9");
}
TEST(sf_rv_teletex_invalid_utf8_falls_back_to_bytes) {
    REQ_RV(); static const BYTE b[] = { 0xe9 }, c[] = { 'a', 0xc3 };
    RV(CERT_RDN_TELETEX_STRING, b, 1, L"\x00e9");
    RV(CERT_RDN_TELETEX_STRING, c, 2, L"a\x00c3");
}
TEST(sf_rv_flag_bits_in_type_other_than_ie4_ignored_for_ascii) {
    REQ_RV();
    RV(CERT_RDN_PRINTABLE_STRING | CERT_RDN_DISABLE_IE4_UTF8_FLAG, "abc", 3, L"abc");
    RV(CERT_RDN_PRINTABLE_STRING | CERT_RDN_ENABLE_T61_UNICODE_FLAG, "abc", 3, L"abc");
}
TEST(sf_rv_bmp_and_utf8_types_are_wide_copies) {
    REQ_RV(); static const WCHAR w[] = L"Wide\x65e5";
    RV(CERT_RDN_BMP_STRING, w, 10, L"Wide\x65e5");
    RV(CERT_RDN_UNICODE_STRING, w, 10, L"Wide\x65e5");
    RV(CERT_RDN_UTF8_STRING, w, 10, L"Wide\x65e5");
}
TEST(sf_rv_bmp_odd_byte_count_truncates_half_char) {
    REQ_RV(); static const WCHAR w[] = L"ab";
    DWORD r = rv_w(CERT_RDN_BMP_STRING, w, 3, NULL, 0);
    EXPECT_EQ(r, 2);
}
TEST(sf_rv_universal_string) {
    REQ_RV(); static const DWORD u[] = { 0x41, 0x1F600, 0xe9 };
    RV(CERT_RDN_UNIVERSAL_STRING, u, 12, L"A\xd83d\xde00\x00e9");
}
TEST(sf_rv_universal_invalid_code_point) {
    REQ_RV(); static const DWORD u[] = { 0x41, 0x110000 };
    WCHAR out[8]; DWORD r = rv_w(CERT_RDN_UNIVERSAL_STRING, u, 8, out, 8);
    EXPECT_EQ(r, 3); EXPECT_EQ(out[0], 'A'); EXPECT_EQ(out[1], 0xfffd);
}
TEST(sf_rv_universal_truncated_pair_replaced) {
    REQ_RV(); static const DWORD u[] = { 0x1F600 }; WCHAR out[8]; DWORD r;
    /* the surrogate pair does not fit in 2 slots (one char + NUL): replacement character */
    r = rv_w(CERT_RDN_UNIVERSAL_STRING, u, 4, out, 2);
    EXPECT_EQ(r, 2); EXPECT_EQ(out[0], 0xfffd); EXPECT_EQ(out[1], 0);
}
TEST(sf_rv_wide_truncation_prefix) {
    REQ_RV(); static const WCHAR w[] = L"abcdef"; WCHAR out[8]; DWORD r;
    memset(out, 0xcc, sizeof out);
    r = rv_w(CERT_RDN_BMP_STRING, w, 12, out, 4);
    EXPECT_EQ(r, 4); CHECK(!wcsncmp(out, L"abc", 3)); EXPECT_EQ(out[3], 0); EXPECT_EQ(out[4], 0xcccc);
}
TEST(sf_rv_narrow_truncation_is_empty) {
    REQ_RV(); WCHAR out[8]; DWORD r;
    memset(out, 0xcc, sizeof out);
    SET_ERR(0);
    r = rv_w(CERT_RDN_PRINTABLE_STRING, "abcdef", 6, out, 4);
    EXPECT_EQ(r, 1); EXPECT_EQ(out[0], 0);
    r = rv_w(CERT_RDN_PRINTABLE_STRING, "abcdef", 6, out, 6);
    EXPECT_EQ(r, 1); EXPECT_EQ(out[0], 0);
    r = rv_w(CERT_RDN_PRINTABLE_STRING, "abcdef", 6, out, 7);
    EXPECT_EQ(r, 7); CHECK(!lstrcmpW(out, L"abcdef"));
}

/* ---------------- A variant ---------------- */
TEST(sf_rv_a_ascii) {
    REQ_RV(); char out[64]; DWORD r;
    r = rv_a(CERT_RDN_PRINTABLE_STRING, "Hello", 5, NULL, 0); EXPECT_EQ(r, 6);
    memset(out, 0xcc, sizeof out);
    r = rv_a(CERT_RDN_PRINTABLE_STRING, "Hello", 5, out, 64); EXPECT_EQ(r, 6); EXPECT_STR(out, "Hello");
    memset(out, 0xcc, sizeof out);
    r = rv_a(CERT_RDN_PRINTABLE_STRING, "Hello", 5, out, 6); EXPECT_EQ(r, 6); EXPECT_STR(out, "Hello");
}
TEST(sf_rv_a_truncation_yields_empty) {
    REQ_RV(); char out[64]; DWORD r;
    memset(out, 0xcc, sizeof out);
    r = rv_a(CERT_RDN_PRINTABLE_STRING, "Hello", 5, out, 5); EXPECT_EQ(r, 1); EXPECT_EQ(out[0], 0);
    static const WCHAR w[] = L"Hello";
    memset(out, 0xcc, sizeof out);
    r = rv_a(CERT_RDN_BMP_STRING, w, 10, out, 3); EXPECT_EQ(r, 1); EXPECT_EQ(out[0], 0);
}
TEST(sf_rv_a_cch_one_and_zero) {
    REQ_RV(); char out[8]; DWORD r;
    memset(out, 0xcc, sizeof out);
    r = rv_a(CERT_RDN_PRINTABLE_STRING, "Hello", 5, out, 1); EXPECT_EQ(r, 1); EXPECT_EQ(out[0], 0);
    memset(out, 0xcc, sizeof out);
    r = rv_a(CERT_RDN_PRINTABLE_STRING, "Hello", 5, out, 0); EXPECT_EQ(r, 6); EXPECT_EQ((unsigned char)out[0], 0xcc);
}
TEST(sf_rv_a_wide_types) {
    REQ_RV(); static const WCHAR w[] = L"Wide"; char out[16]; DWORD r;
    r = rv_a(CERT_RDN_BMP_STRING, w, 8, out, 16); EXPECT_EQ(r, 5); EXPECT_STR(out, "Wide");
    r = rv_a(CERT_RDN_UTF8_STRING, w, 8, out, 16); EXPECT_EQ(r, 5); EXPECT_STR(out, "Wide");
}
TEST(sf_rv_a_size_matches_w_for_ascii) {
    REQ_RV(); int i;
    for (i = 0; i < 50; i++) {
        char v[64]; int n = i + 1; DWORD ra, rw;
        memset(v, 'a' + (i % 20), n);
        ra = rv_a(CERT_RDN_IA5_STRING, v, n, NULL, 0); rw = rv_w(CERT_RDN_IA5_STRING, v, n, NULL, 0);
        CHECKF(ra == rw && ra == (DWORD)n + 1, "len %d: A=%lu W=%lu", n, ra, rw);
    }
}
TEST(sf_rv_value_blob_not_modified_and_not_retained) {
    REQ_RV(); char v[] = "keepme"; WCHAR out[16];
    rv_w(CERT_RDN_PRINTABLE_STRING, v, 6, out, 16);
    EXPECT_STR(v, "keepme");
}
TEST(sf_rv_long_value) {
    REQ_RV(); char v[2000]; int i; WCHAR *out = malloc(4000 * sizeof(WCHAR)); DWORD r;
    for (i = 0; i < 2000; i++) v[i] = (char)('a' + i % 26);
    r = rv_w(CERT_RDN_PRINTABLE_STRING, v, 2000, NULL, 0); EXPECT_EQ(r, 2001);
    r = rv_w(CERT_RDN_PRINTABLE_STRING, v, 2000, out, 4000); EXPECT_EQ(r, 2001); EXPECT_EQ(out[1999], 'a' + 1999 % 26); EXPECT_EQ(out[2000], 0);
    free(out);
}

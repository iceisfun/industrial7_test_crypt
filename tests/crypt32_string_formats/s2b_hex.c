/* CryptStringToBinaryA/W: HEX, HEXRAW, HEXADDR, HEXASCII, HEXASCIIADDR, HEX_ANY. */
#include "sf.h"

#define REQ_S2B() BOOL (WINAPI *fa)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*) = (void*)t_proc("CryptStringToBinaryA"); \
                  BOOL (WINAPI *fw)(LPCWSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*) = (void*)t_proc("CryptStringToBinaryW"); \
                  REQUIRE(fa); REQUIRE(fw); (void)fa; (void)fw

/* ---------------- HEX (simple) ---------------- */
TEST(sf_s2b_hex_plain) {
    REQ_S2B();
    DEC_OK_STR("414243", CRYPT_STRING_HEX, "ABC");
    DEC_OK_STR("41 42 43", CRYPT_STRING_HEX, "ABC");
    DEC_OK_STR("41 42 43\r\n", CRYPT_STRING_HEX, "ABC");
    DEC_OK_STR("4a4B4c", CRYPT_STRING_HEX, "JKL");
    BYTE d[] = { 0x00, 0xff, 0x7f, 0x80 };
    DEC_OK("00ff7f80", CRYPT_STRING_HEX, d, 4);
    DEC_OK("00FF7F80", CRYPT_STRING_HEX, d, 4);
}
TEST(sf_s2b_hex_hexraw_same_parser) {
    REQ_S2B();
    DEC_OK_STR("414243", CRYPT_STRING_HEXRAW, "ABC");
    DEC_OK_STR("41 42,43-", CRYPT_STRING_HEXRAW, "ABC");
}
TEST(sf_s2b_hex_separators) {
    REQ_S2B();
    DEC_OK_STR("41,42,43", CRYPT_STRING_HEX, "ABC");
    DEC_OK_STR("41-42-43", CRYPT_STRING_HEX, "ABC");
    DEC_OK_STR("41\t42\r\n43", CRYPT_STRING_HEX, "ABC");
    DEC_OK_STR(" ,-41,,--42 \t 43,-", CRYPT_STRING_HEX, "ABC");
    DEC_OK_STR("-,41", CRYPT_STRING_HEX, "A");
    DEC_OK_STR("aa,BBff,-,", CRYPT_STRING_HEX, "\xaa\xbb\xff");
    DEC_OK_STR("aa,,-BB---ff,-,", CRYPT_STRING_HEX, "\xaa\xbb\xff");
}
TEST(sf_s2b_hex_separator_inside_a_pair_is_invalid) {
    REQ_S2B();
    DEC_FAIL("1-2", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("4 1", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("010-02", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("4\r\n1", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
}
TEST(sf_s2b_hex_odd_digit_count) {
    REQ_S2B();
    DEC_FAIL("0", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("000", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("11220", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
}
TEST(sf_s2b_hex_invalid_characters) {
    REQ_S2B();
    DEC_FAIL("1122q", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("q1122", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("0x41", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("41;42", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("41.42", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("g1", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    DEC_FAIL("4G", CRYPT_STRING_HEX, ERROR_INVALID_DATA);
}
TEST(sf_s2b_hex_every_ascii_char_before_a_pair) {
    REQ_S2B(); int c;
    for (c = 1; c < 128; c++) {
        char s[8]; sf_dec d; s[0] = (char)c; strcpy(s + 1, "00");
        int sep = (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == '-');
        sf_decode(s, 0, CRYPT_STRING_HEX, 0, &d);
        if (sep) CHECKF(d.ok && d.cb == 1, "char %#x", c);
        else CHECKF(!d.ok && d.err == ERROR_INVALID_DATA, "char %#x ok=%d err=%lu", c, d.ok, d.err);
    }
}
TEST(sf_s2b_hex_empty_and_separator_only) {
    REQ_S2B(); sf_dec d;
    sf_decode("", 0, CRYPT_STRING_HEX, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 0);
    sf_decode("-", 0, CRYPT_STRING_HEX, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 0);
    sf_decode(",-", 0, CRYPT_STRING_HEX, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 0);
    sf_decode(" \t\r\n", 0, CRYPT_STRING_HEX, 1, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 0);
}
TEST(sf_s2b_hex_reports_format_and_zero_skip) {
    REQ_S2B(); sf_dec d;
    sf_decode("4142", 0, CRYPT_STRING_HEX, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.skip, 0); EXPECT_EQ(d.flags, CRYPT_STRING_HEX);
    sf_decode("4142", 0, CRYPT_STRING_HEXRAW, 1, &d);
    CHECK(d.ok); EXPECT_EQ(d.skip, 0); EXPECT_EQ(d.flags, CRYPT_STRING_HEXRAW);
}
TEST(sf_s2b_hex_cch_limits) {
    REQ_S2B();
    sf_expect_dec(__FILE__, __LINE__, "0102", 2, CRYPT_STRING_HEX, "\x01", 1);
    sf_expect_dec(__FILE__, __LINE__, "0102", 4, CRYPT_STRING_HEX, "\x01\x02", 2);
    sf_expect_decfail(__FILE__, __LINE__, "0102", 3, CRYPT_STRING_HEX, ERROR_INVALID_DATA);
    sf_expect_dec(__FILE__, __LINE__, "01 02", 2, CRYPT_STRING_HEX, "\x01", 1);
}
TEST(sf_s2b_hex_size_query_and_exact) {
    REQ_S2B(); DWORD n = 0xdead; BYTE out[8];
    CHECK(fa("010203", 0, CRYPT_STRING_HEX, NULL, &n, NULL, NULL)); EXPECT_EQ(n, 3);
    n = 3; CHECK(fa("010203", 0, CRYPT_STRING_HEX, out, &n, NULL, NULL)); EXPECT_EQ(n, 3);
    n = 8; CHECK(fa("010203", 0, CRYPT_STRING_HEX, out, &n, NULL, NULL)); EXPECT_EQ(n, 3);
}
TEST(sf_s2b_hex_short_buffer_keeps_pcb_and_writes_prefix) {
    REQ_S2B(); BYTE out[8]; DWORD n = 1, sk = 5, fg = 5; memset(out, 0xcc, sizeof out);
    SET_ERR(0);
    CHECK(!fa("0102", 0, CRYPT_STRING_HEX, out, &n, &sk, &fg));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 1); EXPECT_EQ(out[0], 1); EXPECT_EQ(out[1], 0xcc); EXPECT_EQ(sk, 0); EXPECT_EQ(fg, 0);
    n = 1; memset(out, 0xcc, sizeof out); SET_ERR(0);
    CHECK(!fw(L"0102", 0, CRYPT_STRING_HEX, out, &n, NULL, NULL));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 1); EXPECT_EQ(out[0], 1); EXPECT_EQ(out[1], 0xcc);
}
TEST(sf_s2b_hex_error_writes_valid_prefix) {
    REQ_S2B(); BYTE out[8]; DWORD n = 8; memset(out, 0xcc, sizeof out);
    SET_ERR(0);
    CHECK(!fa("0102q3", 0, CRYPT_STRING_HEX, out, &n, NULL, NULL));
    EXPECT_ERR(ERROR_INVALID_DATA); EXPECT_EQ(n, 8); EXPECT_EQ(out[0], 1); EXPECT_EQ(out[1], 2); EXPECT_EQ(out[2], 0xcc);
}
TEST(sf_s2b_hex_size_query_failure_zeroes_pcb) {
    REQ_S2B(); DWORD n = 8; SET_ERR(0);
    CHECK(!fa("0102q", 0, CRYPT_STRING_HEX, NULL, &n, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_DATA); EXPECT_EQ(n, 0);
    n = 8; SET_ERR(0);
    CHECK(!fw(L"0102", 3, CRYPT_STRING_HEX, NULL, &n, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_DATA); EXPECT_EQ(n, 0);
}
TEST(sf_s2b_hex_w_null_pcb) {
    REQ_S2B(); SET_ERR(0);
    CHECK(!fw(L"01", 2, CRYPT_STRING_HEX, NULL, NULL, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_s2b_hex_embedded_nul_with_explicit_cch) {
    REQ_S2B(); BYTE out[8]; DWORD n = 8; memset(out, 0xcc, sizeof out); SET_ERR(0);
    CHECK(!fa("01\0 02", 5, CRYPT_STRING_HEX, out, &n, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_DATA); EXPECT_EQ(out[0], 1); EXPECT_EQ(out[1], 0xcc);
}
TEST(sf_s2b_hex_long_roundtrip_via_hexraw_text) {
    REQ_S2B(); int cb; BYTE d[300]; char txt[2000]; int i;
    for (i = 0; i < 300; i++) d[i] = (BYTE)(i * 3 + 1);
    for (cb = 1; cb <= 260; cb += 7) {
        sf_ref_hex(d, cb, CRYPT_STRING_HEXRAW, "\r\n", txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEXRAW, d, cb);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEX, d, cb);
        sf_ref_hex(d, cb, CRYPT_STRING_HEX, "\r\n", txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEX, d, cb);
        sf_ref_hex(d, cb, CRYPT_STRING_HEX, "\n", txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEX, d, cb);
        sf_ref_hex(d, cb, CRYPT_STRING_HEX, "", txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEX, d, cb);
    }
}

/* ---------------- HEXADDR / HEXASCII / HEXASCIIADDR ---------------- */
/* Data whose ASCII rendering can never be mistaken for hex digits. */
static void fill_safe(BYTE *d, int n) { int i; for (i = 0; i < n; i++) d[i] = (i % 5 == 4) ? (BYTE)(0x80 + i) : (BYTE)('g' + (i % 20)); }

TEST(sf_s2b_hexaddr_literals) {
    REQ_S2B(); BYTE d[17]; int i; for (i = 0; i < 17; i++) d[i] = (BYTE)i;
    DEC_OK("0000\t01 02 03\r\n", CRYPT_STRING_HEXADDR, "\x01\x02\x03", 3);
    DEC_OK("0000\t00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f\r\n0010\t10\r\n", CRYPT_STRING_HEXADDR, d, 17);
    DEC_OK("0000\t00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f\n0010\t10\n", CRYPT_STRING_HEXADDR, d, 17);
}
TEST(sf_s2b_hexaddr_reports_format) {
    REQ_S2B(); sf_dec d;
    sf_decode("0000\t01 02 03\r\n", 0, CRYPT_STRING_HEXADDR, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.flags, CRYPT_STRING_HEXADDR); EXPECT_EQ(d.skip, 0);
}
TEST(sf_s2b_hexaddr_rejects_non_address_start) {
    REQ_S2B();
    DEC_FAIL("01 02 03\r\n", CRYPT_STRING_HEXADDR, ERROR_INVALID_DATA);
    DEC_FAIL("zzzz\t01 02\r\n", CRYPT_STRING_HEXADDR, ERROR_INVALID_DATA);
    DEC_FAIL("", CRYPT_STRING_HEXADDR, ERROR_INVALID_DATA);
}
TEST(sf_s2b_hexaddr_address_must_advance_by_16) {
    REQ_S2B(); BYTE d[48]; int i; for (i = 0; i < 48; i++) d[i] = (BYTE)(i + 1);
    char ok[512], bad[512];
    sf_ref_hex(d, 48, CRYPT_STRING_HEXADDR, "\r\n", ok);
    sf_expect_dec(__FILE__, __LINE__, ok, 0, CRYPT_STRING_HEXADDR, d, 48);
    strcpy(bad, ok);
    char *p = strstr(bad, "0020\t"); if (p) memcpy(p, "0030", 4);
    sf_expect_decfail(__FILE__, __LINE__, bad, 0, CRYPT_STRING_HEXADDR, ERROR_INVALID_DATA);
}
TEST(sf_s2b_hexaddr_roundtrip_sweep) {
    REQ_S2B(); BYTE d[200]; int i, cb; char txt[4096];
    for (i = 0; i < 200; i++) d[i] = (BYTE)(i * 9 + 4);
    for (cb = 1; cb <= 150; cb++) {
        sf_ref_hex(d, cb, CRYPT_STRING_HEXADDR, "\r\n", txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEXADDR, d, cb);
    }
}
TEST(sf_s2b_hexascii_roundtrip_sweep) {
    REQ_S2B(); BYTE d[200]; int cb; char txt[8192];
    fill_safe(d, 200);
    for (cb = 1; cb <= 100; cb++) {
        sf_ref_hex(d, cb, CRYPT_STRING_HEXASCII, "\r\n", txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEXASCII, d, cb);
    }
}
TEST(sf_s2b_hexasciiaddr_roundtrip_sweep) {
    REQ_S2B(); BYTE d[200]; int cb; char txt[8192];
    fill_safe(d, 200);
    for (cb = 1; cb <= 100; cb++) {
        sf_ref_hex(d, cb, CRYPT_STRING_HEXASCIIADDR, "\r\n", txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEXASCIIADDR, d, cb);
        sf_ref_hex(d, cb, CRYPT_STRING_HEXASCIIADDR, "\n", txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_HEXASCIIADDR, d, cb);
    }
}
TEST(sf_s2b_hexascii_literal_with_ascii_column) {
    REQ_S2B(); BYTE d[20]; int i; for (i = 0; i < 20; i++) d[i] = (BYTE)(0x30 + i);
    DEC_OK("30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d 3e 3f   0123456789:;<=>?\r\n"
           "40 41 42 43                                        @ABC\r\n", CRYPT_STRING_HEXASCII, d, 20);
    DEC_OK("0000\t30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d 3e 3f   0123456789:;<=>?\r\n"
           "0010\t40 41 42 43                                        @ABC\r\n", CRYPT_STRING_HEXASCIIADDR, d, 20);
}
TEST(sf_s2b_hexascii_nonprintable_dots) {
    REQ_S2B(); BYTE m[9] = { 0, 1, 2, 0x7f, 0x80, 0xff, 0x41, 0x7e, 0x20 };
    sf_dec d;
    /* the trailing ASCII column "......A~ " must not be parsed as data */
    sf_decode("00 01 02 7f 80 ff 41 7e  20                        ......A~ \r\n", 0, CRYPT_STRING_HEXASCII, 0, &d);
    t_note("HEXASCII with ascii column starting with dots: ok=%d cb=%lu err=%lu", d.ok, d.cb, d.err);
    if (d.ok) { EXPECT_EQ(d.cb, 9); CHECK(!memcmp(d.data, m, 9)); }
}
TEST(sf_s2b_hexascii_w_variant) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    CHECK(fw(L"0000\t01 02 03\r\n", 0, CRYPT_STRING_HEXADDR, out, &n, NULL, NULL));
    EXPECT_EQ(n, 3); CHECK(!memcmp(out, "\x01\x02\x03", 3));
}

/* ---------------- HEX_ANY ---------------- */
TEST(sf_s2b_hex_any_plain_hex) {
    REQ_S2B(); sf_dec d; int w;
    for (w = 0; w < 2; w++) {
        sf_decode("41 42 43", 0, CRYPT_STRING_HEX_ANY, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 3); CHECK(!memcmp(d.data, "ABC", 3)); EXPECT_EQ(d.flags, CRYPT_STRING_HEX);
        sf_decode("414243", 0, CRYPT_STRING_HEX_ANY, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 3); EXPECT_EQ(d.flags, CRYPT_STRING_HEX);
    }
}
TEST(sf_s2b_hex_any_prefers_address_form) {
    REQ_S2B(); sf_dec d; int w;
    for (w = 0; w < 2; w++) {
        sf_decode("0000\t41 42 43\r\n", 0, CRYPT_STRING_HEX_ANY, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 3); CHECK(!memcmp(d.data, "ABC", 3)); EXPECT_EQ(d.flags, CRYPT_STRING_HEXADDR);
    }
}
TEST(sf_s2b_hex_any_ascii_column) {
    REQ_S2B(); sf_dec d;
    sf_decode("30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d 3e 3f   0123456789:;<=>?\r\n", 0, CRYPT_STRING_HEX_ANY, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 16); EXPECT_EQ(d.flags, CRYPT_STRING_HEXASCII);
    sf_decode("0000\t30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d 3e 3f   0123456789:;<=>?\r\n", 0, CRYPT_STRING_HEX_ANY, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 16); EXPECT_EQ(d.flags, CRYPT_STRING_HEXASCIIADDR);
}
TEST(sf_s2b_hex_any_garbage_fails) {
    REQ_S2B();
    DEC_FAIL("zz", CRYPT_STRING_HEX_ANY, ERROR_INVALID_DATA);
    DEC_FAIL("not hex at all", CRYPT_STRING_HEX_ANY, ERROR_INVALID_DATA);
}
TEST(sf_s2b_hex_any_size_query) {
    REQ_S2B(); DWORD n = 0;
    CHECK(fa("0000\t41 42 43\r\n", 0, CRYPT_STRING_HEX_ANY, NULL, &n, NULL, NULL)); EXPECT_EQ(n, 3);
}

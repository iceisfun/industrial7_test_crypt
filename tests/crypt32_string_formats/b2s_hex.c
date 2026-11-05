/* CryptBinaryToStringA/W: HEX, HEXASCII, HEXADDR, HEXASCIIADDR, HEXRAW layouts. */
#include "sf.h"

#define REQ_B2S() BOOL (WINAPI *fa)(const BYTE*, DWORD, DWORD, LPSTR, DWORD*) = (void*)t_proc("CryptBinaryToStringA"); \
                  REQUIRE(fa); (void)fa

static BYTE g_d[400];
static void init_d(void) { int i; for (i = 0; i < (int)sizeof g_d; i++) g_d[i] = (BYTE)(i * 13 + 5); }
static BYTE seq(int n, BYTE *o) { int i; for (i = 0; i < n; i++) o[i] = (BYTE)i; return 0; }

/* ---------------- CRYPT_STRING_HEX ---------------- */
TEST(sf_hex_three_bytes) {
    REQ_B2S();
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEX, "01 02 03\r\n");
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEX | CRYPT_STRING_NOCR, "01 02 03\n");
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, "01 02 03");
}
TEST(sf_hex_single_byte_and_lowercase) {
    REQ_B2S();
    B2S("\xab", 1, CRYPT_STRING_HEX, "ab\r\n");
    B2S("\xff\x00\x7f", 3, CRYPT_STRING_HEX, "ff 00 7f\r\n");
}
TEST(sf_hex_eight_bytes_single_group) {
    REQ_B2S(); BYTE d[16]; seq(16, d);
    B2S(d, 8, CRYPT_STRING_HEX, "00 01 02 03 04 05 06 07\r\n");
}
TEST(sf_hex_nine_bytes_double_space_after_eighth) {
    REQ_B2S(); BYTE d[16]; seq(16, d);
    B2S(d, 9, CRYPT_STRING_HEX, "00 01 02 03 04 05 06 07  08\r\n");
}
TEST(sf_hex_sixteen_bytes_line) {
    REQ_B2S(); BYTE d[32]; seq(32, d);
    B2S(d, 16, CRYPT_STRING_HEX, "00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f\r\n");
}
TEST(sf_hex_seventeen_bytes_wraps) {
    REQ_B2S(); BYTE d[32]; seq(32, d);
    B2S(d, 17, CRYPT_STRING_HEX, "00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f\r\n10\r\n");
    B2S(d, 17, CRYPT_STRING_HEX | CRYPT_STRING_NOCR, "00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f\n10\n");
}
TEST(sf_hex_thirty_three_bytes) {
    REQ_B2S(); BYTE d[40]; seq(40, d);
    B2S(d, 33, CRYPT_STRING_HEX,
        "00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f\r\n"
        "10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f\r\n"
        "20\r\n");
}
TEST(sf_hex_nocrlf_uses_single_spaces_and_joins_lines) {
    REQ_B2S(); BYTE d[32]; seq(32, d);
    B2S(d, 17, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10");
}
TEST(sf_hex_no_trailing_whitespace_before_terminator) {
    REQ_B2S(); BYTE d[16]; seq(16, d); char buf[128]; DWORD n = sizeof buf;
    CHECK(fa(d, 5, CRYPT_STRING_HEX, buf, &n));
    CHECK(n >= 3 && buf[n - 3] != ' ' && buf[n - 2] == '\r' && buf[n - 1] == '\n');
}

/* ---------------- HEXRAW ---------------- */
TEST(sf_hexraw_literals) {
    REQ_B2S(); BYTE d[40]; seq(40, d);
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEXRAW, "010203\r\n");
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCR, "010203\n");
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, "010203");
    B2S(d, 20, CRYPT_STRING_HEXRAW, "000102030405060708090a0b0c0d0e0f10111213\r\n");
}
TEST(sf_hexraw_long_has_no_line_breaks) {
    REQ_B2S(); init_d(); char buf[2048]; DWORD n = sizeof buf;
    CHECK(fa(g_d, 100, CRYPT_STRING_HEXRAW, buf, &n));
    EXPECT_EQ(n, 202); EXPECT_EQ(buf[200], '\r'); EXPECT_EQ(buf[201], '\n'); EXPECT_EQ(strchr(buf, '\r'), buf + 200);
}

/* ---------------- HEXADDR ---------------- */
TEST(sf_hexaddr_literals) {
    REQ_B2S(); BYTE d[40]; seq(40, d);
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEXADDR, "0000\t01 02 03\r\n");
    B2S(d, 17, CRYPT_STRING_HEXADDR, "0000\t00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f\r\n0010\t10\r\n");
    B2S(d, 17, CRYPT_STRING_HEXADDR | CRYPT_STRING_NOCR, "0000\t00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f\n0010\t10\n");
}
TEST(sf_hexaddr_address_grows_in_hex) {
    REQ_B2S(); init_d(); char buf[8192]; DWORD n = sizeof buf; BYTE *big = malloc(5000); int i;
    for (i = 0; i < 5000; i++) big[i] = (BYTE)i;
    CHECK(fa(big, 5000, CRYPT_STRING_HEXADDR, buf, &n));
    CHECK(strstr(buf, "\r\n0100\t") != NULL);
    CHECK(strstr(buf, "\r\n0400\t") != NULL);
    CHECK(strstr(buf, "\r\n1380\t") != NULL);
    free(big);
}

/* ---------------- HEXASCII / HEXASCIIADDR ---------------- */
TEST(sf_hexascii_literals) {
    REQ_B2S();
    B2S("ABC", 3, CRYPT_STRING_HEXASCII, "41 42 43                                           ABC\r\n");
    BYTE d[20]; int i; for (i = 0; i < 20; i++) d[i] = (BYTE)(0x30 + i);
    B2S(d, 20, CRYPT_STRING_HEXASCII,
        "30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d 3e 3f   0123456789:;<=>?\r\n"
        "40 41 42 43                                        @ABC\r\n");
    BYTE m[9] = { 0, 1, 2, 0x7f, 0x80, 0xff, 0x41, 0x7e, 0x20 };
    B2S(m, 9, CRYPT_STRING_HEXASCII, "00 01 02 7f 80 ff 41 7e  20                        ......A~ \r\n");
}
TEST(sf_hexasciiaddr_literals) {
    REQ_B2S();
    B2S("ABC", 3, CRYPT_STRING_HEXASCIIADDR, "0000\t41 42 43                                           ABC\r\n");
    BYTE d[20]; int i; for (i = 0; i < 20; i++) d[i] = (BYTE)(0x30 + i);
    B2S(d, 20, CRYPT_STRING_HEXASCIIADDR,
        "0000\t30 31 32 33 34 35 36 37  38 39 3a 3b 3c 3d 3e 3f   0123456789:;<=>?\r\n"
        "0010\t40 41 42 43                                        @ABC\r\n");
}
TEST(sf_hexascii_ascii_column_is_fixed) {
    REQ_B2S(); init_d(); char buf[512]; DWORD n; int cb;
    for (cb = 1; cb <= 16; cb++) {
        n = sizeof buf;
        CHECK(fa(g_d, cb, CRYPT_STRING_HEXASCII, buf, &n));
        /* hex area plus padding is 51 chars wide, then cb ASCII chars, then CRLF */
        EXPECT_EQ(n, 51 + cb + 2);
    }
}
TEST(sf_hexascii_nonprintable_become_dots) {
    REQ_B2S(); BYTE d[4] = { 0x1f, 0x20, 0x7e, 0x7f }; char buf[256]; DWORD n = sizeof buf;
    CHECK(fa(d, 4, CRYPT_STRING_HEXASCII, buf, &n));
    CHECK(n == 51 + 4 + 2);
    CHECK(!memcmp(buf + 51, ". ~.", 4));
}

/* ---------------- model sweeps ---------------- */
static void sweep(DWORD fmt, int maxcb)
{
    char *exp = malloc(16384); int cb, m;
    init_d();
    for (m = 0; m < 3; m++) {
        DWORD ef = m == 0 ? 0 : m == 1 ? CRYPT_STRING_NOCR : CRYPT_STRING_NOCRLF;
        const char *eol = m == 0 ? "\r\n" : m == 1 ? "\n" : "";
        for (cb = 1; cb <= maxcb; cb++) {
            size_t n = sf_ref_hex(g_d, cb, fmt, eol, exp);
            B2S_RAW(g_d, cb, fmt | ef, exp, n, 1);
        }
    }
    free(exp);
}
TEST(sf_hex_sweep_hex) { REQ_B2S(); sweep(CRYPT_STRING_HEX, 70); }
TEST(sf_hex_sweep_hexraw) { REQ_B2S(); sweep(CRYPT_STRING_HEXRAW, 70); }
TEST(sf_hex_sweep_hexaddr) { REQ_B2S(); sweep(CRYPT_STRING_HEXADDR, 70); }
TEST(sf_hex_sweep_hexascii) { REQ_B2S(); sweep(CRYPT_STRING_HEXASCII, 70); }
TEST(sf_hex_sweep_hexasciiaddr) { REQ_B2S(); sweep(CRYPT_STRING_HEXASCIIADDR, 70); }

TEST(sf_hex_large_input) {
    REQ_B2S(); BYTE *big = malloc(70000); int i; char *exp = malloc(400000); DWORD f;
    DWORD fmts[] = { CRYPT_STRING_HEX, CRYPT_STRING_HEXASCII, CRYPT_STRING_HEXADDR, CRYPT_STRING_HEXASCIIADDR, CRYPT_STRING_HEXRAW };
    for (i = 0; i < 70000; i++) big[i] = (BYTE)(i ^ (i >> 7));
    for (f = 0; f < NELEM(fmts); f++) {
        size_t n = sf_ref_hex(big, 70000, fmts[f], "\r\n", exp);
        B2S_RAW(big, 70000, fmts[f], exp, n, 1);
    }
    free(big); free(exp);
}

/* ---------------- buffer protocol ---------------- */
TEST(sf_hex_short_buffer_matrix) {
    REQ_B2S(); BYTE d[40]; seq(40, d);
    DWORD fmts[] = { CRYPT_STRING_HEX, CRYPT_STRING_HEXASCII, CRYPT_STRING_HEXADDR, CRYPT_STRING_HEXASCIIADDR, CRYPT_STRING_HEXRAW };
    DWORD f;
    for (f = 0; f < NELEM(fmts); f++) {
        char exp[2048]; size_t n = sf_ref_hex(d, 20, fmts[f], "\r\n", exp); DWORD want = (DWORD)n + 1, cap;
        for (cap = 0; cap <= want + 2; cap++) {
            char buf[2048]; DWORD c = cap; BOOL r;
            memset(buf, 0xAA, sizeof buf);
            SET_ERR(0);
            r = fa(d, 20, fmts[f], buf, &c);
            if (cap >= want) { CHECKF(r, "fmt %lu cap %lu", fmts[f], cap); if (r) { EXPECT_EQ(c, n); CHECK(!strcmp(buf, exp)); } }
            else { CHECKF(!r, "fmt %lu cap %lu", fmts[f], cap); EXPECT_ERR(ERROR_MORE_DATA); }
            CHECKF((BYTE)buf[want + 4] == 0xAA, "guard fmt %lu cap %lu", fmts[f], cap);
        }
    }
}
TEST(sf_hex_size_query_matches_output) {
    REQ_B2S(); init_d();
    DWORD fmts[] = { CRYPT_STRING_HEX, CRYPT_STRING_HEXASCII, CRYPT_STRING_HEXADDR, CRYPT_STRING_HEXASCIIADDR, CRYPT_STRING_HEXRAW };
    DWORD f; int cb;
    for (f = 0; f < NELEM(fmts); f++)
        for (cb = 1; cb < 130; cb += 11) {
            DWORD q = 0, n = 4096; char *buf = malloc(8192);
            CHECK(fa(g_d, cb, fmts[f], NULL, &q));
            CHECK(fa(g_d, cb, fmts[f], buf, &n));
            CHECKF(q == n + 1, "fmt %lu cb %d q=%lu n=%lu", fmts[f], cb, q, n);
            CHECK(strlen(buf) == n);
            free(buf);
        }
}
TEST(sf_hex_zero_length_invalid_parameter) {
    REQ_B2S(); char buf[16]; DWORD n = sizeof buf; SET_ERR(0);
    CHECK(!fa((const BYTE*)"a", 0, CRYPT_STRING_HEX, buf, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_hex_w_parity) {
    REQ_B2S();
    BOOL (WINAPI *fw)(const BYTE*, DWORD, DWORD, LPWSTR, DWORD*) = (void*)t_proc("CryptBinaryToStringW"); REQUIRE(fw);
    WCHAR w[64]; DWORD n = 64;
    CHECK(fw((const BYTE*)"\x01\x02\x03", 3, CRYPT_STRING_HEX, w, &n));
    EXPECT_EQ(n, 10); CHECK(!lstrcmpW(w, L"01 02 03\r\n"));
    n = 0; CHECK(fw((const BYTE*)"\x01\x02\x03", 3, CRYPT_STRING_HEX, NULL, &n)); EXPECT_EQ(n, 11);
}

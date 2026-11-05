/* CryptBinaryToStringA/W: base64 family, header formats, flags and the buffer protocol. */
#include "sf.h"

#define REQ_B2S() BOOL (WINAPI *fa)(const BYTE*, DWORD, DWORD, LPSTR, DWORD*) = (void*)t_proc("CryptBinaryToStringA"); \
                  BOOL (WINAPI *fw)(const BYTE*, DWORD, DWORD, LPWSTR, DWORD*) = (void*)t_proc("CryptBinaryToStringW"); \
                  REQUIRE(fa); REQUIRE(fw)

static BYTE g_seq[512];
static void init_seq(void) { int i; for (i = 0; i < (int)sizeof g_seq; i++) g_seq[i] = (BYTE)(i * 7 + 3); }

/* ---------------- RFC 4648 section 10 vectors ---------------- */
static const struct { const char *in; const char *out; } rfc[] = {
    { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" }, { "foob", "Zm9vYg==" },
    { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" },
};

TEST(sf_b2s_rfc4648_crlf) {
    REQ_B2S();
    size_t i;
    for (i = 0; i < NELEM(rfc); i++) {
        char exp[64]; sprintf(exp, "%s\r\n", rfc[i].out);
        B2S(rfc[i].in, (DWORD)strlen(rfc[i].in), CRYPT_STRING_BASE64, exp);
    }
}
TEST(sf_b2s_rfc4648_nocr) {
    REQ_B2S();
    size_t i;
    for (i = 0; i < NELEM(rfc); i++) {
        char exp[64]; sprintf(exp, "%s\n", rfc[i].out);
        B2S(rfc[i].in, (DWORD)strlen(rfc[i].in), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, exp);
    }
}
TEST(sf_b2s_rfc4648_nocrlf) {
    REQ_B2S();
    size_t i;
    for (i = 0; i < NELEM(rfc); i++)
        B2S(rfc[i].in, (DWORD)strlen(rfc[i].in), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, rfc[i].out);
}
TEST(sf_b2s_nocr_and_nocrlf_both_set) {
    REQ_B2S();
    /* NOCRLF (bit 30) wins over NOCR (bit 31): no terminator at all. */
    B2S("foobar", 6, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR | CRYPT_STRING_NOCRLF, "Zm9vYmFy");
}
TEST(sf_b2s_single_zero_byte) {
    REQ_B2S();
    BYTE z = 0;
    B2S(&z, 1, CRYPT_STRING_BASE64, "AA==\r\n");
    z = 0xff; B2S(&z, 1, CRYPT_STRING_BASE64, "/w==\r\n");
}
TEST(sf_b2s_three_byte_groups_alphabet_edges) {
    REQ_B2S();
    BYTE a[] = { 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff };
    B2S(a, 6, CRYPT_STRING_BASE64, "++++////\r\n");
    BYTE b[] = { 0xfb, 0xff };
    B2S(b, 2, CRYPT_STRING_BASE64, "+/8=\r\n");
    BYTE c[] = { 0x00, 0x10, 0x83, 0x10, 0x51, 0x87 };
    B2S(c, 6, CRYPT_STRING_BASE64, "ABCDEFGH\r\n");
}
TEST(sf_b2s_line_wrap_literals) {
    REQ_B2S();
    BYTE s[64]; int i;
    for (i = 0; i < 64; i++) s[i] = (BYTE)i;
    B2S(s, 48, CRYPT_STRING_BASE64, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\r\n");
    B2S(s, 49, CRYPT_STRING_BASE64, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\r\nMA==\r\n");
    B2S(s, 64, CRYPT_STRING_BASE64, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\r\nMDEyMzQ1Njc4OTo7PD0+Pw==\r\n");
    B2S(s, 64, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\nMDEyMzQ1Njc4OTo7PD0+Pw==\n");
    B2S(s, 64, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==");
}
TEST(sf_b2s_no_trailing_break_after_exact_line) {
    REQ_B2S();
    /* 48 input bytes encode to exactly 64 chars: one line, one terminator, no empty second line. */
    char exp[256]; size_t n = sf_ref_b64(g_seq, 0, "", 0, 0, exp); (void)n;
    init_seq();
    n = sf_ref_b64(g_seq, 48, "\r\n", 0, 0, exp);
    EXPECT_EQ(n, 66);
    B2S_RAW(g_seq, 48, CRYPT_STRING_BASE64, exp, n, 1);
    n = sf_ref_b64(g_seq, 96, "\r\n", 0, 0, exp);
    EXPECT_EQ(n, 132);
    B2S_RAW(g_seq, 96, CRYPT_STRING_BASE64, exp, n, 1);
}
TEST(sf_b2s_length_sweep_crlf) {
    REQ_B2S();
    init_seq();
    char *exp = malloc(2048); int cb;
    for (cb = 1; cb <= 200; cb++) {
        size_t n = sf_ref_b64(g_seq, cb, "\r\n", 0, 0, exp);
        B2S_RAW(g_seq, cb, CRYPT_STRING_BASE64, exp, n, 1);
    }
    free(exp);
}
TEST(sf_b2s_length_sweep_lf) {
    REQ_B2S();
    init_seq();
    char *exp = malloc(2048); int cb;
    for (cb = 1; cb <= 200; cb += 1) {
        size_t n = sf_ref_b64(g_seq, cb, "\n", 0, 0, exp);
        B2S_RAW(g_seq, cb, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, exp, n, 1);
    }
    free(exp);
}
TEST(sf_b2s_length_sweep_nocrlf) {
    REQ_B2S();
    init_seq();
    char *exp = malloc(2048); int cb;
    for (cb = 1; cb <= 200; cb++) {
        size_t n = sf_ref_b64(g_seq, cb, "", 0, 0, exp);
        B2S_RAW(g_seq, cb, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, exp, n, 1);
    }
    free(exp);
}
TEST(sf_b2s_large_input) {
    REQ_B2S();
    BYTE *big = malloc(100000); int i; char *exp = malloc(200000);
    for (i = 0; i < 100000; i++) big[i] = (BYTE)(i * 31 + (i >> 8));
    size_t n = sf_ref_b64(big, 100000, "\r\n", 0, 0, exp);
    B2S_RAW(big, 100000, CRYPT_STRING_BASE64, exp, n, 1);
    free(big); free(exp);
}

/* ---------------- header formats ---------------- */
static void check_header_fmt(DWORD fl, const char *hdr, const char *ftr, int cb)
{
    int eolmode; init_seq();
    for (eolmode = 0; eolmode < 3; eolmode++) {
        DWORD ef = eolmode == 0 ? 0 : eolmode == 1 ? CRYPT_STRING_NOCR : CRYPT_STRING_NOCRLF;
        const char *eol = eolmode == 0 ? "\r\n" : eolmode == 1 ? "\n" : "";
        char body[1024], exp[1400];
        size_t bn = sf_ref_b64(g_seq, cb, eol, 0, 0, body);
        size_t n = (size_t)sprintf(exp, "%s%s", hdr, eol);
        memcpy(exp + n, body, bn); n += bn;
        n += sprintf(exp + n, "%s%s", ftr, eol);
        B2S_RAW(g_seq, cb, fl | ef, exp, n, 1);
    }
}
TEST(sf_b2s_header_certificate) {
    REQ_B2S();
    int cb; for (cb = 1; cb <= 70; cb += 3) check_header_fmt(CRYPT_STRING_BASE64HEADER, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", cb);
    B2S("abc", 3, CRYPT_STRING_BASE64HEADER, "-----BEGIN CERTIFICATE-----\r\nYWJj\r\n-----END CERTIFICATE-----\r\n");
}
TEST(sf_b2s_header_request) {
    REQ_B2S();
    int cb; for (cb = 1; cb <= 70; cb += 3) check_header_fmt(CRYPT_STRING_BASE64REQUESTHEADER, "-----BEGIN NEW CERTIFICATE REQUEST-----", "-----END NEW CERTIFICATE REQUEST-----", cb);
    B2S("abc", 3, CRYPT_STRING_BASE64REQUESTHEADER, "-----BEGIN NEW CERTIFICATE REQUEST-----\r\nYWJj\r\n-----END NEW CERTIFICATE REQUEST-----\r\n");
}
TEST(sf_b2s_header_x509_crl) {
    REQ_B2S();
    int cb; for (cb = 1; cb <= 70; cb += 3) check_header_fmt(CRYPT_STRING_BASE64X509CRLHEADER, "-----BEGIN X509 CRL-----", "-----END X509 CRL-----", cb);
    B2S("abc", 3, CRYPT_STRING_BASE64X509CRLHEADER, "-----BEGIN X509 CRL-----\r\nYWJj\r\n-----END X509 CRL-----\r\n");
}
TEST(sf_b2s_header_nocrlf_no_separators) {
    REQ_B2S();
    B2S("abc", 3, CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCRLF, "-----BEGIN CERTIFICATE-----YWJj-----END CERTIFICATE-----");
}
TEST(sf_b2s_header_size_includes_header_footer) {
    REQ_B2S();
    DWORD n = 0;
    /* header(27)+2 + body(4)+2 + footer(25)+2 + NUL */
    EXPECT_EQ(fa((const BYTE*)"abc", 3, CRYPT_STRING_BASE64HEADER, NULL, &n), TRUE);
    EXPECT_EQ(n, 27 + 2 + 4 + 2 + 25 + 2 + 1);
}
TEST(sf_b2s_header_short_buffer_matrix) {
    REQ_B2S();
    const char *exp = "-----BEGIN CERTIFICATE-----\r\nYWJj\r\n-----END CERTIFICATE-----\r\n";
    DWORD want = (DWORD)strlen(exp) + 1, cap;
    for (cap = 0; cap <= want + 2; cap++) {
        char buf[200]; DWORD n = cap; BOOL r;
        memset(buf, 0xAA, sizeof buf);
        SET_ERR(0);
        r = fa((const BYTE*)"abc", 3, CRYPT_STRING_BASE64HEADER, buf, &n);
        if (cap >= want) { CHECKF(r, "cap=%lu", cap); if (r) { EXPECT_EQ(n, want - 1); CHECK(!strcmp(buf, exp)); } }
        else { CHECKF(!r, "cap=%lu", cap); EXPECT_ERR(ERROR_MORE_DATA); }
        CHECKF((BYTE)buf[want + 3] == 0xAA, "no write past want, cap=%lu", cap);
    }
}
TEST(sf_b2s_base64_short_buffer_matrix) {
    REQ_B2S();
    const char *exp = "Zm9vYmFy\r\n";
    DWORD want = (DWORD)strlen(exp) + 1, cap;
    for (cap = 0; cap <= want + 2; cap++) {
        char buf[64]; DWORD n = cap; BOOL r;
        memset(buf, 0xAA, sizeof buf);
        SET_ERR(0);
        r = fa((const BYTE*)"foobar", 6, CRYPT_STRING_BASE64, buf, &n);
        if (cap >= want) { CHECKF(r, "cap=%lu", cap); if (r) { EXPECT_EQ(n, want - 1); CHECK(!strcmp(buf, exp)); } }
        else { CHECKF(!r, "cap=%lu", cap); EXPECT_ERR(ERROR_MORE_DATA); }
        CHECKF((BYTE)buf[want + 1] == 0xAA, "guard intact, cap=%lu", cap);
    }
}
TEST(sf_b2s_short_buffer_pcch_value_observed) {
    REQ_B2S();
    char buf[4]; DWORD n = sizeof buf;
    SET_ERR(0);
    BOOL r = fa((const BYTE*)"foobar", 6, CRYPT_STRING_BASE64, buf, &n);
    CHECK(!r); EXPECT_ERR(ERROR_MORE_DATA);
    t_note("pcchString after ERROR_MORE_DATA with a 4 char buffer = %lu (input value 4)", n);
}

/* ---------------- format value mapping ---------------- */
TEST(sf_b2s_base64_any_encodes_as_base64) {
    REQ_B2S();
    B2S("foobar", 6, CRYPT_STRING_BASE64_ANY, "Zm9vYmFy\r\n");
    B2S("foobar", 6, CRYPT_STRING_ANY, "Zm9vYmFy\r\n");
    B2S("foobar", 6, CRYPT_STRING_ANY | CRYPT_STRING_NOCRLF, "Zm9vYmFy");
    B2S("foobar", 6, CRYPT_STRING_BASE64_ANY | CRYPT_STRING_NOCR, "Zm9vYmFy\n");
}
TEST(sf_b2s_hex_any_encodes_as_hex) {
    REQ_B2S();
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEX_ANY, "01 02 03\r\n");
    B2S("\x01\x02\x03", 3, CRYPT_STRING_HEX_ANY | CRYPT_STRING_NOCR, "01 02 03\n");
}
TEST(sf_b2s_unknown_format_invalid_parameter) {
    REQ_B2S();
    DWORD f; char buf[128];
    for (f = 0xe; f <= 0x20; f++) {
        DWORD n = sizeof buf; SET_ERR(0);
        BOOL r = fa((const BYTE*)"abc", 3, f, buf, &n);
        CHECKF(!r, "format %#lx", f); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        n = 0; SET_ERR(0);
        r = fa((const BYTE*)"abc", 3, f, NULL, &n);
        CHECKF(!r, "size query, format %#lx", f); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}
TEST(sf_b2s_strict_flag_rejected_on_encode) {
    REQ_B2S();
    char buf[128]; DWORD n = sizeof buf; SET_ERR(0);
    BOOL r = fa((const BYTE*)"abc", 3, CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, buf, &n);
    CHECK(!r); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_b2s_ignored_bits_in_flag_high_byte) {
    REQ_B2S();
    /* Bits 24..26 are inside the format mask used by the encoder (0x37ffffff), so they select no valid format. */
    char buf[128]; DWORD n = sizeof buf; SET_ERR(0);
    BOOL r = fa((const BYTE*)"abc", 3, 0x01000000, buf, &n);
    CHECK(!r); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

/* ---------------- URI and percent escapes ---------------- */
TEST(sf_b2s_base64uri_alphabet_no_padding) {
    REQ_B2S();
    BYTE a[] = { 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff };
    B2S(a, 6, CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, "----____");
    BYTE b[] = { 0xfb, 0xff };
    B2S(b, 2, CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, "-_8");
    B2S("f", 1, CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, "Zg");
    B2S("fo", 2, CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, "Zm8");
    B2S("foo", 3, CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, "Zm9v");
}
TEST(sf_b2s_base64uri_with_terminator) {
    REQ_B2S();
    B2S("fo", 2, CRYPT_STRING_BASE64URI, "Zm8\r\n");
    B2S("fo", 2, CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCR, "Zm8\n");
}
TEST(sf_b2s_base64uri_sweep) {
    REQ_B2S();
    init_seq();
    char *exp = malloc(2048); int cb;
    for (cb = 1; cb <= 150; cb++) {
        size_t n = sf_ref_b64(g_seq, cb, "\r\n", 1, 0, exp);
        B2S_RAW(g_seq, cb, CRYPT_STRING_BASE64URI, exp, n, 1);
    }
    free(exp);
}
TEST(sf_b2s_percentescape_base64) {
    REQ_B2S();
    BYTE b[] = { 0xfb, 0xff };
    B2S(b, 2, CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE | CRYPT_STRING_NOCRLF, "%2B%2F8%3D");
    B2S("f", 1, CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE | CRYPT_STRING_NOCRLF, "Zg%3D%3D");
    B2S("foobar", 6, CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE, "Zm9vYmFy\r\n");
}
TEST(sf_b2s_percentescape_line_length_counts_escaped_chars) {
    REQ_B2S();
    BYTE *d = malloc(300); int i; char *exp = malloc(4096);
    for (i = 0; i < 300; i++) d[i] = 0xfb;
    size_t n = sf_ref_b64(d, 300, "\r\n", 0, 1, exp);
    B2S_RAW(d, 300, CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE, exp, n, 1);
    free(d); free(exp);
}

/* ---------------- HASHDATA ---------------- */
TEST(sf_b2s_hashdata_encodes_sha1_of_input) {
    REQ_B2S();
    /* SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d (FIPS 180) */
    B2S("abc", 3, CRYPT_STRING_BASE64 | CRYPT_STRING_HASHDATA, "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=\r\n");
    B2S("abc", 3, CRYPT_STRING_BASE64 | CRYPT_STRING_HASHDATA | CRYPT_STRING_NOCRLF, "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=");
}
TEST(sf_b2s_hashdata_hex) {
    REQ_B2S();
    B2S("abc", 3, CRYPT_STRING_HEXRAW | CRYPT_STRING_HASHDATA | CRYPT_STRING_NOCRLF, "a9993e364706816aba3e25717850c26c9cd0d89d");
    B2S("abc", 3, CRYPT_STRING_HEXRAW | CRYPT_STRING_HASHDATA, "a9993e364706816aba3e25717850c26c9cd0d89d\r\n");
    B2S("abc", 3, CRYPT_STRING_HEX | CRYPT_STRING_HASHDATA | CRYPT_STRING_NOCRLF,
        "a9 99 3e 36 47 06 81 6a ba 3e 25 71 78 50 c2 6c 9c d0 d8 9d"); /* NOCRLF collapses the double space at column 8 (probed) */
}
TEST(sf_b2s_hashdata_binary_is_20_bytes) {
    REQ_B2S();
    static const BYTE sha[20] = { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d };
    B2S_RAW("abc", 3, CRYPT_STRING_BINARY | CRYPT_STRING_HASHDATA, (const char*)sha, 20, 0);
}
TEST(sf_b2s_hashdata_header) {
    REQ_B2S();
    B2S("abc", 3, CRYPT_STRING_BASE64HEADER | CRYPT_STRING_HASHDATA,
        "-----BEGIN CERTIFICATE-----\r\nqZk+NkcGgWq6PiVxeFDCbJzQ2J0=\r\n-----END CERTIFICATE-----\r\n");
}

/* ---------------- BINARY ---------------- */
TEST(sf_b2s_binary_copy_no_terminator) {
    REQ_B2S();
    BYTE d[] = { 0, 1, 2, 0xff, 0x80, 'a' };
    B2S_RAW(d, 6, CRYPT_STRING_BINARY, (const char*)d, 6, 0);
    B2S_RAW(d, 1, CRYPT_STRING_BINARY, (const char*)d, 1, 0);
}
TEST(sf_b2s_binary_size_equals_cb) {
    REQ_B2S();
    BYTE d[300] = { 1 }; DWORD n = 12345; DWORD cb;
    for (cb = 1; cb <= 300; cb += 29) {
        n = 12345; EXPECT_EQ(fa(d, cb, CRYPT_STRING_BINARY, NULL, &n), TRUE); EXPECT_EQ(n, cb);
    }
}
TEST(sf_b2s_binary_nocrlf_flags_do_not_matter) {
    REQ_B2S();
    BYTE d[] = { 9, 8, 7 };
    B2S_RAW(d, 3, CRYPT_STRING_BINARY | CRYPT_STRING_NOCRLF, (const char*)d, 3, 0);
    B2S_RAW(d, 3, CRYPT_STRING_BINARY | CRYPT_STRING_NOCR, (const char*)d, 3, 0);
}
TEST(sf_b2s_binary_w_copies_raw_bytes) {
    REQ_B2S();
    BYTE d[] = { 0x41, 0x00, 0xff, 0x42 }; BYTE out[8]; DWORD n = sizeof out;
    memset(out, 0x55, sizeof out);
    SET_ERR(0);
    BOOL r = fw(d, 4, CRYPT_STRING_BINARY, (LPWSTR)out, &n);
    CHECK(r); EXPECT_EQ(n, 4); CHECK(!memcmp(out, d, 4));
}
TEST(sf_b2s_binary_exact_minus_one_fails) {
    REQ_B2S();
    BYTE d[] = { 1, 2, 3, 4 }; BYTE out[8]; DWORD n = 3;
    SET_ERR(0);
    BOOL r = fa(d, 4, CRYPT_STRING_BINARY, (LPSTR)out, &n);
    CHECK(!r); EXPECT_ERR(ERROR_MORE_DATA);
}

/* ---------------- parameter validation ---------------- */
TEST(sf_b2s_null_input_invalid_parameter) {
    REQ_B2S();
    char buf[32]; DWORD n = sizeof buf; SET_ERR(0);
    CHECK(!fa(NULL, 3, CRYPT_STRING_BASE64, buf, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = 0; SET_ERR(0);
    CHECK(!fa(NULL, 3, CRYPT_STRING_BASE64, NULL, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_b2s_zero_length_invalid_parameter) {
    REQ_B2S();
    char buf[32]; DWORD n = sizeof buf; SET_ERR(0);
    CHECK(!fa((const BYTE*)"abc", 0, CRYPT_STRING_BASE64, buf, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = 0; SET_ERR(0);
    CHECK(!fa((const BYTE*)"abc", 0, CRYPT_STRING_BASE64, NULL, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_b2s_zero_length_all_formats_invalid_parameter) {
    REQ_B2S();
    DWORD f; char buf[32];
    for (f = 0; f <= 0xd; f++) {
        DWORD n = sizeof buf; SET_ERR(0);
        BOOL r = fa((const BYTE*)"abc", 0, f, buf, &n);
        CHECKF(!r, "format %lu", f); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}
TEST(sf_b2s_null_pcch_invalid_parameter_a) {
    REQ_B2S();
    char buf[32]; SET_ERR(0);
    CHECK(!fa((const BYTE*)"abc", 3, CRYPT_STRING_BASE64, buf, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!fa((const BYTE*)"abc", 3, CRYPT_STRING_BASE64, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_b2s_w_zero_capacity_with_buffer_invalid_parameter) {
    REQ_B2S();
    WCHAR buf[32]; DWORD n = 0; SET_ERR(0);
    CHECK(!fw((const BYTE*)"abc", 3, CRYPT_STRING_BASE64, buf, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_b2s_w_null_input_invalid_parameter) {
    REQ_B2S();
    WCHAR buf[32]; DWORD n = 32; SET_ERR(0);
    CHECK(!fw(NULL, 3, CRYPT_STRING_BASE64, buf, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = 0; SET_ERR(0);
    CHECK(!fw(NULL, 3, CRYPT_STRING_BASE64, NULL, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_b2s_w_zero_cb_invalid_parameter) {
    REQ_B2S();
    WCHAR buf[32]; DWORD n = 32; SET_ERR(0);
    CHECK(!fw((const BYTE*)"abc", 0, CRYPT_STRING_BASE64, buf, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_b2s_size_query_ignores_input_pcch) {
    REQ_B2S();
    DWORD n = 0xFFFFFFF0u, m = 5;
    CHECK(fa((const BYTE*)"foobar", 6, CRYPT_STRING_BASE64, NULL, &n));
    CHECK(fa((const BYTE*)"foobar", 6, CRYPT_STRING_BASE64, NULL, &m));
    EXPECT_EQ(n, 11); EXPECT_EQ(m, 11);
    n = 0xFFFFFFF0u; m = 5;
    CHECK(fw((const BYTE*)"foobar", 6, CRYPT_STRING_BASE64, NULL, &n));
    CHECK(fw((const BYTE*)"foobar", 6, CRYPT_STRING_BASE64, NULL, &m));
    EXPECT_EQ(n, 11); EXPECT_EQ(m, 11);
}
TEST(sf_b2s_oversized_buffer_reports_actual_length) {
    REQ_B2S();
    char buf[200]; DWORD n = 200; memset(buf, 'x', sizeof buf);
    CHECK(fa((const BYTE*)"foobar", 6, CRYPT_STRING_BASE64, buf, &n));
    EXPECT_EQ(n, 10); EXPECT_STR(buf, "Zm9vYmFy\r\n"); EXPECT_EQ(buf[11], 'x');
}
TEST(sf_b2s_w_oversized_buffer_reports_actual_length) {
    REQ_B2S();
    WCHAR buf[200]; DWORD n = 200; int i;
    for (i = 0; i < 200; i++) buf[i] = L'x';
    CHECK(fw((const BYTE*)"foobar", 6, CRYPT_STRING_BASE64, buf, &n));
    EXPECT_EQ(n, 10); CHECK(!lstrcmpW(buf, L"Zm9vYmFy\r\n"));
}
TEST(sf_b2s_input_not_modified) {
    REQ_B2S();
    BYTE in[40], copy[40]; int i; char out[200]; DWORD n = sizeof out;
    for (i = 0; i < 40; i++) in[i] = copy[i] = (BYTE)(255 - i * 3);
    CHECK(fa(in, 40, CRYPT_STRING_BASE64, out, &n));
    CHECK(!memcmp(in, copy, 40));
}
TEST(sf_b2s_deterministic_repeat) {
    REQ_B2S();
    char a[200], b[200]; DWORD na = 200, nb = 200; init_seq();
    CHECK(fa(g_seq, 100, CRYPT_STRING_BASE64HEADER, a, &na));
    CHECK(fa(g_seq, 100, CRYPT_STRING_BASE64HEADER, b, &nb));
    EXPECT_EQ(na, nb); CHECK(!strcmp(a, b));
}

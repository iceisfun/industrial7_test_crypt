/* CryptStringToBinaryA/W: base64 family, header scanning, ANY detection and the size protocol. */
#include "sf.h"

#define REQ_S2B() BOOL (WINAPI *fa)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*) = (void*)t_proc("CryptStringToBinaryA"); \
                  BOOL (WINAPI *fw)(LPCWSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*) = (void*)t_proc("CryptStringToBinaryW"); \
                  REQUIRE(fa); REQUIRE(fw); (void)fa; (void)fw

static const struct { const char *plain; const char *b64; } rfc[] = {
    { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" }, { "foob", "Zm9vYg==" },
    { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" },
};

/* ---------------- plain base64 ---------------- */
TEST(sf_s2b_base64_rfc4648_padded) {
    REQ_S2B(); size_t i;
    for (i = 0; i < NELEM(rfc); i++) DEC_OK_STR(rfc[i].b64, CRYPT_STRING_BASE64, rfc[i].plain);
}
TEST(sf_s2b_base64_rfc4648_unpadded) {
    REQ_S2B();
    DEC_OK_STR("Zg", CRYPT_STRING_BASE64, "f");
    DEC_OK_STR("Zm8", CRYPT_STRING_BASE64, "fo");
    DEC_OK_STR("Zm9vYg", CRYPT_STRING_BASE64, "foob");
    DEC_OK_STR("Zm9vYmE", CRYPT_STRING_BASE64, "fooba");
}
TEST(sf_s2b_base64_trailing_crlf_and_lf) {
    REQ_S2B();
    DEC_OK_STR("Zm9vYmFy\r\n", CRYPT_STRING_BASE64, "foobar");
    DEC_OK_STR("Zm9vYmFy\n", CRYPT_STRING_BASE64, "foobar");
    DEC_OK_STR("Zm9vYg==\r\n", CRYPT_STRING_BASE64, "foob");
    DEC_OK_STR("\r\nZm9vYmFy", CRYPT_STRING_BASE64, "foobar");
}
TEST(sf_s2b_base64_whitespace_anywhere) {
    REQ_S2B();
    DEC_OK_STR("Zm 9v\tYm\r\nFy", CRYPT_STRING_BASE64, "foobar");
    DEC_OK_STR(" Z m 9 v Y g = = ", CRYPT_STRING_BASE64, "foob");
    DEC_OK_STR("Z\r\nm\r\n9\r\nv", CRYPT_STRING_BASE64, "foo");
    DEC_OK_STR("Zm9v\r\n\r\n\r\nYmFy\r\n", CRYPT_STRING_BASE64, "foobar");
}
TEST(sf_s2b_base64_alphabet_edges) {
    REQ_S2B();
    BYTE a[] = { 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff };
    DEC_OK("++++////", CRYPT_STRING_BASE64, a, 6);
    BYTE b[] = { 0xfb, 0xff };
    DEC_OK("+/8=", CRYPT_STRING_BASE64, b, 2);
    BYTE c[] = { 0x00, 0x10, 0x83, 0x10, 0x51, 0x87 };
    DEC_OK("ABCDEFGH", CRYPT_STRING_BASE64, c, 6);
}
TEST(sf_s2b_base64_binary_zero_bytes) {
    REQ_S2B(); BYTE z[3] = { 0, 0, 0 };
    DEC_OK("AAAA", CRYPT_STRING_BASE64, z, 3);
    DEC_OK("AA==", CRYPT_STRING_BASE64, z, 1);
    DEC_OK("AAA=", CRYPT_STRING_BASE64, z, 2);
}
TEST(sf_s2b_base64_roundtrip_all_lengths) {
    REQ_S2B(); BYTE d[300]; int i, cb; char txt[1024];
    for (i = 0; i < 300; i++) d[i] = (BYTE)(i * 11 + 1);
    for (cb = 1; cb <= 200; cb++) {
        size_t n = sf_ref_b64(d, cb, "\r\n", 0, 0, txt); (void)n;
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_BASE64, d, cb);
        sf_ref_b64(d, cb, "\n", 0, 0, txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_BASE64, d, cb);
        sf_ref_b64(d, cb, "", 0, 0, txt);
        sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_BASE64, d, cb);
    }
}
TEST(sf_s2b_base64_large_roundtrip) {
    REQ_S2B(); int i; BYTE *d = malloc(60000); char *txt = malloc(120000); BYTE *out = malloc(60000); DWORD n = 60000;
    for (i = 0; i < 60000; i++) d[i] = (BYTE)(i * 7 + (i >> 9));
    sf_ref_b64(d, 60000, "\r\n", 0, 0, txt);
    SET_ERR(0);
    CHECK(fa(txt, 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL));
    EXPECT_EQ(n, 60000); CHECK(!memcmp(out, d, 60000));
    free(d); free(txt); free(out);
}
TEST(sf_s2b_base64_invalid_first_char) {
    REQ_S2B();
    DEC_FAIL("====", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("!!!!", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("*Zm9v", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("=Zm9v", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
}
TEST(sf_s2b_base64_nonstrict_stops_at_invalid_char) {
    REQ_S2B();
    /* After a complete quad the decoder stops at the first non-alphabet character and succeeds. */
    DEC_OK_STR("Zm9vYmFy!!!!", CRYPT_STRING_BASE64, "foobar");
    DEC_OK_STR("Zm9v!Zm9v", CRYPT_STRING_BASE64, "foo");
    DEC_OK_STR("Zm9v\x01\x02", CRYPT_STRING_BASE64, "foo");
}
TEST(sf_s2b_base64_strict_rejects_trailing_garbage) {
    REQ_S2B();
    DEC_OK_STR("Zm9vYmFy", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, "foobar");
    DEC_FAIL("Zm9vYmFy!!!!", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
    DEC_FAIL("Zm9v!Zm9v", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
}
TEST(sf_s2b_base64_partial_quad_before_invalid_char_needs_padding) {
    REQ_S2B();
    /* two or three alphabet chars followed by a stray character: the remaining '=' padding is mandatory */
    DEC_FAIL("QQ!", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("QUI!", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("QQ=!", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
}
TEST(sf_s2b_base64_incomplete_padding) {
    REQ_S2B();
    DEC_FAIL("QQ=", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("QQ=", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
    DEC_FAIL("QUI==", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
    /* a completely unpadded tail is accepted, also in strict mode */
    DEC_OK_STR("QQ", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, "A");
    DEC_OK_STR("QUI", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, "AB");
}
TEST(sf_s2b_base64_padding_with_whitespace) {
    REQ_S2B();
    DEC_OK_STR("QQ = =", CRYPT_STRING_BASE64, "A");
    DEC_OK_STR("QQ=\r\n=", CRYPT_STRING_BASE64, "A");
    DEC_OK_STR("QUI =", CRYPT_STRING_BASE64, "AB");
}
TEST(sf_s2b_base64_stops_at_padding_in_nonstrict) {
    REQ_S2B();
    DEC_OK_STR("QQ==QQ==", CRYPT_STRING_BASE64, "A");
    DEC_OK_STR("QUI=QUI=", CRYPT_STRING_BASE64, "AB");
    DEC_OK_STR("QQ==Zm9v", CRYPT_STRING_BASE64, "A");
}
TEST(sf_s2b_base64_strict_rejects_data_after_padding) {
    REQ_S2B();
    DEC_FAIL("QQ==QQ==", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
}
TEST(sf_s2b_base64_single_sextet_then_stray_char_fails) {
    REQ_S2B();
    DEC_FAIL("Q!", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
    DEC_FAIL("Zm9vQ!", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
    DEC_FAIL("Q!", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("Zm9vQ!", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
}
TEST(sf_s2b_base64_partial_sextet_groups) {
    REQ_S2B();
    /* a lone sextet still yields one byte (its six bits shifted up), two give one, three give two */
    DEC_OK_STR("V", CRYPT_STRING_BASE64, "T");
    DEC_OK_STR("VV", CRYPT_STRING_BASE64, "U");
    DEC_OK_STR("VVV", CRYPT_STRING_BASE64, "UU");
    DEC_OK_STR("VVVV", CRYPT_STRING_BASE64, "UUU");
    DEC_OK_STR("VVVVV", CRYPT_STRING_BASE64, "UUUT");
}
TEST(sf_s2b_base64_padding_counts) {
    REQ_S2B();
    DEC_FAIL("V=", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("VV=", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_FAIL("V==", CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    DEC_OK_STR("V===", CRYPT_STRING_BASE64, "T");
    DEC_OK_STR("VV==", CRYPT_STRING_BASE64, "U");
    DEC_OK_STR("VVV=", CRYPT_STRING_BASE64, "UU");
    DEC_OK_STR("V========", CRYPT_STRING_BASE64, "T");
}
TEST(sf_s2b_base64_data_after_padding_is_ignored) {
    REQ_S2B();
    DEC_OK_STR("V===VVVV", CRYPT_STRING_BASE64, "T");
    DEC_OK_STR("VV==VVVV", CRYPT_STRING_BASE64, "U");
    DEC_OK_STR("VVV=VVVV", CRYPT_STRING_BASE64, "UU");
    DEC_OK_STR("VVVV=VVVV", CRYPT_STRING_BASE64, "UUU");
}
TEST(sf_s2b_base64_cch_inside_padding) {
    REQ_S2B();
    sf_expect_dec(__FILE__, __LINE__, "V===", 4, CRYPT_STRING_BASE64, "T", 1);
    sf_expect_dec(__FILE__, __LINE__, "V===VVVV", 8, CRYPT_STRING_BASE64, "T", 1);
    sf_expect_dec(__FILE__, __LINE__, "V\nVVV", 5, CRYPT_STRING_BASE64, "UUU", 3);
    sf_expect_dec(__FILE__, __LINE__, "VV    VV", 0, CRYPT_STRING_BASE64, "UUU", 3);
    sf_expect_decfail(__FILE__, __LINE__, "V=", 2, CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
    sf_expect_decfail(__FILE__, __LINE__, "VV=", 3, CRYPT_STRING_BASE64, ERROR_INVALID_DATA);
}
TEST(sf_s2b_nocr_nocrlf_flags_rejected_on_decode) {
    REQ_S2B(); BYTE out[8]; DWORD n = 8; SET_ERR(0);
    CHECK(!fa("Zm9v", 4, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, NULL, &n, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_DATA);
    SET_ERR(0); n = 8;
    CHECK(!fa("Zm9v", 0, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &n, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_DATA);
}
TEST(sf_s2b_header_requires_space_after_begin_and_end) {
    REQ_S2B();
    DEC_FAIL("-----BEGIN-----VVVV-----END-----", CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
    DEC_FAIL("-----BEGIN-----VVVV-----END -----", CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
    DEC_FAIL("-----BEGIN -----VVVV-----END-----", CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
    DEC_OK_STR("-----BEGIN -----VVVV-----END -----", CRYPT_STRING_BASE64HEADER, "UUU");
}
TEST(sf_s2b_header_labels_need_not_match) {
    REQ_S2B();
    DEC_OK_STR("-----BEGIN -----V-----END -----", CRYPT_STRING_BASE64HEADER, "T");
    DEC_OK_STR("-----BEGIN foo-----V-----END -----", CRYPT_STRING_BASE64HEADER, "T");
    DEC_OK_STR("-----BEGIN foo-----V-----END bar-----", CRYPT_STRING_BASE64HEADER, "T");
    DEC_OK_STR("-----BEGIN foo-----V-----END bar-----", CRYPT_STRING_BASE64X509CRLHEADER, "T");
    DEC_OK_STR("-----BEGIN foo-----V-----END bar-----", CRYPT_STRING_BASE64REQUESTHEADER, "T");
}
TEST(sf_s2b_base64_empty_input_observed) {
    REQ_S2B(); sf_dec d;
    sf_decode("", 0, CRYPT_STRING_BASE64, 0, &d);
    t_note("BASE64 empty string: ok=%d cb=%lu err=%lu", d.ok, d.cb, d.err);
    sf_decode("\r\n", 0, CRYPT_STRING_BASE64, 0, &d);
    t_note("BASE64 whitespace only: ok=%d cb=%lu err=%lu", d.ok, d.cb, d.err);
}

/* ---------------- size protocol ---------------- */
TEST(sf_s2b_size_query_null_buffer) {
    REQ_S2B(); DWORD n = 0xdead;
    SET_ERR(0);
    CHECK(fa("Zm9vYmFy", 0, CRYPT_STRING_BASE64, NULL, &n, NULL, NULL));
    EXPECT_EQ(n, 6);
    n = 0xdead; CHECK(fa("Zm9vYg==", 0, CRYPT_STRING_BASE64, NULL, &n, NULL, NULL)); EXPECT_EQ(n, 4);
    n = 0xdead; CHECK(fa("Zm9vYmE=", 0, CRYPT_STRING_BASE64, NULL, &n, NULL, NULL)); EXPECT_EQ(n, 5);
}
TEST(sf_s2b_size_query_ignores_incoming_pcb) {
    REQ_S2B(); DWORD n = 0xFFFFFFF0u, m = 3;
    CHECK(fa("Zm9vYmFy", 0, CRYPT_STRING_BASE64, NULL, &n, NULL, NULL));
    CHECK(fa("Zm9vYmFy", 0, CRYPT_STRING_BASE64, NULL, &m, NULL, NULL));
    EXPECT_EQ(n, 6); EXPECT_EQ(m, 6);
}
TEST(sf_s2b_exact_buffer) {
    REQ_S2B(); BYTE out[16]; DWORD n = 6; memset(out, 0xAA, sizeof out);
    CHECK(fa("Zm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL));
    EXPECT_EQ(n, 6); CHECK(!memcmp(out, "foobar", 6)); EXPECT_EQ(out[6], 0xAA);
}
TEST(sf_s2b_short_buffer_more_data) {
    REQ_S2B(); BYTE out[16]; DWORD n = 5; memset(out, 0xAA, sizeof out);
    SET_ERR(0);
    CHECK(!fa("Zm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 5); /* *pcbBinary is left untouched on failure */ EXPECT_EQ(out[0], 0xAA);
}
TEST(sf_s2b_zero_capacity_buffer_more_data) {
    REQ_S2B(); BYTE out[4]; DWORD n = 0;
    SET_ERR(0);
    CHECK(!fa("Zm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 0);
}
TEST(sf_s2b_large_buffer_reports_actual) {
    REQ_S2B(); BYTE out[64]; DWORD n = 64; memset(out, 0xAA, sizeof out);
    CHECK(fa("Zm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL));
    EXPECT_EQ(n, 6); EXPECT_EQ(out[6], 0xAA);
}
TEST(sf_s2b_short_buffer_matrix) {
    REQ_S2B(); DWORD cap;
    for (cap = 0; cap <= 8; cap++) {
        BYTE out[16]; DWORD n = cap; BOOL r; memset(out, 0xAA, sizeof out);
        SET_ERR(0);
        r = fa("Zm9vYmE=", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL);
        if (cap >= 5) { CHECKF(r, "cap %lu", cap); EXPECT_EQ(n, 5); CHECK(!memcmp(out, "fooba", 5)); }
        else { CHECKF(!r, "cap %lu", cap); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, cap); }
        CHECKF(out[8] == 0xAA, "guard cap %lu", cap);
    }
}
TEST(sf_s2b_w_size_protocol) {
    REQ_S2B(); DWORD n = 0; BYTE out[16];
    CHECK(fw(L"Zm9vYmFy", 0, CRYPT_STRING_BASE64, NULL, &n, NULL, NULL)); EXPECT_EQ(n, 6);
    n = 3; SET_ERR(0);
    CHECK(!fw(L"Zm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 3);
    n = 16; CHECK(fw(L"Zm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_EQ(n, 6); CHECK(!memcmp(out, "foobar", 6));
}

/* ---------------- cchString ---------------- */
TEST(sf_s2b_cch_zero_means_nul_terminated) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    CHECK(fa("Zm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_EQ(n, 6);
}
TEST(sf_s2b_cch_explicit_length_truncates_input) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    CHECK(fa("Zm9vYmFy", 4, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_EQ(n, 3); CHECK(!memcmp(out, "foo", 3));
    n = 16; CHECK(fa("Zm9vYmFy", 8, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_EQ(n, 6);
    n = 16; CHECK(fa("Zm9vYmFy", 6, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_EQ(n, 4);
    n = 16; CHECK(fa("Zm9vYmFy", 2, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_EQ(n, 1);
}
TEST(sf_s2b_cch_includes_terminating_nul) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    /* the NUL is not an alphabet character: it ends the decode just like any other stray char */
    SET_ERR(0);
    BOOL r = fa("Zm9vYmFy", 9, CRYPT_STRING_BASE64, out, &n, NULL, NULL);
    CHECK(r); if (r) EXPECT_EQ(n, 6);
}
TEST(sf_s2b_cch_w_variants) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    CHECK(fw(L"Zm9vYmFy", 4, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_EQ(n, 3);
    n = 16; CHECK(fw(L"Zm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_EQ(n, 6);
}
TEST(sf_s2b_w_leading_bom_is_skipped) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    CHECK(fw(L"\xfeffZm9vYmFy", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL));
    EXPECT_EQ(n, 6); CHECK(!memcmp(out, "foobar", 6));
}

/* ---------------- parameter validation ---------------- */
TEST(sf_s2b_null_string_invalid_parameter) {
    REQ_S2B(); BYTE out[8]; DWORD n = 8; SET_ERR(0);
    CHECK(!fa(NULL, 4, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!fw(NULL, 4, CRYPT_STRING_BASE64, out, &n, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_s2b_w_null_pcb_invalid_parameter) {
    REQ_S2B(); SET_ERR(0);
    CHECK(!fw(L"Zm9v", 0, CRYPT_STRING_BASE64, NULL, NULL, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sf_s2b_unknown_format_invalid_data) {
    REQ_S2B(); DWORD f;
    for (f = 0xe; f <= 0x14; f++) {
        BYTE out[8]; DWORD n = 8; SET_ERR(0);
        CHECKF(!fa("Zm9v", 0, f, out, &n, NULL, NULL), "fmt %#lx", f); EXPECT_ERR(ERROR_INVALID_DATA);
    }
}
TEST(sf_s2b_null_skip_and_flags_accepted) {
    REQ_S2B(); BYTE out[8]; DWORD n = 8;
    CHECK(fa("Zm9v", 0, CRYPT_STRING_BASE64, out, &n, NULL, NULL));
    n = 8; DWORD sk = 77; CHECK(fa("Zm9v", 0, CRYPT_STRING_BASE64, out, &n, &sk, NULL)); EXPECT_EQ(sk, 0);
    n = 8; DWORD fg = 77; CHECK(fa("Zm9v", 0, CRYPT_STRING_BASE64, out, &n, NULL, &fg));
}
TEST(sf_s2b_skip_and_flags_reset_on_failure) {
    REQ_S2B(); BYTE out[8]; DWORD n = 8, sk = 77, fg = 77;
    CHECK(!fa("====", 0, CRYPT_STRING_BASE64, out, &n, &sk, &fg));
    EXPECT_EQ(sk, 0);
}
TEST(sf_s2b_plain_base64_reports_format) {
    REQ_S2B(); sf_dec d;
    sf_decode("Zm9v", 0, CRYPT_STRING_BASE64, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.skip, 0); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64);
    sf_decode("Zm9v", 0, CRYPT_STRING_BASE64, 1, &d);
    CHECK(d.ok); EXPECT_EQ(d.skip, 0); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64);
}

/* ---------------- header formats ---------------- */
#define HDR "-----BEGIN CERTIFICATE-----\r\n"
#define FTR "-----END CERTIFICATE-----\r\n"
TEST(sf_s2b_header_basic) {
    REQ_S2B(); sf_dec d; int w;
    for (w = 0; w < 2; w++) {
        sf_decode(HDR "Zm9vYmFy\r\n" FTR, 0, CRYPT_STRING_BASE64HEADER, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 6); CHECK(!memcmp(d.data, "foobar", 6));
        EXPECT_EQ(d.skip, 0); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64HEADER);
    }
}
TEST(sf_s2b_header_leading_junk_reports_skip) {
    REQ_S2B(); sf_dec d; int w;
    for (w = 0; w < 2; w++) {
        sf_decode("junk line\r\nmore junk\r\n" HDR "Zm9vYmFy\r\n" FTR, 0, CRYPT_STRING_BASE64HEADER, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 6); EXPECT_EQ(d.skip, 22);
        sf_decode("x" HDR "Zm9v\r\n" FTR, 0, CRYPT_STRING_BASE64HEADER, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.skip, 1);
    }
}
TEST(sf_s2b_header_trailing_junk_after_footer) {
    REQ_S2B();
    DEC_OK_STR(HDR "Zm9vYmFy\r\n" FTR "trailing garbage that is not base64\r\n", CRYPT_STRING_BASE64HEADER, "foobar");
}
TEST(sf_s2b_header_missing_footer_fails) {
    REQ_S2B();
    DEC_FAIL(HDR "Zm9vYmFy\r\n", CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
}
TEST(sf_s2b_header_missing_header_fails) {
    REQ_S2B();
    DEC_FAIL("Zm9vYmFy\r\n" FTR, CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
    DEC_FAIL("Zm9vYmFy\r\n", CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
}
TEST(sf_s2b_header_empty_string_fails) {
    REQ_S2B();
    DEC_FAIL("", CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
}
TEST(sf_s2b_header_label_is_arbitrary) {
    REQ_S2B();
    DEC_OK_STR("-----BEGIN FOO BAR-----\r\nZm9v\r\n-----END FOO BAR-----\r\n", CRYPT_STRING_BASE64HEADER, "foo");
    DEC_OK_STR("-----BEGIN X509 CRL-----\r\nZm9v\r\n-----END X509 CRL-----\r\n", CRYPT_STRING_BASE64HEADER, "foo");
    DEC_OK_STR("-----BEGIN NEW CERTIFICATE REQUEST-----\r\nZm9v\r\n-----END NEW CERTIFICATE REQUEST-----\r\n", CRYPT_STRING_BASE64HEADER, "foo");
}
TEST(sf_s2b_header_request_and_crl_formats_accept_any_label) {
    REQ_S2B(); sf_dec d;
    DEC_OK_STR(HDR "Zm9v\r\n" FTR, CRYPT_STRING_BASE64REQUESTHEADER, "foo");
    DEC_OK_STR("-----BEGIN NEW CERTIFICATE REQUEST-----\r\nZm9v\r\n-----END NEW CERTIFICATE REQUEST-----\r\n", CRYPT_STRING_BASE64REQUESTHEADER, "foo");
    DEC_OK_STR(HDR "Zm9v\r\n" FTR, CRYPT_STRING_BASE64X509CRLHEADER, "foo");
    DEC_OK_STR("-----BEGIN X509 CRL-----\r\nZm9v\r\n-----END X509 CRL-----\r\n", CRYPT_STRING_BASE64X509CRLHEADER, "foo");
    sf_decode(HDR "Zm9v\r\n" FTR, 0, CRYPT_STRING_BASE64REQUESTHEADER, 0, &d); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64REQUESTHEADER);
    sf_decode(HDR "Zm9v\r\n" FTR, 0, CRYPT_STRING_BASE64X509CRLHEADER, 0, &d); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64X509CRLHEADER);
}
TEST(sf_s2b_header_lf_only_lines) {
    REQ_S2B();
    DEC_OK_STR("-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n", CRYPT_STRING_BASE64HEADER, "foobar");
    DEC_OK_STR("-----BEGIN CERTIFICATE-----Zm9vYmFy-----END CERTIFICATE-----", CRYPT_STRING_BASE64HEADER, "foobar");
}
TEST(sf_s2b_header_multiline_body) {
    REQ_S2B(); BYTE d[100]; int i; char body[512], txt[1024];
    for (i = 0; i < 100; i++) d[i] = (BYTE)(i * 5);
    sf_ref_b64(d, 100, "\r\n", 0, 0, body);
    sprintf(txt, "-----BEGIN CERTIFICATE-----\r\n%s-----END CERTIFICATE-----\r\n", body);
    sf_expect_dec(__FILE__, __LINE__, txt, 0, CRYPT_STRING_BASE64HEADER, d, 100);
}
TEST(sf_s2b_header_empty_body) {
    REQ_S2B(); sf_dec d;
    sf_decode("-----BEGIN CERTIFICATE-----\r\n-----END CERTIFICATE-----\r\n", 0, CRYPT_STRING_BASE64HEADER, 0, &d);
    t_note("header with empty body: ok=%d cb=%lu err=%lu", d.ok, d.cb, d.err);
}
TEST(sf_s2b_header_cch_limits_footer_search) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    const char *s = HDR "Zm9vYmFy\r\n" FTR;
    SET_ERR(0);
    CHECK(!fa(s, (DWORD)strlen(HDR "Zm9vYmFy\r\n"), CRYPT_STRING_BASE64HEADER, out, &n, NULL, NULL));
    EXPECT_ERR(ERROR_INVALID_DATA);
    n = 16; CHECK(fa(s, (DWORD)strlen(s), CRYPT_STRING_BASE64HEADER, out, &n, NULL, NULL)); EXPECT_EQ(n, 6);
}
TEST(sf_s2b_header_two_blocks_decodes_first) {
    REQ_S2B();
    DEC_OK_STR("-----BEGIN CERTIFICATE-----\r\nZm9v\r\n-----END CERTIFICATE-----\r\n"
               "-----BEGIN CERTIFICATE-----\r\nYmFy\r\n-----END CERTIFICATE-----\r\n", CRYPT_STRING_BASE64HEADER, "foo");
}
TEST(sf_s2b_header_footer_without_dashes_fails) {
    REQ_S2B();
    DEC_FAIL("-----BEGIN CERTIFICATE-----\r\nZm9v\r\nEND CERTIFICATE\r\n", CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
    DEC_FAIL("-----BEGIN CERTIFICATE\r\nZm9v\r\n-----END CERTIFICATE-----\r\n", CRYPT_STRING_BASE64HEADER, ERROR_INVALID_DATA);
}
TEST(sf_s2b_header_size_and_short_buffer) {
    REQ_S2B(); DWORD n = 0; BYTE out[8];
    CHECK(fa(HDR "Zm9vYmFy\r\n" FTR, 0, CRYPT_STRING_BASE64HEADER, NULL, &n, NULL, NULL)); EXPECT_EQ(n, 6);
    n = 2; SET_ERR(0);
    CHECK(!fa(HDR "Zm9vYmFy\r\n" FTR, 0, CRYPT_STRING_BASE64HEADER, out, &n, NULL, NULL)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 2);
}
TEST(sf_s2b_header_with_nonheader_format_does_not_skip) {
    REQ_S2B(); sf_dec d;
    /* plain BASE64 with a header present: the dashes are URI-alphabet characters, no skipping is reported */
    sf_decode(HDR "Zm9vYmFy\r\n" FTR, 0, CRYPT_STRING_BASE64, 0, &d);
    EXPECT_EQ(d.skip, 0);
    t_note("BASE64 applied to PEM text: ok=%d cb=%lu err=%lu flags=%lu", d.ok, d.cb, d.err, d.flags);
}

/* ---------------- ANY / BASE64_ANY ---------------- */
TEST(sf_s2b_base64_any_header_and_plain) {
    REQ_S2B(); sf_dec d; int w;
    for (w = 0; w < 2; w++) {
        sf_decode(HDR "Zm9vYmFy\r\n" FTR, 0, CRYPT_STRING_BASE64_ANY, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 6); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64HEADER); EXPECT_EQ(d.skip, 0);
        sf_decode("Zm9vYmFy\r\n", 0, CRYPT_STRING_BASE64_ANY, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 6); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64);
        sf_decode("junk\r\n" HDR "Zm9v\r\n" FTR, 0, CRYPT_STRING_BASE64_ANY, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.skip, 6);
    }
}
TEST(sf_s2b_any_header_and_plain) {
    REQ_S2B(); sf_dec d; int w;
    for (w = 0; w < 2; w++) {
        sf_decode(HDR "Zm9vYmFy\r\n" FTR, 0, CRYPT_STRING_ANY, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 6); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64HEADER);
        sf_decode("Zm9vYmFy\r\n", 0, CRYPT_STRING_ANY, w, &d);
        CHECK(d.ok); EXPECT_EQ(d.cb, 6); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64);
    }
}
TEST(sf_s2b_any_request_header_text) {
    REQ_S2B();
    DEC_OK_STR("-----BEGIN NEW CERTIFICATE REQUEST-----\r\nZm9v\r\n-----END NEW CERTIFICATE REQUEST-----\r\n", CRYPT_STRING_ANY, "foo");
}
TEST(sf_s2b_any_binary_fallback_a) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16, fg = 0; BYTE in[] = { 0x01, 0x02, 0x03, 0xfe };
    SET_ERR(0);
    BOOL r = fa((LPCSTR)in, 4, CRYPT_STRING_ANY, out, &n, NULL, &fg);
    CHECK(r); if (r) { EXPECT_EQ(n, 4); CHECK(!memcmp(out, in, 4)); t_note("ANY on raw bytes reports format %lu", fg); }
}
TEST(sf_s2b_any_w_failure_maps_error) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16; SET_ERR(0);
    /* W maps ANY onto BASE64_ANY (header, base64, base64url: no BINARY) and reports ERROR_INVALID_USER_BUFFER on failure */
    CHECK(!fw(L"====", 4, CRYPT_STRING_ANY, out, &n, NULL, NULL));
    EXPECT_ERR(ERROR_INVALID_USER_BUFFER);
}
TEST(sf_s2b_base64_any_rejects_garbage) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    SET_ERR(0);
    CHECK(!fa("====", 0, CRYPT_STRING_BASE64_ANY, out, &n, NULL, NULL));
    EXPECT_ERR(ERROR_INVALID_DATA);
    n = 16; SET_ERR(0);
    CHECK(!fw(L"====", 4, CRYPT_STRING_BASE64_ANY, out, &n, NULL, NULL));
    EXPECT_ERR(ERROR_INVALID_DATA);
}
TEST(sf_s2b_any_a_falls_back_to_binary_for_garbage) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16, fg = 0, sk = 9;
    CHECK(fa("====", 0, CRYPT_STRING_ANY, out, &n, &sk, &fg));
    EXPECT_EQ(n, 4); CHECK(!memcmp(out, "====", 4)); EXPECT_EQ(fg, CRYPT_STRING_BINARY); EXPECT_EQ(sk, 0);
}
TEST(sf_s2b_any_flag_reports_base64url) {
    REQ_S2B(); sf_dec d;
    sf_decode("-_8", 0, CRYPT_STRING_ANY, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 2); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64URI);
    sf_decode("-_8", 0, CRYPT_STRING_BASE64_ANY, 1, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 2); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64URI);
}

/* ---------------- URI alphabet and percent escapes ---------------- */
TEST(sf_s2b_base64uri_alphabet) {
    REQ_S2B(); BYTE a[] = { 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff }, b[] = { 0xfb, 0xff }; sf_dec d;
    DEC_OK("----____", CRYPT_STRING_BASE64URI, a, 6);
    DEC_OK("-_8", CRYPT_STRING_BASE64URI, b, 2);
    DEC_OK_STR("Zg", CRYPT_STRING_BASE64URI, "f");
    DEC_OK_STR("Zm8", CRYPT_STRING_BASE64URI, "fo");
    DEC_OK_STR("Zm9vYmFy", CRYPT_STRING_BASE64URI, "foobar");
    sf_decode("-_8", 0, CRYPT_STRING_BASE64URI, 0, &d); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64URI);
}
TEST(sf_s2b_base64uri_without_special_chars_reports_uri) {
    REQ_S2B(); sf_dec d;
    sf_decode("Zm9v", 0, CRYPT_STRING_BASE64URI, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64URI);
}
TEST(sf_s2b_base64uri_flag_accepts_standard_alphabet) {
    REQ_S2B(); BYTE b[] = { 0xfb, 0xff }; sf_dec d;
    /* the '+' '/' '=' characters make the decoder fall back to the standard table and report BASE64 */
    DEC_OK("+/8=", CRYPT_STRING_BASE64URI, b, 2);
    sf_decode("+/8=", 0, CRYPT_STRING_BASE64URI, 0, &d); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64);
}
TEST(sf_s2b_base64_flag_autodetects_uri_alphabet) {
    REQ_S2B(); BYTE b[] = { 0xfb, 0xff }, a[] = { 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff }; sf_dec d;
    DEC_OK("-_8", CRYPT_STRING_BASE64, b, 2);
    DEC_OK("----____", CRYPT_STRING_BASE64, a, 6);
    sf_decode("-_8", 0, CRYPT_STRING_BASE64, 0, &d); CHECK(d.ok); EXPECT_EQ(d.flags, CRYPT_STRING_BASE64URI);
}
TEST(sf_s2b_base64_strict_does_not_autodetect_uri) {
    REQ_S2B();
    DEC_FAIL("-_8", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
    DEC_FAIL("----____", CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
}
TEST(sf_s2b_base64uri_strict_accepts_uri_text) {
    REQ_S2B(); BYTE b[] = { 0xfb, 0xff };
    DEC_OK("-_8", CRYPT_STRING_BASE64URI | CRYPT_STRING_STRICT, b, 2);
}
TEST(sf_s2b_base64uri_strict_trailing_garbage_fails) {
    REQ_S2B();
    DEC_FAIL("Zm9v!", CRYPT_STRING_BASE64URI | CRYPT_STRING_STRICT, ERROR_INVALID_DATA);
}
TEST(sf_s2b_percentescape_decode) {
    REQ_S2B(); BYTE b[] = { 0xfb, 0xff };
    DEC_OK("%2B%2F8%3D", CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE, b, 2);
    DEC_OK_STR("Zg%3D%3D", CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE, "f");
    DEC_OK_STR("Zm9vYmFy", CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE, "foobar");
}
TEST(sf_s2b_percentescape_lowercase_hex) {
    REQ_S2B(); BYTE b[] = { 0xfb, 0xff };
    DEC_OK("%2b%2f8%3d", CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE, b, 2);
}
TEST(sf_s2b_percent_without_flag_is_stray_char) {
    REQ_S2B(); sf_dec d;
    sf_decode("Zm9v%2B%2F", 0, CRYPT_STRING_BASE64, 0, &d);
    CHECK(d.ok); EXPECT_EQ(d.cb, 3);
}
TEST(sf_s2b_percentescape_bad_hex_fails) {
    REQ_S2B(); sf_dec d;
    sf_decode("Zm9v%ZZ", 0, CRYPT_STRING_BASE64 | CRYPT_STRING_PERCENTESCAPE, 0, &d);
    t_note("percent escape with non-hex digits: ok=%d cb=%lu err=%lu", d.ok, d.cb, d.err);
}

/* ---------------- BINARY ---------------- */
TEST(sf_s2b_binary_copies_bytes) {
    REQ_S2B(); BYTE in[] = { 0, 1, 2, 3, 0xff, 0x80, 'x' }, out[16]; DWORD n = 16, fg = 99, sk = 99;
    SET_ERR(0);
    CHECK(fa((LPCSTR)in, 7, CRYPT_STRING_BINARY, out, &n, &sk, &fg));
    EXPECT_EQ(n, 7); CHECK(!memcmp(out, in, 7)); EXPECT_EQ(sk, 0); EXPECT_EQ(fg, CRYPT_STRING_BINARY);
}
TEST(sf_s2b_binary_size_query) {
    REQ_S2B(); BYTE in[] = { 5, 6, 7 }; DWORD n = 0xdead;
    CHECK(fa((LPCSTR)in, 3, CRYPT_STRING_BINARY, NULL, &n, NULL, NULL)); EXPECT_EQ(n, 3);
}
TEST(sf_s2b_binary_short_buffer) {
    REQ_S2B(); BYTE in[] = { 5, 6, 7 }, out[4]; DWORD n = 2; SET_ERR(0);
    CHECK(!fa((LPCSTR)in, 3, CRYPT_STRING_BINARY, out, &n, NULL, NULL)); EXPECT_ERR(ERROR_MORE_DATA);
}
TEST(sf_s2b_binary_cch_zero_uses_strlen) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    CHECK(fa("hello", 0, CRYPT_STRING_BINARY, out, &n, NULL, NULL)); EXPECT_EQ(n, 5); CHECK(!memcmp(out, "hello", 5));
}
TEST(sf_s2b_binary_ignores_cch_nul) {
    REQ_S2B(); BYTE out[16]; DWORD n = 16;
    CHECK(fa("ab\0cd", 5, CRYPT_STRING_BINARY, out, &n, NULL, NULL)); EXPECT_EQ(n, 5); CHECK(!memcmp(out, "ab\0cd", 5));
}

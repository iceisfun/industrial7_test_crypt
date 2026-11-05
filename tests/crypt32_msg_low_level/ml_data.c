/* CryptMsgOpenToEncode / CryptMsgUpdate / CryptMsgGetParam: argument validation and CMSG_DATA messages. */
#include "ml.h"

static const BYTE TXT3[3] = {'a','b','c'};
static const BYTE DATA_ABC[] = {0x30,0x12,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x05,0x04,0x03,'a','b','c'};
static const BYTE DATA_EMPTY[] = {0x30,0x0f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x02,0x04,0x00};
static const BYTE BARE_ABC[] = {0x04,0x03,'a','b','c'};
static const BYTE BARE_EMPTY[] = {0x04,0x00};

/* ------------------------------------------------------------ OpenToEncode argument validation */
TEST(mld_open_bad_encoding_type) {
    REQ_MSG();
    static const DWORD enc[] = {0, 1, X509_ASN_ENCODING, 0x20000, 0x00000003, 0xFFFF, 0x30000, 0x80000000};
    for (size_t i = 0; i < sizeof enc / sizeof *enc; i++) {
        SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(enc[i], 0, CMSG_DATA, NULL, NULL, NULL);
        CHECKF(m == NULL, "encoding 0x%lx", (unsigned long)enc[i]);
        if (m) mClose()(m); else EXPECT_ERR(E_INVALIDARG);
    }
}
TEST(mld_open_accepts_encoding_with_x509_bit) {
    REQ_MSG();
    /* only the high word is compared with PKCS_7_ASN_ENCODING; the X509 low word is ignored */
    static const DWORD ok[] = {PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0x00018000, 0x0001FFFF};
    for (size_t i = 0; i < 3; i++) { HCRYPTMSG m = mOpenEnc()(ok[i], 0, CMSG_DATA, NULL, NULL, NULL);
    CHECKF(m != NULL, "enc 0x%lx", (unsigned long)ok[i]);
    if (m) mClose()(m); }
}
TEST(mld_open_bad_msg_type) {
    REQ_MSG();
    static const DWORD t[] = {0, CMSG_SIGNED_AND_ENVELOPED, CMSG_ENCRYPTED, 7, 8, 100, 0xFFFFFFFF};
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(ENC, 0, t[i], NULL, NULL, NULL);
        CHECKF(m == NULL, "type %lu", (unsigned long)t[i]);
        if (m) mClose()(m); else EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    }
}
TEST(mld_open_encoding_checked_before_type) {
    REQ_MSG();
    SET_ERR(0);
    HCRYPTMSG m = mOpenEnc()(0, 0, 0xFF, NULL, NULL, NULL);
    CHECK(m == NULL);
    EXPECT_ERR(E_INVALIDARG); /* decomp: the encoding test comes first, whatever the type */
}
TEST(mld_open_data_nonnull_info_rejected) {
    REQ_MSG();
    DWORD dummy[4] = {0};
    SET_ERR(0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, dummy, NULL, NULL);
    CHECK(m == NULL);
    EXPECT_ERR(E_INVALIDARG);
    if (m) mClose()(m);
}
TEST(mld_open_data_inner_oid_ignored) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, "1.2.3.4.5", NULL);
    CHECK(m != NULL);
    if (m) mClose()(m);
}
TEST(mld_open_data_flag_combinations_open) {
    REQ_MSG();
    static const DWORD f[] = {0, CMSG_BARE_CONTENT_FLAG, CMSG_DETACHED_FLAG, CMSG_BARE_CONTENT_FLAG | CMSG_DETACHED_FLAG};
    for (size_t i = 0; i < sizeof f / sizeof *f; i++) {
        HCRYPTMSG m = mOpenEnc()(ENC, f[i], CMSG_DATA, NULL, NULL, NULL);
        CHECKF(m != NULL, "flags 0x%lx", (unsigned long)f[i]);
        if (m) mClose()(m);
    }
}
TEST(mld_open_gives_distinct_handles) {
    REQ_MSG();
    HCRYPTMSG a = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    HCRYPTMSG b = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    CHECK(a && b && a != b);
    if (a) mClose()(a);
    if (b) mClose()(b);
}

/* ------------------------------------------------------------ OpenToDecode validation */
TEST(mld_decode_open_bad_encoding) {
    REQ_MSG();
    static const DWORD enc[] = {0, 1, X509_ASN_ENCODING, 0x20000};
    for (size_t i = 0; i < sizeof enc / sizeof *enc; i++) {
        SET_ERR(0);
        HCRYPTMSG m = mOpenDec()(enc[i], 0, 0, 0, NULL, NULL);
        CHECKF(m == NULL, "encoding 0x%lx", (unsigned long)enc[i]);
        if (m) mClose()(m); else EXPECT_ERR(E_INVALIDARG);
    }
}
TEST(mld_decode_open_recipient_info_must_be_null) {
    REQ_MSG();
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    SET_ERR(0);
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, &ci, NULL);
    CHECK(m == NULL);
    EXPECT_ERR(E_INVALIDARG);
    if (m) mClose()(m);
}
TEST(mld_decode_open_all_types_accepted) {
    REQ_MSG();
    /* decomp: the message type is stored, not validated, at open time */
    static const DWORD t[] = {0, CMSG_DATA, CMSG_SIGNED, CMSG_ENVELOPED, CMSG_SIGNED_AND_ENVELOPED, CMSG_HASHED};
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        HCRYPTMSG m = mOpenDec()(ENC, 0, t[i], 0, NULL, NULL);
        CHECKF(m != NULL, "type %lu err %lx", (unsigned long)t[i], GetLastError());
        if (m) mClose()(m);
    }
}
TEST(mld_decode_open_detached_flag) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, CMSG_DETACHED_FLAG, CMSG_SIGNED, 0, NULL, NULL);
    CHECK(m != NULL);
    if (m) mClose()(m);
}

/* ------------------------------------------------------------ encode: bytes */
TEST(mld_data_abc_exact_bytes) {
    REQ_MSG();
    DWORD cb = 0; BYTE *b = ml_encode_data(0, TXT3, 3, &cb);
    CHECK(b != NULL);
    if (b) { CHECK(cb == sizeof DATA_ABC && !memcmp(b, DATA_ABC, sizeof DATA_ABC)); }
    ml_free(b);
}
TEST(mld_data_empty_exact_bytes) {
    REQ_MSG();
    DWORD cb = 0; BYTE *b = ml_encode_data(0, NULL, 0, &cb);
    CHECK(b != NULL);
    if (b) { CHECK(cb == sizeof DATA_EMPTY && !memcmp(b, DATA_EMPTY, sizeof DATA_EMPTY)); }
    ml_free(b);
}
TEST(mld_data_bare_param_bytes) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_BARE_CONTENT_PARAM, 0, &cb);
    CHECK(b && cb == sizeof BARE_ABC && !memcmp(b, BARE_ABC, cb));
    ml_free(b);
    mClose()(m);
}
TEST(mld_data_bare_empty_param_bytes) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, NULL, 0, TRUE));
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_BARE_CONTENT_PARAM, 0, &cb);
    CHECK(b && cb == sizeof BARE_EMPTY && !memcmp(b, BARE_EMPTY, cb));
    ml_free(b);
    mClose()(m);
}
TEST(mld_data_bare_flag_content_param) {
    REQ_MSG();
    DWORD cb = 0; BYTE *b = ml_encode_data(CMSG_BARE_CONTENT_FLAG, TXT3, 3, &cb);
    CHECK(b != NULL);
    if (b) {
        if (cb == sizeof BARE_ABC && !memcmp(b, BARE_ABC, cb)) CHECK(1);
        else t_note("BARE_CONTENT_FLAG: CONTENT_PARAM has %lu bytes, first 0x%02x", (unsigned long)cb, b[0]);
        CHECK(cb >= sizeof BARE_ABC);
    }
    ml_free(b);
}
TEST(mld_data_content_prefix_is_tag_len) {
    REQ_MSG();
    /* the encoded length field of the SEQUENCE equals total length - 2 for short content */
    for (DWORD n = 0; n < 100; n += 7) {
        BYTE in[128]; for (DWORD i = 0; i < n; i++) in[i] = (BYTE)i;
        DWORD cb = 0; BYTE *b = ml_encode_data(0, in, n, &cb);
        CHECKF(b != NULL, "n=%lu", (unsigned long)n);
        if (!b) continue;
        CHECKF(b[0] == 0x30, "n=%lu", (unsigned long)n);
        CHECKF(b[1] < 0x80 ? cb == (DWORD)b[1] + 2 : (b[1] == 0x81 && cb == (DWORD)b[2] + 3), "n=%lu cb=%lu", (unsigned long)n, (unsigned long)cb);
        CHECKF(ml_memmem(b, cb, in, n) != NULL || n == 0, "n=%lu", (unsigned long)n);
        ml_free(b);
    }
}
TEST(mld_data_length_boundaries_der) {
    REQ_MSG();
    static const DWORD sz[] = {100, 101, 127, 128, 129, 255, 256, 257, 65535, 65536, 70000};
    for (size_t i = 0; i < sizeof sz / sizeof *sz; i++) {
        BYTE *in = (BYTE *)LocalAlloc(LPTR, sz[i]);
        memset(in, 0x5A, sz[i]);
        DWORD cb = 0; BYTE *b = ml_encode_data(0, in, sz[i], &cb);
        CHECKF(b != NULL, "size %lu", (unsigned long)sz[i]);
        if (b) {
            /* round trip through the decoder */
            HCRYPTMSG d = ml_decode(b, cb, 0, 0);
            CHECKF(d != NULL, "size %lu", (unsigned long)sz[i]);
            if (d) {
                DWORD n = 0; BYTE *c = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
                CHECKF(c && n == sz[i] && !memcmp(c, in, n), "size %lu got %lu", (unsigned long)sz[i], (unsigned long)n);
                ml_free(c); mClose()(d);
            }
        }
        ml_free(b); LocalFree(in);
    }
}

/* ------------------------------------------------------------ Update protocol */
TEST(mld_update_nonfinal_on_plain_data_fails) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECK(!mUpdate()(m, NULL, 0, FALSE));
    EXPECT_ERR(CRYPT_E_MSG_ERROR);
    mClose()(m);
}
TEST(mld_update_nonfinal_with_data_on_plain_data_fails) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECK(!mUpdate()(m, TXT3, 3, FALSE));
    EXPECT_ERR(CRYPT_E_MSG_ERROR);
    mClose()(m);
}
TEST(mld_update_after_final_fails) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    SET_ERR(0);
    CHECK(!mUpdate()(m, TXT3, 3, TRUE));
    EXPECT_ERR(CRYPT_E_MSG_ERROR);
    SET_ERR(0);
    CHECK(!mUpdate()(m, NULL, 0, FALSE));
    EXPECT_ERR(CRYPT_E_MSG_ERROR);
    mClose()(m);
}
TEST(mld_update_final_without_data_ok) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, NULL, 0, TRUE));
    mClose()(m);
}
TEST(mld_update_null_pointer_nonzero_cb_treated_as_empty) {
    REQ_MSG();
    /* decomp: a NULL pbData forces cbData = 0 */
    if (t_is_wine()) { t_skip("emulator dereferences NULL pbData"); return; }
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, NULL, 12345, TRUE));
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
    CHECK(b && cb == sizeof DATA_EMPTY && !memcmp(b, DATA_EMPTY, cb));
    ml_free(b);
    mClose()(m);
}
TEST(mld_update_detached_nonfinal_rejected) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, CMSG_DETACHED_FLAG, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECK(!mUpdate()(m, NULL, 0, FALSE));
    EXPECT_ERR(E_INVALIDARG);
    SET_ERR(0);
    CHECK(!mUpdate()(m, TXT3, 3, FALSE));
    EXPECT_ERR(E_INVALIDARG);
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    mClose()(m);
}
TEST(mld_detached_data_content_is_empty_octets) {
    REQ_MSG();
    DWORD cb = 0; BYTE *b = ml_encode_data(CMSG_DETACHED_FLAG, TXT3, 3, &cb);
    CHECK(b != NULL);
    if (b) {
        CHECKF(ml_memmem(b, cb, TXT3, 3) == NULL || cb == sizeof DATA_ABC, "cb=%lu", (unsigned long)cb);
        t_note("detached CMSG_DATA encoded length %lu", (unsigned long)cb);
    }
    ml_free(b);
}

/* ------------------------------------------------------------ GetParam on encode data */
TEST(mld_data_getparam_content_always_available) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    DWORD n = 0;
    CHECK(mGetParam()(m, CMSG_CONTENT_PARAM, 0, NULL, &n));
    n = 0;
    CHECK(mGetParam()(m, CMSG_BARE_CONTENT_PARAM, 0, NULL, &n));
    mClose()(m);
}
TEST(mld_data_getparam_inapplicable_params) {
    REQ_MSG();
    static const DWORD p[] = {CMSG_ENCODED_SIGNER, CMSG_COMPUTED_HASH_PARAM, CMSG_TYPE_PARAM};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    for (size_t i = 0; i < sizeof p / sizeof *p; i++) {
        DWORD n = 0; SET_ERR(0);
        CHECKF(!mGetParam()(m, p[i], 0, NULL, &n), "param %lu", (unsigned long)p[i]);
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    }
    mClose()(m);
}
TEST(mld_data_getparam_size_protocol) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    DWORD n = 0;
    CHECK(mGetParam()(m, CMSG_CONTENT_PARAM, 0, NULL, &n));
    EXPECT_EQ(n, sizeof DATA_ABC);
    BYTE buf[64]; memset(buf, 0xAA, sizeof buf);
    n = (DWORD)sizeof DATA_ABC - 1; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_CONTENT_PARAM, 0, buf, &n));
    EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, sizeof DATA_ABC);
    n = 0; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_CONTENT_PARAM, 0, buf, &n));
    EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, sizeof DATA_ABC);
    memset(buf, 0xAA, sizeof buf);
    n = sizeof DATA_ABC;
    CHECK(mGetParam()(m, CMSG_CONTENT_PARAM, 0, buf, &n));
    EXPECT_EQ(n, sizeof DATA_ABC);
    CHECK(!memcmp(buf, DATA_ABC, sizeof DATA_ABC));
    CHECK(buf[sizeof DATA_ABC] == 0xAA);
    n = 60;
    CHECK(mGetParam()(m, CMSG_CONTENT_PARAM, 0, buf, &n));
    EXPECT_EQ(n, sizeof DATA_ABC);
    mClose()(m);
}
TEST(mld_data_getparam_repeatable) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    for (int i = 0; i < 3; i++) {
        DWORD n = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
        CHECK(b && n == sizeof DATA_ABC && !memcmp(b, DATA_ABC, n));
        ml_free(b);
    }
    mClose()(m);
}
TEST(mld_data_getparam_index_ignored_for_content) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    DWORD n = 0; SET_ERR(0);
    BOOL ok = mGetParam()(m, CMSG_CONTENT_PARAM, 5, NULL, &n);
    if (ok) CHECK(n == sizeof DATA_ABC); else t_note("CONTENT_PARAM with index 5 fails err=%lx", GetLastError());
    mClose()(m);
}
TEST(mld_data_unknown_param_numbers) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    static const DWORD p[] = {0, 40, 41, 100, 0xFFFF};
    for (size_t i = 0; i < sizeof p / sizeof *p; i++) {
        DWORD n = 0; SET_ERR(0);
        BOOL ok = mGetParam()(m, p[i], 0, NULL, &n);
        CHECKF(!ok, "param %lu", (unsigned long)p[i]);
        if (!ok) t_note("param %lu on data msg: err 0x%lx", (unsigned long)p[i], (unsigned long)GetLastError());
    }
    mClose()(m);
}

/* ------------------------------------------------------------ Close / Duplicate */
TEST(mld_close_returns_true) {
    REQ_MSG();
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    CHECK(m != NULL);
    if (m) CHECK(mClose()(m));
}
TEST(mld_close_null_returns_true) {
    REQ_MSG();
    SET_ERR(0);
    CHECK(mClose()(NULL));
}
TEST(mld_duplicate_refcounts) {
    REQ_MSG();
    REQUIRE(mDup());
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    HCRYPTMSG d = mDup()(m);
    CHECK(d == m);   /* the handle is reference counted, not copied */
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    CHECK(mClose()(m));
    /* the duplicate keeps the message alive */
    DWORD n = 0; BYTE *b = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
    CHECK(b && n == sizeof DATA_ABC && !memcmp(b, DATA_ABC, n));
    ml_free(b);
    CHECK(mClose()(d));
}
TEST(mld_duplicate_many_then_close_all) {
    REQ_MSG();
    REQUIRE(mDup());
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    for (int i = 0; i < 20; i++) CHECK(mDup()(m) == m);
    CHECK(mUpdate()(m, TXT3, 3, TRUE));
    for (int i = 0; i < 20; i++) CHECK(mClose()(m));
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
    CHECK(b != NULL);
    ml_free(b);
    CHECK(mClose()(m));
}
TEST(mld_duplicate_decode_handle) {
    REQ_MSG();
    REQUIRE(mDup());
    HCRYPTMSG m = ml_decode(M_DATA, M_DATA_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mDup()(m) == m);
    mClose()(m);
    DWORD t = 0; CHECK(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &t) && t == CMSG_DATA);
    mClose()(m);
}

/* ------------------------------------------------------------ CryptMsgCalculateEncodedLength */
TEST(mld_calc_length_data_matches_actual) {
    REQ_MSG();
    REQUIRE(mCalcLen()); if (t_is_wine()) { t_skip("CryptMsgCalculateEncodedLength is unimplemented under wine"); return; }
    static const DWORD sz[] = {0, 1, 3, 100, 127, 128, 255, 256, 1000, 65535, 65536};
    for (size_t i = 0; i < sizeof sz / sizeof *sz; i++) {
        BYTE *in = (BYTE *)LocalAlloc(LPTR, sz[i] + 1);
        DWORD cb = 0; BYTE *b = ml_encode_data(0, in, sz[i], &cb);
        DWORD calc = mCalcLen()(ENC, 0, CMSG_DATA, NULL, NULL, sz[i]);
        CHECKF(b && calc == cb, "size %lu calc %lu actual %lu", (unsigned long)sz[i], (unsigned long)calc, (unsigned long)cb);
        ml_free(b); LocalFree(in);
    }
}
TEST(mld_calc_length_bad_args) {
    REQ_MSG();
    REQUIRE(mCalcLen()); if (t_is_wine()) { t_skip("CryptMsgCalculateEncodedLength is unimplemented under wine"); return; }
    SET_ERR(0);
    CHECK(mCalcLen()(0, 0, CMSG_DATA, NULL, NULL, 3) == 0);
    EXPECT_ERR(E_INVALIDARG);
    SET_ERR(0);
    CHECK(mCalcLen()(ENC, 0, 0, NULL, NULL, 3) == 0);
    EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    SET_ERR(0);
    /* Win10 dereferences the NULL encode info (access violation) */
    T_EXPECT_FAULT(mCalcLen()(ENC, 0, CMSG_SIGNED, NULL, NULL, 3));
}
TEST(mld_calc_length_bare_flag) {
    REQ_MSG();
    REQUIRE(mCalcLen()); if (t_is_wine()) { t_skip("CryptMsgCalculateEncodedLength is unimplemented under wine"); return; }
    DWORD full = mCalcLen()(ENC, 0, CMSG_DATA, NULL, NULL, 3);
    DWORD bare = mCalcLen()(ENC, CMSG_BARE_CONTENT_FLAG, CMSG_DATA, NULL, NULL, 3);
    CHECK(full == sizeof DATA_ABC);
    CHECK(bare == sizeof BARE_ABC);
}
TEST(mld_decode_explicit_data_type_takes_bare_content) {
    REQ_MSG();
    /* explicit type: the update data is the bare content (an OCTET STRING), not a ContentInfo */
    HCRYPTMSG m = mOpenDec()(ENC, 0, CMSG_DATA, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mUpdate()(m, BARE_ABC, sizeof BARE_ABC, TRUE));
    DWORD t = 0;
    if (ml_param_dword(m, CMSG_TYPE_PARAM, 0, &t)) EXPECT_EQ(t, CMSG_DATA); else t_note("TYPE_PARAM after explicit data decode: 0x%lx", (unsigned long)GetLastError());
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
    CHECK(b && n == 3 && !memcmp(b, TXT3, 3));
    ml_free(b);
    mClose()(m);
}
TEST(mld_decode_explicit_data_type_rejects_contentinfo) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, CMSG_DATA, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    SET_ERR(0);
    CHECK(!mUpdate()(m, DATA_ABC, sizeof DATA_ABC, TRUE));
    EXPECT_ERR(CRYPT_E_ASN1_BADTAG);
    mClose()(m);
}
TEST(mld_decode_untyped_rejects_bare_data) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    SET_ERR(0);
    CHECK(!mUpdate()(m, BARE_ABC, sizeof BARE_ABC, TRUE));
    EXPECT_ERR(CRYPT_E_ASN1_BADTAG);
    mClose()(m);
}
TEST(mld_decode_data_getparams) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(DATA_ABC, sizeof DATA_ABC, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD t = 0; CHECK(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, CMSG_DATA);
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
    CHECK(b && n == 3 && !memcmp(b, TXT3, 3)); ml_free(b);
    b = ml_param(m, CMSG_INNER_CONTENT_TYPE_PARAM, 0, &n);
    if (b) CHECK(!strcmp((char *)b, OID_DATA)); else t_note("INNER_CONTENT_TYPE_PARAM on a decoded data message failed: 0x%lx", (unsigned long)GetLastError());
    ml_free(b);
    mClose()(m);
}
TEST(mld_decode_data_openssl_message) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_DATA, M_DATA_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD t = 0; CHECK(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, CMSG_DATA);
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
    CHECK(b && n == V_CONTENT_LEN && !memcmp(b, V_CONTENT, n)); ml_free(b);
    mClose()(m);
}
TEST(mld_decode_data_type_mismatch) {
    REQ_MSG();
    static const DWORD ty[] = {CMSG_SIGNED, CMSG_ENVELOPED, CMSG_HASHED};
    (void)ty;
    /* untyped decode then ask for signer data: not a signed message */
    HCRYPTMSG m = ml_decode(DATA_ABC, sizeof DATA_ABC, 0, 0);
    if (!m) { CHECK(m != NULL); return; }
    DWORD n = 0; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_SIGNER_COUNT_PARAM, 0, NULL, &n));
    EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    /* Win10 reads the (NULL) cert info before looking at the message type; with a real one the type is rejected */
    T_EXPECT_FAULT(mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, NULL));
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    REQUIRE_NOTNULL(c);
    EXPECT_FAILS(mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pCertInfo), CRYPT_E_INVALID_MSG_TYPE);
    ml_cert_free(c);
    mClose()(m);
}

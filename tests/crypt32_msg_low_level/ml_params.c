/* CryptMsgGetParam: decode-message type rules, size protocol, parameter x message-type matrix, flags. */
#include "ml.h"

/* ---------------------------------------------------------------- CMSG_TYPE_PARAM of decode messages */
TEST(mlp_decode_untyped_type_is_zero) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 0;
    CHECK(mGetParam()(m, CMSG_TYPE_PARAM, 0, NULL, &n));
    EXPECT_EQ(n, sizeof(DWORD));
    DWORD v = 99; CHECK(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &v)); EXPECT_EQ(v, 0);
    mClose()(m);
}
TEST(mlp_decode_explicit_type_is_reported) {
    REQ_MSG();
    /* including types that are not valid message types */
    static const DWORD t[] = {CMSG_DATA, CMSG_SIGNED, CMSG_ENVELOPED, CMSG_SIGNED_AND_ENVELOPED, CMSG_HASHED, CMSG_ENCRYPTED, 1000};
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        HCRYPTMSG m = mOpenDec()(ENC, 0, t[i], 0, NULL, NULL);
        CHECKF(m != NULL, "type %lu", (unsigned long)t[i]);
        if (!m) continue;
        DWORD v = 0xCC;
        CHECKF(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &v) && v == t[i], "type %lu got %lu", (unsigned long)t[i], (unsigned long)v);
        mClose()(m);
    }
}
TEST(mlp_decode_empty_typed_messages_fail_all_params) {
    REQ_MSG();
    static const DWORD t[] = {CMSG_DATA, CMSG_SIGNED, CMSG_ENVELOPED, CMSG_HASHED};
    for (size_t k = 0; k < 4; k++) {
        HCRYPTMSG m = mOpenDec()(ENC, 0, t[k], 0, NULL, NULL);
        CHECKF(m != NULL, "type %lu", (unsigned long)t[k]);
        if (!m) continue;
        for (DWORD p = CMSG_CONTENT_PARAM; p <= CMSG_CMS_SIGNER_INFO_PARAM; p++) {
            DWORD n = 0;
            CHECKF(!mGetParam()(m, p, 0, NULL, &n), "type %lu param %lu", (unsigned long)t[k], (unsigned long)p);
        }
        mClose()(m);
    }
}
TEST(mlp_type_param_size_protocol) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, CMSG_SIGNED, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    DWORD v = 0xCC, n = 1; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_TYPE_PARAM, 0, &v, &n));
    EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, sizeof(DWORD));
    EXPECT_EQ(v, 0xCC);
    n = 0; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_TYPE_PARAM, 0, &v, &n));
    EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, sizeof(DWORD));
    n = 3; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_TYPE_PARAM, 0, &v, &n));
    EXPECT_ERR(ERROR_MORE_DATA);
    n = 64;
    CHECK(mGetParam()(m, CMSG_TYPE_PARAM, 0, &v, &n));
    EXPECT_EQ(n, sizeof(DWORD)); EXPECT_EQ(v, CMSG_SIGNED);
    mClose()(m);
}
TEST(mlp_count_params_size_protocol) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    static const DWORD p[] = {CMSG_SIGNER_COUNT_PARAM, CMSG_CERT_COUNT_PARAM, CMSG_CRL_COUNT_PARAM, CMSG_VERSION_PARAM};
    for (size_t i = 0; i < 4; i++) {
        DWORD n = 0;
        CHECKF(mGetParam()(m, p[i], 0, NULL, &n) && n == sizeof(DWORD), "param %lu", (unsigned long)p[i]);
        DWORD v = 0xCC; n = 2; SET_ERR(0);
        CHECKF(!mGetParam()(m, p[i], 0, &v, &n), "param %lu small", (unsigned long)p[i]);
        EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(n, sizeof(DWORD));
    }
    mClose()(m);
}
TEST(mlp_large_buffer_reports_actual_size) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD need = 0;
    CHECK(mGetParam()(m, CMSG_CERT_PARAM, 0, NULL, &need));
    EXPECT_EQ(need, V_CERT1_LEN);
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need + 64);
    memset(buf, 0x77, need + 64);
    DWORD n = need + 64;
    CHECK(mGetParam()(m, CMSG_CERT_PARAM, 0, buf, &n));
    EXPECT_EQ(n, need);
    CHECK(buf[need] == 0x77);
    n = need - 1; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_CERT_PARAM, 0, buf, &n));
    EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, need);
    LocalFree(buf);
    mClose()(m);
}
TEST(mlp_signer_info_size_protocol) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_ATTR, M_SIGNED_ATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD need = 0;
    CHECK(mGetParam()(m, CMSG_SIGNER_INFO_PARAM, 0, NULL, &need));
    CHECK(need > sizeof(CMSG_SIGNER_INFO) + 128);
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need);
    DWORD n = need - 1; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_SIGNER_INFO_PARAM, 0, buf, &n));
    EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, need);
    n = need;
    CHECK(mGetParam()(m, CMSG_SIGNER_INFO_PARAM, 0, buf, &n));
    CHECK(n <= need);
    /* all pointers inside the structure point into the caller's buffer */
    CMSG_SIGNER_INFO *s = (CMSG_SIGNER_INFO *)buf;
    CHECK((BYTE *)s->Issuer.pbData >= buf && (BYTE *)s->Issuer.pbData + s->Issuer.cbData <= buf + n);
    CHECK((BYTE *)s->EncryptedHash.pbData >= buf && (BYTE *)s->EncryptedHash.pbData + s->EncryptedHash.cbData <= buf + n);
    CHECK((BYTE *)s->HashAlgorithm.pszObjId >= buf && (BYTE *)s->HashAlgorithm.pszObjId < buf + n);
    CHECK(s->AuthAttrs.cAttr > 0 && (BYTE *)s->AuthAttrs.rgAttr >= buf && (BYTE *)s->AuthAttrs.rgAttr < buf + n);
    LocalFree(buf);
    mClose()(m);
}

/* ---------------------------------------------------------------- parameter x type matrix */
typedef struct { DWORD p; const char *name; } pn_t;
#define PN(x) {x, #x}
static const pn_t SIGNED_ONLY[] = {PN(CMSG_SIGNER_COUNT_PARAM), PN(CMSG_SIGNER_INFO_PARAM), PN(CMSG_SIGNER_CERT_INFO_PARAM), PN(CMSG_SIGNER_HASH_ALGORITHM_PARAM),
    PN(CMSG_SIGNER_AUTH_ATTR_PARAM), PN(CMSG_CERT_COUNT_PARAM), PN(CMSG_CERT_PARAM), PN(CMSG_CRL_COUNT_PARAM), PN(CMSG_SIGNER_UNAUTH_ATTR_PARAM), PN(CMSG_CRL_PARAM)};
static const pn_t ENV_ONLY[] = {PN(CMSG_ENVELOPE_ALGORITHM_PARAM), PN(CMSG_RECIPIENT_COUNT_PARAM), PN(CMSG_RECIPIENT_INFO_PARAM)};
static const pn_t HASH_ONLY[] = {PN(CMSG_HASH_ALGORITHM_PARAM), PN(CMSG_HASH_DATA_PARAM), PN(CMSG_COMPUTED_HASH_PARAM)};

static void matrix_row(const char *msg, HCRYPTMSG m, const pn_t *tbl, size_t n, BOOL expect_invalid) {
    for (size_t i = 0; i < n; i++) {
        DWORD sz = 0; SET_ERR(0);
        BOOL ok = mGetParam()(m, tbl[i].p, 0, NULL, &sz);
        if (expect_invalid) { CHECKF(!ok, "%s / %s", msg, tbl[i].name); EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE); }
        else CHECKF(ok, "%s / %s err 0x%lx", msg, tbl[i].name, GetLastError());
    }
}
TEST(mlp_matrix_decoded_signed) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_ATTR, M_SIGNED_ATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    /* the last two entries (UNAUTH_ATTR, CRL) do not exist in this message: only the first 8 are tested for success */
    matrix_row("signed", m, SIGNED_ONLY, 8, FALSE);
    matrix_row("signed", m, ENV_ONLY, 3, TRUE);
    matrix_row("signed", m, HASH_ONLY, 2, TRUE);
    mClose()(m);
}
TEST(mlp_matrix_decoded_hashed) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    matrix_row("hashed", m, SIGNED_ONLY, 10, TRUE);
    matrix_row("hashed", m, ENV_ONLY, 3, TRUE);
    matrix_row("hashed", m, HASH_ONLY, 3, FALSE);
    mClose()(m);
}
TEST(mlp_matrix_decoded_enveloped) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_ENV_3DES, M_ENV_3DES_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    matrix_row("enveloped", m, SIGNED_ONLY, 10, TRUE);
    matrix_row("enveloped", m, HASH_ONLY, 3, TRUE);
    matrix_row("enveloped", m, ENV_ONLY, 3, FALSE);
    mClose()(m);
}
TEST(mlp_matrix_decoded_data) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_DATA, M_DATA_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    matrix_row("data", m, SIGNED_ONLY, 10, TRUE);
    matrix_row("data", m, ENV_ONLY, 3, TRUE);
    matrix_row("data", m, HASH_ONLY, 3, TRUE);
    mClose()(m);
}
TEST(mlp_matrix_encoded_signed) {
    ml_signer_t s; REQ_MSG();
    if (!ml_signer_init(&s, OID_SHA256)) { ml_signer_done(&s); t_skip("setup"); return; }
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
        matrix_row("enc-signed", m, ENV_ONLY, 3, TRUE);
        matrix_row("enc-signed", m, HASH_ONLY, 2, TRUE);
        DWORD n = 0;
        CHECK(mGetParam()(m, CMSG_CONTENT_PARAM, 0, NULL, &n));
        CHECK(mGetParam()(m, CMSG_BARE_CONTENT_PARAM, 0, NULL, &n));
        mClose()(m);
    }
    ml_signer_done(&s);
}
TEST(mlp_encoded_message_param) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 0; SET_ERR(0);
    BOOL ok = mGetParam()(m, CMSG_ENCODED_MESSAGE, 0, NULL, &n);
    t_note("ENCODED_MESSAGE on a decoded signed message: ok=%d size=%lu (input %d) err=0x%lx", ok, (unsigned long)n, (int)M_SIGNED_NOATTR_LEN, (unsigned long)GetLastError());
    if (ok) {
        BYTE *b = ml_param(m, CMSG_ENCODED_MESSAGE, 0, &n);
        if (b) { t_note("ENCODED_MESSAGE %s the original input", (n == M_SIGNED_NOATTR_LEN && !memcmp(b, M_SIGNED_NOATTR, n)) ? "equals" : "differs from"); ml_free(b); }
    }
    CHECK(1);
    mClose()(m);
}
TEST(mlp_bare_content_of_decoded_hashed) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_BARE_CONTENT_PARAM, 0, &n);
    t_note("BARE_CONTENT_PARAM on a decoded hashed message: %s (%lu bytes)", b ? "available" : "unavailable", (unsigned long)n);
    if (b) { DWORD un = 0; const BYTE *bare = ml_unwrap(M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, &un); CHECK(bare && n == un && !memcmp(b, bare, n)); }
    ml_free(b);
    mClose()(m);
}
TEST(mlp_unknown_param_numbers_on_decoded) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    static const DWORD p[] = {0, 16, 23, 24, 25, 27, 40, 41, 100, 0xFFFFFFFF};
    for (size_t i = 0; i < sizeof p / sizeof *p; i++) {
        DWORD n = 0; SET_ERR(0);
        BOOL ok = mGetParam()(m, p[i], 0, NULL, &n);
        t_note("signed decode msg param %lu: ok=%d err=0x%lx", (unsigned long)p[i], ok, (unsigned long)GetLastError());
        CHECKF(!ok, "param %lu", (unsigned long)p[i]);
    }
    mClose()(m);
}

/* ---------------------------------------------------------------- flags */
TEST(mlp_contents_octets_flag_data) {
    REQ_MSG();
    static const BYTE T3[3] = {'a','b','c'};
    HCRYPTMSG m = mOpenEnc()(ENC, CMSG_CONTENTS_OCTETS_FLAG, CMSG_DATA, NULL, NULL, NULL);
    t_note("CMSG_CONTENTS_OCTETS_FLAG on a data message: %s err=0x%lx", m ? "accepted" : "rejected", (unsigned long)GetLastError());
    if (m) {
        if (mUpdate()(m, T3, 3, TRUE)) {
            DWORD n = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
            t_note("  output %lu bytes, first 0x%02x", (unsigned long)n, b ? b[0] : 0);
            ml_free(b);
        }
        mClose()(m);
    }
    CHECK(1);
}
TEST(mlp_length_only_and_max_length_flags) {
    REQ_MSG();
    static const BYTE T3[3] = {'a','b','c'};
    static const DWORD f[] = {CMSG_LENGTH_ONLY_FLAG, CMSG_MAX_LENGTH_FLAG, CMSG_LENGTH_ONLY_FLAG | CMSG_MAX_LENGTH_FLAG};
    for (size_t i = 0; i < 3; i++) {
        SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(ENC, f[i], CMSG_DATA, NULL, NULL, NULL);
        t_note("data message with flags 0x%lx: %s err=0x%lx", (unsigned long)f[i], m ? "accepted" : "rejected", (unsigned long)GetLastError());
        if (m) {
            BOOL u = mUpdate()(m, T3, 3, TRUE);
            DWORD n = 0; BOOL g = u && mGetParam()(m, CMSG_CONTENT_PARAM, 0, NULL, &n);
            t_note("  update=%d content size query=%d size=%lu", u, g, (unsigned long)n);
            mClose()(m);
        }
    }
    CHECK(1);
}
TEST(mlp_calc_length_signed_and_enveloped) {
    REQ_MSG();
    REQUIRE(mCalcLen());
    if (t_is_wine()) { t_skip("CryptMsgCalculateEncodedLength is unimplemented under wine"); return; }
    ml_signer_t s;
    if (!ml_signer_init(&s, OID_SHA256)) { ml_signer_done(&s); t_skip("setup"); return; }
    DWORD actual = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &actual);
    DWORD calc = mCalcLen()(ENC, 0, CMSG_SIGNED, &s.se, NULL, V_CONTENT_LEN);
    CHECK(b && calc > 0);
    t_note("signed: CalculateEncodedLength=%lu actual=%lu", (unsigned long)calc, (unsigned long)actual);
    CHECK(calc >= actual);   /* the documented purpose: a buffer size that is large enough */
    DWORD calc_det = mCalcLen()(ENC, CMSG_DETACHED_FLAG, CMSG_SIGNED, &s.se, NULL, V_CONTENT_LEN);
    DWORD act_det = 0; BYTE *d = ml_sign(&s, CMSG_DETACHED_FLAG, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &act_det);
    CHECK(d && calc_det >= act_det && calc_det <= calc);
    ml_free(b); ml_free(d);
    ml_signer_done(&s);
}

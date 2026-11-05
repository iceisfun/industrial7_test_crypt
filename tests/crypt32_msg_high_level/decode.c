/* CryptDecodeMessage and CryptMsgGetParam on messages produced by the high-level APIs. */
#include "mh.h"
#include <stdlib.h>

#define PL v_payload, (DWORD)sizeof v_payload
#define DEC U(CryptDecodeMessage)

static const BYTE v_data_msg[] = { 0x30, 0x0b + 2 + 1 + 0, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01 };
/* data ContentInfo carrying the 4 octets "abcd":  SEQ{ OID data, [0]{ OCTET STRING } } */
static const BYTE v_data_ci[] = { 0x30, 0x13, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x06, 0x04, 0x04, 'a', 'b', 'c', 'd' };

/* Windows 10: an index past the last certificate or CRL fails without setting a last error (the recipient and signer
 * parameters, by contrast, report CRYPT_E_INVALID_INDEX). The sentinel proves the error is left untouched. */
#define GP_OUT_OF_RANGE(m, param, idx, buf, pn) do { \
    typeof(&CryptMsgGetParam) gp_ = U(CryptMsgGetParam); SET_ERR(0x5A5A); \
    BOOL r_ = gp_(m, param, idx, buf, pn); CHECKF(!r_, "param %d index %d past the end succeeded", (int)(param), (int)(idx)); EXPECT_ERR(0x5A5A); } while (0)

static BOOL dec_all(DWORD flags, const BYTE *b, DWORD n, DWORD prev, DWORD *mt, DWORD *it, BYTE *out, DWORD *pn, PCCERT_CONTEXT *x, PCCERT_CONTEXT *sc, int cb) {
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); CRYPT_VERIFY_MESSAGE_PARA vp;
    if (cb) mh_verify_para_cb(&vp); else mh_verify_para(&vp);
    return DEC(flags, &dp, &vp, 0, (BYTE *)b, n, prev, mt, it, out, pn, x, sc);
}

TEST(mh_decode_signed_message_type_and_content) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    DWORD mt = 99, it = 99, dn = 0; BYTE d[100]; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1, sc = NULL; SET_ERR(0);
    CHECKF(dec_all(CMSG_SIGNED_FLAG, v_m_sig_noattr, sizeof v_m_sig_noattr, 0, &mt, &it, NULL, &dn, NULL, NULL, 0), "size err 0x%lx", GetLastError());
    EXPECT_EQ(dn, sizeof v_payload); EXPECT_EQ(mt, CMSG_SIGNED); EXPECT_EQ(it, CMSG_DATA);
    mt = it = 99; dn = sizeof d;
    BOOL r = dec_all(CMSG_SIGNED_FLAG, v_m_sig_noattr, sizeof v_m_sig_noattr, 0, &mt, &it, d, &dn, &x, &sc, 0);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(mt, CMSG_SIGNED); EXPECT_EQ(it, CMSG_DATA); CHECK(dn == sizeof v_payload && !memcmp(d, v_payload, dn)); CHECK(CERT_IS(sc, v_s1_cert)); CHECK(x == NULL); }
    FREE_CERT(sc);
}
TEST(mh_decode_type_mask_mismatch_reports_actual_type) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    static const struct { const BYTE *p; DWORD n; DWORD type; DWORD wrongmask; } t[] = {
        { v_m_sig_noattr, sizeof v_m_sig_noattr, CMSG_SIGNED, CMSG_ENVELOPED_FLAG | CMSG_HASHED_FLAG | CMSG_DATA_FLAG },
        { v_m_env_aes128, sizeof v_m_env_aes128, CMSG_ENVELOPED, CMSG_SIGNED_FLAG | CMSG_HASHED_FLAG },
        { v_m_hashed_sha256, sizeof v_m_hashed_sha256, CMSG_HASHED, CMSG_SIGNED_FLAG | CMSG_ENVELOPED_FLAG | CMSG_DATA_FLAG },
        { v_data_ci, sizeof v_data_ci, CMSG_DATA, CMSG_SIGNED_FLAG | CMSG_ENVELOPED_FLAG | CMSG_HASHED_FLAG } };
    for (int i = 0; i < 4; i++) {
        DWORD mt = 99, it = 99, dn = 77; BYTE d[100]; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1, sc = (PCCERT_CONTEXT)1; SET_ERR(0);
        BOOL r = dec_all(t[i].wrongmask, t[i].p, t[i].n, 0, &mt, &it, d, &dn, &x, &sc, 1);
        CHECKF(r == FALSE, "msg %d", i);
        EXPECT_ERR(E_CRYPT_E_UNEXPECTED_MSG_TYPE);
        CHECKF(mt == t[i].type, "msg %d: reported type %lu", i, mt);
        EXPECT_EQ(it, 0); EXPECT_EQ(dn, 0); CHECK(x == NULL); CHECK(sc == NULL);
    }
}
TEST(mh_decode_message_type_flag_values) {
    MH_NOWINE();
    EXPECT_EQ(CMSG_DATA_FLAG, 2); EXPECT_EQ(CMSG_SIGNED_FLAG, 4); EXPECT_EQ(CMSG_ENVELOPED_FLAG, 8);
    EXPECT_EQ(CMSG_SIGNED_AND_ENVELOPED_FLAG, 0x10); EXPECT_EQ(CMSG_HASHED_FLAG, 0x20); EXPECT_EQ(CMSG_ENCRYPTED_FLAG, 0x40);
}
TEST(mh_decode_data_message) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    DWORD mt = 99, it = 99, dn = 0; BYTE d[16]; SET_ERR(0);
    /* a plain data ContentInfo decodes only when the caller does not ask for the inner content type */
    BOOL r = dec_all(CMSG_DATA_FLAG, v_data_ci, sizeof v_data_ci, 0, &mt, NULL, NULL, &dn, NULL, NULL, 0);
    CHECKF(r, "err 0x%lx", GetLastError()); EXPECT_EQ(dn, 4); EXPECT_EQ(mt, CMSG_DATA);
    dn = sizeof d; r = dec_all(CMSG_DATA_FLAG, v_data_ci, sizeof v_data_ci, 0, &mt, NULL, d, &dn, NULL, NULL, 0);
    CHECK(r); if (r) { EXPECT_EQ(dn, 4); CHECK(!memcmp(d, "abcd", 4)); }
    mt = it = 99; dn = 0; SET_ERR(0);
    r = dec_all(CMSG_DATA_FLAG, v_data_ci, sizeof v_data_ci, 0, &mt, &it, NULL, &dn, NULL, NULL, 0);
    EXPECT_FAIL(r == FALSE, 0x80091004u); EXPECT_EQ(mt, CMSG_DATA); EXPECT_EQ(it, 0); EXPECT_EQ(dn, 0);
}
TEST(mh_decode_mask_zero_and_all) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    DWORD mt = 99, dn = 100; BYTE d[100]; SET_ERR(0);
    BOOL r = dec_all(0, v_m_sig_noattr, sizeof v_m_sig_noattr, 0, &mt, NULL, d, &dn, NULL, NULL, 1);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE); EXPECT_EQ(mt, CMSG_SIGNED);
    static const BYTE *m[] = { v_m_sig_noattr, v_m_env_aes128, v_m_hashed_sha256 };
    static const DWORD n[] = { sizeof v_m_sig_noattr, sizeof v_m_env_aes128, sizeof v_m_hashed_sha256 };
    static const DWORD want[] = { CMSG_SIGNED, CMSG_ENVELOPED, CMSG_HASHED };
    for (int i = 0; i < 3; i++) {
        mt = 99; dn = sizeof d; PCCERT_CONTEXT x = NULL, sc = NULL; SET_ERR(0);
        r = dec_all(CMSG_ALL_FLAGS, m[i], n[i], 0, &mt, NULL, d, &dn, &x, &sc, 1);
        CHECKF(r, "msg %d err 0x%lx", i, GetLastError()); EXPECT_EQ(mt, want[i]);
        FREE_CERT(x); FREE_CERT(sc);
    }
}
TEST(mh_decode_hashed_message_is_not_verified) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    BYTE *b = malloc(sizeof v_m_hashed_sha256); memcpy(b, v_m_hashed_sha256, sizeof v_m_hashed_sha256);
    b[sizeof v_m_hashed_sha256 - 3] ^= 0x40;       /* corrupt the stored digest */
    DWORD mt = 0, dn = 100; BYTE d[100]; SET_ERR(0);
    BOOL r = dec_all(CMSG_HASHED_FLAG, b, sizeof v_m_hashed_sha256, 0, &mt, NULL, d, &dn, NULL, NULL, 0);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(mt, CMSG_HASHED); CHECK(dn == sizeof v_payload && !memcmp(d, v_payload, dn)); }
    free(b);
}
TEST(mh_decode_enveloped_requires_decrypt_para) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    DWORD mt = 99, dn = 100; BYTE d[100]; SET_ERR(0);
    BOOL r = DEC(CMSG_ENVELOPED_FLAG, NULL, &vp, 0, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128, 0, &mt, NULL, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    EXPECT_EQ(dn, 0);
}
TEST(mh_decode_signed_requires_verify_para) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp);
    DWORD mt = 99, dn = 100; BYTE d[100]; SET_ERR(0);
    BOOL r = DEC(CMSG_SIGNED_FLAG, &dp, NULL, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, 0, &mt, NULL, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    /* but a length-only query of a signed message needs neither parameter set to verify */
    dn = 0; SET_ERR(0);
    r = DEC(CMSG_SIGNED_FLAG, &dp, NULL, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, 0, &mt, NULL, NULL, &dn, NULL, NULL);
    CHECKF(r, "length-only err 0x%lx", GetLastError()); EXPECT_EQ(dn, sizeof v_payload);
}
TEST(mh_decode_both_para_null_is_invalid) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    DWORD mt = 99, it = 99, dn = 99; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1, sc = (PCCERT_CONTEXT)1; BYTE d[100]; SET_ERR(0);
    BOOL r = DEC(CMSG_ALL_FLAGS, NULL, NULL, 0, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, 0, &mt, &it, d, &dn, &x, &sc);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    EXPECT_EQ(mt, 0); EXPECT_EQ(it, 0); EXPECT_EQ(dn, 0); CHECK(x == NULL); CHECK(sc == NULL);   /* outputs are cleared before validation */
}
TEST(mh_decode_para_cbsize_checks) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    DWORD mt, dn; BYTE d[100];
    dp.cbSize = 0x17; dn = 100; SET_ERR(0);
    BOOL r = DEC(CMSG_ALL_FLAGS, &dp, &vp, 0, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, 0, &mt, NULL, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    mh_dec_para(&dp); vp.cbSize = 0x1f; dn = 100; SET_ERR(0);
    r = DEC(CMSG_ALL_FLAGS, &dp, &vp, 0, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, 0, &mt, NULL, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    /* a valid decrypt para alone is sufficient for message types that need neither */
    mh_dec_para(&dp); dn = 100;
    r = DEC(CMSG_HASHED_FLAG, &dp, NULL, 0, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, 0, &mt, NULL, d, &dn, NULL, NULL);
    CHECK(r);
    mh_verify_para(&vp); dn = 100;
    r = DEC(CMSG_HASHED_FLAG, NULL, &vp, 0, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, 0, &mt, NULL, d, &dn, NULL, NULL);
    CHECK(r);
}
TEST(mh_decode_encoding_type_taken_from_verify_para_first) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); dp.dwMsgAndCertEncodingType = 0;
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    DWORD mt = 0, dn = 100; BYTE d[100]; SET_ERR(0);
    BOOL r = DEC(CMSG_HASHED_FLAG, &dp, &vp, 0, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, 0, &mt, NULL, d, &dn, NULL, NULL);
    CHECKF(r, "err 0x%lx", GetLastError());
    vp.dwMsgAndCertEncodingType = 0; dp.dwMsgAndCertEncodingType = ENC; dn = 100; SET_ERR(0);
    r = DEC(CMSG_HASHED_FLAG, &dp, &vp, 0, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, 0, &mt, NULL, d, &dn, NULL, NULL);
    t_note("verify para encoding type 0 with a valid decrypt para -> %d err 0x%lx", r, GetLastError());
}
TEST(mh_decode_certs_only_message) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    DWORD mt = 0, dn = 100; BYTE d[100]; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = dec_all(CMSG_SIGNED_FLAG, v_m_certs_only, sizeof v_m_certs_only, 0, &mt, NULL, d, &dn, NULL, &sc, 0);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_SIGNER); EXPECT_EQ(mt, CMSG_SIGNED); CHECK(sc == NULL);
    dn = 99; SET_ERR(0);
    r = dec_all(CMSG_SIGNED_FLAG, v_m_certs_only, sizeof v_m_certs_only, 0, &mt, NULL, NULL, &dn, NULL, NULL, 0);
    CHECK(r); EXPECT_EQ(dn, 0);
}
TEST(mh_decode_signer_index) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    for (DWORD idx = 0; idx < 3; idx++) {
        DWORD mt = 0, dn = 100; BYTE d[100]; PCCERT_CONTEXT sc = NULL; SET_ERR(0);
        BOOL r = DEC(CMSG_SIGNED_FLAG, &dp, &vp, idx, (BYTE *)v_m_sig_two_noattr, sizeof v_m_sig_two_noattr, 0, &mt, NULL, d, &dn, NULL, &sc);
        if (idx < 2) { CHECKF(r, "idx %lu err 0x%lx", idx, GetLastError()); CHECK(idx == 0 ? CERT_IS(sc, v_s1_cert) : CERT_IS(sc, v_s2_cert)); }
        else { EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_SIGNER); CHECK(sc == NULL); }
        FREE_CERT(sc);
    }
}
TEST(mh_decode_bare_signed_content_with_prev_inner_type) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC); REQUIRE(U(CryptSignMessage));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG | 0, PL, &cb);
    CHECK(b != NULL); if (!b) return;
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    p.dwFlags = CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG; PCCERT_CONTEXT mc[1] = { mh_ids[MH_S1].pub }; p.cMsgCert = 1; p.rgpMsgCert = mc;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD n = 0;
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *bb = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, bb, &n));
    DWORD mt = 0, dn = 100; BYTE d[100]; PCCERT_CONTEXT sc = NULL; SET_ERR(0);
    BOOL r = dec_all(CMSG_SIGNED_FLAG, bb, n, CMSG_SIGNED, &mt, NULL, d, &dn, NULL, &sc, 0);
    CHECKF(r, "bare content + CMSG_SIGNED hint: err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(mt, CMSG_SIGNED); CHECK(dn == sizeof v_payload && !memcmp(d, v_payload, dn)); CHECK(CERT_IS(sc, v_s1_cert)); }
    FREE_CERT(sc);
    SET_ERR(0); dn = 100;
    r = dec_all(CMSG_SIGNED_FLAG, bb, n, 0, &mt, NULL, d, &dn, NULL, NULL, 0);
    CHECK(r == FALSE);   /* without the hint a bare SignedData is not a ContentInfo */
    free(bb); free(b);
}
TEST(mh_decode_bare_enveloped_content_with_prev_inner_type) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC); REQUIRE(U(CryptEncryptMessage));
    CRYPT_ENCRYPT_MESSAGE_PARA ep; mh_enc_para(&ep, "1.2.840.113549.3.7"); ep.dwFlags = CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG;
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub }; DWORD n = 0;
    CHECK(U(CryptEncryptMessage)(&ep, 1, rc, v_payload, sizeof v_payload, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptEncryptMessage)(&ep, 1, rc, v_payload, sizeof v_payload, b, &n));
    DWORD mt = 0, dn = 100; BYTE d[100]; PCCERT_CONTEXT x = NULL; SET_ERR(0);
    BOOL r = dec_all(CMSG_ENVELOPED_FLAG, b, n, CMSG_ENVELOPED, &mt, NULL, d, &dn, &x, NULL, 0);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(mt, CMSG_ENVELOPED); CHECK(dn == sizeof v_payload && !memcmp(d, v_payload, dn)); CHECK(CERT_IS(x, v_r1_cert)); }
    FREE_CERT(x); free(b);
}
TEST(mh_decode_prev_inner_type_one_is_ignored) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    DWORD mt = 0, dn = 100; BYTE d[100]; SET_ERR(0);
    BOOL r = dec_all(CMSG_HASHED_FLAG, v_m_hashed_sha256, sizeof v_m_hashed_sha256, CMSG_DATA, &mt, NULL, d, &dn, NULL, NULL, 0);
    CHECKF(r, "err 0x%lx", GetLastError()); EXPECT_EQ(mt, CMSG_HASHED);
}
TEST(mh_decode_content_size_protocol) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    DWORD mt = 0, dn = 0; BYTE d[100]; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = dec_all(CMSG_SIGNED_FLAG, v_m_sig_noattr, sizeof v_m_sig_noattr, 0, &mt, NULL, d, &dn, NULL, &sc, 0);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(dn, sizeof v_payload); CHECK(sc == NULL);
    dn = sizeof v_payload - 1; SET_ERR(0);
    r = dec_all(CMSG_SIGNED_FLAG, v_m_sig_noattr, sizeof v_m_sig_noattr, 0, &mt, NULL, d, &dn, NULL, &sc, 0);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(dn, sizeof v_payload);
}
TEST(mh_decode_no_content_outputs) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    DWORD mt = 0; SET_ERR(0);
    CHECK(dec_all(CMSG_SIGNED_FLAG, v_m_sig_noattr, sizeof v_m_sig_noattr, 0, &mt, NULL, NULL, NULL, NULL, NULL, 0));
    EXPECT_EQ(mt, CMSG_SIGNED);
    CHECK(dec_all(CMSG_ALL_FLAGS, v_m_sig_noattr, sizeof v_m_sig_noattr, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0));
    BYTE *b = malloc(sizeof v_m_sig_noattr); memcpy(b, v_m_sig_noattr, sizeof v_m_sig_noattr); b[sizeof v_m_sig_noattr - 4] ^= 1;
    CHECK(!dec_all(CMSG_ALL_FLAGS, b, sizeof v_m_sig_noattr, 0, &mt, NULL, NULL, NULL, NULL, NULL, 0));
    free(b);
}
TEST(mh_decode_garbage_clears_outputs) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC);
    static const BYTE g[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    DWORD mt = 99, it = 99, dn = 99; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1, sc = (PCCERT_CONTEXT)1; BYTE d[100]; SET_ERR(0);
    BOOL r = dec_all(CMSG_ALL_FLAGS, g, sizeof g, 0, &mt, &it, d, &dn, &x, &sc, 0);
    CHECK(r == FALSE); CHECK(GetLastError() != 0);
    EXPECT_EQ(mt, 0); EXPECT_EQ(it, 0); EXPECT_EQ(dn, 0); CHECK(x == NULL); CHECK(sc == NULL);
}
TEST(mh_decode_nested_sign_encrypt_layers) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DEC); REQUIRE(U(CryptSignAndEncryptMessage));
    CRYPT_SIGN_MESSAGE_PARA sp; mh_sign_para(&sp, MH_S1, OID_SHA256);
    PCCERT_CONTEXT mc[1] = { mh_ids[MH_S1].pub }; sp.cMsgCert = 1; sp.rgpMsgCert = mc;
    CRYPT_ENCRYPT_MESSAGE_PARA ep; mh_enc_para(&ep, "1.2.840.113549.3.7");
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub }; DWORD n = 0;
    CHECK(U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, b, &n));
    DWORD mt = 0, it = 0, dn = 0; BYTE inner[1000]; PCCERT_CONTEXT x = NULL; SET_ERR(0);
    dn = sizeof inner;
    BOOL r = dec_all(CMSG_ENVELOPED_FLAG, b, n, 0, &mt, &it, inner, &dn, &x, NULL, 0);
    CHECKF(r, "layer 1 err 0x%lx", GetLastError());
    if (r) {
        EXPECT_EQ(mt, CMSG_ENVELOPED); CHECK(CERT_IS(x, v_r1_cert));
        DWORD mt2 = 0, dn2 = 100; BYTE d[100]; PCCERT_CONTEXT sc = NULL;
        r = dec_all(CMSG_SIGNED_FLAG, inner, dn, it, &mt2, NULL, d, &dn2, NULL, &sc, 0);
        CHECKF(r, "layer 2 err 0x%lx (inner type %lu)", GetLastError(), it);
        if (r) { EXPECT_EQ(mt2, CMSG_SIGNED); CHECK(dn2 == sizeof v_payload && !memcmp(d, v_payload, dn2)); CHECK(CERT_IS(sc, v_s1_cert)); }
        FREE_CERT(sc);
    }
    FREE_CERT(x); free(b);
}

/* ---- CryptMsgGetParam on messages made by the high-level APIs -------------------------------------- */
static HCRYPTMSG open_msg(const BYTE *b, DWORD n) {
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL);
    if (m && !U(CryptMsgUpdate)(m, b, n, TRUE)) { U(CryptMsgClose)(m); return NULL; }
    return m;
}
static DWORD get_dword(HCRYPTMSG m, DWORD param, DWORD idx, DWORD def) {
    DWORD v = def, n = sizeof v; if (!U(CryptMsgGetParam)(m, param, idx, &v, &n)) return def; return v;
}
TEST(mh_msgparam_signed_message_params) {
    MH_INIT(); REQUIRE(U(CryptMsgOpenToDecode)); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA384);
    PCCERT_CONTEXT mc[2] = { mh_ids[MH_S1].pub, mh_ids[MH_S2].pub }; p.cMsgCert = 2; p.rgpMsgCert = mc;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD n = 0;
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    HCRYPTMSG m = open_msg(b, n); CHECK(m != NULL); if (!m) { free(b); return; }
    EXPECT_EQ(get_dword(m, CMSG_TYPE_PARAM, 0, 99), CMSG_SIGNED);
    EXPECT_EQ(get_dword(m, CMSG_SIGNER_COUNT_PARAM, 0, 99), 1);
    EXPECT_EQ(get_dword(m, CMSG_CERT_COUNT_PARAM, 0, 99), 2);
    EXPECT_EQ(get_dword(m, CMSG_CRL_COUNT_PARAM, 0, 99), 0);
    char oid[64]; DWORD on = sizeof oid;
    CRYPT_ALGORITHM_IDENTIFIER *alg = (CRYPT_ALGORITHM_IDENTIFIER *)malloc(256); on = 256;
    CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_HASH_ALGORITHM_PARAM, 0, alg, &on));
    EXPECT_STR(alg->pszObjId, OID_SHA384);
    free(alg);
    on = 0; CHECK(U(CryptMsgGetParam)(m, CMSG_CERT_PARAM, 0, NULL, &on)); CHECK(on == sizeof v_s1_cert || on == sizeof v_s2_cert);
    on = 4; BYTE tmp[4];
    GP_OUT_OF_RANGE(m, CMSG_CERT_PARAM, 2, tmp, &on);
    CERT_INFO *ci = malloc(1024); on = 1024;
    CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_CERT_INFO_PARAM, 0, ci, &on));
    CHECK(ci->SerialNumber.cbData == mh_ids[MH_S1].pub->pCertInfo->SerialNumber.cbData
          && !memcmp(ci->SerialNumber.pbData, mh_ids[MH_S1].pub->pCertInfo->SerialNumber.pbData, ci->SerialNumber.cbData));
    CHECK(ci->Issuer.cbData == mh_ids[MH_S1].pub->pCertInfo->Issuer.cbData);
    free(ci);
    on = 0;
    if (U(CryptMsgGetParam)(m, CMSG_ENCRYPTED_DIGEST, 0, NULL, &on)) EXPECT_EQ(on, 128); else t_note("CMSG_ENCRYPTED_DIGEST unavailable: 0x%lx", GetLastError());
    on = sizeof oid; CHECK(U(CryptMsgGetParam)(m, CMSG_INNER_CONTENT_TYPE_PARAM, 0, oid, &on)); EXPECT_STR(oid, "1.2.840.113549.1.7.1");
    on = 0; CHECK(U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, NULL, &on)); EXPECT_EQ(on, sizeof v_payload);
    U(CryptMsgClose)(m); free(b);
}
TEST(mh_msgparam_signed_wrong_param_for_type) {
    MH_INIT(); REQUIRE(U(CryptMsgOpenToDecode));
    HCRYPTMSG m = open_msg(v_m_sig_noattr, sizeof v_m_sig_noattr); CHECK(m != NULL); if (!m) return;
    DWORD v, n = sizeof v; SET_ERR(0);
    CHECK(!U(CryptMsgGetParam)(m, CMSG_RECIPIENT_COUNT_PARAM, 0, &v, &n));
    EXPECT_ERR(0x80091004u);   /* CRYPT_E_INVALID_MSG_TYPE */
    SET_ERR(0); n = sizeof v;
    CHECK(!U(CryptMsgGetParam)(m, CMSG_HASH_ALGORITHM_PARAM, 0, &v, &n));
    /* crypt32 faults inside and catches it itself: the call fails with the exception code as the last error */
    EXPECT_ERR(0xC0000005u);
    U(CryptMsgClose)(m);
}
TEST(mh_msgparam_hashed_message_params) {
    MH_INIT(); REQUIRE(U(CryptMsgOpenToDecode)); REQUIRE(U(CryptHashMessage));
    CRYPT_HASH_MESSAGE_PARA hp; mh_hash_para(&hp, OID_SHA1);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD n = 0;
    CHECK(U(CryptHashMessage)(&hp, FALSE, 1, a, l, NULL, &n, NULL, NULL));
    BYTE *b = malloc(n); CHECK(U(CryptHashMessage)(&hp, FALSE, 1, a, l, b, &n, NULL, NULL));
    HCRYPTMSG m = open_msg(b, n); CHECK(m != NULL); if (!m) { free(b); return; }
    EXPECT_EQ(get_dword(m, CMSG_TYPE_PARAM, 0, 99), CMSG_HASHED);
    BYTE alg[200]; DWORD an = sizeof alg;
    CHECK(U(CryptMsgGetParam)(m, CMSG_HASH_ALGORITHM_PARAM, 0, alg, &an));
    EXPECT_STR(((CRYPT_ALGORITHM_IDENTIFIER *)alg)->pszObjId, OID_SHA1);
    BYTE h[64]; DWORD hn = sizeof h;
    CHECK(U(CryptMsgGetParam)(m, CMSG_HASH_DATA_PARAM, 0, h, &hn)); CHECK(hn == 20 && !memcmp(h, v_h_sha1, 20));
    hn = 0; CHECK(U(CryptMsgGetParam)(m, CMSG_HASH_DATA_PARAM, 0, NULL, &hn)); EXPECT_EQ(hn, 20);
    hn = 4; SET_ERR(0); CHECK(!U(CryptMsgGetParam)(m, CMSG_HASH_DATA_PARAM, 0, h, &hn)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(hn, 20);
    hn = sizeof h;
    CHECK(U(CryptMsgGetParam)(m, CMSG_COMPUTED_HASH_PARAM, 0, h, &hn)); CHECK(hn == 20 && !memcmp(h, v_h_sha1, 20));
    U(CryptMsgClose)(m); free(b);
}
TEST(mh_msgparam_enveloped_message_params) {
    MH_INIT(); REQUIRE(U(CryptMsgOpenToDecode)); REQUIRE(U(CryptEncryptMessage));
    CRYPT_ENCRYPT_MESSAGE_PARA ep; mh_enc_para(&ep, "1.2.840.113549.3.7");
    PCCERT_CONTEXT rc[2] = { mh_ids[MH_R1].pub, mh_ids[MH_R2].pub }; DWORD n = 0;
    CHECK(U(CryptEncryptMessage)(&ep, 2, rc, v_payload, sizeof v_payload, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptEncryptMessage)(&ep, 2, rc, v_payload, sizeof v_payload, b, &n));
    HCRYPTMSG m = open_msg(b, n); CHECK(m != NULL); if (!m) { free(b); return; }
    EXPECT_EQ(get_dword(m, CMSG_TYPE_PARAM, 0, 99), CMSG_ENVELOPED);
    EXPECT_EQ(get_dword(m, CMSG_RECIPIENT_COUNT_PARAM, 0, 99), 2);
    BYTE alg[200]; DWORD an = sizeof alg;
    CHECK(U(CryptMsgGetParam)(m, CMSG_ENVELOPE_ALGORITHM_PARAM, 0, alg, &an));
    EXPECT_STR(((CRYPT_ALGORITHM_IDENTIFIER *)alg)->pszObjId, "1.2.840.113549.3.7");
    BYTE *ri = malloc(512); DWORD rn = 512;
    CHECK(U(CryptMsgGetParam)(m, CMSG_RECIPIENT_INFO_PARAM, 1, ri, &rn));
    CERT_INFO *ci = (CERT_INFO *)ri;
    CHECK(ci->SerialNumber.cbData == mh_ids[MH_R2].pub->pCertInfo->SerialNumber.cbData
          && !memcmp(ci->SerialNumber.pbData, mh_ids[MH_R2].pub->pCertInfo->SerialNumber.pbData, ci->SerialNumber.cbData));
    SET_ERR(0); rn = 512; CHECK(!U(CryptMsgGetParam)(m, CMSG_RECIPIENT_INFO_PARAM, 2, ri, &rn)); EXPECT_ERR(0x80091008u);
    free(ri);
    DWORD cn = 0; SET_ERR(0);
    BOOL r = U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, NULL, &cn);
    t_note("content of an undecrypted enveloped message -> %d err 0x%lx n=%lu", r, GetLastError(), cn);
    U(CryptMsgClose)(m); free(b);
}
TEST(mh_msgparam_certs_and_crls_of_signed_message) {
    MH_INIT(); REQUIRE(U(CryptMsgOpenToDecode));
    HCRYPTMSG m = open_msg(v_o_p7_crl, sizeof v_o_p7_crl); CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(get_dword(m, CMSG_TYPE_PARAM, 0, 99), CMSG_SIGNED);
    EXPECT_EQ(get_dword(m, CMSG_CERT_COUNT_PARAM, 0, 99), 2);
    EXPECT_EQ(get_dword(m, CMSG_CRL_COUNT_PARAM, 0, 99), 1);
    EXPECT_EQ(get_dword(m, CMSG_SIGNER_COUNT_PARAM, 0, 99), 0);
    BYTE c[1000]; DWORD cn = sizeof c;
    CHECK(U(CryptMsgGetParam)(m, CMSG_CRL_PARAM, 0, c, &cn)); CHECK(cn == sizeof v_o_crl && !memcmp(c, v_o_crl, cn));
    cn = sizeof c; GP_OUT_OF_RANGE(m, CMSG_CRL_PARAM, 1, c, &cn);
    U(CryptMsgClose)(m);
}

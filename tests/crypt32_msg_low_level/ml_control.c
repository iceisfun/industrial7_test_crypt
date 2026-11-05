/* CryptMsgControl: encode-side rejection, decode-side add/delete operations, error codes. */
#include "ml.h"

static const BYTE ATTR_DER[] = {0x30,0x0d,0x06,0x05,0x2a,0x03,0x04,0x05,0x4d,0x31,0x04,0x04,0x02,0xab,0xcd};

static HCRYPTMSG signed_msg(void) { return ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0); }

/* ---------------------------------------------------------------- encode messages allow no control */
static void encode_ctrl_rejected(HCRYPTMSG m, const char *what) {
    for (DWORD i = 1; i <= CMSG_CTRL_ADD_CMS_SIGNER_INFO; i++) {
        SET_ERR(0);
        BOOL ok = mControl()(m, 0, i, NULL);
        CHECKF(!ok, "%s control %lu", what, (unsigned long)i);
        EXPECT_ERR(E_INVALIDARG);
    }
}
TEST(mlc_encode_data_msg_rejects_controls) {
    REQ_MSG();
    if (t_is_wine()) { t_skip("emulator differs for encode-side controls"); return; }
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    encode_ctrl_rejected(m, "data/open");
    CHECK(mUpdate()(m, NULL, 0, TRUE));
    encode_ctrl_rejected(m, "data/final");
    mClose()(m);
}
TEST(mlc_encode_hashed_msg_rejects_controls) {
    REQ_MSG();
    if (t_is_wine()) { t_skip("emulator differs for encode-side controls"); return; }
    CMSG_HASHED_ENCODE_INFO h; memset(&h, 0, sizeof h); h.cbSize = sizeof h; h.HashAlgorithm.pszObjId = OID_SHA1;
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    encode_ctrl_rejected(m, "hashed/open");
    CHECK(mUpdate()(m, NULL, 0, TRUE));
    encode_ctrl_rejected(m, "hashed/final");
    mClose()(m);
}
TEST(mlc_encode_signed_msg_rejects_controls) {
    REQ_MSG();
    if (t_is_wine()) { t_skip("emulator differs for encode-side controls"); return; }
    ml_signer_t s;
    if (!ml_signer_init(&s, OID_SHA256)) { ml_signer_done(&s); t_skip("setup"); return; }
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        encode_ctrl_rejected(m, "signed/open");
        CHECK(mUpdate()(m, NULL, 0, TRUE));
        encode_ctrl_rejected(m, "signed/final");
        mClose()(m);
    }
    ml_signer_done(&s);
}
TEST(mlc_encode_signed_msg_rejects_verify_with_real_parameter) {
    REQ_MSG();
    ml_signer_t s;
    if (!ml_signer_init(&s, OID_SHA256)) { ml_signer_done(&s); t_skip("setup"); return; }
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
        SET_ERR(0);
        CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, s.cert->pCertInfo));
        EXPECT_ERR(E_INVALIDARG);
        mClose()(m);
    }
    ml_signer_done(&s);
}

/* ---------------------------------------------------------------- decode: control type validation */
TEST(mlc_decode_bad_control_type) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, 0, NULL));
    EXPECT_ERR(CRYPT_E_CONTROL_TYPE);
    SET_ERR(0);
    CHECK(!mControl()(m, 1, 0, NULL));
    EXPECT_ERR(CRYPT_E_CONTROL_TYPE);
    mClose()(m);
}
TEST(mlc_decode_unknown_control_types) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    static const DWORD t[] = {0, 22, 23, 100, 0xFFFF, 0xFFFFFFFF};
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        SET_ERR(0);
        CHECKF(!mControl()(m, 0, t[i], NULL), "type %lu", (unsigned long)t[i]);
        EXPECT_ERR(CRYPT_E_CONTROL_TYPE);
    }
    mClose()(m);
}
TEST(mlc_decode_untyped_empty_message_controls) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    CMSG_CTRL_DECRYPT_PARA dp; memset(&dp, 0, sizeof dp); dp.cbSize = sizeof dp;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
    EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_DECRYPT, &dp));
    EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    mClose()(m);
}
TEST(mlc_wrong_type_controls) {
    REQ_MSG();
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    CMSG_CTRL_DECRYPT_PARA dp; memset(&dp, 0, sizeof dp); dp.cbSize = sizeof dp;
    HCRYPTMSG h = ml_decode(M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, 0, 0);
    CHECK(h != NULL);
    if (h) {
        SET_ERR(0);
        CHECK(!mControl()(h, 0, CMSG_CTRL_VERIFY_SIGNATURE, &ci));
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        SET_ERR(0);
        CHECK(!mControl()(h, 0, CMSG_CTRL_DECRYPT, &dp));
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        mClose()(h);
    }
    HCRYPTMSG s = signed_msg();
    CHECK(s != NULL);
    if (s) {
        SET_ERR(0);
        CHECK(!mControl()(s, 0, CMSG_CTRL_VERIFY_HASH, NULL));
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        SET_ERR(0);
        CHECK(!mControl()(s, 0, CMSG_CTRL_DECRYPT, &dp));
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        mClose()(s);
    }
}

/* ---------------------------------------------------------------- detached hash flow */
TEST(mlc_detached_hash_correct_order) {
    REQ_MSG();
    static const BYTE d4[4] = {1,2,3,4};
    HCRYPTMSG m = mOpenDec()(ENC, CMSG_DETACHED_FLAG, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    /* verifying before the message was supplied */
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
    EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    CHECK(mUpdate()(m, X_HASH_MD5_1234_DET, X_HASH_MD5_1234_DET_LEN, TRUE));
    CHECK(mUpdate()(m, d4, 4, TRUE));
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL), "err 0x%lx", GetLastError());
    mClose()(m);
}
TEST(mlc_detached_hash_verify_before_content) {
    REQ_MSG();
    static const BYTE d4[4] = {1,2,3,4};
    HCRYPTMSG m = mOpenDec()(ENC, CMSG_DETACHED_FLAG, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mUpdate()(m, X_HASH_MD5_1234_DET, X_HASH_MD5_1234_DET_LEN, TRUE));
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
    EXPECT_ERR(CRYPT_E_HASH_VALUE);
    /* the attempt finalised the hash: the content can no longer be supplied */
    SET_ERR(0);
    CHECK(!mUpdate()(m, d4, 4, TRUE));
    DWORD e = GetLastError();
    CHECKF(e == (DWORD)NTE_BAD_HASH_STATE || e == (DWORD)CRYPT_E_MSG_ERROR, "err 0x%lx", (unsigned long)e);
    mClose()(m);
}
TEST(mlc_detached_hash_wrong_content) {
    REQ_MSG();
    static const BYTE d4[4] = {1,2,3,5};
    HCRYPTMSG m = mOpenDec()(ENC, CMSG_DETACHED_FLAG, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mUpdate()(m, X_HASH_MD5_1234_DET, X_HASH_MD5_1234_DET_LEN, TRUE));
    CHECK(mUpdate()(m, d4, 4, TRUE));
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
    EXPECT_ERR(CRYPT_E_HASH_VALUE);
    mClose()(m);
}
TEST(mlc_hashed_bare_explicit_type) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, CMSG_HASHED, 0, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mUpdate()(m, X_HASH_MD5_1234_BARE, X_HASH_MD5_1234_BARE_LEN, TRUE));
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL), "err 0x%lx", GetLastError());
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
    CHECK(b && cb == 4 && b[0] == 1 && b[3] == 4);
    ml_free(b);
    mClose()(m);
}

/* ---------------------------------------------------------------- certificates and CRLs */
TEST(mlc_add_del_cert) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 99;
    CHECK(ml_param_dword(m, CMSG_CERT_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 1);
    CERT_BLOB b2 = {V_CERT2_LEN, (BYTE *)V_CERT2};
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_ADD_CERT, &b2), "add err 0x%lx", GetLastError());
    CHECK(ml_param_dword(m, CMSG_CERT_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 2);
    DWORD k = 0; BYTE *c = ml_param(m, CMSG_CERT_PARAM, 1, &k);
    CHECK(c && k == V_CERT2_LEN && !memcmp(c, V_CERT2, k));   /* appended at the end */
    ml_free(c);
    DWORD idx = 0;
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_DEL_CERT, &idx), "del err 0x%lx", GetLastError());
    CHECK(ml_param_dword(m, CMSG_CERT_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 1);
    c = ml_param(m, CMSG_CERT_PARAM, 0, &k);
    CHECK(c && k == V_CERT2_LEN && !memcmp(c, V_CERT2, k));   /* the original certificate was removed */
    ml_free(c);
    mClose()(m);
}
TEST(mlc_del_cert_bad_index) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    DWORD idx = 5;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_DEL_CERT, &idx));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    DWORD n = 0; CHECK(ml_param_dword(m, CMSG_CERT_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 1);
    idx = 1;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_DEL_CERT, &idx));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    mClose()(m);
}
TEST(mlc_add_cert_keeps_signature_valid) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    CERT_BLOB b2 = {V_CERT2_LEN, (BYTE *)V_CERT2};
    CHECK(mControl()(m, 0, CMSG_CTRL_ADD_CERT, &b2));
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    SET_ERR(0);
    CHECKF(c && mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pCertInfo), "err 0x%lx", GetLastError());
    ml_cert_free(c);
    mClose()(m);
}
TEST(mlc_add_crl_del_crl) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 99;
    CHECK(ml_param_dword(m, CMSG_CRL_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 0);
    CRL_BLOB cb = {V_CRL1_LEN, (BYTE *)V_CRL1};
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_ADD_CRL, &cb), "add err 0x%lx", GetLastError());
    CHECK(ml_param_dword(m, CMSG_CRL_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 1);
    DWORD k = 0; BYTE *c = ml_param(m, CMSG_CRL_PARAM, 0, &k);
    CHECK(c && k == V_CRL1_LEN && !memcmp(c, V_CRL1, k));
    ml_free(c);
    DWORD idx = 3;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_DEL_CRL, &idx));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    idx = 0;
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_DEL_CRL, &idx), "del err 0x%lx", GetLastError());
    CHECK(ml_param_dword(m, CMSG_CRL_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 0);
    mClose()(m);
}
TEST(mlc_add_cert_garbage_blob) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    BYTE junk[] = {1,2,3};
    CERT_BLOB b = {sizeof junk, junk};
    SET_ERR(0);
    EXPECT_SUCCEEDS(mControl()(m, 0, CMSG_CTRL_ADD_CERT, &b));   /* the blob is stored without validation */
    mClose()(m);
}
TEST(mlc_add_cert_wrong_type) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    CERT_BLOB b2 = {V_CERT2_LEN, (BYTE *)V_CERT2};
    /* Win10 does not check the message type first: both controls dereference missing signed-data state (access violation) */
    T_EXPECT_FAULT(mControl()(m, 0, CMSG_CTRL_ADD_CERT, &b2));
    DWORD idx = 0;
    T_EXPECT_FAULT(mControl()(m, 0, CMSG_CTRL_DEL_CERT, &idx));
    mClose()(m);
}

/* ---------------------------------------------------------------- unauthenticated attributes */
TEST(mlc_add_del_unauth_attr) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA a; memset(&a, 0, sizeof a);
    a.cbSize = sizeof a; a.dwSignerIndex = 0; a.blob.cbData = sizeof ATTR_DER; a.blob.pbData = (BYTE *)ATTR_DER;
    EXPECT_SUCCEEDS(mControl()(m, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &a));
    /* Win10: CMSG_SIGNER_UNAUTH_ATTR_PARAM does not reflect attributes added by control (still ATTRIBUTES_MISSING); SIGNER_INFO does */
    DWORD n = 0;
    EXPECT_FAILS(mGetParam()(m, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &n), CRYPT_E_ATTRIBUTES_MISSING);
    BYTE *si = ml_param(m, CMSG_SIGNER_INFO_PARAM, 0, &n);
    if (si) {
        CMSG_SIGNER_INFO *sii = (CMSG_SIGNER_INFO *)si;
        CHECK(sii->UnauthAttrs.cAttr == 1 && !strcmp(sii->UnauthAttrs.rgAttr[0].pszObjId, "1.2.3.4.5.77"));
        ml_free(si);
    } else CHECK(si != NULL);
    /* an unauthenticated attribute does not invalidate the signature */
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    SET_ERR(0);
    CHECKF(c && mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pCertInfo), "verify err 0x%lx", GetLastError());
    ml_cert_free(c);
    CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA d; memset(&d, 0, sizeof d);
    d.cbSize = sizeof d; d.dwSignerIndex = 0; d.dwUnauthAttrIndex = 4;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR, &d));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    d.dwUnauthAttrIndex = 0;
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR, &d), "del err 0x%lx", GetLastError());
    SET_ERR(0);
    n = 0;
    CHECK(!mGetParam()(m, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &n));
    mClose()(m);
}
TEST(mlc_unauth_attr_bad_signer_index) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA a; memset(&a, 0, sizeof a);
    a.cbSize = sizeof a; a.dwSignerIndex = 3; a.blob.cbData = sizeof ATTR_DER; a.blob.pbData = (BYTE *)ATTR_DER;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &a));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA d; memset(&d, 0, sizeof d);
    d.cbSize = sizeof d; d.dwSignerIndex = 3;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR, &d));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    mClose()(m);
}
TEST(mlc_unauth_attr_bad_cbsize) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA a; memset(&a, 0, sizeof a);
    a.cbSize = 4; a.blob.cbData = sizeof ATTR_DER; a.blob.pbData = (BYTE *)ATTR_DER;
    /* Win10 does not validate cbSize of these parameter structures: both calls succeed */
    EXPECT_SUCCEEDS(mControl()(m, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &a));
    DWORD n = 0; BYTE *si = ml_param(m, CMSG_SIGNER_INFO_PARAM, 0, &n);
    CHECK(si && ((CMSG_SIGNER_INFO *)si)->UnauthAttrs.cAttr == 1); ml_free(si);
    CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA d; memset(&d, 0, sizeof d);
    d.cbSize = 4;
    EXPECT_SUCCEEDS(mControl()(m, 0, CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR, &d));
    si = ml_param(m, CMSG_SIGNER_INFO_PARAM, 0, &n);
    CHECK(si && ((CMSG_SIGNER_INFO *)si)->UnauthAttrs.cAttr == 0); ml_free(si);
    mClose()(m);
}
TEST(mlc_encoded_signer_param_after_attr_add) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    DWORD n0 = 0; BYTE *before = ml_param(m, CMSG_ENCODED_SIGNER, 0, &n0);
    CHECK(before != NULL);
    CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA a; memset(&a, 0, sizeof a);
    a.cbSize = sizeof a; a.blob.cbData = sizeof ATTR_DER; a.blob.pbData = (BYTE *)ATTR_DER;
    CHECK(mControl()(m, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, &a));
    /* Win10: once an attribute was added, CMSG_ENCODED_SIGNER is no longer available */
    DWORD n1 = 0;
    EXPECT_FAILS(mGetParam()(m, CMSG_ENCODED_SIGNER, 0, NULL, &n1), E_INVALIDARG);
    if (before) CHECK(before[0] == 0x30);
    ml_free(before);
    mClose()(m);
}

/* ---------------------------------------------------------------- signers */
TEST(mlc_del_signer) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_TWO, M_SIGNED_TWO_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD idx = 5;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_DEL_SIGNER, &idx));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    idx = 0;
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_DEL_SIGNER, &idx), "del err 0x%lx", GetLastError());
    DWORD n = 0; CHECK(ml_param_dword(m, CMSG_SIGNER_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 1);
    PCCERT_CONTEXT c2 = ml_cert(V_CERT2, V_CERT2_LEN);
    SET_ERR(0);
    CHECKF(c2 && mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c2->pCertInfo), "remaining signer verify err 0x%lx", GetLastError());
    ml_cert_free(c2);
    mClose()(m);
}
TEST(mlc_add_signer) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    HCRYPTPROV prov = ml_prov(V_KEY2, V_KEY2_LEN);
    PCCERT_CONTEXT c2 = ml_cert(V_CERT2, V_CERT2_LEN);
    CHECK(prov && c2);
    if (prov && c2) {
        CMSG_SIGNER_ENCODE_INFO si; memset(&si, 0, sizeof si);
        si.cbSize = sizeof si; si.pCertInfo = c2->pCertInfo; si.hCryptProv = prov; si.dwKeySpec = AT_KEYEXCHANGE; si.HashAlgorithm.pszObjId = OID_SHA256;
        SET_ERR(0);
        BOOL ok = mControl()(m, 0, CMSG_CTRL_ADD_SIGNER, &si);
        if (!ok) t_note("ADD_SIGNER on a decoded message failed: 0x%lx", (unsigned long)GetLastError());
        CHECKF(ok, "add signer err 0x%lx", GetLastError());
        if (ok) {
            DWORD n = 0; CHECK(ml_param_dword(m, CMSG_SIGNER_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 2);
            SET_ERR(0);
            CHECKF(mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c2->pCertInfo), "verify new signer err 0x%lx", GetLastError());
        }
    }
    ml_cert_free(c2); ml_prov_release(prov);
    mClose()(m);
}
TEST(mlc_add_signer_bad_cbsize) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    CMSG_SIGNER_ENCODE_INFO si; memset(&si, 0, sizeof si);
    si.cbSize = 4;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_ADD_SIGNER, &si));
    EXPECT_ERR(CRYPT_E_UNKNOWN_ALGO);   /* cbSize is not validated; the empty hash algorithm is what fails */
    mClose()(m);
}

/* ---------------------------------------------------------------- attribute certificates */
TEST(mlc_attr_cert_params_empty) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 99;
    CHECK(ml_param_dword(m, CMSG_ATTR_CERT_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 0);
    n = 0; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_ATTR_CERT_PARAM, 0, NULL, &n));
    EXPECT_ERR(0);   /* Win10 fails without setting an error code */
    mClose()(m);
}
TEST(mlc_add_del_attr_cert) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    /* a minimal DER SEQUENCE stands in for an attribute certificate: the blob is stored verbatim */
    static const BYTE ac[] = {0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x02};
    CERT_BLOB b = {sizeof ac, (BYTE *)ac};
    /* Win10 refuses to add an attribute certificate to this decoded signed message */
    EXPECT_FAILS(mControl()(m, 0, CMSG_CTRL_ADD_ATTR_CERT, &b), CRYPT_E_INVALID_MSG_TYPE);
    DWORD n = 99; CHECK(ml_param_dword(m, CMSG_ATTR_CERT_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 0);
    DWORD idx = 0;
    EXPECT_FAILS(mControl()(m, 0, CMSG_CTRL_DEL_ATTR_CERT, &idx), CRYPT_E_INVALID_INDEX);
    mClose()(m);
}
TEST(mlc_strong_signature_control) {
    REQ_MSG();
    HCRYPTMSG m = signed_msg();
    CHECK(m != NULL);
    if (!m) return;
    CERT_STRONG_SIGN_PARA sp; memset(&sp, 0, sizeof sp);
    sp.cbSize = sizeof sp;
    sp.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
    sp.pszOID = (LPSTR)szOID_CERT_STRONG_SIGN_OS_CURRENT;
    EXPECT_SUCCEEDS(mControl()(m, 0, CMSG_CTRL_ENABLE_STRONG_SIGNATURE, &sp));
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    REQUIRE_NOTNULL(c);
    /* with the strong policy on, the 1024-bit RSA signature is rejected with NTE_BAD_ALGID */
    EXPECT_FAILS(mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pCertInfo), NTE_BAD_ALGID);
    ml_cert_free(c);
    mClose()(m);
}

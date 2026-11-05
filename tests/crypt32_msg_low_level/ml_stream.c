/* Streamed encode/decode with CMSG_STREAM_INFO. */
#include "ml.h"

typedef struct { BYTE *buf; DWORD len, cap; DWORD calls, finals; DWORD final_at_call; BOOL fail; DWORD max_chunk; } acc_t;
static BOOL WINAPI acc_cb(const void *arg, BYTE *pb, DWORD cb, BOOL fFinal) {
    acc_t *a = (acc_t *)arg;
    if (a->fail) return FALSE;
    if (a->len + cb > a->cap) { a->cap = (a->len + cb) * 2 + 64; a->buf = (BYTE *)realloc(a->buf, a->cap); }
    if (cb) memcpy(a->buf + a->len, pb, cb);
    a->len += cb; a->calls++;
    if (cb > a->max_chunk) a->max_chunk = cb;
    if (fFinal) { a->finals++; a->final_at_call = a->calls; }
    return TRUE;
}
static void acc_free(acc_t *a) { free(a->buf); memset(a, 0, sizeof *a); }

static const BYTE T3[3] = {'a','b','c'};

/* ---------------------------------------------------------------- data, definite length */
TEST(mlt_data_definite_matches_nonstreamed) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {V_CONTENT_LEN, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
        mClose()(m);
        DWORD cb = 0; BYTE *ref = ml_encode_data(0, V_CONTENT, V_CONTENT_LEN, &cb);
        CHECK(ref != NULL);
        if (ref) CHECKF(a.len == cb && !memcmp(a.buf, ref, cb), "streamed %lu bytes vs %lu", (unsigned long)a.len, (unsigned long)cb);
        ml_free(ref);
        EXPECT_EQ(a.finals, 1);
        EXPECT_EQ(a.final_at_call, a.calls);   /* the final flag is on the last callback */
    }
    acc_free(&a);
}
TEST(mlt_data_definite_chunked_matches_nonstreamed) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {V_CONTENT_LEN, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        DWORD off = 0;
        while (off + 5 < V_CONTENT_LEN) { CHECK(mUpdate()(m, V_CONTENT + off, 5, FALSE)); off += 5; }
        CHECK(mUpdate()(m, V_CONTENT + off, V_CONTENT_LEN - off, TRUE));
        mClose()(m);
        DWORD cb = 0; BYTE *ref = ml_encode_data(0, V_CONTENT, V_CONTENT_LEN, &cb);
        CHECK(ref && a.len == cb && !memcmp(a.buf, ref, cb));
        ml_free(ref);
        EXPECT_EQ(a.finals, 1);
        EXPECT_EQ(a.calls, 8);
    }
    acc_free(&a);
}
TEST(mlt_data_definite_empty_content) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, NULL, 0, TRUE));
        mClose()(m);
        DWORD cb = 0; BYTE *ref = ml_encode_data(0, NULL, 0, &cb);
        CHECK(ref && a.len == cb && !memcmp(a.buf, ref, cb));
        ml_free(ref);
        EXPECT_EQ(a.finals, 1);
    }
    acc_free(&a);
}
TEST(mlt_data_stream_forbids_content_params) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {3, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        DWORD n = 0;
        SET_ERR(0);
        CHECK(!mGetParam()(m, CMSG_CONTENT_PARAM, 0, NULL, &n));
        EXPECT_ERR(E_INVALIDARG);
        SET_ERR(0);
        CHECK(!mGetParam()(m, CMSG_BARE_CONTENT_PARAM, 0, NULL, &n));
        EXPECT_ERR(E_INVALIDARG);
        mClose()(m);
    }
    acc_free(&a);
}
TEST(mlt_data_stream_update_after_final) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {3, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, T3, 3, TRUE));
        SET_ERR(0);
        CHECK(!mUpdate()(m, T3, 3, TRUE));
        EXPECT_ERR(CRYPT_E_MSG_ERROR);
        mClose()(m);
    }
    acc_free(&a);
}
TEST(mlt_data_stream_callback_failure_propagates) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a); a.fail = TRUE;
    CMSG_STREAM_INFO si = {3, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        SET_ERR(0);
        BOOL ok = mUpdate()(m, T3, 3, TRUE);
        CHECK(!ok); EXPECT_ERR(0); /* observed: the failure is reported without a last error */
        mClose()(m);
    }
    acc_free(&a);
}
TEST(mlt_data_stream_open_nonfinal_ok) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {6, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, NULL, 0, FALSE));
        CHECK(mUpdate()(m, T3, 3, FALSE));
        CHECK(mUpdate()(m, T3, 3, TRUE));
        mClose()(m);
        EXPECT_EQ(a.finals, 1);
        EXPECT_EQ(a.len, 23); EXPECT_EQ(a.calls, 3);
    }
    acc_free(&a);
}

/* ---------------------------------------------------------------- data, indefinite length */
TEST(mlt_data_indefinite_structure) {
    REQ_MSG();
    static const BYTE head[] = {0x30,0x80,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x80,0x24,0x80};
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {CMSG_INDEFINITE_LENGTH, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, T3, 3, FALSE));
        CHECK(mUpdate()(m, T3, 3, TRUE));
        mClose()(m);
        EXPECT_EQ(a.len, 33);
        CHECK(a.len >= sizeof head && !memcmp(a.buf, head, sizeof head));
        static const BYTE tail[6] = {0,0,0,0,0,0};
        CHECK(a.len >= 6 && !memcmp(a.buf + a.len - 6, tail, 6));
        EXPECT_EQ(a.finals, 1);
        /* each update becomes its own OCTET STRING segment */
        static const BYTE seg[] = {0x04,0x03,'a','b','c'};
        const BYTE *p = ml_memmem(a.buf, a.len, seg, sizeof seg);
        CHECK(p != NULL);
        if (p) CHECK(ml_memmem(p + 5, a.len - (p - a.buf) - 5, seg, sizeof seg) != NULL);
    }
    acc_free(&a);
}
TEST(mlt_data_indefinite_decodes_nonstreamed) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {CMSG_INDEFINITE_LENGTH, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &si);
    CHECK(m != NULL);
    if (!m) { acc_free(&a); return; }
    DWORD off = 0;
    while (off + 9 < V_CONTENT_LEN) { CHECK(mUpdate()(m, V_CONTENT + off, 9, FALSE)); off += 9; }
    CHECK(mUpdate()(m, V_CONTENT + off, V_CONTENT_LEN - off, TRUE));
    mClose()(m);
    HCRYPTMSG d = ml_decode(a.buf, a.len, 0, 0);
    CHECKF(d != NULL, "err 0x%lx", GetLastError());
    if (d) {
        DWORD t = 0; CHECK(ml_param_dword(d, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, CMSG_DATA);
        DWORD n = 0; BYTE *c = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
        CHECK(c && n == V_CONTENT_LEN && !memcmp(c, V_CONTENT, n));
        ml_free(c); mClose()(d);
    }
    acc_free(&a);
}

/* ---------------------------------------------------------------- hashed / signed / enveloped streamed encode */
TEST(mlt_hashed_stream_callback_not_invoked) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {V_CONTENT_LEN, acc_cb, &a};
    CMSG_HASHED_ENCODE_INFO h; memset(&h, 0, sizeof h); h.cbSize = sizeof h; h.HashAlgorithm.pszObjId = OID_SHA1;
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
        mClose()(m);
        /* observed: a streamed CMSG_HASHED encode never invokes the callback */
        EXPECT_EQ(a.len, 0); EXPECT_EQ(a.calls, 0); EXPECT_EQ(a.finals, 0);
    }
    acc_free(&a);
}
TEST(mlt_signed_stream_definite_verifies) {
    ml_signer_t s; REQ_MSG();
    if (!ml_signer_init(&s, OID_SHA1)) { ml_signer_done(&s); CHECKF(0, "setup failed"); return; }
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {V_CONTENT_LEN, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, &si);
    CHECKF(m != NULL, "err 0x%lx", GetLastError());
    if (m) {
        DWORD off = 0;
        while (off + 11 < V_CONTENT_LEN) { CHECK(mUpdate()(m, V_CONTENT + off, 11, FALSE)); off += 11; }
        CHECK(mUpdate()(m, V_CONTENT + off, V_CONTENT_LEN - off, TRUE));
        mClose()(m);
        EXPECT_EQ(a.finals, 1);
        HCRYPTMSG d = ml_decode(a.buf, a.len, 0, 0);
        CHECKF(d != NULL, "err 0x%lx", GetLastError());
        if (d) {
            SET_ERR(0);
            CHECKF(mControl()(d, 0, CMSG_CTRL_VERIFY_SIGNATURE, s.cert->pCertInfo), "verify err 0x%lx", GetLastError());
            DWORD n = 0; BYTE *c = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
            CHECK(c && n == V_CONTENT_LEN && !memcmp(c, V_CONTENT, n)); ml_free(c);
            mClose()(d);
        }
        DWORD cb = 0; BYTE *ref = ml_sign(&s, 0, OID_SHA1, V_CONTENT, V_CONTENT_LEN, &cb);
        CHECK(ref != NULL); /* observed: byte-identical to the non-streamed message */
        if (ref) { EXPECT_EQ(a.len, cb); CHECK(cb == a.len && !memcmp(ref, a.buf, cb)); }
        ml_free(ref);
    }
    acc_free(&a);
    ml_signer_done(&s);
}
TEST(mlt_signed_stream_indefinite_verifies) {
    ml_signer_t s; REQ_MSG();
    if (!ml_signer_init(&s, OID_SHA1)) { ml_signer_done(&s); CHECKF(0, "setup failed"); return; }
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {CMSG_INDEFINITE_LENGTH, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, &si);
    CHECKF(m != NULL, "err 0x%lx", GetLastError());
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, 10, FALSE));
        CHECK(mUpdate()(m, V_CONTENT + 10, V_CONTENT_LEN - 10, TRUE));
        mClose()(m);
        EXPECT_EQ(a.len, 320); CHECK(a.buf[0] == 0x30 && a.buf[1] == 0x80);
        HCRYPTMSG d = ml_decode(a.buf, a.len, 0, 0);
        CHECKF(d != NULL, "err 0x%lx", GetLastError());
        if (d) {
            SET_ERR(0);
            CHECKF(mControl()(d, 0, CMSG_CTRL_VERIFY_SIGNATURE, s.cert->pCertInfo), "verify err 0x%lx", GetLastError());
            mClose()(d);
        }
    }
    acc_free(&a);
    ml_signer_done(&s);
}
TEST(mlt_enveloped_stream_roundtrip) {
    REQ_MSG();
    HCRYPTPROV ep = ml_prov(NULL, 0), dp = ml_prov(V_KEY1, V_KEY1_LEN);
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    if (!ep || !dp || !c) { ml_cert_free(c); ml_prov_release(ep); ml_prov_release(dp); CHECKF(0, "setup failed"); return; }
    PCERT_INFO rc[1] = {c->pCertInfo};
    CMSG_ENVELOPED_ENCODE_INFO ei; memset(&ei, 0, sizeof ei);
    ei.cbSize = sizeof ei; ei.hCryptProv = ep; ei.ContentEncryptionAlgorithm.pszObjId = OID_3DES; ei.cRecipients = 1; ei.rgpRecipients = rc;
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {CMSG_INDEFINITE_LENGTH, acc_cb, &a};
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_ENVELOPED, &ei, NULL, &si);
    CHECKF(m != NULL, "err 0x%lx", GetLastError());
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, 10, FALSE));
        CHECK(mUpdate()(m, V_CONTENT + 10, V_CONTENT_LEN - 10, TRUE));
        mClose()(m);
        EXPECT_EQ(a.finals, 1);
        HCRYPTMSG d = ml_decode(a.buf, a.len, 0, 0);
        CHECKF(d != NULL, "err 0x%lx", GetLastError());
        if (d) {
            CMSG_CTRL_DECRYPT_PARA p; memset(&p, 0, sizeof p);
            p.cbSize = sizeof p; p.hCryptProv = dp; p.dwKeySpec = AT_KEYEXCHANGE;
            SET_ERR(0);
            CHECKF(mControl()(d, 0, CMSG_CTRL_DECRYPT, &p), "decrypt err 0x%lx", GetLastError());
            DWORD n = 0; BYTE *pt = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
            CHECK(pt && n == V_CONTENT_LEN && !memcmp(pt, V_CONTENT, n)); ml_free(pt);
            mClose()(d);
        }
    }
    acc_free(&a);
    ml_cert_free(c); ml_prov_release(ep); ml_prov_release(dp);
}

/* ---------------------------------------------------------------- streamed decode */
TEST(mlt_decode_stream_bytewise_data) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (!m) return;
    BOOL ok = TRUE; DWORD i;
    for (i = 0; ok && i < M_DATA_LEN; i++) ok = mUpdate()(m, &M_DATA[i], 1, FALSE);
    CHECKF(ok, "failed at byte %lu err 0x%lx", (unsigned long)i, GetLastError());
    CHECK(mUpdate()(m, NULL, 0, TRUE));
    mClose()(m);
    CHECKF(a.len == V_CONTENT_LEN && !memcmp(a.buf, V_CONTENT, a.len), "callback delivered %lu bytes", (unsigned long)a.len);
    EXPECT_EQ(a.finals, 1);
    acc_free(&a);
}
TEST(mlt_decode_stream_whole_message_signed) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (!m) return;
    SET_ERR(0);
    CHECKF(mUpdate()(m, M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, TRUE), "err 0x%lx", GetLastError());
    CHECKF(a.len == V_CONTENT_LEN && !memcmp(a.buf, V_CONTENT, a.len), "callback delivered %lu bytes", (unsigned long)a.len);
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    SET_ERR(0);
    BOOL ok = c && mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pCertInfo);
    CHECKF(ok, "err 0x%lx", GetLastError()); /* observed: verifies */
    ml_cert_free(c);
    mClose()(m);
    acc_free(&a);
}
TEST(mlt_decode_stream_chunks_signed_verify) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (!m) return;
    DWORD off = 0; BOOL ok = TRUE;
    while (off < M_SIGNED_NOATTR_LEN && ok) {
        DWORD n = M_SIGNED_NOATTR_LEN - off < 97 ? M_SIGNED_NOATTR_LEN - off : 97;
        ok = mUpdate()(m, M_SIGNED_NOATTR + off, n, FALSE); off += n;
    }
    CHECKF(ok, "err 0x%lx", GetLastError());
    CHECK(mUpdate()(m, NULL, 0, TRUE));
    CHECK(a.len == V_CONTENT_LEN && !memcmp(a.buf, V_CONTENT, a.len));
    DWORD t = 0; CHECK(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, CMSG_SIGNED);
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    SET_ERR(0);
    CHECKF(c && mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pCertInfo), "verify err 0x%lx", GetLastError());
    ml_cert_free(c);
    mClose()(m);
    acc_free(&a);
}
TEST(mlt_decode_stream_empty_final_insufficient) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mUpdate()(m, NULL, 0, FALSE));
    SET_ERR(0);
    CHECK(!mUpdate()(m, NULL, 0, TRUE));
    EXPECT_ERR(CRYPT_E_STREAM_INSUFFICIENT_DATA);
    mClose()(m);
    acc_free(&a);
}
TEST(mlt_decode_stream_partial_message_final_insufficient) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mUpdate()(m, M_SIGNED_NOATTR, 100, FALSE));
    SET_ERR(0);
    EXPECT_FAIL(!mUpdate()(m, NULL, 0, TRUE), CRYPT_E_MSG_ERROR); /* observed: 100 of 791 bytes then the final update */
    mClose()(m);
    acc_free(&a);
}
TEST(mlt_decode_stream_bogus_content) {
    REQ_MSG();
    static const BYTE junk[] = {1,2,3,4};
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (!m) return;
    SET_ERR(0);
    CHECK(!mUpdate()(m, junk, sizeof junk, TRUE));
    EXPECT_ERR(CRYPT_E_ASN1_BADTAG);
    mClose()(m);
    acc_free(&a);
    m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    a.len = 0;
    if (m) {
        SET_ERR(0);
        BOOL ok = mUpdate()(m, junk, sizeof junk, FALSE);
        CHECK(!ok);
        if (!ok) EXPECT_ERR(CRYPT_E_ASN1_BADTAG);
        mClose()(m);
    }
    acc_free(&a);
}
TEST(mlt_decode_stream_double_final) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (!m) return;
    CHECK(mUpdate()(m, M_DATA, M_DATA_LEN, TRUE));
    SET_ERR(0);
    CHECK(!mUpdate()(m, M_DATA, M_DATA_LEN, TRUE));
    EXPECT_ERR(CRYPT_E_MSG_ERROR);
    mClose()(m);
    acc_free(&a);
}
TEST(mlt_decode_stream_indefinite_roundtrip) {
    REQ_MSG();
    acc_t enc; memset(&enc, 0, sizeof enc);
    CMSG_STREAM_INFO esi = {CMSG_INDEFINITE_LENGTH, acc_cb, &enc};
    HCRYPTMSG e = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, &esi);
    CHECK(e != NULL);
    if (!e) return;
    CHECK(mUpdate()(e, V_CONTENT, 10, FALSE));
    CHECK(mUpdate()(e, V_CONTENT + 10, V_CONTENT_LEN - 10, TRUE));
    mClose()(e);
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (m) {
        BOOL ok = TRUE; DWORD i;
        for (i = 0; ok && i < enc.len; i += 5) ok = mUpdate()(m, enc.buf + i, enc.len - i < 5 ? enc.len - i : 5, FALSE);
        CHECKF(ok, "err 0x%lx", GetLastError());
        CHECK(mUpdate()(m, NULL, 0, TRUE));
        CHECK(a.len == V_CONTENT_LEN && !memcmp(a.buf, V_CONTENT, a.len));
        mClose()(m);
    }
    acc_free(&a); acc_free(&enc);
}
TEST(mlt_decode_stream_getparam_before_data) {
    REQ_MSG();
    acc_t a; memset(&a, 0, sizeof a);
    CMSG_STREAM_INFO si = {0, acc_cb, &a};
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, &si);
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 0; SET_ERR(0);
    EXPECT_FAILS(mGetParam()(m, CMSG_TYPE_PARAM, 0, NULL, &n), CRYPT_E_STREAM_MSG_NOT_READY);
    mClose()(m);
    acc_free(&a);
}

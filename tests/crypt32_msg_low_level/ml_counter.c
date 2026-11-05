/* Counter-signatures: CryptMsgCountersign, CryptMsgCountersignEncoded, CryptMsgVerifyCountersignatureEncoded(Ex). */
#include "ml.h"

#define OID_COUNTERSIGN "1.2.840.113549.1.9.6"

typedef struct { HCRYPTPROV prov; PCCERT_CONTEXT cert; CMSG_SIGNER_ENCODE_INFO si; } cs_t;
static BOOL cs_init(cs_t *c, BOOL second, const char *hash) {
    memset(c, 0, sizeof *c);
    c->prov = second ? ml_prov(V_KEY2, V_KEY2_LEN) : ml_prov(V_KEY1, V_KEY1_LEN);
    c->cert = second ? ml_cert(V_CERT2, V_CERT2_LEN) : ml_cert(V_CERT1, V_CERT1_LEN);
    if (!c->prov || !c->cert) return FALSE;
    c->si.cbSize = sizeof c->si; c->si.pCertInfo = c->cert->pCertInfo; c->si.hCryptProv = c->prov;
    c->si.dwKeySpec = AT_KEYEXCHANGE; c->si.HashAlgorithm.pszObjId = (LPSTR)hash;
    return TRUE;
}
static void cs_done(cs_t *c) { ml_cert_free(c->cert); ml_prov_release(c->prov); }

#define mCountersign()       UIN("crypt32.dll", CryptMsgCountersign)
#define mCountersignEnc()    UIN("crypt32.dll", CryptMsgCountersignEncoded)
#define mVerifyCounter()     UIN("crypt32.dll", CryptMsgVerifyCountersignatureEncoded)
#define mVerifyCounterEx()   UIN("crypt32.dll", CryptMsgVerifyCountersignatureEncodedEx)
#define REQ_CS() do { REQ_MSG(); if (t_is_wine()) { t_skip("CryptMsgCountersign* are unimplemented under wine"); return; } REQUIRE(t_proc_in("crypt32.dll", "CryptMsgCountersign")); REQUIRE(t_proc_in("crypt32.dll", "CryptMsgCountersignEncoded")); \
    REQUIRE(t_proc_in("crypt32.dll", "CryptMsgVerifyCountersignatureEncoded")); REQUIRE(t_proc_in("crypt32.dll", "CryptMsgVerifyCountersignatureEncodedEx")); } while (0)

/* make a countersignature over signer 0 of the noattr vector with signer cs */
static BYTE *make_counter(cs_t *c, BYTE **signer, DWORD *signer_cb, DWORD *out_cb) {
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    BYTE *r = NULL;
    *signer = NULL;
    if (!m) return NULL;
    *signer = ml_param(m, CMSG_ENCODED_SIGNER, 0, signer_cb);
    if (*signer) {
        DWORD n = 0;
        if (mCountersignEnc()(ENC, *signer, *signer_cb, 1, &c->si, NULL, &n)) {
            r = (BYTE *)LocalAlloc(LPTR, n + 8);
            if (!mCountersignEnc()(ENC, *signer, *signer_cb, 1, &c->si, r, &n)) { LocalFree(r); r = NULL; } else *out_cb = n;
        }
    }
    mClose()(m);
    return r;
}

/* Win10: CryptMsgCountersignEncoded returns an encoded countersignature ATTRIBUTE (OID + SET { SignerInfo }), while the
   Verify calls take the SignerInfo itself.  Returns the SignerInfo (LocalAlloc'd) or NULL. */
static BYTE *cs_signerinfo_of(const BYTE *attr, DWORD cb, DWORD *out_cb) {
    DWORD n = 0; BYTE *r = NULL;
    if (!U(CryptDecodeObject)(X509_ASN_ENCODING | ENC, PKCS_ATTRIBUTE, attr, cb, 0, NULL, &n)) return NULL;
    CRYPT_ATTRIBUTE *a = (CRYPT_ATTRIBUTE *)LocalAlloc(LPTR, n + 8);
    if (a && U(CryptDecodeObject)(X509_ASN_ENCODING | ENC, PKCS_ATTRIBUTE, attr, cb, 0, a, &n) &&
        a->pszObjId && !strcmp(a->pszObjId, OID_COUNTERSIGN) && a->cValue == 1) {
        r = (BYTE *)LocalAlloc(LPTR, a->rgValue[0].cbData + 8);
        if (r) { memcpy(r, a->rgValue[0].pbData, a->rgValue[0].cbData); *out_cb = a->rgValue[0].cbData; }
    }
    if (a) LocalFree(a);
    return r;
}
/* like make_counter, but returns the countersigner's SignerInfo */
static BYTE *make_counter_si(cs_t *c, BYTE **signer, DWORD *signer_cb, DWORD *out_cb) {
    DWORD acb = 0; BYTE *attr = make_counter(c, signer, signer_cb, &acb), *r;
    if (!attr) return NULL;
    r = cs_signerinfo_of(attr, acb, out_cb);
    LocalFree(attr);
    return r;
}

TEST(mlk_encoded_signer_param) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_ENCODED_SIGNER, 0, &n);
    CHECK(b != NULL);
    if (b) {
        CHECK(b[0] == 0x30);
        static const BYTE ver1[] = {0x02,0x01,0x01};
        CHECK(ml_memmem(b, n, ver1, 3) != NULL && ml_memmem(b, n, ver1, 3) < b + 6);
        /* the SignerInfo bytes occur verbatim inside the message */
        CHECK(ml_memmem(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, b, n) != NULL);
        ml_free(b);
    }
    DWORD k = 0; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_ENCODED_SIGNER, 3, NULL, &k));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    mClose()(m);
}
TEST(mlk_countersign_encoded_and_verify) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    BYTE *signer; DWORD scb = 0, ccb = 0;
    BYTE *cnt = make_counter_si(&c, &signer, &scb, &ccb);
    CHECK(cnt != NULL);
    if (cnt) {
        CHECK(cnt[0] == 0x30);
        EXPECT_SUCCEEDS(mVerifyCounter()(0, ENC, signer, scb, cnt, ccb, c.cert->pCertInfo));
        /* the countersignature binds the original signer's signature value */
        PCCERT_CONTEXT c1 = ml_cert(V_CERT1, V_CERT1_LEN);
        EXPECT_FAILS(mVerifyCounter()(0, ENC, signer, scb, cnt, ccb, c1->pCertInfo), ML_INVALID_SIG);
        ml_cert_free(c1);
    }
    ml_free(signer); LocalFree(cnt);
    cs_done(&c);
}
TEST(mlk_countersign_encoded_size_protocol) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    DWORD scb = 0; BYTE *signer = m ? ml_param(m, CMSG_ENCODED_SIGNER, 0, &scb) : NULL;
    CHECK(signer != NULL);
    if (signer) {
        DWORD n = 0;
        SET_ERR(0);
        CHECKF(mCountersignEnc()(ENC, signer, scb, 1, &c.si, NULL, &n), "size query err 0x%lx", GetLastError());
        EXPECT_EQ(n, 319);
        BYTE *buf = (BYTE *)LocalAlloc(LPTR, n + 16);
        DWORD m1 = n - 1; SET_ERR(0);
        CHECK(!mCountersignEnc()(ENC, signer, scb, 1, &c.si, buf, &m1));
        EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(m1, n);
        m1 = n + 16; memset(buf, 0xAA, n + 16);
        CHECK(mCountersignEnc()(ENC, signer, scb, 1, &c.si, buf, &m1));
        EXPECT_EQ(m1, n);
        CHECK(buf[m1] == 0xAA);
        LocalFree(buf);
        ml_free(signer);
    }
    if (m) mClose()(m);
    cs_done(&c);
}
TEST(mlk_countersign_encoded_is_deterministic) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    BYTE *s1, *s2; DWORD a = 0, b = 0, n1 = 0, n2 = 0;
    BYTE *x = make_counter(&c, &s1, &a, &n1), *y = make_counter(&c, &s2, &b, &n2);
    CHECK(x && y && n1 == n2 && !memcmp(x, y, n1) == (c.si.cAuthAttr == 0));
    ml_free(s1); ml_free(s2); LocalFree(x); LocalFree(y);
    cs_done(&c);
}
TEST(mlk_countersign_encoded_bad_args) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    DWORD scb = 0; BYTE *signer = m ? ml_param(m, CMSG_ENCODED_SIGNER, 0, &scb) : NULL;
    CHECK(signer != NULL);
    if (signer) {
        DWORD n = 0;
        SET_ERR(0);
        CHECK(!mCountersignEnc()(0, signer, scb, 1, &c.si, NULL, &n));
        EXPECT_ERR(E_INVALIDARG);
        SET_ERR(0);
        EXPECT_SUCCEEDS(mCountersignEnc()(ENC, signer, scb, 0, &c.si, NULL, &n));   /* Win10 does not reject a zero count */
        c.si.HashAlgorithm.pszObjId = "1.2.3.4";
        SET_ERR(0);
        CHECK(!mCountersignEnc()(ENC, signer, scb, 1, &c.si, NULL, &n));
        EXPECT_ERR(CRYPT_E_UNKNOWN_ALGO);
        c.si.HashAlgorithm.pszObjId = OID_SHA256; c.si.cbSize = 4;
        SET_ERR(0);
        CHECK(!mCountersignEnc()(ENC, signer, scb, 1, &c.si, NULL, &n));
        EXPECT_ERR(E_INVALIDARG);
        c.si.cbSize = sizeof c.si;
        BYTE junk[8] = {1,2,3,4,5,6,7,8};
        EXPECT_FAILS(mCountersignEnc()(ENC, junk, sizeof junk, 1, &c.si, NULL, &n), CRYPT_E_ASN1_BADTAG);
        ml_free(signer);
    }
    if (m) mClose()(m);
    cs_done(&c);
}
TEST(mlk_verify_tampered_signer_info) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    BYTE *signer; DWORD scb = 0, ccb = 0;
    BYTE *cnt = make_counter_si(&c, &signer, &scb, &ccb);
    CHECK(cnt != NULL);
    if (cnt) {
        /* flip a bit inside the original signature value that the countersignature covers */
        HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
        DWORD n = 0; BYTE *si = m ? ml_param(m, CMSG_SIGNER_INFO_PARAM, 0, &n) : NULL;
        if (si) {
            CMSG_SIGNER_INFO *s = (CMSG_SIGNER_INFO *)si;
            const BYTE *p = ml_memmem(signer, scb, s->EncryptedHash.pbData, 128);
            CHECK(p != NULL);
            if (p) {
                ((BYTE *)p)[40] ^= 1;
                EXPECT_FAILS(mVerifyCounter()(0, ENC, signer, scb, cnt, ccb, c.cert->pCertInfo), CRYPT_E_HASH_VALUE);
            }
            ml_free(si);
        }
        if (m) mClose()(m);
    }
    ml_free(signer); LocalFree(cnt);
    cs_done(&c);
}
TEST(mlk_verify_bad_args) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    BYTE *signer; DWORD scb = 0, ccb = 0;
    BYTE *cnt = make_counter_si(&c, &signer, &scb, &ccb);
    CHECK(cnt != NULL);
    if (cnt) {
        SET_ERR(0);
        CHECK(!mVerifyCounter()(0, 0, signer, scb, cnt, ccb, c.cert->pCertInfo));
        EXPECT_ERR(E_INVALIDARG);
        EXPECT_FAILS(mVerifyCounter()(0, ENC, signer, scb, cnt, 3, c.cert->pCertInfo), CRYPT_E_ASN1_EOD);
        EXPECT_FAILS(mVerifyCounter()(0, ENC, signer, 5, cnt, ccb, c.cert->pCertInfo), CRYPT_E_ASN1_EOD);
    }
    ml_free(signer); LocalFree(cnt);
    cs_done(&c);
}
TEST(mlk_verify_ex_signer_types) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    BYTE *signer; DWORD scb = 0, ccb = 0;
    BYTE *cnt = make_counter_si(&c, &signer, &scb, &ccb);
    CHECK(cnt != NULL);
    if (cnt) {
        EXPECT_SUCCEEDS(mVerifyCounterEx()(0, ENC, signer, scb, cnt, ccb, CMSG_VERIFY_SIGNER_CERT, (void *)c.cert, 0, NULL));
        EXPECT_SUCCEEDS(mVerifyCounterEx()(0, ENC, signer, scb, cnt, ccb, CMSG_VERIFY_SIGNER_PUBKEY, (void *)&c.cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL));
        PCCERT_CONTEXT c1 = ml_cert(V_CERT1, V_CERT1_LEN);
        EXPECT_FAILS(mVerifyCounterEx()(0, ENC, signer, scb, cnt, ccb, CMSG_VERIFY_SIGNER_CERT, (void *)c1, 0, NULL), ML_INVALID_SIG);
        EXPECT_FAILS(mVerifyCounterEx()(0, ENC, signer, scb, cnt, ccb, CMSG_VERIFY_SIGNER_PUBKEY, (void *)&c1->pCertInfo->SubjectPublicKeyInfo, 0, NULL), ML_INVALID_SIG);
        ml_cert_free(c1);
        EXPECT_FAILS(mVerifyCounterEx()(0, ENC, signer, scb, cnt, ccb, 99, (void *)c.cert, 0, NULL), E_INVALIDARG);
        EXPECT_SUCCEEDS(mVerifyCounterEx()(0, ENC, signer, scb, cnt, ccb, CMSG_VERIFY_SIGNER_CERT, (void *)c.cert, CMSG_VERIFY_COUNTER_SIGN_ENABLE_STRONG_FLAG, NULL));
    }
    ml_free(signer); LocalFree(cnt);
    cs_done(&c);
}
TEST(mlk_countersign_message) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) { cs_done(&c); return; }
    DWORD scb = 0; BYTE *signer = ml_param(m, CMSG_ENCODED_SIGNER, 0, &scb);
    SET_ERR(0);
    BOOL ok = mCountersign()(m, 0, 1, &c.si);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        /* Win10: CMSG_SIGNER_UNAUTH_ATTR_PARAM stays unavailable after the countersignature was added; SIGNER_INFO shows it */
        DWORD n = 0;
        EXPECT_FAILS(mGetParam()(m, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &n), CRYPT_E_ATTRIBUTES_MISSING);
        BYTE *u = ml_param(m, CMSG_SIGNER_INFO_PARAM, 0, &n);
        CHECK(u != NULL);
        if (u) {
            CRYPT_ATTRIBUTES *at = &((CMSG_SIGNER_INFO *)u)->UnauthAttrs;
            CHECK(at->cAttr == 1 && !strcmp(at->rgAttr[0].pszObjId, OID_COUNTERSIGN));
            if (at->cAttr == 1 && at->rgAttr[0].cValue == 1 && signer) {
                CRYPT_ATTR_BLOB *v = &at->rgAttr[0].rgValue[0];
                EXPECT_SUCCEEDS(mVerifyCounter()(0, ENC, signer, scb, v->pbData, v->cbData, c.cert->pCertInfo));
            }
            ml_free(u);
        }
        DWORD v = 0; CHECK(ml_param_dword(m, CMSG_SIGNER_COUNT_PARAM, 0, &v)); EXPECT_EQ(v, 1);
        PCCERT_CONTEXT c1 = ml_cert(V_CERT1, V_CERT1_LEN);
        SET_ERR(0);
        CHECKF(c1 && mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c1->pCertInfo), "outer signature still valid, err 0x%lx", GetLastError());
        ml_cert_free(c1);
    }
    ml_free(signer);
    mClose()(m);
    cs_done(&c);
}
TEST(mlk_countersign_message_bad_args) {
    cs_t c; REQ_CS();
    if (!cs_init(&c, TRUE, OID_SHA256)) { cs_done(&c); CHECKF(0, "setup failed"); return; }
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (m) {
        SET_ERR(0);
        CHECK(!mCountersign()(m, 4, 1, &c.si));
        EXPECT_ERR(CRYPT_E_INVALID_INDEX);
        mClose()(m);
    }
    HCRYPTMSG d = ml_decode(M_DATA, M_DATA_LEN, 0, 0);
    CHECK(d != NULL);
    if (d) {
        SET_ERR(0);
        CHECK(!mCountersign()(d, 0, 1, &c.si));
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        mClose()(d);
    }
    cs_done(&c);
}
TEST(mlk_countersign_md5_sha1_algorithms) {
    cs_t c; REQ_CS();
    static const char *h[] = {OID_SHA1, OID_MD5, OID_SHA256};
    for (size_t i = 0; i < 3; i++) {
        if (!cs_init(&c, TRUE, h[i])) { cs_done(&c); CHECKF(0, "setup failed"); return; }
        BYTE *signer; DWORD scb = 0, ccb = 0;
        BYTE *cnt = make_counter_si(&c, &signer, &scb, &ccb);
        CHECKF(cnt != NULL, "hash %s err 0x%lx", h[i], GetLastError());
        if (cnt) {
            t_label("hash %s", h[i]);
            EXPECT_SUCCEEDS(mVerifyCounter()(0, ENC, signer, scb, cnt, ccb, c.cert->pCertInfo));
        }
        ml_free(signer); LocalFree(cnt);
        cs_done(&c);
    }
}

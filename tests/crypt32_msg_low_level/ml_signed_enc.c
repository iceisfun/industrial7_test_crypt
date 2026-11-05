/* CMSG_SIGNED encoding: open validation, flags, attributes, certs/CRLs, round trips. */
#include "ml.h"

#define REQ_SIGN(s) do { REQ_MSG(); if (!ml_signer_init(&(s), OID_SHA256)) { ml_signer_done(&(s)); t_skip("cannot set up ephemeral signer (provider/key import)"); return; } } while (0)

static BOOL has_attr(const CRYPT_ATTRIBUTES *a, const char *oid) {
    for (DWORD i = 0; i < a->cAttr; i++) if (a->rgAttr[i].pszObjId && !strcmp(a->rgAttr[i].pszObjId, oid)) return TRUE;
    return FALSE;
}
#define OID_CT "1.2.840.113549.1.9.3"
#define OID_MD "1.2.840.113549.1.9.4"
#define OID_ST "1.2.840.113549.1.9.5"

/* verify first signer of decoded msg with cert 1 */
static BOOL verify1(HCRYPTMSG m) {
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    BOOL r = c && mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pCertInfo);
    { DWORD e_ = GetLastError(); ml_cert_free(c); SetLastError(e_); }
    return r;
}

/* ---------------------------------------------------------------- open validation */
TEST(mls_open_null_info) {
    REQ_MSG();
    if (t_is_wine()) { t_skip("emulator dereferences NULL info"); return; }
    /* Win10 dereferences the NULL encode info (access violation) instead of failing */
    HCRYPTMSG volatile m = NULL;
    T_EXPECT_FAULT(m = mOpenEnc()(ENC, 0, CMSG_SIGNED, NULL, NULL, NULL));
    if (m) mClose()(m);
}
TEST(mls_open_bad_signed_cbsize) {
    ml_signer_t s; REQ_SIGN(s);
    static const DWORD cbs[] = {0, 4, 8};
    for (size_t i = 0; i < 3; i++) {
        s.se.cbSize = cbs[i]; SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
        CHECKF(m == NULL, "cbSize %lu", (unsigned long)cbs[i]);
        if (m) mClose()(m); else EXPECT_ERR(E_INVALIDARG);
    }
    ml_signer_done(&s);
}
TEST(mls_open_bad_signer_cbsize) {
    ml_signer_t s; REQ_SIGN(s);
    static const DWORD cbs[] = {0, 4, 8};
    for (size_t i = 0; i < 3; i++) {
        s.si[0].cbSize = cbs[i]; SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
        CHECKF(m == NULL, "signer cbSize %lu", (unsigned long)cbs[i]);
        if (m) mClose()(m); else EXPECT_ERR(E_INVALIDARG);
    }
    ml_signer_done(&s);
}
TEST(mls_open_unknown_hash_algorithm) {
    ml_signer_t s; REQ_SIGN(s);
    static const char *oids[] = {"1.2.3.4", "1.3.14.3.2.99"};
    for (size_t i = 0; i < 2; i++) {
        s.si[0].HashAlgorithm.pszObjId = (LPSTR)oids[i]; SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
        CHECKF(m == NULL, "oid %s", oids[i]);
        if (m) mClose()(m); else EXPECT_ERR(CRYPT_E_UNKNOWN_ALGO);
    }
    ml_signer_done(&s);
}
TEST(mls_open_signer_without_certinfo) {
    ml_signer_t s; REQ_SIGN(s);
    if (t_is_wine()) { ml_signer_done(&s); t_skip("emulator dereferences NULL pCertInfo"); return; }
    s.si[0].pCertInfo = NULL;
    /* Win10 dereferences the NULL pCertInfo (access violation) instead of failing */
    HCRYPTMSG volatile m = NULL;
    T_EXPECT_FAULT(m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL));
    if (m) mClose()(m);
    ml_signer_done(&s);
}
TEST(mls_open_zero_signers_certs_only) {
    ml_signer_t s; REQ_SIGN(s);
    s.se.cSigners = 0; s.se.rgSigners = NULL;
    s.certblob[0].cbData = V_CERT1_LEN; s.certblob[0].pbData = (BYTE *)V_CERT1;
    s.se.cCertEncoded = 1; s.se.rgCertEncoded = s.certblob;
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, NULL, 0, TRUE));
        DWORD cb = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
        CHECK(b != NULL);
        if (b) {
            HCRYPTMSG d = ml_decode(b, cb, 0, 0);
            CHECK(d != NULL);
            if (d) {
                DWORD n = 99; CHECK(ml_param_dword(d, CMSG_SIGNER_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 0);
                CHECK(ml_param_dword(d, CMSG_CERT_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 1);
                mClose()(d);
            }
        }
        ml_free(b);
        mClose()(m);
    }
    ml_signer_done(&s);
}

/* ---------------------------------------------------------------- basic signing */
TEST(mls_sign_roundtrip_verify) {
    ml_signer_t s; REQ_SIGN(s);
    static const char *h[] = {OID_SHA1, OID_SHA256, OID_MD5};
    for (size_t i = 0; i < 3; i++) {
        DWORD cb = 0; BYTE *b = ml_sign(&s, 0, h[i], V_CONTENT, V_CONTENT_LEN, &cb);
        CHECKF(b != NULL, "hash %s err 0x%lx", h[i], GetLastError());
        if (!b) continue;
        HCRYPTMSG d = ml_decode(b, cb, 0, 0);
        CHECKF(d != NULL, "hash %s", h[i]);
        if (d) {
            DWORD t = 0; CHECK(ml_param_dword(d, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, CMSG_SIGNED);
            SET_ERR(0);
            CHECKF(verify1(d), "verify hash %s err 0x%lx", h[i], GetLastError());
            DWORD n = 0; BYTE *c = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
            CHECK(c && n == V_CONTENT_LEN && !memcmp(c, V_CONTENT, n)); ml_free(c);
            mClose()(d);
        }
        ml_free(b);
    }
    ml_signer_done(&s);
}
TEST(mls_sign_signature_bytes_deterministic) {
    ml_signer_t s; REQ_SIGN(s);
    /* PKCS#1 v1.5 signatures are deterministic: with no authenticated attributes the signature
       over the content digest must appear verbatim (big-endian) in the encoded message. */
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA1, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b != NULL);
    if (b) { CHECK(ml_memmem(b, cb, V_SIG1_SHA1, V_SIG1_SHA1_LEN) != NULL); ml_free(b); }
    b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b != NULL);
    if (b) { CHECK(ml_memmem(b, cb, V_SIG1_SHA256, V_SIG1_SHA256_LEN) != NULL); ml_free(b); }
    ml_signer_done(&s);
}
TEST(mls_sign_twice_identical_without_attrs) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD c1 = 0, c2 = 0; BYTE *a = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &c1);
    BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &c2);
    CHECK(a && b && c1 == c2 && !memcmp(a, b, c1));
    ml_free(a); ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_sign_encoded_structure_head) {
    ml_signer_t s; REQ_SIGN(s);
    static const BYTE signed_oid[] = {0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02};
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b != NULL);
    if (b) {
        CHECK(b[0] == 0x30);
        const BYTE *p = ml_memmem(b, cb, signed_oid, sizeof signed_oid);
        CHECK(p != NULL && p < b + 5);
        CHECK(ml_memmem(b, cb, V_CONTENT, V_CONTENT_LEN) != NULL);   /* attached */
        ml_free(b);
    }
    ml_signer_done(&s);
}
TEST(mls_sign_default_has_no_auth_attrs) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; BYTE *si = ml_param(d, CMSG_SIGNER_INFO_PARAM, 0, &n);
        CHECK(si != NULL);
        if (si) {
            CMSG_SIGNER_INFO *i = (CMSG_SIGNER_INFO *)si;
            EXPECT_EQ(i->dwVersion, 1);
            EXPECT_EQ(i->AuthAttrs.cAttr, 0);
            EXPECT_EQ(i->UnauthAttrs.cAttr, 0);
            CHECK(i->HashAlgorithm.pszObjId && !strcmp(i->HashAlgorithm.pszObjId, OID_SHA256));
            CHECK(i->HashEncryptionAlgorithm.pszObjId && !strcmp(i->HashEncryptionAlgorithm.pszObjId, OID_RSA));
            CHECK(i->EncryptedHash.cbData == 128);
            ml_free(si);
        }
        mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_sign_signerinfo_matches_certificate) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; BYTE *si = ml_param(d, CMSG_SIGNER_INFO_PARAM, 0, &n);
        if (si) {
            CMSG_SIGNER_INFO *i = (CMSG_SIGNER_INFO *)si;
            CHECK(i->Issuer.cbData == s.cert->pCertInfo->Issuer.cbData && !memcmp(i->Issuer.pbData, s.cert->pCertInfo->Issuer.pbData, i->Issuer.cbData));
            CHECK(i->SerialNumber.cbData == s.cert->pCertInfo->SerialNumber.cbData && !memcmp(i->SerialNumber.pbData, s.cert->pCertInfo->SerialNumber.pbData, i->SerialNumber.cbData));
            ml_free(si);
        } else CHECK(si != NULL);
        mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_sign_version_param_is_one) {
    ml_signer_t s; REQ_SIGN(s);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
        DWORD v = 99; CHECK(ml_param_dword(m, CMSG_VERSION_PARAM, 0, &v)); EXPECT_EQ(v, 1);
        mClose()(m);
    }
    ml_signer_done(&s);
}
TEST(mls_sign_empty_content) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, NULL, 0, &cb);
    CHECK(b != NULL);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) { SET_ERR(0); CHECKF(verify1(d), "verify empty: 0x%lx", GetLastError()); mClose()(d); }
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_sign_nonfinal_needs_detached_or_stream) {
    ml_signer_t s; REQ_SIGN(s);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        SET_ERR(0);
        CHECK(!mUpdate()(m, V_CONTENT, 4, FALSE));
        EXPECT_ERR(CRYPT_E_MSG_ERROR);
        mClose()(m);
    }
    ml_signer_done(&s);
}
TEST(mls_sign_content_param_before_update) {
    ml_signer_t s; REQ_SIGN(s);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        DWORD n = 0; SET_ERR(0);
        EXPECT_SUCCEEDS(mGetParam()(m, CMSG_CONTENT_PARAM, 0, NULL, &n));
        EXPECT_EQ(n, 136);
        mClose()(m);
    }
    ml_signer_done(&s);
}
TEST(mls_sign_update_after_final) {
    ml_signer_t s; REQ_SIGN(s);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
        SET_ERR(0);
        CHECK(!mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
        EXPECT_ERR(CRYPT_E_MSG_ERROR);
        mClose()(m);
    }
    ml_signer_done(&s);
}

/* ---------------------------------------------------------------- flags */
TEST(mls_bare_content_flag) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cf = 0, cbare = 0;
    BYTE *full = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cf);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    BYTE *bare = NULL;
    if (m) { CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE)); bare = ml_param(m, CMSG_BARE_CONTENT_PARAM, 0, &cbare); mClose()(m); }
    CHECK(full && bare);
    if (full && bare) {
        CHECK(cbare < cf);
        CHECK(bare[0] == 0x30);
        CHECK(ml_memmem(full, cf, bare, cbare) != NULL);          /* full = ContentInfo { signedData, [0] bare } */
        CHECK(cf - cbare <= 24);
        /* the bare form starts with: SEQUENCE { INTEGER 1 ... } */
        const BYTE ver[] = {0x02,0x01,0x01};
        const BYTE *p = ml_memmem(bare, 8, ver, 3);
        CHECK(p != NULL);
    }
    ml_free(full); ml_free(bare);
    ml_signer_done(&s);
}
TEST(mls_bare_flag_content_param_is_bare) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cf = 0; BYTE *full = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cf);
    DWORD cb = 0; BYTE *b = ml_sign(&s, CMSG_BARE_CONTENT_FLAG, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(full && b);
    if (full && b) { t_note("SIGNED with BARE_CONTENT_FLAG: CONTENT_PARAM %lu bytes vs %lu without flag", (unsigned long)cb, (unsigned long)cf); CHECK(cb <= cf); }
    ml_free(full); ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_detached_flag_omits_content) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cd = 0, ca = 0;
    BYTE *det = ml_sign(&s, CMSG_DETACHED_FLAG, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cd);
    BYTE *att = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &ca);
    CHECK(det && att);
    if (det && att) {
        CHECK(ml_memmem(det, cd, V_CONTENT, 8) == NULL);
        CHECK(ml_memmem(att, ca, V_CONTENT, 8) != NULL);
        CHECK(cd < ca);
        CHECK(ml_memmem(det, cd, V_SIG1_SHA256, V_SIG1_SHA256_LEN) != NULL);   /* same signature either way */
    }
    ml_free(det); ml_free(att);
    ml_signer_done(&s);
}
TEST(mls_detached_chunked_updates) {
    ml_signer_t s; REQ_SIGN(s);
    HCRYPTMSG m = mOpenEnc()(ENC, CMSG_DETACHED_FLAG, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        DWORD off = 0;
        while (off + 7 < V_CONTENT_LEN) { CHECKF(mUpdate()(m, V_CONTENT + off, 7, FALSE), "off %lu err 0x%lx", (unsigned long)off, GetLastError()); off += 7; }
        CHECK(mUpdate()(m, V_CONTENT + off, V_CONTENT_LEN - off, TRUE));
        DWORD cb = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
        CHECK(b != NULL);
        if (b) { CHECK(ml_memmem(b, cb, V_SIG1_SHA256, V_SIG1_SHA256_LEN) != NULL); }
        ml_free(b);
        mClose()(m);
    }
    ml_signer_done(&s);
}
TEST(mls_detached_verify_with_separate_content) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = ml_sign(&s, CMSG_DETACHED_FLAG, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b != NULL);
    if (b) {
        HCRYPTMSG d = mOpenDec()(ENC, CMSG_DETACHED_FLAG, 0, 0, NULL, NULL);
        CHECK(d != NULL);
        if (d) {
            CHECK(mUpdate()(d, b, cb, TRUE));
            CHECK(mUpdate()(d, V_CONTENT, V_CONTENT_LEN, TRUE));
            SET_ERR(0);
            CHECKF(verify1(d), "verify detached err 0x%lx", GetLastError());
            mClose()(d);
        }
        /* wrong detached content */
        d = mOpenDec()(ENC, CMSG_DETACHED_FLAG, 0, 0, NULL, NULL);
        if (d) {
            BYTE bad[64]; memcpy(bad, V_CONTENT, V_CONTENT_LEN); bad[3] ^= 1;
            CHECK(mUpdate()(d, b, cb, TRUE));
            CHECK(mUpdate()(d, bad, V_CONTENT_LEN, TRUE));
            SET_ERR(0);
            CHECK(!verify1(d));
            t_note("detached verify with altered content: err 0x%lx", (unsigned long)GetLastError());
            mClose()(d);
        }
    }
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_cms_encapsulated_content_flag) {
    ml_signer_t s; REQ_SIGN(s);
    static const BYTE xyz[3] = {'x','y','z'};
    static const BYTE octets[] = {0x04,0x03,'x','y','z'};
    static const BYTE oid[] = {0x06,0x05,0x2a,0x03,0x04,0x05,0x06};
    HCRYPTMSG m = mOpenEnc()(ENC, CMSG_CMS_ENCAPSULATED_CONTENT_FLAG, CMSG_SIGNED, &s.se, "1.2.3.4.5.6", NULL);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, xyz, 3, TRUE));
        DWORD cb = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
        CHECK(b != NULL);
        if (b) {
            CHECK(ml_memmem(b, cb, octets, sizeof octets) != NULL);
            CHECK(ml_memmem(b, cb, oid, sizeof oid) != NULL);
            HCRYPTMSG d = ml_decode(b, cb, 0, 0);
            CHECK(d != NULL);
            if (d) {
                DWORD n = 0; BYTE *it = ml_param(d, CMSG_INNER_CONTENT_TYPE_PARAM, 0, &n);
                CHECK(it && !strcmp((char *)it, "1.2.3.4.5.6")); ml_free(it);
                SET_ERR(0);
                CHECKF(verify1(d), "verify err 0x%lx", GetLastError());
                DWORD v = 0; if (ml_param_dword(d, CMSG_VERSION_PARAM, 0, &v)) t_note("CMS encapsulated non-data content: version %lu", (unsigned long)v);
                mClose()(d);
            }
        }
        ml_free(b);
        mClose()(m);
    }
    ml_signer_done(&s);
}
TEST(mls_inner_oid_default_is_data) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; BYTE *it = ml_param(d, CMSG_INNER_CONTENT_TYPE_PARAM, 0, &n);
        CHECK(it && !strcmp((char *)it, OID_DATA));
        EXPECT_EQ(n, strlen(OID_DATA) + 1);
        ml_free(it); mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}

/* ---------------------------------------------------------------- attributes */
static BYTE *sign_attr(ml_signer_t *s, DWORD flags, BOOL auth, BOOL unauth, DWORD *cb) {
    static BYTE val[] = {0x04,0x02,0xAB,0xCD};
    s->attrval.cbData = sizeof val; s->attrval.pbData = val;
    s->attr.pszObjId = "1.2.3.4.5.77"; s->attr.cValue = 1; s->attr.rgValue = &s->attrval;
    s->si[0].cAuthAttr = auth ? 1 : 0; s->si[0].rgAuthAttr = auth ? &s->attr : NULL;
    s->si[0].cUnauthAttr = unauth ? 1 : 0; s->si[0].rgUnauthAttr = unauth ? &s->attr : NULL;
    return ml_sign(s, flags, OID_SHA256, V_CONTENT, V_CONTENT_LEN, cb);
}
TEST(mls_authenticated_attributes_flag) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = ml_sign(&s, CMSG_AUTHENTICATED_ATTRIBUTES_FLAG, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b != NULL);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; BYTE *a = ml_param(d, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, &n);
        CHECK(a != NULL);
        if (a) {
            CRYPT_ATTRIBUTES *at = (CRYPT_ATTRIBUTES *)a;
            CHECK(at->cAttr >= 2);
            CHECK(has_attr(at, OID_CT)); CHECK(has_attr(at, OID_MD));
            ml_free(a);
        }
        SET_ERR(0);
        CHECKF(verify1(d), "verify err 0x%lx", GetLastError());
        mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_auth_attr_changes_signature_input) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = ml_sign(&s, CMSG_AUTHENTICATED_ATTRIBUTES_FLAG, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b != NULL);
    if (b) { CHECK(ml_memmem(b, cb, V_SIG1_SHA256, V_SIG1_SHA256_LEN) == NULL); ml_free(b); }   /* signs the attribute set, not the content */
    ml_signer_done(&s);
}
TEST(mls_auth_attr_messagedigest_value) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = ml_sign(&s, CMSG_AUTHENTICATED_ATTRIBUTES_FLAG, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; BYTE *a = ml_param(d, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, &n);
        if (a) {
            CRYPT_ATTRIBUTES *at = (CRYPT_ATTRIBUTES *)a;
            for (DWORD i = 0; i < at->cAttr; i++) if (!strcmp(at->rgAttr[i].pszObjId, OID_MD)) {
                CHECK(at->rgAttr[i].cValue == 1);
                CRYPT_ATTR_BLOB *v = &at->rgAttr[i].rgValue[0];
                CHECK(v->cbData == V_SHA256_LEN + 2 && v->pbData[0] == 0x04 && v->pbData[1] == V_SHA256_LEN && !memcmp(v->pbData + 2, V_SHA256, V_SHA256_LEN));
            }
            ml_free(a);
        } else CHECK(a != NULL);
        mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_user_auth_attribute) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = sign_attr(&s, 0, TRUE, FALSE, &cb);
    CHECK(b != NULL);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; BYTE *a = ml_param(d, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, &n);
        CHECK(a != NULL);
        if (a) {
            CRYPT_ATTRIBUTES *at = (CRYPT_ATTRIBUTES *)a;
            CHECK(has_attr(at, "1.2.3.4.5.77"));
            CHECK(has_attr(at, OID_CT)); CHECK(has_attr(at, OID_MD));   /* mandatory attributes are added */
            ml_free(a);
        }
        SET_ERR(0);
        CHECKF(verify1(d), "verify err 0x%lx", GetLastError());
        mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_user_unauth_attribute) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD cb = 0; BYTE *b = sign_attr(&s, 0, FALSE, TRUE, &cb);
    CHECK(b != NULL);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; BYTE *a = ml_param(d, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, &n);
        CHECK(a != NULL);
        if (a) {
            CRYPT_ATTRIBUTES *at = (CRYPT_ATTRIBUTES *)a;
            CHECK(at->cAttr == 1 && has_attr(at, "1.2.3.4.5.77"));
            if (at->cAttr == 1) CHECK(at->rgAttr[0].cValue == 1 && at->rgAttr[0].rgValue[0].cbData == 4 && at->rgAttr[0].rgValue[0].pbData[2] == 0xAB);
            ml_free(a);
        }
        /* without authenticated attributes the unauthenticated ones do not change the signature */
        CHECK(verify1(d));
        mClose()(d);
    }
    if (b) CHECK(ml_memmem(b, cb, V_SIG1_SHA256, V_SIG1_SHA256_LEN) != NULL);
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_unauth_attr_not_in_signature) {
    ml_signer_t s; REQ_SIGN(s);
    DWORD c1 = 0, c2 = 0;
    BYTE *a = sign_attr(&s, CMSG_AUTHENTICATED_ATTRIBUTES_FLAG, FALSE, FALSE, &c1);
    BYTE *b = sign_attr(&s, CMSG_AUTHENTICATED_ATTRIBUTES_FLAG, FALSE, TRUE, &c2);
    CHECK(a && b && c2 > c1);
    if (a && b) {
        const BYTE *sig = ml_memmem(a, c1, V_SIG1_SHA256, 1);   /* locate by decoding instead */
        (void)sig;
        HCRYPTMSG da = ml_decode(a, c1, 0, 0), db = ml_decode(b, c2, 0, 0);
        CHECK(da && db);
        if (da && db) {
            DWORD na = 0, nb = 0; BYTE *sa = ml_param(da, CMSG_SIGNER_INFO_PARAM, 0, &na), *sb = ml_param(db, CMSG_SIGNER_INFO_PARAM, 0, &nb);
            if (sa && sb) {
                CMSG_SIGNER_INFO *ia = (CMSG_SIGNER_INFO *)sa, *ib = (CMSG_SIGNER_INFO *)sb;
                CHECK(ia->EncryptedHash.cbData == ib->EncryptedHash.cbData && !memcmp(ia->EncryptedHash.pbData, ib->EncryptedHash.pbData, ia->EncryptedHash.cbData));
            } else CHECK(sa && sb);
            ml_free(sa); ml_free(sb);
        }
        if (da) mClose()(da);
        if (db) mClose()(db);
    }
    ml_free(a); ml_free(b);
    ml_signer_done(&s);
}

/* ---------------------------------------------------------------- certificates and CRLs */
TEST(mls_embedded_cert_and_crl_params) {
    ml_signer_t s; REQ_SIGN(s);
    CERT_BLOB cb1[2] = {{V_CERT1_LEN, (BYTE *)V_CERT1}, {V_CERT2_LEN, (BYTE *)V_CERT2}};
    CRL_BLOB crl = {V_CRL1_LEN, (BYTE *)V_CRL1};
    s.se.cCertEncoded = 2; s.se.rgCertEncoded = cb1;
    s.se.cCrlEncoded = 1; s.se.rgCrlEncoded = &crl;
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_SIGNED, &s.se, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
        DWORD cb = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
        HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
        CHECK(d != NULL);
        if (d) {
            DWORD n = 0, k = 0;
            CHECK(ml_param_dword(d, CMSG_CERT_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 2);
            CHECK(ml_param_dword(d, CMSG_CRL_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 1);
            BYTE *c0 = ml_param(d, CMSG_CERT_PARAM, 0, &k);
            CHECK(c0 && k == V_CERT1_LEN && !memcmp(c0, V_CERT1, k)); ml_free(c0);
            c0 = ml_param(d, CMSG_CERT_PARAM, 1, &k);
            CHECK(c0 && k == V_CERT2_LEN && !memcmp(c0, V_CERT2, k)); ml_free(c0);
            c0 = ml_param(d, CMSG_CRL_PARAM, 0, &k);
            CHECK(c0 && k == V_CRL1_LEN && !memcmp(c0, V_CRL1, k)); ml_free(c0);
            SET_ERR(0);
            CHECK(!mGetParam()(d, CMSG_CERT_PARAM, 2, NULL, &k));
            EXPECT_ERR(0);   /* Win10 fails without setting an error code */
            SET_ERR(0);
            CHECK(!mGetParam()(d, CMSG_CRL_PARAM, 1, NULL, &k));
            EXPECT_ERR(0);   /* Win10 fails without setting an error code */
            mClose()(d);
        }
        ml_free(b);
        mClose()(m);
    }
    ml_signer_done(&s);
}
TEST(mls_cert_order_preserved) {
    ml_signer_t s; REQ_SIGN(s);
    CERT_BLOB cb1[2] = {{V_CERT2_LEN, (BYTE *)V_CERT2}, {V_CERT1_LEN, (BYTE *)V_CERT1}};
    s.se.cCertEncoded = 2; s.se.rgCertEncoded = cb1;
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD k = 0; BYTE *c0 = ml_param(d, CMSG_CERT_PARAM, 0, &k);
        CHECK(c0 != NULL);
        if (c0) t_note("certificate order in SET: first is %s", k == V_CERT2_LEN && !memcmp(c0, V_CERT2, k) ? "as supplied" : "reordered");
        ml_free(c0); mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}

/* ---------------------------------------------------------------- two signers */
static BOOL two_signers(ml_signer_t *s) {
    if (t_is_wine()) return FALSE;   /* emulator rejects more than one signer */
    s->prov2 = ml_prov(V_KEY2, V_KEY2_LEN);
    s->cert2 = ml_cert(V_CERT2, V_CERT2_LEN);
    if (!s->prov2 || !s->cert2) return FALSE;
    s->si[1] = s->si[0];
    s->si[1].pCertInfo = s->cert2->pCertInfo;
    s->si[1].hCryptProv = s->prov2;
    s->se.cSigners = 2;
    return TRUE;
}
TEST(mls_two_signers) {
    ml_signer_t s; REQ_SIGN(s);
    if (!two_signers(&s)) { ml_signer_done(&s); t_skip("second signer setup failed"); return; }
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; CHECK(ml_param_dword(d, CMSG_SIGNER_COUNT_PARAM, 0, &n)); EXPECT_EQ(n, 2);
        CHECK(verify1(d));
        CHECK(mControl()(d, 0, CMSG_CTRL_VERIFY_SIGNATURE, s.cert2->pCertInfo));
        for (DWORD i = 0; i < 2; i++) {
            DWORD k = 0; BYTE *si = ml_param(d, CMSG_SIGNER_INFO_PARAM, i, &k);
            CHECKF(si != NULL, "signer %lu", (unsigned long)i);
            if (si) {
                CMSG_SIGNER_INFO *x = (CMSG_SIGNER_INFO *)si;
                PCERT_INFO ci = i == 0 ? s.cert->pCertInfo : s.cert2->pCertInfo;
                CHECK(x->SerialNumber.cbData == ci->SerialNumber.cbData && !memcmp(x->SerialNumber.pbData, ci->SerialNumber.pbData, x->SerialNumber.cbData));
                ml_free(si);
            }
        }
        SET_ERR(0);
        DWORD k = 0;
        CHECK(!mGetParam()(d, CMSG_SIGNER_INFO_PARAM, 2, NULL, &k));
        EXPECT_ERR(CRYPT_E_INVALID_INDEX);
        mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}
TEST(mls_two_signers_verify_ex_by_index) {
    ml_signer_t s; REQ_SIGN(s);
    if (!two_signers(&s)) { ml_signer_done(&s); t_skip("second signer setup failed"); return; }
    DWORD cb = 0; BYTE *b = ml_sign(&s, 0, OID_SHA256, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA p; memset(&p, 0, sizeof p);
        p.cbSize = sizeof p; p.dwSignerType = CMSG_VERIFY_SIGNER_CERT;
        for (DWORD i = 0; i < 2; i++) {
            p.dwSignerIndex = i; p.pvSigner = (void *)(i == 0 ? s.cert : s.cert2);
            SET_ERR(0);
            CHECKF(mControl()(d, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p), "index %lu err 0x%lx", (unsigned long)i, GetLastError());
        }
        /* signer 0 verified against signer 1's certificate must fail */
        p.dwSignerIndex = 0; p.pvSigner = (void *)s.cert2;
        SET_ERR(0);
        CHECK(!mControl()(d, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p));
        t_note("VERIFY_SIGNATURE_EX signer0 vs cert2: err 0x%lx", (unsigned long)GetLastError());
        mClose()(d);
    }
    ml_free(b);
    ml_signer_done(&s);
}

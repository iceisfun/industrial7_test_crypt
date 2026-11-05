/* CMSG_SIGNED decoding of externally produced messages, parameters, verification. */
#include "ml.h"

typedef struct { const char *name; const BYTE *der; DWORD n; BOOL attrs; BOOL detached; BOOL certs; const char *hash; } svec_t;
static const svec_t SV[] = {
    {"attr",         M_SIGNED_ATTR,           M_SIGNED_ATTR_LEN,           TRUE,  FALSE, TRUE,  OID_SHA256},
    {"noattr",       M_SIGNED_NOATTR,         M_SIGNED_NOATTR_LEN,         FALSE, FALSE, TRUE,  OID_SHA256},
    {"noattr_sha1",  M_SIGNED_NOATTR_SHA1,    M_SIGNED_NOATTR_SHA1_LEN,    FALSE, FALSE, TRUE,  OID_SHA1},
    {"nocerts",      M_SIGNED_NOCERTS,        M_SIGNED_NOCERTS_LEN,        TRUE,  FALSE, FALSE, OID_SHA256},
    {"detached",     M_SIGNED_DETACHED,       M_SIGNED_DETACHED_LEN,       TRUE,  TRUE,  TRUE,  OID_SHA256},
    {"det_noattr",   M_SIGNED_DETACHED_NOATTR,M_SIGNED_DETACHED_NOATTR_LEN,FALSE, TRUE,  TRUE,  OID_SHA256},
};
#define NSV (sizeof SV / sizeof *SV)

static HCRYPTMSG open_sv(const svec_t *v) {
    HCRYPTMSG m = mOpenDec()(ENC, v->detached ? CMSG_DETACHED_FLAG : 0, 0, 0, NULL, NULL);
    if (!m) return NULL;
    if (!mUpdate()(m, v->der, v->n, TRUE) || (v->detached && !mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE))) { mClose()(m); return NULL; }
    return m;
}
static BOOL verify_with(HCRYPTMSG m, const BYTE *cert, DWORD cb) {
    PCCERT_CONTEXT c = ml_cert(cert, cb);
    BOOL r = c && mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pCertInfo);
    ml_cert_free(c);
    return r;
}

TEST(mlsd_decode_all_vectors_open) {
    REQ_MSG();
    for (size_t i = 0; i < NSV; i++) {
        HCRYPTMSG m = open_sv(&SV[i]);
        CHECKF(m != NULL, "%s err 0x%lx", SV[i].name, GetLastError());
        if (m) mClose()(m);
    }
}
TEST(mlsd_type_and_counts) {
    REQ_MSG();
    for (size_t i = 0; i < NSV; i++) {
        HCRYPTMSG m = open_sv(&SV[i]);
        if (!m) { CHECKF(m != NULL, "%s", SV[i].name); continue; }
        DWORD v = 0;
        CHECKF(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &v) && v == CMSG_SIGNED, "%s", SV[i].name);
        CHECKF(ml_param_dword(m, CMSG_SIGNER_COUNT_PARAM, 0, &v) && v == 1, "%s", SV[i].name);
        CHECKF(ml_param_dword(m, CMSG_CERT_COUNT_PARAM, 0, &v) && v == (SV[i].certs ? 1 : 0), "%s", SV[i].name);
        CHECKF(ml_param_dword(m, CMSG_CRL_COUNT_PARAM, 0, &v) && v == 0, "%s", SV[i].name);
        CHECKF(ml_param_dword(m, CMSG_VERSION_PARAM, 0, &v) && v == 1, "%s", SV[i].name);
        mClose()(m);
    }
}
TEST(mlsd_verify_all_vectors) {
    REQ_MSG();
    for (size_t i = 0; i < NSV; i++) {
        HCRYPTMSG m = open_sv(&SV[i]);
        if (!m) { CHECKF(m != NULL, "%s", SV[i].name); continue; }
        SET_ERR(0);
        CHECKF(verify_with(m, V_CERT1, V_CERT1_LEN), "%s err 0x%lx", SV[i].name, GetLastError());
        mClose()(m);
    }
}
TEST(mlsd_content_param) {
    REQ_MSG();
    for (size_t i = 0; i < NSV; i++) {
        HCRYPTMSG m = open_sv(&SV[i]);
        if (!m) { CHECKF(m != NULL, "%s", SV[i].name); continue; }
        DWORD n = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
        if (SV[i].detached) { t_note("%s: CONTENT_PARAM after supplying detached content: %lu bytes", SV[i].name, (unsigned long)(b ? n : 0)); ml_free(b); mClose()(m); continue; }
        CHECKF(b && n == V_CONTENT_LEN && !memcmp(b, V_CONTENT, n), "%s (%lu bytes)", SV[i].name, (unsigned long)n);
        ml_free(b);
        mClose()(m);
    }
}
TEST(mlsd_signer_info_fields) {
    REQ_MSG();
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    REQUIRE(c);
    for (size_t i = 0; i < NSV; i++) {
        HCRYPTMSG m = open_sv(&SV[i]);
        if (!m) { CHECKF(m != NULL, "%s", SV[i].name); continue; }
        DWORD n = 0; BYTE *b = ml_param(m, CMSG_SIGNER_INFO_PARAM, 0, &n);
        CHECKF(b != NULL, "%s", SV[i].name);
        if (b) {
            CMSG_SIGNER_INFO *s = (CMSG_SIGNER_INFO *)b;
            CHECKF(s->dwVersion == 1, "%s", SV[i].name);
            CHECKF(s->Issuer.cbData == c->pCertInfo->Issuer.cbData && !memcmp(s->Issuer.pbData, c->pCertInfo->Issuer.pbData, s->Issuer.cbData), "%s issuer", SV[i].name);
            CHECKF(s->SerialNumber.cbData == c->pCertInfo->SerialNumber.cbData && !memcmp(s->SerialNumber.pbData, c->pCertInfo->SerialNumber.pbData, s->SerialNumber.cbData), "%s serial", SV[i].name);
            CHECKF(s->HashAlgorithm.pszObjId && !strcmp(s->HashAlgorithm.pszObjId, SV[i].hash), "%s hash alg", SV[i].name);
            CHECKF(s->HashEncryptionAlgorithm.pszObjId && !strcmp(s->HashEncryptionAlgorithm.pszObjId, OID_RSA), "%s enc alg %s", SV[i].name, s->HashEncryptionAlgorithm.pszObjId ? s->HashEncryptionAlgorithm.pszObjId : "(null)");
            CHECKF(s->EncryptedHash.cbData == 128, "%s sig len", SV[i].name);
            if (SV[i].attrs) CHECKF(s->AuthAttrs.cAttr >= 3, "%s auth attrs %lu", SV[i].name, (unsigned long)s->AuthAttrs.cAttr);
            else CHECKF(s->AuthAttrs.cAttr == 0, "%s", SV[i].name);
            CHECKF(s->UnauthAttrs.cAttr == 0, "%s", SV[i].name);
            ml_free(b);
        }
        mClose()(m);
    }
    ml_cert_free(c);
}
TEST(mlsd_signer_info_encrypted_hash_byte_order) {
    REQ_MSG();
    /* the EncryptedHash blob of CMSG_SIGNER_INFO is the signature in wire order or reversed: record which */
    HCRYPTMSG m = open_sv(&SV[1]);
    if (!m) { CHECK(m != NULL); return; }
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_SIGNER_INFO_PARAM, 0, &n);
    CHECK(b != NULL);
    if (b) {
        CMSG_SIGNER_INFO *s = (CMSG_SIGNER_INFO *)b;
        BOOL same = s->EncryptedHash.cbData == V_SIG1_SHA256_LEN && !memcmp(s->EncryptedHash.pbData, V_SIG1_SHA256, V_SIG1_SHA256_LEN);
        BYTE rev[128]; for (int i = 0; i < 128; i++) rev[i] = V_SIG1_SHA256[127 - i];
        BOOL r = s->EncryptedHash.cbData == 128 && !memcmp(s->EncryptedHash.pbData, rev, 128);
        CHECK(same || r);
        t_note("CMSG_SIGNER_INFO.EncryptedHash byte order: %s", same ? "wire (big-endian)" : r ? "reversed (little-endian)" : "other");
        ml_free(b);
    }
    mClose()(m);
}
TEST(mlsd_signer_info_attr_oids) {
    REQ_MSG();
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); return; }
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, &n);
    CHECK(b != NULL);
    if (b) {
        CRYPT_ATTRIBUTES *a = (CRYPT_ATTRIBUTES *)b;
        int ct = 0, md = 0, st = 0;
        for (DWORD i = 0; i < a->cAttr; i++) {
            if (!strcmp(a->rgAttr[i].pszObjId, "1.2.840.113549.1.9.3")) ct++;
            if (!strcmp(a->rgAttr[i].pszObjId, "1.2.840.113549.1.9.4")) md++;
            if (!strcmp(a->rgAttr[i].pszObjId, "1.2.840.113549.1.9.5")) st++;
            CHECKF(a->rgAttr[i].cValue >= 1, "attr %lu has values", (unsigned long)i);
        }
        CHECK(ct == 1 && md == 1 && st == 1);
        for (DWORD i = 0; i < a->cAttr; i++) if (!strcmp(a->rgAttr[i].pszObjId, "1.2.840.113549.1.9.4")) {
            CRYPT_ATTR_BLOB *v = &a->rgAttr[i].rgValue[0];
            CHECK(v->cbData == 34 && v->pbData[0] == 4 && v->pbData[1] == 32 && !memcmp(v->pbData + 2, V_SHA256, 32));
        }
        ml_free(b);
    }
    mClose()(m);
}
TEST(mlsd_missing_attrs_error) {
    REQ_MSG();
    HCRYPTMSG m = open_sv(&SV[1]);   /* no authenticated attributes */
    if (!m) { CHECK(m != NULL); return; }
    DWORD n = 0xdeadbeef; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_SIGNER_AUTH_ATTR_PARAM, 0, NULL, &n));
    EXPECT_ERR(CRYPT_E_ATTRIBUTES_MISSING);
    EXPECT_EQ(n, 0);
    n = 0xdeadbeef; SET_ERR(0);
    BOOL ok = mGetParam()(m, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &n);
    CHECK(!ok);
    if (!ok) EXPECT_ERR(CRYPT_E_ATTRIBUTES_MISSING);
    mClose()(m);
}
TEST(mlsd_signer_cert_info_param) {
    REQ_MSG();
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    REQUIRE(c);
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); ml_cert_free(c); return; }
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_SIGNER_CERT_INFO_PARAM, 0, &n);
    CHECK(b != NULL);
    if (b) {
        CERT_INFO *ci = (CERT_INFO *)b;
        CHECK(ci->Issuer.cbData == c->pCertInfo->Issuer.cbData && !memcmp(ci->Issuer.pbData, c->pCertInfo->Issuer.pbData, ci->Issuer.cbData));
        CHECK(ci->SerialNumber.cbData == c->pCertInfo->SerialNumber.cbData && !memcmp(ci->SerialNumber.pbData, c->pCertInfo->SerialNumber.pbData, ci->SerialNumber.cbData));
        ml_free(b);
    }
    mClose()(m);
    ml_cert_free(c);
}
TEST(mlsd_signer_cert_id_param) {
    REQ_MSG();
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    REQUIRE(c);
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); ml_cert_free(c); return; }
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_SIGNER_CERT_ID_PARAM, 0, &n);
    CHECK(b != NULL);
    if (b) {
        CERT_ID *id = (CERT_ID *)b;
        EXPECT_EQ(id->dwIdChoice, CERT_ID_ISSUER_SERIAL_NUMBER);
        CHECK(id->IssuerSerialNumber.Issuer.cbData == c->pCertInfo->Issuer.cbData && !memcmp(id->IssuerSerialNumber.Issuer.pbData, c->pCertInfo->Issuer.pbData, id->IssuerSerialNumber.Issuer.cbData));
        CHECK(id->IssuerSerialNumber.SerialNumber.cbData == c->pCertInfo->SerialNumber.cbData);
        ml_free(b);
    }
    mClose()(m);
    ml_cert_free(c);
}
TEST(mlsd_cms_signer_info_param) {
    REQ_MSG();
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); return; }
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_CMS_SIGNER_INFO_PARAM, 0, &n);
    CHECK(b != NULL);
    if (b) {
        CMSG_CMS_SIGNER_INFO *s = (CMSG_CMS_SIGNER_INFO *)b;
        EXPECT_EQ(s->dwVersion, 1);
        EXPECT_EQ(s->SignerId.dwIdChoice, CERT_ID_ISSUER_SERIAL_NUMBER);
        CHECK(s->HashAlgorithm.pszObjId && !strcmp(s->HashAlgorithm.pszObjId, OID_SHA256));
        CHECK(s->EncryptedHash.cbData == 128);
        ml_free(b);
    }
    mClose()(m);
}
TEST(mlsd_signer_hash_algorithm_param) {
    REQ_MSG();
    for (size_t i = 0; i < NSV; i++) {
        HCRYPTMSG m = open_sv(&SV[i]);
        if (!m) { CHECKF(m != NULL, "%s", SV[i].name); continue; }
        DWORD n = 0; BYTE *b = ml_param(m, CMSG_SIGNER_HASH_ALGORITHM_PARAM, 0, &n);
        CHECKF(b && ((CRYPT_ALGORITHM_IDENTIFIER *)b)->pszObjId && !strcmp(((CRYPT_ALGORITHM_IDENTIFIER *)b)->pszObjId, SV[i].hash), "%s", SV[i].name);
        ml_free(b);
        mClose()(m);
    }
}
TEST(mlsd_cert_param_bytes) {
    REQ_MSG();
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); return; }
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_CERT_PARAM, 0, &n);
    CHECK(b && n == V_CERT1_LEN && !memcmp(b, V_CERT1, n));
    ml_free(b);
    SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_CERT_PARAM, 1, NULL, &n));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_CRL_PARAM, 0, NULL, &n));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    mClose()(m);
}
TEST(mlsd_bad_indexes) {
    REQ_MSG();
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); return; }
    static const DWORD pt[] = {CMSG_SIGNER_INFO_PARAM, CMSG_SIGNER_CERT_INFO_PARAM, CMSG_CERT_PARAM};
    for (size_t i = 0; i < sizeof pt / sizeof *pt; i++) {
        DWORD n = 0; SET_ERR(0);
        CHECKF(!mGetParam()(m, pt[i], 7, NULL, &n), "param %lu", (unsigned long)pt[i]);
        EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    }
    static const DWORD pn[] = {CMSG_SIGNER_HASH_ALGORITHM_PARAM, CMSG_SIGNER_AUTH_ATTR_PARAM, CMSG_SIGNER_UNAUTH_ATTR_PARAM, CMSG_SIGNER_CERT_ID_PARAM};
    for (size_t i = 0; i < sizeof pn / sizeof *pn; i++) {
        DWORD n = 0; SET_ERR(0);
        BOOL ok = mGetParam()(m, pn[i], 7, NULL, &n);
        CHECKF(!ok, "param %lu", (unsigned long)pn[i]);
        t_note("signer param %lu with index 7: err 0x%lx", (unsigned long)pn[i], (unsigned long)GetLastError());
    }
    mClose()(m);
}
TEST(mlsd_two_signer_vector) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_TWO, M_SIGNED_TWO_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD v = 0;
    CHECK(ml_param_dword(m, CMSG_SIGNER_COUNT_PARAM, 0, &v)); EXPECT_EQ(v, 2);
    CHECK(ml_param_dword(m, CMSG_CERT_COUNT_PARAM, 0, &v)); EXPECT_EQ(v, 2);
    SET_ERR(0);
    CHECKF(verify_with(m, V_CERT1, V_CERT1_LEN), "err 0x%lx", GetLastError());
    SET_ERR(0);
    CHECKF(verify_with(m, V_CERT2, V_CERT2_LEN), "err 0x%lx", GetLastError());
    mClose()(m);
}
TEST(mlsd_eku_inner_content_type) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_ECT, M_SIGNED_ECT_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD n = 0; BYTE *b = ml_param(m, CMSG_INNER_CONTENT_TYPE_PARAM, 0, &n);
    CHECK(b && !strcmp((char *)b, "1.2.3.4.5.6"));
    ml_free(b);
    b = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
    CHECK(b != NULL);
    if (b) {
        t_note("non-data inner content: CONTENT_PARAM %lu bytes (plaintext %d)", (unsigned long)n, V_CONTENT_LEN);
        CHECK(ml_memmem(b, n, V_CONTENT, V_CONTENT_LEN) != NULL);
        ml_free(b);
    }
    SET_ERR(0);
    CHECKF(verify_with(m, V_CERT1, V_CERT1_LEN), "err 0x%lx", GetLastError());
    mClose()(m);
}

/* ---------------------------------------------------------------- verification failures */
TEST(mlsd_verify_unknown_signer_cert) {
    REQ_MSG();
    for (size_t i = 0; i < NSV; i++) {
        HCRYPTMSG m = open_sv(&SV[i]);
        if (!m) continue;
        SET_ERR(0);
        CHECKF(!verify_with(m, V_CERT2, V_CERT2_LEN), "%s", SV[i].name);
        EXPECT_ERR(CRYPT_E_SIGNER_NOT_FOUND);
        mClose()(m);
    }
}
TEST(mlsd_verify_empty_cert_info) {
    REQ_MSG();
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); return; }
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, &ci));
    EXPECT_ERR(CRYPT_E_SIGNER_NOT_FOUND);
    mClose()(m);
}
static BYTE *dup_vec(const BYTE *p, DWORD n) { BYTE *c = (BYTE *)LocalAlloc(LPTR, n); memcpy(c, p, n); return c; }
TEST(mlsd_tampered_content_attr_vs_noattr_errors) {
    REQ_MSG();
    /* attached content altered inside the message */
    for (size_t i = 0; i < 3; i++) {
        BYTE *c = dup_vec(SV[i].der, SV[i].n);
        const BYTE *p = ml_memmem(c, SV[i].n, V_CONTENT, V_CONTENT_LEN);
        CHECKF(p != NULL, "%s", SV[i].name);
        if (!p) { LocalFree(c); continue; }
        ((BYTE *)p)[5] ^= 0x01;
        HCRYPTMSG m = ml_decode(c, SV[i].n, 0, 0);
        CHECKF(m != NULL, "%s", SV[i].name);
        if (m) {
            SET_ERR(0);
            CHECKF(!verify_with(m, V_CERT1, V_CERT1_LEN), "%s", SV[i].name);
            DWORD e = GetLastError();
            if (SV[i].attrs) CHECKF(e == (DWORD)CRYPT_E_HASH_VALUE, "%s err 0x%lx", SV[i].name, (unsigned long)e);
            else CHECKF(e == (DWORD)NTE_BAD_SIGNATURE, "%s err 0x%lx", SV[i].name, (unsigned long)e);
            mClose()(m);
        }
        LocalFree(c);
    }
}
TEST(mlsd_tampered_signature_fails) {
    REQ_MSG();
    for (size_t i = 0; i < 2; i++) {
        BYTE *c = dup_vec(SV[i].der, SV[i].n);
        HCRYPTMSG m0 = ml_decode(SV[i].der, SV[i].n, 0, 0);
        DWORD n = 0; BYTE *si = m0 ? ml_param(m0, CMSG_SIGNER_INFO_PARAM, 0, &n) : NULL;
        CHECK(si != NULL);
        if (si) {
            CMSG_SIGNER_INFO *s = (CMSG_SIGNER_INFO *)si;
            /* locate the signature in the wire bytes (it is stored big-endian) and flip a bit in its middle */
            BYTE sig[128]; memcpy(sig, s->EncryptedHash.pbData, 128);
            const BYTE *p = ml_memmem(c, SV[i].n, sig, 128);
            if (!p) { for (int k = 0; k < 128; k++) sig[k] = s->EncryptedHash.pbData[127 - k]; p = ml_memmem(c, SV[i].n, sig, 128); }
            CHECK(p != NULL);
            if (p) {
                ((BYTE *)p)[60] ^= 0x10;
                HCRYPTMSG m = ml_decode(c, SV[i].n, 0, 0);
                CHECK(m != NULL);
                if (m) {
                    SET_ERR(0);
                    CHECK(!verify_with(m, V_CERT1, V_CERT1_LEN));
                    EXPECT_ERR(NTE_BAD_SIGNATURE);
                    mClose()(m);
                }
            }
            ml_free(si);
        }
        if (m0) mClose()(m0);
        LocalFree(c);
    }
}
TEST(mlsd_truncated_final_fails) {
    REQ_MSG();
    static const DWORD cut[] = {0, 1, 4, 20, 100, 400, 700};
    for (size_t i = 0; i < sizeof cut / sizeof *cut; i++) {
        HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
        if (!m) { CHECK(m != NULL); continue; }
        SET_ERR(0);
        CHECKF(!mUpdate()(m, M_SIGNED_NOATTR, cut[i], TRUE), "cut %lu", (unsigned long)cut[i]);
        mClose()(m);
    }
}
TEST(mlsd_type_mismatch_unexpected_msg_type) {
    REQ_MSG();
    /* explicit type with bare content of another type */
    DWORD n = 0; const BYTE *bare = ml_unwrap(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, &n);
    CHECK(bare != NULL);
    if (!bare) return;
    HCRYPTMSG m = mOpenDec()(ENC, 0, CMSG_SIGNED, 0, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECKF(mUpdate()(m, bare, n, TRUE), "err 0x%lx", GetLastError());
    HCRYPTMSG h = mOpenDec()(ENC, 0, CMSG_HASHED, 0, NULL, NULL);
    if (h) {
        SET_ERR(0);
        CHECK(!mUpdate()(h, bare, n, TRUE));
        t_note("signed bare content decoded as CMSG_HASHED: err 0x%lx", (unsigned long)GetLastError());
        mClose()(h);
    }
    SET_ERR(0);
    CHECKF(verify_with(m, V_CERT1, V_CERT1_LEN), "verify err 0x%lx", GetLastError());
    mClose()(m);
}
TEST(mlsd_decode_wrong_type_matrix) {
    REQ_MSG();
    /* an untyped decode learns the type from the ContentInfo; type-specific parameters then reject other types */
    struct { const BYTE *d; DWORD n; DWORD want; } v[] = {
        {M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, CMSG_SIGNED}, {M_ENV_AES128, M_ENV_AES128_LEN, CMSG_ENVELOPED},
        {M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, CMSG_HASHED}, {M_DATA, M_DATA_LEN, CMSG_DATA},
    };
    for (size_t i = 0; i < 4; i++) {
        HCRYPTMSG m = ml_decode(v[i].d, v[i].n, 0, 0);
        CHECK(m != NULL);
        if (!m) continue;
        DWORD t = 0; CHECK(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, v[i].want);
        DWORD n = 0; SET_ERR(0);
        BOOL sig = mGetParam()(m, CMSG_SIGNER_COUNT_PARAM, 0, NULL, &n);
        CHECKF(sig == (v[i].want == CMSG_SIGNED), "msg %zu", i);
        if (!sig) EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        SET_ERR(0);
        BOOL rcp = mGetParam()(m, CMSG_RECIPIENT_COUNT_PARAM, 0, NULL, &n);
        CHECKF(rcp == (v[i].want == CMSG_ENVELOPED), "msg %zu", i);
        if (!rcp) EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        SET_ERR(0);
        if (v[i].want != CMSG_SIGNED) {
            BOOL hh = mGetParam()(m, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &n);
            CHECKF(hh == (v[i].want == CMSG_HASHED), "msg %zu", i);
            if (!hh) EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        }
        mClose()(m);
    }
}

/* ---------------------------------------------------------------- VERIFY_SIGNATURE_EX */
TEST(mlsd_verify_ex_signer_types) {
    REQ_MSG();
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    REQUIRE(c);
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); ml_cert_free(c); return; }
    CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p;
    p.dwSignerType = CMSG_VERIFY_SIGNER_CERT; p.pvSigner = (void *)c;
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p), "CERT err 0x%lx", GetLastError());
    p.dwSignerType = CMSG_VERIFY_SIGNER_PUBKEY; p.pvSigner = (void *)&c->pCertInfo->SubjectPublicKeyInfo;
    SET_ERR(0);
    CHECKF(mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p), "PUBKEY err 0x%lx", GetLastError());
    p.dwSignerType = CMSG_VERIFY_SIGNER_NULL; p.pvSigner = NULL;
    SET_ERR(0);
    BOOL ok = mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p);
    t_note("VERIFY_SIGNATURE_EX with SIGNER_NULL: ok=%d err=0x%lx", ok, (unsigned long)GetLastError());
    mClose()(m);
    ml_cert_free(c);
}
TEST(mlsd_verify_ex_bad_parameters) {
    REQ_MSG();
    PCCERT_CONTEXT c = ml_cert(V_CERT1, V_CERT1_LEN);
    REQUIRE(c);
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); ml_cert_free(c); return; }
    CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p; p.dwSignerType = CMSG_VERIFY_SIGNER_CERT; p.pvSigner = (void *)c;
    p.dwSignerIndex = 5; SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p));
    t_note("VERIFY_SIGNATURE_EX signer index 5 of 1: err 0x%lx", (unsigned long)GetLastError());
    p.dwSignerIndex = 0; p.cbSize = 4; SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p));
    t_note("VERIFY_SIGNATURE_EX cbSize 4: err 0x%lx", (unsigned long)GetLastError());
    p.cbSize = sizeof p; p.dwSignerType = 99; SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p));
    t_note("VERIFY_SIGNATURE_EX with signer type 99: err 0x%lx", (unsigned long)GetLastError());
    mClose()(m);
    ml_cert_free(c);
}
TEST(mlsd_verify_ex_wrong_key) {
    REQ_MSG();
    PCCERT_CONTEXT c2 = ml_cert(V_CERT2, V_CERT2_LEN);
    REQUIRE(c2);
    HCRYPTMSG m = open_sv(&SV[1]);
    if (!m) { CHECK(m != NULL); ml_cert_free(c2); return; }
    CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p; p.dwSignerType = CMSG_VERIFY_SIGNER_PUBKEY; p.pvSigner = (void *)&c2->pCertInfo->SubjectPublicKeyInfo;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &p));
    EXPECT_ERR(NTE_BAD_SIGNATURE);
    mClose()(m);
    ml_cert_free(c2);
}

/* ---------------------------------------------------------------- detached decode flow */
TEST(mlsd_detached_content_param_before_content) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, CMSG_DETACHED_FLAG, 0, 0, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, M_SIGNED_DETACHED_NOATTR, M_SIGNED_DETACHED_NOATTR_LEN, TRUE));
    DWORD n = 0; SET_ERR(0);
    BOOL ok = mGetParam()(m, CMSG_CONTENT_PARAM, 0, NULL, &n);
    t_note("detached: CONTENT_PARAM before the content update: ok=%d size=%lu err=0x%lx", ok, (unsigned long)n, (unsigned long)GetLastError());
    CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
    SET_ERR(0);
    CHECKF(verify_with(m, V_CERT1, V_CERT1_LEN), "err 0x%lx", GetLastError());
    mClose()(m);
}
TEST(mlsd_detached_wrong_content_fails) {
    REQ_MSG();
    for (int a = 0; a < 2; a++) {
        const svec_t *v = &SV[a ? 4 : 5];
        HCRYPTMSG m = mOpenDec()(ENC, CMSG_DETACHED_FLAG, 0, 0, NULL, NULL);
        if (!m) { CHECK(m != NULL); continue; }
        BYTE bad[64]; memcpy(bad, V_CONTENT, V_CONTENT_LEN); bad[0] ^= 1;
        CHECK(mUpdate()(m, v->der, v->n, TRUE));
        CHECK(mUpdate()(m, bad, V_CONTENT_LEN, TRUE));
        SET_ERR(0);
        CHECK(!verify_with(m, V_CERT1, V_CERT1_LEN));
        DWORD e = GetLastError();
        CHECKF(e == (a ? (DWORD)CRYPT_E_HASH_VALUE : (DWORD)NTE_BAD_SIGNATURE), "vec %s err 0x%lx", v->name, (unsigned long)e);
        mClose()(m);
    }
}
TEST(mlsd_detached_no_content_verify) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, CMSG_DETACHED_FLAG, 0, 0, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, M_SIGNED_DETACHED_NOATTR, M_SIGNED_DETACHED_NOATTR_LEN, TRUE));
    SET_ERR(0);
    BOOL ok = verify_with(m, V_CERT1, V_CERT1_LEN);
    t_note("detached verify before content supplied: ok=%d err=0x%lx", ok, (unsigned long)GetLastError());
    CHECK(1);
    mClose()(m);
}

/* ---------------------------------------------------------------- GetAndVerifySigner */
static HCERTSTORE mem_store(const BYTE *c1, DWORD n1) {
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (s && c1) U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, c1, n1, CERT_STORE_ADD_ALWAYS, NULL);
    return s;
}
TEST(mlsd_getandverify_from_store) {
    REQ_MSG();
    REQUIRE(U(CryptMsgGetAndVerifySigner)); REQUIRE(U(CertOpenStore));
    HCRYPTMSG m = open_sv(&SV[1]);
    if (!m) { CHECK(m != NULL); return; }
    HCERTSTORE st = mem_store(V_CERT1, V_CERT1_LEN);
    PCCERT_CONTEXT signer = NULL; DWORD idx = 99;
    SET_ERR(0);
    BOOL ok = U(CryptMsgGetAndVerifySigner)(m, 1, &st, 0, &signer, &idx);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        CHECK(signer != NULL); EXPECT_EQ(idx, 0);
        CHECK(signer && signer->cbCertEncoded == V_CERT1_LEN && !memcmp(signer->pbCertEncoded, V_CERT1, V_CERT1_LEN));
        ml_cert_free(signer);
    }
    U(CertCloseStore)(st, 0);
    mClose()(m);
}
TEST(mlsd_getandverify_signer_not_in_store) {
    REQ_MSG();
    REQUIRE(U(CryptMsgGetAndVerifySigner)); REQUIRE(U(CertOpenStore));
    HCRYPTMSG m = open_sv(&SV[3]);   /* message carries no certificates */
    if (!m) { CHECK(m != NULL); return; }
    HCERTSTORE st = mem_store(V_CERT2, V_CERT2_LEN);
    PCCERT_CONTEXT signer = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    BOOL ok = U(CryptMsgGetAndVerifySigner)(m, 1, &st, 0, &signer, NULL);
    CHECK(!ok);
    EXPECT_ERR(CRYPT_E_NOT_FOUND);
    U(CertCloseStore)(st, 0);
    mClose()(m);
}
TEST(mlsd_getandverify_message_certs) {
    REQ_MSG();
    REQUIRE(U(CryptMsgGetAndVerifySigner));
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); return; }
    PCCERT_CONTEXT signer = NULL; DWORD idx = 99;
    SET_ERR(0);
    BOOL ok = U(CryptMsgGetAndVerifySigner)(m, 0, NULL, 0, &signer, &idx);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) { CHECK(signer != NULL); EXPECT_EQ(idx, 0); ml_cert_free(signer); }
    mClose()(m);
}
TEST(mlsd_getandverify_trusted_flag) {
    REQ_MSG();
    REQUIRE(U(CryptMsgGetAndVerifySigner)); REQUIRE(U(CertOpenStore));
    HCRYPTMSG m = open_sv(&SV[0]);
    if (!m) { CHECK(m != NULL); return; }
    PCCERT_CONTEXT signer = NULL;
    /* trusted signer: the certificate must come from the supplied stores, not from the message */
    SET_ERR(0);
    CHECK(!U(CryptMsgGetAndVerifySigner)(m, 0, NULL, CMSG_TRUSTED_SIGNER_FLAG, &signer, NULL));
    t_note("TRUSTED_SIGNER_FLAG with no stores: err 0x%lx", (unsigned long)GetLastError());
    HCERTSTORE empty = mem_store(NULL, 0);
    SET_ERR(0);
    CHECK(!U(CryptMsgGetAndVerifySigner)(m, 1, &empty, CMSG_TRUSTED_SIGNER_FLAG, &signer, NULL));
    EXPECT_ERR(CRYPT_E_NOT_FOUND);
    HCERTSTORE st = mem_store(V_CERT1, V_CERT1_LEN);
    SET_ERR(0);
    BOOL ok = U(CryptMsgGetAndVerifySigner)(m, 1, &st, CMSG_TRUSTED_SIGNER_FLAG, &signer, NULL);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) ml_cert_free(signer);
    U(CertCloseStore)(st, 0); U(CertCloseStore)(empty, 0);
    mClose()(m);
}
TEST(mlsd_getandverify_signer_only_flag) {
    REQ_MSG();
    REQUIRE(U(CryptMsgGetAndVerifySigner));
    /* SIGNER_ONLY: locate the signer without verifying the signature */
    BYTE *c = dup_vec(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN);
    const BYTE *p = ml_memmem(c, M_SIGNED_NOATTR_LEN, V_CONTENT, V_CONTENT_LEN);
    CHECK(p != NULL);
    if (p) ((BYTE *)p)[2] ^= 0x01;
    HCRYPTMSG m = ml_decode(c, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (m) {
        PCCERT_CONTEXT signer = NULL;
        SET_ERR(0);
        CHECK(!U(CryptMsgGetAndVerifySigner)(m, 0, NULL, 0, &signer, NULL));
        EXPECT_ERR(NTE_BAD_SIGNATURE);
        SET_ERR(0);
        BOOL ok = U(CryptMsgGetAndVerifySigner)(m, 0, NULL, CMSG_SIGNER_ONLY_FLAG, &signer, NULL);
        CHECKF(ok, "err 0x%lx", GetLastError());
        if (ok) ml_cert_free(signer);
        mClose()(m);
    }
    LocalFree(c);
}
TEST(mlsd_getandverify_use_signer_index) {
    REQ_MSG();
    REQUIRE(U(CryptMsgGetAndVerifySigner));
    HCRYPTMSG m = ml_decode(M_SIGNED_TWO, M_SIGNED_TWO_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    for (DWORD i = 0; i < 2; i++) {
        PCCERT_CONTEXT signer = NULL; DWORD idx = i;
        SET_ERR(0);
        BOOL ok = U(CryptMsgGetAndVerifySigner)(m, 0, NULL, CMSG_USE_SIGNER_INDEX_FLAG, &signer, &idx);
        CHECKF(ok, "index %lu err 0x%lx", (unsigned long)i, GetLastError());
        if (ok) {
            const BYTE *want = i ? V_CERT2 : V_CERT1; DWORD wn = i ? V_CERT2_LEN : V_CERT1_LEN;
            CHECK(signer && signer->cbCertEncoded == wn && !memcmp(signer->pbCertEncoded, want, wn));
            ml_cert_free(signer);
        }
    }
    PCCERT_CONTEXT signer = NULL; DWORD idx = 5;
    SET_ERR(0);
    CHECK(!U(CryptMsgGetAndVerifySigner)(m, 0, NULL, CMSG_USE_SIGNER_INDEX_FLAG, &signer, &idx));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    mClose()(m);
}
TEST(mlsd_getandverify_wrong_message_type) {
    REQ_MSG();
    REQUIRE(U(CryptMsgGetAndVerifySigner));
    HCRYPTMSG m = ml_decode(M_DATA, M_DATA_LEN, 0, 0);
    if (!m) { CHECK(m != NULL); return; }
    PCCERT_CONTEXT signer = NULL;
    SET_ERR(0);
    CHECK(!U(CryptMsgGetAndVerifySigner)(m, 0, NULL, 0, &signer, NULL));
    t_note("GetAndVerifySigner on a data message: err 0x%lx", (unsigned long)GetLastError());
    mClose()(m);
}

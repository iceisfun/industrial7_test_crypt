/* CryptMsgCountersign, CryptMsgCountersignEncoded, CryptMsgVerifyCountersignatureEncoded(Ex). */
#include "gap1.h"

static const char OID_COUNTERSIGN_DER[] = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x06";   /* 1.2.840.113549.1.9.6 */
static const char OID_MSGDIGEST_DER[]   = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04";   /* 1.2.840.113549.1.9.4 */

/* encoded SignerInfo #0 of the openssl-made message */
static BYTE *signer_info(const BYTE *msg, DWORD n, DWORD *pcb) {
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL);
    if (!m) return NULL;
    BYTE *out = NULL; DWORD cb = 0;
    if (U(CryptMsgUpdate)(m, msg, n, TRUE) && U(CryptMsgGetParam)(m, CMSG_ENCODED_SIGNER, 0, NULL, &cb) && cb) {
        out = malloc(cb);
        if (!U(CryptMsgGetParam)(m, CMSG_ENCODED_SIGNER, 0, out, &cb)) { free(out); out = NULL; }
        else *pcb = cb;
    }
    U(CryptMsgClose)(m);
    return out;
}
static void signer_para(CMSG_SIGNER_ENCODE_INFO *si, const g1_id *id, CRYPT_ATTRIBUTE *attr, CRYPT_ATTR_BLOB *val, int with_attr) {
    static BYTE octet[3] = { 0x04, 0x01, 0xAA };
    memset(si, 0, sizeof *si);
    si->cbSize = sizeof *si; si->pCertInfo = id->cert->pCertInfo; si->hCryptProv = id->prov; si->dwKeySpec = AT_KEYEXCHANGE;
    si->HashAlgorithm.pszObjId = OID_SHA256;
    if (with_attr) {
        val->cbData = 3; val->pbData = octet;
        attr->pszObjId = (LPSTR)"1.2.3.4.5.6.7"; attr->cValue = 1; attr->rgValue = val;
        si->cAuthAttr = 1; si->rgAuthAttr = attr;
    }
}
/* make a countersignature attribute encoding for the openssl signer info */
static BYTE *make_cs(const BYTE *si, DWORD sicb, const g1_id *by, int with_attr, DWORD *pcb) {
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v;
    signer_para(&c, by, &a, &v, with_attr);
    DWORD n = 0;
    if (!U(CryptMsgCountersignEncoded)(ENC, (BYTE *)si, sicb, 1, &c, NULL, &n) || !n) return NULL;
    BYTE *out = malloc(n);
    if (!U(CryptMsgCountersignEncoded)(ENC, (BYTE *)si, sicb, 1, &c, out, &n)) { free(out); return NULL; }
    *pcb = n;
    return out;
}
/* the countersignature attribute is SEQUENCE { OID, SET { SignerInfo } }: return the SignerInfo TLV */
static const BYTE *attr_signer(const BYTE *a, DWORD n, DWORD *pcb) {
    DWORD h = g1_der_hdr(a, n); if (!h || a[0] != 0x30) return NULL;
    const BYTE *p = a + h; DWORD left = n - h;
    if (left < 11 || memcmp(p, OID_COUNTERSIGN_DER, 11)) return NULL;
    p += 11; left -= 11;
    if (!left || p[0] != 0x31) return NULL;
    DWORD sh = g1_der_hdr(p, left); if (!sh) return NULL;
    p += sh; left -= sh;
    if (!left || p[0] != 0x30) return NULL;
    *pcb = g1_der_total(p, left);
    return p;
}

TEST(gap1_csenc_output_structure) {
    REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    for (int attr = 0; attr < 2; attr++) {
        DWORD n = 0; BYTE *cs = make_cs(si, sicb, &g1_A, attr, &n);
        CHECKF(cs != NULL, "attr=%d err 0x%08lx", attr, GetLastError());
        if (!cs) continue;
        CHECK(cs[0] == 0x30);
        CHECK(g1_der_total(cs, n) == n);
        DWORD scb = 0; const BYTE *s = attr_signer(cs, n, &scb);
        CHECKF(s != NULL, "attr=%d: SEQUENCE{countersignature OID, SET{SignerInfo}}", attr);
        if (s) {
            /* SignerInfo ::= SEQUENCE { version 1, issuerAndSerial, digestAlgorithm, [0] authAttrs OPTIONAL, ... } */
            CHECK(s[g1_der_hdr(s, scb)] == 0x02);                      /* version INTEGER */
            CHECK(G1_HAS(s, scb, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"));   /* sha256 digestAlgorithm present */
            int md = G1_HAS(s, scb, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04");
            t_note("attr=%d: messageDigest attribute present: %d (cb %lu)", attr, md, scb);
            if (attr) CHECK(md);                                         /* auth attrs requested -> messageDigest is added */
            CHECK(G1_HAS(s, scb, "\x06\x06\x2a\x03\x04\x05\x06\x07") || !attr);   /* custom attribute 1.2.3.4.5.6.7 */
        }
        free(cs);
    }
    free(si);
}
TEST(gap1_csenc_buffer_protocol) {
    REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v; signer_para(&c, &g1_A, &a, &v, 1);
    DWORD need = 0;
    CHECK(U(CryptMsgCountersignEncoded)(ENC, si, sicb, 1, &c, NULL, &need));
    CHECK(need > 100);
    BYTE *buf = calloc(1, need + 64);
    for (DWORD cap = 0; cap < need; cap += (need / 6 ? need / 6 : 1)) {
        DWORD n = cap; SET_ERR(0);
        CHECKF(!U(CryptMsgCountersignEncoded)(ENC, si, sicb, 1, &c, buf, &n), "cap %lu", cap);
        if (cap) EXPECT_ERR(ERROR_MORE_DATA);
        CHECKF(n == need, "cap %lu: *pcb %lu need %lu", cap, n, need);
    }
    DWORD n = need;
    CHECK(U(CryptMsgCountersignEncoded)(ENC, si, sicb, 1, &c, buf, &n));
    EXPECT_EQ(n, need);
    n = need + 64; memset(buf, 0, need + 64);
    CHECK(U(CryptMsgCountersignEncoded)(ENC, si, sicb, 1, &c, buf, &n));
    EXPECT_EQ(n, need);
    free(buf); free(si);
}
TEST(gap1_csenc_encoding_type_validation) {
    REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v; signer_para(&c, &g1_A, &a, &v, 0);
    static const DWORD bad[] = { 0, X509_ASN_ENCODING, 0x20000 };
    for (unsigned i = 0; i < 3; i++) {
        DWORD n = 0; SET_ERR(0);
        CHECKF(!U(CryptMsgCountersignEncoded)(bad[i], si, sicb, 1, &c, NULL, &n), "type %lx", bad[i]);
        EXPECT_ERR(E_INVALIDARG_);
    }
    free(si);
}
TEST(gap1_csenc_garbage_signer_info) {
    REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v; signer_para(&c, &g1_A, &a, &v, 0);
    static const BYTE g1[] = { 0x01, 0x02, 0x03 }, g2[] = { 0x30, 0x02, 0x05, 0x00 }, g3[] = { 0x30, 0x80 };
    struct { const BYTE *b; DWORD n; } t[] = { { g1, 3 }, { g2, 4 }, { g3, 2 } };
    for (int i = 0; i < 3; i++) {
        DWORD n = 0; SET_ERR(0);
        CHECKF(!U(CryptMsgCountersignEncoded)(ENC, (BYTE *)t[i].b, t[i].n, 1, &c, NULL, &n), "garbage %d", i);
        DWORD e = GetLastError(); CHECKF(CRYPT_E_ASN1_ANY(e), "garbage %d: 0x%08lx", i, e);
    }
}
TEST(gap1_csenc_signer_hash_algorithms) {
    REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    static const char *oids[] = { OID_SHA1, OID_SHA256, OID_SHA512, OID_MD5 };
    for (unsigned i = 0; i < 4; i++) {
        CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v; signer_para(&c, &g1_A, &a, &v, 1);
        c.HashAlgorithm.pszObjId = (LPSTR)oids[i];
        DWORD n = 0; BYTE *buf;
        BOOL r = U(CryptMsgCountersignEncoded)(ENC, si, sicb, 1, &c, NULL, &n);
        CHECKF(r && n, "%s: 0x%08lx", oids[i], GetLastError());
        if (!r) continue;
        buf = malloc(n); r = U(CryptMsgCountersignEncoded)(ENC, si, sicb, 1, &c, buf, &n);
        CHECKF(r, "%s encode", oids[i]);
        if (r) {
            DWORD scb; const BYTE *s = attr_signer(buf, n, &scb);
            CHECKF(s != NULL, "%s structure", oids[i]);
            if (s) {   /* the countersigner SignerInfo declares the hash used */
                int found = (i == 0 && G1_HAS(s, scb, "\x06\x05\x2b\x0e\x03\x02\x1a")) || (i == 1 && G1_HAS(s, scb, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01")) ||
                            (i == 2 && G1_HAS(s, scb, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03")) || (i == 3 && G1_HAS(s, scb, "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05"));
                CHECKF(found, "%s digestAlgorithm in countersigner info", oids[i]);
            }
        }
        free(buf);
    }
    free(si);
}
TEST(gap1_csenc_unknown_hash_algorithm) {
    REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v; signer_para(&c, &g1_A, &a, &v, 1);
    c.HashAlgorithm.pszObjId = (LPSTR)"1.2.3.4.5.99";
    DWORD n = 0; SET_ERR(0);
    CHECK(!U(CryptMsgCountersignEncoded)(ENC, si, sicb, 1, &c, NULL, &n));
    t_note("unknown hash OID -> 0x%08lx", GetLastError());
    CHECK(GetLastError() != 0);
    free(si);
}
TEST(gap1_csenc_zero_countersigners_note) {
    REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    DWORD n = 0; SET_ERR(0);
    BOOL r = U(CryptMsgCountersignEncoded)(ENC, si, sicb, 0, NULL, NULL, &n);
    t_note("zero countersigners: ret %d err 0x%08lx size %lu", r, GetLastError(), n);
    free(si);
}
TEST(gap1_csenc_two_countersigners_note) {
    REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    CMSG_SIGNER_ENCODE_INFO c[2]; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v;
    signer_para(&c[0], &g1_A, &a, &v, 1); signer_para(&c[1], &g1_B, &a, &v, 1);
    DWORD n = 0; SET_ERR(0);
    BOOL r = U(CryptMsgCountersignEncoded)(ENC, si, sicb, 2, c, NULL, &n);
    t_note("two countersigners: ret %d err 0x%08lx size %lu", r, GetLastError(), n);
    if (r && n) {
        BYTE *buf = malloc(n); r = U(CryptMsgCountersignEncoded)(ENC, si, sicb, 2, c, buf, &n);
        CHECK(r);
        if (r) {   /* one attribute whose SET holds two SignerInfos */
            DWORD h = g1_der_hdr(buf, n); const BYTE *p = buf + h + 11;
            CHECK(p[0] == 0x31);
            DWORD sh = g1_der_hdr(p, n); DWORD cnt = 0, left = g1_der_total(p, n) - sh; const BYTE *q = p + sh;
            while (left >= 2 && q[0] == 0x30) { DWORD t = g1_der_total(q, left); if (!t || t > left) break; q += t; left -= t; cnt++; }
            CHECKF(cnt == 2, "SET holds %lu SignerInfos", cnt);
        }
        free(buf);
    }
    free(si);
}
TEST(gap1_csverify_roundtrip_with_attributes) {
    REQUIRE(U(CryptMsgVerifyCountersignatureEncoded)); REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    DWORD n = 0; BYTE *cs = make_cs(si, sicb, &g1_A, 1, &n); REQUIRE(cs);
    DWORD scb = 0; const BYTE *s = attr_signer(cs, n, &scb); REQUIRE(s);
    BOOL r = U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, si, sicb, (BYTE *)s, scb, g1_A.cert->pCertInfo);
    CHECKF(r, "0x%08lx", GetLastError());
    /* wrong countersigner key */
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, si, sicb, (BYTE *)s, scb, g1_B.cert->pCertInfo));
    EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE);
    /* the countersignature covers the original signature value: another message's signer info fails the digest comparison */
    DWORD sicb2 = 0; BYTE *si2 = signer_info(BLOB(v_sig_att_sha1), &sicb2); REQUIRE(si2);
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, si2, sicb2, (BYTE *)s, scb, g1_A.cert->pCertInfo));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
    free(si2); free(cs); free(si);
}
TEST(gap1_csverify_tampered_signer_info) {
    REQUIRE(U(CryptMsgVerifyCountersignatureEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    DWORD n = 0; BYTE *cs = make_cs(si, sicb, &g1_A, 1, &n); REQUIRE(cs);
    DWORD scb = 0; const BYTE *s = attr_signer(cs, n, &scb); REQUIRE(s);
    BYTE *bad = malloc(sicb); memcpy(bad, si, sicb); bad[sicb - 10] ^= 0x01;   /* inside the encrypted digest at the tail */
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, bad, sicb, (BYTE *)s, scb, g1_A.cert->pCertInfo));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
    /* tampered countersignature value (its encrypted digest is at the tail of the countersigner info) */
    BYTE *cbad = malloc(scb); memcpy(cbad, s, scb); cbad[scb - 10] ^= 0x01;
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, si, sicb, cbad, scb, g1_A.cert->pCertInfo));
    EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE);
    free(bad); free(cbad); free(cs); free(si);
}
TEST(gap1_csverify_encoding_type_and_garbage) {
    REQUIRE(U(CryptMsgVerifyCountersignatureEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    DWORD n = 0; BYTE *cs = make_cs(si, sicb, &g1_A, 1, &n); REQUIRE(cs);
    DWORD scb = 0; const BYTE *s = attr_signer(cs, n, &scb); REQUIRE(s);
    static const DWORD bad[] = { 0, X509_ASN_ENCODING, 0x20000 };
    for (unsigned i = 0; i < 3; i++) {
        SET_ERR(0);
        CHECKF(!U(CryptMsgVerifyCountersignatureEncoded)(0, bad[i], si, sicb, (BYTE *)s, scb, g1_A.cert->pCertInfo), "type %lx", bad[i]);
        EXPECT_ERR(E_INVALIDARG_);
    }
    static const BYTE g[] = { 0x00, 0x01, 0x02 };
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, (BYTE *)g, sizeof g, (BYTE *)s, scb, g1_A.cert->pCertInfo));
    DWORD e = GetLastError(); CHECKF(CRYPT_E_ASN1_ANY(e), "garbage signer info 0x%08lx", e);
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, si, sicb, (BYTE *)g, sizeof g, g1_A.cert->pCertInfo));
    e = GetLastError(); CHECKF(CRYPT_E_ASN1_ANY(e), "garbage countersignature 0x%08lx", e);
    free(cs); free(si);
}
TEST(gap1_csverify_no_authenticated_attributes) {
    /* verification needs the countersignature's messageDigest attribute; without authenticated attributes it fails */
    REQUIRE(U(CryptMsgVerifyCountersignatureEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    DWORD n = 0; BYTE *cs = make_cs(si, sicb, &g1_A, 0, &n); REQUIRE(cs);
    DWORD scb = 0; const BYTE *s = attr_signer(cs, n, &scb); REQUIRE(s);
    int has_md = G1_HAS(s, scb, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04");
    SET_ERR(0);
    BOOL r = U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, si, sicb, (BYTE *)s, scb, g1_A.cert->pCertInfo);
    t_note("countersigner without auth attributes: messageDigest present %d, verify ret %d err 0x%08lx", has_md, r, GetLastError());
    if (!has_md) { CHECK(!r); EXPECT_ERR(CRYPT_E_AUTH_ATTR_MISSING_); }
    else CHECK(r);
    free(cs); free(si);
}
TEST(gap1_csverifyex_signer_types) {
    REQUIRE(U(CryptMsgVerifyCountersignatureEncodedEx)); REQUIRE(U(CryptMsgCountersignEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    DWORD n = 0; BYTE *cs = make_cs(si, sicb, &g1_A, 1, &n); REQUIRE(cs);
    DWORD scb = 0; const BYTE *s = attr_signer(cs, n, &scb); REQUIRE(s);
    /* CMSG_VERIFY_SIGNER_PUBKEY */
    CHECKF(U(CryptMsgVerifyCountersignatureEncodedEx)(0, ENC, si, sicb, (BYTE *)s, scb, CMSG_VERIFY_SIGNER_PUBKEY,
            &g1_A.cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL), "pubkey: 0x%08lx", GetLastError());
    /* CMSG_VERIFY_SIGNER_CERT */
    CHECKF(U(CryptMsgVerifyCountersignatureEncodedEx)(0, ENC, si, sicb, (BYTE *)s, scb, CMSG_VERIFY_SIGNER_CERT, (void *)g1_A.cert, 0, NULL),
           "cert: 0x%08lx", GetLastError());
    /* wrong signer through each type */
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncodedEx)(0, ENC, si, sicb, (BYTE *)s, scb, CMSG_VERIFY_SIGNER_PUBKEY,
            &g1_B.cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL));
    EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE);
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncodedEx)(0, ENC, si, sicb, (BYTE *)s, scb, CMSG_VERIFY_SIGNER_CERT, (void *)g1_B.cert, 0, NULL));
    EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE);
    /* bad encoding type */
    SET_ERR(0);
    CHECK(!U(CryptMsgVerifyCountersignatureEncodedEx)(0, 0, si, sicb, (BYTE *)s, scb, CMSG_VERIFY_SIGNER_PUBKEY,
            &g1_A.cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL));
    EXPECT_ERR(E_INVALIDARG_);
    /* unknown signer type */
    SET_ERR(0);
    BOOL r = U(CryptMsgVerifyCountersignatureEncodedEx)(0, ENC, si, sicb, (BYTE *)s, scb, 99, (void *)g1_A.cert, 0, NULL);
    t_note("signer type 99 -> ret %d err 0x%08lx", r, GetLastError());
    CHECK(!r);
    SET_ERR(0);
    r = U(CryptMsgVerifyCountersignatureEncodedEx)(0, ENC, si, sicb, (BYTE *)s, scb, 0, (void *)g1_A.cert, 0, NULL);
    t_note("signer type 0 -> ret %d err 0x%08lx", r, GetLastError());
    CHECK(!r);
    free(cs); free(si);
}
TEST(gap1_csverify_matches_ex_with_pubkey) {
    /* the non-Ex entry point is the Ex one with signer type 1 and the cert's public key info */
    REQUIRE(U(CryptMsgVerifyCountersignatureEncoded)); REQUIRE(U(CryptMsgVerifyCountersignatureEncodedEx)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    DWORD n = 0; BYTE *cs = make_cs(si, sicb, &g1_B, 1, &n); REQUIRE(cs);
    DWORD scb = 0; const BYTE *s = attr_signer(cs, n, &scb); REQUIRE(s);
    const g1_id *ids[2] = { &g1_A, &g1_B };
    for (int i = 0; i < 2; i++) {
        SET_ERR(0);
        BOOL r1 = U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, si, sicb, (BYTE *)s, scb, ids[i]->cert->pCertInfo); DWORD e1 = GetLastError();
        SET_ERR(0);
        BOOL r2 = U(CryptMsgVerifyCountersignatureEncodedEx)(0, ENC, si, sicb, (BYTE *)s, scb, 1, &ids[i]->cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL); DWORD e2 = GetLastError();
        CHECKF(r1 == r2, "id %d: %d vs %d", i, r1, r2);
        if (!r1) CHECKF(e1 == e2, "id %d: 0x%08lx vs 0x%08lx", i, e1, e2);
        CHECKF(r1 == (i == 1), "id %d", i);   /* countersigned by B */
    }
    free(cs); free(si);
}
TEST(gap1_csverify_with_cryptprov) {
    REQUIRE(U(CryptMsgVerifyCountersignatureEncoded)); NOWINE_STUB(); G1_INIT();
    DWORD sicb = 0; BYTE *si = signer_info(BLOB(v_sig_att), &sicb); REQUIRE(si);
    DWORD n = 0; BYTE *cs = make_cs(si, sicb, &g1_A, 1, &n); REQUIRE(cs);
    DWORD scb = 0; const BYTE *s = attr_signer(cs, n, &scb); REQUIRE(s);
    CHECKF(U(CryptMsgVerifyCountersignatureEncoded)(g1_A.prov, ENC, si, sicb, (BYTE *)s, scb, g1_A.cert->pCertInfo), "explicit provider: 0x%08lx", GetLastError());
    free(cs); free(si);
}

/* ---------------- CryptMsgCountersign on a decoded message ---------------- */
static HCRYPTMSG open_decoded(const BYTE *b, DWORD n) {
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL);
    if (m && !U(CryptMsgUpdate)(m, b, n, TRUE)) { U(CryptMsgClose)(m); return NULL; }
    return m;
}
TEST(gap1_cs_add_countersignature_to_message) {
    REQUIRE(U(CryptMsgCountersign)); NOWINE_STUB(); G1_INIT();
    HCRYPTMSG m = open_decoded(BLOB(v_sig_att)); REQUIRE(m);
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v; signer_para(&c, &g1_A, &a, &v, 1);
    BOOL r = U(CryptMsgCountersign)(m, 0, 1, &c);
    CHECKF(r, "0x%08lx", GetLastError());
    if (r) {
        DWORD cb = 0; SET_ERR(0);
        /* the decoded handle does not expose the new attribute; the re-encoded message does */
        CHECK(!U(CryptMsgGetParam)(m, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &cb)); EXPECT_ERR(CRYPT_E_ATTRIBUTES_MISSING_);
        DWORD en0 = 0; BYTE *eb0 = NULL; HCRYPTMSG m4 = NULL;
        if (U(CryptMsgGetParam)(m, CMSG_ENCODED_MESSAGE, 0, NULL, &en0) && en0) {
            eb0 = malloc(en0);
            if (U(CryptMsgGetParam)(m, CMSG_ENCODED_MESSAGE, 0, eb0, &en0)) m4 = open_decoded(eb0, en0);
        }
        REQUIRE(m4);
        cb = 0;
        CHECK(U(CryptMsgGetParam)(m4, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &cb) && cb);
        BYTE *ua = malloc(cb);
        if (U(CryptMsgGetParam)(m4, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, ua, &cb)) {
            CRYPT_ATTRIBUTES *attrs = (CRYPT_ATTRIBUTES *)ua;
            CHECK(attrs->cAttr == 1);
            if (attrs->cAttr == 1) {
                CHECK(!strcmp(attrs->rgAttr[0].pszObjId, "1.2.840.113549.1.9.6"));
                CHECK(attrs->rgAttr[0].cValue == 1);
                if (attrs->rgAttr[0].cValue == 1) {
                    /* the stored value is a SignerInfo that verifies against the original signer */
                    HCRYPTMSG m2 = open_decoded(BLOB(v_sig_att));
                    DWORD scb = 0; BYTE *sin = NULL;
                    if (m2 && U(CryptMsgGetParam)(m2, CMSG_ENCODED_SIGNER, 0, NULL, &scb)) { sin = malloc(scb); U(CryptMsgGetParam)(m2, CMSG_ENCODED_SIGNER, 0, sin, &scb); }
                    if (sin) {
                        BOOL vr = U(CryptMsgVerifyCountersignatureEncoded)(0, ENC, sin, scb, attrs->rgAttr[0].rgValue[0].pbData, attrs->rgAttr[0].rgValue[0].cbData, g1_A.cert->pCertInfo);
                        CHECKF(vr, "stored countersignature verifies: 0x%08lx", GetLastError());
                        free(sin);
                    }
                    if (m2) U(CryptMsgClose)(m2);
                }
            }
        }
        free(ua); U(CryptMsgClose)(m4); free(eb0);
        /* the re-encoded message now carries the countersignature OID */
        DWORD en = 0;
        if (U(CryptMsgGetParam)(m, CMSG_ENCODED_MESSAGE, 0, NULL, &en) && en) {
            BYTE *e = malloc(en);
            if (U(CryptMsgGetParam)(m, CMSG_ENCODED_MESSAGE, 0, e, &en)) CHECK(g1_has(e, en, OID_COUNTERSIGN_DER, 11));
            free(e);
        } else t_note("CMSG_ENCODED_MESSAGE unavailable on a decoded message: 0x%08lx", GetLastError());
    }
    U(CryptMsgClose)(m);
}
TEST(gap1_cs_signer_index_out_of_range) {
    REQUIRE(U(CryptMsgCountersign)); NOWINE_STUB(); G1_INIT();
    HCRYPTMSG m = open_decoded(BLOB(v_sig_att)); REQUIRE(m);
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v; signer_para(&c, &g1_A, &a, &v, 1);
    static const DWORD idx[] = { 1, 2, 1000, 0xFFFFFFFF };
    for (unsigned i = 0; i < 4; i++) {
        SET_ERR(0);
        CHECKF(!U(CryptMsgCountersign)(m, idx[i], 1, &c), "index %lu", idx[i]);
        t_note("signer index %lu -> 0x%08lx", idx[i], GetLastError());
        CHECK(GetLastError() != 0);
    }
    U(CryptMsgClose)(m);
}
TEST(gap1_cs_wrong_message_type) {
    REQUIRE(U(CryptMsgCountersign)); NOWINE_STUB(); G1_INIT();
    HCRYPTMSG m = open_decoded(BLOB(v_dig_sha256)); REQUIRE(m);
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v; signer_para(&c, &g1_A, &a, &v, 1);
    SET_ERR(0);
    CHECK(!U(CryptMsgCountersign)(m, 0, 1, &c));
    t_note("countersign of a hashed message -> 0x%08lx", GetLastError());
    CHECK(GetLastError() != 0);
    U(CryptMsgClose)(m);
}
TEST(gap1_cs_message_after_update_has_no_unauth_attrs_before) {
    REQUIRE(U(CryptMsgGetParam)); NOWINE_STUB(); G1_INIT();
    HCRYPTMSG m = open_decoded(BLOB(v_sig_att)); REQUIRE(m);
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptMsgGetParam)(m, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &cb);
    t_note("unauth attributes before countersigning: ret %d err 0x%08lx cb %lu", r, GetLastError(), cb);
    CHECK(!r);
    U(CryptMsgClose)(m);
}
TEST(gap1_cs_second_countersign_call_rejected) {
    REQUIRE(U(CryptMsgCountersign)); NOWINE_STUB(); G1_INIT();
    HCRYPTMSG m = open_decoded(BLOB(v_sig_att)); REQUIRE(m);
    CMSG_SIGNER_ENCODE_INFO c; CRYPT_ATTRIBUTE a; CRYPT_ATTR_BLOB v;
    signer_para(&c, &g1_A, &a, &v, 1);
    CHECK(U(CryptMsgCountersign)(m, 0, 1, &c));
    /* a decoded message accepts one CryptMsgCountersign call: later calls (any signer) fail with E_INVALIDARG */
    signer_para(&c, &g1_B, &a, &v, 1); SET_ERR(0);
    BOOL r = U(CryptMsgCountersign)(m, 0, 1, &c);
    CHECK(!r); EXPECT_ERR(E_INVALIDARG_);
    signer_para(&c, &g1_A, &a, &v, 1); SET_ERR(0);
    r = U(CryptMsgCountersign)(m, 0, 1, &c);
    CHECK(!r); EXPECT_ERR(E_INVALIDARG_);
    /* the one countersignature is visible in the re-encoded message, not through the decoded handle */
    DWORD cb = 0; SET_ERR(0);
    CHECK(!U(CryptMsgGetParam)(m, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &cb)); EXPECT_ERR(CRYPT_E_ATTRIBUTES_MISSING_);
    DWORD en = 0; BYTE *eb = NULL; HCRYPTMSG m3 = NULL;
    if (U(CryptMsgGetParam)(m, CMSG_ENCODED_MESSAGE, 0, NULL, &en) && en) {
        eb = malloc(en);
        if (U(CryptMsgGetParam)(m, CMSG_ENCODED_MESSAGE, 0, eb, &en)) m3 = open_decoded(eb, en);
    }
    REQUIRE(m3);
    cb = 0;
    if (U(CryptMsgGetParam)(m3, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &cb)) {
        BYTE *ua = malloc(cb);
        if (U(CryptMsgGetParam)(m3, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, ua, &cb)) {
            CRYPT_ATTRIBUTES *at = (CRYPT_ATTRIBUTES *)ua;
            DWORD total = 0;
            for (DWORD i = 0; i < at->cAttr; i++) if (!strcmp(at->rgAttr[i].pszObjId, "1.2.840.113549.1.9.6")) total += at->rgAttr[i].cValue;
            t_note("attributes %lu, countersignature values %lu", at->cAttr, total);
            CHECK(total == 1);
        }
        free(ua);
    }
    U(CryptMsgClose)(m3); free(eb);
    U(CryptMsgClose)(m);
}

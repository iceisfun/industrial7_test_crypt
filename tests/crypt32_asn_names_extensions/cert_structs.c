/* X509_EXTENSIONS, X509_CERT_TO_BE_SIGNED, X509_CERT_CRL_TO_BE_SIGNED, X509_CERT_REQUEST_TO_BE_SIGNED, X509_CERT. */
#include "asn.h"

static BYTE alg_null[] = { 0x05, 0x00 };
static BYTE empty_seq[] = { 0x30, 0x00 };
static BYTE ca_true[] = { 0x30, 0x03, 0x01, 0x01, 0xFF };

static void mk_spki(CERT_PUBLIC_KEY_INFO *k) {
    memset(k, 0, sizeof *k);
    k->Algorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
    k->Algorithm.Parameters.cbData = 2; k->Algorithm.Parameters.pbData = alg_null;
    k->PublicKey.cbData = sizeof v_spki_pubkey_seq; k->PublicKey.pbData = (BYTE *)v_spki_pubkey_seq;
}
static void mk_cert(CERT_INFO *ci, CERT_PUBLIC_KEY_INFO *k) {
    static BYTE serial[] = { 1 };
    memset(ci, 0, sizeof *ci);
    ci->SerialNumber.cbData = 1; ci->SerialNumber.pbData = serial;
    ci->SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
    ci->Issuer.cbData = sizeof v_name_cn_test; ci->Issuer.pbData = (BYTE *)v_name_cn_test;
    ci->Subject = ci->Issuer;
    ci->NotBefore = a_ft(2000, 1, 1, 0, 0, 0); ci->NotAfter = a_ft(2049, 12, 31, 23, 59, 59);
    mk_spki(k); ci->SubjectPublicKeyInfo = *k;
}

/* ---- X509_EXTENSIONS --------------------------------------------------- */
TEST(extensions_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_EXTENSIONS s = { 0, NULL };
    ENC_EQ(X509_EXTENSIONS, &s, v_ext_empty);
    CERT_EXTENSION e = { (LPSTR)szOID_BASIC_CONSTRAINTS2, FALSE, { sizeof empty_seq, empty_seq } };
    s.cExtension = 1; s.rgExtension = &e;
    ENC_EQ(X509_EXTENSIONS, &s, v_ext_one);
    e.fCritical = TRUE; e.Value.cbData = sizeof ca_true; e.Value.pbData = ca_true;
    ENC_EQ(X509_EXTENSIONS, &s, v_ext_critical);
    static BYTE ds[] = { 0x03, 0x02, 0x07, 0x80 };
    CERT_EXTENSION two[2] = { { (LPSTR)szOID_BASIC_CONSTRAINTS2, FALSE, { 2, empty_seq } }, { (LPSTR)szOID_KEY_USAGE, TRUE, { 4, ds } } };
    s.cExtension = 2; s.rgExtension = two;
    ENC_EQ(X509_EXTENSIONS, &s, v_ext_two);
}
TEST(extensions_encode_empty_value_and_bad_oid) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_EXTENSION e = { (LPSTR)"1.2.3", FALSE, { 0, NULL } };
    CERT_EXTENSIONS s = { 1, &e };
    static const BYTE exp[] = { 0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2A, 0x03, 0x04, 0x00 };
    ENC_EQ(X509_EXTENSIONS, &s, exp);
    e.pszObjId = (LPSTR)"abc";
    DWORD cb = 0; SET_ERR(0);
    EXPECT_FAILS(U(CryptEncodeObjectEx)(ENC, X509_EXTENSIONS, &s, 0, NULL, NULL, &cb), 0x80093109);
}
TEST(extensions_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_EXTENSIONS *d = DEC(X509_EXTENSIONS, v_ext_two, 0, NULL);
    if (d) {
        CHECK(d->cExtension == 2);
        if (d->cExtension == 2) {
            CHECK(!strcmp(d->rgExtension[0].pszObjId, "2.5.29.19") && !d->rgExtension[0].fCritical);
            CHECK(d->rgExtension[0].Value.cbData == 2 && !memcmp(d->rgExtension[0].Value.pbData, empty_seq, 2));
            CHECK(!strcmp(d->rgExtension[1].pszObjId, "2.5.29.15") && d->rgExtension[1].fCritical);
            CHECK(d->rgExtension[1].Value.cbData == 4);
        }
        LocalFree(d);
    }
    d = DEC(X509_EXTENSIONS, v_ext_empty, 0, NULL);
    if (d) { CHECK(d->cExtension == 0); LocalFree(d); }
    d = DEC(X509_EXTENSIONS, v_ext_critical_false_explicit, 0, NULL);   /* DEFAULT FALSE encoded explicitly is accepted */
    if (d) { CHECK(d->cExtension == 1 && !d->rgExtension[0].fCritical); LocalFree(d); }
    ROUNDTRIP(X509_EXTENSIONS, v_ext_one);
    ROUNDTRIP(X509_EXTENSIONS, v_ext_critical);
    ROUNDTRIP(X509_EXTENSIONS, v_ext_two);
    ROUNDTRIP(X509_EXTENSIONS, v_ext_empty);
    ROUNDTRIP(szOID_CERT_EXTENSIONS, v_ext_two);
}
TEST(extensions_decode_nocopy_and_share) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD c0, c1, c2;
    CERT_EXTENSIONS *a = DEC(X509_EXTENSIONS, v_ext_two, 0, &c0);
    CERT_EXTENSIONS *n = DEC(X509_EXTENSIONS, v_ext_two, CRYPT_DECODE_NOCOPY_FLAG, &c1);
    CERT_EXTENSIONS *s = DEC(X509_EXTENSIONS, v_ext_two, CRYPT_DECODE_SHARE_OID_STRING_FLAG, &c2);
    if (n) {
        CHECK(n->cExtension == 2);
        if (n->cExtension == 2) CHECK(PTR_IN(n->rgExtension[1].Value.pbData, v_ext_two, sizeof v_ext_two));
        if (a) CHECK(c1 < c0);
    }
    if (s && s->cExtension == 2) {
        CHECK(!strcmp(s->rgExtension[0].pszObjId, "2.5.29.19"));
        CHECK(!PTR_IN(s->rgExtension[0].pszObjId, s, c2));
        if (a) CHECK(c2 < c0);
    }
    if (a && a->cExtension == 2) CHECK(PTR_IN(a->rgExtension[0].pszObjId, a, c0) && PTR_IN(a->rgExtension[1].Value.pbData, a, c0));
    if (a) LocalFree(a);
    if (n) LocalFree(n);
    if (s) LocalFree(s);
}
TEST(extensions_decode_errors) {
    REQUIRE(U(CryptDecodeObjectEx));
    a_dec_fail(__FILE__, __LINE__, X509_EXTENSIONS, v_bc2_ca, sizeof v_bc2_ca, 0, HR_ASN1_BADTAG);
    a_dec_fail(__FILE__, __LINE__, X509_EXTENSIONS, v_ku_ds, sizeof v_ku_ds, 0, HR_ASN1_BADTAG);
    static const BYTE no_value[] = { 0x30, 0x06, 0x30, 0x04, 0x06, 0x02, 0x2A, 0x03 };
    a_dec_fail(__FILE__, __LINE__, X509_EXTENSIONS, no_value, sizeof no_value, 0, HR_ASN1_EOD);
}

/* ---- X509_CERT_TO_BE_SIGNED -------------------------------------------- */
TEST(tbs_cert_encode_v1) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_INFO ci; CERT_PUBLIC_KEY_INFO k; mk_cert(&ci, &k);
    ENC_EQ(X509_CERT_TO_BE_SIGNED, &ci, v_tbs_v1_n);
}
TEST(tbs_cert_encode_algorithm_parameters) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_INFO ci; CERT_PUBLIC_KEY_INFO k; mk_cert(&ci, &k);
    ci.SignatureAlgorithm.Parameters.cbData = 2; ci.SignatureAlgorithm.Parameters.pbData = alg_null;
    ENC_EQ(X509_CERT_TO_BE_SIGNED, &ci, v_tbs_v1_nullparams);
}
TEST(tbs_cert_encode_v3_and_serials) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_INFO ci; CERT_PUBLIC_KEY_INFO k; mk_cert(&ci, &k);
    ci.dwVersion = CERT_V3;
    ENC_EQ(X509_CERT_TO_BE_SIGNED, &ci, v_tbs_v3_n);
    static BYTE s2[] = { 0x01, 0x02 };           /* little-endian blob => big-endian 0x0201 */
    ci.SerialNumber.cbData = 2; ci.SerialNumber.pbData = s2;
    ENC_EQ(X509_CERT_TO_BE_SIGNED, &ci, v_tbs_v3_serial2_n);
    static BYTE s80[] = { 0x80 };
    ci.SerialNumber.cbData = 1; ci.SerialNumber.pbData = s80;
    /* the serial blob is written as the raw big-endian bytes with no sign padding */
    ENC_EQ(X509_CERT_TO_BE_SIGNED, &ci, v_tbs_v3_serial_hi_enc);
}
TEST(tbs_cert_encode_extensions_and_unique_ids) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_INFO ci; CERT_PUBLIC_KEY_INFO k; mk_cert(&ci, &k);
    ci.dwVersion = CERT_V3;
    CERT_EXTENSION e = { (LPSTR)szOID_BASIC_CONSTRAINTS2, FALSE, { sizeof empty_seq, empty_seq } };
    ci.cExtension = 1; ci.rgExtension = &e;
    ENC_EQ(X509_CERT_TO_BE_SIGNED, &ci, v_tbs_v3_ext_n);
    ci.cExtension = 0; ci.rgExtension = NULL;
    static BYTE u1[] = { 0x01 }, u2[] = { 0x02 };
    ci.IssuerUniqueId.cbData = 1; ci.IssuerUniqueId.pbData = u1;
    ci.SubjectUniqueId.cbData = 1; ci.SubjectUniqueId.pbData = u2;
    ENC_EQ(X509_CERT_TO_BE_SIGNED, &ci, v_tbs_v3_uid_n);
}
TEST(tbs_cert_encode_generalized_time_after_2049) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_INFO ci; CERT_PUBLIC_KEY_INFO k; mk_cert(&ci, &k);
    ci.dwVersion = CERT_V3; ci.NotAfter = a_ft(2050, 1, 1, 0, 0, 0);
    ENC_EQ(X509_CERT_TO_BE_SIGNED, &ci, v_tbs_v3_gentime_n);
}
TEST(tbs_cert_decode_v1) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb; CERT_INFO *ci = DEC(X509_CERT_TO_BE_SIGNED, v_tbs_v1, CRYPT_DECODE_TO_BE_SIGNED_FLAG, &cb);
    if (!ci) return;
    EXPECT_EQ(cb, 336); /* observed: CERT_INFO 208 bytes plus its strings and blobs */
    CHECK(ci->dwVersion == CERT_V1);
    CHECK(ci->SerialNumber.cbData == 1 && ci->SerialNumber.pbData[0] == 1);
    CHECK(ci->SignatureAlgorithm.pszObjId && !strcmp(ci->SignatureAlgorithm.pszObjId, szOID_RSA_SHA1RSA));
    CHECK(ci->SignatureAlgorithm.Parameters.cbData == 0);
    CHECK(ci->Issuer.cbData == sizeof v_name_cn_test && !memcmp(ci->Issuer.pbData, v_name_cn_test, sizeof v_name_cn_test));
    CHECK(ci->Subject.cbData == sizeof v_name_cn_test);
    CHECK(a_ft_eq(ci->NotBefore, a_ft(2000, 1, 1, 0, 0, 0)));
    CHECK(a_ft_eq(ci->NotAfter, a_ft(2049, 12, 31, 23, 59, 59)));
    CHECK(!strcmp(ci->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA));
    CHECK(ci->SubjectPublicKeyInfo.Algorithm.Parameters.cbData == 2 && !memcmp(ci->SubjectPublicKeyInfo.Algorithm.Parameters.pbData, alg_null, 2));
    CHECK(ci->SubjectPublicKeyInfo.PublicKey.cbData == sizeof v_spki_pubkey_seq && !memcmp(ci->SubjectPublicKeyInfo.PublicKey.pbData, v_spki_pubkey_seq, sizeof v_spki_pubkey_seq));
    CHECK(ci->SubjectPublicKeyInfo.PublicKey.cUnusedBits == 0);
    CHECK(ci->IssuerUniqueId.cbData == 0 && ci->SubjectUniqueId.cbData == 0 && ci->cExtension == 0);
    LocalFree(ci);
}
TEST(tbs_cert_decode_null_params_preserved) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_INFO *ci = DEC(X509_CERT_TO_BE_SIGNED, v_tbs_v1_nullparams, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (ci) { CHECK(ci->SignatureAlgorithm.Parameters.cbData == 2 && !memcmp(ci->SignatureAlgorithm.Parameters.pbData, alg_null, 2)); LocalFree(ci); }
}
TEST(tbs_cert_decode_v3_ext_uid_serial) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_INFO *ci = DEC(X509_CERT_TO_BE_SIGNED, v_tbs_v3_ext, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (ci) {
        CHECK(ci->dwVersion == CERT_V3 && ci->cExtension == 1);
        if (ci->cExtension == 1) CHECK(!strcmp(ci->rgExtension[0].pszObjId, szOID_BASIC_CONSTRAINTS2) && ci->rgExtension[0].Value.cbData == 2);
        LocalFree(ci);
    }
    ci = DEC(X509_CERT_TO_BE_SIGNED, v_tbs_v3_uid, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (ci) {
        CHECK(ci->IssuerUniqueId.cbData == 1 && ci->IssuerUniqueId.pbData[0] == 1 && ci->IssuerUniqueId.cUnusedBits == 0);
        CHECK(ci->SubjectUniqueId.cbData == 1 && ci->SubjectUniqueId.pbData[0] == 2);
        LocalFree(ci);
    }
    ci = DEC(X509_CERT_TO_BE_SIGNED, v_tbs_v3_serial2, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (ci) { CHECK(ci->SerialNumber.cbData == 2 && ci->SerialNumber.pbData[0] == 0x01 && ci->SerialNumber.pbData[1] == 0x02); LocalFree(ci); }
    ci = DEC(X509_CERT_TO_BE_SIGNED, v_tbs_v3_gentime, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (ci) { CHECK(a_ft_eq(ci->NotAfter, a_ft(2050, 1, 1, 0, 0, 0))); LocalFree(ci); }
    ci = DEC(X509_CERT_TO_BE_SIGNED, v_tbs_v3_serial_hi, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (ci) { /* observed: the serial is byte-reversed (little endian), the redundant leading zero is kept */
        CHECKF(ci->SerialNumber.cbData == 2 && ci->SerialNumber.pbData[0] == 0x80 && ci->SerialNumber.pbData[1] == 0x00, "cb %lu first %02x", ci->SerialNumber.cbData, ci->SerialNumber.pbData[0]); LocalFree(ci); }
}
TEST(tbs_cert_roundtrips) {
    REQUIRE(U(CryptDecodeObjectEx));
    /* decode with the to-be-signed flag, then re-encode (encoding never emits the signature) */
    const BYTE *vs[] = { v_tbs_v1, v_tbs_v1_nullparams, v_tbs_v3, v_tbs_v3_serial2, v_tbs_v3_ext, v_tbs_v3_uid, v_tbs_v3_gentime };
    const DWORD ns[] = { sizeof v_tbs_v1, sizeof v_tbs_v1_nullparams, sizeof v_tbs_v3, sizeof v_tbs_v3_serial2, sizeof v_tbs_v3_ext, sizeof v_tbs_v3_uid, sizeof v_tbs_v3_gentime };
    /* encoding adds NULL parameters where the input had none */
    const BYTE *xs[] = { v_tbs_v1_n, v_tbs_v1_nullparams, v_tbs_v3_n, v_tbs_v3_serial2_n, v_tbs_v3_ext_n, v_tbs_v3_uid_n, v_tbs_v3_gentime_n };
    const DWORD xn[] = { sizeof v_tbs_v1_n, sizeof v_tbs_v1_nullparams, sizeof v_tbs_v3_n, sizeof v_tbs_v3_serial2_n, sizeof v_tbs_v3_ext_n, sizeof v_tbs_v3_uid_n, sizeof v_tbs_v3_gentime_n };
    for (unsigned i = 0; i < 7; i++) {
        void *p = NULL; DWORD cb = 0;
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_CERT_TO_BE_SIGNED, vs[i], ns[i], CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL, &p, &cb);
        CHECKF(r, "vector %u decode err 0x%lx", i, GetLastError());
        if (!r) continue;
        DWORD ec = 0; BYTE *e = a_enc(X509_CERT_TO_BE_SIGNED, p, 0, &ec);
        if (e) DIFF("reencode equals normalized input", e, ec, xs[i], xn[i]); else CHECKF(0, "vector %u reencode failed 0x%lx", i, GetLastError());
        if (e) LocalFree(e);
        LocalFree(p);
    }
}
TEST(tbs_cert_decode_signed_vs_to_be_signed_flag) {
    REQUIRE(U(CryptDecodeObjectEx));
    /* default: input is the full signed certificate, the decoder unwraps the signed content */
    CERT_INFO *ci = DEC(X509_CERT_TO_BE_SIGNED, v_x509_cert, 0, NULL);
    if (ci) { CHECK(ci->dwVersion == CERT_V1 && ci->SerialNumber.cbData == 1); LocalFree(ci); }
    ci = DEC(X509_CERT_TO_BE_SIGNED, v_x509_cert_v3, 0, NULL);
    if (ci) { CHECK(ci->dwVersion == CERT_V3); LocalFree(ci); }
    /* a bare TBS also decodes without the flag on Windows 10 (the decoder accepts both forms) */
    ci = DEC(X509_CERT_TO_BE_SIGNED, v_tbs_v1, 0, NULL);
    if (ci) { CHECK(ci->dwVersion == CERT_V1 && ci->SerialNumber.cbData == 1 && ci->Subject.cbData == sizeof v_name_cn_test); LocalFree(ci); }
    /* and the flag must not be combined with the signed structure */
    a_dec_fail(__FILE__, __LINE__, X509_CERT_TO_BE_SIGNED, v_x509_cert, sizeof v_x509_cert, CRYPT_DECODE_TO_BE_SIGNED_FLAG, HR_ASN1_BADTAG);
}
TEST(tbs_cert_decode_truncated) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (DWORD cut = 0; cut < sizeof v_tbs_v3_ext; cut++) {
        DWORD cb = 0; SET_ERR(0);
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_CERT_TO_BE_SIGNED, v_tbs_v3_ext, cut, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL, NULL, &cb);
        CHECKF(!r, "cut %lu succeeded", cut);
    }
    DEC_FAIL(X509_CERT_TO_BE_SIGNED, v_tbs_truncated, HR_ASN1_EOD);
}
TEST(tbs_cert_decode_wrong_content) {
    REQUIRE(U(CryptDecodeObjectEx));
    a_dec_fail(__FILE__, __LINE__, X509_CERT_TO_BE_SIGNED, v_name_cn_test, sizeof v_name_cn_test, CRYPT_DECODE_TO_BE_SIGNED_FLAG, HR_ASN1_BADTAG);
    a_dec_fail(__FILE__, __LINE__, X509_CERT_TO_BE_SIGNED, v_bc2_empty, sizeof v_bc2_empty, CRYPT_DECODE_TO_BE_SIGNED_FLAG, HR_ASN1_EOD);
    a_dec_fail(__FILE__, __LINE__, X509_CERT_TO_BE_SIGNED, v_ku_ds, sizeof v_ku_ds, CRYPT_DECODE_TO_BE_SIGNED_FLAG, HR_ASN1_BADTAG);
}

/* ---- X509_CERT (signed content) ------------------------------------------ */
TEST(signed_content_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_SIGNED_CONTENT_INFO s; memset(&s, 0, sizeof s);
    s.ToBeSigned.cbData = sizeof v_tbs_v1; s.ToBeSigned.pbData = (BYTE *)v_tbs_v1;
    s.SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
    static BYTE sig_b[] = { 3, 2, 1 };
    s.Signature.cbData = 3; s.Signature.pbData = sig_b;
    /* the signature blob is in CryptoAPI (little-endian) order; the DER carries it reversed */
    /* absent algorithm parameters are written as NULL (Windows 10 always does) */
    ENC_EQ(X509_CERT, &s, v_x509_cert_n);
    static BYTE sig_c[] = { 1, 2, 3 };
    s.Signature.pbData = sig_c; s.Signature.cUnusedBits = 0;
    DWORD cb = 0; BYTE *p = a_enc(X509_CERT, &s, 0, &cb);
    CHECKF(p && cb == sizeof v_x509_cert_n && p[cb - 3] == 3 && p[cb - 1] == 1, "cb %lu last bytes %02x %02x %02x", cb, p ? p[cb - 3] : 0, p ? p[cb - 2] : 0, p ? p[cb - 1] : 0);
    if (p) LocalFree(p);
    s.ToBeSigned.cbData = 3; s.ToBeSigned.pbData = (BYTE *)"\x02\x01\x05";
    s.SignatureAlgorithm.Parameters.cbData = 0; s.Signature.pbData = sig_b;
    ENC_EQ(X509_CERT, &s, v_x509_cert_tiny_n);
}
TEST(signed_content_decode_reversal_flag) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD c1, c2;
    CERT_SIGNED_CONTENT_INFO *a = DEC(X509_CERT, v_x509_cert, 0, &c1);
    CERT_SIGNED_CONTENT_INFO *b = DEC(X509_CERT, v_x509_cert, CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, &c2);
    if (a) {
        CHECK(a->ToBeSigned.cbData == sizeof v_tbs_v1 && !memcmp(a->ToBeSigned.pbData, v_tbs_v1, sizeof v_tbs_v1));
        CHECK(!strcmp(a->SignatureAlgorithm.pszObjId, szOID_RSA_SHA1RSA) && a->SignatureAlgorithm.Parameters.cbData == 0);
        CHECK(a->Signature.cbData == 3 && a->Signature.cUnusedBits == 0);
        CHECK(a->Signature.cbData == 3 && !memcmp(a->Signature.pbData, "\x03\x02\x01", 3));   /* reversed by default */
    }
    if (b) CHECK(b->Signature.cbData == 3 && !memcmp(b->Signature.pbData, "\x01\x02\x03", 3));   /* flag inhibits it */
    if (a) LocalFree(a);
    if (b) LocalFree(b);
}
TEST(signed_content_roundtrip) {
    REQUIRE(U(CryptDecodeObjectEx));
    ROUNDTRIP_TO(X509_CERT, v_x509_cert, v_x509_cert_n);
    ROUNDTRIP(X509_CERT, v_x509_cert_nullparams);
    ROUNDTRIP_TO(X509_CERT, v_x509_cert_v3, v_x509_cert_v3_n);
    ROUNDTRIP_TO(X509_CERT, v_x509_cert_tiny, v_x509_cert_tiny_n);
}
TEST(signed_content_decode_params_and_errors) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_SIGNED_CONTENT_INFO *a = DEC(X509_CERT, v_x509_cert_nullparams, 0, NULL);
    if (a) { CHECK(a->SignatureAlgorithm.Parameters.cbData == 2); LocalFree(a); }
    a = DEC(X509_CERT, v_x509_cert_tiny, 0, NULL);
    if (a) { CHECK(a->ToBeSigned.cbData == 3 && a->ToBeSigned.pbData[0] == 0x02); LocalFree(a); }
    for (DWORD cut = 0; cut < sizeof v_x509_cert; cut++) {
        DWORD cb = 0; SET_ERR(0);
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_CERT, v_x509_cert, cut, 0, NULL, NULL, &cb);
        CHECKF(!r, "cut %lu succeeded", cut);
    }
    a_dec_fail(__FILE__, __LINE__, X509_CERT, v_tbs_v1, sizeof v_tbs_v1, 0, HR_ASN1_BADTAG);
}

/* ---- CRL to be signed ----------------------------------------------------- */
static void mk_crl(CRL_INFO *c) {
    memset(c, 0, sizeof *c);
    c->SignatureAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
    c->Issuer.cbData = sizeof v_name_cn_test; c->Issuer.pbData = (BYTE *)v_name_cn_test;
    c->ThisUpdate = a_ft(2000, 1, 1, 0, 0, 0);
}
TEST(tbs_crl_encode_variants) {
    REQUIRE(U(CryptEncodeObjectEx));
    CRL_INFO c; mk_crl(&c);
    ENC_EQ(X509_CERT_CRL_TO_BE_SIGNED, &c, v_crl_v1_nonext_n);
    c.NextUpdate = a_ft(2049, 12, 31, 23, 59, 59);
    ENC_EQ(X509_CERT_CRL_TO_BE_SIGNED, &c, v_crl_v1_next_n);
    static BYTE ser[] = { 1 };
    CRL_ENTRY e; memset(&e, 0, sizeof e);
    e.SerialNumber.cbData = 1; e.SerialNumber.pbData = ser; e.RevocationDate = a_ft(2000, 1, 1, 0, 0, 0);
    c.cCRLEntry = 1; c.rgCRLEntry = &e;
    ENC_EQ(X509_CERT_CRL_TO_BE_SIGNED, &c, v_crl_v1_entry_n);
}
TEST(tbs_crl_encode_v2_extensions) {
    REQUIRE(U(CryptEncodeObjectEx));
    CRL_INFO c; mk_crl(&c);
    c.NextUpdate = a_ft(2049, 12, 31, 23, 59, 59); c.dwVersion = CRL_V2;
    CERT_EXTENSION x = { (LPSTR)szOID_BASIC_CONSTRAINTS2, FALSE, { sizeof empty_seq, empty_seq } };
    c.cExtension = 1; c.rgExtension = &x;
    ENC_EQ(X509_CERT_CRL_TO_BE_SIGNED, &c, v_crl_v2_ext_n);
    c.cExtension = 0; c.rgExtension = NULL;
    static BYTE ser[] = { 1 };
    CRL_ENTRY e; memset(&e, 0, sizeof e);
    e.SerialNumber.cbData = 1; e.SerialNumber.pbData = ser; e.RevocationDate = a_ft(2000, 1, 1, 0, 0, 0);
    e.cExtension = 1; e.rgExtension = &x;
    c.cCRLEntry = 1; c.rgCRLEntry = &e;
    ENC_EQ(X509_CERT_CRL_TO_BE_SIGNED, &c, v_crl_v2_entry_ext_n);
}
TEST(tbs_crl_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CRL_INFO *c = DEC(X509_CERT_CRL_TO_BE_SIGNED, v_crl_v1_entry, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (c) {
        CHECK(c->dwVersion == CRL_V1);
        CHECK(!strcmp(c->SignatureAlgorithm.pszObjId, szOID_RSA_SHA1RSA));
        CHECK(c->Issuer.cbData == sizeof v_name_cn_test);
        CHECK(a_ft_eq(c->ThisUpdate, a_ft(2000, 1, 1, 0, 0, 0)) && a_ft_eq(c->NextUpdate, a_ft(2049, 12, 31, 23, 59, 59)));
        CHECK(c->cCRLEntry == 1);
        if (c->cCRLEntry == 1) CHECK(c->rgCRLEntry[0].SerialNumber.cbData == 1 && c->rgCRLEntry[0].SerialNumber.pbData[0] == 1 && c->rgCRLEntry[0].cExtension == 0 && a_ft_eq(c->rgCRLEntry[0].RevocationDate, a_ft(2000, 1, 1, 0, 0, 0)));
        LocalFree(c);
    }
    c = DEC(X509_CERT_CRL_TO_BE_SIGNED, v_crl_v1_nonext, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (c) { CHECK(c->NextUpdate.dwLowDateTime == 0 && c->NextUpdate.dwHighDateTime == 0 && c->cCRLEntry == 0); LocalFree(c); }
    c = DEC(X509_CERT_CRL_TO_BE_SIGNED, v_crl_v2_ext, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (c) { CHECK(c->dwVersion == CRL_V2 && c->cExtension == 1 && !strcmp(c->rgExtension[0].pszObjId, szOID_BASIC_CONSTRAINTS2)); LocalFree(c); }
    c = DEC(X509_CERT_CRL_TO_BE_SIGNED, v_crl_v2_entry_ext, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (c) { CHECK(c->cCRLEntry == 1 && c->rgCRLEntry[0].cExtension == 1); LocalFree(c); }
    c = DEC(X509_CERT_CRL_TO_BE_SIGNED, v_crl_signed, 0, NULL);
    if (c) { CHECK(c->dwVersion == CRL_V1 && c->Issuer.cbData == sizeof v_name_cn_test); LocalFree(c); }
    /* a bare CRL TBS decodes without the flag too */
    c = DEC(X509_CERT_CRL_TO_BE_SIGNED, v_crl_v1_next, 0, NULL);
    if (c) { CHECK(c->dwVersion == CRL_V1 && c->cCRLEntry == 0); LocalFree(c); }
}
TEST(tbs_crl_roundtrips) {
    REQUIRE(U(CryptDecodeObjectEx));
    const BYTE *vs[] = { v_crl_v1_nonext, v_crl_v1_next, v_crl_v1_entry, v_crl_v2_ext, v_crl_v2_entry_ext };
    const DWORD ns[] = { sizeof v_crl_v1_nonext, sizeof v_crl_v1_next, sizeof v_crl_v1_entry, sizeof v_crl_v2_ext, sizeof v_crl_v2_entry_ext };
    const BYTE *xs[] = { v_crl_v1_nonext_n, v_crl_v1_next_n, v_crl_v1_entry_n, v_crl_v2_ext_n, v_crl_v2_entry_ext_n };
    const DWORD xn[] = { sizeof v_crl_v1_nonext_n, sizeof v_crl_v1_next_n, sizeof v_crl_v1_entry_n, sizeof v_crl_v2_ext_n, sizeof v_crl_v2_entry_ext_n };
    for (unsigned i = 0; i < 5; i++) {
        void *p = NULL; DWORD cb = 0;
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_CERT_CRL_TO_BE_SIGNED, vs[i], ns[i], CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL, &p, &cb);
        CHECKF(r, "vector %u err 0x%lx", i, GetLastError());
        if (!r) continue;
        DWORD ec = 0; BYTE *e = a_enc(X509_CERT_CRL_TO_BE_SIGNED, p, 0, &ec);
        if (e) DIFF("reencode equals normalized input", e, ec, xs[i], xn[i]); else CHECKF(0, "vector %u reencode failed 0x%lx", i, GetLastError());
        if (e) LocalFree(e);
        LocalFree(p);
    }
}

/* ---- certificate request ------------------------------------------------- */
TEST(tbs_request_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_REQUEST_INFO r; memset(&r, 0, sizeof r);
    r.Subject.cbData = sizeof v_name_cn_test; r.Subject.pbData = (BYTE *)v_name_cn_test;
    CERT_PUBLIC_KEY_INFO k; mk_spki(&k); r.SubjectPublicKeyInfo = k;
    ENC_EQ(X509_CERT_REQUEST_TO_BE_SIGNED, &r, v_csr_noattr);
    CRYPT_ATTR_BLOB val = { sizeof empty_seq, empty_seq };
    CRYPT_ATTRIBUTE a = { (LPSTR)szOID_RSA_certExtensions, 1, &val };
    r.cAttribute = 1; r.rgAttribute = &a;
    ENC_EQ(X509_CERT_REQUEST_TO_BE_SIGNED, &r, v_csr_attr);
}
TEST(tbs_request_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_REQUEST_INFO *r = DEC(X509_CERT_REQUEST_TO_BE_SIGNED, v_csr_attr, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (r) {
        CHECK(r->dwVersion == CERT_REQUEST_V1);
        CHECK(r->Subject.cbData == sizeof v_name_cn_test);
        CHECK(!strcmp(r->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA));
        CHECK(r->cAttribute == 1);
        if (r->cAttribute == 1) CHECK(!strcmp(r->rgAttribute[0].pszObjId, szOID_RSA_certExtensions) && r->rgAttribute[0].cValue == 1 && r->rgAttribute[0].rgValue[0].cbData == 2);
        LocalFree(r);
    }
    r = DEC(X509_CERT_REQUEST_TO_BE_SIGNED, v_csr_noattr, CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL);
    if (r) { CHECK(r->cAttribute == 0); LocalFree(r); }
    r = DEC(X509_CERT_REQUEST_TO_BE_SIGNED, v_csr_signed, 0, NULL);
    if (r) { CHECK(r->dwVersion == 0 && r->cAttribute == 0); LocalFree(r); }
    /* a bare request TBS decodes without the flag too */
    r = DEC(X509_CERT_REQUEST_TO_BE_SIGNED, v_csr_noattr, 0, NULL);
    if (r) { CHECK(r->dwVersion == 0 && r->cAttribute == 0 && r->Subject.cbData == sizeof v_name_cn_test); LocalFree(r); }
    const BYTE *vs[] = { v_csr_noattr, v_csr_attr };
    const DWORD ns[] = { sizeof v_csr_noattr, sizeof v_csr_attr };
    for (unsigned i = 0; i < 2; i++) {
        void *p = NULL; DWORD cb = 0;
        BOOL ok = U(CryptDecodeObjectEx)(ENC, X509_CERT_REQUEST_TO_BE_SIGNED, vs[i], ns[i], CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_TO_BE_SIGNED_FLAG, NULL, &p, &cb);
        CHECK(ok);
        if (!ok) continue;
        DWORD ec; BYTE *e = a_enc(X509_CERT_REQUEST_TO_BE_SIGNED, p, 0, &ec);
        if (e) DIFF("reencode equals normalized input", e, ec, vs[i], ns[i]); else CHECKF(0, "vector %u reencode failed 0x%lx", i, GetLastError());
        if (e) LocalFree(e);
        LocalFree(p);
    }
}
TEST(public_key_info_encode_decode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_PUBLIC_KEY_INFO k; mk_spki(&k);
    ENC_EQ(X509_PUBLIC_KEY_INFO, &k, v_spki_rsa_tiny);
    CERT_PUBLIC_KEY_INFO *d = DEC(X509_PUBLIC_KEY_INFO, v_spki_rsa_tiny, 0, NULL);
    if (d) { CHECK(!strcmp(d->Algorithm.pszObjId, szOID_RSA_RSA) && d->Algorithm.Parameters.cbData == 2); CHECK(d->PublicKey.cbData == sizeof v_spki_pubkey_seq); LocalFree(d); }
    ROUNDTRIP(X509_PUBLIC_KEY_INFO, v_spki_rsa_tiny);
}

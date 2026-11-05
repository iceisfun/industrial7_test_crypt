/* crypt32 encode/decode of PKCS and CMS structures: attributes, signer infos, certificate requests,
 * RC2 parameters, S/MIME capabilities, time stamp requests and certificate trust lists. */
#include "kp.h"

#define PKCS7_SIGNER_INFO_T ((LPCSTR)500)
#define CMS_SIGNER_INFO_T   ((LPCSTR)501)

/* Name { CN=A (PrintableString) } and a small RSA SubjectPublicKeyInfo used by several vectors */
static const BYTE name_a[] = {0x30,0x0c,0x31,0x0a,0x30,0x08,6,3,0x55,4,3,0x13,1,0x41};
static const BYTE attr3[] = {0x30,9, 6,2,0x2a,3, 0x31,3, 2,1,5};
static const BYTE attr4[] = {0x30,9, 6,2,0x2a,4, 0x31,3, 2,1,5};
static const BYTE v_05[]   = {2,1,5};

/* ---------------------------------------------------------------- PKCS_ATTRIBUTE */
TEST(kpp_attribute_encode_single_value) {
    REQ_CRYPT32();
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 };
    CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 1, &v };
    ENC_EQ(PKCS_ATTRIBUTE, &a, attr3, sizeof attr3);
}
TEST(kpp_attribute_encode_no_values) {
    REQ_CRYPT32();
    CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 0, NULL };
    ENC_EQ(PKCS_ATTRIBUTE, &a, V(0x30,6, 6,2,0x2a,3, 0x31,0));
}
TEST(kpp_attribute_encode_values_are_der_sorted) {
    REQ_CRYPT32();
    /* the values form a DER SET OF: they are emitted ordered by their encoding, not in input order */
    CRYPT_ATTR_BLOB v[2] = { {2, (BYTE *)"\x05\x00"}, {3, (BYTE *)"\x02\x01\x01"} };
    CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 2, v };
    ENC_EQ(PKCS_ATTRIBUTE, &a, V(0x30,0x0b, 6,2,0x2a,3, 0x31,5, 2,1,1, 5,0));
    CRYPT_ATTR_BLOB w[2] = { {3, (BYTE *)"\x02\x01\x01"}, {2, (BYTE *)"\x05\x00"} };
    a.rgValue = w;
    ENC_EQ(PKCS_ATTRIBUTE, &a, V(0x30,0x0b, 6,2,0x2a,3, 0x31,5, 2,1,1, 5,0));
}
TEST(kpp_attribute_encode_sort_longer_vs_shorter) {
    REQ_CRYPT32();
    /* octet-wise comparison of the encodings: 04 01 ff sorts before 04 02 00 00 */
    CRYPT_ATTR_BLOB v[2] = { {4, (BYTE *)"\x04\x02\x00\x00"}, {3, (BYTE *)"\x04\x01\xff"} };
    CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 2, v };
    ENC_EQ(PKCS_ATTRIBUTE, &a, V(0x30,0x0d, 6,2,0x2a,3, 0x31,7, 4,1,0xff, 4,2,0,0));
}
TEST(kpp_attribute_encode_bad_oid) {
    REQ_CRYPT32();
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 };
    CRYPT_ATTRIBUTE a = { (LPSTR)"not an oid", 1, &v };
    ENC_FAIL(PKCS_ATTRIBUTE, &a, 0);
}
TEST(kpp_attribute_decode) {
    REQ_CRYPT32();
    CRYPT_ATTRIBUTE *r = DEC_OK(PKCS_ATTRIBUTE, attr3, sizeof attr3, 0);
    if (r) { EXPECT_STR(r->pszObjId, "1.2.3"); CHECK(r->cValue == 1); if (r->cValue == 1) BLOB_IS(r->rgValue[0], 2,1,5); kp_free(r); }
}
TEST(kpp_attribute_decode_multiple_values_keep_wire_order) {
    REQ_CRYPT32();
    CRYPT_ATTRIBUTE *r = DEC_OK(PKCS_ATTRIBUTE, V(0x30,0x0b, 6,2,0x2a,3, 0x31,5, 5,0, 2,1,1), 0);
    if (r) { CHECK(r->cValue == 2); if (r->cValue == 2) { BLOB_IS(r->rgValue[0], 5,0); BLOB_IS(r->rgValue[1], 2,1,1); } kp_free(r); }
}
TEST(kpp_attribute_decode_empty_set) {
    REQ_CRYPT32();
    CRYPT_ATTRIBUTE *r = DEC_OK(PKCS_ATTRIBUTE, V(0x30,6, 6,2,0x2a,3, 0x31,0), 0);
    if (r) { EXPECT_STR(r->pszObjId, "1.2.3"); CHECK(r->cValue == 0); kp_free(r); }
}
TEST(kpp_attribute_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(PKCS_ATTRIBUTE, KP_E_BADTAG, 0x31, 0);
    DEC_FAILV(PKCS_ATTRIBUTE, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(PKCS_ATTRIBUTE, KP_E_BADTAG, 0x30, 6, 6, 2, 0x2a, 3, 0x30, 0);       /* values must be a SET */
    DEC_FAILV(PKCS_ATTRIBUTE, 0, 0x30, 4, 6, 2, 0x2a, 3);                          /* no value set */
    DEC_FAILV(PKCS_ATTRIBUTE, KP_E_TRUNC, 0x30, 9, 6, 2, 0x2a, 3, 0x31, 3, 2);
}
TEST(kpp_attribute_many_values_roundtrip) {
    REQ_CRYPT32();
    CRYPT_ATTR_BLOB v[20]; BYTE d[20][3]; DWORD cb;
    for (int i = 0; i < 20; i++) { d[i][0] = 2; d[i][1] = 1; d[i][2] = (BYTE)(19 - i); v[i].cbData = 3; v[i].pbData = d[i]; }
    CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 20, v };
    BYTE *e = kp_enc_alloc(PKCS_ATTRIBUTE, &a, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    CRYPT_ATTRIBUTE *r = kp_dec_alloc(PKCS_ATTRIBUTE, e, cb, 0, NULL);
    CHECK(r && r->cValue == 20);
    if (r && r->cValue == 20) for (int i = 0; i < 20; i++) CHECK(r->rgValue[i].pbData[2] == i);     /* ascending after sorting */
    kp_free(r); kp_free(e);
}

/* ---------------------------------------------------------------- PKCS_ATTRIBUTES */
TEST(kpp_attributes_encode_empty) {
    REQ_CRYPT32();
    CRYPT_ATTRIBUTES as = { 0, NULL };
    ENC_EQ(PKCS_ATTRIBUTES, &as, V(0x31,0));
}
TEST(kpp_attributes_encode_sorted) {
    REQ_CRYPT32();
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 };
    CRYPT_ATTRIBUTE a[2] = { { (LPSTR)"1.2.4", 1, &v }, { (LPSTR)"1.2.3", 1, &v } };
    CRYPT_ATTRIBUTES as = { 2, a };
    ENC_EQ(PKCS_ATTRIBUTES, &as, V(0x31,0x16, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5, 0x30,9,6,2,0x2a,4,0x31,3,2,1,5));
}
TEST(kpp_attributes_encode_single) {
    REQ_CRYPT32();
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 };
    CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 1, &v };
    CRYPT_ATTRIBUTES as = { 1, &a };
    ENC_EQ(PKCS_ATTRIBUTES, &as, V(0x31,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5));
}
TEST(kpp_attributes_decode) {
    REQ_CRYPT32();
    CRYPT_ATTRIBUTES *r = DEC_OK(PKCS_ATTRIBUTES, V(0x31,0x16, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5, 0x30,9,6,2,0x2a,4,0x31,3,2,1,5), 0);
    if (r) {
        CHECK(r->cAttr == 2);
        if (r->cAttr == 2) { EXPECT_STR(r->rgAttr[0].pszObjId, "1.2.3"); EXPECT_STR(r->rgAttr[1].pszObjId, "1.2.4"); CHECK(r->rgAttr[1].cValue == 1); BLOB_IS(r->rgAttr[1].rgValue[0], 2,1,5); }
        kp_free(r);
    }
}
TEST(kpp_attributes_decode_empty_and_errors) {
    REQ_CRYPT32();
    CRYPT_ATTRIBUTES *r = DEC_OK(PKCS_ATTRIBUTES, V(0x31,0), 0);
    if (r) { CHECK(r->cAttr == 0); kp_free(r); }
    DEC_FAILV(PKCS_ATTRIBUTES, KP_E_BADTAG, 0x30, 0);
    DEC_FAILV(PKCS_ATTRIBUTES, KP_E_BADTAG, 0x31, 3, 2, 1, 1);
    DEC_FAILV(PKCS_ATTRIBUTES, KP_E_TRUNC, 0x31, 0x0b, 0x30, 9, 6);
}

/* ---------------------------------------------------------------- PKCS7_SIGNER_INFO / CMS_SIGNER_INFO */
static void fill_signer(CMSG_SIGNER_INFO *s, CRYPT_INTEGER_BLOB *serial, BYTE *sbyte) {
    memset(s, 0, sizeof *s);
    s->dwVersion = 1;
    s->Issuer.cbData = sizeof name_a; s->Issuer.pbData = (BYTE *)name_a;
    *sbyte = 5; serial->cbData = 1; serial->pbData = sbyte; s->SerialNumber = *serial;
    s->HashAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
    s->HashEncryptionAlgorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
    s->EncryptedHash.cbData = 2; s->EncryptedHash.pbData = (BYTE *)"\xaa\xbb";
}
#define SIGNER_BASE \
    2,1,1, 0x30,0x11, 0x30,0x0c,0x31,0x0a,0x30,0x08,6,3,0x55,4,3,0x13,1,0x41, 2,1,5, \
    0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0
#define SIGNER_TAIL 0x30,0x0d,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0, 4,2,0xaa,0xbb
TEST(kpp_pkcs7_signer_encode_minimal) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    ENC_EQ(PKCS7_SIGNER_INFO_T, &s, V(0x30,0x34, SIGNER_BASE, SIGNER_TAIL));
}
TEST(kpp_pkcs7_signer_encode_auth_attrs) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 }; CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 1, &v };
    s.AuthAttrs.cAttr = 1; s.AuthAttrs.rgAttr = &a;
    ENC_EQ(PKCS7_SIGNER_INFO_T, &s, V(0x30,0x41, SIGNER_BASE, 0xa0,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5, SIGNER_TAIL));
}
TEST(kpp_pkcs7_signer_encode_unauth_attrs) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 }; CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 1, &v };
    s.UnauthAttrs.cAttr = 1; s.UnauthAttrs.rgAttr = &a;
    ENC_EQ(PKCS7_SIGNER_INFO_T, &s, V(0x30,0x41, SIGNER_BASE, SIGNER_TAIL, 0xa1,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5));
}
TEST(kpp_pkcs7_signer_encode_both_attr_sets) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 }; CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 1, &v };
    s.AuthAttrs.cAttr = 1; s.AuthAttrs.rgAttr = &a; s.UnauthAttrs.cAttr = 1; s.UnauthAttrs.rgAttr = &a;
    ENC_EQ(PKCS7_SIGNER_INFO_T, &s, V(0x30,0x4e, SIGNER_BASE, 0xa0,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5, SIGNER_TAIL, 0xa1,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5));
}
TEST(kpp_pkcs7_signer_encode_version_and_serial_forms) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    s.dwVersion = 3;
    BYTE big[2] = {0x80, 0x00}; s.SerialNumber.cbData = 2; s.SerialNumber.pbData = big;      /* LE 0x0080 */
    ENC_EQ(PKCS7_SIGNER_INFO_T, &s, V(0x30,0x35, 2,1,3, 0x30,0x12, 0x30,0x0c,0x31,0x0a,0x30,0x08,6,3,0x55,4,3,0x13,1,0x41, 2,2,0,0x80,
        0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, SIGNER_TAIL));
}
TEST(kpp_pkcs7_signer_encode_empty_hash_allowed) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    s.EncryptedHash.cbData = 0; s.EncryptedHash.pbData = NULL;
    ENC_EQ(PKCS7_SIGNER_INFO_T, &s, V(0x30,0x32, SIGNER_BASE, 0x30,0x0d,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0, 4,0));
}
TEST(kpp_pkcs7_signer_encode_bad_issuer_blob) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    s.Issuer.cbData = 0; s.Issuer.pbData = NULL;
    DWORD cb = 0; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, PKCS7_SIGNER_INFO_T, &s, 0, NULL, NULL, &cb);
    t_note("empty issuer name: ok=%d cb=%lu err=0x%lx", ok, cb, ok ? 0 : GetLastError());
}
TEST(kpp_pkcs7_signer_bad_hash_oid) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    s.HashAlgorithm.pszObjId = (LPSTR)"bogus";
    ENC_FAIL(PKCS7_SIGNER_INFO_T, &s, 0);
}
TEST(kpp_pkcs7_signer_decode) {
    REQ_P7();
    CMSG_SIGNER_INFO *r = DEC_OK(PKCS7_SIGNER_INFO_T, V(0x30,0x41, SIGNER_BASE, 0xa0,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5, SIGNER_TAIL), 0);
    if (r) {
        CHECK(r->dwVersion == 1);
        BLOB_IS(r->Issuer, 0x30,0x0c,0x31,0x0a,0x30,0x08,6,3,0x55,4,3,0x13,1,0x41);
        BLOB_IS(r->SerialNumber, 5);
        EXPECT_STR(r->HashAlgorithm.pszObjId, szOID_OIWSEC_sha1);
        BLOB_IS(r->HashAlgorithm.Parameters, 5, 0);
        EXPECT_STR(r->HashEncryptionAlgorithm.pszObjId, szOID_RSA_RSA);
        BLOB_IS(r->EncryptedHash, 0xaa, 0xbb);
        CHECK(r->AuthAttrs.cAttr == 1); CHECK(r->UnauthAttrs.cAttr == 0);
        if (r->AuthAttrs.cAttr == 1) EXPECT_STR(r->AuthAttrs.rgAttr[0].pszObjId, "1.2.3");
        kp_free(r);
    }
}
TEST(kpp_pkcs7_signer_decode_unauth_only) {
    REQ_P7();
    CMSG_SIGNER_INFO *r = DEC_OK(PKCS7_SIGNER_INFO_T, V(0x30,0x41, SIGNER_BASE, SIGNER_TAIL, 0xa1,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5), 0);
    if (r) { CHECK(r->AuthAttrs.cAttr == 0 && r->UnauthAttrs.cAttr == 1); kp_free(r); }
}
TEST(kpp_pkcs7_signer_decode_serial_negative_and_padded) {
    REQ_P7();
    CMSG_SIGNER_INFO *r = DEC_OK(PKCS7_SIGNER_INFO_T, V(0x30,0x35, 2,1,3, 0x30,0x12, 0x30,0x0c,0x31,0x0a,0x30,0x08,6,3,0x55,4,3,0x13,1,0x41, 2,2,0,0x80,
        0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, SIGNER_TAIL), 0);
    if (r) { CHECK(r->dwVersion == 3); BLOB_IS(r->SerialNumber, 0x80, 0x00); kp_free(r); }
}
TEST(kpp_pkcs7_signer_decode_errors) {
    REQ_P7();
    DEC_FAILV(PKCS7_SIGNER_INFO_T, KP_E_BADTAG, 0x31, 0);
    DEC_FAILV(PKCS7_SIGNER_INFO_T, KP_E_BADTAG, 0x30, 3, 4, 1, 1);
    DEC_FAILV(PKCS7_SIGNER_INFO_T, 0, 0x30, 3, 2, 1, 1);
    DEC_FAILV(PKCS7_SIGNER_INFO_T, KP_E_TRUNC, 0x30, 0x34, 2, 1, 1);
}
TEST(kpp_pkcs7_signer_roundtrip_with_attrs) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    CRYPT_ATTR_BLOB v[2] = { {3, (BYTE *)v_05}, {2, (BYTE *)"\x05\x00"} };
    CRYPT_ATTRIBUTE a[2] = { { (LPSTR)"1.2.4", 2, v }, { (LPSTR)"1.2.3", 1, v } };
    s.AuthAttrs.cAttr = 2; s.AuthAttrs.rgAttr = a;
    DWORD cb; BYTE *e = kp_enc_alloc(PKCS7_SIGNER_INFO_T, &s, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    CMSG_SIGNER_INFO *r = kp_dec_alloc(PKCS7_SIGNER_INFO_T, e, cb, 0, NULL);
    CHECK(r && r->AuthAttrs.cAttr == 2);
    if (r && r->AuthAttrs.cAttr == 2) { EXPECT_STR(r->AuthAttrs.rgAttr[0].pszObjId, "1.2.3"); EXPECT_STR(r->AuthAttrs.rgAttr[1].pszObjId, "1.2.4"); CHECK(r->AuthAttrs.rgAttr[1].cValue == 2); }
    kp_free(r); kp_free(e);
}
TEST(kpp_counter_sign_oid_uses_signer_info_codec) {
    REQ_P7();
    CMSG_SIGNER_INFO s; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&s, &ser, &sb);
    DWORD c1 = 0, c2 = 0;
    BYTE *a = kp_enc_alloc(PKCS7_SIGNER_INFO_T, &s, 0, &c1);
    BYTE *b = kp_enc_alloc(szOID_RSA_counterSign, &s, 0, &c2);
    if (!b) { t_note("szOID_RSA_counterSign as structure type: err=0x%lx", GetLastError()); kp_free(a); return; }
    CHECK(a && c1 == c2 && !memcmp(a, b, c1));
    kp_free(a); kp_free(b);
}

static void fill_cms_signer(CMSG_CMS_SIGNER_INFO *s) {
    memset(s, 0, sizeof *s);
    s->dwVersion = 3;
    s->SignerId.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
    s->SignerId.KeyId.cbData = 3; s->SignerId.KeyId.pbData = (BYTE *)"\x01\x02\x03";
    s->HashAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
    s->HashEncryptionAlgorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
    s->EncryptedHash.cbData = 2; s->EncryptedHash.pbData = (BYTE *)"\xaa\xbb";
}
TEST(kpp_cms_signer_encode_key_identifier) {
    REQ_P7();
    CMSG_CMS_SIGNER_INFO s; fill_cms_signer(&s);
    ENC_EQ(CMS_SIGNER_INFO_T, &s, V(0x30,0x26, 2,1,3, 0x80,3,1,2,3, 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, SIGNER_TAIL));
}
TEST(kpp_cms_signer_encode_issuer_serial) {
    REQ_P7();
    CMSG_CMS_SIGNER_INFO s; fill_cms_signer(&s);
    s.dwVersion = 1;
    s.SignerId.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;
    s.SignerId.IssuerSerialNumber.Issuer.cbData = sizeof name_a; s.SignerId.IssuerSerialNumber.Issuer.pbData = (BYTE *)name_a;
    BYTE sb = 5; s.SignerId.IssuerSerialNumber.SerialNumber.cbData = 1; s.SignerId.IssuerSerialNumber.SerialNumber.pbData = &sb;
    ENC_EQ(CMS_SIGNER_INFO_T, &s, V(0x30,0x34, SIGNER_BASE, SIGNER_TAIL));
}
TEST(kpp_cms_signer_encode_invalid_id_choice) {
    REQ_P7();
    CMSG_CMS_SIGNER_INFO s; fill_cms_signer(&s);
    s.SignerId.dwIdChoice = 0;
    DWORD cb = 0; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, CMS_SIGNER_INFO_T, &s, 0, NULL, NULL, &cb);
    t_note("SignerId choice 0: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    s.SignerId.dwIdChoice = 9;
    ok = U(CryptEncodeObjectEx)(KP_ENC, CMS_SIGNER_INFO_T, &s, 0, NULL, NULL, &cb);
    t_note("SignerId choice 9: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}
TEST(kpp_cms_signer_decode_key_identifier) {
    REQ_P7();
    CMSG_CMS_SIGNER_INFO *r = DEC_OK(CMS_SIGNER_INFO_T, V(0x30,0x26, 2,1,3, 0x80,3,1,2,3, 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, SIGNER_TAIL), 0);
    if (r) {
        CHECK(r->dwVersion == 3 && r->SignerId.dwIdChoice == CERT_ID_KEY_IDENTIFIER);
        BLOB_IS(r->SignerId.KeyId, 1,2,3);
        BLOB_IS(r->EncryptedHash, 0xaa, 0xbb);
        kp_free(r);
    }
}
TEST(kpp_cms_signer_decode_issuer_serial) {
    REQ_P7();
    CMSG_CMS_SIGNER_INFO *r = DEC_OK(CMS_SIGNER_INFO_T, V(0x30,0x34, SIGNER_BASE, SIGNER_TAIL), 0);
    if (r) {
        CHECK(r->dwVersion == 1 && r->SignerId.dwIdChoice == CERT_ID_ISSUER_SERIAL_NUMBER);
        BLOB_IS(r->SignerId.IssuerSerialNumber.SerialNumber, 5);
        CHECK(r->SignerId.IssuerSerialNumber.Issuer.cbData == sizeof name_a);
        kp_free(r);
    }
}
TEST(kpp_signer_encode_requires_pkcs7_encoding_bit) {
    REQ_CRYPT32();
    /* the signer-info encoders test the high word of dwCertEncodingType: plain X509_ASN_ENCODING is E_INVALIDARG */
    CMSG_CMS_SIGNER_INFO s; fill_cms_signer(&s);
    ENC_FAIL(CMS_SIGNER_INFO_T, &s, KP_E_INVALIDARG);
    CMSG_SIGNER_INFO p; CRYPT_INTEGER_BLOB ser; BYTE sb; fill_signer(&p, &ser, &sb);
    DWORD cb = 0; SET_ERR(0);
    BOOL ok = U(CryptEncodeObjectEx)(X509_ASN_ENCODING, PKCS7_SIGNER_INFO_T, &p, 0, NULL, NULL, &cb);
    t_note("PKCS7_SIGNER_INFO with X509_ASN_ENCODING only: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    kp_enc_type = KP_ENC_P7;
    ok = U(CryptEncodeObjectEx)(PKCS_7_ASN_ENCODING, CMS_SIGNER_INFO_T, &s, 0, NULL, NULL, &cb);
    CHECK(ok);
    ok = U(CryptEncodeObjectEx)(KP_ENC_P7, CMS_SIGNER_INFO_T, &s, 0, NULL, NULL, &cb);
    CHECK(ok);
    kp_enc_type = X509_ASN_ENCODING;
}
TEST(kpp_cms_signer_decode_errors) {
    REQ_P7();
    DEC_FAILV(CMS_SIGNER_INFO_T, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(CMS_SIGNER_INFO_T, 0, 0x30, 3, 2, 1, 3);
    DEC_FAILV(CMS_SIGNER_INFO_T, KP_E_TRUNC, 0x30, 0x26, 2, 1, 3, 0x80, 3);
}

/* ---------------------------------------------------------------- X509_CERT_REQUEST_TO_BE_SIGNED */
static void fill_req(CERT_REQUEST_INFO *q) {
    memset(q, 0, sizeof *q);
    q->dwVersion = CERT_REQUEST_V1;
    q->Subject.cbData = sizeof name_a; q->Subject.pbData = (BYTE *)name_a;
    q->SubjectPublicKeyInfo.Algorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
    q->SubjectPublicKeyInfo.PublicKey.cbData = 8; q->SubjectPublicKeyInfo.PublicKey.pbData = (BYTE *)"\x30\x06\x02\x01\x0b\x02\x01\x03";
}
#define REQ_BODY 2,1,0, 0x30,0x0c,0x31,0x0a,0x30,0x08,6,3,0x55,4,3,0x13,1,0x41, \
    0x30,0x1a, 0x30,0x0d,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0, 3,9,0, 0x30,6,2,1,0x0b,2,1,3
TEST(kpp_cert_request_encode_no_attributes) {
    REQ_TYPE(X509_CERT_REQUEST_TO_BE_SIGNED);
    CERT_REQUEST_INFO q; fill_req(&q);
    ENC_EQ(X509_CERT_REQUEST_TO_BE_SIGNED, &q, V(0x30,0x2f, REQ_BODY, 0xa0,0));
}
TEST(kpp_cert_request_encode_attribute) {
    REQ_TYPE(X509_CERT_REQUEST_TO_BE_SIGNED);
    CERT_REQUEST_INFO q; fill_req(&q);
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 }; CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 1, &v };
    q.cAttribute = 1; q.rgAttribute = &a;
    ENC_EQ(X509_CERT_REQUEST_TO_BE_SIGNED, &q, V(0x30,0x3a, REQ_BODY, 0xa0,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5));
}
TEST(kpp_cert_request_decode) {
    REQ_TYPE(X509_CERT_REQUEST_TO_BE_SIGNED);
    CERT_REQUEST_INFO *r = DEC_OK(X509_CERT_REQUEST_TO_BE_SIGNED, V(0x30,0x3a, REQ_BODY, 0xa0,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5), 0);
    if (r) {
        CHECK(r->dwVersion == 0);
        CHECK(r->Subject.cbData == sizeof name_a && !memcmp(r->Subject.pbData, name_a, sizeof name_a));
        EXPECT_STR(r->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA);
        BLOB_IS(r->SubjectPublicKeyInfo.PublicKey, 0x30,6,2,1,0x0b,2,1,3);
        CHECK(r->cAttribute == 1);
        if (r->cAttribute == 1) EXPECT_STR(r->rgAttribute[0].pszObjId, "1.2.3");
        kp_free(r);
    }
}
TEST(kpp_cert_request_decode_no_attrs) {
    REQ_TYPE(X509_CERT_REQUEST_TO_BE_SIGNED);
    CERT_REQUEST_INFO *r = DEC_OK(X509_CERT_REQUEST_TO_BE_SIGNED, V(0x30,0x2f, REQ_BODY, 0xa0,0), 0);
    if (r) { CHECK(r->cAttribute == 0); kp_free(r); }
}
TEST(kpp_cert_request_decode_errors) {
    REQ_TYPE(X509_CERT_REQUEST_TO_BE_SIGNED);
    DEC_FAILV(X509_CERT_REQUEST_TO_BE_SIGNED, KP_E_BADTAG, 2, 1, 0);
    DEC_FAILV(X509_CERT_REQUEST_TO_BE_SIGNED, 0, 0x30, 3, 2, 1, 0);
    DEC_FAILV(X509_CERT_REQUEST_TO_BE_SIGNED, KP_E_TRUNC, 0x30, 0x2f, 2, 1, 0, 0x30, 0x0c);
}
TEST(kpp_cert_request_roundtrip_version) {
    REQ_TYPE(X509_CERT_REQUEST_TO_BE_SIGNED);
    CERT_REQUEST_INFO q; fill_req(&q); DWORD cb;
    BYTE *e = kp_enc_alloc(X509_CERT_REQUEST_TO_BE_SIGNED, &q, 0, &cb);
    CHECK(e && cb == 0x2f + 2);
    kp_free(e);
}

/* ---------------------------------------------------------------- PKCS_RC2_CBC_PARAMETERS */
TEST(kpp_rc2_encode_versions) {
    REQ_TYPE(PKCS_RC2_CBC_PARAMETERS);
    CRYPT_RC2_CBC_PARAMETERS p; memset(&p, 0, sizeof p);
    p.dwVersion = CRYPT_RC2_128BIT_VERSION; ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,3, 2,1,58));
    p.dwVersion = CRYPT_RC2_64BIT_VERSION;  ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,3, 2,1,120));
    p.dwVersion = CRYPT_RC2_56BIT_VERSION;  ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,3, 2,1,52));
    p.dwVersion = CRYPT_RC2_40BIT_VERSION;  ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,4, 2,2,0,160));
}
TEST(kpp_rc2_encode_iv) {
    REQ_TYPE(PKCS_RC2_CBC_PARAMETERS);
    CRYPT_RC2_CBC_PARAMETERS p; memset(&p, 0, sizeof p);
    p.dwVersion = CRYPT_RC2_64BIT_VERSION; p.fIV = TRUE;
    for (int i = 0; i < 8; i++) p.rgbIV[i] = (BYTE)(i + 1);
    ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,0x0d, 2,1,120, 4,8,1,2,3,4,5,6,7,8));
    p.fIV = FALSE;
    ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,3, 2,1,120));
}
TEST(kpp_rc2_encode_nonstandard_versions) {
    REQ_TYPE(PKCS_RC2_CBC_PARAMETERS);
    CRYPT_RC2_CBC_PARAMETERS p; memset(&p, 0, sizeof p);
    p.dwVersion = 0; ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,3, 2,1,0));
    p.dwVersion = 128; ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,4, 2,2,0,128));
    p.dwVersion = 1000; ENC_EQ(PKCS_RC2_CBC_PARAMETERS, &p, V(0x30,4, 2,2,3,0xe8));
}
TEST(kpp_rc2_decode) {
    REQ_TYPE(PKCS_RC2_CBC_PARAMETERS);
    CRYPT_RC2_CBC_PARAMETERS *r = DEC_OK(PKCS_RC2_CBC_PARAMETERS, V(0x30,0x0d, 2,1,120, 4,8,1,2,3,4,5,6,7,8), 0);
    if (r) { CHECK(r->dwVersion == 120 && r->fIV); CHECK(!memcmp(r->rgbIV, "\x01\x02\x03\x04\x05\x06\x07\x08", 8)); kp_free(r); }
    r = DEC_OK(PKCS_RC2_CBC_PARAMETERS, V(0x30,4, 2,2,0,160), 0);
    if (r) { CHECK(r->dwVersion == 160 && !r->fIV); kp_free(r); }
}
TEST(kpp_rc2_decode_sizes) {
    REQ_TYPE(PKCS_RC2_CBC_PARAMETERS);
    DWORD cb = 0;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, PKCS_RC2_CBC_PARAMETERS, (const BYTE[]){0x30,3,2,1,58}, 5, 0, NULL, NULL, &cb));
    EXPECT_EQ(cb, sizeof(CRYPT_RC2_CBC_PARAMETERS));
}
TEST(kpp_rc2_decode_errors) {
    REQ_TYPE(PKCS_RC2_CBC_PARAMETERS);
    DEC_FAILV(PKCS_RC2_CBC_PARAMETERS, KP_E_BADTAG, 2, 1, 58);
    DEC_FAILV(PKCS_RC2_CBC_PARAMETERS, 0, 0x30, 0);
    DEC_FAILV(PKCS_RC2_CBC_PARAMETERS, KP_E_BADTAG, 0x30, 5, 2, 1, 58, 2, 0);
    DEC_FAILV(PKCS_RC2_CBC_PARAMETERS, KP_E_TRUNC, 0x30, 0x0d, 2, 1, 58, 4, 8, 1);
}
TEST(kpp_rc2_decode_short_iv) {
    REQ_TYPE(PKCS_RC2_CBC_PARAMETERS);
    DWORD cb = 100; BYTE buf[100];
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, PKCS_RC2_CBC_PARAMETERS, (const BYTE[]){0x30,7,2,1,58,4,2,1,2}, 9, 0, NULL, buf, &cb);
    t_note("4-byte IV in RC2 parameters: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}

/* ---------------------------------------------------------------- PKCS_SMIME_CAPABILITIES */
TEST(kpp_smime_encode_empty) {
    REQ_CRYPT32();
    CRYPT_SMIME_CAPABILITIES c = { 0, NULL };
    ENC_EQ(PKCS_SMIME_CAPABILITIES, &c, V(0x30,0));
}
TEST(kpp_smime_encode_absent_vs_present_params) {
    REQ_CRYPT32();
    CRYPT_SMIME_CAPABILITY cap[2];
    cap[0].pszObjId = (LPSTR)"1.2.3"; cap[0].Parameters.cbData = 0; cap[0].Parameters.pbData = NULL;
    cap[1].pszObjId = (LPSTR)"1.2.4"; cap[1].Parameters.cbData = 3; cap[1].Parameters.pbData = (BYTE *)"\x02\x01\x40";
    CRYPT_SMIME_CAPABILITIES c = { 2, cap };
    /* unlike algorithm identifiers, no NULL is substituted for missing parameters */
    ENC_EQ(PKCS_SMIME_CAPABILITIES, &c, V(0x30,0x0f, 0x30,4,6,2,0x2a,3, 0x30,7,6,2,0x2a,4,2,1,0x40));
}
TEST(kpp_smime_encode_preserves_order) {
    REQ_CRYPT32();
    CRYPT_SMIME_CAPABILITY cap[2];
    cap[0].pszObjId = (LPSTR)"1.2.9"; cap[0].Parameters.cbData = 0; cap[0].Parameters.pbData = NULL;
    cap[1].pszObjId = (LPSTR)"1.2.3"; cap[1].Parameters.cbData = 0; cap[1].Parameters.pbData = NULL;
    CRYPT_SMIME_CAPABILITIES c = { 2, cap };
    ENC_EQ(PKCS_SMIME_CAPABILITIES, &c, V(0x30,0x0c, 0x30,4,6,2,0x2a,9, 0x30,4,6,2,0x2a,3));      /* a SEQUENCE OF, not sorted */
}
TEST(kpp_smime_encode_bad_oid) {
    REQ_CRYPT32();
    CRYPT_SMIME_CAPABILITY cap = { (LPSTR)"zzz", { 0, NULL } };
    CRYPT_SMIME_CAPABILITIES c = { 1, &cap };
    ENC_FAIL(PKCS_SMIME_CAPABILITIES, &c, 0);
}
TEST(kpp_smime_decode) {
    REQ_CRYPT32();
    CRYPT_SMIME_CAPABILITIES *r = DEC_OK(PKCS_SMIME_CAPABILITIES, V(0x30,0x0f, 0x30,4,6,2,0x2a,3, 0x30,7,6,2,0x2a,4,2,1,0x40), 0);
    if (r) {
        CHECK(r->cCapability == 2);
        if (r->cCapability == 2) { EXPECT_STR(r->rgCapability[0].pszObjId, "1.2.3"); CHECK(r->rgCapability[0].Parameters.cbData == 0); EXPECT_STR(r->rgCapability[1].pszObjId, "1.2.4"); BLOB_IS(r->rgCapability[1].Parameters, 2,1,0x40); }
        kp_free(r);
    }
}
TEST(kpp_smime_decode_null_params_kept) {
    REQ_CRYPT32();
    CRYPT_SMIME_CAPABILITIES *r = DEC_OK(PKCS_SMIME_CAPABILITIES, V(0x30,8, 0x30,6,6,2,0x2a,3,5,0), 0);
    if (r) { CHECK(r->cCapability == 1); if (r->cCapability == 1) BLOB_IS(r->rgCapability[0].Parameters, 5, 0); kp_free(r); }
}
TEST(kpp_smime_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(PKCS_SMIME_CAPABILITIES, KP_E_BADTAG, 0x31, 0);
    DEC_FAILV(PKCS_SMIME_CAPABILITIES, KP_E_BADTAG, 0x30, 3, 2, 1, 1);
    DEC_FAILV(PKCS_SMIME_CAPABILITIES, KP_E_TRUNC, 0x30, 8, 0x30, 6);
}
TEST(kpp_smime_oid_string_type) {
    REQ_CRYPT32();
    CRYPT_SMIME_CAPABILITY cap = { (LPSTR)"1.2.3", { 0, NULL } };
    CRYPT_SMIME_CAPABILITIES c = { 1, &cap };
    ENC_EQ(szOID_RSA_SMIMECapabilities, &c, V(0x30,6, 0x30,4,6,2,0x2a,3));
    CRYPT_SMIME_CAPABILITIES *r = DEC_OK(szOID_RSA_SMIMECapabilities, V(0x30,6, 0x30,4,6,2,0x2a,3), 0);
    if (r) { CHECK(r->cCapability == 1); kp_free(r); }
}

/* ---------------------------------------------------------------- szOID_RSA_signingTime */
TEST(kpp_signing_time_oid_encode_matches_choice_of_time) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    ENC_EQ(szOID_RSA_signingTime, &ft, V(0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z'));
    st.wYear = 2050; SystemTimeToFileTime(&st, &ft);
    { DWORD cb = 0; BYTE *e = kp_enc_alloc(szOID_RSA_signingTime, &ft, 0, &cb);       /* docs: UTC time with a two-digit year */
      t_note("signingTime for year 2050: %s, %lu bytes, tag 0x%02x", e ? "encodes" : "fails", cb, e ? e[0] : 0); kp_free(e); }
}
TEST(kpp_signing_time_oid_decode) {
    REQ_CRYPT32();
    FILETIME *f = DEC_OK(szOID_RSA_signingTime, V(0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z'), 0);
    if (f) { SYSTEMTIME st; FileTimeToSystemTime(f, &st); CHECK(st.wYear == 2005 && st.wMonth == 6 && st.wDay == 6 && st.wHour == 16 && st.wMinute == 10); kp_free(f); }
}

/* ---------------------------------------------------------------- PKCS_TIME_REQUEST */
TEST(kpp_time_request_encode_no_attributes) {
    REQ_TYPE(PKCS_TIME_REQUEST);
    CRYPT_TIME_STAMP_REQUEST_INFO q; memset(&q, 0, sizeof q);
    q.pszTimeStampAlgorithm = (LPSTR)"1.2.3"; q.pszContentType = (LPSTR)"1.2.4";
    q.Content.cbData = 3; q.Content.pbData = (BYTE *)"\x04\x01\x77";
    ENC_EQ(PKCS_TIME_REQUEST, &q, V(0x30,0x0f, 6,2,0x2a,3, 0x30,9, 6,2,0x2a,4, 0xa0,3,4,1,0x77));
}
TEST(kpp_time_request_encode_with_attribute) {
    REQ_TYPE(PKCS_TIME_REQUEST);
    CRYPT_TIME_STAMP_REQUEST_INFO q; memset(&q, 0, sizeof q);
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 }; CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 1, &v };
    q.pszTimeStampAlgorithm = (LPSTR)"1.2.3"; q.pszContentType = (LPSTR)"1.2.4";
    q.Content.cbData = 3; q.Content.pbData = (BYTE *)"\x04\x01\x77"; q.cAttribute = 1; q.rgAttribute = &a;
    ENC_EQ(PKCS_TIME_REQUEST, &q, V(0x30,0x1c, 6,2,0x2a,3, 0x31,0x0b, 0x30,9,6,2,0x2a,3,0x31,3,2,1,5, 0x30,9, 6,2,0x2a,4, 0xa0,3,4,1,0x77));
}
TEST(kpp_time_request_decode) {
    REQ_TYPE(PKCS_TIME_REQUEST);
    CRYPT_TIME_STAMP_REQUEST_INFO *r = DEC_OK(PKCS_TIME_REQUEST, V(0x30,0x0f, 6,2,0x2a,3, 0x30,9, 6,2,0x2a,4, 0xa0,3,4,1,0x77), 0);
    if (r) { EXPECT_STR(r->pszTimeStampAlgorithm, "1.2.3"); EXPECT_STR(r->pszContentType, "1.2.4"); BLOB_IS(r->Content, 4,1,0x77); CHECK(r->cAttribute == 0); kp_free(r); }
}
TEST(kpp_time_request_decode_errors) {
    REQ_TYPE(PKCS_TIME_REQUEST);
    DEC_FAILV(PKCS_TIME_REQUEST, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(PKCS_TIME_REQUEST, 0, 0x30, 4, 6, 2, 0x2a, 3);
}

/* ---------------------------------------------------------------- PKCS_CTL / PKCS_SORTED_CTL */
static const char *ctl_usage[] = { "1.2.3" };
static void fill_ctl(CTL_INFO *c, FILETIME *tu) {
    memset(c, 0, sizeof *c);
    c->SubjectUsage.cUsageIdentifier = 1; c->SubjectUsage.rgpszUsageIdentifier = (LPSTR *)ctl_usage;
    c->ThisUpdate = *tu;
    c->SubjectAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
}
TEST(kpp_ctl_encode_minimal) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft);
    ENC_EQ(PKCS_CTL, &c, V(0x30,0x20, 0x30,4,6,2,0x2a,3, 0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z', 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0));
}
TEST(kpp_ctl_encode_identifiers_and_next_update) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft);
    BYTE lid[] = { 'i', 'd' }; BYTE seq[] = { 7 };
    c.ListIdentifier.cbData = 2; c.ListIdentifier.pbData = lid;
    c.SequenceNumber.cbData = 1; c.SequenceNumber.pbData = seq;
    st.wYear = 2006; SystemTimeToFileTime(&st, &c.NextUpdate);
    ENC_EQ(PKCS_CTL, &c, V(0x30,0x36, 0x30,4,6,2,0x2a,3, 4,2,'i','d', 2,1,7,
        0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z', 0x17,0x0d,'0','6','0','6','0','6','1','6','1','0','0','0','Z', 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0));
}
TEST(kpp_ctl_version_default_omitted_and_v1_explicit) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft);
    DWORD cb0, cb1; BYTE *e0 = kp_enc_alloc(PKCS_CTL, &c, 0, &cb0);
    c.dwVersion = 1; BYTE *e1 = kp_enc_alloc(PKCS_CTL, &c, 0, &cb1);
    CHECK(e0 && e1);
    if (e0 && e1) { CHECK(cb1 == cb0 + 3); CHECK(e1[2] == 2 && e1[3] == 1 && e1[4] == 1); }     /* version 1 is written, version 0 (v1 of the spec) is the DEFAULT */
    kp_free(e0); kp_free(e1);
}
TEST(kpp_ctl_decode_roundtrip) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft);
    BYTE lid[] = { 'i', 'd' }; c.ListIdentifier.cbData = 2; c.ListIdentifier.pbData = lid;
    DWORD cb; BYTE *e = kp_enc_alloc(PKCS_CTL, &c, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    CTL_INFO *r = kp_dec_alloc(PKCS_CTL, e, cb, 0, NULL);
    CHECK(r != NULL);
    if (r) {
        CHECK(r->dwVersion == 0 && r->SubjectUsage.cUsageIdentifier == 1);
        if (r->SubjectUsage.cUsageIdentifier == 1) EXPECT_STR(r->SubjectUsage.rgpszUsageIdentifier[0], "1.2.3");
        BLOB_IS(r->ListIdentifier, 'i', 'd');
        CHECK(r->SequenceNumber.cbData == 0);
        CHECK(r->ThisUpdate.dwLowDateTime == ft.dwLowDateTime && r->ThisUpdate.dwHighDateTime == ft.dwHighDateTime);
        CHECK(r->NextUpdate.dwLowDateTime == 0 && r->NextUpdate.dwHighDateTime == 0);
        EXPECT_STR(r->SubjectAlgorithm.pszObjId, szOID_OIWSEC_sha1);
        CHECK(r->cCTLEntry == 0 && r->cExtension == 0);
        kp_free(r);
    }
    kp_free(e);
}
TEST(kpp_ctl_entries_roundtrip) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft);
    BYTE id1[] = { 1, 2, 3 }, id2[] = { 9 };
    CTL_ENTRY ent[2]; memset(ent, 0, sizeof ent);
    ent[0].SubjectIdentifier.cbData = 3; ent[0].SubjectIdentifier.pbData = id1;
    ent[1].SubjectIdentifier.cbData = 1; ent[1].SubjectIdentifier.pbData = id2;
    c.cCTLEntry = 2; c.rgCTLEntry = ent;
    DWORD cb; BYTE *e = kp_enc_alloc(PKCS_CTL, &c, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    CTL_INFO *r = kp_dec_alloc(PKCS_CTL, e, cb, 0, NULL);
    CHECK(r && r->cCTLEntry == 2);
    if (r && r->cCTLEntry == 2) {
        BLOB_IS(r->rgCTLEntry[0].SubjectIdentifier, 1, 2, 3); BLOB_IS(r->rgCTLEntry[1].SubjectIdentifier, 9);
        CHECK(r->rgCTLEntry[0].cAttribute == 0);
    }
    kp_free(r); kp_free(e);
}
TEST(kpp_ctl_entry_attributes_roundtrip) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft);
    BYTE id1[] = { 1, 2, 3 };
    CRYPT_ATTR_BLOB v = { 3, (BYTE *)v_05 }; CRYPT_ATTRIBUTE a = { (LPSTR)"1.2.3", 1, &v };
    CTL_ENTRY ent; memset(&ent, 0, sizeof ent);
    ent.SubjectIdentifier.cbData = 3; ent.SubjectIdentifier.pbData = id1; ent.cAttribute = 1; ent.rgAttribute = &a;
    c.cCTLEntry = 1; c.rgCTLEntry = &ent;
    DWORD cb; BYTE *e = kp_enc_alloc(PKCS_CTL, &c, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    CTL_INFO *r = kp_dec_alloc(PKCS_CTL, e, cb, 0, NULL);
    CHECK(r && r->cCTLEntry == 1 && r->rgCTLEntry[0].cAttribute == 1);
    if (r && r->cCTLEntry == 1 && r->rgCTLEntry[0].cAttribute == 1) EXPECT_STR(r->rgCTLEntry[0].rgAttribute[0].pszObjId, "1.2.3");
    kp_free(r); kp_free(e);
}
TEST(kpp_ctl_extensions_roundtrip) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft);
    CERT_EXTENSION ex = { (LPSTR)"1.2.3.4", TRUE, { 3, (BYTE *)"\x04\x01\x01" } };
    c.cExtension = 1; c.rgExtension = &ex;
    DWORD cb; BYTE *e = kp_enc_alloc(PKCS_CTL, &c, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    CTL_INFO *r = kp_dec_alloc(PKCS_CTL, e, cb, 0, NULL);
    CHECK(r && r->cExtension == 1);
    if (r && r->cExtension == 1) { EXPECT_STR(r->rgExtension[0].pszObjId, "1.2.3.4"); CHECK(r->rgExtension[0].fCritical); BLOB_IS(r->rgExtension[0].Value, 4,1,1); }
    kp_free(r); kp_free(e);
}
TEST(kpp_ctl_encode_bad_usage_oid) {
    REQ_CRYPT32();
    static const char *bad[] = { "not an oid" };
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft); c.SubjectUsage.rgpszUsageIdentifier = (LPSTR *)bad;
    ENC_FAIL(PKCS_CTL, &c, 0);
}
TEST(kpp_ctl_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(PKCS_CTL, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(PKCS_CTL, 0, 0x30, 0);
    DEC_FAILV(PKCS_CTL, KP_E_TRUNC, 0x30, 0x20, 0x30, 4);
}
TEST(kpp_sorted_ctl_encode_note) {
    REQ_CRYPT32();
    SYSTEMTIME st = { 2005, 6, 0, 6, 16, 10, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    CTL_INFO c; fill_ctl(&c, &ft);
    BYTE id1[] = { 1, 2, 3 }, id2[] = { 9 };
    CTL_ENTRY ent[2]; memset(ent, 0, sizeof ent);
    ent[0].SubjectIdentifier.cbData = 1; ent[0].SubjectIdentifier.pbData = id2;
    ent[1].SubjectIdentifier.cbData = 3; ent[1].SubjectIdentifier.pbData = id1;
    c.cCTLEntry = 2; c.rgCTLEntry = ent;
    DWORD cb = 0; BYTE *e = kp_enc_alloc(PKCS_SORTED_CTL, &c, 0, &cb);
    if (!e) { t_note("PKCS_SORTED_CTL encode: err=0x%lx", GetLastError()); return; }
    DWORD cb2; BYTE *p = kp_enc_alloc(PKCS_CTL, &c, 0, &cb2);
    CHECK(p != NULL);
    t_note("sorted CTL %lu bytes, plain CTL %lu bytes", cb, cb2);
    CHECK(e[0] == 0x30);
    kp_free(e); kp_free(p);
}

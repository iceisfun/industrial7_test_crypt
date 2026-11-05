/* CTL contexts: creation, decoded CTL_INFO, duplicate/free, properties, store operations, finders. */
#include "cc.h"

#define E_INVALID_DATA 13
static void rel(PCCTL_CONTEXT c) { if (c) U(CertFreeCTLContext)(c); }
static void relc(PCCERT_CONTEXT c) { if (c) U(CertFreeCertificateContext)(c); }
static int blob_is(const CRYPT_DATA_BLOB *b, const BYTE *p, DWORD n) { return b->cbData == n && (n == 0 || !memcmp(b->pbData, p, n)); }

/* ---- CertCreateCTLContext ---- */
TEST(ctlctx_create_bad_encoding_type) {
    REQUIRE(U(CertCreateCTLContext));
    SET_ERR(0);
    PCCTL_CONTEXT c = U(CertCreateCTLContext)(0, VEC(v_ctl_signed));
    CHECK(c == NULL); EXPECT_ERR(CC_E_INVALIDARG);
    rel(c);
    SET_ERR(0);
    c = U(CertCreateCTLContext)(0, NULL, 0);
    CHECK(c == NULL); EXPECT_ERR(CC_E_INVALIDARG);
}
TEST(ctlctx_create_null_data) {
    REQUIRE(U(CertCreateCTLContext));
    SET_ERR(0);
    PCCTL_CONTEXT c = U(CertCreateCTLContext)(CC_X509, NULL, 0);
    CHECK(c == NULL); EXPECT_ERR(E_INVALID_DATA);
    BYTE z = 0;
    SET_ERR(0);
    c = U(CertCreateCTLContext)(CC_X509, &z, 0);
    CHECK(c == NULL); EXPECT_ERR(E_INVALID_DATA);
}
TEST(ctlctx_create_bare_ctl_rejected) {
    /* a CTL must arrive wrapped in a PKCS#7 SignedData */
    REQUIRE(U(CertCreateCTLContext));
    SET_ERR(0);
    PCCTL_CONTEXT c = U(CertCreateCTLContext)(CC_X509, VEC(v_ctl_content));
    CHECK(c == NULL); EXPECT_ERR(E_INVALID_DATA);
    SET_ERR(0);
    c = U(CertCreateCTLContext)(CC_X509, VEC(v_ctl_content_min));
    CHECK(c == NULL); EXPECT_ERR(E_INVALID_DATA);
}
TEST(ctlctx_create_wrong_object_rejected) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c;
    SET_ERR(0);
    c = U(CertCreateCTLContext)(CC_X509, VEC(v_crl_basic));
    CHECK(c == NULL); EXPECT_ERR(E_INVALID_DATA); rel(c);
    SET_ERR(0);
    c = U(CertCreateCTLContext)(CC_X509, VEC(v_ca1));
    CHECK(c == NULL); rel(c);
}
TEST(ctlctx_create_wrong_inner_content_type) {
    REQUIRE(U(CertCreateCTLContext));
    SET_ERR(0);
    PCCTL_CONTEXT c = U(CertCreateCTLContext)(CC_X509, VEC(v_ctl_signed_wrongtype));
    CHECK(c == NULL); EXPECT_ERR(E_INVALID_DATA);
    rel(c);
}
TEST(ctlctx_create_truncated) {
    REQUIRE(U(CertCreateCTLContext));
    static const DWORD cuts[] = { 1, 4, 8, 64, 200, 400 };
    for (unsigned i = 0; i < sizeof cuts / sizeof cuts[0]; i++) {
        PCCTL_CONTEXT c = U(CertCreateCTLContext)(CC_X509, v_ctl_signed, sizeof v_ctl_signed - cuts[i]);
        CHECKF(c == NULL, "cut %lu", cuts[i]);
        rel(c);
    }
    PCCTL_CONTEXT c = U(CertCreateCTLContext)(CC_X509, v_ctl_signed, 5);
    CHECK(c == NULL); rel(c);
}
TEST(ctlctx_create_signed) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    CHECK(c != NULL);
    if (!c) return;
    EXPECT_EQ(c->dwMsgAndCertEncodingType, CC_X509P7);
    EXPECT_EQ(c->cbCtlEncoded, sizeof v_ctl_signed);
    CHECK(c->pbCtlEncoded != v_ctl_signed);
    CHECK(!memcmp(c->pbCtlEncoded, v_ctl_signed, sizeof v_ctl_signed));
    CHECK(c->hCryptMsg != NULL);
    EXPECT_EQ(c->cbCtlContent, sizeof v_ctl_content);
    CHECK(c->pbCtlContent && !memcmp(c->pbCtlContent, v_ctl_content, sizeof v_ctl_content));
    rel(c);
}
TEST(ctlctx_create_bad_signature_still_loads) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed_badsig));
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->pCtlInfo->cCTLEntry, 3); rel(c); }
}
TEST(ctlctx_create_without_embedded_certs) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed_nocerts));
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->pCtlInfo->cCTLEntry, 3); rel(c); }
}
TEST(ctlctx_create_usage_only_no_entries) {
    REQUIRE(U(CertCreateCTLContext));
    SET_ERR(0);
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed_usage_only));
    t_note("CTL with an empty subject list: %s (err 0x%lx)", c ? "created" : "rejected", c ? 0 : GetLastError());
    if (c) EXPECT_EQ(c->pCtlInfo->cCTLEntry, 0);
    rel(c);
}
TEST(ctlctx_info_header) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    PCTL_INFO i = c->pCtlInfo;
    EXPECT_EQ(i->dwVersion, 0);
    EXPECT_EQ(i->SubjectUsage.cUsageIdentifier, 2);
    if (i->SubjectUsage.cUsageIdentifier == 2) {
        EXPECT_STR(i->SubjectUsage.rgpszUsageIdentifier[0], "1.3.6.1.5.5.7.3.3");
        EXPECT_STR(i->SubjectUsage.rgpszUsageIdentifier[1], "1.3.6.1.5.5.7.3.1");
    }
    CHECK(blob_is(&i->ListIdentifier, (const BYTE *)"cryptt-list-1", 13));
    static const BYTE seq[] = { 0x02, 0x01 };
    CHECK(blob_is(&i->SequenceNumber, seq, 2));
    EXPECT_EQ(cc_ft(i->ThisUpdate), V_THIS_FT);
    EXPECT_EQ(cc_ft(i->NextUpdate), V_NEXT_FT);
    EXPECT_STR(i->SubjectAlgorithm.pszObjId, "1.3.14.3.2.26");
    EXPECT_EQ(i->cExtension, 0);
    rel(c);
}
TEST(ctlctx_info_minimal_optional_fields_absent) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed_min));
    REQUIRE(c);
    PCTL_INFO i = c->pCtlInfo;
    EXPECT_EQ(i->ListIdentifier.cbData, 0);
    EXPECT_EQ(i->SequenceNumber.cbData, 0);
    EXPECT_EQ(cc_ft(i->NextUpdate), 0);
    EXPECT_EQ(cc_ft(i->ThisUpdate), V_THIS_FT);
    EXPECT_EQ(i->cCTLEntry, 1);
    rel(c);
}
TEST(ctlctx_info_entries) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    PCTL_INFO i = c->pCtlInfo;
    REQUIRE(i->cCTLEntry == 3);
    CHECK(blob_is(&i->rgCTLEntry[0].SubjectIdentifier, VEC(v_sha1_1001)));
    CHECK(blob_is(&i->rgCTLEntry[1].SubjectIdentifier, VEC(v_sha1_1002)));
    CHECK(blob_is(&i->rgCTLEntry[2].SubjectIdentifier, VEC(v_sha1_1003)));
    EXPECT_EQ(i->rgCTLEntry[0].cAttribute, 1);
    EXPECT_EQ(i->rgCTLEntry[1].cAttribute, 1);
    EXPECT_EQ(i->rgCTLEntry[2].cAttribute, 1);
    if (i->rgCTLEntry[0].cAttribute == 1) {
        PCRYPT_ATTRIBUTE a = &i->rgCTLEntry[0].rgAttribute[0];
        EXPECT_STR(a->pszObjId, "1.3.6.1.4.1.311.10.11.11");
        EXPECT_EQ(a->cValue, 1);
        if (a->cValue == 1) {
            /* the attribute value is DER: OCTET STRING { friendly name, UTF-16LE } */
            CHECK(a->rgValue[0].cbData == sizeof v_ctl_prop11_value + 2);
            CHECK(a->rgValue[0].pbData[0] == 0x04 && a->rgValue[0].pbData[1] == sizeof v_ctl_prop11_value);
            CHECK(!memcmp(a->rgValue[0].pbData + 2, v_ctl_prop11_value, sizeof v_ctl_prop11_value));
        }
    }
    rel(c);
}
TEST(ctlctx_info_expired_ctl_nextupdate) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed_expired));
    REQUIRE(c);
    EXPECT_EQ(cc_ft(c->pCtlInfo->NextUpdate), V_EXP_NEXT_FT);
    CHECK(blob_is(&c->pCtlInfo->ListIdentifier, (const BYTE *)"cryptt-list-exp", 15));
    EXPECT_EQ(c->pCtlInfo->cCTLEntry, 2);
    rel(c);
}
TEST(ctlctx_encoding_type_always_includes_pkcs7) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = U(CertCreateCTLContext)(CC_X509P7, VEC(v_ctl_signed));
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->dwMsgAndCertEncodingType, CC_X509P7); rel(c); }
    c = U(CertCreateCTLContext)(PKCS_7_ASN_ENCODING, VEC(v_ctl_signed));
    t_note("PKCS7-only encoding type for a CTL: %s", c ? "accepted" : "rejected");
    rel(c);
}

/* ---- dup / free ---- */
TEST(ctlctx_duplicate_null) { REQUIRE(U(CertDuplicateCTLContext)); CHECK(U(CertDuplicateCTLContext)(NULL) == NULL); }
TEST(ctlctx_free_null_is_true) { REQUIRE(U(CertFreeCTLContext)); CHECK(U(CertFreeCTLContext)(NULL)); }
TEST(ctlctx_duplicate_same_pointer) {
    REQUIRE(U(CertDuplicateCTLContext));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    PCCTL_CONTEXT d = U(CertDuplicateCTLContext)(c);
    CHECK(d == c);
    CHECK(U(CertFreeCTLContext)(d));
    EXPECT_EQ(c->pCtlInfo->cCTLEntry, 3);
    CHECK(U(CertFreeCTLContext)(c));
}
TEST(ctlctx_store_copy_survives_store_close) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCTL_CONTEXT c = NULL;
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, &c));
    REQUIRE(c);
    CHECK(c->hCertStore == s);
    cc_close(s);
    EXPECT_EQ(c->pCtlInfo->cCTLEntry, 3);
    rel(c);
}

/* ---- properties ---- */
#define CPROP CERT_DESCRIPTION_PROP_ID
TEST(ctlprop_enum_fresh_has_none) {
    REQUIRE(U(CertEnumCTLContextProperties));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    EXPECT_EQ(cc_props_ctl(c), 0);
    rel(c);
}
TEST(ctlprop_set_prop0_invalidarg) {
    REQUIRE(U(CertSetCTLContextProperty));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    SET_ERR(0);
    CHECK(!U(CertSetCTLContextProperty)(c, 0, 0, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    SET_ERR(0);
    CHECK(!U(CertSetCTLContextProperty)(NULL, 0, 0, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    rel(c);
}
TEST(ctlprop_get_missing) {
    REQUIRE(U(CertGetCTLContextProperty));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    DWORD cb = 0;
    SET_ERR(0);
    CHECK(!U(CertGetCTLContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb)); EXPECT_ERR(CC_E_NOT_FOUND);
    SET_ERR(0);
    CHECK(!U(CertGetCTLContextProperty)(c, CPROP, NULL, &cb)); EXPECT_ERR(CC_E_NOT_FOUND);
    rel(c);
}
TEST(ctlprop_access_state_implicit) {
    REQUIRE(U(CertGetCTLContextProperty));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    DWORD cb = 0, a = 0xdeadbeef;
    CHECK(U(CertGetCTLContextProperty)(c, CERT_ACCESS_STATE_PROP_ID, NULL, &cb));
    EXPECT_EQ(cb, 4);
    cb = 4;
    CHECK(U(CertGetCTLContextProperty)(c, CERT_ACCESS_STATE_PROP_ID, &a, &cb));
    CHECK(!(a & CERT_ACCESS_STATE_WRITE_PERSIST_FLAG));
    EXPECT_EQ(cc_props_ctl(c), 0);
    rel(c);
}
static void ctl_hash_case(const BYTE *der, DWORD n, DWORD propid, ALG_ID alg, DWORD len) {
    PCCTL_CONTEXT c = cc_ctl(der, n);
    REQUIRE(c);
    BYTE want[32], got[32]; DWORD wcb = sizeof want, gcb = 0;
    CHECK(cc_hash(alg, der, n, want, &wcb));
    CHECK(U(CertGetCTLContextProperty)(c, propid, NULL, &gcb));
    EXPECT_EQ(gcb, len);
    gcb = len - 1;
    SET_ERR(0);
    CHECK(!U(CertGetCTLContextProperty)(c, propid, got, &gcb)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(gcb, len);
    gcb = sizeof got;
    CHECK(U(CertGetCTLContextProperty)(c, propid, got, &gcb));
    EXPECT_EQ(gcb, len);
    CHECK(!memcmp(got, want, len));
    rel(c);
}
TEST(ctlprop_sha1_hash) { REQUIRE(U(CertGetCTLContextProperty)); ctl_hash_case(VEC(v_ctl_signed), CERT_HASH_PROP_ID, CALG_SHA1, 20); }
TEST(ctlprop_sha1_hash_alias) { REQUIRE(U(CertGetCTLContextProperty)); ctl_hash_case(VEC(v_ctl_signed_min), CERT_SHA1_HASH_PROP_ID, CALG_SHA1, 20); }
TEST(ctlprop_md5_hash) { REQUIRE(U(CertGetCTLContextProperty)); ctl_hash_case(VEC(v_ctl_signed), CERT_MD5_HASH_PROP_ID, CALG_MD5, 16); }
TEST(ctlprop_hash_covers_whole_message) {
    /* a different signature gives a different hash although the CTL content is the same */
    REQUIRE(U(CertGetCTLContextProperty));
    PCCTL_CONTEXT a = cc_ctl(VEC(v_ctl_signed)), b = cc_ctl(VEC(v_ctl_signed_badsig));
    REQUIRE(a && b);
    BYTE ha[20], hb[20]; DWORD ca = 20, cb = 20;
    CHECK(U(CertGetCTLContextProperty)(a, CERT_HASH_PROP_ID, ha, &ca));
    CHECK(U(CertGetCTLContextProperty)(b, CERT_HASH_PROP_ID, hb, &cb));
    CHECK(memcmp(ha, hb, 20) != 0);
    rel(a); rel(b);
}
TEST(ctlprop_hash_becomes_enumerated) {
    REQUIRE(U(CertGetCTLContextProperty));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    BYTE h[20]; DWORD cb = 20;
    CHECK(U(CertGetCTLContextProperty)(c, CERT_HASH_PROP_ID, h, &cb));
    EXPECT_EQ(cc_props_ctl(c), 1);
    EXPECT_EQ(U(CertEnumCTLContextProperties)(c, 0), CERT_HASH_PROP_ID);
    rel(c);
}
TEST(ctlprop_set_get_delete_roundtrip) {
    REQUIRE(U(CertSetCTLContextProperty));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    BYTE d[] = { 'a', 0, 'b', 0, 0, 0 };
    CRYPT_DATA_BLOB b = { sizeof d, d };
    CHECK(U(CertSetCTLContextProperty)(c, CPROP, 0, &b));
    EXPECT_EQ(cc_props_ctl(c), 1);
    BYTE got[16]; DWORD cb = 2;
    SET_ERR(0);
    CHECK(!U(CertGetCTLContextProperty)(c, CPROP, got, &cb)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, sizeof d);
    cb = sizeof got;
    CHECK(U(CertGetCTLContextProperty)(c, CPROP, got, &cb));
    EXPECT_EQ(cb, sizeof d);
    CHECK(!memcmp(got, d, sizeof d));
    CHECK(U(CertSetCTLContextProperty)(c, CPROP, 0, NULL));
    EXPECT_EQ(cc_props_ctl(c), 0);
    cb = 0;
    SET_ERR(0);
    CHECK(!U(CertGetCTLContextProperty)(c, CPROP, NULL, &cb)); EXPECT_ERR(CC_E_NOT_FOUND);
    rel(c);
}
TEST(ctlprop_user_range_id) {
    REQUIRE(U(CertSetCTLContextProperty));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    BYTE d[4] = { 4, 3, 2, 1 }; CRYPT_DATA_BLOB b = { 4, d };
    CHECK(U(CertSetCTLContextProperty)(c, 0x8abc, 0, &b));
    BYTE got[8]; DWORD cb = sizeof got;
    CHECK(U(CertGetCTLContextProperty)(c, 0x8abc, got, &cb));
    EXPECT_EQ(cb, 4);
    CHECK(!memcmp(got, d, 4));
    SET_ERR(0);
    CHECK(!U(CertSetCTLContextProperty)(c, 0x10000, 0, &b)); EXPECT_ERR(CC_E_INVALIDARG);
    rel(c);
}
TEST(ctlprop_copied_on_add_to_store) {
    REQUIRE(U(CertAddCTLContextToStore));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    BYTE d[2] = { 1, 2 }; CRYPT_DATA_BLOB b = { 2, d };
    CHECK(U(CertSetCTLContextProperty)(c, CPROP, 0, &b));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCTL_CONTEXT o = NULL;
    CHECK(U(CertAddCTLContextToStore)(s, c, CERT_STORE_ADD_ALWAYS, &o));
    REQUIRE(o);
    CHECK(o != c);
    CHECK(o->pbCtlEncoded != c->pbCtlEncoded);
    BYTE got[4]; DWORD cb = sizeof got;
    CHECK(U(CertGetCTLContextProperty)(o, CPROP, got, &cb));
    EXPECT_EQ(cb, 2);
    rel(o); rel(c);
    cc_close(s);
}

/* ---- store operations ---- */
TEST(ctlstore_add_bad_args) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCTLToStore)(s, 0, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCTLToStore)(s, CC_X509, NULL, 0, CERT_STORE_ADD_ALWAYS, NULL)); EXPECT_ERR(E_INVALID_DATA);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCTLToStore)(s, CC_X509, VEC(v_ctl_content), CERT_STORE_ADD_ALWAYS, NULL)); EXPECT_ERR(E_INVALID_DATA);
    EXPECT_EQ(cc_count_ctls(s), 0);
    cc_close(s);
}
TEST(ctlstore_add_returns_store_context) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCTL_CONTEXT c = NULL;
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, &c));
    REQUIRE(c);
    CHECK(c->hCertStore == s);
    EXPECT_EQ(c->pCtlInfo->cCTLEntry, 3);
    EXPECT_EQ(cc_count_ctls(s), 1);
    rel(c);
    cc_close(s);
}
TEST(ctlstore_same_ctl_different_signature_is_same) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_NEW, NULL));
    SET_ERR(0);
    CHECK(!cc_add_ctl(s, VEC(v_ctl_signed_badsig), CERT_STORE_ADD_NEW, NULL)); EXPECT_ERR(CC_E_EXISTS);
    SET_ERR(0);
    CHECK(!cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_NEW, NULL)); EXPECT_ERR(CC_E_EXISTS);
    EXPECT_EQ(cc_count_ctls(s), 1);
    cc_close(s);
}
TEST(ctlstore_different_list_id_is_distinct) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_NEW, NULL));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_expired), CERT_STORE_ADD_NEW, NULL));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_min), CERT_STORE_ADD_NEW, NULL));
    EXPECT_EQ(cc_count_ctls(s), 3);
    cc_close(s);
}
TEST(ctlstore_different_usage_is_distinct) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_min), CERT_STORE_ADD_NEW, NULL));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_usage_only), CERT_STORE_ADD_NEW, NULL));
    t_note("CTL count after adding two CTLs with different usage: %d", cc_count_ctls(s));
    cc_close(s);
}
TEST(ctlstore_add_always_duplicates) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, NULL));
    EXPECT_EQ(cc_count_ctls(s), 2);
    cc_close(s);
}
TEST(ctlstore_use_existing) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCTL_CONTEXT a = NULL, b = NULL;
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, &a));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_badsig), CERT_STORE_ADD_USE_EXISTING, &b));
    CHECK(a && a == b);
    EXPECT_EQ(cc_count_ctls(s), 1);
    rel(a); rel(b);
    cc_close(s);
}
TEST(ctlstore_replace_existing) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, NULL));
    PCCTL_CONTEXT n = NULL;
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_badsig), CERT_STORE_ADD_REPLACE_EXISTING, &n));
    REQUIRE(n);
    CHECK(!memcmp(n->pbCtlEncoded, v_ctl_signed_badsig, sizeof v_ctl_signed_badsig));
    EXPECT_EQ(cc_count_ctls(s), 1);
    rel(n);
    cc_close(s);
}
TEST(ctlstore_add_context_copy_and_properties) {
    REQUIRE(U(CertAddCTLContextToStore));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(U(CertAddCTLContextToStore)(s, c, CERT_STORE_ADD_ALWAYS, NULL));
    EXPECT_EQ(cc_count_ctls(s), 1);
    rel(c);
    cc_close(s);
}
TEST(ctlstore_link) {
    REQUIRE(U(CertAddCTLLinkToStore));
    HCERTSTORE s1 = cc_store(), s2 = cc_store(); REQUIRE(s1 && s2);
    PCCTL_CONTEXT o = NULL;
    CHECK(cc_add_ctl(s1, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, &o));
    REQUIRE(o);
    PCCTL_CONTEXT l = NULL;
    SET_ERR(0);
    BOOL ok = U(CertAddCTLLinkToStore)(s2, o, CERT_STORE_ADD_ALWAYS, &l);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        EXPECT_EQ(cc_count_ctls(s2), 1);
        CHECK(l && l->hCertStore == s2);
        SET_ERR(0);
        CHECK(!U(CertAddCTLLinkToStore)(s2, o, CERT_STORE_ADD_NEW, NULL)); EXPECT_ERR(CC_E_EXISTS);
        rel(l);
    }
    rel(o);
    cc_close(s1); cc_close(s2);
}
TEST(ctlstore_enum_empty) {
    REQUIRE(U(CertEnumCTLsInStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    SET_ERR(0);
    CHECK(U(CertEnumCTLsInStore)(s, NULL) == NULL);
    EXPECT_ERR(CC_E_NOT_FOUND);
    cc_close(s);
}
TEST(ctlstore_enum_visits_each) {
    REQUIRE(U(CertEnumCTLsInStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_expired), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_min), CERT_STORE_ADD_ALWAYS, NULL));
    int seen[3] = { 0 }, n = 0; PCCTL_CONTEXT c = NULL;
    while ((c = U(CertEnumCTLsInStore)(s, c)) != NULL) {
        n++;
        if (c->cbCtlEncoded == sizeof v_ctl_signed) seen[0]++;
        else if (c->cbCtlEncoded == sizeof v_ctl_signed_expired) seen[1]++;
        else if (c->cbCtlEncoded == sizeof v_ctl_signed_min) seen[2]++;
    }
    EXPECT_EQ(n, 3);
    EXPECT_EQ(seen[0] + seen[1] + seen[2], 3);
    cc_close(s);
}
TEST(ctlstore_delete) {
    REQUIRE(U(CertDeleteCTLFromStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_min), CERT_STORE_ADD_ALWAYS, NULL));
    PCCTL_CONTEXT c = U(CertEnumCTLsInStore)(s, NULL);
    REQUIRE(c);
    PCCTL_CONTEXT held = U(CertDuplicateCTLContext)(c);
    CHECK(U(CertDeleteCTLFromStore)(c));
    EXPECT_EQ(cc_count_ctls(s), 1);
    CHECK(held->pCtlInfo != NULL);
    rel(held);
    cc_close(s);
}

/* ---- CertFindCTLInStore ---- */
static HCERTSTORE three_ctls(void) {
    HCERTSTORE s = cc_store();
    cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, NULL);
    cc_add_ctl(s, VEC(v_ctl_signed_expired), CERT_STORE_ADD_ALWAYS, NULL);
    cc_add_ctl(s, VEC(v_ctl_signed_min), CERT_STORE_ADD_ALWAYS, NULL);
    return s;
}
TEST(ctlfind_any) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    int n = 0; PCCTL_CONTEXT c = NULL;
    while ((c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_ANY, NULL, c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    c = U(CertFindCTLInStore)(s, 77, 123, CTL_FIND_ANY, NULL, NULL);
    CHECK(c != NULL); rel(c);
    cc_close(s);
}
TEST(ctlfind_empty_store) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_ANY, NULL, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    cc_close(s);
}
TEST(ctlfind_sha1_hash) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    BYTE h[20]; DWORD cb = 20;
    CHECK(cc_hash(CALG_SHA1, VEC(v_ctl_signed_expired), h, &cb));
    CRYPT_HASH_BLOB hb = { 20, h };
    PCCTL_CONTEXT c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_SHA1_HASH, &hb, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->cbCtlEncoded, sizeof v_ctl_signed_expired); CHECK(!memcmp(c->pbCtlEncoded, v_ctl_signed_expired, c->cbCtlEncoded)); }
    PCCTL_CONTEXT again = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_SHA1_HASH, &hb, c);
    CHECK(again == NULL);
    h[0] ^= 1;
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_SHA1_HASH, &hb, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    cc_close(s);
}
TEST(ctlfind_md5_hash) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    BYTE h[16]; DWORD cb = 16;
    CHECK(cc_hash(CALG_MD5, VEC(v_ctl_signed_min), h, &cb));
    CRYPT_HASH_BLOB hb = { 16, h };
    PCCTL_CONTEXT c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_MD5_HASH, &hb, NULL);
    CHECK(c != NULL);
    if (c) EXPECT_EQ(c->cbCtlEncoded, sizeof v_ctl_signed_min);
    rel(c);
    cc_close(s);
}
TEST(ctlfind_existing) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    PCCTL_CONTEXT probe = cc_ctl(VEC(v_ctl_signed_badsig));
    REQUIRE(probe);
    PCCTL_CONTEXT c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_EXISTING, probe, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(c->cbCtlEncoded == sizeof v_ctl_signed); }
    rel(c); rel(probe);
    cc_close(s);
    s = cc_store();
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed_min), CERT_STORE_ADD_ALWAYS, NULL));
    probe = cc_ctl(VEC(v_ctl_signed));
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_EXISTING, probe, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    rel(probe);
    cc_close(s);
}
TEST(ctlfind_usage) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    LPSTR oids_cs[] = { (LPSTR)"1.3.6.1.5.5.7.3.3" };
    LPSTR oids_other[] = { (LPSTR)"1.3.6.1.5.5.7.3.4" };
    CTL_FIND_USAGE_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p;
    p.SubjectUsage.cUsageIdentifier = 1; p.SubjectUsage.rgpszUsageIdentifier = oids_cs;
    int n = 0; PCCTL_CONTEXT c = NULL;
    /* ListIdentifier.cbData == 0: any list identifier matches */
    while ((c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_USAGE, &p, c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    /* a CTL must contain all requested usages; none contains this one */
    p.SubjectUsage.rgpszUsageIdentifier = oids_other;
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_USAGE, &p, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    /* no usages requested: any CTL matches */
    p.SubjectUsage.cUsageIdentifier = 0; p.SubjectUsage.rgpszUsageIdentifier = NULL;
    n = 0;
    while ((c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_USAGE, &p, c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    cc_close(s);
}
TEST(ctlfind_usage_list_identifier) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    CTL_FIND_USAGE_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p;
    int n = 0; PCCTL_CONTEXT c = NULL;
    p.ListIdentifier.cbData = 13; p.ListIdentifier.pbData = (BYTE *)"cryptt-list-1";
    while ((c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_USAGE, &p, c)) != NULL) { n++; CHECK(c->cbCtlEncoded == sizeof v_ctl_signed); }
    EXPECT_EQ(n, 1);
    p.ListIdentifier.cbData = 9; p.ListIdentifier.pbData = (BYTE *)"not-there";
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_USAGE, &p, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    /* CTL_FIND_NO_LIST_ID_CBDATA: only CTLs that have no list identifier */
    p.ListIdentifier.cbData = CTL_FIND_NO_LIST_ID_CBDATA; p.ListIdentifier.pbData = NULL;
    n = 0;
    while ((c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_USAGE, &p, c)) != NULL) { n++; CHECK(c->cbCtlEncoded == sizeof v_ctl_signed_min); }
    EXPECT_EQ(n, 1);
    cc_close(s);
}
TEST(ctlfind_usage_signer) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    PCCERT_CONTEXT sc = cc_cert(VEC(v_signer)), other = cc_cert(VEC(v_ca2));
    REQUIRE(sc && other);
    CTL_FIND_USAGE_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p;
    int n = 0; PCCTL_CONTEXT c = NULL;
    p.pSigner = sc->pCertInfo;
    while ((c = U(CertFindCTLInStore)(s, CC_X509P7, 0, CTL_FIND_USAGE, &p, c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    p.pSigner = other->pCertInfo;
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, CC_X509P7, 0, CTL_FIND_USAGE, &p, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    p.pSigner = CTL_FIND_NO_SIGNER_PTR;
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, CC_X509P7, 0, CTL_FIND_USAGE, &p, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    relc(sc); relc(other);
    cc_close(s);
}
TEST(ctlfind_usage_same_usage_flag) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    LPSTR oids_cs[] = { (LPSTR)"1.3.6.1.5.5.7.3.3" };
    LPSTR oids_both[] = { (LPSTR)"1.3.6.1.5.5.7.3.3", (LPSTR)"1.3.6.1.5.5.7.3.1" };
    CTL_FIND_USAGE_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p;
    p.SubjectUsage.cUsageIdentifier = 1; p.SubjectUsage.rgpszUsageIdentifier = oids_cs;
    SET_ERR(0);
    PCCTL_CONTEXT c = U(CertFindCTLInStore)(s, 0, CTL_FIND_SAME_USAGE_FLAG, CTL_FIND_USAGE, &p, NULL);
    CHECK(c == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    p.SubjectUsage.cUsageIdentifier = 2; p.SubjectUsage.rgpszUsageIdentifier = oids_both;
    int n = 0;
    while ((c = U(CertFindCTLInStore)(s, 0, CTL_FIND_SAME_USAGE_FLAG, CTL_FIND_USAGE, &p, c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    cc_close(s);
}
TEST(ctlfind_subject_cert) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001)), l3 = cc_cert(VEC(v_cert_1003)), r0 = cc_cert(VEC(v_cert_r0));
    REQUIRE(l1 && l3 && r0);
    CTL_FIND_SUBJECT_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p; p.dwSubjectType = CTL_CERT_SUBJECT_TYPE;
    int n = 0; PCCTL_CONTEXT c = NULL;
    p.pvSubject = (void *)l1;
    while ((c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_SUBJECT, &p, c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    p.pvSubject = (void *)l3; n = 0;
    while ((c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_SUBJECT, &p, c)) != NULL) { n++; CHECK(c->cbCtlEncoded == sizeof v_ctl_signed); }
    EXPECT_EQ(n, 1);
    p.pvSubject = (void *)r0;
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_SUBJECT, &p, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    relc(l1); relc(l3); relc(r0);
    cc_close(s);
}
TEST(ctlfind_subject_any_type) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE s = three_ctls(); REQUIRE(s);
    CTL_ANY_SUBJECT_INFO info; memset(&info, 0, sizeof info);
    info.SubjectAlgorithm.pszObjId = (LPSTR)"1.3.14.3.2.26";
    info.SubjectIdentifier.cbData = sizeof v_sha1_1003; info.SubjectIdentifier.pbData = (BYTE *)v_sha1_1003;
    CTL_FIND_SUBJECT_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p; p.dwSubjectType = CTL_ANY_SUBJECT_TYPE; p.pvSubject = &info;
    PCCTL_CONTEXT c = U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_SUBJECT, &p, NULL);
    CHECK(c != NULL); rel(c);
    info.SubjectIdentifier.pbData = (BYTE *)v_sha1_r0;
    SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(s, 0, 0, CTL_FIND_SUBJECT, &p, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    cc_close(s);
}

/* ---- serialization ---- */
TEST(ctlser_layout_and_roundtrip) {
    REQUIRE(U(CertSerializeCTLStoreElement)); REQUIRE(U(CertAddSerializedElementToStore));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    DWORD cb = 0;
    CHECK(U(CertSerializeCTLStoreElement)(c, 0, NULL, &cb));
    EXPECT_EQ(cb, sizeof v_ctl_signed + 12);
    BYTE *buf = LocalAlloc(LPTR, cb);
    DWORD cb2 = cb - 1;
    SET_ERR(0);
    CHECK(!U(CertSerializeCTLStoreElement)(c, 0, buf, &cb2)); EXPECT_ERR(ERROR_MORE_DATA);
    cb2 = cb;
    CHECK(U(CertSerializeCTLStoreElement)(c, 0, buf, &cb2));
    DWORD *h = (DWORD *)buf;
    EXPECT_EQ(h[0], CC_PROP_CTL); EXPECT_EQ(h[1], 0x10001); EXPECT_EQ(h[2], sizeof v_ctl_signed);
    CHECK(!memcmp(buf + 12, v_ctl_signed, sizeof v_ctl_signed));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    DWORD type = 0; const void *ctx = NULL;
    CHECK(U(CertAddSerializedElementToStore)(s, buf, cb, CERT_STORE_ADD_ALWAYS, 0, CERT_STORE_CTL_CONTEXT_FLAG, &type, &ctx));
    EXPECT_EQ(type, CERT_STORE_CTL_CONTEXT);
    EXPECT_EQ(cc_count_ctls(s), 1);
    rel((PCCTL_CONTEXT)ctx);
    LocalFree(buf);
    cc_close(s); rel(c);
}

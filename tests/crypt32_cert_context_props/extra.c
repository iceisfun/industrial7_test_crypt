/* Additional context lifetime / property sharing checks. */
#include "ccp.h"

TEST(ccp_extra_free_null_context_succeeds) {
    REQUIRE(C32(CertFreeCertificateContext));
    CHECK(C32(CertFreeCertificateContext)(NULL));
}
TEST(ccp_extra_duplicate_null_is_null) {
    REQUIRE(C32(CertDuplicateCertificateContext));
    CHECK(C32(CertDuplicateCertificateContext)(NULL) == NULL);
}
TEST(ccp_extra_duplicate_shares_properties) {
    PCCERT_CONTEXT c, d; BYTE v[3] = {1, 2, 3}, o[8]; DWORD cb = sizeof o; CRYPT_DATA_BLOB b;
    REQUIRE(C32(CertDuplicateCertificateContext));
    c = ccp_ctx(&fx_leaf);
    if (!c) { CHECK(0); return; }
    d = C32(CertDuplicateCertificateContext)(c);
    CHECK(d == c);
    b.cbData = 3; b.pbData = v;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_DESCRIPTION_PROP_ID, 0, &b));
    CHECK(C32(CertGetCertificateContextProperty)(d, CERT_DESCRIPTION_PROP_ID, o, &cb) && cb == 3 && !memcmp(o, v, 3));
    ccp_free(d); ccp_free(c);
}
TEST(ccp_extra_set_property_survives_after_one_free) {
    PCCERT_CONTEXT c, d; BYTE v[2] = {9, 8}, o[8]; DWORD cb = sizeof o; CRYPT_DATA_BLOB b;
    REQUIRE(C32(CertDuplicateCertificateContext));
    c = ccp_ctx(&fx_root);
    if (!c) { CHECK(0); return; }
    d = C32(CertDuplicateCertificateContext)(c);
    b.cbData = 2; b.pbData = v;
    CHECK(C32(CertSetCertificateContextProperty)(d, CERT_DESCRIPTION_PROP_ID, 0, &b));
    ccp_free(c);
    CHECK(C32(CertGetCertificateContextProperty)(d, CERT_DESCRIPTION_PROP_ID, o, &cb) && cb == 2 && !memcmp(o, v, 2));
    ccp_free(d);
}
TEST(ccp_extra_property_not_shared_between_independent_creates) {
    PCCERT_CONTEXT a, b; BYTE v[2] = {5, 6}; DWORD cb = 0; CRYPT_DATA_BLOB blob;
    REQUIRE(C32(CertSetCertificateContextProperty));
    a = ccp_ctx(&fx_leaf); b = ccp_ctx(&fx_leaf);
    if (!a || !b) { CHECK(0); ccp_free(a); ccp_free(b); return; }
    CHECK(a != b);
    blob.cbData = 2; blob.pbData = v;
    CHECK(C32(CertSetCertificateContextProperty)(a, CERT_DESCRIPTION_PROP_ID, 0, &blob));
    SET_ERR(0);
    CHECK(!C32(CertGetCertificateContextProperty)(b, CERT_DESCRIPTION_PROP_ID, NULL, &cb));
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    ccp_free(a); ccp_free(b);
}
TEST(ccp_extra_delete_property_with_null_data) {
    PCCERT_CONTEXT c; BYTE v[2] = {5, 6}; DWORD cb = 0; CRYPT_DATA_BLOB blob;
    REQUIRE(C32(CertSetCertificateContextProperty));
    c = ccp_ctx(&fx_leaf2);
    if (!c) { CHECK(0); return; }
    blob.cbData = 2; blob.pbData = v;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_DESCRIPTION_PROP_ID, 0, &blob));
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_DESCRIPTION_PROP_ID, 0, NULL));
    SET_ERR(0);
    CHECK(!C32(CertGetCertificateContextProperty)(c, CERT_DESCRIPTION_PROP_ID, NULL, &cb));
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    ccp_free(c);
}
TEST(ccp_extra_hash_prop_matches_across_fixture_table) {
    int i; BYTE h[20]; DWORD cb;
    REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        PCCERT_CONTEXT c = ccp_ctx(ccp_all[i]);
        if (!c) { CHECKF(0, "%s", ccp_all[i]->name); continue; }
        cb = 20;
        CHECKF(C32(CertGetCertificateContextProperty)(c, CERT_HASH_PROP_ID, h, &cb) && cb == 20 && !memcmp(h, ccp_all[i]->sha1, 20), "%s", ccp_all[i]->name);
        cb = 20;
        CHECKF(C32(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, h, &cb) && cb == 20 && !memcmp(h, ccp_all[i]->sha1, 20), "%s", ccp_all[i]->name);
        ccp_free(c);
    }
}

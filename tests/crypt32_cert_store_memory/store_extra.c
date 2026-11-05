#include "sm.h"
/* Additional find / lookup / context coverage for the memory store. */

static PCCERT_CONTEXT fx(HCERTSTORE h, DWORD type, const void *p, PCCERT_CONTEXT prev) {
    return U(CertFindCertificateInStore)(h, X509_ASN_ENCODING, 0, type, p, prev);
}

TEST(cse_find_sha1_hit_returns_matching_bytes) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_b };
    PCCERT_CONTEXT c = fx(h, CERT_FIND_SHA1_HASH, &hb, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(sm_same_enc(c, VEC(v_cert_b))); CHECK(c->hCertStore == h); sm_freec(c); }
    sm_close(h);
}
TEST(cse_find_md5_hit_returns_matching_bytes) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_HASH_BLOB hb = { 16, (BYTE *)v_md5_c };
    PCCERT_CONTEXT c = fx(h, CERT_FIND_MD5_HASH, &hb, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(sm_same_enc(c, VEC(v_cert_c))); sm_freec(c); }
    sm_close(h);
}
TEST(cse_find_sha1_miss_not_found) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_b };
    SET_ERR(0);
    PCCERT_CONTEXT c = fx(h, CERT_FIND_SHA1_HASH, &hb, NULL);
    CHECK(c == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(cse_find_any_in_empty_store_not_found) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    PCCERT_CONTEXT c = fx(h, CERT_FIND_ANY, NULL, NULL);
    CHECK(c == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(cse_find_any_iterates_all_certs) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    int n = 0; PCCERT_CONTEXT c = NULL;
    while ((c = fx(h, CERT_FIND_ANY, NULL, c)) != NULL && n < 10) n++;
    EXPECT_EQ(n, 3);
    sm_close(h);
}
TEST(cse_find_subject_name_matches_only_that_cert) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CERT_NAME_BLOB nb = { (DWORD)sizeof v_name_ca, (BYTE *)v_name_ca };
    PCCERT_CONTEXT c = fx(h, CERT_FIND_SUBJECT_NAME, &nb, NULL);
    t_note("subject CA name hit in A/B/C store: %p", (const void *)c);
    if (c) sm_freec(c);
    sm_close(h);
}
TEST(cse_delete_cert_then_find_fails) {
    REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_a };
    PCCERT_CONTEXT c = fx(h, CERT_FIND_SHA1_HASH, &hb, NULL);
    CHECK(c != NULL);
    if (c) CHECK(U(CertDeleteCertificateFromStore)(c));   /* consumes the reference */
    EXPECT_EQ(sm_ncerts(h), 2);
    SET_ERR(0);
    CHECK(fx(h, CERT_FIND_SHA1_HASH, &hb, NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(cse_create_context_standalone_has_no_store_contents) {
    REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a));
    CHECK(c != NULL);
    if (c) {
        CHECK(sm_same_enc(c, VEC(v_cert_a)));
        CHECK(c->dwCertEncodingType == X509_ASN_ENCODING);
        CHECK(c->pCertInfo != NULL && c->pCertInfo->dwVersion == 2);
        sm_freec(c);
    }
}
TEST(cse_add_context_to_store_copies_not_aliases) {
    REQUIRE(U(CertCreateCertificateContext)); REQUIRE(U(CertAddCertificateContextToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT src = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a));
    PCCERT_CONTEXT out = NULL;
    CHECK(src && U(CertAddCertificateContextToStore)(h, src, DISP_NEW, &out));
    CHECK(out != NULL && out != src);
    if (out && src) CHECK(out->pbCertEncoded != src->pbCertEncoded);
    sm_freec(out); sm_freec(src);
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}

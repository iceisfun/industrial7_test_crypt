#include "sm.h"
/* CRL and CTL contexts in stores: dispositions, enumeration, find, delete, ref counts, accessors. */

static int crl_is(PCCRL_CONTEXT c, const BYTE *p, DWORD n) { return c && c->cbCrlEncoded == n && !memcmp(c->pbCrlEncoded, p, n); }
static int ctl_is(PCCTL_CONTEXT c, const BYTE *p, DWORD n) { return c && c->cbCtlEncoded == n && !memcmp(c->pbCtlEncoded, p, n); }
static void freecrl(PCCRL_CONTEXT c) { if (c) U(CertFreeCRLContext)(c); }
static void freectl(PCCTL_CONTEXT c) { if (c) U(CertFreeCTLContext)(c); }

/* ====================== CRL ====================== */
TEST(csr_crl_add_new_and_enum) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCRL_CONTEXT c = NULL;
    CHECK(sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, &c));
    CHECK(crl_is(c, VEC(v_crl_1a)));
    CHECK(c && c->hCertStore == h);
    CHECK(c && c->pCrlInfo && c->pCrlInfo->cCRLEntry == 1);
    freecrl(c);
    EXPECT_EQ(sm_ncrls(h), 1); EXPECT_EQ(sm_ncerts(h), 0); EXPECT_EQ(sm_nctls(h), 0);
    sm_close(h);
}
TEST(csr_crl_add_two_issuers) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    CHECK(sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL));
    CHECK(sm_addcrl(h, VEC(v_crl_2), DISP_NEW, NULL));
    EXPECT_EQ(sm_ncrls(h), 2);
    sm_close(h);
}
TEST(csr_crl_enum_newest_first) {
    REQUIRE(U(CertEnumCRLsInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    sm_addcrl(h, VEC(v_crl_2), DISP_NEW, NULL);
    PCCRL_CONTEXT c = U(CertEnumCRLsInStore)(h, NULL);
    CHECK(crl_is(c, VEC(v_crl_2)));
    c = U(CertEnumCRLsInStore)(h, c);
    CHECK(crl_is(c, VEC(v_crl_1a)));
    SET_ERR(0);
    c = U(CertEnumCRLsInStore)(h, c);
    CHECK(c == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csr_crl_new_same_issuer_exists) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    PCCRL_CONTEXT c = (PCCRL_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!sm_addcrl(h, VEC(v_crl_1b), DISP_NEW, &c)); EXPECT_ERR(HR_EXISTS);
    CHECK(c == NULL);
    EXPECT_EQ(sm_ncrls(h), 1);
    sm_close(h);
}
TEST(csr_crl_new_identical_exists) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    SET_ERR(0);
    CHECK(!sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL)); EXPECT_ERR(HR_EXISTS);
    sm_close(h);
}
TEST(csr_crl_use_existing) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    PCCRL_CONTEXT c = NULL;
    CHECK(sm_addcrl(h, VEC(v_crl_1b), DISP_USE, &c));
    CHECK(crl_is(c, VEC(v_crl_1a)));            /* the existing CRL is used, not the new one */
    EXPECT_EQ(sm_ncrls(h), 1);
    freecrl(c); sm_close(h);
}
TEST(csr_crl_replace_existing) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    PCCRL_CONTEXT c = NULL;
    CHECK(sm_addcrl(h, VEC(v_crl_1b), DISP_REPL, &c));
    CHECK(crl_is(c, VEC(v_crl_1b)));
    EXPECT_EQ(sm_ncrls(h), 1);
    freecrl(c); sm_close(h);
}
TEST(csr_crl_replace_adds_when_missing) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    CHECK(sm_addcrl(h, VEC(v_crl_1a), DISP_REPL, NULL));
    EXPECT_EQ(sm_ncrls(h), 1);
    sm_close(h);
}
TEST(csr_crl_always_duplicates) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    for (int i = 0; i < 3; i++) CHECK(sm_addcrl(h, VEC(v_crl_1a), DISP_ALWAYS, NULL));
    EXPECT_EQ(sm_ncrls(h), 3);
    sm_close(h);
}
TEST(csr_crl_newer_replaces_by_thisupdate) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    PCCRL_CONTEXT c = NULL;
    CHECK(sm_addcrl(h, VEC(v_crl_1b), DISP_NEWER, &c));
    CHECK(crl_is(c, VEC(v_crl_1b)));
    EXPECT_EQ(sm_ncrls(h), 1);
    freecrl(c); sm_close(h);
}
TEST(csr_crl_newer_older_rejected) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1b), DISP_NEW, NULL);
    SET_ERR(0);
    CHECK(!sm_addcrl(h, VEC(v_crl_1a), DISP_NEWER, NULL)); EXPECT_ERR(HR_EXISTS);
    PCCRL_CONTEXT c = U(CertEnumCRLsInStore)(h, NULL);
    CHECK(crl_is(c, VEC(v_crl_1b)));
    freecrl(c); sm_close(h);
}
TEST(csr_crl_newer_same_rejected) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    SET_ERR(0);
    CHECK(!sm_addcrl(h, VEC(v_crl_1a), DISP_NEWER, NULL)); EXPECT_ERR(HR_EXISTS);
    sm_close(h);
}
TEST(csr_crl_newer_inherit_and_replace_inherit) {
    REQUIRE(U(CertSetCRLContextProperty));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCRL_CONTEXT c = NULL;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, &c);
    static const WCHAR fn[] = L"crlname";
    CRYPT_DATA_BLOB b = { sizeof fn, (BYTE *)fn };
    CHECK(U(CertSetCRLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b));
    freecrl(c); c = NULL;
    CHECK(sm_addcrl(h, VEC(v_crl_1b), DISP_NEWER_INH, &c));
    DWORD cb = 0;
    CHECK(U(CertGetCRLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_EQ(cb, sizeof fn);
    freecrl(c); c = NULL;
    CHECK(sm_addcrl(h, VEC(v_crl_1a), DISP_REPL_INH, &c));
    CHECK(crl_is(c, VEC(v_crl_1a)));
    cb = 0;
    CHECK(U(CertGetCRLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_EQ(cb, sizeof fn);
    freecrl(c); sm_close(h);
}
TEST(csr_crl_invalid_disposition) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCRL_CONTEXT c = (PCCRL_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!sm_addcrl(h, VEC(v_crl_1a), 0, &c)); EXPECT_ERR(HR_INVALIDARG);
    CHECK(c == NULL);
    SET_ERR(0);
    CHECK(!sm_addcrl(h, VEC(v_crl_1a), 8, NULL)); EXPECT_ERR(HR_INVALIDARG);
    sm_close(h);
}
TEST(csr_crl_add_context_other_store) {
    REQUIRE(U(CertAddCRLContextToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCRL_CONTEXT c = NULL, c2 = NULL;
    sm_addcrl(s, VEC(v_crl_1a), DISP_NEW, &c);
    CHECK(U(CertAddCRLContextToStore)(d, c, DISP_NEW, &c2));
    CHECK(c2 && c2 != c && c2->hCertStore == d && crl_is(c2, VEC(v_crl_1a)));
    freecrl(c); freecrl(c2); sm_close(s); sm_close(d);
}
TEST(csr_crl_add_link) {
    REQUIRE(U(CertAddCRLLinkToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCRL_CONTEXT c = NULL;
    sm_addcrl(s, VEC(v_crl_1a), DISP_NEW, &c);
    CHECK(U(CertAddCRLLinkToStore)(d, c, DISP_NEW, NULL));
    EXPECT_EQ(sm_ncrls(d), 1);
    SET_ERR(0);
    CHECK(!U(CertAddCRLLinkToStore)(d, c, DISP_NEW, NULL)); EXPECT_ERR(HR_EXISTS);
    freecrl(c); sm_close(s); sm_close(d);
}
TEST(csr_crl_garbage_fails) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    static const BYTE junk[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    SET_ERR(0);
    CHECK(!sm_addcrl(h, VEC(junk), DISP_NEW, NULL));
    DWORD e = GetLastError();
    CHECKF((e & 0xFFFFFF00) == 0x80093100 || e == HR_INVALIDARG, "gle=0x%lx", e);
    EXPECT_EQ(sm_ncrls(h), 0);
    sm_close(h);
}
TEST(csr_crl_delete) {
    REQUIRE(U(CertDeleteCRLFromStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCRL_CONTEXT c = NULL, keep;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, &c);
    keep = U(CertDuplicateCRLContext)(c);
    CHECK(U(CertDeleteCRLFromStore)(c));
    EXPECT_EQ(sm_ncrls(h), 0);
    CHECK(crl_is(keep, VEC(v_crl_1a)));
    freecrl(keep); sm_close(h);
}
TEST(csr_crl_delete_during_enum) {
    REQUIRE(U(CertDeleteCRLFromStore));
    if (t_is_wine()) { t_skip("emulator faults when enumerating past a deleted CRL"); return; }
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    sm_addcrl(h, VEC(v_crl_2), DISP_NEW, NULL);
    PCCRL_CONTEXT c = NULL; int n = 0;
    while ((c = U(CertEnumCRLsInStore)(h, c)) != NULL && n < 5) { n++; CHECK(U(CertDeleteCRLFromStore)(U(CertDuplicateCRLContext)(c))); }
    EXPECT_EQ(n, 2); EXPECT_EQ(sm_ncrls(h), 0);
    sm_close(h);
}
TEST(csr_crl_duplicate_and_free) {
    REQUIRE(U(CertDuplicateCRLContext));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCRL_CONTEXT c = NULL;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, &c);
    PCCRL_CONTEXT d = U(CertDuplicateCRLContext)(c);
    CHECK(d == c);
    CHECK(U(CertFreeCRLContext)(d));
    sm_close(h);
    CHECK(crl_is(c, VEC(v_crl_1a)));
    CHECK(U(CertFreeCRLContext)(c));
    CHECK(U(CertDuplicateCRLContext)(NULL) == NULL);
    CHECK(U(CertFreeCRLContext)(NULL));
}
TEST(csr_crl_create_context) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(X509_ASN_ENCODING, VEC(v_crl_2));
    CHECK(crl_is(c, VEC(v_crl_2)));
    CHECK(c && c->pbCrlEncoded != v_crl_2);
    CHECK(c && c->pCrlInfo->cCRLEntry == 0);
    freecrl(c);
    SET_ERR(0);
    CHECK(U(CertCreateCRLContext)(X509_ASN_ENCODING, VEC(v_cert_a)) == NULL);
    DWORD e = GetLastError();
    CHECKF((e & 0xFFFFFF00) == 0x80093100, "gle=0x%lx", e);
}
TEST(csr_crl_info_entries) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(X509_ASN_ENCODING, VEC(v_crl_1b));
    CHECK(c && c->pCrlInfo->cCRLEntry == 2);
    if (c && c->pCrlInfo->cCRLEntry == 2) {
        CHECK(c->pCrlInfo->rgCRLEntry[0].SerialNumber.cbData == 2);
        CHECK(c->pCrlInfo->Issuer.cbData == sizeof v_name_ca && !memcmp(c->pCrlInfo->Issuer.pbData, v_name_ca, sizeof v_name_ca));
    }
    freecrl(c);
}
TEST(csr_crl_find_in_crl) {
    REQUIRE(U(CertFindCertificateInCRL)); REQUIRE(U(CertCreateCRLContext)); REQUIRE(U(CertCreateCertificateContext));
    PCCRL_CONTEXT crl = U(CertCreateCRLContext)(X509_ASN_ENCODING, VEC(v_crl_1a));   /* revokes 0x1001 only */
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a));
    PCCERT_CONTEXT b = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_b));
    PCRL_ENTRY e = (PCRL_ENTRY)(ULONG_PTR)1;
    CHECK(U(CertFindCertificateInCRL)(a, crl, 0, NULL, &e));
    CHECK(e != NULL && e != (PCRL_ENTRY)1);
    e = (PCRL_ENTRY)(ULONG_PTR)1;
    CHECK(U(CertFindCertificateInCRL)(b, crl, 0, NULL, &e));
    CHECK(e == NULL);                                  /* not revoked: success with NULL entry */
    freecrl(crl); sm_freec(a); sm_freec(b);
}
TEST(csr_crl_get_crl_from_store_issuer) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1b), DISP_NEW, NULL);
    sm_addcrl(h, VEC(v_crl_2), DISP_NEW, NULL);
    PCCERT_CONTEXT ca = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_ca));
    PCCERT_CONTEXT b = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_b));
    DWORD fl = CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG;
    PCCRL_CONTEXT c = U(CertGetCRLFromStore)(h, ca, NULL, &fl);
    CHECK(crl_is(c, VEC(v_crl_1b)));
    EXPECT_EQ(fl & CERT_STORE_SIGNATURE_FLAG, 0);       /* signature verified against the issuer's key */
    EXPECT_EQ(fl & CERT_STORE_TIME_VALIDITY_FLAG, 0);
    c = U(CertGetCRLFromStore)(h, ca, c, &fl);
    CHECK(c == NULL); EXPECT_ERR(HR_NOT_FOUND);
    fl = CERT_STORE_SIGNATURE_FLAG;
    c = U(CertGetCRLFromStore)(h, b, NULL, &fl);
    CHECK(crl_is(c, VEC(v_crl_2)));
    freecrl(c); sm_freec(ca); sm_freec(b); sm_close(h);
}
TEST(csr_crl_get_crl_wrong_issuer_signature_flag) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_2), DISP_NEW, NULL);
    /* crl_2 is issued by name B and signed by B's key: asking with issuer A finds nothing */
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a));
    DWORD fl = 0;
    SET_ERR(0);
    PCCRL_CONTEXT c = U(CertGetCRLFromStore)(h, a, NULL, &fl);
    CHECK(c == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_freec(a); sm_close(h);
}
TEST(csr_crl_find_any_issued_by) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    sm_addcrl(h, VEC(v_crl_2), DISP_NEW, NULL);
    PCCRL_CONTEXT c = NULL; int n = 0;
    while ((c = U(CertFindCRLInStore)(h, X509_ASN_ENCODING, 0, CRL_FIND_ANY, NULL, c)) != NULL) n++;
    EXPECT_EQ(n, 2);
    PCCERT_CONTEXT ca = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_ca));
    c = U(CertFindCRLInStore)(h, X509_ASN_ENCODING, 0, CRL_FIND_ISSUED_BY, ca, NULL);
    CHECK(crl_is(c, VEC(v_crl_1a)));
    c = U(CertFindCRLInStore)(h, X509_ASN_ENCODING, 0, CRL_FIND_ISSUED_BY, ca, c);
    CHECK(c == NULL);
    sm_freec(ca); sm_close(h);
}
TEST(csr_crl_find_existing) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    sm_addcrl(h, VEC(v_crl_2), DISP_NEW, NULL);
    PCCRL_CONTEXT probe = U(CertCreateCRLContext)(X509_ASN_ENCODING, VEC(v_crl_2));
    PCCRL_CONTEXT c = U(CertFindCRLInStore)(h, X509_ASN_ENCODING, 0, CRL_FIND_EXISTING, probe, NULL);
    CHECK(crl_is(c, VEC(v_crl_2)));
    freecrl(c); freecrl(probe); sm_close(h);
}
TEST(csr_crl_find_none_in_empty) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    CHECK(U(CertFindCRLInStore)(h, X509_ASN_ENCODING, 0, CRL_FIND_ANY, NULL, NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csr_crl_property_hash) {
    REQUIRE(U(CertGetCRLContextProperty));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCRL_CONTEXT c = NULL;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, &c);
    BYTE buf[20]; DWORD cb = sizeof buf;
    CHECK(U(CertGetCRLContextProperty)(c, CERT_HASH_PROP_ID, buf, &cb));
    EXPECT_EQ(cb, 20); CHECK(!memcmp(buf, v_sha1_crl_1a, 20));
    cb = 5;
    SET_ERR(0);
    CHECK(!U(CertGetCRLContextProperty)(c, CERT_HASH_PROP_ID, buf, &cb)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, 20);
    SET_ERR(0);
    cb = 0;
    CHECK(!U(CertGetCRLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_ERR(HR_NOT_FOUND);
    freecrl(c); sm_close(h);
}
TEST(csr_crl_property_enum_and_delete) {
    REQUIRE(U(CertEnumCRLContextProperties));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCRL_CONTEXT c = NULL;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, &c);
    static const WCHAR fn[] = L"x";
    CRYPT_DATA_BLOB b = { sizeof fn, (BYTE *)fn };
    CHECK(U(CertSetCRLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b));
    DWORD id = 0; int seen = 0, n = 0;
    while ((id = U(CertEnumCRLContextProperties)(c, id)) != 0 && n++ < 50) if (id == CERT_FRIENDLY_NAME_PROP_ID) seen = 1;
    CHECK(seen);
    CHECK(U(CertSetCRLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, NULL));
    DWORD cb = 0; SET_ERR(0);
    CHECK(!U(CertGetCRLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_ERR(HR_NOT_FOUND);
    freecrl(c); sm_close(h);
}
TEST(csr_crl_in_cert_enum_not_mixed) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    EXPECT_EQ(sm_ncerts(h), 3); EXPECT_EQ(sm_ncrls(h), 1);
    sm_close(h);
}

/* ====================== CTL ====================== */
TEST(csr_ctl_create_context_fields) {
    REQUIRE(U(CertCreateCTLContext));
    PCCTL_CONTEXT c = U(CertCreateCTLContext)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, VEC(v_ctl_1b));
    CHECK(c != NULL);
    if (!c) { t_note("CertCreateCTLContext failed gle=0x%lx", GetLastError()); return; }
    CHECK(ctl_is(c, VEC(v_ctl_1b)));
    CHECK(c->pCtlInfo->cCTLEntry == 3);
    CHECK(c->pCtlInfo->SubjectUsage.cUsageIdentifier == 1 &&
          !strcmp(c->pCtlInfo->SubjectUsage.rgpszUsageIdentifier[0], "1.3.6.1.5.5.7.3.2"));
    CHECK(c->pCtlInfo->ListIdentifier.cbData == 11 && !memcmp(c->pCtlInfo->ListIdentifier.pbData, "CryptTList1", 11));
    CHECK(c->pCtlInfo->SubjectAlgorithm.pszObjId && !strcmp(c->pCtlInfo->SubjectAlgorithm.pszObjId, "1.3.14.3.2.26"));
    CHECK(c->hCryptMsg != NULL);
    freectl(c);
}
TEST(csr_ctl_create_context_garbage) {
    REQUIRE(U(CertCreateCTLContext));
    SET_ERR(0);
    CHECK(U(CertCreateCTLContext)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, VEC(v_cert_a)) == NULL);
    t_note("CTL from cert bytes gle=0x%lx", GetLastError());
    SET_ERR(0);
    CHECK(U(CertCreateCTLContext)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, v_ctl_1a, 10) == NULL);
}
TEST(csr_ctl_add_new_and_enum) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCTL_CONTEXT c = NULL;
    BOOL r = U(CertAddEncodedCTLToStore)(h, ENC, VEC(v_ctl_1a), DISP_NEW, &c);
    CHECK(r);
    if (r) { CHECK(ctl_is(c, VEC(v_ctl_1a))); CHECK(c->hCertStore == h); }
    freectl(c);
    EXPECT_EQ(sm_nctls(h), 1); EXPECT_EQ(sm_ncerts(h), 0); EXPECT_EQ(sm_ncrls(h), 0);
    sm_close(h);
}
static BOOL addctl(HCERTSTORE h, const BYTE *p, DWORD n, DWORD d, PCCTL_CONTEXT *o) { return U(CertAddEncodedCTLToStore)(h, ENC, p, n, d, o); }
TEST(csr_ctl_add_two_lists) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    CHECK(addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL));
    CHECK(addctl(h, VEC(v_ctl_2), DISP_NEW, NULL));
    EXPECT_EQ(sm_nctls(h), 2);
    PCCTL_CONTEXT c = U(CertEnumCTLsInStore)(h, NULL);
    CHECK(ctl_is(c, VEC(v_ctl_2)));                     /* newest first */
    freectl(c); sm_close(h);
}
TEST(csr_ctl_new_identical_exists) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL);
    PCCTL_CONTEXT c = (PCCTL_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!addctl(h, VEC(v_ctl_1a), DISP_NEW, &c)); EXPECT_ERR(HR_EXISTS);
    CHECK(c == NULL);
    sm_close(h);
}
TEST(csr_ctl_same_list_newer_thisupdate) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL);
    PCCTL_CONTEXT c = NULL;
    BOOL r = addctl(h, VEC(v_ctl_1b), DISP_NEWER, &c);
    CHECK(r);
    t_note("NEWER with later ThisUpdate: added=%d count=%d (matching by usage+list id)", r, sm_nctls(h));
    if (r) { CHECK(ctl_is(c, VEC(v_ctl_1b))); EXPECT_EQ(sm_nctls(h), 1); }
    freectl(c); sm_close(h);
}
TEST(csr_ctl_same_list_older_rejected) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1b), DISP_NEW, NULL);
    SET_ERR(0);
    BOOL r = addctl(h, VEC(v_ctl_1a), DISP_NEWER, NULL);
    CHECK(!r); EXPECT_ERR(HR_EXISTS);
    EXPECT_EQ(sm_nctls(h), 1);
    sm_close(h);
}
TEST(csr_ctl_always_duplicates) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    for (int i = 0; i < 3; i++) CHECK(addctl(h, VEC(v_ctl_1a), DISP_ALWAYS, NULL));
    EXPECT_EQ(sm_nctls(h), 3);
    sm_close(h);
}
TEST(csr_ctl_replace_existing_identical) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL);
    PCCTL_CONTEXT c = NULL;
    CHECK(addctl(h, VEC(v_ctl_1a), DISP_REPL, &c));
    CHECK(ctl_is(c, VEC(v_ctl_1a)));
    EXPECT_EQ(sm_nctls(h), 1);
    freectl(c); sm_close(h);
}
TEST(csr_ctl_use_existing_identical) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL);
    PCCTL_CONTEXT c = NULL;
    CHECK(addctl(h, VEC(v_ctl_1a), DISP_USE, &c));
    CHECK(ctl_is(c, VEC(v_ctl_1a)));
    EXPECT_EQ(sm_nctls(h), 1);
    freectl(c); sm_close(h);
}
TEST(csr_ctl_invalid_disposition) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCTL_CONTEXT c = (PCCTL_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!addctl(h, VEC(v_ctl_1a), 0, &c)); EXPECT_ERR(HR_INVALIDARG);
    CHECK(c == NULL);
    sm_close(h);
}
TEST(csr_ctl_context_and_link_copies) {
    REQUIRE(U(CertAddCTLContextToStore)); REQUIRE(U(CertAddCTLLinkToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(), l = sm_mem(); if (!s || !d || !l) return;
    PCCTL_CONTEXT c = NULL, c2 = NULL;
    addctl(s, VEC(v_ctl_1a), DISP_NEW, &c);
    CHECK(U(CertAddCTLContextToStore)(d, c, DISP_NEW, &c2));
    CHECK(c2 && c2 != c && c2->hCertStore == d);
    CHECK(U(CertAddCTLLinkToStore)(l, c, DISP_NEW, NULL));
    EXPECT_EQ(sm_nctls(d), 1); EXPECT_EQ(sm_nctls(l), 1);
    freectl(c); freectl(c2); sm_close(s); sm_close(d); sm_close(l);
}
TEST(csr_ctl_delete) {
    REQUIRE(U(CertDeleteCTLFromStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCTL_CONTEXT c = NULL, keep;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, &c);
    keep = U(CertDuplicateCTLContext)(c);
    CHECK(U(CertDeleteCTLFromStore)(c));
    EXPECT_EQ(sm_nctls(h), 0);
    CHECK(ctl_is(keep, VEC(v_ctl_1a)));
    freectl(keep); sm_close(h);
}
TEST(csr_ctl_delete_during_enum) {
    REQUIRE(U(CertDeleteCTLFromStore));
    if (t_is_wine()) { t_skip("emulator loops when enumerating past a deleted CTL"); return; }
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL); addctl(h, VEC(v_ctl_2), DISP_NEW, NULL);
    PCCTL_CONTEXT c = NULL; int n = 0;
    while ((c = U(CertEnumCTLsInStore)(h, c)) != NULL && n < 5) { n++; CHECK(U(CertDeleteCTLFromStore)(U(CertDuplicateCTLContext)(c))); }
    EXPECT_EQ(n, 2); EXPECT_EQ(sm_nctls(h), 0);
    sm_close(h);
}
TEST(csr_ctl_duplicate_free_null) {
    REQUIRE(U(CertDuplicateCTLContext));
    CHECK(U(CertDuplicateCTLContext)(NULL) == NULL);
    CHECK(U(CertFreeCTLContext)(NULL));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCTL_CONTEXT c = NULL;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, &c);
    CHECK(U(CertDuplicateCTLContext)(c) == c);
    CHECK(U(CertFreeCTLContext)(c));
    sm_close(h);
    CHECK(ctl_is(c, VEC(v_ctl_1a)));
    CHECK(U(CertFreeCTLContext)(c));
}
TEST(csr_ctl_find_any_sha1_md5) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL); addctl(h, VEC(v_ctl_2), DISP_NEW, NULL);
    PCCTL_CONTEXT c = NULL; int n = 0;
    while ((c = U(CertFindCTLInStore)(h, ENC, 0, CTL_FIND_ANY, NULL, c)) != NULL) n++;
    EXPECT_EQ(n, 2);
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_ctl_2 };
    c = U(CertFindCTLInStore)(h, ENC, 0, CTL_FIND_SHA1_HASH, &hb, NULL);
    CHECK(ctl_is(c, VEC(v_ctl_2)));
    freectl(c);
    BYTE z[20] = { 0 }; hb.pbData = z; SET_ERR(0);
    CHECK(U(CertFindCTLInStore)(h, ENC, 0, CTL_FIND_SHA1_HASH, &hb, NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csr_ctl_find_usage) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL); addctl(h, VEC(v_ctl_2), DISP_NEW, NULL);
    LPSTR u[1] = { (LPSTR)"1.3.6.1.5.5.7.3.2" };
    CTL_FIND_USAGE_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p; p.SubjectUsage.cUsageIdentifier = 1; p.SubjectUsage.rgpszUsageIdentifier = u;
    p.ListIdentifier.cbData = 11; p.ListIdentifier.pbData = (BYTE *)"CryptTList2";
    PCCTL_CONTEXT c = U(CertFindCTLInStore)(h, ENC, 0, CTL_FIND_USAGE, &p, NULL);
    CHECK(ctl_is(c, VEC(v_ctl_2)));
    freectl(c);
    u[0] = (LPSTR)"1.3.6.1.5.5.7.3.1";
    p.ListIdentifier.cbData = 0; p.ListIdentifier.pbData = NULL;
    SET_ERR(0);
    c = U(CertFindCTLInStore)(h, ENC, 0, CTL_FIND_USAGE, &p, NULL);
    t_note("find usage serverAuth (not in any CTL) -> %p gle=0x%lx", c, GetLastError());
    freectl(c);
    sm_close(h);
}
TEST(csr_ctl_find_subject_in_ctl) {
    REQUIRE(U(CertFindSubjectInCTL)); REQUIRE(U(CertCreateCTLContext));
    if (t_is_wine()) { t_skip("emulator aborts on this unimplemented export"); return; }
    PCCTL_CONTEXT ctl = U(CertCreateCTLContext)(ENC, VEC(v_ctl_1a));     /* subjects A and B */
    if (!ctl) { t_skip("ctl not parsed"); return; }
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_c));
    PCTL_ENTRY e = U(CertFindSubjectInCTL)(X509_ASN_ENCODING, CTL_CERT_SUBJECT_TYPE, (void *)a, ctl, 0);
    CHECK(e != NULL);
    if (e) CHECK(e->SubjectIdentifier.cbData == 20 && !memcmp(e->SubjectIdentifier.pbData, v_sha1_a, 20));
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(X509_ASN_ENCODING, CTL_CERT_SUBJECT_TYPE, (void *)c, ctl, 0) == NULL);
    CTL_ANY_SUBJECT_INFO id; memset(&id, 0, sizeof id);
    id.SubjectAlgorithm.pszObjId = (LPSTR)"1.3.14.3.2.26";
    id.SubjectIdentifier.cbData = 20; id.SubjectIdentifier.pbData = (BYTE *)v_sha1_b;
    e = U(CertFindSubjectInCTL)(X509_ASN_ENCODING, CTL_ANY_SUBJECT_TYPE, &id, ctl, 0);
    CHECK(e != NULL);
    sm_freec(a); sm_freec(c); freectl(ctl);
}
TEST(csr_ctl_find_subject_by_store_find) {
    REQUIRE(U(CertFindCTLInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL); addctl(h, VEC(v_ctl_2), DISP_NEW, NULL);
    PCCERT_CONTEXT cc = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_c));
    CTL_FIND_SUBJECT_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p; p.dwSubjectType = CTL_CERT_SUBJECT_TYPE; p.pvSubject = (void *)cc;
    PCCTL_CONTEXT c = U(CertFindCTLInStore)(h, ENC, 0, CTL_FIND_SUBJECT, &p, NULL);
    CHECK(ctl_is(c, VEC(v_ctl_2)));                 /* only list 2 trusts C */
    freectl(c);
    sm_freec(cc); sm_close(h);
}
TEST(csr_ctl_property_hash) {
    REQUIRE(U(CertGetCTLContextProperty));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCTL_CONTEXT c = NULL;
    addctl(h, VEC(v_ctl_1b), DISP_NEW, &c);
    BYTE buf[20]; DWORD cb = sizeof buf;
    CHECK(U(CertGetCTLContextProperty)(c, CERT_SHA1_HASH_PROP_ID, buf, &cb));
    EXPECT_EQ(cb, 20); CHECK(!memcmp(buf, v_sha1_ctl_1b, 20));
    cb = 0; SET_ERR(0);
    CHECK(!U(CertGetCTLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_ERR(HR_NOT_FOUND);
    static const WCHAR fn[] = L"ctlname";
    CRYPT_DATA_BLOB b = { sizeof fn, (BYTE *)fn };
    CHECK(U(CertSetCTLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b));
    cb = 0; CHECK(U(CertGetCTLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_EQ(cb, sizeof fn);
    DWORD id = 0; int seen = 0, n = 0;
    while ((id = U(CertEnumCTLContextProperties)(c, id)) != 0 && n++ < 50) if (id == CERT_FRIENDLY_NAME_PROP_ID) seen = 1;
    CHECK(seen);
    freectl(c); sm_close(h);
}
TEST(csr_ctl_replace_inherit_properties) {
    REQUIRE(U(CertSetCTLContextProperty));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCTL_CONTEXT c = NULL;
    addctl(h, VEC(v_ctl_1a), DISP_NEW, &c);
    static const WCHAR fn[] = L"ctlname";
    CRYPT_DATA_BLOB b = { sizeof fn, (BYTE *)fn };
    U(CertSetCTLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b);
    freectl(c); c = NULL;
    CHECK(addctl(h, VEC(v_ctl_1a), DISP_REPL_INH, &c));
    DWORD cb = 0;
    CHECK(U(CertGetCTLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_EQ(cb, sizeof fn);
    freectl(c);
    CHECK(addctl(h, VEC(v_ctl_1a), DISP_REPL, &c));
    cb = 0; SET_ERR(0);
    CHECK(!U(CertGetCTLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb));
    freectl(c); sm_close(h);
}
TEST(csr_all_three_types_in_one_store) {
    REQUIRE(U(CertAddEncodedCTLToStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    addctl(h, VEC(v_ctl_1a), DISP_NEW, NULL);
    EXPECT_EQ(sm_ncerts(h), 3); EXPECT_EQ(sm_ncrls(h), 1); EXPECT_EQ(sm_nctls(h), 1);
    sm_close(h);
}

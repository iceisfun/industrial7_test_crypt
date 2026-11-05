/* Certificate comparison and CertFindCertificateInStore / issuer / subject lookup. */
#include "ccp.h"

static const FX *const set_all[] = {&fx_root, &fx_inter, &fx_leaf, &fx_leafi, &fx_ec256, &fx_sha1leaf, &fx_leaf2, &fx_nestbad, &fx_root2, &fx_leafexp, &fx_leaffut, &fx_utf8};
#define NSET ((int)(sizeof set_all / sizeof set_all[0]))

static HCERTSTORE bigstore(void) {
    HCERTSTORE s = ccp_mem(); int i;
    if (!s) return NULL;
    for (i = 0; i < NSET; i++) { PCCERT_CONTEXT c = ccp_add(s, set_all[i]); if (!c) { ccp_close(s); return NULL; } ccp_free(c); }
    return s;
}
/* Count matches and check that each is one of the expected fixtures (names listed in want, NULL-terminated). */
static int count_find(HCERTSTORE s, DWORD flags, DWORD type, void *para) {
    PCCERT_CONTEXT c = NULL; int n = 0;
    while ((c = C32(CertFindCertificateInStore)(s, ENC, flags, type, para, c)) != NULL && n < 100) n++;
    return n;
}
static const FX *which(PCCERT_CONTEXT c) {
    int i;
    for (i = 0; i < ccp_nall; i++) if (c->cbCertEncoded == ccp_all[i]->cb && !memcmp(c->pbCertEncoded, ccp_all[i]->der, c->cbCertEncoded)) return ccp_all[i];
    return NULL;
}
/* Returns the single/first matching fixture, or NULL. */
static const FX *find1(HCERTSTORE s, DWORD flags, DWORD type, void *para) {
    PCCERT_CONTEXT c = C32(CertFindCertificateInStore)(s, ENC, flags, type, para, NULL);
    const FX *f = c ? which(c) : NULL;
    ccp_free(c); return f;
}

/* ---- comparison helpers ---- */
TEST(ccp_cmp_certificate_same_issuer_and_serial) {
    PCCERT_CONTEXT a = ccp_ctx(&fx_root), b = ccp_ctx(&fx_root2), c = ccp_ctx(&fx_inter);
    REQUIRE(C32(CertCompareCertificate));
    if (!a || !b || !c) { CHECK(0); return; }
    CHECK(C32(CertCompareCertificate)(ENC, a->pCertInfo, a->pCertInfo));
    /* root and root2 have identical issuer name and serial number but different keys */
    CHECK(C32(CertCompareCertificate)(ENC, a->pCertInfo, b->pCertInfo));
    CHECK(!C32(CertCompareCertificate)(ENC, a->pCertInfo, c->pCertInfo));
    CHECK(!C32(CertCompareCertificate)(ENC, c->pCertInfo, a->pCertInfo));
    ccp_free(a); ccp_free(b); ccp_free(c);
}
TEST(ccp_cmp_certificate_same_issuer_different_serial) {
    PCCERT_CONTEXT a = ccp_ctx(&fx_leaf), b = ccp_ctx(&fx_nestbad);
    REQUIRE(C32(CertCompareCertificate));
    if (!a || !b) { CHECK(0); return; }
    CHECK(blob_eq(&a->pCertInfo->Issuer, fx_nestbad.iss, fx_nestbad.cbIss));
    CHECK(!C32(CertCompareCertificate)(ENC, a->pCertInfo, b->pCertInfo));
    ccp_free(a); ccp_free(b);
}
TEST(ccp_cmp_certificate_ignores_subject) {
    PCCERT_CONTEXT a = ccp_ctx(&fx_root), b = ccp_ctx(&fx_root2); CERT_INFO ci;
    REQUIRE(C32(CertCompareCertificate));
    if (!a || !b) { CHECK(0); return; }
    ci = *b->pCertInfo; ci.Subject = a->pCertInfo->Issuer; ci.SubjectPublicKeyInfo = a->pCertInfo->SubjectPublicKeyInfo;
    CHECK(C32(CertCompareCertificate)(ENC, a->pCertInfo, &ci));
    ccp_free(a); ccp_free(b);
}
TEST(ccp_cmp_certificate_name_exact_bytes) {
    PCCERT_CONTEXT r = ccp_ctx(&fx_root), l = ccp_ctx(&fx_leaf), i = ccp_ctx(&fx_inter);
    REQUIRE(C32(CertCompareCertificateName));
    if (!r || !l || !i) { CHECK(0); return; }
    CHECK(C32(CertCompareCertificateName)(ENC, &r->pCertInfo->Subject, &r->pCertInfo->Issuer));      /* self-signed */
    CHECK(C32(CertCompareCertificateName)(ENC, &l->pCertInfo->Issuer, &r->pCertInfo->Subject));
    CHECK(!C32(CertCompareCertificateName)(ENC, &l->pCertInfo->Issuer, &l->pCertInfo->Subject));
    CHECK(!C32(CertCompareCertificateName)(ENC, &i->pCertInfo->Subject, &r->pCertInfo->Subject));
    ccp_free(r); ccp_free(l); ccp_free(i);
}
TEST(ccp_cmp_certificate_name_copy_of_bytes) {
    PCCERT_CONTEXT r = ccp_ctx(&fx_root); BYTE copy[256]; CERT_NAME_BLOB nb;
    REQUIRE(C32(CertCompareCertificateName));
    if (!r) { CHECK(0); return; }
    memcpy(copy, r->pCertInfo->Subject.pbData, r->pCertInfo->Subject.cbData);
    nb.cbData = r->pCertInfo->Subject.cbData; nb.pbData = copy;
    CHECK(C32(CertCompareCertificateName)(ENC, &nb, &r->pCertInfo->Subject));
    copy[nb.cbData - 1] ^= 1;
    CHECK(!C32(CertCompareCertificateName)(ENC, &nb, &r->pCertInfo->Subject));
    nb.cbData--;
    CHECK(!C32(CertCompareCertificateName)(ENC, &nb, &r->pCertInfo->Subject));
    ccp_free(r);
}
TEST(ccp_cmp_integer_blob_basic) {
    BYTE a1[] = {1}, a2[] = {1, 0}, a3[] = {1, 0, 0, 0}, b1[] = {2}, c1[] = {1, 2}, c2[] = {1, 2, 0}, z1[] = {0}, z2[] = {0, 0};
    CRYPT_INTEGER_BLOB A1 = {1, a1}, A2 = {2, a2}, A3 = {4, a3}, B1 = {1, b1}, C1 = {2, c1}, C2 = {3, c2}, Z1 = {1, z1}, Z2 = {2, z2};
    REQUIRE(C32(CertCompareIntegerBlob));
    CHECK(C32(CertCompareIntegerBlob)(&A1, &A1));
    CHECK(C32(CertCompareIntegerBlob)(&A1, &A2));          /* trailing (most significant) zero octets are ignored */
    CHECK(C32(CertCompareIntegerBlob)(&A2, &A3));
    CHECK(C32(CertCompareIntegerBlob)(&A3, &A1));
    CHECK(!C32(CertCompareIntegerBlob)(&A1, &B1));
    CHECK(!C32(CertCompareIntegerBlob)(&A1, &C1));
    CHECK(C32(CertCompareIntegerBlob)(&C1, &C2));
    CHECK(!C32(CertCompareIntegerBlob)(&C2, &A1));
    CHECK(C32(CertCompareIntegerBlob)(&Z1, &Z2));
}
TEST(ccp_cmp_integer_blob_serials_from_certs) {
    PCCERT_CONTEXT a = ccp_ctx(&fx_leaf), b = ccp_ctx(&fx_nestbad), c = ccp_ctx(&fx_root2), d = ccp_ctx(&fx_root);
    REQUIRE(C32(CertCompareIntegerBlob));
    if (!a || !b || !c || !d) { CHECK(0); return; }
    CHECK(C32(CertCompareIntegerBlob)(&a->pCertInfo->SerialNumber, &a->pCertInfo->SerialNumber));
    CHECK(!C32(CertCompareIntegerBlob)(&a->pCertInfo->SerialNumber, &b->pCertInfo->SerialNumber));
    CHECK(C32(CertCompareIntegerBlob)(&c->pCertInfo->SerialNumber, &d->pCertInfo->SerialNumber));
    ccp_free(a); ccp_free(b); ccp_free(c); ccp_free(d);
}
TEST(ccp_cmp_public_key_info) {
    PCCERT_CONTEXT r = ccp_ctx(&fx_root), r2 = ccp_ctx(&fx_root2), l = ccp_ctx(&fx_leaf), e = ccp_ctx(&fx_ec256);
    REQUIRE(C32(CertComparePublicKeyInfo));
    if (!r || !r2 || !l || !e) { CHECK(0); return; }
    CHECK(C32(CertComparePublicKeyInfo)(ENC, &r->pCertInfo->SubjectPublicKeyInfo, &r->pCertInfo->SubjectPublicKeyInfo));
    CHECK(!C32(CertComparePublicKeyInfo)(ENC, &r->pCertInfo->SubjectPublicKeyInfo, &r2->pCertInfo->SubjectPublicKeyInfo));
    CHECK(!C32(CertComparePublicKeyInfo)(ENC, &r->pCertInfo->SubjectPublicKeyInfo, &l->pCertInfo->SubjectPublicKeyInfo));
    CHECK(!C32(CertComparePublicKeyInfo)(ENC, &r->pCertInfo->SubjectPublicKeyInfo, &e->pCertInfo->SubjectPublicKeyInfo));
    CHECK(!C32(CertComparePublicKeyInfo)(ENC, &e->pCertInfo->SubjectPublicKeyInfo, &r->pCertInfo->SubjectPublicKeyInfo));
    ccp_free(r); ccp_free(r2); ccp_free(l); ccp_free(e);
}
TEST(ccp_cmp_public_key_info_copy) {
    PCCERT_CONTEXT e = ccp_ctx(&fx_ec256), e2 = ccp_ctx(&fx_ec256);
    REQUIRE(C32(CertComparePublicKeyInfo));
    if (!e || !e2) { CHECK(0); return; }
    CHECK(C32(CertComparePublicKeyInfo)(ENC, &e->pCertInfo->SubjectPublicKeyInfo, &e2->pCertInfo->SubjectPublicKeyInfo));
    ccp_free(e); ccp_free(e2);
}
TEST(ccp_cmp_public_key_info_modified_bit_differs) {
    PCCERT_CONTEXT r = ccp_ctx(&fx_root); CERT_PUBLIC_KEY_INFO k; BYTE copy[300];
    REQUIRE(C32(CertComparePublicKeyInfo));
    if (!r) { CHECK(0); return; }
    k = r->pCertInfo->SubjectPublicKeyInfo;
    memcpy(copy, k.PublicKey.pbData, k.PublicKey.cbData);
    copy[k.PublicKey.cbData - 1] ^= 0x01;
    k.PublicKey.pbData = copy;
    CHECK(!C32(CertComparePublicKeyInfo)(ENC, &r->pCertInfo->SubjectPublicKeyInfo, &k));
    copy[k.PublicKey.cbData - 1] ^= 0x01;
    CHECK(C32(CertComparePublicKeyInfo)(ENC, &r->pCertInfo->SubjectPublicKeyInfo, &k));
    ccp_free(r);
}

/* ---- CertFindCertificateInStore ---- */
TEST(ccp_find_null_store_is_invalidarg) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertFindCertificateInStore));
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(NULL, ENC, 0, CERT_FIND_ANY, NULL, NULL);
    EXPECT_FAIL(c == NULL, E_INVALIDARG_);
}
TEST(ccp_find_any_enumerates_all) {
    HCERTSTORE s = bigstore();
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ANY, NULL), NSET);
    ccp_close(s);
}
TEST(ccp_find_empty_store_not_found) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT c;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_ANY, NULL, NULL);
    EXPECT_FAIL(c == NULL, CRYPT_E_NOT_FOUND_);
    ccp_close(s);
}
TEST(ccp_find_end_of_enumeration_sets_not_found) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c = NULL; int n = 0;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    SET_ERR(0);
    while ((c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_ANY, NULL, c)) != NULL) n++;
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    EXPECT_EQ(n, NSET);
    ccp_close(s);
}
TEST(ccp_find_prev_context_is_released_by_call) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT a, b, dup;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    a = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_ANY, NULL, NULL);
    CHECK(a != NULL);
    dup = C32(CertDuplicateCertificateContext)(a);       /* keep a usable after the call frees prev */
    b = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_ANY, NULL, a);
    CHECK(b != NULL && b != dup);
    CHECK(dup->cbCertEncoded > 0 && dup->pbCertEncoded[0] == 0x30);
    ccp_free(b); ccp_free(dup);
    ccp_close(s);
}
TEST(ccp_find_sha1_hash_every_fixture) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        CRYPT_HASH_BLOB h; h.cbData = 20; h.pbData = (BYTE *)set_all[i]->sha1;
        CHECKF(find1(s, 0, CERT_FIND_SHA1_HASH, &h) == set_all[i], "%s", set_all[i]->name);
        CHECKF(find1(s, 0, CERT_FIND_HASH, &h) == set_all[i], "%s (CERT_FIND_HASH)", set_all[i]->name);
    }
    ccp_close(s);
}
TEST(ccp_find_sha1_hash_no_match) {
    HCERTSTORE s = bigstore(); BYTE z[20] = {0}; CRYPT_HASH_BLOB h; PCCERT_CONTEXT c;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    h.cbData = 20; h.pbData = z; SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_SHA1_HASH, &h, NULL);
    EXPECT_FAIL(c == NULL, CRYPT_E_NOT_FOUND_);
    h.cbData = 19; h.pbData = (BYTE *)fx_root.sha1;       /* wrong length */
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_SHA1_HASH, &h, NULL);
    EXPECT_FAIL(c == NULL, CRYPT_E_NOT_FOUND_);
    h.cbData = 0; h.pbData = NULL; SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_SHA1_HASH, &h, NULL);
    CHECK(c == NULL);
    ccp_close(s);
}
TEST(ccp_find_md5_hash_every_fixture) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        CRYPT_HASH_BLOB h; h.cbData = 16; h.pbData = (BYTE *)set_all[i]->md5;
        CHECKF(find1(s, 0, CERT_FIND_MD5_HASH, &h) == set_all[i], "%s", set_all[i]->name);
    }
    ccp_close(s);
}
TEST(ccp_find_signature_hash) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        CRYPT_HASH_BLOB h; h.cbData = set_all[i]->cbSigHash; h.pbData = (BYTE *)set_all[i]->sighash;
        CHECKF(find1(s, 0, CERT_FIND_SIGNATURE_HASH, &h) == set_all[i], "%s", set_all[i]->name);
    }
    ccp_close(s);
}
TEST(ccp_find_key_identifier) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        CRYPT_HASH_BLOB h; h.cbData = 20; h.pbData = (BYTE *)(set_all[i]->hasski ? set_all[i]->ski : set_all[i]->spkisha1);
        CHECKF(find1(s, 0, CERT_FIND_KEY_IDENTIFIER, &h) == set_all[i], "%s", set_all[i]->name);
    }
    ccp_close(s);
}
TEST(ccp_find_pubkey_md5_hash) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        CRYPT_HASH_BLOB h; h.cbData = 16; h.pbData = (BYTE *)set_all[i]->pubmd5;
        CHECKF(find1(s, 0, CERT_FIND_PUBKEY_MD5_HASH, &h) == set_all[i], "%s", set_all[i]->name);
    }
    ccp_close(s);
}
TEST(ccp_find_subject_name_exact) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        CERT_NAME_BLOB nb; nb.cbData = set_all[i]->cbSubj; nb.pbData = (BYTE *)set_all[i]->subj;
        /* root and root2 share a subject: the first one added wins, the count is 2 */
        if (set_all[i] == &fx_root || set_all[i] == &fx_root2) { EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_NAME, &nb), 2); continue; }
        CHECKF(find1(s, 0, CERT_FIND_SUBJECT_NAME, &nb) == set_all[i], "%s", set_all[i]->name);
        EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_NAME, &nb), 1);
    }
    ccp_close(s);
}
TEST(ccp_find_issuer_name_counts) {
    HCERTSTORE s = bigstore(); CERT_NAME_BLOB nb;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    /* issued under "Test Root CA": root, root2, inter, leaf, sha1leaf, nestbad, leafexp, leaffut, leaf2 */
    nb.cbData = fx_root.cbSubj; nb.pbData = (BYTE *)fx_root.subj;
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ISSUER_NAME, &nb), 9);
    nb.cbData = fx_inter.cbSubj; nb.pbData = (BYTE *)fx_inter.subj;
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ISSUER_NAME, &nb), 1);
    CHECK(find1(s, 0, CERT_FIND_ISSUER_NAME, &nb) == &fx_leafi);
    nb.cbData = fx_ec256.cbSubj; nb.pbData = (BYTE *)fx_ec256.subj;
    CHECK(find1(s, 0, CERT_FIND_ISSUER_NAME, &nb) == &fx_ec256);
    ccp_close(s);
}
TEST(ccp_find_name_blob_must_match_exactly) {
    HCERTSTORE s = bigstore(); CERT_NAME_BLOB nb; BYTE copy[256]; PCCERT_CONTEXT c;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    memcpy(copy, fx_leaf.subj, fx_leaf.cbSubj);
    nb.cbData = fx_leaf.cbSubj; nb.pbData = copy;
    CHECK(find1(s, 0, CERT_FIND_SUBJECT_NAME, &nb) == &fx_leaf);
    copy[fx_leaf.cbSubj - 2] ^= 0x20;       /* flip case of the last character */
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_SUBJECT_NAME, &nb, NULL);
    EXPECT_FAIL(c == NULL, CRYPT_E_NOT_FOUND_);
    ccp_close(s);
}
TEST(ccp_find_subject_str_w) {
    HCERTSTORE s = bigstore();
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"leaf.cryptt.test"), 1);
    CHECK(find1(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"leaf.cryptt.test") == &fx_leaf);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"Test Root CA"), 2);           /* root, root2 */
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"Test Intermediate"), 1);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"no such name anywhere"), 0);
    ccp_close(s);
}
TEST(ccp_find_subject_str_is_case_insensitive_substring) {
    HCERTSTORE s = bigstore();
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"LEAF.CRYPTT.TEST"), 1);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"eaf.cryptt"), 1);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"root ca"), 2);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"expired leaf"), 1);
    ccp_close(s);
}
TEST(ccp_find_subject_str_a_matches_w) {
    HCERTSTORE s = bigstore();
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_A, (void *)"leaf.cryptt.test"), 1);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_A, (void *)"Test Root CA"), 2);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR, (void *)L"Test Root CA"), 2);     /* CERT_FIND_SUBJECT_STR is the wide variant */
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_A, (void *)"zzz"), 0);
    ccp_close(s);
}
TEST(ccp_find_issuer_str) {
    HCERTSTORE s = bigstore();
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ISSUER_STR_W, (void *)L"Test Root CA"), 9);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ISSUER_STR_A, (void *)"Test Intermediate"), 1);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ISSUER_STR, (void *)L"test intermediate"), 1);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ISSUER_STR_W, (void *)L"ec p256 self"), 1);
    ccp_close(s);
}
TEST(ccp_find_subject_str_non_ascii) {
    HCERTSTORE s = bigstore();
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"Grüße"), 1);
    CHECK(find1(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"Grüße") == &fx_utf8);
    ccp_close(s);
}
TEST(ccp_find_subject_attr_cn) {
    HCERTSTORE s = bigstore(); CERT_RDN_ATTR a; CERT_RDN rdn; static const WCHAR v[] = L"Test Intermediate";
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    memset(&a, 0, sizeof a);
    a.pszObjId = (LPSTR)szOID_COMMON_NAME; a.dwValueType = CERT_RDN_UTF8_STRING; a.Value.cbData = 34; a.Value.pbData = (BYTE *)v;   /* UTF-16 values, as in decoded names */
    rdn.cRDNAttr = 1; rdn.rgRDNAttr = &a;
    CHECK(find1(s, 0, CERT_FIND_SUBJECT_ATTR, &rdn) == &fx_inter);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ISSUER_ATTR, &rdn), 1);
    a.dwValueType = 0;                               /* ANY type matches as well */
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_ATTR, &rdn), 1);
    a.dwValueType = CERT_RDN_BMP_STRING;             /* the BMP type and 8-bit values never match a UTF-16 decoded UTF8 attribute */
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_ATTR, &rdn), 0);
    a.dwValueType = CERT_RDN_UTF8_STRING; a.Value.cbData = 17; a.Value.pbData = (BYTE *)"Test Intermediate";
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_ATTR, &rdn), 0);
    a.Value.cbData = 34; a.Value.pbData = (BYTE *)v;
    a.pszObjId = (LPSTR)szOID_ORGANIZATION_NAME;     /* wrong attribute type for this value */
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_ATTR, &rdn), 0);
    ccp_close(s);
}
TEST(ccp_find_subject_attr_multiple_attrs_must_all_match) {
    HCERTSTORE s = bigstore(); CERT_RDN_ATTR a[2]; CERT_RDN rdn; WCHAR o[] = L"cryptt", cn[] = L"leaf.cryptt.test";
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    memset(a, 0, sizeof a);
    a[0].pszObjId = (LPSTR)szOID_ORGANIZATION_NAME; a[0].dwValueType = CERT_RDN_UTF8_STRING; a[0].Value.cbData = 12; a[0].Value.pbData = (BYTE *)o;
    a[1].pszObjId = (LPSTR)szOID_COMMON_NAME; a[1].dwValueType = CERT_RDN_UTF8_STRING; a[1].Value.cbData = 32; a[1].Value.pbData = (BYTE *)cn;
    rdn.cRDNAttr = 2; rdn.rgRDNAttr = a;
    CHECK(find1(s, 0, CERT_FIND_SUBJECT_ATTR, &rdn) == &fx_leaf);
    cn[0] = 'x';
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_ATTR, &rdn), 0);
    ccp_close(s);
}
TEST(ccp_find_subject_cert_by_issuer_serial) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        PCCERT_CONTEXT c = ccp_ctx(set_all[i]);
        const FX *f;
        if (!c) { CHECK(0); continue; }
        f = find1(s, 0, CERT_FIND_SUBJECT_CERT, c->pCertInfo);
        /* root/root2 share issuer+serial: either answer is valid, and both exist */
        if (set_all[i] == &fx_root || set_all[i] == &fx_root2) CHECKF(f == &fx_root || f == &fx_root2, "%s", set_all[i]->name);
        else CHECKF(f == set_all[i], "%s", set_all[i]->name);
        ccp_free(c);
    }
    ccp_close(s);
}
TEST(ccp_find_subject_cert_uses_only_issuer_and_serial) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); CERT_INFO ci;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s || !c) { CHECK(0); return; }
    memset(&ci, 0, sizeof ci);
    ci.Issuer = c->pCertInfo->Issuer; ci.SerialNumber = c->pCertInfo->SerialNumber;
    CHECK(find1(s, 0, CERT_FIND_SUBJECT_CERT, &ci) == &fx_leaf);
    { PCCERT_CONTEXT n = ccp_ctx(&fx_nestbad); ci.SerialNumber = n->pCertInfo->SerialNumber;
      CHECK(find1(s, 0, CERT_FIND_SUBJECT_CERT, &ci) == &fx_nestbad);     /* same issuer, other serial */
      ccp_free(n); }
    ccp_free(c); ccp_close(s);
}
TEST(ccp_find_issuer_of_prefers_matching_aki) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT leaf = ccp_ctx(&fx_leaf), c; PCCERT_CONTEXT a;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s || !leaf) { CHECK(0); return; }
    a = ccp_add(s, &fx_root2); ccp_free(a);      /* same subject name as the real issuer, other key */
    a = ccp_add(s, &fx_root); ccp_free(a);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_ISSUER_OF, (void *)leaf, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(which(c) == &fx_root); ccp_free(c); }
    ccp_free(leaf); ccp_close(s);
}
TEST(ccp_find_issuer_of_not_found) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT leaf = ccp_ctx(&fx_leafi), c, a;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s || !leaf) { CHECK(0); return; }
    a = ccp_add(s, &fx_root); ccp_free(a);
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_ISSUER_OF, (void *)leaf, NULL);
    EXPECT_FAIL(c == NULL, CRYPT_E_NOT_FOUND_);
    a = ccp_add(s, &fx_inter); ccp_free(a);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_ISSUER_OF, (void *)leaf, NULL);
    CHECK(c != NULL && which(c) == &fx_inter);
    ccp_free(c); ccp_free(leaf); ccp_close(s);
}
TEST(ccp_find_existing) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        PCCERT_CONTEXT c = ccp_ctx(set_all[i]);
        if (!c) { CHECK(0); continue; }
        CHECKF(find1(s, 0, CERT_FIND_EXISTING, (void *)c) == set_all[i], "%s", set_all[i]->name);
        ccp_free(c);
    }
    { PCCERT_CONTEXT c = ccp_ctx(&fx_rsa1024); SET_ERR(0);
      CHECK(C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_EXISTING, (void *)c, NULL) == NULL); EXPECT_ERR(CRYPT_E_NOT_FOUND_); ccp_free(c); }
    ccp_close(s);
}
TEST(ccp_find_public_key) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        PCCERT_CONTEXT c = ccp_ctx(set_all[i]);
        if (!c) { CHECK(0); continue; }
        CHECKF(find1(s, 0, CERT_FIND_PUBLIC_KEY, &c->pCertInfo->SubjectPublicKeyInfo) == set_all[i], "%s", set_all[i]->name);
        EXPECT_EQ(count_find(s, 0, CERT_FIND_PUBLIC_KEY, &c->pCertInfo->SubjectPublicKeyInfo), 1);
        ccp_free(c);
    }
    ccp_close(s);
}
TEST(ccp_find_property) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c; DWORD id = 0x9500, id2 = CERT_DESCRIPTION_PROP_ID; BYTE d[2] = {1, 2}; CRYPT_DATA_BLOB b;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    b.cbData = 2; b.pbData = d;
    EXPECT_EQ(count_find(s, 0, CERT_FIND_PROPERTY, &id), 0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_HASH, &(CRYPT_HASH_BLOB){20, (BYTE *)fx_utf8.sha1}, NULL);
    CHECK(c != NULL);
    if (c) {
        CHECK(C32(CertSetCertificateContextProperty)(c, id, 0, &b));
        CHECK(C32(CertSetCertificateContextProperty)(c, id2, 0, &b));
        ccp_free(c);
    }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_PROPERTY, &id), 1);
    CHECK(find1(s, 0, CERT_FIND_PROPERTY, &id) == &fx_utf8);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_PROPERTY, &id2), 1);
    ccp_close(s);
}
TEST(ccp_find_property_hash_ids_match_all) {
    HCERTSTORE s = bigstore(); DWORD id = CERT_SHA1_HASH_PROP_ID;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    /* a computed (never explicitly set) property counts as present */
    EXPECT_EQ(count_find(s, 0, CERT_FIND_PROPERTY, &id), NSET);
    ccp_close(s);
}
TEST(ccp_find_key_spec) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c; DWORD spec = AT_SIGNATURE, other = AT_KEYEXCHANGE; CRYPT_KEY_PROV_INFO ki; static WCHAR cn[] = L"cryptt_findspec";
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_KEY_SPEC, &spec), 0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_HASH, &(CRYPT_HASH_BLOB){20, (BYTE *)fx_leafi.sha1}, NULL);
    CHECK(c != NULL);
    if (c) {
        memset(&ki, 0, sizeof ki); ki.pwszContainerName = cn; ki.dwProvType = PROV_RSA_FULL; ki.dwKeySpec = AT_SIGNATURE;
        CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &ki));
        ccp_free(c);
    }
    EXPECT_EQ(count_find(s, 0, CERT_FIND_KEY_SPEC, &spec), 1);
    CHECK(find1(s, 0, CERT_FIND_KEY_SPEC, &spec) == &fx_leafi);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_KEY_SPEC, &other), 0);
    ccp_close(s);
}
TEST(ccp_find_has_private_key_none) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_HAS_PRIVATE_KEY, NULL, NULL);
    CHECK(c == NULL);
    ccp_free(c); ccp_close(s);
}
TEST(ccp_find_cert_id_issuer_serial) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        PCCERT_CONTEXT c = ccp_ctx(set_all[i]); CERT_ID id; const FX *f;
        if (!c) { CHECK(0); continue; }
        memset(&id, 0, sizeof id);
        id.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;
        id.IssuerSerialNumber.Issuer = c->pCertInfo->Issuer; id.IssuerSerialNumber.SerialNumber = c->pCertInfo->SerialNumber;
        f = find1(s, 0, CERT_FIND_CERT_ID, &id);
        if (set_all[i] == &fx_root || set_all[i] == &fx_root2) CHECKF(f == &fx_root || f == &fx_root2, "%s", set_all[i]->name);
        else CHECKF(f == set_all[i], "%s", set_all[i]->name);
        ccp_free(c);
    }
    ccp_close(s);
}
TEST(ccp_find_cert_id_key_identifier_and_hash) {
    HCERTSTORE s = bigstore(); int i;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    for (i = 0; i < NSET; i++) {
        CERT_ID id;
        memset(&id, 0, sizeof id);
        id.dwIdChoice = CERT_ID_KEY_IDENTIFIER; id.KeyId.cbData = 20; id.KeyId.pbData = (BYTE *)(set_all[i]->hasski ? set_all[i]->ski : set_all[i]->spkisha1);
        CHECKF(find1(s, 0, CERT_FIND_CERT_ID, &id) == set_all[i], "keyid %s", set_all[i]->name);
        memset(&id, 0, sizeof id);
        id.dwIdChoice = CERT_ID_SHA1_HASH; id.HashId.cbData = 20; id.HashId.pbData = (BYTE *)set_all[i]->sha1;
        CHECKF(find1(s, 0, CERT_FIND_CERT_ID, &id) == set_all[i], "hash %s", set_all[i]->name);
    }
    ccp_close(s);
}
TEST(ccp_find_cert_id_bad_choice) {
    HCERTSTORE s = bigstore(); CERT_ID id; PCCERT_CONTEXT c;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    memset(&id, 0, sizeof id); id.dwIdChoice = 0;
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_CERT_ID, &id, NULL);
    CHECK(c == NULL); EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    id.dwIdChoice = 9; SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_CERT_ID, &id, NULL);
    CHECK(c == NULL); EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    ccp_free(c); ccp_close(s);
}
TEST(ccp_find_enhkey_usage) {
    HCERTSTORE s = bigstore(); CERT_ENHKEY_USAGE u; LPSTR oid[1];
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    u.cUsageIdentifier = 1; u.rgpszUsageIdentifier = oid;
    oid[0] = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
    CHECK(find1(s, 0, CERT_FIND_ENHKEY_USAGE, &u) == &fx_leaf);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ENHKEY_USAGE, &u), 1);
    oid[0] = (LPSTR)szOID_PKIX_KP_CODE_SIGNING;
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ENHKEY_USAGE, &u), 2);          /* leafi, ec256 */
    oid[0] = (LPSTR)szOID_PKIX_KP_EMAIL_PROTECTION;
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ENHKEY_USAGE, &u), 0);
    ccp_close(s);
}
TEST(ccp_find_enhkey_usage_all_listed_must_be_present) {
    HCERTSTORE s = bigstore(); CERT_ENHKEY_USAGE u; LPSTR oid[2];
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    u.cUsageIdentifier = 2; u.rgpszUsageIdentifier = oid;
    oid[0] = (LPSTR)szOID_PKIX_KP_SERVER_AUTH; oid[1] = (LPSTR)szOID_PKIX_KP_CLIENT_AUTH;
    CHECK(find1(s, 0, CERT_FIND_ENHKEY_USAGE, &u) == &fx_leaf);
    oid[1] = (LPSTR)szOID_PKIX_KP_CODE_SIGNING;
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ENHKEY_USAGE, &u), 0);
    ccp_close(s);
}
TEST(ccp_find_enhkey_usage_optional_includes_certs_without_eku) {
    HCERTSTORE s = bigstore(); CERT_ENHKEY_USAGE u; LPSTR oid[1]; int with_opt, without;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    u.cUsageIdentifier = 1; u.rgpszUsageIdentifier = oid; oid[0] = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
    without = count_find(s, 0, CERT_FIND_ENHKEY_USAGE, &u);
    with_opt = count_find(s, CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, &u);
    EXPECT_EQ(without, 1);
    /* certs lacking any EKU (root, root2, inter, sha1leaf, leaf2, nestbad, leafexp, leaffut, utf8) are now acceptable */
    EXPECT_EQ(with_opt, 10);
    ccp_close(s);
}
TEST(ccp_find_enhkey_usage_no_eku_flag) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c = NULL; int n = 0;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    while ((c = C32(CertFindCertificateInStore)(s, ENC, CERT_FIND_NO_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, NULL, c)) != NULL && n < 50) {
        const FX *f = which(c);
        CHECK(f != &fx_leaf && f != &fx_leafi && f != &fx_ec256);
        n++;
    }
    EXPECT_EQ(n, 9);
    ccp_close(s);
}
TEST(ccp_find_enhkey_usage_or_flag) {
    HCERTSTORE s = bigstore(); CERT_ENHKEY_USAGE u; LPSTR oid[2];
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    u.cUsageIdentifier = 2; u.rgpszUsageIdentifier = oid;
    oid[0] = (LPSTR)szOID_PKIX_KP_SERVER_AUTH; oid[1] = (LPSTR)szOID_PKIX_KP_CODE_SIGNING;
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ENHKEY_USAGE, &u), 0);                           /* no cert has both */
    EXPECT_EQ(count_find(s, CERT_FIND_OR_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, &u), 3);   /* leaf, leafi, ec256 */
    ccp_close(s);
}
TEST(ccp_find_ctl_usage_matches_enhkey_usage) {
    HCERTSTORE s = bigstore(); CTL_USAGE u; LPSTR oid[1];
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    u.cUsageIdentifier = 1; u.rgpszUsageIdentifier = oid; oid[0] = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
    CHECK(find1(s, 0, CERT_FIND_CTL_USAGE, &u) == &fx_leaf);
    ccp_close(s);
}
TEST(ccp_find_enhkey_usage_property_only_and_ext_only_flags) {
    HCERTSTORE s = bigstore(); CERT_ENHKEY_USAGE u; LPSTR oid[1]; PCCERT_CONTEXT c; LPSTR pu[1];
    CERT_ENHKEY_USAGE set;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    u.cUsageIdentifier = 1; u.rgpszUsageIdentifier = oid; oid[0] = (LPSTR)szOID_PKIX_KP_EMAIL_PROTECTION;
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_HASH, &(CRYPT_HASH_BLOB){20, (BYTE *)fx_root.sha1}, NULL);
    CHECK(c != NULL);
    if (c) {
        pu[0] = (LPSTR)szOID_PKIX_KP_EMAIL_PROTECTION; set.cUsageIdentifier = 1; set.rgpszUsageIdentifier = pu;
        CHECK(C32(CertSetEnhancedKeyUsage)(c, &set));
        ccp_free(c);
    }
    CHECK(find1(s, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, &u) == &fx_root);
    EXPECT_EQ(count_find(s, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, &u), 0);
    CHECK(find1(s, 0, CERT_FIND_ENHKEY_USAGE, &u) == &fx_root);
    /* the extension usage on leaf is not visible with the property-only flag */
    oid[0] = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
    EXPECT_EQ(count_find(s, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, &u), 0);
    CHECK(find1(s, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, &u) == &fx_leaf);
    ccp_close(s);
}
TEST(ccp_find_archived_not_returned) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c; CRYPT_DATA_BLOB b = {0, NULL}; CRYPT_HASH_BLOB h;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    h.cbData = 20; h.pbData = (BYTE *)fx_utf8.sha1;
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_HASH, &h, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(C32(CertSetCertificateContextProperty)(c, CERT_ARCHIVED_PROP_ID, 0, &b)); ccp_free(c); }
    /* lookups by hash still return an archived certificate; ANY, string finds and enumeration skip it */
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_HASH, &h, NULL);
    CHECK(c != NULL && which(c) == &fx_utf8);
    ccp_free(c);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_ANY, NULL), NSET - 1);
    EXPECT_EQ(count_find(s, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"Gr\u00fc\u00dfe"), 0);
    { int n = 0; c = NULL; while ((c = C32(CertEnumCertificatesInStore)(s, c)) != NULL && n < 100) n++; EXPECT_EQ(n, NSET - 1); }
    ccp_close(s);
}
TEST(ccp_find_unknown_type_fails) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c;
    REQUIRE(C32(CertFindCertificateInStore));
    if (!s) { CHECK(0); return; }
    SET_ERR(0);
    c = C32(CertFindCertificateInStore)(s, ENC, 0, 0x7F << 16, NULL, NULL);
    CHECK(c == NULL);
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    ccp_free(c); ccp_close(s);
}
TEST(ccp_find_after_delete_from_store) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c; CRYPT_HASH_BLOB h;
    REQUIRE(C32(CertDeleteCertificateFromStore));
    if (!s) { CHECK(0); return; }
    h.cbData = 20; h.pbData = (BYTE *)fx_leafi.sha1;
    c = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_SHA1_HASH, &h, NULL);
    CHECK(c != NULL);
    if (c) {
        CHECK(C32(CertDeleteCertificateFromStore)(c));         /* frees the context as well */
        SET_ERR(0);
        CHECK(C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_SHA1_HASH, &h, NULL) == NULL);
        EXPECT_ERR(CRYPT_E_NOT_FOUND_);
        EXPECT_EQ(count_find(s, 0, CERT_FIND_ANY, NULL), NSET - 1);
    }
    ccp_close(s);
}

/* ---- CertGetSubjectCertificateFromStore ---- */
TEST(ccp_get_subject_cert_found) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), r;
    REQUIRE(C32(CertGetSubjectCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    r = C32(CertGetSubjectCertificateFromStore)(s, ENC, l->pCertInfo);
    CHECK(r != NULL && which(r) == &fx_leaf);
    ccp_free(r); ccp_free(l); ccp_close(s);
}
TEST(ccp_get_subject_cert_not_found) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT l = ccp_ctx(&fx_rsa1024), r;
    REQUIRE(C32(CertGetSubjectCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    SET_ERR(0);
    r = C32(CertGetSubjectCertificateFromStore)(s, ENC, l->pCertInfo);
    EXPECT_FAIL(r == NULL, CRYPT_E_NOT_FOUND_);
    ccp_free(l); ccp_close(s);
}
TEST(ccp_get_subject_cert_null_info) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT r;
    REQUIRE(C32(CertGetSubjectCertificateFromStore));
    if (!s) { CHECK(0); return; }
    SET_ERR(0);
    r = C32(CertGetSubjectCertificateFromStore)(s, ENC, NULL);
    EXPECT_FAIL(r == NULL, E_INVALIDARG_);
    ccp_close(s);
}
TEST(ccp_get_subject_cert_encoding_zero) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), r;
    REQUIRE(C32(CertGetSubjectCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    SET_ERR(0);
    r = C32(CertGetSubjectCertificateFromStore)(s, 0, l->pCertInfo);
    CHECK(r == NULL);
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    ccp_free(r); ccp_free(l); ccp_close(s);
}

/* ---- CertGetIssuerCertificateFromStore ---- */
TEST(ccp_get_issuer_basic) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), r; DWORD fl = 0;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    /* root and root2 share their subject name; the store yields the later added one first, then the other */
    CHECK(r != NULL && which(r) == &fx_root2);
    EXPECT_EQ(fl, 0);
    if (r) { PCCERT_CONTEXT r2 = C32(CertGetIssuerCertificateFromStore)(s, l, r, &fl); CHECK(r2 != NULL && which(r2) == &fx_root); ccp_free(r2); }
    ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_chain_up) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT l = ccp_ctx(&fx_leafi), i, r; DWORD fl = 0, fl2 = 0;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    i = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(i != NULL && which(i) == &fx_inter);
    if (i) { r = C32(CertGetIssuerCertificateFromStore)(s, i, NULL, &fl2); CHECK(r != NULL && which(r) == &fx_root2); ccp_free(r); }
    ccp_free(i); ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_self_signed) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT c = ccp_ctx(&fx_ec256), r; DWORD fl = 0;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !c) { CHECK(0); return; }
    { PCCERT_CONTEXT x = ccp_add(s, &fx_ec256); ccp_free(x); }
    SET_ERR(0);
    r = C32(CertGetIssuerCertificateFromStore)(s, c, NULL, &fl);
    EXPECT_FAIL(r == NULL, CRYPT_E_SELF_SIGNED);
    ccp_free(c); ccp_close(s);
}
TEST(ccp_get_issuer_not_in_store) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), r; DWORD fl = 0;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    SET_ERR(0);
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    EXPECT_FAIL(r == NULL, CRYPT_E_NOT_FOUND_);
    ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_signature_flag_ok) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), r, a, b; DWORD fl = CERT_STORE_SIGNATURE_FLAG;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    a = ccp_add(s, &fx_root); ccp_free(a);
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r != NULL && which(r) == &fx_root);
    EXPECT_EQ(fl, 0);        /* the requested check passed, so its bit is cleared */
    ccp_free(r);
    /* in a store that also has root2 (same name, other key) the first candidate is root2 and fails the check */
    b = ccp_add(s, &fx_root2); ccp_free(b);
    fl = CERT_STORE_SIGNATURE_FLAG;
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r != NULL && which(r) == &fx_root2);
    EXPECT_EQ(fl, CERT_STORE_SIGNATURE_FLAG);
    ccp_free(r); ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_signature_flag_fails_for_forged_cert) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf2), r, a; DWORD fl = CERT_STORE_SIGNATURE_FLAG;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    a = ccp_add(s, &fx_root); ccp_free(a);     /* name matches, key does not: leaf2 was signed by root2's key */
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r != NULL && which(r) == &fx_root);
    CHECK((fl & CERT_STORE_SIGNATURE_FLAG) != 0);          /* flag stays set when the verification fails */
    ccp_free(r);
    fl = 0;     /* not requested: no verification */
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r != NULL); EXPECT_EQ(fl, 0);
    ccp_free(r); ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_signature_flag_with_matching_forged_issuer) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf2), r, a; DWORD fl = CERT_STORE_SIGNATURE_FLAG;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    a = ccp_add(s, &fx_root2); ccp_free(a);
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r != NULL && which(r) == &fx_root2);
    EXPECT_EQ(fl, 0);
    ccp_free(r); ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_time_validity_flag) {
    HCERTSTORE s = bigstore(); DWORD fl; PCCERT_CONTEXT c, r;
    struct { const FX *f; int bad; } tab[] = {{&fx_leaf, 0}, {&fx_leafexp, 1}, {&fx_leaffut, 1}};
    int k;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s) { CHECK(0); return; }
    for (k = 0; k < 3; k++) {
        c = ccp_ctx(tab[k].f); fl = CERT_STORE_TIME_VALIDITY_FLAG;
        if (!c) { CHECK(0); continue; }
        r = C32(CertGetIssuerCertificateFromStore)(s, c, NULL, &fl);
        CHECKF(r != NULL, "%s", tab[k].f->name);
        CHECKF(((fl & CERT_STORE_TIME_VALIDITY_FLAG) != 0) == tab[k].bad, "%s flags=0x%lx", tab[k].f->name, (unsigned long)fl);
        CHECKF((fl & ~CERT_STORE_TIME_VALIDITY_FLAG) == 0, "%s other bits 0x%lx", tab[k].f->name, (unsigned long)fl);
        ccp_free(r); ccp_free(c);
    }
    ccp_close(s);
}
TEST(ccp_get_issuer_revocation_flag_without_crl) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), r; DWORD fl = CERT_STORE_REVOCATION_FLAG;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r != NULL);
    EXPECT_EQ(fl, CERT_STORE_REVOCATION_FLAG | CERT_STORE_NO_CRL_FLAG);   /* no CRL available: both bits set */
    ccp_free(r); ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_all_flags_together) {
    HCERTSTORE s = bigstore(); PCCERT_CONTEXT l = ccp_ctx(&fx_leafi), r; DWORD fl = CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG | CERT_STORE_REVOCATION_FLAG;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r != NULL && which(r) == &fx_inter);
    /* signature and time pass (bits cleared); revocation cannot be checked without a CRL */
    EXPECT_EQ(fl, CERT_STORE_REVOCATION_FLAG | CERT_STORE_NO_CRL_FLAG);
    ccp_free(r); ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_iterates_with_prev_issuer) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf2), r1, r2, r3, a; DWORD fl = 0;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    a = ccp_add(s, &fx_root); ccp_free(a); a = ccp_add(s, &fx_root2); ccp_free(a);
    r1 = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r1 != NULL);
    r2 = r1 ? C32(CertGetIssuerCertificateFromStore)(s, l, r1, &fl) : NULL;     /* frees r1 */
    CHECK(r2 != NULL);
    r3 = r2 ? C32(CertGetIssuerCertificateFromStore)(s, l, r2, &fl) : NULL;
    CHECK(r3 == NULL);
    ccp_free(l); ccp_close(s);
}
TEST(ccp_get_issuer_no_issuer_flags_untouched_on_failure) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), r; DWORD fl = CERT_STORE_SIGNATURE_FLAG;
    REQUIRE(C32(CertGetIssuerCertificateFromStore));
    if (!s || !l) { CHECK(0); return; }
    SET_ERR(0);
    r = C32(CertGetIssuerCertificateFromStore)(s, l, NULL, &fl);
    CHECK(r == NULL);
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    ccp_free(l); ccp_close(s);
}

/* ---- CertIsRDNAttrsInCertificateName ---- */
static BOOL rdn_has(const FX *f, DWORD flags, const char *oid, DWORD vt, const void *val, DWORD cb) {
    CERT_RDN_ATTR a; CERT_RDN r; CERT_NAME_BLOB nb;
    memset(&a, 0, sizeof a); a.pszObjId = (LPSTR)oid; a.dwValueType = vt; a.Value.cbData = cb; a.Value.pbData = (BYTE *)val;
    r.cRDNAttr = 1; r.rgRDNAttr = &a;
    nb.cbData = f->cbSubj; nb.pbData = (BYTE *)f->subj;
    return C32(CertIsRDNAttrsInCertificateName)(ENC, flags, &nb, &r);
}
/* CERT_NAME_INFO values of UTF8/BMP name attributes are UTF-16 (value type stays CERT_RDN_UTF8_STRING), so the
 * attribute value to look for is UTF-16 with a byte count, or NUL terminated with cb 0 and the UNICODE flag. */
static BOOL rdn_hasw(const FX *f, DWORD flags, const char *oid, DWORD vt, const WCHAR *val, DWORD nch) { return rdn_has(f, flags, oid, vt, val, nch * 2); }
TEST(ccp_rdn_attrs_exact_utf8) {
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    CHECK(rdn_hasw(&fx_leaf, 0, szOID_COMMON_NAME, CERT_RDN_UTF8_STRING, L"leaf.cryptt.test", 16));
    CHECK(rdn_hasw(&fx_leaf, 0, szOID_COMMON_NAME, 0, L"leaf.cryptt.test", 16));                  /* ANY type */
    CHECK(rdn_hasw(&fx_leaf, 0, szOID_ORGANIZATION_NAME, CERT_RDN_UTF8_STRING, L"cryptt", 6));
    CHECK(rdn_has(&fx_leaf, 0, szOID_COUNTRY_NAME, 0, "US", 2));                                  /* PrintableString: 8-bit value */
    /* an 8-bit value never matches a UTF8 (UTF-16 decoded) attribute, and neither does the BMP/UNICODE value type */
    SET_ERR(0);
    EXPECT_FAIL(!rdn_has(&fx_leaf, 0, szOID_COMMON_NAME, CERT_RDN_UTF8_STRING, "leaf.cryptt.test", 16), CRYPT_E_NO_MATCH);
    SET_ERR(0);
    EXPECT_FAIL(!rdn_has(&fx_leaf, 0, szOID_COMMON_NAME, 0, "leaf.cryptt.test", 16), CRYPT_E_NO_MATCH);
    SET_ERR(0);
    EXPECT_FAIL(!rdn_hasw(&fx_leaf, 0, szOID_COMMON_NAME, CERT_RDN_BMP_STRING, L"leaf.cryptt.test", 16), CRYPT_E_NO_MATCH);
}
TEST(ccp_rdn_attrs_mismatch_sets_no_match) {
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    SET_ERR(0);
    EXPECT_FAIL(!rdn_hasw(&fx_leaf, 0, szOID_COMMON_NAME, 0, L"leaf.cryptt.tesT", 16), CRYPT_E_NO_MATCH);
    SET_ERR(0);
    EXPECT_FAIL(!rdn_hasw(&fx_leaf, 0, szOID_COMMON_NAME, 0, L"leaf.cryptt.tes", 15), CRYPT_E_NO_MATCH);        /* length must be equal */
    SET_ERR(0);
    EXPECT_FAIL(!rdn_hasw(&fx_leaf, 0, szOID_LOCALITY_NAME, 0, L"x", 1), CRYPT_E_NO_MATCH);                      /* attribute absent */
    SET_ERR(0);
    EXPECT_FAIL(!rdn_hasw(&fx_leaf, 0, szOID_COMMON_NAME, CERT_RDN_PRINTABLE_STRING, L"leaf.cryptt.test", 16), CRYPT_E_NO_MATCH); /* value type differs */
    SET_ERR(0);
    EXPECT_FAIL(!rdn_hasw(&fx_leaf, 0, szOID_ORGANIZATION_NAME, 0, L"leaf.cryptt.test", 16), CRYPT_E_NO_MATCH);  /* right value, wrong attribute */
}
TEST(ccp_rdn_attrs_case_insensitive_flag) {
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    SET_ERR(0);
    EXPECT_FAIL(!rdn_hasw(&fx_leaf, 0, szOID_COMMON_NAME, 0, L"LEAF.CRYPTT.TEST", 16), CRYPT_E_NO_MATCH);
    CHECK(rdn_hasw(&fx_leaf, CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG, szOID_COMMON_NAME, 0, L"LEAF.CRYPTT.TEST", 16));
    CHECK(rdn_hasw(&fx_leaf, CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG, szOID_COMMON_NAME, 0, L"Leaf.cryptt.test", 16));
    CHECK(rdn_hasw(&fx_leaf, CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG, szOID_ORGANIZATION_NAME, 0, L"CrYpTt", 6));
    CHECK(!rdn_hasw(&fx_leaf, CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG, szOID_ORGANIZATION_NAME, 0, L"CrYpTx", 6));
    /* case folding does not apply to an unterminated length of zero without the UNICODE flag */
    CHECK(!rdn_has(&fx_leaf, CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG, szOID_COMMON_NAME, 0, L"leaf.cryptt.test", 0));
}
TEST(ccp_rdn_attrs_unicode_flag) {
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    CHECK(rdn_has(&fx_leaf, CERT_UNICODE_IS_RDN_ATTRS_FLAG, szOID_COMMON_NAME, 0, L"leaf.cryptt.test", 32));
    CHECK(rdn_has(&fx_leaf, CERT_UNICODE_IS_RDN_ATTRS_FLAG, szOID_COMMON_NAME, 0, L"leaf.cryptt.test", 0));        /* NUL terminated when cb == 0 */
    CHECK(!rdn_has(&fx_leaf, CERT_UNICODE_IS_RDN_ATTRS_FLAG, szOID_COMMON_NAME, 0, L"Leaf.cryptt.test", 32));
    CHECK(rdn_has(&fx_leaf, CERT_UNICODE_IS_RDN_ATTRS_FLAG | CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG, szOID_COMMON_NAME, 0, L"Leaf.Cryptt.Test", 32));
    CHECK(rdn_has(&fx_utf8, CERT_UNICODE_IS_RDN_ATTRS_FLAG, szOID_COMMON_NAME, 0, L"Grüße cryptt", 0));
    /* without the UNICODE flag a zero byte count does not mean "NUL terminated" */
    SET_ERR(0);
    EXPECT_FAIL(!rdn_has(&fx_leaf, 0, szOID_COMMON_NAME, 0, L"leaf.cryptt.test", 0), CRYPT_E_NO_MATCH);
}
TEST(ccp_rdn_attrs_null_oid_matches_any_attribute) {
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    if (t_is_wine()) { t_skip("emulator dereferences a NULL attribute OID"); return; }
    CHECK(rdn_hasw(&fx_leaf, 0, NULL, 0, L"leaf.cryptt.test", 16));
    CHECK(rdn_hasw(&fx_leaf, 0, NULL, 0, L"cryptt", 6));
    SET_ERR(0);
    EXPECT_FAIL(!rdn_hasw(&fx_leaf, 0, NULL, 0, L"nothing", 7), CRYPT_E_NO_MATCH);
}
TEST(ccp_rdn_attrs_null_value_matches_presence) {
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    CHECK(rdn_has(&fx_leaf, 0, szOID_COMMON_NAME, 0, NULL, 0));
    CHECK(!rdn_has(&fx_leaf, 0, szOID_LOCALITY_NAME, 0, NULL, 0));
}
TEST(ccp_rdn_attrs_all_attrs_must_be_present) {
    CERT_RDN_ATTR a[2]; CERT_RDN r; CERT_NAME_BLOB nb;
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    memset(a, 0, sizeof a);
    a[0].pszObjId = (LPSTR)szOID_COMMON_NAME; a[0].Value.cbData = 32; a[0].Value.pbData = (BYTE *)L"leaf.cryptt.test";
    a[1].pszObjId = (LPSTR)szOID_COUNTRY_NAME; a[1].Value.cbData = 2; a[1].Value.pbData = (BYTE *)"US";
    r.cRDNAttr = 2; r.rgRDNAttr = a; nb.cbData = fx_leaf.cbSubj; nb.pbData = (BYTE *)fx_leaf.subj;
    CHECK(C32(CertIsRDNAttrsInCertificateName)(ENC, 0, &nb, &r));
    a[1].Value.pbData = (BYTE *)"DE";
    SET_ERR(0);
    EXPECT_FAIL(!C32(CertIsRDNAttrsInCertificateName)(ENC, 0, &nb, &r), CRYPT_E_NO_MATCH);
    r.cRDNAttr = 0;      /* nothing to look for */
    CHECK(C32(CertIsRDNAttrsInCertificateName)(ENC, 0, &nb, &r));
}
TEST(ccp_rdn_attrs_bad_name_blob) {
    CERT_RDN_ATTR a; CERT_RDN r; CERT_NAME_BLOB nb; BYTE junk[] = {0x30, 0x03, 0x01, 0x01, 0x00};
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    memset(&a, 0, sizeof a); a.pszObjId = (LPSTR)szOID_COMMON_NAME; r.cRDNAttr = 1; r.rgRDNAttr = &a;
    nb.cbData = sizeof junk; nb.pbData = junk;
    SET_ERR(0);
    CHECK(!C32(CertIsRDNAttrsInCertificateName)(ENC, 0, &nb, &r));
    EXPECT_ASN1_ERR();
    nb.cbData = 0; nb.pbData = NULL; SET_ERR(0);
    CHECK(!C32(CertIsRDNAttrsInCertificateName)(ENC, 0, &nb, &r));
    EXPECT_ERR(0x80093102);
}
TEST(ccp_rdn_attrs_issuer_and_subject_names) {
    CERT_RDN_ATTR a; CERT_RDN r; CERT_NAME_BLOB nb;
    REQUIRE(C32(CertIsRDNAttrsInCertificateName));
    memset(&a, 0, sizeof a); a.pszObjId = (LPSTR)szOID_COMMON_NAME; a.Value.cbData = 24; a.Value.pbData = (BYTE *)L"Test Root CA";
    r.cRDNAttr = 1; r.rgRDNAttr = &a;
    nb.cbData = fx_leaf.cbIss; nb.pbData = (BYTE *)fx_leaf.iss;
    CHECK(C32(CertIsRDNAttrsInCertificateName)(ENC, 0, &nb, &r));
    nb.cbData = fx_leaf.cbSubj; nb.pbData = (BYTE *)fx_leaf.subj;
    SET_ERR(0);
    EXPECT_FAIL(!C32(CertIsRDNAttrsInCertificateName)(ENC, 0, &nb, &r), CRYPT_E_NO_MATCH);
}

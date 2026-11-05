#include "sm.h"
/* Certificate add dispositions, enumeration, find, delete, properties and context ref-counting. */

static const WCHAR g_fn[] = L"CryptT Friendly";
static BOOL set_fn(PCCERT_CONTEXT c, const WCHAR *s) {
    CRYPT_DATA_BLOB b = { (DWORD)((lstrlenW(s) + 1) * 2), (BYTE *)s };
    return U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b);
}
static int has_fn(PCCERT_CONTEXT c) {
    DWORD cb = 0;
    return U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb) && cb > 0;
}

static PCCERT_CONTEXT first_a(HCERTSTORE h) {
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_a };
    return U(CertFindCertificateInStore)(h, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
}

/* ---------------- basic add ---------------- */
TEST(csc_add_new_returns_copy_in_store) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_NEW, &c));
    CHECK(c != NULL);
    if (c) {
        CHECK(sm_same_enc(c, VEC(v_cert_a)));
        CHECK(c->pbCertEncoded != v_cert_a);          /* the store keeps its own copy */
        CHECK(c->hCertStore == h);
        CHECK(c->pCertInfo != NULL && c->pCertInfo->SerialNumber.cbData == 2);
        sm_freec(c);
    }
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_add_new_null_out_ok) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_add_new_duplicate_fails_exists) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    BOOL r = sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    CHECK(!r); EXPECT_ERR(HR_EXISTS);
    CHECK(c == NULL);                                  /* out pointer is cleared on failure */
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_add_new_duplicate_null_out) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL)); EXPECT_ERR(HR_EXISTS);
    sm_close(h);
}
TEST(csc_add_distinct_certs_all_new) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    EXPECT_EQ(sm_ncerts(h), 3);
    sm_close(h);
}
TEST(csc_add_disposition_invalid) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    DWORD bad[] = { 0, 8, 9, 0x10, 0x100, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        PCCERT_CONTEXT c = (PCCERT_CONTEXT)(ULONG_PTR)1;
        SET_ERR(0);
        BOOL r = sm_addc(h, VEC(v_cert_a), bad[i], &c);
        CHECKF(!r, "disp 0x%lx", bad[i]);
        EXPECT_ERR(HR_INVALIDARG);
        CHECKF(c == NULL, "disp 0x%lx out cleared", bad[i]);
    }
    EXPECT_EQ(sm_ncerts(h), 0);
    sm_close(h);
}
TEST(csc_add_garbage_encoding_fails) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    static const BYTE junk[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(junk), DISP_NEW, &c));
    DWORD e = GetLastError();
    CHECKF((e & 0xFFFFFF00) == 0x80093100 || e == HR_INVALIDARG, "gle=0x%lx", e);
    CHECK(c == NULL);
    EXPECT_EQ(sm_ncerts(h), 0);
    sm_close(h);
}
TEST(csc_add_truncated_cert_fails) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    CHECK(!sm_addc(h, v_cert_a, sizeof v_cert_a - 5, DISP_NEW, NULL));
    DWORD e = GetLastError();
    CHECKF((e & 0xFFFFFF00) == 0x80093100, "gle=0x%lx", e);
    EXPECT_EQ(sm_ncerts(h), 0);
    sm_close(h);
}
TEST(csc_add_zero_length_fails) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    CHECK(!sm_addc(h, v_cert_a, 0, DISP_NEW, NULL));
    t_note("zero-length cert add gle=0x%lx", GetLastError());
    sm_close(h);
}
TEST(csc_add_crl_bytes_as_cert_fails) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(v_crl_1a), DISP_NEW, NULL));
    DWORD e = GetLastError();
    CHECKF((e & 0xFFFFFF00) == 0x80093100, "gle=0x%lx", e);
    EXPECT_EQ(sm_ncerts(h), 0);
    sm_close(h);
}
TEST(csc_add_cert_bytes_as_crl_fails) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    CHECK(!sm_addcrl(h, VEC(v_cert_a), DISP_NEW, NULL));
    DWORD e = GetLastError();
    CHECKF((e & 0xFFFFFF00) == 0x80093100, "gle=0x%lx", e);
    EXPECT_EQ(sm_ncrls(h), 0);
    sm_close(h);
}
TEST(csc_add_encoding_type_zero) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertAddEncodedCertificateToStore)(h, 0, VEC(v_cert_a), DISP_NEW, NULL);
    t_note("encoding type 0 -> %d gle=0x%lx", r, GetLastError());
    sm_close(h);
}
TEST(csc_add_encoding_with_pkcs7_bit) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    CHECK(U(CertAddEncodedCertificateToStore)(h, ENC, VEC(v_cert_a), DISP_NEW, &c));
    if (c) { t_note("ctx encoding type 0x%lx", c->dwCertEncodingType); sm_freec(c); }
    sm_close(h);
}
TEST(csc_add_context_copies_into_other_store) {
    REQUIRE(U(CertAddCertificateContextToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCERT_CONTEXT c = NULL, c2 = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &c);
    CHECK(U(CertAddCertificateContextToStore)(d, c, DISP_NEW, &c2));
    CHECK(c2 && c2 != c);
    CHECK(c2 && c2->hCertStore == d);
    CHECK(sm_same_enc(c2, VEC(v_cert_a)));
    EXPECT_EQ(sm_ncerts(s), 1); EXPECT_EQ(sm_ncerts(d), 1);
    sm_freec(c); sm_freec(c2); sm_close(s); sm_close(d);
}
TEST(csc_add_context_copies_properties) {
    REQUIRE(U(CertAddCertificateContextToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCERT_CONTEXT c = NULL, c2 = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &c);
    CHECK(set_fn(c, g_fn));
    CHECK(U(CertAddCertificateContextToStore)(d, c, DISP_NEW, &c2));
    CHECK(c2 && has_fn(c2));
    sm_freec(c); sm_freec(c2); sm_close(s); sm_close(d);
}
TEST(csc_add_context_from_create_context) {
    REQUIRE(U(CertAddCertificateContextToStore)); REQUIRE(U(CertCreateCertificateContext));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_b));
    CHECK(c != NULL); if (!c) { sm_close(h); return; }
    CHECK(c->hCertStore == NULL);
    PCCERT_CONTEXT out = NULL;
    CHECK(U(CertAddCertificateContextToStore)(h, c, DISP_NEW, &out));
    CHECK(out && out != c && out->hCertStore == h);
    sm_freec(out); sm_freec(c); sm_close(h);
}
TEST(csc_add_context_invalid_disposition) {
    REQUIRE(U(CertAddCertificateContextToStore)); REQUIRE(U(CertCreateCertificateContext));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_b));
    PCCERT_CONTEXT out = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!U(CertAddCertificateContextToStore)(h, c, 0, &out)); EXPECT_ERR(HR_INVALIDARG);
    CHECK(out == NULL);
    sm_freec(c); sm_close(h);
}

/* ---------------- USE_EXISTING ---------------- */
TEST(csc_use_existing_returns_existing) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT first = NULL, second = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &first);
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_USE, &second));
    CHECK(second != NULL);
    t_note("USE_EXISTING returned same pointer: %d", first == second);
    CHECK(sm_same_enc(second, VEC(v_cert_a)));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_freec(first); sm_freec(second); sm_close(h);
}
TEST(csc_use_existing_adds_when_missing) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_USE, &c));
    CHECK(c != NULL);
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_freec(c); sm_close(h);
}
TEST(csc_use_existing_null_out) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_USE, NULL));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_use_existing_merges_properties) {
    REQUIRE(U(CertAddCertificateContextToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCERT_CONTEXT cs = NULL, cd = NULL, r = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &cs);
    sm_addc(d, VEC(v_cert_a), DISP_NEW, &cd);
    set_fn(cs, g_fn);
    CHECK(!has_fn(cd));
    CHECK(U(CertAddCertificateContextToStore)(d, cs, DISP_USE, &r));
    CHECK(r && has_fn(r));                 /* properties of the new context are added to the existing one */
    EXPECT_EQ(sm_ncerts(d), 1);
    sm_freec(cs); sm_freec(cd); sm_freec(r); sm_close(s); sm_close(d);
}
TEST(csc_use_existing_different_encoding_same_issuer_serial) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    BOOL r = sm_addc(h, VEC(v_cert_a2), DISP_USE, &c);
    /* decomp: for certificates the match is by issuer+serial; a different encoding yields CERT_E_MALFORMED */
    CHECK(!r); EXPECT_ERR(HR_MALFORMED);
    CHECK(c == NULL);
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_new_matches_by_issuer_serial) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(v_cert_a2), DISP_NEW, NULL));   /* same issuer+serial, different bytes */
    EXPECT_ERR(HR_EXISTS);
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}

/* ---------------- REPLACE ---------------- */
TEST(csc_replace_existing_swaps_context) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    PCCERT_CONTEXT c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a2), DISP_REPL, &c));
    CHECK(sm_same_enc(c, VEC(v_cert_a2)));
    EXPECT_EQ(sm_ncerts(h), 1);
    PCCERT_CONTEXT e = U(CertEnumCertificatesInStore)(h, NULL);
    CHECK(sm_same_enc(e, VEC(v_cert_a2)));
    sm_freec(e); sm_freec(c); sm_close(h);
}
TEST(csc_replace_existing_adds_when_missing) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_REPL, NULL));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_replace_existing_drops_properties) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    set_fn(c, g_fn); sm_freec(c);
    CHECK(sm_addc(h, VEC(v_cert_a2), DISP_REPL, &c));
    CHECK(c && !has_fn(c));
    sm_freec(c); sm_close(h);
}
TEST(csc_replace_existing_old_context_stays_valid) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT old = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &old);
    sm_addc(h, VEC(v_cert_a2), DISP_REPL, NULL);
    CHECK(sm_same_enc(old, VEC(v_cert_a)));               /* our reference outlives the replacement */
    sm_freec(old); sm_close(h);
}
TEST(csc_replace_inherit_keeps_properties) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    set_fn(c, g_fn); sm_freec(c); c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a2), DISP_REPL_INH, &c));
    CHECK(sm_same_enc(c, VEC(v_cert_a2)));
    CHECK(c && has_fn(c));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_freec(c); sm_close(h);
}
TEST(csc_replace_inherit_identical_cert_keeps_existing) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    set_fn(c, g_fn); sm_freec(c); c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_REPL_INH, &c));
    CHECK(c && has_fn(c));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_freec(c); sm_close(h);
}
TEST(csc_replace_inherit_adds_when_missing) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    CHECK(sm_addc(h, VEC(v_cert_b), DISP_REPL_INH, NULL));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}

/* ---------------- ALWAYS ---------------- */
TEST(csc_always_creates_duplicates) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    for (int i = 0; i < 4; i++) CHECK(sm_addc(h, VEC(v_cert_a), DISP_ALWAYS, NULL));
    EXPECT_EQ(sm_ncerts(h), 4);
    sm_close(h);
}
TEST(csc_always_distinct_contexts) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT a = NULL, b = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_ALWAYS, &a);
    sm_addc(h, VEC(v_cert_a), DISP_ALWAYS, &b);
    CHECK(a && b && a != b);
    sm_freec(a); sm_freec(b); sm_close(h);
}
TEST(csc_always_then_new_fails) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_ALWAYS, NULL);
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL)); EXPECT_ERR(HR_EXISTS);
    sm_close(h);
}

/* ---------------- NEWER ---------------- */
TEST(csc_newer_replaces_older_notbefore) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);               /* NotBefore 2020 */
    PCCERT_CONTEXT c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a2), DISP_NEWER, &c));       /* NotBefore 2021 */
    CHECK(sm_same_enc(c, VEC(v_cert_a2)));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_freec(c); sm_close(h);
}
TEST(csc_newer_older_candidate_rejected) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a2), DISP_NEW, NULL);
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(v_cert_a), DISP_NEWER, &c)); EXPECT_ERR(HR_EXISTS);
    CHECK(c == NULL);
    PCCERT_CONTEXT e = U(CertEnumCertificatesInStore)(h, NULL);
    CHECK(sm_same_enc(e, VEC(v_cert_a2)));
    sm_freec(e); sm_close(h);
}
TEST(csc_newer_equal_notbefore_rejected) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(v_cert_a), DISP_NEWER, NULL)); EXPECT_ERR(HR_EXISTS);
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_newer_adds_when_missing) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_NEWER, NULL));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_newer_does_not_inherit) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c); set_fn(c, g_fn); sm_freec(c); c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a2), DISP_NEWER, &c));
    CHECK(c && !has_fn(c));
    sm_freec(c); sm_close(h);
}
TEST(csc_newer_inherit_inherits) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c); set_fn(c, g_fn); sm_freec(c); c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a2), DISP_NEWER_INH, &c));
    CHECK(sm_same_enc(c, VEC(v_cert_a2)));
    CHECK(c && has_fn(c));
    sm_freec(c); sm_close(h);
}
TEST(csc_newer_inherit_older_rejected) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a2), DISP_NEW, NULL);
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(v_cert_a), DISP_NEWER_INH, NULL)); EXPECT_ERR(HR_EXISTS);
    sm_close(h);
}
TEST(csc_newer_inherit_equal_rejected) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    SET_ERR(0);
    CHECK(!sm_addc(h, VEC(v_cert_a), DISP_NEWER_INH, NULL)); EXPECT_ERR(HR_EXISTS);
    sm_close(h);
}

/* ---------------- enumeration ---------------- */
TEST(csc_enum_returns_newest_first) {
    REQUIRE(U(CertEnumCertificatesInStore));
    /* decomp: new elements become the list head and enumeration starts at the head */
    HCERTSTORE h = sm_abc(); if (!h) return;
    const BYTE *exp[3] = { v_cert_c, v_cert_b, v_cert_a };
    DWORD n[3] = { sizeof v_cert_c, sizeof v_cert_b, sizeof v_cert_a };
    PCCERT_CONTEXT c = NULL; int i = 0;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL && i < 3) { CHECKF(sm_same_enc(c, exp[i], n[i]), "idx %d", i); i++; }
    EXPECT_EQ(i, 3);
    sm_close(h);
}
TEST(csc_enum_end_sets_not_found) {
    REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL) {}
    EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csc_enum_null_store) {
    REQUIRE(U(CertEnumCertificatesInStore));
    SET_ERR(0);
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(NULL, NULL);
    t_note("enum NULL store -> %p gle=0x%lx", c, GetLastError());
}
TEST(csc_enum_prev_is_released_by_call) {
    REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT a = U(CertEnumCertificatesInStore)(h, NULL);
    PCCERT_CONTEXT keep = U(CertDuplicateCertificateContext)(a);
    PCCERT_CONTEXT b = U(CertEnumCertificatesInStore)(h, a);   /* consumes one ref of a */
    CHECK(b != NULL && b != keep);
    CHECK(sm_same_enc(keep, VEC(v_cert_c)));                   /* the duplicate is still valid */
    sm_freec(keep); sm_freec(b); sm_close(h);
}
TEST(csc_enum_returns_same_element_each_time) {
    REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT a1 = U(CertEnumCertificatesInStore)(h, NULL);
    PCCERT_CONTEXT a2 = U(CertEnumCertificatesInStore)(h, NULL);
    CHECK(a1 == a2);                                           /* memory store contexts are shared elements */
    sm_freec(a1); sm_freec(a2); sm_close(h);
}
TEST(csc_enum_delete_every_element_while_enumerating) {
    REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = NULL; int seen = 0;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL) {
        seen++;
        CHECK(U(CertDeleteCertificateFromStore)(U(CertDuplicateCertificateContext)(c)));
    }
    EXPECT_EQ(seen, 3);
    EXPECT_EQ(sm_ncerts(h), 0);
    sm_close(h);
}
TEST(csc_enum_delete_middle_only) {
    REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = NULL; int seen = 0;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL) {
        seen++;
        if (seen > 10) { sm_freec(c); break; }       /* bounded: an emulator may loop here */
        if (sm_same_enc(c, VEC(v_cert_b))) CHECK(U(CertDeleteCertificateFromStore)(U(CertDuplicateCertificateContext)(c)));
    }
    t_note("contexts visited while deleting the middle one: %d", seen);
    EXPECT_EQ(sm_ncerts(h), 2);
    sm_close(h);
}
TEST(csc_enum_delete_current_by_consuming_ref) {
    REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    CHECK(U(CertDeleteCertificateFromStore)(c));              /* consumes the enumeration reference */
    EXPECT_EQ(sm_ncerts(h), 2);
    PCCERT_CONTEXT f = U(CertEnumCertificatesInStore)(h, NULL);
    CHECK(sm_same_enc(f, VEC(v_cert_b)));       /* C (the first) was deleted */
    sm_freec(f); sm_close(h);
}
TEST(csc_enum_add_during_enumeration_visible) {
    REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    PCCERT_CONTEXT c = NULL; int seen = 0;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL) {
        seen++;
        if (seen == 1) sm_addc(h, VEC(v_cert_b), DISP_NEW, NULL);
        if (seen > 5) { sm_freec(c); break; }
    }
    t_note("certs visited when adding mid-enumeration: %d", seen);
    EXPECT_EQ(sm_ncerts(h), 2);
    sm_close(h);
}

/* ---------------- delete ---------------- */
TEST(csc_delete_removes_and_keeps_context_readable) {
    REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL, keep;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    keep = U(CertDuplicateCertificateContext)(c);
    CHECK(U(CertDeleteCertificateFromStore)(c));
    EXPECT_EQ(sm_ncerts(h), 0);
    CHECK(sm_same_enc(keep, VEC(v_cert_a)));
    sm_freec(keep); sm_close(h);
}
TEST(csc_delete_then_readd_new_succeeds) {
    REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    U(CertDeleteCertificateFromStore)(c);
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL));
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}
TEST(csc_delete_second_time) {
    REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL, d;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    d = U(CertDuplicateCertificateContext)(c);
    CHECK(U(CertDeleteCertificateFromStore)(c));
    SET_ERR(0);
    BOOL r = U(CertDeleteCertificateFromStore)(d);
    t_note("second delete of same context -> %d gle=0x%lx", r, GetLastError());
    sm_close(h);
}
TEST(csc_delete_context_without_store) {
    REQUIRE(U(CertDeleteCertificateFromStore)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a));
    CHECK(c != NULL); if (!c) return;
    SET_ERR(0);
    BOOL r = U(CertDeleteCertificateFromStore)(c);
    t_note("delete of context with no store -> %d gle=0x%lx", r, GetLastError());
}
TEST(csc_delete_one_of_duplicates) {
    REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT a = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_ALWAYS, &a);
    sm_addc(h, VEC(v_cert_a), DISP_ALWAYS, NULL);
    U(CertDeleteCertificateFromStore)(a);
    EXPECT_EQ(sm_ncerts(h), 1);
    sm_close(h);
}

/* ---------------- ref counting ---------------- */
TEST(csc_duplicate_returns_same_pointer) {
    REQUIRE(U(CertDuplicateCertificateContext));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    PCCERT_CONTEXT d = U(CertDuplicateCertificateContext)(c);
    CHECK(d == c);
    CHECK(U(CertFreeCertificateContext)(d));
    CHECK(sm_same_enc(c, VEC(v_cert_a)));
    CHECK(U(CertFreeCertificateContext)(c));
    sm_close(h);
}
TEST(csc_duplicate_null) {
    REQUIRE(U(CertDuplicateCertificateContext));
    SET_ERR(0);
    PCCERT_CONTEXT d = U(CertDuplicateCertificateContext)(NULL);
    CHECK(d == NULL);
}
TEST(csc_free_null_returns_true) {
    REQUIRE(U(CertFreeCertificateContext));
    CHECK(U(CertFreeCertificateContext)(NULL));
}
TEST(csc_context_survives_store_close_with_refs) {
    REQUIRE(U(CertDuplicateCertificateContext));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    for (int i = 0; i < 10; i++) U(CertDuplicateCertificateContext)(c);
    sm_close(h);
    CHECK(sm_same_enc(c, VEC(v_cert_c)));
    for (int i = 0; i < 11; i++) CHECK(U(CertFreeCertificateContext)(c));
}
TEST(csc_create_context_no_store) {
    REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_c));
    CHECK(c != NULL);
    if (c) {
        t_note("hCertStore of a storeless context: %p", c->hCertStore);
        CHECK(sm_same_enc(c, VEC(v_cert_c)));
        CHECK(c->pbCertEncoded != v_cert_c);
        U(CertFreeCertificateContext)(c);
    }
}

/* ---------------- find ---------------- */
static PCCERT_CONTEXT fnd(HCERTSTORE h, DWORD flags, DWORD type, const void *para, PCCERT_CONTEXT prev) {
    return U(CertFindCertificateInStore)(h, X509_ASN_ENCODING, flags, type, para, prev);
}
TEST(csc_find_any_iterates) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = NULL; int n = 0;
    while ((c = fnd(h, 0, CERT_FIND_ANY, NULL, c)) != NULL) n++;
    EXPECT_EQ(n, 3); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csc_find_sha1_hash) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_HASH_BLOB hb = { sizeof v_sha1_b, (BYTE *)v_sha1_b };
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_b)));
    PCCERT_CONTEXT n = fnd(h, 0, CERT_FIND_SHA1_HASH, &hb, c);
    CHECK(n == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csc_find_hash_alias_equals_sha1) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_HASH_BLOB hb = { sizeof v_sha1_c, (BYTE *)v_sha1_c };
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_HASH, &hb, NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_c)));
    sm_freec(c); sm_close(h);
}
TEST(csc_find_md5_hash) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_HASH_BLOB hb = { sizeof v_md5_a, (BYTE *)v_md5_a };
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_MD5_HASH, &hb, NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_a)));
    sm_freec(c); sm_close(h);
}
TEST(csc_find_hash_not_found) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    BYTE z[20] = { 0 };
    CRYPT_HASH_BLOB hb = { 20, z };
    SET_ERR(0);
    CHECK(fnd(h, 0, CERT_FIND_SHA1_HASH, &hb, NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    hb.cbData = 5;
    SET_ERR(0);
    CHECK(fnd(h, 0, CERT_FIND_SHA1_HASH, &hb, NULL) == NULL);
    sm_close(h);
}
TEST(csc_find_subject_str_w) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_SUBJECT_STR_W, L"CryptT Cert B", NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_b)));
    sm_freec(c);
    c = fnd(h, 0, CERT_FIND_SUBJECT_STR_W, L"cert b", NULL);      /* case-insensitive substring */
    CHECK(sm_same_enc(c, VEC(v_cert_b)));
    sm_freec(c); sm_close(h);
}
TEST(csc_find_subject_str_a) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_SUBJECT_STR_A, "Cert C", NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_c)));
    sm_freec(c); sm_close(h);
}
TEST(csc_find_subject_str_multiple_matches) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = NULL; int n = 0;
    while ((c = fnd(h, 0, CERT_FIND_SUBJECT_STR_W, L"CryptT Cert", c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    sm_close(h);
}
TEST(csc_find_subject_str_none) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    SET_ERR(0);
    CHECK(fnd(h, 0, CERT_FIND_SUBJECT_STR_W, L"Nonexistent Subject", NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csc_find_issuer_str) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = NULL; int n = 0;
    while ((c = fnd(h, 0, CERT_FIND_ISSUER_STR_W, L"Store CA", c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    sm_close(h);
}
TEST(csc_find_subject_name_blob) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CERT_NAME_BLOB nb = { sizeof v_name_b, (BYTE *)v_name_b };
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_SUBJECT_NAME, &nb, NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_b)));
    sm_freec(c); sm_close(h);
}
TEST(csc_find_issuer_name_blob) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CERT_NAME_BLOB nb = { sizeof v_name_ca, (BYTE *)v_name_ca };
    PCCERT_CONTEXT c = NULL; int n = 0;
    while ((c = fnd(h, 0, CERT_FIND_ISSUER_NAME, &nb, c)) != NULL) n++;
    EXPECT_EQ(n, 3);
    sm_close(h);
}
TEST(csc_find_existing_uses_issuer_serial) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT probe = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a2));
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_EXISTING, probe, NULL);
    t_note("CERT_FIND_EXISTING for same issuer+serial different bytes: %s", c ? "found" : "not found");
    sm_freec(c);
    sm_freec(probe); sm_close(h);
}
TEST(csc_find_existing_identical) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT probe = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_c));
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_EXISTING, probe, NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_c)));
    sm_freec(c); sm_freec(probe); sm_close(h);
}
TEST(csc_find_subject_cert_issuer_serial) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT src = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a));
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    ci.Issuer = src->pCertInfo->Issuer; ci.SerialNumber = src->pCertInfo->SerialNumber;
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_SUBJECT_CERT, &ci, NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_a)));
    sm_freec(c); sm_freec(src); sm_close(h);
}
TEST(csc_find_public_key) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT src = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_c));
    PCCERT_CONTEXT c = fnd(h, 0, CERT_FIND_PUBLIC_KEY, &src->pCertInfo->SubjectPublicKeyInfo, NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_c)));
    sm_freec(c); sm_freec(src); sm_close(h);
}
TEST(csc_find_property) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT b = fnd(h, 0, CERT_FIND_SUBJECT_STR_W, L"Cert B", NULL);
    set_fn(b, g_fn); sm_freec(b);
    DWORD id = CERT_FRIENDLY_NAME_PROP_ID;
    PCCERT_CONTEXT c = U(CertFindCertificateInStore)(h, 0, 0, CERT_FIND_PROPERTY, &id, NULL);
    CHECK(sm_same_enc(c, VEC(v_cert_b)));
    PCCERT_CONTEXT n = U(CertFindCertificateInStore)(h, 0, 0, CERT_FIND_PROPERTY, &id, c);
    CHECK(n == NULL);
    sm_close(h);
}
TEST(csc_find_issuer_of_requires_issuer_in_store) {
    REQUIRE(U(CertFindCertificateInStore)); REQUIRE(U(CertGetIssuerCertificateFromStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT sub = fnd(h, 0, CERT_FIND_SUBJECT_STR_W, L"Cert A", NULL);
    SET_ERR(0);
    PCCERT_CONTEXT iss = fnd(h, 0, CERT_FIND_ISSUER_OF, sub, NULL);
    CHECK(iss == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_addc(h, VEC(v_cert_ca), DISP_NEW, NULL);
    iss = fnd(h, 0, CERT_FIND_ISSUER_OF, sub, NULL);
    CHECK(sm_same_enc(iss, VEC(v_cert_ca)));
    DWORD fl = 0;
    PCCERT_CONTEXT i2 = U(CertGetIssuerCertificateFromStore)(h, sub, NULL, &fl);
    CHECK(sm_same_enc(i2, VEC(v_cert_ca)));
    sm_freec(i2); sm_freec(iss); sm_freec(sub); sm_close(h);
}
TEST(csc_find_in_empty_store) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    CHECK(fnd(h, 0, CERT_FIND_ANY, NULL, NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csc_find_unknown_type) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    SET_ERR(0);
    PCCERT_CONTEXT c = U(CertFindCertificateInStore)(h, X509_ASN_ENCODING, 0, 0x7F0000, NULL, NULL);
    CHECK(c == NULL);
    t_note("unknown find type gle=0x%lx", GetLastError());
    sm_close(h);
}
TEST(csc_find_prev_from_deleted_context_continues) {
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT a = fnd(h, 0, CERT_FIND_ANY, NULL, NULL);
    PCCERT_CONTEXT b = fnd(h, 0, CERT_FIND_ANY, NULL, a);
    CHECK(sm_same_enc(b, VEC(v_cert_b)));
    sm_freec(b); sm_close(h);
}

/* ---------------- properties ---------------- */
TEST(csc_prop_hash_is_sha1) {
    REQUIRE(U(CertGetCertificateContextProperty));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = first_a(h);
    BYTE buf[32]; DWORD cb = sizeof buf;
    CHECK(U(CertGetCertificateContextProperty)(c, CERT_HASH_PROP_ID, buf, &cb));
    EXPECT_EQ(cb, 20); CHECK(cb == 20 && !memcmp(buf, v_sha1_a, 20));
    cb = sizeof buf;
    CHECK(U(CertGetCertificateContextProperty)(c, CERT_MD5_HASH_PROP_ID, buf, &cb));
    EXPECT_EQ(cb, 16); CHECK(cb == 16 && !memcmp(buf, v_md5_a, 16));
    sm_freec(c); sm_close(h);
}
TEST(csc_prop_buffer_protocol) {
    REQUIRE(U(CertGetCertificateContextProperty));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = first_a(h);
    DWORD cb = 0;
    CHECK(U(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, NULL, &cb)); EXPECT_EQ(cb, 20);
    BYTE buf[20]; cb = 19;
    SET_ERR(0);
    CHECK(!U(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, buf, &cb));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, 20);
    cb = 0;
    SET_ERR(0);
    CHECK(!U(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, buf, &cb));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, 20);
    cb = 20;
    CHECK(U(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, buf, &cb)); EXPECT_EQ(cb, 20);
    CHECK(!memcmp(buf, v_sha1_a, 20));
    sm_freec(c); sm_close(h);
}
TEST(csc_prop_unset_not_found) {
    REQUIRE(U(CertGetCertificateContextProperty));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    DWORD cb = 0;
    SET_ERR(0);
    CHECK(!U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_ERR(HR_NOT_FOUND);
    SET_ERR(0);
    CHECK(!U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb)); EXPECT_ERR(HR_NOT_FOUND);
    sm_freec(c); sm_close(h);
}
TEST(csc_prop_friendly_name_roundtrip) {
    REQUIRE(U(CertSetCertificateContextProperty));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    CHECK(set_fn(c, g_fn));
    WCHAR buf[64]; DWORD cb = sizeof buf;
    CHECK(U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, buf, &cb));
    EXPECT_EQ(cb, sizeof g_fn); EXPECT_WSTR(buf, g_fn);
    sm_freec(c); sm_close(h);
}
TEST(csc_prop_visible_through_other_handle) {
    REQUIRE(U(CertSetCertificateContextProperty));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c1 = first_a(h);
    set_fn(c1, g_fn);
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_a };
    PCCERT_CONTEXT c2 = fnd(h, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
    CHECK(c2 && has_fn(c2));
    sm_freec(c1); sm_freec(c2); sm_close(h);
}
TEST(csc_prop_delete_with_null) {
    REQUIRE(U(CertSetCertificateContextProperty));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    set_fn(c, g_fn); CHECK(has_fn(c));
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, NULL));
    CHECK(!has_fn(c));
    sm_freec(c); sm_close(h);
}
TEST(csc_prop_enumerate) {
    REQUIRE(U(CertEnumCertificateContextProperties));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    set_fn(c, g_fn);
    DWORD id = 0; int seen_fn = 0, n = 0;
    while ((id = U(CertEnumCertificateContextProperties)(c, id)) != 0 && n < 50) { n++; if (id == CERT_FRIENDLY_NAME_PROP_ID) seen_fn = 1; }
    CHECK(seen_fn);
    sm_freec(c); sm_close(h);
}
TEST(csc_prop_set_on_link_visible_on_original) {
    REQUIRE(U(CertAddCertificateLinkToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCERT_CONTEXT orig = NULL, link = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &orig);
    CHECK(U(CertAddCertificateLinkToStore)(d, orig, DISP_NEW, &link));
    EXPECT_EQ(sm_ncerts(d), 1);
    if (link) { set_fn(link, g_fn); t_note("friendly name set on link visible on original: %d", has_fn(orig)); CHECK(sm_same_enc(link, VEC(v_cert_a))); }
    sm_freec(orig); sm_freec(link); sm_close(s); sm_close(d);
}
TEST(csc_link_survives_original_delete) {
    REQUIRE(U(CertAddCertificateLinkToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCERT_CONTEXT orig = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &orig);
    CHECK(U(CertAddCertificateLinkToStore)(d, orig, DISP_NEW, NULL));
    U(CertDeleteCertificateFromStore)(orig);
    EXPECT_EQ(sm_ncerts(s), 0);
    EXPECT_EQ(sm_ncerts(d), 1);
    PCCERT_CONTEXT l = U(CertEnumCertificatesInStore)(d, NULL);
    CHECK(sm_same_enc(l, VEC(v_cert_a)));
    sm_freec(l); sm_close(s); sm_close(d);
}
TEST(csc_link_duplicate_new_fails) {
    REQUIRE(U(CertAddCertificateLinkToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCERT_CONTEXT orig = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &orig);
    CHECK(U(CertAddCertificateLinkToStore)(d, orig, DISP_NEW, NULL));
    SET_ERR(0);
    CHECK(!U(CertAddCertificateLinkToStore)(d, orig, DISP_NEW, NULL)); EXPECT_ERR(HR_EXISTS);
    sm_freec(orig); sm_close(s); sm_close(d);
}
TEST(csc_link_invalid_disposition) {
    REQUIRE(U(CertAddCertificateLinkToStore));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCERT_CONTEXT orig = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &orig);
    PCCERT_CONTEXT o = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!U(CertAddCertificateLinkToStore)(d, orig, 0, &o)); EXPECT_ERR(HR_INVALIDARG);
    sm_freec(orig); sm_close(s); sm_close(d);
}
TEST(csc_cert_info_fields) {
    REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT c = first_a(h);
    CHECK(c->pCertInfo->dwVersion == CERT_V3);
    CHECK(c->pCertInfo->SerialNumber.cbData == 2 && c->pCertInfo->SerialNumber.pbData[0] == 0x01 && c->pCertInfo->SerialNumber.pbData[1] == 0x10);
    CHECK(c->pCertInfo->Issuer.cbData == sizeof v_name_ca && !memcmp(c->pCertInfo->Issuer.pbData, v_name_ca, sizeof v_name_ca));
    CHECK(c->pCertInfo->Subject.cbData == sizeof v_name_a && !memcmp(c->pCertInfo->Subject.pbData, v_name_a, sizeof v_name_a));
    sm_freec(c); sm_close(h);
}

static BOOL archive(PCCERT_CONTEXT a) {
    static BYTE dummy[1]; CRYPT_DATA_BLOB b = { 0, dummy };
    return U(CertSetCertificateContextProperty)(a, CERT_ARCHIVED_PROP_ID, 0, &b);
}
/* ---------------- archived ---------------- */
TEST(csc_archived_cert_hidden_from_enum) {
    REQUIRE(U(CertSetCertificateContextProperty));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT a = first_a(h);
        if (!archive(a)) { if (t_is_wine()) { t_skip("emulator cannot archive"); return; } CHECK(0); }
    sm_freec(a);
    EXPECT_EQ(sm_ncerts(h), 2);
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_a };
    SET_ERR(0);
    CHECK(U(CertFindCertificateInStore)(h, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &hb, NULL) == NULL);
    EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csc_archived_cert_visible_with_enum_archived_flag) {
    REQUIRE(U(CertSetCertificateContextProperty));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_ENUM_ARCHIVED_FLAG, NULL);
    if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL); sm_addc(h, VEC(v_cert_b), DISP_NEW, NULL);
    PCCERT_CONTEXT a = first_a(h);
        if (!archive(a) && t_is_wine()) { t_skip("emulator cannot archive"); return; }
    sm_freec(a);
    EXPECT_EQ(sm_ncerts(h), 2);
    sm_close(h);
}
TEST(csc_archived_cert_unarchive_with_null_property) {
    REQUIRE(U(CertSetCertificateContextProperty));
    HCERTSTORE h = sm_abc(); if (!h) return;
    PCCERT_CONTEXT a = first_a(h);
        if (!archive(a) && t_is_wine()) { t_skip("emulator cannot archive"); return; }
    EXPECT_EQ(sm_ncerts(h), 2);
    CHECK(U(CertSetCertificateContextProperty)(a, CERT_ARCHIVED_PROP_ID, 0, NULL));
    EXPECT_EQ(sm_ncerts(h), 3);
    sm_freec(a); sm_close(h);
}
TEST(csc_enum_prev_from_other_store) {
    REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE h1 = sm_abc(), h2 = sm_abc(); if (!h1 || !h2) return;
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h1, NULL);
    SET_ERR(0);
    PCCERT_CONTEXT n = U(CertEnumCertificatesInStore)(h2, c);
    if (t_is_wine()) t_note("emulator accepts a foreign prev context");
    else { CHECK(n == NULL); EXPECT_ERR(HR_INVALIDARG); }
    sm_freec(n);
    sm_close(h1); sm_close(h2);
}

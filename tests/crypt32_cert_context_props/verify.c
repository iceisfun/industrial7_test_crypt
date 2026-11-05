/* Time validity, validity nesting, signature verification and certificate hashing. */
#include "ccp.h"

static FILETIME ft_of(const int *a) {
    SYSTEMTIME st; FILETIME ft;
    memset(&st, 0, sizeof st);
    st.wYear = a[0]; st.wMonth = a[1]; st.wDay = a[2]; st.wHour = a[3]; st.wMinute = a[4]; st.wSecond = a[5];
    SystemTimeToFileTime(&st, &ft); return ft;
}
static FILETIME ft_add(FILETIME f, long long ticks) {
    ULARGE_INTEGER u; u.LowPart = f.dwLowDateTime; u.HighPart = f.dwHighDateTime; u.QuadPart += ticks;
    f.dwLowDateTime = u.LowPart; f.dwHighDateTime = u.HighPart; return f;
}

/* ---- CertVerifyTimeValidity ---- */
TEST(ccp_time_validity_boundaries_every_fixture) {
    int i; REQUIRE(C32(CertVerifyTimeValidity));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); FILETIME nb, na, t;
        if (!c) { CHECK(0); continue; }
        nb = ft_of(f->nb); na = ft_of(f->na);
        t = ft_add(nb, -1);     CHECKF(C32(CertVerifyTimeValidity)(&t, c->pCertInfo) == -1, "%s nb-1", f->name);
        t = nb;                 CHECKF(C32(CertVerifyTimeValidity)(&t, c->pCertInfo) == 0, "%s nb", f->name);
        t = ft_add(nb, 10000000); CHECKF(C32(CertVerifyTimeValidity)(&t, c->pCertInfo) == 0, "%s nb+1s", f->name);
        t = na;                 CHECKF(C32(CertVerifyTimeValidity)(&t, c->pCertInfo) == 0, "%s na", f->name);
        t = ft_add(na, 1);      CHECKF(C32(CertVerifyTimeValidity)(&t, c->pCertInfo) == 1, "%s na+1", f->name);
        t = ft_add(na, 10000000); CHECKF(C32(CertVerifyTimeValidity)(&t, c->pCertInfo) == 1, "%s na+1s", f->name);
        ccp_free(c);
    }
}
TEST(ccp_time_validity_return_values_are_exact) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); FILETIME t;
    REQUIRE(C32(CertVerifyTimeValidity));
    if (!c) { CHECK(0); return; }
    t = ft_ymd(1990, 1, 1); EXPECT_EQ((DWORD)C32(CertVerifyTimeValidity)(&t, c->pCertInfo), 0xFFFFFFFF);
    t = ft_ymd(2030, 6, 1); EXPECT_EQ(C32(CertVerifyTimeValidity)(&t, c->pCertInfo), 0);
    t = ft_ymd(2100, 1, 1); EXPECT_EQ(C32(CertVerifyTimeValidity)(&t, c->pCertInfo), 1);
    ccp_free(c);
}
TEST(ccp_time_validity_null_time_uses_now) {
    PCCERT_CONTEXT e = ccp_ctx(&fx_expired), f = ccp_ctx(&fx_future);
    REQUIRE(C32(CertVerifyTimeValidity));
    if (!e || !f) { CHECK(0); return; }
    EXPECT_EQ(C32(CertVerifyTimeValidity)(NULL, e->pCertInfo), 1);
    EXPECT_EQ((DWORD)C32(CertVerifyTimeValidity)(NULL, f->pCertInfo), 0xFFFFFFFF);
    ccp_free(e); ccp_free(f);
}
TEST(ccp_time_validity_current_time_matches_explicit_now) {
    PCCERT_CONTEXT l = ccp_ctx(&fx_leaf); SYSTEMTIME st; FILETIME now;
    REQUIRE(C32(CertVerifyTimeValidity));
    if (!l) { CHECK(0); return; }
    GetSystemTime(&st); SystemTimeToFileTime(&st, &now);
    EXPECT_EQ(C32(CertVerifyTimeValidity)(NULL, l->pCertInfo), C32(CertVerifyTimeValidity)(&now, l->pCertInfo));
    ccp_free(l);
}
TEST(ccp_time_validity_only_uses_validity_fields) {
    PCCERT_CONTEXT l = ccp_ctx(&fx_leaf); CERT_INFO ci; FILETIME t = ft_ymd(2030, 1, 1);
    REQUIRE(C32(CertVerifyTimeValidity));
    if (!l) { CHECK(0); return; }
    memset(&ci, 0, sizeof ci);
    ci.NotBefore = l->pCertInfo->NotBefore; ci.NotAfter = l->pCertInfo->NotAfter;
    EXPECT_EQ(C32(CertVerifyTimeValidity)(&t, &ci), 0);
    ci.NotBefore = ft_ymd(2031, 1, 1); ci.NotAfter = ft_ymd(2032, 1, 1);
    EXPECT_EQ((DWORD)C32(CertVerifyTimeValidity)(&t, &ci), 0xFFFFFFFF);
    ccp_free(l);
}

/* ---- CertVerifyValidityNesting ---- */
TEST(ccp_nesting_table) {
    struct { const FX *sub, *iss; int nested; } t[] = {
        {&fx_leaf, &fx_root, 1}, {&fx_inter, &fx_root, 1}, {&fx_leafi, &fx_inter, 1}, {&fx_root, &fx_root, 1}, {&fx_leaf, &fx_leaf, 1},
        {&fx_nestbad, &fx_root, 0}, {&fx_nestbad2, &fx_root, 0}, {&fx_root, &fx_leaf, 0}, {&fx_root, &fx_inter, 0}, {&fx_leafexp, &fx_root, 0},
        {&fx_leaffut, &fx_root, 1}, {&fx_leafi, &fx_root, 1}, {&fx_inter, &fx_leaf, 0},
    };
    int i; REQUIRE(C32(CertVerifyValidityNesting));
    for (i = 0; i < (int)(sizeof t / sizeof t[0]); i++) {
        PCCERT_CONTEXT a = ccp_ctx(t[i].sub), b = ccp_ctx(t[i].iss);
        if (!a || !b) { CHECK(0); continue; }
        /* TRUE when the subject period lies within the issuer period */
        CHECKF((C32(CertVerifyValidityNesting)(a->pCertInfo, b->pCertInfo) != 0) == t[i].nested, "%s in %s", t[i].sub->name, t[i].iss->name);
        ccp_free(a); ccp_free(b);
    }
}
TEST(ccp_nesting_returns_exactly_one_or_zero) {
    PCCERT_CONTEXT a = ccp_ctx(&fx_leaf), b = ccp_ctx(&fx_root);
    REQUIRE(C32(CertVerifyValidityNesting));
    if (!a || !b) { CHECK(0); return; }
    EXPECT_EQ(C32(CertVerifyValidityNesting)(a->pCertInfo, b->pCertInfo), 1);
    EXPECT_EQ(C32(CertVerifyValidityNesting)(b->pCertInfo, a->pCertInfo), 0);
    ccp_free(a); ccp_free(b);
}
TEST(ccp_nesting_boundaries_inclusive) {
    CERT_INFO s, i;
    REQUIRE(C32(CertVerifyValidityNesting));
    memset(&s, 0, sizeof s); memset(&i, 0, sizeof i);
    i.NotBefore = ft_ymd(2020, 1, 1); i.NotAfter = ft_ymd(2030, 1, 1);
    s.NotBefore = i.NotBefore; s.NotAfter = i.NotAfter;
    CHECK(C32(CertVerifyValidityNesting)(&s, &i));                            /* identical periods nest */
    s.NotBefore = ft_add(i.NotBefore, -1); CHECK(!C32(CertVerifyValidityNesting)(&s, &i));
    s.NotBefore = i.NotBefore; s.NotAfter = ft_add(i.NotAfter, 1); CHECK(!C32(CertVerifyValidityNesting)(&s, &i));
    s.NotAfter = ft_add(i.NotAfter, -1); s.NotBefore = ft_add(i.NotBefore, 1); CHECK(C32(CertVerifyValidityNesting)(&s, &i));
}

/* ---- CertVerifySubjectCertificateContext ---- */
TEST(ccp_verify_subject_rejects_unknown_flag_bits) {
    PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), r = ccp_ctx(&fx_root); DWORD bad[] = {8, 0x10, 0x10000, 0x20000, 0x80000000, 0xFFFFFFF8}; int k;
    REQUIRE(C32(CertVerifySubjectCertificateContext));
    if (!l || !r) { CHECK(0); return; }
    for (k = 0; k < 6; k++) {
        DWORD fl = bad[k]; SET_ERR(0);
        EXPECT_FAIL(!C32(CertVerifySubjectCertificateContext)(l, r, &fl), E_INVALIDARG_);
        EXPECT_EQ(fl, bad[k]);
    }
    ccp_free(l); ccp_free(r);
}
TEST(ccp_verify_subject_signature_and_revocation_need_issuer) {
    PCCERT_CONTEXT l = ccp_ctx(&fx_leaf); DWORD flags[] = {CERT_STORE_SIGNATURE_FLAG, CERT_STORE_REVOCATION_FLAG, 3, 5, 7}; int k;
    REQUIRE(C32(CertVerifySubjectCertificateContext));
    if (t_is_wine()) { t_skip("emulator dereferences the NULL issuer"); return; }
    if (!l) { CHECK(0); return; }
    for (k = 0; k < 5; k++) {
        DWORD fl = flags[k]; SET_ERR(0);
        EXPECT_FAIL(!C32(CertVerifySubjectCertificateContext)(l, NULL, &fl), E_INVALIDARG_);
    }
    ccp_free(l);
}
TEST(ccp_verify_subject_time_only_without_issuer) {
    PCCERT_CONTEXT l = ccp_ctx(&fx_leaf), e = ccp_ctx(&fx_leafexp); DWORD fl;
    REQUIRE(C32(CertVerifySubjectCertificateContext));
    if (!l || !e) { CHECK(0); return; }
    fl = CERT_STORE_TIME_VALIDITY_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(l, NULL, &fl)); EXPECT_EQ(fl, 0);
    fl = CERT_STORE_TIME_VALIDITY_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(e, NULL, &fl)); EXPECT_EQ(fl, CERT_STORE_TIME_VALIDITY_FLAG);
    fl = 0; CHECK(C32(CertVerifySubjectCertificateContext)(e, NULL, &fl)); EXPECT_EQ(fl, 0);
    ccp_free(l); ccp_free(e);
}
TEST(ccp_verify_subject_signature_flag) {
    PCCERT_CONTEXT leaf = ccp_ctx(&fx_leaf), leaf2 = ccp_ctx(&fx_leaf2), root = ccp_ctx(&fx_root), root2 = ccp_ctx(&fx_root2); DWORD fl;
    REQUIRE(C32(CertVerifySubjectCertificateContext));
    if (!leaf || !leaf2 || !root || !root2) { CHECK(0); return; }
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(leaf, root, &fl)); EXPECT_EQ(fl, 0);
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(leaf, root2, &fl)); EXPECT_EQ(fl, CERT_STORE_SIGNATURE_FLAG);
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(leaf2, root, &fl)); EXPECT_EQ(fl, CERT_STORE_SIGNATURE_FLAG);
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(leaf2, root2, &fl)); EXPECT_EQ(fl, 0);
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(root, root, &fl)); EXPECT_EQ(fl, 0);    /* self-signed */
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(root, root2, &fl)); EXPECT_EQ(fl, CERT_STORE_SIGNATURE_FLAG);
    fl = 0; CHECK(C32(CertVerifySubjectCertificateContext)(leaf, root2, &fl)); EXPECT_EQ(fl, 0);                              /* not requested: not checked */
    ccp_free(leaf); ccp_free(leaf2); ccp_free(root); ccp_free(root2);
}
TEST(ccp_verify_subject_signature_and_time_combined) {
    PCCERT_CONTEXT leaf = ccp_ctx(&fx_leafexp), root = ccp_ctx(&fx_root), root2 = ccp_ctx(&fx_root2); DWORD fl;
    REQUIRE(C32(CertVerifySubjectCertificateContext));
    if (!leaf || !root || !root2) { CHECK(0); return; }
    fl = CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG;
    CHECK(C32(CertVerifySubjectCertificateContext)(leaf, root, &fl));
    EXPECT_EQ(fl, CERT_STORE_TIME_VALIDITY_FLAG);              /* signature fine, expired */
    fl = CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG;
    CHECK(C32(CertVerifySubjectCertificateContext)(leaf, root2, &fl));
    EXPECT_EQ(fl, CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG);
    ccp_free(leaf); ccp_free(root); ccp_free(root2);
}
TEST(ccp_verify_subject_ec_signature) {
    PCCERT_CONTEXT e = ccp_ctx(&fx_ec256), r = ccp_ctx(&fx_root), e2 = ccp_ctx(&fx_ec384v1); DWORD fl;
    REQUIRE(C32(CertVerifySubjectCertificateContext));
    if (!e || !r || !e2) { CHECK(0); return; }
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(e, e, &fl)); EXPECT_EQ(fl, 0);
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(e2, e2, &fl)); EXPECT_EQ(fl, 0);
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(e, r, &fl)); EXPECT_EQ(fl, CERT_STORE_SIGNATURE_FLAG);
    fl = CERT_STORE_SIGNATURE_FLAG; CHECK(C32(CertVerifySubjectCertificateContext)(e, e2, &fl)); EXPECT_EQ(fl, CERT_STORE_SIGNATURE_FLAG);
    ccp_free(e); ccp_free(r); ccp_free(e2);
}

/* ---- CryptVerifyCertificateSignature(Ex) ---- */
static const struct { const FX *sub, *iss; } sigpairs[] = {
    {&fx_root, &fx_root}, {&fx_inter, &fx_root}, {&fx_leaf, &fx_root}, {&fx_leafi, &fx_inter}, {&fx_ec256, &fx_ec256}, {&fx_sha1leaf, &fx_root},
    {&fx_ec384v1, &fx_ec384v1}, {&fx_expired, &fx_expired}, {&fx_future, &fx_future}, {&fx_nestbad, &fx_root}, {&fx_nestbad2, &fx_root},
    {&fx_root2, &fx_root2}, {&fx_leaf2, &fx_root2}, {&fx_rsa1024, &fx_rsa1024}, {&fx_negserial, &fx_negserial}, {&fx_utf8, &fx_utf8},
    {&fx_leafexp, &fx_root}, {&fx_leaffut, &fx_root},
};
#define NPAIRS ((int)(sizeof sigpairs / sizeof sigpairs[0]))

TEST(ccp_sig_verify_plain_all_pairs) {
    int i; REQUIRE(C32(CryptVerifyCertificateSignature));
    for (i = 0; i < NPAIRS; i++) {
        PCCERT_CONTEXT is = ccp_ctx(sigpairs[i].iss);
        if (!is) { CHECK(0); continue; }
        CHECKF(C32(CryptVerifyCertificateSignature)(0, ENC, sigpairs[i].sub->der, sigpairs[i].sub->cb, &is->pCertInfo->SubjectPublicKeyInfo), "%s by %s", sigpairs[i].sub->name, sigpairs[i].iss->name);
        ccp_free(is);
    }
}
TEST(ccp_sig_verify_wrong_issuer_key_fails) {
    int i, j, tested = 0; REQUIRE(C32(CryptVerifyCertificateSignature));
    for (i = 0; i < NPAIRS; i++) for (j = 0; j < ccp_nall; j++) {
        const FX *k = ccp_all[j]; PCCERT_CONTEXT is;
        if (k == sigpairs[i].iss || (k->cbPub == sigpairs[i].iss->cbPub && !memcmp(k->pub, sigpairs[i].iss->pub, k->cbPub))) continue;
        if ((i + j) % 3) continue;      /* sample the matrix */
        is = ccp_ctx(k);
        if (!is) { CHECK(0); continue; }
        SET_ERR(0);
        CHECKF(!C32(CryptVerifyCertificateSignature)(0, ENC, sigpairs[i].sub->der, sigpairs[i].sub->cb, &is->pCertInfo->SubjectPublicKeyInfo), "%s must not verify under %s", sigpairs[i].sub->name, k->name);
        CHECK(GetLastError() != 0);
        tested++;
        ccp_free(is);
    }
    CHECK(tested > 20);
}
TEST(ccp_sig_verify_rsa_bad_signature_error) {
    PCCERT_CONTEXT is = ccp_ctx(&fx_root2);
    REQUIRE(C32(CryptVerifyCertificateSignature));
    if (!is) { CHECK(0); return; }
    SET_ERR(0);
    CHECK(!C32(CryptVerifyCertificateSignature)(0, ENC, fx_leaf.der, fx_leaf.cb, &is->pCertInfo->SubjectPublicKeyInfo));
    t_note("RSA signature mismatch last error 0x%lx (NTE_BAD_SIGNATURE = 0x80090006)", (unsigned long)GetLastError());
    /* exact error depends on the RSA verify path; not hard-checked */
    CHECK(GetLastError() != 0);
    ccp_free(is);
}
TEST(ccp_sig_verify_tampered_signature_byte) {
    int i; REQUIRE(C32(CryptVerifyCertificateSignature));
    for (i = 0; i < NPAIRS; i += 2) {
        const FX *f = sigpairs[i].sub; PCCERT_CONTEXT is = ccp_ctx(sigpairs[i].iss); BYTE *b = (BYTE *)LocalAlloc(LPTR, f->cb);
        if (!is || !b) { CHECK(0); continue; }
        memcpy(b, f->der, f->cb);
        b[f->cb - 1] ^= 0x01;           /* last signature octet */
        SET_ERR(0);
        CHECKF(!C32(CryptVerifyCertificateSignature)(0, ENC, b, f->cb, &is->pCertInfo->SubjectPublicKeyInfo), "%s", f->name);
        LocalFree(b); ccp_free(is);
    }
}
TEST(ccp_sig_verify_tampered_tbs_byte) {
    int i; REQUIRE(C32(CryptVerifyCertificateSignature));
    for (i = 1; i < NPAIRS; i += 2) {
        const FX *f = sigpairs[i].sub; PCCERT_CONTEXT is = ccp_ctx(sigpairs[i].iss); BYTE *b = (BYTE *)LocalAlloc(LPTR, f->cb);
        const BYTE *subj; size_t off;
        if (!is || !b) { CHECK(0); continue; }
        memcpy(b, f->der, f->cb);
        /* flip a bit inside the encoded subject name (a character of the common name) */
        for (off = 0; off + f->cbSubj <= f->cb; off++) if (!memcmp(b + off, f->subj, f->cbSubj)) break;
        CHECKF(off + f->cbSubj <= f->cb, "%s subject located", f->name);
        b[off + f->cbSubj - 1] ^= 0x01;
        SET_ERR(0);
        CHECKF(!C32(CryptVerifyCertificateSignature)(0, ENC, b, f->cb, &is->pCertInfo->SubjectPublicKeyInfo), "%s", f->name);
        LocalFree(b); ccp_free(is);
    }
}
TEST(ccp_sig_verify_truncated_or_garbage_encoding) {
    PCCERT_CONTEXT is = ccp_ctx(&fx_root);
    REQUIRE(C32(CryptVerifyCertificateSignature));
    if (!is) { CHECK(0); return; }
    SET_ERR(0);
    CHECK(!C32(CryptVerifyCertificateSignature)(0, ENC, fx_root.der, fx_root.cb - 5, &is->pCertInfo->SubjectPublicKeyInfo));
    EXPECT_ASN1_ERR();
    SET_ERR(0);
    CHECK(!C32(CryptVerifyCertificateSignature)(0, ENC, fx_root.der, 3, &is->pCertInfo->SubjectPublicKeyInfo));
    EXPECT_ASN1_ERR();
    ccp_free(is);
}
TEST(ccp_sig_verify_encoding_type_zero) {
    PCCERT_CONTEXT is = ccp_ctx(&fx_root);
    REQUIRE(C32(CryptVerifyCertificateSignature));
    if (!is) { CHECK(0); return; }
    SET_ERR(0);
    CHECK(!C32(CryptVerifyCertificateSignature)(0, 0, fx_root.der, fx_root.cb, &is->pCertInfo->SubjectPublicKeyInfo));
    CHECK(GetLastError() != 0);
    ccp_free(is);
}
TEST(ccp_sig_verify_ex_subject_blob_and_cert_agree) {
    int i; REQUIRE(C32(CryptVerifyCertificateSignatureEx));
    for (i = 0; i < NPAIRS; i++) {
        PCCERT_CONTEXT is = ccp_ctx(sigpairs[i].iss), sc = ccp_ctx(sigpairs[i].sub); CRYPT_DATA_BLOB b;
        if (!is || !sc) { CHECK(0); continue; }
        b.cbData = sigpairs[i].sub->cb; b.pbData = (BYTE *)sigpairs[i].sub->der;
        CHECKF(C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &b, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)is, 0, NULL), "blob/cert %s", sigpairs[i].sub->name);
        CHECKF(C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)sc, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)is, 0, NULL), "cert/cert %s", sigpairs[i].sub->name);
        CHECKF(C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)sc, CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, &is->pCertInfo->SubjectPublicKeyInfo, 0, NULL), "cert/pubkey %s", sigpairs[i].sub->name);
        CHECKF(C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &b, CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, &is->pCertInfo->SubjectPublicKeyInfo, 0, NULL), "blob/pubkey %s", sigpairs[i].sub->name);
        ccp_free(is); ccp_free(sc);
    }
}
TEST(ccp_sig_verify_ex_wrong_issuer) {
    PCCERT_CONTEXT leaf = ccp_ctx(&fx_leaf), r2 = ccp_ctx(&fx_root2);
    REQUIRE(C32(CryptVerifyCertificateSignatureEx));
    if (!leaf || !r2) { CHECK(0); return; }
    SET_ERR(0);
    CHECK(!C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)leaf, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)r2, 0, NULL));
    CHECK(GetLastError() != 0);
    ccp_free(leaf); ccp_free(r2);
}
TEST(ccp_sig_verify_ex_invalid_types_and_flags) {
    PCCERT_CONTEXT r = ccp_ctx(&fx_root); CRYPT_DATA_BLOB b; DWORD st[] = {0, 5, 0x100}, it[] = {0, 5, 0x100}; int k;
    REQUIRE(C32(CryptVerifyCertificateSignatureEx));
    if (!r) { CHECK(0); return; }
    b.cbData = fx_root.cb; b.pbData = (BYTE *)fx_root.der;
    for (k = 0; k < 3; k++) {
        SET_ERR(0);
        EXPECT_FAIL(!C32(CryptVerifyCertificateSignatureEx)(0, ENC, st[k], &b, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)r, 0, NULL), E_INVALIDARG_);
        SET_ERR(0);
        EXPECT_FAIL(!C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &b, it[k], (void *)r, 0, NULL), E_INVALIDARG_);
    }
    SET_ERR(0);       /* flags 4 and 8 together are contradictory */
    EXPECT_FAIL(!C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &b, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)r, 0xC, NULL), E_INVALIDARG_);
    SET_ERR(0);       /* flag 2 only applies to CRL subjects */
    EXPECT_FAIL(!C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &b, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)r, 2, NULL), E_INVALIDARG_);
    ccp_free(r);
}
TEST(ccp_sig_verify_ex_unknown_signature_algorithm_fails) {
    BYTE *buf; PCCERT_CONTEXT r = ccp_ctx(&fx_root); CRYPT_DATA_BLOB b; size_t i, hit = 0;
    static const BYTE oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
    REQUIRE(C32(CryptVerifyCertificateSignatureEx));
    if (!r) { CHECK(0); return; }
    buf = (BYTE *)LocalAlloc(LPTR, fx_root.cb); memcpy(buf, fx_root.der, fx_root.cb);
    /* the outer signatureAlgorithm is the last occurrence of the sha256WithRSA OID */
    for (i = 0; i + sizeof oid <= fx_root.cb; i++) if (!memcmp(buf + i, oid, sizeof oid)) hit = i;
    CHECK(hit > 100);
    buf[hit + 8] = 0x7e;
    b.cbData = fx_root.cb; b.pbData = buf;
    SET_ERR(0);
    CHECK(!C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &b, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)r, 0, NULL));
    t_note("unknown signature algorithm OID: last error 0x%lx", (unsigned long)GetLastError());
    CHECK(GetLastError() != 0);
    LocalFree(buf); ccp_free(r);
}
TEST(ccp_sig_verify_ex_issuer_null_type_for_standard_alg_fails) {
    CRYPT_DATA_BLOB b;
    REQUIRE(C32(CryptVerifyCertificateSignatureEx));
    b.cbData = fx_root.cb; b.pbData = (BYTE *)fx_root.der;
    SET_ERR(0);
    EXPECT_FAIL(!C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &b, CRYPT_VERIFY_CERT_SIGN_ISSUER_NULL, NULL, 0, NULL), E_INVALIDARG_);
}

/* ---- hashing ---- */
TEST(ccp_hash_certificate_sha1_default) {
    int i; REQUIRE(C32(CryptHashCertificate));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; BYTE h[64]; DWORD cb = sizeof h;
        CHECKF(C32(CryptHashCertificate)(0, 0, 0, f->der, f->cb, h, &cb) && cb == 20 && !memcmp(h, f->sha1, 20), "%s alg 0", f->name);
        cb = sizeof h;
        CHECKF(C32(CryptHashCertificate)(0, CALG_SHA1, 0, f->der, f->cb, h, &cb) && cb == 20 && !memcmp(h, f->sha1, 20), "%s sha1", f->name);
    }
}
TEST(ccp_hash_certificate_md5_and_sha256) {
    int i; REQUIRE(C32(CryptHashCertificate));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; BYTE h[64]; DWORD cb = sizeof h;
        CHECKF(C32(CryptHashCertificate)(0, CALG_MD5, 0, f->der, f->cb, h, &cb) && cb == 16 && !memcmp(h, f->md5, 16), "%s md5", f->name);
        cb = sizeof h;
        if (C32(CryptHashCertificate)(0, CALG_SHA_256, 0, f->der, f->cb, h, &cb)) CHECKF(cb == 32 && !memcmp(h, f->sha256, 32), "%s sha256", f->name);
        else t_note("CALG_SHA_256 unsupported by the default provider (0x%lx)", (unsigned long)GetLastError());
    }
}
TEST(ccp_hash_certificate_size_protocol) {
    BYTE h[32]; DWORD cb = 0;
    REQUIRE(C32(CryptHashCertificate));
    SET_ERR(0);
    CHECK(C32(CryptHashCertificate)(0, CALG_SHA1, 0, fx_root.der, fx_root.cb, NULL, &cb) && cb == 20);
    cb = 19; SET_ERR(0);
    EXPECT_FAIL(!C32(CryptHashCertificate)(0, CALG_SHA1, 0, fx_root.der, fx_root.cb, h, &cb), ERROR_MORE_DATA);
    EXPECT_EQ(cb, 20);
    cb = 0; SET_ERR(0);
    EXPECT_FAIL(!C32(CryptHashCertificate)(0, CALG_MD5, 0, fx_root.der, fx_root.cb, h, &cb), ERROR_MORE_DATA);
    EXPECT_EQ(cb, 16);
    cb = 32; memset(h, 0xEE, 32);
    CHECK(C32(CryptHashCertificate)(0, CALG_SHA1, 0, fx_root.der, fx_root.cb, h, &cb) && cb == 20 && h[20] == 0xEE);
}
TEST(ccp_hash_certificate_hashes_raw_bytes) {
    /* any byte string can be hashed: SHA-1("abc") */
    static const BYTE abc[] = {'a', 'b', 'c'};
    static const BYTE want[20] = {0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d};
    BYTE h[20]; DWORD cb = 20;
    REQUIRE(C32(CryptHashCertificate));
    CHECK(C32(CryptHashCertificate)(0, CALG_SHA1, 0, abc, 3, h, &cb) && cb == 20 && !memcmp(h, want, 20));
    { static const BYTE md5[16] = {0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72};
      BYTE m[16]; cb = 16; CHECK(C32(CryptHashCertificate)(0, CALG_MD5, 0, abc, 3, m, &cb) && cb == 16 && !memcmp(m, md5, 16)); }
    cb = 20;      /* empty input */
    { static const BYTE e[20] = {0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09};
      CHECK(C32(CryptHashCertificate)(0, CALG_SHA1, 0, abc, 0, h, &cb) && !memcmp(h, e, 20)); }
}
TEST(ccp_hash_certificate_bad_algid) {
    BYTE h[64]; DWORD cb = sizeof h;
    REQUIRE(C32(CryptHashCertificate));
    SET_ERR(0);
    CHECK(!C32(CryptHashCertificate)(0, 0x1234, 0, fx_root.der, fx_root.cb, h, &cb));
    t_note("bad ALG_ID last error 0x%lx", (unsigned long)GetLastError());
    EXPECT_ERR(NTE_BAD_ALGID_);
    cb = sizeof h; SET_ERR(0);
    CHECK(!C32(CryptHashCertificate)(0, CALG_RC4, 0, fx_root.der, fx_root.cb, h, &cb));
    CHECK(GetLastError() != 0);
}
TEST(ccp_hash_certificate2_sha_family) {
    static const struct { const WCHAR *alg; DWORD len; } t[] = {{L"SHA1", 20}, {L"SHA256", 32}, {L"SHA384", 48}, {L"SHA512", 64}, {L"MD5", 16}, {L"MD2", 16}, {L"MD4", 16}};
    int k; REQUIRE(C32(CryptHashCertificate2));
    for (k = 0; k < 7; k++) {
        BYTE h[64]; DWORD cb = 0;
        BOOL ok = C32(CryptHashCertificate2)(t[k].alg, 0, NULL, fx_root.der, fx_root.cb, NULL, &cb);
        CHECKF(ok && cb == t[k].len, "%ls size", t[k].alg);
        cb = sizeof h; memset(h, 0, sizeof h);
        ok = C32(CryptHashCertificate2)(t[k].alg, 0, NULL, fx_root.der, fx_root.cb, h, &cb);
        CHECKF(ok && cb == t[k].len, "%ls", t[k].alg);
        if (!wcscmp(t[k].alg, L"SHA1")) CHECK(!memcmp(h, fx_root.sha1, 20));
        if (!wcscmp(t[k].alg, L"SHA256")) CHECK(!memcmp(h, fx_root.sha256, 32));
        if (!wcscmp(t[k].alg, L"MD5")) CHECK(!memcmp(h, fx_root.md5, 16));
    }
}
TEST(ccp_hash_certificate2_all_fixtures_sha256) {
    int i; REQUIRE(C32(CryptHashCertificate2));
    for (i = 0; i < ccp_nall; i++) {
        BYTE h[32]; DWORD cb = 32;
        CHECKF(C32(CryptHashCertificate2)(L"SHA256", 0, NULL, ccp_all[i]->der, ccp_all[i]->cb, h, &cb) && cb == 32 && !memcmp(h, ccp_all[i]->sha256, 32), "%s", ccp_all[i]->name);
    }
}
TEST(ccp_hash_certificate2_size_protocol_and_errors) {
    BYTE h[64]; DWORD cb;
    REQUIRE(C32(CryptHashCertificate2));
    cb = 31; SET_ERR(0);
    EXPECT_FAIL(!C32(CryptHashCertificate2)(L"SHA256", 0, NULL, fx_root.der, fx_root.cb, h, &cb), ERROR_MORE_DATA);
    EXPECT_EQ(cb, 32);
    cb = sizeof h; SET_ERR(0);
    CHECK(!C32(CryptHashCertificate2)(L"NO_SUCH_HASH", 0, NULL, fx_root.der, fx_root.cb, h, &cb));
    t_note("unknown CNG hash name: last error 0x%lx", (unsigned long)GetLastError());
    CHECK(GetLastError() != 0);
    cb = sizeof h; SET_ERR(0);
    CHECK(!C32(CryptHashCertificate2)(L"RSA", 0, NULL, fx_root.der, fx_root.cb, h, &cb));    /* an algorithm that is not a hash */
    CHECK(GetLastError() != 0);
}
TEST(ccp_hash_to_be_signed_matches_signature_hash) {
    int i; REQUIRE(C32(CryptHashToBeSigned));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; BYTE h[64]; DWORD cb = 0;
        CHECKF(C32(CryptHashToBeSigned)(0, ENC, f->der, f->cb, NULL, &cb) && cb == f->cbSigHash, "%s size %lu", f->name, (unsigned long)cb);
        cb = sizeof h; memset(h, 0, sizeof h);
        CHECKF(C32(CryptHashToBeSigned)(0, ENC, f->der, f->cb, h, &cb) && cb == f->cbSigHash && !memcmp(h, f->sighash, cb), "%s", f->name);
    }
}
TEST(ccp_hash_to_be_signed_buffer_errors) {
    BYTE h[64]; DWORD cb = 5;
    REQUIRE(C32(CryptHashToBeSigned));
    SET_ERR(0);
    EXPECT_FAIL(!C32(CryptHashToBeSigned)(0, ENC, fx_root.der, fx_root.cb, h, &cb), ERROR_MORE_DATA);
    EXPECT_EQ(cb, 32);
    SET_ERR(0);
    cb = sizeof h;
    CHECK(!C32(CryptHashToBeSigned)(0, ENC, fx_root.der, 20, h, &cb));
    EXPECT_ASN1_ERR();
}
TEST(ccp_hash_public_key_info_sha1_of_spki) {
    int i; REQUIRE(C32(CryptHashPublicKeyInfo));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE h[32]; DWORD cb = sizeof h;
        if (!c) { CHECK(0); continue; }
        CHECKF(C32(CryptHashPublicKeyInfo)(0, 0, 0, ENC, &c->pCertInfo->SubjectPublicKeyInfo, h, &cb) && cb == 20 && !memcmp(h, f->spkisha1, 20), "%s", f->name);
        cb = sizeof h;
        CHECKF(C32(CryptHashPublicKeyInfo)(0, CALG_SHA1, 0, ENC, &c->pCertInfo->SubjectPublicKeyInfo, h, &cb) && cb == 20 && !memcmp(h, f->spkisha1, 20), "%s sha1", f->name);
        ccp_free(c);
    }
}
TEST(ccp_hash_public_key_info_md5_and_size) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BYTE h[32]; DWORD cb = 0;
    REQUIRE(C32(CryptHashPublicKeyInfo));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CryptHashPublicKeyInfo)(0, CALG_MD5, 0, ENC, &c->pCertInfo->SubjectPublicKeyInfo, NULL, &cb) && cb == 16);
    cb = 15; SET_ERR(0);
    EXPECT_FAIL(!C32(CryptHashPublicKeyInfo)(0, CALG_MD5, 0, ENC, &c->pCertInfo->SubjectPublicKeyInfo, h, &cb), ERROR_MORE_DATA);
    ccp_free(c);
}

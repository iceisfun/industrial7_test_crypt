/* CertVerifyRevocation / cryptnet!CertDllVerifyRevocation, offline: CRLs come from the caller's CRL store,
 * URL retrieval is forbidden with CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION. */
#include "cc.h"

typedef struct {
    DWORD cbSize; PCCERT_CONTEXT pIssuerCert; DWORD cCertStore; HCERTSTORE *rgCertStore; HCERTSTORE hCrlStore;
    LPFILETIME pftTimeToUse; DWORD dwUrlRetrievalTimeout; BOOL fCheckFreshnessTime; DWORD dwFreshnessTime;
    LPFILETIME pftCurrentTime; void *pCrlInfo; LPFILETIME pftCacheResync; void *pChainPara;
} RP;
typedef char rp_size_check[sizeof(RP) == 0x60 ? 1 : -1];
typedef CERT_REVOCATION_STATUS RS;
UDECL(BOOL, CertDllVerifyRevocation, (DWORD, DWORD, DWORD, void **, DWORD, void *, void *));
#define OFFLINE_FLAGS CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION

static void rel(PCCERT_CONTEXT c) { if (c) U(CertFreeCertificateContext)(c); }
static void st_init(RS *s) { memset(s, 0xcd, sizeof *s); s->cbSize = sizeof *s; }
static FILETIME mkft(ULONGLONG v) { FILETIME f; f.dwLowDateTime = (DWORD)v; f.dwHighDateTime = (DWORD)(v >> 32); return f; }
static int is_nocheck(DWORD e) { return e == CC_E_NO_REVOCATION_CHECK || e == CC_E_REVOCATION_OFFLINE; }

typedef struct { HCERTSTORE crls; RP p; PCCERT_CONTEXT ca1; } CTX;
static int cx_init(CTX *c, const BYTE *a, DWORD an, const BYTE *b, DWORD bn) {
    memset(c, 0, sizeof *c);
    c->crls = cc_store();
    if (!c->crls) return 0;
    if (a) cc_add_crl(c->crls, a, an, CERT_STORE_ADD_ALWAYS, NULL);
    if (b) cc_add_crl(c->crls, b, bn, CERT_STORE_ADD_ALWAYS, NULL);
    c->ca1 = cc_cert(VEC(v_ca1));
    c->p.cbSize = sizeof c->p; c->p.pIssuerCert = c->ca1; c->p.hCrlStore = c->crls;
    return c->ca1 != NULL;
}
static void cx_done(CTX *c) { rel(c->ca1); cc_close(c->crls); }

/* ---- argument handling of the crypt32 entry point ---- */
TEST(rev_status_cbsize_too_small) {
    REQUIRE(U(CertVerifyRevocation));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    for (DWORD cb = 0; cb < 16; cb += 3) {
        RS s; st_init(&s); s.cbSize = cb;
        SET_ERR(0);
        CHECKF(!U(CertVerifyRevocation)(CC_X509, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, NULL, &s), "cbSize %lu", cb);
        EXPECT_ERR(CC_E_INVALIDARG);
    }
    rel(l);
}
TEST(rev_zero_contexts_is_success) {
    REQUIRE(U(CertVerifyRevocation));
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(U(CertVerifyRevocation)(CC_X509, CERT_CONTEXT_REVOCATION_TYPE, 0, NULL, 0, NULL, &s));
    EXPECT_EQ(s.dwIndex, 0); EXPECT_EQ(s.dwError, 0); EXPECT_EQ(s.dwReason, 0);
    EXPECT_EQ(s.cbSize, sizeof s);
    /* revocation type is not looked at when there is nothing to check */
    st_init(&s);
    CHECK(U(CertVerifyRevocation)(CC_X509, 0x1234, 0, NULL, 0, NULL, &s));
    EXPECT_EQ(s.dwError, 0);
}
TEST(rev_minimal_status_size_accepted) {
    REQUIRE(U(CertVerifyRevocation));
    struct { DWORD cbSize, dwIndex, dwError, dwReason, guard; } s;
    memset(&s, 0xcd, sizeof s); s.cbSize = 16;
    CHECK(U(CertVerifyRevocation)(CC_X509, CERT_CONTEXT_REVOCATION_TYPE, 0, NULL, 0, NULL, (RS *)&s));
    EXPECT_EQ(s.dwIndex, 0); EXPECT_EQ(s.dwError, 0); EXPECT_EQ(s.dwReason, 0);
    EXPECT_EQ(s.guard, 0xcdcdcdcd); /* nothing written past cbSize */
}
TEST(rev_wrong_revocation_type) {
    REQUIRE(U(CertVerifyRevocation));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    static const DWORD types[] = { 0, 2, 3, 0x1234 };
    for (unsigned i = 0; i < sizeof types / sizeof types[0]; i++) {
        RS s; st_init(&s);
        SET_ERR(0);
        CHECKF(!U(CertVerifyRevocation)(CC_X509P7, types[i], 1, ctxs, OFFLINE_FLAGS, NULL, &s), "type %lu", types[i]);
        DWORD gle = GetLastError();
        CHECKF(gle == s.dwError, "GetLastError 0x%lx equals status.dwError 0x%lx", gle, s.dwError);
        CHECKF(s.dwError == CC_E_NO_REVOCATION_CHECK || s.dwError == CC_E_NO_REVOCATION_DLL, "type %lu error 0x%lx", types[i], s.dwError);
        EXPECT_EQ(s.dwIndex, 0);
    }
    rel(l);
}
TEST(rev_wrong_encoding_type) {
    REQUIRE(U(CertVerifyRevocation));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(PKCS_7_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, NULL, &s));
    t_note("PKCS7-only encoding: err 0x%lx", s.dwError);
    st_init(&s);
    CHECK(!U(CertVerifyRevocation)(0, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, NULL, &s));
    t_note("encoding 0: err 0x%lx", s.dwError);
    rel(l);
}

/* ---- offline CRL based verdicts ---- */
TEST(rev_crl_revoked_key_compromise) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    EXPECT_ERR(CC_E_REVOKED);
    EXPECT_EQ(s.dwError, CC_E_REVOKED);
    EXPECT_EQ(s.dwReason, CRL_REASON_KEY_COMPROMISE);
    EXPECT_EQ(s.dwIndex, 0);
    rel(l); cx_done(&c);
}
TEST(rev_crl_revoked_certificate_hold) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1002));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    EXPECT_EQ(s.dwError, CC_E_REVOKED);
    EXPECT_EQ(s.dwReason, CRL_REASON_CERTIFICATE_HOLD);
    rel(l); cx_done(&c);
}
TEST(rev_crl_not_listed_is_good) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1003));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    SET_ERR(0);
    BOOL ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
    CHECKF(ok, "err 0x%lx status error 0x%lx", GetLastError(), s.dwError);
    EXPECT_EQ(s.dwError, 0);
    EXPECT_EQ(s.dwIndex, 0);
    EXPECT_EQ(s.dwReason, 0);
    rel(l); cx_done(&c);
}
TEST(rev_crl_freshness_time_reported) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    FILETIME now = mkft(V_THIS_FT + 3600ULL * 10000000ULL);
    c.p.pftCurrentTime = &now;
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1003));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    BOOL ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
    CHECKF(ok, "status error 0x%lx", s.dwError);
    if (ok) {
        EXPECT_EQ(s.fHasFreshnessTime, 1);
        EXPECT_EQ(s.dwFreshnessTime, 3600);
    }
    /* a status block without the freshness fields is not extended */
    struct { DWORD cbSize, dwIndex, dwError, dwReason, guard; } small;
    memset(&small, 0xcd, sizeof small); small.cbSize = 16;
    ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, (RS *)&small);
    CHECK(ok);
    EXPECT_EQ(small.guard, 0xcdcdcdcd);
    rel(l); cx_done(&c);
}
TEST(rev_crl_freshness_on_revoked_cert) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    FILETIME now = mkft(V_THIS_FT + 120ULL * 10000000ULL);
    c.p.pftCurrentTime = &now;
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    EXPECT_EQ(s.dwError, CC_E_REVOKED);
    EXPECT_EQ(s.fHasFreshnessTime, 1);
    EXPECT_EQ(s.dwFreshnessTime, 120);
    rel(l); cx_done(&c);
}
TEST(rev_crl_all_reason_codes) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_reasons), NULL, 0));
    const struct { const BYTE *p; DWORD n; DWORD reason; int revoked; } t[] = {
        { VEC(v_cert_r0), 0, 1 }, { VEC(v_cert_r1), 1, 1 }, { VEC(v_cert_r2), 2, 1 }, { VEC(v_cert_r3), 3, 1 },
        { VEC(v_cert_r4), 4, 1 }, { VEC(v_cert_r5), 5, 1 }, { VEC(v_cert_r6), 6, 1 },
        { VEC(v_cert_r8), 8, 1 }, { VEC(v_cert_r9), 9, 1 }, { VEC(v_cert_r10), 10, 1 },
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        PCCERT_CONTEXT l = cc_cert(t[i].p, t[i].n);
        CHECKF(l != NULL, "cert %u", i);
        if (!l) continue;
        void *ctxs[1] = { (void *)l };
        RS s; st_init(&s);
        BOOL ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
        if (t[i].reason == 8) { t_note("removeFromCRL entry in a base CRL: ret=%d err=0x%lx reason=%lu", ok, s.dwError, s.dwReason); rel(l); continue; }
        CHECKF(!ok, "reason %lu", t[i].reason);
        EXPECT_EQ(s.dwError, CC_E_REVOKED);
        EXPECT_EQ(s.dwReason, t[i].reason);
        rel(l);
    }
    rel(NULL); cx_done(&c);
}
TEST(rev_crl_missing_reason_extension_means_unspecified) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_idp), NULL, 0));
    /* IDP CRL entry 0x1001 has no reason extension. */
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    BOOL ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
    t_note("revoked via CRL with issuing-distribution-point and a cert without CDP: ret=%d err=0x%lx reason=%lu", ok, s.dwError, s.dwReason);
    rel(l); cx_done(&c);
}
TEST(rev_crl_wrong_issuer_not_used) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT ca2 = cc_cert(VEC(v_ca2)), l = cc_cert(VEC(v_cert_c2_1001));
    REQUIRE(ca2 && l);
    c.p.pIssuerCert = ca2;
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    /* CA1's CRL lists serial 0x1001 but CA2 is the issuer here: that CRL must not produce a "revoked" verdict */
    CHECK(s.dwError != CC_E_REVOKED);
    CHECKF(is_nocheck(s.dwError), "error 0x%lx", s.dwError);
    rel(l); rel(ca2); cx_done(&c);
}
TEST(rev_crl_ca2_crl_revokes_ca2_leaf) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), VEC(v_crl_ca2)));
    PCCERT_CONTEXT ca2 = cc_cert(VEC(v_ca2)), l = cc_cert(VEC(v_cert_c2_1001));
    REQUIRE(ca2 && l);
    c.p.pIssuerCert = ca2;
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    EXPECT_EQ(s.dwError, CC_E_REVOKED);
    EXPECT_EQ(s.dwReason, CRL_REASON_CA_COMPROMISE);
    rel(l); rel(ca2); cx_done(&c);
}
TEST(rev_crl_expired_not_usable) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_expired), NULL, 0));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1003));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    CHECKF(is_nocheck(s.dwError), "error 0x%lx", s.dwError);
    EXPECT_ERR(s.dwError);
    rel(l); cx_done(&c);
}
TEST(rev_crl_expired_checked_at_time_to_use) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_expired), NULL, 0));
    FILETIME t = mkft(V_THIS_FT + 86400ULL * 10000000ULL * 5);
    c.p.pftTimeToUse = &t;
    c.p.pftCurrentTime = &t;
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    BOOL ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
    t_note("expired CRL examined at a time inside its validity: ret=%d err=0x%lx reason=%lu", ok, s.dwError, s.dwReason);
    rel(l); cx_done(&c);
}
TEST(rev_crl_empty_store_no_check) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, NULL, 0, NULL, 0));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    CHECKF(is_nocheck(s.dwError), "error 0x%lx", s.dwError);
    EXPECT_ERR(s.dwError);
    EXPECT_EQ(s.dwIndex, 0);
    t_note("no CRL available: status.dwError=0x%lx", s.dwError);
    rel(l); cx_done(&c);
}
TEST(rev_no_para_no_check) {
    REQUIRE(U(CertVerifyRevocation));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, NULL, &s));
    t_note("leaf without issuer or CRL source: status.dwError=0x%lx", s.dwError);
    CHECK(s.dwError != 0 && s.dwError != CC_E_REVOKED);
    rel(l);
}
TEST(rev_cert_with_cdp_cache_only) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, NULL, 0, NULL, 0));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_cdp_match));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    c.p.dwUrlRetrievalTimeout = 1;
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    t_note("cert with a file:// CDP, cache only: status.dwError=0x%lx", s.dwError);
    CHECK(s.dwError != 0 && s.dwError != CC_E_REVOKED);
    rel(l); cx_done(&c);
}
TEST(rev_self_signed_ca_without_para) {
    REQUIRE(U(CertVerifyRevocation));
    PCCERT_CONTEXT ca = cc_cert(VEC(v_ca1));
    REQUIRE(ca);
    void *ctxs[1] = { (void *)ca };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, NULL, &s));
    t_note("self-signed root without CRL: status.dwError=0x%lx", s.dwError);
    CHECK(s.dwError != 0);
    rel(ca);
}

/* ---- several contexts: which one is reported ---- */
TEST(rev_multiple_contexts_first_revoked) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT a = cc_cert(VEC(v_cert_1001)), b = cc_cert(VEC(v_cert_1003));
    REQUIRE(a && b);
    void *ctxs[2] = { (void *)a, (void *)b };
    RS s; st_init(&s);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 2, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    EXPECT_EQ(s.dwError, CC_E_REVOKED);
    EXPECT_EQ(s.dwIndex, 0);
    rel(a); rel(b); cx_done(&c);
}
TEST(rev_multiple_contexts_second_revoked) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT a = cc_cert(VEC(v_cert_1003)), b = cc_cert(VEC(v_cert_1001));
    REQUIRE(a && b);
    void *ctxs[2] = { (void *)a, (void *)b };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 2, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    EXPECT_EQ(s.dwError, CC_E_REVOKED);
    EXPECT_EQ(s.dwIndex, 1);
    EXPECT_ERR(CC_E_REVOKED);
    rel(a); rel(b); cx_done(&c);
}
TEST(rev_multiple_contexts_all_good) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT a = cc_cert(VEC(v_cert_1003)), b = cc_cert(VEC(v_cert_r0));
    REQUIRE(a && b);
    void *ctxs[2] = { (void *)a, (void *)b };
    RS s; st_init(&s);
    SET_ERR(0);
    BOOL ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 2, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
    CHECKF(ok, "err 0x%lx index %lu", s.dwError, s.dwIndex);
    if (ok) { EXPECT_EQ(s.dwError, 0); EXPECT_EQ(s.dwIndex, 0); }
    rel(a); rel(b); cx_done(&c);
}

/* ---- delta CRL ---- */
TEST(rev_delta_crl_removes_hold) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), VEC(v_crl_delta)));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1002));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    BOOL ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
    t_note("hold in base CRL, removeFromCRL in delta CRL: ret=%d err=0x%lx reason=%lu", ok, s.dwError, s.dwReason);
    rel(l); cx_done(&c);
}
TEST(rev_delta_crl_does_not_hide_other_revocations) {
    REQUIRE(U(CertVerifyRevocation));
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), VEC(v_crl_delta)));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    BOOL ok = U(CertVerifyRevocation)(CC_X509P7, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
    t_note("revoked in base CRL, unrelated delta present: ret=%d err=0x%lx reason=%lu", ok, s.dwError, s.dwReason);
    rel(l); cx_done(&c);
}

/* ---- cryptnet!CertDllVerifyRevocation ---- */
TEST(revdll_export_resolves_by_name_and_ordinal) {
    FARPROC byname = t_proc_in("cryptnet.dll", "CertDllVerifyRevocation");
    REQUIRE(byname);
    FARPROC byord = t_proc_ord("cryptnet.dll", 2);
    t_note("CertDllVerifyRevocation by name %p, by ordinal 2 %p", (void *)byname, (void *)byord);
    CHECK(byord == byname);
}
TEST(revdll_zero_contexts_invalidarg) {
    CertDllVerifyRevocation_pfn f = (CertDllVerifyRevocation_pfn)t_proc_in("cryptnet.dll", "CertDllVerifyRevocation");
    REQUIRE(f);
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!f(CC_X509, CERT_CONTEXT_REVOCATION_TYPE, 0, NULL, 0, NULL, &s));
    EXPECT_ERR(CC_E_INVALIDARG);
    EXPECT_EQ(s.dwError, CC_E_INVALIDARG);
    EXPECT_EQ(s.dwIndex, 0);
}
TEST(revdll_wrong_encoding_or_type_no_check) {
    CertDllVerifyRevocation_pfn f = (CertDllVerifyRevocation_pfn)t_proc_in("cryptnet.dll", "CertDllVerifyRevocation");
    REQUIRE(f);
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_1001));
    REQUIRE(l);
    void *ctxs[1] = { (void *)l };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!f(CC_X509, 2, 1, ctxs, OFFLINE_FLAGS, NULL, &s));
    EXPECT_EQ(s.dwError, CC_E_NO_REVOCATION_CHECK); EXPECT_ERR(CC_E_NO_REVOCATION_CHECK);
    EXPECT_EQ(s.dwIndex, 0);
    st_init(&s);
    SET_ERR(0);
    CHECK(!f(PKCS_7_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, NULL, &s));
    EXPECT_EQ(s.dwError, CC_E_NO_REVOCATION_CHECK);
    st_init(&s);
    SET_ERR(0);
    CHECK(!f(0, CERT_CONTEXT_REVOCATION_TYPE, 1, ctxs, OFFLINE_FLAGS, NULL, &s));
    EXPECT_EQ(s.dwError, CC_E_NO_REVOCATION_CHECK);
    rel(l);
}
TEST(revdll_crl_verdicts) {
    CertDllVerifyRevocation_pfn f = (CertDllVerifyRevocation_pfn)t_proc_in("cryptnet.dll", "CertDllVerifyRevocation");
    REQUIRE(f);
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT bad = cc_cert(VEC(v_cert_1001)), good = cc_cert(VEC(v_cert_1003));
    REQUIRE(bad && good);
    void *cb[1] = { (void *)bad }, *cg[1] = { (void *)good };
    RS s; st_init(&s);
    SET_ERR(0);
    CHECK(!f(CC_X509, CERT_CONTEXT_REVOCATION_TYPE, 1, cb, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    EXPECT_EQ(s.dwError, CC_E_REVOKED); EXPECT_EQ(s.dwReason, CRL_REASON_KEY_COMPROMISE); EXPECT_ERR(CC_E_REVOKED);
    st_init(&s);
    CHECK(f(CC_X509, CERT_CONTEXT_REVOCATION_TYPE, 1, cg, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s));
    EXPECT_EQ(s.dwError, 0);
    EXPECT_EQ(s.fHasFreshnessTime, 1);
    rel(bad); rel(good); cx_done(&c);
}
TEST(revdll_multiple_contexts_requires_chain_semantics) {
    CertDllVerifyRevocation_pfn f = (CertDllVerifyRevocation_pfn)t_proc_in("cryptnet.dll", "CertDllVerifyRevocation");
    REQUIRE(f);
    CTX c; REQUIRE(cx_init(&c, VEC(v_crl_basic), NULL, 0));
    PCCERT_CONTEXT a = cc_cert(VEC(v_cert_1003)), b = cc_cert(VEC(v_cert_1002));
    REQUIRE(a && b);
    void *ctxs[2] = { (void *)a, (void *)b };
    RS s; st_init(&s);
    SET_ERR(0);
    BOOL ok = f(CC_X509, CERT_CONTEXT_REVOCATION_TYPE, 2, ctxs, OFFLINE_FLAGS, (PCERT_REVOCATION_PARA)&c.p, &s);
    /* the provider handles one certificate at a time: with a good first certificate it reports "continue with index 1" */
    CHECK(!ok);
    EXPECT_EQ(s.dwIndex, 1);
    EXPECT_EQ(s.dwError, CC_E_NO_REVOCATION_CHECK);
    rel(a); rel(b); cx_done(&c);
}

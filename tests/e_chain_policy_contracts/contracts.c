/* Chain-build status vs. policy result, kept apart. Synthetic fixtures only; chains are built with URL retrieval
 * restricted to the cache (no network).  A TRUE return from CertVerifyCertificateChainPolicy only says the policy ran. */
#include "cp.h"
#include "urlvec.h"

#define F_URL_CACHE   CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
#define F_REV_CACHE   CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
#define F_REV_CHAIN   CERT_CHAIN_REVOCATION_CHECK_CHAIN
#define F_REV_END     CERT_CHAIN_REVOCATION_CHECK_END_CERT

typedef struct {
    int built;
    DWORD cerr, cinfo;      /* chain context TrustStatus */
    DWORD serr, sinfo;      /* simple chain 0 TrustStatus */
    DWORD cElem;
    DWORD eerr[6];          /* per element error status */
    DWORD rev[6];           /* per element revocation result (0 if no info) */
    PRES base;
} OBS;

static HCERTSTORE emptystore(void) {
    return U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
}

/* Build with exactly the given chain flags (no implicit URL-cache flag), at y/m/d. */
static PCCERT_CHAIN_CONTEXT build(int leaf, DWORD flags, HCERTSTORE add, int y, int m, int d) {
    CERT_CHAIN_PARA para; FILETIME ft; PCCERT_CHAIN_CONTEXT ctx = NULL;
    PCCERT_CONTEXT lc = cp_cert(leaf);
    if (!lc) return NULL;
    memset(&para, 0, sizeof para); para.cbSize = sizeof para;
    cp_time(&ft, y, m, d);
    if (!U(CertGetCertificateChain)(cp_engine_trusted(), lc, &ft, add, &para, flags, NULL, &ctx)) return NULL;
    return ctx;
}

static void observe(OBS *o, PCCERT_CHAIN_CONTEXT c, DWORD polflags) {
    memset(o, 0, sizeof *o);
    if (!c) return;
    o->built = 1;
    o->cerr = c->TrustStatus.dwErrorStatus; o->cinfo = c->TrustStatus.dwInfoStatus;
    if (c->cChain >= 1) {
        PCERT_SIMPLE_CHAIN sc = c->rgpChain[0];
        o->serr = sc->TrustStatus.dwErrorStatus; o->sinfo = sc->TrustStatus.dwInfoStatus;
        o->cElem = sc->cElement;
        for (DWORD i = 0; i < sc->cElement && i < 6; i++) {
            o->eerr[i] = sc->rgpElement[i]->TrustStatus.dwErrorStatus;
            o->rev[i] = sc->rgpElement[i]->pRevocationInfo ? sc->rgpElement[i]->pRevocationInfo->dwRevocationResult : 0;
        }
    }
    o->base = cp_run(CERT_CHAIN_POLICY_BASE, c, polflags, NULL);
}

static void dump(const char *tag, const OBS *o) {
    t_note("OBS %s built=%d chain(err=0x%lx info=0x%lx) simple(err=0x%lx info=0x%lx) n=%lu e0=0x%lx/%lx e1=0x%lx/%lx e2=0x%lx/%lx | policy ret=%d gle=%lu dwError=0x%lx ci=%ld ei=%ld",
           tag, o->built, o->cerr, o->cinfo, o->serr, o->sinfo, o->cElem, o->eerr[0], o->rev[0], o->eerr[1], o->rev[1], o->eerr[2], o->rev[2],
           o->base.ret, o->base.gle, o->base.err, (long)o->base.ci, (long)o->base.ei);
}

/* ---- URL-bearing fixtures (own root, own engine) ---- */
static PCCERT_CONTEXT ucert(int i) {
    static PCCERT_CONTEXT c[U__COUNT];
    if (!c[i]) c[i] = U(CertCreateCertificateContext)(X509_ASN_ENCODING, g_ucerts[i].p, g_ucerts[i].n);
    return c[i];
}
static HCERTCHAINENGINE uengine(void) {
    static HCERTCHAINENGINE e;
    if (!e) {
        CERT_CHAIN_ENGINE_CONFIG cfg; HCERTSTORE r = emptystore();
        U(CertAddCertificateContextToStore)(r, ucert(U_ROOT), CERT_STORE_ADD_ALWAYS, NULL);
        memset(&cfg, 0, sizeof cfg); cfg.cbSize = offsetof(CERT_CHAIN_ENGINE_CONFIG, dwExclusiveFlags); cfg.hExclusiveRoot = r;
        if (!U(CertCreateCertificateChainEngine)(&cfg, &e)) e = NULL;
    }
    return e;
}
static PCCERT_CHAIN_CONTEXT ubuild(int leaf, DWORD flags, int with_inter) {
    CERT_CHAIN_PARA para; FILETIME ft; PCCERT_CHAIN_CONTEXT ctx = NULL; HCERTSTORE add = emptystore();
    if (with_inter) U(CertAddCertificateContextToStore)(add, ucert(U_INTER), CERT_STORE_ADD_ALWAYS, NULL);
    memset(&para, 0, sizeof para); para.cbSize = sizeof para; cp_time(&ft, 2024, 6, 1);
    if (!U(CertGetCertificateChain)(uengine(), ucert(leaf), &ft, add, &para, flags, NULL, &ctx)) ctx = NULL;
    U(CertCloseStore)(add, 0);
    return ctx;
}

/* Expected observation. Chain TrustStatus (context and simple chain) and per-element status are compared independently
 * of the policy result: ret says only that the policy ran. */
typedef struct {
    DWORD cerr, cinfo, serr, sinfo, nel;
    DWORD e0, e1, e2;      /* element error status */
    DWORD r0, r1;          /* element revocation result (0: none / good) */
    DWORD perr; LONG pci, pei;   /* policy status */
} EXP;

static void verify(const char *tag, const OBS *o, const EXP *x) {
    t_label("%s", tag);
    CHECK(o->built);
    CHECKF(o->cerr == x->cerr, "chain dwErrorStatus 0x%lx want 0x%lx", o->cerr, x->cerr);
    CHECKF(o->cinfo == x->cinfo, "chain dwInfoStatus 0x%lx want 0x%lx", o->cinfo, x->cinfo);
    CHECKF(o->serr == x->serr, "simple chain dwErrorStatus 0x%lx want 0x%lx", o->serr, x->serr);
    CHECKF(o->sinfo == x->sinfo, "simple chain dwInfoStatus 0x%lx want 0x%lx", o->sinfo, x->sinfo);
    CHECKF(o->cElem == x->nel, "element count %lu want %lu", o->cElem, x->nel);
    CHECKF(o->eerr[0] == x->e0, "element 0 status 0x%lx want 0x%lx", o->eerr[0], x->e0);
    CHECKF(o->eerr[1] == x->e1, "element 1 status 0x%lx want 0x%lx", o->eerr[1], x->e1);
    CHECKF(o->eerr[2] == x->e2, "element 2 status 0x%lx want 0x%lx", o->eerr[2], x->e2);
    CHECKF(o->rev[0] == x->r0, "element 0 revocation result 0x%lx want 0x%lx", o->rev[0], x->r0);
    CHECKF(o->rev[1] == x->r1, "element 1 revocation result 0x%lx want 0x%lx", o->rev[1], x->r1);
    /* BOOL TRUE = the policy ran, whatever the verdict */
    CHECKF(o->base.ret == TRUE, "policy BOOL %d want TRUE", o->base.ret);
    CHECKF(o->base.err == x->perr, "policy dwError 0x%lx want 0x%lx", o->base.err, x->perr);
    CHECKF(o->base.ci == x->pci, "policy lChainIndex %ld want %ld", (long)o->base.ci, (long)x->pci);
    CHECKF(o->base.ei == x->pei, "policy lElementIndex %ld want %ld", (long)o->base.ei, (long)x->pei);
    CHECKF(o->base.ssz == sizeof(CERT_CHAIN_POLICY_STATUS), "status cbSize %lu", o->base.ssz);
    t_label(NULL);
}

static void run_main(const char *tag, int leaf, DWORD flags, int store, int y, DWORD polflags, const EXP *x) {
    OBS o; PCCERT_CHAIN_CONTEXT c;
    HCERTSTORE add = store == 1 ? emptystore() : store == 2 ? cp_addstore_crl() : cp_addstore();
    c = build(leaf, flags, add, y, 6, 1);
    observe(&o, c, polflags);
    verify(tag, &o, x);
    cp_free(c);
}
static void run_url(const char *tag, int leaf, DWORD flags, int with_inter, DWORD polflags, const EXP *x) {
    OBS o; PCCERT_CHAIN_CONTEXT c = ubuild(leaf, flags, with_inter);
    observe(&o, c, polflags);
    verify(tag, &o, x);
    cp_free(c);
}

#define GOOD_CTX 0x2100u   /* info status of a complete chain to a trusted root */
#define PARTIAL  0x10000u  /* CERT_TRUST_IS_PARTIAL_CHAIN */
#define NOTIME   0x1u
#define REVUNK   0x40u
#define OFFLINE  0x1000000u

TEST(flag_values_are_distinct_bits) {
    CHECK(F_URL_CACHE == 0x4);
    CHECK(F_REV_CACHE == 0x80000000u);
    CHECK(F_REV_CHAIN == 0x20000000u);
    CHECK(F_REV_END == 0x10000000u);
    CHECK((F_URL_CACHE & F_REV_CACHE) == 0);
}

/* (1) missing intermediate, nothing retrievable */
TEST(missing_intermediate_empty_cache_is_partial_chain) {
    static const EXP x = {PARTIAL, 0, PARTIAL, 0, 1, 0, 0, 0, 0, 0, 0x800B010A, 0, -1};
    NEED_ENV();
    run_main("orphan, empty additional store", C_ORPHAN, F_URL_CACHE, 1, 2024, 0, &x);
    run_main("orphan, store without its issuer", C_ORPHAN, F_URL_CACHE, 0, 2024, 0, &x);
    run_url("orphan with issuer URL, empty retrieval cache", U_ORPHAN, F_URL_CACHE, 0, 0, &x);
    run_url("leaf with issuer URL, issuer not supplied", U_LEAF, F_URL_CACHE, 0, 0, &x);
}
TEST(missing_intermediate_policy_error_wins_over_revocation_status) {
    /* the chain also carries revocation-offline status for the leaf; the BASE verdict stays the chaining error */
    static const EXP x = {PARTIAL | OFFLINE | REVUNK, 0, PARTIAL | OFFLINE | REVUNK, 0, 1, OFFLINE | REVUNK, 0, 0, 0x80092013, 0, 0x800B010A, 0, -1};
    NEED_ENV();
    run_url("orphan, revocation requested, cache only", U_ORPHAN, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 0, 0, &x);
    run_url("leaf, issuer missing, revocation requested", U_LEAF, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 0, 0, &x);
}

/* (2) trusted chain, revocation requested, no usable cached evidence: not a good verdict */
TEST(good_chain_without_revocation_request_has_clean_status) {
    static const EXP x = {0, GOOD_CTX, 0, GOOD_CTX, 3, 0, 0, 0, 0, 0, 0, -1, -1};
    NEED_ENV();
    run_main("srv, no revocation", C_SRV, F_URL_CACHE, 0, 2024, 0, &x);
    run_url("url fixture, no revocation, retrieval cache only", U_LEAF, F_URL_CACHE, 1, 0, &x);
}
TEST(revocation_without_cdp_is_no_revocation_check) {
    static const EXP x = {REVUNK, GOOD_CTX, REVUNK, GOOD_CTX, 3, REVUNK, REVUNK, 0, 0x80092012, 0x80092012, 0x80092012, 0, 0};
    NEED_ENV();
    run_main("whole chain, URL cache only", C_SRV, F_REV_CHAIN | F_URL_CACHE, 0, 2024, 0, &x);
    run_main("whole chain, revocation cache only", C_SRV, F_REV_CHAIN | F_REV_CACHE, 0, 2024, 0, &x);
    run_main("whole chain, both cache flags", C_SRV, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 0, 2024, 0, &x);
}
TEST(revocation_end_cert_only_checks_element_zero) {
    static const EXP x = {REVUNK, GOOD_CTX, REVUNK, GOOD_CTX, 3, REVUNK, 0, 0, 0x80092012, 0, 0x80092012, 0, 0};
    NEED_ENV();
    run_main("end cert, URL cache only", C_SRV, F_REV_END | F_URL_CACHE, 0, 2024, 0, &x);
    run_main("end cert, both cache flags", C_SRV, F_REV_END | F_URL_CACHE | F_REV_CACHE, 0, 2024, 0, &x);
}
TEST(revocation_offline_with_cdp_is_distinct_from_no_check) {
    /* URLs present, nothing cached: revocation offline (0x80092013 / chain bit 0x1000000), not "no check" */
    static const EXP x = {OFFLINE | REVUNK, GOOD_CTX, OFFLINE | REVUNK, GOOD_CTX, 3, OFFLINE | REVUNK, OFFLINE | REVUNK, 0, 0x80092013, 0x80092013, 0x80092013, 0, 0};
    static const EXP xe = {OFFLINE | REVUNK, GOOD_CTX, OFFLINE | REVUNK, GOOD_CTX, 3, OFFLINE | REVUNK, 0, 0, 0x80092013, 0, 0x80092013, 0, 0};
    NEED_ENV();
    run_url("whole chain, revocation cache only", U_LEAF, F_REV_CHAIN | F_REV_CACHE, 1, 0, &x);
    run_url("whole chain, both cache flags", U_LEAF, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 1, 0, &x);
    run_url("end cert, revocation cache only", U_LEAF, F_REV_END | F_REV_CACHE, 1, 0, &xe);
}
TEST(revocation_unknown_never_equals_good_verdict) {
    OBS g, r; PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = build(C_SRV, F_URL_CACHE, cp_addstore(), 2024, 6, 1); observe(&g, c, 0); cp_free(c);
    c = build(C_SRV, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, cp_addstore(), 2024, 6, 1); observe(&r, c, 0); cp_free(c);
    CHECK(g.base.ret == TRUE && r.base.ret == TRUE);        /* both: policy ran */
    CHECK(g.base.err == 0 && g.base.ci == -1 && g.base.ei == -1);
    CHECK(r.base.err != g.base.err && r.base.ci != g.base.ci);
    CHECK(g.cerr == 0 && r.cerr == REVUNK);
}
TEST(revocation_unknown_ignore_flags_in_base_policy) {
    static const EXP x_all = {REVUNK, GOOD_CTX, REVUNK, GOOD_CTX, 3, REVUNK, REVUNK, 0, 0x80092012, 0x80092012, 0, -1, -1};
    static const EXP x_end = {REVUNK, GOOD_CTX, REVUNK, GOOD_CTX, 3, REVUNK, REVUNK, 0, 0x80092012, 0x80092012, 0x80092012, 0, 1};
    NEED_ENV();
    run_main("ignore all unknown revocation", C_SRV, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 0, 2024, 0xF00, &x_all);
    run_main("ignore end-cert unknown only: CA remains", C_SRV, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 0, 2024, 0x100, &x_end);
}
TEST(cached_crl_from_store_vs_missing_cdp) {
    /* CRL in the supplied store covers the leaf but the issuer's own status is still unknown (element 1) */
    static const EXP xg = {REVUNK, GOOD_CTX, REVUNK, GOOD_CTX, 3, 0, REVUNK, 0, 0, 0x80092012, 0x80092012, 0, 1};
    static const EXP xr = {0x44, GOOD_CTX, 0x44, GOOD_CTX, 3, 0x4, REVUNK, 0, 0x80092010, 0x80092012, 0x80092010, 0, 0};
    NEED_ENV();
    run_main("good leaf, CRL in store", C_SRV, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 2, 2024, 0, &xg);
    run_main("revoked leaf, CRL in store", C_REVOKED, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 2, 2024, 0, &xr);
    run_main("revoked leaf, ignore unknown does not hide revoked", C_REVOKED, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 2, 2024, 0xF00, &xr);
}

/* (3) expired leaf, otherwise valid chain */
TEST(expired_leaf_valid_chain) {
    static const EXP x = {NOTIME, GOOD_CTX, NOTIME, GOOD_CTX, 3, NOTIME, 0, 0, 0, 0, 0x800B0101, 0, 0};
    static const EXP xi = {NOTIME, GOOD_CTX, NOTIME, GOOD_CTX, 3, NOTIME, 0, 0, 0, 0, 0, -1, -1};
    static const EXP xok = {0, GOOD_CTX, 0, GOOD_CTX, 3, 0, 0, 0, 0, 0, 0, -1, -1};
    NEED_ENV();
    run_main("expired at 2024", C_EXPIRED, F_URL_CACHE, 0, 2024, 0, &x);
    run_main("expired, ignore not-time-valid: chain status stays", C_EXPIRED, F_URL_CACHE, 0, 2024, 0x7, &xi);
    run_main("expired, ignore not-time-valid (single flag)", C_EXPIRED, F_URL_CACHE, 0, 2024, 0x1, &xi);
    run_main("same leaf evaluated inside its validity", C_EXPIRED, F_URL_CACHE, 0, 2020, 0, &xok);
}
TEST(expired_leaf_with_revocation_requested_reports_expiry_first) {
    static const EXP x = {NOTIME | REVUNK, GOOD_CTX, NOTIME | REVUNK, GOOD_CTX, 3, NOTIME | REVUNK, REVUNK, 0, 0x80092012, 0x80092012, 0x800B0101, 0, 0};
    NEED_ENV();
    run_main("expired + revocation requested", C_EXPIRED, F_REV_CHAIN | F_URL_CACHE | F_REV_CACHE, 0, 2024, 0, &x);
}

/* ---- harness boundary ---- */

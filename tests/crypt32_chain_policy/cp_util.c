#include "cp.h"

static PCCERT_CONTEXT g_ctx[C__COUNT];
PCCERT_CONTEXT cp_cert(int idx) {
    if (idx < 0 || idx >= C__COUNT) return NULL;
    if (!g_ctx[idx] && U(CertCreateCertificateContext))
        g_ctx[idx] = U(CertCreateCertificateContext)(X509_ASN_ENCODING, g_certs[idx].p, g_certs[idx].n);
    return g_ctx[idx];
}
static HCERTSTORE mem(void) {
    return U(CertOpenStore) ? U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL) : NULL;
}
static void addc(HCERTSTORE s, int idx) {
    PCCERT_CONTEXT c = cp_cert(idx);
    if (c) U(CertAddCertificateContextToStore)(s, c, CERT_STORE_ADD_ALWAYS, NULL);
}
static HCERTSTORE g_add, g_addcrl, g_roots, g_empty, g_peers;
static void fill_add(HCERTSTORE s) {
    addc(s, C_ROOT); addc(s, C_ROOT2); addc(s, C_INTER); addc(s, C_INTSHORT); addc(s, C_INTER_EE);
    addc(s, C_INTER_NOBC); addc(s, C_INTER_PL0); addc(s, C_INTER_SUB);
}
HCERTSTORE cp_addstore(void) {
    if (!g_add && (g_add = mem())) fill_add(g_add);
    return g_add;
}
HCERTSTORE cp_addstore_crl(void) {
    if (!g_addcrl && (g_addcrl = mem())) {
        fill_add(g_addcrl);
        U(CertAddEncodedCRLToStore)(g_addcrl, X509_ASN_ENCODING, v_crl, sizeof v_crl, CERT_STORE_ADD_ALWAYS, NULL);
    }
    return g_addcrl;
}
static HCERTCHAINENGINE mkengine(HCERTSTORE roots, HCERTSTORE peers) {
    CERT_CHAIN_ENGINE_CONFIG cfg; HCERTCHAINENGINE e = NULL;
    memset(&cfg, 0, sizeof cfg);
    cfg.cbSize = sizeof cfg;
    cfg.hExclusiveRoot = roots;
    cfg.hExclusiveTrustedPeople = peers;
    cfg.dwUrlRetrievalTimeout = 0;
    if (!U(CertCreateCertificateChainEngine) || !U(CertCreateCertificateChainEngine)(&cfg, &e)) return NULL;
    return e;
}
static HCERTCHAINENGINE g_eng_t, g_eng_e;
HCERTCHAINENGINE cp_engine_trusted(void) {
    if (!g_eng_t) { g_roots = mem(); if (g_roots) { addc(g_roots, C_ROOT); g_eng_t = mkengine(g_roots, NULL); } }
    return g_eng_t;
}
HCERTCHAINENGINE cp_engine_empty(void) {
    if (!g_eng_e) { g_empty = mem(); if (g_empty) g_eng_e = mkengine(g_empty, NULL); }
    return g_eng_e;
}
HCERTCHAINENGINE cp_engine_peer(int leaf) {
    HCERTSTORE p = mem(); if (!p) return NULL;
    addc(p, leaf);
    cp_engine_trusted();
    return mkengine(g_roots, p);       /* intentionally not cached; leaked until process exit */
}
void cp_time(FILETIME *ft, int y, int m, int d) {
    SYSTEMTIME st; memset(&st, 0, sizeof st); st.wYear = y; st.wMonth = m; st.wDay = d; st.wHour = 12;
    SystemTimeToFileTime(&st, ft);
}
PCCERT_CHAIN_CONTEXT cp_chain_ex(HCERTCHAINENGINE eng, int leaf, DWORD flags, HCERTSTORE add, LPCSTR usage, int y) {
    CERT_CHAIN_PARA para; FILETIME ft; PCCERT_CHAIN_CONTEXT ctx = NULL; LPSTR ids[1];
    PCCERT_CONTEXT lc = cp_cert(leaf);
    if (!lc || !U(CertGetCertificateChain)) return NULL;
    if (!eng) eng = cp_engine_trusted();
    if (!add) add = cp_addstore();
    memset(&para, 0, sizeof para); para.cbSize = sizeof para;
    if (usage) {
        ids[0] = (LPSTR)usage;
        para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        para.RequestedUsage.Usage.cUsageIdentifier = 1;
        para.RequestedUsage.Usage.rgpszUsageIdentifier = ids;
    }
    cp_time(&ft, y ? y : 2024, 6, 1);
    if (!U(CertGetCertificateChain)(eng, lc, &ft, add, &para, flags | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL, &ctx)) return NULL;
    return ctx;
}
PCCERT_CHAIN_CONTEXT cp_chain(int leaf) { return cp_chain_ex(NULL, leaf, 0, NULL, NULL, 0); }
void cp_free(PCCERT_CHAIN_CONTEXT c) { if (c) U(CertFreeCertificateChain)(c); }

PRES cp_run_ex(LPCSTR oid, PCCERT_CHAIN_CONTEXT c, DWORD para_cb, DWORD flags, void *extra, DWORD status_cb, void *extra_status) {
    CERT_CHAIN_POLICY_PARA p; CERT_CHAIN_POLICY_STATUS s; PRES r;
    memset(&p, 0, sizeof p); p.cbSize = para_cb; p.dwFlags = flags; p.pvExtraPolicyPara = extra;
    memset(&s, 0, sizeof s); s.cbSize = status_cb; s.dwError = 0xDEADBEEF; s.lChainIndex = 0x7777; s.lElementIndex = 0x6666;
    s.pvExtraPolicyStatus = extra_status;
    SetLastError(0xABCD0001);
    r.ret = U(CertVerifyCertificateChainPolicy)(oid, c, &p, &s);
    r.gle = GetLastError();
    r.err = s.dwError; r.ci = s.lChainIndex; r.ei = s.lElementIndex; r.ssz = s.cbSize;
    return r;
}
PRES cp_run(LPCSTR oid, PCCERT_CHAIN_CONTEXT c, DWORD flags, void *extra) {
    return cp_run_ex(oid, c, sizeof(CERT_CHAIN_POLICY_PARA), flags, extra, sizeof(CERT_CHAIN_POLICY_STATUS), NULL);
}

void syn_init(SYN *s, int nchain, const int *nel) {
    memset(s, 0, sizeof *s);
    s->cc.cbSize = sizeof s->cc;
    s->cc.cChain = nchain;
    s->cc.rgpChain = s->pc;
    for (int i = 0; i < nchain; i++) {
        s->pc[i] = &s->sc[i];
        s->sc[i].cbSize = sizeof s->sc[i];
        s->sc[i].cElement = nel[i];
        s->sc[i].rgpElement = s->pe[i];
        for (int j = 0; j < nel[i]; j++) {
            s->pe[i][j] = &s->el[i][j];
            s->el[i][j].cbSize = sizeof s->el[i][j];
            s->el[i][j].pCertContext = cp_cert(j == nel[i] - 1 ? C_ROOT : C_SRV);
        }
    }
}
void syn_el(SYN *s, int c, int e, DWORD err, DWORD info) {
    s->el[c][e].TrustStatus.dwErrorStatus = err; s->el[c][e].TrustStatus.dwInfoStatus = info;
}
void syn_ctx(SYN *s, DWORD err, DWORD info) { s->cc.TrustStatus.dwErrorStatus = err; s->cc.TrustStatus.dwInfoStatus = info; }
void syn_chain(SYN *s, int c, DWORD err, DWORD info) { s->sc[c].TrustStatus.dwErrorStatus = err; s->sc[c].TrustStatus.dwInfoStatus = info; }
void syn_rev(SYN *s, int c, int e, DWORD result) {
    s->ri[c][e].cbSize = sizeof s->ri[c][e];
    s->ri[c][e].dwRevocationResult = result;
    s->el[c][e].pRevocationInfo = &s->ri[c][e];
}

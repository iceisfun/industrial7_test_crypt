#include "pkiutil.h"

const PKI_ITEM *pki_find(const char *id) {
    for (const PKI_ITEM *p = pki_items; p->id; p++) if (!strcmp(p->id, id)) return p;
    return NULL;
}
FILETIME pki_ft(int y, int mo, int d, int h, int mi, int s) {
    SYSTEMTIME st = {0}; FILETIME ft = {0};
    st.wYear = y; st.wMonth = mo; st.wDay = d; st.wHour = h; st.wMinute = mi; st.wSecond = s;
    SystemTimeToFileTime(&st, &ft);
    return ft;
}
PCCERT_CONTEXT pki_cert(const char *id) {
    const PKI_ITEM *p = pki_find(id);
    if (!p) return NULL;
    return U(CertCreateCertificateContext)(ENC, p->der, p->len);
}
HCERTSTORE pki_store(const char *ids) {
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!s) return NULL;
    if (!ids) return s;
    char buf[1024]; lstrcpynA(buf, ids, sizeof buf);
    for (char *tok = strtok(buf, " "); tok; tok = strtok(NULL, " ")) {
        const PKI_ITEM *p = pki_find(tok);
        if (!p) { t_note("pki_store: unknown id %s", tok); continue; }
        BOOL ok;
        if (!strncmp(tok, "crl_", 4)) ok = U(CertAddEncodedCRLToStore)(s, ENC, p->der, p->len, CERT_STORE_ADD_ALWAYS, NULL);
        else ok = U(CertAddEncodedCertificateToStore)(s, ENC, p->der, p->len, CERT_STORE_ADD_ALWAYS, NULL);
        if (!ok) t_note("pki_store: add %s failed %lu", tok, GetLastError());
    }
    return s;
}
/* Custom trust anchors need exclusive trust mode: hRestrictedRoot must be a subset of the system Root store,
 * so a private test root can only be trusted through hExclusiveRoot.  roots -> hExclusiveRoot,
 * trust -> hExclusiveTrustedPeople, others -> rghAdditionalStore.  A NULL list means "no such store". */
BOOL pki_eng_open(PKI_ENG *e, const char *roots, const char *others, const char *trust, DWORD engflags) {
    return pki_eng_open_ex(e, roots, others, trust, engflags, 0, 0);
}
BOOL pki_eng_open_ex(PKI_ENG *e, const char *roots, const char *others, const char *trust, DWORD engflags, DWORD maxcache, DWORD cycle) {
    memset(e, 0, sizeof *e);
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg);
    cfg.cbSize = sizeof cfg;
    if (roots) { e->root = pki_store(roots); cfg.hExclusiveRoot = e->root; }
    if (trust) { e->trust = pki_store(trust); cfg.hExclusiveTrustedPeople = e->trust; }
    if (others) { e->other = pki_store(others); cfg.cAdditionalStore = 1; cfg.rghAdditionalStore = &e->other; }
    cfg.dwFlags = engflags;
    cfg.dwUrlRetrievalTimeout = 0; cfg.MaximumCachedCertificates = maxcache; cfg.CycleDetectionModulus = cycle;
    BOOL ok = U(CertCreateCertificateChainEngine)(&cfg, &e->h);
    if (!ok && t_is_wine()) {
        /* emulator without exclusive trust mode: fall back to a restricted root (validation aid only) */
        memset(&cfg, 0, sizeof cfg); cfg.cbSize = 0x50;
        cfg.hRestrictedRoot = e->root; cfg.hRestrictedTrust = e->trust; cfg.hRestrictedOther = e->other;
        if (e->other) { cfg.cAdditionalStore = 1; cfg.rghAdditionalStore = &e->other; }
        cfg.dwFlags = engflags; cfg.MaximumCachedCertificates = maxcache; cfg.CycleDetectionModulus = cycle;
        ok = U(CertCreateCertificateChainEngine)(&cfg, &e->h);
    }
    if (!ok) t_note("engine creation failed: 0x%lx", GetLastError());
    return ok;
}
/* classic restricted mode: rootcert (may be NULL) is added as the only hRestrictedRoot certificate */
BOOL pki_eng_open_restricted(PKI_ENG *e, PCCERT_CONTEXT rootcert, int with_root_store, const char *others, const char *trust, DWORD engflags) {
    memset(e, 0, sizeof *e);
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg);
    cfg.cbSize = CFG_CB;
    if (with_root_store) {
        e->root = pki_store(NULL);
        if (rootcert) U(CertAddCertificateContextToStore)(e->root, rootcert, CERT_STORE_ADD_ALWAYS, NULL);
        cfg.hRestrictedRoot = e->root;
    }
    if (trust) { e->trust = pki_store(trust); cfg.hRestrictedTrust = e->trust; }
    if (others) { e->other = pki_store(others); cfg.hRestrictedOther = e->other; }
    cfg.dwFlags = engflags;
    BOOL ok = U(CertCreateCertificateChainEngine)(&cfg, &e->h);
    return ok;
}
/* first certificate of the current user's system Root store (duplicate), or NULL */
PCCERT_CONTEXT pki_first_system_root(void) {
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG, L"Root");
    if (!s) return NULL;
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(s, NULL);
    PCCERT_CONTEXT out = NULL;
    if (c) {   /* detach from the system store: copy into a standalone context */
        out = U(CertCreateCertificateContext)(c->dwCertEncodingType, c->pbCertEncoded, c->cbCertEncoded);
        U(CertFreeCertificateContext)(c);
    }
    U(CertCloseStore)(s, 0);
    return out;
}
void pki_eng_close(PKI_ENG *e) {
    if (e->h) U(CertFreeCertificateChainEngine)(e->h);
    if (e->root) U(CertCloseStore)(e->root, 0);
    if (e->trust) U(CertCloseStore)(e->trust, 0);
    if (e->other) U(CertCloseStore)(e->other, 0);
    memset(e, 0, sizeof *e);
}
PCCERT_CHAIN_CONTEXT pki_chain(HCERTCHAINENGINE eng, const char *leaf, const char *addl, int y, int mo, int d, int h, int mi, int s,
                               DWORD flags, CERT_CHAIN_PARA *para) {
    PCCERT_CONTEXT c = pki_cert(leaf);
    if (!c) return NULL;
    HCERTSTORE as = addl ? pki_store(addl) : NULL;
    FILETIME ft = y ? pki_ft(y, mo, d, h, mi, s) : (FILETIME){0};
    CERT_CHAIN_PARA def; memset(&def, 0, sizeof def); def.cbSize = sizeof def;
    PCCERT_CHAIN_CONTEXT out = NULL;
    BOOL ok = U(CertGetCertificateChain)(eng, c, y ? &ft : NULL, as, para ? para : &def, flags, NULL, &out);
    if (!ok) { t_note("CertGetCertificateChain(%s) failed 0x%lx", leaf, GetLastError()); out = NULL; }
    if (as) U(CertCloseStore)(as, 0);
    U(CertFreeCertificateContext)(c);
    return out;
}
PCCERT_CHAIN_CONTEXT pki_chain_para(HCERTCHAINENGINE eng, const char *leaf, const char *addl, int y, int mo, int d, int h, int mi, int s,
                               DWORD flags, int usage_and, int n_usage, const char **usage) {
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    p.RequestedUsage.dwType = usage_and ? USAGE_MATCH_TYPE_AND : USAGE_MATCH_TYPE_OR;
    p.RequestedUsage.Usage.cUsageIdentifier = n_usage;
    p.RequestedUsage.Usage.rgpszUsageIdentifier = (LPSTR *)usage;
    return pki_chain(eng, leaf, addl, y, mo, d, h, mi, s, flags, &p);
}
void pki_chain_free(PCCERT_CHAIN_CONTEXT c) { if (c) U(CertFreeCertificateChain)(c); }
const char *pki_id_of(PCCERT_CONTEXT c) {
    if (!c) return NULL;
    for (const PKI_ITEM *p = pki_items; p->id; p++)
        if (p->len == c->cbCertEncoded && !memcmp(p->der, c->pbCertEncoded, p->len)) return p->id;
    return NULL;
}
const char *pki_elem_id(PCCERT_CHAIN_CONTEXT c, int chain, int elem) {
    if (!c || chain >= (int)c->cChain) return NULL;
    PCERT_SIMPLE_CHAIN sc = c->rgpChain[chain];
    if (elem >= (int)sc->cElement) return NULL;
    const char *id = pki_id_of(sc->rgpElement[elem]->pCertContext);
    return id ? id : "?";
}
DWORD pki_nelem(PCCERT_CHAIN_CONTEXT c, int chain) { return (c && chain < (int)c->cChain) ? c->rgpChain[chain]->cElement : 0xffffffff; }
DWORD pki_elem_err(PCCERT_CHAIN_CONTEXT c, int chain, int elem) { return c->rgpChain[chain]->rgpElement[elem]->TrustStatus.dwErrorStatus; }
DWORD pki_elem_info(PCCERT_CHAIN_CONTEXT c, int chain, int elem) { return c->rgpChain[chain]->rgpElement[elem]->TrustStatus.dwInfoStatus; }
void pki_note_chain(const char *tag, PCCERT_CHAIN_CONTEXT c) {
    if (!c) { t_note("%s: no chain", tag); return; }
    char buf[512]; int n = snprintf(buf, sizeof buf, "chain err=0x%lx info=0x%lx cChain=%lu:", c->TrustStatus.dwErrorStatus, c->TrustStatus.dwInfoStatus, c->cChain);
    for (DWORD i = 0; i < c->cChain && n < 400; i++) {
        PCERT_SIMPLE_CHAIN sc = c->rgpChain[i];
        n += snprintf(buf + n, sizeof buf - n, " [");
        for (DWORD j = 0; j < sc->cElement && n < 450; j++)
            n += snprintf(buf + n, sizeof buf - n, "%s(e%lx,i%lx) ", pki_elem_id(c, i, j), sc->rgpElement[j]->TrustStatus.dwErrorStatus, sc->rgpElement[j]->TrustStatus.dwInfoStatus);
        n += snprintf(buf + n, sizeof buf - n, "]");
    }
    t_note("%s: %s", tag, buf);
}
void pki_scenario(const char *tag, const char *leaf, const char *roots, const char *others, const char *addl,
                  int y, int mo, int d, int h, int mi, int s, DWORD flags, DWORD want_err, DWORD want_nelem) {
    PKI_ENG e;
    if (!pki_eng_open(&e, roots, others, NULL, 0)) { CHECKF(0, "%s: engine", tag); return; }
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, leaf, addl, y, mo, d, h, mi, s, flags | PKI_OFFLINE, NULL);
    CHECKF(c != NULL, "%s: chain built", tag);
    if (c) {
        pki_note_chain(tag, c);
        CHECKF(c->cChain >= 1, "%s: cChain", tag);
        if (c->cChain >= 1) {
            CHECKF(c->TrustStatus.dwErrorStatus == want_err, "%s: chain error got 0x%lx want 0x%lx", tag, c->TrustStatus.dwErrorStatus, want_err);
            CHECKF(c->rgpChain[0]->cElement == want_nelem, "%s: elements got %lu want %lu", tag, c->rgpChain[0]->cElement, want_nelem);
            CHECKF(c->rgpChain[0]->TrustStatus.dwErrorStatus == want_err, "%s: simple chain error got 0x%lx", tag, c->rgpChain[0]->TrustStatus.dwErrorStatus);
            const char *id0 = pki_elem_id(c, 0, 0);
            CHECKF(id0 && !strcmp(id0, leaf), "%s: element 0 is the end cert (%s)", tag, id0 ? id0 : "null");
        }
    }
    pki_chain_free(c);
    pki_eng_close(&e);
}

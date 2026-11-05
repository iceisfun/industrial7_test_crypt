/* Shared helpers for the crypt32_chain_policy area. Every crypt32 call goes through GetProcAddress. */
#ifndef CP_H
#define CP_H
#include "t.h"
#include <wincrypt.h>
#include "vectors.h"

#define CERR_UNTRUSTEDROOT   0x800B0109u
#define CERR_CHAINING        0x800B010Au
#define CERR_EXPIRED         0x800B0101u
#define CERR_VALIDITYNEST    0x800B0102u
#define CERR_ROLE            0x800B0103u
#define CERR_PURPOSE         0x800B0106u
#define CERR_UNTRUSTEDTESTROOT 0x800B010Du
#define CERR_REVOCATION_FAIL 0x800B010Eu
#define CERR_CN_NO_MATCH     0x800B010Fu
#define CERR_WRONG_USAGE     0x800B0110u
#define CERR_UNTRUSTEDCA     0x800B0112u
#define CERR_INVALID_POLICY  0x800B0113u
#define CERR_INVALID_NAME    0x800B0114u
#define CERR_CRITICAL        0x800B0105u
#define CERR_REVOKED         0x800B010Cu
#define CRYPTERR_REVOKED     0x80092010u
#define CRYPTERR_NO_REVOCATION_CHECK 0x80092012u
#define CRYPTERR_REVOCATION_OFFLINE  0x80092013u
#define TERR_BASIC_CONSTRAINTS 0x80096019u
#define TERR_CERT_SIGNATURE  0x80096004u
#define EINVALIDARG_HR       0x80070057u

typedef struct { BOOL ret; DWORD gle; DWORD err; LONG ci, ei; DWORD ssz; } PRES;

PCCERT_CONTEXT cp_cert(int idx);                 /* cached context for vectors.h index (NULL on failure) */
HCERTSTORE cp_addstore(void);                    /* intermediates + roots + CRL (memory store) */
HCERTSTORE cp_addstore_crl(void);                /* same, plus the CRL revoking serial 0x7777 */
HCERTCHAINENGINE cp_engine_trusted(void);        /* exclusive root = {root}, no trusted people */
HCERTCHAINENGINE cp_engine_empty(void);          /* exclusive root = empty store */
HCERTCHAINENGINE cp_engine_peer(int leaf);       /* exclusive root = {root}, exclusive trusted people = {leaf} */
void cp_time(FILETIME *ft, int y, int m, int d); /* UTC date */
/* Build a chain offline. eng NULL -> trusted engine. flags added to CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL. */
PCCERT_CHAIN_CONTEXT cp_chain_ex(HCERTCHAINENGINE eng, int leaf, DWORD flags, HCERTSTORE add, LPCSTR usage, int y);
PCCERT_CHAIN_CONTEXT cp_chain(int leaf);         /* trusted engine, 2024-06-01, no revocation, no usage */
void cp_free(PCCERT_CHAIN_CONTEXT c);
/* Run a policy: para cbSize = sizeof, status cbSize = sizeof, status pre-filled with garbage. */
PRES cp_run(LPCSTR oid, PCCERT_CHAIN_CONTEXT c, DWORD flags, void *extra);
PRES cp_run_ex(LPCSTR oid, PCCERT_CHAIN_CONTEXT c, DWORD para_cb, DWORD flags, void *extra, DWORD status_cb, void *extra_status);

/* Synthetic chain context: only the fields the policies read. */
#define SYN_MAXC 3
#define SYN_MAXE 5
typedef struct {
    CERT_CHAIN_CONTEXT cc;
    PCERT_SIMPLE_CHAIN pc[SYN_MAXC];
    CERT_SIMPLE_CHAIN sc[SYN_MAXC];
    PCERT_CHAIN_ELEMENT pe[SYN_MAXC][SYN_MAXE];
    CERT_CHAIN_ELEMENT el[SYN_MAXC][SYN_MAXE];
    CERT_REVOCATION_INFO ri[SYN_MAXC][SYN_MAXE];
} SYN;
/* nel[i] = element count of chain i. Elements get real certificates (root for the last, srv for the rest). */
void syn_init(SYN *s, int nchain, const int *nel);
void syn_el(SYN *s, int c, int e, DWORD err, DWORD info);
void syn_ctx(SYN *s, DWORD err, DWORD info);
void syn_chain(SYN *s, int c, DWORD err, DWORD info);
void syn_rev(SYN *s, int c, int e, DWORD result);   /* attach revocation info with dwRevocationResult */

#define CPCERT(n) cp_cert(C_##n)
#define NEED_ENV() do { if (!U(CertGetCertificateChain) || !U(CertVerifyCertificateChainPolicy) || !cp_engine_trusted()) { t_skip("chain environment unavailable"); return; } } while (0)
#endif

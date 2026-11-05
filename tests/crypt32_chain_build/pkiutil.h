/* Helpers shared by the crypt32_chain_build tests.  Every crypt32 call goes through U(). */
#ifndef PKIUTIL_H
#define PKIUTIL_H
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS 1
#include "t.h"
#include <wincrypt.h>
#include "pki.h"

#define ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
/* flags that keep chain building off the wire */
#define PKI_OFFLINE (CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE)
#define REV_END_CACHE  (CERT_CHAIN_REVOCATION_CHECK_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY)
#define REV_CHAIN_CACHE (CERT_CHAIN_REVOCATION_CHECK_CHAIN | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY)
#define REV_XROOT_CACHE (CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY)

#define OID_SERVER  "1.3.6.1.5.5.7.3.1"
#define OID_CLIENT  "1.3.6.1.5.5.7.3.2"
#define OID_CODE    "1.3.6.1.5.5.7.3.3"
#define OID_EMAIL   "1.3.6.1.5.5.7.3.4"
#define OID_ANYEKU  "2.5.29.37.0"
#define OID_POL1    "1.3.6.1.4.1.99999.1"
#define OID_POL2    "1.3.6.1.4.1.99999.2"

/* a fixed evaluation time (2025-06-01 00:00:00 UTC) used by most scenarios */
#define PKI_T0 2025, 6, 1, 0, 0, 0
#define PKI_NOW 0, 0, 0, 0, 0, 0     /* y == 0 means pTime = NULL */

#define CFG_CB (t_is_wine() ? 0x50 : (DWORD)sizeof(CERT_CHAIN_ENGINE_CONFIG))   /* wine rejects the Win8 sized struct */
typedef struct {
    HCERTCHAINENGINE h;
    HCERTSTORE root, trust, other;
} PKI_ENG;

const PKI_ITEM *pki_find(const char *id);
FILETIME pki_ft(int y, int mo, int d, int h, int mi, int s);
PCCERT_CONTEXT pki_cert(const char *id);          /* standalone context, free with CertFreeCertificateContext */
HCERTSTORE pki_store(const char *ids);            /* memory store of space separated cert/crl ids; NULL ids -> empty */
/* engine in exclusive trust mode: roots/others/trust are id lists ("" = empty store, NULL = no store) */
BOOL pki_eng_open(PKI_ENG *e, const char *roots, const char *others, const char *trust, DWORD engflags);
BOOL pki_eng_open_ex(PKI_ENG *e, const char *roots, const char *others, const char *trust, DWORD engflags, DWORD maxcache, DWORD cycle);
BOOL pki_eng_open_restricted(PKI_ENG *e, PCCERT_CONTEXT rootcert, int with_root_store, const char *others, const char *trust, DWORD engflags);
PCCERT_CONTEXT pki_first_system_root(void);
void pki_eng_close(PKI_ENG *e);
/* build a chain for the cert `leaf`; addl = ids for hAdditionalStore (NULL = none); ft==0 -> NULL pTime */
PCCERT_CHAIN_CONTEXT pki_chain(HCERTCHAINENGINE eng, const char *leaf, const char *addl, int y, int mo, int d, int h, int mi, int s,
                               DWORD flags, CERT_CHAIN_PARA *para);
PCCERT_CHAIN_CONTEXT pki_chain_para(HCERTCHAINENGINE eng, const char *leaf, const char *addl, int y, int mo, int d, int h, int mi, int s,
                               DWORD flags, int usage_and, int n_usage, const char **usage);
void pki_chain_free(PCCERT_CHAIN_CONTEXT c);
/* which pki id does this certificate context carry (NULL if unknown) */
const char *pki_id_of(PCCERT_CONTEXT c);
const char *pki_elem_id(PCCERT_CHAIN_CONTEXT c, int chain, int elem);
#define EXPECT_ID(c, ch, el, id) do { const char *g_ = pki_elem_id((c), (ch), (el)); \
    CHECKF(g_ && !strcmp(g_, (id)), "element [%d][%d] is %s want %s", (int)(ch), (int)(el), g_ ? g_ : "(none)", (id)); } while (0)
void pki_note_chain(const char *tag, PCCERT_CHAIN_CONTEXT c);
DWORD pki_nelem(PCCERT_CHAIN_CONTEXT c, int chain);
DWORD pki_elem_err(PCCERT_CHAIN_CONTEXT c, int chain, int elem);
DWORD pki_elem_info(PCCERT_CHAIN_CONTEXT c, int chain, int elem);
/* generic scenario runner: expected exact chain error status & element count of simple chain 0 */
void pki_scenario(const char *tag, const char *leaf, const char *roots, const char *others, const char *addl,
                  int y, int mo, int d, int h, int mi, int s, DWORD flags, DWORD want_err, DWORD want_nelem);
#endif

/* Shared helpers for the crypt32 high-level message / CryptQueryObject tests.
 * Every call into the DLL goes through U(): LoadLibrary -> GetProcAddress -> invoke. */
#ifndef MH_H
#define MH_H
#include "t.h"
#include <wincrypt.h>
#include "vectors.h"

#define ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define E_INVALIDARG_ ((DWORD)0x80070057)
#define CRYPT_E_ASN1_ANY(e) (((e) & 0xFFFFFF00u) == 0x80093100u)
#define E_NTE_BAD_SIGNATURE 0x80090006u
#define E_CRYPT_E_HASH_VALUE 0x80091007u
#define E_CRYPT_E_UNKNOWN_ALGO 0x80091002u
#define E_CRYPT_E_NOT_FOUND 0x80092004u
#define E_CRYPT_E_NO_MATCH 0x80092009u
#define E_CRYPT_E_UNEXPECTED_MSG_TYPE 0x8009200Au
#define E_CRYPT_E_NO_DECRYPT_CERT 0x8009200Cu
#define E_CRYPT_E_NO_SIGNER 0x8009200Eu

#define OID_SHA1   "1.3.14.3.2.26"
#define OID_SHA256 "2.16.840.1.101.3.4.2.1"
#define OID_SHA384 "2.16.840.1.101.3.4.2.2"
#define OID_SHA512 "2.16.840.1.101.3.4.2.3"
#define OID_MD5    "1.2.840.113549.2.5"

#define BLOB(x) x, (DWORD)sizeof(x)

enum { MH_S1, MH_S2, MH_R1, MH_R2, MH_N };
typedef struct { PCCERT_CONTEXT priv;   /* in mh_priv_store, ephemeral key attached as CERT_KEY_PROV_HANDLE */
                 PCCERT_CONTEXT pub; }  /* in mh_pub_store, no key */
    mh_id;
extern mh_id mh_ids[MH_N];
extern HCERTSTORE mh_priv_store, mh_pub_store;
extern HCRYPTPROV mh_prov[MH_N];
int mh_init(void);                              /* 1 when the fixtures exist, else t_skip + 0 */
/* these crypt32 exports are unimplemented stubs that abort the process under Wine */
#define MH_NOWINE() do { if (t_is_wine()) { t_skip("export is a stub under wine"); return; } } while (0)
#define MH_INIT() do { if (!mh_init()) return; } while (0)

/* parameter structure fillers */
void mh_sign_para(CRYPT_SIGN_MESSAGE_PARA *p, int who, const char *hashoid);
void mh_verify_para(CRYPT_VERIFY_MESSAGE_PARA *p);                 /* signer lookup in mh_pub_store via callback-less default (hCryptProv=0) */
void mh_hash_para(CRYPT_HASH_MESSAGE_PARA *p, const char *oid);
void mh_enc_para(CRYPT_ENCRYPT_MESSAGE_PARA *p, const char *oid);
void mh_dec_para(CRYPT_DECRYPT_MESSAGE_PARA *p);
extern HCERTSTORE mh_dec_stores[1];
/* verify para whose pfnGetSignerCertificate looks the signer up in mh_pub_store (message certs ignored) */
void mh_verify_para_cb(CRYPT_VERIFY_MESSAGE_PARA *p);
extern int mh_cb_calls;

/* Sign v_payload (or any buffer) with signer `who`. Returns malloc'ed blob (caller frees) or NULL. */
BYTE *mh_sign(int who, const char *hashoid, int detached, DWORD flags, const BYTE *data, DWORD cb, DWORD *pcb);
/* Copy a verified blob into a cert store opened over the message (CryptGetMessageCertificates). */
int mh_count_certs(HCERTSTORE s);
/* DER helpers */
DWORD mh_der_total(const BYTE *p, DWORD cb);    /* header+content length of the first TLV, 0 if malformed */
DWORD mh_der_hdr(const BYTE *p, DWORD cb);      /* header length of the first TLV */
int mh_has(const BYTE *hay, DWORD n, const void *needle, DWORD m);
#define MH_HAS(b, n, lit) mh_has((b), (n), (lit), sizeof(lit) - 1)
/* DER encoded OID content + header for the PKCS#7 content types */
#define MH_OID_SIGNED    "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
#define MH_OID_DATA      "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
#define MH_OID_ENVELOPED "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03"
#define MH_OID_HASHED    "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x05"
#define MH_OID_OAEP      "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07"
/* hex {ASN} text / base64 text encodings of a blob (malloc'ed, caller frees) */
char *mh_to_b64(const BYTE *p, DWORD cb, DWORD strflags, DWORD *pcch);
char *mh_to_asnhex(const BYTE *p, DWORD cb, DWORD *pcch);
/* fresh memory store: certs in privmask carry their ephemeral key, certs in pubmask do not (bit = 1 << MH_xx). */
HCERTSTORE mh_make_store(unsigned privmask, unsigned pubmask);
#define CERT_IS(ctx, vec) ((ctx) != NULL && (ctx)->cbCertEncoded == sizeof(vec) && !memcmp((ctx)->pbCertEncoded, (vec), sizeof(vec)))
#define FREE_CERT(c) do { if (c) U(CertFreeCertificateContext)(c); (c) = NULL; } while (0)
#endif

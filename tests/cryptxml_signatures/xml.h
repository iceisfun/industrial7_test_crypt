/* Shared declarations for the cryptxml_signatures area.
 * The SDK header is deliberately not used (several of its declarations are unusable in C); every
 * type below is laid out as the DLL uses it (checked against the observed field offsets), and every
 * entry point is resolved with GetProcAddress through the typedefs declared here. */
#ifndef XML_H
#define XML_H
#include "t.h"
#include <bcrypt.h>

typedef HANDLE HCX;

/* ---- HRESULTs observed in the implementation ----------------------------------------------- */
#define X_E_INVALIDARG      ((HRESULT)0x80070057)
#define X_E_NOTIMPL_ALGO    ((HRESULT)0x80004001)   /* E_NOTIMPL, returned for unknown key value types */
#define X_E_LARGE           ((HRESULT)0x80092101)
#define X_E_TOO_MANY_TRANSFORMS ((HRESULT)0x80092102)
#define X_E_ALGORITHM       ((HRESULT)0x80092104)
#define X_E_HANDLE          ((HRESULT)0x80092106)
#define X_E_OPERATION       ((HRESULT)0x80092107)
#define X_E_UNRESOLVED_REF  ((HRESULT)0x80092108)
#define X_E_VERIFY_FAILED   ((HRESULT)0x8009210D)
#define X_E_TOO_MANY_SIGS   ((HRESULT)0x8009210E)
#define X_E_INVALID_KEYVALUE ((HRESULT)0x8009210F)
#define X_E_NON_UNIQUE_ID   ((HRESULT)0x80092112)
#define X_WS_E_INVALID_FORMAT ((HRESULT)0x803D0000)

/* ---- constants ------------------------------------------------------------------------------ */
#define X_CS_AUTO 0
#define X_CS_UTF8 1
#define X_CS_UTF16LE 2
#define X_CS_UTF16BE 3
#define X_PROP_MAX_HEAP 1
#define X_PROP_SIG_LOCATION 2
#define X_PROP_MAX_SIGS 3
#define X_PROP_DOC_DECL 4
#define X_PROP_OUT_CHARSET 5
#define X_PROP_HMAC_LEN 6
#define X_FLAG_NO_SERIALIZE 0x80000000u
#define X_FLAG_DISABLE_EXT 0x10000000u
#define X_FLAG_REF_AS_OBJECT 1
#define X_REFERENCE_DATA_TRANSFORMED 1
#define X_KEYINFO_NONE 0
#define X_KEYINFO_ENCODED 1
#define X_KEYINFO_PARAM 2
#define X_SIGN_ADD_KEYVALUE 1
#define X_NCRYPT_KEY_SPEC 0xFFFFFFFFu
#define X_GROUP_HASH 1
#define X_GROUP_SIGN 2
#define X_FIND_URI 1
#define X_FIND_NAME 2
#define X_FIND_CNG_ALGID 3
#define X_FIND_SIGN_ALGID 4
/* status */
#define XS_E_NOT_RESOLVED 0x1
#define XS_E_DIGEST_INVALID 0x2
#define XS_E_SIGNATURE_INVALID 0x10000
#define XS_E_KEYINFO_NOT_PARSED 0x20000
#define XS_I_INTERNAL_REFERENCE 0x1
#define XS_I_KEY_AVAILABLE 0x2
#define XS_I_DIGESTING 0x4
#define XS_I_DIGEST_VALID 0x8
#define XS_I_SIGNATURE_VALID 0x10000
#define XS_I_OPENED_TO_ENCODE 0x80000000u

/* ---- structures ----------------------------------------------------------------------------- */
typedef struct { DWORD dwCharset; ULONG cbData; BYTE *pbData; } XBLOB;
typedef struct { ULONG cbSize; LPCWSTR wszAlgorithm; XBLOB Encoded; } XALG;
typedef struct { ULONG cbData; BYTE *pbData; } XDBLOB;
typedef struct { DWORD dwPropId; const void *pvValue; ULONG cbValue; } XPROP;
typedef struct { ULONG cbSize; DWORD dwErrorStatus; DWORD dwInfoStatus; } XSTATUS;

typedef HRESULT (CALLBACK *XWRITE)(void *state, const BYTE *pb, ULONG cb);
typedef HRESULT (CALLBACK *XREAD)(void *state, BYTE *pb, ULONG cb, ULONG *pcbRead);
typedef HRESULT (CALLBACK *XCLOSE)(void *state);
typedef struct { void *pvCallbackState; ULONG cbBufferSize; XREAD pfnRead; XCLOSE pfnClose; } XPROV;

typedef struct { ULONG cbSize; LPCWSTR wszAlgorithm; ULONG cbBufferSize; DWORD dwFlags; void *pfnCreateTransform; } XTRANSINFO;
typedef struct { ULONG cbSize; ULONG cTransformInfo; XTRANSINFO **rgpTransformInfo; } XTRANSCFG;

typedef struct { DWORD cbSize; WCHAR *wszAlgorithmURI; WCHAR *wszName; DWORD dwGroupId; WCHAR *wszCNGAlgid;
                 WCHAR *wszCNGExtraAlgid; DWORD dwSignFlags; DWORD dwVerifyFlags; void *pvPaddingInfo; void *pvExtraInfo; } XALGINFO;
typedef struct { LPCWSTR wszCNGAlgid; LPCWSTR wszCNGExtraAlgid; } XSIGNALGID;

typedef struct { ULONG cbSize; HCX hReference; LPCWSTR wszId; LPCWSTR wszUri; LPCWSTR wszType; XALG DigestMethod;
                 XDBLOB DigestValue; ULONG cTransform; XALG *rgTransform; } XREF;
typedef struct { ULONG cReference; XREF **rgpReference; } XREFS;
typedef struct { ULONG cbSize; LPCWSTR wszId; XALG Canonicalization; XALG SignatureMethod; ULONG cReference;
                 XREF **rgpReference; XBLOB Encoded; } XSIGNEDINFO;
typedef struct { XDBLOB P, Q, G, Y, J, Seed, Counter; } XDSAKV;
typedef struct { XDBLOB Modulus, Exponent; } XRSAKV;
typedef struct { LPCWSTR wszNamedCurve; XDBLOB X, Y; XBLOB ExplicitPara; } XECKV;
typedef struct { DWORD dwType; union { XDSAKV DSA; XRSAKV RSA; XECKV EC; XBLOB Custom; } u; } XKEYVALUE;
typedef struct { DWORD dwType; union { LPCWSTR wszKeyName; XKEYVALUE KeyValue; XBLOB Custom; } u; } XKEYINFOITEM;
typedef struct { ULONG cbSize; LPCWSTR wszId; UINT cKeyInfo; XKEYINFOITEM *rgKeyInfo; void *hVerifyKey; } XKEYINFO;
typedef struct { ULONG cbSize; HCX hObject; LPCWSTR wszId; LPCWSTR wszMimeType; LPCWSTR wszEncoding; XREFS Manifest; XBLOB Encoded; } XOBJECT;
typedef struct { ULONG cbSize; HCX hSignature; LPCWSTR wszId; XSIGNEDINFO SignedInfo; XDBLOB SignatureValue;
                 XKEYINFO *pKeyInfo; ULONG cObject; XOBJECT **rgpObject; } XSIG;
typedef struct { ULONG cbSize; HCX hDocCtxt; const XTRANSCFG *pTransformsConfig; ULONG cSignature; XSIG **rgpSignature; } XDOC;
typedef struct { LPCWSTR wszId; LPCWSTR wszKeyName; XDBLOB SKI; LPCWSTR wszSubjectName; ULONG cCertificate;
                 XDBLOB *rgCertificate; ULONG cCRL; XDBLOB *rgCRL; } XKEYINFOPARAM;

/* ---- entry points --------------------------------------------------------------------------- */
UDECL(HRESULT, CryptXmlOpenToDecode, (const XTRANSCFG *cfg, DWORD flags, const XPROP *rg, ULONG c, const XBLOB *enc, HCX *ph));
UDECL(HRESULT, CryptXmlOpenToEncode, (const XTRANSCFG *cfg, DWORD flags, LPCWSTR id, const XPROP *rg, ULONG c, const XBLOB *enc, HCX *ph));
UDECL(HRESULT, CryptXmlClose, (HCX h));
UDECL(HRESULT, CryptXmlAddObject, (HCX h, DWORD flags, const XPROP *rg, ULONG c, const XBLOB *enc, const XOBJECT **ppObj));
UDECL(HRESULT, CryptXmlCreateReference, (HCX h, DWORD flags, LPCWSTR id, LPCWSTR uri, LPCWSTR type, const XALG *digest, ULONG cT, const XALG *rgT, HCX *phRef));
UDECL(HRESULT, CryptXmlDigestReference, (HCX hRef, DWORD flags, XPROV *prov));
UDECL(HRESULT, CryptXmlEncode, (HCX h, DWORD charset, const XPROP *rg, ULONG c, void *state, XWRITE pfn));
UDECL(HRESULT, CryptXmlGetAlgorithmInfo, (const XALG *alg, DWORD flags, XALGINFO **pp));
UDECL(HRESULT, CryptXmlGetDocContext, (HCX h, const XDOC **pp));
UDECL(HRESULT, CryptXmlGetReference, (HCX h, const XREF **pp));
UDECL(HRESULT, CryptXmlGetSignature, (HCX h, const XSIG **pp));
UDECL(HRESULT, CryptXmlGetStatus, (HCX h, XSTATUS *ps));
UDECL(HRESULT, CryptXmlGetTransforms, (const XTRANSCFG **pp));
UDECL(HRESULT, CryptXmlImportPublicKey, (DWORD flags, XKEYVALUE *kv, void **phKey));
UDECL(HRESULT, CryptXmlSetHMACSecret, (HCX h, const BYTE *secret, ULONG cb));
UDECL(HRESULT, CryptXmlSign, (HCX h, ULONG_PTR key, DWORD spec, DWORD flags, DWORD kiSpec, const void *kiParam, const XALG *sigMethod, const XALG *canon));
UDECL(HRESULT, CryptXmlVerifySignature, (HCX h, void *hKey, DWORD flags));
typedef BOOL (CALLBACK *XENUMCB)(const XALGINFO *info, void *arg);
UDECL(HRESULT, CryptXmlEnumAlgorithmInfo, (DWORD group, DWORD flags, void *arg, XENUMCB cb));
UDECL(const XALGINFO *, CryptXmlFindAlgorithmInfo, (DWORD findBy, const void *value, DWORD group, DWORD flags));

/* All resolved lazily by name from cryptxml.dll (the module under test for this area). */
#define XFN(name) ((name##_pfn)t_proc_in("cryptxml.dll", #name))

/* ---- algorithm URIs ------------------------------------------------------------------------- */
#define U_SHA1   L"http://www.w3.org/2000/09/xmldsig#sha1"
#define U_SHA256 L"http://www.w3.org/2001/04/xmlenc#sha256"
#define U_SHA384 L"http://www.w3.org/2001/04/xmldsig-more#sha384"
#define U_SHA512 L"http://www.w3.org/2001/04/xmlenc#sha512"
#define U_HMAC1   L"http://www.w3.org/2000/09/xmldsig#hmac-sha1"
#define U_HMAC256 L"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
#define U_HMAC384 L"http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
#define U_HMAC512 L"http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
#define U_RSA1   L"http://www.w3.org/2000/09/xmldsig#rsa-sha1"
#define U_RSA256 L"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
#define U_RSA384 L"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
#define U_RSA512 L"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
#define U_DSA1   L"http://www.w3.org/2000/09/xmldsig#dsa-sha1"
#define U_ECDSA1   L"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
#define U_ECDSA256 L"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
#define U_ECDSA384 L"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
#define U_ECDSA512 L"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
#define U_C14N   L"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
#define U_C14N_C L"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
#define U_EXC    L"http://www.w3.org/2001/10/xml-exc-c14n#"
#define U_EXC_C  L"http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
#define U_ENVELOPED L"http://www.w3.org/2000/09/xmldsig#enveloped-signature"

/* ---- helpers (helpers.c) -------------------------------------------------------------------- */
typedef struct { BYTE *p; size_t n, cap; int calls; HRESULT fail_with; } XBUF;   /* write-callback sink */
HRESULT CALLBACK x_write_cb(void *state, const BYTE *pb, ULONG cb);
void   x_buf_free(XBUF *b);
/* NUL-terminated copy of the collected bytes (caller does not free; valid until next x_buf_str). */
const char *x_buf_str(XBUF *b);

typedef struct { const BYTE *p; size_t n, pos; size_t chunk; int reads, closes; HRESULT read_fail; } XMEM;  /* read-callback source */
HRESULT CALLBACK x_read_cb(void *state, BYTE *pb, ULONG cb, ULONG *pcb);
HRESULT CALLBACK x_close_cb(void *state);
void x_prov(XPROV *pv, XMEM *m, const void *data, size_t n, size_t chunk);

/* independent digests through CNG (alg = BCRYPT_*_ALGORITHM); secret != NULL selects HMAC */
int x_hash(const WCHAR *alg, const BYTE *secret, ULONG cbSecret, const void *data, size_t n, BYTE *out, ULONG *cbOut);

/* build a UTF-16 copy (LE or BE) of an ASCII/UTF-8 string, optionally with a BOM */
BYTE *x_utf16(const char *s, int be, int bom, ULONG *cb);

/* replace first occurrence of `from` with same-length `to` inside a heap copy of s */
char *x_tamper(const char *s, const char *from, const char *to);

/* open a decoded document from NUL-terminated UTF-8 text; returns the HRESULT */
HRESULT x_decode(const char *xml, const XPROP *props, ULONG cprops, HCX *ph);
/* shortcut: decode, fetch first signature struct; hDoc returned for closing */
const XSIG *x_first_sig(HCX hDoc);
int  x_find(const char *hay, const char *needle);   /* 1 if present */
void x_status(HCX h, XSTATUS *s);

#define XCHK_HR(call, want) do { HRESULT hr_ = (call); t_check(hr_ == (HRESULT)(want), __FILE__, __LINE__, #call, "got 0x%08lx want 0x%08lx", (unsigned long)hr_, (unsigned long)(HRESULT)(want)); } while (0)

/* Win10 CryptXmlImportPublicKey quirk (probed, identical in std and adm, repeatable): a successful import returns a valid
 * key handle but the HRESULT is E_NOTIMPL (0x80004001), or S_FALSE (1) when X_FLAG_DISABLE_EXT is set. Failures return a
 * NULL handle. Success is therefore judged on the handle, and the code is pinned to the observed value. */
#define X_IMPORT_OK_HR(fl) (((fl) & X_FLAG_DISABLE_EXT) ? (HRESULT)1 : X_E_NOTIMPL_ALGO)
#define XIMPORT_OK(fl, pkv, pkey) do { *(pkey) = NULL; HRESULT ih_ = XFN(CryptXmlImportPublicKey)((fl), (pkv), (pkey)); \
    t_check(*(pkey) != NULL, __FILE__, __LINE__, "import returns a key handle", "hr 0x%08lx", (unsigned long)ih_); \
    t_check(ih_ == X_IMPORT_OK_HR(fl), __FILE__, __LINE__, "import success code", "got 0x%08lx want 0x%08lx", (unsigned long)ih_, (unsigned long)X_IMPORT_OK_HR(fl)); } while (0)

/* base64 of a byte string (heap, caller frees) */
char *x_b64(const BYTE *p, size_t n);
/* decoded base64 (no whitespace tolerance beyond skipping spaces); returns heap buffer, *n = length */
BYTE *x_unb64(const char *s, size_t *n);
/* heap copy of the text of the first <[prefix:]name ...>text</...> element, or NULL */
char *x_elem_text(const char *xml, const char *name);
/* canonical form (inclusive C14N 1.0 of a restricted XML subset) of the first SignedInfo element, with the
 * namespace declaration of the enclosing Signature element made explicit; heap, caller frees */
char *x_canon_signedinfo(const char *xml);

#include "vectors.h"
#endif

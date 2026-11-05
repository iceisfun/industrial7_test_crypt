#ifndef CNET_H
#define CNET_H
#include "t.h"
#include <wincrypt.h>
#include <wchar.h>
#include "vectors.h"

#define ERR_INVALIDARG   0x80070057UL
#define ERR_NOTIMPL      0x80004001UL
#define ERR_CRYPT_NOTFOUND 0x80092004UL
#define ERR_NO_REVCHECK  0x80092012UL

typedef struct { const char *name; const unsigned char *p; size_t n; } cn_vec;
#define VEC(x) { #x, x, sizeof(x) }

/* path of a fresh scratch file holding the bytes, and its file:/// URL (wide and narrow) */
int  cn_mkfile(const char *leaf, const void *p, size_t n, char *path, size_t cap);
void cn_url_w(const char *path, WCHAR *out, size_t cch);
void cn_url_a(const char *path, char *out, size_t cch);

/* CryptRetrieveObjectByUrlW through the module list; ppv is preset to a sentinel by the caller if wanted */
BOOL cn_retrieve_w(const WCHAR *url, LPCSTR oid, DWORD flags, DWORD timeout, LPVOID *ppv, LPVOID verify);
BOOL cn_retrieve_a(const char *url, LPCSTR oid, DWORD flags, DWORD timeout, LPVOID *ppv, LPVOID verify);

int cn_count_certs(HCERTSTORE s);
int cn_count_crls(HCERTSTORE s);
int cn_count_ctls(HCERTSTORE s);

/* expected CRYPT_URL_ARRAY single-buffer size for the given URLs */
DWORD cn_urlarray_size(int n, const WCHAR * const *urls);
/* check the single-buffer layout of a URL array and compare strings (returns 1 when all good) */
int cn_check_urlarray(const CRYPT_URL_ARRAY *a, DWORD cb, int n, const WCHAR * const *urls);
/* run CryptGetObjectUrl(oid, para, flags, ...) with size query then fetch; buf must be freed by caller (LocalFree-free: static buffer). */
BOOL cn_geturl(LPCSTR oid, LPVOID para, DWORD flags, BYTE *buf, DWORD cap, DWORD *cb);
extern const WCHAR *CN_URLS_A_ISSUER[2]; extern const WCHAR *CN_URLS_A_CDP[3];
#endif

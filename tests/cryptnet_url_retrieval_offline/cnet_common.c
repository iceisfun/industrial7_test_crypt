#include "cnet.h"

int cn_mkfile(const char *leaf, const void *p, size_t n, char *path, size_t cap) {
    t_tmpfile(path, cap, leaf);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w = 0; BOOL ok = n ? WriteFile(h, p, (DWORD)n, &w, NULL) : TRUE;
    CloseHandle(h);
    return ok && w == n;
}

void cn_url_a(const char *path, char *out, size_t cch) {
    size_t o = 0;
    const char *pre = "file:///";
    while (*pre && o + 1 < cch) out[o++] = *pre++;
    for (; *path && o + 4 < cch; path++) {
        if (*path == '\\') out[o++] = '/';
        else if (*path == ' ') { out[o++] = '%'; out[o++] = '2'; out[o++] = '0'; }
        else if (*path == '%') { out[o++] = '%'; out[o++] = '2'; out[o++] = '5'; }
        else out[o++] = *path;
    }
    out[o] = 0;
}
void cn_url_w(const char *path, WCHAR *out, size_t cch) {
    char tmp[1200]; cn_url_a(path, tmp, sizeof tmp);
    size_t i = 0; for (; tmp[i] && i + 1 < cch; i++) out[i] = (WCHAR)(unsigned char)tmp[i];
    out[i] = 0;
}

BOOL cn_retrieve_w(const WCHAR *url, LPCSTR oid, DWORD flags, DWORD timeout, LPVOID *ppv, LPVOID verify) {
    return U(CryptRetrieveObjectByUrlW)(url, oid, flags, timeout, ppv, NULL, NULL, verify, NULL);
}
BOOL cn_retrieve_a(const char *url, LPCSTR oid, DWORD flags, DWORD timeout, LPVOID *ppv, LPVOID verify) {
    return U(CryptRetrieveObjectByUrlA)(url, oid, flags, timeout, ppv, NULL, NULL, verify, NULL);
}

int cn_count_certs(HCERTSTORE s) {
    int n = 0; PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL) n++;
    return n;
}
int cn_count_crls(HCERTSTORE s) {
    int n = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertEnumCRLsInStore)(s, c)) != NULL) n++;
    return n;
}
int cn_count_ctls(HCERTSTORE s) {
    int n = 0; PCCTL_CONTEXT c = NULL;
    while ((c = U(CertEnumCTLsInStore)(s, c)) != NULL) n++;
    return n;
}

DWORD cn_urlarray_size(int n, const WCHAR * const *urls) {
    DWORD cb = 16 + 8 * n;
    for (int i = 0; i < n; i++) cb += (DWORD)(2 * (wcslen(urls[i]) + 1));
    return cb;
}

int cn_check_urlarray(const CRYPT_URL_ARRAY *a, DWORD cb, int n, const WCHAR * const *urls) {
    int ok = 1;
    CHECKF(a->cUrl == (DWORD)n, "cUrl %lu want %d", a->cUrl, n);
    if (a->cUrl != (DWORD)n) return 0;
    CHECK((const BYTE *)a->rgwszUrl == (const BYTE *)a + 16);
    CHECKF(cb == cn_urlarray_size(n, urls), "cb %lu want %lu", cb, cn_urlarray_size(n, urls));
    const BYTE *strs = (const BYTE *)a + 16 + 8 * n;
    for (int i = 0; i < n; i++) {
        CHECKF(!wcscmp(a->rgwszUrl[i], urls[i]), "url[%d] = %ls", i, a->rgwszUrl[i]);
        CHECK((const BYTE *)a->rgwszUrl[i] >= strs && (const BYTE *)a->rgwszUrl[i] < (const BYTE *)a + cb);
        if (wcscmp(a->rgwszUrl[i], urls[i])) ok = 0;
    }
    return ok;
}

BOOL cn_geturl(LPCSTR oid, LPVOID para, DWORD flags, BYTE *buf, DWORD cap, DWORD *cb) {
    *cb = cap;
    return U(CryptGetObjectUrl)(oid, para, flags, (PCRYPT_URL_ARRAY)buf, cb, NULL, NULL, NULL);
}

const WCHAR *CN_URLS_A_ISSUER[2] = { L"http://ca.example.test/ca1.cer", L"ldap://ldap.example.test/CN=CA?cACertificate?base" };
const WCHAR *CN_URLS_A_CDP[3] = { L"http://crl.example.test/a.crl", L"ldap://ldap.example.test/CN=CA?certificateRevocationList?base", L"http://crl2.example.test/b.crl" };

int cn_file_scheme_works(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    char path[MAX_PATH]; WCHAR url[1200];
    cached = 0;
    if (!cn_mkfile("probe.cer", v_cert_b, sizeof v_cert_b, path, sizeof path)) return 0;
    cn_url_w(path, url, 1200);
    LPVOID obj = NULL;
    if (cn_retrieve_w(url, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL) && obj) {
        U(CertFreeCertificateContext)((PCCERT_CONTEXT)obj);
        cached = 1;
    }
    return cached;
}

/* Images signed at run time with mssign32!SignerSign and an ephemeral key, then verified with WinVerifyTrust.
 * Skips (with a note) when the platform cannot sign. Nothing is persisted: the key lives in a VERIFYCONTEXT provider. */
#include "wvt.h"

typedef struct { DWORD cbSize; LPCWSTR pwszFileName; HANDLE hFile; } W_SIGNER_FILE_INFO;
typedef struct { DWORD cbSize; DWORD *pdwIndex; DWORD dwSubjectChoice; union { W_SIGNER_FILE_INFO *pSignerFileInfo; void *pSignerBlobInfo; }; } W_SIGNER_SUBJECT_INFO;
typedef struct { DWORD cbSize; PCCERT_CONTEXT pSigningCert; DWORD dwCertPolicy; HCERTSTORE hCertStore; } W_SIGNER_CERT_STORE_INFO;
typedef struct { DWORD cbSize; DWORD dwCertChoice; union { LPCWSTR pwszSpcFile; W_SIGNER_CERT_STORE_INFO *pCertStoreInfo; void *p; }; HWND hwnd; } W_SIGNER_CERT;
typedef struct { DWORD cbSize; ALG_ID algidHash; DWORD dwAttrChoice; void *pAttr; PCRYPT_ATTRIBUTES psAuthenticated, psUnauthenticated; } W_SIGNER_SIGNATURE_INFO;
typedef HRESULT (WINAPI *signersign_t)(W_SIGNER_SUBJECT_INFO *, W_SIGNER_CERT *, W_SIGNER_SIGNATURE_INFO *, void *, LPCWSTR, PCRYPT_ATTRIBUTES, void *);

typedef struct { HCRYPTPROV prov; HCRYPTKEY key; PCCERT_CONTEXT cert; WCHAR cont[96]; } EPH;

T_SWEEPER(wvt_containers) {
    (void)phase;
    HCRYPTPROV p = 0;
    if (!U(CryptAcquireContextW)(&p, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;
    char stale[64][160]; int n = 0; BYTE buf[512]; DWORD cb, fl = CRYPT_FIRST;
    for (;;) {
        cb = sizeof buf;
        if (!U(CryptGetProvParam)(p, PP_ENUMCONTAINERS, buf, &cb, fl)) break;
        fl = CRYPT_NEXT;
        if (!strncmp((char *)buf, prefix, strlen(prefix)) && n < 64) lstrcpynA(stale[n++], (char *)buf, sizeof stale[0]);
    }
    U(CryptReleaseContext)(p, 0);
    for (int i = 0; i < n; i++) {
        WCHAR w[160]; HCRYPTPROV d = 0;
        MultiByteToWideChar(CP_ACP, 0, stale[i], -1, w, 160);
        U(CryptAcquireContextW)(&d, w, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
    }
}

static int eph_make(EPH *e, const WCHAR *cn) {
    memset(e, 0, sizeof *e);
    /* Win10: a SHA256RSA signature through a VERIFYCONTEXT key fails with NTE_BAD_TYPE (0x8009000a), so the key lives in a
     * uniquely named container that eph_free deletes (and the sweeper removes after a crash). */
    lstrcpynW(e->cont, t_unique_w("sig"), 96);
    if (!U(CryptAcquireContextW)(&e->prov, e->cont, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) { t_note("CryptAcquireContext failed %lu", (unsigned long)GetLastError()); return 0; }
    if (!U(CryptGenKey)(e->prov, AT_SIGNATURE, (2048u << 16), &e->key)) { t_note("CryptGenKey failed %lu", (unsigned long)GetLastError()); return 0; }
    BYTE name[256]; DWORD ncb = sizeof name;
    if (!U(CertStrToNameW)(X509_ASN_ENCODING, cn, CERT_X500_NAME_STR, NULL, name, &ncb, NULL)) return 0;
    CERT_NAME_BLOB nb = { ncb, name };
    LPSTR oids[1] = { szOID_PKIX_KP_CODE_SIGNING }; CERT_ENHKEY_USAGE eku = { 1, oids };
    BYTE *ee = NULL; DWORD ecb = 0;
    if (!U(CryptEncodeObjectEx)(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku, CRYPT_ENCODE_ALLOC_FLAG, NULL, &ee, &ecb)) return 0;
    CERT_EXTENSION ext = { szOID_ENHANCED_KEY_USAGE, FALSE, { ecb, ee } }; CERT_EXTENSIONS exts = { 1, &ext };
    CRYPT_ALGORITHM_IDENTIFIER alg; memset(&alg, 0, sizeof alg); alg.pszObjId = szOID_RSA_SHA256RSA;
    SYSTEMTIME s0 = { 2020, 1, 0, 1 }, s1 = { 2120, 1, 0, 1 }; FILETIME f0, f1; SystemTimeToFileTime(&s0, &f0); SystemTimeToFileTime(&s1, &f1);
    SYSTEMTIME ss0, ss1; FileTimeToSystemTime(&f0, &ss0); FileTimeToSystemTime(&f1, &ss1);
    CRYPT_KEY_PROV_INFO kpi; memset(&kpi, 0, sizeof kpi); kpi.pwszContainerName = e->cont; kpi.pwszProvName = (LPWSTR)MS_ENH_RSA_AES_PROV_W; kpi.dwProvType = PROV_RSA_AES; kpi.dwKeySpec = AT_SIGNATURE;
    e->cert = U(CertCreateSelfSignCertificate)(e->prov, &nb, 0, &kpi, &alg, &ss0, &ss1, &exts);
    if (!e->cert) {
        t_note("CertCreateSelfSignCertificate(kpi) failed 0x%08lx", (unsigned long)GetLastError());
        e->cert = U(CertCreateSelfSignCertificate)(e->prov, &nb, 0, NULL, &alg, &ss0, &ss1, &exts);
        if (!e->cert) t_note("CertCreateSelfSignCertificate(no kpi) failed 0x%08lx", (unsigned long)GetLastError());
    }
    if (!e->cert) {
        /* build the certificate by hand: TBS from the exported public key, signed with the in-memory key */
        DWORD pkcb = 0; U(CryptExportPublicKeyInfo)(e->prov, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &pkcb);
        CERT_PUBLIC_KEY_INFO *pub = (CERT_PUBLIC_KEY_INFO *)HeapAlloc(GetProcessHeap(), 0, pkcb ? pkcb : 1);
        if (pub && U(CryptExportPublicKeyInfo)(e->prov, AT_SIGNATURE, X509_ASN_ENCODING, pub, &pkcb)) {
            CERT_INFO ci; memset(&ci, 0, sizeof ci); BYTE serial[1] = { 0x2a };
            ci.dwVersion = CERT_V3; ci.SerialNumber.cbData = 1; ci.SerialNumber.pbData = serial;
            ci.SignatureAlgorithm = alg; ci.Issuer = nb; ci.Subject = nb; ci.NotBefore = f0; ci.NotAfter = f1;
            ci.SubjectPublicKeyInfo = *pub; ci.cExtension = 1; ci.rgExtension = &ext;
            DWORD tcb = 0;
            if (U(CryptSignAndEncodeCertificate)(e->prov, AT_SIGNATURE, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &ci, &alg, NULL, NULL, &tcb)) {
                BYTE *der = (BYTE *)HeapAlloc(GetProcessHeap(), 0, tcb);
                if (der && U(CryptSignAndEncodeCertificate)(e->prov, AT_SIGNATURE, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &ci, &alg, NULL, der, &tcb))
                    e->cert = U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, tcb);
                if (der) HeapFree(GetProcessHeap(), 0, der);
            } else t_note("CryptSignAndEncodeCertificate failed 0x%08lx", (unsigned long)GetLastError());
        } else t_note("CryptExportPublicKeyInfo failed 0x%08lx", (unsigned long)GetLastError());
        if (pub) HeapFree(GetProcessHeap(), 0, pub);
    }
    LocalFree(ee);
    if (!e->cert) { t_note("cannot build an ephemeral certificate"); return 0; }
    DWORD spec = AT_SIGNATURE;
    U(CertSetCertificateContextProperty)(e->cert, CERT_KEY_SPEC_PROP_ID, 0, &spec);
    if (!U(CertSetCertificateContextProperty)(e->cert, CERT_KEY_PROV_HANDLE_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, (void *)e->prov)) { t_note("set prov handle failed %lu", (unsigned long)GetLastError()); return 0; }
    return 1;
}
static void eph_free(EPH *e) {
    if (e->cert) U(CertFreeCertificateContext)(e->cert);
    if (e->key) U(CryptDestroyKey)(e->key);
    if (e->prov) U(CryptReleaseContext)(e->prov, 0);
    if (e->cont[0]) { HCRYPTPROV d = 0; U(CryptAcquireContextW)(&d, e->cont, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET); }
    memset(e, 0, sizeof *e);
}
/* sign file in place; returns HRESULT */
static HRESULT sign_file(EPH *e, const WCHAR *path, ALG_ID hash) {
    signersign_t f = (signersign_t)t_proc_in("mssign32.dll", "SignerSign"); if (!f) return E_NOTIMPL;
    W_SIGNER_FILE_INFO fi = { sizeof fi, path, NULL }; DWORD idx = 0;
    W_SIGNER_SUBJECT_INFO si = { sizeof si, &idx, 1 /* SIGNER_SUBJECT_FILE */, { &fi } };
    W_SIGNER_CERT_STORE_INFO csi = { sizeof csi, e->cert, 0, NULL };
    W_SIGNER_CERT sc = { sizeof sc, 2 /* SIGNER_CERT_STORE */, { 0 }, NULL }; sc.pCertStoreInfo = &csi;
    W_SIGNER_SIGNATURE_INFO sg = { sizeof sg, hash, 0 /* SIGNER_NO_ATTR */, NULL, NULL, NULL };
    return f(&si, &sc, &sg, NULL, NULL, NULL, NULL);
}
#define SIGN_SETUP(name, hashalg) \
    WVT_REQUIRE_WVT(); \
    if (!t_proc_in("mssign32.dll", "SignerSign")) { if (t_is_wine()) t_skip("mssign32!SignerSign missing"); else CHECKF(0, "mssign32!SignerSign missing"); return; } \
    EPH eph; WCHAR p[MAX_PATH]; wvt_path(p, name); \
    if (!eph_make(&eph, L"CN=cryptt WVT runtime signer")) { CHECKF(0, "cannot create the ephemeral signing cert"); eph_free(&eph); return; } \
    wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned); \
    HRESULT shr = sign_file(&eph, p, hashalg); \
    if (FAILED(shr)) { CHECKF(0, "SignerSign failed 0x%08lx (lasterr %lu)", (unsigned long)shr, (unsigned long)GetLastError()); wvt_del(p); eph_free(&eph); return; }

TEST(wvt_sign_selfsigned_untrusted_root) {
    SIGN_SETUP("sg1.exe", CALG_SHA_256)
    DWORD e; WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p);
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_UNTRUSTEDROOT);
    wvt_del(p); eph_free(&eph);
}
TEST(wvt_sign_hash_only_ok) {
    SIGN_SETUP("sg2.exe", CALG_SHA_256)
    DWORD e; WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwProvFlags |= WTD_HASH_ONLY_FLAG;
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), 0);
    wvt_del(p); eph_free(&eph);
}
TEST(wvt_sign_signer_is_our_cert) {
    SIGN_SETUP("sg3.exe", CALG_SHA_256)
    DWORD e; WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_UNTRUSTEDROOT);
    CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    CRYPT_PROVIDER_SGNR *s = pd ? U(WTHelperGetProvSignerFromChain)(pd, 0, FALSE, 0) : NULL;
    CRYPT_PROVIDER_CERT *c = s ? U(WTHelperGetProvCertFromChain)(s, 0) : NULL;
    CHECK(c && c->pCert);
    if (c && c->pCert) {
        CHECK(U(CertCompareCertificate)(X509_ASN_ENCODING, c->pCert->pCertInfo, eph.cert->pCertInfo));
        CHECK(c->fSelfSigned); CHECK(!c->fTrustedRoot);
    }
    if (s && s->psSigner) EXPECT_STR(s->psSigner->HashAlgorithm.pszObjId, "2.16.840.1.101.3.4.2.1");
    wvt_close(&WVT_V2, &w); wvt_del(p); eph_free(&eph);
}
TEST(wvt_sign_sha1_digest_algorithm) {
    SIGN_SETUP("sg4.exe", CALG_SHA1)
    DWORD e; WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);
    CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    CRYPT_PROVIDER_SGNR *s = pd ? U(WTHelperGetProvSignerFromChain)(pd, 0, FALSE, 0) : NULL;
    if (s && s->psSigner) EXPECT_STR(s->psSigner->HashAlgorithm.pszObjId, "1.3.14.3.2.26");
    wvt_close(&WVT_V2, &w);
    LONG (WINAPI *gh)(const WCHAR *, DWORD, void *, BYTE *, DWORD *, ALG_ID *) = (void *)t_proc("WTHelperGetFileHash");
    REQUIRE_NOTNULL((void *)gh);
    { BYTE h[64]; DWORD cb = sizeof h; ALG_ID alg = 0; LONG hr = gh(p, 0, NULL, h, &cb, &alg);
        EXPECT_EQ(hr, 0); EXPECT_EQ(cb, 20); EXPECT_EQ(alg, CALG_SHA1); }
    wvt_del(p); eph_free(&eph);
}
TEST(wvt_sign_file_hash_helper_sha256) {
    SIGN_SETUP("sg5.exe", CALG_SHA_256)
    LONG (WINAPI *gh)(const WCHAR *, DWORD, void *, BYTE *, DWORD *, ALG_ID *) = (void *)t_proc("WTHelperGetFileHash");
    REQUIRE_NOTNULL((void *)gh);
    {
        BYTE h[64]; DWORD cb = sizeof h; ALG_ID alg = 0;
        EXPECT_EQ(gh(p, 0, NULL, h, &cb, &alg), 0); EXPECT_EQ(cb, 32); EXPECT_EQ(alg, 0xffffffff); /* Win10 reports an ALG_ID only for SHA1 digests; SHA256 gives -1 */
        /* the Authenticode digest of the image is the same value the embedded fixture carries (identical image bytes) */
        CHECK(!memcmp(h, fix_pe_sha256, 32));
    }
    wvt_del(p); eph_free(&eph);
}
TEST(wvt_sign_tamper_after_signing) {
    SIGN_SETUP("sg6.exe", CALG_SHA_256)
    HANDLE h = CreateFileW(p, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    BYTE b = 0; DWORD n;
    SetFilePointer(h, 0x200, NULL, FILE_BEGIN); ReadFile(h, &b, 1, &n, NULL); b ^= 0x10;
    SetFilePointer(h, 0x200, NULL, FILE_BEGIN); WriteFile(h, &b, 1, &n, NULL); CloseHandle(h);
    DWORD e; WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p);
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_BAD_DIGEST);
    wvt_del(p); eph_free(&eph);
}
TEST(wvt_sign_resign_observed) {
    SIGN_SETUP("sg7.exe", CALG_SHA_256)
    HRESULT hr2 = sign_file(&eph, p, CALG_SHA_256);
    EXPECT_EQ(hr2, 0);
    DWORD e; WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);
    CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    REQUIRE_NOTNULL(pd);
    EXPECT_EQ(pd->csSigners, 1);
    wvt_close(&WVT_V2, &w); wvt_del(p); eph_free(&eph);
}
TEST(wvt_sign_signature_info_reports_signed) {
    SIGN_SETUP("sg8.exe", CALG_SHA_256)
    typedef HRESULT (WINAPI *gsi_t)(const WCHAR *, HANDLE, DWORD, void *, PCCERT_CONTEXT *, HANDLE *);
    gsi_t f = (gsi_t)t_proc("WTGetSignatureInfo");
    REQUIRE_NOTNULL((void *)f);
    {
        BYTE si[0x58]; memset(si, 0, sizeof si); *(DWORD *)si = sizeof si; PCCERT_CONTEXT c = NULL;
        HRESULT hr = f(p, INVALID_HANDLE_VALUE, 1, si, &c, NULL); DWORD *d = (DWORD *)si;
        EXPECT_EQ(hr, 0); EXPECT_EQ(d[1], 2); EXPECT_EQ(d[2], 1); CHECK(c != NULL);   /* untrusted-root signature present */
        if (c) U(CertFreeCertificateContext)(c);
    }
    wvt_del(p); eph_free(&eph);
}
TEST(wvt_sign_cert_choice_runtime_cert) {
    WVT_REQUIRE_WVT();
    EPH eph; if (!eph_make(&eph, L"CN=cryptt WVT runtime cert choice")) { CHECKF(0, "cannot create the ephemeral cert"); eph_free(&eph); return; }
    WVTD w; WINTRUST_CERT_INFO ci; memset(&w, 0, sizeof w); memset(&ci, 0, sizeof ci);
    ci.cbStruct = sizeof ci; ci.psCertContext = (CERT_CONTEXT *)eph.cert; ci.dwFlags = WTCI_DONT_OPEN_STORES; ci.pcwszDisplayName = L"runtime";
    w.d.cbStruct = sizeof w; w.d.dwUIChoice = WTD_UI_NONE; w.d.dwUnionChoice = WTD_CHOICE_CERT; w.d.pCert = &ci;
    w.d.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    DWORD e; EXPECT_EQ(wvt_call(&WVT_CERTV, &w, &e), WVT_E_UNTRUSTEDROOT);
    eph_free(&eph);
}

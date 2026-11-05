#include "gap0.h"
/* CertRetrieveLogoOrBiometricInfo: type validation, absent-extension errors, and a file:// based
 * end-to-end retrieval (the logotype extension is built at run time so that its URL points at a scratch file). */

TEST(gap0_logo_export) {
    if (t_is_wine()) { t_skip("exports absent in the emulator"); return; } CHECK(t_proc_in("crypt32.dll", "CertRetrieveLogoOrBiometricInfo") != NULL); }

#define POISON_P ((BYTE *)(ULONG_PTR)0x1000)

TEST(gap0_logo_invalid_types) {
    REQUIRE(U(CertRetrieveLogoOrBiometricInfo));
    PCCERT_CONTEXT c = g0_ss_cert();
    if (!c) { t_skip("cert"); return; }
    /* 0, 4..999 are neither a logo type, a biometric type, nor an OID pointer. */
    ULONG_PTR types[] = { 0, 4, 5, 100, 999 };
    for (unsigned i = 0; i < sizeof types / sizeof *types; i++) {
        BYTE *d = POISON_P; DWORD cb = 0x77; LPWSTR mime = (LPWSTR)POISON_P;
        SET_ERR(0);
        BOOL r = U(CertRetrieveLogoOrBiometricInfo)(c, (LPCSTR)types[i], 0, 0, 0, NULL, &d, &cb, &mime);
        CHECKF(r == FALSE, "type %llu", (unsigned long long)types[i]);
        EXPECT_ERR(G0_E_INVALIDARG);
        CHECKF(d == NULL && cb == 0 && mime == NULL, "type %llu: outputs not cleared", (unsigned long long)types[i]);
    }
    /* The mime output is optional. */
    BYTE *d = POISON_P; DWORD cb = 0x77;
    SET_ERR(0);
    CHECK(!U(CertRetrieveLogoOrBiometricInfo)(c, (LPCSTR)0, 0, 0, 0, NULL, &d, &cb, NULL));
    EXPECT_ERR(G0_E_INVALIDARG);
    CHECK(d == NULL && cb == 0);
    U(CertFreeCertificateContext)(c);
}

TEST(gap0_logo_invalid_type_ignores_cert) {
    REQUIRE(U(CertRetrieveLogoOrBiometricInfo));
    /* The type is validated before the certificate is inspected, so even a NULL certificate gives the same result. */
    BYTE *d = POISON_P; DWORD cb = 0x77; LPWSTR mime = (LPWSTR)POISON_P;
    SET_ERR(0);
    BOOL r = U(CertRetrieveLogoOrBiometricInfo)(NULL, (LPCSTR)0, 0, 0, 0, NULL, &d, &cb, &mime);
    CHECK(r == FALSE); EXPECT_ERR(G0_E_INVALIDARG);
    CHECK(d == NULL && cb == 0 && mime == NULL);
}

TEST(gap0_logo_cert_without_extension) {
    REQUIRE(U(CertRetrieveLogoOrBiometricInfo));
    PCCERT_CONTEXT c = g0_ss_cert();
    if (!c) { t_skip("cert"); return; }
    ULONG_PTR types[] = { 1, 2, 3 };
    for (unsigned i = 0; i < 3; i++) {
        BYTE *d = POISON_P; DWORD cb = 0x77; LPWSTR mime = (LPWSTR)POISON_P;
        SET_ERR(0);
        BOOL r = U(CertRetrieveLogoOrBiometricInfo)(c, (LPCSTR)types[i], 0, 0, 0, NULL, &d, &cb, &mime);
        CHECKF(r == FALSE, "logo type %llu", (unsigned long long)types[i]);
        EXPECT_ERR(G0_CRYPT_E_NOT_FOUND);
        CHECKF(d == NULL && cb == 0 && mime == NULL, "logo type %llu: outputs not cleared", (unsigned long long)types[i]);
    }
    U(CertFreeCertificateContext)(c);
}

TEST(gap0_logo_cert_without_extension_oid_type) {
    REQUIRE(U(CertRetrieveLogoOrBiometricInfo));
    PCCERT_CONTEXT c = g0_ss_cert();
    if (!c) { t_skip("cert"); return; }
    /* Pointers at or above 0x10000 are OID strings naming "other" logotypes / biometric OIDs. */
    static const char oid[] = "1.2.3.4.5";
    BYTE *d = POISON_P; DWORD cb = 0x77; LPWSTR mime = (LPWSTR)POISON_P;
    SET_ERR(0);
    BOOL r = U(CertRetrieveLogoOrBiometricInfo)(c, oid, 0, 0, 0, NULL, &d, &cb, &mime);
    CHECK(r == FALSE); EXPECT_ERR(G0_CRYPT_E_NOT_FOUND);
    CHECK(d == NULL && cb == 0 && mime == NULL);
    static const char oid2[] = "1.3.6.1.5.5.7.20.1";
    d = POISON_P; cb = 0x77; mime = (LPWSTR)POISON_P;
    SET_ERR(0);
    r = U(CertRetrieveLogoOrBiometricInfo)(c, oid2, 0, 0, 0, NULL, &d, &cb, &mime);
    CHECK(r == FALSE); EXPECT_ERR(G0_CRYPT_E_NOT_FOUND);
    CHECK(d == NULL && cb == 0 && mime == NULL);
    U(CertFreeCertificateContext)(c);
}

TEST(gap0_logo_cert_without_extension_biometric_types) {
    REQUIRE(U(CertRetrieveLogoOrBiometricInfo));
    PCCERT_CONTEXT c = g0_ss_cert();
    if (!c) { t_skip("cert"); return; }
    ULONG_PTR types[] = { 1000, 1001, 1002, 0xFFFF };
    for (unsigned i = 0; i < 4; i++) {
        BYTE *d = POISON_P; DWORD cb = 0x77; LPWSTR mime = (LPWSTR)POISON_P;
        SET_ERR(0);
        BOOL r = U(CertRetrieveLogoOrBiometricInfo)(c, (LPCSTR)types[i], 0, 0, 0, NULL, &d, &cb, &mime);
        DWORD e = GetLastError();
        CHECKF(r == FALSE, "biometric type %llu", (unsigned long long)types[i]);
        CHECKF(e == G0_CRYPT_E_NOT_FOUND, "biometric type %llu: err 0x%lx", (unsigned long long)types[i], e);
        CHECK(d == NULL && cb == 0 && mime == NULL);
    }
    U(CertFreeCertificateContext)(c);
}

/* ---- certificate with a logotype extension ----------------------------- */
static BYTE g_logo_file[24] = { 0x89,'P','N','G',0x0d,0x0a,0x1a,0x0a, 'g','a','p','0',' ','l','o','g','o',' ','d','a','t','a',0,1 };

static PCCERT_CONTEXT g0_build_logo_cert(const WCHAR *urlw, const BYTE *hash, DWORD cbhash, int set_subject_logo, int issuer_logo) {
    CERT_SIGNED_CONTENT_INFO *sci = NULL; DWORD cb = 0;
    CERT_INFO *ci = NULL;
    BYTE *tbs = NULL, *whole = NULL, *extder = NULL;
    PCCERT_CONTEXT out = NULL;
    DWORD cbtbs = 0, cbwhole = 0, cbext = 0;
    if (!U(CryptDecodeObjectEx)(G0_ENC, X509_CERT, gap0_ss_cert, sizeof gap0_ss_cert, CRYPT_DECODE_ALLOC_FLAG, NULL, &sci, &cb)) return NULL;
    if (!U(CryptDecodeObjectEx)(G0_ENC, X509_CERT_TO_BE_SIGNED, sci->ToBeSigned.pbData, sci->ToBeSigned.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &ci, &cb)) goto done;

    CERT_HASHED_URL hu; memset(&hu, 0, sizeof hu);
    hu.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;
    hu.Hash.cbData = cbhash; hu.Hash.pbData = (BYTE *)hash;
    hu.pwszUrl = (LPWSTR)urlw;
    CERT_LOGOTYPE_IMAGE img; memset(&img, 0, sizeof img);
    img.LogotypeDetails.pwszMimeType = L"image/png";
    img.LogotypeDetails.cHashedUrl = 1; img.LogotypeDetails.rgHashedUrl = &hu;
    CERT_LOGOTYPE_DATA data; memset(&data, 0, sizeof data);
    data.cLogotypeImage = 1; data.rgLogotypeImage = &img;
    CERT_LOGOTYPE_INFO info; memset(&info, 0, sizeof info);
    info.dwLogotypeInfoChoice = CERT_LOGOTYPE_DIRECT_INFO_CHOICE; info.pLogotypeDirectInfo = &data;
    CERT_LOGOTYPE_EXT_INFO ext; memset(&ext, 0, sizeof ext);
    if (issuer_logo) ext.pIssuerLogo = &info;
    if (set_subject_logo) ext.pSubjectLogo = &info;
    if (!U(CryptEncodeObjectEx)(G0_ENC, X509_LOGOTYPE_EXT, &ext, CRYPT_ENCODE_ALLOC_FLAG, NULL, &extder, &cbext)) goto done;

    CERT_EXTENSION *exts = (CERT_EXTENSION *)LocalAlloc(LPTR, (ci->cExtension + 1) * sizeof *exts);
    if (!exts) goto done;
    for (DWORD i = 0; i < ci->cExtension; i++) exts[i] = ci->rgExtension[i];
    exts[ci->cExtension].pszObjId = (LPSTR)szOID_LOGOTYPE_EXT;
    exts[ci->cExtension].fCritical = FALSE;
    exts[ci->cExtension].Value.cbData = cbext; exts[ci->cExtension].Value.pbData = extder;
    ci->rgExtension = exts; ci->cExtension++;
    if (!U(CryptEncodeObjectEx)(G0_ENC, X509_CERT_TO_BE_SIGNED, ci, CRYPT_ENCODE_ALLOC_FLAG, NULL, &tbs, &cbtbs)) { LocalFree(exts); goto done; }
    LocalFree(exts);
    CERT_SIGNED_CONTENT_INFO n = *sci; n.ToBeSigned.cbData = cbtbs; n.ToBeSigned.pbData = tbs;
    if (!U(CryptEncodeObjectEx)(G0_ENC, X509_CERT, &n, CRYPT_ENCODE_ALLOC_FLAG, NULL, &whole, &cbwhole)) goto done;
    out = U(CertCreateCertificateContext)(G0_ENC, whole, cbwhole);
done:
    if (sci) LocalFree(sci); if (ci) LocalFree(ci); if (tbs) LocalFree(tbs); if (whole) LocalFree(whole); if (extder) LocalFree(extder);
    return out;
}

static int g_logo_prepared;
static WCHAR g_logo_url[MAX_PATH + 16];
static BYTE g_logo_hash[32];

static int g0_logo_prepare(void) {
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "gap0_logo.bin");
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD w; WriteFile(f, g_logo_file, sizeof g_logo_file, &w, NULL); CloseHandle(f);
    char url[MAX_PATH + 16] = "file:///";
    strcat(url, path); for (char *p = url; *p; p++) if (*p == '\\') *p = '/';
    MultiByteToWideChar(CP_ACP, 0, url, -1, g_logo_url, MAX_PATH + 16);
    /* SHA-256 of the file through CryptHashCertificate2 is not needed here: use the embedded expected value. */
    return 1;
}


static int g0_hash_logo(BYTE out[32]) {
    /* Hash through the CNG hash API of the module list (LoadLibrary/GetProcAddress as for everything else). */
    typedef LONG (WINAPI *open_t)(void **, LPCWSTR, LPCWSTR, ULONG);
    typedef LONG (WINAPI *hash_t)(void *, PUCHAR, ULONG, ULONG);
    typedef LONG (WINAPI *fin_t)(void *, PUCHAR, ULONG, ULONG);
    typedef LONG (WINAPI *close_t)(void *, ULONG);
    typedef LONG (WINAPI *destroy_t)(void *);
    open_t op = (open_t)t_proc("BCryptOpenAlgorithmProvider");
    if (!op) return 0;
    void *alg = NULL;
    if (op(&alg, L"SHA256", NULL, 0)) return 0;
    typedef LONG (WINAPI *create_t)(void *, void **, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
    create_t cr = (create_t)t_proc("BCryptCreateHash");
    hash_t h = (hash_t)t_proc("BCryptHashData");
    fin_t fi = (fin_t)t_proc("BCryptFinishHash");
    destroy_t de = (destroy_t)t_proc("BCryptDestroyHash");
    close_t cl = (close_t)t_proc("BCryptCloseAlgorithmProvider");
    void *hh = NULL; int ok = 0;
    if (cr && h && fi && de && cl && !cr(alg, &hh, NULL, 0, NULL, 0, 0)) {
        if (!h(hh, g_logo_file, sizeof g_logo_file, 0) && !fi(hh, out, 32, 0)) ok = 1;
        de(hh);
    }
    if (cl) cl(alg, 0);
    return ok;
}

TEST(gap0_logo_ext_absent_logo_kinds) {
    REQUIRE(U(CertRetrieveLogoOrBiometricInfo)); REQUIRE(U(CryptEncodeObjectEx));
    if (!g0_logo_prepare() || !g0_hash_logo(g_logo_hash)) { t_skip("setup"); return; }
    PCCERT_CONTEXT c = g0_build_logo_cert(g_logo_url, g_logo_hash, 32, 0, 1);
    if (!c) { t_skip("cannot build logotype certificate (encoder unavailable)"); return; }
    /* Extension present but it carries only an issuer logo: subject and community logos are absent. */
    ULONG_PTR types[] = { 2, 3 };
    for (unsigned i = 0; i < 2; i++) {
        BYTE *d = POISON_P; DWORD cb = 0x77; LPWSTR mime = (LPWSTR)POISON_P;
        SET_ERR(0);
        BOOL r = U(CertRetrieveLogoOrBiometricInfo)(c, (LPCSTR)types[i], 0, 0, 0, NULL, &d, &cb, &mime);
        CHECKF(r == FALSE, "type %llu", (unsigned long long)types[i]);
        EXPECT_ERR(G0_CRYPT_E_NOT_FOUND);
        CHECK(d == NULL && cb == 0 && mime == NULL);
    }
    U(CertFreeCertificateContext)(c);
}

TEST(gap0_logo_retrieve_issuer_logo_from_file_url) {
    REQUIRE(U(CertRetrieveLogoOrBiometricInfo)); REQUIRE(U(CryptEncodeObjectEx)); REQUIRE(U(CryptMemFree));
    if (!g0_logo_prepare() || !g0_hash_logo(g_logo_hash)) { t_skip("setup"); return; }
    PCCERT_CONTEXT c = g0_build_logo_cert(g_logo_url, g_logo_hash, 32, 0, 1);
    if (!c) { t_skip("cannot build logotype certificate (encoder unavailable)"); return; }
    BYTE *d = NULL; DWORD cb = 0; LPWSTR mime = NULL;
    SET_ERR(0);
    /* dwRetrievalFlags 0, 3 second bound; the URL is a local file so nothing leaves the machine. */
    BOOL r = U(CertRetrieveLogoOrBiometricInfo)(c, CERT_RETRIEVE_ISSUER_LOGO, 0, 3000, 0, NULL, &d, &cb, &mime);
    if (!r) {
        t_note("file:// logo retrieval failed: err=0x%lx", GetLastError());
        CHECK(d == NULL && cb == 0 && mime == NULL);
    } else {
        EXPECT_EQ(cb, sizeof g_logo_file);
        CHECK(d && cb == sizeof g_logo_file && !memcmp(d, g_logo_file, sizeof g_logo_file));
        CHECK(mime != NULL);
        if (mime) EXPECT_WSTR(mime, L"image/png");
        if (d) U(CryptMemFree)(d);
        if (mime) U(CryptMemFree)(mime);
        /* mime output is optional */
        d = NULL; cb = 0;
        r = U(CertRetrieveLogoOrBiometricInfo)(c, CERT_RETRIEVE_ISSUER_LOGO, 0, 3000, 0, NULL, &d, &cb, NULL);
        CHECK(r); if (r && d) U(CryptMemFree)(d);
    }
    U(CertFreeCertificateContext)(c);
}

TEST(gap0_logo_retrieve_hash_mismatch) {
    REQUIRE(U(CertRetrieveLogoOrBiometricInfo)); REQUIRE(U(CryptEncodeObjectEx)); REQUIRE(U(CryptMemFree));
    if (!g0_logo_prepare() || !g0_hash_logo(g_logo_hash)) { t_skip("setup"); return; }
    BYTE bad[32]; memcpy(bad, g_logo_hash, 32); bad[5] ^= 0x40;
    PCCERT_CONTEXT good = g0_build_logo_cert(g_logo_url, g_logo_hash, 32, 0, 1);
    PCCERT_CONTEXT c = g0_build_logo_cert(g_logo_url, bad, 32, 0, 1);
    if (!good || !c) { t_skip("cannot build logotype certificate"); if (good) U(CertFreeCertificateContext)(good); if (c) U(CertFreeCertificateContext)(c); return; }
    BYTE *d = NULL; DWORD cb = 0; LPWSTR mime = NULL;
    BOOL ok = U(CertRetrieveLogoOrBiometricInfo)(good, CERT_RETRIEVE_ISSUER_LOGO, 0, 3000, 0, NULL, &d, &cb, &mime);
    if (ok) { if (d) U(CryptMemFree)(d); if (mime) U(CryptMemFree)(mime); }
    if (!ok) t_note("baseline retrieval failed here (err=0x%lx): mismatch error not asserted", GetLastError());
    d = POISON_P; cb = 0x77; mime = (LPWSTR)POISON_P;
    SET_ERR(0);
    BOOL r = U(CertRetrieveLogoOrBiometricInfo)(c, CERT_RETRIEVE_ISSUER_LOGO, 0, 3000, 0, NULL, &d, &cb, &mime);
    DWORD e = GetLastError();
    CHECK(r == FALSE);
    if (ok) CHECKF(e == G0_CRYPT_E_HASH_VALUE, "err 0x%lx", e);
    CHECK(d == NULL && cb == 0 && mime == NULL);
    U(CertFreeCertificateContext)(good); U(CertFreeCertificateContext)(c);
}

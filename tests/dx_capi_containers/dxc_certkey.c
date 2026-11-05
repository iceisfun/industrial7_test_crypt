#include "dxc.h"
/* CryptAcquireCertificatePrivateKey on certificates bound (CERT_KEY_PROV_INFO_PROP_ID) to a
 * persisted CAPI container. Pinned from crypt32 CryptAcquireCertificatePrivateKey:
 *  - flags 0x40|0x80 together -> ERROR_INVALID_PARAMETER; NULL cert -> last error 0x80070057
 *  - CACHE (1), or USE_PROV_INFO (2) with CERT_SET_KEY_CONTEXT_PROP_ID in the provider info, store the
 *    handle in CERT_KEY_CONTEXT_PROP_ID (cbSize 0x18) and report *pfCallerFree = FALSE; otherwise TRUE
 *  - COMPARE_KEY (4) mismatch -> NTE_BAD_PUBLIC_KEY; no property -> CRYPT_E_NO_KEY_PROPERTY */

typedef struct {
    int pi; char cont[160]; WCHAR wcont[160]; WCHAR wprov[128];
    HCRYPTPROV h; PCCERT_CONTEXT cert; DWORD spec;
    CRYPT_KEY_PROV_INFO kpi;
} fx_t;

static void fx_kpi(fx_t *f, const char *cont, DWORD spec, DWORD kflags) {
    memset(&f->kpi, 0, sizeof f->kpi);
    int n = 0; while (cont[n]) { f->wcont[n] = cont[n]; n++; } f->wcont[n] = 0;
    MultiByteToWideChar(CP_ACP, 0, dxc_provs[f->pi].a, -1, f->wprov, 128);
    f->kpi.pwszContainerName = f->wcont; f->kpi.pwszProvName = f->wprov;
    f->kpi.dwProvType = dxc_provs[f->pi].type; f->kpi.dwFlags = kflags; f->kpi.dwKeySpec = spec;
}

static PCCERT_CONTEXT make_cert(HCRYPTPROV h, CRYPT_KEY_PROV_INFO *kpi, const char *cn) {
    BYTE nb[256]; DWORD nl = sizeof nb;
    char dn[200]; snprintf(dn, sizeof dn, "CN=%s", cn);
    if (!U(CertStrToNameA)(X509_ASN_ENCODING, dn, CERT_X500_NAME_STR, NULL, nb, &nl, NULL)) return NULL;
    CERT_NAME_BLOB subj = { nl, nb };
    CRYPT_ALGORITHM_IDENTIFIER alg; memset(&alg, 0, sizeof alg);
    alg.pszObjId = (LPSTR)"1.2.840.10040.4.3";          /* id-dsa-with-sha1 */
    int dss = kpi->dwProvType == PROV_DSS || kpi->dwProvType == PROV_DSS_DH;
    return U(CertCreateSelfSignCertificate)(h, &subj, 0, kpi, dss ? &alg : NULL, NULL, NULL, NULL);
}

/* container + key + self-signed certificate with the key provider info property set */
static int fx_make(fx_t *f, int pi, const char *tag, DWORD spec, DWORD kflags) {
    memset(f, 0, sizeof *f);
    f->pi = pi; f->spec = spec;
    if (!U(CertCreateSelfSignCertificate) || !U(CertStrToNameA) || !U(CryptAcquireCertificatePrivateKey) ||
        !U(CertFreeCertificateContext) || !U(CertGetCertificateContextProperty)) { t_skip("missing crypt32 export"); return 0; }
    if (!dxc_have(pi)) { t_skip("provider not available"); return 0; }
    dxc_prepare(pi, 0);
    snprintf(f->cont, sizeof f->cont, "%s", dxc_name(tag));
    dxc_del(f->cont, pi, 0);
    fx_kpi(f, f->cont, spec, kflags);
    HCRYPTKEY k = 0;
    if (!dxc_acq(&f->h, f->cont, pi, CRYPT_NEWKEYSET)) { CHECKF(0, "container create err 0x%lx", GetLastError()); return 0; }
    if (!U(CryptGenKey)(f->h, spec, 0, &k)) { CHECKF(0, "genkey err 0x%lx", GetLastError()); dxc_rel(f->h); dxc_del(f->cont, pi, 0); return 0; }
    U(CryptDestroyKey)(k);
    f->cert = make_cert(f->h, &f->kpi, tag);
    if (!f->cert) {
        CHECKF(0, "self-sign err 0x%lx", GetLastError());
        dxc_rel(f->h); dxc_del(f->cont, pi, 0); return 0;
    }
    return 1;
}
static void fx_free(fx_t *f) {
    if (f->cert) U(CertFreeCertificateContext)(f->cert);     /* releases a cached key context */
    dxc_rel(f->h);
    dxc_del(f->cont, f->pi, 0);
}

/* The self-signed certificate carries the provider info property that the API reads. */
static void c_property_present(int pi) {
    fx_t f; if (!fx_make(&f, pi, "ck_prop", AT_KEYEXCHANGE, 0)) return;
    BYTE buf[1024]; DWORD n = sizeof buf;
    BOOL ok = U(CertGetCertificateContextProperty)(f.cert, CERT_KEY_PROV_INFO_PROP_ID, buf, &n);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        CRYPT_KEY_PROV_INFO *p = (CRYPT_KEY_PROV_INFO *)buf;
        EXPECT_WSTR(p->pwszContainerName, f.wcont);
        EXPECT_WSTR(p->pwszProvName, f.wprov);
        EXPECT_EQ(p->dwProvType, dxc_provs[pi].type);
        EXPECT_EQ(p->dwKeySpec, AT_KEYEXCHANGE);
    }
    fx_free(&f);
}
TEST(dxc_certkey_prov_info_property_0) { c_property_present(3); }
TEST(dxc_certkey_prov_info_property_1) { c_property_present(1); }

/* ------------------------------------------------------------- basic, no cache */
static void c_basic(int pi, DWORD spec) {
    fx_t f; if (!fx_make(&f, pi, "ck_bas", spec, 0)) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD ks = 0; BOOL free_it = 99;
    SET_ERR(0);
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(f.cert, 0, NULL, &h, &ks, &free_it);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        CHECK(h != 0);
        EXPECT_EQ(ks, spec);
        EXPECT_EQ(free_it, TRUE);
        /* it is a CAPI provider handle bound to the container */
        char nm[300]; DWORD l = sizeof nm;
        CHECK(dxc_gpp((HCRYPTPROV)h, PP_CONTAINER, nm, &l, 0));
        EXPECT_STR(nm, f.cont);
        HCRYPTKEY k = 0;
        CHECK(U(CryptGetUserKey)((HCRYPTPROV)h, ks, &k));
        if (k) U(CryptDestroyKey)(k);
        /* a second call returns another, independent handle */
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h2 = 0; BOOL fr2 = 99;
        CHECK(U(CryptAcquireCertificatePrivateKey)(f.cert, 0, NULL, &h2, NULL, &fr2));
        CHECK(h2 != 0 && h2 != h);
        EXPECT_EQ(fr2, TRUE);
        dxc_rel((HCRYPTPROV)h2);
        dxc_rel((HCRYPTPROV)h);
    }
    fx_free(&f);
}
TEST(dxc_certkey_acquire_keyx_rsa_aes) { c_basic(3, AT_KEYEXCHANGE); }
TEST(dxc_certkey_acquire_sig_rsa_aes) { c_basic(3, AT_SIGNATURE); }
TEST(dxc_certkey_acquire_keyx_enhanced) { c_basic(1, AT_KEYEXCHANGE); }
TEST(dxc_certkey_acquire_sig_base) { c_basic(0, AT_SIGNATURE); }
TEST(dxc_certkey_acquire_sig_dss) { c_basic(4, AT_SIGNATURE); }

TEST(dxc_certkey_optional_outputs_null) {
    fx_t f; if (!fx_make(&f, 3, "ck_null", AT_KEYEXCHANGE, 0)) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0;
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(f.cert, 0, NULL, &h, NULL, NULL);
    CHECKF(ok, "err 0x%lx", GetLastError());
    dxc_rel((HCRYPTPROV)h);
    h = 0;
    ok = U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_CACHE_FLAG, NULL, &h, NULL, NULL);
    CHECKF(ok, "cache err 0x%lx", GetLastError());
    CHECK(h != 0);
    fx_free(&f);
}

TEST(dxc_certkey_silent_flag) {
    fx_t f; if (!fx_make(&f, 3, "ck_sil", AT_KEYEXCHANGE, 0)) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; BOOL fr = 0;
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &h, NULL, &fr);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) { EXPECT_EQ(fr, TRUE); dxc_rel((HCRYPTPROV)h); }
    fx_free(&f);
}

/* ------------------------------------------------------------- cache semantics */
TEST(dxc_certkey_cache_flag_semantics) {
    fx_t f; if (!fx_make(&f, 3, "ck_cache", AT_KEYEXCHANGE, 0)) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h1 = 0, h2 = 0, h3 = 0; DWORD ks1 = 0, ks2 = 0; BOOL fr1 = 99, fr2 = 99, fr3 = 99;
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_CACHE_FLAG, NULL, &h1, &ks1, &fr1);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (!ok) { fx_free(&f); return; }
    CHECK(h1 != 0); EXPECT_EQ(ks1, AT_KEYEXCHANGE); EXPECT_EQ(fr1, FALSE);   /* owned by the certificate context */
    /* second call hits the cache: same handle */
    CHECK(U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_CACHE_FLAG, NULL, &h2, &ks2, &fr2));
    EXPECT_EQ(h2, h1); EXPECT_EQ(ks2, AT_KEYEXCHANGE); EXPECT_EQ(fr2, FALSE);
    /* flags without CACHE/USE_PROV_INFO never consult the cache */
    CHECK(U(CryptAcquireCertificatePrivateKey)(f.cert, 0, NULL, &h3, NULL, &fr3));
    CHECK(h3 != 0 && h3 != h1); EXPECT_EQ(fr3, TRUE);
    dxc_rel((HCRYPTPROV)h3);
    /* the cache lives in the certificate: a duplicate reference sees the same handle */
    PCCERT_CONTEXT d = U(CertDuplicateCertificateContext)(f.cert);
    if (d) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h4 = 0; BOOL fr4 = 99;
        CHECK(U(CryptAcquireCertificatePrivateKey)(d, CRYPT_ACQUIRE_CACHE_FLAG, NULL, &h4, NULL, &fr4));
        EXPECT_EQ(h4, h1); EXPECT_EQ(fr4, FALSE);
        U(CertFreeCertificateContext)(d);
    }
    /* the context handle is usable while the cert lives */
    char nm[300]; DWORD l = sizeof nm;
    CHECK(dxc_gpp((HCRYPTPROV)h1, PP_CONTAINER, nm, &l, 0));
    EXPECT_STR(nm, f.cont);
    /* CERT_KEY_CONTEXT_PROP_ID (5) now holds the cached handle */
    CERT_KEY_CONTEXT kc; DWORD n = sizeof kc; memset(&kc, 0, sizeof kc);
    BOOL pk = U(CertGetCertificateContextProperty)(f.cert, CERT_KEY_CONTEXT_PROP_ID, &kc, &n);
    CHECKF(pk, "key ctx prop err 0x%lx", GetLastError());
    if (pk) {
        EXPECT_EQ(kc.cbSize, sizeof(CERT_KEY_CONTEXT));
        EXPECT_EQ(kc.hCryptProv, h1);
        EXPECT_EQ(kc.dwKeySpec, AT_KEYEXCHANGE);
    }
    fx_free(&f);
}

TEST(dxc_certkey_use_prov_info_flag_without_set_key_context) {
    /* USE_PROV_INFO_KEY_FLAG caches only if the provider info asks for it (CERT_SET_KEY_CONTEXT_PROP_ID) */
    fx_t f; if (!fx_make(&f, 3, "ck_upi0", AT_KEYEXCHANGE, 0)) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; BOOL fr = 99;
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, NULL, &h, NULL, &fr);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) { EXPECT_EQ(fr, TRUE); dxc_rel((HCRYPTPROV)h); }
    fx_free(&f);
}

TEST(dxc_certkey_use_prov_info_flag_with_set_key_context) {
    fx_t f; if (!fx_make(&f, 3, "ck_upi1", AT_KEYEXCHANGE, CERT_SET_KEY_CONTEXT_PROP_ID)) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0, h2 = 0; BOOL fr = 99, fr2 = 99;
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, NULL, &h, NULL, &fr);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        EXPECT_EQ(fr, FALSE);
        CHECK(U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, NULL, &h2, NULL, &fr2));
        EXPECT_EQ(h2, h); EXPECT_EQ(fr2, FALSE);
    }
    fx_free(&f);
}

TEST(dxc_certkey_preset_key_context_property) {
    fx_t f; if (!fx_make(&f, 3, "ck_pre", AT_KEYEXCHANGE, 0)) return;
    HCRYPTPROV mine = 0;
    CHECK(dxc_acq(&mine, f.cont, 3, 0));
    CERT_KEY_CONTEXT kc; memset(&kc, 0, sizeof kc);
    kc.cbSize = sizeof kc; kc.hCryptProv = mine; kc.dwKeySpec = AT_KEYEXCHANGE;
    BOOL ok = U(CertSetCertificateContextProperty)(f.cert, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, &kc);
    CHECKF(ok, "set err 0x%lx", GetLastError());
    if (ok) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD ks = 0; BOOL fr = 99;
        CHECK(U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_CACHE_FLAG, NULL, &h, &ks, &fr));
        EXPECT_EQ(h, mine); EXPECT_EQ(ks, AT_KEYEXCHANGE); EXPECT_EQ(fr, FALSE);
        /* drop the property while we still own the handle */
        CHECK(U(CertSetCertificateContextProperty)(f.cert, CERT_KEY_CONTEXT_PROP_ID, 0, NULL));
    }
    dxc_rel(mine);
    fx_free(&f);
}

/* ------------------------------------------------------------- errors */
TEST(dxc_certkey_invalid_flag_combination) {
    fx_t f; if (!fx_make(&f, 3, "ck_inv", AT_KEYEXCHANGE, 0)) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0x1234; BOOL fr = 99;
    SET_ERR(0);
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG, NULL, &h, NULL, &fr);
    CHECK(!ok); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    fx_free(&f);
}

TEST(dxc_certkey_null_certificate) {
    REQUIRE(U(CryptAcquireCertificatePrivateKey));
    if (t_is_wine()) { t_skip("emulator faults on a NULL certificate"); return; }
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD ks = 0; BOOL fr = 0;
    /* Win10 dereferences the certificate pointer without validating it */
    T_EXPECT_FAULT(U(CryptAcquireCertificatePrivateKey)(NULL, 0, NULL, &h, &ks, &fr));
    CHECK(h == 0);
}

TEST(dxc_certkey_no_key_property) {
    fx_t f; if (!fx_make(&f, 3, "ck_nop", AT_KEYEXCHANGE, 0)) return;
    PCCERT_CONTEXT bare = U(CertCreateCertificateContext)(X509_ASN_ENCODING, f.cert->pbCertEncoded, f.cert->cbCertEncoded);
    CHECK(bare != NULL);
    if (bare) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; BOOL fr = 99;
        SET_ERR(0);
        CHECK(!U(CryptAcquireCertificatePrivateKey)(bare, 0, NULL, &h, NULL, &fr));
        EXPECT_ERR(X_CRYPT_E_NO_KEY_PROPERTY);
        CHECK(h == 0);
        /* NO_HEALING skips the key-identifier fallback; still a failure */
        SET_ERR(0);
        CHECK(!U(CryptAcquireCertificatePrivateKey)(bare, CRYPT_ACQUIRE_NO_HEALING, NULL, &h, NULL, &fr));
        t_note("no property + NO_HEALING: err 0x%lx", GetLastError());
        U(CertFreeCertificateContext)(bare);
    }
    fx_free(&f);
}

TEST(dxc_certkey_missing_container) {
    fx_t f; if (!fx_make(&f, 3, "ck_mis", AT_KEYEXCHANGE, 0)) return;
    PCCERT_CONTEXT bare = U(CertCreateCertificateContext)(X509_ASN_ENCODING, f.cert->pbCertEncoded, f.cert->cbCertEncoded);
    CHECK(bare != NULL);
    if (bare) {
        fx_t g = f;
        char other[160]; snprintf(other, sizeof other, "%s", dxc_name("ck_gone"));
        dxc_del(other, 3, 0);
        fx_kpi(&g, other, AT_KEYEXCHANGE, 0);
        CHECK(U(CertSetCertificateContextProperty)(bare, CERT_KEY_PROV_INFO_PROP_ID, 0, &g.kpi));
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; BOOL fr = 99;
        SET_ERR(0);
        CHECK(!U(CryptAcquireCertificatePrivateKey)(bare, 0, NULL, &h, NULL, &fr));
        EXPECT_ERR(X_NTE_BAD_KEYSET);
        CHECK(h == 0);
        SET_ERR(0);
        CHECK(!U(CryptAcquireCertificatePrivateKey)(bare, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_NO_HEALING, NULL, &h, NULL, &fr));
        EXPECT_ERR(X_NTE_BAD_KEYSET);
        U(CertFreeCertificateContext)(bare);
    }
    fx_free(&f);
}

TEST(dxc_certkey_container_deleted_after_cert_created) {
    fx_t f; if (!fx_make(&f, 3, "ck_del", AT_KEYEXCHANGE, 0)) return;
    dxc_rel(f.h); f.h = 0;
    dxc_del(f.cont, 3, 0);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; BOOL fr = 99;
    SET_ERR(0);
    CHECK(!U(CryptAcquireCertificatePrivateKey)(f.cert, 0, NULL, &h, NULL, &fr));
    EXPECT_ERR(X_NTE_BAD_KEYSET);
    fx_free(&f);
}

TEST(dxc_certkey_compare_key_flag) {
    fx_t f; if (!fx_make(&f, 3, "ck_cmp", AT_KEYEXCHANGE, 0)) return;
    /* a second container with a different key pair, bound to a copy of the first certificate */
    const char *c2 = dxc_name("ck_cmp2"); dxc_del(c2, 3, 0);
    HCRYPTPROV h2 = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h2, c2, 3, CRYPT_NEWKEYSET));
    CHECK(U(CryptGenKey)(h2, AT_KEYEXCHANGE, 0, &k)); if (k) U(CryptDestroyKey)(k);
    PCCERT_CONTEXT bare = U(CertCreateCertificateContext)(X509_ASN_ENCODING, f.cert->pbCertEncoded, f.cert->cbCertEncoded);
    CHECK(bare != NULL);
    if (bare) {
        fx_t g = f; fx_kpi(&g, c2, AT_KEYEXCHANGE, 0);
        CHECK(U(CertSetCertificateContextProperty)(bare, CERT_KEY_PROV_INFO_PROP_ID, 0, &g.kpi));
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; BOOL fr = 99;
        /* without COMPARE_KEY the mismatch is not detected */
        BOOL ok = U(CryptAcquireCertificatePrivateKey)(bare, 0, NULL, &h, NULL, &fr);
        CHECKF(ok, "plain err 0x%lx", GetLastError());
        if (ok) dxc_rel((HCRYPTPROV)h);
        h = 0;
        SET_ERR(0);
        ok = U(CryptAcquireCertificatePrivateKey)(bare, CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &h, NULL, &fr);
        CHECK(!ok); EXPECT_ERR(X_NTE_BAD_PUBLIC_KEY);
        if (ok) dxc_rel((HCRYPTPROV)h);
        U(CertFreeCertificateContext)(bare);
    }
    /* the matching container passes the comparison */
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; BOOL fr = 99;
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(f.cert, CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &h, NULL, &fr);
    CHECKF(ok, "matching err 0x%lx", GetLastError());
    if (ok) dxc_rel((HCRYPTPROV)h);
    dxc_rel(h2); dxc_del(c2, 3, 0);
    fx_free(&f);
}

TEST(dxc_certkey_wrong_keyspec_in_info) {
    /* property says AT_SIGNATURE but only a key exchange key exists: the acquire itself works, the key spec is echoed */
    fx_t f; if (!fx_make(&f, 3, "ck_wsp", AT_KEYEXCHANGE, 0)) return;
    PCCERT_CONTEXT bare = U(CertCreateCertificateContext)(X509_ASN_ENCODING, f.cert->pbCertEncoded, f.cert->cbCertEncoded);
    if (bare) {
        fx_t g = f; fx_kpi(&g, f.cont, AT_SIGNATURE, 0);
        CHECK(U(CertSetCertificateContextProperty)(bare, CERT_KEY_PROV_INFO_PROP_ID, 0, &g.kpi));
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD ks = 0; BOOL fr = 99;
        BOOL ok = U(CryptAcquireCertificatePrivateKey)(bare, 0, NULL, &h, &ks, &fr);
        t_note("keyspec AT_SIGNATURE without such key: ok=%d err 0x%lx ks=%lu", ok, GetLastError(), ks);
        if (ok) dxc_rel((HCRYPTPROV)h);
        h = 0;
        SET_ERR(0);
        ok = U(CryptAcquireCertificatePrivateKey)(bare, CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &h, &ks, &fr);
        CHECK(!ok);
        t_note("same with COMPARE_KEY: err 0x%lx", GetLastError());
        if (ok) dxc_rel((HCRYPTPROV)h);
        U(CertFreeCertificateContext)(bare);
    }
    fx_free(&f);
}

/* ------------------------------------------------------------- the key really signs for the certificate */
TEST(dxc_certkey_signature_verifies_against_cert_key) {
    fx_t f; if (!fx_make(&f, 3, "ck_sig", AT_SIGNATURE, 0)) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD ks = 0; BOOL fr = 0;
    if (!U(CryptAcquireCertificatePrivateKey)(f.cert, 0, NULL, &h, &ks, &fr)) { CHECKF(0, "err 0x%lx", GetLastError()); fx_free(&f); return; }
    HCRYPTHASH hh = 0;
    CHECK(U(CryptCreateHash)((HCRYPTPROV)h, CALG_SHA1, 0, 0, &hh));
    static const BYTE msg[] = "certificate bound signing key";
    CHECK(U(CryptHashData)(hh, msg, sizeof msg - 1, 0));
    BYTE sig[512]; DWORD sl = sizeof sig;
    BOOL ok = U(CryptSignHashA)(hh, ks, NULL, 0, sig, &sl);
    CHECKF(ok, "sign err 0x%lx", GetLastError());
    U(CryptDestroyHash)(hh);
    if (ok) {
        /* import the public key out of the certificate and verify */
        HCRYPTPROV v = 0; HCRYPTKEY pub = 0;
        CHECK(dxc_acq(&v, NULL, 3, CRYPT_VERIFYCONTEXT));
        CHECK(U(CryptImportPublicKeyInfo)(v, X509_ASN_ENCODING, &f.cert->pCertInfo->SubjectPublicKeyInfo, &pub));
        HCRYPTHASH vh = 0;
        CHECK(U(CryptCreateHash)(v, CALG_SHA1, 0, 0, &vh));
        CHECK(U(CryptHashData)(vh, msg, sizeof msg - 1, 0));
        CHECKF(U(CryptVerifySignatureA)(vh, sig, sl, pub, NULL, 0), "verify err 0x%lx", GetLastError());
        U(CryptDestroyHash)(vh);
        if (pub) U(CryptDestroyKey)(pub);
        dxc_rel(v);
    }
    if (fr) dxc_rel((HCRYPTPROV)h);
    fx_free(&f);
}

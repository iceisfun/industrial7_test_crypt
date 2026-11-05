#include "dxgap0.h"
/* FindCertsByIssuer (wintrust.dll) enumerates the current user's My store (and refreshes legacy IE3 client
 * certificates), so it lives in the state-changing area. A throw-away certificate with a key container is
 * added to HKCU\My and removed again in every test, also at start-up to sweep earlier aborted runs. */

UDECL(HRESULT, FindCertsByIssuer, (PCERT_CHAIN, DWORD *, DWORD *, BYTE *, DWORD, LPCWSTR, DWORD));

#define MS_ENH "Microsoft Enhanced Cryptographic Provider v1.0"
#define NAME_PREFIX "cryptt_gap0_fci_"

static char g_cn[96], g_cont[96];
static WCHAR g_contw[96], g_provw[] = L"" MS_ENH;

static void names(void) {
    snprintf(g_cn, sizeof g_cn, NAME_PREFIX "%lu", GetCurrentProcessId());
    snprintf(g_cont, sizeof g_cont, "%s", g_cn);
    MultiByteToWideChar(CP_ACP, 0, g_cont, -1, g_contw, 96);
}

static void del_container(const char *name) {
    HCRYPTPROV h = 0;
    U(CryptAcquireContextA)(&h, name, MS_ENH, PROV_RSA_FULL, CRYPT_DELETEKEYSET | CRYPT_SILENT);
}

/* Remove every certificate of ours from HKCU\My plus its container (also from dead processes). */
static void sweep(void) {
    HCERTSTORE s = dx_open_hkcu(L"My");
    if (!s) return;
    PCCERT_CONTEXT c = NULL;
    int again = 1;
    while (again) {
        again = 0;
        c = NULL;
        while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL) {
            char nm[128] = "";
            U(CertGetNameStringA)(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nm, sizeof nm);
            if (strncmp(nm, NAME_PREFIX, strlen(NAME_PREFIX))) continue;
            DWORD cb = 0;
            if (U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb) && cb) {
                CRYPT_KEY_PROV_INFO *ki = (CRYPT_KEY_PROV_INFO *)LocalAlloc(LPTR, cb);
                if (ki && U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, ki, &cb)) {
                    char cont[128]; WideCharToMultiByte(CP_ACP, 0, ki->pwszContainerName, -1, cont, sizeof cont, NULL, NULL);
                    del_container(cont);
                }
                if (ki) LocalFree(ki);
            }
            U(CertDeleteCertificateFromStore)(U(CertDuplicateCertificateContext)(c));   /* frees the duplicate */
            again = 1;
            break;   /* enumeration is invalid after a delete: restart */
        }
        if (again && c) U(CertFreeCertificateContext)(c);
    }
    U(CertCloseStore)(s, 0);
}

static PCCERT_CONTEXT make_cert(HCERTSTORE my, CERT_NAME_BLOB *subj_out, BYTE **subj_buf) {
    HCRYPTPROV hp = 0; HCRYPTKEY hk = 0; PCCERT_CONTEXT ctx = NULL;
    del_container(g_cont);
    if (!U(CryptAcquireContextA)(&hp, g_cont, MS_ENH, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_SILENT)) return NULL;
    if (!U(CryptGenKey)(hp, AT_SIGNATURE, (1024u << 16), &hk)) { U(CryptReleaseContext)(hp, 0); del_container(g_cont); return NULL; }
    U(CryptDestroyKey)(hk);
    char dn[160]; snprintf(dn, sizeof dn, "CN=%s", g_cn);
    DWORD cbn = 0;
    if (!U(CertStrToNameA)(DX_ENC, dn, CERT_X500_NAME_STR, NULL, NULL, &cbn, NULL)) goto out;
    BYTE *nb = (BYTE *)LocalAlloc(LPTR, cbn);
    if (!U(CertStrToNameA)(DX_ENC, dn, CERT_X500_NAME_STR, NULL, nb, &cbn, NULL)) { LocalFree(nb); goto out; }
    CRYPT_KEY_PROV_INFO kpi; memset(&kpi, 0, sizeof kpi);
    kpi.pwszContainerName = g_contw; kpi.pwszProvName = g_provw; kpi.dwProvType = PROV_RSA_FULL; kpi.dwKeySpec = AT_SIGNATURE;
    CERT_NAME_BLOB nblob = { cbn, nb };
    ctx = U(CertCreateSelfSignCertificate)(hp, &nblob, 0, &kpi, NULL, NULL, NULL, NULL);
    if (!ctx) { LocalFree(nb); goto out; }
    if (!U(CertAddCertificateContextToStore)(my, ctx, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        U(CertFreeCertificateContext)(ctx); ctx = NULL; LocalFree(nb); goto out;
    }
    subj_out->cbData = cbn; subj_out->pbData = nb; *subj_buf = nb;
out:
    U(CryptReleaseContext)(hp, 0);
    if (!ctx) del_container(g_cont);
    return ctx;
}

#define PREP() \
    FindCertsByIssuer_pfn fci = (FindCertsByIssuer_pfn)t_proc_in("wintrust.dll", "FindCertsByIssuer"); \
    if (t_is_wine()) { t_skip("stub in the emulator"); return; } \
    REQUIRE(fci); REQUIRE(U(CertOpenStore)); REQUIRE(U(CryptAcquireContextA)); \
    names(); sweep(); \
    HCERTSTORE my = dx_open_hkcu(L"My"); \
    if (!my) { t_skip("HKCU\\My unavailable"); return; } \
    CERT_NAME_BLOB issuer = { 0, NULL }; BYTE *nbuf = NULL; \
    PCCERT_CONTEXT cert = make_cert(my, &issuer, &nbuf); \
    if (!cert) { U(CertCloseStore)(my, 0); sweep(); t_skip("cannot create a persisted test certificate here"); return; }

#define DONE() do { U(CertFreeCertificateContext)(cert); if (nbuf) LocalFree(nbuf); U(CertCloseStore)(my, 0); sweep(); del_container(g_cont); } while (0)

TEST(dx_gap0_fci_size_query_then_fetch) {
    PREP();
    DWORD cb = 0xAAAA, cnt = 0xBBBB;
    HRESULT hr = fci(NULL, &cb, &cnt, issuer.pbData, issuer.cbData, NULL, 0);
    if (hr != 0) { t_note("size query hr=0x%lx", (unsigned long)hr); DONE(); return; }
    CHECK(cnt >= 1); CHECK(cb > 0);
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, cb + 64);
    DWORD cb2 = cb, cnt2 = 0;
    hr = fci((PCERT_CHAIN)buf, &cb2, &cnt2, issuer.pbData, issuer.cbData, NULL, 0);
    CHECKF(hr == 0, "hr=0x%lx", (unsigned long)hr);
    EXPECT_EQ(cnt2, cnt); EXPECT_EQ(cb2, cb);
    int found = 0;
    PCERT_CHAIN ch = (PCERT_CHAIN)buf;
    for (DWORD i = 0; hr == 0 && i < cnt2; i++) {
        if (ch[i].cCerts == 0 || !ch[i].certs) continue;
        if (ch[i].certs[0].cbData == cert->cbCertEncoded && !memcmp(ch[i].certs[0].pbData, cert->pbCertEncoded, cert->cbCertEncoded)) {
            found = 1;
            CHECK(ch[i].keyLocatorInfo.pwszContainerName && !lstrcmpW(ch[i].keyLocatorInfo.pwszContainerName, g_contw));
            EXPECT_EQ(ch[i].keyLocatorInfo.dwProvType, PROV_RSA_FULL);
            EXPECT_EQ(ch[i].keyLocatorInfo.dwKeySpec, AT_SIGNATURE);
        }
    }
    CHECK(found);
    LocalFree(buf);
    DONE();
}

TEST(dx_gap0_fci_buffer_too_small) {
    PREP();
    DWORD cb = 0, cnt = 0;
    HRESULT hr = fci(NULL, &cb, &cnt, issuer.pbData, issuer.cbData, NULL, 0);
    if (hr != 0 || cb < 2) { t_note("size query hr=0x%lx", (unsigned long)hr); DONE(); return; }
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, cb + 64);
    DWORD need = cb, c2 = 0;
    DWORD small_sizes[] = { 1, cb / 2, cb - 1 };
    for (unsigned i = 0; i < 3; i++) {
        DWORD s = small_sizes[i]; c2 = 0;
        hr = fci((PCERT_CHAIN)buf, &s, &c2, issuer.pbData, issuer.cbData, NULL, 0);
        CHECKF(hr == (HRESULT)0x80070018, "size %lu: hr=0x%lx", small_sizes[i], (unsigned long)hr);
        EXPECT_EQ(s, need);        /* required size reported back */
        EXPECT_EQ(c2, cnt);
    }
    /* A non-NULL buffer with *pcb == 0 behaves like a size query. */
    DWORD z = 0; c2 = 0;
    hr = fci((PCERT_CHAIN)buf, &z, &c2, issuer.pbData, issuer.cbData, NULL, 0);
    CHECKF(hr == 0, "zero size: hr=0x%lx", (unsigned long)hr);
    EXPECT_EQ(z, need); EXPECT_EQ(c2, cnt);
    LocalFree(buf);
    DONE();
}

TEST(dx_gap0_fci_unknown_issuer_not_found) {
    PREP();
    BYTE nb[128]; DWORD cbn = sizeof nb;
    if (!U(CertStrToNameA)(DX_ENC, "CN=cryptt_gap0_no_such_issuer_anywhere", CERT_X500_NAME_STR, NULL, nb, &cbn, NULL)) { DONE(); t_skip("name"); return; }
    DWORD cb = 0xAAAA, cnt = 0xBBBB;
    HRESULT hr = fci(NULL, &cb, &cnt, nb, cbn, NULL, 0);
    CHECKF(hr == (HRESULT)0x80092004, "hr=0x%lx", (unsigned long)hr);
    EXPECT_EQ(cb, 0); EXPECT_EQ(cnt, 0);
    /* same result when a buffer is supplied */
    BYTE buf[64]; cb = sizeof buf; cnt = 0xBBBB;
    hr = fci((PCERT_CHAIN)buf, &cb, &cnt, nb, cbn, NULL, 0);
    CHECKF(hr == (HRESULT)0x80092004, "hr=0x%lx", (unsigned long)hr);
    EXPECT_EQ(cb, 0); EXPECT_EQ(cnt, 0);
    DONE();
}

TEST(dx_gap0_fci_key_spec_filter_observed) {
    PREP();
    DWORD specs[] = { 0, AT_KEYEXCHANGE, AT_SIGNATURE, 3 };
    for (unsigned i = 0; i < 4; i++) {
        DWORD cb = 0, cnt = 0;
        HRESULT hr = fci(NULL, &cb, &cnt, issuer.pbData, issuer.cbData, NULL, specs[i]);
        t_note("dwKeySpec=%lu: hr=0x%lx cb=%lu cnt=%lu", specs[i], (unsigned long)hr, cb, cnt);
    }
    /* The certificate holds an AT_SIGNATURE key, so asking for exactly that spec must find it. */
    DWORD cb = 0, cnt = 0;
    HRESULT hr = fci(NULL, &cb, &cnt, issuer.pbData, issuer.cbData, NULL, AT_SIGNATURE);
    if (hr == 0) CHECK(cnt >= 1);
    DONE();
}

TEST(dx_gap0_fci_export_lives_in_wintrust) {
    if (t_is_wine()) { t_skip("emulator"); return; }
    CHECK(t_proc_in("wintrust.dll", "FindCertsByIssuer") != NULL);
}

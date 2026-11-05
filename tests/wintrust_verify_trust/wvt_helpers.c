/* WTHelper* / Trust* exports, exercised with synthetic provider data where the behaviour is pure. */
#include "wvt.h"

static PCCERT_CONTEXT mk(const BYTE *d, DWORD n) { return U(CertCreateCertificateContext)(X509_ASN_ENCODING, d, n); }

/* ---- WTHelperGetKnownUsages ---------------------------------------------------- */
TEST(wvt_known_usages_null_out) {
    BOOL (WINAPI *f)(DWORD, PCCRYPT_OID_INFO **) = (void *)t_proc("WTHelperGetKnownUsages"); if (!f) { t_skip("missing export"); return; }
    SET_ERR(0); CHECK(!f(0, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(1, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(2, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(3, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(wvt_known_usages_bad_action_clears_out) {
    BOOL (WINAPI *f)(DWORD, PCCRYPT_OID_INFO **) = (void *)t_proc("WTHelperGetKnownUsages"); if (!f) { t_skip("missing export"); return; }
    static const DWORD acts[] = { 0, 3, 4, 100, 0xffffffff };
    for (int i = 0; i < 5; i++) {
        PCCRYPT_OID_INFO *u = (PCCRYPT_OID_INFO *)(ULONG_PTR)0x1000;   /* never dereferenced or freed on this path */
        SET_ERR(0); CHECK(!f(acts[i], &u)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECKF(u == NULL, "action %lu", (unsigned long)acts[i]);
    }
}
TEST(wvt_known_usages_alloc_and_free) {
    BOOL (WINAPI *f)(DWORD, PCCRYPT_OID_INFO **) = (void *)t_proc("WTHelperGetKnownUsages"); if (!f) { t_skip("missing export"); return; }
    PCCRYPT_OID_INFO *u = NULL;
    CHECK(f(1, &u)); CHECK(u != NULL);
    int n = 0, code = 0;
    for (PCCRYPT_OID_INFO *p = u; p && *p && n < 1000; p++, n++) {
        CHECK((*p)->dwGroupId == CRYPT_ENHKEY_USAGE_OID_GROUP_ID);
        CHECK((*p)->cbSize >= sizeof(CRYPT_OID_INFO));
        CHECK((*p)->pszOID != NULL);
        if ((*p)->pszOID && !strcmp((*p)->pszOID, "1.3.6.1.5.5.7.3.3")) code = 1;
    }
    CHECK(n > 5); CHECK(code);
    t_note("known usages: %d entries", n);
    SET_ERR(0xdeadbeef);
    CHECK(f(2, &u)); CHECK(u == NULL);
}
TEST(wvt_known_usages_free_null_ok) {
    BOOL (WINAPI *f)(DWORD, PCCRYPT_OID_INFO **) = (void *)t_proc("WTHelperGetKnownUsages"); if (!f) { t_skip("missing export"); return; }
    PCCRYPT_OID_INFO *u = NULL;
    CHECK(f(2, &u)); CHECK(u == NULL);
}
TEST(wvt_known_usages_alloc_twice_distinct) {
    BOOL (WINAPI *f)(DWORD, PCCRYPT_OID_INFO **) = (void *)t_proc("WTHelperGetKnownUsages"); if (!f) { t_skip("missing export"); return; }
    PCCRYPT_OID_INFO *a = NULL, *b = NULL;
    CHECK(f(1, &a)); CHECK(f(1, &b)); CHECK(a && b && a != b);
    if (a && b) { int i = 0; while (a[i] && b[i] && a[i] == b[i]) i++; CHECK(a[i] == NULL && b[i] == NULL); } /* same registered infos */
    f(2, &a); f(2, &b);
}

/* ---- WTHelperGetFileName / GetFileHandle (pure on WINTRUST_DATA) ---------------------- */
static WVTD mkw(DWORD choice, void *p) { WVTD w; memset(&w, 0, sizeof w); w.d.cbStruct = sizeof w; w.d.dwUnionChoice = choice; w.d.pFile = p; return w; }
TEST(wvt_getfilename_file_choice) {
    WCHAR *(WINAPI *f)(void *) = (void *)t_proc("WTHelperGetFileName"); if (!f) { t_skip("missing export"); return; }
    WINTRUST_FILE_INFO fi = { sizeof fi, L"C:\\dir\\file.exe" }; WVTD w = mkw(WTD_CHOICE_FILE, &fi);
    CHECK(f(&w) == fi.pcwszFilePath);
    fi.pcwszFilePath = NULL; EXPECT_WSTR(f(&w), L"Unspecified Name");
}
TEST(wvt_getfilename_catalog_choice) {
    WCHAR *(WINAPI *f)(void *) = (void *)t_proc("WTHelperGetFileName"); if (!f) { t_skip("missing export"); return; }
    WINTRUST_CATALOG_INFO ci; memset(&ci, 0, sizeof ci); ci.cbStruct = sizeof ci;
    ci.pcwszCatalogFilePath = L"c.cat"; ci.pcwszMemberTag = L"TAG"; ci.pcwszMemberFilePath = L"member.dll";
    WVTD w = mkw(WTD_CHOICE_CATALOG, &ci);
    CHECK(f(&w) == ci.pcwszMemberFilePath);
    ci.pcwszCatalogFilePath = NULL; EXPECT_WSTR(f(&w), L"Unspecified Name");
    ci.pcwszCatalogFilePath = L"c.cat"; ci.pcwszMemberTag = NULL; EXPECT_WSTR(f(&w), L"Unspecified Name");
    ci.pcwszMemberTag = L"TAG"; ci.pcwszMemberFilePath = NULL; EXPECT_WSTR(f(&w), L"Unspecified Name");
}
TEST(wvt_getfilename_blob_choice) {
    WCHAR *(WINAPI *f)(void *) = (void *)t_proc("WTHelperGetFileName"); if (!f) { t_skip("missing export"); return; }
    WINTRUST_BLOB_INFO bi; memset(&bi, 0, sizeof bi); bi.cbStruct = sizeof bi;
    WVTD w = mkw(WTD_CHOICE_BLOB, &bi);
    EXPECT_WSTR(f(&w), L"Blob");
    bi.pcwszDisplayName = L"my blob"; CHECK(f(&w) == bi.pcwszDisplayName);
}
TEST(wvt_getfilename_signer_choice) {
    WCHAR *(WINAPI *f)(void *) = (void *)t_proc("WTHelperGetFileName"); if (!f) { t_skip("missing export"); return; }
    WINTRUST_SGNR_INFO si; memset(&si, 0, sizeof si); si.cbStruct = sizeof si;
    WVTD w = mkw(WTD_CHOICE_SIGNER, &si);
    EXPECT_WSTR(f(&w), L"Signer");
    si.pcwszDisplayName = L"my signer"; CHECK(f(&w) == si.pcwszDisplayName);
}
TEST(wvt_getfilename_cert_choice) {
    WCHAR *(WINAPI *f)(void *) = (void *)t_proc("WTHelperGetFileName"); if (!f) { t_skip("missing export"); return; }
    WINTRUST_CERT_INFO ci; memset(&ci, 0, sizeof ci); ci.cbStruct = sizeof ci;
    WVTD w = mkw(WTD_CHOICE_CERT, &ci);
    EXPECT_WSTR(f(&w), L"Certificate");
    ci.pcwszDisplayName = L"my cert"; CHECK(f(&w) == ci.pcwszDisplayName);
}
TEST(wvt_getfilename_other_choices) {
    WCHAR *(WINAPI *f)(void *) = (void *)t_proc("WTHelperGetFileName"); if (!f) { t_skip("missing export"); return; }
    static const DWORD ch[] = { 0, 6, 7, 100 };
    for (int i = 0; i < 4; i++) { WVTD w = mkw(ch[i], NULL); EXPECT_WSTR(f(&w), L"Unspecified Name"); }
}
TEST(wvt_getfilehandle_choices) {
    HANDLE (WINAPI *f)(void *) = (void *)t_proc("WTHelperGetFileHandle"); if (!f) { t_skip("missing export"); return; }
    WINTRUST_FILE_INFO fi = { sizeof fi, L"x", (HANDLE)(ULONG_PTR)0x1234 }; WVTD w = mkw(WTD_CHOICE_FILE, &fi);
    CHECK(f(&w) == fi.hFile);
    fi.hFile = NULL; CHECK(f(&w) == NULL);
    WINTRUST_CATALOG_INFO ci; memset(&ci, 0, sizeof ci); ci.cbStruct = sizeof ci; ci.hMemberFile = (HANDLE)(ULONG_PTR)0x4321;
    w = mkw(WTD_CHOICE_CATALOG, &ci); CHECK(f(&w) == ci.hMemberFile);
    static const DWORD ch[] = { 0, WTD_CHOICE_BLOB, WTD_CHOICE_SIGNER, WTD_CHOICE_CERT, 6, 99 };
    for (int i = 0; i < 6; i++) { w = mkw(ch[i], NULL); CHECKF(f(&w) == INVALID_HANDLE_VALUE, "choice %lu", (unsigned long)ch[i]); }
}

/* ---- provider-chain accessors on synthetic provider data ------------------------------ */
TEST(wvt_chain_accessors_synthetic) {
    if (!U(WTHelperGetProvSignerFromChain)) { t_skip("missing export"); return; }
    CRYPT_PROVIDER_SGNR sg[2]; CRYPT_PROVIDER_SGNR cs[3]; CRYPT_PROVIDER_CERT ce[3]; WVT_PD pd;
    memset(sg, 0, sizeof sg); memset(cs, 0, sizeof cs); memset(ce, 0, sizeof ce); memset(&pd, 0, sizeof pd);
    pd.d.cbStruct = sizeof pd; pd.d.csSigners = 2; pd.d.pasSigners = sg;
    sg[0].csCounterSigners = 3; sg[0].pasCounterSigners = cs; sg[0].csCertChain = 3; sg[0].pasCertChain = ce;
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 0, FALSE, 0) == &sg[0]);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 1, FALSE, 0) == &sg[1]);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 2, FALSE, 0) == NULL);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 0, FALSE, 99) == &sg[0]);      /* counter index ignored for primary */
    for (DWORD i = 0; i < 3; i++) CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 0, TRUE, i) == &cs[i]);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 0, TRUE, 3) == NULL);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 1, TRUE, 0) == NULL);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 2, TRUE, 0) == NULL);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 0, 2, 1) == &cs[1]);           /* any non-zero BOOL */
    for (DWORD i = 0; i < 3; i++) CHECK(U(WTHelperGetProvCertFromChain)(&sg[0], i) == &ce[i]);
    CHECK(U(WTHelperGetProvCertFromChain)(&sg[0], 3) == NULL);
    CHECK(U(WTHelperGetProvCertFromChain)(&sg[1], 0) == NULL);
    CHECK(U(WTHelperGetProvCertFromChain)(NULL, 0) == NULL);
    pd.d.csSigners = 0;
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd.d, 0, FALSE, 0) == NULL);
}
TEST(wvt_private_data_synthetic) {
    if (!U(WTHelperGetProvPrivateDataFromChain)) { t_skip("missing export"); return; }
    CRYPT_PROVIDER_PRIVDATA pr[3]; WVT_PD pd; memset(pr, 0, sizeof pr); memset(&pd, 0, sizeof pd);
    pr[0].gProviderID = (GUID){ 0x11111111, 0x2222, 0x3333, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    pr[1].gProviderID = (GUID){ 0x11111111, 0x2222, 0x3333, { 1, 2, 3, 4, 5, 6, 7, 9 } };
    pr[2].gProviderID = pr[0].gProviderID;
    pd.d.csProvPrivData = 3; pd.d.pasProvPrivData = pr;
    GUID g0 = pr[0].gProviderID, g1 = pr[1].gProviderID;
    CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd.d, &g0) == &pr[0]);        /* first match wins */
    CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd.d, &g1) == &pr[1]);
    GUID g2 = g0; g2.Data1++;     CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd.d, &g2) == NULL);
    g2 = g0; g2.Data2++;          CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd.d, &g2) == NULL);
    g2 = g0; g2.Data3++;          CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd.d, &g2) == NULL);
    g2 = g0; g2.Data4[7] = 0xee;  CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd.d, &g2) == NULL);
    g2 = g0; g2.Data4[0] = 0xee;  CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd.d, &g2) == NULL);
    pd.d.csProvPrivData = 0;      CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd.d, &g0) == NULL);
    CHECK(U(WTHelperGetProvPrivateDataFromChain)(NULL, &g0) == NULL);
}

/* ---- certificate helpers -------------------------------------------------------------- */
TEST(wvt_cert_is_self_signed_table) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    if (!U(WTHelperCertIsSelfSigned)) { t_skip("missing export"); return; }
    static const struct { const BYTE *d; DWORD n; BOOL want; const char *nm; } t[] = {
        { fix_cert_self, sizeof fix_cert_self, TRUE, "self (AKI==SKI)" },
        { fix_cert_ca, sizeof fix_cert_ca, TRUE, "ca (AKI==SKI)" },
        { fix_cert_noext, sizeof fix_cert_noext, TRUE, "noext (issuer==subject, no key ids)" },
        { fix_cert_leaf, sizeof fix_cert_leaf, FALSE, "leaf" },
        { fix_cert_tls, sizeof fix_cert_tls, FALSE, "tls leaf" },
        { fix_cert_akimm, sizeof fix_cert_akimm, FALSE, "same names but AKI != SKI" } };
    for (int i = 0; i < 6; i++) {
        PCCERT_CONTEXT c = mk(t[i].d, t[i].n); CHECK(c != NULL); if (!c) continue;
        BOOL r = U(WTHelperCertIsSelfSigned)(X509_ASN_ENCODING, c->pCertInfo);
        CHECKF((r != 0) == (t[i].want != 0), "%s: got %d", t[i].nm, r);
        U(CertFreeCertificateContext)(c);
    }
}
TEST(wvt_cert_is_self_signed_encoding_variants) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    if (!U(WTHelperCertIsSelfSigned)) { t_skip("missing export"); return; }
    PCCERT_CONTEXT c = mk(fix_cert_self, sizeof fix_cert_self); if (!c) { CHECK(0); return; }
    /* with both key identifiers present the answer does not depend on the name comparison */
    CHECK(U(WTHelperCertIsSelfSigned)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, c->pCertInfo));
    CHECK(U(WTHelperCertIsSelfSigned)(PKCS_7_ASN_ENCODING, c->pCertInfo));
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_trust_is_certificate_self_signed) {
    BOOL (WINAPI *f)(PCCERT_CONTEXT, DWORD, DWORD) = (void *)t_proc("TrustIsCertificateSelfSigned"); if (!f) { t_skip("missing export"); return; }
    SET_ERR(0); CHECK(!f(NULL, X509_ASN_ENCODING, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    PCCERT_CONTEXT c = mk(fix_cert_self, sizeof fix_cert_self); if (!c) { CHECK(0); return; }
    SET_ERR(0); CHECK(!f(c, X509_ASN_ENCODING, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(c, X509_ASN_ENCODING, 0x80)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(f(c, X509_ASN_ENCODING, 0));
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_trust_is_certificate_self_signed_table) {
    BOOL (WINAPI *f)(PCCERT_CONTEXT, DWORD, DWORD) = (void *)t_proc("TrustIsCertificateSelfSigned"); if (!f) { t_skip("missing export"); return; }
    static const struct { const BYTE *d; DWORD n; BOOL want; const char *nm; } t[] = {
        { fix_cert_self, sizeof fix_cert_self, TRUE, "self" }, { fix_cert_ca, sizeof fix_cert_ca, TRUE, "ca" },
        { fix_cert_noext, sizeof fix_cert_noext, TRUE, "noext" }, { fix_cert_leaf, sizeof fix_cert_leaf, FALSE, "leaf" },
        { fix_cert_akimm, sizeof fix_cert_akimm, FALSE, "same names, signed by another key" } };
    for (int i = 0; i < 5; i++) {
        PCCERT_CONTEXT c = mk(t[i].d, t[i].n); if (!c) { CHECK(0); continue; }
        BOOL r = f(c, X509_ASN_ENCODING, 0);
        CHECKF((r != 0) == (t[i].want != 0), "%s: got %d", t[i].nm, r);
        U(CertFreeCertificateContext)(c);
    }
}
TEST(wvt_check_cert_usage_table) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    BOOL (WINAPI *f)(PCCERT_CONTEXT, LPCSTR) = (void *)t_proc("WTHelperCheckCertUsage"); if (!f) { t_skip("missing export"); return; }
    static const struct { const BYTE *d; DWORD n; const char *oid; BOOL want; const char *nm; } t[] = {
        { fix_cert_leaf, sizeof fix_cert_leaf, "1.3.6.1.5.5.7.3.3", TRUE, "leaf/codesign" },
        { fix_cert_leaf, sizeof fix_cert_leaf, "1.3.6.1.5.5.7.3.1", FALSE, "leaf/serverauth" },
        { fix_cert_leaf, sizeof fix_cert_leaf, "1.2.3.4", FALSE, "leaf/unknown" },
        { fix_cert_tls, sizeof fix_cert_tls, "1.3.6.1.5.5.7.3.1", TRUE, "tls/serverauth" },
        { fix_cert_tls, sizeof fix_cert_tls, "1.3.6.1.5.5.7.3.3", FALSE, "tls/codesign" },
        { fix_cert_self, sizeof fix_cert_self, "1.3.6.1.5.5.7.3.3", TRUE, "self/codesign" },
        { fix_cert_self, sizeof fix_cert_self, "1.3.6.1.5.5.7.3.4", FALSE, "self/email" },
        { fix_cert_ca, sizeof fix_cert_ca, "1.3.6.1.5.5.7.3.3", TRUE, "ca without EKU: any usage" },
        { fix_cert_ca, sizeof fix_cert_ca, "1.2.3.4", TRUE, "ca without EKU: any oid" },
        { fix_cert_noext, sizeof fix_cert_noext, "1.3.6.1.5.5.7.3.2", TRUE, "noext: any usage" } };
    for (int i = 0; i < 10; i++) {
        PCCERT_CONTEXT c = mk(t[i].d, t[i].n); if (!c) { CHECK(0); continue; }
        SET_ERR(0xdeadbeef);
        BOOL r = f(c, t[i].oid);
        CHECKF((r != 0) == (t[i].want != 0), "%s: got %d", t[i].nm, r);
        if (!r) CHECKF(GetLastError() == (DWORD)0x800B0110, "%s: lasterr 0x%08lx", t[i].nm, (unsigned long)GetLastError());
        U(CertFreeCertificateContext)(c);
    }
}
TEST(wvt_check_cert_usage_property_eku) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    BOOL (WINAPI *f)(PCCERT_CONTEXT, LPCSTR) = (void *)t_proc("WTHelperCheckCertUsage"); if (!f) { t_skip("missing export"); return; }
    PCCERT_CONTEXT c0 = mk(fix_cert_noext, sizeof fix_cert_noext); if (!c0) { CHECK(0); return; }
    PCCERT_CONTEXT c = U(CertDuplicateCertificateContext)(c0);
    LPSTR oids[1] = { "1.3.6.1.5.5.7.3.3" }; CERT_ENHKEY_USAGE eku = { 1, oids };
    CRYPT_DATA_BLOB blob; BYTE *enc = NULL; DWORD cb = 0;
    CHECK(U(CryptEncodeObjectEx)(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku, CRYPT_ENCODE_ALLOC_FLAG, NULL, &enc, &cb));
    blob.cbData = cb; blob.pbData = enc;
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_ENHKEY_USAGE_PROP_ID, 0, &blob));
    CHECK(f(c, "1.3.6.1.5.5.7.3.3"));
    SET_ERR(0); CHECK(!f(c, "1.3.6.1.5.5.7.3.1")); EXPECT_ERR((DWORD)0x800B0110);
    LocalFree(enc);
    /* the 1.3.6.1.4.1.311.10.4.1 marker in the property usage vetoes everything */
    LPSTR oids2[2] = { "1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.10.4.1" }; CERT_ENHKEY_USAGE eku2 = { 2, oids2 };
    enc = NULL; cb = 0;
    CHECK(U(CryptEncodeObjectEx)(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku2, CRYPT_ENCODE_ALLOC_FLAG, NULL, &enc, &cb));
    blob.cbData = cb; blob.pbData = enc;
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_ENHKEY_USAGE_PROP_ID, 0, &blob));
    SET_ERR(0); CHECK(!f(c, "1.3.6.1.5.5.7.3.3")); EXPECT_ERR((DWORD)0x800B0110);
    LocalFree(enc);
    U(CertFreeCertificateContext)(c); U(CertFreeCertificateContext)(c0);
}
TEST(wvt_get_agency_info_args) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    BOOL (WINAPI *f)(PCCERT_CONTEXT, DWORD *, void *) = (void *)t_proc("WTHelperGetAgencyInfo"); if (!f) { t_skip("missing export"); return; }
    PCCERT_CONTEXT c = mk(fix_cert_self, sizeof fix_cert_self); if (!c) { CHECK(0); return; }
    DWORD cb = 77;
    SET_ERR(0); CHECK(!f(NULL, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(c, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    cb = 77; CHECK(!f(c, &cb, NULL)); EXPECT_EQ(cb, 0);        /* no agency-info extension */
    BYTE buf[64]; cb = sizeof buf; CHECK(!f(c, &cb, buf)); EXPECT_EQ(cb, 0);
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_is_in_root_store_synthetic) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    BOOL (WINAPI *f)(CRYPT_PROVIDER_DATA *, PCCERT_CONTEXT) = (void *)t_proc("WTHelperIsInRootStore"); if (!f) { t_skip("missing export"); return; }
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL), other = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CHECK(st && other); if (!st || !other) return;
    WVT_PD pd; memset(&pd, 0, sizeof pd); pd.d.cbStruct = sizeof pd; pd.d.dwEncoding = X509_ASN_ENCODING;
    HCERTSTORE arr[1] = { st };
    PCCERT_CONTEXT c = mk(fix_cert_ca, sizeof fix_cert_ca); if (!c) { CHECK(0); return; }
    CHECK(!f(&pd.d, c));                       /* no stores */
    pd.d.chStores = 1; pd.d.pahStores = arr;
    CHECK(!f(&pd.d, c));                       /* store empty */
    CHECK(U(CertAddCertificateContextToStore)(st, c, CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(f(&pd.d, c));                        /* found by hash although c is a different context */
    PCCERT_CONTEXT inroot = U(CertEnumCertificatesInStore)(st, NULL);
    CHECK(inroot && f(&pd.d, inroot));         /* context owned by the store itself */
    PCCERT_CONTEXT lf = mk(fix_cert_leaf, sizeof fix_cert_leaf);
    CHECK(lf && !f(&pd.d, lf));
    CHECK(U(CertAddCertificateContextToStore)(other, lf, CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(!f(&pd.d, lf));                      /* only the first store is the root store */
    pd.d.chStores = 0;
    CHECK(!f(&pd.d, c));
    if (inroot) U(CertFreeCertificateContext)(inroot);
    if (lf) U(CertFreeCertificateContext)(lf);
    U(CertFreeCertificateContext)(c); U(CertCloseStore)(st, 0); U(CertCloseStore)(other, 0);
}
TEST(wvt_is_chained_to_microsoft_args) {
    BOOL (WINAPI *f)(PCCERT_CONTEXT, HCERTSTORE, int) = (void *)t_proc("WTHelperIsChainedToMicrosoft"); if (!f) { t_skip("missing export"); return; }
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    PCCERT_CONTEXT c = mk(fix_cert_self, sizeof fix_cert_self); if (!c || !st) { CHECK(0); return; }
    SET_ERR(0); CHECK(!f(NULL, st, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(c, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(NULL, NULL, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(!f(c, st, 0));
    CHECK(!f(c, st, 1));
    U(CertFreeCertificateContext)(c); U(CertCloseStore)(st, 0);
}
TEST(wvt_is_chained_to_microsoft_from_state_args) {
    BOOL (WINAPI *f)(CRYPT_PROVIDER_DATA *, int) = (void *)t_proc("WTHelperIsChainedToMicrosoftFromStateData"); if (!f) { t_skip("missing export"); return; }
    SET_ERR(0); CHECK(!f(NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    WVT_PD pd; memset(&pd, 0, sizeof pd);
    CHECK(!f(&pd.d, 0));                       /* no step-error array */
    DWORD steps[38]; memset(steps, 0, sizeof steps); pd.d.padwTrustStepErrors = steps; pd.d.cdwTrustStepErrors = 38;
    static const int bad[] = { TRUSTERROR_STEP_FINAL_WVTINIT, TRUSTERROR_STEP_FINAL_INITPROV, TRUSTERROR_STEP_FINAL_OBJPROV, TRUSTERROR_STEP_FINAL_SIGPROV };
    for (int i = 0; i < 4; i++) { steps[bad[i]] = 0x800B0100; CHECKF(!f(&pd.d, 0), "step %d", bad[i]); steps[bad[i]] = 0; }
}
TEST(wvt_is_chained_to_microsoft_from_state_real) {
    WVT_REQUIRE_WVT();
    BOOL (WINAPI *f)(CRYPT_PROVIDER_DATA *, int) = (void *)t_proc("WTHelperIsChainedToMicrosoftFromStateData"); if (!f) { t_skip("missing export"); return; }
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; wvt_path(p, "ms.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY; wvt_call(&WVT_V2, &w, &e);
    CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    CHECK(pd != NULL);
    if (pd) { CHECK(!f(pd, 0)); CHECK(!f(pd, 1)); }
    wvt_close(&WVT_V2, &w); wvt_del(p);
}

/* ---- stores / issuer ----------------------------------------------------------------------- */
TEST(wvt_trust_find_issuer_args) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    PCCERT_CONTEXT (WINAPI *f)(PCCERT_CONTEXT, DWORD, DWORD, HCERTSTORE *, FILETIME *, DWORD *, DWORD *, DWORD) = (void *)t_proc("TrustFindIssuerCertificate");
    if (!f) { t_skip("missing export"); return; }
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); HCERTSTORE arr[1] = { st };
    PCCERT_CONTEXT c = mk(fix_cert_leaf, sizeof fix_cert_leaf); FILETIME ft; GetSystemTimeAsFileTime(&ft);
    if (!c || !st) { CHECK(0); return; }
    SET_ERR(0); CHECK(f(NULL, X509_ASN_ENCODING, 1, arr, &ft, NULL, NULL, 0) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(f(c, X509_ASN_ENCODING, 1, NULL, &ft, NULL, NULL, 0) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(f(c, X509_ASN_ENCODING, 1, arr, NULL, NULL, NULL, 0) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(f(c, X509_ASN_ENCODING, 1, arr, &ft, NULL, NULL, 1) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CertFreeCertificateContext)(c); U(CertCloseStore)(st, 0);
}
TEST(wvt_trust_find_issuer_in_store) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    PCCERT_CONTEXT (WINAPI *f)(PCCERT_CONTEXT, DWORD, DWORD, HCERTSTORE *, FILETIME *, DWORD *, DWORD *, DWORD) = (void *)t_proc("TrustFindIssuerCertificate");
    if (!f) { t_skip("missing export"); return; }
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); HCERTSTORE arr[1] = { st };
    PCCERT_CONTEXT leaf = mk(fix_cert_leaf, sizeof fix_cert_leaf); FILETIME ft; GetSystemTimeAsFileTime(&ft);
    if (!leaf || !st) { CHECK(0); return; }
    CHECK(U(CertAddEncodedCertificateToStore)(st, X509_ASN_ENCODING, fix_cert_ca, sizeof fix_cert_ca, CERT_STORE_ADD_ALWAYS, NULL));
    DWORD conf = 0xdeadbeef, err = 0xdeadbeef;
    PCCERT_CONTEXT iss = f(leaf, X509_ASN_ENCODING, 1, arr, &ft, &conf, &err, 0);
    CHECK(iss != NULL);
    if (iss) {
        CHECK(iss->cbCertEncoded == sizeof fix_cert_ca && !memcmp(iss->pbCertEncoded, fix_cert_ca, sizeof fix_cert_ca));
        CHECK(conf != 0xdeadbeef); t_note("issuer confidence 0x%08lx error 0x%08lx", (unsigned long)conf, (unsigned long)err);
        U(CertFreeCertificateContext)(iss);
    }
    /* the wrapper takes (count, stores, time, encoding) in a different order */
    PCCERT_CONTEXT (WINAPI *g)(PCCERT_CONTEXT, DWORD, HCERTSTORE *, FILETIME *, DWORD, DWORD *, DWORD *) = (void *)t_proc("WTHelperCertFindIssuerCertificate");
    if (g) {
        iss = g(leaf, 1, arr, &ft, X509_ASN_ENCODING, NULL, NULL);
        CHECK(iss != NULL);
        if (iss) { CHECK(iss->cbCertEncoded == sizeof fix_cert_ca); U(CertFreeCertificateContext)(iss); }
    }
    U(CertFreeCertificateContext)(leaf); U(CertCloseStore)(st, 0);
}
TEST(wvt_trust_find_issuer_self_signed_returns_self) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    PCCERT_CONTEXT (WINAPI *f)(PCCERT_CONTEXT, DWORD, DWORD, HCERTSTORE *, FILETIME *, DWORD *, DWORD *, DWORD) = (void *)t_proc("TrustFindIssuerCertificate");
    if (!f) { t_skip("missing export"); return; }
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); HCERTSTORE arr[1] = { st };
    PCCERT_CONTEXT c = mk(fix_cert_self, sizeof fix_cert_self); FILETIME ft; GetSystemTimeAsFileTime(&ft);
    if (!c || !st) { CHECK(0); return; }
    CHECK(U(CertAddCertificateContextToStore)(st, c, CERT_STORE_ADD_ALWAYS, NULL));
    SET_ERR(0);
    PCCERT_CONTEXT iss = f(c, X509_ASN_ENCODING, 1, arr, &ft, NULL, NULL, 0);
    EXPECT_EQ(GetLastError(), 0x80092004); /* CRYPT_E_NOT_FOUND */
    CHECK(iss == NULL);
    if (iss) { CHECK(iss->cbCertEncoded == sizeof fix_cert_self && !memcmp(iss->pbCertEncoded, fix_cert_self, sizeof fix_cert_self)); U(CertFreeCertificateContext)(iss); }
    U(CertFreeCertificateContext)(c); U(CertCloseStore)(st, 0);
}
TEST(wvt_trust_find_issuer_not_present) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    PCCERT_CONTEXT (WINAPI *f)(PCCERT_CONTEXT, DWORD, DWORD, HCERTSTORE *, FILETIME *, DWORD *, DWORD *, DWORD) = (void *)t_proc("TrustFindIssuerCertificate");
    if (!f) { t_skip("missing export"); return; }
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); HCERTSTORE arr[1] = { st };
    PCCERT_CONTEXT c = mk(fix_cert_leaf, sizeof fix_cert_leaf); FILETIME ft; GetSystemTimeAsFileTime(&ft);
    if (!c || !st) { CHECK(0); return; }
    DWORD err = 0xdeadbeef;
    PCCERT_CONTEXT iss = f(c, X509_ASN_ENCODING, 1, arr, &ft, NULL, &err, 0);
    CHECK(iss == NULL);
    t_note("issuer absent: lasterror 0x%08lx pdwError 0x%08lx", (unsigned long)GetLastError(), (unsigned long)err);
    U(CertFreeCertificateContext)(c); U(CertCloseStore)(st, 0);
}
TEST(wvt_trust_find_issuer_zero_stores) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    PCCERT_CONTEXT (WINAPI *f)(PCCERT_CONTEXT, DWORD, DWORD, HCERTSTORE *, FILETIME *, DWORD *, DWORD *, DWORD) = (void *)t_proc("TrustFindIssuerCertificate");
    if (!f) { t_skip("missing export"); return; }
    HCERTSTORE arr[1] = { NULL };
    PCCERT_CONTEXT c = mk(fix_cert_leaf, sizeof fix_cert_leaf); FILETIME ft; GetSystemTimeAsFileTime(&ft);
    if (!c) { CHECK(0); return; }
    PCCERT_CONTEXT iss = f(c, X509_ASN_ENCODING, 0, arr, &ft, NULL, NULL, 0);
    CHECK(iss == NULL);
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_trust_open_stores_args) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    BOOL (WINAPI *f)(ULONG_PTR, DWORD *, HCERTSTORE *, DWORD) = (void *)t_proc("TrustOpenStores"); if (!f) { t_skip("missing export"); return; }
    DWORD n = 0;
    SET_ERR(0); CHECK(!f(0, NULL, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(0, &n, NULL, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(0, &n, NULL, 0x100)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(wvt_trust_open_stores_from_provider) {
    WVT_REQUIRE_WVT();
    BOOL (WINAPI *f)(ULONG_PTR, DWORD *, HCERTSTORE *, DWORD) = (void *)t_proc("TrustOpenStores"); if (!f) { t_skip("missing export"); return; }
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; wvt_path(p, "os.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY; wvt_call(&WVT_V2, &w, &e);
    CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    if (pd && pd->hProv) {
        DWORD n = 0; SET_ERR(0);
        BOOL r = f(pd->hProv, &n, NULL, 0);
        t_note("TrustOpenStores size query: ret=%d n=%lu lasterr=0x%lx", r, (unsigned long)n, (unsigned long)GetLastError());
        if (r && n) {
            CHECK(GetLastError() == ERROR_MORE_DATA);      /* the size-only call leaves ERROR_MORE_DATA behind */
            HCERTSTORE *arr = (HCERTSTORE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (n + 1) * sizeof(HCERTSTORE));
            DWORD m = n - 1; SET_ERR(0);
            CHECK(!f(pd->hProv, &m, arr, 0)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(m, n);
            m = n; CHECK(f(pd->hProv, &m, arr, 0)); EXPECT_EQ(m, n);
            for (DWORD i = 0; i < m; i++) { CHECK(arr[i] != NULL); if (arr[i]) U(CertCloseStore)(arr[i], 0); }
            HeapFree(GetProcessHeap(), 0, arr);
        }
    }
    wvt_close(&WVT_V2, &w); wvt_del(p);
}
TEST(wvt_open_known_stores_adds_stores) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    WVT_REQUIRE_WVT();
    BOOL (WINAPI *f)(CRYPT_PROVIDER_DATA *) = (void *)t_proc("WTHelperOpenKnownStores"); if (!f) { t_skip("missing export"); return; }
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; wvt_path(p, "ks.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY; wvt_call(&WVT_V2, &w, &e);
    CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    CHECK(pd != NULL);
    if (pd) {
        DWORD before = pd->chStores;
        BOOL r = f(pd);
        t_note("WTHelperOpenKnownStores: ret=%d chStores %lu -> %lu", r, (unsigned long)before, (unsigned long)pd->chStores);
        CHECK(r); CHECK(pd->chStores > before);
    }
    wvt_close(&WVT_V2, &w); wvt_del(p);
}

/* ---- WTHelperGetFileHash ------------------------------------------------------------------- */
typedef LONG (WINAPI *getfilehash_t)(const WCHAR *, DWORD, void *, BYTE *, DWORD *, ALG_ID *);
TEST(wvt_get_file_hash_signed_pe) {
    getfilehash_t f = (getfilehash_t)t_proc("WTHelperGetFileHash"); if (!f) { t_skip("missing export"); return; }
    WCHAR p[MAX_PATH]; wvt_path(p, "gh.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    DWORD cb = 0; ALG_ID alg = 0;
    LONG r = f(p, 0, NULL, NULL, &cb, &alg);
    EXPECT_EQ(r, 0); EXPECT_EQ(cb, 32); EXPECT_EQ(alg, 0xffffffff); /* SHA256 digests are not reported as an ALG_ID (SHA1 gives CALG_SHA1) */
    BYTE h[64]; memset(h, 0, sizeof h); cb = sizeof h; alg = 0;
    r = f(p, 0, NULL, h, &cb, &alg);
    EXPECT_EQ(r, 0); EXPECT_EQ(cb, 32); CHECK(!memcmp(h, fix_pe_sha256, 32)); EXPECT_EQ(alg, 0xffffffff);
    cb = 31; memset(h, 0, sizeof h);
    r = f(p, 0, NULL, h, &cb, &alg);
    EXPECT_EQ(r, ERROR_MORE_DATA); EXPECT_EQ(cb, 32); CHECK(h[0] == 0);
    wvt_del(p);
}
TEST(wvt_get_file_hash_unsigned_pe) {
    getfilehash_t f = (getfilehash_t)t_proc("WTHelperGetFileHash"); if (!f) { t_skip("missing export"); return; }
    WCHAR p[MAX_PATH]; wvt_path(p, "gh2.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    DWORD cb = 99; BYTE h[64]; ALG_ID alg = 0;
    LONG r = f(p, 0, NULL, h, &cb, &alg);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE); EXPECT_EQ(cb, 0);
    wvt_del(p);
}
TEST(wvt_get_file_hash_text_file) {
    getfilehash_t f = (getfilehash_t)t_proc("WTHelperGetFileHash"); if (!f) { t_skip("missing export"); return; }
    WCHAR p[MAX_PATH]; wvt_path(p, "gh3.txt"); wvt_write(p, "abc", 3);
    DWORD cb = 99; ALG_ID alg = 0;
    LONG r = f(p, 0, NULL, NULL, &cb, &alg);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE); EXPECT_EQ(cb, 0);
    wvt_del(p);
}
TEST(wvt_get_file_hash_tampered_pe) {
    getfilehash_t f = (getfilehash_t)t_proc("WTHelperGetFileHash"); if (!f) { t_skip("missing export"); return; }
    BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sizeof fix_pe_signed); memcpy(b, fix_pe_signed, sizeof fix_pe_signed); b[0x201] ^= 4;
    WCHAR p[MAX_PATH]; wvt_path(p, "gh4.exe"); wvt_write(p, b, sizeof fix_pe_signed); HeapFree(GetProcessHeap(), 0, b);
    DWORD cb = 0; ALG_ID alg = 0;
    LONG r = f(p, 0, NULL, NULL, &cb, &alg);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE); /* the digest mismatch is not distinguished here */
    wvt_del(p);
}

/* ---- registry policy (read only) ------------------------------------------------------------------ */
TEST(wvt_reg_policy_flags_read) {
    void (WINAPI *f)(DWORD *) = (void *)t_proc("WintrustGetRegPolicyFlags"); if (!f) { t_skip("missing export"); return; }
    DWORD fl = 0xdeadbeef; f(&fl);
    CHECK(fl != 0xdeadbeef);
    t_note("WintrustGetRegPolicyFlags = 0x%08lx (default 0x00023c00)", (unsigned long)fl);
    DWORD fl2 = 0x55555555; f(&fl2); EXPECT_EQ(fl, fl2);
}
TEST(wvt_default_for_usage_args) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    BOOL (WINAPI *f)(DWORD, const char *, CRYPT_PROVIDER_DEFUSAGE *) = (void *)t_proc("WintrustGetDefaultForUsage"); if (!f) { t_skip("missing export"); return; }
    CRYPT_PROVIDER_DEFUSAGE u; memset(&u, 0, sizeof u); u.cbStruct = sizeof u;
    SET_ERR(0); CHECK(!f(1, NULL, &u)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(1, "1.3.6.1.5.5.7.3.3", NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    u.cbStruct = 0x20; SET_ERR(0); CHECK(!f(1, "1.3.6.1.5.5.7.3.3", &u)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    u.cbStruct = 0; SET_ERR(0); CHECK(!f(1, "1.3.6.1.5.5.7.3.3", &u)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(wvt_default_for_usage_code_signing_observed) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    BOOL (WINAPI *f)(DWORD, const char *, CRYPT_PROVIDER_DEFUSAGE *) = (void *)t_proc("WintrustGetDefaultForUsage"); if (!f) { t_skip("missing export"); return; }
    CRYPT_PROVIDER_DEFUSAGE u; memset(&u, 0, sizeof u); u.cbStruct = sizeof u;
    SET_ERR(0); BOOL r = f(1, "1.3.6.1.5.5.7.3.3", &u);
    t_note("default for code signing: ret=%d lasterr=%lu action {%08lx-%04x-%04x}", r, (unsigned long)GetLastError(),
           (unsigned long)u.gActionID.Data1, u.gActionID.Data2, u.gActionID.Data3);
    if (r) { f(2, "1.3.6.1.5.5.7.3.3", &u); }
}

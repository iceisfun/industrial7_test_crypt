/* CertCreateSelfSignCertificate with named vs unnamed NCrypt keys. */
#include "ew.h"

static void del_key(void *a) { NCRYPT_KEY_HANDLE k = (NCRYPT_KEY_HANDLE)(ULONG_PTR)a; if (k) NCR(NCryptDeleteKey)(k, 0); }
static void free_prov(void *a) { NCRYPT_PROV_HANDLE p = (NCRYPT_PROV_HANDLE)(ULONG_PTR)a; if (p) NCR(NCryptFreeObject)(p); }
static void free_cert(void *a) { if (a) C32(CertFreeCertificateContext)((PCCERT_CONTEXT)a); }

T_SWEEPER(ew_keys) {
    NCRYPT_PROV_HANDLE p = 0; NCryptKeyName *kn; PVOID st = NULL; size_t pl = strlen(prefix); int again = 1;
    (void)phase;
    if (!NCR(NCryptOpenStorageProvider) || !NCR(NCryptEnumKeys) || !NCR(NCryptOpenKey) || !NCR(NCryptDeleteKey)) return;
    if (NCR(NCryptOpenStorageProvider)(&p, MS_KEY_STORAGE_PROVIDER, 0)) return;
    while (again) {
        again = 0; st = NULL;
        while (!NCR(NCryptEnumKeys)(p, NULL, &kn, &st, 0)) {
            char nm[200]; int i; NCRYPT_KEY_HANDLE kh;
            for (i = 0; i < 199 && kn->pszName[i]; i++) nm[i] = (char)kn->pszName[i];
            nm[i] = 0;
            if (!strncmp(nm, prefix, pl) && !NCR(NCryptOpenKey)(p, &kh, kn->pszName, kn->dwLegacyKeySpec, 0)) { NCR(NCryptDeleteKey)(kh, 0); again = 1; }
            NCR(NCryptFreeBuffer)(kn);
            if (again) break;
        }
        if (st) NCR(NCryptFreeBuffer)(st);
    }
    NCR(NCryptFreeObject)(p);
}

static int name_blob(CERT_NAME_BLOB *nb, BYTE *buf, DWORD cap) {
    nb->cbData = cap; nb->pbData = buf;
    return C32(CertStrToNameA)(X509_ASN_ENCODING, "CN=cryptt e_win10", CERT_X500_NAME_STR, NULL, buf, &nb->cbData, NULL);
}
/* the exe re-launches as a child: unnamed key; argv[1] = flags */
CHILD(unnamed_selfsign) {
    NCRYPT_PROV_HANDLE p; NCRYPT_KEY_HANDLE k; BYTE nm[128]; CERT_NAME_BLOB nb; PCCERT_CONTEXT c;
    if (!name_blob(&nb, nm, sizeof nm)) return 20;
    if (NCR(NCryptOpenStorageProvider)(&p, MS_KEY_STORAGE_PROVIDER, 0)) return 21;
    if (NCR(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, NULL, 0, 0)) return 22;
    if (NCR(NCryptFinalizeKey)(k, 0)) return 23;
    c = C32(CertCreateSelfSignCertificate)(k, &nb, argc > 1 ? (DWORD)atoi(argv[1]) : 0, NULL, NULL, NULL, NULL, NULL);
    return c ? 11 : 12;
}
TEST(ew_selfsign_named_key_gets_key_prov_info) {
    NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0, k2 = 0; BYTE nm[128]; CERT_NAME_BLOB nb; PCCERT_CONTEXT c;
    const WCHAR *name = t_unique_w("key"); DWORD n = 0; BYTE *pb;
    REQUIRE(C32(CertCreateSelfSignCertificate)); REQUIRE(NCR(NCryptCreatePersistedKey));
    REQUIRE_OK(name_blob(&nb, nm, sizeof nm));
    REQUIRE_EQ(NCR(NCryptOpenStorageProvider)(&p, MS_KEY_STORAGE_PROVIDER, 0), 0);
    t_defer(free_prov, (void *)(ULONG_PTR)p);
    REQUIRE_EQ(NCR(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, name, 0, NCRYPT_OVERWRITE_KEY_FLAG), 0);
    t_defer(del_key, (void *)(ULONG_PTR)k);
    REQUIRE_EQ(NCR(NCryptFinalizeKey)(k, 0), 0);
    c = C32(CertCreateSelfSignCertificate)(k, &nb, 0, NULL, NULL, NULL, NULL, NULL);
    REQUIRE_NOTNULL(c); t_defer(free_cert, (void *)c);
    SET_ERR(0);
    EXPECT_CAPI_OK(C32(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &n));
    CHECK(n > sizeof(CRYPT_KEY_PROV_INFO));
    pb = (BYTE *)LocalAlloc(LPTR, n);
    if (pb && C32(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, pb, &n)) {
        CRYPT_KEY_PROV_INFO *ki = (CRYPT_KEY_PROV_INFO *)pb;
        EXPECT_WSTR(ki->pwszContainerName, name);
        EXPECT_WSTR(ki->pwszProvName, MS_KEY_STORAGE_PROVIDER);
        EXPECT_EQ(ki->dwProvType, 0);
        EXPECT_EQ(ki->dwFlags, 0);
        EXPECT_EQ(ki->dwKeySpec, 1);                                                                  /* AT_KEYEXCHANGE */
        EXPECT_EQ(ki->cProvParam, 0);
    } else CHECK(0);
    LocalFree(pb);
    /* negative control: NO_KEY_INFO on the same named key attaches nothing */
    { PCCERT_CONTEXT c2 = C32(CertCreateSelfSignCertificate)(k, &nb, CERT_CREATE_SELFSIGN_NO_KEY_INFO, NULL, NULL, NULL, NULL, NULL); DWORD n2 = 0;
      REQUIRE_NOTNULL(c2); t_defer(free_cert, (void *)c2);
      SET_ERR(0); EXPECT_CAPI_FAIL(C32(CertGetCertificateContextProperty)(c2, CERT_KEY_PROV_INFO_PROP_ID, NULL, &n2), ERR_CRYPT_E_NOT_FOUND); }
    /* the key is addressable by its unique name until deleted; afterwards NTE_BAD_KEYSET */
    EXPECT_EQ(NCR(NCryptOpenKey)(p, &k2, name, 0, 0), 0);
    if (k2) NCR(NCryptFreeObject)(k2);
}
TEST(ew_selfsign_unnamed_key_hangs_unless_no_key_info) {
    /* An ephemeral (unnamed) CNG key makes CertCreateSelfSignCertificate block forever; CERT_CREATE_SELFSIGN_NO_KEY_INFO avoids it.
     * Run in a child with a short budget so the hang is observable and bounded. */
    char a[16];
    REQUIRE(C32(CertCreateSelfSignCertificate));
    t_set_timeout(60);
    sprintf(a, "%lu", (unsigned long)CERT_CREATE_SELFSIGN_NO_KEY_INFO);
    EXPECT_EQ(t_run_child("unnamed_selfsign", a, 20000), 11);                                           /* control: returns a certificate */
    sprintf(a, "%lu", (unsigned long)(CERT_CREATE_SELFSIGN_NO_KEY_INFO | CERT_CREATE_SELFSIGN_NO_SIGN));
    EXPECT_EQ(t_run_child("unnamed_selfsign", a, 20000), 11);
    EXPECT_EQ(t_run_child("unnamed_selfsign", "0", 8000), 0xDEAD0001);                                  /* killed after 8 s */
}

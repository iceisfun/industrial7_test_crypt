/* State-changing: CertAddEncodedCertificateToSystemStoreA. Uses uniquely named per-user system stores
   (HKCU\Software\Microsoft\SystemCertificates\cryptt_gap1_<pid>_<n>) that are removed again. */
#include "t.h"
#include <wincrypt.h>
#include "vectors.h"

#define ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define PFX "cryptt_gap1_"
#define BLOB(x) x, (DWORD)sizeof(x)

static BOOL WINAPI sweep_cb(const void *name, DWORD flags, PCERT_SYSTEM_STORE_INFO info, void *res, void *arg) {
    const WCHAR *w = name;
    if (!wcsncmp(w, L"cryptt_gap1_", 12)) {
        typeof(&CertUnregisterSystemStore) un = U(CertUnregisterSystemStore);
        if (un) un(w, CERT_SYSTEM_STORE_CURRENT_USER);
    }
    return TRUE;
}
static BOOL WINAPI count_cb(const void *n, DWORD fl, PCERT_SYSTEM_STORE_INFO i, void *r, void *a) { if (!wcsncmp(n, L"cryptt_gap1_", 12)) (*(int *)a)++; return TRUE; }
static void sweep(void) {
    typeof(&CertEnumSystemStore) en = U(CertEnumSystemStore);
    if (en) en(CERT_SYSTEM_STORE_CURRENT_USER, NULL, NULL, sweep_cb);
}
static int g_n;
static void make_name(char *out, size_t cap) { snprintf(out, cap, PFX "%lu_%d", GetCurrentProcessId(), ++g_n); }
static void remove_store(const char *name) {
    WCHAR w[128]; MultiByteToWideChar(CP_ACP, 0, name, -1, w, 128);
    U(CertUnregisterSystemStore)(w, CERT_SYSTEM_STORE_CURRENT_USER);
}
static HCERTSTORE open_existing(const char *name) {
    WCHAR w[128]; MultiByteToWideChar(CP_ACP, 0, name, -1, w, 128);
    return U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, w);
}
static int count_certs(HCERTSTORE s) {
    int n = 0; PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL) n++;
    return n;
}
static int has_cert(HCERTSTORE s, const BYTE *der, DWORD cb) {
    PCCERT_CONTEXT c = NULL; int found = 0;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL)
        if (c->cbCertEncoded == cb && !memcmp(c->pbCertEncoded, der, cb)) found = 1;
    return found;
}
#define PREREQ() do { REQUIRE(U(CertAddEncodedCertificateToSystemStoreA)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertUnregisterSystemStore)); sweep(); } while (0)

TEST(dxgap1_add_creates_store_and_adds_certificate) {
    PREREQ();
    char name[64]; make_name(name, sizeof name);
    BOOL r = U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA);
    if (!r) { DWORD e = GetLastError(); t_skip("cannot write the per-user store (0x%08lx)", e); remove_store(name); return; }
    HCERTSTORE s = open_existing(name);
    CHECK(s != NULL);
    if (s) {
        CHECK(count_certs(s) == 1);
        CHECK(has_cert(s, BLOB(v_certA)));
        U(CertCloseStore)(s, 0);
    }
    remove_store(name);
    SET_ERR(0);
    CHECK(open_existing(name) == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(dxgap1_add_same_certificate_replaces_existing) {
    PREREQ();
    char name[64]; make_name(name, sizeof name);
    if (!U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA)) { t_skip("store not writable"); remove_store(name); return; }
    CHECK(U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA));
    CHECK(U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA));
    HCERTSTORE s = open_existing(name); CHECK(s != NULL);
    if (s) { CHECK(count_certs(s) == 1); U(CertCloseStore)(s, 0); }
    remove_store(name);
}
TEST(dxgap1_add_distinct_certificates_accumulate) {
    PREREQ();
    char name[64]; make_name(name, sizeof name);
    if (!U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA)) { t_skip("store not writable"); remove_store(name); return; }
    CHECK(U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certB, sizeof v_certB));
    HCERTSTORE s = open_existing(name); CHECK(s != NULL);
    if (s) {
        CHECK(count_certs(s) == 2);
        CHECK(has_cert(s, BLOB(v_certA)) && has_cert(s, BLOB(v_certB)));
        U(CertCloseStore)(s, 0);
    }
    remove_store(name);
}
TEST(dxgap1_add_certificate_with_same_id_but_other_encoding_is_separate_entry) {
    /* certC shares serial+issuer with certA but its encoding (hence SHA-1 thumbprint) differs: the store keys on the hash */
    PREREQ();
    char name[64]; make_name(name, sizeof name);
    if (!U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA)) { t_skip("store not writable"); remove_store(name); return; }
    CHECK(U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certC, sizeof v_certC));
    HCERTSTORE s = open_existing(name); CHECK(s != NULL);
    if (s) { CHECK(count_certs(s) == 2); U(CertCloseStore)(s, 0); }
    remove_store(name);
}
TEST(dxgap1_add_garbage_certificate_fails_and_still_creates_store) {
    PREREQ();
    char name[64]; make_name(name, sizeof name);
    static const BYTE junk[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    SET_ERR(0);
    BOOL r = U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)junk, sizeof junk);
    DWORD e = GetLastError();
    CHECK(r == FALSE);
    CHECKF((e & 0xFFFFFF00u) == 0x80093100u, "error 0x%08lx", e);     /* ASN.1 decode error */
    HCERTSTORE s = open_existing(name);
    t_note("store after a failed add: %s", s ? "exists" : "absent");
    if (s) { CHECK(count_certs(s) == 0); U(CertCloseStore)(s, 0); }
    remove_store(name);
}
TEST(dxgap1_add_truncated_and_empty_encodings) {
    PREREQ();
    char name[64]; make_name(name, sizeof name);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA - 7));
    DWORD e = GetLastError(); CHECKF(e != 0, "0x%08lx", e);
    t_note("truncated certificate -> 0x%08lx", e);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, 0));
    t_note("zero length -> 0x%08lx", GetLastError());
    CHECK(GetLastError() != 0);
    remove_store(name);
}
TEST(dxgap1_added_certificate_has_hash_property_and_no_key) {
    PREREQ();
    char name[64]; make_name(name, sizeof name);
    if (!U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA)) { t_skip("store not writable"); remove_store(name); return; }
    HCERTSTORE s = open_existing(name); REQUIRE(s);
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(s, NULL);
    CHECK(c != NULL);
    if (c) {
        BYTE h1[20], h2[20]; DWORD n1 = 20, n2 = 20;
        CHECK(U(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, h1, &n1));
        CHECK(U(CryptHashCertificate)(0, CALG_SHA1, 0, v_certA, sizeof v_certA, h2, &n2));
        CHECK(n1 == 20 && n2 == 20 && !memcmp(h1, h2, 20));
        DWORD kp = 0; SET_ERR(0);
        CHECK(!U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &kp));
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
        U(CertFreeCertificateContext)(c);
    }
    U(CertCloseStore)(s, 0);
    remove_store(name);
}
TEST(dxgap1_store_name_is_case_insensitive) {
    PREREQ();
    char name[64], up[64]; make_name(name, sizeof name);
    if (!U(CertAddEncodedCertificateToSystemStoreA)(name, (BYTE *)v_certA, sizeof v_certA)) { t_skip("store not writable"); remove_store(name); return; }
    strcpy(up, name); for (char *p = up; *p; p++) if (*p >= 'a' && *p <= 'z') *p -= 32;
    CHECK(U(CertAddEncodedCertificateToSystemStoreA)(up, (BYTE *)v_certB, sizeof v_certB));
    HCERTSTORE s = open_existing(name); CHECK(s != NULL);
    if (s) { CHECKF(count_certs(s) == 2, "count %d", count_certs(s)); U(CertCloseStore)(s, 0); }
    remove_store(name);
}
TEST(dxgap1_sweep_leaves_nothing_behind) {
    PREREQ();
    int left = 0;
    typeof(&CertEnumSystemStore) en = U(CertEnumSystemStore);
    en(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &left, count_cb);
    CHECKF(left == 0, "%d leftover stores", left);
}

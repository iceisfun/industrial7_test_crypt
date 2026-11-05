/* Using the persisted key: signatures, exportability, PFX export of persisted keys and re-import. */
#include "pk.h"

static const BYTE *sig_be(void) { return fx_rsa_sig_be; }

/* ---- signing --------------------------------------------------------------------------------------- */
#define RSA_SIGN_TEST(nm, imp, acq) TEST(pfxp_sign_rsa_##nm) { \
    PK_SETUP(fx_rsa_pfx, imp); \
    BYTE sig[512]; DWORD len = sizeof sig, spec = 0; \
    DWORD r = pk_sign(c, acq, sig, &len, &spec); \
    EXPECT_HR(r, 0); \
    if (!r) { EXPECT_EQ(len, 256); if (!pk_sha1) CHECK(!memcmp(sig, sig_be(), 256)); EXPECT_HR(pk_verify(c, sig, len), 0); } \
    pk_done(c, s); }
RSA_SIGN_TEST(default,        0, 0)
RSA_SIGN_TEST(default_silent, 0, CRYPT_ACQUIRE_SILENT_FLAG)
RSA_SIGN_TEST(exportable,     CRYPT_EXPORTABLE, 0)
RSA_SIGN_TEST(ksp,            PKCS12_ALWAYS_CNG_KSP, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)
RSA_SIGN_TEST(ksp_prefer,     PKCS12_ALWAYS_CNG_KSP, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG)
RSA_SIGN_TEST(ksp_exportable, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)
RSA_SIGN_TEST(ksp_cached,     PKCS12_ALWAYS_CNG_KSP, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_CACHE_FLAG)
RSA_SIGN_TEST(csp_cached,     0, CRYPT_ACQUIRE_CACHE_FLAG)

#define EC_SIGN_TEST(nm, imp, acq) TEST(pfxp_sign_ec_##nm) { \
    PK_SETUP(fx_ec_pfx, imp); \
    BYTE sig[256]; DWORD len = sizeof sig, spec = 0; \
    DWORD r = pk_sign(c, acq, sig, &len, &spec); \
    EXPECT_HR(r, 0); \
    if (!r) { EXPECT_EQ(len, 64); EXPECT_EQ(spec, CERT_NCRYPT_KEY_SPEC); EXPECT_HR(pk_verify(c, sig, len), 0); \
        sig[10] ^= 1; CHECK(pk_verify(c, sig, len) != 0); } \
    pk_done(c, s); }
EC_SIGN_TEST(default,    0, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)
EC_SIGN_TEST(exportable, CRYPT_EXPORTABLE, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)
EC_SIGN_TEST(prefer,     0, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG)
EC_SIGN_TEST(cached,     0, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_CACHE_FLAG)

TEST(pfxp_sign_rsa_tamper_fails_verify) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    BYTE sig[512]; DWORD len = sizeof sig, spec;
    if (!pk_sign(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, sig, &len, &spec)) {
        sig[100] ^= 0x40; CHECK(pk_verify(c, sig, len) != 0);
    }
    pk_done(c, s);
}
TEST(pfxp_sign_rsa_ksp_signature_size_query) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0, n = 0; BOOL cf = FALSE;
    if (U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &h, &spec, &cf)) {
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        EXPECT_HR(U(NCryptSignHash)(h, &pi, (PBYTE)fx_hash, 32, NULL, 0, &n, BCRYPT_PAD_PKCS1), 0);
        EXPECT_EQ(n, 256);
        BYTE small[255]; DWORD m = 0;
        EXPECT_HR(U(NCryptSignHash)(h, &pi, (PBYTE)fx_hash, 32, small, sizeof small, &m, BCRYPT_PAD_PKCS1), NTE_BUFFER_TOO_SMALL);
        pk_release(h, spec, cf);
    } else CHECKF(0, "acquire %lx", GetLastError());
    pk_done(c, s);
}

/* ---- exportability of the persisted key ----------------------------------------------------------- */
static int key_exportable(PCCERT_CONTEXT c, int *known) {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0, v = 0, cb = 0; BOOL cf = FALSE; int r = 0;
    *known = 0;
    if (!U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, NULL, &h, &spec, &cf)) return 0;
    if (spec == CERT_NCRYPT_KEY_SPEC) {
        if (!U(NCryptGetProperty)(h, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&v, 4, &cb, 0)) { *known = 1; r = (v & NCRYPT_ALLOW_EXPORT_FLAG) != 0; }
    } else {
        HCRYPTKEY k = 0;
        if (U(CryptGetUserKey)(h, spec, &k)) {
            cb = 4;
            if (U(CryptGetKeyParam)(k, KP_PERMISSIONS, (BYTE *)&v, &cb, 0)) { *known = 1; r = (v & CRYPT_EXPORT) != 0; }
            U(CryptDestroyKey)(k);
        }
    }
    pk_release(h, spec, cf);
    return r;
}
#define EXPT_TEST(nm, fx, imp, want) TEST(pfxp_exportable_##nm) { \
    PK_SETUP(fx, imp); int known, e = key_exportable(c, &known); \
    CHECK(known); if (known) CHECKF(e == want, "exportable=%d want %d", e, want); \
    pk_done(c, s); }
EXPT_TEST(rsa_default_no,     fx_rsa_pfx, 0, 0)
EXPT_TEST(rsa_flag_yes,       fx_rsa_pfx, CRYPT_EXPORTABLE, 1)
EXPT_TEST(rsa_user_no,        fx_rsa_pfx, CRYPT_USER_KEYSET, 0)
EXPT_TEST(rsa_ksp_no,         fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP, 0)
EXPT_TEST(rsa_ksp_yes,        fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, 1)
EXPT_TEST(ec_default_no,      fx_ec_pfx, 0, 0)
EXPT_TEST(ec_flag_yes,        fx_ec_pfx, CRYPT_EXPORTABLE, 1)

TEST(pfxp_export_key_nonexportable_csp_blob) {
    PK_SETUP(fx_rsa_pfx, 0);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i && i->dwProvType != 0) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0, n = 0; BOOL cf = FALSE; HCRYPTKEY k = 0;
        if (U(CryptAcquireCertificatePrivateKey)(c, 0, NULL, &h, &spec, &cf)) {
            CHECK(U(CryptGetUserKey)(h, spec, &k));
            SET_ERR(0);
            CHECK(!U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, NULL, &n));
            EXPECT_HR(GetLastError(), NTE_BAD_KEY_STATE);
            n = 0; CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, NULL, &n)); CHECK(n > 20);
            U(CryptDestroyKey)(k); pk_release(h, spec, cf);
        }
    } else t_skip("default RSA import went to a KSP on this system");
    pk_free_info(i);
    pk_done(c, s);
}
TEST(pfxp_export_key_exportable_csp_blob) {
    PK_SETUP(fx_rsa_pfx, CRYPT_EXPORTABLE);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i && i->dwProvType != 0) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0, n = 0; BOOL cf = FALSE; HCRYPTKEY k = 0;
        if (U(CryptAcquireCertificatePrivateKey)(c, 0, NULL, &h, &spec, &cf)) {
            CHECK(U(CryptGetUserKey)(h, spec, &k));
            CHECK(U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, NULL, &n));
            CHECK(n > 256 * 4);
            BYTE *b = (BYTE *)LocalAlloc(LPTR, n);
            if (b && U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n)) {
                BLOBHEADER *bh = (BLOBHEADER *)b; RSAPUBKEY *rk = (RSAPUBKEY *)(b + sizeof *bh);
                EXPECT_EQ(bh->bType, PRIVATEKEYBLOB); EXPECT_EQ(rk->magic, 0x32415352); EXPECT_EQ(rk->bitlen, 2048);
            }
            if (b) LocalFree(b);
            U(CryptDestroyKey)(k); pk_release(h, spec, cf);
        }
    } else t_skip("default RSA import went to a KSP on this system");
    pk_free_info(i);
    pk_done(c, s);
}
TEST(pfxp_export_key_nonexportable_ksp) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0, n = 0; BOOL cf = FALSE;
    if (U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &h, &spec, &cf)) {
        SECURITY_STATUS st = U(NCryptExportKey)(h, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, NULL, 0, &n, 0);
        CHECK(st != 0);
        t_note("export of non-exportable KSP key (private blob): 0x%08lx", (DWORD)st);
        st = U(NCryptExportKey)(h, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &n, 0);
        EXPECT_HR(st, 0); CHECK(n >= 24 + 3 + 256);
        pk_release(h, spec, cf);
    } else CHECKF(0, "acquire %lx", GetLastError());
    pk_done(c, s);
}
TEST(pfxp_export_key_exportable_ksp) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0, n = 0; BOOL cf = FALSE;
    if (U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &h, &spec, &cf)) {
        { DWORD pol = 0, pc = 0; EXPECT_HR(U(NCryptGetProperty)(h, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&pol, 4, &pc, 0), 0); EXPECT_EQ(pol, NCRYPT_ALLOW_EXPORT_FLAG); }
        /* CRYPT_EXPORTABLE grants only the encrypted export; a plaintext blob needs NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG */
        EXPECT_HR(U(NCryptExportKey)(h, 0, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, NULL, 0, &n, 0), 0x80090029);
        n = 0;
        SECURITY_STATUS st = U(NCryptExportKey)(h, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &n, 0);
        EXPECT_HR(st, 0);
        BYTE *b = (BYTE *)LocalAlloc(LPTR, n);
        if (b && !U(NCryptExportKey)(h, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, b, n, &n, 0)) {
            BCRYPT_RSAKEY_BLOB *kb = (BCRYPT_RSAKEY_BLOB *)b;
            EXPECT_EQ(kb->Magic, BCRYPT_RSAPUBLIC_MAGIC); EXPECT_EQ(kb->BitLength, 2048);
            /* modulus is the tail of the certificate's SubjectPublicKeyInfo key bytes */
            const BYTE *mod = b + sizeof *kb + kb->cbPublicExp;
            CRYPT_BIT_BLOB *pk = &c->pCertInfo->SubjectPublicKeyInfo.PublicKey; int found = 0; DWORD o;
            for (o = 0; o + 256 <= pk->cbData; o++) if (!memcmp(pk->pbData + o, mod, 256)) found = 1;
            CHECK(found);
        }
        if (b) LocalFree(b);
        pk_release(h, spec, cf);
    } else CHECKF(0, "acquire %lx", GetLastError());
    pk_done(c, s);
}

/* ---- PFXExportCertStoreEx from persisted keys ------------------------------------------------------ */
static HCERTSTORE reimport_nopersist(const CRYPT_DATA_BLOB *b, LPCWSTR pw) {
    return U(PFXImportCertStore)((CRYPT_DATA_BLOB *)b, pw, PKCS12_NO_PERSIST_KEY | (t_is_wine() ? 0 : PKCS12_IMPORT_SILENT));
}
static BOOL has_key_context(PCCERT_CONTEXT c) { DWORD cb = 0; return U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &cb); }
static BOOL export_store(HCERTSTORE s, CRYPT_DATA_BLOB *o, LPCWSTR pw, DWORD fl) {
    o->cbData = 0; o->pbData = NULL;
    if (!U(PFXExportCertStoreEx)(s, o, pw, NULL, fl)) return FALSE;
    o->pbData = (BYTE *)LocalAlloc(LPTR, o->cbData);
    if (!o->pbData) return FALSE;
    return U(PFXExportCertStoreEx)(s, o, pw, NULL, fl);
}
#define EXPORT_OK_TEST(nm, fx, imp, der) TEST(pfxp_pfx_export_##nm) { \
    PK_SETUP(fx, imp); CRYPT_DATA_BLOB o; \
    BOOL ok = export_store(s, &o, L"export-pw", EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY); \
    CHECKF(ok, "export failed %lx", GetLastError()); \
    if (ok) { \
        HCERTSTORE s2 = reimport_nopersist(&o, L"export-pw"); CHECK(s2 != NULL); \
        if (s2) { PCCERT_CONTEXT c2 = pk_first(s2); CHECK(c2 != NULL); \
            if (c2) { CHECK(c2->cbCertEncoded == sizeof der && !memcmp(c2->pbCertEncoded, der, sizeof der)); CHECK(has_key_context(c2)); \
                BYTE sig[512]; DWORD len = sizeof sig, sp; \
                DWORD r = pk_sign_keyctx(c2, sig, &len, &sp); EXPECT_HR(r, 0); \
                if (!r) EXPECT_HR(pk_verify(c2, sig, len), 0); \
                U(CertFreeCertificateContext)(c2); } \
            U(CertCloseStore)(s2, 0); } \
        LocalFree(o.pbData); } \
    pk_done(c, s); }
EXPORT_OK_TEST(rsa_csp_exportable, fx_rsa_pfx, CRYPT_EXPORTABLE, fx_rsa_der)
EXPORT_OK_TEST(rsa_ksp_exportable, fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, fx_rsa_der)
EXPORT_OK_TEST(ec_exportable,      fx_ec_pfx, CRYPT_EXPORTABLE, fx_ec_der)
EXPORT_OK_TEST(ec_ksp_exportable,  fx_ec_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, fx_ec_der)

static const DWORD nonexp_errs[] = { NTE_BAD_KEY_STATE, ERROR_ACCESS_DENIED, NTE_PERM, NTE_NOT_SUPPORTED };
static int err_in(DWORD e, const DWORD *l, int n) { int i; for (i = 0; i < n; i++) if (l[i] == e) return 1; return 0; }
#define EXPORT_FAIL_TEST(nm, fx, imp) TEST(pfxp_pfx_export_nonexportable_reports_##nm) { \
    PK_SETUP(fx, imp); CRYPT_DATA_BLOB o = {0, NULL}; SET_ERR(0); \
    BOOL ok = U(PFXExportCertStoreEx)(s, &o, L"export-pw", NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY); \
    CHECK(!ok); \
    DWORD e = GetLastError(); t_note("non-exportable " #nm ": err 0x%08lx", e); \
    CHECKF(err_in(e, nonexp_errs, 4), "unexpected last error 0x%08lx", e); \
    pk_done(c, s); }
EXPORT_FAIL_TEST(rsa_csp, fx_rsa_pfx, 0)
EXPORT_FAIL_TEST(rsa_ksp, fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP)
EXPORT_FAIL_TEST(ec_ksp,  fx_ec_pfx, 0)

#define EXPORT_SILENT_TEST(nm, fx, imp, der) TEST(pfxp_pfx_export_nonexportable_without_report_##nm) { \
    PK_SETUP(fx, imp); CRYPT_DATA_BLOB o; \
    BOOL ok = export_store(s, &o, L"export-pw", EXPORT_PRIVATE_KEYS); \
    t_note(#nm ": EXPORT_PRIVATE_KEYS of a non-exportable key without REPORT flags: %s err=0x%lx", ok ? "ok" : "failed", ok ? 0 : GetLastError()); \
    if (ok) { HCERTSTORE s2 = reimport_nopersist(&o, L"export-pw"); CHECK(s2 != NULL); \
        if (s2) { PCCERT_CONTEXT c2 = pk_first(s2); CHECK(c2 != NULL); \
            if (c2) { CHECK(c2->cbCertEncoded == sizeof der && !memcmp(c2->pbCertEncoded, der, sizeof der)); \
                t_note(#nm ": re-imported cert has key context = %d", has_key_context(c2)); U(CertFreeCertificateContext)(c2); } \
            U(CertCloseStore)(s2, 0); } \
        LocalFree(o.pbData); } \
    pk_done(c, s); }
EXPORT_SILENT_TEST(rsa_ksp, fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP, fx_rsa_der)
EXPORT_SILENT_TEST(ec,      fx_ec_pfx, 0, fx_ec_der)
EXPORT_SILENT_TEST(rsa_csp, fx_rsa_pfx, 0, fx_rsa_der)

TEST(pfxp_pfx_export_without_private_keys_flag_drops_key) {
    PK_SETUP(fx_rsa_pfx, CRYPT_EXPORTABLE); CRYPT_DATA_BLOB o;
    BOOL ok = export_store(s, &o, L"export-pw", 0);
    CHECK(ok);
    if (ok) {
        HCERTSTORE s2 = reimport_nopersist(&o, L"export-pw"); CHECK(s2 != NULL);
        if (s2) { PCCERT_CONTEXT c2 = pk_first(s2); CHECK(c2 != NULL); if (c2) { CHECK(!has_key_context(c2)); U(CertFreeCertificateContext)(c2); } U(CertCloseStore)(s2, 0); }
        LocalFree(o.pbData);
    }
    pk_done(c, s);
}
TEST(pfxp_pfx_export_key_blob_larger_than_certonly) {
    PK_SETUP(fx_rsa_pfx, CRYPT_EXPORTABLE); CRYPT_DATA_BLOB a, b;
    BOOL oa = export_store(s, &a, L"export-pw", 0), ob = export_store(s, &b, L"export-pw", EXPORT_PRIVATE_KEYS);
    CHECK(oa); CHECK(ob);
    if (oa && ob) CHECK(b.cbData > a.cbData + 1000);
    if (oa) LocalFree(a.pbData);
    if (ob) LocalFree(b.pbData);
    pk_done(c, s);
}
TEST(pfxp_pfx_export_size_query_matches) {
    PK_SETUP(fx_rsa_pfx, CRYPT_EXPORTABLE); CRYPT_DATA_BLOB q = {0, NULL}, o;
    CHECK(U(PFXExportCertStoreEx)(s, &q, L"export-pw", NULL, EXPORT_PRIVATE_KEYS));
    CHECK(q.cbData > 1000);
    CHECK(export_store(s, &o, L"export-pw", EXPORT_PRIVATE_KEYS));
    if (o.pbData) { CHECK(o.cbData <= q.cbData + 64 && o.cbData + 64 >= q.cbData); LocalFree(o.pbData); }
    pk_done(c, s);
}
TEST(pfxp_pfx_export_wrong_password_on_reimport) {
    PK_SETUP(fx_rsa_pfx, CRYPT_EXPORTABLE); CRYPT_DATA_BLOB o;
    if (export_store(s, &o, L"export-pw", EXPORT_PRIVATE_KEYS)) {
        SET_ERR(0);
        HCERTSTORE s2 = reimport_nopersist(&o, L"other-pw");
        CHECK(s2 == NULL); EXPECT_ERR(86);
        if (s2) U(CertCloseStore)(s2, 0);
        LocalFree(o.pbData);
    }
    pk_done(c, s);
}
TEST(pfxp_pfx_export_report_no_private_key_on_keyless_cert) {
    PK_NEEDS();
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    CHECK(s != NULL); if (!s) return;
    CHECK(U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_rsa_der, sizeof fx_rsa_der, CERT_STORE_ADD_ALWAYS, NULL));
    CRYPT_DATA_BLOB o = {0, NULL}; SET_ERR(0);
    /* the size query succeeds for a keyless cert even with REPORT_NO_PRIVATE_KEY; last error is left alone */
    CHECK(U(PFXExportCertStoreEx)(s, &o, L"pw", NULL, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY));
    EXPECT_ERR(0);
    EXPECT_NE(o.cbData, 0);
    CHECK(U(PFXExportCertStoreEx)(s, &o, L"pw", NULL, EXPORT_PRIVATE_KEYS));
    U(CertCloseStore)(s, 0);
}

/* ---- re-import of an export, persisting again ------------------------------------------------------ */
#define ROUNDTRIP_TEST(nm, fx, imp1, imp2, der) TEST(pfxp_roundtrip_##nm) { \
    PK_SETUP(fx, imp1); CRYPT_DATA_BLOB o; \
    if (export_store(s, &o, L"export-pw", EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)) { \
        HCERTSTORE s2 = pk_import_pw(o.pbData, o.cbData, L"export-pw", imp2); \
        CHECK(s2 != NULL); \
        if (s2) { PCCERT_CONTEXT c2 = pk_first(s2); CHECK(c2 != NULL); \
            if (c2) { CRYPT_KEY_PROV_INFO *i = pk_info(c2); CHECK(i != NULL); \
                if (i) { EXPECT_EQ(pk_open_status(i), 0); pk_free_info(i); } \
                BYTE sig[512]; DWORD len = sizeof sig, sp; DWORD r = pk_sign(c2, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, sig, &len, &sp); EXPECT_HR(r, 0); \
                if (!r) EXPECT_HR(pk_verify(c2, sig, len), 0); } \
            pk_done(c2, s2); } \
        LocalFree(o.pbData); } else CHECKF(0, "export failed %lx", GetLastError()); \
    pk_done(c, s); }
ROUNDTRIP_TEST(rsa_csp_to_csp,  fx_rsa_pfx, CRYPT_EXPORTABLE, CRYPT_EXPORTABLE, fx_rsa_der)
ROUNDTRIP_TEST(rsa_csp_to_ksp,  fx_rsa_pfx, CRYPT_EXPORTABLE, PKCS12_ALWAYS_CNG_KSP, fx_rsa_der)
ROUNDTRIP_TEST(rsa_ksp_to_ksp,  fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, PKCS12_ALWAYS_CNG_KSP, fx_rsa_der)
ROUNDTRIP_TEST(rsa_ksp_to_default, fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, 0, fx_rsa_der)
ROUNDTRIP_TEST(rsa_overwrite,   fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, PKCS12_ALWAYS_CNG_KSP | PKCS12_ALLOW_OVERWRITE_KEY, fx_rsa_der)
ROUNDTRIP_TEST(ec_to_ec,        fx_ec_pfx, CRYPT_EXPORTABLE, CRYPT_EXPORTABLE, fx_ec_der)
ROUNDTRIP_TEST(ec_overwrite,    fx_ec_pfx, CRYPT_EXPORTABLE, PKCS12_ALLOW_OVERWRITE_KEY, fx_ec_der)

TEST(pfxp_roundtrip_provider_name_attribute_note) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE); CRYPT_DATA_BLOB o;
    if (export_store(s, &o, L"export-pw", EXPORT_PRIVATE_KEYS)) {
        HCERTSTORE s2 = pk_import_pw(o.pbData, o.cbData, L"export-pw", 0);
        if (s2) { PCCERT_CONTEXT c2 = pk_first(s2); CRYPT_KEY_PROV_INFO *i = pk_info(c2);
            if (i) { t_note("KSP key exported then re-imported with flags 0: type=%lu prov=%ls", i->dwProvType, i->pwszProvName); pk_free_info(i); }
            pk_done(c2, s2); }
        LocalFree(o.pbData);
    }
    pk_done(c, s);
}

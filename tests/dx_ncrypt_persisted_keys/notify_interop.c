#include "dxk.h"

#ifndef NCRYPT_REGISTER_NOTIFY_FLAG
#define NCRYPT_REGISTER_NOTIFY_FLAG 1
#define NCRYPT_UNREGISTER_NOTIFY_FLAG 2
#endif

#define NREQ() do { REQUIRE(U(NCryptNotifyChangeKey)); if (t_is_wine()) { t_skip("NCryptNotifyChangeKey unimplemented in emulator"); return; } } while (0)
/* ---- NCryptNotifyChangeKey ---- */
TEST(dxpk_notify_resolves) { CHECK(U(NCryptNotifyChangeKey) != NULL); }
TEST(dxpk_notify_invalid_provider) {
    NREQ(); HANDLE h = NULL;
    EXPECT_S(U(NCryptNotifyChangeKey)(0, &h, NCRYPT_REGISTER_NOTIFY_FLAG), NTE_INVALID_HANDLE);
    EXPECT_S(U(NCryptNotifyChangeKey)(0, NULL, 0), NTE_INVALID_HANDLE);
}
TEST(dxpk_notify_provider_handle_type) {
    K_BEGIN(p); NCRYPT_KEY_HANDLE k = 0; HANDLE h = NULL; NREQ();
    if (!U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, NULL, 0, 0)) {
        EXPECT_S(U(NCryptNotifyChangeKey)(k, &h, NCRYPT_REGISTER_NOTIFY_FLAG), NTE_INVALID_HANDLE);
        k_free(k);
    }
    k_free(p);
}
TEST(dxpk_notify_register_unregister) {
    K_BEGIN(p); NREQ(); HANDLE h = NULL;
    if (t_is_wine()) { t_skip("not implemented in emulator"); k_free(p); return; }
    SECURITY_STATUS s = U(NCryptNotifyChangeKey)(p, &h, NCRYPT_REGISTER_NOTIFY_FLAG);
    EXPECT_S(s, 0);
    if (!s) {
        CHECK(h != NULL && h != INVALID_HANDLE_VALUE);
        DWORD w = WaitForSingleObject(h, 0);
        CHECK(w == WAIT_TIMEOUT);       /* nothing changed yet */
        EXPECT_S(U(NCryptNotifyChangeKey)(p, &h, NCRYPT_UNREGISTER_NOTIFY_FLAG), 0);
        CHECK(h == INVALID_HANDLE_VALUE);
    }
    k_free(p);
}
TEST(dxpk_notify_signals_on_key_creation) {
    KP_BEGIN(p); NREQ(); HANDLE h = NULL; WCHAR n[96]; k_name(n, 96, L"notif");
    SECURITY_STATUS s = U(NCryptNotifyChangeKey)(p, &h, NCRYPT_REGISTER_NOTIFY_FLAG);
    EXPECT_S(s, 0);
    if (s) { k_free(p); return; }
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    DWORD w = WaitForSingleObject(h, 5000);
    t_note("wait after key creation -> %lu", w);
    CHECK(w == WAIT_OBJECT_0);
    k_del(p, n, 0);
    U(NCryptNotifyChangeKey)(p, &h, NCRYPT_UNREGISTER_NOTIFY_FLAG);
    k_free(p);
}
TEST(dxpk_notify_bad_flags_note) {
    K_BEGIN(p); NREQ(); HANDLE h = NULL;
    DWORD fl[] = { 0, 0x4, 0x80, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_REGISTER_NOTIFY_FLAG | NCRYPT_UNREGISTER_NOTIFY_FLAG };
    for (int i = 0; i < 5; i++) {
        h = NULL; SECURITY_STATUS s = U(NCryptNotifyChangeKey)(p, &h, fl[i]);
        t_note("notify flags 0x%lx -> 0x%08lx h=%p", fl[i], S(s), h);
        if (!s && h && h != INVALID_HANDLE_VALUE) U(NCryptNotifyChangeKey)(p, &h, NCRYPT_UNREGISTER_NOTIFY_FLAG);
    }
    k_free(p);
}

/* ---- cross-process ---- */
CHILD(dxpk_open) {
    if (argc < 2) return 90;
    WCHAR n[128]; MultiByteToWideChar(CP_ACP, 0, argv[1], -1, n, 128);
    NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0;
    if (!U(NCryptOpenStorageProvider) || U(NCryptOpenStorageProvider)(&p, KSP, 0)) return 91;
    SECURITY_STATUS s = U(NCryptOpenKey)(p, &k, n, 0, NCRYPT_SILENT_FLAG);
    if (s) return 92;
    DWORD bits = 0, cb; U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, &cb, 0);
    U(NCryptFreeObject)(k); U(NCryptFreeObject)(p);
    return bits == 1024 ? 0 : 93;
}
CHILD(dxpk_create) {
    if (argc < 2) return 90;
    WCHAR n[128]; MultiByteToWideChar(CP_ACP, 0, argv[1], -1, n, 128);
    NCRYPT_PROV_HANDLE p = 0;
    if (!U(NCryptOpenStorageProvider) || U(NCryptOpenStorageProvider)(&p, KSP, 0)) return 91;
    SECURITY_STATUS s = k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL);
    U(NCryptFreeObject)(p);
    return s ? 92 : 0;
}
TEST(dxpk_visible_in_other_process) {
    KP_BEGIN(p); WCHAR n[96]; char an[96]; k_name(n, 96, L"xproc");
    WideCharToMultiByte(CP_ACP, 0, n, -1, an, sizeof an, NULL, NULL);
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_EQ(t_run_child("dxpk_open", an, 60000), 0);
    k_del(p, n, 0);
    EXPECT_EQ(t_run_child("dxpk_open", an, 60000), 92);   /* deleted key is gone for everybody */
    k_free(p);
}
TEST(dxpk_created_in_other_process_visible_here) {
    KP_BEGIN(p); WCHAR n[96]; char an[96]; NCRYPT_KEY_HANDLE k = 0; k_name(n, 96, L"xproc2");
    WideCharToMultiByte(CP_ACP, 0, n, -1, an, sizeof an, NULL, NULL);
    EXPECT_EQ(t_run_child("dxpk_create", an, 60000), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &k, n, 0, 0), 0);
    CHECK(k_has_name(p, 0, n, NULL));
    k_free(k);
    EXPECT_S(k_del(p, n, 0), 0);
    k_free(p);
}
static DWORD WINAPI thr_open(LPVOID a) {
    NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0; DWORD r = 1;
    if (!k_prov(&p)) { if (!U(NCryptOpenKey)(p, &k, (WCHAR *)a, 0, 0)) { r = 0; k_free(k); } k_free(p); }
    return r;
}
TEST(dxpk_cross_thread_open) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"xthr");
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    HANDLE t = CreateThread(NULL, 0, thr_open, n, 0, NULL);
    CHECK(t != NULL);
    if (t) { DWORD w = WaitForSingleObject(t, 20000); EXPECT_EQ(w, WAIT_OBJECT_0); DWORD r = 9; GetExitCodeThread(t, &r); EXPECT_EQ(r, 0); CloseHandle(t); }
    k_del(p, n, 0); k_free(p);
}
static DWORD WINAPI thr_use(LPVOID a) {
    NCRYPT_KEY_HANDLE k = (NCRYPT_KEY_HANDLE)a; DWORD v = 0, cb = 0;
    return U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, &cb, 0) == 0 && v == 1024 ? 0 : 1;
}
TEST(dxpk_key_handle_usable_cross_thread) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"xthr2"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    HANDLE t = CreateThread(NULL, 0, thr_use, (LPVOID)k, 0, NULL);
    if (t) { WaitForSingleObject(t, 20000); DWORD r = 9; GetExitCodeThread(t, &r); EXPECT_EQ(r, 0); CloseHandle(t); }
    k_del(p, n, 0); k_free(p);
}

/* ---- CryptoAPI interop ---- */
UDECL(BOOL, CryptAcquireCertificatePrivateKey_x, (PCCERT_CONTEXT, DWORD, void *, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *, DWORD *, BOOL *));

static PCCERT_CONTEXT make_cert_for(NCRYPT_KEY_HANDLE k, const WCHAR *kname)
{
    CERT_NAME_BLOB subj = { 0 };
    BYTE enc[256]; DWORD cb = sizeof enc;
    if (!U(CertStrToNameW)(X509_ASN_ENCODING, L"CN=cryptt persisted", 0, NULL, enc, &cb, NULL)) return NULL;
    subj.cbData = cb; subj.pbData = enc;
    CRYPT_KEY_PROV_INFO ki = { 0 };
    ki.pwszContainerName = (LPWSTR)kname; ki.pwszProvName = (LPWSTR)KSP; ki.dwProvType = 0; ki.dwKeySpec = 0;
    CRYPT_ALGORITHM_IDENTIFIER alg = { (LPSTR)szOID_RSA_SHA256RSA, { 0, NULL } };
    PCCERT_CONTEXT c = U(CertCreateSelfSignCertificate)(k, &subj, 0, &ki, &alg, NULL, NULL, NULL);
    return c;
}
TEST(dxpk_capi_cert_acquire_ncrypt_key) {
    KP_BEGIN(p); REQUIRE(U(CertCreateSelfSignCertificate)); REQUIRE(U(CertStrToNameW)); REQUIRE(U(CryptAcquireCertificatePrivateKey));
    REQUIRE(U(CertFreeCertificateContext));
    WCHAR n[96]; k_name(n, 96, L"capicert"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, AT_KEYEXCHANGE, 0, &k), 0);
    PCCERT_CONTEXT c = make_cert_for(k, n);
    CHECKF(c != NULL, "self-sign err %lu", GetLastError());
    if (c) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL free_it = FALSE;
        BOOL ok = U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &h, &spec, &free_it);
        CHECKF(ok, "acquire err 0x%08lx", GetLastError());
        if (ok) {
            EXPECT_EQ(spec, CERT_NCRYPT_KEY_SPEC);
            CHECK(free_it && h != 0);
            WCHAR nm[96] = { 0 }; DWORD cb = 0;
            EXPECT_S(U(NCryptGetProperty)(h, NCRYPT_NAME_PROPERTY, (PBYTE)nm, sizeof nm, &cb, 0), 0);
            EXPECT_WSTR(nm, n);
            if (free_it) U(NCryptFreeObject)(h);
        }
        /* CAPI-only request must not hand out a CNG key for a KSP-backed property */
        h = 0; spec = 0; free_it = FALSE;
        ok = U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &h, &spec, &free_it);
        t_note("acquire (any key type, compare) -> %d spec=0x%lx err=0x%08lx", ok, spec, GetLastError());
        if (ok && free_it) { if (spec == CERT_NCRYPT_KEY_SPEC) U(NCryptFreeObject)(h); else U(CryptReleaseContext)(h, 0); }
        U(CertFreeCertificateContext)(c);
    }
    k_free(k); k_del(p, n, 0); k_free(p);
}
TEST(dxpk_capi_cert_acquire_after_key_deleted) {
    KP_BEGIN(p); REQUIRE(U(CertCreateSelfSignCertificate)); REQUIRE(U(CertStrToNameW)); REQUIRE(U(CryptAcquireCertificatePrivateKey));
    WCHAR n[96]; k_name(n, 96, L"capidel"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    PCCERT_CONTEXT c = make_cert_for(k, n);
    CHECK(c != NULL);
    EXPECT_S(U(NCryptDeleteKey)(k, 0), 0);
    if (c) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL fr = FALSE;
        BOOL ok = U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &h, &spec, &fr);
        DWORD e = GetLastError();
        CHECK(!ok);
        t_note("acquire for deleted key -> err 0x%08lx", e);
        if (ok && fr) U(NCryptFreeObject)(h);
        U(CertFreeCertificateContext)(c);
    }
    k_free(p);
}
TEST(dxpk_capi_acquire_context_ksp_name_note) {
    K_NEEDS(); REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext));
    K_BEGIN(p);
    WCHAR n[96]; k_name(n, 96, L"capictx"); NCRYPT_KEY_HANDLE k = 0;
    if (t_is_wine()) { t_skip("persistence unsupported"); k_free(p); return; }
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, AT_KEYEXCHANGE, 0, &k), 0);
    HCRYPTPROV h = 0;
    BOOL ok = U(CryptAcquireContextW)(&h, n, KSP, PROV_RSA_FULL, CRYPT_SILENT);
    t_note("CryptAcquireContext(KSP name, PROV_RSA_FULL) -> %d err=0x%08lx", ok, GetLastError());
    if (ok) U(CryptReleaseContext)(h, 0);
    h = 0;
    ok = U(CryptAcquireContextW)(&h, n, KSP, 0, CRYPT_SILENT);
    t_note("CryptAcquireContext(KSP name, type 0) -> %d err=0x%08lx", ok, GetLastError());
    if (ok) U(CryptReleaseContext)(h, 0);
    k_free(k); k_del(p, n, 0); k_free(p);
}
TEST(dxpk_capi_container_visible_to_ksp_note) {
    KP_BEGIN(p); REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext));
    WCHAR n[96]; k_name(n, 96, L"capicont"); HCRYPTPROV h = 0;
    if (!U(CryptAcquireContextW)(&h, n, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
        t_note("cannot create CAPI container err=0x%08lx", GetLastError()); k_free(p); return;
    }
    U(CryptReleaseContext)(h, 0);
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptOpenKey)(p, &k, n, AT_KEYEXCHANGE, NCRYPT_SILENT_FLAG);
    t_note("KSP open of CAPI container name (no key generated) -> 0x%08lx", S(s));
    if (!s) k_free(k);
    h = 0;
    CHECK(U(CryptAcquireContextW)(&h, n, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET | CRYPT_SILENT));
    k_free(p);
}
TEST(dxpk_write_to_legacy_store_flag) {
    KP_BEGIN(p); REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext));
    WCHAR n[96]; k_name(n, 96, L"legacy"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, AT_KEYEXCHANGE, 0), 0);
    DWORD bits = 1024; U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0);
    SECURITY_STATUS s = U(NCryptFinalizeKey)(k, NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG | NCRYPT_SILENT_FLAG);
    t_note("finalize with WRITE_KEY_TO_LEGACY_STORE -> 0x%08lx", S(s));
    if (!s) {
        HCRYPTPROV h = 0;
        BOOL ok = U(CryptAcquireContextW)(&h, n, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_SILENT);
        t_note("legacy CAPI container open -> %d err=0x%08lx", ok, GetLastError());
        if (ok) U(CryptReleaseContext)(h, 0);
        h = 0;
        U(CryptAcquireContextW)(&h, n, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET | CRYPT_SILENT);
    }
    k_free(k); k_del(p, n, 0); k_free(p);
}

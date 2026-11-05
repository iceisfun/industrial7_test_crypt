/* cryptowinrt.dll entry points (DllGetActivationFactory / DllGetClassObject / DllCanUnloadNow) and
 * activation of its runtime classes through the runtime (RoGetActivationFactory). */
#include "wr.h"

#define CLASS_E_CLASSNOTAVAILABLE_HR 0x80040111u
#define E_INVALIDARG_HR 0x80070057u
#define E_NOINTERFACE_HR 0x80004002u
#define E_NOTIMPL_HR 0x80004001u
#define WINE_SKIP() do { if (t_is_wine()) { t_skip("emulator implements only a subset of cryptowinrt"); return; } } while (0)

typedef HRESULT (WINAPI *pfn_gaf)(HSTRING, void **);
typedef HRESULT (WINAPI *pfn_gco)(const GUID *, const GUID *, void **);
typedef HRESULT (WINAPI *pfn_cun)(void);
static pfn_gaf p_gaf(void) { return (pfn_gaf)t_proc_in("cryptowinrt.dll", "DllGetActivationFactory"); }
static pfn_gco p_gco(void) { return (pfn_gco)t_proc_in("cryptowinrt.dll", "DllGetClassObject"); }
static pfn_cun p_cun(void) { return (pfn_cun)t_proc_in("cryptowinrt.dll", "DllCanUnloadNow"); }

/* classes implemented in cryptowinrt.dll (recovered from the DLL's runtime class table) */
static const WCHAR *k_classes[] = {
    CLS_BUFFER, CLS_DATAPROT, CLS_ASYMNAMES, CLS_ASYMPROV, CLS_ENGINE, CLS_ECCNAMES, CLS_HASHNAMES, CLS_HASHPROV,
    CLS_KDFNAMES, CLS_KDFPROV, CLS_KDFPARAMS, CLS_MACNAMES, CLS_MACPROV, CLS_PERSISTED, CLS_SYMNAMES, CLS_SYMPROV,
};
#define NCLASSES (sizeof k_classes / sizeof *k_classes)
static const WCHAR *k_extra[] = {
    L"Windows.Security.Credentials.KeyCredentialManager", L"Windows.Internal.Security.Cryptography.Core.SymmetricPopKey",
    L"Windows.Security.Credentials.KeyCredential", L"Windows.Security.Credentials.KeyCredentialAttestationResult",
    L"Windows.Security.Credentials.KeyCredentialOperationResult", L"Windows.Security.Credentials.KeyCredentialRetrievalResult",
};

static HRESULT direct(const WCHAR *cls, UINT32 n, void **f) {
    HSTRING h = wr_hsn(cls, n); HRESULT hr;
    *f = (void *)(ULONG_PTR)1;
    hr = p_gaf()(h, f);
    wr_hsfree(h); return hr;
}

TEST(winrt_activation_exports_present) {
    HMODULE m = t_module("cryptowinrt.dll");
    if (!m) { t_skip("cryptowinrt.dll not loadable"); return; }
    CHECK(GetProcAddress(m, "DllGetActivationFactory") != NULL);
    CHECK(GetProcAddress(m, "DllGetClassObject") != NULL);
    CHECK(GetProcAddress(m, "DllCanUnloadNow") != NULL);
}
TEST(winrt_activation_export_ordinals) {
    HMODULE m = t_module("cryptowinrt.dll"); if (!m) { t_skip("no module"); return; }
    CHECK(t_proc_ord("cryptowinrt.dll", 1) == GetProcAddress(m, "DllCanUnloadNow"));
    CHECK(t_proc_ord("cryptowinrt.dll", 2) == GetProcAddress(m, "DllGetActivationFactory"));
    CHECK(t_proc_ord("cryptowinrt.dll", 3) == GetProcAddress(m, "DllGetClassObject"));
}
TEST(winrt_activation_exports_absent_names) {
    HMODULE m = t_module("cryptowinrt.dll"); if (!m) { t_skip("no module"); return; }
    SET_ERR(0); CHECK(GetProcAddress(m, "DllRegisterServer") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0); CHECK(GetProcAddress(m, "RoGetActivationFactory") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(winrt_activation_direct_all_classes) {
    WINE_SKIP();
    WR_NEED(); if (!p_gaf()) { t_skip("DllGetActivationFactory missing"); return; }
    for (size_t i = 0; i < NCLASSES; i++) {
        void *f; HRESULT hr = direct(k_classes[i], (UINT32)lstrlenW(k_classes[i]), &f);
        t_check(hr == S_OK && f && f != (void *)1, __FILE__, __LINE__, "DllGetActivationFactory", "%ls hr 0x%08lx", k_classes[i], (unsigned long)hr);
        if (SUCCEEDED(hr) && f) wr_release(f);
    }
}
TEST(winrt_activation_direct_extra_classes) {
    WR_NEED(); if (!p_gaf()) { t_skip("DllGetActivationFactory missing"); return; }
    for (size_t i = 0; i < sizeof k_extra / sizeof *k_extra; i++) {
        void *f; HRESULT hr = direct(k_extra[i], (UINT32)lstrlenW(k_extra[i]), &f);
        if (SUCCEEDED(hr) && f) wr_release(f);
        else t_note("%ls: DllGetActivationFactory hr 0x%08lx", k_extra[i], (unsigned long)hr);
        CHECK(SUCCEEDED(hr) || hr == (HRESULT)CLASS_E_CLASSNOTAVAILABLE_HR);
    }
}
TEST(winrt_activation_direct_unknown_class) {
    WINE_SKIP();
    WR_NEED(); if (!p_gaf()) { t_skip("DllGetActivationFactory missing"); return; }
    static const WCHAR *bad[] = {
        L"Windows.Security.Cryptography.NoSuchClass", L"Windows.Security.Cryptography.CryptographicBuffer ",
        L"Windows.Security.Cryptography.CryptographicBuffe", L"Windows.Security.Cryptography.CryptographicBufferX",
        L"windows.security.cryptography.cryptographicbuffer", L"WINDOWS.SECURITY.CRYPTOGRAPHY.CRYPTOGRAPHICBUFFER",
        L"Windows.Security.Cryptography.Core.HashAlgorithmProvide", L"Windows.Security.Cryptography.Core",
        L"Windows.Security.Cryptography", L"CryptographicBuffer", L"Windows.Foundation.Uri", L"x", L"Windows.Security.Cryptography.Certificates.CertificateEnrollmentManager",
        L"Windows.Security.Cryptography.Core.CryptographicHash", L"Windows.Security.Cryptography.Core.CryptographicKey",
        L"Windows.Security.Cryptography.Core.HashAlgorithmNames.", L"\\Windows.Security.Cryptography.CryptographicBuffer",
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *f; HRESULT hr = direct(bad[i], (UINT32)lstrlenW(bad[i]), &f);
        t_check(hr == (HRESULT)CLASS_E_CLASSNOTAVAILABLE_HR && f == NULL, __FILE__, __LINE__, "unknown class", "%ls hr 0x%08lx", bad[i], (unsigned long)hr);
        if (SUCCEEDED(hr) && f) wr_release(f);
    }
}
TEST(winrt_activation_direct_empty_and_null_class) {
    WINE_SKIP();
    WR_NEED(); if (!p_gaf()) { t_skip("DllGetActivationFactory missing"); return; }
    void *f = (void *)1;
    EXPECT_HR(p_gaf()(NULL, &f), E_INVALIDARG_HR);
    CHECK(f == NULL);
    HSTRING e = wr_hs(L"");
    CHECK(e == NULL);
    f = (void *)1; EXPECT_HR(p_gaf()(e, &f), E_INVALIDARG_HR); CHECK(f == NULL);
}
TEST(winrt_activation_direct_embedded_nul) {
    WINE_SKIP();
    WR_NEED(); if (!p_gaf()) { t_skip("DllGetActivationFactory missing"); return; }
    /* the exact class name followed by NUL and more characters is not the class name */
    WCHAR buf[128]; lstrcpyW(buf, CLS_BUFFER); UINT32 n = (UINT32)lstrlenW(buf);
    buf[n] = 0; buf[n + 1] = L'x'; buf[n + 2] = 0;
    void *f; HRESULT hr = direct(buf, n + 2, &f);
    EXPECT_HR(hr, E_INVALIDARG_HR); CHECK(f == NULL);
    hr = direct(buf, n + 1, &f);               /* name + trailing NUL */
    EXPECT_HR(hr, E_INVALIDARG_HR); CHECK(f == NULL);
    buf[0] = 0; hr = direct(buf, n, &f);       /* leading NUL */
    EXPECT_HR(hr, E_INVALIDARG_HR); CHECK(f == NULL);
}
TEST(winrt_activation_direct_returns_cached_singleton) {
    WINE_SKIP();
    WR_NEED(); if (!p_gaf()) { t_skip("DllGetActivationFactory missing"); return; }
    for (size_t i = 0; i < NCLASSES; i++) {
        void *a, *b; direct(k_classes[i], (UINT32)lstrlenW(k_classes[i]), &a); direct(k_classes[i], (UINT32)lstrlenW(k_classes[i]), &b);
        t_check(a && a == b && a != (void *)1, __FILE__, __LINE__, "same factory object", "%ls %p %p", k_classes[i], a, b);
        if (a && a != (void *)1) wr_release(a); if (b && b != (void *)1) wr_release(b);
    }
}
TEST(winrt_activation_factory_refcount_balanced) {
    WINE_SKIP();
    WR_NEED(); if (!p_gaf()) { t_skip("DllGetActivationFactory missing"); return; }
    void *f; HRESULT hr = direct(CLS_HASHNAMES, (UINT32)lstrlenW(CLS_HASHNAMES), &f);
    if (FAILED(hr) || !f || f == (void *)1) { CHECK(!"factory"); return; }
    ULONG a = wr_addref(f), b = wr_addref(f);
    EXPECT_EQ(b, a + 1);
    EXPECT_EQ(wr_release(f), a);
    EXPECT_EQ(wr_release(f), a - 1);
    wr_release(f);
}

/* ---- through the runtime ------------------------------------------------------------------------ */
TEST(winrt_activation_runtime_all_classes) {
    WR_NEED();
    for (size_t i = 0; i < NCLASSES; i++) {
        void *f; HRESULT hr = wr_activate(k_classes[i], &f);
        if (FAILED(hr) && t_is_wine()) { t_skip("class not registered under wine"); return; }
        t_check(hr == S_OK && f, __FILE__, __LINE__, "RoGetActivationFactory", "%ls hr 0x%08lx", k_classes[i], (unsigned long)hr);
        if (f) wr_release(f);
    }
}
TEST(winrt_activation_runtime_served_by_cryptowinrt) {
    WR_NEED();
    HMODULE m = t_module("cryptowinrt.dll");
    for (size_t i = 0; i < NCLASSES; i++) {
        void *f; HRESULT hr = wr_activate(k_classes[i], &f);
        if (FAILED(hr)) { if (t_is_wine()) { t_skip("not registered"); return; } CHECK(!"activate"); continue; }
        HMODULE owner = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)WR_VT(f)[0], &owner);
        t_check(owner == m, __FILE__, __LINE__, "factory vtable in cryptowinrt.dll", "%ls owner %p module %p", k_classes[i], owner, m);
        wr_release(f);
    }
}
TEST(winrt_activation_runtime_same_object_as_direct) {
    WR_NEED(); if (!p_gaf()) { t_skip("no export"); return; }
    for (size_t i = 0; i < NCLASSES; i++) {
        void *a, *b = NULL; HRESULT hr = wr_activate(k_classes[i], &a);
        if (FAILED(hr)) { if (t_is_wine()) { t_skip("not registered"); return; } continue; }
        direct(k_classes[i], (UINT32)lstrlenW(k_classes[i]), &b);
        void *ua = NULL, *ub = NULL;
        wr_qi(a, &WR_IID_IUnknown, &ua); if (b && b != (void *)1) wr_qi(b, &WR_IID_IUnknown, &ub);
        if (ua != ub) t_note("%ls: runtime factory %p differs from direct %p", k_classes[i], ua, ub);
        wr_release(ua); wr_release(ub); wr_release(a); if (b && b != (void *)1) wr_release(b);
    }
}
TEST(winrt_activation_runtime_unknown_class) {
    WR_NEED();
    static const WCHAR *bad[] = { L"Windows.Security.Cryptography.NoSuchClass", L"NoSuchNamespace.NoSuchClass", L"Windows.Security.Cryptography.Core.CryptographicKey", L"x" };
    for (size_t i = 0; i < 4; i++) {
        void *f = NULL; HRESULT hr = wr_activate(bad[i], &f);
        t_check(FAILED(hr) && f == NULL, __FILE__, __LINE__, "RoGetActivationFactory(unknown)", "%ls hr 0x%08lx", bad[i], (unsigned long)hr);
        t_note("%ls -> 0x%08lx", bad[i], (unsigned long)hr);
    }
}
TEST(winrt_activation_runtime_null_class_name) {
    WR_NEED();
    void *f = (void *)1;
    HRESULT hr = UIN("combase.dll", RoGetActivationFactory)(NULL, &WR_IID_IActivationFactory, &f);
    CHECK(FAILED(hr));
    t_note("RoGetActivationFactory(NULL) -> 0x%08lx", (unsigned long)hr);
}
TEST(winrt_activation_runtime_wrong_interface) {
    WR_NEED();
    HSTRING h = wr_hs(CLS_BUFFER); void *f = (void *)1;
    HRESULT hr = UIN("combase.dll", RoGetActivationFactory)(h, &WR_IID_IBuffer, &f);
    wr_hsfree(h);
    if (t_is_wine()) { t_skip("wine"); return; }
    CHECK(FAILED(hr)); CHECK(f == NULL);
    t_note("RoGetActivationFactory(CryptographicBuffer, IBuffer) -> 0x%08lx", (unsigned long)hr);
}
TEST(winrt_activation_factory_interfaces_agile) {
    WINE_SKIP();
    WR_NEED();
    for (size_t i = 0; i < NCLASSES; i++) {
        void *f = wr_factory(k_classes[i], 0); if (!f) return;
        void *o = NULL; HRESULT hr = wr_qi(f, &WR_IID_IAgileObject, &o);
        t_check(hr == S_OK && o, __FILE__, __LINE__, "IAgileObject", "%ls hr 0x%08lx", k_classes[i], (unsigned long)hr);
        wr_release(o);
        o = NULL; hr = wr_qi(f, &WR_IID_IMarshal, &o);
        t_check(hr == S_OK && o, __FILE__, __LINE__, "IMarshal (free-threaded marshaler)", "%ls hr 0x%08lx", k_classes[i], (unsigned long)hr);
        wr_release(o);
        o = NULL; hr = wr_qi(f, &WR_IID_IInspectable, &o); CHECK(hr == S_OK); wr_release(o);
        o = NULL; hr = wr_qi(f, &WR_IID_IBuffer, &o);
        t_check(hr == (HRESULT)E_NOINTERFACE_HR && !o, __FILE__, __LINE__, "IBuffer on factory", "%ls hr 0x%08lx", k_classes[i], (unsigned long)hr);
        wr_release(o); wr_release(f);
    }
}
TEST(winrt_activation_factory_getiids_first_is_factory) {
    WR_NEED();
    for (size_t i = 0; i < NCLASSES; i++) {
        void *f = wr_factory(k_classes[i], 0); if (!f) return;
        ULONG n = 0; GUID *ids = NULL; HRESULT hr = wr_getiids(f, &n, &ids);
        if (hr == E_NOTIMPL && t_is_wine()) { t_skip("stub"); wr_release(f); return; }
        t_check(hr == S_OK && n >= 2 && ids, __FILE__, __LINE__, "GetIids", "%ls hr 0x%08lx n %lu", k_classes[i], (unsigned long)hr, n);
        if (n >= 2 && ids) t_check(IsEqualGUID(&ids[0], &WR_IID_IActivationFactory), __FILE__, __LINE__, "GetIids[0] == IActivationFactory", "%ls", k_classes[i]);
        wr_cofree(ids); wr_release(f);
    }
}
TEST(winrt_activation_factory_getiids_each_iid_queryable) {
    WR_NEED();
    for (size_t i = 0; i < NCLASSES; i++) {
        void *f = wr_factory(k_classes[i], 0); if (!f) return;
        ULONG n = 0; GUID *ids = NULL;
        if (wr_getiids(f, &n, &ids) != S_OK) { wr_release(f); continue; }
        for (ULONG k = 0; k < n; k++) {
            void *o = NULL; HRESULT hr = wr_qi(f, &ids[k], &o);
            t_check(hr == S_OK && o, __FILE__, __LINE__, "QI(GetIids[k])", "%ls k=%lu hr 0x%08lx", k_classes[i], k, (unsigned long)hr);
            wr_release(o);
        }
        wr_cofree(ids); wr_release(f);
    }
}
static int has_iids(const WCHAR *cls, const GUID **want, ULONG nwant) {
    if (t_is_wine()) { t_skip("emulator GetIids is a stub"); return -1; }
    void *f = wr_factory(cls, 0); if (!f) return -1;
    ULONG n = 0; GUID *ids = NULL; int ok = 1;
    HRESULT hr = wr_getiids(f, &n, &ids);
    if (hr != S_OK || n != nwant + 1) ok = 0;
    for (ULONG k = 0; ok && k < nwant; k++) if (!IsEqualGUID(&ids[k + 1], want[k])) ok = 0;
    wr_cofree(ids); wr_release(f); return ok;
}
TEST(winrt_activation_factory_iids_hash_provider) {
    WR_NEED(); const GUID *w[] = { &WR_IID_IHashAlgorithmProviderStatics };
    int r = has_iids(CLS_HASHPROV, w, 1); if (r >= 0) CHECK(r);
}
TEST(winrt_activation_factory_iids_hash_names) {
    WR_NEED(); const GUID *w[] = { &WR_IID_IHashAlgorithmNamesStatics };
    int r = has_iids(CLS_HASHNAMES, w, 1); if (r >= 0) CHECK(r);
}
TEST(winrt_activation_factory_iids_engine) {
    WR_NEED(); const GUID *w[] = { &WR_IID_ICryptographicEngineStatics, &WR_IID_ICryptographicEngineStatics2 };
    int r = has_iids(CLS_ENGINE, w, 2); if (r >= 0) CHECK(r);
}
TEST(winrt_activation_factory_iids_asym_provider) {
    WR_NEED(); const GUID *w[] = { &WR_IID_IAsymmetricKeyAlgorithmProviderStatics };
    int r = has_iids(CLS_ASYMPROV, w, 1); if (r >= 0) CHECK(r);
}
TEST(winrt_activation_factory_iids_asym_names) {
    WR_NEED(); const GUID *w[] = { &WR_IID_IAsymmetricAlgorithmNamesStatics, &WR_IID_IAsymmetricAlgorithmNamesStatics2 };
    int r = has_iids(CLS_ASYMNAMES, w, 2); if (r >= 0) CHECK(r);
}
TEST(winrt_activation_factory_iids_dataprotection) {
    WR_NEED(); const GUID *w[] = { &WR_IID_IDataProtectionProviderFactory };
    int r = has_iids(CLS_DATAPROT, w, 1); if (r >= 0) CHECK(r);
}
TEST(winrt_activation_factory_iids_buffer) {
    WR_NEED(); const GUID *w[] = { &WR_IID_ICryptographicBufferStatics };
    int r = has_iids(CLS_BUFFER, w, 1); if (r >= 0) CHECK(r);
}
TEST(winrt_activation_activate_instance_statics_notimpl) {
    /* classes that are pure static holders cannot be default-constructed: ActivateInstance is E_NOTIMPL, out cleared */
    WR_NEED();
    static const WCHAR *s[] = { CLS_ENGINE, CLS_ASYMNAMES };
    for (int i = 0; i < 2; i++) {
        void *f = wr_factory(s[i], 0); if (!f) return;
        void *o = (void *)1; HRESULT hr = VF(f, 6, void **)(f, &o);
        t_check(hr == (HRESULT)E_NOTIMPL_HR && o == NULL, __FILE__, __LINE__, "ActivateInstance", "%ls hr 0x%08lx", s[i], (unsigned long)hr);
        wr_release(f);
    }
}
TEST(winrt_activation_activate_instance_all_statics_fail_cleanly) {
    WR_NEED();
    static const WCHAR *s[] = { CLS_BUFFER, CLS_HASHNAMES, CLS_HASHPROV, CLS_MACNAMES, CLS_MACPROV, CLS_SYMNAMES, CLS_SYMPROV, CLS_ASYMPROV, CLS_KDFNAMES, CLS_KDFPROV, CLS_ECCNAMES };
    for (size_t i = 0; i < sizeof s / sizeof *s; i++) {
        void *f = wr_factory(s[i], 0); if (!f) return;
        void *o = (void *)1; HRESULT hr = VF(f, 6, void **)(f, &o);
        if (SUCCEEDED(hr)) { t_note("%ls: ActivateInstance succeeded", s[i]); wr_release(o); }
        else t_check(o == NULL || t_is_wine(), __FILE__, __LINE__, "out cleared", "%ls hr 0x%08lx", s[i], (unsigned long)hr);
        wr_release(f);
    }
}
TEST(winrt_activation_dataprotection_activate_instance) {
    WR_NEED();
    void *f = wr_factory(CLS_DATAPROT, 0); if (!f) return;
    void *o = NULL; HRESULT hr = VF(f, 6, void **)(f, &o);
    EXPECT_HR(hr, S_OK); CHECK(o != NULL);
    if (o) {
        HSTRING n = NULL; HRESULT h2 = wr_getclassname(o, &n);
        if (SUCCEEDED(h2)) CHECK(wr_hs_eq(n, CLS_DATAPROT)); wr_hsfree(n);
        wr_release(o);
    }
    wr_release(f);
}
TEST(winrt_activation_factory_getruntimeclassname_trust) {
    WR_NEED();
    void *f = wr_factory(CLS_HASHPROV, 0); if (!f) return;
    HSTRING n = NULL; HRESULT hr = wr_getclassname(f, &n);
    t_note("factory GetRuntimeClassName -> 0x%08lx", (unsigned long)hr); wr_hsfree(n);
    int lvl = -1; hr = wr_gettrust(f, &lvl);
    t_note("factory GetTrustLevel -> 0x%08lx level %d", (unsigned long)hr, lvl);
    wr_release(f);
}
TEST(winrt_activation_provider_object_class_names) {
    WR_NEED(); void *p = NULL;
    if (wr_hash_open(L"SHA256", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(p, &n), S_OK);
    CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.HashAlgorithmProvider")); wr_hsfree(n);
    void *u = NULL; EXPECT_HR(wr_qi(p, &WR_IID_IHashAlgorithmProvider, &u), S_OK); wr_release(u);
    u = NULL; EXPECT_HR(wr_qi(p, &WR_IID_IAgileObject, &u), S_OK); wr_release(u);
    u = NULL; EXPECT_HR(wr_qi(p, &WR_IID_IBuffer, &u), E_NOINTERFACE_HR); CHECK(u == NULL);
    wr_release(p);
}

/* ---- DllGetClassObject / DllCanUnloadNow ---------------------------------------------------------- */
static const GUID k_rand_clsid = { 0x1b2d3c4e, 0x5f60, 0x4a71, { 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9 } };
static const GUID k_iid_classfactory = { 0x00000001, 0, 0, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };
TEST(winrt_activation_getclassobject_unknown_clsid) {
    if (!p_gco()) { t_skip("DllGetClassObject missing"); return; }
    void *o = (void *)1;
    HRESULT hr = p_gco()(&k_rand_clsid, &k_iid_classfactory, &o);
    EXPECT_HR(hr, CLASS_E_CLASSNOTAVAILABLE_HR);
    if (!t_is_wine()) CHECK(o == NULL);
}
TEST(winrt_activation_getclassobject_unknown_clsid_other_iids) {
    if (!p_gco()) { t_skip("DllGetClassObject missing"); return; }
    const GUID *iids[] = { &WR_IID_IUnknown, &WR_IID_IActivationFactory, &WR_IID_IInspectable, &WR_IID_IMarshal };
    for (int i = 0; i < 4; i++) {
        void *o = (void *)1; HRESULT hr = p_gco()(&k_rand_clsid, iids[i], &o);
        t_check(hr == (HRESULT)CLASS_E_CLASSNOTAVAILABLE_HR, __FILE__, __LINE__, "DllGetClassObject", "iid %d hr 0x%08lx", i, (unsigned long)hr);
    }
}
TEST(winrt_activation_getclassobject_null_clsid_value) {
    if (!p_gco()) { t_skip("DllGetClassObject missing"); return; }
    GUID z = { 0 }; void *o = (void *)1;
    HRESULT hr = p_gco()(&z, &k_iid_classfactory, &o);
    EXPECT_HR(hr, CLASS_E_CLASSNOTAVAILABLE_HR);
}
TEST(winrt_activation_getclassobject_runtime_class_ids_are_not_clsids) {
    /* the activation-factory IIDs are interface ids, not class ids: no class object is exposed for them */
    if (!p_gco()) { t_skip("DllGetClassObject missing"); return; }
    void *o = (void *)1;
    HRESULT hr = p_gco()(&WR_IID_ICryptographicBufferStatics, &k_iid_classfactory, &o);
    EXPECT_HR(hr, CLASS_E_CLASSNOTAVAILABLE_HR);
}
TEST(winrt_activation_canunloadnow_returns_hresult) {
    if (!p_cun()) { t_skip("DllCanUnloadNow missing"); return; }
    HRESULT hr = p_cun()();
    CHECK(hr == S_OK || hr == S_FALSE);
    t_note("DllCanUnloadNow -> %ld", (long)hr);
}
TEST(winrt_activation_canunloadnow_false_with_live_object) {
    WR_NEED(); if (!p_cun()) { t_skip("DllCanUnloadNow missing"); return; }
    if (!wr_cbs()) return;
    BYTE d[3] = { 1, 2, 3 }; void *b = wr_mkbuf(d, 3); if (!b) return;
    EXPECT_HR(p_cun()(), S_FALSE);
    wr_release(b);
}
TEST(winrt_activation_canunloadnow_false_with_live_provider) {
    WR_NEED(); if (!p_cun()) { t_skip("DllCanUnloadNow missing"); return; }
    void *p = NULL;
    if (wr_hash_open(L"SHA256", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    EXPECT_HR(p_cun()(), S_FALSE);
    wr_release(p);
}
TEST(winrt_activation_canunloadnow_repeatable) {
    if (!p_cun()) { t_skip("DllCanUnloadNow missing"); return; }
    HRESULT a = p_cun()(), b = p_cun()();
    EXPECT_HR(a, b);
}

/* ---- concurrency ------------------------------------------------------------------------------------ */
static volatile LONG g_thr_fail;
static DWORD WINAPI act_thread(LPVOID arg) {
    UIN("combase.dll", RoInitialize)(RO_INIT_MULTITHREADED);
    for (int i = 0; i < 40; i++)
        for (size_t c = 0; c < NCLASSES; c++) {
            void *f = NULL; HRESULT hr = wr_activate(k_classes[(c + (size_t)arg) % NCLASSES], &f);
            if (hr != S_OK || !f) InterlockedIncrement(&g_thr_fail);
            wr_release(f);
        }
    return 0;
}
TEST(winrt_activation_concurrent_activation) {
    WINE_SKIP();
    WR_NEED();
    void *probe; HRESULT hr = wr_activate(CLS_BUFFER, &probe);
    if (FAILED(hr)) { if (t_is_wine()) t_skip("not registered"); else CHECK(!"activate"); return; }
    wr_release(probe);
    HANDLE th[4]; g_thr_fail = 0;
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, act_thread, (LPVOID)(ULONG_PTR)i, 0, NULL);
    for (int i = 0; i < 4; i++) { if (th[i]) { CHECK(WaitForSingleObject(th[i], 20000) == WAIT_OBJECT_0); CloseHandle(th[i]); } }
    EXPECT_EQ(g_thr_fail, 0);
}

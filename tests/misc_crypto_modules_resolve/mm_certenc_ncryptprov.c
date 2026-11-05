/* certenc.dll (ATL COM server for the CertEncode classes) and the key-storage interface entry
 * points of ncryptprov.dll / ncrypt.dll. */
#include "t.h"
#include <objbase.h>
#include <oaidl.h>

typedef HRESULT (WINAPI *DllGetClassObject_t)(const GUID *, const GUID *, void **);
typedef HRESULT (WINAPI *DllCanUnloadNow_t)(void);

#define EQ32(got, want) do { unsigned g_ = (unsigned)(got); \
    t_check(g_ == (unsigned)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%08x want 0x%08x", g_, (unsigned)(want)); } while (0)

static const GUID kIID_IUnknown      = {0x00000000,0x0000,0x0000,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID kIID_IClassFactory = {0x00000001,0x0000,0x0000,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID kIID_IDispatch     = {0x00020400,0x0000,0x0000,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID kIID_IMarshal      = {0x00000003,0x0000,0x0000,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID kBogus             = {0xdeadbeef,0xcafe,0xf00d,{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}};
static const GUID kNull              = {0};

/* CertEncode coclass identifiers (certenc.h). */
typedef struct { const char *name; GUID clsid; } CLS;
static const CLS kClasses[] = {
    {"CCertEncodeStringArray", {0x19a76fe0,0x7494,0x11d0,{0x88,0x16,0x00,0xa0,0xc9,0x03,0xb8,0x3c}}},
    {"CCertEncodeLongArray",   {0x4e0680a0,0xa0a2,0x11d0,{0x88,0x21,0x00,0xa0,0xc9,0x03,0xb8,0x3c}}},
    {"CCertEncodeDateArray",   {0x301f77b0,0xa470,0x11d0,{0x88,0x21,0x00,0xa0,0xc9,0x03,0xb8,0x3c}}},
    {"CCertEncodeCRLDistInfo", {0x01fa60a0,0xbbff,0x11d0,{0x88,0x25,0x00,0xa0,0xc9,0x03,0xb8,0x3c}}},
    {"CCertEncodeAltName",     {0x1cfc4cda,0x1271,0x11d1,{0x9b,0xd4,0x00,0xc0,0x4f,0xb6,0x83,0xfa}}},
};
#define NCLS ((int)(sizeof kClasses / sizeof kClasses[0]))

#define NEED_CE() DllGetClassObject_t gco = (DllGetClassObject_t)t_proc_in("certenc.dll", "DllGetClassObject"); \
    DllCanUnloadNow_t cun = (DllCanUnloadNow_t)t_proc_in("certenc.dll", "DllCanUnloadNow"); \
    REQUIRE(gco); REQUIRE(cun)

/* Returns a factory or NULL (every listed class is served on Win10, so anything else is a failure). */
static IClassFactory *get_factory(DllGetClassObject_t gco, int i) {
    void *p = (void *)7;
    HRESULT hr = gco(&kClasses[i].clsid, &kIID_IClassFactory, &p);
    EQ32(hr, S_OK);
    CHECK(p != NULL && p != (void *)7);
    return hr == S_OK ? (IClassFactory *)p : NULL;
}

TEST(mm_certenc_can_unload_idle) {
    NEED_CE();
    EQ32(cun(), S_OK);           /* no objects and no locks yet */
    EQ32(cun(), S_OK);
}
TEST(mm_certenc_bogus_clsid) {
    NEED_CE();
    void *p = (void *)7;
    EQ32(gco(&kBogus, &kIID_IClassFactory, &p), 0x80040111);   /* CLASS_E_CLASSNOTAVAILABLE */
    CHECK(p == NULL);
    p = (void *)7;
    EQ32(gco(&kNull, &kIID_IClassFactory, &p), 0x80040111);
    CHECK(p == NULL);
    p = (void *)7;
    EQ32(gco(&kBogus, &kIID_IUnknown, &p), 0x80040111);
    CHECK(p == NULL);
}
TEST(mm_certenc_null_ppv) {
    NEED_CE();
    EQ32(gco(&kClasses[0].clsid, &kIID_IClassFactory, NULL), E_POINTER);
    EQ32(gco(&kBogus, &kIID_IClassFactory, NULL), E_POINTER);
}
TEST(mm_certenc_factory_for_every_class) {
    NEED_CE();
    for (int i = 0; i < NCLS; i++) {
        IClassFactory *f = get_factory(gco, i);
        if (!f) continue;
        ULONG r = f->lpVtbl->Release(f);
        /* the factory is shared: the final Release leaves one reference (observed on Win10) */
        CHECKF(r == 1, "%s release count %lu", kClasses[i].name, (unsigned long)r);
    }
    EQ32(cun(), S_OK);
}
TEST(mm_certenc_factory_iunknown_identity) {
    NEED_CE();
    for (int i = 0; i < NCLS; i++) {
        IClassFactory *f = get_factory(gco, i);
        if (!f) continue;
        IUnknown *u = NULL;
        EQ32(f->lpVtbl->QueryInterface(f, &kIID_IUnknown, (void **)&u), S_OK);
        CHECK(u != NULL);
        if (u) {
            IUnknown *u2 = NULL;
            EQ32(u->lpVtbl->QueryInterface(u, &kIID_IUnknown, (void **)&u2), S_OK);
            CHECK(u2 == u);
            if (u2) u2->lpVtbl->Release(u2);
            u->lpVtbl->Release(u);
        }
        f->lpVtbl->Release(f);
    }
}
TEST(mm_certenc_factory_unsupported_interface) {
    NEED_CE();
    IClassFactory *f = get_factory(gco, 0); REQUIRE(f);
    void *p = (void *)7;
    EQ32(f->lpVtbl->QueryInterface(f, &kBogus, &p), E_NOINTERFACE);
    CHECK(p == NULL);
    p = (void *)7;
    EQ32(f->lpVtbl->QueryInterface(f, &kIID_IDispatch, &p), E_NOINTERFACE);   /* a factory is not a dispatch object */
    CHECK(p == NULL);
    f->lpVtbl->Release(f);
}
TEST(mm_certenc_getclassobject_unsupported_interface) {
    NEED_CE();
    void *p = (void *)7;
    EQ32(gco(&kClasses[0].clsid, &kBogus, &p), E_NOINTERFACE);
    CHECK(p == NULL);
    p = (void *)7;
    HRESULT hr = gco(&kClasses[0].clsid, &kIID_IDispatch, &p);
    EQ32(hr, E_NOINTERFACE); CHECK(p == NULL);
    if (p && p != (void *)7) ((IUnknown *)p)->lpVtbl->Release((IUnknown *)p);
    EQ32(cun(), S_OK);
}
TEST(mm_certenc_factory_refcounting) {
    NEED_CE();
    IClassFactory *f = get_factory(gco, 0); REQUIRE(f);
    ULONG a = f->lpVtbl->AddRef(f);
    ULONG b = f->lpVtbl->AddRef(f);
    CHECK(b == a + 1);
    CHECK(f->lpVtbl->Release(f) == a);
    CHECK(f->lpVtbl->Release(f) == a - 1);
    CHECK(f->lpVtbl->Release(f) == 1);     /* shared factory: one reference remains */
    EQ32(a, 3);
}
TEST(mm_certenc_lockserver_controls_unload) {
    NEED_CE();
    IClassFactory *f = get_factory(gco, 0); REQUIRE(f);
    EQ32(cun(), S_FALSE);                  /* the held factory keeps the module in use */
    EQ32(f->lpVtbl->LockServer(f, TRUE), S_OK);
    EQ32(f->lpVtbl->LockServer(f, TRUE), S_OK);
    EQ32(f->lpVtbl->LockServer(f, FALSE), S_OK);
    f->lpVtbl->Release(f);
    EQ32(cun(), S_FALSE);                  /* still one lock after the factory is gone */
    IClassFactory *g = get_factory(gco, 1); REQUIRE(g);
    EQ32(g->lpVtbl->LockServer(g, FALSE), S_OK);   /* the lock count is per server, not per factory */
    g->lpVtbl->Release(g);
    EQ32(cun(), S_OK);
}
TEST(mm_certenc_create_instance_keeps_module_alive) {
    NEED_CE();
    for (int i = 0; i < NCLS; i++) {
        IClassFactory *f = get_factory(gco, i);
        if (!f) continue;
        IUnknown *o = NULL;
        EQ32(f->lpVtbl->CreateInstance(f, NULL, &kIID_IUnknown, (void **)&o), S_OK);
        CHECKF(o != NULL, "%s", kClasses[i].name);
        if (o) {
            CHECK(cun() == S_FALSE);       /* a live object holds the module */
            o->lpVtbl->Release(o);
        }
        /* a held class factory also keeps the module in use (observed on Win10) */
        CHECKF(cun() == S_FALSE, "%s factory still holds the module", kClasses[i].name);
        f->lpVtbl->Release(f);
        CHECKF(cun() == S_OK, "%s unloadable after release", kClasses[i].name);
    }
}
TEST(mm_certenc_create_instance_dispatch) {
    NEED_CE();
    for (int i = 0; i < NCLS; i++) {
        IClassFactory *f = get_factory(gco, i);
        if (!f) continue;
        IDispatch *d = NULL;
        EQ32(f->lpVtbl->CreateInstance(f, NULL, &kIID_IDispatch, (void **)&d), S_OK);
        CHECKF(d != NULL, "%s", kClasses[i].name);
        if (d) {
            UINT n = 99;
            EQ32(d->lpVtbl->GetTypeInfoCount(d, &n), S_OK);
            CHECKF(n == 1, "%s typeinfo count %u", kClasses[i].name, n);
            IUnknown *u = NULL;
            EQ32(d->lpVtbl->QueryInterface(d, &kIID_IUnknown, (void **)&u), S_OK);
            if (u) {
                IUnknown *u2 = NULL;
                EQ32(u->lpVtbl->QueryInterface(u, &kIID_IUnknown, (void **)&u2), S_OK);
                CHECK(u == u2);
                if (u2) u2->lpVtbl->Release(u2);
                u->lpVtbl->Release(u);
            }
            void *bad = (void *)7;
            EQ32(d->lpVtbl->QueryInterface(d, &kBogus, &bad), E_NOINTERFACE);
            CHECK(bad == NULL);
            d->lpVtbl->Release(d);
        }
        f->lpVtbl->Release(f);
    }
    EQ32(cun(), S_OK);
}
TEST(mm_certenc_create_instance_bad_interface) {
    NEED_CE();
    IClassFactory *f = get_factory(gco, 0); REQUIRE(f);
    void *p = (void *)7;
    EQ32(f->lpVtbl->CreateInstance(f, NULL, &kBogus, &p), E_NOINTERFACE);
    CHECK(p == NULL);
    EQ32(cun(), S_FALSE);                  /* the held factory keeps the module in use */
    f->lpVtbl->Release(f);
    EQ32(cun(), S_OK);                     /* the failed object was released */
}
TEST(mm_certenc_create_instance_null_out) {
    NEED_CE();
    IClassFactory *f = get_factory(gco, 0); REQUIRE(f);
    EQ32(f->lpVtbl->CreateInstance(f, NULL, &kIID_IUnknown, NULL), E_POINTER);
    f->lpVtbl->Release(f);
}
TEST(mm_certenc_create_instance_no_aggregation) {
    NEED_CE();
    IClassFactory *f = get_factory(gco, 0); REQUIRE(f);
    /* an outer unknown with an interface other than IUnknown is a COM contract violation */
    IUnknown *outer = (IUnknown *)(ULONG_PTR)0x10;   /* never dereferenced on a rejecting path */
    void *p = (void *)7;
    HRESULT hr = f->lpVtbl->CreateInstance(f, outer, &kIID_IDispatch, &p);
    CHECKF(hr == (HRESULT)CLASS_E_NOAGGREGATION, "hr 0x%08x", (unsigned)hr);
    CHECK(p == NULL);
    f->lpVtbl->Release(f);
}
TEST(mm_certenc_instances_are_distinct) {
    NEED_CE();
    IClassFactory *f = get_factory(gco, 0); REQUIRE(f);
    IUnknown *a = NULL, *b = NULL;
    EQ32(f->lpVtbl->CreateInstance(f, NULL, &kIID_IUnknown, (void **)&a), S_OK);
    EQ32(f->lpVtbl->CreateInstance(f, NULL, &kIID_IUnknown, (void **)&b), S_OK);
    CHECK(a && b && a != b);
    if (a) a->lpVtbl->Release(a);
    CHECK(cun() == S_FALSE);
    if (b) b->lpVtbl->Release(b);
    EQ32(cun(), S_FALSE);                  /* the factory itself still holds the module */
    f->lpVtbl->Release(f);
    EQ32(cun(), S_OK);
}
TEST(mm_certenc_factories_distinct_per_class) {
    NEED_CE();
    IClassFactory *fs[8] = {0};
    for (int i = 0; i < NCLS; i++) fs[i] = get_factory(gco, i);
    for (int i = 0; i < NCLS; i++)
        for (int j = i + 1; j < NCLS; j++)
            if (fs[i] && fs[j]) CHECKF(fs[i] != fs[j], "%s vs %s", kClasses[i].name, kClasses[j].name);
    for (int i = 0; i < NCLS; i++) if (fs[i]) fs[i]->lpVtbl->Release(fs[i]);
}
TEST(mm_certenc_registration_entry_points_resolve_only) {
    /* DllRegisterServer/DllUnregisterServer write HKCR/HKLM; never invoked */
    if (!t_module("certenc.dll")) { if (t_is_wine()) t_skip("certenc.dll absent"); else CHECKF(0, "certenc.dll absent"); return; }
    CHECK(t_proc_in("certenc.dll", "DllRegisterServer") != NULL);
    CHECK(t_proc_in("certenc.dll", "DllUnregisterServer") != NULL);
}

/* ======================== ncryptprov.dll / ncrypt.dll ========================================= */
typedef HRESULT (WINAPI *GKSI_t)(const WCHAR *, void **, DWORD);

/* NCRYPT_KEY_STORAGE_FUNCTION_TABLE: version, then provider callbacks. */
typedef struct { USHORT major, minor; } IFVER;
typedef struct {
    IFVER Version;
    void *pfnOpenProvider, *pfnOpenKey, *pfnCreatePersistedKey, *pfnGetProviderProperty, *pfnGetKeyProperty,
         *pfnSetProviderProperty, *pfnSetKeyProperty, *pfnFinalizeKey, *pfnDeleteKey, *pfnFreeProvider,
         *pfnFreeKey, *pfnFreeBuffer, *pfnEncrypt, *pfnDecrypt, *pfnIsAlgSupported, *pfnEnumAlgorithms,
         *pfnEnumKeys, *pfnImportKey, *pfnExportKey, *pfnSignHash, *pfnVerifySignature, *pfnPromptUser,
         *pfnNotifyChangeKey, *pfnSecretAgreement, *pfnDeriveKey, *pfnFreeSecret;
} KSFT;

static const WCHAR kMsKsp[] = L"Microsoft Software Key Storage Provider";

TEST(mm_ksp_get_key_storage_interface_returns_table) {
    GKSI_t f = (GKSI_t)t_proc_in("ncryptprov.dll", "GetKeyStorageInterface"); REQUIRE(f);
    KSFT *t = (KSFT *)7;
    EQ32(f(kMsKsp, (void **)&t, 0), S_OK);
    CHECK(t != NULL && t != (KSFT *)7);
    if (!t || t == (KSFT *)7) return;
    CHECKF(t->Version.major == 3 && t->Version.minor == 0, "table version %u.%u", t->Version.major, t->Version.minor);
    HMODULE m = t_module("ncryptprov.dll");
    MEMORY_BASIC_INFORMATION mbi;
    CHECK(VirtualQuery(t, &mbi, sizeof mbi) && mbi.AllocationBase == (PVOID)m);   /* static table inside the DLL */
    void **fn = (void **)&t->pfnOpenProvider;
    int nz = 0;
    for (int i = 0; i < 25; i++) if (fn[i]) nz++;
    CHECKF(nz == 25, "%d of 25 callbacks non-NULL", nz);
}
TEST(mm_ksp_core_callbacks_present) {
    GKSI_t f = (GKSI_t)t_proc_in("ncryptprov.dll", "GetKeyStorageInterface"); REQUIRE(f);
    for (DWORD fl = 0; fl < 2; fl++) {
        KSFT *t = NULL;
        EQ32(f(kMsKsp, (void **)&t, fl), S_OK);
        if (!t) { CHECK(0); continue; }
        CHECKF(t->pfnOpenProvider, "flags %lu OpenProvider", fl);
        CHECKF(t->pfnOpenKey, "flags %lu OpenKey", fl);
        CHECKF(t->pfnCreatePersistedKey, "flags %lu CreatePersistedKey", fl);
        CHECKF(t->pfnFreeProvider, "flags %lu FreeProvider", fl);
        CHECKF(t->pfnFreeKey, "flags %lu FreeKey", fl);
        CHECKF(t->pfnFreeBuffer, "flags %lu FreeBuffer", fl);
        CHECKF(t->pfnFinalizeKey && t->pfnDeleteKey, "flags %lu Finalize/Delete", fl);
        CHECKF(t->pfnGetProviderProperty && t->pfnGetKeyProperty, "flags %lu GetProperty", fl);
    }
}
TEST(mm_ksp_table_is_stable_across_calls) {
    GKSI_t f = (GKSI_t)t_proc_in("ncryptprov.dll", "GetKeyStorageInterface"); REQUIRE(f);
    KSFT *a = NULL, *b = NULL, *c = NULL;
    EQ32(f(kMsKsp, (void **)&a, 0), S_OK);
    EQ32(f(kMsKsp, (void **)&b, 0), S_OK);
    EQ32(f(L"Microsoft Smart Card Key Storage Provider", (void **)&c, 0), S_OK);
    CHECK(a && a == b);
    CHECK(c == a);                          /* the provider name does not select the table */
}
TEST(mm_ksp_flag_bit0_selects_table) {
    GKSI_t f = (GKSI_t)t_proc_in("ncryptprov.dll", "GetKeyStorageInterface"); REQUIRE(f);
    KSFT *z = NULL, *o = NULL, *e = NULL;
    EQ32(f(kMsKsp, (void **)&z, 0), S_OK);
    EQ32(f(kMsKsp, (void **)&o, 1), S_OK);
    EQ32(f(kMsKsp, (void **)&e, 2), S_OK);   /* bit 0 clear -> same table as flags 0 */
    CHECK(z && o && e);
    CHECK(e == z);
    EQ32(f(kMsKsp, (void **)&e, 3), S_OK);
    CHECK(e == o);                          /* bit 0 set */
    CHECK(z != o);                          /* observed: flags 0 and 1 give different tables */
}
TEST(mm_ksp_other_flag_bits_are_ignored) {
    GKSI_t f = (GKSI_t)t_proc_in("ncryptprov.dll", "GetKeyStorageInterface"); REQUIRE(f);
    KSFT *a = NULL, *b = NULL;
    EQ32(f(kMsKsp, (void **)&a, 0), S_OK);
    EQ32(f(kMsKsp, (void **)&b, 0xFFFFFFFEu), S_OK);
    CHECK(a == b);
}
TEST(mm_ksp_provider_name_is_not_validated) {
    GKSI_t f = (GKSI_t)t_proc_in("ncryptprov.dll", "GetKeyStorageInterface"); REQUIRE(f);
    KSFT *a = NULL, *b = NULL;
    EQ32(f(kMsKsp, (void **)&a, 0), S_OK);
    EQ32(f(L"No such provider cryptt", (void **)&b, 0), S_OK);
    CHECK(a == b);
    b = NULL;
    EQ32(f(L"", (void **)&b, 0), S_OK);
    CHECK(a == b);
}
TEST(mm_ksp_resolve_only_entry_points) {
    if (!t_module("ncryptprov.dll")) { if (t_is_wine()) t_skip("ncryptprov.dll absent"); else CHECKF(0, "ncryptprov.dll absent"); return; }
    /* SKCacheFlush drops cached secrets and SetAuditingInterface installs global callbacks; resolve only */
    CHECK(t_proc_in("ncryptprov.dll", "SKCacheFlush") != NULL);
    CHECK(t_proc_in("ncryptprov.dll", "SetAuditingInterface") != NULL);
}

TEST(mm_ncrypt_get_key_storage_interface_stub) {
    GKSI_t f = (GKSI_t)t_proc_in("ncrypt.dll", "GetKeyStorageInterface"); REQUIRE(f);
    if (t_is_wine()) { t_skip("emulator export differs"); return; }
    void *p = (void *)7;
    EQ32(f(kMsKsp, &p, 0), 0x8007007F);     /* HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND) */
    CHECK(p == (void *)7);                  /* nothing is written */
    EQ32(f(NULL, NULL, 0), 0x8007007F);
    EQ32(f(kMsKsp, &p, 1), 0x8007007F);
}
TEST(mm_ncrypt_get_isolation_server_interface_stub) {
    typedef HRESULT (WINAPI *GISI_t)(void *, void *, void *);
    GISI_t f = (GISI_t)t_proc_in("ncrypt.dll", "GetIsolationServerInterface"); REQUIRE(f);
    if (t_is_wine()) { t_skip("emulator export differs"); return; }
    EQ32(f(NULL, NULL, NULL), 0x8007007F);
    void *p = (void *)7;
    EQ32(f(&p, &p, &p), 0x8007007F);
    CHECK(p == (void *)7);
}
TEST(mm_ncrypt_storage_stubs_share_one_body) {
    if (!t_module("ncrypt.dll") || t_is_wine()) { t_skip("ncrypt.dll absent or emulated"); return; }
    FARPROC a = t_proc_in("ncrypt.dll", "GetKeyStorageInterface");
    FARPROC b = t_proc_in("ncrypt.dll", "GetIsolationServerInterface");
    CHECK(a && a == b);
    /* the third alias belongs to the secure-channel surface and is deliberately not called */
}
TEST(mm_ncrypt_and_ncryptprov_tables_differ_in_origin) {
    FARPROC a = t_proc_in("ncrypt.dll", "GetKeyStorageInterface");
    FARPROC b = t_proc_in("ncryptprov.dll", "GetKeyStorageInterface");
    if (!a || !b) { t_skip("module absent"); return; }
    CHECK(a != b);                          /* ncrypt's export is a stub, the provider's is the real one */
}


/* Resolve-only coverage of the small crypt-related modules: every export is looked up by name
 * and by ordinal through GetProcAddress, never called. Tables in mm_exports.h come from the
 * Windows 10 export directories. */
#include "t.h"
#include "mm_exports.h"

#define NEXP(a) ((unsigned)(sizeof(a) / sizeof((a)[0])))

static int in_image(HMODULE m, FARPROC p) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void *)p, &mbi, sizeof mbi)) return 0;
    return mbi.AllocationBase == (void *)m;
}

static int load_or_skip(const char *dll, HMODULE *out) {
    *out = t_module(dll);
    if (!*out) { t_skip("%s not present", dll); return 0; }
    return 1;
}

/* every named export resolves by name; the address is inside the image unless it is a forwarder */
static void by_name(const char *dll, const mm_exp *e, unsigned n) {
    HMODULE m; if (!load_or_skip(dll, &m)) return;
    for (unsigned i = 0; i < n; i++) {
        SET_ERR(0);
        FARPROC p = GetProcAddress(m, e[i].name);
        if (!p && t_is_wine()) { t_note("emulator lacks %s!%s", dll, e[i].name); continue; }
        CHECKF(p != NULL, "%s!%s", dll, e[i].name);
        if (!p) continue;
        if (!e[i].fwd) CHECKF(in_image(m, p), "%s!%s inside image", dll, e[i].name);
        else CHECKF(!in_image(m, p), "%s!%s forwarded out of image", dll, e[i].name);
    }
}

/* ordinal and name give the same address; ordinals are 1..n without holes */
static void by_ord(const char *dll, const mm_exp *e, unsigned n) {
    HMODULE m; if (!load_or_skip(dll, &m)) return;
    for (unsigned i = 0; i < n; i++) {
        FARPROC a = GetProcAddress(m, (LPCSTR)(ULONG_PTR)e[i].ord);
        FARPROC b = GetProcAddress(m, e[i].name);
        if (t_is_wine() && (!a || !b)) continue;
        CHECKF(a != NULL && a == b, "%s ordinal %u == %s", dll, e[i].ord, e[i].name);
        CHECKF(e[i].ord == i + 1, "%s ordinals contiguous at %s", dll, e[i].name);
    }
}

/* names that are not exports fail with ERROR_PROC_NOT_FOUND; lookup is case sensitive */
static void negatives(const char *dll, const mm_exp *e, unsigned n) {
    HMODULE m; if (!load_or_skip(dll, &m)) return;
    SET_ERR(0);
    CHECK(GetProcAddress(m, "NoSuchExport_cryptt") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)(n + 1)) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)0xFFFF) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    char buf[128]; lstrcpynA(buf, e[0].name, sizeof buf);
    for (char *c = buf; *c; c++) { if (*c >= 'A' && *c <= 'Z') *c += 32; else if (*c >= 'a' && *c <= 'z') *c -= 32; }
    if (strcmp(buf, e[0].name)) {
        SET_ERR(0);
        CHECK(GetProcAddress(m, buf) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
    /* a decorated/undecorated variant is not an export either */
    snprintf(buf, sizeof buf, "_%s", e[0].name);
    SET_ERR(0);
    CHECK(GetProcAddress(m, buf) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    /* the harness lookup agrees with the direct lookup */
    for (unsigned i = 0; i < n; i++)
        CHECKF(t_proc_in(dll, e[i].name) == GetProcAddress(m, e[i].name), "t_proc_in %s", e[i].name);
}

#define MODTESTS(mod, dll) \
    TEST(mm_exports_##mod##_by_name) { by_name(dll, exp_##mod, NEXP(exp_##mod)); } \
    TEST(mm_exports_##mod##_by_ordinal) { by_ord(dll, exp_##mod, NEXP(exp_##mod)); } \
    TEST(mm_exports_##mod##_negatives) { negatives(dll, exp_##mod, NEXP(exp_##mod)); } \
    TEST(mm_exports_##mod##_count) { \
        HMODULE m; if (!load_or_skip(dll, &m)) return; \
        /* nothing beyond the documented range resolves */ \
        for (unsigned o = NEXP(exp_##mod) + 1; o < NEXP(exp_##mod) + 6; o++) \
            CHECKF(GetProcAddress(m, (LPCSTR)(ULONG_PTR)o) == NULL, "ordinal %u", o); \
        CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)0) == NULL); \
    }

MODTESTS(cryptngc, "cryptngc.dll")
MODTESTS(keyiso, "keyiso.dll")
MODTESTS(certprop, "certprop.dll")
MODTESTS(cryptcatsvc, "cryptcatsvc.dll")
MODTESTS(capisp, "capisp.dll")
MODTESTS(certenc, "certenc.dll")
MODTESTS(ncryptprov, "ncryptprov.dll")
MODTESTS(cryptdlg, "cryptdlg.dll")
MODTESTS(cryptext, "cryptext.dll")
MODTESTS(cryptui, "cryptui.dll")

/* ---- aliases and forwarders -------------------------------------------------------------- */
TEST(mm_exports_keyiso_auditing_forwarder) {
    if (!t_module("keyiso.dll") || !t_module("ncryptprov.dll")) { t_skip("module absent"); return; }
    FARPROC a = t_proc_in("keyiso.dll", "KeyIsoSetAuditingInterface");
    FARPROC b = t_proc_in("ncryptprov.dll", "SetAuditingInterface");
    CHECK(a != NULL); CHECK(b != NULL);
    /* keyiso forwards NCRYPTPROV.SetAuditingInterface: both names give the same code address */
    CHECK(a == b);
    FARPROC o = t_proc_ord("keyiso.dll", 2);
    CHECK(o == b);
}

TEST(mm_exports_cryptngc_fido_share_one_stub) {
    if (!t_module("cryptngc.dll")) { t_skip("cryptngc.dll absent"); return; }
    FARPROC a = t_proc_in("cryptngc.dll", "FidoCreateCredential");
    FARPROC b = t_proc_in("cryptngc.dll", "FidoGetCredential");
    FARPROC c = t_proc_in("cryptngc.dll", "FidoSignWithCredential");
    CHECK(a && a == b && b == c);
    CHECK(t_proc_ord("cryptngc.dll", 1) == a);
    CHECK(t_proc_ord("cryptngc.dll", 3) == a);
}

TEST(mm_exports_cryptui_free_pages_share_one_body) {
    if (!t_module("cryptui.dll") || t_is_wine()) { t_skip("cryptui.dll absent or emulated"); return; }
    const char *n[] = {"CryptUIFreeCertificatePropertiesPagesA", "CryptUIFreeCertificatePropertiesPagesW",
                       "CryptUIFreeViewSignaturesPagesA", "CryptUIFreeViewSignaturesPagesW"};
    FARPROC p0 = t_proc_in("cryptui.dll", n[0]);
    CHECK(p0 != NULL);
    for (int i = 1; i < 4; i++) CHECKF(t_proc_in("cryptui.dll", n[i]) == p0, "%s", n[i]);
}

TEST(mm_exports_servicemain_names_are_distinct_code) {
    if (!t_module("certprop.dll")) { t_skip("certprop.dll absent"); return; }
    FARPROC a = t_proc_in("certprop.dll", "CertPropServiceMain");
    FARPROC b = t_proc_in("certprop.dll", "ScPolicyServiceMain");
    FARPROC c = t_proc_in("certprop.dll", "SvchostPushServiceGlobals");
    CHECK(a && b && c); CHECK(a != b); CHECK(b != c); CHECK(a != c);
    /* resolve only: these are service entry points and must not be called here */
}

TEST(mm_exports_capisp_resolve_only) {
    if (!t_module("capisp.dll")) { t_skip("capisp.dll absent"); return; }
    /* sysprep helpers rewrite machine key state; the corpus never calls them. */
    const char *n[] = {"CAPISysPrep_Generalize", "CryptoSysPrep_Clean", "CryptoSysPrep_Specialize",
                       "CryptoSysPrep_Specialize_Clone", "CryptoSysPrep_Specialize_Offline"};
    for (int i = 0; i < 5; i++) CHECKF(t_proc_in("capisp.dll", n[i]) != NULL, "%s", n[i]);
}

TEST(mm_exports_cryptcatsvc_resolve_only) {
    if (!t_module("cryptcatsvc.dll")) { t_skip("cryptcatsvc.dll absent"); return; }
    const char *n[] = {"CatDbOfflineRebuildDatabasesRundll32W", "CatDbOfflineRebuildDatabasesW",
                       "CryptCATAdminCatalogDatabase", "CryptsvcDllCtrl"};
    for (int i = 0; i < 4; i++) CHECKF(t_proc_in("cryptcatsvc.dll", n[i]) != NULL, "%s", n[i]);
}

TEST(mm_exports_u_search_order_finds_small_modules) {
    /* U() finds each name somewhere in the module list */
    if (t_is_wine()) { t_skip("emulator export set differs"); return; }
    CHECK(t_proc("GetKeyStorageInterface") != NULL || !t_module("ncryptprov.dll"));
    CHECK(t_proc("NgcGetEventInterface") != NULL || !t_module("cryptngc.dll"));
    CHECK(t_proc("GetFriendlyNameOfCertW") != NULL || !t_module("cryptdlg.dll"));
    CHECK(t_proc("MyFormatEnhancedKeyUsageString") != NULL || !t_module("cryptui.dll"));
}

TEST(mm_exports_modules_load_idempotent) {
    const char *d[] = {"cryptngc.dll", "keyiso.dll", "certprop.dll", "cryptcatsvc.dll", "capisp.dll",
                       "certenc.dll", "ncryptprov.dll", "cryptdlg.dll", "cryptext.dll", "cryptui.dll"};
    for (int i = 0; i < 10; i++) {
        HMODULE a = t_module(d[i]);
        if (!a) { t_note("%s absent", d[i]); continue; }
        HMODULE b = GetModuleHandleA(d[i]);
        CHECKF(a == b, "%s", d[i]);
        char path[MAX_PATH]; DWORD n = GetModuleFileNameA(a, path, sizeof path);
        CHECKF(n > 0 && n < sizeof path, "%s", d[i]);
    }
}

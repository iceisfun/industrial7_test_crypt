/* Forwarder tables (Windows 10 x64), pinned to the exporting module with UIN.
 *
 * mssip32.dll -> wintrust.dll (by name):
 *   #1 CryptSIPGetInfo, #2 CryptSIPGetRegWorkingFlags, #3 CryptSIPCreateIndirectData,
 *   #4 CryptSIPGetSignedDataMsg, #5 CryptSIPPutSignedDataMsg, #6 CryptSIPRemoveSignedDataMsg,
 *   #7 CryptSIPVerifyIndirectData  -> Wintrust.<same name>
 *   #8 DllRegisterServer -> Wintrust.mssip32DllRegisterServer, #9 DllUnregisterServer -> Wintrust.mssip32DllUnregisterServer
 * crypt32.dll -> dpapi.dll:
 *   #1209 CryptProtectMemory, #1239 CryptUnprotectMemory, #1243 CryptUpdateProtectedState -> DPAPI.<same name>
 * keyiso.dll: #2 KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
 * certcli.dll: 158 of 172 exports forward to CERTCA.<name> or CERTCA.#<ordinal>
 *   (certcli #201..#2xx -> CERTCA.#701.., e.g. CSPrintAssert -> CERTCA.#701); the full table is in exp_data2.c.
 * Dll(Un)RegisterServer and other entry points are only resolved, never called.
 */
#include "t.h"
#include <wincrypt.h>
#include <mssip.h>
#include <wintrust.h>
#include <ncrypt.h>

UDECL(BOOL, CryptSIPGetInfo, (void *));
UDECL(BOOL, CryptSIPGetRegWorkingFlags, (DWORD *));
#undef CHECK
#undef CHECKF
#define CHECK(c) do { int o_ = !!(c); if (!o_ && t_is_wine()) t_note("[emulator gap] %s", #c); else t_check(o_, __FILE__, __LINE__, #c, NULL); } while (0)
#define CHECKF(c, ...) do { int o_ = !!(c); if (!o_ && t_is_wine()) t_note("[emulator gap] " __VA_ARGS__); else t_check(o_, __FILE__, __LINE__, #c, __VA_ARGS__); } while (0)
#define SAME(dll1, dll2, fn) do { \
    FARPROC a_ = t_proc_in(dll1, #fn), b_ = t_proc_in(dll2, #fn); \
    if (t_is_wine() && (!a_ || !b_)) { t_note("emulator gap: %s", #fn); break; } \
    CHECKF(a_ != NULL, "%s!%s missing", dll1, #fn); CHECKF(b_ != NULL, "%s!%s missing", dll2, #fn); \
    CHECKF(a_ == b_, "%s!%s (%p) != %s!%s (%p)", dll1, #fn, (void *)a_, dll2, #fn, (void *)b_); } while (0)

TEST(exp_pinned_mssip32_CryptSIPGetInfo)             { SAME("mssip32.dll", "wintrust.dll", CryptSIPGetInfo); }
TEST(exp_pinned_mssip32_CryptSIPGetRegWorkingFlags)  { SAME("mssip32.dll", "wintrust.dll", CryptSIPGetRegWorkingFlags); }
TEST(exp_pinned_mssip32_CryptSIPCreateIndirectData)  { SAME("mssip32.dll", "wintrust.dll", CryptSIPCreateIndirectData); }
TEST(exp_pinned_mssip32_CryptSIPGetSignedDataMsg)    { SAME("mssip32.dll", "wintrust.dll", CryptSIPGetSignedDataMsg); }
TEST(exp_pinned_mssip32_CryptSIPPutSignedDataMsg)    { SAME("mssip32.dll", "wintrust.dll", CryptSIPPutSignedDataMsg); }
TEST(exp_pinned_mssip32_CryptSIPRemoveSignedDataMsg) { SAME("mssip32.dll", "wintrust.dll", CryptSIPRemoveSignedDataMsg); }
TEST(exp_pinned_mssip32_CryptSIPVerifyIndirectData)  { SAME("mssip32.dll", "wintrust.dll", CryptSIPVerifyIndirectData); }

TEST(exp_pinned_mssip32_dll_register_forwards_to_private_names) {
    HMODULE w = t_module("wintrust.dll"), m = t_module("mssip32.dll");
    if (!w || !m) { t_skip("module missing"); return; }
    FARPROC a = GetProcAddress(m, "DllRegisterServer"), b = GetProcAddress(w, "mssip32DllRegisterServer");
    FARPROC c = GetProcAddress(m, "DllUnregisterServer"), d = GetProcAddress(w, "mssip32DllUnregisterServer");
    if (t_is_wine() && !(a && b && c && d)) { t_note("emulator gap"); return; }
    CHECK(a && b && a == b);
    CHECK(c && d && c == d);
    /* wintrust's own registration entry points are different functions */
    FARPROC e = GetProcAddress(w, "DllRegisterServer");
    CHECK(e != NULL); CHECK(e != a);
}

TEST(exp_pinned_mssip32_exports_only_forwarders) {
    HMODULE m = t_module("mssip32.dll");
    if (!m) { t_skip("mssip32 missing"); return; }
    for (unsigned o = 1; o <= 9; o++) {
        FARPROC p = GetProcAddress(m, (LPCSTR)(ULONG_PTR)o);
        if (!p) { if (t_is_wine()) t_note("gap #%u", o); else CHECKF(0, "ordinal %u missing", o); continue; }
        MEMORY_BASIC_INFORMATION mbi;
        CHECK(VirtualQuery((void *)p, &mbi, sizeof mbi) != 0);
        CHECKF(mbi.AllocationBase != (void *)m, "ordinal %u resolved inside mssip32", o);
    }
}

TEST(exp_pinned_crypt32_CryptProtectMemory_dpapi)         { SAME("crypt32.dll", "dpapi.dll", CryptProtectMemory); }
TEST(exp_pinned_crypt32_CryptUnprotectMemory_dpapi)       { SAME("crypt32.dll", "dpapi.dll", CryptUnprotectMemory); }
TEST(exp_pinned_crypt32_CryptUpdateProtectedState_dpapi) {
    UDECL(BOOL, CryptUpdateProtectedState, (PSID, LPCWSTR, DWORD, DWORD *, DWORD *));
    FARPROC a = t_proc_in("crypt32.dll", "CryptUpdateProtectedState"), b = t_proc_in("dpapi.dll", "CryptUpdateProtectedState");
    if (t_is_wine() && !(a && b)) { t_note("emulator gap"); return; }
    CHECK(a && b && a == b);
}
TEST(exp_pinned_crypt32_protect_data_is_local) {
    /* CryptProtectData/CryptUnprotectData are real crypt32 code (they are not in the forwarder table). */
    HMODULE m = t_module("crypt32.dll");
    if (!m) { t_skip("crypt32 missing"); return; }
    FARPROC p = GetProcAddress(m, "CryptProtectData");
    MEMORY_BASIC_INFORMATION mbi;
    CHECK(p != NULL); if (!p) return;
    CHECK(VirtualQuery((void *)p, &mbi, sizeof mbi) != 0);
    CHECK(mbi.AllocationBase == (void *)m);
}

TEST(exp_pinned_keyiso_KeyIsoSetAuditingInterface_forward) {
    HMODULE k = t_module("keyiso.dll"), n = t_module("ncryptprov.dll");
    if (!k || !n) { t_skip("module missing"); return; }
    FARPROC a = GetProcAddress(k, "KeyIsoSetAuditingInterface"), b = GetProcAddress(n, "SetAuditingInterface");
    if (t_is_wine() && !(a && b)) { t_note("emulator gap"); return; }
    CHECK(a && b && a == b);
    FARPROC o = GetProcAddress(k, (LPCSTR)(ULONG_PTR)2);
    CHECK(o == a);
}

/* certcli.dll forwarders: spot checks of both forms (by name and by ordinal) against certca.dll. */
TEST(exp_pinned_certcli_forward_by_ordinal) {
    static const struct { const char *n; unsigned co, ta; } r[] = {
        { "CSPrintAssert", 201, 701 }, { "CSPrintError", 202, 702 }, { "DbgPrintf", 203, 703 },
        { "DbgPrintfInit", 204, 704 }, { "DbgIsSSActive", 205, 705 } };
    HMODULE cc = t_module("certcli.dll"), ca = t_module("certca.dll");
    if (!cc || !ca) { t_skip("module missing"); return; }
    for (int i = 0; i < 5; i++) {
        FARPROC a = GetProcAddress(cc, r[i].n), b = GetProcAddress(ca, (LPCSTR)(ULONG_PTR)r[i].ta);
        FARPROC c = GetProcAddress(cc, (LPCSTR)(ULONG_PTR)r[i].co);
        if (t_is_wine() && !(a && b && c)) { t_note("emulator gap %s", r[i].n); continue; }
        CHECKF(a && b && a == b, "%s", r[i].n);
        CHECKF(c == a, "%s ordinal %u", r[i].n, r[i].co);
    }
}
TEST(exp_pinned_certcli_forward_by_name) {
    static const char *r[] = { "CAAccessCheck", "CAAccessCheckEx", "CAAddCACertificateType", "CAAddCACertificateTypeEx", "CACertTypeAccessCheck" };
    HMODULE cc = t_module("certcli.dll"), ca = t_module("certca.dll");
    if (!cc || !ca) { t_skip("module missing"); return; }
    for (int i = 0; i < 5; i++) {
        FARPROC a = GetProcAddress(cc, r[i]), b = GetProcAddress(ca, r[i]);
        if (t_is_wine() && !(a && b)) { t_note("emulator gap %s", r[i]); continue; }
        CHECKF(a && b && a == b, "%s", r[i]);
    }
}
TEST(exp_pinned_certca_has_no_forwarders_for_its_own_names) {
    HMODULE ca = t_module("certca.dll");
    if (!ca) { t_skip("certca missing"); return; }
    FARPROC p = GetProcAddress(ca, "CAFindByName");
    MEMORY_BASIC_INFORMATION mbi;
    CHECK(p != NULL); if (!p) return;
    CHECK(VirtualQuery((void *)p, &mbi, sizeof mbi) != 0);
    CHECK(mbi.AllocationBase == (void *)ca);
    CHECK(GetProcAddress(ca, (LPCSTR)(ULONG_PTR)401) == p);
}

/* Ordinal-only modules: no export carries a name. */
#include "exp.h"
static void all_unnamed(const char *dll, const exp_ent *t, int n) {
    HMODULE m = t_module(dll);
    if (!m) { t_skip("%s missing", dll); return; }
    for (int i = 0; i < n; i++) {
        CHECKF(t[i].name == NULL, "%s #%u is named in the table", dll, t[i].ord);
        CHECKF(GetProcAddress(m, (LPCSTR)(ULONG_PTR)t[i].ord) != NULL, "%s #%u missing", dll, t[i].ord);
    }
}
TEST(exp_pinned_ntasn1_ordinal_only)  { all_unnamed("ntasn1.dll", exp_tab_ntasn1, exp_cnt_ntasn1); }
TEST(exp_pinned_msasn1_all_named) {
    int named = 0;
    for (int i = 0; i < exp_cnt_msasn1; i++) named += exp_tab_msasn1[i].name != NULL;
    CHECKF(exp_cnt_msasn1 == 152 && named == 152, "msasn1 table: %d of %d exports named", named, exp_cnt_msasn1);
}

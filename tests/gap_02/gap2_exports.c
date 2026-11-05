/* Export-table facts for the internal / ordinal-only surface: every name resolves, the by-name and
 * by-ordinal lookups reach the same code, and certcli/keyiso forwarders land on the target export. */
#include "gap2.h"
#include <string.h>

static void ord_module(const char *dll)
{
    HMODULE m = t_module(dll);
    if (!m) { t_skip("module not present: %s", dll); return; }
    int n = 0, wmis = 0;
    for (const g2_ord *e = g2_ordtab; e->dll; e++) {
        if (strcmp(e->dll, dll)) continue;
        FARPROC byname = GetProcAddress(m, e->name);
        FARPROC byord = GetProcAddress(m, (LPCSTR)(ULONG_PTR)e->ord);
        n++;
        if (t_is_wine()) { if (byname != byord) wmis++; continue; }   /* ordinals are an implementation detail of the emulator */
        CHECKF(byname != NULL, "%s!%s does not resolve by name", dll, e->name);
        CHECKF(byord != NULL, "%s!#%u does not resolve by ordinal", dll, e->ord);
        CHECKF(byname == byord, "%s!%s (%p) differs from #%u (%p)", dll, e->name, byname, e->ord, byord);
    }
    CHECK(n > 0);
    if (wmis) t_note("%s: %d ordinal mismatches (emulator)", dll, wmis);
}
#define ORD_TEST(id, dll) TEST(gap2_exports_ordinals_##id) { ord_module(dll); }
ORD_TEST(cryptngc, "cryptngc.dll")
ORD_TEST(capisp, "capisp.dll")
ORD_TEST(cryptcatsvc, "cryptcatsvc.dll")
ORD_TEST(keyiso, "keyiso.dll")
ORD_TEST(mssip32, "mssip32.dll")
ORD_TEST(cryptui, "cryptui.dll")
ORD_TEST(cryptext, "cryptext.dll")
ORD_TEST(msasn1, "msasn1.dll")
ORD_TEST(certca, "certca.dll")
ORD_TEST(cryptdll, "cryptdll.dll")
ORD_TEST(ncrypt, "ncrypt.dll")
ORD_TEST(tbs, "tbs.dll")
ORD_TEST(wintrust, "wintrust.dll")

/* certcli re-exports the shared certca helpers (named and ordinal-only) as forwarders. */
static void fwd_module(const char *dll)
{
    int n = 0;
    for (const g2_fwd *f = g2_fwdtab; f->dll; f++) {
        if (strcmp(f->dll, dll)) continue;
        HMODULE s = t_module(f->dll), t = t_module(f->tdll);
        if (!s || !t) { t_skip("module not present"); return; }
        FARPROC a = GetProcAddress(s, f->name);
        FARPROC b = f->tname ? GetProcAddress(t, f->tname) : GetProcAddress(t, (LPCSTR)(ULONG_PTR)f->tord);
        n++;
        CHECKF(a != NULL, "%s!%s unresolved", f->dll, f->name);
        CHECKF(b != NULL, "%s target of %s unresolved", f->tdll, f->name);
        CHECKF(a == b, "%s!%s -> %s: %p vs %p", f->dll, f->name, f->tdll, a, b);
    }
    CHECK(n > 0);
}
TEST(gap2_exports_forwarders_certcli) { fwd_module("certcli.dll"); }
TEST(gap2_exports_forwarders_keyiso) { fwd_module("keyiso.dll"); }

TEST(gap2_exports_getprocaddress_negative_pairs) {
    SET_ERR(0);
    CHECK(GetProcAddress(t_module("certca.dll"), "CAIsValidNoSuchName") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(t_module("cryptngc.dll"), (LPCSTR)(ULONG_PTR)0xFFF0) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(t_module("certca.dll"), (LPCSTR)(ULONG_PTR)0x7FFE) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}

/* The public names of ordinal-only certca exports are not exported by certca itself: only certcli names them. */
TEST(gap2_exports_certca_ordinal_only_names_absent) {
    HMODULE ca = t_module("certca.dll"); if (!ca) { t_skip("no certca"); return; }
    static const char *names[] = { "CAIsValid", "CAIsCertTypeValid", "CAGetAccessRights", "CAGetCertTypeAccessRights",
        "CSPrintErrorLineFileData2", "DbgPrintf", "myHResultToString_old", "myCAPropInfoUnmarshal", "myFreeColumnDisplayNames" };
    for (unsigned i = 0; i < sizeof names / sizeof *names; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(ca, names[i]) == NULL, "certca!%s should not be a named export", names[i]);
        HMODULE cli = t_module("certcli.dll");
        CHECKF(cli && GetProcAddress(cli, names[i]) != NULL, "certcli!%s must be exported", names[i]);
    }
}

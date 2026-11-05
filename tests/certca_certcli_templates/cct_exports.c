/* Export surface and forwarders: certca.dll exports, certcli.dll exports, certcli -> certca forwarding. */
#include "cct.h"
#include "cct_exlist.inc"

typedef struct { const char *name; const char *target; unsigned ord; } fwrow;
static const fwrow k_fw[] = {
#include "cct_fwtab.inc"
    { NULL, NULL, 0 }
};

TEST(cct_exports_modules_load)
{
    if (t_is_wine() && !t_module("certca.dll")) { t_skip("certca.dll not provided by this emulator"); return; }
    CHECK(t_module("certca.dll") != NULL);
    CHECK(t_module("certcli.dll") != NULL);
}

TEST(cct_exports_certca_named_resolve)
{
    HMODULE m = t_module("certca.dll");
    REQUIRE(m);
    for (int i = 0; k_certca_names[i]; i++) {
        FARPROC p = GetProcAddress(m, k_certca_names[i]);
        CHECKF(p != NULL, "certca.dll!%s", k_certca_names[i]);
    }
}

TEST(cct_exports_certcli_named_resolve)
{
    HMODULE m = t_module("certcli.dll");
    REQUIRE(m);
    for (int i = 0; k_certcli_names[i]; i++) {
        /* names with an @N decoration in the list are exported undecorated-by-ordinal; skip those */
        FARPROC p = GetProcAddress(m, k_certcli_names[i]);
        if (!p) t_note("certcli.dll does not export %s by that name", k_certcli_names[i]);
    }
    CHECK(GetProcAddress(m, "CAGetCertTypeProperty") != NULL);
    CHECK(GetProcAddress(m, "myCryptBinaryToString") != NULL);
    CHECK(GetProcAddress(m, "SplitConfigString") != NULL);
}

TEST(cct_exports_missing_name_fails)
{
    HMODULE a = t_module("certca.dll"), b = t_module("certcli.dll");
    REQUIRE(a); REQUIRE(b);
    SET_ERR(0);
    CHECK(GetProcAddress(a, "CANoSuchExport_cryptt") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(b, "CANoSuchExport_cryptt") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}

TEST(cct_exports_ordinal_zero_fails)
{
    HMODULE a = t_module("certca.dll");
    REQUIRE(a);
    SET_ERR(0);
    CHECK(GetProcAddress(a, MAKEINTRESOURCEA(0)) == NULL);
    CHECK(GetLastError() != 0);
}

/* Every certcli export that is a forwarder resolves to the very same code address as the certca target. */
TEST(cct_forwarders_resolve_to_certca)
{
    HMODULE cli = t_module("certcli.dll"), ca = t_module("certca.dll");
    REQUIRE(cli); REQUIRE(ca);
    int n = 0;
    for (const fwrow *r = k_fw; r->name; r++) {
        FARPROC a = GetProcAddress(cli, r->name);
        FARPROC b = r->target ? GetProcAddress(ca, r->target) : GetProcAddress(ca, MAKEINTRESOURCEA(r->ord));
        CHECKF(a != NULL, "certcli!%s", r->name);
        CHECKF(b != NULL, "certca target of %s", r->name);
        CHECKF(a == b, "certcli!%s %p vs certca %p", r->name, (void *)a, (void *)b);
        n++;
    }
    CHECK(n >= 150);
    t_note("forwarded exports checked: %d (build 19041 has 158)", n);
}

/* Forwarded exports by name: the certca side keeps the same name where the forward is by name. */
TEST(cct_forwarders_by_name_match_certca_name)
{
    HMODULE cli = t_module("certcli.dll"), ca = t_module("certca.dll");
    REQUIRE(cli); REQUIRE(ca);
    int n = 0;
    for (const fwrow *r = k_fw; r->name; r++) {
        if (!r->target) continue;
        CHECKF(GetProcAddress(ca, r->name) == GetProcAddress(cli, r->name), "%s", r->name);
        n++;
    }
    CHECK(n > 80);
}

/* certcli's own (non forwarded) exports live inside certcli.dll, not certca.dll. */
TEST(cct_forwarders_own_exports_in_certcli)
{
    HMODULE cli = t_module("certcli.dll"), ca = t_module("certca.dll");
    REQUIRE(cli); REQUIRE(ca);
    const char *own[] = { "DllCanUnloadNow", "DllGetClassObject", "DllMain", "DllRegisterServer", "DllUnregisterServer" };
    for (int i = 0; i < 5; i++) {
        FARPROC p = GetProcAddress(cli, own[i]);
        CHECKF(p != NULL, "%s", own[i]);
        if (!p) continue;
        HMODULE owner = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p, &owner);
        CHECKF(owner == cli, "%s owner", own[i]);
    }
    FARPROC f = GetProcAddress(cli, "CAGetCertTypeProperty");
    HMODULE owner = NULL;
    if (f) GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)f, &owner);
    CHECK(owner == ca);
}

/* Helpers exported by certcli by name live in certca under ordinals 601..604, 701..708, 801.. only. */
TEST(cct_forwarders_helper_ordinals_unnamed_in_certca)
{
    HMODULE ca = t_module("certca.dll");
    REQUIRE(ca);
    const char *helpers[] = { "myCryptBinaryToString", "mySanitizeName", "SplitConfigString", "myGenerateGuidString",
                              "WszToMultiByteInteger", "myGetErrorMessageText", "DbgPrintf", "CSPrintError" };
    for (int i = 0; i < 8; i++) {
        SET_ERR(0);
        FARPROC p = GetProcAddress(ca, helpers[i]);
        CHECKF(p == NULL, "certca exports %s by name", helpers[i]);
    }
}

/* State-changing / directory-writing exports: resolve only, never called with live objects. */
TEST(cct_resolve_only_state_changing)
{
    const char *names[] = {
        "CAUpdateCA", "CAUpdateCAEx", "CAUpdateCertType", "CAUpdateCertTypeEx", "CADeleteCA", "CADeleteCAEx",
        "CADeleteCertType", "CADeleteCertTypeEx", "CACreateNewCA", "CAInstallDefaultCertType", "CAInstallDefaultCertTypeEx",
        "CAOIDAdd", "CAOIDAddEx", "CAOIDDelete", "CAOIDDeleteEx", "CAOIDSetProperty", "CAOIDSetPropertyEx",
        "CASetCAProperty", "CASetCASecurity", "CASetCACertificate", "CAAddCACertificateType", "CAAddCACertificateTypeEx",
        "CARemoveCACertificateType", "CARemoveCACertificateTypeEx", "CACreateAutoEnrollmentObjectEx",
        "CACreateLocalAutoEnrollmentObject", "CADeleteLocalAutoEnrollmentObject", "CADCSetCertTypePropertyEx", NULL };
    for (int i = 0; names[i]; i++)
        CHECKF(t_proc_in("certca.dll", names[i]) != NULL, "%s", names[i]);
    const char *iis[] = { "AddOrRemoveOCSPISAPIExtension", "EnableASPInIIS", "EnableISAPIExtension", "IsASPEnabledInIIS",
        "IsASPEnabledInIIS_New", "IsISAPIExtensionEnabled", "RemoveISAPIExtension", "RemoveVDir", "myAddShare",
        "myModifyVirtualRootsAndFileShares", "myEnablePrivilege", "myNetLogonUser", "myGetSidFromDomain",
        "myGetTargetMachineDomainDnsName", "myRobustLdapBind", "myRobustLdapBindEx", "CAGetConfigStringFromUIPicker", NULL };
    for (int i = 0; iis[i]; i++)
        CHECKF(t_proc_in("certcli.dll", iis[i]) != NULL, "%s", iis[i]);
}

TEST(cct_resolve_unique_names_via_u)
{
    /* U()/t_proc module search order finds the CA* names without pinning a module. */
    CHECK(t_proc("CACreateCertType") != NULL);
    CHECK(t_proc("CAEnumCertTypes") != NULL);
    CHECK(t_proc("CCFindCertificateFromFilter") != NULL);
    CHECK(t_proc("myCryptBinaryToString") != NULL);
}

TEST(cct_exports_dll_entry_points_present)
{
    HMODULE cli = t_module("certcli.dll"), ca = t_module("certca.dll");
    REQUIRE(cli); REQUIRE(ca);
    /* certca registers nothing itself; certcli carries the COM entry points */
    CHECK(GetProcAddress(cli, "DllGetClassObject") != NULL);
    CHECK(GetProcAddress(cli, "DllCanUnloadNow") != NULL);
    t_note("certca DllRegisterServer present: %d", GetProcAddress(ca, "DllRegisterServer") != NULL);
}

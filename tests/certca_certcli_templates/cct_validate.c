/* Parameter validation of the certca.dll / certcli.dll CA* surface. Every case here is rejected by the export itself
 * before any directory access, so no object, directory or network is involved. Each case runs against both certca.dll
 * and certcli.dll (certcli forwards). */
#include "cct.h"

static const char *const MODS[2] = { "certca.dll", "certcli.dll" };
#define SENT ((void *)(ULONG_PTR)0x5ca1ab1e)
#define FAKE ((void *)(ULONG_PTR)0x1)          /* never dereferenced on the paths below */

/* VT(testname, export, expected, call-expression using f) */
#define VT(tn, fn, want, ...) \
TEST(cct_val_##tn) { \
    for (int m_ = 0; m_ < 2; m_++) { \
        fn##_pfn f = (fn##_pfn)t_proc_in(MODS[m_], #fn); \
        if (!f) { t_skip("missing export: " #fn); return; } \
        void *out = SENT; (void)out; \
        HRESULT hr_ = (HRESULT)(__VA_ARGS__); \
        CHECKF(hr_ == (HRESULT)(want), "%s!%s: got 0x%lx want 0x%lx", MODS[m_], #fn, (long)hr_, (long)(HRESULT)(want)); \
    } \
}

/* ---- certificate-type handle functions ---- */
VT(closecerttype_null,      CACloseCertType, E_PTR, f(NULL))
VT(getprop_null_handle,     CAGetCertTypeProperty, E_PTR, f(NULL, L"cn", (LPWSTR **)&out))
VT(getpropex_null_handle,   CAGetCertTypePropertyEx, E_PTR, f(NULL, L"cn", &out))
VT(setprop_null_handle,     CASetCertTypeProperty, E_PTR, f(NULL, L"cn", NULL))
VT(freeprop_null_handle,    CAFreeCertTypeProperty, E_PTR, f(NULL, NULL))
VT(freeprop_any_handle_null_ptr, CAFreeCertTypeProperty, 0, f(FAKE, NULL))
VT(getflags_null_handle,    CAGetCertTypeFlags, E_PTR, f(NULL, (DWORD *)&out))
VT(getflags_null_out,       CAGetCertTypeFlags, E_PTR, f(FAKE, NULL))
VT(getflagsex_null_handle,  CAGetCertTypeFlagsEx, E_PTR, f(NULL, 4, (DWORD *)&out))
VT(getflagsex_null_out,     CAGetCertTypeFlagsEx, E_PTR, f(FAKE, 4, NULL))
VT(setflags_null_handle,    CASetCertTypeFlags, E_PTR, f(NULL, 0))
VT(setflagsex_null_handle,  CASetCertTypeFlagsEx, E_PTR, f(NULL, 1, 0))
VT(setkeyspec_null_handle,  CASetCertTypeKeySpec, E_PTR, f(NULL, 1))
VT(getkeyspec_null_handle,  CAGetCertTypeKeySpec, E_PTR, f(NULL, (DWORD *)&out))
VT(getkeyspec_null_out,     CAGetCertTypeKeySpec, E_PTR, f(FAKE, NULL))
VT(setexpiry_null_handle,   CASetCertTypeExpiration, E_PTR, f(NULL, NULL, NULL))
VT(getexpiry_null_handle,   CAGetCertTypeExpiration, E_PTR, f(NULL, NULL, NULL))
VT(setext_null_handle,      CASetCertTypeExtension, E_PTR, f(NULL, L"2.5.29.15", 0, NULL))
VT(getext_null_handle,      CAGetCertTypeExtensions, E_PTR, f(NULL, (CERT_EXTENSIONS **)&out))
VT(getextex_null_handle,    CAGetCertTypeExtensionsEx, E_PTR, f(NULL, 0, NULL, (CERT_EXTENSIONS **)&out))
VT(freeext_null_ptr,        CAFreeCertTypeExtensions, 0, f(NULL, NULL))
VT(freeext_ignores_handle,  CAFreeCertTypeExtensions, 0, f(FAKE, NULL))
VT(getsec_null_handle,      CACertTypeGetSecurity, E_PTR, f(NULL, (PSECURITY_DESCRIPTOR *)&out))
VT(setsec_null_handle,      CACertTypeSetSecurity, E_PTR, f(NULL, FAKE))
VT(accesscheck_null_handle, CACertTypeAccessCheck, E_PTR, f(NULL, NULL))
VT(accesscheckex_null_handle, CACertTypeAccessCheckEx, E_PTR, f(NULL, NULL, 1))
VT(authzaccesscheck_null_handle, CACertTypeAuthzAccessCheck, E_PTR, f(NULL, NULL, 1))
VT(updatecerttype_null,     CAUpdateCertType, E_PTR, f(NULL))
VT(updatecerttypeex_null,   CAUpdateCertTypeEx, E_PTR, f(NULL, 0, NULL))
VT(updatecerttypeex_null_even_with_flags, CAUpdateCertTypeEx, E_PTR, f(NULL, 1, NULL))
VT(deletecerttype_null,     CADeleteCertType, E_PTR, f(NULL))
VT(deletecerttypeex_null,   CADeleteCertTypeEx, E_PTR, f(NULL, 0, NULL))
VT(enumnextcerttype_null,   CAEnumNextCertType, E_PTR, f(NULL, (HCT *)&out))
VT(enumnextcerttype_null_out, CAEnumNextCertType, E_PTR, f(FAKE, NULL))
VT(createcerttype_null_name, CACreateCertType, E_PTR, f(NULL, NULL, 0, (HCT *)&out))
VT(createcerttype_null_out, CACreateCertType, E_PTR, f(L"cryptt_val", NULL, 0, NULL))
VT(createcerttype_both_null, CACreateCertType, E_PTR, f(NULL, NULL, 0, NULL))
VT(clonecerttype_null_source, CACloneCertType, E_BADARG, f(NULL, L"cryptt_clone", NULL, NULL, 0, (HCT *)&out))
VT(clonecerttype_null_name, CACloneCertType, E_BADARG, f(FAKE, NULL, NULL, NULL, 0, (HCT *)&out))
VT(clonecerttype_null_out,  CACloneCertType, E_BADARG, f(FAKE, L"cryptt_clone", NULL, NULL, 0, NULL))
VT(enumcerttypes_null_out,  CAEnumCertTypes, E_PTR, f(0, NULL))
VT(enumcerttypesex_null_out, CAEnumCertTypesEx, E_PTR, f(NULL, 0, NULL))
VT(enumcerttypesex_ldap_flag_null_out, CAEnumCertTypesEx, E_PTR, f(NULL, 0x800, NULL))
VT(enumcerttypesforca_null_ca, CAEnumCertTypesForCA, E_PTR, f(NULL, 0, (HCT *)&out))
VT(enumcerttypesforcaex_null_ca, CAEnumCertTypesForCAEx, E_PTR, f(NULL, NULL, 0, (HCT *)&out))
VT(installdefaultex_ldap_flag_null, CAInstallDefaultCertTypeEx, E_PTR, f(NULL, 0x800))

/* ---- CA handle functions ---- */
VT(closeca_null,            CACloseCA, E_PTR, f(NULL))
VT(enumnextca_null,         CAEnumNextCA, E_PTR, f(NULL, (HCA *)&out))
VT(enumnextca_null_out,     CAEnumNextCA, E_PTR, f(FAKE, NULL))
VT(getcaprop_null,          CAGetCAProperty, E_PTR, f(NULL, L"cn", (LPWSTR **)&out))
VT(setcaprop_null,          CASetCAProperty, E_PTR, f(NULL, L"cn", NULL))
VT(freecaprop_null_handle,  CAFreeCAProperty, E_PTR, f(NULL, NULL))
VT(freecaprop_any_handle,   CAFreeCAProperty, 0, f(FAKE, NULL))
VT(getcaflags_null,         CAGetCAFlags, E_PTR, f(NULL, (DWORD *)&out))
VT(getcaflags_null_out,     CAGetCAFlags, E_PTR, f(FAKE, NULL))
VT(setcaflags_null,         CASetCAFlags, E_PTR, f(NULL, 0))
VT(getcaexpiry_null,        CAGetCAExpiration, E_PTR, f(NULL, (DWORD *)&out, (DWORD *)&out))
VT(setcaexpiry_null,        CASetCAExpiration, E_PTR, f(NULL, 1, 1))
VT(getcacert_null,          CAGetCACertificate, E_PTR, f(NULL, (PCCERT_CONTEXT *)&out))
VT(setcacert_null,          CASetCACertificate, E_PTR, f(NULL, NULL))
VT(getcasec_null,           CAGetCASecurity, E_PTR, f(NULL, (PSECURITY_DESCRIPTOR *)&out))
VT(setcasec_null,           CASetCASecurity, E_PTR, f(NULL, FAKE))
VT(cacheck_null,            CAAccessCheck, E_PTR, f(NULL, NULL))
VT(cacheckex_null,          CAAccessCheckEx, E_PTR, f(NULL, NULL, 1))
VT(updateca_null,           CAUpdateCA, E_PTR, f(NULL))
VT(updatecaex_null,         CAUpdateCAEx, E_PTR, f(NULL, 0, NULL))
VT(deleteca_null,           CADeleteCA, E_PTR, f(NULL))
VT(deletecaex_null,         CADeleteCAEx, E_PTR, f(NULL, 0, NULL))
VT(findbyname_null_name,    CAFindByName, E_PTR, f(NULL, NULL, 0, (HCA *)&out))
VT(findbyname_null_out,     CAFindByName, E_PTR, f(L"cryptt_none", NULL, 0, NULL))
VT(findbyname_flag_0x1000,  CAFindByName, E_NOIMPL, f(L"cryptt_none", NULL, 0x1000, (HCA *)&out))
VT(findbycerttype_null_name, CAFindByCertType, E_PTR, f(NULL, NULL, 0, (HCA *)&out))
VT(findbycerttype_null_out, CAFindByCertType, E_PTR, f(L"cryptt_none", NULL, 0, NULL))
VT(findbycerttype_flag_0x1000, CAFindByCertType, E_NOIMPL, f(L"cryptt_none", NULL, 0x1000, (HCA *)&out))
VT(findbyissuerdn_null_blob, CAFindByIssuerDN, E_PTR, f(NULL, NULL, 0, (HCA *)&out))
VT(createnewca_null_name,   CACreateNewCA, E_PTR, f(NULL, NULL, 0, (HCA *)&out))
VT(createnewca_null_out,    CACreateNewCA, E_PTR, f(L"cryptt_none", NULL, 0, NULL))
VT(createnewca_flag_0x1000, CACreateNewCA, E_NOIMPL, f(L"cryptt_none", NULL, 0x1000, (HCA *)&out))

TEST(cct_val_findbyissuerdn_flag_0x1000_and_null_out)
{
    for (int m = 0; m < 2; m++) {
        CAFindByIssuerDN_pfn f = (CAFindByIssuerDN_pfn)t_proc_in(MODS[m], "CAFindByIssuerDN");
        REQUIRE(f);
        BYTE dn[] = { 0x30, 0x00 };
        CRYPT_DATA_BLOB b = { sizeof dn, dn };
        void *out = SENT;
        CHECK(f(&b, NULL, 0, NULL) == E_PTR);
        CHECK(f(&b, NULL, 0x1000, (HCA *)&out) == E_NOIMPL);
        CHECK(out == SENT);
    }
}

TEST(cct_val_out_params_untouched_on_validation_failure)
{
    CAFindByName_pfn fb = CCA(CAFindByName);
    CACreateCertType_pfn cc = CCA(CACreateCertType);
    CACloneCertType_pfn cl = CCA(CACloneCertType);
    REQUIRE(fb); REQUIRE(cc); REQUIRE(cl);
    HCA a = SENT; HCT t = SENT;
    CHECK(fb(NULL, NULL, 0, &a) == E_PTR); CHECK(a == SENT);
    CHECK(fb(L"x", NULL, 0x1000, &a) == E_NOIMPL); CHECK(a == SENT);
    CHECK(cc(NULL, NULL, 0, &t) == E_PTR); CHECK(t == SENT);
    CHECK(cl(NULL, L"x", NULL, NULL, 0, &t) == E_BADARG); CHECK(t == SENT);
}

TEST(cct_val_counts_of_null_handles_are_zero)
{
    for (int m = 0; m < 2; m++) {
        CACountCAs_pfn a = (CACountCAs_pfn)t_proc_in(MODS[m], "CACountCAs");
        CACountCertTypes_pfn b = (CACountCertTypes_pfn)t_proc_in(MODS[m], "CACountCertTypes");
        REQUIRE(a); REQUIRE(b);
        CHECK(a(NULL) == 0);
        CHECK(b(NULL) == 0);
    }
}

TEST(cct_val_freeprop_releases_with_localfree)
{
    for (int m = 0; m < 2; m++) {
        CAFreeCertTypeProperty_pfn f1 = (CAFreeCertTypeProperty_pfn)t_proc_in(MODS[m], "CAFreeCertTypeProperty");
        CAFreeCAProperty_pfn f2 = (CAFreeCAProperty_pfn)t_proc_in(MODS[m], "CAFreeCAProperty");
        CAFreeCertTypeExtensions_pfn f3 = (CAFreeCertTypeExtensions_pfn)t_proc_in(MODS[m], "CAFreeCertTypeExtensions");
        REQUIRE(f1); REQUIRE(f2); REQUIRE(f3);
        LPWSTR *a = (LPWSTR *)LocalAlloc(LPTR, 32);
        CHECK(a && f1(FAKE, a) == 0);                /* handle is not dereferenced, memory is LocalFree'd */
        LPWSTR *b = (LPWSTR *)LocalAlloc(LPTR, 32);
        CHECK(b && f2(FAKE, b) == 0);
        CERT_EXTENSIONS *c = (CERT_EXTENSIONS *)LocalAlloc(LPTR, 32);
        CHECK(c && f3(FAKE, c) == 0);
    }
}

TEST(cct_val_freeprop_null_handle_keeps_memory)
{
    CAFreeCertTypeProperty_pfn f1 = CCA(CAFreeCertTypeProperty);
    CAFreeCAProperty_pfn f2 = CCA(CAFreeCAProperty);
    REQUIRE(f1); REQUIRE(f2);
    LPWSTR *a = (LPWSTR *)LocalAlloc(LPTR, 32);
    CHECK(a != NULL); if (!a) return;
    CHECK(f1(NULL, a) == E_PTR);
    CHECK(f2(NULL, a) == E_PTR);
    CHECK(LocalSize(a) >= 32);            /* still a valid allocation: neither call freed it */
    LocalFree(a);
}

TEST(cct_val_cacerttypequery_struct_copy)
{
    CACertTypeQuery_pfn f = CCA(CACertTypeQuery);
    REQUIRE(f);
    DWORD in[10], out[10];
    memset(in, 0, sizeof in); memset(out, 0xee, sizeof out);
    in[0] = 0x11223344; in[8] = 0x55667788;
    DWORD r = f(in, out);
    CHECK(r == 0x55667788);             /* returns the dword at offset 0x20 */
    CHECK(out[0] == 0x11223344);        /* copies the dword at offset 0 */
    CHECK(out[1] == 0xeeeeeeee);
    CHECK(f(NULL, out) == E_BADARG);
    CHECK(f(in, NULL) == E_BADARG);
    CHECK(f(NULL, NULL) == E_BADARG);
}

/* ---- OID registry wrappers ---- */
VT(oidcreatenew_null_out,   CAOIDCreateNew, E_BADARG, f(1, 0, NULL))
VT(oidcreatenewex_null_out, CAOIDCreateNewEx, E_BADARG, f(1, 0, NULL, NULL))
VT(oidcreatenewex_ldap_flag_null_ldap, CAOIDCreateNewEx, E_PTR, f(1, 0x800, NULL, (LPWSTR *)&out))
VT(oidcreatenewex_ldap_flag_null_ldap_out, CAOIDCreateNewEx, E_PTR, f(1, 0x800, NULL, NULL))
VT(oidaddex_bad_flags,      CAOIDAddEx, E_BADARG, f(1, 1, NULL, L"1.2.3.4"))
VT(oidaddex_ldap_flag_null_ldap, CAOIDAddEx, E_PTR, f(1, 0x800, NULL, L"1.2.3.4"))
VT(oiddeleteex_bad_flags,   CAOIDDeleteEx, E_BADARG, f(1, NULL, L"1.2.3.4"))
VT(oiddeleteex_ldap_flag_null_ldap, CAOIDDeleteEx, E_PTR, f(0x800, NULL, L"1.2.3.4"))
VT(oidgetpropex_bad_flags,  CAOIDGetPropertyEx, E_BADARG, f(1, NULL, L"1.2.3.4", 1, &out))
VT(oidgetpropex_ldap_flag_null_ldap, CAOIDGetPropertyEx, E_PTR, f(0x800, NULL, L"1.2.3.4", 1, &out))
VT(oidsetpropex_bad_flags,  CAOIDSetPropertyEx, E_BADARG, f(2, NULL, L"1.2.3.4", 1, &out))
VT(oidsetpropex_ldap_flag_null_ldap, CAOIDSetPropertyEx, E_PTR, f(0x800, NULL, L"1.2.3.4", 1, &out))
VT(oidgetldapurl_null_out,  CAOIDGetLdapURL, E_BADARG, f(0, 0, NULL))
VT(oidfreeproperty_null,    CAOIDFreeProperty, 0, f(NULL))
VT(oidfreeldapurl_null,     CAOIDFreeLdapURL, 0, f(NULL))

TEST(cct_val_oid_flag_bit_must_be_ldap_scope)
{
    /* any non-zero flag set without bit 0x800 is rejected identically by all *Ex wrappers */
    static const DWORD flags[] = { 1, 2, 4, 0x10, 0x400, 0x1000, 0x7ff, 0x80000000 };
    CAOIDAddEx_pfn add = CCA(CAOIDAddEx);
    CAOIDDeleteEx_pfn del = CCA(CAOIDDeleteEx);
    REQUIRE(add); REQUIRE(del);
    for (int i = 0; i < 8; i++) {
        CHECKF(add(1, flags[i], NULL, L"1.2.3.4") == E_BADARG, "add flags 0x%lx", flags[i]);
        CHECKF(del(flags[i], NULL, L"1.2.3.4") == E_BADARG, "del flags 0x%lx", flags[i]);
    }
}

TEST(cct_val_oid_free_functions_are_the_same_routine)
{
    HMODULE ca = t_module("certca.dll");
    REQUIRE(ca);
    CHECK(GetProcAddress(ca, "CAOIDFreeProperty") == GetProcAddress(ca, "CAOIDFreeLdapURL"));
    CAOIDFreeProperty_pfn fp = CCA(CAOIDFreeProperty);
    CAOIDFreeLdapURL_pfn fu = CCA(CAOIDFreeLdapURL);
    REQUIRE(fp); REQUIRE(fu);
    void *a = LocalAlloc(LPTR, 16), *b = LocalAlloc(LPTR, 16);
    CHECK(a && fp(a) == 0);
    CHECK(b && fu(b) == 0);
}

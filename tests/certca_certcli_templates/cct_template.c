/* In-memory certificate template object behaviour. A template object can only be created through
 * CACreateCertType, which also reserves a new template OID in the directory (verified in the decompilation:
 * CCertTypeInfo::Create -> I_CAOIDCreateNew). Therefore:
 *   - on a machine without a directory the create fails and these tests are skipped (the failure HRESULT is noted);
 *   - on a domain-joined machine the create is only attempted when CRYPTT_ALLOW_DS_WRITE=1 is set in the
 *     environment; the OID that was reserved is removed again (CAOIDDelete) at exit.
 * The template itself is never written to the directory (CAUpdateCertType is never called). */
#include "cct.h"
#include <sddl.h>
#include "modules.h"

#define SENT ((void *)(ULONG_PTR)0x5ca1ab1e)

static HCT g_tpl;
static int g_tried;
static HRESULT g_hr = (HRESULT)0xdeadbeef;
static WCHAR g_name[80];
static struct { HRESULT hr; HCT h; const WCHAR *name; WCHAR *oid; } cj;

static void w_create(void *a) { cj.hr = CCA(CACreateCertType)(cj.name, NULL, 0, &cj.h); }
static void w_cleanup(void *a)
{
    LPWSTR *v = NULL;
    cj.oid = NULL;
    if (CCA(CAGetCertTypeProperty)(cj.h, L"msPKI-Cert-Template-OID", &v) == 0 && v && v[0]) {
        cj.oid = (WCHAR *)LocalAlloc(LPTR, (lstrlenW(v[0]) + 1) * sizeof(WCHAR));
        if (cj.oid) lstrcpyW(cj.oid, v[0]);
    }
    if (v) CCA(CAFreeCertTypeProperty)(cj.h, v);
    CCA(CACloseCertType)(cj.h);
    if (cj.oid && CCA(CAOIDDelete)) CCA(CAOIDDelete)(cj.oid);
}

static void tpl_cleanup(void)
{
    if (!g_tpl) return;
    cj.h = g_tpl;
    cct_bounded(w_cleanup, NULL, 5000);
    g_tpl = NULL;
}

const WCHAR *cct_template_name(void) { return g_name; }

HCT cct_template(void)
{
    if (g_tried) return g_tpl;
    g_tried = 1;
    if (!t_module("certca.dll") || !CCA(CACreateCertType)) return NULL;
    if (cct_domain_joined() && !getenv("CRYPTT_ALLOW_DS_WRITE")) { g_hr = 0; return NULL; }
    wsprintfW(g_name, L"%hsTpl%lu", T_TMP_PREFIX, GetCurrentProcessId());
    cj.h = NULL; cj.name = g_name; cj.hr = (HRESULT)0xdeadbeef;
    if (!cct_bounded(w_create, NULL, 5000)) { g_hr = (HRESULT)0xdeadbee0; return NULL; }
    g_hr = cj.hr;
    if (SUCCEEDED(cj.hr) && cj.h) { g_tpl = cj.h; atexit(tpl_cleanup); }
    return g_tpl;
}

#define NEED_TPL() HCT h = cct_template(); \
    if (!h) { t_skip("no template object can be created here (create hr=0x%lx)", (long)g_hr); return; }

static const FILETIME F1 = { 0x11111111, 0x01d00000 }, F2 = { 0x22222222, 0x01d00001 };

TEST(cct_tpl_create_report)
{
    CCT_NEED_MODULES();
    HCT h = cct_template();
    t_note("CACreateCertType(\"%ls\") hr=0x%lx handle=%p domain=%d", cct_template_name(), (long)g_hr, (void *)h, cct_domain_joined());
    if (!h) { t_skip("create not possible here"); return; }
    CHECK(1);
}

TEST(cct_tpl_cn_property_is_creation_name)
{
    NEED_TPL();
    LPWSTR *v = NULL;
    HRESULT hr = CCA(CAGetCertTypeProperty)(h, L"cn", &v);
    CHECK(hr == 0); CHECK(v != NULL);
    if (v) {
        CHECK(v[0] && !lstrcmpW(v[0], cct_template_name()));
        CHECK(v[1] == NULL);
        CHECK(CCA(CAFreeCertTypeProperty)(h, v) == 0);
    }
}

TEST(cct_tpl_cn_property_ex_returns_same_value)
{
    NEED_TPL();
    LPWSTR *v = NULL;
    HRESULT hr = CCA(CAGetCertTypePropertyEx)(h, L"cn", &v);
    CHECK(hr == 0);
    if (v) { CHECK(v[0] && !lstrcmpW(v[0], cct_template_name())); CCA(CAFreeCertTypeProperty)(h, v); }
}

TEST(cct_tpl_property_null_arguments)
{
    NEED_TPL();
    LPWSTR *v = (LPWSTR *)SENT;
    CHECK(CCA(CAGetCertTypeProperty)(h, NULL, &v) == E_PTR);
    CHECK(CCA(CAGetCertTypeProperty)(h, L"cn", NULL) == E_PTR);
    CHECK(CCA(CASetCertTypeProperty)(h, NULL, NULL) == E_PTR);
}

TEST(cct_tpl_display_name_roundtrip_observed)
{
    NEED_TPL();
    WCHAR txt[] = L"cryptt display name";
    LPWSTR vals[2] = { txt, NULL };
    HRESULT hr = CCA(CASetCertTypeProperty)(h, L"displayName", vals);
    CHECK(hr == 0);
    LPWSTR *v = NULL;
    hr = CCA(CAGetCertTypeProperty)(h, L"displayName", &v);
    t_note("displayName after set: hr=0x%lx value=%ls", (long)hr, (v && v[0]) ? v[0] : L"-");
    if (v) CCA(CAFreeCertTypeProperty)(h, v);
}

TEST(cct_tpl_set_property_multi_value_roundtrip)
{
    NEED_TPL();
    WCHAR a[] = L"1.3.6.1.5.5.7.3.2", b[] = L"1.3.6.1.5.5.7.3.4";
    LPWSTR vals[3] = { a, b, NULL };
    HRESULT hr = CCA(CASetCertTypeProperty)(h, L"pKIExtendedKeyUsage", vals);
    t_note("set pKIExtendedKeyUsage: 0x%lx", (long)hr);
    if (hr != 0) return;
    LPWSTR *v = NULL;
    hr = CCA(CAGetCertTypeProperty)(h, L"pKIExtendedKeyUsage", &v);
    CHECK(hr == 0);
    if (v) {
        int n = 0; while (v[n]) n++;
        CHECKF(n == 2, "count %d", n);
        if (n == 2) { CHECK(!lstrcmpW(v[0], a)); CHECK(!lstrcmpW(v[1], b)); }
        CCA(CAFreeCertTypeProperty)(h, v);
    }
}

TEST(cct_tpl_unknown_property_get_observed)
{
    NEED_TPL();
    LPWSTR *v = (LPWSTR *)SENT;
    HRESULT hr = CCA(CAGetCertTypeProperty)(h, L"cryptt-no-such-property", &v);
    t_note("get unknown property: hr=0x%lx out=%p", (long)hr, (void *)v);
    if (hr == 0 && v && v != SENT) CCA(CAFreeCertTypeProperty)(h, v);
}

TEST(cct_tpl_general_flags_roundtrip)
{
    NEED_TPL();
    DWORD f = 0;
    CHECK(CCA(CAGetCertTypeFlags)(h, &f) == 0);
    DWORD save = f;
    CHECK(CCA(CASetCertTypeFlags)(h, 0x0040) == 0);
    CHECK(CCA(CAGetCertTypeFlags)(h, &f) == 0);
    CHECKF((f & 0xffff) == 0x0040, "flags 0x%lx", f);
    CHECK(CCA(CASetCertTypeFlags)(h, 0x0840) == 0);
    CHECK(CCA(CAGetCertTypeFlags)(h, &f) == 0);
    CHECKF((f & 0xffff) == 0x0840, "flags 0x%lx", f);
    CCA(CASetCertTypeFlags)(h, save & 0xffff);
}

TEST(cct_tpl_flags_ex_selectors_roundtrip)
{
    NEED_TPL();
    DWORD sv[4] = { 0 }, f = 0;
    for (DWORD sel = 1; sel <= 3; sel++) CHECK(CCA(CAGetCertTypeFlagsEx)(h, sel, &sv[sel]) == 0);
    CHECK(CCA(CASetCertTypeFlagsEx)(h, 1, 0x00000040) == 0);
    CHECK(CCA(CASetCertTypeFlagsEx)(h, 2, 0x00000001) == 0);
    CHECK(CCA(CASetCertTypeFlagsEx)(h, 3, 0x00000010) == 0);
    CHECK(CCA(CAGetCertTypeFlagsEx)(h, 1, &f) == 0); CHECKF(f == 0x40, "enroll 0x%lx", f);
    CHECK(CCA(CAGetCertTypeFlagsEx)(h, 2, &f) == 0); CHECKF(f == 0x01, "subject 0x%lx", f);
    CHECK(CCA(CAGetCertTypeFlagsEx)(h, 3, &f) == 0); CHECKF(f == 0x10, "key 0x%lx", f);
    for (DWORD sel = 1; sel <= 3; sel++) CCA(CASetCertTypeFlagsEx)(h, sel, sv[sel]);
}

TEST(cct_tpl_flags_ex_selectors_independent)
{
    NEED_TPL();
    DWORD a, b, c;
    CCA(CASetCertTypeFlagsEx)(h, 1, 0x1);
    CCA(CASetCertTypeFlagsEx)(h, 2, 0x2);
    CCA(CASetCertTypeFlagsEx)(h, 3, 0x4);
    CCA(CASetCertTypeFlagsEx)(h, 1, 0x8);
    CCA(CAGetCertTypeFlagsEx)(h, 1, &a); CCA(CAGetCertTypeFlagsEx)(h, 2, &b); CCA(CAGetCertTypeFlagsEx)(h, 3, &c);
    CHECK(a == 0x8); CHECK(b == 0x2); CHECK(c == 0x4);
}

TEST(cct_tpl_flags_ex_invalid_selector)
{
    NEED_TPL();
    DWORD f = 0x77;
    CHECK(CCA(CASetCertTypeFlagsEx)(h, 0, 1) == E_BADARG);
    CHECK(CCA(CASetCertTypeFlagsEx)(h, 5, 1) == E_BADARG);
    CHECK(CCA(CASetCertTypeFlagsEx)(h, 99, 1) == E_BADARG);
    HRESULT hr = CCA(CAGetCertTypeFlagsEx)(h, 0, &f);
    CHECK(hr == 0); CHECK(f == 0);          /* unknown selector reads as zero */
}

TEST(cct_tpl_flags_enrollee_supplies_subject)
{
    NEED_TPL();
    DWORD save = 0, f = 0;
    CCA(CAGetCertTypeFlagsEx)(h, 2, &save);
    const DWORD CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
    CHECK(CCA(CASetCertTypeFlagsEx)(h, 2, save | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) == 0);
    CHECK(CCA(CAGetCertTypeFlagsEx)(h, 2, &f) == 0);
    CHECK((f & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0);
    CHECK(CCA(CASetCertTypeFlagsEx)(h, 2, save & ~CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) == 0);
    CHECK(CCA(CAGetCertTypeFlagsEx)(h, 2, &f) == 0);
    CHECK((f & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) == 0);
    CCA(CASetCertTypeFlagsEx)(h, 2, save);
}

TEST(cct_tpl_keyspec_roundtrip)
{
    NEED_TPL();
    DWORD save = 0, k = 0;
    CHECK(CCA(CAGetCertTypeKeySpec)(h, &save) == 0);
    for (DWORD v = 0; v <= 2; v++) {
        CHECK(CCA(CASetCertTypeKeySpec)(h, v) == 0);
        CHECK(CCA(CAGetCertTypeKeySpec)(h, &k) == 0);
        CHECKF(k == v, "keyspec %lu got %lu", v, k);
    }
    CCA(CASetCertTypeKeySpec)(h, save);
}

TEST(cct_tpl_expiration_roundtrip)
{
    NEED_TPL();
    FILETIME s1, s2, g1, g2;
    CHECK(CCA(CAGetCertTypeExpiration)(h, &s1, &s2) == 0);
    CHECK(CCA(CASetCertTypeExpiration)(h, (FILETIME *)&F1, (FILETIME *)&F2) == 0);
    CHECK(CCA(CAGetCertTypeExpiration)(h, &g1, &g2) == 0);
    CHECK(g1.dwLowDateTime == F1.dwLowDateTime && g1.dwHighDateTime == F1.dwHighDateTime);
    CHECK(g2.dwLowDateTime == F2.dwLowDateTime && g2.dwHighDateTime == F2.dwHighDateTime);
    CCA(CASetCertTypeExpiration)(h, &s1, &s2);
}

TEST(cct_tpl_expiration_partial_update)
{
    NEED_TPL();
    FILETIME s1, s2, g1, g2;
    CCA(CAGetCertTypeExpiration)(h, &s1, &s2);
    CCA(CASetCertTypeExpiration)(h, (FILETIME *)&F1, (FILETIME *)&F2);
    CHECK(CCA(CASetCertTypeExpiration)(h, NULL, (FILETIME *)&F1) == 0);     /* only the overlap period changes */
    CCA(CAGetCertTypeExpiration)(h, &g1, &g2);
    CHECK(g1.dwLowDateTime == F1.dwLowDateTime && g1.dwHighDateTime == F1.dwHighDateTime);
    CHECK(g2.dwLowDateTime == F1.dwLowDateTime && g2.dwHighDateTime == F1.dwHighDateTime);
    CHECK(CCA(CASetCertTypeExpiration)(h, (FILETIME *)&F2, NULL) == 0);     /* only the validity period changes */
    CCA(CAGetCertTypeExpiration)(h, &g1, &g2);
    CHECK(g1.dwLowDateTime == F2.dwLowDateTime && g2.dwLowDateTime == F1.dwLowDateTime);
    CHECK(CCA(CASetCertTypeExpiration)(h, NULL, NULL) == 0);
    CCA(CASetCertTypeExpiration)(h, &s1, &s2);
}

TEST(cct_tpl_expiration_get_accepts_null_outputs)
{
    NEED_TPL();
    FILETIME a;
    CHECK(CCA(CAGetCertTypeExpiration)(h, &a, NULL) == 0);
    CHECK(CCA(CAGetCertTypeExpiration)(h, NULL, &a) == 0);
    CHECK(CCA(CAGetCertTypeExpiration)(h, NULL, NULL) == 0);
}

TEST(cct_tpl_security_roundtrip)
{
    NEED_TPL();
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!U(ConvertStringSecurityDescriptorToSecurityDescriptorW) ||
        !U(ConvertStringSecurityDescriptorToSecurityDescriptorW)(L"O:BAG:BAD:(A;;GA;;;BA)", SDDL_REVISION_1, &sd, NULL)) {
        t_skip("cannot build a security descriptor"); return;
    }
    PSECURITY_DESCRIPTOR orig = NULL;
    HRESULT hr0 = CCA(CACertTypeGetSecurity)(h, &orig);
    CHECK(CCA(CACertTypeSetSecurity)(h, sd) == 0);
    PSECURITY_DESCRIPTOR back = NULL;
    HRESULT hr = CCA(CACertTypeGetSecurity)(h, &back);
    CHECK(hr == 0); CHECK(back != NULL);
    if (back) {
        DWORD a = GetSecurityDescriptorLength(sd), b = GetSecurityDescriptorLength(back);
        CHECK(a == b);
        CHECK(a == b && !memcmp(sd, back, a));
        CHECK(back != sd);                  /* a private copy is returned */
        LocalFree(back);
    }
    if (hr0 == 0 && orig) { CCA(CACertTypeSetSecurity)(h, orig); LocalFree(orig); }
    LocalFree(sd);
}

TEST(cct_tpl_security_set_copies_input)
{
    NEED_TPL();
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!U(ConvertStringSecurityDescriptorToSecurityDescriptorW)(L"O:BAG:BAD:(A;;GA;;;WD)", SDDL_REVISION_1, &sd, NULL)) { t_skip("no SD"); return; }
    DWORD n = GetSecurityDescriptorLength(sd);
    BYTE *copy = (BYTE *)LocalAlloc(LPTR, n);
    memcpy(copy, sd, n);
    CHECK(CCA(CACertTypeSetSecurity)(h, copy) == 0);
    memset(copy, 0, n); LocalFree(copy);       /* the template keeps its own copy */
    PSECURITY_DESCRIPTOR back = NULL;
    CHECK(CCA(CACertTypeGetSecurity)(h, &back) == 0);
    CHECK(back && IsValidSecurityDescriptor(back));
    if (back) { CHECK(GetSecurityDescriptorLength(back) == n && !memcmp(back, sd, n)); LocalFree(back); }
    LocalFree(sd);
}

TEST(cct_tpl_security_invalid_descriptor)
{
    NEED_TPL();
    BYTE junk[64]; memset(junk, 0xff, sizeof junk);
    HRESULT hr = CCA(CACertTypeSetSecurity)(h, junk);
    CHECKF(hr == HR_BAD_SD, "hr=0x%lx", (long)hr);
    SECURITY_DESCRIPTOR zero; memset(&zero, 0, sizeof zero);
    hr = CCA(CACertTypeSetSecurity)(h, &zero);
    t_note("zeroed SD set -> 0x%lx", (long)hr);
}

TEST(cct_tpl_security_null_arguments)
{
    NEED_TPL();
    CHECK(CCA(CACertTypeSetSecurity)(h, NULL) == E_PTR);
    CHECK(CCA(CACertTypeGetSecurity)(h, NULL) == E_PTR);
}

TEST(cct_tpl_extensions_get_and_free)
{
    NEED_TPL();
    CERT_EXTENSIONS *e = NULL;
    HRESULT hr = CCA(CAGetCertTypeExtensions)(h, &e);
    t_note("CAGetCertTypeExtensions -> 0x%lx count=%lu", (long)hr, e ? e->cExtension : 0);
    CHECK(hr == 0);
    if (hr == 0 && e) {
        for (DWORD i = 0; i < e->cExtension; i++) CHECK(e->rgExtension[i].pszObjId != NULL);
        CHECK(CCA(CAFreeCertTypeExtensions)(h, e) == 0);
    }
}

TEST(cct_tpl_extensions_reflect_key_usage_oid_set)
{
    NEED_TPL();
    CERT_EXTENSIONS *e = NULL;
    if (CCA(CAGetCertTypeExtensions)(h, &e) != 0 || !e) { t_skip("no extensions"); return; }
    int ku = 0, tpl = 0;
    for (DWORD i = 0; i < e->cExtension; i++) {
        if (!strcmp(e->rgExtension[i].pszObjId, "2.5.29.15")) ku++;
        if (!strcmp(e->rgExtension[i].pszObjId, "1.3.6.1.4.1.311.21.7") || !strcmp(e->rgExtension[i].pszObjId, "1.3.6.1.4.1.311.20.2")) tpl++;
    }
    t_note("extensions: keyUsage=%d templateInfo=%d of %lu", ku, tpl, e->cExtension);
    CHECK(ku <= 1); CHECK(tpl <= 2);
    CCA(CAFreeCertTypeExtensions)(h, e);
}

TEST(cct_tpl_count_and_next_for_single_object)
{
    NEED_TPL();
    CHECK(CCA(CACountCertTypes)(h) == 1);
    HCT next = (HCT)SENT;
    CHECK(CCA(CAEnumNextCertType)(h, &next) == 0);
    CHECK(next == NULL);
}

TEST(cct_tpl_close_null_after_use_is_not_needed)
{
    CCT_NEED_MODULES();
    /* the shared template is closed at exit; closing NULL must still report E_POINTER */
    CHECK(CCA(CACloseCertType)(NULL) == E_PTR);
}

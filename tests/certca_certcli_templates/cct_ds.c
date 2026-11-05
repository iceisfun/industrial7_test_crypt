/* Directory-dependent lookups on a machine that is not domain joined. These calls end in a directory-service
 * query; on a workgroup / standalone machine they fail locally. They are run on a bounded worker thread, never on
 * a domain-joined machine, and the exact HRESULT is recorded with t_note because it depends on the environment
 * (no network, no DS, cached templates). Only invariants that hold in every environment are hard checks:
 * success implies a usable handle; failure leaves the output parameter alone.
 *
 * Side effect to be aware of: a template enumeration consults (and may create) the per-user template cache key
 * under HKCU\Software\Microsoft\Cryptography. Nothing is written to a directory or to HKLM. */
#include "cct.h"

#define SENT ((void *)(ULONG_PTR)0x5ca1ab1e)
#define BOUND_MS 5000

static struct {
    HRESULT hr; void *out; DWORD flags; const WCHAR *name; int which;
} g;

static void w_enum(void *a)      { g.hr = CCA(CAEnumCertTypes)(g.flags, (HCT *)&g.out); }
static void w_enumex(void *a)    { g.hr = CCA(CAEnumCertTypesEx)(NULL, g.flags, (HCT *)&g.out); }
static void w_firstca(void *a)   { g.hr = CCA(CAEnumFirstCA)(NULL, g.flags, (HCA *)&g.out); }
static void w_byname(void *a)    { g.hr = CCA(CAFindByName)(g.name, NULL, g.flags, (HCA *)&g.out); }
static void w_bytype(void *a)    { g.hr = CCA(CAFindByCertType)(g.name, NULL, g.flags, (HCA *)&g.out); }
static void w_typebyname(void *a){ g.hr = CCA(CAFindCertTypeByName)(g.name, NULL, g.flags, (HCT *)&g.out); }
static void w_bydn(void *a)
{
    static BYTE dn[] = { 0x30, 0x1b, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x10,
                         'c','r','y','p','t','t','-','n','o','-','s','u','c','h','-','c','a' };
    CRYPT_DATA_BLOB b = { sizeof dn, dn };
    g.hr = CCA(CAFindByIssuerDN)(&b, NULL, g.flags, (HCA *)&g.out);
}

static int run(void (*fn)(void *), DWORD flags, const WCHAR *name)
{
    g.hr = (HRESULT)0xdeadbeef; g.out = SENT; g.flags = flags; g.name = name;
    if (!cct_bounded(fn, NULL, BOUND_MS)) { t_note("directory call did not finish within %d ms", BOUND_MS); return 0; }
    return 1;
}

static void settle_ct(const char *what)
{
    if (SUCCEEDED(g.hr)) {
        t_note("%s succeeded (hr=0x%lx, handle=%p)", what, (long)g.hr, g.out);
        if (g.out != SENT && g.out) CCA(CACloseCertType)((HCT)g.out);
    } else {
        t_note("%s failed as expected without a directory: 0x%lx", what, (long)g.hr);
        CHECKF(g.out == SENT, "%s: output parameter modified on failure", what);
    }
}

TEST(cct_ds_enum_certtypes_default_flags)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAEnumCertTypes)); REQUIRE(CCA(CACloseCertType));
    if (!run(w_enum, 0, NULL)) return;
    settle_ct("CAEnumCertTypes(0)");
    CHECK(g.hr != (HRESULT)0xdeadbeef);
}

TEST(cct_ds_enum_certtypes_machine_and_user_flags)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAEnumCertTypes)); REQUIRE(CCA(CACloseCertType));
    static const DWORD fl[] = { 0x40, 0x80, 0xc0, 0x400 };
    for (int i = 0; i < 4; i++) {
        if (!run(w_enum, fl[i], NULL)) return;
        char what[48]; wsprintfA(what, "CAEnumCertTypes(0x%lx)", fl[i]);
        settle_ct(what);
    }
}

TEST(cct_ds_enum_certtypes_ex_null_scope)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAEnumCertTypesEx)); REQUIRE(CCA(CACloseCertType));
    if (!run(w_enumex, 0, NULL)) return;
    settle_ct("CAEnumCertTypesEx(NULL,0)");
}

TEST(cct_ds_enum_certtypes_ex_ldap_flag_ignored_scope)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAEnumCertTypesEx));
    /* bit 0x800 with a NULL scope is passed through as "no handle": same result class as the plain call */
    if (!run(w_enumex, 0x800, NULL)) return;
    settle_ct("CAEnumCertTypesEx(NULL,0x800)");
}

TEST(cct_ds_enum_first_ca)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAEnumFirstCA)); REQUIRE(CCA(CACloseCA)); REQUIRE(CCA(CACountCAs));
    if (!run(w_firstca, 0, NULL)) return;
    if (SUCCEEDED(g.hr)) {
        t_note("CAEnumFirstCA succeeded, handle=%p", g.out);
        if (g.out != SENT && g.out) {
            DWORD n = CCA(CACountCAs)((HCA)g.out);
            t_note("CACountCAs = %lu", n);
            CHECK(n >= 1);
            CCA(CACloseCA)((HCA)g.out);
        }
    } else {
        t_note("CAEnumFirstCA failed: 0x%lx", (long)g.hr);
        CHECK(g.out == SENT);
    }
}

TEST(cct_ds_find_ca_by_name_unknown)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAFindByName)); REQUIRE(CCA(CACloseCA));
    if (!run(w_byname, 0, L"cryptt-no-such-ca")) return;
    if (g.hr == 0) {
        CHECK(g.out != NULL);                 /* success never hands back a NULL handle */
        t_note("unexpected CA found: %p", g.out);
        if (g.out && g.out != SENT) CCA(CACloseCA)((HCA)g.out);
    } else t_note("CAFindByName(unknown) -> 0x%lx", (long)g.hr);
}

TEST(cct_ds_find_ca_by_certtype_unknown)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAFindByCertType)); REQUIRE(CCA(CACloseCA));
    if (!run(w_bytype, 0, L"cryptt-no-such-template")) return;
    if (g.hr == 0) {
        CHECK(g.out != NULL);
        if (g.out && g.out != SENT) CCA(CACloseCA)((HCA)g.out);
    } else t_note("CAFindByCertType(unknown) -> 0x%lx", (long)g.hr);
}

TEST(cct_ds_find_ca_by_issuer_dn_unknown)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAFindByIssuerDN)); REQUIRE(CCA(CACloseCA));
    if (!run(w_bydn, 0, NULL)) return;
    if (g.hr == 0 && g.out && g.out != SENT) { t_note("issuer DN matched a CA"); CCA(CACloseCA)((HCA)g.out); }
    else t_note("CAFindByIssuerDN(unknown) -> 0x%lx", (long)g.hr);
}

TEST(cct_ds_find_certtype_by_name_unknown)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAFindCertTypeByName)); REQUIRE(CCA(CACloseCertType));
    if (!run(w_typebyname, 0, L"cryptt-no-such-template")) return;
    if (SUCCEEDED(g.hr)) {
        /* success may legitimately return a NULL list when the name matches nothing */
        t_note("CAFindCertTypeByName succeeded, handle=%p", g.out);
        if (g.out && g.out != SENT) CCA(CACloseCertType)((HCT)g.out);
    } else {
        t_note("CAFindCertTypeByName(unknown) -> 0x%lx", (long)g.hr);
        CHECK(g.out == SENT);
    }
}

TEST(cct_ds_certtype_enum_count_matches_chain)
{
    CCT_NEED_MODULES(); CCT_NEED_NO_DOMAIN();
    REQUIRE(CCA(CAEnumCertTypes)); REQUIRE(CCA(CACountCertTypes)); REQUIRE(CCA(CAEnumNextCertType)); REQUIRE(CCA(CACloseCertType));
    if (!run(w_enum, 0, NULL)) return;
    if (FAILED(g.hr) || !g.out || g.out == SENT) { t_skip("no templates enumerable here (0x%lx)", (long)g.hr); return; }
    HCT first = (HCT)g.out;
    DWORD cnt = CCA(CACountCertTypes)(first);
    DWORD walked = 0;
    HCT cur = first;
    CCA(CAEnumNextCertType); /* resolve once */
    while (cur && walked < 1000) {
        HCT next = NULL;
        HRESULT hr = CCA(CAEnumNextCertType)(cur, &next);
        CHECK(hr == 0);
        walked++;
        if (cur != first) CCA(CACloseCertType)(cur);   /* each next handle is an extra reference */
        cur = next;
    }
    CHECKF(cnt == walked, "count %lu, walked %lu", cnt, walked);
    CCA(CACloseCertType)(first);
}

/* On a domain-joined machine none of the calls above are made. Document that. */
TEST(cct_ds_environment_report)
{
    CCT_NEED_MODULES();
    int st = cct_join_status();
    t_note("NetGetJoinInformation status = %d (1 unjoined, 2 workgroup, 3 domain)", st);
    CHECK(st >= 0 && st <= 3);
}

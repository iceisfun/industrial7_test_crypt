/* Provider registration (BCryptRegisterProvider / BCryptUnregisterProvider) and registration queries.
 * The test providers point at an existing system DLL that is never loaded: nothing resolves the name
 * to an algorithm, and every registration is removed again. Needs elevation. */
#include "cfg.h"
#include <wchar.h>

typedef struct {
    PWSTR fns[4];
    CRYPT_INTERFACE_REG ir[2];
    PCRYPT_INTERFACE_REG irs[2];
    CRYPT_IMAGE_REG img;
    PWSTR aliases[3];
    CRYPT_PROVIDER_REG reg;
    WCHAR path[MAX_PATH];
} PR;

static void pr_init(PR *p, int with_second_iface, int naliases) {
    memset(p, 0, sizeof *p);
    cfg_sysdll(p->path, MAX_PATH, L"bcryptprimitives.dll");
    p->fns[0] = L"AES"; p->fns[1] = L"cryptt_fnx"; p->fns[2] = L"SHA256";
    p->ir[0].dwInterface = BCRYPT_CIPHER_INTERFACE; p->ir[0].cFunctions = 2; p->ir[0].rgpszFunctions = &p->fns[0];
    p->irs[0] = &p->ir[0];
    p->img.pszImage = p->path; p->img.cInterfaces = 1; p->img.rgpInterfaces = p->irs;
    if (with_second_iface) {
        p->ir[1].dwInterface = BCRYPT_HASH_INTERFACE; p->ir[1].cFunctions = 1; p->ir[1].rgpszFunctions = &p->fns[2];
        p->irs[1] = &p->ir[1]; p->img.cInterfaces = 2;
    }
    p->aliases[0] = L"cryptt_alias_one"; p->aliases[1] = L"cryptt_alias_two"; p->aliases[2] = L"cryptt_alias_three";
    p->reg.cAliases = naliases; p->reg.rgpszAliases = naliases ? p->aliases : NULL;
    p->reg.pUM = &p->img;
}
static NTSTATUS reg(const WCHAR *n, ULONG fl, PR *p) { return UN(BCryptRegisterProvider)(n, fl, &p->reg); }
static NTSTATUS unreg(const WCHAR *n) { return UN(BCryptUnregisterProvider)(n); }
#define NEEDP() do { if (!cfg_begin()) return; if (!UN(BCryptRegisterProvider) || !UN(BCryptUnregisterProvider)) { t_skip("missing export"); return; } } while (0)

TEST(dxctx_prov_register_unregister_roundtrip) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "prov", 1);
    CHECK(!cfg_has_provider(n));
    ST_OK(reg(n, 0, &p));
    CHECK(cfg_has_provider(n));
    ST_OK(unreg(n));
    CHECK(!cfg_has_provider(n));
    cfg_cleanup_all();
}
TEST(dxctx_prov_register_duplicate_collides) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provdup", 1);
    ST_OK(reg(n, 0, &p));
    ULONG st = (ULONG)reg(n, 0, &p);
    CHECKF(!NT_OK(st), "second registration returned 0x%lx", st);
    CHECKF(st == S_NAME_COLLISION, "0x%lx", st);
    ST_OK(unreg(n));
    cfg_cleanup_all();
}
TEST(dxctx_prov_register_overwrite) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provow", 1);
    ST_OK(reg(n, 0, &p));
    PR q; pr_init(&q, 1, 2);
    ST_OK(reg(n, CRYPT_OVERWRITE, &q));
    /* the new registration replaced the old one: two aliases and a hash interface are now visible */
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    ULONG st = (ULONG)U(BCryptQueryProviderRegistration)(n, CRYPT_UM, BCRYPT_HASH_INTERFACE, &cb, &r);
    ST_OK(st);
    if (NT_OK(st) && r) {
        EXPECT_EQ(r->cAliases, 2);
        U(BCryptFreeBuffer)(r);
    }
    ST_OK(unreg(n));
    cfg_cleanup_all();
}
TEST(dxctx_prov_overwrite_flag_on_new_name) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provowN", 1);
    ULONG st = (ULONG)reg(n, CRYPT_OVERWRITE, &p);
    t_note("CRYPT_OVERWRITE on a name that does not exist -> 0x%lx", st);
    if (NT_OK(st)) { CHECK(cfg_has_provider(n)); ST_OK(unreg(n)); }
    cfg_cleanup_all();
}
TEST(dxctx_prov_unregister_nonexistent) {
    NEEDP();
    WCHAR n[96]; cfg_name(n, 96, "provnx", 1);
    ULONG st = (ULONG)unreg(n);
    CHECKF(!NT_OK(st), "unregister of an unknown provider returned 0x%lx", st);
    t_note("unregister nonexistent provider -> 0x%lx", st);
    CHECKF(st == S_NOT_FOUND || st == S_OBJECT_NAME_NOT_FOUND || st == 0xC0000001, "0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_prov_unregister_twice) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "prov2x", 1);
    ST_OK(reg(n, 0, &p));
    ST_OK(unreg(n));
    CHECK(!NT_OK(unreg(n)));
    cfg_cleanup_all();
}
TEST(dxctx_prov_enum_registered_contains_system_providers) {
    NEEDP();
    static WCHAR l[512][96]; NTSTATUS st;
    int n = cfg_enum_registered(l, 512, &st);
    ST_OK(st);
    CHECK(n > 0);
    int hasprim = 0;
    for (int i = 0; i < n; i++) if (!lstrcmpiW(l[i], L"Microsoft Primitive Provider")) hasprim = 1;
    CHECK(hasprim);
}
TEST(dxctx_prov_enum_registered_counts) {
    NEEDP();
    static WCHAR a[512][96], b[512][96]; NTSTATUS st;
    int n0 = cfg_enum_registered(a, 512, &st);
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provenum", 1);
    ST_OK(reg(n, 0, &p));
    int n1 = cfg_enum_registered(b, 512, &st);
    CHECK(n1 == n0 + 1);
    ST_OK(unreg(n));
    CHECK(cfg_enum_registered(b, 512, &st) == n0);
    cfg_cleanup_all();
}
TEST(dxctx_prov_query_registration_um) {
    NEEDP();
    PR p; pr_init(&p, 1, 2); WCHAR n[96]; cfg_name(n, 96, "provq", 1);
    ST_OK(reg(n, 0, &p));
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    ULONG st = (ULONG)U(BCryptQueryProviderRegistration)(n, CRYPT_UM, 0, &cb, &r);
    ST_OK(st);
    if (NT_OK(st) && r) {
        CHECK(cb >= sizeof *r);
        EXPECT_EQ(r->cAliases, 2);
        if (r->cAliases == 2) {
            CHECK(!lstrcmpiW(r->rgpszAliases[0], L"cryptt_alias_one") || !lstrcmpiW(r->rgpszAliases[1], L"cryptt_alias_one"));
            CHECK(!lstrcmpiW(r->rgpszAliases[0], L"cryptt_alias_two") || !lstrcmpiW(r->rgpszAliases[1], L"cryptt_alias_two"));
        }
        CHECK(r->pUM != NULL);
        if (r->pUM) {
            CHECK(!lstrcmpiW(r->pUM->pszImage, p.path));
            EXPECT_EQ(r->pUM->cInterfaces, 2);
        }
        CHECK(r->pKM == NULL);
        U(BCryptFreeBuffer)(r);
    }
    ST_OK(unreg(n));
    cfg_cleanup_all();
}
TEST(dxctx_prov_query_registration_interface_filter) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provqi", 1);
    ST_OK(reg(n, 0, &p));
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    ULONG st = (ULONG)U(BCryptQueryProviderRegistration)(n, CRYPT_UM, BCRYPT_CIPHER_INTERFACE, &cb, &r);
    ST_OK(st);
    if (NT_OK(st) && r) {
        CHECK(r->pUM && r->pUM->cInterfaces == 1);
        if (r->pUM && r->pUM->cInterfaces == 1) {
            EXPECT_EQ(r->pUM->rgpInterfaces[0]->dwInterface, BCRYPT_CIPHER_INTERFACE);
            EXPECT_EQ(r->pUM->rgpInterfaces[0]->cFunctions, 2);
        }
        U(BCryptFreeBuffer)(r);
    }
    r = NULL; cb = 0;
    st = (ULONG)U(BCryptQueryProviderRegistration)(n, CRYPT_UM, BCRYPT_HASH_INTERFACE, &cb, &r);
    t_note("query of an interface the provider does not implement -> 0x%lx", st);
    if (NT_OK(st) && r) { CHECK(!r->pUM || r->pUM->cInterfaces == 0); U(BCryptFreeBuffer)(r); }
    ST_OK(unreg(n));
    cfg_cleanup_all();
}
TEST(dxctx_prov_query_registration_nonexistent) {
    NEEDP();
    WCHAR n[96]; cfg_name(n, 96, "provqnx", 1);
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    ULONG st = (ULONG)U(BCryptQueryProviderRegistration)(n, CRYPT_UM, 0, &cb, &r);
    CHECKF(!NT_OK(st), "query of an unregistered provider returned 0x%lx", st);
    CHECK(r == NULL);
    t_note("query unregistered provider -> 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_prov_query_registration_after_unregister) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provqu", 1);
    ST_OK(reg(n, 0, &p));
    ST_OK(unreg(n));
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    ULONG st = (ULONG)U(BCryptQueryProviderRegistration)(n, CRYPT_UM, 0, &cb, &r);
    CHECKF(!NT_OK(st), "registration still queryable (0x%lx)", st);
    if (r) U(BCryptFreeBuffer)(r);
    cfg_cleanup_all();
}
TEST(dxctx_prov_query_system_provider) {
    NEEDP();
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    ULONG st = (ULONG)U(BCryptQueryProviderRegistration)(L"Microsoft Primitive Provider", CRYPT_UM, 0, &cb, &r);
    ST_OK(st);
    if (NT_OK(st) && r) {
        CHECK(r->pUM != NULL);
        if (r->pUM && r->pUM->pszImage) t_note("Primitive provider UM image: %ls", r->pUM->pszImage);
        U(BCryptFreeBuffer)(r);
    }
}
TEST(dxctx_prov_register_km_only) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provkm", 1);
    p.reg.pKM = p.reg.pUM; p.reg.pUM = NULL;
    ULONG st = (ULONG)reg(n, 0, &p);
    t_note("kernel-mode-only registration -> 0x%lx", st);
    if (NT_OK(st)) { CHECK(cfg_has_provider(n)); ST_OK(unreg(n)); }
    cfg_cleanup_all();
}
TEST(dxctx_prov_register_um_and_km) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provboth", 1);
    p.reg.pKM = p.reg.pUM;
    ULONG st = (ULONG)reg(n, 0, &p);
    t_note("UM+KM registration -> 0x%lx", st);
    if (NT_OK(st)) { CHECK(cfg_has_provider(n)); ST_OK(unreg(n)); }
    cfg_cleanup_all();
}
TEST(dxctx_prov_register_many_aliases) {
    NEEDP();
    PR p; pr_init(&p, 0, 3); WCHAR n[96]; cfg_name(n, 96, "provals", 1);
    ST_OK(reg(n, 0, &p));
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    if (NT_OK(U(BCryptQueryProviderRegistration)(n, CRYPT_UM, 0, &cb, &r)) && r) { EXPECT_EQ(r->cAliases, 3); U(BCryptFreeBuffer)(r); }
    ST_OK(unreg(n));
    cfg_cleanup_all();
}
TEST(dxctx_prov_register_flags_rejected_before_driver) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96]; cfg_name(n, 96, "provfl", 1);
    ST_EQ(reg(n, 2, &p), S_INVALID_PARAMETER);
    ST_EQ(reg(n, 0x10000, &p), S_INVALID_PARAMETER);
    CHECK(!cfg_has_provider(n));
    cfg_cleanup_all();
}
TEST(dxctx_prov_name_case_insensitive) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96], u[96]; cfg_name(n, 96, "provcase", 1);
    ST_OK(reg(n, 0, &p));
    wcscpy(u, n); CharUpperW(u);
    ULONG st = (ULONG)reg(u, 0, &p);
    t_note("registration of case variant name -> 0x%lx", st);
    CHECK(st == S_NAME_COLLISION);
    if (NT_OK(st)) unreg(u);
    ST_OK(unreg(n));
    cfg_cleanup_all();
}
TEST(dxctx_prov_resolve_providers_unregistered) {
    NEEDP();
    if (!U(BCryptResolveProviders)) { t_skip("missing export"); return; }
    WCHAR n[96]; cfg_name(n, 96, "provres", 1);
    ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
    ULONG st = (ULONG)U(BCryptResolveProviders)(NULL, BCRYPT_HASH_INTERFACE, NULL, n, CRYPT_UM, 0, &cb, &r);
    CHECKF(!NT_OK(st), "resolving an unregistered provider returned 0x%lx", st);
    t_note("resolve unregistered provider -> 0x%lx", st);
    if (r) U(BCryptFreeBuffer)(r);
    cfg_cleanup_all();
}
TEST(dxctx_prov_registered_provider_in_context) {
    NEEDP();
    PR p; pr_init(&p, 0, 0); WCHAR n[96], c[96]; cfg_name(n, 96, "provctx", 1);
    cfg_name(c, 96, "ctxprov", 0);
    ST_OK(reg(n, 0, &p));
    CRYPT_CONTEXT_CONFIG cc = {0, 0};
    ST_OK(U(BCryptCreateContext)(CRYPT_LOCAL, c, &cc));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, c, BCRYPT_CIPHER_INTERFACE, L"cryptt_fnx", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)UN(BCryptAddContextFunctionProvider)(CRYPT_LOCAL, c, BCRYPT_CIPHER_INTERFACE, L"cryptt_fnx", n, CRYPT_PRIORITY_BOTTOM);
    ST_OK(st);
    if (NT_OK(st)) {
        static WCHAR l[8][96]; NTSTATUS s;
        int k = cfg_enum_fprov(CRYPT_LOCAL, c, BCRYPT_CIPHER_INTERFACE, L"cryptt_fnx", l, 8, &s);
        CHECK(k == 1);
        if (k == 1) CHECK(!lstrcmpiW(l[0], n));
        /* unregistering a provider that a context still references */
        ULONG u = (ULONG)unreg(n);
        t_note("unregister provider still referenced by a context function -> 0x%lx", u);
    }
    U(BCryptDeleteContext)(CRYPT_LOCAL, c);
    unreg(n);
    cfg_cleanup_all();
}

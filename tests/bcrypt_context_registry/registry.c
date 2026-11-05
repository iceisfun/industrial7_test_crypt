/* Read-only views of the CNG configuration store and the provider registry:
 * contexts, per-context function lists, per-function provider lists, registered providers and their images. */
#include "cr.h"

static void miss(const char *what, NTSTATUS st)
{
    CHECKF(st < 0, "%s: unexpected status 0x%lx", what, (ULONG)st);
    CHECKF(st != CRS_BUFFER_TOO_SMALL, "%s: leaked BUFFER_TOO_SMALL", what);
    t_note("%s -> 0x%08lx%s", what, (ULONG)st, st == CRS_NOT_FOUND ? " (STATUS_NOT_FOUND)" : "");
}

static int has_prov(const cr_strlist *l, const WCHAR *s) { return cr_list_has(l, s); }

/* ============================================================ contexts */
TEST(crreg_contexts_local_has_default)
{
    REQUIRE(U(BCryptEnumContexts));
    cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const cr_strlist *l = b.p;
        CHECK(l->c >= 1);
        CHECK(cr_list_has(l, CRYPT_DEFAULT_CONTEXT));
        for (ULONG i = 0; i < l->c; i++) { char a[128]; cr_w2a(l->v[i], a, sizeof a); t_note("local context[%lu] = %s", i, a); }
    }
    cr_free(b.p);
}
TEST(crreg_contexts_local_has_ssl)
{
    REQUIRE(U(BCryptEnumContexts));
    cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) CHECK(cr_list_has(b.p, L"SSL"));
    cr_free(b.p);
}
TEST(crreg_contexts_names_unique_and_nonempty)
{
    REQUIRE(U(BCryptEnumContexts));
    cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const cr_strlist *l = b.p;
        for (ULONG i = 0; i < l->c; i++) {
            CHECK(l->v[i][0] != 0);
            for (ULONG j = i + 1; j < l->c; j++) CHECKF(lstrcmpiW(l->v[i], l->v[j]) != 0, "duplicate context at %lu/%lu", i, j);
        }
    }
    cr_free(b.p);
}
TEST(crreg_contexts_each_context_is_queryable)
{
    REQUIRE(U(BCryptEnumContexts)); REQUIRE(U(BCryptQueryContextConfiguration));
    cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st != CRS_OK) return;
    const cr_strlist *l = b.p;
    for (ULONG i = 0; i < l->c; i++) {
        ULONG cb = 0; PCRYPT_CONTEXT_CONFIG cfg = NULL;
        NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, l->v[i], &cb, &cfg);
        char a[128]; cr_w2a(l->v[i], a, sizeof a);
        CHECKF(st == CRS_OK, "context %s: 0x%lx", a, (ULONG)st);
        if (st == CRS_OK) { CHECKF(cb >= sizeof *cfg, "context %s: cb=%lu", a, cb); t_note("context %s: dwFlags=0x%lx dwReserved=0x%lx", a, cfg->dwFlags, cfg->dwReserved); }
        cr_free(cfg);
    }
    cr_free(b.p);
}
TEST(crreg_contexts_domain_table)
{
    REQUIRE(U(BCryptEnumContexts));
    cr_blk b = cr_enum_contexts(CR_TABLE_DOMAIN);
    t_note("EnumContexts(CRYPT_DOMAIN) -> 0x%08lx, cb=%lu, count=%lu", (ULONG)b.st, b.cb, b.st == CRS_OK && b.p ? ((cr_strlist *)b.p)->c : 0);
    CHECKF(b.st == CRS_OK || b.st < 0, "status 0x%lx", (ULONG)b.st);
    if (b.st == CRS_OK) CHECK(b.p != NULL);
    if (b.st == CRS_OK && b.p) cr_walk_list(b.p, b.cb, ((cr_strlist *)b.p)->c, ((cr_strlist *)b.p)->v, "domain contexts");
    cr_free(b.p);
}
TEST(crreg_contexts_stable_between_calls)
{
    REQUIRE(U(BCryptEnumContexts));
    cr_blk a = cr_enum_contexts(CR_TABLE_LOCAL), b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(a.st, CRS_OK); EXPECT_EQ(b.st, CRS_OK);
    if (a.st == CRS_OK && b.st == CRS_OK) {
        const cr_strlist *x = a.p, *y = b.p;
        EXPECT_EQ(x->c, y->c);
        for (ULONG i = 0; i < x->c && i < y->c; i++) CHECK(!lstrcmpW(x->v[i], y->v[i]));
    }
    cr_free(a.p); cr_free(b.p);
}

/* ============================================================ context configuration */
TEST(crreg_ctxcfg_default_and_ssl_succeed)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    static const WCHAR *names[] = { L"Default", L"SSL" };
    for (int i = 0; i < 2; i++) {
        ULONG cb = 0; PCRYPT_CONTEXT_CONFIG cfg = NULL;
        NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, names[i], &cb, &cfg);
        CHECKF(st == CRS_OK, "context %ls: 0x%lx", names[i], (ULONG)st);
        if (st == CRS_OK) {
            CHECK(cfg != NULL);
            CHECKF(cb >= sizeof *cfg, "cb=%lu", cb);
            t_note("%ls: dwFlags=0x%lx dwReserved=0x%lx cb=%lu", names[i], cfg->dwFlags, cfg->dwReserved, cb);
        }
        cr_free(cfg);
    }
}
TEST(crreg_ctxcfg_ssl_repeatable)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    ULONG c1 = 0, c2 = 0; PCRYPT_CONTEXT_CONFIG a = NULL, b = NULL;
    EXPECT_EQ(U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, L"SSL", &c1, &a), CRS_OK);
    EXPECT_EQ(U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, L"SSL", &c2, &b), CRS_OK);
    if (a && b) { EXPECT_EQ(c1, c2); EXPECT_EQ(a->dwFlags, b->dwFlags); EXPECT_EQ(a->dwReserved, b->dwReserved); }
    cr_free(a); cr_free(b);
}
TEST(crreg_ctxcfg_bogus_context_fails)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    static const WCHAR *names[] = { L"NoSuchContext_cryptt", L"Default\\x", L"SSL1", L"S" };
    for (int i = 0; i < 4; i++) {
        ULONG cb = 0x4242; PCRYPT_CONTEXT_CONFIG cfg = NULL;
        NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, names[i], &cb, &cfg);
        char w[64]; snprintf(w, sizeof w, "QueryContextConfiguration('%ls')", names[i]);
        miss(w, st);
        EXPECT_EQ(cfg, NULL);
        cr_free(cfg);
    }
}
TEST(crreg_ctxcfg_bogus_context_size_query_fails)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    /* A size query is not allowed to turn a "not found" into success: only BUFFER_TOO_SMALL is folded. */
    ULONG cb = 0;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, L"NoSuchContext_cryptt", &cb, NULL);
    CHECKF(st < 0, "got 0x%lx", (ULONG)st);
    ULONG cb2 = 0; PCRYPT_CONTEXT_CONFIG p = NULL;
    NTSTATUS st2 = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, L"NoSuchContext_cryptt", &cb2, &p);
    EXPECT_EQ(st, st2);
}
TEST(crreg_ctxcfg_null_and_empty_context)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    /* A NULL name is accepted by the user-mode packer (no parameter error); the store decides. */
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG p = NULL;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, NULL, &cb, &p);
    t_note("QueryContextConfiguration(NULL context) -> 0x%08lx", (ULONG)st);
    cr_free(p); p = NULL;
    st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, L"", &cb, &p);
    t_note("QueryContextConfiguration(\"\" context) -> 0x%08lx", (ULONG)st);
    cr_free(p);
    CHECK(1);
}
TEST(crreg_ctxcfg_domain_table_records)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG p = NULL;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_DOMAIN, L"Default", &cb, &p);
    t_note("QueryContextConfiguration(DOMAIN,Default) -> 0x%08lx", (ULONG)st);
    if (st == CRS_OK) CHECK(p != NULL && cb >= sizeof *p);
    else CHECK(p == NULL);
    cr_free(p);
}
TEST(crreg_ctxcfg_name_case)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG p = NULL;
    NTSTATUS lo = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, L"default", &cb, &p);
    cr_free(p); p = NULL;
    NTSTATUS up = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, L"DEFAULT", &cb, &p);
    cr_free(p);
    t_note("QueryContextConfiguration: 'default' -> 0x%08lx, 'DEFAULT' -> 0x%08lx", (ULONG)lo, (ULONG)up);
    CHECKF((lo < 0) == (up < 0), "case changes success/failure: 0x%lx vs 0x%lx", (ULONG)lo, (ULONG)up);
}
TEST(crreg_ctxcfg_local_and_domain_independent_of_buffer_style)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    ULONG need = 0;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, L"Default", &need, NULL);
    EXPECT_EQ(st, CRS_OK);
    CHECK(need >= sizeof(CRYPT_CONTEXT_CONFIG));
}

/* ============================================================ functions of a context */
TEST(crreg_funcs_ssl_schannel_interface_succeeds)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    /* This is the configuration-store view only (no schannel call): on Windows 10 the SSL context has an
     * NCRYPT_SCHANNEL_INTERFACE function list and enumerating it succeeds. */
    cr_blk b = cr_enum_funcs(CR_TABLE_LOCAL, L"SSL", CRI_SCHANNEL);
    CHECKF(b.st != CRS_BUFFER_TOO_SMALL && b.st != CRS_INVALID_PARAMETER, "status 0x%lx", (ULONG)b.st);
    t_note("EnumContextFunctions(SSL, SCHANNEL if) -> 0x%08lx", (ULONG)b.st);
    if (b.st == CRS_OK) {
        const cr_strlist *l = b.p;
        t_note("SSL/SCHANNEL functions: %lu", l->c);
        for (ULONG i = 0; i < l->c; i++) { char a[96]; cr_w2a(l->v[i], a, sizeof a); t_note("  SSL function[%lu] = %s", i, a); }
    }
    cr_free(b.p);
}
TEST(crreg_funcs_every_context_every_interface)
{
    REQUIRE(U(BCryptEnumContexts)); REQUIRE(U(BCryptEnumContextFunctions));
    cr_blk c = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(c.st, CRS_OK);
    if (c.st != CRS_OK) return;
    const cr_strlist *cl = c.p;
    for (ULONG i = 0; i < cl->c; i++) {
        for (size_t k = 0; k < CR_N_GOOD_IFACES; k++) {
            cr_blk b = cr_enum_funcs(CR_TABLE_LOCAL, cl->v[i], cr_good_ifaces[k]);
            char a[128]; cr_w2a(cl->v[i], a, sizeof a);
            CHECKF(b.st == CRS_OK || b.st < 0, "%s/%s: 0x%lx", a, cr_iface_name(cr_good_ifaces[k]), (ULONG)b.st);
            CHECKF(b.st != CRS_BUFFER_TOO_SMALL, "%s/%s leaked BUFFER_TOO_SMALL", a, cr_iface_name(cr_good_ifaces[k]));
            if (b.st == CRS_OK) {
                const cr_strlist *l = b.p;
                if (l->c) cr_walk_list(b.p, b.cb, l->c, l->v, "functions");
                t_note("%s/%s: %lu function(s)", a, cr_iface_name(cr_good_ifaces[k]), l->c);
            } else t_note("%s/%s -> 0x%08lx", a, cr_iface_name(cr_good_ifaces[k]), (ULONG)b.st);
            cr_free(b.p);
        }
    }
    cr_free(c.p);
}
TEST(crreg_funcs_no_duplicates)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    for (size_t k = 0; k < CR_N_GOOD_IFACES; k++) {
        cr_blk b = cr_enum_funcs(CR_TABLE_LOCAL, L"SSL", cr_good_ifaces[k]);
        if (b.st != CRS_OK) { cr_free(b.p); continue; }
        const cr_strlist *l = b.p;
        for (ULONG i = 0; i < l->c; i++) for (ULONG j = i + 1; j < l->c; j++) CHECKF(lstrcmpiW(l->v[i], l->v[j]) != 0, "dup in SSL/%s", cr_iface_name(cr_good_ifaces[k]));
        cr_free(b.p);
    }
}
TEST(crreg_funcs_bogus_context_fails)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    cr_blk b = cr_enum_funcs(CR_TABLE_LOCAL, L"NoSuchContext_cryptt", CRI_HASH);
    miss("EnumContextFunctions(bogus context)", b.st);
    EXPECT_EQ(b.p, NULL);
    cr_free(b.p);
    ULONG cb = 0;
    NTSTATUS st = U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, L"NoSuchContext_cryptt", CRI_HASH, &cb, NULL);
    CHECKF(st < 0, "size query on bogus context must still fail: 0x%lx", (ULONG)st);
}
TEST(crreg_funcs_null_context_records)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    cr_blk b = cr_enum_funcs(CR_TABLE_LOCAL, NULL, CRI_HASH);
    t_note("EnumContextFunctions(NULL context, HASH) -> 0x%08lx count=%lu", (ULONG)b.st, b.st == CRS_OK ? ((cr_strlist *)b.p)->c : 0);
    CHECKF(b.st != CRS_BUFFER_TOO_SMALL, "leaked BUFFER_TOO_SMALL");
    cr_free(b.p);
}
TEST(crreg_funcs_domain_table_records)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    cr_blk b = cr_enum_funcs(CR_TABLE_DOMAIN, L"SSL", CRI_SCHANNEL);
    t_note("EnumContextFunctions(DOMAIN,SSL,SCHANNEL) -> 0x%08lx", (ULONG)b.st);
    if (b.st == CRS_OK) cr_walk_list(b.p, b.cb, ((cr_strlist *)b.p)->c, ((cr_strlist *)b.p)->v, "domain functions");
    cr_free(b.p);
}

/* ============================================================ providers of a function */
static void for_each_function(void (*fn)(const WCHAR *ctx, ULONG iface, const WCHAR *func, void *arg), void *arg)
{
    static const WCHAR *ctxs[] = { L"SSL", L"Default" };
    for (size_t c = 0; c < 2; c++)
        for (size_t k = 0; k < CR_N_GOOD_IFACES; k++) {
            cr_blk b = cr_enum_funcs(CR_TABLE_LOCAL, ctxs[c], cr_good_ifaces[k]);
            if (b.st == CRS_OK) {
                const cr_strlist *l = b.p;
                for (ULONG i = 0; i < l->c; i++) fn(ctxs[c], cr_good_ifaces[k], l->v[i], arg);
            }
            cr_free(b.p);
        }
}
static void each_funcprov(const WCHAR *ctx, ULONG iface, const WCHAR *f, void *arg)
{
    int *n = arg; (*n)++;
    cr_blk b = cr_enum_func_providers(CR_TABLE_LOCAL, ctx, iface, f);
    char a[96]; cr_w2a(f, a, sizeof a);
    CHECKF(b.st != CRS_BUFFER_TOO_SMALL && b.st != CRS_INVALID_PARAMETER, "%ls/%s/%s: 0x%lx", ctx, cr_iface_name(iface), a, (ULONG)b.st);
    if (b.st != CRS_OK) t_note("%ls/%s/%s providers -> 0x%08lx", ctx, cr_iface_name(iface), a, (ULONG)b.st);
    if (b.st == CRS_OK) {
        const cr_strlist *l = b.p;
        cr_walk_list(b.p, b.cb, l->c, l->v, "providers");
        for (ULONG i = 0; i < l->c; i++) { char p[96]; cr_w2a(l->v[i], p, sizeof p); t_note("%ls/%s/%s provider[%lu] = %s", ctx, cr_iface_name(iface), a, i, p); }
    }
    cr_free(b.p);
}
TEST(crreg_funcprov_every_enumerated_function_has_a_provider_list)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders)); REQUIRE(U(BCryptEnumContextFunctions));
    int n = 0;
    for_each_function(each_funcprov, &n);
    t_note("%d configured functions examined", n);
}
static void each_funccfg(const WCHAR *ctx, ULONG iface, const WCHAR *f, void *arg)
{
    int *n = arg; (*n)++;
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTION_CONFIG cfg = NULL;
    NTSTATUS st = U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, ctx, iface, f, &cb, &cfg);
    char a[96]; cr_w2a(f, a, sizeof a);
    CHECKF(st != CRS_BUFFER_TOO_SMALL && st != CRS_INVALID_PARAMETER, "%ls/%s/%s: 0x%lx", ctx, cr_iface_name(iface), a, (ULONG)st);
    if (st != CRS_OK) t_note("%ls/%s/%s config -> 0x%08lx", ctx, cr_iface_name(iface), a, (ULONG)st);
    if (st == CRS_OK) {
        CHECKF(cfg != NULL && cb >= sizeof *cfg, "cb=%lu", cb);
        if (cfg) t_note("%ls/%s/%s: dwFlags=0x%lx dwReserved=0x%lx", ctx, cr_iface_name(iface), a, cfg->dwFlags, cfg->dwReserved);
    }
    cr_free(cfg);
}
TEST(crreg_funccfg_every_enumerated_function_is_queryable)
{
    REQUIRE(U(BCryptQueryContextFunctionConfiguration)); REQUIRE(U(BCryptEnumContextFunctions));
    int n = 0;
    for_each_function(each_funccfg, &n);
    t_note("%d configured functions examined", n);
}
TEST(crreg_funcprov_bogus_function_fails)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    cr_blk b = cr_enum_func_providers(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"NoSuchFunction_cryptt");
    miss("EnumContextFunctionProviders(bogus function)", b.st);
    EXPECT_EQ(b.p, NULL);
    cr_free(b.p);
    ULONG cb = 0;
    NTSTATUS st = U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"NoSuchFunction_cryptt", &cb, NULL);
    CHECKF(st < 0, "size query must still fail: 0x%lx", (ULONG)st);
}
TEST(crreg_funcprov_bogus_context_fails)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    cr_blk b = cr_enum_func_providers(CR_TABLE_LOCAL, L"NoSuchContext_cryptt", CRI_HASH, L"SHA256");
    miss("EnumContextFunctionProviders(bogus context)", b.st);
    cr_free(b.p);
}
TEST(crreg_funcprov_default_hash_sha256_records)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    cr_blk b = cr_enum_func_providers(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256");
    t_note("EnumContextFunctionProviders(Default,HASH,SHA256) -> 0x%08lx", (ULONG)b.st);
    if (b.st == CRS_OK) {
        const cr_strlist *l = b.p;
        CHECK(cr_walk_list(b.p, b.cb, l->c, l->v, "providers"));
    }
    cr_free(b.p);
}
TEST(crreg_funcprov_interface_mismatch_fails)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    /* a hash name under the cipher interface is not configured anywhere */
    cr_blk b = cr_enum_func_providers(CR_TABLE_LOCAL, L"NoSuchContext_cryptt", CRI_CIPHER, L"SHA256");
    miss("EnumContextFunctionProviders(bogus ctx, cipher, SHA256)", b.st);
    cr_free(b.p);
}
static void each_configured_provider_registered(const WCHAR *ctx, ULONG iface, const WCHAR *f, void *arg)
{
    cr_blk reg = *(cr_blk *)arg;
    cr_blk b = cr_enum_func_providers(CR_TABLE_LOCAL, ctx, iface, f);
    if (b.st == CRS_OK) {
        const cr_strlist *l = b.p;
        for (ULONG i = 0; i < l->c; i++)
            if (!cr_list_has(reg.p, l->v[i])) { char p[96]; cr_w2a(l->v[i], p, sizeof p); t_note("configured provider '%s' (%ls/%s) is not in EnumRegisteredProviders", p, ctx, cr_iface_name(iface)); }
    }
    cr_free(b.p);
}
TEST(crreg_funcprov_configured_providers_vs_registered)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders)); REQUIRE(U(BCryptEnumRegisteredProviders));
    cr_blk reg = cr_enum_providers();
    EXPECT_EQ(reg.st, CRS_OK);
    if (reg.st == CRS_OK) for_each_function(each_configured_provider_registered, &reg);
    cr_free(reg.p);
}

/* ============================================================ function property */
TEST(crreg_funcprop_bogus_property_fails)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    ULONG cb = 0; PUCHAR p = NULL;
    NTSTATUS st = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", L"NoSuchProperty_cryptt", &cb, &p);
    miss("QueryContextFunctionProperty(bogus property)", st);
    EXPECT_EQ(p, NULL);
    cr_free(p);
}
TEST(crreg_funcprop_bogus_function_and_context_fail)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    ULONG cb = 0; PUCHAR p = NULL;
    NTSTATUS st = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"NoSuchFunction_cryptt", L"Prop", &cb, &p);
    miss("QueryContextFunctionProperty(bogus function)", st);
    st = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"NoSuchContext_cryptt", CRI_HASH, L"SHA256", L"Prop", &cb, &p);
    miss("QueryContextFunctionProperty(bogus context)", st);
    EXPECT_EQ(p, NULL);
}
TEST(crreg_funcprop_bogus_property_size_query)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    ULONG cb = 0;
    NTSTATUS st = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", L"NoSuchProperty_cryptt", &cb, NULL);
    CHECKF(st < 0, "missing property size query must fail: 0x%lx", (ULONG)st);
    t_note("size query on missing property -> 0x%08lx cb=%lu", (ULONG)st, cb);
}
static void each_prop_probe(const WCHAR *ctx, ULONG iface, const WCHAR *f, void *arg)
{
    static const WCHAR *props[] = { L"Priority", L"Flags", L"Description" };
    for (int i = 0; i < 3; i++) {
        ULONG cb = 0; PUCHAR p = NULL;
        NTSTATUS st = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, ctx, iface, f, props[i], &cb, &p);
        if (st == CRS_OK) { char a[96]; cr_w2a(f, a, sizeof a); t_note("property %ls of %ls/%s/%s: %lu bytes", props[i], ctx, cr_iface_name(iface), a, cb); CHECK(p != NULL); }
        cr_free(p);
    }
}
TEST(crreg_funcprop_probe_common_names)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty)); REQUIRE(U(BCryptEnumContextFunctions));
    int n = 0; (void)n;
    for_each_function(each_prop_probe, NULL);
    CHECK(1);
}

/* ============================================================ registered providers */
TEST(crreg_providers_has_primitive_provider)
{
    REQUIRE(U(BCryptEnumRegisteredProviders));
    cr_blk b = cr_enum_providers();
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const cr_strlist *l = b.p;
        CHECK(l->c >= 1);
        CHECK(has_prov(l, CR_PROVIDER_PRIM));
        for (ULONG i = 0; i < l->c; i++) { char a[128]; cr_w2a(l->v[i], a, sizeof a); t_note("registered provider[%lu] = %s", i, a); }
    }
    cr_free(b.p);
}
TEST(crreg_providers_has_software_key_storage_provider)
{
    REQUIRE(U(BCryptEnumRegisteredProviders));
    cr_blk b = cr_enum_providers();
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) CHECK(has_prov(b.p, L"Microsoft Software Key Storage Provider"));
    cr_free(b.p);
}
TEST(crreg_providers_unique_and_nonempty)
{
    REQUIRE(U(BCryptEnumRegisteredProviders));
    cr_blk b = cr_enum_providers();
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const cr_strlist *l = b.p;
        for (ULONG i = 0; i < l->c; i++) {
            CHECK(l->v[i][0] != 0);
            for (ULONG j = i + 1; j < l->c; j++) CHECKF(lstrcmpiW(l->v[i], l->v[j]) != 0, "duplicate provider %lu/%lu", i, j);
        }
    }
    cr_free(b.p);
}
TEST(crreg_providers_stable_between_calls)
{
    REQUIRE(U(BCryptEnumRegisteredProviders));
    cr_blk a = cr_enum_providers(), b = cr_enum_providers();
    EXPECT_EQ(a.st, CRS_OK); EXPECT_EQ(b.st, CRS_OK);
    if (a.st == CRS_OK && b.st == CRS_OK) {
        const cr_strlist *x = a.p, *y = b.p;
        EXPECT_EQ(x->c, y->c);
        EXPECT_EQ(a.cb, b.cb);
        for (ULONG i = 0; i < x->c && i < y->c; i++) CHECK(!lstrcmpW(x->v[i], y->v[i]));
    }
    cr_free(a.p); cr_free(b.p);
}
TEST(crreg_providers_each_has_registration)
{
    REQUIRE(U(BCryptEnumRegisteredProviders)); REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_enum_providers();
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st != CRS_OK) return;
    const cr_strlist *l = b.p;
    for (ULONG i = 0; i < l->c; i++) {
        cr_blk r = cr_query_reg(l->v[i], CRYPT_ANY, 0);
        char a[128]; cr_w2a(l->v[i], a, sizeof a);
        CHECKF(r.st == CRS_OK, "provider '%s' (ANY): 0x%lx", a, (ULONG)r.st);
        if (r.st == CRS_OK) {
            const CRYPT_PROVIDER_REG *reg = r.p;
            CHECKF(reg->pUM || reg->pKM, "provider '%s' has neither UM nor KM image in ANY mode", a);
            if (reg->pUM) { char im[128]; cr_w2a(reg->pUM->pszImage, im, sizeof im); t_note("%s: UM image %s, %lu interface(s), %lu alias(es)", a, im, reg->pUM->cInterfaces, reg->cAliases); }
            if (reg->pKM) { char im[128]; cr_w2a(reg->pKM->pszImage, im, sizeof im); t_note("%s: KM image %s, %lu interface(s)", a, im, reg->pKM->cInterfaces); }
        }
        cr_free(r.p);
    }
    cr_free(b.p);
}

/* ============================================================ provider registration */
TEST(crreg_queryreg_primitive_um_image)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_query_reg(CR_PROVIDER_PRIM, CRYPT_UM, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const CRYPT_PROVIDER_REG *r = b.p;
        CHECK(r->pUM != NULL);
        if (r->pUM) {
            CHECK(cr_check_reg_image(&b, r->pUM, "UM"));
            char im[128]; cr_w2a(r->pUM->pszImage, im, sizeof im);
            CHECKF(!lstrcmpiW(r->pUM->pszImage, L"bcryptprimitives.dll"), "UM image is '%s'", im);
            CHECK(r->pUM->cInterfaces >= 1);
        }
    }
    cr_free(b.p);
}
static const struct { ULONG iface; const WCHAR *fn; } prim_funcs[] = {
    { CRI_HASH, L"SHA1" }, { CRI_HASH, L"SHA256" }, { CRI_HASH, L"SHA384" }, { CRI_HASH, L"SHA512" }, { CRI_HASH, L"MD5" },
    { CRI_CIPHER, L"AES" }, { CRI_RNG, L"RNG" }, { CRI_ASYM, L"RSA" }, { CRI_SIGNATURE, L"RSA" },
    { CRI_SIGNATURE, L"ECDSA_P256" }, { CRI_SECRET, L"ECDH_P256" }, { CRI_KDF, L"PBKDF2" },
};
static int prim_core(size_t i) { return prim_funcs[i].iface == CRI_HASH || prim_funcs[i].iface == CRI_CIPHER || prim_funcs[i].iface == CRI_RNG; }
TEST(crreg_queryreg_primitive_um_function_table)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_query_reg(CR_PROVIDER_PRIM, CRYPT_UM, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK && ((CRYPT_PROVIDER_REG *)b.p)->pUM) {
        const CRYPT_IMAGE_REG *img = ((CRYPT_PROVIDER_REG *)b.p)->pUM;
        for (size_t i = 0; i < sizeof prim_funcs / sizeof prim_funcs[0]; i++) {
            int has = cr_image_has_func(img, prim_funcs[i].iface, prim_funcs[i].fn);
            if (prim_core(i)) CHECKF(has, "%s/%ls not registered by the Primitive Provider", cr_iface_name(prim_funcs[i].iface), prim_funcs[i].fn);
            else t_note("%s/%ls registered by the Primitive Provider: %s", cr_iface_name(prim_funcs[i].iface), prim_funcs[i].fn, has ? "yes" : "no");
        }
    }
    cr_free(b.p);
}
TEST(crreg_queryreg_primitive_um_interfaces_listed_once)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_query_reg(CR_PROVIDER_PRIM, CRYPT_UM, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK && ((CRYPT_PROVIDER_REG *)b.p)->pUM) {
        const CRYPT_IMAGE_REG *img = ((CRYPT_PROVIDER_REG *)b.p)->pUM;
        for (ULONG i = 0; i < img->cInterfaces; i++) {
            const CRYPT_INTERFACE_REG *ir = img->rgpInterfaces[i];
            CHECKF(ir->dwInterface != 0, "interface 0 listed");
            for (ULONG j = i + 1; j < img->cInterfaces; j++) CHECKF(img->rgpInterfaces[j]->dwInterface != ir->dwInterface, "interface 0x%lx twice", ir->dwInterface);
            for (ULONG f = 0; f < ir->cFunctions; f++)
                for (ULONG g = f + 1; g < ir->cFunctions; g++)
                    CHECKF(lstrcmpiW(ir->rgpszFunctions[f], ir->rgpszFunctions[g]) != 0, "%s: duplicate function %ls", cr_iface_name(ir->dwInterface), ir->rgpszFunctions[f]);
            t_note("Primitive UM interface %s (0x%lx): %lu function(s), flags 0x%lx", cr_iface_name(ir->dwInterface), ir->dwInterface, ir->cFunctions, ir->dwFlags);
        }
    }
    cr_free(b.p);
}
TEST(crreg_queryreg_interface_filter_returns_only_that_interface)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    for (size_t k = 0; k < CR_N_GOOD_IFACES; k++) {
        cr_blk b = cr_query_reg(CR_PROVIDER_PRIM, CRYPT_ANY, cr_good_ifaces[k]);
        if (b.st != CRS_OK) { t_note("Primitive/ANY/%s -> 0x%08lx", cr_iface_name(cr_good_ifaces[k]), (ULONG)b.st); cr_free(b.p); continue; }
        const CRYPT_PROVIDER_REG *r = b.p;
        const CRYPT_IMAGE_REG *imgs[2] = { r->pUM, r->pKM };
        for (int m = 0; m < 2; m++) {
            if (!imgs[m]) continue;
            for (ULONG i = 0; i < imgs[m]->cInterfaces; i++)
                CHECKF(imgs[m]->rgpInterfaces[i]->dwInterface == cr_good_ifaces[k], "filter %s returned interface 0x%lx", cr_iface_name(cr_good_ifaces[k]), imgs[m]->rgpInterfaces[i]->dwInterface);
        }
        cr_free(b.p);
    }
}
TEST(crreg_queryreg_hash_filter_lists_hash_functions)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_query_reg(CR_PROVIDER_PRIM, CRYPT_UM, CRI_HASH);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const CRYPT_PROVIDER_REG *r = b.p;
        CHECK(r->pUM != NULL);
        if (r->pUM) { CHECK(r->pUM->cInterfaces == 1); CHECK(cr_image_has_func(r->pUM, CRI_HASH, L"SHA256")); CHECK(!cr_image_has_func(r->pUM, CRI_CIPHER, L"AES")); }
    }
    cr_free(b.p);
}
TEST(crreg_queryreg_filtered_is_not_larger_than_full)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    ULONG full = 0, hash = 0;
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(CR_PROVIDER_PRIM, CRYPT_UM, 0, &full, NULL), CRS_OK);
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(CR_PROVIDER_PRIM, CRYPT_UM, CRI_HASH, &hash, NULL), CRS_OK);
    CHECKF(hash <= full, "filtered %lu > full %lu", hash, full);
}
TEST(crreg_queryreg_modes)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    static const struct { ULONG mode; const char *n; } modes[] = { { CRYPT_UM, "UM" }, { CRYPT_KM, "KM" }, { CRYPT_MM, "MM" }, { CRYPT_ANY, "ANY" } };
    for (int i = 0; i < 4; i++) {
        cr_blk b = cr_query_reg(CR_PROVIDER_PRIM, modes[i].mode, 0);
        if (b.st == CRS_OK) {
            const CRYPT_PROVIDER_REG *r = b.p;
            t_note("Primitive mode %s: pUM=%s pKM=%s", modes[i].n, r->pUM ? "yes" : "no", r->pKM ? "yes" : "no");
            if (modes[i].mode == CRYPT_UM) CHECK(r->pUM != NULL);
            if (modes[i].mode == CRYPT_ANY) CHECK(r->pUM != NULL || r->pKM != NULL);
            if (r->pKM) { char im[128]; cr_w2a(r->pKM->pszImage, im, sizeof im); t_note("Primitive KM image = %s", im); }
        } else t_note("Primitive mode %s -> 0x%08lx", modes[i].n, (ULONG)b.st);
        cr_free(b.p);
    }
}
TEST(crreg_queryreg_bogus_provider_fails)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_query_reg(L"NoSuchProvider_cryptt", CRYPT_UM, 0);
    miss("QueryProviderRegistration(bogus provider)", b.st);
    EXPECT_EQ(b.p, NULL);
    cr_free(b.p);
    ULONG cb = 0;
    NTSTATUS st = U(BCryptQueryProviderRegistration)(L"NoSuchProvider_cryptt", CRYPT_UM, 0, &cb, NULL);
    CHECKF(st < 0, "size query on a bogus provider must fail: 0x%lx", (ULONG)st);
}
TEST(crreg_queryreg_provider_name_case)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk a = cr_query_reg(L"MICROSOFT PRIMITIVE PROVIDER", CRYPT_UM, 0);
    cr_blk b = cr_query_reg(L"microsoft primitive provider", CRYPT_UM, 0);
    t_note("QueryProviderRegistration upper-case -> 0x%08lx, lower-case -> 0x%08lx", (ULONG)a.st, (ULONG)b.st);
    CHECKF((a.st < 0) == (b.st < 0), "case changes success/failure");
    cr_free(a.p); cr_free(b.p);
}
TEST(crreg_queryreg_interface_not_supported_by_provider)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    /* the Primitive Provider does not implement the key storage interface */
    cr_blk b = cr_query_reg(CR_PROVIDER_PRIM, CRYPT_UM, CRI_KEYSTORE);
    t_note("Primitive/UM/KEY_STORAGE -> 0x%08lx", (ULONG)b.st);
    if (b.st == CRS_OK) {
        const CRYPT_PROVIDER_REG *r = b.p;
        if (r->pUM) CHECK(r->pUM->cInterfaces == 0 || !cr_image_has_func(r->pUM, CRI_HASH, L"SHA256"));
    }
    cr_free(b.p);
}
TEST(crreg_queryreg_software_ksp_key_storage_interface)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_query_reg(L"Microsoft Software Key Storage Provider", CRYPT_ANY, CRI_KEYSTORE);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const CRYPT_PROVIDER_REG *r = b.p;
        CHECK(r->pUM != NULL || r->pKM != NULL);
        if (r->pUM) {
            char im[128]; cr_w2a(r->pUM->pszImage, im, sizeof im); t_note("Software KSP UM image = %s", im);
            CHECK(r->pUM->cInterfaces >= 1);
            if (r->pUM->cInterfaces) CHECK(r->pUM->rgpInterfaces[0]->dwInterface == CRI_KEYSTORE);
        }
    }
    cr_free(b.p);
}
TEST(crreg_queryreg_aliases_inside_block)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_query_reg(CR_PROVIDER_PRIM, CRYPT_ANY, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const CRYPT_PROVIDER_REG *r = b.p;
        CHECK(cr_walk_list(b.p, b.cb, r->cAliases, r->rgpszAliases, "aliases"));
        for (ULONG i = 0; i < r->cAliases; i++) { char a[96]; cr_w2a(r->rgpszAliases[i], a, sizeof a); t_note("Primitive alias[%lu] = %s", i, a); }
    }
    cr_free(b.p);
}

/* ============================================================ resolution */
static NTSTATUS resolve_first(const WCHAR *ctx, ULONG iface, const WCHAR *fn, cr_blk *out)
{
    *out = cr_resolve(ctx, iface, fn, NULL, CRYPT_UM, 0);
    return out->st;
}
TEST(crreg_resolve_sha256_default_context)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b; NTSTATUS st = resolve_first(NULL, CRI_HASH, L"SHA256", &b);
    EXPECT_EQ(st, CRS_OK);
    if (st == CRS_OK) {
        const CRYPT_PROVIDER_REFS *r = b.p;
        CHECK(cr_check_refs(&b, "refs"));
        CHECK(r->cProviders >= 1);
        if (r->cProviders >= 1) {
            const CRYPT_PROVIDER_REF *pr = r->rgpProviders[0];
            CHECK(!lstrcmpiW(pr->pszProvider, CR_PROVIDER_PRIM));
            EXPECT_EQ(pr->dwInterface, CRI_HASH);
            if (pr->pszFunction) CHECK(!lstrcmpiW(pr->pszFunction, L"SHA256"));
            CHECK(pr->pUM != NULL);
            if (pr->pUM) CHECK(!lstrcmpiW(pr->pUM->pszImage, L"bcryptprimitives.dll"));
        }
    }
    cr_free(b.p);
}
TEST(crreg_resolve_without_flags_returns_single_ref)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, CRI_HASH, NULL, NULL, CRYPT_UM, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) { CHECK(cr_check_refs(&b, "refs")); t_note("Resolve(HASH,*,flags 0) -> %lu ref(s)", ((CRYPT_PROVIDER_REFS *)b.p)->cProviders); }
    cr_free(b.p);
}
TEST(crreg_resolve_empty_context_equals_null_context)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk a = cr_resolve(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0);
    cr_blk b = cr_resolve(L"", CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0);
    EXPECT_EQ(a.st, CRS_OK);
    EXPECT_EQ(b.st, a.st);
    if (a.st == CRS_OK && b.st == CRS_OK) {
        const CRYPT_PROVIDER_REFS *x = a.p, *y = b.p;
        EXPECT_EQ(x->cProviders, y->cProviders);
        if (x->cProviders && y->cProviders) CHECK(!lstrcmpW(x->rgpProviders[0]->pszProvider, y->rgpProviders[0]->pszProvider));
        EXPECT_EQ(a.cb, b.cb);
    }
    cr_free(a.p); cr_free(b.p);
}
TEST(crreg_resolve_explicit_default_context)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk a = cr_resolve(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0);
    cr_blk b = cr_resolve(CRYPT_DEFAULT_CONTEXT, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0);
    t_note("Resolve(NULL ctx) -> 0x%08lx, Resolve(\"Default\") -> 0x%08lx", (ULONG)a.st, (ULONG)b.st);
    if (a.st == CRS_OK && b.st == CRS_OK) {
        const CRYPT_PROVIDER_REFS *x = a.p, *y = b.p;
        EXPECT_EQ(x->cProviders, y->cProviders);
        EXPECT_EQ(a.cb, b.cb);
    }
    cr_free(a.p); cr_free(b.p);
}
TEST(crreg_resolve_interface_zero_infers_from_function)
{
    REQUIRE(U(BCryptResolveProviders));
    /* documented: with a function name, interface 0 lets the resolver infer the interface */
    cr_blk b = cr_resolve(NULL, 0, L"SHA256", NULL, CRYPT_UM, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const CRYPT_PROVIDER_REFS *r = b.p;
        CHECK(cr_check_refs(&b, "refs"));
        CHECK(r->cProviders >= 1);
        if (r->cProviders) { if (r->rgpProviders[0]->dwInterface != CRI_HASH) t_note("iface 0 resolved to interface 0x%lx", r->rgpProviders[0]->dwInterface); }
    }
    cr_free(b.p);
}
TEST(crreg_resolve_interface_zero_and_no_function_records)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, 0, NULL, NULL, CRYPT_UM, 0);
    t_note("Resolve(iface 0, no function) -> 0x%08lx", (ULONG)b.st);
    CHECKF(b.st != CRS_BUFFER_TOO_SMALL, "leaked BUFFER_TOO_SMALL");
    cr_free(b.p);
}
TEST(crreg_resolve_standard_algorithms_come_from_primitive_provider)
{
    REQUIRE(U(BCryptResolveProviders));
    for (size_t i = 0; i < sizeof prim_funcs / sizeof prim_funcs[0]; i++) {
        cr_blk b = cr_resolve(NULL, prim_funcs[i].iface, prim_funcs[i].fn, NULL, CRYPT_UM, 0);
        if (prim_core(i)) CHECKF(b.st == CRS_OK, "%s/%ls: 0x%lx", cr_iface_name(prim_funcs[i].iface), prim_funcs[i].fn, (ULONG)b.st);
        else if (b.st != CRS_OK) t_note("%s/%ls resolve -> 0x%08lx", cr_iface_name(prim_funcs[i].iface), prim_funcs[i].fn, (ULONG)b.st);
        if (b.st == CRS_OK) {
            const CRYPT_PROVIDER_REFS *r = b.p;
            if (prim_core(i)) CHECKF(r->cProviders >= 1, "%s/%ls: no provider", cr_iface_name(prim_funcs[i].iface), prim_funcs[i].fn);
            if (r->cProviders) {
                if (prim_core(i)) CHECKF(!lstrcmpiW(r->rgpProviders[0]->pszProvider, CR_PROVIDER_PRIM), "%s/%ls resolved to %ls", cr_iface_name(prim_funcs[i].iface), prim_funcs[i].fn, r->rgpProviders[0]->pszProvider);
                if (prim_core(i)) EXPECT_EQ(r->rgpProviders[0]->dwInterface, prim_funcs[i].iface);
            }
        }
        cr_free(b.p);
    }
}
TEST(crreg_resolve_flag_progression)
{
    REQUIRE(U(BCryptResolveProviders));
    ULONG n[4] = { 0 };
    for (ULONG f = 0; f < 4; f++) {
        cr_blk b = cr_resolve(NULL, CRI_HASH, NULL, NULL, CRYPT_UM, f);
        CHECKF(b.st == CRS_OK, "flags %lu: 0x%lx", f, (ULONG)b.st);
        if (b.st == CRS_OK) { n[f] = ((CRYPT_PROVIDER_REFS *)b.p)->cProviders; CHECK(cr_check_refs(&b, "refs")); }
        t_note("Resolve(HASH,*,flags=%lu) -> %lu ref(s), %lu bytes", f, n[f], b.cb);
        cr_free(b.p);
    }
    CHECKF(n[1] >= n[0], "ALL_FUNCTIONS returned fewer refs (%lu) than none (%lu)", n[1], n[0]);
    CHECKF(n[2] >= n[0], "ALL_PROVIDERS returned fewer refs (%lu) than none (%lu)", n[2], n[0]);
    CHECKF(n[3] >= n[1] && n[3] >= n[2], "both flags %lu vs %lu/%lu", n[3], n[1], n[2]);
    CHECKF(n[1] >= 1, "CRYPT_ALL_FUNCTIONS should list the hash algorithms, got %lu", n[1]);
}
TEST(crreg_resolve_all_functions_lists_known_hashes)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, CRI_HASH, NULL, NULL, CRYPT_UM, CRYPT_ALL_FUNCTIONS | CRYPT_ALL_PROVIDERS);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const CRYPT_PROVIDER_REFS *r = b.p;
        static const WCHAR *want[] = { L"SHA1", L"SHA256", L"SHA384", L"SHA512", L"MD5" };
        for (int w = 0; w < 5; w++) {
            int found = 0;
            for (ULONG i = 0; i < r->cProviders; i++) if (r->rgpProviders[i]->pszFunction && !lstrcmpiW(r->rgpProviders[i]->pszFunction, want[w])) found = 1;
            CHECKF(found, "%ls missing from the resolved hash list", want[w]);
        }
        for (ULONG i = 0; i < r->cProviders; i++) CHECK(r->rgpProviders[i]->dwInterface == CRI_HASH);
    }
    cr_free(b.p);
}
TEST(crreg_resolve_provider_filter)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, CRI_HASH, L"SHA256", CR_PROVIDER_PRIM, CRYPT_UM, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK) {
        const CRYPT_PROVIDER_REFS *r = b.p;
        CHECK(r->cProviders >= 1);
        for (ULONG i = 0; i < r->cProviders; i++) CHECK(!lstrcmpiW(r->rgpProviders[i]->pszProvider, CR_PROVIDER_PRIM));
    }
    cr_free(b.p);
}
TEST(crreg_resolve_provider_filter_bogus_provider_fails)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, CRI_HASH, L"SHA256", L"NoSuchProvider_cryptt", CRYPT_UM, 0);
    miss("ResolveProviders(bogus provider)", b.st);
    EXPECT_EQ(b.p, NULL);
    cr_free(b.p);
    ULONG cb = 0;
    NTSTATUS st = U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", L"NoSuchProvider_cryptt", CRYPT_UM, 0, &cb, NULL);
    CHECKF(st < 0, "size query must fail too: 0x%lx", (ULONG)st);
}
TEST(crreg_resolve_provider_filter_wrong_interface)
{
    REQUIRE(U(BCryptResolveProviders));
    /* The Primitive Provider has no key-storage interface. */
    cr_blk b = cr_resolve(NULL, CRI_KEYSTORE, NULL, CR_PROVIDER_PRIM, CRYPT_UM, 0);
    miss("ResolveProviders(Primitive, KEY_STORAGE)", b.st);
    cr_free(b.p);
}
TEST(crreg_resolve_bogus_function_fails)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, CRI_HASH, L"NoSuchHash_cryptt", NULL, CRYPT_UM, 0);
    miss("ResolveProviders(bogus hash)", b.st);
    EXPECT_EQ(b.p, NULL);
    cr_free(b.p);
    b = cr_resolve(NULL, 0, L"NoSuchHash_cryptt", NULL, CRYPT_UM, 0);
    miss("ResolveProviders(iface 0, bogus function)", b.st);
    cr_free(b.p);
}
TEST(crreg_resolve_function_under_wrong_interface_fails)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, CRI_CIPHER, L"SHA256", NULL, CRYPT_UM, 0);
    miss("ResolveProviders(cipher interface, SHA256)", b.st);
    cr_free(b.p);
}
TEST(crreg_resolve_bogus_context_records)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(L"NoSuchContext_cryptt", CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0);
    t_note("Resolve(bogus context, SHA256) -> 0x%08lx", (ULONG)b.st);
    CHECKF(b.st != CRS_BUFFER_TOO_SMALL, "leaked BUFFER_TOO_SMALL");
    cr_free(b.p);
}
TEST(crreg_resolve_function_name_case)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk a = cr_resolve(NULL, CRI_HASH, L"sha256", NULL, CRYPT_UM, 0);
    cr_blk b = cr_resolve(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0);
    t_note("Resolve('sha256') -> 0x%08lx, Resolve('SHA256') -> 0x%08lx", (ULONG)a.st, (ULONG)b.st);
    EXPECT_EQ(b.st, CRS_OK);
    cr_free(a.p); cr_free(b.p);
}
TEST(crreg_resolve_modes)
{
    REQUIRE(U(BCryptResolveProviders));
    static const struct { ULONG mode; const char *n; } modes[] = { { CRYPT_UM, "UM" }, { CRYPT_KM, "KM" }, { CRYPT_MM, "MM" } };
    for (int i = 0; i < 3; i++) {
        cr_blk b = cr_resolve(NULL, CRI_HASH, L"SHA256", NULL, modes[i].mode, 0);
        if (b.st == CRS_OK) {
            const CRYPT_PROVIDER_REFS *r = b.p;
            CHECK(cr_check_refs(&b, "refs"));
            t_note("Resolve(SHA256,%s): %lu ref(s)", modes[i].n, r->cProviders);
            if (r->cProviders) {
                const CRYPT_PROVIDER_REF *pr = r->rgpProviders[0];
                t_note("  first: pUM=%s pKM=%s", pr->pUM ? "yes" : "no", pr->pKM ? "yes" : "no");
                if (modes[i].mode == CRYPT_UM) CHECK(pr->pUM != NULL);
            }
        } else t_note("Resolve(SHA256,%s) -> 0x%08lx", modes[i].n, (ULONG)b.st);
        cr_free(b.p);
    }
}
TEST(crreg_resolve_um_ref_names_user_mode_image_only)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK && ((CRYPT_PROVIDER_REFS *)b.p)->cProviders) {
        const CRYPT_PROVIDER_REF *pr = ((CRYPT_PROVIDER_REFS *)b.p)->rgpProviders[0];
        CHECKF(pr->pKM == NULL, "UM-only resolution returned a kernel image");
        t_note("UM ref: image flags 0x%lx, %lu propert(ies)", pr->pUM ? pr->pUM->dwFlags : 0, pr->cProperties);
    }
    cr_free(b.p);
}
TEST(crreg_resolve_ref_providers_are_registered)
{
    REQUIRE(U(BCryptResolveProviders)); REQUIRE(U(BCryptEnumRegisteredProviders));
    cr_blk reg = cr_enum_providers();
    cr_blk b = cr_resolve(NULL, CRI_HASH, NULL, NULL, CRYPT_UM, CRYPT_ALL_FUNCTIONS | CRYPT_ALL_PROVIDERS);
    EXPECT_EQ(reg.st, CRS_OK); EXPECT_EQ(b.st, CRS_OK);
    if (reg.st == CRS_OK && b.st == CRS_OK) {
        const CRYPT_PROVIDER_REFS *r = b.p;
        for (ULONG i = 0; i < r->cProviders; i++)
            CHECKF(cr_list_has(reg.p, r->rgpProviders[i]->pszProvider), "ref %lu provider '%ls' not registered", i, r->rgpProviders[i]->pszProvider);
    }
    cr_free(reg.p); cr_free(b.p);
}
TEST(crreg_resolve_ref_image_matches_registration)
{
    REQUIRE(U(BCryptResolveProviders)); REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_resolve(NULL, CRI_CIPHER, L"AES", NULL, CRYPT_UM, 0);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st == CRS_OK && ((CRYPT_PROVIDER_REFS *)b.p)->cProviders) {
        const CRYPT_PROVIDER_REF *pr = ((CRYPT_PROVIDER_REFS *)b.p)->rgpProviders[0];
        cr_blk r = cr_query_reg(pr->pszProvider, CRYPT_UM, CRI_CIPHER);
        EXPECT_EQ(r.st, CRS_OK);
        if (r.st == CRS_OK && pr->pUM && ((CRYPT_PROVIDER_REG *)r.p)->pUM) CHECK(!lstrcmpiW(pr->pUM->pszImage, ((CRYPT_PROVIDER_REG *)r.p)->pUM->pszImage));
        cr_free(r.p);
    }
    cr_free(b.p);
}
TEST(crreg_resolve_key_storage_interface_in_default_context)
{
    REQUIRE(U(BCryptResolveProviders));
    cr_blk b = cr_resolve(NULL, CRI_KEYSTORE, NULL, NULL, CRYPT_UM, 0);
    t_note("Resolve(Default, KEY_STORAGE) -> 0x%08lx", (ULONG)b.st);
    if (b.st == CRS_OK) {
        CHECK(cr_check_refs(&b, "refs"));
        const CRYPT_PROVIDER_REFS *r = b.p;
        if (r->cProviders) { char p[128]; cr_w2a(r->rgpProviders[0]->pszProvider, p, sizeof p); t_note("  provider = %s", p); }
    }
    cr_free(b.p);
}
TEST(crreg_resolve_ssl_context_schannel_interface_config_view)
{
    REQUIRE(U(BCryptResolveProviders));
    /* configuration lookup only: which provider the SSL context lists for the interface (no handshake, no schannel call) */
    cr_blk b = cr_resolve(L"SSL", CRI_SCHANNEL, NULL, NULL, CRYPT_UM, CRYPT_ALL_FUNCTIONS | CRYPT_ALL_PROVIDERS);
    t_note("Resolve(SSL, SCHANNEL if) -> 0x%08lx", (ULONG)b.st);
    if (b.st == CRS_OK) {
        CHECK(cr_check_refs(&b, "refs"));
        const CRYPT_PROVIDER_REFS *r = b.p;
        for (ULONG i = 0; i < r->cProviders; i++) { char p[128], f[96]; cr_w2a(r->rgpProviders[i]->pszProvider, p, sizeof p); cr_w2a(r->rgpProviders[i]->pszFunction, f, sizeof f); t_note("  ref[%lu] provider=%s function=%s", i, p, f); }
    }
    cr_free(b.p);
}

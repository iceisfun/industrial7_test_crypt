/* Buffer protocol shared by every CNG configuration query:
 *   ppBuffer == NULL          -> size query: STATUS_SUCCESS, *pcbBuffer = required size
 *   *ppBuffer == NULL         -> the call allocates (process heap), release with BCryptFreeBuffer; *pcbBuffer ignored on entry
 *   *ppBuffer != NULL         -> the caller's block of *pcbBuffer bytes is filled in place; too small gives
 *                                STATUS_BUFFER_TOO_SMALL with the required size in *pcbBuffer and the pointer unchanged.
 * The result is always ONE block: the header structure first, all arrays and strings after it, pointers fixed up. */
#include "cr.h"

typedef NTSTATUS (*cr_call)(ULONG *cb, void **pp);
typedef void (*cr_validate)(const void *p, ULONG cb);

static ULONG g_table = CR_TABLE_LOCAL, g_iface, g_mode, g_flags;
static const WCHAR *g_ctx, *g_fn, *g_prov, *g_prop;

static NTSTATUS call_contexts(ULONG *cb, void **pp)  { return U(BCryptEnumContexts)(g_table, cb, (PCRYPT_CONTEXTS *)pp); }
static NTSTATUS call_providers(ULONG *cb, void **pp) { return U(BCryptEnumRegisteredProviders)(cb, (PCRYPT_PROVIDERS *)pp); }
static NTSTATUS call_ctxcfg(ULONG *cb, void **pp)    { return U(BCryptQueryContextConfiguration)(g_table, g_ctx, cb, (PCRYPT_CONTEXT_CONFIG *)pp); }
static NTSTATUS call_funcs(ULONG *cb, void **pp)     { return U(BCryptEnumContextFunctions)(g_table, g_ctx, g_iface, cb, (PCRYPT_CONTEXT_FUNCTIONS *)pp); }
static NTSTATUS call_funcprov(ULONG *cb, void **pp)  { return U(BCryptEnumContextFunctionProviders)(g_table, g_ctx, g_iface, g_fn, cb, (PCRYPT_CONTEXT_FUNCTION_PROVIDERS *)pp); }
static NTSTATUS call_funccfg(ULONG *cb, void **pp)   { return U(BCryptQueryContextFunctionConfiguration)(g_table, g_ctx, g_iface, g_fn, cb, (PCRYPT_CONTEXT_FUNCTION_CONFIG *)pp); }
static NTSTATUS call_reg(ULONG *cb, void **pp)       { return U(BCryptQueryProviderRegistration)(g_prov, g_mode, g_iface, cb, (PCRYPT_PROVIDER_REG *)pp); }
static NTSTATUS call_resolve(ULONG *cb, void **pp)   { return U(BCryptResolveProviders)(g_ctx, g_iface, g_fn, g_prov, g_mode, g_flags, cb, (PCRYPT_PROVIDER_REFS *)pp); }
static NTSTATUS call_funcprop(ULONG *cb, void **pp)  { return U(BCryptQueryContextFunctionProperty)(g_table, g_ctx, g_iface, g_fn, g_prop, cb, (PUCHAR *)pp); }

static void val_list(const void *p, ULONG cb)
{
    const cr_strlist *l = p;
    if (cb < sizeof *l) { CHECKF(0, "block too small for header: %lu", cb); return; }
    cr_walk_list(p, cb, l->c, l->v, "list");
}
static void val_cfg(const void *p, ULONG cb) { CHECKF(cb >= 8, "config block %lu bytes", cb); }
static void val_reg(const void *p, ULONG cb)
{
    const CRYPT_PROVIDER_REG *r = p; cr_blk b = { (void *)p, cb, 0 };
    if (cb < sizeof *r) { CHECKF(0, "block too small: %lu", cb); return; }
    cr_walk_list(p, cb, r->cAliases, r->rgpszAliases, "aliases");
    if (r->pUM) cr_check_reg_image(&b, r->pUM, "UM");
    if (r->pKM) cr_check_reg_image(&b, r->pKM, "KM");
}
static void val_refs(const void *p, ULONG cb) { cr_blk b = { (void *)p, cb, 0 }; cr_check_refs(&b, "refs"); }
static void val_none(const void *p, ULONG cb) { }

/* Run the full protocol against one known-good query. */
static void cr_protocol(const char *name, cr_call call, cr_validate val, ULONG min_need)
{
    ULONG need = 0;
    NTSTATUS st;
    void *buf, *p;
    ULONG cb;

    /* 1. size query */
    st = call(&need, NULL);
    CHECKF(st == CRS_OK, "%s size query: 0x%lx", name, (ULONG)st);
    CHECKF(need >= min_need, "%s required size %lu < %lu", name, need, min_need);
    if (st != CRS_OK || need < min_need) { t_note("%s: skipping the rest of the protocol", name); return; }

    /* 2. the entry value of *pcbBuffer does not influence a size query */
    static const ULONG entry[] = { 0, 1, 7, 0x10000, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof entry / sizeof entry[0]; i++) {
        cb = entry[i];
        st = call(&cb, NULL);
        CHECKF(st == CRS_OK && cb == need, "%s size query with entry cb=0x%lx: st=0x%lx cb=%lu want %lu", name, entry[i], (ULONG)st, cb, need);
    }

    /* 3. allocation mode: entry *pcbBuffer is ignored */
    for (size_t i = 0; i < 3; i++) {
        static const ULONG e[] = { 0, 3, 0x7FFFFFFF };
        p = NULL; cb = e[i];
        st = call(&cb, &p);
        CHECKF(st == CRS_OK, "%s allocate mode (entry cb 0x%lx): 0x%lx", name, e[i], (ULONG)st);
        if (st != CRS_OK) continue;
        CHECK(p != NULL);
        EXPECT_EQ(cb, need);
        if (p) { CHECK(HeapValidate(GetProcessHeap(), 0, p)); val(p, cb); }
        cr_free(p);
    }

    /* 4. caller block, exact size */
    buf = HeapAlloc(GetProcessHeap(), 0, need);
    if (!buf) { t_skip("alloc"); return; }
    memset(buf, 0xCC, need);
    p = buf; cb = need;
    st = call(&cb, &p);
    CHECKF(st == CRS_OK, "%s exact buffer: 0x%lx", name, (ULONG)st);
    EXPECT_EQ(p, buf);
    EXPECT_EQ(cb, need);
    if (st == CRS_OK) val(buf, cb);
    HeapFree(GetProcessHeap(), 0, buf);

    /* 5. caller block, larger than needed */
    buf = HeapAlloc(GetProcessHeap(), 0, need + 256);
    if (!buf) { t_skip("alloc"); return; }
    memset(buf, 0xCC, need + 256);
    p = buf; cb = need + 256;
    st = call(&cb, &p);
    CHECKF(st == CRS_OK, "%s oversize buffer: 0x%lx", name, (ULONG)st);
    EXPECT_EQ(p, buf);
    CHECKF(cb <= need + 256, "%s oversize: cb=%lu", name, cb);
    if (cb != need) t_note("%s: with a %lu byte buffer *pcbBuffer came back %lu (exact need %lu)", name, need + 256, cb, need);
    if (st == CRS_OK) val(buf, cb < need ? need : cb);
    HeapFree(GetProcessHeap(), 0, buf);

    /* 6. too small: need-1, need/2, 1, 0 */
    buf = HeapAlloc(GetProcessHeap(), 0, need);
    if (!buf) { t_skip("alloc"); return; }
    ULONG smalls[4] = { need - 1, need / 2, 1, 0 };
    for (int i = 0; i < 4; i++) {
        memset(buf, 0xCC, need);
        p = buf; cb = smalls[i];
        st = call(&cb, &p);
        CHECKF(st == CRS_BUFFER_TOO_SMALL, "%s buffer of %lu: got 0x%lx", name, smalls[i], (ULONG)st);
        EXPECT_EQ(p, buf);       /* pointer variable untouched */
        EXPECT_EQ(cb, need);     /* required size reported */
    }
    HeapFree(GetProcessHeap(), 0, buf);

    /* 7. a failed too-small call leaves nothing behind that breaks the next call */
    p = NULL; cb = 0;
    st = call(&cb, &p);
    CHECKF(st == CRS_OK && cb == need, "%s after too-small calls: 0x%lx cb=%lu", name, (ULONG)st, cb);
    cr_free(p);
}

TEST(crbuf_enumcontexts_protocol)
{
    REQUIRE(U(BCryptEnumContexts)); REQUIRE(U(BCryptFreeBuffer));
    g_table = CR_TABLE_LOCAL;
    cr_protocol("EnumContexts(local)", call_contexts, val_list, sizeof(CRYPT_CONTEXTS));
}
TEST(crbuf_enumregistered_protocol)
{
    REQUIRE(U(BCryptEnumRegisteredProviders)); REQUIRE(U(BCryptFreeBuffer));
    cr_protocol("EnumRegisteredProviders", call_providers, val_list, sizeof(CRYPT_PROVIDERS));
}
TEST(crbuf_querycontextcfg_protocol_default)
{
    REQUIRE(U(BCryptQueryContextConfiguration)); REQUIRE(U(BCryptFreeBuffer));
    g_table = CR_TABLE_LOCAL; g_ctx = L"Default";
    cr_protocol("QueryContextConfiguration(Default)", call_ctxcfg, val_cfg, sizeof(CRYPT_CONTEXT_CONFIG));
}
TEST(crbuf_querycontextcfg_protocol_ssl)
{
    REQUIRE(U(BCryptQueryContextConfiguration)); REQUIRE(U(BCryptFreeBuffer));
    g_table = CR_TABLE_LOCAL; g_ctx = L"SSL";
    cr_protocol("QueryContextConfiguration(SSL)", call_ctxcfg, val_cfg, sizeof(CRYPT_CONTEXT_CONFIG));
}
TEST(crbuf_enumfuncs_protocol_ssl_schannel_interface)
{
    REQUIRE(U(BCryptEnumContextFunctions)); REQUIRE(U(BCryptFreeBuffer));
    g_table = CR_TABLE_LOCAL; g_ctx = L"SSL"; g_iface = CRI_SCHANNEL;
    cr_protocol("EnumContextFunctions(SSL,SCHANNEL if)", call_funcs, val_list, sizeof(CRYPT_CONTEXT_FUNCTIONS));
}
TEST(crbuf_enumfuncs_protocol_default_hash)
{
    REQUIRE(U(BCryptEnumContextFunctions)); REQUIRE(U(BCryptFreeBuffer));
    g_table = CR_TABLE_LOCAL; g_ctx = L"Default"; g_iface = CRI_HASH;
    cr_blk b = cr_enum_funcs(g_table, g_ctx, g_iface);
    if (b.st != CRS_OK) { t_note("EnumContextFunctions(Default,HASH) -> 0x%08lx; protocol not run", (ULONG)b.st); return; }
    cr_free(b.p);
    cr_protocol("EnumContextFunctions(Default,HASH)", call_funcs, val_list, sizeof(CRYPT_CONTEXT_FUNCTIONS));
}
TEST(crbuf_enumfuncs_ssl_context_name_case)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    /* Context lookup goes through the registry key name: record whether lookup is case-insensitive. */
    cr_blk a = cr_enum_funcs(CR_TABLE_LOCAL, L"SSL", CRI_SCHANNEL);
    cr_blk l = cr_enum_funcs(CR_TABLE_LOCAL, L"ssl", CRI_SCHANNEL);
    EXPECT_EQ(a.st, CRS_OK);
    t_note("EnumContextFunctions: 'SSL' -> 0x%08lx, 'ssl' -> 0x%08lx", (ULONG)a.st, (ULONG)l.st);
    cr_free(a.p); cr_free(l.p);
}

/* pick the first (context, interface, function) triple that has providers; used by the next tests */
static int cr_pick_function(const WCHAR **ctx, ULONG *iface, WCHAR *fn, size_t fncap)
{
    static const WCHAR *ctxs[] = { L"SSL", L"Default" };
    for (size_t c = 0; c < 2; c++) {
        for (size_t i = 0; i < CR_N_GOOD_IFACES; i++) {
            cr_blk b = cr_enum_funcs(CR_TABLE_LOCAL, ctxs[c], cr_good_ifaces[i]);
            if (b.st != CRS_OK) continue;
            const cr_strlist *l = b.p;
            if (l->c > 0) {
                lstrcpynW(fn, l->v[0], (int)fncap);
                *ctx = ctxs[c]; *iface = cr_good_ifaces[i];
                cr_free(b.p);
                return 1;
            }
            cr_free(b.p);
        }
    }
    return 0;
}

TEST(crbuf_enumfuncprov_protocol)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders)); REQUIRE(U(BCryptEnumContextFunctions)); REQUIRE(U(BCryptFreeBuffer));
    static WCHAR fn[128]; const WCHAR *ctx; ULONG iface;
    if (!cr_pick_function(&ctx, &iface, fn, 128)) { t_skip("no configured function found in SSL/Default"); return; }
    g_table = CR_TABLE_LOCAL; g_ctx = ctx; g_iface = iface; g_fn = fn;
    char a[128]; cr_w2a(fn, a, sizeof a);
    t_note("function under test: context %ls interface %s function %s", ctx, cr_iface_name(iface), a);
    cr_protocol("EnumContextFunctionProviders", call_funcprov, val_list, sizeof(CRYPT_CONTEXT_FUNCTION_PROVIDERS));
}
TEST(crbuf_queryfunccfg_protocol)
{
    REQUIRE(U(BCryptQueryContextFunctionConfiguration)); REQUIRE(U(BCryptEnumContextFunctions)); REQUIRE(U(BCryptFreeBuffer));
    static WCHAR fn[128]; const WCHAR *ctx; ULONG iface;
    if (!cr_pick_function(&ctx, &iface, fn, 128)) { t_skip("no configured function found in SSL/Default"); return; }
    g_table = CR_TABLE_LOCAL; g_ctx = ctx; g_iface = iface; g_fn = fn;
    cr_protocol("QueryContextFunctionConfiguration", call_funccfg, val_cfg, sizeof(CRYPT_CONTEXT_FUNCTION_CONFIG));
}
TEST(crbuf_queryreg_protocol_primitive_um)
{
    REQUIRE(U(BCryptQueryProviderRegistration)); REQUIRE(U(BCryptFreeBuffer));
    g_prov = CR_PROVIDER_PRIM; g_mode = CRYPT_UM; g_iface = 0;
    cr_protocol("QueryProviderRegistration(Primitive,UM,all)", call_reg, val_reg, sizeof(CRYPT_PROVIDER_REG));
}
TEST(crbuf_queryreg_protocol_primitive_any_hash)
{
    REQUIRE(U(BCryptQueryProviderRegistration)); REQUIRE(U(BCryptFreeBuffer));
    g_prov = CR_PROVIDER_PRIM; g_mode = CRYPT_ANY; g_iface = CRI_HASH;
    cr_protocol("QueryProviderRegistration(Primitive,ANY,HASH)", call_reg, val_reg, sizeof(CRYPT_PROVIDER_REG));
}
TEST(crbuf_queryreg_protocol_primitive_mm)
{
    REQUIRE(U(BCryptQueryProviderRegistration)); REQUIRE(U(BCryptFreeBuffer));
    g_prov = CR_PROVIDER_PRIM; g_mode = CRYPT_MM; g_iface = 0;
    cr_blk b = cr_query_reg(g_prov, g_mode, g_iface);
    if (b.st != CRS_OK) { t_note("QueryProviderRegistration(Primitive,MM) -> 0x%08lx; protocol not run", (ULONG)b.st); return; }
    cr_free(b.p);
    cr_protocol("QueryProviderRegistration(Primitive,MM,all)", call_reg, val_reg, sizeof(CRYPT_PROVIDER_REG));
}
TEST(crbuf_resolve_protocol_sha256)
{
    REQUIRE(U(BCryptResolveProviders)); REQUIRE(U(BCryptFreeBuffer));
    g_ctx = NULL; g_iface = CRI_HASH; g_fn = L"SHA256"; g_prov = NULL; g_mode = CRYPT_UM; g_flags = 0;
    cr_protocol("ResolveProviders(SHA256)", call_resolve, val_refs, sizeof(CRYPT_PROVIDER_REFS));
}
TEST(crbuf_resolve_protocol_all_hash_functions_all_providers)
{
    REQUIRE(U(BCryptResolveProviders)); REQUIRE(U(BCryptFreeBuffer));
    g_ctx = NULL; g_iface = CRI_HASH; g_fn = NULL; g_prov = NULL; g_mode = CRYPT_UM; g_flags = CRYPT_ALL_FUNCTIONS | CRYPT_ALL_PROVIDERS;
    cr_protocol("ResolveProviders(HASH,*,all)", call_resolve, val_refs, sizeof(CRYPT_PROVIDER_REFS));
}
TEST(crbuf_resolve_protocol_mm_mode)
{
    REQUIRE(U(BCryptResolveProviders)); REQUIRE(U(BCryptFreeBuffer));
    g_ctx = NULL; g_iface = CRI_CIPHER; g_fn = L"AES"; g_prov = NULL; g_mode = CRYPT_MM; g_flags = CRYPT_ALL_PROVIDERS;
    cr_blk b = cr_resolve(g_ctx, g_iface, g_fn, g_prov, g_mode, g_flags);
    if (b.st != CRS_OK) { t_note("ResolveProviders(AES,MM) -> 0x%08lx; protocol not run", (ULONG)b.st); return; }
    cr_free(b.p);
    cr_protocol("ResolveProviders(AES,MM)", call_resolve, val_refs, sizeof(CRYPT_PROVIDER_REFS));
}

/* ---- allocation-mode behaviours that are independent of the API ----------------------------- */
TEST(crbuf_alloc_mode_blocks_are_independent)
{
    REQUIRE(U(BCryptEnumContexts)); REQUIRE(U(BCryptFreeBuffer));
    cr_blk a = cr_enum_contexts(CR_TABLE_LOCAL), b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(a.st, CRS_OK); EXPECT_EQ(b.st, CRS_OK);
    CHECK(a.p && b.p && a.p != b.p);
    EXPECT_EQ(a.cb, b.cb);
    cr_free(a.p);
    /* b stays valid after a is released */
    if (b.p) val_list(b.p, b.cb);
    cr_free(b.p);
}
TEST(crbuf_alloc_mode_block_sized_by_cb)
{
    REQUIRE(U(BCryptEnumRegisteredProviders));
    cr_blk b = cr_enum_providers();
    EXPECT_EQ(b.st, CRS_OK);
    if (b.p) {
        SIZE_T sz = HeapSize(GetProcessHeap(), 0, b.p);
        CHECKF(sz != (SIZE_T)-1 && sz >= b.cb, "heap block %llu bytes, reported %lu", (unsigned long long)sz, b.cb);
        /* the whole reported range is readable */
        volatile BYTE x = 0; for (ULONG i = 0; i < b.cb; i++) x ^= ((BYTE *)b.p)[i];
    }
    cr_free(b.p);
}
TEST(crbuf_alloc_mode_header_is_first_in_block)
{
    REQUIRE(U(BCryptEnumContexts));
    cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.p) {
        const cr_strlist *l = b.p;
        if (l->c) {
            CHECK((const BYTE *)l->v >= (const BYTE *)b.p + sizeof(cr_strlist));
            for (ULONG i = 0; i < l->c; i++) CHECK((const BYTE *)l->v[i] >= (const BYTE *)l->v + (size_t)l->c * sizeof(WCHAR *));
        }
    }
    cr_free(b.p);
}
TEST(crbuf_user_block_is_filled_in_place_and_pointers_target_it)
{
    REQUIRE(U(BCryptEnumContexts));
    ULONG need = 0;
    EXPECT_EQ(U(BCryptEnumContexts)(CR_TABLE_LOCAL, &need, NULL), CRS_OK);
    BYTE *buf = HeapAlloc(GetProcessHeap(), 0, need + 64);
    if (!buf) return;
    memset(buf, 0, need + 64);
    PCRYPT_CONTEXTS p = (PCRYPT_CONTEXTS)buf; ULONG cb = need + 64;
    EXPECT_EQ(U(BCryptEnumContexts)(CR_TABLE_LOCAL, &cb, &p), CRS_OK);
    EXPECT_EQ(p, buf);
    for (ULONG i = 0; i < p->cContexts; i++) CHECK((BYTE *)p->rgpszContexts[i] >= buf && (BYTE *)p->rgpszContexts[i] < buf + need + 64);
    HeapFree(GetProcessHeap(), 0, buf);
}
TEST(crbuf_user_block_copy_is_relocatable_by_size_only)
{
    REQUIRE(U(BCryptEnumRegisteredProviders));
    /* Two caller blocks filled by two calls hold the same strings (content equality, pointers differ). */
    ULONG need = 0;
    EXPECT_EQ(U(BCryptEnumRegisteredProviders)(&need, NULL), CRS_OK);
    BYTE *b1 = HeapAlloc(GetProcessHeap(), 0, need), *b2 = HeapAlloc(GetProcessHeap(), 0, need);
    if (!b1 || !b2) { if (b1) HeapFree(GetProcessHeap(), 0, b1); if (b2) HeapFree(GetProcessHeap(), 0, b2); return; }
    PCRYPT_PROVIDERS p1 = (PCRYPT_PROVIDERS)b1, p2 = (PCRYPT_PROVIDERS)b2; ULONG c1 = need, c2 = need;
    EXPECT_EQ(U(BCryptEnumRegisteredProviders)(&c1, &p1), CRS_OK);
    EXPECT_EQ(U(BCryptEnumRegisteredProviders)(&c2, &p2), CRS_OK);
    EXPECT_EQ(c1, c2);
    EXPECT_EQ(p1->cProviders, p2->cProviders);
    for (ULONG i = 0; i < p1->cProviders && i < p2->cProviders; i++) CHECK(!lstrcmpW(p1->rgpszProviders[i], p2->rgpszProviders[i]));
    HeapFree(GetProcessHeap(), 0, b1); HeapFree(GetProcessHeap(), 0, b2);
}

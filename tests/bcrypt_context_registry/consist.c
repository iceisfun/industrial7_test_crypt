/* Cross-API consistency, concurrency and lifetime of the configuration queries. */
#include "cr.h"

#define NTHREADS 4
#define ITERS 25

static volatile LONG g_fail;
static DWORD WINAPI worker(LPVOID arg)
{
    for (int i = 0; i < ITERS; i++) {
        cr_blk a = cr_enum_contexts(CR_TABLE_LOCAL);
        cr_blk b = cr_enum_providers();
        cr_blk c = cr_resolve(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0);
        cr_blk d = cr_query_reg(CR_PROVIDER_PRIM, CRYPT_UM, CRI_HASH);
        if (a.st != CRS_OK || b.st != CRS_OK || c.st != CRS_OK || d.st != CRS_OK) InterlockedIncrement(&g_fail);
        else {
            if (!cr_list_has(a.p, CRYPT_DEFAULT_CONTEXT) || !cr_list_has(b.p, CR_PROVIDER_PRIM)) InterlockedIncrement(&g_fail);
            if (((CRYPT_PROVIDER_REFS *)c.p)->cProviders < 1) InterlockedIncrement(&g_fail);
        }
        cr_free(a.p); cr_free(b.p); cr_free(c.p); cr_free(d.p);
    }
    return 0;
}
TEST(crcon_concurrent_queries)
{
    REQUIRE(U(BCryptEnumContexts)); REQUIRE(U(BCryptEnumRegisteredProviders)); REQUIRE(U(BCryptResolveProviders)); REQUIRE(U(BCryptQueryProviderRegistration));
    HANDLE th[NTHREADS]; int n = 0;
    g_fail = 0;
    for (int i = 0; i < NTHREADS; i++) { th[n] = CreateThread(NULL, 0, worker, NULL, 0, NULL); if (th[n]) n++; }
    CHECK(n == NTHREADS);
    DWORD w = WaitForMultipleObjects(n, th, TRUE, 60000);
    EXPECT_EQ(w, WAIT_OBJECT_0);
    for (int i = 0; i < n; i++) CloseHandle(th[i]);
    EXPECT_EQ(g_fail, 0);
}
static DWORD WINAPI free_thread(LPVOID arg) { cr_free(arg); return 0; }
TEST(crcon_block_may_be_freed_on_another_thread)
{
    REQUIRE(U(BCryptEnumContexts)); REQUIRE(U(BCryptFreeBuffer));
    cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(b.st, CRS_OK);
    HANDLE th = CreateThread(NULL, 0, free_thread, b.p, 0, NULL);
    if (!th) { cr_free(b.p); return; }
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    CloseHandle(th);
}
TEST(crcon_many_alloc_free_cycles)
{
    REQUIRE(U(BCryptEnumRegisteredProviders)); REQUIRE(U(BCryptFreeBuffer));
    for (int i = 0; i < 300; i++) {
        cr_blk b = cr_enum_providers();
        if (b.st != CRS_OK) { CHECKF(0, "cycle %d: 0x%lx", i, (ULONG)b.st); break; }
        cr_free(b.p);
    }
}
TEST(crcon_memory_does_not_grow_over_cycles)
{
    REQUIRE(U(BCryptEnumContexts)); REQUIRE(U(BCryptFreeBuffer));
    HANDLE heap = GetProcessHeap();
    SIZE_T base = 0, after = 0;
    for (int i = 0; i < 20; i++) { cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL); cr_free(b.p); }   /* warm up */
    PROCESS_HEAP_ENTRY e;
    for (int pass = 0; pass < 2; pass++) {
        SIZE_T used = 0;
        if (!HeapLock(heap)) { t_skip("HeapLock"); return; }
        memset(&e, 0, sizeof e);
        while (HeapWalk(heap, &e)) if (e.wFlags & PROCESS_HEAP_ENTRY_BUSY) used += e.cbData;
        HeapUnlock(heap);
        if (pass == 0) { base = used; for (int i = 0; i < 500; i++) { cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL); cr_free(b.p); } }
        else after = used;
    }
    CHECKF(after < base + 256 * 1024, "busy heap bytes %llu -> %llu", (unsigned long long)base, (unsigned long long)after);
}
TEST(crcon_failed_calls_do_not_leak_blocks)
{
    REQUIRE(U(BCryptResolveProviders));
    HANDLE heap = GetProcessHeap();
    for (int i = 0; i < 10; i++) { cr_blk b = cr_resolve(NULL, CRI_HASH, L"NoSuchHash_cryptt", NULL, CRYPT_UM, 0); cr_free(b.p); }
    SIZE_T used[2] = { 0, 0 };
    for (int pass = 0; pass < 2; pass++) {
        if (!HeapLock(heap)) { t_skip("HeapLock"); return; }
        PROCESS_HEAP_ENTRY e; memset(&e, 0, sizeof e);
        while (HeapWalk(heap, &e)) if (e.wFlags & PROCESS_HEAP_ENTRY_BUSY) used[pass] += e.cbData;
        HeapUnlock(heap);
        if (pass == 0) for (int i = 0; i < 300; i++) { cr_blk b = cr_resolve(NULL, CRI_HASH, L"NoSuchHash_cryptt", NULL, CRYPT_UM, 0); cr_free(b.p); }
    }
    CHECKF(used[1] < used[0] + 256 * 1024, "busy heap bytes %llu -> %llu", (unsigned long long)used[0], (unsigned long long)used[1]);
}
TEST(crcon_registered_providers_cover_resolution_for_default_context)
{
    REQUIRE(U(BCryptEnumRegisteredProviders)); REQUIRE(U(BCryptResolveProviders));
    cr_blk reg = cr_enum_providers();
    EXPECT_EQ(reg.st, CRS_OK);
    for (int i = 0; i < 3; i++) {
        static const struct { ULONG ifc; const WCHAR *fn; } t[] = { { CRI_HASH, L"SHA256" }, { CRI_CIPHER, L"AES" }, { CRI_RNG, L"RNG" } };
        cr_blk b = cr_resolve(NULL, t[i].ifc, t[i].fn, NULL, CRYPT_UM, 0);
        if (b.st == CRS_OK && ((CRYPT_PROVIDER_REFS *)b.p)->cProviders && reg.st == CRS_OK)
            CHECK(cr_list_has(reg.p, ((CRYPT_PROVIDER_REFS *)b.p)->rgpProviders[0]->pszProvider));
        cr_free(b.p);
    }
    cr_free(reg.p);
}
TEST(crcon_open_algorithm_provider_with_resolved_provider)
{
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    static const WCHAR *algs[] = { L"SHA256", L"AES", L"RNG", L"RSA", L"ECDSA_P256", L"PBKDF2" };
    for (int i = 0; i < 6; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NTSTATUS st = U(BCryptOpenAlgorithmProvider)(&h, algs[i], CR_PROVIDER_PRIM, 0);
        CHECKF(st == CRS_OK, "%ls with the Primitive Provider: 0x%lx", algs[i], (ULONG)st);
        if (st == CRS_OK) U(BCryptCloseAlgorithmProvider)(h, 0);
    }
}
TEST(crcon_open_algorithm_provider_with_unregistered_provider)
{
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x55;
    NTSTATUS st = U(BCryptOpenAlgorithmProvider)(&h, L"SHA256", L"NoSuchProvider_cryptt", 0);
    CHECKF(st < 0, "opened with a provider that is not registered: 0x%lx", (ULONG)st);
    t_note("BCryptOpenAlgorithmProvider(SHA256, bogus provider) -> 0x%08lx", (ULONG)st);
    if (st >= 0) U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(crcon_resolve_agrees_with_query_registration_for_each_ref)
{
    REQUIRE(U(BCryptResolveProviders)); REQUIRE(U(BCryptQueryProviderRegistration));
    cr_blk b = cr_resolve(NULL, CRI_HASH, NULL, NULL, CRYPT_UM, CRYPT_ALL_FUNCTIONS | CRYPT_ALL_PROVIDERS);
    EXPECT_EQ(b.st, CRS_OK);
    if (b.st != CRS_OK) return;
    const CRYPT_PROVIDER_REFS *r = b.p;
    for (ULONG i = 0; i < r->cProviders; i++) {
        const CRYPT_PROVIDER_REF *pr = r->rgpProviders[i];
        cr_blk reg = cr_query_reg(pr->pszProvider, CRYPT_UM, CRI_HASH);
        CHECKF(reg.st == CRS_OK, "ref %lu provider %ls: 0x%lx", i, pr->pszProvider, (ULONG)reg.st);
        if (reg.st == CRS_OK && pr->pszFunction && ((CRYPT_PROVIDER_REG *)reg.p)->pUM && !cr_image_has_func(((CRYPT_PROVIDER_REG *)reg.p)->pUM, CRI_HASH, pr->pszFunction))
            t_note("ref %lu: %ls not in provider registration of %ls", i, pr->pszFunction, pr->pszProvider);
        cr_free(reg.p);
    }
    cr_free(b.p);
}

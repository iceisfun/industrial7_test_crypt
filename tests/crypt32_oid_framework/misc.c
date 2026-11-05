/* CryptMem*, async handle stubs, crypt TLS slots, default contexts, file version helper. */
#include "fw.h"
#include <winver.h>

UDECL(DWORD, I_CryptAllocTls, (void));
UDECL(DWORD, I_CryptAllocTlsEx, (void *));
UDECL(void *, I_CryptGetTls, (DWORD));
UDECL(BOOL, I_CryptSetTls, (DWORD, void *));
UDECL(void *, I_CryptDetachTls, (DWORD));
UDECL(BOOL, I_CryptFreeTls, (DWORD, void (WINAPI *)(void *)));
UDECL(BOOL, I_CryptGetFileVersion, (LPCWSTR, DWORD *, DWORD *));

/* ================= CryptMemAlloc / Realloc / Free ================= */
TEST(cryptmem_alloc_nonnull_and_zeroed) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(CryptMemFree));
    static const ULONG sz[] = {1, 2, 7, 8, 15, 16, 17, 255, 256, 4095, 4096, 65536, 1000000};
    for (size_t i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        BYTE *p = U(CryptMemAlloc)(sz[i]);
        CHECKF(p != NULL, "size %lu", sz[i]);
        if (!p) continue;
        int nz = 0;
        for (ULONG k = 0; k < sz[i]; k++) nz |= p[k];
        CHECKF(nz == 0, "size %lu not zero-filled", sz[i]);
        memset(p, 0xA5, sz[i]);
        U(CryptMemFree)(p);
    }
}
TEST(cryptmem_alloc_zero_size_is_valid) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(CryptMemFree));
    void *p = U(CryptMemAlloc)(0);
    CHECK(p != NULL);
    U(CryptMemFree)(p);
}
TEST(cryptmem_alloc_distinct_blocks) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(CryptMemFree));
    void *p[16];
    for (int i = 0; i < 16; i++) { p[i] = U(CryptMemAlloc)(24); CHECK(p[i] != NULL); }
    for (int i = 0; i < 16; i++) for (int j = i + 1; j < 16; j++) CHECK(p[i] != p[j]);
    for (int i = 0; i < 16; i++) U(CryptMemFree)(p[i]);
}
TEST(cryptmem_alloc_is_local_heap_memory) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(LocalSize)); REQUIRE(U(LocalFree));
    void *p = U(CryptMemAlloc)(100);
    CHECK(p != NULL);
    if (!p) return;
    CHECK(U(LocalSize)((HLOCAL)p) >= 100);
    CHECK(U(LocalFree)((HLOCAL)p) == NULL); /* allocated with LocalAlloc: LocalFree is the matching release */
}
TEST(cryptmem_free_accepts_local_alloc_memory) {
    REQUIRE(U(CryptMemFree)); REQUIRE(U(LocalAlloc));
    HLOCAL p = U(LocalAlloc)(LPTR, 64);
    CHECK(p != NULL);
    U(CryptMemFree)(p);
}
TEST(cryptmem_free_null_is_noop) {
    REQUIRE(U(CryptMemFree));
    void (WINAPI *pfree)(void *) = U(CryptMemFree); /* resolve first: a failed module lookup sets last error */
    SET_ERR(0x1357);
    pfree(NULL);
    CHECK(GetLastError() == 0x1357);
}
TEST(cryptmem_free_preserves_last_error) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(CryptMemFree));
    void *p = U(CryptMemAlloc)(32);
    void (WINAPI *pfree)(void *) = U(CryptMemFree);
    SET_ERR(0x2468);
    pfree(p);
    CHECK(GetLastError() == 0x2468);
}
TEST(cryptmem_alloc_preserves_last_error_on_success) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(CryptMemFree));
    void *(WINAPI *palloc)(ULONG) = U(CryptMemAlloc);
    SET_ERR(0x3579);
    void *p = palloc(32);
    DWORD e = GetLastError();
    CHECK(p != NULL);
    CHECKF(e == 0x3579, "last error 0x%lx", e);
    U(CryptMemFree)(p);
}
TEST(cryptmem_realloc_null_allocates) {
    REQUIRE(U(CryptMemRealloc)); REQUIRE(U(CryptMemFree));
    BYTE *p = U(CryptMemRealloc)(NULL, 48);
    CHECK(p != NULL);
    if (p) { memset(p, 0x11, 48); U(CryptMemFree)(p); }
}
TEST(cryptmem_realloc_grow_preserves_content) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(CryptMemRealloc)); REQUIRE(U(CryptMemFree));
    BYTE *p = U(CryptMemAlloc)(40);
    CHECK(p != NULL);
    if (!p) return;
    for (int i = 0; i < 40; i++) p[i] = (BYTE)(i * 7 + 1);
    ULONG steps[] = {41, 100, 4000, 100000};
    for (size_t s = 0; s < 4; s++) {
        BYTE *q = U(CryptMemRealloc)(p, steps[s]);
        CHECKF(q != NULL, "grow to %lu", steps[s]);
        if (!q) break;
        p = q;
        int ok = 1;
        for (int i = 0; i < 40; i++) if (p[i] != (BYTE)(i * 7 + 1)) ok = 0;
        CHECKF(ok, "content preserved at %lu", steps[s]);
    }
    U(CryptMemFree)(p);
}
TEST(cryptmem_realloc_shrink_preserves_prefix) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(CryptMemRealloc)); REQUIRE(U(CryptMemFree));
    BYTE *p = U(CryptMemAlloc)(256);
    CHECK(p != NULL);
    if (!p) return;
    for (int i = 0; i < 256; i++) p[i] = (BYTE)i;
    BYTE *q = U(CryptMemRealloc)(p, 16);
    CHECK(q != NULL);
    if (q) { int ok = 1; for (int i = 0; i < 16; i++) if (q[i] != i) ok = 0; CHECK(ok); U(CryptMemFree)(q); }
    else U(CryptMemFree)(p);
}
TEST(cryptmem_realloc_result_is_freeable_by_cryptmemfree) {
    REQUIRE(U(CryptMemRealloc)); REQUIRE(U(CryptMemFree)); REQUIRE(U(LocalSize));
    BYTE *p = U(CryptMemRealloc)(NULL, 77);
    CHECK(p != NULL);
    if (p) { CHECK(U(LocalSize)((HLOCAL)p) >= 77); U(CryptMemFree)(p); }
}
TEST(cryptmem_many_allocations_roundtrip) {
    REQUIRE(U(CryptMemAlloc)); REQUIRE(U(CryptMemFree));
    static void *p[2000];
    for (int i = 0; i < 2000; i++) { p[i] = U(CryptMemAlloc)(1 + (i % 97)); if (p[i]) memset(p[i], i, 1 + (i % 97)); }
    int bad = 0;
    for (int i = 0; i < 2000; i++) {
        if (!p[i]) { bad++; continue; }
        BYTE *b = p[i];
        for (int k = 0; k < 1 + (i % 97); k++) if (b[k] != (BYTE)i) bad++;
    }
    CHECK(bad == 0);
    for (int i = 0; i < 2000; i++) U(CryptMemFree)(p[i]);
}

/* ================= Async handle API: unimplemented stubs ================= */
#define NOWINE_ASYNC() do { if (t_is_wine()) { t_skip("async handle exports abort under wine"); return; } } while (0)
TEST(cryptasync_create_not_implemented) {
    REQUIRE(U(CryptCreateAsyncHandle)); NOWINE_ASYNC();
    HCRYPTASYNC h = (HCRYPTASYNC)(ULONG_PTR)0x1234;
    SET_ERR(0);
    BOOL r = U(CryptCreateAsyncHandle)(0, &h);
    CHECK(r == FALSE); CHECK(GetLastError() == ERR_NOTIMPL); CHECK(h == NULL);
}
TEST(cryptasync_create_flags_ignored) {
    REQUIRE(U(CryptCreateAsyncHandle)); NOWINE_ASYNC();
    static const DWORD fl[] = {1, 0x80000000, 0xFFFFFFFF};
    for (size_t i = 0; i < 3; i++) {
        HCRYPTASYNC h = (HCRYPTASYNC)(ULONG_PTR)0x1234;
        SET_ERR(0);
        CHECKF(U(CryptCreateAsyncHandle)(fl[i], &h) == FALSE && GetLastError() == ERR_NOTIMPL && h == NULL, "flags 0x%lx", fl[i]);
    }
}
TEST(cryptasync_set_not_implemented) {
    REQUIRE(U(CryptSetAsyncParam)); NOWINE_ASYNC();
    SET_ERR(0);
    BOOL r = U(CryptSetAsyncParam)(NULL, "oid", (void *)1, NULL);
    CHECK(r == FALSE); CHECK(GetLastError() == ERR_NOTIMPL);
    SET_ERR(0);
    r = U(CryptSetAsyncParam)((HCRYPTASYNC)(ULONG_PTR)0x77, NULL, NULL, NULL);
    CHECK(r == FALSE); CHECK(GetLastError() == ERR_NOTIMPL);
}
TEST(cryptasync_get_not_implemented_clears_outputs) {
    REQUIRE(U(CryptGetAsyncParam)); NOWINE_ASYNC();
    LPVOID pv = (LPVOID)(ULONG_PTR)0x99; PFN_CRYPT_ASYNC_PARAM_FREE_FUNC pf = (PFN_CRYPT_ASYNC_PARAM_FREE_FUNC)(ULONG_PTR)0x98;
    SET_ERR(0);
    BOOL r = U(CryptGetAsyncParam)(NULL, "oid", &pv, &pf);
    CHECK(r == FALSE); CHECK(GetLastError() == ERR_NOTIMPL);
    CHECK(pv == NULL); CHECK(pf == NULL);
}
TEST(cryptasync_get_null_outputs_allowed) {
    REQUIRE(U(CryptGetAsyncParam)); NOWINE_ASYNC();
    SET_ERR(0);
    CHECK(U(CryptGetAsyncParam)(NULL, NULL, NULL, NULL) == FALSE);
    CHECK(GetLastError() == ERR_NOTIMPL);
}
TEST(cryptasync_get_only_one_output) {
    REQUIRE(U(CryptGetAsyncParam)); NOWINE_ASYNC();
    LPVOID pv = (LPVOID)(ULONG_PTR)0x99;
    SET_ERR(0);
    CHECK(U(CryptGetAsyncParam)(NULL, NULL, &pv, NULL) == FALSE);
    CHECK(pv == NULL);
    PFN_CRYPT_ASYNC_PARAM_FREE_FUNC pf = (PFN_CRYPT_ASYNC_PARAM_FREE_FUNC)(ULONG_PTR)0x98;
    CHECK(U(CryptGetAsyncParam)(NULL, NULL, NULL, &pf) == FALSE);
    CHECK(pf == NULL);
}
TEST(cryptasync_close_not_implemented) {
    REQUIRE(U(CryptCloseAsyncHandle)); NOWINE_ASYNC();
    SET_ERR(0);
    BOOL r = U(CryptCloseAsyncHandle)(NULL);
    CHECK(r == FALSE); CHECK(GetLastError() == ERR_NOTIMPL);
    SET_ERR(0);
    r = U(CryptCloseAsyncHandle)((HCRYPTASYNC)(ULONG_PTR)0x4321);
    CHECK(r == FALSE); CHECK(GetLastError() == ERR_NOTIMPL);
}

/* ================= crypt32 TLS slots ================= */
TEST(crypttls_alloc_returns_nonzero_distinct) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)(), b = UN(I_CryptAllocTls)(), c = UN(I_CryptAllocTls)();
    CHECK(a && b && c);
    CHECK(a != b && b != c && a != c);
    UN(I_CryptFreeTls)(c, NULL); UN(I_CryptFreeTls)(b, NULL); UN(I_CryptFreeTls)(a, NULL);
}
TEST(crypttls_alloc_ex_null_callback) {
    REQUIRE(UN(I_CryptAllocTlsEx)); REQUIRE(UN(I_CryptFreeTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptGetTls));
    DWORD a = UN(I_CryptAllocTlsEx)(NULL);
    CHECK(a != 0);
    CHECK(UN(I_CryptSetTls)(a, (void *)0x10));
    CHECK(UN(I_CryptGetTls)(a) == (void *)0x10);
    CHECK(UN(I_CryptFreeTls)(a, NULL) == TRUE);
}
TEST(crypttls_fresh_slot_reads_null_and_clears_last_error) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptGetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    SET_ERR(0x4321);
    void *v = UN(I_CryptGetTls)(a);
    CHECK(v == NULL);
    CHECK(GetLastError() == 0);
    UN(I_CryptFreeTls)(a, NULL);
}
TEST(crypttls_set_get_roundtrip) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptGetTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    CHECK(UN(I_CryptSetTls)(a, (void *)0xABCDEF0));
    CHECK(UN(I_CryptGetTls)(a) == (void *)0xABCDEF0);
    CHECK(UN(I_CryptSetTls)(a, (void *)0x1));
    CHECK(UN(I_CryptGetTls)(a) == (void *)0x1);
    CHECK(UN(I_CryptSetTls)(a, NULL));
    SET_ERR(0x99);
    CHECK(UN(I_CryptGetTls)(a) == NULL);
    CHECK(GetLastError() == 0);
    UN(I_CryptFreeTls)(a, NULL);
}
TEST(crypttls_get_nonnull_clears_last_error) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptGetTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0x5);
    void *(WINAPI *pget)(DWORD) = UN(I_CryptGetTls);
    SET_ERR(0x77);
    void *v = pget(a);
    DWORD e = GetLastError();
    CHECK(v == (void *)0x5);
    CHECKF(e == 0, "last error 0x%lx", e); /* probed: success clears it, like TlsGetValue */
    UN(I_CryptSetTls)(a, NULL);
    UN(I_CryptFreeTls)(a, NULL);
}
TEST(crypttls_slots_are_independent) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptGetTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD s[20];
    for (int i = 0; i < 20; i++) { s[i] = UN(I_CryptAllocTls)(); CHECK(s[i] != 0); }
    for (int i = 0; i < 20; i++) CHECK(UN(I_CryptSetTls)(s[i], (void *)(ULONG_PTR)(0x1000 + i)));
    for (int i = 0; i < 20; i++) CHECK(UN(I_CryptGetTls)(s[i]) == (void *)(ULONG_PTR)(0x1000 + i));
    for (int i = 19; i >= 0; i--) CHECK(UN(I_CryptFreeTls)(s[i], NULL));
}
TEST(crypttls_index_zero_invalid) {
    REQUIRE(UN(I_CryptGetTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptDetachTls)); REQUIRE(UN(I_CryptFreeTls));
    SET_ERR(0); CHECK(UN(I_CryptGetTls)(0) == NULL); CHECK(GetLastError() == ERR_INVALIDARG);
    SET_ERR(0); CHECK(UN(I_CryptSetTls)(0, (void *)1) == FALSE); CHECK(GetLastError() == ERR_INVALIDARG);
    SET_ERR(0); CHECK(UN(I_CryptDetachTls)(0) == NULL); CHECK(GetLastError() == ERR_INVALIDARG);
    SET_ERR(0); CHECK(UN(I_CryptFreeTls)(0, NULL) == FALSE); CHECK(GetLastError() == ERR_INVALIDARG);
}
TEST(crypttls_index_never_allocated_invalid) {
    REQUIRE(UN(I_CryptGetTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls));
    SET_ERR(0); CHECK(UN(I_CryptGetTls)(100000) == NULL); CHECK(GetLastError() == ERR_INVALIDARG);
    SET_ERR(0); CHECK(UN(I_CryptSetTls)(100000, (void *)1) == FALSE); CHECK(GetLastError() == ERR_INVALIDARG);
    SET_ERR(0); CHECK(UN(I_CryptFreeTls)(100000, NULL) == FALSE); CHECK(GetLastError() == ERR_INVALIDARG);
    SET_ERR(0); CHECK(UN(I_CryptFreeTls)(0x7FFFFFFF, NULL) == FALSE); CHECK(GetLastError() == ERR_INVALIDARG);
}
TEST(crypttls_free_twice_fails) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    CHECK(UN(I_CryptFreeTls)(a, NULL) == TRUE);
    SET_ERR(0);
    CHECK(UN(I_CryptFreeTls)(a, NULL) == FALSE);
    CHECK(GetLastError() == ERR_INVALIDARG);
}
TEST(crypttls_index_reuse_is_lifo) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)(), b = UN(I_CryptAllocTls)(), c = UN(I_CryptAllocTls)();
    UN(I_CryptFreeTls)(a, NULL);
    UN(I_CryptFreeTls)(c, NULL);
    DWORD n1 = UN(I_CryptAllocTls)(), n2 = UN(I_CryptAllocTls)();
    CHECK(n1 == c); /* most recently freed index first */
    CHECK(n2 == a);
    UN(I_CryptFreeTls)(n1, NULL); UN(I_CryptFreeTls)(n2, NULL); UN(I_CryptFreeTls)(b, NULL);
}
TEST(crypttls_reused_index_starts_empty) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptFreeTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptGetTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0x1234);
    UN(I_CryptFreeTls)(a, NULL);
    DWORD b = UN(I_CryptAllocTls)();
    CHECK(b == a);
    SET_ERR(0x55);
    CHECK(UN(I_CryptGetTls)(b) == NULL);
    UN(I_CryptFreeTls)(b, NULL);
}
static volatile LONG g_free_calls; static void *volatile g_free_vals[8];
static void WINAPI free_cb(void *p) { LONG i = InterlockedIncrement(&g_free_calls) - 1; if (i < 8) g_free_vals[i] = p; }
TEST(crypttls_detach_returns_and_clears) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptDetachTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptGetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0x777);
    CHECK(UN(I_CryptDetachTls)(a) == (void *)0x777);
    SET_ERR(0x31);
    CHECK(UN(I_CryptGetTls)(a) == NULL);
    CHECK(GetLastError() == 0);
    SET_ERR(0x31);
    CHECK(UN(I_CryptDetachTls)(a) == NULL);
    CHECK(GetLastError() == 0);
    UN(I_CryptFreeTls)(a, NULL);
}
TEST(crypttls_detach_prevents_free_callback) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptDetachTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0x777);
    UN(I_CryptDetachTls)(a);
    g_free_calls = 0;
    CHECK(UN(I_CryptFreeTls)(a, free_cb));
    CHECK(g_free_calls == 0);
}
TEST(crypttls_free_invokes_callback_for_value) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0xFACE);
    g_free_calls = 0;
    CHECK(UN(I_CryptFreeTls)(a, free_cb) == TRUE);
    CHECK(g_free_calls == 1);
    CHECK(g_free_vals[0] == (void *)0xFACE);
}
TEST(crypttls_free_skips_callback_for_null_value) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    g_free_calls = 0;
    CHECK(UN(I_CryptFreeTls)(a, free_cb) == TRUE);
    CHECK(g_free_calls == 0);
}
TEST(crypttls_free_clears_value_for_later_get) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls)); REQUIRE(UN(I_CryptGetTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0xBEEF);
    UN(I_CryptFreeTls)(a, NULL);
    CHECK(UN(I_CryptGetTls)(a) == NULL);
}
typedef struct { DWORD idx; HANDLE ready, go; void *val; void *seen_other; } TLSTH;
static DWORD WINAPI tls_thread(void *p) {
    TLSTH *t = p;
    t->seen_other = UN(I_CryptGetTls)(t->idx);              /* must not see the main thread's value */
    UN(I_CryptSetTls)(t->idx, t->val);
    SetEvent(t->ready);
    WaitForSingleObject(t->go, 10000);
    t->seen_other = (void *)((ULONG_PTR)t->seen_other | ((ULONG_PTR)UN(I_CryptGetTls)(t->idx) == (ULONG_PTR)t->val ? 0 : 0x8000000000000000ull));
    return 0;
}
TEST(crypttls_values_are_per_thread) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls)); REQUIRE(UN(I_CryptGetTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0x1111);
    TLSTH t = {a, CreateEventA(NULL, TRUE, FALSE, NULL), CreateEventA(NULL, TRUE, FALSE, NULL), (void *)0x2222, NULL};
    HANDLE h = CreateThread(NULL, 0, tls_thread, &t, 0, NULL);
    CHECK(WaitForSingleObject(t.ready, 10000) == WAIT_OBJECT_0);
    CHECK(UN(I_CryptGetTls)(a) == (void *)0x1111);
    SetEvent(t.go);
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CHECK(t.seen_other == NULL);
    CloseHandle(h); CloseHandle(t.ready); CloseHandle(t.go);
    UN(I_CryptFreeTls)(a, NULL);
}
TEST(crypttls_free_callback_sees_other_threads_values) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0x1111);
    TLSTH t = {a, CreateEventA(NULL, TRUE, FALSE, NULL), CreateEventA(NULL, TRUE, FALSE, NULL), (void *)0x2222, NULL};
    HANDLE h = CreateThread(NULL, 0, tls_thread, &t, 0, NULL);
    CHECK(WaitForSingleObject(t.ready, 10000) == WAIT_OBJECT_0);
    g_free_calls = 0;
    CHECK(UN(I_CryptFreeTls)(a, free_cb) == TRUE);
    CHECK(g_free_calls == 2);
    int s1 = 0, s2 = 0;
    for (int i = 0; i < 2 && i < 8; i++) { if (g_free_vals[i] == (void *)0x1111) s1++; if (g_free_vals[i] == (void *)0x2222) s2++; }
    CHECK(s1 == 1 && s2 == 1);
    SetEvent(t.go);
    WaitForSingleObject(h, 10000);
    CloseHandle(h); CloseHandle(t.ready); CloseHandle(t.go);
}
static DWORD WINAPI tls_get_thread(void *p) { DWORD *a = p; SET_ERR(0x6666); void *v = UN(I_CryptGetTls)(*a); return (v == NULL && GetLastError() == 0) ? 0 : 1; }
TEST(crypttls_new_thread_sees_empty_slot_with_zero_error) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptSetTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD a = UN(I_CryptAllocTls)();
    UN(I_CryptSetTls)(a, (void *)0x4242);
    HANDLE h = CreateThread(NULL, 0, tls_get_thread, &a, 0, NULL);
    DWORD code = 99;
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    GetExitCodeThread(h, &code); CloseHandle(h);
    CHECK(code == 0);
    UN(I_CryptFreeTls)(a, NULL);
}
static DWORD WINAPI tls_late_thread(void *p) {
    /* slot allocated after the thread started */
    HANDLE *ev = p;
    SetEvent(ev[0]);
    WaitForSingleObject(ev[1], 10000);
    DWORD *idx = (DWORD *)ev[2];
    void *v0 = UN(I_CryptGetTls)(*idx);
    BOOL s = UN(I_CryptSetTls)(*idx, (void *)0x88);
    void *v1 = UN(I_CryptGetTls)(*idx);
    return (v0 == NULL && s && v1 == (void *)0x88) ? 0 : 1;
}
TEST(crypttls_slot_allocated_after_thread_start_usable_in_thread) {
    REQUIRE(UN(I_CryptAllocTls)); REQUIRE(UN(I_CryptFreeTls));
    DWORD idx = 0;
    HANDLE ev[3] = {CreateEventA(NULL, TRUE, FALSE, NULL), CreateEventA(NULL, TRUE, FALSE, NULL), (HANDLE)&idx};
    HANDLE h = CreateThread(NULL, 0, tls_late_thread, ev, 0, NULL);
    WaitForSingleObject(ev[0], 10000);
    idx = UN(I_CryptAllocTls)();
    SetEvent(ev[1]);
    DWORD code = 99;
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    GetExitCodeThread(h, &code); CloseHandle(h);
    CHECK(code == 0);
    CloseHandle(ev[0]); CloseHandle(ev[1]);
    UN(I_CryptFreeTls)(idx, NULL);
}

/* ================= CryptInstallDefaultContext ================= */
static HCRYPTPROV acquire_ctx(void) {
    HCRYPTPROV h = 0;
    if (!U(CryptAcquireContextW)) return 0;
    if (!U(CryptAcquireContextW)(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 0;
    return h;
}
static void release_ctx(HCRYPTPROV h) { if (h && U(CryptReleaseContext)) U(CryptReleaseContext)(h, 0); }
#define REQ_DC() do { REQUIRE(U(CryptInstallDefaultContext)); REQUIRE(U(CryptUninstallDefaultContext)); } while (0)

TEST(defctx_uninstall_null_succeeds) {
    REQ_DC();
    SET_ERR(0x42);
    CHECK(U(CryptUninstallDefaultContext)(NULL, 0, NULL) == TRUE);
}
TEST(defctx_install_invalid_type) {
    REQ_DC();
    static const DWORD bad[] = {0, 3, 4, 0xFF, 0xFFFFFFFF};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        HCRYPTDEFAULTCONTEXT h = (HCRYPTDEFAULTCONTEXT)(ULONG_PTR)0x1234;
        SET_ERR(0);
        BOOL r = U(CryptInstallDefaultContext)(0, bad[i], "1.2.3", 0, NULL, &h);
        CHECKF(r == FALSE && GetLastError() == ERR_INVALIDARG && h == NULL, "type 0x%lx: r=%d err=0x%lx", bad[i], r, GetLastError());
    }
}
TEST(defctx_install_multi_oid_count_limits) {
    REQ_DC();
    CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA p;
    LPSTR oids[1] = {"1.2.3.4"};
    p.cOID = 0; p.rgpszOID = oids;
    HCRYPTDEFAULTCONTEXT h = (HCRYPTDEFAULTCONTEXT)(ULONG_PTR)0x1234;
    SET_ERR(0);
    CHECK(U(CryptInstallDefaultContext)(0, CRYPT_DEFAULT_CONTEXT_MULTI_CERT_SIGN_OID, &p, 0, NULL, &h) == FALSE);
    CHECK(GetLastError() == ERR_INVALIDARG); CHECK(h == NULL);
    p.cOID = 0x10000; p.rgpszOID = NULL; h = (HCRYPTDEFAULTCONTEXT)(ULONG_PTR)0x1234;
    SET_ERR(0);
    CHECK(U(CryptInstallDefaultContext)(0, CRYPT_DEFAULT_CONTEXT_MULTI_CERT_SIGN_OID, &p, 0, NULL, &h) == FALSE);
    CHECK(GetLastError() == ERR_INVALIDARG); CHECK(h == NULL);
}
TEST(defctx_install_process_flag_requires_para) {
    REQ_DC();
    HCRYPTDEFAULTCONTEXT h = (HCRYPTDEFAULTCONTEXT)(ULONG_PTR)0x1234;
    SET_ERR(0);
    CHECK(U(CryptInstallDefaultContext)(0, CRYPT_DEFAULT_CONTEXT_CERT_SIGN_OID, NULL, CRYPT_DEFAULT_CONTEXT_PROCESS_FLAG, NULL, &h) == FALSE);
    CHECK(GetLastError() == ERR_INVALIDARG); CHECK(h == NULL);
    h = (HCRYPTDEFAULTCONTEXT)(ULONG_PTR)0x1234;
    SET_ERR(0);
    CHECK(U(CryptInstallDefaultContext)(0, CRYPT_DEFAULT_CONTEXT_MULTI_CERT_SIGN_OID, NULL, CRYPT_DEFAULT_CONTEXT_PROCESS_FLAG, NULL, &h) == FALSE);
    CHECK(GetLastError() == ERR_INVALIDARG); CHECK(h == NULL);
}
TEST(defctx_install_uninstall_thread_single_oid) {
    REQ_DC();
    HCRYPTPROV prov = acquire_ctx();
    if (!prov) { t_skip("cannot acquire verify context"); return; }
    HCRYPTDEFAULTCONTEXT h = NULL;
    BOOL r = U(CryptInstallDefaultContext)(prov, CRYPT_DEFAULT_CONTEXT_CERT_SIGN_OID, "1.2.3.4.cryptt", 0, NULL, &h);
    CHECK(r == TRUE); CHECK(h != NULL);
    if (r) CHECK(U(CryptUninstallDefaultContext)(h, 0, NULL) == TRUE);
    release_ctx(prov);
}
TEST(defctx_install_uninstall_thread_multi_oid) {
    REQ_DC();
    HCRYPTPROV prov = acquire_ctx();
    if (!prov) { t_skip("cannot acquire verify context"); return; }
    LPSTR oids[3] = {"1.2.3.4.cryptt.a", "1.2.3.4.cryptt.b", "1.2.3.4.cryptt.c"};
    CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA p = {3, oids};
    HCRYPTDEFAULTCONTEXT h = NULL;
    BOOL r = U(CryptInstallDefaultContext)(prov, CRYPT_DEFAULT_CONTEXT_MULTI_CERT_SIGN_OID, &p, 0, NULL, &h);
    CHECK(r == TRUE); CHECK(h != NULL);
    memset(oids, 0, sizeof oids); /* the OID strings are copied at install time */
    if (r) CHECK(U(CryptUninstallDefaultContext)(h, 0, NULL) == TRUE);
    release_ctx(prov);
}
TEST(defctx_install_null_para_installs_empty_context) {
    REQ_DC();
    HCRYPTDEFAULTCONTEXT h = NULL;
    BOOL r = U(CryptInstallDefaultContext)(0, CRYPT_DEFAULT_CONTEXT_MULTI_CERT_SIGN_OID, NULL, 0, NULL, &h);
    CHECK(r == TRUE); CHECK(h != NULL);
    if (r) CHECK(U(CryptUninstallDefaultContext)(h, 0, NULL) == TRUE);
}
TEST(defctx_nested_lifo_uninstall) {
    REQ_DC();
    HCRYPTPROV prov = acquire_ctx();
    if (!prov) { t_skip("cannot acquire verify context"); return; }
    HCRYPTDEFAULTCONTEXT h1 = NULL, h2 = NULL, h3 = NULL;
    CHECK(U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.n1", 0, NULL, &h1));
    CHECK(U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.n2", 0, NULL, &h2));
    CHECK(U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.n3", 0, NULL, &h3));
    CHECK(h1 && h2 && h3 && h1 != h2 && h2 != h3 && h1 != h3);
    CHECK(U(CryptUninstallDefaultContext)(h3, 0, NULL));
    CHECK(U(CryptUninstallDefaultContext)(h2, 0, NULL));
    CHECK(U(CryptUninstallDefaultContext)(h1, 0, NULL));
    release_ctx(prov);
}
TEST(defctx_nested_out_of_order_uninstall) {
    REQ_DC();
    HCRYPTPROV prov = acquire_ctx();
    if (!prov) { t_skip("cannot acquire verify context"); return; }
    HCRYPTDEFAULTCONTEXT h1 = NULL, h2 = NULL, h3 = NULL;
    CHECK(U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.o1", 0, NULL, &h1));
    CHECK(U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.o2", 0, NULL, &h2));
    CHECK(U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.o3", 0, NULL, &h3));
    CHECK(U(CryptUninstallDefaultContext)(h2, 0, NULL));
    CHECK(U(CryptUninstallDefaultContext)(h1, 0, NULL));
    CHECK(U(CryptUninstallDefaultContext)(h3, 0, NULL));
    release_ctx(prov);
}
TEST(defctx_reinstall_after_uninstall) {
    REQ_DC();
    HCRYPTPROV prov = acquire_ctx();
    if (!prov) { t_skip("cannot acquire verify context"); return; }
    for (int i = 0; i < 20; i++) {
        HCRYPTDEFAULTCONTEXT h = NULL;
        CHECK(U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.re", 0, NULL, &h));
        CHECK(U(CryptUninstallDefaultContext)(h, 0, NULL));
    }
    release_ctx(prov);
}
static DWORD WINAPI defctx_other_thread(void *p) {
    HCRYPTDEFAULTCONTEXT h = p;
    SET_ERR(0);
    BOOL r = U(CryptUninstallDefaultContext)(h, 0, NULL);
    return (!r && GetLastError() == ERR_INVALIDARG) ? 0 : 1;
}
TEST(defctx_thread_context_cannot_be_uninstalled_by_other_thread) {
    REQ_DC();
    HCRYPTPROV prov = acquire_ctx();
    if (!prov) { t_skip("cannot acquire verify context"); return; }
    HCRYPTDEFAULTCONTEXT h = NULL;
    CHECK(U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.xt", 0, NULL, &h));
    HANDLE th = CreateThread(NULL, 0, defctx_other_thread, h, 0, NULL);
    DWORD code = 9;
    CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0);
    GetExitCodeThread(th, &code); CloseHandle(th);
    CHECK(code == 0);
    CHECK(U(CryptUninstallDefaultContext)(h, 0, NULL));
    release_ctx(prov);
}
static DWORD WINAPI defctx_proc_uninstall_thread(void *p) {
    return U(CryptUninstallDefaultContext)((HCRYPTDEFAULTCONTEXT)p, 0, NULL) ? 0 : 1;
}
TEST(defctx_process_context_uninstalled_from_other_thread) {
    REQ_DC();
    HCRYPTPROV prov = acquire_ctx();
    if (!prov) { t_skip("cannot acquire verify context"); return; }
    HCRYPTDEFAULTCONTEXT h = NULL;
    BOOL r = U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.proc", CRYPT_DEFAULT_CONTEXT_PROCESS_FLAG, NULL, &h);
    CHECK(r == TRUE); CHECK(h != NULL);
    if (r) {
        HANDLE th = CreateThread(NULL, 0, defctx_proc_uninstall_thread, h, 0, NULL);
        DWORD code = 9;
        CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0);
        GetExitCodeThread(th, &code); CloseHandle(th);
        CHECK(code == 0);
    }
    release_ctx(prov);
}
TEST(defctx_flags_unknown_bits_thread_context) {
    REQ_DC();
    HCRYPTPROV prov = acquire_ctx();
    if (!prov) { t_skip("cannot acquire verify context"); return; }
    HCRYPTDEFAULTCONTEXT h = NULL;
    BOOL r = U(CryptInstallDefaultContext)(prov, 1, "1.2.3.cryptt.fl", CRYPT_DEFAULT_CONTEXT_AUTO_RELEASE_FLAG, NULL, &h);
    CHECK(r == TRUE);
    if (r) CHECK(U(CryptUninstallDefaultContext)(h, 0, NULL));
    release_ctx(prov);
}

/* ================= I_CryptGetFileVersion ================= */
TEST(cryptfileversion_system_dll) {
    REQUIRE(UN(I_CryptGetFileVersion));
    WCHAR path[MAX_PATH + 16];
    UINT n = GetSystemDirectoryW(path, MAX_PATH);
    CHECK(n > 0 && n < MAX_PATH);
    lstrcatW(path, L"\\kernel32.dll");
    DWORD ms = 0xdead, ls = 0xdead;
    BOOL r = UN(I_CryptGetFileVersion)(path, &ms, &ls);
    CHECK(r == TRUE);
    CHECK((ms >> 16) >= 6);
    t_note("kernel32.dll version %lu.%lu.%lu.%lu", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff);
}
TEST(cryptfileversion_matches_version_api) {
    REQUIRE(UN(I_CryptGetFileVersion));
    BOOL (WINAPI *pSize)(LPCWSTR, LPDWORD) = NULL;
    HMODULE ver = t_module("version.dll");
    DWORD (WINAPI *pGetSize)(LPCWSTR, LPDWORD) = ver ? (void *)GetProcAddress(ver, "GetFileVersionInfoSizeW") : NULL;
    BOOL (WINAPI *pGet)(LPCWSTR, DWORD, DWORD, LPVOID) = ver ? (void *)GetProcAddress(ver, "GetFileVersionInfoW") : NULL;
    BOOL (WINAPI *pQuery)(LPCVOID, LPCWSTR, LPVOID *, PUINT) = ver ? (void *)GetProcAddress(ver, "VerQueryValueW") : NULL;
    (void)pSize;
    if (!pGetSize || !pGet || !pQuery) { t_skip("version.dll unavailable"); return; }
    WCHAR path[MAX_PATH + 16];
    GetSystemDirectoryW(path, MAX_PATH);
    lstrcatW(path, L"\\crypt32.dll");
    DWORD z; DWORD sz = pGetSize(path, &z);
    CHECK(sz > 0);
    BYTE *buf = HeapAlloc(GetProcessHeap(), 0, sz);
    VS_FIXEDFILEINFO *fi = NULL; UINT fl = 0;
    if (buf && pGet(path, 0, sz, buf) && pQuery(buf, L"\\", (void **)&fi, &fl) && fi) {
        DWORD ms = 0, ls = 0;
        CHECK(UN(I_CryptGetFileVersion)(path, &ms, &ls) == TRUE);
        CHECK(ms == fi->dwFileVersionMS);
        CHECK(ls == fi->dwFileVersionLS);
    } else CHECK(0);
    if (buf) HeapFree(GetProcessHeap(), 0, buf);
}
TEST(cryptfileversion_missing_file) {
    REQUIRE(UN(I_CryptGetFileVersion));
    DWORD ms = 0xdead, ls = 0xbeef;
    BOOL r = UN(I_CryptGetFileVersion)(L"C:\\cryptt-no-such-dir\\none.dll", &ms, &ls);
    CHECK(r == FALSE); CHECK(ms == 0); CHECK(ls == 0);
}
TEST(cryptfileversion_file_without_version_resource) {
    REQUIRE(UN(I_CryptGetFileVersion));
    char a[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(a, sizeof a, "nover.txt");
    HANDLE f = CreateFileA(a, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD wr; WriteFile(f, "hello", 5, &wr, NULL); CloseHandle(f);
    MultiByteToWideChar(CP_ACP, 0, a, -1, w, MAX_PATH);
    DWORD ms = 0xdead, ls = 0xbeef;
    CHECK(UN(I_CryptGetFileVersion)(w, &ms, &ls) == FALSE);
    CHECK(ms == 0 && ls == 0);
}
TEST(cryptfileversion_own_exe_without_version_info) {
    REQUIRE(UN(I_CryptGetFileVersion));
    WCHAR w[MAX_PATH];
    GetModuleFileNameW(NULL, w, MAX_PATH);
    DWORD ms = 0xdead, ls = 0xbeef;
    BOOL r = UN(I_CryptGetFileVersion)(w, &ms, &ls);
    CHECK(r == FALSE); /* the test executable carries no VERSIONINFO resource */
    CHECK(ms == 0 && ls == 0);
}

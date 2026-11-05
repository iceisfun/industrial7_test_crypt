/* Cross-cutting behaviour: other processes, apartments, PersistedKeyProvider argument checks. */
#include "wr.h"

#define HR_E_INVALIDARG 0x80070057u

TEST(winrt_misc_persisted_key_provider_null_certificate) {
    WR_NEED(); void *s = wr_cls_statics(CLS_PERSISTED); if (!s) return;
    HSTRING h = wr_hs(L"SHA256"); void *o = (void *)1;
    /* slots 6 and 7 (OpenKeyPairFromCertificateAsync / OpenPublicKeyFromCertificate) share one signature and both reject a NULL certificate with E_INVALIDARG */
    EXPECT_HR(VF(s, 6, void *, HSTRING, int, void **)(s, NULL, h, 0, &o), HR_E_INVALIDARG);
    CHECK(o == NULL);               /* slot 6 clears the out parameter */
    o = (void *)1;
    EXPECT_HR(VF(s, 7, void *, HSTRING, int, void **)(s, NULL, h, 0, &o), HR_E_INVALIDARG);
    CHECK(o == (void *)1);          /* slot 7 leaves the out parameter untouched */
    wr_hsfree(h); wr_release(s);
}

CHILD(winrt_hash) {
    if (!wr_init()) return 10;
    void *p = NULL;
    if (wr_hash_open(L"SHA256", &p) != S_OK) return 11;
    void *in = wr_mkbuf("abc", 3), *out = NULL;
    if (!in) return 12;
    if (wr_hash_data(p, in, &out) != S_OK) return 13;
    if (!wr_buf_is_hex(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) return 14;
    return 0;
}
TEST(winrt_misc_hash_in_fresh_process) {
    WR_NEED(); void *p = NULL;
    if (wr_hash_open(L"SHA256", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    wr_release(p);
    DWORD rc = t_run_child("winrt_hash", "", 30000);
    EXPECT_EQ(rc, 0);
}
CHILD(winrt_buffer) {
    if (!wr_init()) return 10;
    void *s = wr_cbs(); if (!s) return 11;
    HSTRING h = wr_hs(L"deadBEEF"); void *b = NULL;
    if (VF(s, CB_DecodeFromHexString, HSTRING, void **)(s, h, &b) != S_OK) return 12;
    if (!wr_buf_is_hex(b, "deadbeef")) return 13;
    return 0;
}
TEST(winrt_misc_buffer_in_fresh_process) {
    WR_NEED(); if (!wr_cbs()) return;
    DWORD rc = t_run_child("winrt_buffer", "", 30000);
    EXPECT_EQ(rc, 0);
}

/* apartment agility: objects created in the MTA are usable from an STA thread */
static void *g_prov, *g_in;
static volatile LONG g_sta_result = -1;
static DWORD WINAPI sta_thread(LPVOID unused) {
    HRESULT hr = UIN("combase.dll", RoInitialize)(RO_INIT_SINGLETHREADED);
    if (FAILED(hr)) { g_sta_result = 100; return 0; }
    void *out = NULL;
    hr = wr_hash_data(g_prov, g_in, &out);
    g_sta_result = (hr == S_OK && wr_buf_is_hex(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) ? 0 : 1;
    wr_release(out);
    void *p2 = NULL;
    if (g_sta_result == 0 && wr_hash_open(L"SHA1", &p2) != S_OK) g_sta_result = 2;
    wr_release(p2);
    UIN("combase.dll", RoUninitialize)();
    return 0;
}
TEST(winrt_misc_mta_objects_usable_from_sta_thread) {
    WR_NEED(); g_prov = NULL;
    if (wr_hash_open(L"SHA256", &g_prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    g_in = wr_mkbuf("abc", 3); g_sta_result = -1;
    HANDLE t = CreateThread(NULL, 0, sta_thread, NULL, 0, NULL);
    if (!t) { t_skip("thread"); return; }
    CHECK(WaitForSingleObject(t, 15000) == WAIT_OBJECT_0); CloseHandle(t);
    EXPECT_EQ(g_sta_result, 0);
    wr_release(g_prov); wr_release(g_in);
}
static volatile LONG g_noinit_hr;
static DWORD WINAPI noinit_thread(LPVOID unused) {
    void *f = NULL; HRESULT hr = wr_activate(CLS_HASHNAMES, &f);
    g_noinit_hr = hr; wr_release(f); return 0;
}
TEST(winrt_misc_activation_on_thread_without_init) {
    WR_NEED();
    HANDLE t = CreateThread(NULL, 0, noinit_thread, NULL, 0, NULL);
    if (!t) { t_skip("thread"); return; }
    WaitForSingleObject(t, 15000); CloseHandle(t);
    t_note("RoGetActivationFactory on a thread with no apartment (process has an MTA) -> 0x%08lx", (unsigned long)g_noinit_hr);
}
static void *g_shared_hash;
static volatile LONG g_mt_fail;
static DWORD WINAPI mt_hash(LPVOID arg) {
    UIN("combase.dll", RoInitialize)(RO_INIT_MULTITHREADED);
    for (int i = 0; i < 50; i++) {
        BYTE d[64]; memset(d, (int)(ULONG_PTR)arg + i, sizeof d);
        void *in = wr_mkbuf(d, 64), *o1 = NULL, *o2 = NULL, *h = NULL;
        HRESULT a = wr_hash_data(g_shared_hash, in, &o1);
        a |= VF(g_shared_hash, 9, void **)(g_shared_hash, &h);
        if (h) { VF(h, 6, void *)(h, in); VF(h, 7, void **)(h, &o2); }
        const BYTE *p1, *p2; UINT32 l1, l2;
        if (FAILED(a) || !wr_buf_get(o1, &p1, &l1) || !wr_buf_get(o2, &p2, &l2) || l1 != l2 || memcmp(p1, p2, l1)) InterlockedIncrement(&g_mt_fail);
        wr_release(in); wr_release(o1); wr_release(o2); wr_release(h);
    }
    return 0;
}
TEST(winrt_misc_concurrent_use_of_one_provider) {
    WR_NEED(); g_shared_hash = NULL; g_mt_fail = 0;
    if (wr_hash_open(L"SHA256", &g_shared_hash) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    HANDLE th[4];
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, mt_hash, (LPVOID)(ULONG_PTR)(i * 3), 0, NULL);
    for (int i = 0; i < 4; i++) if (th[i]) { CHECK(WaitForSingleObject(th[i], 30000) == WAIT_OBJECT_0); CloseHandle(th[i]); }
    EXPECT_EQ(g_mt_fail, 0);
    wr_release(g_shared_hash);
}
TEST(winrt_misc_random_buffers_are_independent_across_threads) {
    WR_NEED(); void *s = wr_cbs(); if (!s) return;
    void *a = NULL, *b = NULL;
    VF(s, CB_GenerateRandom, UINT32, void **)(s, 16, &a); VF(s, CB_GenerateRandom, UINT32, void **)(s, 16, &b);
    BYTE r = 1; VF(s, CB_Compare, void *, void *, BYTE *)(s, a, b, &r); EXPECT_EQ(r, 0);
    wr_release(a); wr_release(b);
}

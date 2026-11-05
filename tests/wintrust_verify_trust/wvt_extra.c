/* Catalog subject (negative / cache paths), concurrency and cross-process behaviour. */
#include "wvt.h"

static void cat_data(WVTD *w, WINTRUST_CATALOG_INFO *ci, const WCHAR *cat, const WCHAR *tag, const WCHAR *member) {
    memset(w, 0, sizeof *w); memset(ci, 0, sizeof *ci);
    ci->cbStruct = sizeof *ci; ci->pcwszCatalogFilePath = cat; ci->pcwszMemberTag = tag; ci->pcwszMemberFilePath = member;
    w->d.cbStruct = sizeof *w; w->d.dwUIChoice = WTD_UI_NONE; w->d.dwUnionChoice = WTD_CHOICE_CATALOG; w->d.pCatalog = ci;
    w->d.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL; w->d.dwStateAction = WTD_STATEACTION_IGNORE;
}

TEST(wvt_catalog_missing_catalog_file) {
    WVT_REQUIRE_WVT();
    WCHAR cat[MAX_PATH], pe[MAX_PATH]; wvt_path(cat, "none.cat"); wvt_del(cat); wvt_path(pe, "m1.exe"); wvt_write(pe, fix_pe_unsigned, sizeof fix_pe_unsigned);
    WVTD w; WINTRUST_CATALOG_INFO ci; cat_data(&w, &ci, cat, L"TAG", pe);
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    t_note("missing catalog file -> 0x%08lx", (unsigned long)r);
    CHECK(r != 0); EXPECT_EQ((DWORD)r, e);
    wvt_del(pe);
}
TEST(wvt_catalog_missing_member_file) {
    WVT_REQUIRE_WVT();
    WCHAR cat[MAX_PATH], pe[MAX_PATH]; wvt_path(cat, "c2.cat"); wvt_write(cat, "junk", 4); wvt_path(pe, "m2.exe"); wvt_del(pe);
    WVTD w; WINTRUST_CATALOG_INFO ci; cat_data(&w, &ci, cat, L"TAG", pe);
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    t_note("missing member file -> 0x%08lx", (unsigned long)r);
    CHECK(r != 0);
    wvt_del(cat);
}
TEST(wvt_catalog_garbage_catalog) {
    WVT_REQUIRE_WVT();
    WCHAR cat[MAX_PATH], pe[MAX_PATH]; wvt_path(cat, "c3.cat"); wvt_write(cat, "this is not a catalog", 21);
    wvt_path(pe, "m3.exe"); wvt_write(pe, fix_pe_unsigned, sizeof fix_pe_unsigned);
    WVTD w; WINTRUST_CATALOG_INFO ci; cat_data(&w, &ci, cat, L"TAG", pe);
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    t_note("garbage catalog -> 0x%08lx", (unsigned long)r);
    CHECK(r != 0);
    wvt_del(cat); wvt_del(pe);
}
TEST(wvt_catalog_null_member_tag_and_path) {
    WVT_REQUIRE_WVT();
    WCHAR cat[MAX_PATH]; wvt_path(cat, "c4.cat"); wvt_write(cat, "junk", 4);
    WVTD w; WINTRUST_CATALOG_INFO ci; cat_data(&w, &ci, cat, NULL, NULL);
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    t_note("catalog subject with no tag and no member -> 0x%08lx", (unsigned long)r);
    CHECK(r != 0);
    wvt_del(cat);
}
TEST(wvt_catalog_state_returned_on_failure) {
    WVT_REQUIRE_WVT();
    WCHAR cat[MAX_PATH], pe[MAX_PATH]; wvt_path(cat, "c5.cat"); wvt_write(cat, "junk", 4);
    wvt_path(pe, "m5.exe"); wvt_write(pe, fix_pe_unsigned, sizeof fix_pe_unsigned);
    WVTD w; WINTRUST_CATALOG_INFO ci; cat_data(&w, &ci, cat, L"TAG", pe); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    CHECK(r != 0);
    t_note("state handle after failed catalog verify: %p", w.d.hWVTStateData);
    if (w.d.hWVTStateData) { CHECK(wvt_close(&WVT_V2, &w) == 0); CHECK(w.d.hWVTStateData == NULL); }
    wvt_del(cat); wvt_del(pe);
}
TEST(wvt_catalog_auto_cache_repeat_is_stable) {
    WVT_REQUIRE_WVT();
    WCHAR cat[MAX_PATH], pe[MAX_PATH]; wvt_path(cat, "c6.cat"); wvt_write(cat, "junk", 4);
    wvt_path(pe, "m6.exe"); wvt_write(pe, fix_pe_unsigned, sizeof fix_pe_unsigned);
    LONG first = 0;
    for (int i = 0; i < 3; i++) {
        WVTD w; WINTRUST_CATALOG_INFO ci; cat_data(&w, &ci, cat, L"TAG", pe); w.d.dwStateAction = WTD_STATEACTION_AUTO_CACHE;
        DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
        if (i == 0) first = r; else CHECK(r == first);
        CHECK(r != 0);
        CHECK(w.d.dwStateAction == WTD_STATEACTION_AUTO_CACHE);
    }
    WVTD w; WINTRUST_CATALOG_INFO ci; cat_data(&w, &ci, cat, L"TAG", pe); w.d.dwStateAction = WTD_STATEACTION_AUTO_CACHE_FLUSH;
    EXPECT_EQ(U(WinVerifyTrust)(NULL, (GUID *)&WVT_V2, &w), 0);
    wvt_del(cat); wvt_del(pe);
}
TEST(wvt_catalog_auto_cache_with_file_choice_is_plain_verify) {
    /* AUTO_CACHE is only special for the catalog union; with a file subject it is not VERIFY/CLOSE so no state is returned */
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "ac.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_AUTO_CACHE; DWORD e;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    t_note("AUTO_CACHE with file subject -> 0x%08lx state=%p", (unsigned long)r, w.d.hWVTStateData);
    CHECK(w.d.hWVTStateData == NULL);
    wvt_del(p);
}
TEST(wvt_catalog_v1_hash_calc_shape) {
    /* the catalog subject normally carries the member hash: calculate it with the catalog admin API (SHA-1 default) */
    BOOL (WINAPI *calc)(HANDLE, DWORD *, BYTE *, DWORD) = (void *)t_proc("CryptCATAdminCalcHashFromFileHandle"); REQUIRE(calc);
    WCHAR pe[MAX_PATH]; wvt_path(pe, "hh.exe"); wvt_write(pe, fix_pe_unsigned, sizeof fix_pe_unsigned);
    HANDLE h = CreateFileW(pe, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD cb = 0; SET_ERR(0);
    BOOL qr = calc(h, &cb, NULL, 0); t_note("size query: ret=%d err=%lu cb=%lu", qr, (unsigned long)GetLastError(), (unsigned long)cb);
    EXPECT_EQ(cb, 20);
    BYTE hash[20]; cb = 20; CHECK(calc(h, &cb, hash, 0)); EXPECT_EQ(cb, 20);
    /* Authenticode SHA-1 over the same image regions */
    BYTE h1[20]; BYTE *img = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sizeof fix_pe_unsigned); memcpy(img, fix_pe_unsigned, sizeof fix_pe_unsigned);
    HCRYPTPROV prov = 0; HCRYPTHASH hh = 0;
    if (U(CryptAcquireContextW)(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) && U(CryptCreateHash)(prov, CALG_SHA1, 0, 0, &hh)) {
        U(CryptHashData)(hh, img, 0x58 + 64, 0); U(CryptHashData)(hh, img + 0x58 + 68, 0x58 + 112 + 32 - (0x58 + 68), 0);
        U(CryptHashData)(hh, img + 0x58 + 112 + 40, 0x200 - (0x58 + 112 + 40), 0); U(CryptHashData)(hh, img + 0x200, 0x200, 0);
        DWORD n = 20; U(CryptGetHashParam)(hh, HP_HASHVAL, h1, &n, 0);
        CHECK(!memcmp(h1, hash, 20));
    }
    if (hh) U(CryptDestroyHash)(hh); if (prov) U(CryptReleaseContext)(prov, 0);
    HeapFree(GetProcessHeap(), 0, img); CloseHandle(h); wvt_del(pe);
}

/* ---- concurrency / processes ------------------------------------------------------------------------ */
typedef struct { const WCHAR *path; LONG want; volatile LONG bad; int loops; } WORK;
static DWORD WINAPI worker(LPVOID p) {
    WORK *w = (WORK *)p;
    for (int i = 0; i < w->loops; i++) {
        WVTD d; WINTRUST_FILE_INFO fi; wvt_init_file(&d, &fi, w->path); d.d.dwStateAction = (i & 1) ? WTD_STATEACTION_VERIFY : WTD_STATEACTION_IGNORE;
        LONG r = U(WinVerifyTrust)(NULL, (GUID *)&WVT_V2, &d);
        if (r != w->want) InterlockedIncrement(&w->bad);
        if (d.d.dwStateAction == WTD_STATEACTION_VERIFY) { d.d.dwStateAction = WTD_STATEACTION_CLOSE; U(WinVerifyTrust)(NULL, (GUID *)&WVT_V2, &d); }
    }
    return 0;
}
TEST(wvt_threads_concurrent_verification) {
    WVT_REQUIRE_WVT();
    WCHAR ps[MAX_PATH], pu[MAX_PATH]; wvt_path(ps, "th1.exe"); wvt_write(ps, fix_pe_signed, sizeof fix_pe_signed);
    wvt_path(pu, "th2.exe"); wvt_write(pu, fix_pe_unsigned, sizeof fix_pe_unsigned);
    WORK w[4] = { { ps, WVT_E_UNTRUSTEDROOT, 0, 15 }, { pu, WVT_E_NOSIGNATURE, 0, 15 }, { ps, WVT_E_UNTRUSTEDROOT, 0, 15 }, { pu, WVT_E_NOSIGNATURE, 0, 15 } };
    HANDLE th[4];
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, worker, &w[i], 0, NULL);
    DWORD wr = WaitForMultipleObjects(4, th, TRUE, 60000);
    CHECK(wr == WAIT_OBJECT_0);
    if (wr != WAIT_OBJECT_0) { for (int i = 0; i < 4; i++) TerminateThread(th[i], 1); }
    for (int i = 0; i < 4; i++) { CHECKF(w[i].bad == 0, "thread %d saw %ld unexpected results", i, (long)w[i].bad); CloseHandle(th[i]); }
    wvt_del(ps); wvt_del(pu);
}
static DWORD WINAPI closer(LPVOID p) {
    WVTD *d = (WVTD *)p; d->d.dwStateAction = WTD_STATEACTION_CLOSE;
    return (DWORD)U(WinVerifyTrust)(NULL, (GUID *)&WVT_V2, d);
}
TEST(wvt_state_closed_on_other_thread) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; wvt_path(p, "ot.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY; EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_UNTRUSTEDROOT);
    CHECK(w.d.hWVTStateData != NULL);
    HANDLE t = CreateThread(NULL, 0, closer, &w, 0, NULL);
    CHECK(WaitForSingleObject(t, 20000) == WAIT_OBJECT_0);
    DWORD rc = 99; GetExitCodeThread(t, &rc); CloseHandle(t);
    EXPECT_EQ(rc, 0); CHECK(w.d.hWVTStateData == NULL);
    wvt_del(p);
}
CHILD(wvt_child_verify) {
    WCHAR p[MAX_PATH]; wvt_path(p, "child.exe");
    int mode = argc > 0 ? atoi(argv[0]) : 0;
    wvt_write(p, mode ? fix_pe_signed : fix_pe_unsigned, mode ? sizeof fix_pe_signed : sizeof fix_pe_unsigned);
    WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); DWORD e;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    wvt_del(p);
    if (mode) return (r == WVT_E_UNTRUSTEDROOT && e == (DWORD)r) ? 0 : 1;
    return (r == WVT_E_NOSIGNATURE && e == (DWORD)r) ? 0 : 2;
}
TEST(wvt_child_process_signed) { WVT_REQUIRE_WVT(); EXPECT_EQ(t_run_child("wvt_child_verify", "1", 60000), 0); }
TEST(wvt_child_process_unsigned) { WVT_REQUIRE_WVT(); EXPECT_EQ(t_run_child("wvt_child_verify", "0", 60000), 0); }

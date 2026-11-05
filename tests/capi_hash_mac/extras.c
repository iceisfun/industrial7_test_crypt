/* Cross-module (advapi32 thunks vs cryptsp), threading and length-sweep tests for CryptoAPI hashing. */
#include "h.h"

static const ALG_ID g_all[] = { CALG_MD2, CALG_MD4, CALG_MD5, CALG_SHA1, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512 };
#define NALL (sizeof g_all / sizeof g_all[0])

/* ---- the same flow through each pinned module --------------------------- */
#define PIN_FLOW(MOD, SUFFIX) \
TEST(capi_hash_pinned_##SUFFIX##_flow) { \
    HMODULE m = t_module(MOD); if (!m) { t_skip("no " MOD); return; } \
    BOOL (WINAPI *acq)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD) = (void *)GetProcAddress(m, "CryptAcquireContextA"); \
    BOOL (WINAPI *rel)(HCRYPTPROV, DWORD) = (void *)GetProcAddress(m, "CryptReleaseContext"); \
    BOOL (WINAPI *cr)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH *) = (void *)GetProcAddress(m, "CryptCreateHash"); \
    BOOL (WINAPI *hd)(HCRYPTHASH, const BYTE *, DWORD, DWORD) = (void *)GetProcAddress(m, "CryptHashData"); \
    BOOL (WINAPI *gp)(HCRYPTHASH, DWORD, BYTE *, DWORD *, DWORD) = (void *)GetProcAddress(m, "CryptGetHashParam"); \
    BOOL (WINAPI *dh)(HCRYPTHASH, HCRYPTHASH *, DWORD, HCRYPTHASH *) = (void *)GetProcAddress(m, "CryptDuplicateHash"); \
    BOOL (WINAPI *de)(HCRYPTHASH) = (void *)GetProcAddress(m, "CryptDestroyHash"); \
    if (!acq || !rel || !cr || !hd || !gp || !dh || !de) { t_skip("missing export in " MOD); return; } \
    HCRYPTPROV p = 0; HCRYPTHASH h = 0, d = 0; BYTE o[32]; DWORD ol = 32, a = 0; \
    CHECK(acq(&p, NULL, PROVNAME_AES, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)); if (!p) return; \
    CHECK(cr(p, CALG_SHA_256, 0, 0, &h)); \
    CHECK(hd(h, (const BYTE *)"abc", 3, 0)); \
    SET_ERR(0); CHECK(!cr(p, CALG_SHA_256, 0, 7, &d)); EXPECT_ERR(E_NTE_BAD_FLAGS); \
    CHECK(dh(h, NULL, 0, &d)); \
    ol = 4; CHECK(gp(h, HP_ALGID, (BYTE *)&a, &ol, 0)); CHECK(a == CALG_SHA_256); \
    ol = 32; CHECK(gp(h, HP_HASHVAL, o, &ol, 0)); \
    EXPECT_HEX(o, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); \
    SET_ERR(0); CHECK(!hd(h, (const BYTE *)"x", 1, 0)); EXPECT_ERR(E_NTE_BAD_HASH_STATE); \
    CHECK(hd(d, (const BYTE *)"d", 1, 0)); \
    CHECK(de(h)); CHECK(de(d)); CHECK(rel(p, 0)); }
PIN_FLOW("advapi32.dll", advapi32)
PIN_FLOW("cryptsp.dll", cryptsp)

TEST(capi_hash_cross_module_handle_use) {
    HMODULE a = t_module("advapi32.dll"), s = t_module("cryptsp.dll"); if (!a || !s) { t_skip("module missing"); return; }
    BOOL (WINAPI *cr)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH *) = (void *)GetProcAddress(a, "CryptCreateHash");
    BOOL (WINAPI *de)(HCRYPTHASH) = (void *)GetProcAddress(s, "CryptDestroyHash");
    BOOL (WINAPI *gp)(HCRYPTHASH, DWORD, BYTE *, DWORD *, DWORD) = (void *)GetProcAddress(s, "CryptGetHashParam");
    if (!cr || !de || !gp) { t_skip("missing export"); return; }
    HCRYPTPROV p = h_acq_aes(); if (!p) return; HCRYPTHASH h = 0; DWORD v = 0, dl = 4;
    /* advapi32's Crypt* entry points are thin jumps into cryptsp, so the handles are interchangeable */
    CHECK(cr(p, CALG_MD5, 0, 0, &h));
    CHECK(gp(h, HP_ALGID, (BYTE *)&v, &dl, 0)); CHECK(v == CALG_MD5);
    CHECK(de(h)); h_rel(p);
}

/* ---- length sweep: incremental feeds in different chunkings agree ---------- */
TEST(capi_hash_length_sweep_chunking_consistent) {
    REQUIRE(U(CryptCreateHash)); HCRYPTPROV p = h_acq_aes(); if (!p) return; size_t ai; DWORD n;
    __typeof__(&CryptCreateHash) cr = U(CryptCreateHash); __typeof__(&CryptHashData) hd = U(CryptHashData);
    __typeof__(&CryptGetHashParam) gp = U(CryptGetHashParam); __typeof__(&CryptDestroyHash) de = U(CryptDestroyHash);
    BYTE buf[300]; for (n = 0; n < sizeof buf; n++) buf[n] = (BYTE)(n * 13 + 5);
    for (ai = 0; ai < NALL; ai++) {
        for (n = 0; n <= 300; n += (n < 140 ? 1 : 13)) {
            BYTE a[64], b[64], c[64]; DWORD la = 64, lb = 64, lc = 64, off; HCRYPTHASH h = 0;
            cr(p, g_all[ai], 0, 0, &h); if (n) hd(h, buf, n, 0); gp(h, HP_HASHVAL, a, &la, 0); de(h);
            cr(p, g_all[ai], 0, 0, &h);
            for (off = 0; off < n; off++) hd(h, buf + off, 1, 0);
            gp(h, HP_HASHVAL, b, &lb, 0); de(h);
            cr(p, g_all[ai], 0, 0, &h);
            hd(h, buf, n / 3, 0); hd(h, buf + n / 3, n - n / 3, 0);
            gp(h, HP_HASHVAL, c, &lc, 0); de(h);
            CHECKF(la == h_digest_len(g_all[ai]) && la == lb && la == lc && !memcmp(a, b, la) && !memcmp(a, c, la), "alg 0x%lx n %lu chunking differs", g_all[ai], n);
        }
    }
    h_rel(p);
}
TEST(capi_hash_distinct_digests_across_algs_same_input) {
    REQUIRE(U(CryptCreateHash)); HCRYPTPROV p = h_acq_aes(); if (!p) return; size_t i;
    char hx[NALL][140];
    for (i = 0; i < NALL; i++) { BYTE d[64]; DWORD dl = 64; CHECK(h_hash(p, g_all[i], (const BYTE *)"abc", 3, d, &dl)); h_bin2hex(d, dl, hx[i]); CHECK(dl == h_digest_len(g_all[i])); }
    for (i = 1; i < NALL; i++) CHECK(strcmp(hx[i], hx[i - 1]) != 0);
    h_rel(p);
}
TEST(capi_hash_unaligned_buffer) {
    REQUIRE(U(CryptCreateHash)); HCRYPTPROV p = h_acq_aes(); if (!p) return; int off;
    BYTE raw[80]; BYTE d[20]; DWORD dl;
    for (off = 0; off < 8; off++) {
        memcpy(raw + off, "abc", 3); dl = 20;
        CHECKF(h_hash(p, CALG_SHA1, raw + off, 3, d, &dl), "off %d", off);
        EXPECT_HEX(d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
    h_rel(p);
}

/* ---- threads --------------------------------------------------------------- */
typedef struct { HCRYPTPROV shared; int ok; int iters; } thr_t;
static DWORD WINAPI thr_main(LPVOID arg) {
    thr_t *t = (thr_t *)arg; int i; t->ok = 1;
    HCRYPTPROV p = t->shared ? t->shared : h_acq_aes();
    if (!p) { t->ok = 0; return 0; }
    for (i = 0; i < t->iters; i++) {
        HCRYPTHASH h = 0; BYTE d[32]; DWORD dl = 32;
        if (!U(CryptCreateHash)(p, CALG_SHA_256, 0, 0, &h)) { t->ok = 0; break; }
        if (!U(CryptHashData)(h, (const BYTE *)"abc", 3, 0) || !U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0)) t->ok = 0;
        else {
            static const BYTE e[32] = { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
                0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
            if (dl != 32 || memcmp(d, e, 32)) t->ok = 0;
        }
        U(CryptDestroyHash)(h);
    }
    if (!t->shared) h_rel(p);
    return 0;
}
static void run_threads(HCRYPTPROV shared) {
    HANDLE th[4]; thr_t t[4]; int i;
    for (i = 0; i < 4; i++) { t[i].shared = shared; t[i].ok = 0; t[i].iters = 200; th[i] = CreateThread(NULL, 0, thr_main, &t[i], 0, NULL); }
    DWORD w = WaitForMultipleObjects(4, th, TRUE, 30000);
    CHECK(w == WAIT_OBJECT_0);
    for (i = 0; i < 4; i++) { if (w == WAIT_OBJECT_0) CHECKF(t[i].ok, "thread %d", i); CloseHandle(th[i]); }
}
TEST(capi_hash_threads_own_providers) { REQUIRE(U(CryptCreateHash)); run_threads(0); }
TEST(capi_hash_threads_shared_provider) {
    REQUIRE(U(CryptCreateHash)); HCRYPTPROV p = h_acq_aes(); if (!p) return; run_threads(p); h_rel(p);
}
static DWORD WINAPI thr_use_hash(LPVOID arg) {
    HCRYPTHASH h = (HCRYPTHASH)arg; BYTE d[20]; DWORD dl = 20;
    if (!U(CryptHashData)(h, (const BYTE *)"bc", 2, 0)) return 1;
    if (!U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0)) return 2;
    static const BYTE e[20] = { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d };
    return memcmp(d, e, 20) ? 3 : 0;
}
TEST(capi_hash_handle_usable_from_other_thread) {
    REQUIRE(U(CryptCreateHash)); HCRYPTPROV p = h_acq_aes(); if (!p) return; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h)); CHECK(U(CryptHashData)(h, (const BYTE *)"a", 1, 0));
    HANDLE t = CreateThread(NULL, 0, thr_use_hash, (LPVOID)h, 0, NULL); DWORD code = 99;
    if (t) { CHECK(WaitForSingleObject(t, 20000) == WAIT_OBJECT_0); GetExitCodeThread(t, &code); CloseHandle(t); }
    CHECKF(code == 0, "thread result %lu", code);
    U(CryptDestroyHash)(h); h_rel(p);
}

/* ---- review additions: duplicate independence and known answers over the duplicate */
TEST(capi_hash_review_duplicate_diverges_independently) {
    REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptDuplicateHash)); REQUIRE(U(CryptGetHashParam));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    HCRYPTHASH a = 0, b = 0; BYTE da[20], db[20]; DWORD la = 20, lb = 20; char hx[64];
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &a));
    CHECK(U(CryptHashData)(a, (const BYTE *)"a", 1, 0));
    CHECK(U(CryptDuplicateHash)(a, NULL, 0, &b));
    CHECK(U(CryptHashData)(a, (const BYTE *)"bc", 2, 0));
    CHECK(U(CryptHashData)(b, (const BYTE *)"bc", 2, 0));
    CHECK(U(CryptGetHashParam)(a, HP_HASHVAL, da, &la, 0));
    CHECK(U(CryptGetHashParam)(b, HP_HASHVAL, db, &lb, 0));
    CHECK(la == 20 && lb == 20 && !memcmp(da, db, 20));
    h_bin2hex(da, 20, hx);
    CHECK(!strcmp(hx, "a9993e364706816aba3e25717850c26c9cd0d89d")); /* SHA-1("abc") */
    U(CryptDestroyHash)(a); U(CryptDestroyHash)(b);
    U(CryptReleaseContext)(p, 0);
}
TEST(capi_hash_review_empty_hashdata_then_value) {
    REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptHashData)); REQUIRE(U(CryptGetHashParam));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    HCRYPTHASH h = 0; BYTE d[16]; DWORD l = 16; char hx[64];
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"", 0, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &l, 0));
    h_bin2hex(d, 16, hx);
    CHECK(l == 16 && !strcmp(hx, "d41d8cd98f00b204e9800998ecf8427e")); /* RFC 1321 empty */
    U(CryptDestroyHash)(h);
    U(CryptReleaseContext)(p, 0);
}

/* mssign32 Pvk* functions working on a file handle / file name, plus PvkGetCryptProv / PvkFreeCryptProv.
 * PvkPrivateKeySave* to a file is not exercised: it always asks for a password through a modal dialog. */
#include "mssfix.h"

static HANDLE open_ro(const char *p) {
    return CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}
static int have_key(HCRYPTPROV h, DWORD spec) {
    HCRYPTKEY k = 0;
    if (!U(CryptGetUserKey)(h, spec, &k)) return 0;
    U(CryptDestroyKey)(k);
    return 1;
}
static int mkpvk(char *path, size_t cap, const char *leaf, int which, int spec) {
    BYTE pvk[2048]; DWORD n = fx_pvk(which, spec, 0, 0, pvk, sizeof pvk);
    t_tmpfile(path, cap, leaf);
    return fx_write_file(path, pvk, n);
}

TEST(mssigner_pvkfile_load_w) {
    PvkPrivateKeyLoad_pfn fn = UN(PvkPrivateKeyLoad); REQUIRE(fn);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    char p[MAX_PATH]; CHECK(mkpvk(p, sizeof p, "k1.pvk", FX_A, 1));
    HANDLE h = open_ro(p);
    DWORD spec = 0;
    BOOL r = fn(f.hProv, h, NULL, NULL, 0, &spec);
    CHECK(r);
    EXPECT_EQ(spec, 1);
    CHECK(have_key(f.hProv, AT_KEYEXCHANGE));
    DWORD pos = SetFilePointer(h, 0, NULL, FILE_CURRENT);
    EXPECT_EQ(pos, 24 + 1172);        /* the file is consumed up to the end of the key blob */
    CloseHandle(h); DeleteFileA(p); fx_close(&f);
}
TEST(mssigner_pvkfile_load_a) {
    PvkPrivateKeyLoadA_pfn fn = UN(PvkPrivateKeyLoadA); REQUIRE(fn);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    char p[MAX_PATH]; CHECK(mkpvk(p, sizeof p, "k2.pvk", FX_A, 2));
    HANDLE h = open_ro(p);
    DWORD spec = 0;
    CHECK(fn(f.hProv, h, NULL, NULL, 0, &spec));
    EXPECT_EQ(spec, 2);
    CHECK(have_key(f.hProv, AT_SIGNATURE));
    CloseHandle(h); DeleteFileA(p); fx_close(&f);
}
TEST(mssigner_pvkfile_load_keyspec_mismatch) {
    PvkPrivateKeyLoad_pfn fn = UN(PvkPrivateKeyLoad); REQUIRE(fn);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    char p[MAX_PATH]; CHECK(mkpvk(p, sizeof p, "k3.pvk", FX_B, 1));
    HANDLE h = open_ro(p);
    DWORD spec = 2;
    SET_ERR(0);
    CHECK(!fn(f.hProv, h, NULL, NULL, 0, &spec));
    EXPECT_ERR(PVK_E_WRONGTYPE);
    EXPECT_EQ(spec, 1);
    CloseHandle(h); DeleteFileA(p); fx_close(&f);
}
TEST(mssigner_pvkfile_load_invalid_handles) {
    PvkPrivateKeyLoad_pfn fn = UN(PvkPrivateKeyLoad); REQUIRE(fn);
    PvkPrivateKeyLoadA_pfn fa = UN(PvkPrivateKeyLoadA); REQUIRE(fa);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    HANDLE hs[2] = { INVALID_HANDLE_VALUE, NULL };
    for (int i = 0; i < 2; i++) {
        DWORD spec = 1;
        SET_ERR(0);
        CHECK(!fn(f.hProv, hs[i], NULL, NULL, 0, &spec));
        EXPECT_ERR(PVK_E_BADFILE);
        EXPECT_EQ(spec, 0);
        spec = 1;
        SET_ERR(0);
        CHECK(!fa(f.hProv, hs[i], NULL, NULL, 0, &spec));
        EXPECT_ERR(PVK_E_BADFILE);
        EXPECT_EQ(spec, 0);
    }
    fx_close(&f);
}
TEST(mssigner_pvkfile_load_empty_file) {
    PvkPrivateKeyLoad_pfn fn = UN(PvkPrivateKeyLoad); REQUIRE(fn);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "empty.pvk");
    CHECK(fx_write_file(p, "", 0));
    HANDLE h = open_ro(p);
    DWORD spec = 1;
    SET_ERR(0);
    CHECK(!fn(f.hProv, h, NULL, NULL, 0, &spec));
    EXPECT_ERR(PVK_E_BADFILE);
    EXPECT_EQ(spec, 0);
    CloseHandle(h); DeleteFileA(p); fx_close(&f);
}
TEST(mssigner_pvkfile_load_truncated_file) {
    PvkPrivateKeyLoad_pfn fn = UN(PvkPrivateKeyLoad); REQUIRE(fn);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    static const DWORD cut[] = { 1, 23, 24, 100, 700, 1195 };
    for (int i = 0; i < 6; i++) {
        char p[MAX_PATH]; t_tmpfile(p, sizeof p, "trunc.pvk");
        CHECK(fx_write_file(p, pvk, cut[i]));
        HANDLE h = open_ro(p);
        DWORD spec = 1;
        SET_ERR(0);
        BOOL r = fn(f.hProv, h, NULL, NULL, 0, &spec);
        CHECKF(!r, "cut %lu", cut[i]);
        EXPECT_ERR(PVK_E_BADFILE);
        CHECKF(spec == 0, "cut %lu spec %lu", cut[i], spec);
        CloseHandle(h); DeleteFileA(p);
    }
    fx_close(&f);
}
TEST(mssigner_pvkfile_load_starts_at_current_position) {
    /* the loader reads from the handle's current position (the file size is only used for the legacy format) */
    PvkPrivateKeyLoad_pfn fn = UN(PvkPrivateKeyLoad); REQUIRE(fn);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    BYTE pvk[2100]; memset(pvk, 0x77, 7);
    DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk + 7, sizeof pvk - 7);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "off.pvk");
    CHECK(fx_write_file(p, pvk, n + 7));
    HANDLE h = open_ro(p);
    SetFilePointer(h, 7, NULL, FILE_BEGIN);
    DWORD spec = 0;
    CHECK(fn(f.hProv, h, NULL, NULL, 0, &spec));
    EXPECT_EQ(spec, 1);
    CloseHandle(h);
    /* positioned at end of file: nothing to read */
    h = open_ro(p);
    SetFilePointer(h, 0, NULL, FILE_END);
    spec = 1;
    SET_ERR(0);
    CHECK(!fn(f.hProv, h, NULL, NULL, 0, &spec));
    EXPECT_ERR(PVK_E_BADFILE);
    CloseHandle(h); DeleteFileA(p); fx_close(&f);
}
TEST(mssigner_pvkfile_load_large_garbage_file) {
    PvkPrivateKeyLoad_pfn fn = UN(PvkPrivateKeyLoad); REQUIRE(fn);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    BYTE *big = calloc(1, 0x4001);
    memset(big, 0x42, 0x4001);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "big.pvk");
    CHECK(fx_write_file(p, big, 0x4001));
    HANDLE h = open_ro(p);
    DWORD spec = 1;
    SET_ERR(0);
    CHECK(!fn(f.hProv, h, NULL, NULL, 0, &spec));
    EXPECT_ERR(PVK_E_BADFILE);
    EXPECT_EQ(spec, 0);
    CloseHandle(h); DeleteFileA(p); free(big); fx_close(&f);
}
TEST(mssigner_pvkfile_load_small_garbage_file) {
    PvkPrivateKeyLoad_pfn fn = UN(PvkPrivateKeyLoad); REQUIRE(fn);
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    BYTE g[200]; memset(g, 0x42, sizeof g);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "garb.pvk");
    CHECK(fx_write_file(p, g, sizeof g));
    HANDLE h = open_ro(p);
    DWORD spec = 1;
    SET_ERR(0);
    BOOL r = fn(f.hProv, h, NULL, NULL, 0, &spec);
    CHECK(!r);
    t_note("200 bytes of garbage: last error 0x%08lx", GetLastError());
    EXPECT_EQ(spec, 0);
    CloseHandle(h); DeleteFileA(p); fx_close(&f);
}

/* ---- AcquireContext on a file handle ---- */
TEST(mssigner_pvkfile_acquire_context_w) {
    PvkPrivateKeyAcquireContext_pfn fn = UN(PvkPrivateKeyAcquireContext); REQUIRE(fn);
    PvkPrivateKeyReleaseContext_pfn rel = UN(PvkPrivateKeyReleaseContext); REQUIRE(rel);
    char p[MAX_PATH]; CHECK(mkpvk(p, sizeof p, "ac1.pvk", FX_A, 1));
    HANDLE h = open_ro(p);
    HCRYPTPROV hp = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)1; DWORD spec = 0;
    BOOL r = fn(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, h, NULL, NULL, &spec, &hp, &tmp);
    CHECK(r);
    if (r) {
        EXPECT_EQ(spec, 1);
        CHECK(hp != 0 && have_key(hp, AT_KEYEXCHANGE));
        CHECK(tmp != NULL && lstrlenW(tmp) == 38 && !wcsncmp(tmp, L"TmpKey", 6));
        WCHAR name[64]; lstrcpynW(name, tmp, 64);
        CHECK(rel(hp, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, tmp));
        HCRYPTPROV h2 = 0;
        SET_ERR(0);
        BOOL o = U(CryptAcquireContextW)(&h2, name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0);
        CHECK(!o); EXPECT_ERR(NTE_BAD_KEYSET);
        if (o) U(CryptReleaseContext)(h2, 0);
    }
    CloseHandle(h); DeleteFileA(p);
}
TEST(mssigner_pvkfile_acquire_context_a) {
    PvkPrivateKeyAcquireContextA_pfn fn = UN(PvkPrivateKeyAcquireContextA); REQUIRE(fn);
    PvkPrivateKeyReleaseContextA_pfn rel = UN(PvkPrivateKeyReleaseContextA); REQUIRE(rel);
    char p[MAX_PATH]; CHECK(mkpvk(p, sizeof p, "ac2.pvk", FX_B, 2));
    HANDLE h = open_ro(p);
    HCRYPTPROV hp = 0; LPSTR tmp = NULL; DWORD spec = 0;
    BOOL r = fn(MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, h, NULL, NULL, &spec, &hp, &tmp);
    CHECK(r);
    if (r) {
        EXPECT_EQ(spec, 2);
        CHECK(have_key(hp, AT_SIGNATURE));
        CHECK(tmp && strlen(tmp) == 38 && !strncmp(tmp, "TmpKey", 6));
        CHECK(rel(hp, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, tmp));
    }
    CloseHandle(h); DeleteFileA(p);
}
TEST(mssigner_pvkfile_acquire_context_failures_clear_outputs) {
    PvkPrivateKeyAcquireContext_pfn fn = UN(PvkPrivateKeyAcquireContext); REQUIRE(fn);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "ac3.pvk");
    CHECK(fx_write_file(p, "short", 5));
    HANDLE h = open_ro(p);
    HCRYPTPROV hp = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)1; DWORD spec = 3;
    CHECK(!fn(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, h, NULL, NULL, &spec, &hp, &tmp));
    EXPECT_EQ(hp, 0);
    CHECK(tmp == NULL);
    EXPECT_EQ(spec, 0);
    CloseHandle(h); DeleteFileA(p);
    /* mismatching key type */
    CHECK(mkpvk(p, sizeof p, "ac4.pvk", FX_A, 1));
    h = open_ro(p);
    hp = 0x1234; tmp = (LPWSTR)(ULONG_PTR)1; spec = 2;
    CHECK(!fn(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, h, NULL, NULL, &spec, &hp, &tmp));
    EXPECT_EQ(hp, 0);
    CHECK(tmp == NULL);
    EXPECT_EQ(spec, 1);
    CloseHandle(h); DeleteFileA(p);
}

/* ---- PvkGetCryptProv / PvkFreeCryptProv ---- */
TEST(mssigner_pvkfile_getcryptprov_from_file) {
    PvkGetCryptProv_pfn fn = UN(PvkGetCryptProv); REQUIRE(fn);
    PvkFreeCryptProv_pfn fr = UN(PvkFreeCryptProv); REQUIRE(fr);
    char p[MAX_PATH]; CHECK(mkpvk(p, sizeof p, "gp1.pvk", FX_A, 1));
    LPWSTR wp = fx_w(p);
    HCRYPTPROV hp = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)1; DWORD spec = 0;
    DWORD r = fn(NULL, L"cryptt caption", MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, wp, NULL, &spec, &tmp, &hp);
    EXPECT_EQ(r, 0);
    if (r == 0) {
        EXPECT_EQ(spec, 1);
        CHECK(hp != 0 && have_key(hp, AT_KEYEXCHANGE));
        CHECK(tmp != NULL);
        WCHAR name[64]; lstrcpynW(name, tmp, 64);
        fr(hp, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, tmp);
        HCRYPTPROV h2 = 0;
        SET_ERR(0);
        BOOL o = U(CryptAcquireContextW)(&h2, name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0);
        CHECK(!o); EXPECT_ERR(NTE_BAD_KEYSET);
        if (o) U(CryptReleaseContext)(h2, 0);
    }
    free(wp); DeleteFileA(p);
}
TEST(mssigner_pvkfile_getcryptprov_missing_file) {
    PvkGetCryptProv_pfn fn = UN(PvkGetCryptProv); REQUIRE(fn);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "missing.pvk");
    LPWSTR wp = fx_w(p);
    HCRYPTPROV hp = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)1; DWORD spec = 0;
    DWORD r = fn(NULL, L"cap", MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, wp, NULL, &spec, &tmp, &hp);
    EXPECT_EQ(r, HR_FILE_NOT_FOUND);       /* SignError(ERROR_FILE_NOT_FOUND) */
    EXPECT_EQ(hp, 0);
    CHECK(tmp == NULL);
    free(wp);
}
TEST(mssigner_pvkfile_getcryptprov_directory) {
    PvkGetCryptProv_pfn fn = UN(PvkGetCryptProv); REQUIRE(fn);
    LPWSTR wp = fx_w(t_tmpdir());
    HCRYPTPROV hp = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)1; DWORD spec = 0;
    DWORD r = fn(NULL, L"cap", MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, wp, NULL, &spec, &tmp, &hp);
    EXPECT_EQ(r, 0x80070005u);             /* CreateFile on a directory without BACKUP_SEMANTICS: access denied */
    EXPECT_EQ(hp, 0);
    CHECK(tmp == NULL);
    free(wp);
}
TEST(mssigner_pvkfile_getcryptprov_bad_file_content) {
    PvkGetCryptProv_pfn fn = UN(PvkGetCryptProv); REQUIRE(fn);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "gpbad.pvk");
    CHECK(fx_write_file(p, "", 0));
    LPWSTR wp = fx_w(p);
    HCRYPTPROV hp = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)1; DWORD spec = 0;
    DWORD r = fn(NULL, L"cap", MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, wp, NULL, &spec, &tmp, &hp);
    CHECK(r != 0 && (LONG)r < 0);          /* SignError never returns a success-range value */
    t_note("empty pvk file: PvkGetCryptProv = 0x%08lx", r);
    EXPECT_EQ(hp, 0);
    CHECK(tmp == NULL);
    free(wp); DeleteFileA(p);
}
TEST(mssigner_pvkfile_getcryptprov_container_not_found) {
    PvkGetCryptProv_pfn fn = UN(PvkGetCryptProv); REQUIRE(fn);
    WCHAR cont[64]; _snwprintf(cont, 63, L"cryptt_nosuch_%lu", GetCurrentProcessId());
    HCRYPTPROV hp = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)1; DWORD spec = 0;
    DWORD r = fn(NULL, L"cap", MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, NULL, cont, &spec, &tmp, &hp);
    EXPECT_EQ(r, (DWORD)NTE_BAD_KEYSET);   /* CryptAcquireContext error passed through SignError */
    EXPECT_EQ(hp, 0);
    CHECK(tmp == NULL);
    EXPECT_EQ(spec, 0);
}
TEST(mssigner_pvkfile_getcryptprov_container_unknown_provider) {
    PvkGetCryptProv_pfn fn = UN(PvkGetCryptProv); REQUIRE(fn);
    HCRYPTPROV hp = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)1; DWORD spec = 0;
    DWORD r = fn(NULL, L"cap", L"cryptt no such provider", PROV_RSA_AES, NULL, L"c", &spec, &tmp, &hp);
    CHECK(r != 0 && (LONG)r < 0);
    t_note("unknown provider name: 0x%08lx", r);
    EXPECT_EQ(hp, 0);
}
TEST(mssigner_pvkfile_free_cryptprov_variants) {
    PvkFreeCryptProv_pfn fr = UN(PvkFreeCryptProv); REQUIRE(fr);
    fr(0, NULL, 0, NULL);                 /* nothing to do */
    HCRYPTPROV h = 0;
    CHECK(U(CryptAcquireContextW)(&h, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    if (!h) return;
    CHECK(U(CryptContextAddRef)(h, NULL, 0));
    fr(h, NULL, 0, NULL);                 /* releases exactly one reference */
    BYTE b[4];
    CHECK(U(CryptGenRandom)(h, 4, b));
    CHECK(U(CryptReleaseContext)(h, 0));
}

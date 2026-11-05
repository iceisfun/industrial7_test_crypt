#include "dp.h"
/* dpapi.dll: NoUI variants, iCryptIdentifyProtection, CryptUpdateProtectedState, CryptResetMachineCredentials, cross-process blobs */

UDECL(ULONG, iCryptIdentifyProtection, (int, PUCHAR, ULONG, PUINT, PUINT));
UDECL(BOOL, CryptResetMachineCredentials, (DWORD));

static const BYTE SECRET[] = "noui secret payload";
static const GUID PROVIDER = DP_PROVIDER_GUID;

#define NEED_DPAPI_FN(f) do { if (!t_proc_in("dpapi.dll", #f)) { t_skip("dpapi.dll does not export " #f); return; } } while (0)

/* ---- export presence (GetProcAddress by name and ordinal) ---- */

static const struct { const char *n; unsigned ord; } DPEXP[] = {
    { "CryptProtectDataNoUI", 1 }, { "CryptProtectMemory", 2 }, { "CryptResetMachineCredentials", 3 },
    { "CryptUnprotectDataNoUI", 4 }, { "CryptUnprotectMemory", 5 }, { "CryptUpdateProtectedState", 6 }, { "iCryptIdentifyProtection", 7 },
};
TEST(dpapi_exports_by_name) {
    if (!t_module("dpapi.dll")) { t_skip("no dpapi.dll"); return; }
    for (size_t i = 0; i < sizeof DPEXP / sizeof *DPEXP; i++) CHECKF(t_proc_in("dpapi.dll", DPEXP[i].n) != NULL, "%s", DPEXP[i].n);
}
TEST(dpapi_exports_by_ordinal) {
    if (!t_module("dpapi.dll")) { t_skip("no dpapi.dll"); return; }
    DP_NOT_WINE();
    for (size_t i = 0; i < sizeof DPEXP / sizeof *DPEXP; i++) {
        FARPROC a = t_proc_ord("dpapi.dll", DPEXP[i].ord), b = t_proc_in("dpapi.dll", DPEXP[i].n);
        CHECKF(a != NULL && a == b, "%s ordinal %u", DPEXP[i].n, DPEXP[i].ord);
    }
}
TEST(dpapi_exports_missing_name) {
    HMODULE m = t_module("dpapi.dll");
    if (!m) { t_skip("no dpapi.dll"); return; }
    SET_ERR(0);
    CHECK(GetProcAddress(m, "CryptProtectDataNoUIW") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "CryptProtectDataA") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "") == NULL);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "cryptprotectmemory") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);   /* names are case sensitive */
}
TEST(dpapi_exports_crypt32_has_data_api) {
    CHECK(t_proc_in("crypt32.dll", "CryptProtectData") != NULL);
    CHECK(t_proc_in("crypt32.dll", "CryptUnprotectData") != NULL);
    CHECK(t_proc_in("crypt32.dll", "CryptProtectMemory") != NULL);
    CHECK(t_proc_in("crypt32.dll", "CryptUnprotectMemory") != NULL);
    if (!t_is_wine()) CHECK(t_proc_in("crypt32.dll", "CryptUpdateProtectedState") != NULL);
}
TEST(dpapi_exports_no_ansi_wide_variants) {
    HMODULE m = t_module("crypt32.dll");
    CHECK(GetProcAddress(m, "CryptProtectDataA") == NULL);
    CHECK(GetProcAddress(m, "CryptProtectDataW") == NULL);
    CHECK(GetProcAddress(m, "CryptUnprotectDataA") == NULL);
    CHECK(GetProcAddress(m, "CryptUnprotectDataW") == NULL);
    CHECK(GetProcAddress(m, "CryptProtectMemoryW") == NULL);
}
TEST(dpapi_exports_reset_machine_credentials_resolves) {
    NEED_DPAPI_FN(CryptResetMachineCredentials);
    CHECK(t_proc_in("dpapi.dll", "CryptResetMachineCredentials") != NULL);   /* resolve only: the call clears machine DPAPI credentials */
}
TEST(dpapi_exports_distinct_addresses) {
    if (!t_module("dpapi.dll")) { t_skip("no dpapi.dll"); return; }
    for (size_t i = 0; i < sizeof DPEXP / sizeof *DPEXP; i++) for (size_t j = i + 1; j < sizeof DPEXP / sizeof *DPEXP; j++) {
        FARPROC a = t_proc_in("dpapi.dll", DPEXP[i].n), b = t_proc_in("dpapi.dll", DPEXP[j].n);
        if (a && b) CHECKF(a != b, "%s == %s", DPEXP[i].n, DPEXP[j].n);
    }
}

/* ---- CryptProtectDataNoUI / CryptUnprotectDataNoUI ---- */

static BOOL noui_protect(const void *d, DWORD n, LPCWSTR descr, const void *ent, DWORD el, DWORD flags, DATA_BLOB *out) {
    DATA_BLOB in = { n, (BYTE *)d }, e = { el, (BYTE *)ent };
    return UIN("dpapi.dll", CryptProtectDataNoUI)(&in, descr, ent ? &e : NULL, NULL, NULL, flags, NULL, 0, out);
}
static BOOL noui_unprotect(const void *b, DWORD n, LPWSTR *descr, const void *ent, DWORD el, DWORD flags, DATA_BLOB *out) {
    DATA_BLOB in = { n, (BYTE *)b }, e = { el, (BYTE *)ent };
    return UIN("dpapi.dll", CryptUnprotectDataNoUI)(&in, descr, ent ? &e : NULL, NULL, NULL, flags, NULL, 0, out);
}

TEST(dpapi_noui_roundtrip) {
    NEED_DPAPI_FN(CryptProtectDataNoUI); NEED_DPAPI_FN(CryptUnprotectDataNoUI);
    DATA_BLOB b = { 0 }, p = { 0 };
    LPWSTR d = NULL;
    BOOL r = noui_protect(SECRET, sizeof SECRET, L"noui", NULL, 0, 0, &b);
    CHECKF(r, "err=%lu", GetLastError());
    if (r) {
        r = noui_unprotect(b.pbData, b.cbData, &d, NULL, 0, 0, &p);
        CHECKF(r, "err=%lu", GetLastError());
        CHECK(p.cbData == sizeof SECRET && p.pbData && !memcmp(p.pbData, SECRET, sizeof SECRET));
        CHECK(d && !lstrcmpW(d, L"noui"));
    }
    if (d) LocalFree(d);
    dp_free(&b); dp_free(&p);
}
TEST(dpapi_noui_entropy_roundtrip_and_mismatch) {
    NEED_DPAPI_FN(CryptProtectDataNoUI); NEED_DPAPI_FN(CryptUnprotectDataNoUI);
    static const BYTE e1[] = "alpha", e2[] = "bravo";
    DATA_BLOB b = { 0 }, p = { 0 };
    CHECK(noui_protect(SECRET, sizeof SECRET, NULL, e1, sizeof e1, 0, &b));
    if (b.pbData) {
        CHECK(noui_unprotect(b.pbData, b.cbData, NULL, e1, sizeof e1, 0, &p)); dp_free(&p);
        SET_ERR(0);
        CHECK(!noui_unprotect(b.pbData, b.cbData, NULL, e2, sizeof e2, 0, &p)); EXPECT_ERR(ERROR_INVALID_DATA);
        SET_ERR(0);
        CHECK(!noui_unprotect(b.pbData, b.cbData, NULL, NULL, 0, 0, &p)); EXPECT_ERR(ERROR_INVALID_DATA);
    }
    dp_free(&b);
}
TEST(dpapi_noui_blob_readable_by_crypt32) {
    NEED_DPAPI_FN(CryptProtectDataNoUI);
    if (!U(CryptUnprotectData)) { t_skip("no CryptUnprotectData"); return; }
    DATA_BLOB b = { 0 }, p = { 0 };
    CHECK(noui_protect(SECRET, sizeof SECRET, L"x-compat", NULL, 0, 0, &b));
    if (b.pbData) {
        LPWSTR d = NULL;
        CHECK(dp_unprotect(b.pbData, b.cbData, &d, NULL, 0, 0, &p));
        CHECK(p.cbData == sizeof SECRET && !memcmp(p.pbData, SECRET, sizeof SECRET));
        CHECK(d && !lstrcmpW(d, L"x-compat"));
        if (d) LocalFree(d);
    }
    dp_free(&b); dp_free(&p);
}
TEST(dpapi_noui_crypt32_blob_readable_by_noui) {
    NEED_DPAPI_FN(CryptUnprotectDataNoUI);
    if (!U(CryptProtectData)) { t_skip("no CryptProtectData"); return; }
    DATA_BLOB b = { 0 }, p = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"x-compat2", NULL, 0, 0, &b));
    if (b.pbData) {
        LPWSTR d = NULL;
        CHECK(noui_unprotect(b.pbData, b.cbData, &d, NULL, 0, 0, &p));
        CHECK(p.cbData == sizeof SECRET && !memcmp(p.pbData, SECRET, sizeof SECRET));
        if (d) LocalFree(d);
    }
    dp_free(&b); dp_free(&p);
}
TEST(dpapi_noui_protect_null_args) {
    NEED_DPAPI_FN(CryptProtectDataNoUI);
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET }, out = { 0 };
    DATA_BLOB nul = { 5, NULL };
    SET_ERR(0);
    CHECK(!UIN("dpapi.dll", CryptProtectDataNoUI)(&in, L"d", NULL, NULL, NULL, 0, NULL, 0, NULL));
    DWORD e1 = GetLastError();
    SET_ERR(0);
    CHECK(!UIN("dpapi.dll", CryptProtectDataNoUI)(NULL, L"d", NULL, NULL, NULL, 0, NULL, 0, &out));
    DWORD e2 = GetLastError();
    SET_ERR(0);
    CHECK(!UIN("dpapi.dll", CryptProtectDataNoUI)(&nul, L"d", NULL, NULL, NULL, 0, NULL, 0, &out));
    DWORD e3 = GetLastError();
    t_note("ProtectDataNoUI NULL out -> %lu, NULL in -> %lu, NULL pbData -> %lu", e1, e2, e3);
    CHECK(e1 != 0 && e2 != 0 && e3 != 0);
    CHECK(out.pbData == NULL);
}
TEST(dpapi_noui_unprotect_null_args) {
    NEED_DPAPI_FN(CryptUnprotectDataNoUI);
    BYTE junk[64] = { 0 };
    DATA_BLOB in = { sizeof junk, junk }, out = { 0x11, (BYTE *)(ULONG_PTR)1 };
    SET_ERR(0);
    CHECK(!UIN("dpapi.dll", CryptUnprotectDataNoUI)(&in, NULL, NULL, NULL, NULL, 0, NULL, 0, NULL));
    DWORD e1 = GetLastError();
    SET_ERR(0);
    CHECK(!UIN("dpapi.dll", CryptUnprotectDataNoUI)(NULL, NULL, NULL, NULL, NULL, 0, NULL, 0, &out));
    DWORD e2 = GetLastError();
    t_note("UnprotectDataNoUI NULL out -> %lu, NULL in -> %lu", e1, e2);
    CHECK(e1 != 0 && e2 != 0);
}
TEST(dpapi_noui_unprotect_garbage) {
    NEED_DPAPI_FN(CryptUnprotectDataNoUI);
    BYTE junk[128]; dp_fill(junk, sizeof junk, 77);
    DATA_BLOB out = { 0 };
    SET_ERR(0);
    CHECK(!noui_unprotect(junk, sizeof junk, NULL, NULL, 0, 0, &out));
    DWORD e = GetLastError();
    CHECKF(DP_IS_BLOB_ERR(e), "err=%lu", e);
}
TEST(dpapi_noui_empty_data) {
    NEED_DPAPI_FN(CryptProtectDataNoUI); NEED_DPAPI_FN(CryptUnprotectDataNoUI);
    BYTE z = 0;
    DATA_BLOB b = { 0 }, p = { 0 };
    BOOL r = noui_protect(&z, 0, NULL, NULL, 0, 0, &b);
    CHECKF(r, "err=%lu", GetLastError());
    if (r) { CHECK(noui_unprotect(b.pbData, b.cbData, NULL, NULL, 0, 0, &p)); CHECK(p.cbData == 0); }
    dp_free(&b); dp_free(&p);
}
TEST(dpapi_noui_local_machine) {
    NEED_DPAPI_FN(CryptProtectDataNoUI); NEED_DPAPI_FN(CryptUnprotectDataNoUI);
    DATA_BLOB b = { 0 }, p = { 0 };
    BOOL r = noui_protect(SECRET, sizeof SECRET, NULL, NULL, 0, CRYPTPROTECT_LOCAL_MACHINE, &b);
    CHECKF(r, "err=%lu", GetLastError());
    if (r) { CHECK(noui_unprotect(b.pbData, b.cbData, NULL, NULL, 0, 0, &p)); CHECK(p.cbData == sizeof SECRET); }
    dp_free(&b); dp_free(&p);
}

/* ---- iCryptIdentifyProtection ---- */

/* build a layout-correct synthetic blob: descr L"", salt 16, no strong data */
static DWORD synth(BYTE *b, DWORD cap, DWORD cipherAlg, DWORD hashAlg, DWORD total) {
    memset(b, 0, cap);
    dp_wr(b, 0, 1); memcpy(b + 4, &PROVIDER, 16); dp_wr(b, 20, 1);
    memset(b + 24, 0x11, 16);
    dp_wr(b, 40, 0); dp_wr(b, 44, 2);
    DWORD o = 48 + 2;
    dp_wr(b, o, cipherAlg); dp_wr(b, o + 4, 256); dp_wr(b, o + 8, 16); o += 12;
    memset(b + o, 0x22, 16); o += 16;
    dp_wr(b, o, 0); o += 4;                           /* strong length */
    dp_wr(b, o, hashAlg); dp_wr(b, o + 4, 512); dp_wr(b, o + 8, 0); o += 12;
    return total;
}
static const DWORD SYNTH_MIN = 106;                   /* uVar5 + 0xf with salt 16, strong 0 */

TEST(dpapi_identify_synthetic_blob) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    unsigned a = 0, h = 0;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), 0);
    EXPECT_EQ(a, CALG_AES_256); EXPECT_EQ(h, CALG_SHA_512);
}
TEST(dpapi_identify_reports_arbitrary_alg_ids) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, 0x6603, 0x8004, 200);       /* 3DES / SHA1 */
    unsigned a = 0, h = 0;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), 0);
    EXPECT_EQ(a, 0x6603); EXPECT_EQ(h, 0x8004);
}
TEST(dpapi_identify_null_outputs) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    unsigned a = 0xAA, h = 0xBB;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, NULL, &h), 0); EXPECT_EQ(h, CALG_SHA_512);
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, NULL), 0); EXPECT_EQ(a, CALG_AES_256);
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, NULL, NULL), 0);
}
TEST(dpapi_identify_minimum_size_boundary) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    unsigned a = 0xAA, h = 0xBB;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, SYNTH_MIN - 1, &a, &h), ERROR_INVALID_DATA);
    CHECK(a == 0xAA && h == 0xBB);                             /* outputs untouched on failure */
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, SYNTH_MIN, &a, &h), 0);
    EXPECT_EQ(a, CALG_AES_256);
}
TEST(dpapi_identify_small_sizes) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    static const ULONG sz[] = { 0, 1, 0x10, 0x32, 0x33, 0x34, 0x43, 0x44, 0x50, 0x5a, 0x69 };
    for (size_t i = 0; i < sizeof sz / sizeof *sz; i++) {
        unsigned a = 0, h = 0;
        ULONG r = UN(iCryptIdentifyProtection)(1, b, sz[i], &a, &h);
        CHECKF(r == ERROR_INVALID_DATA, "size 0x%lx -> %lu", sz[i], r);
    }
}
TEST(dpapi_identify_version_field) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    static const struct { DWORD v; ULONG want; } t[] = { { 0, 0 }, { 1, 0 }, { 2, ERROR_INVALID_DATA }, { 3, ERROR_INVALID_DATA }, { 0x80000000u, ERROR_INVALID_DATA }, { 0xffffffffu, ERROR_INVALID_DATA } };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
        dp_wr(b, 0, t[i].v);
        unsigned a, h;
        ULONG r = UN(iCryptIdentifyProtection)(1, b, 200, &a, &h);
        CHECKF(r == t[i].want, "version %lu -> %lu want %lu", t[i].v, r, t[i].want);
    }
}
TEST(dpapi_identify_masterkey_version_field) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    static const struct { DWORD v; ULONG want; } t[] = { { 0, 0 }, { 1, 0 }, { 2, ERROR_INVALID_DATA }, { 0xffffffffu, ERROR_INVALID_DATA } };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
        dp_wr(b, 20, t[i].v);
        unsigned a, h;
        ULONG r = UN(iCryptIdentifyProtection)(1, b, 200, &a, &h);
        CHECKF(r == t[i].want, "mk version %lu -> %lu want %lu", t[i].v, r, t[i].want);
    }
}
TEST(dpapi_identify_provider_guid_every_byte) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    for (int i = 0; i < 16; i++) {
        BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
        b[4 + i] ^= 0x01;
        unsigned a, h;
        ULONG r = UN(iCryptIdentifyProtection)(1, b, 200, &a, &h);
        CHECKF(r == ERROR_INVALID_DATA, "guid byte %d -> %lu", i, r);
    }
}
TEST(dpapi_identify_masterkey_guid_not_validated) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    memset(b + 24, 0, 16);
    unsigned a = 0, h = 0;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), 0);
    memset(b + 24, 0xff, 16);
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), 0);
}
TEST(dpapi_identify_flags_not_validated) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    dp_wr(b, 40, 0xffffffffu);
    unsigned a = 0, h = 0;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), 0);
    EXPECT_EQ(a, CALG_AES_256);
}
TEST(dpapi_identify_salt_length_beyond_buffer) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    dp_wr(b, 50 + 8, 1000);
    unsigned a = 0, h = 0;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), ERROR_INVALID_DATA);
}
TEST(dpapi_identify_strong_length_beyond_buffer) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    dp_wr(b, 50 + 12 + 16, 500);
    unsigned a = 0, h = 0;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), ERROR_INVALID_DATA);
}
TEST(dpapi_identify_description_length_beyond_buffer) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    dp_wr(b, 44, 400);
    unsigned a = 0, h = 0;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), ERROR_INVALID_DATA);
}
TEST(dpapi_identify_strong_data_shifts_hash_alg) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    /* strong length 8: the hash algorithm field sits after the strong bytes */
    BYTE b[256]; memset(b, 0, sizeof b);
    synth(b, sizeof b, CALG_AES_256, 0xdead, 200);
    DWORD o = 50 + 12 + 16;
    dp_wr(b, o, 8);
    memmove(b + o + 4 + 8, b + o + 4, 12);
    memset(b + o + 4, 0x33, 8);
    dp_wr(b, o + 4 + 8, CALG_SHA_512);
    unsigned a = 0, h = 0;
    EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b, 200, &a, &h), 0);
    EXPECT_EQ(h, CALG_SHA_512);
    EXPECT_EQ(a, CALG_AES_256);
}
TEST(dpapi_identify_unknown_type_not_supported) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[256]; synth(b, sizeof b, CALG_AES_256, CALG_SHA_512, 200);
    static const int types[] = { 0, 5, 6, 100, -1, 0x7fffffff, (int)0x80000000 };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        unsigned a = 0xAA, h = 0xBB;
        ULONG r = UN(iCryptIdentifyProtection)(types[i], b, 200, &a, &h);
        CHECKF(r == ERROR_NOT_SUPPORTED, "type %d -> %lu", types[i], r);
        CHECKF(a == 0xAA && h == 0xBB, "type %d touched outputs", types[i]);
    }
}
TEST(dpapi_identify_unknown_type_ignores_pointers) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    EXPECT_EQ(UN(iCryptIdentifyProtection)(0, NULL, 0, NULL, NULL), ERROR_NOT_SUPPORTED);
    EXPECT_EQ(UN(iCryptIdentifyProtection)(9, NULL, 0, NULL, NULL), ERROR_NOT_SUPPORTED);
}
TEST(dpapi_identify_types_2_3_4_garbage_observed) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    BYTE b[64]; memset(b, 0, sizeof b);
    for (int t = 2; t <= 4; t++) {
        unsigned a = 0xAA, h = 0xBB;
        ULONG r = UN(iCryptIdentifyProtection)(t, b, 0, &a, &h);
        t_note("iCryptIdentifyProtection(type %d, size 0) -> %lu", t, r);
    }
}
TEST(dpapi_identify_real_blob) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    if (!U(CryptProtectData)) { t_skip("no CryptProtectData"); return; }
    DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"id", NULL, 0, 0, &b));
    if (b.pbData) {
        unsigned a = 0, h = 0;
        EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b.pbData, b.cbData, &a, &h), 0);
        EXPECT_EQ(a, CALG_AES_256); EXPECT_EQ(h, CALG_SHA_512);
    }
    dp_free(&b);
}
TEST(dpapi_identify_real_blob_entropy_same_algs) {
    NEED_DPAPI_FN(iCryptIdentifyProtection);
    if (!U(CryptProtectData)) { t_skip("no CryptProtectData"); return; }
    DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"id", "e", 1, CRYPTPROTECT_LOCAL_MACHINE, &b));
    if (b.pbData) {
        unsigned a = 0, h = 0;
        EXPECT_EQ(UN(iCryptIdentifyProtection)(1, b.pbData, b.cbData, &a, &h), 0);
        EXPECT_EQ(a, CALG_AES_256); EXPECT_EQ(h, CALG_SHA_512);
    }
    dp_free(&b);
}

/* ---- CryptUpdateProtectedState (only parameter validation: valid calls rewrite master keys) ---- */

TEST(dpapi_ups_both_null) {
    if (!U(CryptUpdateProtectedState)) { t_skip("missing CryptUpdateProtectedState"); return; }
    DWORD s = 0x77, f = 0x88;
    SET_ERR(0);
    CHECK(!U(CryptUpdateProtectedState)(NULL, NULL, 0, &s, &f)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(s == 0x77 && f == 0x88);
}
TEST(dpapi_ups_both_null_flags_ignored) {
    if (!U(CryptUpdateProtectedState)) { t_skip("missing CryptUpdateProtectedState"); return; }
    static const DWORD fl[] = { 0, 1, 2, 0xffffffffu };
    for (size_t i = 0; i < sizeof fl / sizeof *fl; i++) {
        SET_ERR(0);
        CHECK(!U(CryptUpdateProtectedState)(NULL, NULL, fl[i], NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}
TEST(dpapi_ups_invalid_sid_no_password) {
    if (!U(CryptUpdateProtectedState)) { t_skip("missing CryptUpdateProtectedState"); return; }
    BYTE bad[32]; memset(bad, 0, sizeof bad);           /* revision 0 is not a valid SID */
    DWORD s = 0x77, f = 0x88;
    SET_ERR(0);
    CHECK(!U(CryptUpdateProtectedState)(bad, NULL, 0, &s, &f)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(s == 0x77 && f == 0x88);
}
TEST(dpapi_ups_invalid_sid_with_password) {
    if (!U(CryptUpdateProtectedState)) { t_skip("missing CryptUpdateProtectedState"); return; }
    BYTE bad[32]; memset(bad, 0xff, sizeof bad);        /* revision 255, subauth count 255 */
    SET_ERR(0);
    CHECK(!U(CryptUpdateProtectedState)(bad, L"password", 0, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(dpapi_ups_invalid_sid_bad_revision_variants) {
    if (!U(CryptUpdateProtectedState)) { t_skip("missing CryptUpdateProtectedState"); return; }
    for (int rev = 0; rev < 256; rev += 51) {
        if (rev == 1) continue;
        BYTE sid[16] = { (BYTE)rev, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 };   /* S-1-5-18 layout with a wrong revision */
        SET_ERR(0);
        CHECKF(!U(CryptUpdateProtectedState)(sid, NULL, 0, NULL, NULL), "rev %d", rev);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}
TEST(dpapi_ups_invalid_sid_too_many_subauthorities) {
    if (!U(CryptUpdateProtectedState)) { t_skip("missing CryptUpdateProtectedState"); return; }
    BYTE sid[8 + 4 * 16]; memset(sid, 0, sizeof sid);
    sid[0] = 1; sid[1] = 16; sid[7] = 5;                 /* 16 sub authorities: more than SID_MAX_SUB_AUTHORITIES (15) */
    SET_ERR(0);
    CHECK(!U(CryptUpdateProtectedState)(sid, NULL, 0, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(dpapi_ups_resolves_in_both_modules) {
    if (!t_is_wine()) CHECK(UIN("crypt32.dll", CryptUpdateProtectedState) != NULL);
    if (t_module("dpapi.dll")) CHECK(UIN("dpapi.dll", CryptUpdateProtectedState) != NULL);
}

/* ---- cross-process data blobs ---- */

/* argv: 1=hex blob 2=hex entropy or "-" ; expected plaintext SECRET. exit 0 ok, 1 call failed (low byte of error in bits 8..), 2 mismatch */
CHILD(dpapi_data_unprot) {
    if (argc < 3) return 9;
    if (!U(CryptUnprotectData)) return 8;
    static BYTE blob[8192], ent[1024];
    int n = dp_unhex(argv[1], blob, sizeof blob);
    int el = strcmp(argv[2], "-") ? dp_unhex(argv[2], ent, sizeof ent) : -1;
    DATA_BLOB in = { (DWORD)n, blob }, e = { (DWORD)(el < 0 ? 0 : el), ent }, out = { 0 };
    LPWSTR d = NULL;
    if (!U(CryptUnprotectData)(&in, &d, el < 0 ? NULL : &e, NULL, NULL, 0, &out)) return 1 | (int)(GetLastError() << 8);
    if (out.cbData != sizeof SECRET || memcmp(out.pbData, SECRET, sizeof SECRET)) return 2;
    return (d && !lstrcmpW(d, L"child-view")) ? 0 : 3;
}
static DWORD run_data_child(const BYTE *blob, DWORD n, const BYTE *ent, DWORD el) {
    static char args[8192];
    char *p = args;
    p += sprintf(p, "\"");
    dp_hex(blob, n, p); p += 2 * n;
    p += sprintf(p, "\" ");
    if (ent) { dp_hex(ent, el, p); p += 2 * el; } else p += sprintf(p, "-");
    return t_run_child("dpapi_data_unprot", args, 30000);
}
TEST(dpapi_xproc_blob_unprotected_in_child) {
    DP_NEED_DATA();
    DATA_BLOB b = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"child-view", NULL, 0, 0, &b));
    if (b.pbData) {
        if (b.cbData > 2048) { t_skip("blob too large for command line"); return; }
        EXPECT_EQ(run_data_child(b.pbData, b.cbData, NULL, 0), 0);
    }
    dp_free(&b);
}
TEST(dpapi_xproc_blob_with_entropy_in_child) {
    DP_NEED_DATA();
    static const BYTE ent[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    DATA_BLOB b = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"child-view", ent, sizeof ent, 0, &b));
    if (b.pbData && b.cbData <= 2048) EXPECT_EQ(run_data_child(b.pbData, b.cbData, ent, sizeof ent), 0);
    dp_free(&b);
}
TEST(dpapi_xproc_blob_wrong_entropy_in_child) {
    DP_NEED_DATA();
    static const BYTE ent[] = { 1, 2, 3, 4, 5, 6, 7, 8 }, bad[] = { 1, 2, 3, 4, 5, 6, 7, 9 };
    DATA_BLOB b = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"child-view", ent, sizeof ent, 0, &b));
    if (b.pbData && b.cbData <= 2048) {
        DWORD rc = run_data_child(b.pbData, b.cbData, bad, sizeof bad);
        CHECK((rc & 0xff) == 1);
        EXPECT_EQ(rc >> 8, ERROR_INVALID_DATA);
    }
    dp_free(&b);
}
TEST(dpapi_xproc_blob_no_entropy_in_child_fails) {
    DP_NEED_DATA();
    static const BYTE ent[] = { 9, 9 };
    DATA_BLOB b = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"child-view", ent, sizeof ent, 0, &b));
    if (b.pbData && b.cbData <= 2048) {
        DWORD rc = run_data_child(b.pbData, b.cbData, NULL, 0);
        CHECK((rc & 0xff) == 1); EXPECT_EQ(rc >> 8, ERROR_INVALID_DATA);
    }
    dp_free(&b);
}
TEST(dpapi_xproc_local_machine_blob_in_child) {
    DP_NEED_DATA();
    DATA_BLOB b = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"child-view", NULL, 0, CRYPTPROTECT_LOCAL_MACHINE, &b));
    if (b.pbData && b.cbData <= 2048) EXPECT_EQ(run_data_child(b.pbData, b.cbData, NULL, 0), 0);
    dp_free(&b);
}
CHILD(dpapi_data_selfrt) {
    DATA_BLOB b = { 0 }, p = { 0 };
    if (!dp_protect(SECRET, sizeof SECRET, L"self", NULL, 0, 0, &b)) return 1;
    if (!dp_unprotect(b.pbData, b.cbData, NULL, NULL, 0, 0, &p)) return 2;
    return p.cbData == sizeof SECRET && !memcmp(p.pbData, SECRET, sizeof SECRET) ? 0 : 3;
}
TEST(dpapi_xproc_child_does_own_roundtrip) {
    DP_NEED_DATA();
    EXPECT_EQ(t_run_child("dpapi_data_selfrt", "", 30000), 0);
}

/* ---- threads ---- */

static DWORD WINAPI worker(LPVOID p) {
    int *rc = p;
    for (int i = 0; i < 5; i++) {
        BYTE pt[200]; dp_fill(pt, sizeof pt, (DWORD)(ULONG_PTR)rc + i);
        DATA_BLOB b = { 0 }, o = { 0 };
        if (!dp_protect(pt, sizeof pt, NULL, NULL, 0, 0, &b)) { *rc = 1; return 0; }
        if (!dp_unprotect(b.pbData, b.cbData, NULL, NULL, 0, 0, &o) || o.cbData != sizeof pt || memcmp(o.pbData, pt, sizeof pt)) { *rc = 2; return 0; }
        dp_free(&b); dp_free(&o);
    }
    *rc = 0;
    return 0;
}
TEST(dpapi_threads_concurrent_roundtrips) {
    DP_NEED_DATA();
    HANDLE h[4]; int rc[4];
    for (int i = 0; i < 4; i++) { rc[i] = -1; h[i] = CreateThread(NULL, 0, worker, &rc[i], 0, NULL); CHECK(h[i] != NULL); }
    for (int i = 0; i < 4; i++) if (h[i]) { CHECK(WaitForSingleObject(h[i], 60000) == WAIT_OBJECT_0); CloseHandle(h[i]); CHECKF(rc[i] == 0, "thread %d rc=%d", i, rc[i]); }
}
TEST(dpapi_data_protect_in_one_thread_unprotect_in_main) {
    DP_NEED_DATA();
    int rc = -1;
    HANDLE h = CreateThread(NULL, 0, worker, &rc, 0, NULL);
    CHECK(h != NULL);
    if (h) { CHECK(WaitForSingleObject(h, 60000) == WAIT_OBJECT_0); CloseHandle(h); }
    EXPECT_EQ(rc, 0);
}

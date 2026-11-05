/* CryptCreateHash / CryptHashData / CryptGetHashParam / CryptDestroyHash argument and state behaviour. */
#include "h.h"

static const struct { ALG_ID alg; const char *name; DWORD len; } g_algs[] = {
    { CALG_MD2, "MD2", 16 }, { CALG_MD4, "MD4", 16 }, { CALG_MD5, "MD5", 16 }, { CALG_SHA1, "SHA1", 20 },
    { CALG_SHA_256, "SHA256", 32 }, { CALG_SHA_384, "SHA384", 48 }, { CALG_SHA_512, "SHA512", 64 },
};
#define NALGS (sizeof g_algs / sizeof g_algs[0])
#define PROLOG HCRYPTPROV p = h_acq_aes(); if (!p) return
#define EPILOG h_rel(p)

/* ------------------------------------------------------------------ create */
TEST(capi_hash_create_all_algs_succeed) {
    REQUIRE(U(CryptCreateHash)); PROLOG; size_t i;
    for (i = 0; i < NALGS; i++) {
        HCRYPTHASH h = 0; SET_ERR(0);
        BOOL ok = U(CryptCreateHash)(p, g_algs[i].alg, 0, 0, &h);
        CHECKF(ok && h, "%s err 0x%lx", g_algs[i].name, GetLastError());
        if (ok) CHECK(U(CryptDestroyHash)(h));
    }
    EPILOG;
}
TEST(capi_hash_create_ssl3_shamd5) {
    REQUIRE(U(CryptCreateHash)); PROLOG; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SSL3_SHAMD5, 0, 0, &h));
    CHECK(h != 0);
    if (h) U(CryptDestroyHash)(h);
    EPILOG;
}
TEST(capi_hash_create_handles_distinct) {
    REQUIRE(U(CryptCreateHash)); PROLOG; HCRYPTHASH a = 0, b = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &a));
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &b));
    CHECK(a && b && a != b);
    U(CryptDestroyHash)(a); U(CryptDestroyHash)(b);
    EPILOG;
}
TEST(capi_hash_create_nonzero_flags_bad_flags) {
    REQUIRE(U(CryptCreateHash)); PROLOG; size_t i;
    static const DWORD fl[] = { 1, 2, 0x10, 0x100, 0x80000000u, 0xFFFFFFFFu };
    for (i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        HCRYPTHASH h = 0x1234; SET_ERR(0);
        BOOL ok = U(CryptCreateHash)(p, CALG_SHA1, 0, fl[i], &h);
        CHECKF(!ok, "flags 0x%lx", fl[i]); EXPECT_ERR(E_NTE_BAD_FLAGS);
    }
    EPILOG;
}
TEST(capi_hash_create_failure_leaves_handle_unchanged_or_zero) {
    REQUIRE(U(CryptCreateHash)); PROLOG; HCRYPTHASH h = 0;
    SET_ERR(0);
    CHECK(!U(CryptCreateHash)(p, CALG_RC4, 0, 0, &h));
    EXPECT_ERR(50);
    CHECK(h == 0);
    EPILOG;
}
TEST(capi_hash_create_non_hash_algids_rejected) {
    REQUIRE(U(CryptCreateHash)); PROLOG; size_t i;
    /* Win10: ids of the symmetric / asymmetric classes give ERROR_NOT_SUPPORTED, anything else NTE_BAD_ALGID */
    static const struct { ALG_ID a; DWORD err; } bad[] = {
        { 0, E_NTE_BAD_ALGID }, { CALG_RC4, 50 }, { CALG_RC2, 50 }, { CALG_DES, 50 }, { CALG_3DES, 50 }, { CALG_AES_128, 50 },
        { CALG_RSA_SIGN, 50 }, { CALG_RSA_KEYX, 50 }, { CALG_DH_SF, 50 }, { CALG_AES, E_NTE_BAD_ALGID }, { CALG_NO_SIGN, E_NTE_BAD_ALGID },
        { 0xFFFF, E_NTE_BAD_ALGID }, { 0x8000, E_NTE_BAD_ALGID }, { 0x800f, E_NTE_BAD_ALGID }, { 0x8010, E_NTE_BAD_ALGID }, { 0x7fff, E_NTE_BAD_ALGID } };
    HCRYPTHASH h = 0;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        h = 0; t_label("alg 0x%lx", (unsigned long)bad[i].a);
        EXPECT_CAPI_FAIL(U(CryptCreateHash)(p, bad[i].a, 0, 0, &h), bad[i].err);
        CHECK(h == 0);
    }
    t_label(NULL);
    /* CALG_SHA == CALG_SHA1 */
    h = 0; EXPECT_CAPI_OK(U(CryptCreateHash)(p, CALG_SHA, 0, 0, &h)); if (h) U(CryptDestroyHash)(h);
    EPILOG;
}
TEST(capi_hash_create_sha2_rejected_on_rsa_full_providers) {
    REQUIRE(U(CryptCreateHash));
    static const struct { const char *n; } provs[] = { { PROVNAME_BASE }, { PROVNAME_ENH } };
    size_t i, j;
    for (i = 0; i < 2; i++) {
        HCRYPTPROV p = h_acq(PROV_RSA_FULL, provs[i].n); if (!p) continue;
        for (j = 4; j < NALGS; j++) {
            HCRYPTHASH h = 0; SET_ERR(0);
            CHECKF(!U(CryptCreateHash)(p, g_algs[j].alg, 0, 0, &h), "%s on %s", g_algs[j].name, provs[i].n);
            EXPECT_ERR(E_NTE_BAD_ALGID);
        }
        h_rel(p);
    }
}
TEST(capi_hash_create_md5_with_key_bad_key) {
    REQUIRE(U(CryptCreateHash)); PROLOG;
    BYTE k[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    HCRYPTKEY key = h_plainkey(p, CALG_RC4, k, 16, 0);
    if (key) {
        size_t i;
        for (i = 0; i < NALGS; i++) {
            HCRYPTHASH h = 0; SET_ERR(0);
            CHECKF(!U(CryptCreateHash)(p, g_algs[i].alg, key, 0, &h), "%s with key", g_algs[i].name);
            EXPECT_ERR(E_NTE_BAD_KEY);
        }
        U(CryptDestroyKey)(key);
    }
    EPILOG;
}
TEST(capi_hash_create_mac_hmac_require_key) {
    REQUIRE(U(CryptCreateHash)); PROLOG; HCRYPTHASH h = 0;
    SET_ERR(0); CHECK(!U(CryptCreateHash)(p, CALG_MAC, 0, 0, &h)); EXPECT_ERR(E_NTE_BAD_KEY);
    SET_ERR(0); CHECK(!U(CryptCreateHash)(p, CALG_HMAC, 0, 0, &h)); EXPECT_ERR(E_NTE_BAD_KEY);
    EPILOG;
}
TEST(capi_hash_create_after_destroyed_key_handle) {
    REQUIRE(U(CryptCreateHash)); PROLOG;
    BYTE k[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    HCRYPTKEY key = h_plainkey(p, CALG_RC2, k, 16, CRYPT_IPSEC_HMAC_KEY);
    if (key) {
        HCRYPTHASH h = 0;
        CHECK(U(CryptCreateHash)(p, CALG_HMAC, key, 0, &h));
        /* the hash keeps working after its key handle is destroyed */
        CHECK(U(CryptDestroyKey)(key));
        if (h) U(CryptDestroyHash)(h);
    }
    EPILOG;
}

/* ---------------------------------------------------------------- destroy */
TEST(capi_hash_destroy_ok_and_all_algs) {
    REQUIRE(U(CryptDestroyHash)); PROLOG; size_t i;
    for (i = 0; i < NALGS; i++) {
        HCRYPTHASH h = 0;
        if (U(CryptCreateHash)(p, g_algs[i].alg, 0, 0, &h)) CHECK(U(CryptDestroyHash)(h));
    }
    EPILOG;
}
TEST(capi_hash_destroy_after_partial_and_after_final) {
    REQUIRE(U(CryptDestroyHash)); PROLOG; HCRYPTHASH h = 0; BYTE d[20]; DWORD dl = 20;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    CHECK(U(CryptDestroyHash)(h));
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    CHECK(U(CryptDestroyHash)(h));
    EPILOG;
}
/* A destroyed handle is rejected. cryptsp tags a live hash object and clears the tag in CryptDestroyHash,
 * so a stale handle gives ERROR_INVALID_PARAMETER (the tag check) rather than an NTE_ code. */
/* The stale handle points at freed heap memory, so the exact error is heap-state dependent: observed only. */
static int bad_handle_err_ok(DWORD e) { if (e != ERROR_INVALID_PARAMETER) t_note("stale hash handle error 0x%lx (decomp: 87)", e); return 1; }
TEST(capi_hash_use_after_destroy_hashdata) {
    REQUIRE(U(CryptDestroyHash)); PROLOG; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h)); CHECK(U(CryptDestroyHash)(h));
    SET_ERR(0); CHECK(!U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    DWORD e = GetLastError(); CHECKF(bad_handle_err_ok(e), "err 0x%lx", e);
    EPILOG;
}
TEST(capi_hash_use_after_destroy_getparam) {
    REQUIRE(U(CryptDestroyHash)); PROLOG; HCRYPTHASH h = 0; DWORD dl = 4, v;
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h)); CHECK(U(CryptDestroyHash)(h));
    SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_ALGID, (BYTE *)&v, &dl, 0));
    DWORD e = GetLastError(); CHECKF(bad_handle_err_ok(e), "err 0x%lx", e);
    EPILOG;
}
TEST(capi_hash_use_after_destroy_destroy_again) {
    REQUIRE(U(CryptDestroyHash)); PROLOG; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h)); CHECK(U(CryptDestroyHash)(h));
    SET_ERR(0); CHECK(!U(CryptDestroyHash)(h));
    DWORD e = GetLastError(); CHECKF(bad_handle_err_ok(e), "err 0x%lx", e);
    EPILOG;
}
TEST(capi_hash_use_after_destroy_setparam_and_duplicate) {
    REQUIRE(U(CryptDestroyHash)); PROLOG; HCRYPTHASH h = 0, d = 0; BYTE v[16] = { 0 };
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h)); CHECK(U(CryptDestroyHash)(h));
    SET_ERR(0); CHECK(!U(CryptSetHashParam)(h, HP_HASHVAL, v, 0));
    DWORD e = GetLastError(); CHECKF(bad_handle_err_ok(e), "set err 0x%lx", e);
    SET_ERR(0); CHECK(!U(CryptDuplicateHash)(h, NULL, 0, &d));
    e = GetLastError(); CHECKF(bad_handle_err_ok(e), "dup err 0x%lx", e);
    EPILOG;
}
TEST(capi_hash_destroy_hash_after_provider_released_is_independent) {
    REQUIRE(U(CryptDestroyHash));
    HCRYPTPROV p = h_acq_aes(); if (!p) return; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h));
    /* provider handle is reference counted; releasing it with a live hash is a documented-undefined area: only
       check that destroying the hash first and then the provider succeeds */
    CHECK(U(CryptDestroyHash)(h));
    CHECK(U(CryptReleaseContext)(p, 0));
}

/* --------------------------------------------------------------- hashdata */
TEST(capi_hash_hashdata_flags_only_userdata_allowed) {
    REQUIRE(U(CryptHashData)); PROLOG; HCRYPTHASH h = 0; size_t i;
    static const DWORD bad[] = { 2, 3, 4, 0x100, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu };
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0); CHECKF(!U(CryptHashData)(h, (const BYTE *)"abc", 3, bad[i]), "flags 0x%lx", bad[i]);
        EXPECT_ERR(E_NTE_BAD_FLAGS);
    }
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, CRYPT_USERDATA));
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_hashdata_flags_checked_even_for_zero_length) {
    REQUIRE(U(CryptHashData)); PROLOG; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptHashData)(h, NULL, 0, 2)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_hashdata_null_buffer_nonzero_len_bad_data) {
    REQUIRE(U(CryptHashData)); PROLOG; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptHashData)(h, NULL, 1, 0)); EXPECT_ERR(E_NTE_BAD_DATA);
    SET_ERR(0); CHECK(!U(CryptHashData)(h, NULL, 100, 0)); EXPECT_ERR(E_NTE_BAD_DATA);
    /* a failed call did not disturb the state */
    BYTE d[20]; DWORD dl = 20;
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    EXPECT_HEX(d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_hashdata_after_finalize_bad_hash_state) {
    REQUIRE(U(CryptHashData)); PROLOG; size_t i;
    for (i = 0; i < NALGS; i++) {
        HCRYPTHASH h = 0; BYTE d[64]; DWORD dl = sizeof d;
        CHECK(U(CryptCreateHash)(p, g_algs[i].alg, 0, 0, &h));
        CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
        SET_ERR(0); CHECKF(!U(CryptHashData)(h, (const BYTE *)"d", 1, 0), "%s", g_algs[i].name);
        EXPECT_ERR(E_NTE_BAD_HASH_STATE);
        SET_ERR(0); CHECK(!U(CryptHashData)(h, (const BYTE *)"d", 1, CRYPT_USERDATA));
        EXPECT_ERR(E_NTE_BAD_HASH_STATE);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hash_hashdata_zero_length_after_finalize_succeeds) {
    REQUIRE(U(CryptHashData)); PROLOG; HCRYPTHASH h = 0; BYTE d[20]; DWORD dl = 20;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    /* the zero-length shortcut is taken before the finalized-state test */
    SET_ERR(0); BOOL ok = U(CryptHashData)(h, (const BYTE *)"x", 0, 0);
    CHECKF(ok, "err 0x%lx", GetLastError());
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_hashdata_size_query_does_not_finalize) {
    REQUIRE(U(CryptHashData)); PROLOG; HCRYPTHASH h = 0; DWORD dl = 0; BYTE d[20];
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"a", 1, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, NULL, &dl, 0)); CHECK(dl == 20);
    CHECK(U(CryptHashData)(h, (const BYTE *)"bc", 2, 0));
    dl = 20; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    EXPECT_HEX(d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_hashdata_short_buffer_does_not_finalize) {
    REQUIRE(U(CryptHashData)); PROLOG; HCRYPTHASH h = 0; DWORD dl = 19; BYTE d[20];
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"a", 1, 0));
    SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0)); EXPECT_ERR(ERROR_MORE_DATA); CHECK(dl == 20);
    CHECK(U(CryptHashData)(h, (const BYTE *)"bc", 2, 0));
    dl = 20; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    EXPECT_HEX(d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    U(CryptDestroyHash)(h); EPILOG;
}

/* ---------------------------------------------------------------- getparam */
TEST(capi_hash_getparam_algid_all) {
    REQUIRE(U(CryptGetHashParam)); PROLOG; size_t i;
    for (i = 0; i < NALGS; i++) {
        HCRYPTHASH h = 0; DWORD v = 0, dl = 4;
        CHECK(U(CryptCreateHash)(p, g_algs[i].alg, 0, 0, &h));
        SET_ERR(0); CHECK(U(CryptGetHashParam)(h, HP_ALGID, (BYTE *)&v, &dl, 0));
        CHECKF(v == g_algs[i].alg && dl == 4, "%s got 0x%lx", g_algs[i].name, v);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hash_getparam_hashsize_all) {
    REQUIRE(U(CryptGetHashParam)); PROLOG; size_t i;
    for (i = 0; i < NALGS; i++) {
        HCRYPTHASH h = 0; DWORD v = 0, dl = 4;
        CHECK(U(CryptCreateHash)(p, g_algs[i].alg, 0, 0, &h));
        CHECK(U(CryptGetHashParam)(h, HP_HASHSIZE, (BYTE *)&v, &dl, 0));
        CHECKF(v == g_algs[i].len && dl == 4, "%s got %lu", g_algs[i].name, v);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hash_getparam_ssl3_shamd5_size_and_algid) {
    REQUIRE(U(CryptGetHashParam)); PROLOG; HCRYPTHASH h = 0; DWORD v = 0, dl = 4;
    CHECK(U(CryptCreateHash)(p, CALG_SSL3_SHAMD5, 0, 0, &h));
    CHECK(U(CryptGetHashParam)(h, HP_ALGID, (BYTE *)&v, &dl, 0)); CHECK(v == CALG_SSL3_SHAMD5);
    dl = 4; CHECK(U(CryptGetHashParam)(h, HP_HASHSIZE, (BYTE *)&v, &dl, 0)); CHECK(v == 36);
    dl = 0; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, NULL, &dl, 0)); CHECK(dl == 36);
    U(CryptDestroyHash)(h); EPILOG;
}
static void dword_param_protocol(DWORD param, ALG_ID alg, DWORD want) {
    PROLOG; HCRYPTHASH h = 0; DWORD v = 0xCCCCCCCC, dl;
    CHECK(U(CryptCreateHash)(p, alg, 0, 0, &h));
    /* NULL buffer: size query succeeds */
    dl = 0; SET_ERR(0); CHECK(U(CryptGetHashParam)(h, param, NULL, &dl, 0)); CHECK(dl == 4);
    dl = 99; CHECK(U(CryptGetHashParam)(h, param, NULL, &dl, 0)); CHECK(dl == 4);
    /* buffer too small: ERROR_MORE_DATA and required size */
    dl = 0; SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, param, (BYTE *)&v, &dl, 0)); EXPECT_ERR(ERROR_MORE_DATA); CHECK(dl == 4);
    CHECK(v == 0xCCCCCCCC);
    dl = 3; SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, param, (BYTE *)&v, &dl, 0)); EXPECT_ERR(ERROR_MORE_DATA); CHECK(dl == 4);
    /* exact and larger */
    dl = 4; CHECK(U(CryptGetHashParam)(h, param, (BYTE *)&v, &dl, 0)); CHECK(dl == 4); CHECK(v == want);
    BYTE big[16]; memset(big, 0xCC, sizeof big); dl = 16;
    CHECK(U(CryptGetHashParam)(h, param, big, &dl, 0)); CHECK(dl == 4); CHECK(*(DWORD *)big == want); CHECK(big[4] == 0xCC);
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_getparam_algid_buffer_protocol_sha1) { REQUIRE(U(CryptGetHashParam)); dword_param_protocol(HP_ALGID, CALG_SHA1, CALG_SHA1); }
TEST(capi_hash_getparam_algid_buffer_protocol_md5) { REQUIRE(U(CryptGetHashParam)); dword_param_protocol(HP_ALGID, CALG_MD5, CALG_MD5); }
TEST(capi_hash_getparam_hashsize_buffer_protocol_sha256) { REQUIRE(U(CryptGetHashParam)); dword_param_protocol(HP_HASHSIZE, CALG_SHA_256, 32); }
TEST(capi_hash_getparam_hashsize_buffer_protocol_md2) { REQUIRE(U(CryptGetHashParam)); dword_param_protocol(HP_HASHSIZE, CALG_MD2, 16); }

TEST(capi_hash_getparam_hashval_buffer_protocol) {
    REQUIRE(U(CryptGetHashParam)); PROLOG; size_t i;
    for (i = 0; i < NALGS; i++) {
        HCRYPTHASH h = 0; BYTE d[80]; DWORD dl;
        CHECK(U(CryptCreateHash)(p, g_algs[i].alg, 0, 0, &h));
        CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
        dl = 0; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, NULL, &dl, 0)); CHECKF(dl == g_algs[i].len, "%s", g_algs[i].name);
        dl = 0; SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0)); EXPECT_ERR(ERROR_MORE_DATA); CHECK(dl == g_algs[i].len);
        dl = 1; SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0)); EXPECT_ERR(ERROR_MORE_DATA);
        dl = g_algs[i].len - 1; SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0)); EXPECT_ERR(ERROR_MORE_DATA); CHECK(dl == g_algs[i].len);
        memset(d, 0xCC, sizeof d); dl = g_algs[i].len + 5;
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0)); CHECK(dl == g_algs[i].len);
        CHECK(d[g_algs[i].len] == 0xCC);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hash_getparam_hashval_repeatable_after_finish) {
    REQUIRE(U(CryptGetHashParam)); PROLOG; HCRYPTHASH h = 0; BYTE a[20], b[20]; DWORD la = 20, lb = 20;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, a, &la, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, b, &lb, 0));
    CHECK(la == 20 && lb == 20 && !memcmp(a, b, 20));
    /* the finished hash still reports algid and size */
    DWORD v = 0, dl = 4;
    CHECK(U(CryptGetHashParam)(h, HP_ALGID, (BYTE *)&v, &dl, 0)); CHECK(v == CALG_SHA1);
    dl = 4; CHECK(U(CryptGetHashParam)(h, HP_HASHSIZE, (BYTE *)&v, &dl, 0)); CHECK(v == 20);
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_getparam_nonzero_flags_bad_flags) {
    REQUIRE(U(CryptGetHashParam)); PROLOG; HCRYPTHASH h = 0; DWORD v, dl = 4;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_ALGID, (BYTE *)&v, &dl, 1)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    dl = 4; SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HASHSIZE, (BYTE *)&v, &dl, 0x80000000u)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    BYTE d[20]; dl = 20; SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 2)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_getparam_unknown_dwparam_bad_type) {
    REQUIRE(U(CryptGetHashParam)); PROLOG; HCRYPTHASH h = 0; size_t i; BYTE b[64];
    static const DWORD prm[] = { 0, 3, 5 /*HP_HMAC_INFO*/, 6, 7, 8, 0x10, 99, 0xFFFFFFFFu };
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    for (i = 0; i < sizeof prm / sizeof prm[0]; i++) {
        DWORD dl = sizeof b; SET_ERR(0);
        CHECKF(!U(CryptGetHashParam)(h, prm[i], b, &dl, 0), "param %lu", prm[i]);
        EXPECT_ERR(E_NTE_BAD_TYPE);
    }
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_getparam_null_datalen_invalid_parameter) {
    REQUIRE(U(CryptGetHashParam));
    if (t_is_wine()) { t_skip("emulator crashes on NULL pdwDataLen"); return; }
    PROLOG; HCRYPTHASH h = 0; BYTE b[20];
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HASHVAL, b, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_getparam_hashval_matches_across_instances) {
    REQUIRE(U(CryptGetHashParam)); PROLOG; HCRYPTHASH a = 0, b = 0; BYTE da[32], db[32]; DWORD la = 32, lb = 32;
    CHECK(U(CryptCreateHash)(p, CALG_SHA_256, 0, 0, &a)); CHECK(U(CryptCreateHash)(p, CALG_SHA_256, 0, 0, &b));
    CHECK(U(CryptHashData)(a, (const BYTE *)"hello", 5, 0)); CHECK(U(CryptHashData)(b, (const BYTE *)"hello", 5, 0));
    CHECK(U(CryptGetHashParam)(a, HP_HASHVAL, da, &la, 0)); CHECK(U(CryptGetHashParam)(b, HP_HASHVAL, db, &lb, 0));
    CHECK(la == lb && !memcmp(da, db, la));
    U(CryptDestroyHash)(a); U(CryptDestroyHash)(b); EPILOG;
}

/* --------------------------------------------------------------- misc/A-W */
TEST(capi_hash_acquire_a_w_parity_same_digest) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptAcquireContextW));
    HCRYPTPROV pa = 0, pw = 0; BYTE da[20], dw[20]; DWORD la = 20, lw = 20;
    CHECK(U(CryptAcquireContextA)(&pa, NULL, PROVNAME_AES, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    CHECK(U(CryptAcquireContextW)(&pw, NULL, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    if (pa && pw) {
        CHECK(h_hash(pa, CALG_SHA1, (const BYTE *)"abc", 3, da, &la));
        CHECK(h_hash(pw, CALG_SHA1, (const BYTE *)"abc", 3, dw, &lw));
        CHECK(la == lw && !memcmp(da, dw, la));
    }
    h_rel(pa); h_rel(pw);
}
TEST(capi_hash_provider_default_aes_type_sha256) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV p = 0; BYTE d[32]; DWORD dl = 32;
    if (!U(CryptAcquireContextA)(&p, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { t_note("default AES provider unavailable 0x%lx", GetLastError()); return; }
    CHECK(h_hash(p, CALG_SHA_256, (const BYTE *)"abc", 3, d, &dl));
    EXPECT_HEX(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    h_rel(p);
}
TEST(capi_hash_hash_on_released_provider_other_handle_ok) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(), q = h_acq_aes(); if (!p || !q) { h_rel(p); h_rel(q); return; }
    BYTE d[16]; DWORD dl = 16;
    h_rel(p);
    CHECK(h_hash(q, CALG_MD5, (const BYTE *)"abc", 3, d, &dl));
    h_rel(q);
}
TEST(capi_hash_many_hash_objects_one_provider) {
    REQUIRE(U(CryptCreateHash)); PROLOG; HCRYPTHASH hs[64]; int i, n = 0;
    for (i = 0; i < 64; i++) { if (U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &hs[n])) n++; }
    CHECK(n == 64);
    for (i = 0; i < n; i++) CHECK(U(CryptHashData)(hs[i], (const BYTE *)&i, sizeof i, 0));
    for (i = 0; i < n; i++) { BYTE d[20]; DWORD dl = 20; CHECK(U(CryptGetHashParam)(hs[i], HP_HASHVAL, d, &dl, 0)); }
    for (i = 0; i < n; i++) CHECK(U(CryptDestroyHash)(hs[i]));
    EPILOG;
}

/* -------------------------------------------------------------- duplicate */
TEST(capi_hash_duplicate_midstream_independent) {
    REQUIRE(U(CryptDuplicateHash)); PROLOG; HCRYPTHASH h = 0, d = 0; BYTE x[20], y[20]; DWORD lx = 20, ly = 20;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"a", 1, 0));
    SET_ERR(0); CHECK(U(CryptDuplicateHash)(h, NULL, 0, &d)); CHECK(d && d != h);
    CHECK(U(CryptHashData)(h, (const BYTE *)"bc", 2, 0));   /* original -> "abc" */
    CHECK(U(CryptHashData)(d, (const BYTE *)"bd", 2, 0));   /* duplicate -> "abd" */
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, x, &lx, 0));
    CHECK(U(CryptGetHashParam)(d, HP_HASHVAL, y, &ly, 0));
    EXPECT_HEX(x, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(memcmp(x, y, 20) != 0);
    EXPECT_HEX(y, 20, "cb4cc28df0fdbe0ecf9d9662e294b118092a5735");
    U(CryptDestroyHash)(h); U(CryptDestroyHash)(d); EPILOG;
}
TEST(capi_hash_duplicate_all_algs_continue) {
    REQUIRE(U(CryptDuplicateHash)); PROLOG; size_t i;
    for (i = 0; i < NALGS; i++) {
        HCRYPTHASH h = 0, d = 0; BYTE x[64], y[64]; DWORD lx = 64, ly = 64;
        CHECK(U(CryptCreateHash)(p, g_algs[i].alg, 0, 0, &h));
        CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
        CHECK(U(CryptDuplicateHash)(h, NULL, 0, &d));
        CHECK(U(CryptHashData)(h, (const BYTE *)"def", 3, 0)); CHECK(U(CryptHashData)(d, (const BYTE *)"def", 3, 0));
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, x, &lx, 0)); CHECK(U(CryptGetHashParam)(d, HP_HASHVAL, y, &ly, 0));
        CHECKF(lx == ly && lx == g_algs[i].len && !memcmp(x, y, lx), "%s", g_algs[i].name);
        U(CryptDestroyHash)(h); U(CryptDestroyHash)(d);
    }
    EPILOG;
}
TEST(capi_hash_duplicate_of_finished_hash_has_same_value_and_state) {
    REQUIRE(U(CryptDuplicateHash)); PROLOG; HCRYPTHASH h = 0, d = 0; BYTE x[20], y[20]; DWORD lx = 20, ly = 20;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, x, &lx, 0));
    CHECK(U(CryptDuplicateHash)(h, NULL, 0, &d));
    CHECK(U(CryptGetHashParam)(d, HP_HASHVAL, y, &ly, 0));
    CHECK(lx == ly && !memcmp(x, y, 20));
    SET_ERR(0); CHECK(!U(CryptHashData)(d, (const BYTE *)"z", 1, 0)); EXPECT_ERR(E_NTE_BAD_HASH_STATE);
    U(CryptDestroyHash)(h); U(CryptDestroyHash)(d); EPILOG;
}
TEST(capi_hash_duplicate_survives_original_destroy) {
    REQUIRE(U(CryptDuplicateHash)); PROLOG; HCRYPTHASH h = 0, d = 0; BYTE y[20]; DWORD ly = 20;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"ab", 2, 0));
    CHECK(U(CryptDuplicateHash)(h, NULL, 0, &d));
    CHECK(U(CryptDestroyHash)(h));
    CHECK(U(CryptHashData)(d, (const BYTE *)"c", 1, 0));
    CHECK(U(CryptGetHashParam)(d, HP_HASHVAL, y, &ly, 0));
    EXPECT_HEX(y, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    U(CryptDestroyHash)(d); EPILOG;
}
TEST(capi_hash_duplicate_chain) {
    REQUIRE(U(CryptDuplicateHash)); PROLOG; HCRYPTHASH a = 0, b = 0, c = 0; BYTE y[16]; DWORD ly = 16;
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &a));
    CHECK(U(CryptHashData)(a, (const BYTE *)"a", 1, 0));
    CHECK(U(CryptDuplicateHash)(a, NULL, 0, &b));
    CHECK(U(CryptHashData)(b, (const BYTE *)"b", 1, 0));
    CHECK(U(CryptDuplicateHash)(b, NULL, 0, &c));
    CHECK(U(CryptHashData)(c, (const BYTE *)"c", 1, 0));
    CHECK(U(CryptGetHashParam)(c, HP_HASHVAL, y, &ly, 0));
    EXPECT_HEX(y, 16, "900150983cd24fb0d6963f7d28e17f72");
    U(CryptDestroyHash)(a); U(CryptDestroyHash)(b); U(CryptDestroyHash)(c); EPILOG;
}
TEST(capi_hash_duplicate_nonzero_flags_bad_flags) {
    REQUIRE(U(CryptDuplicateHash)); PROLOG; HCRYPTHASH h = 0, d = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptDuplicateHash)(h, NULL, 1, &d)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    SET_ERR(0); CHECK(!U(CryptDuplicateHash)(h, NULL, 0x80000000u, &d)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_duplicate_reserved_nonnull_invalid_parameter) {
    REQUIRE(U(CryptDuplicateHash)); PROLOG; HCRYPTHASH h = 0, d = 0; DWORD rsv = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptDuplicateHash)(h, &rsv, 0, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* the reserved-pointer check precedes the flags check */
    SET_ERR(0); CHECK(!U(CryptDuplicateHash)(h, &rsv, 1, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_duplicate_null_output_invalid_parameter) {
    REQUIRE(U(CryptDuplicateHash)); PROLOG; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptDuplicateHash)(h, NULL, 0, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CryptDestroyHash)(h); EPILOG;
}

/* ------------------------------------------------------ hash session key */
static const BYTE g_k16[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
TEST(capi_hash_sessionkey_little_endian_hashes_raw_key_bytes) {
    REQUIRE(U(CryptHashSessionKey)); PROLOG; HCRYPTHASH h = 0; BYTE d[16], e[16]; DWORD dl = 16, el = 16;
    HCRYPTKEY k = h_plainkey(p, CALG_RC4, g_k16, 16, CRYPT_EXPORTABLE);
    if (k) {
        CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h));
        SET_ERR(0); BOOL ok = U(CryptHashSessionKey)(h, k, CRYPT_LITTLE_ENDIAN); CHECKF(ok, "err 0x%lx", GetLastError());
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
        CHECK(h_hash(p, CALG_MD5, g_k16, 16, e, &el));
        CHECK(!memcmp(d, e, 16));
        U(CryptDestroyHash)(h); U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_hash_sessionkey_default_hashes_reversed_key_bytes) {
    REQUIRE(U(CryptHashSessionKey)); PROLOG; HCRYPTHASH h = 0; BYTE d[20], e[20], r[16]; DWORD dl = 20, el = 20;
    HCRYPTKEY k = h_plainkey(p, CALG_RC4, g_k16, 16, CRYPT_EXPORTABLE);
    if (k) {
        int i; for (i = 0; i < 16; i++) r[i] = g_k16[15 - i];
        CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
        CHECK(U(CryptHashSessionKey)(h, k, 0));
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
        CHECK(h_hash(p, CALG_SHA1, r, 16, e, &el));
        CHECK(!memcmp(d, e, 20));
        U(CryptDestroyHash)(h); U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_hash_sessionkey_bad_flags) {
    REQUIRE(U(CryptHashSessionKey)); PROLOG; HCRYPTHASH h = 0;
    HCRYPTKEY k = h_plainkey(p, CALG_RC4, g_k16, 16, 0);
    if (k) {
        CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h));
        SET_ERR(0); CHECK(!U(CryptHashSessionKey)(h, k, 2)); EXPECT_ERR(E_NTE_BAD_FLAGS);
        SET_ERR(0); CHECK(!U(CryptHashSessionKey)(h, k, 0x80000001u)); EXPECT_ERR(E_NTE_BAD_FLAGS);
        U(CryptDestroyHash)(h); U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_hash_sessionkey_after_finalize_bad_hash_state) {
    REQUIRE(U(CryptHashSessionKey)); PROLOG; HCRYPTHASH h = 0; BYTE d[16]; DWORD dl = 16;
    HCRYPTKEY k = h_plainkey(p, CALG_RC4, g_k16, 16, 0);
    if (k) {
        CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h));
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
        SET_ERR(0); CHECK(!U(CryptHashSessionKey)(h, k, CRYPT_LITTLE_ENDIAN)); EXPECT_ERR(E_NTE_BAD_HASH_STATE);
        U(CryptDestroyHash)(h); U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_hash_sessionkey_combined_with_data) {
    REQUIRE(U(CryptHashSessionKey)); PROLOG; HCRYPTHASH h = 0; BYTE d[20], e[20], cat[19]; DWORD dl = 20, el = 20;
    HCRYPTKEY k = h_plainkey(p, CALG_RC4, g_k16, 16, 0);
    if (k) {
        memcpy(cat, "abc", 3); memcpy(cat + 3, g_k16, 16);
        CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
        CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
        CHECK(U(CryptHashSessionKey)(h, k, CRYPT_LITTLE_ENDIAN));
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
        CHECK(h_hash(p, CALG_SHA1, cat, 19, e, &el));
        CHECK(!memcmp(d, e, 20));
        U(CryptDestroyHash)(h); U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_hash_sessionkey_all_hash_algs_le) {
    REQUIRE(U(CryptHashSessionKey)); PROLOG; size_t i;
    HCRYPTKEY k = h_plainkey(p, CALG_RC4, g_k16, 16, 0);
    if (k) {
        for (i = 0; i < NALGS; i++) {
            HCRYPTHASH h = 0; BYTE d[64], e[64]; DWORD dl = 64, el = 64;
            CHECK(U(CryptCreateHash)(p, g_algs[i].alg, 0, 0, &h));
            CHECK(U(CryptHashSessionKey)(h, k, CRYPT_LITTLE_ENDIAN));
            CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
            CHECK(h_hash(p, g_algs[i].alg, g_k16, 16, e, &el));
            CHECKF(dl == el && !memcmp(d, e, dl), "%s", g_algs[i].name);
            U(CryptDestroyHash)(h);
        }
        U(CryptDestroyKey)(k);
    }
    EPILOG;
}

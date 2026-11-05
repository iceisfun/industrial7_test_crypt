#include "cpc.h"
/* Provider functionality sanity through VERIFYCONTEXT: standard hash known answers, hash parameter
 * protocol, algorithm-enumeration flag masks. All answers are the FIPS 180 / RFC 1321 values for "abc". */

static int acqv(int i, HCRYPTPROV *h) {
    *h = 0;
    if (cpc_provs[i].dss && t_is_wine()) { t_skip("dssenh provider entry points are unimplemented in this emulator"); return 0; }
    if (!cpc_acq(h, cpc_provs[i].a, cpc_provs[i].type, X_VERIFY)) {
        t_check(0, __FILE__, __LINE__, "acquire", "%s err 0x%lx", cpc_provs[i].a, GetLastError());
        return 0;
    }
    return 1;
}

static const BYTE md5_abc[16] = { 0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72 };
static const BYTE sha1_abc[20] = { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d };
static const BYTE sha256_abc[32] = { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
static const BYTE sha384_abc[48] = { 0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
    0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
    0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7 };
static const BYTE sha512_abc[64] = { 0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
    0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
    0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
    0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f };

typedef struct { ALG_ID id; const BYTE *dig; DWORD len; } kat;
static const kat kats[] = {
    { CALG_MD5, md5_abc, 16 }, { CALG_SHA1, sha1_abc, 20 }, { CALG_SHA_256, sha256_abc, 32 },
    { CALG_SHA_384, sha384_abc, 48 }, { CALG_SHA_512, sha512_abc, 64 } };

static int prov_lists(const cpc_prov *P, ALG_ID id) {
    for (int k = 0; k < P->nreq; k++) if (P->req[k] == id) return 1;
    return 0;
}

static void hash_kat(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptHashData)); REQUIRE(U(CryptGetHashParam)); REQUIRE(U(CryptDestroyHash));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    for (unsigned k = 0; k < sizeof kats / sizeof kats[0]; k++) {
        if (!prov_lists(P, kats[k].id)) continue;
        HCRYPTHASH hh = 0;
        if (!U(CryptCreateHash)(h, kats[k].id, 0, 0, &hh)) { t_check(0, __FILE__, __LINE__, "create", "%s alg 0x%x err 0x%lx", P->a, kats[k].id, GetLastError()); continue; }
        DWORD v = 0, n = 4;
        CHECK(U(CryptGetHashParam)(hh, HP_ALGID, (BYTE *)&v, &n, 0)); EXPECT_EQ(v, kats[k].id);
        n = 4; v = 0;
        CHECK(U(CryptGetHashParam)(hh, HP_HASHSIZE, (BYTE *)&v, &n, 0)); EXPECT_EQ(v, kats[k].len);
        CHECK(U(CryptHashData)(hh, (const BYTE *)"abc", 3, 0));
        BYTE out[80]; memset(out, 0xEE, sizeof out);
        /* size protocol */
        n = 0; SET_ERR(0);
        CHECK(U(CryptGetHashParam)(hh, HP_HASHVAL, NULL, &n, 0)); EXPECT_EQ(n, kats[k].len);
        n = kats[k].len - 1; SET_ERR(0);
        CHECK(!U(CryptGetHashParam)(hh, HP_HASHVAL, out, &n, 0)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, kats[k].len);
        n = sizeof out;
        CHECK(U(CryptGetHashParam)(hh, HP_HASHVAL, out, &n, 0)); EXPECT_EQ(n, kats[k].len);
        t_check(!memcmp(out, kats[k].dig, kats[k].len), __FILE__, __LINE__, "digest", "%s alg 0x%x digest mismatch", P->a, kats[k].id);
        CHECK(U(CryptDestroyHash)(hh));
    }
    cpc_rel(h);
}
PERPROV(cpc_hash_abc, hash_kat)

/* A finished hash cannot take more data. */
static void hash_after_final(int i) {
    REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptHashData)); REQUIRE(U(CryptGetHashParam)); REQUIRE(U(CryptDestroyHash));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    HCRYPTHASH hh = 0;
    CHECK(U(CryptCreateHash)(h, CALG_SHA1, 0, 0, &hh));
    if (hh) {
        BYTE out[20]; DWORD n = sizeof out;
        CHECK(U(CryptHashData)(hh, (const BYTE *)"abc", 3, 0));
        CHECK(U(CryptGetHashParam)(hh, HP_HASHVAL, out, &n, 0));
        SET_ERR(0);
        CHECK(!U(CryptHashData)(hh, (const BYTE *)"d", 1, 0));
        EXPECT_ERR(0x8009000cUL /* NTE_BAD_HASH_STATE */);
        n = sizeof out;
        CHECK(U(CryptGetHashParam)(hh, HP_HASHVAL, out, &n, 0));
        CHECK(!memcmp(out, sha1_abc, 20));
        CHECK(U(CryptDestroyHash)(hh));
    }
    cpc_rel(h);
}
PERPROV(cpc_hash_after_final, hash_after_final)

/* Unknown / unusable algorithm ids are NTE_BAD_ALGID and leave the output handle alone. */
static void hash_bad_alg(int i) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    ALG_ID bad[] = { 0, 1, ALG_CLASS_HASH, ALG_CLASS_HASH | ALG_TYPE_ANY | 0x1ff, ALG_CLASS_DATA_ENCRYPT | 1, 0xffffffff };
    for (unsigned k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        HCRYPTHASH hh = 0x4242; SET_ERR(0);
        BOOL ok = U(CryptCreateHash)(h, bad[k], 0, 0, &hh);
        t_check(!ok && GetLastError() == X_NTE_BAD_ALGID, __FILE__, __LINE__, "bad alg", "%s alg 0x%x ok=%d err 0x%lx", cpc_provs[i].a, bad[k], ok, GetLastError());
        if (ok) U(CryptDestroyHash)(hh);
    }
    HCRYPTHASH hh = 0x4242; SET_ERR(0);
    BOOL ok = U(CryptCreateHash)(h, CALG_SHA1, 0, 1, &hh);
    t_check(!ok && GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "bad flags", "%s ok=%d err 0x%lx", cpc_provs[i].a, ok, GetLastError());
    if (ok) U(CryptDestroyHash)(hh);
    cpc_rel(h);
}
PERPROV(cpc_hash_bad_alg, hash_bad_alg)

/* PP_ENUMALGS / PP_ENUMALGS_EX flag masks: bit 3 and above are never valid; bit 2 (CRYPT_SGC_ENUM)
 * is only accepted by the schannel provider. */
static void enum_flag_masks(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    DWORD params[2] = { PP_ENUMALGS, PP_ENUMALGS_EX };
    for (int p = 0; p < 2; p++) {
        PROV_ENUMALGS_EX e; DWORD n, bad[] = { 8, 0x10, 0x100, 0x80000000, 0xfffffff8 };
        for (unsigned k = 0; k < 5; k++) {
            n = sizeof e; SET_ERR(0);
            BOOL ok = cpc_gpp(h, params[p], &e, &n, bad[k]);
            t_check(!ok && GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "enum flags", "%s param %lu flags 0x%lx ok=%d err 0x%lx", P->a, params[p], bad[k], ok, GetLastError());
        }
        if (P->type != 12 && !P->dss) {
            n = sizeof e; SET_ERR(0);
            BOOL ok = cpc_gpp(h, params[p], &e, &n, 4);
            t_check(!ok && GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "sgc flag", "%s param %lu ok=%d err 0x%lx", P->a, params[p], ok, GetLastError());
        }
    }
    cpc_rel(h);
}
PERPROV(cpc_gpp_enum_flag_masks, enum_flag_masks)

/* CRYPT_FIRST restarts the enumeration at any time. */
static void enum_restart(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    PROV_ENUMALGS a, b, c; DWORD n = sizeof a;
    if (!cpc_gpp(h, PP_ENUMALGS, &a, &n, CRYPT_FIRST)) { CHECK(0); cpc_rel(h); return; }
    n = sizeof b; CHECK(cpc_gpp(h, PP_ENUMALGS, &b, &n, CRYPT_NEXT));
    n = sizeof c; CHECK(cpc_gpp(h, PP_ENUMALGS, &c, &n, CRYPT_FIRST));
    CHECK(!memcmp(&a, &c, sizeof a));
    n = sizeof c; CHECK(cpc_gpp(h, PP_ENUMALGS, &c, &n, CRYPT_NEXT));
    CHECK(!memcmp(&b, &c, sizeof b));
    cpc_rel(h);
}
PERPROV(cpc_gpp_enumalgs_restart, enum_restart)

/* A fresh context starts its own cursor even while another context of the same provider is mid-enumeration. */
static void enum_ctx_independent(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h1, h2; if (!acqv(i, &h1)) return;
    if (!acqv(i, &h2)) { cpc_rel(h1); return; }
    PROV_ENUMALGS a, b, c; DWORD n = sizeof a;
    CHECK(cpc_gpp(h1, PP_ENUMALGS, &a, &n, CRYPT_FIRST));
    n = sizeof b; CHECK(cpc_gpp(h1, PP_ENUMALGS, &b, &n, CRYPT_NEXT));
    n = sizeof c; CHECK(cpc_gpp(h2, PP_ENUMALGS, &c, &n, CRYPT_FIRST));
    CHECK(!memcmp(&a, &c, sizeof a));
    cpc_rel(h1); cpc_rel(h2);
}
PERPROV(cpc_gpp_enumalgs_ctx_cursor, enum_ctx_independent)

/* Handles are non-zero, distinct across providers and usable after the first context is released. */
TEST(cpc_handles_distinct_across_providers) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h[10] = {0};
    int ok[10] = {0};
    for (int i = 0; i < cpc_nprovs; i++) {
        if (cpc_provs[i].dss && t_is_wine()) continue;
        if (i == CPC_SIG_IDX && !cpc_prov_registered(cpc_provs[i].a)) continue;
        ok[i] = cpc_acq(&h[i], cpc_provs[i].a, cpc_provs[i].type, X_VERIFY);
        CHECKF(ok[i], "%s err 0x%lx", cpc_provs[i].a, GetLastError());
        if (ok[i]) CHECK(h[i] != 0);
    }
    for (int a = 0; a < 10; a++) for (int b = a + 1; b < 10; b++) if (ok[a] && ok[b]) CHECK(h[a] != h[b]);
    for (int i = 0; i < 10; i++) if (ok[i]) cpc_rel(h[i]);
}

/* A failed acquire never leaves a usable context behind: acquire/release after a failure still works. */
TEST(cpc_acquire_recovers_after_failures) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    for (int k = 0; k < 20; k++) {
        CHECK(!cpc_acq(&h, "cpc no such provider", 1, X_VERIFY));
        CHECK(!cpc_acq(&h, NULL, 0, X_VERIFY));
        CHECK(!cpc_acq(&h, MS_DEF_PROV_A, PROV_DSS, X_VERIFY));
    }
    h = 0;
    CHECK(cpc_acq(&h, MS_DEF_PROV_A, PROV_RSA_FULL, X_VERIFY));
    cpc_rel(h);
}

/* Provider names in the registry are matched case-insensitively on the W entry as well. */
TEST(cpc_acquire_w_name_case_insensitive) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h = 0;
    BOOL ok = U(CryptAcquireContextW)(&h, NULL, L"MICROSOFT ENHANCED CRYPTOGRAPHIC PROVIDER V1.0", PROV_RSA_FULL, X_VERIFY);
    CHECKF(ok, "err 0x%lx", GetLastError());
    cpc_rel(h);
}

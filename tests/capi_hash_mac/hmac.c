/* CryptSetHashParam, HMAC (CALG_HMAC + HP_HMAC_INFO), MAC (CALG_MAC) and TLS1PRF hashes. */
#include "h.h"
#include "vectors.h"

#define PROLOG HCRYPTPROV p = h_acq_aes(); if (!p) return
#define EPILOG h_rel(p)

static const struct { ALG_ID alg; const char *name; DWORD len; const char *const *hm; } g_h[] = {
    { CALG_MD2, "MD2", 16, hv_hmac_MD2 }, { CALG_MD4, "MD4", 16, hv_hmac_MD4 }, { CALG_MD5, "MD5", 16, hv_hmac_MD5 },
    { CALG_SHA1, "SHA1", 20, hv_hmac_SHA1 }, { CALG_SHA_256, "SHA256", 32, hv_hmac_SHA256 },
    { CALG_SHA_384, "SHA384", 48, hv_hmac_SHA384 }, { CALG_SHA_512, "SHA512", 64, hv_hmac_SHA512 },
};
#define NH (sizeof g_h / sizeof g_h[0])

/* start an HMAC hash with the given key (RC2 plaintext key blob, CRYPT_IPSEC_HMAC_KEY) and inner hash alg */
static HCRYPTHASH hmac_begin(HCRYPTPROV p, ALG_ID halg, const BYTE *key, DWORD klen, BOOL *okp) {
    HCRYPTKEY k = h_plainkey(p, CALG_RC2, key, klen, CRYPT_IPSEC_HMAC_KEY);
    HCRYPTHASH h = 0; HMAC_INFO hi; *okp = FALSE;
    if (!k) return 0;
    if (!U(CryptCreateHash)(p, CALG_HMAC, k, 0, &h)) { t_note("HMAC create failed 0x%lx", GetLastError()); U(CryptDestroyKey)(k); return 0; }
    memset(&hi, 0, sizeof hi); hi.HashAlgid = halg;
    /* the key handle must stay valid until HP_HMAC_INFO has been applied */
    if (!U(CryptSetHashParam)(h, HP_HMAC_INFO, (BYTE *)&hi, 0)) { t_note("HMAC_INFO set failed 0x%lx", GetLastError()); U(CryptDestroyHash)(h); U(CryptDestroyKey)(k); return 0; }
    U(CryptDestroyKey)(k);
    *okp = TRUE; return h;
}
static void hmac_rows(ALG_ID alg, const char *const *exp, DWORD chunk) {
    PROLOG; size_t i;
    for (i = 0; i < HV_NHMAC; i++) {
        BYTE key[200], data[400], out[80], e[80]; DWORD ol = sizeof out, off; BOOL ok;
        int kl = h_hex2bin(hv_hmac_ins[i].key, key, sizeof key), dl = h_hex2bin(hv_hmac_ins[i].data, data, sizeof data);
        HCRYPTHASH h = hmac_begin(p, alg, key, (DWORD)kl, &ok);
        if (!h) { CHECKF(0, "begin %s", hv_hmac_ins[i].name); continue; }
        for (off = 0; off < (DWORD)dl; off += chunk) { DWORD n = (DWORD)dl - off < chunk ? (DWORD)dl - off : chunk; CHECK(U(CryptHashData)(h, data + off, n, 0)); }
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0));
        int el = h_hex2bin(exp[i], e, sizeof e);
        CHECKF(el == (int)ol && !memcmp(out, e, ol), "hmac mismatch %s", hv_hmac_ins[i].name);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
#define HMAC_TESTS(IDX, NAME) \
TEST(capi_hmac_kat_##NAME) { REQUIRE(U(CryptCreateHash)); hmac_rows(g_h[IDX].alg, g_h[IDX].hm, 100000); } \
TEST(capi_hmac_kat_chunk1_##NAME) { REQUIRE(U(CryptCreateHash)); hmac_rows(g_h[IDX].alg, g_h[IDX].hm, 1); } \
TEST(capi_hmac_kat_chunk13_##NAME) { REQUIRE(U(CryptCreateHash)); hmac_rows(g_h[IDX].alg, g_h[IDX].hm, 13); }
HMAC_TESTS(0, MD2) HMAC_TESTS(1, MD4) HMAC_TESTS(2, MD5) HMAC_TESTS(3, SHA1)
HMAC_TESTS(4, SHA256) HMAC_TESTS(5, SHA384) HMAC_TESTS(6, SHA512)

/* RFC 2202 test case 1 and RFC 4231 test case 1/2 spelled out */
TEST(capi_hmac_rfc_spot_values) {
    REQUIRE(U(CryptCreateHash)); PROLOG; BOOL ok; BYTE out[64]; DWORD ol;
    BYTE k20[20]; memset(k20, 0x0b, 20);
    HCRYPTHASH h = hmac_begin(p, CALG_MD5, k20, 20, &ok);
    if (h) { ol = 64; CHECK(U(CryptHashData)(h, (const BYTE *)"Hi There", 8, 0)); CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0)); EXPECT_HEX(out, 16, "9294727a3638bb1c13f48ef8158bfc9d"); U(CryptDestroyHash)(h); }
    h = hmac_begin(p, CALG_SHA1, k20, 20, &ok);
    if (h) { ol = 64; CHECK(U(CryptHashData)(h, (const BYTE *)"Hi There", 8, 0)); CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0)); EXPECT_HEX(out, 20, "b617318655057264e28bc0b6fb378c8ef146be00"); U(CryptDestroyHash)(h); }
    h = hmac_begin(p, CALG_SHA_256, k20, 20, &ok);
    if (h) { ol = 64; CHECK(U(CryptHashData)(h, (const BYTE *)"Hi There", 8, 0)); CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0)); EXPECT_HEX(out, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"); U(CryptDestroyHash)(h); }
    h = hmac_begin(p, CALG_SHA_256, (const BYTE *)"Jefe", 4, &ok);
    if (h) { ol = 64; CHECK(U(CryptHashData)(h, (const BYTE *)"what do ya want for nothing?", 28, 0)); CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0)); EXPECT_HEX(out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"); U(CryptDestroyHash)(h); }
    h = hmac_begin(p, CALG_SHA_512, (const BYTE *)"Jefe", 4, &ok);
    if (h) { ol = 64; CHECK(U(CryptHashData)(h, (const BYTE *)"what do ya want for nothing?", 28, 0)); CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0));
        EXPECT_HEX(out, 64, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"); U(CryptDestroyHash)(h); }
    EPILOG;
}

/* ------------------------------------------------------- HMAC parameter behaviour */
static HCRYPTKEY g_noinfo_key;
static HCRYPTHASH new_hmac_noinfo(HCRYPTPROV p) {
    BYTE k[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 }; HCRYPTHASH h = 0;
    HCRYPTKEY key = h_plainkey(p, CALG_RC2, k, 16, CRYPT_IPSEC_HMAC_KEY);
    if (!key) return 0;
    U(CryptCreateHash)(p, CALG_HMAC, key, 0, &h); g_noinfo_key = key; return h;
}
TEST(capi_hmac_getparam_algid_and_size) {
    REQUIRE(U(CryptCreateHash)); PROLOG; size_t i;
    for (i = 0; i < NH; i++) {
        BOOL ok; BYTE k[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 }; DWORD v = 0, dl = 4;
        HCRYPTHASH h = hmac_begin(p, g_h[i].alg, k, 16, &ok); if (!h) continue;
        CHECK(U(CryptGetHashParam)(h, HP_ALGID, (BYTE *)&v, &dl, 0)); CHECKF(v == CALG_HMAC, "%s algid 0x%lx", g_h[i].name, v);
        dl = 4; CHECK(U(CryptGetHashParam)(h, HP_HASHSIZE, (BYTE *)&v, &dl, 0)); CHECKF(v == g_h[i].len, "%s size %lu", g_h[i].name, v);
        dl = 0; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, NULL, &dl, 0)); CHECKF(dl == g_h[i].len, "%s val size %lu", g_h[i].name, dl);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hmac_get_hmac_info_is_bad_type) {
    REQUIRE(U(CryptCreateHash)); PROLOG; BOOL ok; BYTE k[16] = { 1 }; BYTE buf[64]; DWORD dl = sizeof buf;
    HCRYPTHASH h = hmac_begin(p, CALG_SHA1, k, 16, &ok);
    if (h) { SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HMAC_INFO, buf, &dl, 0)); EXPECT_ERR(E_NTE_BAD_TYPE); U(CryptDestroyHash)(h); }
    EPILOG;
}
TEST(capi_hmac_info_unsupported_inner_alg_bad_algid) {
    REQUIRE(U(CryptCreateHash)); PROLOG; size_t i;
    static const ALG_ID bad[] = { 0, CALG_RC4, CALG_MAC, CALG_HMAC, CALG_SSL3_SHAMD5, CALG_TLS1PRF, CALG_RSA_SIGN, 0x800f, 0xFFFF };
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        HCRYPTHASH h = new_hmac_noinfo(p); HMAC_INFO hi; if (!h) continue;
        memset(&hi, 0, sizeof hi); hi.HashAlgid = bad[i];
        SET_ERR(0); CHECKF(!U(CryptSetHashParam)(h, HP_HMAC_INFO, (BYTE *)&hi, 0), "alg 0x%lx", bad[i]); EXPECT_ERR(E_NTE_BAD_ALGID);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hmac_info_on_plain_hash_bad_type) {
    REQUIRE(U(CryptCreateHash)); PROLOG; size_t i;
    static const ALG_ID a[] = { CALG_MD5, CALG_SHA1, CALG_SHA_256 };
    for (i = 0; i < 3; i++) {
        HCRYPTHASH h = 0; HMAC_INFO hi; memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1;
        CHECK(U(CryptCreateHash)(p, a[i], 0, 0, &h));
        SET_ERR(0); CHECK(!U(CryptSetHashParam)(h, HP_HMAC_INFO, (BYTE *)&hi, 0)); EXPECT_ERR(E_NTE_BAD_TYPE);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hmac_info_flags_nonzero_bad_flags) {
    REQUIRE(U(CryptCreateHash)); PROLOG; HCRYPTHASH h = new_hmac_noinfo(p); HMAC_INFO hi;
    if (h) {
        memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1;
        SET_ERR(0); CHECK(!U(CryptSetHashParam)(h, HP_HMAC_INFO, (BYTE *)&hi, 1)); EXPECT_ERR(E_NTE_BAD_FLAGS);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hmac_explicit_default_pads_equal_default) {
    REQUIRE(U(CryptCreateHash)); PROLOG; BYTE k[20]; memset(k, 0x0b, 20);
    BYTE in[64], outp[64], r1[20], r2[20]; DWORD l1 = 20, l2 = 20; HMAC_INFO hi; BOOL ok;
    memset(in, 0x36, 64); memset(outp, 0x5c, 64);
    HCRYPTHASH a = hmac_begin(p, CALG_SHA1, k, 20, &ok);
    HCRYPTHASH b = new_hmac_noinfo(p);
    HCRYPTKEY key = h_plainkey(p, CALG_RC2, k, 20, CRYPT_IPSEC_HMAC_KEY); HCRYPTHASH c = 0;
    if (key) { U(CryptCreateHash)(p, CALG_HMAC, key, 0, &c); /* key released with the provider */ }
    if (a && c) {
        memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1; hi.pbInnerString = in; hi.cbInnerString = 64; hi.pbOuterString = outp; hi.cbOuterString = 64;
        CHECK(U(CryptSetHashParam)(c, HP_HMAC_INFO, (BYTE *)&hi, 0));
        CHECK(U(CryptHashData)(a, (const BYTE *)"Hi There", 8, 0)); CHECK(U(CryptHashData)(c, (const BYTE *)"Hi There", 8, 0));
        CHECK(U(CryptGetHashParam)(a, HP_HASHVAL, r1, &l1, 0)); CHECK(U(CryptGetHashParam)(c, HP_HASHVAL, r2, &l2, 0));
        CHECK(l1 == l2 && !memcmp(r1, r2, l1));
        EXPECT_HEX(r2, 20, "b617318655057264e28bc0b6fb378c8ef146be00");
    }
    if (a) U(CryptDestroyHash)(a); if (b) U(CryptDestroyHash)(b); if (c) U(CryptDestroyHash)(c);
    EPILOG;
}
TEST(capi_hmac_get_after_finish_repeatable_and_hashdata_rejected) {
    REQUIRE(U(CryptCreateHash)); PROLOG; BOOL ok; BYTE k[4] = { 'J','e','f','e' }; BYTE a[20], b[20]; DWORD la = 20, lb = 20;
    HCRYPTHASH h = hmac_begin(p, CALG_SHA1, k, 4, &ok);
    if (h) {
        CHECK(U(CryptHashData)(h, (const BYTE *)"what do ya want for nothing?", 28, 0));
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, a, &la, 0));
        EXPECT_HEX(a, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, b, &lb, 0)); CHECK(!memcmp(a, b, 20));
        SET_ERR(0); CHECK(!U(CryptHashData)(h, (const BYTE *)"x", 1, 0)); EXPECT_ERR(E_NTE_BAD_HASH_STATE);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hmac_duplicate_midstream) {
    REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptDuplicateHash)); PROLOG; BOOL ok; BYTE k[4] = { 'J','e','f','e' }; BYTE a[20], b[20]; DWORD la = 20, lb = 20;
    HCRYPTHASH h = hmac_begin(p, CALG_SHA1, k, 4, &ok), d = 0;
    if (h) {
        CHECK(U(CryptHashData)(h, (const BYTE *)"what do ya ", 11, 0));
        SET_ERR(0); BOOL dup = U(CryptDuplicateHash)(h, NULL, 0, &d); CHECKF(dup, "dup err 0x%lx", GetLastError());
        if (dup) {
            CHECK(U(CryptHashData)(h, (const BYTE *)"want for nothing?", 17, 0)); CHECK(U(CryptHashData)(d, (const BYTE *)"want for nothing?", 17, 0));
            CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, a, &la, 0)); CHECK(U(CryptGetHashParam)(d, HP_HASHVAL, b, &lb, 0));
            CHECK(!memcmp(a, b, 20)); EXPECT_HEX(b, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
            U(CryptDestroyHash)(d);
        }
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hmac_key_change_alters_mac) {
    REQUIRE(U(CryptCreateHash)); PROLOG; BOOL ok; BYTE k1[8] = { 1,2,3,4,5,6,7,8 }, k2[8] = { 1,2,3,4,5,6,7,9 }; BYTE a[20], b[20]; DWORD la = 20, lb = 20;
    HCRYPTHASH h1 = hmac_begin(p, CALG_SHA1, k1, 8, &ok), h2 = hmac_begin(p, CALG_SHA1, k2, 8, &ok);
    if (h1 && h2) {
        CHECK(U(CryptHashData)(h1, (const BYTE *)"m", 1, 0)); CHECK(U(CryptHashData)(h2, (const BYTE *)"m", 1, 0));
        CHECK(U(CryptGetHashParam)(h1, HP_HASHVAL, a, &la, 0)); CHECK(U(CryptGetHashParam)(h2, HP_HASHVAL, b, &lb, 0));
        CHECK(memcmp(a, b, 20) != 0);
    }
    if (h1) U(CryptDestroyHash)(h1); if (h2) U(CryptDestroyHash)(h2);
    EPILOG;
}
TEST(capi_hmac_hashing_without_info_observed) {
    REQUIRE(U(CryptCreateHash)); PROLOG; HCRYPTHASH h = new_hmac_noinfo(p);
    if (h) {
        SET_ERR(0); BOOL ok = U(CryptHashData)(h, (const BYTE *)"abc", 3, 0);
        t_note("HashData on HMAC hash before HP_HMAC_INFO: %d err 0x%lx", ok, ok ? 0 : GetLastError());
        BYTE d[64]; DWORD dl = 64; SET_ERR(0); ok = U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0);
        t_note("HP_HASHVAL on HMAC hash before HP_HMAC_INFO: %d len %lu err 0x%lx", ok, dl, ok ? 0 : GetLastError());
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hmac_nondefault_pads_observed) {
    REQUIRE(U(CryptCreateHash)); PROLOG; BYTE k[20]; memset(k, 0x0b, 20); HMAC_INFO hi; BYTE in[64], ou[64], r[20]; DWORD rl = 20;
    HCRYPTHASH h = new_hmac_noinfo(p);
    HCRYPTKEY key = h_plainkey(p, CALG_RC2, k, 20, CRYPT_IPSEC_HMAC_KEY); HCRYPTHASH c = 0;
    if (key) { U(CryptCreateHash)(p, CALG_HMAC, key, 0, &c); /* key released with the provider */ }
    if (c) {
        memset(in, 0x37, 64); memset(ou, 0x5d, 64);
        memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1; hi.pbInnerString = in; hi.cbInnerString = 64; hi.pbOuterString = ou; hi.cbOuterString = 64;
        BOOL ok = U(CryptSetHashParam)(c, HP_HMAC_INFO, (BYTE *)&hi, 0);
        t_note("non-default pad set: %d err 0x%lx", ok, ok ? 0 : GetLastError());
        if (ok) {
            CHECK(U(CryptHashData)(c, (const BYTE *)"Hi There", 8, 0)); CHECK(U(CryptGetHashParam)(c, HP_HASHVAL, r, &rl, 0));
            char hx[64]; h_bin2hex(r, rl, hx);
            CHECK(strcmp(hx, "b617318655057264e28bc0b6fb378c8ef146be00") != 0);
            t_note("non-default pad (0x37/0x5d) HMAC-SHA1 = %s", hx);
        }
        U(CryptDestroyHash)(c);
    }
    if (h) U(CryptDestroyHash)(h);
    EPILOG;
}

/* ------------------------------------------------------------- SetHashParam */
static const BYTE g_val[64] = { 0xA0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
    32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,0xBF };
TEST(capi_hash_setparam_hashval_roundtrip_all_algs) {
    REQUIRE(U(CryptSetHashParam)); PROLOG; size_t i;
    for (i = 0; i < NH; i++) {
        HCRYPTHASH h = 0; BYTE out[80]; DWORD ol = sizeof out;
        CHECK(U(CryptCreateHash)(p, g_h[i].alg, 0, 0, &h));
        SET_ERR(0); BOOL ok = U(CryptSetHashParam)(h, HP_HASHVAL, g_val, 0);
        CHECKF(ok, "%s err 0x%lx", g_h[i].name, GetLastError());
        if (ok) {
            CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0));
            CHECKF(ol == g_h[i].len && !memcmp(out, g_val, ol), "%s", g_h[i].name);
        }
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hash_setparam_hashval_then_hashdata_bad_state) {
    REQUIRE(U(CryptSetHashParam)); PROLOG; size_t i;
    for (i = 0; i < NH; i++) {
        HCRYPTHASH h = 0;
        CHECK(U(CryptCreateHash)(p, g_h[i].alg, 0, 0, &h));
        if (U(CryptSetHashParam)(h, HP_HASHVAL, g_val, 0)) {
            SET_ERR(0); CHECKF(!U(CryptHashData)(h, (const BYTE *)"a", 1, 0), "%s", g_h[i].name); EXPECT_ERR(E_NTE_BAD_HASH_STATE);
        } else CHECK(0);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}
TEST(capi_hash_setparam_hashval_overrides_computed_value) {
    REQUIRE(U(CryptSetHashParam)); PROLOG; HCRYPTHASH h = 0; BYTE out[20]; DWORD ol = 20;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    BOOL ok = U(CryptSetHashParam)(h, HP_HASHVAL, g_val, 0);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) { CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0)); CHECK(!memcmp(out, g_val, 20)); }
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_setparam_ssl3_shamd5_36_bytes) {
    REQUIRE(U(CryptSetHashParam)); PROLOG; HCRYPTHASH h = 0; BYTE out[40]; DWORD ol = sizeof out;
    CHECK(U(CryptCreateHash)(p, CALG_SSL3_SHAMD5, 0, 0, &h));
    BOOL ok = U(CryptSetHashParam)(h, HP_HASHVAL, g_val, 0);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) { CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0)); CHECK(ol == 36 && !memcmp(out, g_val, 36)); }
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_setparam_nonzero_flags_bad_flags) {
    REQUIRE(U(CryptSetHashParam)); PROLOG; HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptSetHashParam)(h, HP_HASHVAL, g_val, 1)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    SET_ERR(0); CHECK(!U(CryptSetHashParam)(h, HP_HASHVAL, g_val, 0x80000000u)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_setparam_unsettable_dwparam_bad_type) {
    REQUIRE(U(CryptSetHashParam)); PROLOG; HCRYPTHASH h = 0; size_t i;
    static const DWORD prm[] = { 0, HP_ALGID, 3, HP_HASHSIZE, 8, 9, 0x10, 99, 0xFFFFFFFFu };
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    for (i = 0; i < sizeof prm / sizeof prm[0]; i++) {
        SET_ERR(0); CHECKF(!U(CryptSetHashParam)(h, prm[i], g_val, 0), "param %lu", prm[i]); EXPECT_ERR(E_NTE_BAD_TYPE);
    }
    U(CryptDestroyHash)(h); EPILOG;
}
TEST(capi_hash_setparam_tls1prf_values_on_plain_hash_bad_hash) {
    REQUIRE(U(CryptSetHashParam)); PROLOG; size_t i;
    static const ALG_ID a[] = { CALG_MD5, CALG_SHA1, CALG_SHA_256 };
    for (i = 0; i < 3; i++) {
        HCRYPTHASH h = 0; CRYPT_DATA_BLOB b; b.cbData = 5; b.pbData = (BYTE *)"label";
        CHECK(U(CryptCreateHash)(p, a[i], 0, 0, &h));
        SET_ERR(0); CHECK(!U(CryptSetHashParam)(h, HP_TLS1PRF_LABEL, (BYTE *)&b, 0)); EXPECT_ERR(E_NTE_BAD_HASH);
        SET_ERR(0); CHECK(!U(CryptSetHashParam)(h, HP_TLS1PRF_SEED, (BYTE *)&b, 0)); EXPECT_ERR(E_NTE_BAD_HASH);
        U(CryptDestroyHash)(h);
    }
    EPILOG;
}

/* -------------------------------------------------------------------- MAC */
static void mac_rows(ALG_ID kalg, const BYTE *key, DWORD klen, DWORD bs, const hv_mac *rows, size_t n) {
    PROLOG; size_t i; int nmatch = 0;
    HCRYPTKEY k = h_plainkey(p, kalg, key, klen, 0);
    if (k) {
        for (i = 0; i < n; i++) {
            BYTE data[200], out[32], e[32]; DWORD ol = sizeof out; HCRYPTHASH h = 0;
            int dl = h_hex2bin(rows[i].data, data, sizeof data), el = h_hex2bin(rows[i].mac, e, sizeof e);
            BOOL ok = U(CryptCreateHash)(p, CALG_MAC, k, 0, &h);
            CHECKF(ok, "create MAC err 0x%lx", GetLastError()); if (!ok) continue;
            CHECK(U(CryptHashData)(h, data, (DWORD)dl, 0));
            CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0));
            CHECKF(ol == bs && el == (int)bs, "MAC row %zu length %lu", i, ol);
            /* CBC-MAC value (zero IV, whole blocks): the final-block layout is implementation defined, so observe only */
            if (ol == bs && el == (int)bs) { if (!memcmp(out, e, bs)) nmatch++; else t_note("MAC row %zu differs from plain CBC-MAC", i); }
            U(CryptDestroyHash)(h);
        }
        U(CryptDestroyKey)(k);
        t_note("MAC rows equal to plain CBC-MAC: %d of %zu", nmatch, n);
    }
    EPILOG;
}
TEST(capi_mac_des_cbc_known_answers) {
    REQUIRE(U(CryptCreateHash)); static const BYTE key[8] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    mac_rows(CALG_DES, key, 8, 8, hv_desmac, HV_NDESMAC);
}
TEST(capi_mac_aes128_cbc_known_answers) {
    REQUIRE(U(CryptCreateHash));
    static const BYTE key[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    /* data = pattern (i*7+3) bytes */
    BYTE pat[80]; int i; for (i = 0; i < 80; i++) pat[i] = (BYTE)(i * 7 + 3);
    static const struct { int n; const char *mac; } v[] = {
        { 16, "268590873ef180ab539cf461a5c5f892" }, { 32, "e234097cd413dd84532e948e444fd43b" },
        { 48, "c491c4ed0d20ffe84e0d3d4559964089" }, { 80, "7467e8bb26335dc3f049f19414677b48" } };
    PROLOG; HCRYPTKEY k = h_plainkey(p, CALG_AES_128, key, 16, 0);
    if (k) {
        for (i = 0; i < 4; i++) {
            HCRYPTHASH h = 0; BYTE out[32]; DWORD ol = 32;
            if (!U(CryptCreateHash)(p, CALG_MAC, k, 0, &h)) { CHECK(0); continue; }
            CHECK(U(CryptHashData)(h, pat, v[i].n, 0)); CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0));
            CHECK(ol == 16);
            { BYTE e[16]; h_hex2bin(v[i].mac, e, 16); if (memcmp(out, e, 16)) t_note("AES MAC len %d differs from plain CBC-MAC", v[i].n); }
            U(CryptDestroyHash)(h);
        }
        U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_mac_chunked_equals_oneshot) {
    REQUIRE(U(CryptCreateHash)); PROLOG; static const BYTE key[8] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    HCRYPTKEY k = h_plainkey(p, CALG_DES, key, 8, 0);
    if (k) {
        BYTE data[64], a[8], b[8]; DWORD la = 8, lb = 8; int i; HCRYPTHASH h1 = 0, h2 = 0;
        for (i = 0; i < 64; i++) data[i] = (BYTE)(i * 7 + 3);
        CHECK(U(CryptCreateHash)(p, CALG_MAC, k, 0, &h1)); CHECK(U(CryptCreateHash)(p, CALG_MAC, k, 0, &h2));
        CHECK(U(CryptHashData)(h1, data, 64, 0));
        for (i = 0; i < 64; i += 5) CHECK(U(CryptHashData)(h2, data + i, (64 - i < 5) ? 64 - i : 5, 0));
        CHECK(U(CryptGetHashParam)(h1, HP_HASHVAL, a, &la, 0)); CHECK(U(CryptGetHashParam)(h2, HP_HASHVAL, b, &lb, 0));
        CHECK(!memcmp(a, b, 8));
        U(CryptDestroyHash)(h1); U(CryptDestroyHash)(h2); U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_mac_getparam_algid_size_and_state) {
    REQUIRE(U(CryptCreateHash)); PROLOG; static const BYTE key[8] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    HCRYPTKEY k = h_plainkey(p, CALG_DES, key, 8, 0);
    if (k) {
        HCRYPTHASH h = 0; DWORD v = 0, dl = 4; BYTE out[16];
        CHECK(U(CryptCreateHash)(p, CALG_MAC, k, 0, &h));
        CHECK(U(CryptGetHashParam)(h, HP_ALGID, (BYTE *)&v, &dl, 0)); CHECK(v == CALG_MAC);
        dl = 4; CHECK(U(CryptGetHashParam)(h, HP_HASHSIZE, (BYTE *)&v, &dl, 0)); CHECK(v == 8);
        dl = 0; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, NULL, &dl, 0)); CHECK(dl == 8);
        CHECK(U(CryptHashData)(h, (const BYTE *)"12345678", 8, 0));
        dl = 4; SET_ERR(0); CHECK(!U(CryptGetHashParam)(h, HP_HASHVAL, out, &dl, 0)); EXPECT_ERR(ERROR_MORE_DATA); CHECK(dl == 8);
        dl = 8; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, out, &dl, 0));
        SET_ERR(0); CHECK(!U(CryptHashData)(h, (const BYTE *)"x", 1, 0)); EXPECT_ERR(E_NTE_BAD_HASH_STATE);
        U(CryptDestroyHash)(h); U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_mac_partial_block_observed) {
    REQUIRE(U(CryptCreateHash)); PROLOG; static const BYTE key[8] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    HCRYPTKEY k = h_plainkey(p, CALG_DES, key, 8, 0);
    if (k) {
        HCRYPTHASH h = 0; BYTE out[8]; DWORD dl = 8; char hx[32];
        CHECK(U(CryptCreateHash)(p, CALG_MAC, k, 0, &h));
        CHECK(U(CryptHashData)(h, (const BYTE *)"abcde", 5, 0));
        BOOL ok = U(CryptGetHashParam)(h, HP_HASHVAL, out, &dl, 0); CHECK(ok);
        if (ok) { h_bin2hex(out, 8, hx); t_note("DES MAC of 'abcde' (partial block): %s", hx); }
        U(CryptDestroyHash)(h); U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_mac_with_hashsessionkey_updates_state) {
    REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptHashSessionKey)); PROLOG; static const BYTE key[8] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
    HCRYPTKEY k = h_plainkey(p, CALG_DES, key, 8, 0), k2 = h_plainkey(p, CALG_DES, key, 8, 0);
    if (k && k2) {
        HCRYPTHASH h = 0; BOOL ok;
        CHECK(U(CryptCreateHash)(p, CALG_MAC, k, 0, &h));
        SET_ERR(0); ok = U(CryptHashSessionKey)(h, k2, CRYPT_LITTLE_ENDIAN); t_note("CryptHashSessionKey into MAC: %d err 0x%lx", ok, ok ? 0 : GetLastError());
        U(CryptDestroyHash)(h);
    }
    if (k) U(CryptDestroyKey)(k); if (k2) U(CryptDestroyKey)(k2);
    EPILOG;
}
TEST(capi_mac_stream_key_observed) {
    REQUIRE(U(CryptCreateHash)); PROLOG; BYTE k16[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    HCRYPTKEY k = h_plainkey(p, CALG_RC4, k16, 16, 0);
    if (k) {
        HCRYPTHASH h = 0; SET_ERR(0); BOOL ok = U(CryptCreateHash)(p, CALG_MAC, k, 0, &h);
        t_note("CALG_MAC with RC4 key: %d err 0x%lx", ok, ok ? 0 : GetLastError());
        if (ok) U(CryptDestroyHash)(h);
        U(CryptDestroyKey)(k);
    }
    EPILOG;
}

/* ----------------------------------------------------------------- TLS1PRF */
TEST(capi_tls1prf_known_answer_observed) {
    REQUIRE(U(CryptCreateHash)); PROLOG; BYTE sec[48], seed[64]; int i;
    for (i = 0; i < 48; i++) sec[i] = (BYTE)(i * 7 + 3);
    for (i = 0; i < 64; i++) seed[i] = (BYTE)(i * 7 + 3);
    HCRYPTKEY k = h_plainkey(p, CALG_RC2, sec, 48, CRYPT_IPSEC_HMAC_KEY);
    if (k) {
        HCRYPTHASH h = 0; SET_ERR(0);
        BOOL ok = U(CryptCreateHash)(p, CALG_TLS1PRF, k, 0, &h);
        t_note("CALG_TLS1PRF create: %d err 0x%lx", ok, ok ? 0 : GetLastError());
        if (ok) {
            CRYPT_DATA_BLOB lab, sd; lab.cbData = 13; lab.pbData = (BYTE *)"master secret"; sd.cbData = 64; sd.pbData = seed;
            BOOL a = U(CryptSetHashParam)(h, HP_TLS1PRF_LABEL, (BYTE *)&lab, 0), b = U(CryptSetHashParam)(h, HP_TLS1PRF_SEED, (BYTE *)&sd, 0);
            t_note("set label %d seed %d", a, b);
            BYTE out[48]; DWORD ol = 48;
            if (a && b && U(CryptGetHashParam)(h, HP_HASHVAL, out, &ol, 0)) {
                char hx[100]; h_bin2hex(out, ol, hx);
                t_note("TLS1PRF 48 bytes: %s (expect %s)", hx, "9202f7f7b67c5965fc540f92dba6a5fc5885f60f4ec735017dcb4685f2d9619c54b48511f9095aea2be04e4d0dd510ee");
            }
            U(CryptDestroyHash)(h);
        }
        U(CryptDestroyKey)(k);
    }
    EPILOG;
}
TEST(capi_tls1prf_without_key_fails) {
    REQUIRE(U(CryptCreateHash)); PROLOG; HCRYPTHASH h = 0; SET_ERR(0);
    BOOL ok = U(CryptCreateHash)(p, CALG_TLS1PRF, 0, 0, &h);
    t_note("TLS1PRF create without key: ok=%d err 0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CryptDestroyHash)(h);
    EPILOG;
}

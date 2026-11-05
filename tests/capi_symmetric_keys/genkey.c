#include "ck.h"
/* CryptGenKey / CryptGetKeyParam / CryptDestroyKey / CryptDuplicateKey on the AES provider (ephemeral). */

typedef struct { ALG_ID alg; const char *name; DWORD keybits, blockbits, ivbytes, effbits; } algrow;
static const algrow rows[] = {
    { CALG_DES,     "DES",     64,  64,  8,  56  },
    { CALG_3DES,    "3DES",    192, 64,  8,  168 },
    { CALG_3DES_112,"3DES112", 128, 64,  8,  112 },
    { CALG_RC2,     "RC2",     128, 64,  8,  0   },
    { CALG_RC4,     "RC4",     128, 0,   0,  0   },
    { CALG_AES_128, "AES128",  128, 128, 16, 0   },
    { CALG_AES_192, "AES192",  192, 128, 16, 0   },
    { CALG_AES_256, "AES256",  256, 128, 16, 0   },
};

TEST(genkey_default_algid_keylen_blocklen) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(rows); i++) {
        HCRYPTKEY k = 0; BOOL ok;
        if (!U(CryptGenKey)(p, rows[i].alg, 0, &k)) { CHECKF(0, "%s GenKey 0x%lx", rows[i].name, GetLastError()); continue; }
        CHECK(k != 0);
        EXPECT_EQ(ck_param_dw(k, KP_ALGID, &ok), rows[i].alg); CHECK(ok);
        EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), rows[i].keybits); CHECK(ok);
        EXPECT_EQ(ck_param_dw(k, KP_BLOCKLEN, &ok), rows[i].blockbits); CHECK(ok);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_default_padding_and_mode) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(rows); i++) {
        HCRYPTKEY k = 0; BOOL ok;
        if (!U(CryptGenKey)(p, rows[i].alg, 0, &k)) { CHECK(0); continue; }
        DWORD pad = ck_param_dw(k, KP_PADDING, &ok); CHECKF(ok, "%s", rows[i].name);
        if (rows[i].blockbits) {
            EXPECT_EQ(pad, PKCS5_PADDING);
            EXPECT_EQ(ck_param_dw(k, KP_MODE, &ok), CRYPT_MODE_CBC); CHECK(ok);
            { DWORD mb = ck_param_dw(k, KP_MODE_BITS, &ok); CHECK(ok); t_note("%s default KP_MODE_BITS %lu", rows[i].name, mb); }
        } else EXPECT_EQ(pad, 0);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_iv_length_matches_blocksize) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(rows); i++) {
        HCRYPTKEY k = 0; if (!U(CryptGenKey)(p, rows[i].alg, 0, &k)) { CHECK(0); continue; }
        DWORD n = 0; BYTE iv[32];
        /* NULL buffer: size query succeeds */
        CHECK(U(CryptGetKeyParam)(k, KP_IV, NULL, &n, 0)); EXPECT_EQ(n, rows[i].ivbytes);
        if (rows[i].ivbytes) {
            /* a too-small buffer fails with ERROR_MORE_DATA and reports the size */
            n = rows[i].ivbytes - 1; SET_ERR(0);
            EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_IV, iv, &n, 0), ERROR_MORE_DATA);
            EXPECT_EQ(n, rows[i].ivbytes);
            n = rows[i].ivbytes; CHECK(U(CryptGetKeyParam)(k, KP_IV, iv, &n, 0)); EXPECT_EQ(n, rows[i].ivbytes);
            n = sizeof iv; CHECK(U(CryptGetKeyParam)(k, KP_IV, iv, &n, 0)); EXPECT_EQ(n, rows[i].ivbytes);
        }
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_keylen_buffer_protocol) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = 0; CHECK(U(CryptGenKey)(p, CALG_AES_128, 0, &k)); if (!k) return;
    DWORD n = 0, v = 0;
    CHECK(U(CryptGetKeyParam)(k, KP_KEYLEN, NULL, &n, 0)); EXPECT_EQ(n, 4);
    n = 3; SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_KEYLEN, (BYTE *)&v, &n, 0), ERROR_MORE_DATA); EXPECT_EQ(n, 4);
    n = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_KEYLEN, (BYTE *)&v, &n, 0), ERROR_MORE_DATA); EXPECT_EQ(n, 4);
    n = 8; CHECK(U(CryptGetKeyParam)(k, KP_KEYLEN, (BYTE *)&v, &n, 0)); EXPECT_EQ(n, 4); EXPECT_EQ(v, 128);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(genkey_getkeyparam_null_length_pointer) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = 0; CHECK(U(CryptGenKey)(p, CALG_AES_128, 0, &k)); if (!k) return;
    DWORD v;
    SET_ERR(0); EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_ALGID, (BYTE *)&v, NULL, 0), ERROR_INVALID_PARAMETER);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(genkey_getkeyparam_nonzero_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = 0; CHECK(U(CryptGenKey)(p, CALG_AES_128, 0, &k)); if (!k) return;
    DWORD v, n = 4;
    static const DWORD fl[] = { 1, 2, 0x10, 0x80000000 };
    for (unsigned i = 0; i < SIZEOFA(fl); i++) {
        n = 4; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_ALGID, (BYTE *)&v, &n, fl[i]), NTE_BAD_FLAGS_);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(genkey_getkeyparam_unknown_param) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = 0; CHECK(U(CryptGenKey)(p, CALG_AES_128, 0, &k)); if (!k) return;
    static const DWORD kp[] = { 0x63, 0x7f, 0x1000, 0xdeadbeef };
    for (unsigned i = 0; i < SIZEOFA(kp); i++) {
        DWORD v, n = 4; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, kp[i], (BYTE *)&v, &n, 0), NTE_BAD_TYPE_);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(genkey_salt_param_by_algorithm) {
    NEED_CRYPT(); NEED_PROV(p);
    /* KP_SALT: DES/3DES/AES report an empty salt successfully; RC2/RC4 report their salt length */
    static const ALG_ID zero[] = { CALG_DES, CALG_3DES, CALG_3DES_112, CALG_AES_128, CALG_AES_192, CALG_AES_256 };
    for (unsigned i = 0; i < SIZEOFA(zero); i++) {
        HCRYPTKEY k = 0; if (!U(CryptGenKey)(p, zero[i], 0, &k)) { CHECK(0); continue; }
        DWORD n = 99; BYTE b[16];
        CHECK(U(CryptGetKeyParam)(k, KP_SALT, b, &n, 0)); EXPECT_EQ(n, 0);
        U(CryptDestroyKey)(k);
    }
    static const ALG_ID st[] = { CALG_RC2, CALG_RC4 };
    for (unsigned i = 0; i < 2; i++) {
        HCRYPTKEY k = 0; if (!U(CryptGenKey)(p, st[i], 0, &k)) { CHECK(0); continue; }
        DWORD n = 99; BYTE b[16];
        BOOL r = U(CryptGetKeyParam)(k, KP_SALT, NULL, &n, 0);
        CHECK(r); t_note("alg 0x%x default salt length on this provider: %lu", st[i], n);
        CHECK(n == 0 || n == 11);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_effective_keylen_param) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(rows); i++) {
        HCRYPTKEY k = 0; if (!U(CryptGenKey)(p, rows[i].alg, 0, &k)) { CHECK(0); continue; }
        BOOL ok; SET_ERR(0);
        DWORD v = ck_param_dw(k, KP_EFFECTIVE_KEYLEN, &ok);
        if (rows[i].effbits) { CHECKF(ok, "%s", rows[i].name); EXPECT_EQ(v, rows[i].effbits); }
        else if (rows[i].alg == CALG_RC2) { CHECK(ok); t_note("RC2 default effective keylen %lu", v); CHECK(v >= 40 && v <= 128); }
        else { CHECKF(!ok, "%s unexpectedly succeeded", rows[i].name); EXPECT_ERR(NTE_BAD_KEY_); }
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_explicit_key_lengths_rc4_rc2) {
    NEED_CRYPT(); NEED_PROV(p);
    static const DWORD bits[] = { 40, 48, 56, 64, 80, 96, 112, 128 };
    static const ALG_ID algs[] = { CALG_RC4, CALG_RC2 };
    for (int a = 0; a < 2; a++) for (unsigned i = 0; i < SIZEOFA(bits); i++) {
        HCRYPTKEY k = 0; BOOL ok;
        if (!U(CryptGenKey)(p, algs[a], (bits[i] << 16), &k)) { CHECKF(0, "alg %x bits %lu err 0x%lx", algs[a], bits[i], GetLastError()); continue; }
        DWORD kl = ck_param_dw(k, KP_KEYLEN, &ok); CHECK(ok); EXPECT_EQ(kl, bits[i]);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_key_length_not_multiple_of_eight_bad_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    /* observed in CheckKeyLength: (flags >> 16) & 7 != 0 -> NTE_BAD_FLAGS */
    static const DWORD bits[] = { 41, 47, 57, 121, 127, 129 };
    for (unsigned i = 0; i < SIZEOFA(bits); i++) {
        HCRYPTKEY k = 0; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGenKey)(p, CALG_RC4, bits[i] << 16, &k), NTE_BAD_FLAGS_);
    }
    ck_release(p);
}
TEST(genkey_key_length_out_of_range) {
    NEED_CRYPT(); NEED_PROV(p);
    static const DWORD bits[] = { 8, 16, 24, 32, 4096, 8192 };
    for (unsigned i = 0; i < SIZEOFA(bits); i++) {
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, CALG_RC4, bits[i] << 16, &k);
        if (r) { t_note("RC4 %lu-bit GenKey accepted", bits[i]); U(CryptDestroyKey)(k); } else EXPECT_ERR(NTE_BAD_FLAGS_);
    }
    ck_release(p);
}
TEST(genkey_fixed_size_algs_reject_wrong_length) {
    NEED_CRYPT(); NEED_PROV(p);
    static const struct { ALG_ID a; DWORD bits; } t[] = {
        { CALG_AES_128, 192 }, { CALG_AES_128, 256 }, { CALG_AES_192, 128 }, { CALG_AES_256, 128 },
        { CALG_DES, 128 }, { CALG_3DES, 128 }, { CALG_3DES_112, 192 } };
    for (unsigned i = 0; i < SIZEOFA(t); i++) {
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, t[i].a, t[i].bits << 16, &k);
        CHECKF(!r, "alg %x bits %lu accepted", t[i].a, t[i].bits);
        if (r) U(CryptDestroyKey)(k); else EXPECT_ERR(NTE_BAD_FLAGS_);
    }
    ck_release(p);
}
TEST(genkey_matching_explicit_length_accepted) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(rows); i++) {
        if (rows[i].alg == CALG_3DES_112 || rows[i].alg == CALG_DES) continue;
        HCRYPTKEY k = 0; BOOL ok;
        if (!U(CryptGenKey)(p, rows[i].alg, rows[i].keybits << 16, &k)) { CHECKF(0, "%s 0x%lx", rows[i].name, GetLastError()); continue; }
        EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), rows[i].keybits);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_invalid_algids) {
    NEED_CRYPT(); NEED_PROV(p);
    static const ALG_ID bad[] = { 0, CALG_MD5, CALG_SHA1, CALG_SHA_256, CALG_HMAC, CALG_MAC, 0x600D /* RC5 */, 0x6000, 0x6604, 0x6700, 0x6FFF, 0xFFFF, CALG_RSA_SIGN | 0x10000 };
    for (unsigned i = 0; i < SIZEOFA(bad); i++) {
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, bad[i], 0, &k);
        CHECKF(!r, "alg 0x%x accepted", bad[i]);
        if (r) { U(CryptDestroyKey)(k); continue; }
        EXPECT_ERR(NTE_BAD_ALGID_);
    }
    ck_release(p);
}
TEST(genkey_invalid_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    /* observed in CPGenKey: flags & 0x1fe8 -> NTE_BAD_FLAGS (includes CRYPT_UPDATE_KEY = 8) */
    static const DWORD fl[] = { CRYPT_UPDATE_KEY, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000 };
    for (unsigned i = 0; i < SIZEOFA(fl); i++) {
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, CALG_AES_128, fl[i], &k);
        CHECKF(!r, "flag 0x%lx accepted", fl[i]);
        if (r) U(CryptDestroyKey)(k); else EXPECT_ERR(NTE_BAD_FLAGS_);
    }
    ck_release(p);
}
TEST(genkey_create_salt_rejected_for_des_family) {
    NEED_CRYPT(); NEED_PROV(p);
    static const ALG_ID a[] = { CALG_DES, CALG_3DES, CALG_3DES_112 };
    for (unsigned i = 0; i < 3; i++) {
        HCRYPTKEY k = 0; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGenKey)(p, a[i], CRYPT_CREATE_SALT, &k), NTE_BAD_FLAGS_);
    }
    ck_release(p);
}
TEST(genkey_create_salt_rc2_rc4) {
    NEED_CRYPT(); NEED_PROV(p);
    static const ALG_ID a[] = { CALG_RC2, CALG_RC4 };
    for (unsigned i = 0; i < 2; i++) {
        HCRYPTKEY k = 0; BYTE salt[32]; DWORD n = sizeof salt;
        if (!U(CryptGenKey)(p, a[i], CRYPT_CREATE_SALT, &k)) { CHECKF(0, "0x%lx", GetLastError()); continue; }
        BOOL r = U(CryptGetKeyParam)(k, KP_SALT, salt, &n, 0);
        CHECK(r); t_note("alg 0x%x CREATE_SALT salt length %lu", a[i], n);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_accepts_exportable_nosalt_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    static const DWORD fl[] = { CRYPT_EXPORTABLE, CRYPT_NO_SALT, CRYPT_EXPORTABLE | CRYPT_NO_SALT };
    for (unsigned i = 0; i < SIZEOFA(fl); i++) {
        HCRYPTKEY k = 0;
        if (!U(CryptGenKey)(p, CALG_AES_128, fl[i], &k)) { CHECKF(0, "flags %lx err 0x%lx", fl[i], GetLastError()); continue; }
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(genkey_two_keys_differ) {
    NEED_CRYPT(); NEED_PROV(p);
    BYTE b1[32], b2[32];
    for (int r = 0; r < 4; r++) {
        HCRYPTKEY k1 = 0, k2 = 0; DWORD n1 = sizeof b1, n2 = sizeof b2;
        CHECK(U(CryptGenKey)(p, CALG_AES_256, CRYPT_EXPORTABLE, &k1));
        CHECK(U(CryptGenKey)(p, CALG_AES_256, CRYPT_EXPORTABLE, &k2));
        CHECK(k1 != k2);
        BYTE blob1[128], blob2[128]; n1 = sizeof blob1; n2 = sizeof blob2;
        CHECK(U(CryptExportKey)(k1, 0, PLAINTEXTKEYBLOB, 0, blob1, &n1));
        CHECK(U(CryptExportKey)(k2, 0, PLAINTEXTKEYBLOB, 0, blob2, &n2));
        EXPECT_EQ(n1, 8 + 4 + 32);
        CHECK(memcmp(blob1 + 12, blob2 + 12, 32) != 0);
        U(CryptDestroyKey)(k1); U(CryptDestroyKey)(k2);
    }
    ck_release(p);
}
TEST(genkey_invalid_provider) {
    NEED_CRYPT();
    HCRYPTKEY k = 0xCC; SET_ERR(0);
    EXPECT_CAPI_FAIL(U(CryptGenKey)(0, CALG_AES_128, 0, &k), ERROR_INVALID_PARAMETER);
}
TEST(genkey_provider_without_aes_alg) {
    NEED_CRYPT();
    HCRYPTPROV p = ck_base(); if (!p) { t_skip("base provider unavailable"); return; }
    HCRYPTKEY k = 0; SET_ERR(0);
    BOOL r = U(CryptGenKey)(p, CALG_AES_256, 0, &k);
    if (r) { t_note("AES-256 GenKey accepted by base provider"); U(CryptDestroyKey)(k); } else EXPECT_ERR(NTE_BAD_ALGID_);
    ck_release(p);
}
TEST(genkey_base_provider_key_lengths) {
    NEED_CRYPT();
    HCRYPTPROV p = ck_base(); if (!p) { t_skip("base provider unavailable"); return; }
    HCRYPTKEY k = 0; BOOL ok;
    CHECK(U(CryptGenKey)(p, CALG_RC4, 0, &k)); if (k) { t_note("base RC4 default keylen %lu", ck_param_dw(k, KP_KEYLEN, &ok)); U(CryptDestroyKey)(k); }
    k = 0; CHECK(U(CryptGenKey)(p, CALG_RC2, 40 << 16, &k)); if (k) { EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), 40); U(CryptDestroyKey)(k); }
    k = 0; SET_ERR(0);
    BOOL r = U(CryptGenKey)(p, CALG_RC4, 128 << 16, &k);
    t_note("base provider RC4-128 GenKey: %s", r ? "ok" : "rejected");
    if (r) U(CryptDestroyKey)(k); else EXPECT_ERR(NTE_BAD_FLAGS_);
    k = 0; SET_ERR(0);
    r = U(CryptGenKey)(p, CALG_3DES, 0, &k);
    t_note("base provider 3DES GenKey: %s", r ? "ok" : "rejected");
    if (r) U(CryptDestroyKey)(k); else EXPECT_ERR(NTE_BAD_ALGID_);
    ck_release(p);
}

/* ---- destroy / duplicate --------------------------------------------- */
/* cryptsp handles are pointers to a tagged block that CryptDestroyKey clears and frees; operating on a
 * destroyed handle is reported as ERROR_INVALID_PARAMETER (tag mismatch) on Windows 10; the documented
 * NTE_BAD_KEY is accepted too. */
#define DEAD_KEY_ERR() do { DWORD e_ = GetLastError(); CHECKF(e_ == ERROR_INVALID_PARAMETER || e_ == (DWORD)NTE_BAD_KEY_, "err 0x%lx", e_); } while (0)
TEST(destroykey_then_use_all_apis_fails) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = 0; CHECK(U(CryptGenKey)(p, CALG_AES_128, CRYPT_EXPORTABLE, &k)); if (!k) return;
    CHECK(U(CryptDestroyKey)(k));
    DWORD v, n = 4; BYTE buf[64]; DWORD len = 16, ex = sizeof buf; HCRYPTKEY d = 0;
    memset(buf, 0, sizeof buf);
    SET_ERR(0); CHECK(!U(CryptGetKeyParam)(k, KP_ALGID, (BYTE *)&v, &n, 0)); DEAD_KEY_ERR();
    v = CRYPT_MODE_ECB;
    SET_ERR(0); CHECK(!U(CryptSetKeyParam)(k, KP_MODE, (BYTE *)&v, 0)); DEAD_KEY_ERR();
    SET_ERR(0); CHECK(!U(CryptEncrypt)(k, 0, TRUE, 0, buf, &len, sizeof buf)); DEAD_KEY_ERR();
    len = 16; SET_ERR(0); CHECK(!U(CryptDecrypt)(k, 0, TRUE, 0, buf, &len)); DEAD_KEY_ERR();
    SET_ERR(0); CHECK(!U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, buf, &ex)); DEAD_KEY_ERR();
    SET_ERR(0); CHECK(!U(CryptDuplicateKey)(k, NULL, 0, &d)); DEAD_KEY_ERR();
    ck_release(p);
}
TEST(destroykey_returns_true_and_provider_still_usable) {
    NEED_CRYPT(); NEED_PROV(p);
    for (int i = 0; i < 20; i++) {
        HCRYPTKEY k = 0; CHECK(U(CryptGenKey)(p, CALG_RC4, 0, &k)); CHECK(U(CryptDestroyKey)(k));
    }
    HCRYPTKEY k = 0; CHECK(U(CryptGenKey)(p, CALG_RC4, 0, &k)); U(CryptDestroyKey)(k);
    ck_release(p);
}
TEST(destroykey_imported_key) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); CHECK(k != 0);
    CHECK(U(CryptDestroyKey)(k)); ck_release(p);
}
TEST(duplicatekey_independent_state) {
    NEED_CRYPT(); NEED_PROV(p); REQUIRE(U(CryptDuplicateKey));
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), d = 0; if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    CHECK(U(CryptDuplicateKey)(k, NULL, 0, &d)); CHECK(d != 0 && d != k);
    BOOL ok; EXPECT_EQ(ck_param_dw(d, KP_ALGID, &ok), CALG_AES_128);
    BYTE iv[16]; DWORD n = 16;
    CHECK(U(CryptGetKeyParam)(d, KP_IV, iv, &n, 0)); CHECK_BYTES(iv, sp_iv, 16);
    /* changing the duplicate's IV leaves the original alone */
    BYTE iv2[16]; memset(iv2, 0x55, 16); ck_set_iv(d, iv2);
    n = 16; CHECK(U(CryptGetKeyParam)(k, KP_IV, iv, &n, 0)); CHECK_BYTES(iv, sp_iv, 16);
    /* both encrypt (the duplicate with its own IV) */
    BYTE b[32]; DWORD len;
    CHECK(ck_enc(k, sp_pt, 16, b, 32, &len)); EXPECT_EQ(len, 32); CHECK_BYTES(b, sp_cbcpad32_128 /* prefix: first block of pad32 */, 16);
    U(CryptDestroyKey)(k);
    CHECK(ck_enc(d, sp_pt, 16, b, 32, &len)); EXPECT_EQ(len, 32);  /* duplicate survives destruction of the source */
    U(CryptDestroyKey)(d); ck_release(p);
}
TEST(duplicatekey_copies_mid_stream_state) {
    NEED_CRYPT(); NEED_PROV(p);
    /* a duplicate of an RC4 key taken after some output continues from the same stream position */
    HCRYPTKEY k = ck_key(p, CALG_RC4, rc4_key128, 16), d = 0; if (!k) { CHECK(0); return; }
    BYTE a[16], b[16]; DWORD n = 16;
    memcpy(a, rc4_pt64, 16); CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, a, &n, 16));
    CHECK(U(CryptDuplicateKey)(k, NULL, 0, &d)); if (!d) return;
    n = 16; memcpy(a, rc4_pt64 + 16, 16); CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, a, &n, 16));
    n = 16; memcpy(b, rc4_pt64 + 16, 16); CHECK(U(CryptEncrypt)(d, 0, FALSE, 0, b, &n, 16));
    CHECK_BYTES(a, rc4_ct128 + 16, 16); CHECK_BYTES(b, rc4_ct128 + 16, 16);
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(d); ck_release(p);
}
TEST(duplicatekey_bad_reserved_and_flags) {
    NEED_CRYPT(); NEED_PROV(p); REQUIRE(U(CryptDuplicateKey));
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), d = 0; if (!k) { CHECK(0); return; }
    DWORD res = 1;
    SET_ERR(0); EXPECT_FAIL(!U(CryptDuplicateKey)(k, &res, 0, &d), ERROR_INVALID_PARAMETER);
    SET_ERR(0); EXPECT_FAIL(!U(CryptDuplicateKey)(k, NULL, 1, &d), NTE_BAD_FLAGS_);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(duplicatekey_null_output_pointer) {
    NEED_CRYPT(); NEED_PROV(p); REQUIRE(U(CryptDuplicateKey));
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    SET_ERR(0); EXPECT_FAIL(!U(CryptDuplicateKey)(k, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(duplicatekey_of_duplicate_chain) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_3DES, tdes_key, 24), a = 0, b = 0; if (!k) { CHECK(0); return; }
    ck_set_mode(k, CRYPT_MODE_ECB);
    CHECK(U(CryptDuplicateKey)(k, NULL, 0, &a)); CHECK(U(CryptDuplicateKey)(a, NULL, 0, &b));
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(a);
    BYTE buf[32]; DWORD n = 24; memcpy(buf, des_pt24, 24);
    CHECK(U(CryptEncrypt)(b, 0, FALSE, 0, buf, &n, 32)); CHECK_BYTES(buf, tdes_ecb24, 24);
    EXPECT_EQ(ck_param_dw(b, KP_MODE, NULL), CRYPT_MODE_ECB);
    U(CryptDestroyKey)(b); ck_release(p);
}
TEST(key_handle_values_unique) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY h[8];
    for (int i = 0; i < 8; i++) { h[i] = 0; CHECK(U(CryptGenKey)(p, CALG_RC4, 0, &h[i])); CHECK(h[i] != 0); }
    for (int i = 0; i < 8; i++) for (int j = i + 1; j < 8; j++) CHECK(h[i] != h[j]);
    for (int i = 0; i < 8; i++) U(CryptDestroyKey)(h[i]);
    ck_release(p);
}

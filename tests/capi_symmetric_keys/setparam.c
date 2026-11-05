#include "ck.h"
/* CryptSetKeyParam / KP_* round trips and their effect on the cipher. */

static const struct { ALG_ID a; const char *n; const BYTE *k; DWORD kl, blk; } brows[] = {
    { CALG_AES_128, "AES128", sp_key128, 16, 16 }, { CALG_AES_192, "AES192", sp_key192, 24, 16 }, { CALG_AES_256, "AES256", sp_key256, 32, 16 },
    { CALG_DES, "DES", des_key, 8, 8 }, { CALG_3DES, "3DES", tdes_key, 24, 8 }, { CALG_3DES_112, "3DES112", tdes112_key, 16, 8 },
    { CALG_RC2, "RC2", rc2_v7_key, 16, 8 } };

TEST(setparam_iv_roundtrip_block_algs) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(brows); i++) {
        HCRYPTKEY k = ck_key(p, brows[i].a, brows[i].k, brows[i].kl); if (!k) { CHECK(0); continue; }
        BYTE iv[16], got[16]; for (int j = 0; j < 16; j++) iv[j] = (BYTE)(0xA0 + j);
        CHECKF(ck_set_iv(k, iv), "%s 0x%lx", brows[i].n, GetLastError());
        DWORD n = sizeof got; memset(got, 0, sizeof got);
        CHECK(U(CryptGetKeyParam)(k, KP_IV, got, &n, 0)); EXPECT_EQ(n, brows[i].blk); CHECK_BYTES(got, iv, brows[i].blk);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(setparam_iv_changes_cbc_output_ecb_unaffected) {
    NEED_CRYPT(); NEED_PROV(p);
    BYTE iv2[16]; memset(iv2, 0x11, 16);
    for (int ecb = 0; ecb < 2; ecb++) {
        HCRYPTKEY a = ck_key(p, CALG_AES_128, sp_key128, 16), b = ck_key(p, CALG_AES_128, sp_key128, 16);
        if (!a || !b) { CHECK(0); return; }
        if (ecb) { ck_set_mode(a, CRYPT_MODE_ECB); ck_set_mode(b, CRYPT_MODE_ECB); }
        ck_set_iv(a, sp_iv); ck_set_iv(b, iv2);
        BYTE x[16], y[16]; DWORD n = 16, m = 16; memcpy(x, sp_pt, 16); memcpy(y, sp_pt, 16);
        CHECK(U(CryptEncrypt)(a, 0, FALSE, 0, x, &n, 16)); CHECK(U(CryptEncrypt)(b, 0, FALSE, 0, y, &m, 16));
        if (ecb) CHECK_BYTES(x, y, 16); else CHECK(memcmp(x, y, 16) != 0);
        U(CryptDestroyKey)(a); U(CryptDestroyKey)(b);
    }
    ck_release(p);
}
TEST(setparam_mode_roundtrip) {
    NEED_CRYPT(); NEED_PROV(p);
    static const DWORD modes[] = { CRYPT_MODE_CBC, CRYPT_MODE_ECB, CRYPT_MODE_OFB, CRYPT_MODE_CFB };
    for (unsigned i = 0; i < SIZEOFA(brows); i++) {
        HCRYPTKEY k = ck_key(p, brows[i].a, brows[i].k, brows[i].kl); if (!k) { CHECK(0); continue; }
        for (unsigned m = 0; m < 4; m++) {
            BOOL ok; SET_ERR(0);
            if (!ck_set_mode(k, modes[m])) { t_note("%s set mode %lu failed 0x%lx", brows[i].n, modes[m], GetLastError()); continue; }
            EXPECT_EQ(ck_param_dw(k, KP_MODE, &ok), modes[m]); CHECK(ok);
        }
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(setparam_mode_ecb_cbc_cfb_always_accepted) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    CHECK(ck_set_mode(k, CRYPT_MODE_ECB)); CHECK(ck_set_mode(k, CRYPT_MODE_CBC)); CHECK(ck_set_mode(k, CRYPT_MODE_CFB));
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_mode_invalid_values) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    /* decomp: only the low byte is range-checked ((BYTE)(mode-1) < 4), so 0x101 would be stored; avoid such values */
    static const DWORD bad[] = { 0, CRYPT_MODE_CTS, 6, 7, 0x100, 0x200, 0x80 };
    for (unsigned i = 0; i < SIZEOFA(bad); i++) {
        SET_ERR(0);
        EXPECT_FAIL(!ck_set_mode(k, bad[i]), NTE_BAD_DATA_);
        BOOL ok; EXPECT_EQ(ck_param_dw(k, KP_MODE, &ok), CRYPT_MODE_CBC);   /* unchanged */
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_mode_switch_ecb_changes_output) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    BYTE b[32]; DWORD n = 32;
    ck_set_mode(k, CRYPT_MODE_ECB); ck_set_iv(k, sp_iv);
    memcpy(b, sp_pt, 32); CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 32)); CHECK_BYTES(b, sp_ecb128, 32);
    ck_set_mode(k, CRYPT_MODE_CBC); ck_set_iv(k, sp_iv);
    n = 32; memcpy(b, sp_pt, 32); CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 32)); CHECK_BYTES(b, sp_cbc128, 32);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_mode_bits_roundtrip) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    static const DWORD good[] = { 1, 8, 16, 32, 64 };
    for (unsigned i = 0; i < SIZEOFA(good); i++) {
        DWORD v = good[i]; SET_ERR(0);
        BOOL r = U(CryptSetKeyParam)(k, KP_MODE_BITS, (BYTE *)&v, 0);
        if (!r) { t_note("KP_MODE_BITS %lu rejected 0x%lx", v, GetLastError()); continue; }
        BOOL ok; EXPECT_EQ(ck_param_dw(k, KP_MODE_BITS, &ok), v);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_mode_bits_invalid) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    static const DWORD bad[] = { 0, 65, 128, 0x100, 0xffffffff };
    for (unsigned i = 0; i < SIZEOFA(bad); i++) {
        DWORD v = bad[i]; SET_ERR(0);
        BOOL r = U(CryptSetKeyParam)(k, KP_MODE_BITS, (BYTE *)&v, 0);
        CHECKF(!r, "mode bits %lu accepted", v);
        if (!r) EXPECT_ERR(NTE_BAD_DATA_);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_padding_pkcs5_accepted) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    CHECK(ck_set_pad(k, PKCS5_PADDING)); BOOL ok; EXPECT_EQ(ck_param_dw(k, KP_PADDING, &ok), PKCS5_PADDING);
    SET_ERR(0);
    for (DWORD v = 0; v <= 4; v++) { if (v == PKCS5_PADDING) continue; BOOL r = ck_set_pad(k, v); t_note("KP_PADDING = %lu -> %s 0x%lx", v, r ? "ok" : "rejected", r ? 0 : GetLastError()); }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_effective_keylen_rc2) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_RC2, rc2_v7_key, 16); if (!k) { CHECK(0); return; }
    static const DWORD ok_vals[] = { 40, 56, 64, 80, 128 };
    for (unsigned i = 0; i < SIZEOFA(ok_vals); i++) {
        DWORD v = ok_vals[i]; BOOL ok;
        CHECKF(U(CryptSetKeyParam)(k, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0), "eff %lu 0x%lx", v, GetLastError());
        EXPECT_EQ(ck_param_dw(k, KP_EFFECTIVE_KEYLEN, &ok), v);
    }
    DWORD zero = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_EFFECTIVE_KEYLEN, (BYTE *)&zero, 0), NTE_BAD_DATA_);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_effective_keylen_changes_rc2_output) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY a = ck_key(p, CALG_RC2, rc2_v7_key, 16), b = ck_key(p, CALG_RC2, rc2_v7_key, 16); if (!a || !b) { CHECK(0); return; }
    DWORD e1 = 64, e2 = 128; U(CryptSetKeyParam)(a, KP_EFFECTIVE_KEYLEN, (BYTE *)&e1, 0); U(CryptSetKeyParam)(b, KP_EFFECTIVE_KEYLEN, (BYTE *)&e2, 0);
    ck_set_mode(a, CRYPT_MODE_ECB); ck_set_mode(b, CRYPT_MODE_ECB);
    BYTE x[8] = { 0 }, y[8] = { 0 }; DWORD n = 8, m = 8;
    CHECK(U(CryptEncrypt)(a, 0, FALSE, 0, x, &n, 8)); CHECK(U(CryptEncrypt)(b, 0, FALSE, 0, y, &m, 8));
    CHECK_BYTES(x, rc2_v6_ct, 8); CHECK_BYTES(y, rc2_v7_ct, 8);
    U(CryptDestroyKey)(a); U(CryptDestroyKey)(b); ck_release(p);
}
TEST(setparam_effective_keylen_wrong_algorithms) {
    NEED_CRYPT(); NEED_PROV(p);
    static const ALG_ID a[] = { CALG_DES, CALG_3DES, CALG_AES_128, CALG_RC4 };
    static const BYTE *ks[] = { des_key, tdes_key, sp_key128, rc4_key128 };
    static const DWORD kl[] = { 8, 24, 16, 16 };
    for (unsigned i = 0; i < 4; i++) {
        HCRYPTKEY k = ck_key(p, a[i], ks[i], kl[i]); if (!k) { CHECK(0); continue; }
        DWORD v = 64; SET_ERR(0);
        EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0), NTE_BAD_KEY_);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(setparam_salt_wrong_algorithms) {
    NEED_CRYPT(); NEED_PROV(p);
    static const ALG_ID a[] = { CALG_DES, CALG_3DES, CALG_AES_128, CALG_AES_256 };
    static const BYTE *ks[] = { des_key, tdes_key, sp_key128, sp_key256 };
    static const DWORD kl[] = { 8, 24, 16, 32 };
    for (unsigned i = 0; i < 4; i++) {
        HCRYPTKEY k = ck_key(p, a[i], ks[i], kl[i]); if (!k) { CHECK(0); continue; }
        BYTE salt[11] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }; SET_ERR(0);
        EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_SALT, salt, 0), NTE_BAD_KEY_);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(setparam_salt_ex_rc2_rc4) {
    NEED_CRYPT(); NEED_PROV(p);
    static const ALG_ID a[] = { CALG_RC2, CALG_RC4 };
    for (unsigned i = 0; i < 2; i++) {
        HCRYPTKEY k = ck_key(p, a[i], rc2_v7_key, 16); if (!k) { CHECK(0); continue; }
        BYTE sb[16 + 8]; CRYPT_DATA_BLOB *blob = (CRYPT_DATA_BLOB *)sb; BYTE salt[11] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9 };
        blob->cbData = 11; blob->pbData = salt;
        SET_ERR(0);
        BOOL r = U(CryptSetKeyParam)(k, KP_SALT_EX, (BYTE *)blob, 0);
        t_note("alg 0x%x KP_SALT_EX set: %s 0x%lx", a[i], r ? "ok" : "fail", r ? 0 : GetLastError());
        if (r) {
            BYTE out[32]; DWORD n = sizeof out;
            BOOL g = U(CryptGetKeyParam)(k, KP_SALT, out, &n, 0);
            t_note("  KP_SALT readback %s len %lu", g ? "ok" : "fail", n);
        }
        blob->cbData = 25; SET_ERR(0);
        r = U(CryptSetKeyParam)(k, KP_SALT_EX, (BYTE *)blob, 0);
        CHECK(!r); if (!r) EXPECT_ERR(NTE_BAD_DATA_);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(setparam_salt_ex_wrong_algorithm) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    BYTE salt[11] = { 0 }; CRYPT_DATA_BLOB blob; blob.cbData = 11; blob.pbData = salt; SET_ERR(0);
    EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_SALT_EX, (BYTE *)&blob, 0), NTE_BAD_KEY_);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_unknown_param) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    static const DWORD kp[] = { 0x15, 0x20, 0x63, 0x7f, 0x1000, 0xdeadbeef };
    for (unsigned i = 0; i < SIZEOFA(kp); i++) {
        DWORD v = 0; SET_ERR(0);
        BOOL r = U(CryptSetKeyParam)(k, kp[i], (BYTE *)&v, 0);
        t_note("SetKeyParam(0x%lx) -> 0x%lx", kp[i], GetLastError());
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_nonzero_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    /* decomp CPSetKeyParam: only the 0x400 flag bit may be set */
    static const DWORD bad[] = { 1, 2, 4, 8, 0x10, 0x100, 0x200, 0x800, 0x80000000 };
    DWORD mode = CRYPT_MODE_ECB;
    for (unsigned i = 0; i < SIZEOFA(bad); i++) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_MODE, (BYTE *)&mode, bad[i]), NTE_BAD_FLAGS_);
    }
    BOOL ok; EXPECT_EQ(ck_param_dw(k, KP_MODE, &ok), CRYPT_MODE_CBC);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_read_only_params_rejected) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    static const DWORD kp[] = { KP_ALGID, KP_KEYLEN, KP_BLOCKLEN };
    for (unsigned i = 0; i < 3; i++) {
        DWORD v = 0x100; SET_ERR(0);
        BOOL r = U(CryptSetKeyParam)(k, kp[i], (BYTE *)&v, 0);
        t_note("SetKeyParam(read-only 0x%lx) -> %s 0x%lx", kp[i], r ? "ok" : "fail", r ? 0 : GetLastError());
    }
    BOOL ok; EXPECT_EQ(ck_param_dw(k, KP_ALGID, &ok), CALG_AES_128); EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), 128); EXPECT_EQ(ck_param_dw(k, KP_BLOCKLEN, &ok), 128);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_permissions_semantics) {
    NEED_CRYPT(); NEED_PROV(p);
    /* decomp CPSetKeyParam(KP_PERMISSIONS): bits outside 0x13f -> NTE_BAD_FLAGS; CRYPT_EXPORT (4) and the archive bit
     * (0x100) cannot be newly granted (NTE_BAD_DATA) and are never cleared; the remaining bits are replaced. */
    HCRYPTKEY k = 0; CHECK(U(CryptGenKey)(p, CALG_AES_128, CRYPT_EXPORTABLE, &k)); if (!k) return;
    BOOL ok; DWORD perm = ck_param_dw(k, KP_PERMISSIONS, &ok); CHECK(ok);
    t_note("default KP_PERMISSIONS=0x%lx", perm);
    static const DWORD badbits[] = { 0x40, 0x80, 0x200, 0x400, 0x1000, 0x80000000 };
    for (unsigned i = 0; i < SIZEOFA(badbits); i++) {
        DWORD v = badbits[i]; SET_ERR(0);
        EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_PERMISSIONS, (BYTE *)&v, 0), NTE_BAD_FLAGS_);
    }
    DWORD v = 0; CHECK(U(CryptSetKeyParam)(k, KP_PERMISSIONS, (BYTE *)&v, 0));
    DWORD after = ck_param_dw(k, KP_PERMISSIONS, &ok); CHECK(ok);
    EXPECT_EQ(after, perm & 0x104);                       /* only EXPORT/ARCHIVE survive */
    v = 0x3b; if (perm & 4) { CHECK(U(CryptSetKeyParam)(k, KP_PERMISSIONS, (BYTE *)&v, 0)); EXPECT_EQ(ck_param_dw(k, KP_PERMISSIONS, &ok), (perm & 0x104) | 0x3b); }
    U(CryptDestroyKey)(k);
    /* a key imported without CRYPT_EXPORTABLE cannot gain CRYPT_EXPORT */
    CHECK(ck_import_plain(p, CALG_AES_128, sp_key128, 16, 0, &k)); if (!k) return;
    perm = ck_param_dw(k, KP_PERMISSIONS, &ok);
    t_note("non-exportable import KP_PERMISSIONS=0x%lx", perm);
    if (!(perm & 4)) { v = 4; SET_ERR(0); EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_PERMISSIONS, (BYTE *)&v, 0), NTE_BAD_DATA_); }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(getparam_keylen_for_imported_keys) {
    NEED_CRYPT(); NEED_PROV(p);
    static const struct { ALG_ID a; const BYTE *k; DWORD kl, bits; } t[] = {
        { CALG_DES, des_key, 8, 64 }, { CALG_3DES, tdes_key, 24, 192 }, { CALG_3DES_112, tdes112_key, 16, 128 },
        { CALG_AES_128, sp_key128, 16, 128 }, { CALG_AES_192, sp_key192, 24, 192 }, { CALG_AES_256, sp_key256, 32, 256 },
        { CALG_RC2, rc2_v7_key, 16, 128 }, { CALG_RC4, rc4_key128, 16, 128 } };
    for (unsigned i = 0; i < SIZEOFA(t); i++) {
        HCRYPTKEY k = ck_key(p, t[i].a, t[i].k, t[i].kl); if (!k) { CHECK(0); continue; }
        BOOL ok; EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), t[i].bits); EXPECT_EQ(ck_param_dw(k, KP_ALGID, &ok), t[i].a);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(getparam_certificate_and_other_params_on_symmetric_key) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    static const DWORD kp[] = { KP_CERTIFICATE, KP_GET_USE_COUNT, KP_ADMIN_PIN, KP_KEYEXCHANGE_PIN, KP_SIGNATURE_PIN, KP_P, KP_G, KP_Q, KP_X, KP_OAEP_PARAMS };
    for (unsigned i = 0; i < SIZEOFA(kp); i++) {
        BYTE b[512]; DWORD n = sizeof b; SET_ERR(0);
        BOOL r = U(CryptGetKeyParam)(k, kp[i], b, &n, 0);
        t_note("GetKeyParam(%lu) on AES key: %s 0x%lx n=%lu", kp[i], r ? "ok" : "fail", r ? 0 : GetLastError(), n);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(getparam_buffer_protocol_dword_params) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    static const DWORD kp[] = { KP_ALGID, KP_KEYLEN, KP_BLOCKLEN, KP_MODE, KP_MODE_BITS, KP_PADDING, KP_PERMISSIONS };
    for (unsigned i = 0; i < SIZEOFA(kp); i++) {
        DWORD n = 0; DWORD v;
        CHECKF(U(CryptGetKeyParam)(k, kp[i], NULL, &n, 0), "kp %lu size query 0x%lx", kp[i], GetLastError()); EXPECT_EQ(n, 4);
        n = 2; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, kp[i], (BYTE *)&v, &n, 0), ERROR_MORE_DATA); EXPECT_EQ(n, 4);
        n = 4; CHECK(U(CryptGetKeyParam)(k, kp[i], (BYTE *)&v, &n, 0)); EXPECT_EQ(n, 4);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(setparam_iv_does_not_follow_after_final) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE b[48]; DWORD n;
    CHECK(ck_enc(k, sp_pt, 20, b, 48, &n));
    BYTE iv[16]; DWORD l = 16; CHECK(U(CryptGetKeyParam)(k, KP_IV, iv, &l, 0));
    t_note("KP_IV after a Final encrypt equals original IV: %d, equals last ciphertext block: %d", !memcmp(iv, sp_iv, 16), !memcmp(iv, b + 16, 16));
    U(CryptDestroyKey)(k); ck_release(p);
}

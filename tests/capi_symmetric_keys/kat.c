#include "ck.h"
/* Known-answer tests: keys imported as PLAINTEXTKEYBLOB, ciphers driven through CryptEncrypt/CryptDecrypt.
 * Vectors: FIPS-197, SP 800-38A, RFC 2268, RFC 6229 style RC4, DES/3DES from the standards; the
 * multi-block and padded outputs were computed once at authoring time (see vectors.h). */

typedef struct {
    ALG_ID alg; const BYTE *key; DWORD keylen;
    DWORD mode;                 /* 0 = leave default (CBC) */
    const BYTE *iv;             /* NULL = do not set */
    DWORD eff;                  /* RC2 effective key bits, 0 = leave */
    const BYTE *pt; DWORD ptlen;
    const BYTE *ct; DWORD ctlen;
    BOOL final;                 /* Final flag for the single call */
} kat_t;

static HCRYPTKEY kat_mk(HCRYPTPROV p, const kat_t *k) {
    HCRYPTKEY h = ck_key(p, k->alg, k->key, k->keylen);
    if (!h) return 0;
    if (k->eff) U(CryptSetKeyParam)(h, KP_EFFECTIVE_KEYLEN, (BYTE *)&k->eff, 0);
    if (k->mode) ck_set_mode(h, k->mode);
    if (k->iv) ck_set_iv(h, k->iv);
    return h;
}
static void kat_run(HCRYPTPROV p, const kat_t *k, const char *name) {
    BYTE buf[256]; DWORD n;
    HCRYPTKEY h = kat_mk(p, k);
    if (!h) { CHECKF(0, "import failed for %s err=0x%lx", name, GetLastError()); return; }
    n = k->ptlen; memcpy(buf, k->pt, k->ptlen);
    BOOL r = U(CryptEncrypt)(h, 0, k->final, 0, buf, &n, sizeof buf);
    CHECKF(r, "%s encrypt err=0x%lx", name, GetLastError());
    if (r) { EXPECT_EQ(n, k->ctlen); if (n == k->ctlen) CHECK_BYTES(buf, k->ct, k->ctlen); }
    U(CryptDestroyKey)(h);
    h = kat_mk(p, k);
    if (!h) return;
    n = k->ctlen; memcpy(buf, k->ct, k->ctlen);
    r = U(CryptDecrypt)(h, 0, k->final, 0, buf, &n);
    CHECKF(r, "%s decrypt err=0x%lx", name, GetLastError());
    if (r) { EXPECT_EQ(n, k->ptlen); if (n == k->ptlen) CHECK_BYTES(buf, k->pt, k->ptlen); }
    U(CryptDestroyKey)(h);
}
#define KAT(alg, key, mode, iv, eff, pt, ct, fin) { alg, key, sizeof key, mode, iv, eff, pt, sizeof pt, ct, sizeof ct, fin }

TEST(kat_aes_fips197_c1_c3) {
    NEED_CRYPT(); NEED_PROV(p);
    const kat_t t[] = {
        { CALG_AES_128, aes128_fips_key, 16, CRYPT_MODE_ECB, NULL, 0, aes_pt16, 16, aes128_fips_ct, 16, FALSE },
        { CALG_AES_192, aes192_fips_key, 24, CRYPT_MODE_ECB, NULL, 0, aes_pt16, 16, aes192_fips_ct, 16, FALSE },
        { CALG_AES_256, aes256_fips_key, 32, CRYPT_MODE_ECB, NULL, 0, aes_pt16, 16, aes256_fips_ct, 16, FALSE },
    };
    for (int i = 0; i < 3; i++) kat_run(p, &t[i], "fips197");
    ck_release(p);
}
TEST(kat_aes128_fips197_ecb_only) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t t = { CALG_AES_128, aes128_fips_key, 16, CRYPT_MODE_ECB, NULL, 0, aes_pt16, 16, aes128_fips_ct, 16, FALSE };
    kat_run(p, &t, "aes128 ecb");
    ck_release(p);
}
TEST(kat_aes_sp800_38a_ecb) {
    NEED_CRYPT(); NEED_PROV(p);
    const kat_t t[] = {
        { CALG_AES_128, sp_key128, 16, CRYPT_MODE_ECB, NULL, 0, sp_pt, 64, sp_ecb128, 64, FALSE },
        { CALG_AES_192, sp_key192, 24, CRYPT_MODE_ECB, NULL, 0, sp_pt, 64, sp_ecb192, 64, FALSE },
        { CALG_AES_256, sp_key256, 32, CRYPT_MODE_ECB, NULL, 0, sp_pt, 64, sp_ecb256, 64, FALSE },
    };
    for (int i = 0; i < 3; i++) kat_run(p, &t[i], "sp800-38a ecb");
    ck_release(p);
}
TEST(kat_aes_sp800_38a_cbc) {
    NEED_CRYPT(); NEED_PROV(p);
    const kat_t t[] = {
        { CALG_AES_128, sp_key128, 16, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 64, sp_cbc128, 64, FALSE },
        { CALG_AES_192, sp_key192, 24, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 64, sp_cbc192, 64, FALSE },
        { CALG_AES_256, sp_key256, 32, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 64, sp_cbc256, 64, FALSE },
    };
    for (int i = 0; i < 3; i++) kat_run(p, &t[i], "sp800-38a cbc");
    ck_release(p);
}
TEST(kat_aes_default_mode_is_cbc) {
    NEED_CRYPT(); NEED_PROV(p);
    /* no KP_MODE set: the key must behave as CBC */
    kat_t t = { CALG_AES_128, sp_key128, 16, 0, sp_iv, 0, sp_pt, 64, sp_cbc128, 64, FALSE };
    kat_run(p, &t, "default mode cbc");
    ck_release(p);
}
TEST(kat_aes_cbc_pkcs5_unaligned20) {
    NEED_CRYPT(); NEED_PROV(p);
    /* Final=TRUE with PKCS#5 padding (the default): 20 bytes -> 32 */
    const kat_t t[] = {
        { CALG_AES_128, sp_key128, 16, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 20, sp_cbcpad20_128, 32, TRUE },
        { CALG_AES_192, sp_key192, 24, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 20, sp_cbcpad20_192, 32, TRUE },
        { CALG_AES_256, sp_key256, 32, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 20, sp_cbcpad20_256, 32, TRUE },
    };
    for (int i = 0; i < 3; i++) kat_run(p, &t[i], "aes cbc pad20");
    ck_release(p);
}
TEST(kat_aes_cbc_pkcs5_aligned32_adds_block) {
    NEED_CRYPT(); NEED_PROV(p);
    /* block-aligned input still gets a full padding block when Final=TRUE */
    const kat_t t[] = {
        { CALG_AES_128, sp_key128, 16, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 32, sp_cbcpad32_128, 48, TRUE },
        { CALG_AES_192, sp_key192, 24, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 32, sp_cbcpad32_192, 48, TRUE },
        { CALG_AES_256, sp_key256, 32, CRYPT_MODE_CBC, sp_iv, 0, sp_pt, 32, sp_cbcpad32_256, 48, TRUE },
    };
    for (int i = 0; i < 3; i++) kat_run(p, &t[i], "aes cbc pad32");
    ck_release(p);
}
TEST(kat_aes_cfb8) {
    NEED_CRYPT(); NEED_PROV(p);
    const BYTE *keys[3] = { sp_key128, sp_key192, sp_key256 };
    const BYTE *cts[3] = { sp_cfb8_128, sp_cfb8_192, sp_cfb8_256 };
    ALG_ID algs[3] = { CALG_AES_128, CALG_AES_192, CALG_AES_256 };
    DWORD kl[3] = { 16, 24, 32 };
    for (int i = 0; i < 3; i++) {
        kat_t t = { algs[i], keys[i], kl[i], CRYPT_MODE_CFB, sp_iv, 0, sp_pt, 16, cts[i], 16, FALSE };
        HCRYPTKEY h = kat_mk(p, &t);
        if (!h) { CHECK(0); continue; }
        BYTE buf[32]; DWORD n = 16; memcpy(buf, sp_pt, 16);
        if (U(CryptEncrypt)(h, 0, FALSE, 0, buf, &n, sizeof buf)) { EXPECT_EQ(n, 16); CHECK_BYTES(buf, cts[i], 16); }
        else CHECKF(0, "cfb8 16 bytes err=0x%lx", GetLastError());
        U(CryptDestroyKey)(h);
        h = kat_mk(p, &t);
        n = 20; memcpy(buf, sp_pt, 20);
        BOOL r = U(CryptEncrypt)(h, 0, FALSE, 0, buf, &n, sizeof buf);
        if (!r) { t_note("CFB(8-bit) non-final 20 bytes failed err=0x%lx", GetLastError()); U(CryptDestroyKey)(h); continue; }
        EXPECT_EQ(n, 20); CHECK_BYTES(buf, cts[i], 20);
        U(CryptDestroyKey)(h);
    }
    ck_release(p);
}
TEST(kat_des_ecb_classic) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t t = KAT(CALG_DES, des_key, CRYPT_MODE_ECB, NULL, 0, des_pt8, des_ecb8, FALSE);
    kat_run(p, &t, "des ecb 8");
    /* the classic worked example: key 133457799BBCDFF1, plaintext 0123456789ABCDEF -> 85E813540F0AB405 */
    static const BYTE want[8] = { 0x85,0xE8,0x13,0x54,0x0F,0x0A,0xB4,0x05 };
    CHECK_BYTES(des_ecb8, want, 8);
    ck_release(p);
}
TEST(kat_des_ecb_cbc_24) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t a = KAT(CALG_DES, des_key, CRYPT_MODE_ECB, NULL, 0, des_pt24, des_ecb24, FALSE);
    kat_t b = KAT(CALG_DES, des_key, CRYPT_MODE_CBC, des_iv, 0, des_pt24, des_cbc24, FALSE);
    kat_run(p, &a, "des ecb 24"); kat_run(p, &b, "des cbc 24");
    ck_release(p);
}
TEST(kat_des_cbc_pkcs5_20) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t a = { CALG_DES, des_key, 8, CRYPT_MODE_CBC, des_iv, 0, des_pt24, 20, des_cbcpad20, sizeof des_cbcpad20, TRUE };
    kat_run(p, &a, "des cbc pad");
    EXPECT_EQ(sizeof des_cbcpad20, 24);
    ck_release(p);
}
TEST(kat_des_cfb8_20) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t a = { CALG_DES, des_key, 8, CRYPT_MODE_CFB, des_iv, 0, des_pt24, 16, des_cfb8_20, 16, FALSE };
    HCRYPTKEY h = kat_mk(p, &a); if (!h) { CHECK(0); return; }
    BYTE buf[32]; DWORD n = 16; memcpy(buf, des_pt24, 16);
    if (U(CryptEncrypt)(h, 0, FALSE, 0, buf, &n, sizeof buf)) { EXPECT_EQ(n, 16); CHECK_BYTES(buf, des_cfb8_20, 16); }
    else CHECKF(0, "des cfb8 16 err=0x%lx", GetLastError());
    U(CryptDestroyKey)(h);
    h = kat_mk(p, &a); n = 20; memcpy(buf, des_pt24, 20);
    if (U(CryptEncrypt)(h, 0, FALSE, 0, buf, &n, sizeof buf)) { EXPECT_EQ(n, 20); CHECK_BYTES(buf, des_cfb8_20, 20); }
    else t_note("DES CFB non-final 20 bytes failed 0x%lx", GetLastError());
    U(CryptDestroyKey)(h); ck_release(p);
}
TEST(kat_3des_ecb_cbc_24) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t a = KAT(CALG_3DES, tdes_key, CRYPT_MODE_ECB, NULL, 0, des_pt24, tdes_ecb24, FALSE);
    kat_t b = KAT(CALG_3DES, tdes_key, CRYPT_MODE_CBC, des_iv, 0, des_pt24, tdes_cbc24, FALSE);
    kat_run(p, &a, "3des ecb"); kat_run(p, &b, "3des cbc");
    ck_release(p);
}
TEST(kat_3des_cbc_pkcs5_20) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t a = { CALG_3DES, tdes_key, 24, CRYPT_MODE_CBC, des_iv, 0, des_pt24, 20, tdes_cbcpad20, sizeof tdes_cbcpad20, TRUE };
    kat_run(p, &a, "3des cbc pad");
    ck_release(p);
}
TEST(kat_3des112_ecb_cbc_24) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t a = KAT(CALG_3DES_112, tdes112_key, CRYPT_MODE_ECB, NULL, 0, des_pt24, tdes112_ecb24, FALSE);
    kat_t b = KAT(CALG_3DES_112, tdes112_key, CRYPT_MODE_CBC, des_iv, 0, des_pt24, tdes112_cbc24, FALSE);
    kat_run(p, &a, "3des112 ecb"); kat_run(p, &b, "3des112 cbc");
    ck_release(p);
}
TEST(kat_3des_with_k1_eq_k2_eq_k3_is_single_des) {
    NEED_CRYPT(); NEED_PROV(p);
    BYTE k[24]; memcpy(k, des_key, 8); memcpy(k + 8, des_key, 8); memcpy(k + 16, des_key, 8);
    kat_t a = { CALG_3DES, k, 24, CRYPT_MODE_ECB, NULL, 0, des_pt24, 24, des_ecb24, 24, FALSE };
    kat_run(p, &a, "3des==des");
    ck_release(p);
}
TEST(kat_rc2_rfc2268) {
    NEED_CRYPT(); NEED_PROV(p);
    const BYTE *k[] = { rc2_v1_key, rc2_v2_key, rc2_v3_key, rc2_v6_key, rc2_v7_key };
    const BYTE *pt[] = { rc2_v1_pt, rc2_v2_pt, rc2_v3_pt, rc2_v6_pt, rc2_v7_pt };
    const BYTE *ct[] = { rc2_v1_ct, rc2_v2_ct, rc2_v3_ct, rc2_v6_ct, rc2_v7_ct };
    DWORD kl[] = { 8, 8, 8, 16, 16 }, eff[] = { 63, 64, 64, 64, 128 };
    for (int i = 0; i < 5; i++) {
        kat_t t = { CALG_RC2, k[i], kl[i], CRYPT_MODE_ECB, NULL, eff[i], pt[i], 8, ct[i], 8, FALSE };
        kat_run(p, &t, "rc2");
    }
    ck_release(p);
}
TEST(kat_rc2_short_keys_rfc2268) {
    NEED_CRYPT(); NEED_PROV(p);
    /* 1 and 7 byte keys: minimum accepted RC2 plaintext key size is provider-dependent -> observe only */
    const BYTE *k[] = { rc2_v4_key, rc2_v5_key }; DWORD kl[] = { 1, 7 };
    const BYTE *ct[] = { rc2_v4_ct, rc2_v5_ct }; const BYTE *pt[] = { rc2_v4_pt, rc2_v5_pt };
    for (int i = 0; i < 2; i++) {
        HCRYPTKEY h = ck_key(p, CALG_RC2, k[i], kl[i]);
        if (!h) { t_note("RC2 %lu-byte plaintext key import rejected: 0x%lx", kl[i], GetLastError()); continue; }
        DWORD e = 64; U(CryptSetKeyParam)(h, KP_EFFECTIVE_KEYLEN, (BYTE *)&e, 0); ck_set_mode(h, CRYPT_MODE_ECB);
        BYTE b[16]; DWORD n = 8; memcpy(b, pt[i], 8);
        if (U(CryptEncrypt)(h, 0, FALSE, 0, b, &n, 16)) CHECK_BYTES(b, ct[i], 8); else t_note("encrypt 0x%lx", GetLastError());
        U(CryptDestroyKey)(h);
    }
    ck_release(p);
}
/* Windows rsaenh (decomp CPImportKey case 8) skips the 88-bit zero salt of 5-byte keys only with CRYPT_NO_SALT;
 * the emulator ignores that flag, so the NO_SALT-dependent tests are skipped there. */
#define NOSALT_NEEDS_WINDOWS() do { if (t_is_wine()) { t_skip("emulator ignores CRYPT_NO_SALT on 5-byte plaintext import"); return; } } while (0)
TEST(kat_rc4_40_nosalt) {
    NEED_CRYPT(); NEED_PROV(p); NOSALT_NEEDS_WINDOWS();
    kat_t a = KAT(CALG_RC4, rc4_key40, 0, NULL, 0, rc4_pt64, rc4_ct40, FALSE); /* ck_key imports with CRYPT_NO_SALT */
    kat_run(p, &a, "rc4-40");
    ck_release(p);
}
TEST(kat_rc4_128) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t b = KAT(CALG_RC4, rc4_key128, 0, NULL, 0, rc4_pt64, rc4_ct128, FALSE);
    kat_run(p, &b, "rc4-128");
    ck_release(p);
}
TEST(kat_rc4_40bit_rfc6229_keystream) {
    NEED_CRYPT(); NEED_PROV(p); NOSALT_NEEDS_WINDOWS();
    /* encrypting zeros yields the key stream: RFC 6229, key 0102030405, offset 0 */
    static const BYTE want[16] = { 0xb2,0x39,0x63,0x05,0xf0,0x3d,0xc0,0x27,0xcc,0xc3,0x52,0x4a,0x0a,0x11,0x18,0xa8 };
    HCRYPTKEY h = ck_key(p, CALG_RC4, rc4_key40, 5); if (!h) { CHECK(0); return; }
    BYTE b[16] = { 0 }; DWORD n = 16;
    CHECK(U(CryptEncrypt)(h, 0, FALSE, 0, b, &n, 16)); CHECK_BYTES(b, want, 16);
    U(CryptDestroyKey)(h); ck_release(p);
}
TEST(kat_rc4_40bit_import_without_nosalt_adds_zero_salt) {
    NEED_CRYPT(); NEED_PROV(p);
    /* decomp CPImportKey: a 5-byte key imported without CRYPT_NO_SALT is made RSA-base-compatible, i.e.
     * it behaves as key||11 zero bytes (a 128-bit key with an 88-bit zero salt). */
    HCRYPTKEY h = 0;
    CHECK(ck_import_plain(p, CALG_RC4, rc4_key40, 5, CRYPT_EXPORTABLE, &h));
    if (!h) return;
    BYTE b[64]; DWORD n = 64; memcpy(b, rc4_pt64, 64);
    CHECK(U(CryptEncrypt)(h, 0, FALSE, 0, b, &n, 64));
    CHECK_BYTES(b, rc4_ct40_salted, 64);
    U(CryptDestroyKey)(h);
    ck_release(p);
}
TEST(kat_rc4_short_key_import) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY h = 0; SET_ERR(0);
    BOOL r = ck_import_plain(p, CALG_RC4, "Key", 3, CRYPT_NO_SALT, &h);
    t_note("RC4 3-byte plaintext key import: %s err=0x%lx", r ? "ok" : "rejected", GetLastError());
    if (h) U(CryptDestroyKey)(h);
    ck_release(p);
}
TEST(kat_rc4_final_true_has_no_padding) {
    NEED_CRYPT(); NEED_PROV(p);
    kat_t a = KAT(CALG_RC4, rc4_key128, 0, NULL, 0, rc4_pt64, rc4_ct128, TRUE);
    kat_run(p, &a, "rc4 final");
    HCRYPTKEY h = ck_key(p, CALG_RC4, rc4_key128, 16); if (!h) { CHECK(0); return; }
    BYTE b[64]; DWORD n = 13; memcpy(b, rc4_pt64, 13);
    CHECK(U(CryptEncrypt)(h, 0, TRUE, 0, b, &n, sizeof b)); EXPECT_EQ(n, 13);
    CHECK_BYTES(b, rc4_ct128, 13);
    U(CryptDestroyKey)(h); ck_release(p);
}
TEST(kat_rc4_streaming_chunks_equal_oneshot) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY h = ck_key(p, CALG_RC4, rc4_key128, 16); if (!h) { CHECK(0); return; }
    BYTE b[64]; memcpy(b, rc4_pt64, 64);
    static const DWORD chunks[] = { 1, 7, 0, 20, 3, 33 };
    DWORD off = 0;
    for (unsigned i = 0; i < SIZEOFA(chunks); i++) {
        DWORD n = chunks[i];
        CHECK(U(CryptEncrypt)(h, 0, i == SIZEOFA(chunks) - 1, 0, b + off, &n, 64 - off));
        EXPECT_EQ(n, chunks[i]); off += chunks[i];
    }
    EXPECT_EQ(off, 64);
    CHECK_BYTES(b, rc4_ct128, 64);
    U(CryptDestroyKey)(h); ck_release(p);
}
TEST(kat_rc4_final_resets_stream) {
    NEED_CRYPT(); NEED_PROV(p);
    /* Final=TRUE restarts the RC4 key stream: two Final=TRUE calls give the same ciphertext. */
    HCRYPTKEY h = ck_key(p, CALG_RC4, rc4_key128, 16); if (!h) { CHECK(0); return; }
    BYTE a[16], b[16]; DWORD n = 16;
    memcpy(a, rc4_pt64, 16); CHECK(U(CryptEncrypt)(h, 0, TRUE, 0, a, &n, 16));
    n = 16; memcpy(b, rc4_pt64, 16); CHECK(U(CryptEncrypt)(h, 0, TRUE, 0, b, &n, 16));
    CHECK_BYTES(a, b, 16); CHECK_BYTES(a, rc4_ct128, 16);
    U(CryptDestroyKey)(h); ck_release(p);
}
TEST(kat_rc4_nonfinal_continues_stream) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY h = ck_key(p, CALG_RC4, rc4_key128, 16); if (!h) { CHECK(0); return; }
    BYTE a[16], b[16]; DWORD n = 16;
    memcpy(a, rc4_pt64, 16); CHECK(U(CryptEncrypt)(h, 0, FALSE, 0, a, &n, 16));
    n = 16; memcpy(b, rc4_pt64 + 16, 16); CHECK(U(CryptEncrypt)(h, 0, FALSE, 0, b, &n, 16));
    CHECK_BYTES(a, rc4_ct128, 16);
    CHECK_BYTES(b, rc4_ct128 + 16, 16);
    U(CryptDestroyKey)(h); ck_release(p);
}
TEST(kat_rc4_decrypt_symmetry) {
    NEED_CRYPT(); NEED_PROV(p); NOSALT_NEEDS_WINDOWS();
    HCRYPTKEY h = ck_key(p, CALG_RC4, rc4_key40, 5); if (!h) { CHECK(0); return; }
    BYTE b[64]; DWORD n = 64; memcpy(b, rc4_ct40, 64);
    CHECK(U(CryptDecrypt)(h, 0, TRUE, 0, b, &n)); EXPECT_EQ(n, 64); CHECK_BYTES(b, rc4_pt64, 64);
    U(CryptDestroyKey)(h); ck_release(p);
}
TEST(kat_algid_cross_providers_aes_provider_and_enhanced) {
    NEED_CRYPT();
    /* same DES/RC4 vectors on the Enhanced provider (no AES there) */
    HCRYPTPROV p = ck_enh(); if (!p) { t_skip("enhanced provider unavailable"); return; }
    kat_t a = KAT(CALG_DES, des_key, CRYPT_MODE_ECB, NULL, 0, des_pt8, des_ecb8, FALSE);
    kat_t b = KAT(CALG_RC4, rc4_key128, 0, NULL, 0, rc4_pt64, rc4_ct128, FALSE);
    kat_t c = KAT(CALG_3DES, tdes_key, CRYPT_MODE_CBC, des_iv, 0, des_pt24, tdes_cbc24, FALSE);
    kat_run(p, &a, "enh des"); kat_run(p, &b, "enh rc4"); kat_run(p, &c, "enh 3des");
    ck_release(p);
}
TEST(kat_aes_not_available_on_enhanced_provider) {
    NEED_CRYPT();
    HCRYPTPROV p = ck_enh(); if (!p) { t_skip("enhanced provider unavailable"); return; }
    HCRYPTKEY k = 1;
    SET_ERR(0);
    BOOL r = U(CryptGenKey)(p, CALG_AES_128, 0, &k);
    if (r) { t_note("AES_128 GenKey succeeded on PROV_RSA_FULL enhanced provider"); U(CryptDestroyKey)(k); }
    else { CHECK(GetLastError() == (DWORD)NTE_BAD_ALGID_); }
    ck_release(p);
}

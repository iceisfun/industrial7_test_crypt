#include "ck.h"
/* CryptDeriveKey from hash values. Derivation (documented): key = leading bytes of the hash value; when more
 * key bytes are needed than the hash is long, two 64-byte blocks (0x36 / 0x5c, XORed with the hash) are
 * hashed and concatenated. The expected key bytes were computed at authoring time. */

static const BYTE *dk_vec(int hashi, DWORD n) {
    static const BYTE *tab[3][4] = {
        { dk_md5_8, dk_md5_16, dk_md5_24, dk_md5_32 },
        { dk_sha1_8, dk_sha1_16, dk_sha1_24, dk_sha1_32 },
        { dk_sha256_8, dk_sha256_16, dk_sha256_24, dk_sha256_32 } };
    return tab[hashi][n == 8 ? 0 : n == 16 ? 1 : n == 24 ? 2 : 3];
}
/* Windows (decomp CPDeriveKey): for 3DES and AES keys, unless the hash is SHA-2 family, the key is ALWAYS taken from
 * the ipad/opad extension X1||X2 (even when the hash is long enough); DES, 3DES-112, RC2 and RC4 use the digest prefix. */
static const BYTE *dkx_vec(int hashi, DWORD n) {
    static const BYTE *tab[2][3] = { { dkx_md5_16, dkx_md5_24, dkx_md5_32 }, { dkx_sha1_16, dkx_sha1_24, dkx_sha1_32 } };
    return tab[hashi][n == 16 ? 0 : n == 24 ? 1 : 2];
}
static const BYTE *expect_key(int hashi, ALG_ID a, DWORD n) {
    int ext = hashi < 2 && (a == CALG_3DES || a == CALG_AES_128 || a == CALG_AES_192 || a == CALG_AES_256);
    return ext ? dkx_vec(hashi, n) : dk_vec(hashi, n);
}
static const ALG_ID hashalgs[3] = { CALG_MD5, CALG_SHA1, CALG_SHA_256 };
static const char *hashnames[3] = { "MD5", "SHA1", "SHA256" };

static HCRYPTHASH pw_hash(HCRYPTPROV p, ALG_ID ha) {
    HCRYPTHASH h = 0;
    if (!U(CryptCreateHash)(p, ha, 0, 0, &h)) return 0;
    if (!U(CryptHashData)(h, (const BYTE *)"password", 8, 0)) { U(CryptDestroyHash)(h); return 0; }
    return h;
}
/* encrypt one 16/8 byte block in ECB with both keys and compare */
static void same_cipher(HCRYPTKEY a, HCRYPTKEY b, DWORD blk, const char *what) {
    BYTE x[16], y[16]; DWORD n = blk, m = blk;
    memcpy(x, sp_pt, 16); memcpy(y, sp_pt, 16);
    ck_set_mode(a, CRYPT_MODE_ECB); ck_set_mode(b, CRYPT_MODE_ECB);
    BOOL r1 = U(CryptEncrypt)(a, 0, FALSE, 0, x, &n, 16), r2 = U(CryptEncrypt)(b, 0, FALSE, 0, y, &m, 16);
    CHECKF(r1 && r2, "%s encrypt 0x%lx", what, GetLastError());
    if (r1 && r2) { t_check(!memcmp(x, y, blk), __FILE__, __LINE__, what, "derived key differs from expected bytes"); }
}
#define NEED_HASH() do { REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptHashData)); REQUIRE(U(CryptDestroyHash)); REQUIRE(U(CryptDeriveKey)); } while (0)

static const struct { ALG_ID a; const char *n; DWORD len, blk; } dalgs[] = {
    { CALG_DES, "DES", 8, 8 }, { CALG_3DES, "3DES", 24, 8 }, { CALG_3DES_112, "3DES112", 16, 8 },
    { CALG_AES_128, "AES128", 16, 16 }, { CALG_AES_192, "AES192", 24, 16 }, { CALG_AES_256, "AES256", 32, 16 },
    { CALG_RC4, "RC4", 16, 0 } };

TEST(derive_matches_documented_algorithm) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    for (int hi = 0; hi < 3; hi++) for (unsigned ai = 0; ai < SIZEOFA(dalgs); ai++) {
        if (dalgs[ai].a == CALG_RC4) continue;
        HCRYPTHASH h = pw_hash(p, hashalgs[hi]); if (!h) { CHECK(0); continue; }
        HCRYPTKEY k = 0; char what[64];
        snprintf(what, sizeof what, "%s via %s", dalgs[ai].n, hashnames[hi]);
        if (!U(CryptDeriveKey)(p, dalgs[ai].a, h, 0, &k)) { CHECKF(0, "%s err 0x%lx", what, GetLastError()); U(CryptDestroyHash)(h); continue; }
        HCRYPTKEY ref = ck_key(p, dalgs[ai].a, expect_key(hi, dalgs[ai].a, dalgs[ai].len), dalgs[ai].len);
        if (ref) { same_cipher(k, ref, dalgs[ai].blk, what); U(CryptDestroyKey)(ref); } else CHECK(0);
        U(CryptDestroyKey)(k); U(CryptDestroyHash)(h);
    }
    ck_release(p);
}
TEST(derive_rc4_default_is_128bit_prefix) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    for (int hi = 0; hi < 3; hi++) {
        HCRYPTHASH h = pw_hash(p, hashalgs[hi]); HCRYPTKEY k = 0, ref;
        if (!h || !U(CryptDeriveKey)(p, CALG_RC4, h, 0, &k)) { CHECKF(0, "%s 0x%lx", hashnames[hi], GetLastError()); continue; }
        BOOL ok; EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), 128);
        ref = ck_key(p, CALG_RC4, dk_vec(hi, 16), 16);
        BYTE x[32], y[32]; DWORD n = 32, m = 32; memset(x, 0, 32); memset(y, 0, 32);
        CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, x, &n, 32)); CHECK(U(CryptEncrypt)(ref, 0, FALSE, 0, y, &m, 32));
        CHECK_BYTES(x, y, 32);
        U(CryptDestroyKey)(k); U(CryptDestroyKey)(ref); U(CryptDestroyHash)(h);
    }
    ck_release(p);
}
TEST(derive_reported_key_lengths) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    for (unsigned ai = 0; ai < SIZEOFA(dalgs); ai++) {
        HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; BOOL ok;
        if (!h || !U(CryptDeriveKey)(p, dalgs[ai].a, h, 0, &k)) { CHECK(0); continue; }
        DWORD kl = ck_param_dw(k, KP_KEYLEN, &ok); CHECK(ok);
        EXPECT_EQ(kl, dalgs[ai].a == CALG_DES ? 64 : dalgs[ai].a == CALG_3DES ? 192 : dalgs[ai].len * 8);
        EXPECT_EQ(ck_param_dw(k, KP_ALGID, &ok), dalgs[ai].a);
        U(CryptDestroyKey)(k); U(CryptDestroyHash)(h);
    }
    ck_release(p);
}
TEST(derive_rc2_rc4_explicit_lengths) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    static const DWORD bits[] = { 40, 56, 64, 96, 128 };
    static const ALG_ID algs[] = { CALG_RC2, CALG_RC4 };
    for (int a = 0; a < 2; a++) for (unsigned i = 0; i < SIZEOFA(bits); i++) {
        HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; BOOL ok;
        if (!h) { CHECK(0); continue; }
        if (!U(CryptDeriveKey)(p, algs[a], h, (bits[i] << 16) | CRYPT_NO_SALT, &k)) { CHECKF(0, "alg %x bits %lu 0x%lx", algs[a], bits[i], GetLastError()); U(CryptDestroyHash)(h); continue; }
        EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), bits[i]);
        if (algs[a] == CALG_RC4) {   /* leading bits[i]/8 digest bytes */
            HCRYPTKEY ref = ck_key(p, CALG_RC4, dk_sha1_16, bits[i] / 8);
            BYTE x[16] = { 0 }, y[16] = { 0 }; DWORD n = 16, m = 16;
            if (ref && (bits[i] != 40 || !t_is_wine())) {
                CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, x, &n, 16)); CHECK(U(CryptEncrypt)(ref, 0, FALSE, 0, y, &m, 16));
                CHECK_BYTES(x, y, 16);
            }
            if (ref) U(CryptDestroyKey)(ref);
        }
        U(CryptDestroyKey)(k); U(CryptDestroyHash)(h);
    }
    ck_release(p);
}
TEST(derive_invalid_algid) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    static const ALG_ID bad[] = { 0, CALG_MD5, CALG_SHA1, CALG_HMAC, 0x6FFF, 0xFFFF };
    for (unsigned i = 0; i < SIZEOFA(bad); i++) {
        HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; SET_ERR(0);
        if (!h) { CHECK(0); continue; }
        EXPECT_FAIL(!U(CryptDeriveKey)(p, bad[i], h, 0, &k), NTE_BAD_ALGID_);
        U(CryptDestroyHash)(h);
    }
    ck_release(p);
}
TEST(derive_invalid_flags) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    /* Win10 probe: every undefined flag gives NTE_BAD_FLAGS except 0x8, which advapi32 rejects with 87 */
    static const DWORD fl[] = { 2, 8, 0x20, 0x40, 0x80, 0x100, 0x200, 0x800, 0x1000, 0x2000, 0x4000, 0x8000 };
    for (unsigned i = 0; i < SIZEOFA(fl); i++) {
        HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; SET_ERR(0);
        if (!h) { CHECK(0); continue; }
        BOOL r = U(CryptDeriveKey)(p, CALG_AES_128, h, fl[i], &k);
        t_label("flag 0x%lx", fl[i]);
        CHECKF(!r, "flag 0x%lx accepted", fl[i]);
        if (r) U(CryptDestroyKey)(k); else EXPECT_ERR(fl[i] == 8 ? ERROR_INVALID_PARAMETER : NTE_BAD_FLAGS_);
        U(CryptDestroyHash)(h);
    }
    ck_release(p);
}
TEST(derive_valid_flags_accepted) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    static const DWORD fl[] = { 0, CRYPT_EXPORTABLE, CRYPT_NO_SALT, CRYPT_EXPORTABLE | CRYPT_NO_SALT };
    for (unsigned i = 0; i < SIZEOFA(fl); i++) {
        HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0;
        if (!h) { CHECK(0); continue; }
        BOOL r = U(CryptDeriveKey)(p, CALG_AES_128, h, fl[i], &k);
        CHECKF(r, "flags 0x%lx err 0x%lx", fl[i], GetLastError());
        if (r) U(CryptDestroyKey)(k);
        U(CryptDestroyHash)(h);
    }
    ck_release(p);
}
TEST(derive_exportable_flag_controls_export) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    for (int ex = 0; ex < 2; ex++) {
        HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; if (!h) { CHECK(0); continue; }
        CHECK(U(CryptDeriveKey)(p, CALG_AES_128, h, ex ? CRYPT_EXPORTABLE : 0, &k));
        BYTE blob[64]; DWORD n = sizeof blob; SET_ERR(0);
        BOOL r = U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, blob, &n);
        if (ex) { CHECK(r); EXPECT_EQ(n, 12 + 16); if (r) CHECK_BYTES(blob + 12, dkx_sha1_16, 16); }
        else { CHECK(!r); EXPECT_ERR(NTE_BAD_KEY_STATE_); }
        U(CryptDestroyKey)(k); U(CryptDestroyHash)(h);
    }
    ck_release(p);
}
TEST(derive_key_length_flag_for_fixed_algs) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    /* wrong explicit length for AES-128 is rejected as BAD_FLAGS, right one accepted */
    HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; if (!h) { CHECK(0); return; }
    SET_ERR(0); EXPECT_FAIL(!U(CryptDeriveKey)(p, CALG_AES_128, h, 256u << 16, &k), NTE_BAD_FLAGS_);
    CHECK(U(CryptDeriveKey)(p, CALG_AES_128, h, 128u << 16, &k)); if (k) U(CryptDestroyKey)(k);
    SET_ERR(0); EXPECT_FAIL(!U(CryptDeriveKey)(p, CALG_AES_128, h, 127u << 16, &k), NTE_BAD_FLAGS_);
    U(CryptDestroyHash)(h); ck_release(p);
}
TEST(derive_does_not_depend_on_hash_reuse) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    /* two derives from the same hash handle give the same key */
    HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY a = 0, b = 0; if (!h) { CHECK(0); return; }
    CHECK(U(CryptDeriveKey)(p, CALG_AES_128, h, 0, &a));
    CHECK(U(CryptDeriveKey)(p, CALG_AES_128, h, 0, &b));
    if (a && b) same_cipher(a, b, 16, "second derive from same hash");
    if (a) U(CryptDestroyKey)(a);
    if (b) U(CryptDestroyKey)(b);
    U(CryptDestroyHash)(h); ck_release(p);
}
TEST(derive_hash_finalized_afterwards) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; if (!h) { CHECK(0); return; }
    CHECK(U(CryptDeriveKey)(p, CALG_AES_128, h, 0, &k));
    SET_ERR(0);
    BOOL r = U(CryptHashData)(h, (const BYTE *)"x", 1, 0);
    t_note("CryptHashData after CryptDeriveKey: %s err=0x%lx", r ? "ok" : "fail", GetLastError());
    BYTE hv[20]; DWORD n = 20;
    if (U(CryptGetHashParam)) { CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, hv, &n, 0)); if (!r) CHECK_BYTES(hv, sha1_pw, 20); }
    if (k) U(CryptDestroyKey)(k);
    U(CryptDestroyHash)(h); ck_release(p);
}
TEST(derive_different_data_different_key) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    HCRYPTHASH h1 = pw_hash(p, CALG_SHA1), h2 = 0; HCRYPTKEY a = 0, b = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h2)); CHECK(U(CryptHashData)(h2, (const BYTE *)"Password", 8, 0));
    CHECK(U(CryptDeriveKey)(p, CALG_AES_128, h1, CRYPT_EXPORTABLE, &a)); CHECK(U(CryptDeriveKey)(p, CALG_AES_128, h2, CRYPT_EXPORTABLE, &b));
    BYTE x[32], y[32]; DWORD n = 32, m = 32;
    CHECK(U(CryptExportKey)(a, 0, PLAINTEXTKEYBLOB, 0, x, &n)); CHECK(U(CryptExportKey)(b, 0, PLAINTEXTKEYBLOB, 0, y, &m));
    CHECK(memcmp(x + 12, y + 12, 16) != 0);
    U(CryptDestroyKey)(a); U(CryptDestroyKey)(b); U(CryptDestroyHash)(h1); U(CryptDestroyHash)(h2); ck_release(p);
}
TEST(derive_create_salt_and_nosalt_des_family) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    /* CRYPT_CREATE_SALT is rejected for DES-family derived keys, as it is for CryptGenKey */
    HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; if (!h) { CHECK(0); return; }
    SET_ERR(0); BOOL r = U(CryptDeriveKey)(p, CALG_DES, h, CRYPT_CREATE_SALT, &k);
    t_note("DeriveKey(DES, CREATE_SALT): %s err=0x%lx", r ? "ok" : "fail", GetLastError());
    if (r) U(CryptDestroyKey)(k);
    k = 0; r = U(CryptDeriveKey)(p, CALG_RC4, h, CRYPT_CREATE_SALT, &k);
    t_note("DeriveKey(RC4, CREATE_SALT): %s err=0x%lx", r ? "ok" : "fail", GetLastError());
    if (r) U(CryptDestroyKey)(k);
    U(CryptDestroyHash)(h); ck_release(p);
}
TEST(derive_base_provider_default_rc4_is_40bit) {
    NEED_CRYPT(); NEED_HASH();
    HCRYPTPROV p = ck_base(); if (!p) { t_skip("base provider unavailable"); return; }
    HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; BOOL ok; if (!h) { CHECK(0); return; }
    CHECK(U(CryptDeriveKey)(p, CALG_RC4, h, 0, &k));
    if (k) { EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), 40); U(CryptDestroyKey)(k); }
    k = 0; SET_ERR(0);
    BOOL r = U(CryptDeriveKey)(p, CALG_RC4, h, 128u << 16, &k);
    CHECK(!r); if (!r) EXPECT_ERR(NTE_BAD_FLAGS_); if (r) U(CryptDestroyKey)(k);
    U(CryptDestroyHash)(h); ck_release(p);
}
TEST(derive_40bit_default_salt_behaviour) {
    NEED_CRYPT(); NEED_PROV(p); NEED_HASH();
    /* 40-bit RC4 derived without CRYPT_NO_SALT: observe whether an 11 byte zero salt is appended */
    HCRYPTHASH h = pw_hash(p, CALG_SHA1); HCRYPTKEY k = 0; if (!h) { CHECK(0); return; }
    CHECK(U(CryptDeriveKey)(p, CALG_RC4, h, 40u << 16, &k)); if (!k) return;
    BYTE x[16] = { 0 }, y[16] = { 0 }, z[16] = { 0 }; DWORD n = 16;
    CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, x, &n, 16));
    BYTE salted[16]; memcpy(salted, dk_sha1_16, 5); memset(salted + 5, 0, 11);
    HCRYPTKEY a = ck_key(p, CALG_RC4, dk_sha1_16, 5), b = ck_key(p, CALG_RC4, salted, 16);
    n = 16; CHECK(U(CryptEncrypt)(a, 0, FALSE, 0, y, &n, 16)); n = 16; CHECK(U(CryptEncrypt)(b, 0, FALSE, 0, z, &n, 16));
    t_note("40-bit derived RC4 stream equals: unsalted=%d  zero-salted(16B)=%d", !memcmp(x, y, 16), !memcmp(x, z, 16));
    CHECK(!memcmp(x, y, 16) || !memcmp(x, z, 16));
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(a); U(CryptDestroyKey)(b); U(CryptDestroyHash)(h); ck_release(p);
}

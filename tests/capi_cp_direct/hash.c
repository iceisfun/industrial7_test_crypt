#include "cp.h"
/* Hash entry points of the CSPs: CPCreateHash, CPHashData, CPGetHashParam, CPSetHashParam,
 * CPDuplicateHash, CPDestroyHash, CPHashSessionKey.  Known answers: RFC 1319/1320/1321, FIPS 180,
 * RFC 2202 and RFC 4231 (HMAC). */

static int hx(const char *s, BYTE *out) {
    int n = 0;
    while (s[0] && s[1]) {
        unsigned v; char t[3] = { s[0], s[1], 0 };
        sscanf(t, "%x", &v); out[n++] = (BYTE)v; s += 2;
    }
    return n;
}
static void hash_vs(const cpf *f, ULONG_PTR p, ALG_ID alg, const void *data, DWORD len, const char *hex, const char *what) {
    BYTE want[64], got[64];
    int wl = hx(hex, want);
    DWORD gl = cp_hash(f, p, alg, data, len, got, sizeof got);
    CHECKF(gl == (DWORD)wl, "%s: length %lu want %d (err=0x%lx)", what, gl, wl, GetLastError());
    if (gl == (DWORD)wl) t_check(!memcmp(got, want, wl), __FILE__, __LINE__, what, "digest mismatch");
}

/* ---- known answers --------------------------------------------------------------------- */
TEST(cpd_hash_kat_md5) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    hash_vs(&R, p, CALG_MD5, "", 0, "d41d8cd98f00b204e9800998ecf8427e", "md5 empty");
    hash_vs(&R, p, CALG_MD5, "a", 1, "0cc175b9c0f1b6a831c399e269772661", "md5 a");
    hash_vs(&R, p, CALG_MD5, "abc", 3, "900150983cd24fb0d6963f7d28e17f72", "md5 abc");
    hash_vs(&R, p, CALG_MD5, "message digest", 14, "f96b697d7cb7938d525a2f31aaf161d0", "md5 message digest");
    hash_vs(&R, p, CALG_MD5, "abcdefghijklmnopqrstuvwxyz", 26, "c3fcd3d76192e4007dfb496cca67e13b", "md5 alphabet");
    cp_rel(&R, p);
}
TEST(cpd_hash_kat_sha1) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    hash_vs(&R, p, CALG_SHA1, "", 0, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1 empty");
    hash_vs(&R, p, CALG_SHA1, "abc", 3, "a9993e364706816aba3e25717850c26c9cd0d89d", "sha1 abc");
    hash_vs(&R, p, CALG_SHA1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1", "sha1 448 bit");
    cp_rel(&R, p);
}
TEST(cpd_hash_kat_md2_md4) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    hash_vs(&R, p, CALG_MD2, "", 0, "8350e5a3e24c153df2275c9f80692773", "md2 empty");
    hash_vs(&R, p, CALG_MD2, "abc", 3, "da853b0d3f88d99b30283a69e6ded6bb", "md2 abc");
    hash_vs(&R, p, CALG_MD4, "", 0, "31d6cfe0d16ae931b73c59d7e0c089c0", "md4 empty");
    hash_vs(&R, p, CALG_MD4, "abc", 3, "a448017aaf21d8525fc10ae87aa6729d", "md4 abc");
    cp_rel(&R, p);
}
TEST(cpd_hash_kat_sha2_on_aes_provider) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    hash_vs(&R, p, CALG_SHA_256, "abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 abc");
    hash_vs(&R, p, CALG_SHA_256, "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256 empty");
    hash_vs(&R, p, CALG_SHA_384, "abc", 3,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "sha384 abc");
    hash_vs(&R, p, CALG_SHA_512, "abc", 3,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "sha512 abc");
    cp_rel(&R, p);
}
TEST(cpd_hash_kat_chunked_equals_oneshot) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE buf[1000]; for (int i = 0; i < 1000; i++) buf[i] = (BYTE)(i * 7 + 3);
    BYTE want[20], got[20];
    DWORD wl = cp_hash(&R, p, CALG_SHA1, buf, sizeof buf, want, sizeof want);
    EXPECT_EQ(wl, 20);
    static const DWORD chunk[] = { 1, 3, 63, 64, 65, 127, 999 };
    for (size_t c = 0; c < NELEM(chunk); c++) {
        ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); if (!h) { CHECK(h); continue; }
        DWORD off = 0;
        while (off < sizeof buf) {
            DWORD n = sizeof buf - off < chunk[c] ? sizeof buf - off : chunk[c];
            OKAY(R.HashData(p, h, buf + off, n, 0));
            off += n;
        }
        DWORD gl = sizeof got;
        OKAY(R.GetHashParam(p, h, HP_HASHVAL, got, &gl, 0));
        EXPECT_EQ(gl, 20);
        SAMEBYTES(got, want, 20);
        R.DestroyHash(p, h);
    }
    cp_rel(&R, p);
}
TEST(cpd_hash_kat_million_a) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE blk[1000]; memset(blk, 'a', sizeof blk);
    for (int i = 0; i < 1000; i++) OKAY(R.HashData(p, h, blk, sizeof blk, 0));
    BYTE d[20], want[20]; DWORD n = sizeof d;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    hx("34aa973cd4c4daa4f61eeb2bdbad27316534016f", want);
    SAMEBYTES(d, want, 20);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}

/* ---- HMAC ------------------------------------------------------------------------------ */
static void hmac_case(const cpf *f, ULONG_PTR p, ALG_ID halg, const void *key, DWORD klen, const char *data, const char *hex, const char *what) {
    BYTE want[64], got[64]; int wl = hx(hex, want);
    ULONG_PTR k = cp_hkey(f, p, key, klen);
    if (!k) { CHECKF(0, "%s: key import failed 0x%lx", what, GetLastError()); return; }
    ULONG_PTR h = 0;
    if (!f->CreateHash(p, CALG_HMAC, k, 0, &h)) { CHECKF(0, "%s: CreateHash 0x%lx", what, GetLastError()); f->DestroyKey(p, k); return; }
    HMAC_INFO hi; memset(&hi, 0, sizeof hi); hi.HashAlgid = halg;
    OKAY(f->SetHashParam(p, h, HP_HMAC_INFO, (BYTE *)&hi, 0));
    OKAY(f->HashData(p, h, (const BYTE *)data, (DWORD)strlen(data), 0));
    DWORD gl = sizeof got;
    OKAY(f->GetHashParam(p, h, HP_HASHVAL, got, &gl, 0));
    CHECKF(gl == (DWORD)wl, "%s: len %lu want %d", what, gl, wl);
    if (gl == (DWORD)wl) t_check(!memcmp(got, want, wl), __FILE__, __LINE__, what, "hmac mismatch");
    f->DestroyHash(p, h); f->DestroyKey(p, k);
}
TEST(cpd_hmac_rfc2202_md5) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE k1[16]; memset(k1, 0x0b, 16);
    hmac_case(&R, p, CALG_MD5, k1, 16, "Hi There", "9294727a3638bb1c13f48ef8158bfc9d", "hmac-md5 tc1");
    hmac_case(&R, p, CALG_MD5, "Jefe", 4, "what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738", "hmac-md5 tc2");
    cp_rel(&R, p);
}
TEST(cpd_hmac_rfc2202_sha1) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE k1[20]; memset(k1, 0x0b, 20);
    hmac_case(&R, p, CALG_SHA1, k1, 20, "Hi There", "b617318655057264e28bc0b6fb378c8ef146be00", "hmac-sha1 tc1");
    hmac_case(&R, p, CALG_SHA1, "Jefe", 4, "what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", "hmac-sha1 tc2");
    cp_rel(&R, p);
}
TEST(cpd_hmac_rfc4231_sha2_on_aes_provider) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE k1[20]; memset(k1, 0x0b, 20);
    hmac_case(&R, p, CALG_SHA_256, k1, 20, "Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "hmac-sha256 tc1");
    hmac_case(&R, p, CALG_SHA_256, "Jefe", 4, "what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "hmac-sha256 tc2");
    hmac_case(&R, p, CALG_SHA_384, k1, 20, "Hi There",
              "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6", "hmac-sha384 tc1");
    hmac_case(&R, p, CALG_SHA_512, k1, 20, "Hi There",
              "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", "hmac-sha512 tc1");
    cp_rel(&R, p);
}
TEST(cpd_hmac_hashsize_follows_inner_algorithm) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16]; memset(key, 0x42, 16);
    ULONG_PTR k = cp_hkey(&R, p, key, 16); REQUIRE(k);
    ALG_ID algs[] = { CALG_MD5, CALG_SHA1 };
    DWORD sizes[] = { 16, 20 };
    for (int i = 0; i < 2; i++) {
        ULONG_PTR h = 0; OKAY(R.CreateHash(p, CALG_HMAC, k, 0, &h)); if (!h) continue;
        HMAC_INFO hi; memset(&hi, 0, sizeof hi); hi.HashAlgid = algs[i];
        OKAY(R.SetHashParam(p, h, HP_HMAC_INFO, (BYTE *)&hi, 0));
        BOOL ok; DWORD sz = cp_hp_dw(&R, p, h, HP_HASHSIZE, &ok);
        CHECK(ok); EXPECT_EQ(sz, sizes[i]);
        R.DestroyHash(p, h);
    }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_hmac_info_wrong_inner_algorithm) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16]; memset(key, 1, 16);
    ULONG_PTR k = cp_hkey(&R, p, key, 16); REQUIRE(k);
    ULONG_PTR h = 0; OKAY(R.CreateHash(p, CALG_HMAC, k, 0, &h)); REQUIRE(h);
    HMAC_INFO hi; memset(&hi, 0, sizeof hi);
    ALG_ID bad[] = { CALG_MAC, CALG_RC4, CALG_HMAC, 0, 0x1234, CALG_SSL3_SHAMD5 };
    for (size_t i = 0; i < NELEM(bad); i++) {
        hi.HashAlgid = bad[i];
        FAILS(R.SetHashParam(p, h, HP_HMAC_INFO, (BYTE *)&hi, 0), CPE_BAD_ALGID);
    }
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_hmac_info_on_plain_hash_bad_type) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    HMAC_INFO hi; memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1;
    FAILS(R.SetHashParam(p, h, HP_HMAC_INFO, (BYTE *)&hi, 0), CPE_BAD_TYPE);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_hmac_custom_pads_equal_defaults) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[20]; memset(key, 0x0b, 20);
    ULONG_PTR k = cp_hkey(&R, p, key, 20); REQUIRE(k);
    BYTE inner[64], outer[64]; memset(inner, 0x36, 64); memset(outer, 0x5c, 64);
    ULONG_PTR h = 0; OKAY(R.CreateHash(p, CALG_HMAC, k, 0, &h)); REQUIRE(h);
    HMAC_INFO hi; memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1;
    hi.pbInnerString = inner; hi.cbInnerString = 64; hi.pbOuterString = outer; hi.cbOuterString = 64;
    OKAY(R.SetHashParam(p, h, HP_HMAC_INFO, (BYTE *)&hi, 0));
    OKAY(R.HashData(p, h, (const BYTE *)"Hi There", 8, 0));
    BYTE got[20], want[20]; DWORD n = sizeof got;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, got, &n, 0));
    hx("b617318655057264e28bc0b6fb378c8ef146be00", want);
    SAMEBYTES(got, want, 20);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_hmac_requires_key) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = 0;
    FAILS(R.CreateHash(p, CALG_HMAC, 0, 0, &h), CPE_BAD_KEY);
    FAILS(R.CreateHash(p, CALG_MAC, 0, 0, &h), CPE_BAD_KEY);
    cp_rel(&R, p);
}
TEST(cpd_hmac_key_must_be_a_key_handle) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h0 = cp_mkhash(&R, p, CALG_MD5), h = 0;
    FAILS(R.CreateHash(p, CALG_HMAC, h0, 0, &h), CPE_BAD_KEY);
    R.DestroyHash(p, h0);
    cp_rel(&R, p);
}
TEST(cpd_mac_des_cbc_hashsize_is_block_size) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[8] = { 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };
    ULONG_PTR k = cp_key(&R, p, CALG_DES, key, 8); REQUIRE(k);
    ULONG_PTR h = 0; OKAY(R.CreateHash(p, CALG_MAC, k, 0, &h)); REQUIRE(h);
    BOOL ok; DWORD sz = cp_hp_dw(&R, p, h, HP_HASHSIZE, &ok);
    CHECK(ok); EXPECT_EQ(sz, 8);
    OKAY(R.HashData(p, h, (const BYTE *)"01234567", 8, 0));
    BYTE mac[8]; DWORD n = sizeof mac;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, mac, &n, 0));
    EXPECT_EQ(n, 8);
    /* One-block DES-CBC-MAC with a zero IV equals the single-block DES-ECB encryption. */
    ULONG_PTR k2 = cp_key(&R, p, CALG_DES, key, 8);
    BYTE blk[16]; memcpy(blk, "01234567", 8);
    DWORD bl = 8;
    OKAY(R.SetKeyParam(p, k2, KP_MODE, (BYTE *)&(DWORD){ CRYPT_MODE_ECB }, 0));
    OKAY(R.Encrypt(p, k2, 0, FALSE, 0, blk, &bl, sizeof blk));
    t_note("DES CBC-MAC of one block %s the single-block ECB encryption", memcmp(mac, blk, 8) ? "differs from" : "equals");
    R.DestroyKey(p, k2);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}

/* ---- CPCreateHash validation ------------------------------------------------------------ */
TEST(cpd_createhash_flags_checked_before_handles) {
    NEED_RSA();
    ULONG_PTR h = 0x1234;
    /* dwFlags is the very first check; the provider handle is not even touched. */
    FAILS(R.CreateHash(0, CALG_MD5, 0, 1, &h), CPE_BAD_FLAGS);
    FAILS(R.CreateHash(0, CALG_MD5, 0, 0x80000000, &h), CPE_BAD_FLAGS);
    FAILS(R.CreateHash(0, 0xffff, 0, 0x100, &h), CPE_BAD_FLAGS);
}
TEST(cpd_createhash_each_flag_bit_bad) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    for (int b = 0; b < 32; b++) {
        ULONG_PTR h = 0;
        FAILS(R.CreateHash(p, CALG_MD5, 0, 1u << b, &h), CPE_BAD_FLAGS);
    }
    cp_rel(&R, p);
}
TEST(cpd_createhash_wrong_handle_kind_provider) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k));
    ULONG_PTR h0 = cp_mkhash(&R, p, CALG_MD5), h = 0;
    if (k) FAILS(R.CreateHash(k, CALG_MD5, 0, 0, &h), CPE_BAD_UID);
    if (h0) FAILS(R.CreateHash(h0, CALG_MD5, 0, 0, &h), CPE_BAD_UID);
    if (k) R.DestroyKey(p, k);
    if (h0) R.DestroyHash(p, h0);
    cp_rel(&R, p);
}
TEST(cpd_createhash_unsupported_algorithms) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    /* cipher and key-exchange ids are recognised ALG_IDs but not hashes: ERROR_NOT_SUPPORTED */
    ALG_ID ns[] = { CALG_RC4, CALG_RC2, CALG_DES, CALG_RSA_SIGN, CALG_RSA_KEYX, CALG_AES_128 };
    for (size_t i = 0; i < NELEM(ns); i++) {
        ULONG_PTR h = 0x99;
        FAILS(R.CreateHash(p, ns[i], 0, 0, &h), ERROR_NOT_SUPPORTED);
    }
    ALG_ID bad[] = { 0, 1, 0x1234, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512, 0x8006, 0x8007, 0x8010, 0xffffffff };
    for (size_t i = 0; i < NELEM(bad); i++) {
        ULONG_PTR h = 0x99;
        FAILS(R.CreateHash(p, bad[i], 0, 0, &h), CPE_BAD_ALGID);
    }
    cp_rel(&R, p);
}
TEST(cpd_createhash_sha2_needs_aes_provider_type) {
    NEED_RSA();
    ULONG_PTR e = rsa_enh(&R), a = rsa_aes(&R); REQUIRE(e && a);
    ALG_ID alg[] = { CALG_SHA_256, CALG_SHA_384, CALG_SHA_512 };
    for (int i = 0; i < 3; i++) {
        ULONG_PTR h = 0;
        FAILS(R.CreateHash(e, alg[i], 0, 0, &h), CPE_BAD_ALGID);
        OKAY(R.CreateHash(a, alg[i], 0, 0, &h));
        if (h) R.DestroyHash(a, h);
    }
    cp_rel(&R, e); cp_rel(&R, a);
}
TEST(cpd_createhash_plain_hash_rejects_key) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k)); REQUIRE(k);
    ALG_ID algs[] = { CALG_MD5, CALG_SHA1, CALG_MD2, CALG_MD4 };
    for (size_t i = 0; i < NELEM(algs); i++) {
        ULONG_PTR h = 0;
        FAILS(R.CreateHash(p, algs[i], k, 0, &h), CPE_BAD_KEY);
    }
    /* SSL3_SHAMD5 ignores the key argument */
    { ULONG_PTR h = 0; OKAY(R.CreateHash(p, CALG_SSL3_SHAMD5, k, 0, &h)); if (h) R.DestroyHash(p, h); }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_createhash_all_supported_digest_sizes) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    struct { ALG_ID a; DWORD sz; } t[] = { { CALG_MD2, 16 }, { CALG_MD4, 16 }, { CALG_MD5, 16 }, { CALG_SHA1, 20 },
        { CALG_SHA_256, 32 }, { CALG_SHA_384, 48 }, { CALG_SHA_512, 64 }, { CALG_SSL3_SHAMD5, 36 } };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR h = cp_mkhash(&R, p, t[i].a);
        if (!h) { CHECKF(0, "alg 0x%x: create failed 0x%lx", t[i].a, GetLastError()); continue; }
        BOOL ok; DWORD sz = cp_hp_dw(&R, p, h, HP_HASHSIZE, &ok);
        CHECK(ok); CHECKF(sz == t[i].sz, "alg 0x%x size %lu want %lu", t[i].a, sz, t[i].sz);
        EXPECT_EQ(cp_hp_dw(&R, p, h, HP_ALGID, &ok), t[i].a); CHECK(ok);
        R.DestroyHash(p, h);
    }
    cp_rel(&R, p);
}
TEST(cpd_createhash_handles_distinct_and_nonzero) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR a = cp_mkhash(&R, p, CALG_MD5), b = cp_mkhash(&R, p, CALG_MD5);
    CHECK(a && b); CHECK(a != b);
    R.DestroyHash(p, a); R.DestroyHash(p, b);
    cp_rel(&R, p);
}
TEST(cpd_createhash_many_live_hashes) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h[200]; int ok = 0;
    for (int i = 0; i < 200; i++) { h[i] = cp_mkhash(&R, p, i & 1 ? CALG_MD5 : CALG_SHA1); if (h[i]) ok++; }
    EXPECT_EQ(ok, 200);
    for (int i = 0; i < 200; i++) if (h[i]) OKAY(R.DestroyHash(p, h[i]));
    cp_rel(&R, p);
}

/* ---- CPHashData ------------------------------------------------------------------------- */
TEST(cpd_hashdata_flags_checked_first) {
    NEED_RSA();
    /* Flag check precedes every handle check: zero handles do not matter. */
    FAILS(R.HashData(0, 0, (const BYTE *)"a", 1, 2), CPE_BAD_FLAGS);
    FAILS(R.HashData(0, 0, NULL, 0, 0x80), CPE_BAD_FLAGS);
}
TEST(cpd_hashdata_flag_values) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    OKAY(R.HashData(p, h, (const BYTE *)"a", 1, 0));
    OKAY(R.HashData(p, h, (const BYTE *)"a", 1, CRYPT_USERDATA));
    for (int b = 1; b < 32; b++) FAILS(R.HashData(p, h, (const BYTE *)"a", 1, 1u << b), CPE_BAD_FLAGS);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_hashdata_zero_length_is_success) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    OKAY(R.HashData(p, h, NULL, 0, 0));
    OKAY(R.HashData(p, h, (const BYTE *)"x", 0, 0));
    BYTE d[16], want[16]; DWORD n = sizeof d;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    hx("d41d8cd98f00b204e9800998ecf8427e", want);
    SAMEBYTES(d, want, 16);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_hashdata_null_data_with_length_bad_data) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    FAILS(R.HashData(p, h, NULL, 1, 0), CPE_BAD_DATA);
    FAILS(R.HashData(p, h, NULL, 100, 0), CPE_BAD_DATA);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_hashdata_wrong_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k));
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5);
    if (k && h) {
        FAILS(R.HashData(k, h, (const BYTE *)"a", 1, 0), CPE_BAD_UID);
        FAILS(R.HashData(p, k, (const BYTE *)"a", 1, 0), CPE_BAD_HASH);
        FAILS(R.HashData(h, h, (const BYTE *)"a", 1, 0), CPE_BAD_UID);
        FAILS(R.HashData(p, p, (const BYTE *)"a", 1, 0), CPE_BAD_HASH);
    }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_hashdata_zero_length_checks_provider_only) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k)); REQUIRE(k);
    /* The length==0 shortcut sits before the hash-handle lookup, after the provider lookup. */
    OKAY(R.HashData(p, k, NULL, 0, 0));
    FAILS(R.HashData(k, k, NULL, 0, 0), CPE_BAD_UID);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_hashdata_other_provider_context_bad_uid) {
    NEED_RSA(); ULONG_PTR a = rsa_enh(&R), b = rsa_enh(&R); REQUIRE(a && b);
    ULONG_PTR h = cp_mkhash(&R, a, CALG_MD5); REQUIRE(h);
    FAILS(R.HashData(b, h, (const BYTE *)"a", 1, 0), CPE_BAD_UID);
    OKAY(R.HashData(a, h, (const BYTE *)"a", 1, 0));
    R.DestroyHash(a, h);
    cp_rel(&R, a); cp_rel(&R, b);
}
TEST(cpd_hashdata_after_hashval_read_bad_hash_state) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    OKAY(R.HashData(p, h, (const BYTE *)"abc", 3, 0));
    BYTE d[20]; DWORD n = sizeof d;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    FAILS(R.HashData(p, h, (const BYTE *)"d", 1, 0), CPE_BAD_HASH_STATE);
    /* The finished digest remains readable and unchanged. */
    BYTE d2[20]; n = sizeof d2;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d2, &n, 0));
    SAMEBYTES(d, d2, 20);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_hashdata_empty_length_after_finish_still_ok) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE d[20]; DWORD n = sizeof d;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    OKAY(R.HashData(p, h, NULL, 0, 0));
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}

/* ---- CPGetHashParam --------------------------------------------------------------------- */
TEST(cpd_gethashparam_flags_first) {
    NEED_RSA();
    BYTE b[32]; DWORD n = sizeof b;
    FAILS(R.GetHashParam(0, 0, HP_HASHVAL, b, &n, 1), CPE_BAD_FLAGS);
    FAILS(R.GetHashParam(0, 0, HP_HASHVAL, b, &n, 0x8000), CPE_BAD_FLAGS);
}
TEST(cpd_gethashparam_hashval_buffer_protocol) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    OKAY(R.HashData(p, h, cp_abc, 3, 0));
    DWORD need = 0; BYTE d[64];
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, NULL, &need, 0));
    EXPECT_EQ(need, 20);
    /* A size query must not finalise the hash: adding data afterwards still works (below). */
    DWORD n = 19;
    FAILS(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0), ERROR_MORE_DATA);
    EXPECT_EQ(n, 20);
    n = 0;
    FAILS(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0), ERROR_MORE_DATA);
    EXPECT_EQ(n, 20);
    /* After the failed attempts the hash is still open: more data may be added. */
    OKAY(R.HashData(p, h, (const BYTE *)"d", 1, 0));
    n = 20;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    BYTE want[20]; hx("81fe8bfe87576c3ecb22426f8e57847382917acf", want); /* sha1("abcd") */
    SAMEBYTES(d, want, 20);
    n = 64;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    EXPECT_EQ(n, 20);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_gethashparam_null_pcb) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    BYTE d[32];
    FAILS(R.GetHashParam(p, h, HP_HASHVAL, d, NULL, 0), ERROR_INVALID_PARAMETER);
    FAILS(R.GetHashParam(p, h, HP_ALGID, d, NULL, 0), ERROR_INVALID_PARAMETER);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_gethashparam_dword_params_protocol) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    DWORD ps[] = { HP_ALGID, HP_HASHSIZE };
    DWORD want[] = { CALG_MD5, 16 };
    for (int i = 0; i < 2; i++) {
        DWORD v = 0, n = 0;
        OKAY(R.GetHashParam(p, h, ps[i], NULL, &n, 0));
        EXPECT_EQ(n, 4);
        for (DWORD l = 0; l < 4; l++) {
            n = l; v = 0x55555555;
            FAILS(R.GetHashParam(p, h, ps[i], (BYTE *)&v, &n, 0), ERROR_MORE_DATA);
            EXPECT_EQ(n, 4); EXPECT_EQ(v, 0x55555555);
        }
        n = 4;
        OKAY(R.GetHashParam(p, h, ps[i], (BYTE *)&v, &n, 0));
        EXPECT_EQ(v, want[i]); EXPECT_EQ(n, 4);
    }
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_gethashparam_unknown_param_bad_type) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    DWORD bad[] = { 0, 3, 5, 6, 7, 0x100, 0xffff };
    for (size_t i = 0; i < NELEM(bad); i++) {
        BYTE b[16]; DWORD n = sizeof b;
        FAILS(R.GetHashParam(p, h, bad[i], b, &n, 0), CPE_BAD_TYPE);
    }
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_gethashparam_wrong_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k));
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5);
    ULONG_PTR p2 = rsa_enh(&R);
    BYTE b[32]; DWORD n;
    if (k && h) {
        n = sizeof b; FAILS(R.GetHashParam(k, h, HP_HASHVAL, b, &n, 0), CPE_BAD_UID);
        n = sizeof b; FAILS(R.GetHashParam(p, k, HP_HASHVAL, b, &n, 0), CPE_BAD_HASH);
        n = sizeof b; FAILS(R.GetHashParam(p2, h, HP_HASHVAL, b, &n, 0), CPE_BAD_UID);
    }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_gethashparam_hashval_twice_identical) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    OKAY(R.HashData(p, h, cp_abc, 3, 0));
    BYTE a[16], b[16]; DWORD n = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, a, &n, 0));
    n = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, b, &n, 0));
    SAMEBYTES(a, b, 16);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_gethashparam_hashsize_of_empty_hash) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    BOOL ok; EXPECT_EQ(cp_hp_dw(&R, p, h, HP_HASHSIZE, &ok), 20); CHECK(ok);
    BYTE d[20]; DWORD n = 20;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    BYTE want[20]; hx("da39a3ee5e6b4b0d3255bfef95601890afd80709", want);
    SAMEBYTES(d, want, 20);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}

/* ---- CPSetHashParam --------------------------------------------------------------------- */
TEST(cpd_sethashparam_flags_first) {
    NEED_RSA();
    BYTE b[20] = { 0 };
    FAILS(R.SetHashParam(0, 0, HP_HASHVAL, b, 1), CPE_BAD_FLAGS);
    FAILS(R.SetHashParam(0, 0, HP_HMAC_INFO, b, 0x40), CPE_BAD_FLAGS);
}
TEST(cpd_sethashparam_unknown_param_bad_type) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE b[20] = { 0 };
    DWORD bad[] = { 0, 1, 3, 4, 8, 9, 0x100 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.SetHashParam(p, h, bad[i], b, 0), CPE_BAD_TYPE);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_sethashparam_prf_params_need_prf_hash) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE b[16] = { 0 };
    FAILS(R.SetHashParam(p, h, HP_TLS1PRF_LABEL, b, 0), CPE_BAD_HASH);
    FAILS(R.SetHashParam(p, h, HP_TLS1PRF_SEED, b, 0), CPE_BAD_HASH);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_sethashparam_hashval_sha1_roundtrip) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE v[20]; for (int i = 0; i < 20; i++) v[i] = (BYTE)(0xa0 + i);
    OKAY(R.SetHashParam(p, h, HP_HASHVAL, v, 0));
    BYTE g[20]; DWORD n = sizeof g;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, g, &n, 0));
    EXPECT_EQ(n, 20);
    SAMEBYTES(g, v, 20);
    /* A hash whose value was set is finished. */
    FAILS(R.HashData(p, h, (const BYTE *)"a", 1, 0), CPE_BAD_HASH_STATE);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_sethashparam_hashval_after_finish_bad_hash_state) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE v[20] = { 1 }, g[20]; DWORD n = sizeof g;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, g, &n, 0));
    t_note("SetHashParam(HP_HASHVAL) after a finished SHA1: %d err=0x%lx", R.SetHashParam(p, h, HP_HASHVAL, v, 0), GetLastError());
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_sethashparam_wrong_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k));
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1);
    BYTE v[20] = { 0 };
    if (k && h) {
        FAILS(R.SetHashParam(k, h, HP_HASHVAL, v, 0), CPE_BAD_UID);
        FAILS(R.SetHashParam(p, k, HP_HASHVAL, v, 0), CPE_BAD_HASH);
    }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p);
}

/* ---- CPDuplicateHash / CPDestroyHash ---------------------------------------------------- */
TEST(cpd_duplicatehash_midstream_independent) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    OKAY(R.HashData(p, h, (const BYTE *)"a", 1, 0));
    ULONG_PTR d = 0;
    OKAY(R.DuplicateHash(p, h, NULL, 0, &d));
    CHECK(d != 0); CHECK(d != h);
    if (!d) { R.DestroyHash(p, h); return; }
    OKAY(R.HashData(p, h, (const BYTE *)"bc", 2, 0));
    OKAY(R.HashData(p, d, (const BYTE *)"bd", 2, 0));
    BYTE a[16], b[16], wa[16], wb[16]; DWORD n = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, a, &n, 0)); n = 16;
    OKAY(R.GetHashParam(p, d, HP_HASHVAL, b, &n, 0));
    hx("900150983cd24fb0d6963f7d28e17f72", wa); /* md5("abc") */
    DWORD l = cp_hash(&R, p, CALG_MD5, "abd", 3, wb, 16);
    EXPECT_EQ(l, 16);
    SAMEBYTES(a, wa, 16); SAMEBYTES(b, wb, 16);
    R.DestroyHash(p, h); R.DestroyHash(p, d);
    cp_rel(&R, p);
}
TEST(cpd_duplicatehash_of_finished_hash) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    OKAY(R.HashData(p, h, cp_abc, 3, 0));
    BYTE a[20], b[20]; DWORD n = 20;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, a, &n, 0));
    ULONG_PTR d = 0; SET_ERR(0);
    BOOL r = R.DuplicateHash(p, h, NULL, 0, &d);
    t_note("DuplicateHash of finished hash: %d err=0x%lx", r, GetLastError());
    if (r && d) {
        n = 20;
        if (R.GetHashParam(p, d, HP_HASHVAL, b, &n, 0)) SAMEBYTES(a, b, 20);
        R.DestroyHash(p, d);
    }
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_duplicatehash_reserved_and_flags) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5), d = 0; REQUIRE(h);
    DWORD reserved = 0;
    FAILS(R.DuplicateHash(p, h, &reserved, 0, &d), ERROR_INVALID_PARAMETER);
    FAILS(R.DuplicateHash(p, h, NULL, 1, &d), CPE_BAD_FLAGS);
    FAILS(R.DuplicateHash(p, h, NULL, 0x100, &d), CPE_BAD_FLAGS);
    /* reserved pointer is tested before the flags */
    FAILS(R.DuplicateHash(p, h, &reserved, 1, &d), ERROR_INVALID_PARAMETER);
    /* both are checked before any handle: the zero provider handle is never dereferenced */
    FAILS(R.DuplicateHash(0, 0, NULL, 1, &d), CPE_BAD_FLAGS);
    FAILS(R.DuplicateHash(0, 0, &reserved, 0, &d), ERROR_INVALID_PARAMETER);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_duplicatehash_wrong_kind_is_bad_hash) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0, d = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k)); REQUIRE(k);
    FAILS(R.DuplicateHash(p, k, NULL, 0, &d), CPE_BAD_HASH);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_duplicatehash_other_context_is_bad_uid) {
    NEED_RSA(); ULONG_PTR a = rsa_enh(&R), b = rsa_enh(&R); REQUIRE(a && b);
    ULONG_PTR h = cp_mkhash(&R, a, CALG_MD5), d = 0; REQUIRE(h);
    FAILS(R.DuplicateHash(b, h, NULL, 0, &d), CPE_BAD_UID);
    R.DestroyHash(a, h);
    cp_rel(&R, a); cp_rel(&R, b);
}
TEST(cpd_duplicatehash_survives_original_destroy) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5), d = 0; REQUIRE(h);
    OKAY(R.HashData(p, h, (const BYTE *)"ab", 2, 0));
    OKAY(R.DuplicateHash(p, h, NULL, 0, &d)); REQUIRE(d);
    OKAY(R.DestroyHash(p, h));
    OKAY(R.HashData(p, d, (const BYTE *)"c", 1, 0));
    BYTE g[16], w[16]; DWORD n = 16;
    OKAY(R.GetHashParam(p, d, HP_HASHVAL, g, &n, 0));
    hx("900150983cd24fb0d6963f7d28e17f72", w);
    SAMEBYTES(g, w, 16);
    R.DestroyHash(p, d);
    cp_rel(&R, p);
}
TEST(cpd_duplicatehash_hmac) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[20]; memset(key, 0x0b, 20);
    ULONG_PTR k = cp_hkey(&R, p, key, 20); REQUIRE(k);
    ULONG_PTR h = 0, d = 0; OKAY(R.CreateHash(p, CALG_HMAC, k, 0, &h)); REQUIRE(h);
    HMAC_INFO hi; memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1;
    OKAY(R.SetHashParam(p, h, HP_HMAC_INFO, (BYTE *)&hi, 0));
    OKAY(R.HashData(p, h, (const BYTE *)"Hi ", 3, 0));
    SET_ERR(0);
    BOOL r = R.DuplicateHash(p, h, NULL, 0, &d);
    if (r && d) {
        OKAY(R.HashData(p, d, (const BYTE *)"There", 5, 0));
        BYTE g[20], w[20]; DWORD n = 20;
        OKAY(R.GetHashParam(p, d, HP_HASHVAL, g, &n, 0));
        hx("b617318655057264e28bc0b6fb378c8ef146be00", w);
        SAMEBYTES(g, w, 20);
        R.DestroyHash(p, d);
    } else t_note("DuplicateHash of an HMAC hash fails err=0x%lx", GetLastError());
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_destroyhash_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k));
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5);
    if (k && h) {
        FAILS(R.DestroyHash(p, k), CPE_BAD_HASH);
        FAILS(R.DestroyHash(k, h), CPE_BAD_UID);
        FAILS(R.DestroyHash(p2, h), CPE_BAD_UID);
        OKAY(R.DestroyHash(p, h));
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_destroyhash_hmac_and_mac_hashes) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    ULONG_PTR k = cp_hkey(&R, p, key, 16); REQUIRE(k);
    ULONG_PTR h = 0;
    OKAY(R.CreateHash(p, CALG_HMAC, k, 0, &h));
    if (h) OKAY(R.DestroyHash(p, h));
    h = 0;
    BYTE dk[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    ULONG_PTR k2 = cp_key(&R, p, CALG_DES, dk, 8);
    OKAY(R.CreateHash(p, CALG_MAC, k2, 0, &h));
    if (h) OKAY(R.DestroyHash(p, h));
    if (k2) R.DestroyKey(p, k2);
    /* Destroying the hash must not destroy the key it was created from. */
    BOOL ok; cp_kp_dw(&R, p, k, KP_ALGID, &ok); CHECK(ok);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}

/* ---- CPHashSessionKey -------------------------------------------------------------------- */
TEST(cpd_hashsessionkey_hashes_key_material) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(0x10 + i);
    ULONG_PTR k = cp_key(&R, p, CALG_RC4, key, 16); REQUIRE(k);
    BYTE fwd[16], rev[16], rk[16], got[16];
    for (int i = 0; i < 16; i++) rk[i] = key[15 - i];
    EXPECT_EQ(cp_hash(&R, p, CALG_MD5, key, 16, fwd, 16), 16);
    EXPECT_EQ(cp_hash(&R, p, CALG_MD5, rk, 16, rev, 16), 16);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    OKAY(R.HashSessionKey(p, h, k, 0));
    DWORD n = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, got, &n, 0));
    int f = !memcmp(got, fwd, 16), r = !memcmp(got, rev, 16);
    CHECK(f || r);
    t_note("HashSessionKey flags 0 hashes the key bytes in %s order", f ? "stored" : (r ? "reversed" : "unknown"));
    R.DestroyHash(p, h);
    h = cp_mkhash(&R, p, CALG_MD5);
    OKAY(R.HashSessionKey(p, h, k, CRYPT_LITTLE_ENDIAN));
    n = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, got, &n, 0));
    int f2 = !memcmp(got, fwd, 16), r2 = !memcmp(got, rev, 16);
    CHECK(f2 || r2);
    CHECK(f2 != f);  /* the flag flips the byte order */
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_hashsessionkey_flags) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16] = { 0 }; key[0] = 9;
    ULONG_PTR k = cp_key(&R, p, CALG_RC4, key, 16), h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(k && h);
    DWORD bad[] = { 2, 4, 0x100, 0x8000, 0x80000000 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.HashSessionKey(p, h, k, bad[i]), CPE_BAD_FLAGS);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_hashsessionkey_after_finish_bad_hash_state) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16] = { 7 };
    ULONG_PTR k = cp_key(&R, p, CALG_RC4, key, 16), h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(k && h);
    BYTE d[16]; DWORD n = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    FAILS(R.HashSessionKey(p, h, k, 0), CPE_BAD_HASH_STATE);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_hashsessionkey_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16] = { 7 };
    ULONG_PTR k = cp_key(&R, p, CALG_RC4, key, 16), h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(k && h);
    FAILS(R.HashSessionKey(k, h, k, 0), CPE_BAD_UID);
    FAILS(R.HashSessionKey(p, k, k, 0), CPE_BAD_HASH);
    FAILS(R.HashSessionKey(p, h, h, 0), CPE_BAD_KEY);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_hashsessionkey_matches_hashdata_of_deskey) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[24]; for (int i = 0; i < 24; i++) key[i] = (BYTE)(i * 11 + 1);
    ULONG_PTR k = cp_key(&R, p, CALG_3DES, key, 24); REQUIRE(k);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    if (R.HashSessionKey(p, h, k, 0)) {
        BYTE g[20]; DWORD n = 20;
        OKAY(R.GetHashParam(p, h, HP_HASHVAL, g, &n, 0));
        t_note("HashSessionKey on a plaintext-imported 3DES key succeeds (digest length %lu)", n);
    } else t_note("HashSessionKey on a plaintext-imported 3DES key fails 0x%lx", GetLastError());
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}

#include "ck.h"
/* CryptEncrypt / CryptDecrypt protocol: Final flag, length/buffer in-out, padding, chaining, hash-while-encrypt. */

static HCRYPTKEY aesk(HCRYPTPROV p) { return ck_key(p, CALG_AES_128, sp_key128, 16); }

TEST(encrypt_final_size_query_null_buffer) {
    NEED_CRYPT(); NEED_PROV(p);
    static const DWORD in[] = { 0, 1, 15, 16, 17, 31, 32, 33 };
    static const DWORD out[] = { 16, 16, 16, 32, 32, 32, 48, 48 };
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    for (unsigned i = 0; i < SIZEOFA(in); i++) {
        DWORD n = in[i];
        CHECKF(U(CryptEncrypt)(k, 0, TRUE, 0, NULL, &n, 0), "len %lu err 0x%lx", in[i], GetLastError());
        EXPECT_EQ(n, out[i]);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_size_query_does_not_advance_chain) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    DWORD n = 20;
    CHECK(U(CryptEncrypt)(k, 0, TRUE, 0, NULL, &n, 0)); EXPECT_EQ(n, 32);
    BYTE b[48]; DWORD len;
    CHECK(ck_enc(k, sp_pt, 20, b, 48, &len)); EXPECT_EQ(len, 32); CHECK_BYTES(b, sp_cbcpad20_128, 32);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_final_too_small_buffer_more_data) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE b[64]; memcpy(b, sp_pt, 20);
    static const DWORD caps[] = { 0, 16, 20, 31 };
    for (unsigned i = 0; i < SIZEOFA(caps); i++) {
        DWORD n = 20; SET_ERR(0);
        BOOL r = U(CryptEncrypt)(k, 0, TRUE, 0, b, &n, caps[i]);
        CHECKF(!r, "cap %lu", caps[i]);
        EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(n, 32);
    }
    /* the key is unaffected by the failed attempts */
    DWORD len; CHECK(ck_enc(k, sp_pt, 20, b, 64, &len)); EXPECT_EQ(len, 32); CHECK_BYTES(b, sp_cbcpad20_128, 32);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_final_exact_buffer_ok) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE b[32]; memcpy(b, sp_pt, 20); DWORD n = 20;
    CHECK(U(CryptEncrypt)(k, 0, TRUE, 0, b, &n, 32)); EXPECT_EQ(n, 32); CHECK_BYTES(b, sp_cbcpad20_128, 32);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_final_empty_input_yields_padding_block) {
    NEED_CRYPT(); NEED_PROV(p);
    static const struct { ALG_ID a; const BYTE *k; DWORD kl, blk; } t[] = {
        { CALG_AES_128, sp_key128, 16, 16 }, { CALG_DES, des_key, 8, 8 }, { CALG_3DES, tdes_key, 24, 8 } };
    for (unsigned i = 0; i < 3; i++) {
        HCRYPTKEY k = ck_key(p, t[i].a, t[i].k, t[i].kl); if (!k) { CHECK(0); continue; }
        BYTE b[32]; DWORD n = 0;
        CHECK(U(CryptEncrypt)(k, 0, TRUE, 0, b, &n, sizeof b)); EXPECT_EQ(n, t[i].blk);
        /* and it decrypts back to nothing */
        CHECK(U(CryptDecrypt)(k, 0, TRUE, 0, b, &n)); EXPECT_EQ(n, 0);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(encrypt_nonfinal_empty_is_noop) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    BYTE b[16]; DWORD n = 0;
    CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, sizeof b)); EXPECT_EQ(n, 0);
    n = 0; CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, NULL, &n, 0)); EXPECT_EQ(n, 0);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_nonfinal_short_or_unaligned_fails) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_mode(k, CRYPT_MODE_ECB);
    static const DWORD lens[] = { 1, 8, 15, 17, 20, 31 };
    for (unsigned i = 0; i < SIZEOFA(lens); i++) {
        BYTE b[64]; memset(b, 0xa5, sizeof b); DWORD n = lens[i]; SET_ERR(0);
        BOOL r = U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, sizeof b);
        CHECKF(!r, "len %lu succeeded", lens[i]);
        if (!r && lens[i] < 16) { EXPECT_ERR(NTE_BAD_DATA_); EXPECT_EQ(n, 16); }
        else if (!r) t_note("non-final unaligned len %lu -> err 0x%lx", lens[i], GetLastError());
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_nonfinal_aligned_has_no_padding) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE b[64]; memcpy(b, sp_pt, 48); DWORD n = 48;
    CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 64)); EXPECT_EQ(n, 48); CHECK_BYTES(b, sp_cbc128, 48);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_nonfinal_null_buffer_leaves_length) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    DWORD n = 32; CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, NULL, &n, 0)); EXPECT_EQ(n, 32);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_nonfinal_buffer_smaller_than_data) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    BYTE b[64]; memcpy(b, sp_pt, 32); DWORD n = 32; SET_ERR(0);
    BOOL r = U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 16);
    CHECK(!r); if (!r) { DWORD e = GetLastError(); CHECKF(e == ERROR_MORE_DATA || e == (DWORD)NTE_BAD_LEN_, "0x%lx", e); t_note("dwBufLen < dwDataLen non-final: 0x%lx len=%lu", e, n); }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_invalid_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    /* decomp LocalEncrypt: (flags & ~CRYPT_OAEP) != 0 -> NTE_BAD_FLAGS */
    static const DWORD fl[] = { 1, 2, 4, 8, 0x10, 0x20, 0x80, 0x100, 0x8000, 0x80000000 };
    for (unsigned i = 0; i < SIZEOFA(fl); i++) {
        BYTE b[32] = { 0 }; DWORD n = 16; SET_ERR(0);
        EXPECT_FAIL(!U(CryptEncrypt)(k, 0, TRUE, fl[i], b, &n, 32), NTE_BAD_FLAGS_);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(decrypt_invalid_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    static const DWORD fl[] = { 1, 2, 4, 8, 0x10, 0x80, 0x100, 0x8000 };
    for (unsigned i = 0; i < SIZEOFA(fl); i++) {
        BYTE b[32] = { 0 }; DWORD n = 16; SET_ERR(0);
        CHECKF(!U(CryptDecrypt)(k, 0, TRUE, fl[i], b, &n), "flag 0x%lx accepted", fl[i]);
        t_note("decrypt flag 0x%lx -> 0x%lx", fl[i], GetLastError());
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_final_resets_iv_chain) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE a[48], b[48]; DWORD la, lb;
    CHECK(ck_enc(k, sp_pt, 20, a, 48, &la)); CHECK(ck_enc(k, sp_pt, 20, b, 48, &lb));
    EXPECT_EQ(la, lb); CHECK_BYTES(a, b, 32); CHECK_BYTES(a, sp_cbcpad20_128, 32);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_nonfinal_chains_across_calls) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE a[16], b[16]; DWORD n = 16;
    memcpy(a, sp_pt, 16); CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, a, &n, 16));
    n = 16; memcpy(b, sp_pt, 16); CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 16));
    CHECK_BYTES(a, sp_cbc128, 16);
    CHECK(memcmp(a, b, 16) != 0);  /* same plaintext, chained -> different ciphertext */
    /* resetting the IV restarts the chain */
    ck_set_iv(k, sp_iv); n = 16; memcpy(b, sp_pt, 16); CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 16));
    CHECK_BYTES(b, a, 16);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_stream_chunks_equal_oneshot_cbc_pkcs5) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE out[64]; DWORD off = 0, n;
    memcpy(out, sp_pt, 16); n = 16; CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, out, &n, 64)); EXPECT_EQ(n, 16); off = 16;
    memcpy(out + 16, sp_pt + 16, 4); n = 4; CHECK(U(CryptEncrypt)(k, 0, TRUE, 0, out + 16, &n, 48)); EXPECT_EQ(n, 16);
    CHECK_BYTES(out, sp_cbcpad20_128, 32);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(decrypt_stream_chunks_equal_oneshot_cbc_pkcs5) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE b[48]; DWORD n = 16;
    memcpy(b, sp_cbcpad20_128, 16); CHECK(U(CryptDecrypt)(k, 0, FALSE, 0, b, &n)); EXPECT_EQ(n, 16); CHECK_BYTES(b, sp_pt, 16);
    n = 16; memcpy(b + 16, sp_cbcpad20_128 + 16, 16); CHECK(U(CryptDecrypt)(k, 0, TRUE, 0, b + 16, &n)); EXPECT_EQ(n, 4);
    CHECK_BYTES(b + 16, sp_pt + 16, 4);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(decrypt_final_unaligned_length_fails) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    static const DWORD lens[] = { 1, 15, 17, 31 };
    for (unsigned i = 0; i < SIZEOFA(lens); i++) {
        BYTE b[48]; memcpy(b, sp_cbcpad20_128, 32); DWORD n = lens[i]; SET_ERR(0);
        EXPECT_FAIL(!U(CryptDecrypt)(k, 0, TRUE, 0, b, &n), NTE_BAD_DATA_);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(decrypt_final_bad_padding_bad_data) {
    NEED_CRYPT(); NEED_PROV(p);
    for (int pass = 0; pass < 2; pass++) {
        HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
        ck_set_iv(k, sp_iv);
        BYTE b[32]; memcpy(b, sp_cbcpad20_128, 32);
        if (pass == 0) b[31] ^= 0x55;        /* garbles the last block -> random padding */
        else { b[16] ^= 0x01; b[0] ^= 0; }   /* flips plaintext bits of last block */
        DWORD n = 32; SET_ERR(0);
        BOOL r = U(CryptDecrypt)(k, 0, TRUE, 0, b, &n);
        if (pass == 0) { CHECK(!r); if (!r) EXPECT_ERR(NTE_BAD_DATA_); }
        else t_note("bit-flip in last-1 block: %s", r ? "decrypted (padding intact)" : "failed");
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(decrypt_final_all_padding_values_checked) {
    NEED_CRYPT(); NEED_PROV(p);
    /* craft ECB blocks whose decrypted last block ends in an invalid pad count: encrypt a raw block with Final=FALSE
     * then decrypt with Final=TRUE and check rejection of pad bytes 0, 17 and inconsistent run */
    static const BYTE last[3][16] = {
        { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0 },
        { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,17 },
        { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,2,3 } };
    for (int i = 0; i < 3; i++) {
        HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
        ck_set_mode(k, CRYPT_MODE_ECB);
        BYTE b[16]; DWORD n = 16; memcpy(b, last[i], 16);
        CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 16));
        n = 16; SET_ERR(0);
        EXPECT_FAIL(!U(CryptDecrypt)(k, 0, TRUE, 0, b, &n), NTE_BAD_DATA_);
        U(CryptDestroyKey)(k);
    }
    /* valid pad of a full block (16 x 0x10) yields length 0 */
    HCRYPTKEY k = aesk(p); ck_set_mode(k, CRYPT_MODE_ECB);
    BYTE b[16]; memset(b, 16, 16); DWORD n = 16;
    CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 16));
    n = 16; CHECK(U(CryptDecrypt)(k, 0, TRUE, 0, b, &n)); EXPECT_EQ(n, 0);
    /* single pad byte 0x01 */
    BYTE c[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,1 };
    n = 16; CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, c, &n, 16));
    n = 16; CHECK(U(CryptDecrypt)(k, 0, TRUE, 0, c, &n)); EXPECT_EQ(n, 15);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(decrypt_nonfinal_does_not_strip_padding) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    BYTE b[32]; memcpy(b, sp_cbcpad20_128, 32); DWORD n = 32;
    CHECK(U(CryptDecrypt)(k, 0, FALSE, 0, b, &n)); EXPECT_EQ(n, 32);
    CHECK_BYTES(b, sp_pt, 20);
    for (int i = 20; i < 32; i++) CHECK(b[i] == 12);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(decrypt_final_zero_length) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    BYTE b[16]; DWORD n = 0; SET_ERR(0);
    BOOL r = U(CryptDecrypt)(k, 0, TRUE, 0, b, &n);
    t_note("CryptDecrypt(Final, len 0): %s err=0x%lx len=%lu", r ? "ok" : "fail", GetLastError(), n);
    n = 0; CHECK(U(CryptDecrypt)(k, 0, FALSE, 0, b, &n)); EXPECT_EQ(n, 0);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(des_family_padding_sizes) {
    NEED_CRYPT(); NEED_PROV(p);
    static const struct { ALG_ID a; const BYTE *k; DWORD kl; } t[] = { { CALG_DES, des_key, 8 }, { CALG_3DES, tdes_key, 24 }, { CALG_3DES_112, tdes112_key, 16 }, { CALG_RC2, rc2_v7_key, 16 } };
    for (unsigned i = 0; i < 4; i++) for (DWORD len = 0; len <= 17; len++) {
        HCRYPTKEY k = ck_key(p, t[i].a, t[i].k, t[i].kl); if (!k) { CHECK(0); break; }
        BYTE b[48]; memset(b, 0x61, sizeof b); DWORD n = len;
        BOOL r = U(CryptEncrypt)(k, 0, TRUE, 0, b, &n, sizeof b);
        CHECKF(r, "alg %x len %lu", t[i].a, len);
        if (r) {
            EXPECT_EQ(n, (len / 8 + 1) * 8);
            DWORD m = n; CHECK(U(CryptDecrypt)(k, 0, TRUE, 0, b, &m)); EXPECT_EQ(m, len);
            for (DWORD j = 0; j < len; j++) if (b[j] != 0x61) { CHECK(0); break; }
        }
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(aes_padding_roundtrip_all_lengths) {
    NEED_CRYPT(); NEED_PROV(p);
    for (DWORD len = 0; len <= 40; len++) {
        HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
        ck_set_iv(k, sp_iv);
        BYTE b[64]; memset(b, 0x42, sizeof b); for (DWORD j = 0; j < len; j++) b[j] = (BYTE)(j * 7 + 1);
        BYTE orig[64]; memcpy(orig, b, 64); DWORD n = len;
        CHECK(U(CryptEncrypt)(k, 0, TRUE, 0, b, &n, 64)); EXPECT_EQ(n, (len / 16 + 1) * 16);
        DWORD m = n; CHECK(U(CryptDecrypt)(k, 0, TRUE, 0, b, &m)); EXPECT_EQ(m, len);
        CHECK(!memcmp(b, orig, len));
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(encrypt_with_hash_hashes_plaintext) {
    NEED_CRYPT(); NEED_PROV(p); REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptGetHashParam)); REQUIRE(U(CryptDestroyHash));
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_iv(k, sp_iv);
    HCRYPTHASH h = 0; CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h)); if (!h) return;
    BYTE b[48]; memcpy(b, sp_pt, 20); DWORD n = 20;
    CHECK(U(CryptEncrypt)(k, h, TRUE, 0, b, &n, 48)); EXPECT_EQ(n, 32); CHECK_BYTES(b, sp_cbcpad20_128, 32);
    BYTE hv[20]; DWORD hl = 20;
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, hv, &hl, 0)); EXPECT_EQ(hl, 20); CHECK_BYTES(hv, sha1_sp20, 20);
    U(CryptDestroyHash)(h); U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_with_hash_chunked) {
    NEED_CRYPT(); NEED_PROV(p); REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptGetHashParam)); REQUIRE(U(CryptDestroyHash));
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    HCRYPTHASH h = 0; CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h)); if (!h) return;
    BYTE b[48]; DWORD n = 16;
    memcpy(b, sp_pt, 16); CHECK(U(CryptEncrypt)(k, h, FALSE, 0, b, &n, 48));
    n = 16; memcpy(b, sp_pt + 16, 16); CHECK(U(CryptEncrypt)(k, h, TRUE, 0, b, &n, 48)); EXPECT_EQ(n, 32);
    BYTE hv[20]; DWORD hl = 20;
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, hv, &hl, 0)); CHECK_BYTES(hv, sha1_sp32, 20);
    U(CryptDestroyHash)(h); U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_with_hash_final_size_query_does_not_hash) {
    NEED_CRYPT(); NEED_PROV(p); REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptGetHashParam)); REQUIRE(U(CryptDestroyHash));
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    HCRYPTHASH h = 0; CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h)); if (!h) return;
    DWORD n = 20; CHECK(U(CryptEncrypt)(k, h, TRUE, 0, NULL, &n, 0)); EXPECT_EQ(n, 32);
    BYTE hv[20]; DWORD hl = 20; BYTE b[48]; memcpy(b, sp_pt, 20); n = 20;
    ck_set_iv(k, sp_iv);
    CHECK(U(CryptEncrypt)(k, h, TRUE, 0, b, &n, 48));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, hv, &hl, 0)); CHECK_BYTES(hv, sha1_sp20, 20);
    U(CryptDestroyHash)(h); U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_with_destroyed_hash_fails) {
    NEED_CRYPT(); NEED_PROV(p); REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptDestroyHash));
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    HCRYPTHASH h = 0; CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h)); if (!h) return;
    CHECK(U(CryptDestroyHash)(h));
    BYTE b[48] = { 0 }; DWORD n = 16; SET_ERR(0);
    CHECK(!U(CryptEncrypt)(k, h, TRUE, 0, b, &n, 48)); t_note("encrypt with destroyed hash: 0x%lx", GetLastError());
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(rc4_encrypt_size_query_and_small_buffer) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_RC4, rc4_key128, 16); if (!k) { CHECK(0); return; }
    BYTE b[32]; DWORD n = 20;
    SET_ERR(0); BOOL q = U(CryptEncrypt)(k, 0, TRUE, 0, NULL, &n, 0);
    t_note("rc4 final size query: %s len=%lu err=0x%lx", q ? "ok" : "fail", n, GetLastError());
    memcpy(b, rc4_pt64, 20); n = 20; SET_ERR(0);
    CHECK(!U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 10));
    t_note("rc4 dwBufLen<dwDataLen err 0x%lx len %lu", GetLastError(), n);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(ecb_mode_equal_blocks_equal_ciphertext) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    ck_set_mode(k, CRYPT_MODE_ECB);
    BYTE b[32]; memcpy(b, sp_pt, 16); memcpy(b + 16, sp_pt, 16); DWORD n = 32;
    CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 32)); CHECK_BYTES(b, b + 16, 16);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(cbc_equal_blocks_differ) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = aesk(p); if (!k) { CHECK(0); return; }
    BYTE b[32]; memcpy(b, sp_pt, 16); memcpy(b + 16, sp_pt, 16); DWORD n = 32;
    CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 32)); CHECK(memcmp(b, b + 16, 16) != 0);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(encrypt_in_place_matches_separate_buffers) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k1 = aesk(p), k2 = aesk(p); if (!k1 || !k2) { CHECK(0); return; }
    BYTE a[32], b[32]; memset(a, 7, 32); memset(b, 7, 32); DWORD n1 = 32, n2 = 32;
    CHECK(U(CryptEncrypt)(k1, 0, FALSE, 0, a, &n1, 32)); CHECK(U(CryptEncrypt)(k2, 0, FALSE, 0, b, &n2, 32));
    CHECK_BYTES(a, b, 32);
    U(CryptDestroyKey)(k1); U(CryptDestroyKey)(k2); ck_release(p);
}
TEST(two_keys_same_material_independent_chains) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k1 = aesk(p), k2 = aesk(p); if (!k1 || !k2) { CHECK(0); return; }
    BYTE a[16], b[16]; DWORD n = 16;
    memcpy(a, sp_pt, 16); CHECK(U(CryptEncrypt)(k1, 0, FALSE, 0, a, &n, 16));
    n = 16; memcpy(a, sp_pt, 16); CHECK(U(CryptEncrypt)(k1, 0, FALSE, 0, a, &n, 16));  /* k1 advanced twice */
    n = 16; memcpy(b, sp_pt, 16); CHECK(U(CryptEncrypt)(k2, 0, FALSE, 0, b, &n, 16));  /* k2 fresh */
    CHECK(memcmp(a, b, 16) != 0);
    U(CryptDestroyKey)(k1); U(CryptDestroyKey)(k2); ck_release(p);
}

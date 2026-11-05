/* AES side of cryptdll: aesCTSEncryptMsg/aesCTSDecryptMsg (RFC 3962 CBC-CS3), the AES128/AES256 crypto systems
 * (RFC 3961/3962 aes*-cts-hmac-sha1-96), string-to-key, PRF+, KRBFXCF2 (RFC 6113). */
#include "ck.h"
#include "ck_vec.h"

/* ---- aesCTS*Msg ---------------------------------------------------------------------------------------- */
TEST(ckaes_cts_rfc3962_encrypt_vectors) {
    CK_NEED(aesCTSEncryptMsg);
    static const BYTE key[16] = { 'c','h','i','c','k','e','n',' ','t','e','r','i','y','a','k','i' };
    static const char txt[] = "I would like the General Gau's Chicken, please, and wait a minute...";
    static const struct { size_t n; const char *ct; } v[] = {
        { 17, "c6353568f2bf8cb4d8a580362da7ff7f97" },
        { 31, "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5" } };
    for (size_t i = 0; i < 2; i++) {
        BYTE buf[64], iv[16] = {0};
        memcpy(buf, txt, v[i].n);
        EXPECT_NS(CKP(aesCTSEncryptMsg)(16, (PUCHAR)key, (ULONG)v[i].n, buf, iv), 0);
        CHECKF(ck_eqhex(buf, v[i].n, v[i].ct), "length %zu", v[i].n);
    }
}

TEST(ckaes_cts_kat_table_encrypt) {
    CK_NEED(aesCTSEncryptMsg);
    for (size_t i = 0; i < CK_CTS_KAT_N; i++) {
        size_t kl, n; BYTE *k = ck_hexa(ck_cts_kat[i].key, &kl), *in = ck_hexa(ck_cts_kat[i].in, &n);
        BYTE iv[16] = {0};
        NTSTATUS st = CKP(aesCTSEncryptMsg)((ULONG)kl, k, (ULONG)n, in, iv);
        CHECKF(st == 0 && ck_eqhex(in, n, ck_cts_kat[i].out), "row %zu key %zu len %zu st=0x%08lx", i, kl, n, (unsigned long)st);
        free(k); free(in);
    }
}

TEST(ckaes_cts_kat_table_decrypt) {
    CK_NEED(aesCTSDecryptMsg);
    for (size_t i = 0; i < CK_CTS_KAT_N; i++) {
        size_t kl, n; BYTE *k = ck_hexa(ck_cts_kat[i].key, &kl), *ct = ck_hexa(ck_cts_kat[i].out, &n);
        BYTE iv[16] = {0};
        NTSTATUS st = CKP(aesCTSDecryptMsg)((ULONG)kl, k, (ULONG)n, ct, iv);
        CHECKF(st == 0 && ck_eqhex(ct, n, ck_cts_kat[i].in), "row %zu key %zu len %zu st=0x%08lx", i, kl, n, (unsigned long)st);
        free(k); free(ct);
    }
}

TEST(ckaes_cts_nonzero_iv_encrypt_and_decrypt) {
    CK_NEED(aesCTSEncryptMsg); CK_NEED(aesCTSDecryptMsg);
    for (size_t i = 0; i < CK_CTSIV_KAT_N; i++) {
        size_t kl, il, n; BYTE *k = ck_hexa(ck_ctsiv_kat[i].key, &kl), *iv0 = ck_hexa(ck_ctsiv_kat[i].iv, &il), *in = ck_hexa(ck_ctsiv_kat[i].in, &n);
        BYTE iv[16]; memcpy(iv, iv0, 16);
        EXPECT_NS(CKP(aesCTSEncryptMsg)((ULONG)kl, k, (ULONG)n, in, iv), 0);
        CHECKF(ck_eqhex(in, n, ck_ctsiv_kat[i].out), "enc row %zu", i);
        memcpy(iv, iv0, 16);
        EXPECT_NS(CKP(aesCTSDecryptMsg)((ULONG)kl, k, (ULONG)n, in, iv), 0);
        CHECKF(ck_eqhex(in, n, ck_ctsiv_kat[i].in), "dec row %zu", i);
        free(k); free(iv0); free(in);
    }
}

TEST(ckaes_cts_single_block_ignores_supplied_iv) {
    CK_NEED(aesCTSEncryptMsg); CK_NEED(aesCTSDecryptMsg);
    /* exactly 16 bytes: the routine clears the IV buffer itself and runs plain CBC with a zero IV */
    static const BYTE key[16] = { 'c','h','i','c','k','e','n',' ','t','e','r','i','y','a','k','i' };
    BYTE ref[16], a[16], iv[16];
    memcpy(ref, "I would like the", 16);
    memset(iv, 0, 16);
    EXPECT_NS(CKP(aesCTSEncryptMsg)(16, (PUCHAR)key, 16, ref, iv), 0);
    memcpy(a, "I would like the", 16);
    memset(iv, 0xFF, 16);
    EXPECT_NS(CKP(aesCTSEncryptMsg)(16, (PUCHAR)key, 16, a, iv), 0);
    CHECK(!memcmp(a, ref, 16));
    memset(iv, 0xAA, 16);
    EXPECT_NS(CKP(aesCTSDecryptMsg)(16, (PUCHAR)key, 16, a, iv), 0);
    CHECK(!memcmp(a, "I would like the", 16));
}

TEST(ckaes_cts_single_block_matches_plain_cbc_vector) {
    CK_NEED(aesCTSEncryptMsg);
    /* AES-128 single block with zero IV equals ECB: FIPS-197 appendix C.1 */
    static const BYTE key[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    BYTE pt[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff }, iv[16] = {0};
    EXPECT_NS(CKP(aesCTSEncryptMsg)(16, (PUCHAR)key, 16, pt, iv), 0);
    CHECK(ck_eqhex(pt, 16, "69c4e0d86a7b0430d8cdb78070b4c55a"));
}

TEST(ckaes_cts_fips197_aes256_single_block) {
    CK_NEED(aesCTSEncryptMsg);
    BYTE key[32]; for (int i = 0; i < 32; i++) key[i] = (BYTE)i;
    BYTE pt[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff }, iv[16] = {0};
    EXPECT_NS(CKP(aesCTSEncryptMsg)(32, key, 16, pt, iv), 0);
    CHECK(ck_eqhex(pt, 16, "8ea2b7ca516745bfeafc49904b496089"));
}

TEST(ckaes_cts_fips197_aes192_single_block) {
    CK_NEED(aesCTSEncryptMsg);
    BYTE key[24]; for (int i = 0; i < 24; i++) key[i] = (BYTE)i;
    BYTE pt[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff }, iv[16] = {0};
    EXPECT_NS(CKP(aesCTSEncryptMsg)(24, key, 16, pt, iv), 0);
    CHECK(ck_eqhex(pt, 16, "dda97ca4864cdfe06eaf70a0ec0d7191"));
}

TEST(ckaes_cts_roundtrip_all_lengths) {
    CK_NEED(aesCTSEncryptMsg); CK_NEED(aesCTSDecryptMsg);
    BYTE key[32]; for (int i = 0; i < 32; i++) key[i] = (BYTE)(i * 3 + 1);
    static const ULONG ks[] = { 16, 24, 32 };
    for (size_t kk = 0; kk < 3; kk++) for (ULONG n = 16; n <= 140; n++) {
        BYTE orig[160], buf[160], iv[16];
        for (ULONG i = 0; i < n; i++) orig[i] = (BYTE)(i * 7 + n);
        memcpy(buf, orig, n); memset(buf + n, 0xDD, 16);
        memset(iv, 0x11, 16);
        EXPECT_NS(CKP(aesCTSEncryptMsg)(ks[kk], key, n, buf, iv), 0);
        CHECKF(memcmp(buf, orig, n) != 0, "key %lu len %lu ciphertext equals plaintext", (unsigned long)ks[kk], (unsigned long)n);
        for (int i = 0; i < 16; i++) if (buf[n + i] != 0xDD) { CHECKF(0, "key %lu len %lu overrun", (unsigned long)ks[kk], (unsigned long)n); break; }
        memset(iv, 0x11, 16);
        EXPECT_NS(CKP(aesCTSDecryptMsg)(ks[kk], key, n, buf, iv), 0);
        CHECKF(!memcmp(buf, orig, n), "key %lu len %lu", (unsigned long)ks[kk], (unsigned long)n);
    }
}

TEST(ckaes_cts_ciphertext_has_plaintext_length) {
    CK_NEED(aesCTSEncryptMsg);
    BYTE key[16] = {0}, iv[16] = {0};
    for (ULONG n = 17; n <= 48; n++) {
        BYTE buf[96]; memset(buf, 0x77, sizeof buf);
        EXPECT_NS(CKP(aesCTSEncryptMsg)(16, key, n, buf, iv), 0);
        for (ULONG i = n; i < 96; i++) CHECKF(buf[i] == 0x77, "len %lu byte %lu touched", (unsigned long)n, (unsigned long)i);
    }
}

TEST(ckaes_cts_short_message_rejected) {
    CK_NEED(aesCTSEncryptMsg); CK_NEED(aesCTSDecryptMsg);
    BYTE key[16] = {1}, iv[16] = {0};
    for (ULONG n = 0; n < 16; n++) {
        BYTE buf[16], ref[16]; memset(buf, 0x5C, 16); memcpy(ref, buf, 16);
        EXPECT_NS(CKP(aesCTSEncryptMsg)(16, key, n, buf, iv), NS_INVALID_PARAM);
        CHECKF(!memcmp(buf, ref, 16), "encrypt len %lu modified data", (unsigned long)n);
        EXPECT_NS(CKP(aesCTSDecryptMsg)(16, key, n, buf, iv), NS_INVALID_PARAM);
        CHECKF(!memcmp(buf, ref, 16), "decrypt len %lu modified data", (unsigned long)n);
    }
}

TEST(ckaes_cts_invalid_key_lengths) {
    CK_NEED(aesCTSEncryptMsg); CK_NEED(aesCTSDecryptMsg);
    static const ULONG bad[] = { 1, 8, 15, 17, 23, 25, 31, 33, 48, 64 };
    BYTE key[64] = {7}, iv[16] = {0};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        BYTE buf[32] = {0};
        EXPECT_NS(CKP(aesCTSEncryptMsg)(bad[i], key, 32, buf, iv), NS_INVALID_PARAM);
        EXPECT_NS(CKP(aesCTSDecryptMsg)(bad[i], key, 32, buf, iv), NS_INVALID_PARAM);
    }
    BYTE buf[32] = {0};
    NTSTATUS st = CKP(aesCTSEncryptMsg)(0, key, 32, buf, iv);
    CHECKF(st < 0, "zero-length key accepted (0x%08lx)", (unsigned long)st);
}

TEST(ckaes_cts_wrong_key_does_not_recover_plaintext) {
    CK_NEED(aesCTSEncryptMsg); CK_NEED(aesCTSDecryptMsg);
    BYTE k1[16] = {1}, k2[16] = {2}, iv[16] = {0}, buf[40], orig[40];
    for (int i = 0; i < 40; i++) orig[i] = (BYTE)i;
    memcpy(buf, orig, 40);
    CKP(aesCTSEncryptMsg)(16, k1, 40, buf, iv);
    memset(iv, 0, 16);
    EXPECT_NS(CKP(aesCTSDecryptMsg)(16, k2, 40, buf, iv), 0);    /* no integrity check: succeeds with garbage */
    CHECK(memcmp(buf, orig, 40) != 0);
}

TEST(ckaes_cts_swap_of_last_two_blocks_is_visible) {
    CK_NEED(aesCTSEncryptMsg);
    /* for a 32-byte message CBC-CS3 equals plain CBC with the two ciphertext blocks swapped */
    BYTE key[16] = { 9 }, pt[32], a[32], iv[16] = {0};
    for (int i = 0; i < 32; i++) pt[i] = (BYTE)(i + 1);
    memcpy(a, pt, 32);
    EXPECT_NS(CKP(aesCTSEncryptMsg)(16, key, 32, a, iv), 0);
    BYTE b0[16], b1[16];
    memcpy(b0, pt, 16); memcpy(b1, pt + 16, 16);
    memset(iv, 0, 16);
    BYTE one[16]; memcpy(one, pt, 16);
    EXPECT_NS(CKP(aesCTSEncryptMsg)(16, key, 16, one, iv), 0);   /* C1 = E(P1) */
    CHECK(!memcmp(a + 16, one, 16));                              /* first output block of CBC sits in the second slot */
}

/* ---- string-to-key --------------------------------------------------------------------------------------- */
static NTSTATUS s2k_run(LONG et, const char *pw16, const char *salt16, ULONG iter, BYTE *key, ULONG keylen) {
    const CSX *c = ck_cs(et);
    if (!c) return NS_NO_CSYSTEM;
    USHORT pl, sl; WCHAR *pw = ck_wide(pw16, &pl), *sa = ck_wide(salt16, &sl);
    UNICODE_STRING up = { pl, (USHORT)(pl + 2), pw }, us = { sl, (USHORT)(sl + 2), sa };
    BYTE buf[64]; memset(buf, 0xEE, sizeof buf);
    NTSTATUS st = ((csx_hashpw_fn)c->HashPassword)(&up, &us, iter, buf);
    memcpy(key, buf, keylen);
    for (ULONG i = keylen; i < 64; i++) if (buf[i] != 0xEE) { t_check(0, __FILE__, __LINE__, "hashpw overrun", "byte %lu written", (unsigned long)i); break; }
    free(pw); free(sa);
    return st;
}

TEST(ckaes_s2k_generated_table) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_S2K_KAT_N; i++) {
        BYTE k[32]; int soft = ck_s2k_kat[i].pw[0] == 0;
        NTSTATUS st = s2k_run(ET_AES128, ck_s2k_kat[i].pw, ck_s2k_kat[i].salt, ck_s2k_kat[i].iter, k, 16);
        if (soft && st) { t_note("aes128 string-to-key with empty password -> 0x%08lx", (unsigned long)st); }
        else { CHECKF(st == 0, "row %zu st=0x%08lx", i, (unsigned long)st); CHECKF(ck_eqhex(k, 16, ck_s2k_kat[i].k128), "aes128 row %zu iter %u", i, ck_s2k_kat[i].iter); }
        st = s2k_run(ET_AES256, ck_s2k_kat[i].pw, ck_s2k_kat[i].salt, ck_s2k_kat[i].iter, k, 32);
        if (soft && st) { t_note("aes256 string-to-key with empty password -> 0x%08lx", (unsigned long)st); }
        else { CHECKF(st == 0, "row %zu st=0x%08lx", i, (unsigned long)st); CHECKF(ck_eqhex(k, 32, ck_s2k_kat[i].k256), "aes256 row %zu iter %u", i, ck_s2k_kat[i].iter); }
    }
}

TEST(ckaes_s2k_rfc3962_appendix_b) {
    CK_NEED(CDLocateCSystem);
    static const struct { ULONG it; const char *k128, *k256; } v[] = {
        { 1, "42263c6e89f4fc28b8df68ee09799f15", "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161" },
        { 2, "c651bf29e2300ac27fa469d693bdda13", "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff" },
        { 1200, "4c01cd46d632d01e6dbe230a01ed642a", "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a" } };
    /* "password" / "ATHENA.MIT.EDUraeburn" as UTF-16LE */
    char p[64] = {0}, s[128] = {0};
    const char *ps = "password";
    for (int i = 0; ps[i]; i++) sprintf(p + 4 * i, "%02x00", ps[i]);
    const char *ss = "ATHENA.MIT.EDUraeburn";
    for (int i = 0; ss[i]; i++) sprintf(s + 4 * i, "%02x00", ss[i]);
    for (size_t i = 0; i < 3; i++) {
        BYTE k[32];
        EXPECT_NS(s2k_run(ET_AES128, p, s, v[i].it, k, 16), 0);
        CHECKF(ck_eqhex(k, 16, v[i].k128), "aes128 iter %lu", (unsigned long)v[i].it);
        EXPECT_NS(s2k_run(ET_AES256, p, s, v[i].it, k, 32), 0);
        CHECKF(ck_eqhex(k, 32, v[i].k256), "aes256 iter %lu", (unsigned long)v[i].it);
    }
}

TEST(ckaes_s2k_utf8_conversion_of_password) {
    CK_NEED(CDLocateCSystem);
    /* U+1D11E (surrogate pair) must be hashed as the 4-byte UTF-8 sequence f0 9d 84 9e */
    const CSX *c = ck_cs(ET_AES128);
    CHECK(c != NULL);
    if (!c) return;
    WCHAR pw[] = { 0xD834, 0xDD1E, 0 }, sa[] = { 'E','X','A','M','P','L','E','.','C','O','M','p','i','a','n','i','s','t', 0 };
    UNICODE_STRING up = { 4, 6, pw }, us = { 36, 38, sa };
    BYTE k[16];
    EXPECT_NS(((csx_hashpw_fn)c->HashPassword)(&up, &us, 50, k), 0);
    const char *want = NULL;
    for (size_t i = 0; i < CK_S2K_KAT_N; i++) if (ck_s2k_kat[i].iter == 50) want = ck_s2k_kat[i].k128;
    CHECK(want != NULL);
    if (want) CHECK(ck_eqhex(k, 16, want));
}

TEST(ckaes_s2k_length_field_is_in_bytes) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_AES128);
    CHECK(c != NULL);
    if (!c) return;
    WCHAR pw[] = { 'p','a','s','s','w','o','r','d','X','X' }, sa[] = { 'a','b','c' };
    UNICODE_STRING up8 = { 16, 20, pw }, up10 = { 20, 20, pw }, us = { 6, 6, sa };
    BYTE a[16], b[16];
    EXPECT_NS(((csx_hashpw_fn)c->HashPassword)(&up8, &us, 3, a), 0);
    EXPECT_NS(((csx_hashpw_fn)c->HashPassword)(&up10, &us, 3, b), 0);
    CHECK(memcmp(a, b, 16));
    WCHAR pw2[] = { 'p','a','s','s','w','o','r','d' };
    UNICODE_STRING up = { 16, 16, pw2 };
    BYTE d[16];
    EXPECT_NS(((csx_hashpw_fn)c->HashPassword)(&up, &us, 3, d), 0);
    CHECK(!memcmp(a, d, 16));   /* trailing characters beyond Length are ignored */
}

TEST(ckaes_s2k_iterations_is_the_pbkdf2_count) {
    CK_NEED(CDLocateCSystem);
    BYTE a[16], b[16], c[16];
    char p[64] = {0}, s[64] = {0};
    for (int i = 0; i < 8; i++) sprintf(p + 4 * i, "%02x00", "password"[i]);
    for (int i = 0; i < 4; i++) sprintf(s + 4 * i, "%02x00", "salt"[i]);
    EXPECT_NS(s2k_run(ET_AES128, p, s, 5, a, 16), 0);
    EXPECT_NS(s2k_run(ET_AES128, p, s, 5, b, 16), 0);
    EXPECT_NS(s2k_run(ET_AES128, p, s, 6, c, 16), 0);
    CHECK(!memcmp(a, b, 16)); CHECK(memcmp(a, c, 16));
}

TEST(ckaes_s2k_aes128_differs_from_aes256_prefix) {
    CK_NEED(CDLocateCSystem);
    BYTE a[16], b[32];
    char p[64] = {0}, s[64] = {0};
    for (int i = 0; i < 8; i++) sprintf(p + 4 * i, "%02x00", "password"[i]);
    for (int i = 0; i < 4; i++) sprintf(s + 4 * i, "%02x00", "salt"[i]);
    EXPECT_NS(s2k_run(ET_AES128, p, s, 3, a, 16), 0);
    EXPECT_NS(s2k_run(ET_AES256, p, s, 3, b, 32), 0);
    CHECK(memcmp(a, b, 16));   /* the derivation depends on the key length through PBKDF2's output size */
}

/* ---- random key / initialize / finish / control ---------------------------------------------------------- */
TEST(ckaes_randomkey_seed_protocol) {
    CK_NEED(CDLocateCSystem);
    const CSX *a = ck_cs(ET_AES128), *b = ck_cs(ET_AES256);
    CHECK(a && b);
    if (!(a && b)) return;
    BYTE seed[40], key[40];
    for (int i = 0; i < 40; i++) seed[i] = (BYTE)(0x30 + i);
    memset(key, 0, 40);
    EXPECT_NS(((csx_rndkey_fn)a->RandomKey)(seed, 16, key), 0);
    CHECK(!memcmp(key, seed, 16));
    for (int i = 16; i < 40; i++) CHECKF(key[i] == 0, "overrun %d", i);
    memset(key, 0, 40);
    EXPECT_NS(((csx_rndkey_fn)b->RandomKey)(seed, 32, key), 0);
    CHECK(!memcmp(key, seed, 32));
    for (int i = 32; i < 40; i++) CHECKF(key[i] == 0, "overrun %d", i);
    static const ULONG bad[] = { 1, 8, 15, 17, 24, 32, 33, 64 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) EXPECT_NS(((csx_rndkey_fn)a->RandomKey)(seed, bad[i], key), NS_NOT_SUPPORTED);
    static const ULONG bad2[] = { 1, 16, 31, 33, 48 };
    for (size_t i = 0; i < sizeof bad2 / sizeof bad2[0]; i++) EXPECT_NS(((csx_rndkey_fn)b->RandomKey)(seed, bad2[i], key), NS_NOT_SUPPORTED);
}

TEST(ckaes_randomkey_zero_seed_generates_random_key) {
    CK_NEED(CDLocateCSystem);
    const CSX *a = ck_cs(ET_AES128), *b = ck_cs(ET_AES256);
    CHECK(a && b);
    if (!(a && b)) return;
    BYTE k1[40], k2[40]; memset(k1, 0, 40); memset(k2, 0, 40);
    EXPECT_NS(((csx_rndkey_fn)a->RandomKey)(NULL, 0, k1), 0);
    EXPECT_NS(((csx_rndkey_fn)a->RandomKey)(NULL, 0, k2), 0);
    CHECK(memcmp(k1, k2, 16));
    for (int i = 16; i < 40; i++) CHECK(k1[i] == 0 && k2[i] == 0);
    memset(k1, 0, 40); memset(k2, 0, 40);
    EXPECT_NS(((csx_rndkey_fn)b->RandomKey)(NULL, 0, k1), 0);
    EXPECT_NS(((csx_rndkey_fn)b->RandomKey)(NULL, 0, k2), 0);
    CHECK(memcmp(k1, k2, 32));
    for (int i = 32; i < 40; i++) CHECK(k1[i] == 0 && k2[i] == 0);
}

TEST(ckaes_initialize_key_sizes) {
    CK_NEED(CDLocateCSystem);
    static const LONG ets[] = { ET_AES128, ET_AES256 };
    for (size_t e = 0; e < 2; e++) {
        const CSX *c = ck_cs(ets[e]);
        CHECK(c != NULL);
        if (!c) continue;
        BYTE key[64]; for (int i = 0; i < 64; i++) key[i] = (BYTE)i;
        static const ULONG good[] = { 16, 32 };
        for (size_t i = 0; i < 2; i++) {
            PVOID st = NULL;
            EXPECT_NS(((csx_init_fn)c->Initialize)(key, good[i], 1, &st), 0);
            CHECKF(st != NULL, "etype %ld key %lu", (long)ets[e], (unsigned long)good[i]);
            EXPECT_NS(((csx_fin_fn)c->Finish)(&st), 0);
            CHECK(st == NULL);
        }
        static const ULONG bad[] = { 0, 1, 8, 15, 17, 24, 31, 33, 48, 64 };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            PVOID st = (PVOID)(ULONG_PTR)0x1111;
            EXPECT_NS(((csx_init_fn)c->Initialize)(key, bad[i], 1, &st), NS_INVALID_PARAM);
            CHECKF(st == NULL, "state must be cleared for key size %lu", (unsigned long)bad[i]);
        }
    }
}

TEST(ckaes_finish_is_idempotent) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_AES128);
    CHECK(c != NULL);
    if (!c) return;
    PVOID st = NULL;
    EXPECT_NS(((csx_fin_fn)c->Finish)(&st), 0);
    BYTE key[16] = {1};
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 16, 1, &st), 0);
    EXPECT_NS(((csx_fin_fn)c->Finish)(&st), 0);
    CHECK(st == NULL);
    EXPECT_NS(((csx_fin_fn)c->Finish)(&st), 0);
}

TEST(ckaes_control_is_unsupported) {
    CK_NEED(CDLocateCSystem);
    const CSX *a = ck_cs(ET_AES128), *b = ck_cs(ET_AES256);
    CHECK(a && b);
    if (!(a && b)) return;
    BYTE key[16] = {1}, data[8] = {0}; PVOID st = NULL;
    EXPECT_NS(((csx_init_fn)a->Initialize)(key, 16, 1, &st), 0);
    for (ULONG f = 0; f < 4; f++) { EXPECT_NS(((csx_ctl_fn)a->Control)(f, st, data, 8), NS_NOT_SUPPORTED); EXPECT_NS(((csx_ctl_fn)b->Control)(f, st, data, 8), NS_NOT_SUPPORTED); }
    ((csx_fin_fn)a->Finish)(&st);
}

/* ---- encrypt / decrypt ------------------------------------------------------------------------------------ */
TEST(ckaes_decrypt_known_answers) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_AESENC_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_aesenc_kat[i].key, &kl), *p = ck_hexa(ck_aesenc_kat[i].plain, &pl), *ct = ck_hexa(ck_aesenc_kat[i].ct, &cl);
        BYTE out[256]; ULONG ol = (ULONG)cl;
        NTSTATUS st = ck_cs_decrypt((LONG)ck_aesenc_kat[i].etype, k, (ULONG)kl, ck_aesenc_kat[i].usage, ct, (ULONG)cl, out, &ol);
        CHECKF(st == 0 && ol == pl && !memcmp(out, p, pl), "row %zu etype %u usage %u plen %zu st=0x%08lx outlen %lu", i, ck_aesenc_kat[i].etype, ck_aesenc_kat[i].usage, pl, (unsigned long)st, (unsigned long)ol);
        free(k); free(p); free(ct);
    }
}

CHILD(ck_aes_encrypt_kat) {
    CC(ck_install_seq_rng(0xa0));
    for (size_t i = 0; i < CK_AESENC_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_aesenc_kat[i].key, &kl), *p = ck_hexa(ck_aesenc_kat[i].plain, &pl), *ct = ck_hexa(ck_aesenc_kat[i].ct, &cl);
        BYTE out[256]; ULONG ol = (ULONG)cl + 20;
        memset(out, 0xEE, sizeof out);
        NTSTATUS st = ck_cs_encrypt((LONG)ck_aesenc_kat[i].etype, k, (ULONG)kl, ck_aesenc_kat[i].usage, p, (ULONG)pl, out, &ol);
        if (st != 0 || ol != cl || memcmp(out, ct, cl)) { printf("encrypt row %zu failed st=0x%08lx outlen=%lu want %zu\n", i, (unsigned long)st, (unsigned long)ol, cl); return __LINE__; }
        free(k); free(p); free(ct);
    }
    return 0;
}
TEST(ckaes_encrypt_known_answers_with_fixed_confounder) {
    CK_NEED(CDRegisterRng);
    DWORD ec = t_run_child("ck_aes_encrypt_kat", "", 30000);
    t_check(ec == 0, __FILE__, __LINE__, "child exit 0", "exit code %lu", (unsigned long)ec);
}

TEST(ckaes_encrypt_decrypt_roundtrip) {
    CK_NEED(CDLocateCSystem);
    static const struct { LONG et; ULONG kl; } c[] = { {ET_AES128, 16}, {ET_AES256, 32}, {ET_AES128, 32}, {ET_AES256, 16} };
    BYTE key[32]; for (int i = 0; i < 32; i++) key[i] = (BYTE)(0x90 + i);
    for (size_t t = 0; t < 4; t++) for (ULONG n = 0; n <= 70; n++) {
        BYTE pt[80], ct[160], back[160];
        for (ULONG i = 0; i < n; i++) pt[i] = (BYTE)(i ^ n);
        ULONG cl = n + 28 + 4;
        EXPECT_NS(ck_cs_encrypt(c[t].et, key, c[t].kl, 5, pt, n, ct, &cl), 0);
        CHECKF(cl == n + 28, "cipher length %lu for %lu", (unsigned long)cl, (unsigned long)n);
        ULONG bl = cl;
        EXPECT_NS(ck_cs_decrypt(c[t].et, key, c[t].kl, 5, ct, cl, back, &bl), 0);
        CHECKF(bl == n && !memcmp(back, pt, n), "etype %ld key %lu len %lu", (long)c[t].et, (unsigned long)c[t].kl, (unsigned long)n);
    }
}

TEST(ckaes_encrypt_is_randomized_by_confounder) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {3}, pt[10] = "plaintext", a[64], b[64]; ULONG la = 64, lb = 64;
    EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 16, 1, pt, 10, a, &la), 0);
    EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 16, 1, pt, 10, b, &lb), 0);
    CHECK(la == lb && memcmp(a, b, la));
}

TEST(ckaes_encrypt_output_size_check_quirk) {
    CK_NEED(CDLocateCSystem);
    /* only confounder+plaintext (n+16) must fit according to the entry check even though n+28 bytes are produced:
       the buffer here is large enough, the declared size is not consulted for the 12-byte checksum */
    BYTE key[16] = {4}, pt[20] = {0}, out[128]; 
    for (ULONG n = 0; n <= 20; n++) {
        ULONG ol = n + 15;
        EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 16, 1, pt, n, out, &ol), NS_INVALID_PARAM);
        ol = n + 16;
        memset(out, 0, sizeof out);
        EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 16, 1, pt, n, out, &ol), 0);
        CHECKF(ol == n + 28, "n=%lu reported %lu", (unsigned long)n, (unsigned long)ol);
    }
}

TEST(ckaes_decrypt_input_and_output_size_checks) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {5}, pt[10] = "abcdefghi", ct[64], out[64]; ULONG cl = 64;
    EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 16, 2, pt, 10, ct, &cl), 0);
    for (ULONG n = 0; n < 28; n++) { ULONG ol = 64; EXPECT_NS(ck_cs_decrypt(ET_AES128, key, 16, 2, ct, n, out, &ol), NS_INVALID_PARAM); }
    ULONG ol = cl - 13;
    EXPECT_NS(ck_cs_decrypt(ET_AES128, key, 16, 2, ct, cl, out, &ol), NS_INVALID_PARAM);
    memset(out, 0, sizeof out);
    ol = cl - 12;                                   /* room for confounder + plaintext is enough */
    EXPECT_NS(ck_cs_decrypt(ET_AES128, key, 16, 2, ct, cl, out, &ol), 0);
    CHECK(ol == 10 && !memcmp(out, pt, 10));
}

TEST(ckaes_decrypt_detects_tampering_anywhere) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {6}, pt[40], ct[96], out[96]; ULONG cl = 96;
    for (int i = 0; i < 40; i++) pt[i] = (BYTE)i;
    EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 16, 2, pt, 40, ct, &cl), 0);
    for (ULONG pos = 0; pos < cl; pos++) {
        BYTE bad[96]; memcpy(bad, ct, cl); bad[pos] ^= 0x01;
        ULONG ol = cl;
        NTSTATUS st = ck_cs_decrypt(ET_AES128, key, 16, 2, bad, cl, out, &ol);
        CHECKF(st == NS_MSG_ALTERED, "flip at %lu -> 0x%08lx", (unsigned long)pos, (unsigned long)st);
    }
}

TEST(ckaes_decrypt_rejects_wrong_usage_and_key) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {7}, key2[16] = {8}, pt[12] = "hello world", ct[64], out[64]; ULONG cl = 64, ol;
    EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 16, 3, pt, 12, ct, &cl), 0);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_AES128, key, 16, 3, ct, cl, out, &ol), 0);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_AES128, key, 16, 4, ct, cl, out, &ol), NS_MSG_ALTERED);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_AES128, key2, 16, 3, ct, cl, out, &ol), NS_MSG_ALTERED);
}

TEST(ckaes_usage_separates_keys) {
    CK_NEED(CDLocateCSystem);
    /* same key, plaintext and usage numbers differing by one bit are not interchangeable */
    BYTE key[32] = {9}, pt[16] = "0123456789abcde", ct[80], out[80]; ULONG cl = 80, ol;
    EXPECT_NS(ck_cs_encrypt(ET_AES256, key, 32, 0x100, pt, 16, ct, &cl), 0);
    static const ULONG other[] = { 0, 0x101, 0x1000000, 0x200, 0xFFFFFFFF };
    for (size_t i = 0; i < 5; i++) { ol = cl; EXPECT_NS(ck_cs_decrypt(ET_AES256, key, 32, other[i], ct, cl, out, &ol), NS_MSG_ALTERED); }
}

TEST(ckaes_aes128_and_aes256_key_sizes_cross_use) {
    CK_NEED(CDLocateCSystem);
    /* etype 17 and 18 share their code: the AES variant follows the key length, not the etype */
    BYTE key[32]; for (int i = 0; i < 32; i++) key[i] = (BYTE)(i + 50);
    BYTE pt[9] = "crossing", ct[64], out[64]; ULONG cl = 64, ol;
    EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 32, 1, pt, 9, ct, &cl), 0);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_AES256, key, 32, 1, ct, cl, out, &ol), 0);
    CHECK(ol == 9 && !memcmp(out, pt, 9));
}

TEST(ckaes_decrypt_output_is_decrypted_in_place_buffer_independent) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {10}, pt[33], ct[96], out[96]; ULONG cl = 96, ol;
    for (int i = 0; i < 33; i++) pt[i] = (BYTE)(255 - i);
    EXPECT_NS(ck_cs_encrypt(ET_AES128, key, 16, 9, pt, 33, ct, &cl), 0);
    BYTE keep[96]; memcpy(keep, ct, cl);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_AES128, key, 16, 9, ct, cl, out, &ol), 0);
    CHECK(!memcmp(keep, ct, cl));   /* the input buffer is not modified */
}

/* ---- PRF+ and KRB-FX-CF2 ---------------------------------------------------------------------------------- */
TEST(ckaes_prfplus_known_answers) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_PRFP_KAT_N; i++) {
        const CSX *c = ck_cs((LONG)ck_prfp_kat[i].etype);
        CHECK(c != NULL && c->PrfPlus != NULL);
        if (!c || !c->PrfPlus) continue;
        size_t kl, sl; BYTE *k = ck_hexa(ck_prfp_kat[i].key, &kl), *s = ck_hexa(ck_prfp_kat[i].s, &sl);
        BYTE out[128]; BYTE dummy = 0; memset(out, 0xEE, sizeof out);
        NTSTATUS st = ((csx_prf_fn)c->PrfPlus)(k, (ULONG)kl, sl ? s : &dummy, (ULONG)sl, out, ck_prfp_kat[i].n);
        CHECKF(st == 0 && ck_eqhex(out, ck_prfp_kat[i].n, ck_prfp_kat[i].out), "row %zu etype %u n %u st=0x%08lx", i, ck_prfp_kat[i].etype, ck_prfp_kat[i].n, (unsigned long)st);
        for (ULONG j = ck_prfp_kat[i].n; j < 128; j++) CHECKF(out[j] == 0xEE, "row %zu overrun at %lu", i, (unsigned long)j);
        free(k); free(s);
    }
}

TEST(ckaes_krbfxcf2_rfc6113_sample) {
    CK_NEED(KRBFXCF2);
    /* RFC 6113 section 5.1 / test vectors: keys from string-to-key("key1","key1") and ("key2","key2"), 4096 iterations,
       pepper strings "a" and "b" */
    for (size_t i = 0; i < CK_CF2_KAT_N; i++) {
        size_t l1, l2, pl1, pl2, ol; BYTE *k1 = ck_hexa(ck_cf2_kat[i].k1, &l1), *k2 = ck_hexa(ck_cf2_kat[i].k2, &l2);
        BYTE *p1 = ck_hexa(ck_cf2_kat[i].p1, &pl1), *p2 = ck_hexa(ck_cf2_kat[i].p2, &pl2), *want = ck_hexa(ck_cf2_kat[i].out, &ol);
        BYTE out[64], dummy = 0; memset(out, 0xEE, sizeof out);
        NTSTATUS st = CKP(KRBFXCF2)(ck_cf2_kat[i].e1, k1, (ULONG)l1, pl1 ? p1 : &dummy, (ULONG)pl1, ck_cf2_kat[i].e2, k2, (ULONG)l2, pl2 ? p2 : &dummy, (ULONG)pl2, out);
        CHECKF(st == 0 && !memcmp(out, want, ol), "row %zu etypes %u/%u st=0x%08lx", i, ck_cf2_kat[i].e1, ck_cf2_kat[i].e2, (unsigned long)st);
        for (size_t j = ol; j < 64; j++) CHECKF(out[j] == 0xEE, "row %zu overrun", i);
        free(k1); free(k2); free(p1); free(p2); free(want);
    }
}

TEST(ckaes_krbfxcf2_published_aes_values) {
    CK_NEED(KRBFXCF2);
    /* the published AES samples: string-to-key keys are derived through this DLL itself */
    static const char *p1 = "6b00650079003100", *s1 = "6b00650079003100", *p2 = "6b00650079003200", *s2 = "6b00650079003200";
    static const struct { LONG et; ULONG kl; const char *want; } v[] = {
        { ET_AES128, 16, "97df97e4b798b29eb31ed7280287a92a" },
        { ET_AES256, 32, "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b" } };
    for (size_t i = 0; i < 2; i++) {
        BYTE k1[32], k2[32], out[32];
        EXPECT_NS(s2k_run(v[i].et, p1, s1, 4096, k1, v[i].kl), 0);
        EXPECT_NS(s2k_run(v[i].et, p2, s2, 4096, k2, v[i].kl), 0);
        EXPECT_NS(CKP(KRBFXCF2)(v[i].et, k1, v[i].kl, (PUCHAR)"a", 1, v[i].et, k2, v[i].kl, (PUCHAR)"b", 1, out), 0);
        CHECKF(ck_eqhex(out, v[i].kl, v[i].want), "etype %ld", (long)v[i].et);
    }
}

TEST(ckaes_krbfxcf2_errors) {
    CK_NEED(KRBFXCF2);
    BYTE k[32] = {1}, out[32] = {0};
    EXPECT_NS(CKP(KRBFXCF2)(0x1234, k, 16, (PUCHAR)"a", 1, ET_AES128, k, 16, (PUCHAR)"b", 1, out), NS_NO_CSYSTEM);
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES128, k, 16, (PUCHAR)"a", 1, 0x1234, k, 16, (PUCHAR)"b", 1, out), NS_NO_CSYSTEM);
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES128, k, 32, (PUCHAR)"a", 1, ET_AES128, k, 16, (PUCHAR)"b", 1, out), NS_INVALID_PARAM);
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES128, k, 16, (PUCHAR)"a", 1, ET_AES128, k, 32, (PUCHAR)"b", 1, out), NS_INVALID_PARAM);
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES256, k, 16, (PUCHAR)"a", 1, ET_AES128, k, 16, (PUCHAR)"b", 1, out), NS_INVALID_PARAM);
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES128, k, 16, (PUCHAR)"a", 1, ET_AES256, k, 16, (PUCHAR)"b", 1, out), NS_INVALID_PARAM);
}

TEST(ckaes_krbfxcf2_output_is_symmetric_in_swap_of_pairs) {
    CK_NEED(KRBFXCF2);
    BYTE k1[16], k2[16], a[16], b[16];
    for (int i = 0; i < 16; i++) { k1[i] = (BYTE)i; k2[i] = (BYTE)(i * 3 + 1); }
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES128, k1, 16, (PUCHAR)"x", 1, ET_AES128, k2, 16, (PUCHAR)"y", 1, a), 0);
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES128, k2, 16, (PUCHAR)"y", 1, ET_AES128, k1, 16, (PUCHAR)"x", 1, b), 0);
    CHECK(!memcmp(a, b, 16));      /* XOR is commutative */
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES128, k1, 16, (PUCHAR)"x", 1, ET_AES128, k2, 16, (PUCHAR)"x", 1, b), 0);
    CHECK(memcmp(a, b, 16));
}

TEST(ckaes_krbfxcf2_same_input_gives_zero_mask) {
    CK_NEED(KRBFXCF2);
    BYTE k[16], out[16];
    for (int i = 0; i < 16; i++) k[i] = (BYTE)(i + 7);
    EXPECT_NS(CKP(KRBFXCF2)(ET_AES128, k, 16, (PUCHAR)"p", 1, ET_AES128, k, 16, (PUCHAR)"p", 1, out), 0);
    for (int i = 0; i < 16; i++) CHECKF(out[i] == 0, "byte %d", i);
}

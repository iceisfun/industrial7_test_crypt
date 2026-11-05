/* RC4-HMAC (RFC 4757), the older RC4 variants, RC4-MD4 and the DES crypto systems of cryptdll. */
#include "ck.h"
#include "ck_vec.h"

static void le32(ULONG v, BYTE out[4]) { out[0] = (BYTE)v; out[1] = (BYTE)(v >> 8); out[2] = (BYTE)(v >> 16); out[3] = (BYTE)(v >> 24); }

/* ---- NT hash (HashPassword of the RC4 systems) ------------------------------------------------------------- */
static NTSTATUS nthash(LONG et, const char *pw16, BYTE *out) {
    const CSX *c = ck_cs(et);
    if (!c) return NS_NO_CSYSTEM;
    USHORT pl; WCHAR *pw = ck_wide(pw16, &pl);
    UNICODE_STRING up = { pl, (USHORT)(pl + 2), pw };
    BYTE buf[40]; memset(buf, 0xEE, sizeof buf);
    NTSTATUS st = ((csx_hashpw_fn)c->HashPassword)(&up, NULL, 0, buf);
    memcpy(out, buf, 16);
    for (int i = 16; i < 40; i++) if (buf[i] != 0xEE) { t_check(0, __FILE__, __LINE__, "nthash overrun", "byte %d", i); break; }
    free(pw);
    return st;
}

TEST(ckrc4_hashpassword_is_nt_hash) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_NT_KAT_N; i++) {
        BYTE h[16];
        EXPECT_NS(nthash(ET_RC4_HMAC, ck_nt_kat[i].pw, h), 0);
        CHECKF(ck_eqhex(h, 16, ck_nt_kat[i].hash), "row %zu", i);
    }
}

TEST(ckrc4_hashpassword_known_nt_hashes) {
    CK_NEED(CDLocateCSystem);
    BYTE h[16];
    EXPECT_NS(nthash(ET_RC4_HMAC, "700061007300730077006f0072006400", h), 0);
    CHECK(ck_eqhex(h, 16, "8846f7eaee8fb117ad06bdd830b7586c"));
    EXPECT_NS(nthash(ET_RC4_HMAC, "", h), 0);
    CHECK(ck_eqhex(h, 16, "31d6cfe0d16ae931b73c59d7e0c089c0"));
}

TEST(ckrc4_hashpassword_shared_by_md4_variant) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_NT_KAT_N; i++) {
        BYTE h[16];
        EXPECT_NS(nthash(ET_RC4_MD4, ck_nt_kat[i].pw, h), 0);
        CHECKF(ck_eqhex(h, 16, ck_nt_kat[i].hash), "row %zu", i);
    }
}

TEST(ckrc4_hashpassword_ignores_salt_and_count) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_HMAC);
    CHECK(c != NULL);
    if (!c) return;
    WCHAR pw[] = { 'p','a','s','s','w','o','r','d' }, sa[] = { 's','a','l','t' };
    UNICODE_STRING up = { 16, 16, pw }, us = { 8, 8, sa };
    BYTE a[16], b[16];
    EXPECT_NS(((csx_hashpw_fn)c->HashPassword)(&up, &us, 4096, a), 0);
    EXPECT_NS(((csx_hashpw_fn)c->HashPassword)(&up, NULL, 0, b), 0);
    CHECK(!memcmp(a, b, 16));
    CHECK(ck_eqhex(a, 16, "8846f7eaee8fb117ad06bdd830b7586c"));
}

/* ---- RC4-HMAC random key ----------------------------------------------------------------------------------- */
TEST(ckrc4_randomkey_protocol) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_HMAC);
    CHECK(c != NULL);
    if (!c) return;
    BYTE seed[32], k1[32], k2[32]; for (int i = 0; i < 32; i++) seed[i] = (BYTE)(0x20 + i);
    memset(k1, 0, 32); memset(k2, 0, 32);
    EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(seed, 16, k1), 0);
    CHECK(!memcmp(k1, seed, 16));
    for (int i = 16; i < 32; i++) CHECK(k1[i] == 0);
    static const ULONG bad[] = { 1, 8, 15, 17, 32 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(seed, bad[i], k1), NS_NOT_SUPPORTED);
    memset(k1, 0, 32);
    EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(NULL, 0, k1), 0);
    EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(NULL, 0, k2), 0);
    CHECK(memcmp(k1, k2, 16));
    for (int i = 16; i < 32; i++) CHECK(k1[i] == 0 && k2[i] == 0);
}

/* ---- RC4-HMAC encrypt / decrypt ---------------------------------------------------------------------------- */
TEST(ckrc4h_decrypt_known_answers) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_RC4H_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_rc4h_kat[i].key, &kl), *p = ck_hexa(ck_rc4h_kat[i].plain, &pl), *ct = ck_hexa(ck_rc4h_kat[i].ct, &cl);
        BYTE out[128]; ULONG ol = (ULONG)cl;
        NTSTATUS st = ck_cs_decrypt(ET_RC4_HMAC, k, (ULONG)kl, ck_rc4h_kat[i].usage, ct, (ULONG)cl, out, &ol);
        CHECKF(st == 0 && ol == pl && !memcmp(out, p, pl), "row %zu usage %u plen %zu st=0x%08lx outlen %lu", i, ck_rc4h_kat[i].usage, pl, (unsigned long)st, (unsigned long)ol);
        free(k); free(p); free(ct);
    }
}

CHILD(ck_rc4h_encrypt_kat) {
    CC(ck_install_seq_rng(0x10));
    for (size_t i = 0; i < CK_RC4H_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_rc4h_kat[i].key, &kl), *p = ck_hexa(ck_rc4h_kat[i].plain, &pl), *ct = ck_hexa(ck_rc4h_kat[i].ct, &cl);
        BYTE out[160]; ULONG ol = (ULONG)cl;
        memset(out, 0xEE, sizeof out);
        NTSTATUS st = ck_cs_encrypt(ET_RC4_HMAC, k, (ULONG)kl, ck_rc4h_kat[i].usage, p, (ULONG)pl, out, &ol);
        if (st != 0 || ol != cl || memcmp(out, ct, cl)) { printf("rc4h row %zu failed st=0x%08lx outlen=%lu\n", i, (unsigned long)st, (unsigned long)ol); return __LINE__; }
        free(k); free(p); free(ct);
    }
    for (size_t i = 0; i < CK_RC4OLD_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_rc4old_kat[i].key, &kl), *p = ck_hexa(ck_rc4old_kat[i].plain, &pl), *ct = ck_hexa(ck_rc4old_kat[i].ct, &cl);
        BYTE out[160]; ULONG ol = (ULONG)cl;
        NTSTATUS st = ck_cs_encrypt(ET_RC4_HMAC_OLD, k, (ULONG)kl, ck_rc4old_kat[i].usage, p, (ULONG)pl, out, &ol);
        if (st != 0 || ol != cl || memcmp(out, ct, cl)) { printf("rc4 old row %zu failed st=0x%08lx outlen=%lu\n", i, (unsigned long)st, (unsigned long)ol); return __LINE__; }
        free(k); free(p); free(ct);
    }
    return 0;
}
TEST(ckrc4h_encrypt_known_answers_with_fixed_confounder) {
    CK_NEED(CDRegisterRng);
    DWORD ec = t_run_child("ck_rc4h_encrypt_kat", "", 30000);
    t_check(ec == 0, __FILE__, __LINE__, "child exit 0", "exit code %lu", (unsigned long)ec);
}

TEST(ckrc4h_encrypt_structure_verified_by_independent_model) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16]; memcpy(key, "\x88\x46\xf7\xea\xee\x8f\xb1\x17\xad\x06\xbd\xd8\x30\xb7\x58\x6c", 16);
    for (ULONG n = 0; n <= 40; n += 3) for (ULONG usage = 0; usage <= 8; usage += 4) {
        BYTE pt[64], ct[128]; for (ULONG i = 0; i < n; i++) pt[i] = (BYTE)(i * 3 + n);
        ULONG cl = 128;
        EXPECT_NS(ck_cs_encrypt(ET_RC4_HMAC, key, 16, usage, pt, n, ct, &cl), 0);
        CHECKF(cl == n + 24, "length %lu", (unsigned long)cl);
        BYTE u[4], k1[16], k3[16], dec[80], chk[16];
        le32(usage, u);
        ck_hmac_md5(key, 16, u, 4, NULL, 0, k1);
        ck_hmac_md5(k1, 16, ct, 16, NULL, 0, k3);               /* K3 = HMAC(K1, checksum) */
        memcpy(dec, ct + 16, n + 8);
        ck_rc4(k3, 16, dec, n + 8);                              /* confounder || plaintext */
        ck_hmac_md5(k1, 16, dec, n + 8, NULL, 0, chk);           /* checksum = HMAC(K1, confounder||plaintext) */
        CHECKF(!memcmp(chk, ct, 16), "n=%lu usage=%lu checksum", (unsigned long)n, (unsigned long)usage);
        CHECKF(n == 0 || !memcmp(dec + 8, pt, n), "n=%lu usage=%lu plaintext", (unsigned long)n, (unsigned long)usage);
    }
}

TEST(ckrc4h_encrypt_decrypt_roundtrip) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(i + 1);
    for (ULONG n = 0; n <= 100; n++) {
        BYTE pt[128], ct[160], back[160];
        for (ULONG i = 0; i < n; i++) pt[i] = (BYTE)(i * 11);
        ULONG cl = 160, bl;
        EXPECT_NS(ck_cs_encrypt(ET_RC4_HMAC, key, 16, 7, pt, n, ct, &cl), 0);
        bl = cl;
        EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC, key, 16, 7, ct, cl, back, &bl), 0);
        CHECKF(bl == n && !memcmp(back, pt, n), "len %lu", (unsigned long)n);
    }
}

TEST(ckrc4h_encrypt_ignores_declared_output_size) {
    CK_NEED(CDLocateCSystem);
    /* unlike AES/DES, the RC4-HMAC encrypt routine never reads *OutputLength: it only stores the produced size */
    BYTE key[16] = {1}, pt[8] = "payload", ct[64]; ULONG cl = 0;
    EXPECT_NS(ck_cs_encrypt(ET_RC4_HMAC, key, 16, 1, pt, 8, ct, &cl), 0);
    EXPECT_EQ(cl, 32);
}

TEST(ckrc4h_decrypt_detects_tampering) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {2}, pt[30], ct[64], out[64]; ULONG cl = 64;
    for (int i = 0; i < 30; i++) pt[i] = (BYTE)i;
    EXPECT_NS(ck_cs_encrypt(ET_RC4_HMAC, key, 16, 3, pt, 30, ct, &cl), 0);
    for (ULONG pos = 0; pos < cl; pos++) {
        BYTE bad[64]; memcpy(bad, ct, cl); bad[pos] ^= 0x80;
        ULONG ol = cl;
        NTSTATUS st = ck_cs_decrypt(ET_RC4_HMAC, key, 16, 3, bad, cl, out, &ol);
        CHECKF(st == NS_UNSUCCESSFUL, "flip at %lu -> 0x%08lx", (unsigned long)pos, (unsigned long)st);
    }
}

TEST(ckrc4h_decrypt_wrong_key_or_usage) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {2}, key2[16] = {3}, pt[5] = "abcd", ct[64], out[64]; ULONG cl = 64, ol;
    EXPECT_NS(ck_cs_encrypt(ET_RC4_HMAC, key, 16, 3, pt, 5, ct, &cl), 0);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC, key2, 16, 3, ct, cl, out, &ol), NS_UNSUCCESSFUL);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC, key, 16, 4, ct, cl, out, &ol), NS_UNSUCCESSFUL);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC, key, 16, 3, ct, cl, out, &ol), 0);
}

TEST(ckrc4h_decrypt_short_input) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {2}, in[32] = {0}, out[32];
    for (ULONG n = 0; n < 24; n++) { ULONG ol = 32; EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC, key, 16, 1, in, n, out, &ol), NS_INVALID_PARAM); }
}

TEST(ckrc4h_key_longer_than_64_bytes_is_truncated) {
    CK_NEED(CDLocateCSystem);
    /* the HMAC-MD5 helper copies at most 64 key bytes and does not hash longer keys first */
    BYTE k80[80], pt[7] = "secret", ct[64], out[64]; ULONG cl = 64, ol;
    for (int i = 0; i < 80; i++) k80[i] = (BYTE)(i * 3 + 1);
    EXPECT_NS(ck_cs_encrypt(ET_RC4_HMAC, k80, 64, 1, pt, 7, ct, &cl), 0);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC, k80, 80, 1, ct, cl, out, &ol), 0);
    CHECK(ol == 7 && !memcmp(out, pt, 7));
    BYTE k81[81]; memcpy(k81, k80, 80); k81[80] = 0x55;
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC, k81, 81, 1, ct, cl, out, &ol), 0);
}

TEST(ckrc4h_key_zero_padding_equivalence) {
    CK_NEED(CDLocateCSystem);
    BYTE short_key[10], long_key[16] = {0}, pt[5] = "abcd", ct[64], out[64]; ULONG cl = 64, ol;
    for (int i = 0; i < 10; i++) short_key[i] = long_key[i] = (BYTE)(i + 9);
    EXPECT_NS(ck_cs_encrypt(ET_RC4_HMAC, short_key, 10, 1, pt, 5, ct, &cl), 0);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC, long_key, 16, 1, ct, cl, out, &ol), 0);
}

TEST(ckrc4h_control_rekeys_with_hmac) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_HMAC);
    CHECK(c != NULL);
    if (!c) return;
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(i * 7 + 2);
    PVOID st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 16, 5, &st), 0);
    BYTE ctl[5] = "ctrl";
    EXPECT_NS(((csx_ctl_fn)c->Control)(1, st, ctl, 4), 0);
    BYTE pt[12] = "after rekey", ct[64]; ULONG cl = 64;
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st, pt, 12, ct, &cl), 0);
    ((csx_fin_fn)c->Finish)(&st);
    /* independent model: K1' = HMAC(HMAC(key, LE(usage)), "ctrl") */
    BYTE u[4], k1[16], k1b[16], k3[16], dec[24], chk[16];
    le32(5, u);
    ck_hmac_md5(key, 16, u, 4, NULL, 0, k1);
    ck_hmac_md5(k1, 16, ctl, 4, NULL, 0, k1b);
    ck_hmac_md5(k1b, 16, ct, 16, NULL, 0, k3);
    memcpy(dec, ct + 16, 20); ck_rc4(k3, 16, dec, 20);
    ck_hmac_md5(k1b, 16, dec, 20, NULL, 0, chk);
    CHECK(!memcmp(chk, ct, 16));
    CHECK(!memcmp(dec + 8, pt, 12));
    st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 16, 5, &st), 0);
    EXPECT_NS(((csx_ctl_fn)c->Control)(0, st, ctl, 4), NS_INVALID_PARAM);
    EXPECT_NS(((csx_ctl_fn)c->Control)(2, st, ctl, 4), NS_INVALID_PARAM);
    ((csx_fin_fn)c->Finish)(&st);
}

TEST(ckrc4h_finish_clears_state) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_HMAC);
    CHECK(c != NULL);
    if (!c) return;
    BYTE key[16] = {1}; PVOID st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 16, 1, &st), 0);
    CHECK(st != NULL);
    EXPECT_NS(((csx_fin_fn)c->Finish)(&st), 0);
    CHECK(st == NULL);
}

TEST(ckrc4h_states_are_independent) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_HMAC);
    CHECK(c != NULL);
    if (!c) return;
    BYTE k1[16] = {1}, k2[16] = {2}; PVOID a = NULL, b = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(k1, 16, 1, &a), 0);
    EXPECT_NS(((csx_init_fn)c->Initialize)(k2, 16, 1, &b), 0);
    CHECK(a != b);
    BYTE pt[4] = "abc", ca[64], cb[64], out[64]; ULONG la = 64, lb = 64, lo;
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(a, pt, 4, ca, &la), 0);
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(b, pt, 4, cb, &lb), 0);
    lo = la; EXPECT_NS(((csx_crypt_fn)c->Decrypt)(a, ca, la, out, &lo), 0);
    lo = lb; EXPECT_NS(((csx_crypt_fn)c->Decrypt)(b, cb, lb, out, &lo), 0);
    lo = la; EXPECT_NS(((csx_crypt_fn)c->Decrypt)(b, ca, la, out, &lo), NS_UNSUCCESSFUL);
    ((csx_fin_fn)c->Finish)(&a); ((csx_fin_fn)c->Finish)(&b);
}

TEST(ckrc4h_state_is_reusable_across_messages) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_HMAC);
    CHECK(c != NULL);
    if (!c) return;
    BYTE k[16] = {9}; PVOID st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(k, 16, 1, &st), 0);
    for (int i = 0; i < 5; i++) {
        BYTE pt[16], ct[64], out[64]; ULONG cl = 64, ol;
        memset(pt, i, 16);
        EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st, pt, 16, ct, &cl), 0);
        ol = cl; EXPECT_NS(((csx_crypt_fn)c->Decrypt)(st, ct, cl, out, &ol), 0);
        CHECK(ol == 16 && !memcmp(out, pt, 16));
    }
    ((csx_fin_fn)c->Finish)(&st);
}

/* ---- older RC4 variants ------------------------------------------------------------------------------------ */
TEST(ckrc4old_decrypt_known_answers) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_RC4OLD_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_rc4old_kat[i].key, &kl), *p = ck_hexa(ck_rc4old_kat[i].plain, &pl), *ct = ck_hexa(ck_rc4old_kat[i].ct, &cl);
        BYTE out[128]; ULONG ol = (ULONG)cl;
        NTSTATUS st = ck_cs_decrypt(ET_RC4_HMAC_OLD, k, (ULONG)kl, ck_rc4old_kat[i].usage, ct, (ULONG)cl, out, &ol);
        CHECKF(st == 0 && ol == pl && !memcmp(out, p, pl), "row %zu usage %u plen %zu st=0x%08lx", i, ck_rc4old_kat[i].usage, pl, (unsigned long)st);
        free(k); free(p); free(ct);
    }
}

TEST(ckrc4old_tamper_and_short_input) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {2}, pt[20], ct[64], out[64]; ULONG cl = 64;
    for (int i = 0; i < 20; i++) pt[i] = (BYTE)i;
    EXPECT_NS(ck_cs_encrypt(ET_RC4_HMAC_OLD, key, 16, 3, pt, 20, ct, &cl), 0);
    CHECK(cl == 44);
    for (ULONG pos = 0; pos < cl; pos++) {
        BYTE bad[64]; memcpy(bad, ct, cl); bad[pos] ^= 0x04;
        ULONG ol = cl;
        NTSTATUS st = ck_cs_decrypt(ET_RC4_HMAC_OLD, key, 16, 3, bad, cl, out, &ol);
        CHECKF(st == NS_UNSUCCESSFUL, "flip at %lu -> 0x%08lx", (unsigned long)pos, (unsigned long)st);
    }
    for (ULONG n = 0; n < 24; n++) { ULONG ol = 64; EXPECT_NS(ck_cs_decrypt(ET_RC4_HMAC_OLD, key, 16, 3, ct, n, out, &ol), NS_INVALID_PARAM); }
}

TEST(ckrc4old_roundtrip_old_and_exp_variants) {
    CK_NEED(CDLocateCSystem);
    static const LONG ets[] = { ET_RC4_HMAC_OLD, ET_RC4_HMAC_OLD_EXP, ET_RC4_HMAC_EXP };
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(0x40 + i);
    for (size_t e = 0; e < 3; e++) for (ULONG n = 0; n <= 50; n += 5) {
        BYTE pt[64], ct[128], back[128]; for (ULONG i = 0; i < n; i++) pt[i] = (BYTE)(i + e);
        ULONG cl = 128, bl;
        NTSTATUS st = ck_cs_encrypt(ets[e], key, 16, 9, pt, n, ct, &cl);
        if (st) { t_note("etype %ld encrypt -> 0x%08lx", (long)ets[e], (unsigned long)st); break; }
        bl = cl;
        EXPECT_NS(ck_cs_decrypt(ets[e], key, 16, 9, ct, cl, back, &bl), 0);
        CHECKF(bl == n && !memcmp(back, pt, n), "etype %ld len %lu", (long)ets[e], (unsigned long)n);
    }
}

TEST(ckrc4md4_decrypt_known_answers) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_RC4MD4_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_rc4md4_kat[i].key, &kl), *p = ck_hexa(ck_rc4md4_kat[i].plain, &pl), *ct = ck_hexa(ck_rc4md4_kat[i].ct, &cl);
        BYTE out[128]; ULONG ol = (ULONG)cl;
        NTSTATUS st = ck_cs_decrypt(ET_RC4_MD4, k, (ULONG)kl, 0, ct, (ULONG)cl, out, &ol);
        CHECKF(st == 0 && ol == pl && !memcmp(out, p, pl), "row %zu plen %zu st=0x%08lx", i, pl, (unsigned long)st);
        free(k); free(p); free(ct);
    }
}

TEST(ckrc4md4_encrypt_known_answers) {
    CK_NEED(CDLocateCSystem);
    /* RC4-MD4 uses no confounder: the 24-byte header is zero before encryption, so the output is deterministic */
    for (size_t i = 0; i < CK_RC4MD4_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_rc4md4_kat[i].key, &kl), *p = ck_hexa(ck_rc4md4_kat[i].plain, &pl), *ct = ck_hexa(ck_rc4md4_kat[i].ct, &cl);
        BYTE out[128]; ULONG ol = (ULONG)cl;
        NTSTATUS st = ck_cs_encrypt(ET_RC4_MD4, k, (ULONG)kl, 0, p, (ULONG)pl, out, &ol);
        CHECKF(st == 0 && ol == cl && !memcmp(out, ct, cl), "row %zu plen %zu st=0x%08lx", i, pl, (unsigned long)st);
        free(k); free(p); free(ct);
    }
}

TEST(ckrc4md4_buffer_size_protocol) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {1,2,3,4,5,6,7,8}, pt[10] = "123456789", ct[64], out[64];
    ULONG ol = 33;
    EXPECT_NS(ck_cs_encrypt(ET_RC4_MD4, key, 16, 0, pt, 10, ct, &ol), NS_BUF_TOO_SMALL);
    ol = 34;
    EXPECT_NS(ck_cs_encrypt(ET_RC4_MD4, key, 16, 0, pt, 10, ct, &ol), 0);
    EXPECT_EQ(ol, 34);
    ULONG dl = 33;
    EXPECT_NS(ck_cs_decrypt(ET_RC4_MD4, key, 16, 0, ct, 34, out, &dl), NS_BUF_TOO_SMALL);
    EXPECT_EQ(dl, 34);     /* the required size is reported back */
}

TEST(ckrc4md4_header_must_decrypt_to_zero) {
    CK_NEED(CDLocateCSystem);
    BYTE key[16] = {1,2,3,4,5,6,7,8}, pt[10] = "123456789", ct[64], out[64]; ULONG cl = 64, ol;
    EXPECT_NS(ck_cs_encrypt(ET_RC4_MD4, key, 16, 0, pt, 10, ct, &cl), 0);
    for (ULONG pos = 0; pos < 24; pos++) {
        BYTE bad[64]; memcpy(bad, ct, cl); bad[pos] ^= 0x20; ol = cl;
        EXPECT_NS(ck_cs_decrypt(ET_RC4_MD4, key, 16, 0, bad, cl, out, &ol), NS_UNSUCCESSFUL);
    }
    BYTE bad[64]; memcpy(bad, ct, cl); bad[30] ^= 1; ol = cl;
    EXPECT_NS(ck_cs_decrypt(ET_RC4_MD4, key, 16, 0, bad, cl, out, &ol), 0);       /* no integrity protection on the body */
}

TEST(ckrc4md4_short_key_rejected) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_MD4);
    CHECK(c != NULL);
    if (!c) return;
    BYTE key[16] = {1};
    for (ULONG n = 0; n < 8; n++) { PVOID st = NULL; EXPECT_NS(((csx_init_fn)c->Initialize)(key, n, 0, &st), NS_NO_CSYSTEM); }
    PVOID st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st), 0);
    ((csx_fin_fn)c->Finish)(&st);
}

TEST(ckrc4md4_only_first_eight_key_bytes_matter) {
    CK_NEED(CDLocateCSystem);
    BYTE k1[16], k2[16], pt[5] = "abcd", ct[64], out[64]; ULONG cl = 64, ol;
    for (int i = 0; i < 16; i++) { k1[i] = (BYTE)(i + 1); k2[i] = (BYTE)(i < 8 ? i + 1 : 0xEE); }
    EXPECT_NS(ck_cs_encrypt(ET_RC4_MD4, k1, 16, 0, pt, 5, ct, &cl), 0);
    ol = cl; EXPECT_NS(ck_cs_decrypt(ET_RC4_MD4, k2, 16, 0, ct, cl, out, &ol), 0);
    CHECK(ol == 5 && !memcmp(out, pt, 5));
}

TEST(ckrc4md4_keystream_is_cumulative_across_messages) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_MD4);
    CHECK(c != NULL);
    if (!c) return;
    BYTE key[8] = {8,7,6,5,4,3,2,1}; PVOID st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st), 0);
    BYTE m1[4] = "abc", m2[4] = "xyz", c1[64], c2[64]; ULONG l1 = 64, l2 = 64;
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st, m1, 4, c1, &l1), 0);
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st, m2, 4, c2, &l2), 0);
    ((csx_fin_fn)c->Finish)(&st);
    /* model: one RC4 stream over (zeros24 || m1 || zeros24 || m2) */
    BYTE all[56]; memset(all, 0, sizeof all); memcpy(all + 24, m1, 4); memcpy(all + 52, m2, 4);
    ck_rc4(key, 8, all, 56);
    CHECK(l1 == 28 && l2 == 28 && !memcmp(c1, all, 28) && !memcmp(c2, all + 28, 28));
}

TEST(ckrc4md4_control_advances_keystream) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_MD4);
    CHECK(c != NULL);
    if (!c) return;
    BYTE key[8] = {8,7,6,5,4,3,2,1}; PVOID st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st), 0);
    BYTE junk[10] = {0};
    EXPECT_NS(((csx_ctl_fn)c->Control)(1, st, junk, 10), 0);
    EXPECT_NS(((csx_ctl_fn)c->Control)(2, st, junk, 10), NS_INVALID_PARAM);
    EXPECT_NS(((csx_ctl_fn)c->Control)(1, st, junk, 0x81), NS_INVALID_PARAM);
    EXPECT_NS(((csx_ctl_fn)c->Control)(1, st, junk, 0x80), 0);
    BYTE pt[4] = "abc", ct[64]; ULONG cl = 64;
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st, pt, 4, ct, &cl), 0);
    ((csx_fin_fn)c->Finish)(&st);
    BYTE all[10 + 0x80 + 28]; memset(all, 0, sizeof all); memcpy(all + 138 + 24, pt, 4);
    ck_rc4(key, 8, all, sizeof all);
    CHECK(!memcmp(ct, all + 138, 28));
}

TEST(ckrc4md4_randomkey_forty_bit) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_RC4_MD4);
    CHECK(c != NULL);
    if (!c) return;
    BYTE a[16], b[16];
    EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(NULL, 0, a), 0);
    EXPECT_NS(((csx_rndkey_fn)c->RandomKey)((PUCHAR)"ignored seed", 12, b), 0);   /* the seed is not used at all */
    for (int i = 5; i < 16; i++) CHECKF(a[i] == 0xAB && b[i] == 0xAB, "byte %d", i);
    CHECK(memcmp(a, b, 5));
}

/* ---- DES ---------------------------------------------------------------------------------------------------- */
TEST(ckdes_randomkey_known_answers) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_MD5);
    CHECK(c != NULL);
    if (!c) return;
    for (size_t i = 0; i < CK_DESRND_KAT_N; i++) {
        size_t sl, kl; BYTE *s = ck_hexa(ck_desrnd_kat[i].seed, &sl), *want = ck_hexa(ck_desrnd_kat[i].key, &kl);
        BYTE out[16]; memset(out, 0, sizeof out);
        EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(s, 8, out), 0);
        CHECKF(!memcmp(out, want, 8), "seed %s", ck_desrnd_kat[i].seed);
        for (int j = 8; j < 16; j++) CHECK(out[j] == 0);
        free(s); free(want);
    }
}

TEST(ckdes_randomkey_weak_key_seed_forced_away) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_CRC);
    CHECK(c != NULL);
    if (!c) return;
    BYTE seed[8] = {0}, out[8];
    EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(seed, 8, out), 0);
    CHECK(ck_eqhex(out, 8, "01010101010101f1"));
    memset(seed, 0xFF, 8);
    EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(seed, 8, out), 0);
    CHECK(ck_eqhex(out, 8, "fefefefefefefe0e"));
}

TEST(ckdes_randomkey_has_odd_parity) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_MD5);
    CHECK(c != NULL);
    if (!c) return;
    for (int t = 0; t < 40; t++) {
        BYTE seed[8], out[8];
        for (int i = 0; i < 8; i++) seed[i] = (BYTE)(t * 37 + i * 91 + 5);
        EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(seed, 8, out), 0);
        for (int i = 0; i < 7; i++) CHECKF(__builtin_parity(out[i]) == 1, "seed %d byte %d", t, i);
    }
    for (int t = 0; t < 20; t++) {
        BYTE out[8];
        EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(NULL, 0, out), 0);
        for (int i = 0; i < 8; i++) CHECKF(__builtin_parity(out[i]) == 1, "random key %d byte %d", t, i);
    }
}

TEST(ckdes_randomkey_seed_length_protocol) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_MD5);
    CHECK(c != NULL);
    if (!c) return;
    BYTE seed[16] = {1,2,3,4,5,6,7,8,9}, out[16];
    static const ULONG bad[] = { 1, 7, 9, 16 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) EXPECT_NS(((csx_rndkey_fn)c->RandomKey)(seed, bad[i], out), NS_NOT_SUPPORTED);
}

TEST(ckdes_hashpassword_rfc3961_vectors) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_MD5);
    CHECK(c != NULL);
    if (!c) return;
    for (size_t i = 0; i < CK_DESP_KAT_N; i++) {
        size_t n; BYTE *p = ck_hexa(ck_desp_kat[i].pw, &n);
        WCHAR w[128] = {0}; for (size_t j = 0; j < n; j++) w[j] = p[j];
        UNICODE_STRING up = { (USHORT)(2 * n), (USHORT)(2 * n + 2), w };
        BYTE k[16]; memset(k, 0xEE, 16);
        NTSTATUS st = ((csx_hashpw_fn)c->HashPassword)(&up, NULL, 0, k);
        if (n == 0) { t_note("empty DES password -> 0x%08lx", (unsigned long)st); free(p); continue; }
        CHECKF(st == 0 && ck_eqhex(k, 8, ck_desp_kat[i].key), "row %zu (%zu chars) st=0x%08lx", i, n, (unsigned long)st);
        for (int j = 8; j < 16; j++) CHECKF(k[j] == 0xEE, "row %zu overrun", i);
        free(p);
    }
}

TEST(ckdes_hashpassword_ignores_salt_argument) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_CRC);
    CHECK(c != NULL);
    if (!c) return;
    WCHAR pw[] = { 'p','a','s','s','w','o','r','d' }, sa[] = { 'S','A','L','T' };
    UNICODE_STRING up = { 16, 16, pw }, us = { 8, 8, sa };
    BYTE a[8], b[8];
    EXPECT_NS(((csx_hashpw_fn)c->HashPassword)(&up, &us, 0, a), 0);
    EXPECT_NS(((csx_hashpw_fn)c->HashPassword)(&up, NULL, 77, b), 0);
    CHECK(!memcmp(a, b, 8));
}

TEST(ckdes_initialize_requires_eight_byte_key) {
    CK_NEED(CDLocateCSystem);
    static const LONG ets[] = { ET_DES_CRC, ET_DES_MD5, ET_DES_PLAIN };
    for (size_t e = 0; e < 3; e++) {
        const CSX *c = ck_cs(ets[e]);
        CHECK(c != NULL);
        if (!c) continue;
        BYTE key[16] = {1,2,3,4,5,6,7,8};
        static const ULONG bad[] = { 0, 1, 7, 9, 16 };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) { PVOID st = NULL; EXPECT_NS(((csx_init_fn)c->Initialize)(key, bad[i], 0, &st), NS_INVALID_PARAM); }
        PVOID st = NULL;
        EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st), 0);
        CHECK(st != NULL);
        EXPECT_NS(((csx_fin_fn)c->Finish)(&st), 0);
        CHECK(st == NULL);
    }
}

TEST(ckdes_plain_known_answers) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_DESPLAIN_KAT_N; i++) {
        size_t kl, il, cl; BYTE *k = ck_hexa(ck_desplain_kat[i].key, &kl), *in = ck_hexa(ck_desplain_kat[i].in, &il), *ct = ck_hexa(ck_desplain_kat[i].out, &cl);
        BYTE out[64]; ULONG ol = 64;
        memset(out, 0xEE, sizeof out);
        NTSTATUS st = ck_cs_encrypt(ET_DES_PLAIN, k, 8, 0, in, (ULONG)il, out, &ol);
        CHECKF(st == 0 && ol == cl && !memcmp(out, ct, cl), "encrypt row %zu len %zu st=0x%08lx", i, il, (unsigned long)st);
        BYTE back[64]; ULONG bl = 64;
        st = ck_cs_decrypt(ET_DES_PLAIN, k, 8, 0, ct, (ULONG)cl, back, &bl);
        CHECKF(st == 0 && bl == cl && !memcmp(back, in, il), "decrypt row %zu", i);
        for (size_t j = il; j < cl; j++) CHECKF(back[j] == 0, "row %zu pad byte %zu", i, j);
        free(k); free(in); free(ct);
    }
}

TEST(ckdes_plain_classic_vector) {
    CK_NEED(CDLocateCSystem);
    BYTE key[8] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 }, pt[8] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF }, ct[8]; ULONG ol = 8;
    EXPECT_NS(ck_cs_encrypt(ET_DES_PLAIN, key, 8, 0, pt, 8, ct, &ol), 0);
    CHECK(ol == 8 && ck_eqhex(ct, 8, "85e813540f0ab405"));
}

TEST(ckdes_plain_buffer_size_protocol) {
    CK_NEED(CDLocateCSystem);
    BYTE key[8] = {1,2,3,4,5,6,7,8}, pt[9] = "12345678", ct[32];
    ULONG ol = 15;
    EXPECT_NS(ck_cs_encrypt(ET_DES_PLAIN, key, 8, 0, pt, 9, ct, &ol), NS_BUF_TOO_SMALL);
    ol = 16;
    EXPECT_NS(ck_cs_encrypt(ET_DES_PLAIN, key, 8, 0, pt, 9, ct, &ol), 0);
    EXPECT_EQ(ol, 16);
}

TEST(ckdes_md5_decrypt_known_answers) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_DESMD5_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_desmd5_kat[i].key, &kl), *p = ck_hexa(ck_desmd5_kat[i].plain, &pl), *ct = ck_hexa(ck_desmd5_kat[i].ct, &cl);
        BYTE out[160]; ULONG ol = 160;
        NTSTATUS st = ck_cs_decrypt(ET_DES_MD5, k, 8, 0, ct, (ULONG)cl, out, &ol);
        CHECKF(st == 0 && ol == pl && !memcmp(out, p, pl), "row %zu plen %zu st=0x%08lx outlen %lu", i, pl, (unsigned long)st, (unsigned long)ol);
        free(k); free(p); free(ct);
    }
}

TEST(ckdes_crc_decrypt_known_answers) {
    CK_NEED(CDLocateCSystem);
    for (size_t i = 0; i < CK_DESCRC_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_descrc_kat[i].key, &kl), *p = ck_hexa(ck_descrc_kat[i].plain, &pl), *ct = ck_hexa(ck_descrc_kat[i].ct, &cl);
        BYTE out[160]; ULONG ol = 160;
        NTSTATUS st = ck_cs_decrypt(ET_DES_CRC, k, 8, 0, ct, (ULONG)cl, out, &ol);
        CHECKF(st == 0 && ol == pl && !memcmp(out, p, pl), "row %zu plen %zu st=0x%08lx outlen %lu", i, pl, (unsigned long)st, (unsigned long)ol);
        free(k); free(p); free(ct);
    }
}

CHILD(ck_des_encrypt_kat) {
    CC(ck_install_seq_rng(0x30));
    for (size_t i = 0; i < CK_DESMD5_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_desmd5_kat[i].key, &kl), *p = ck_hexa(ck_desmd5_kat[i].plain, &pl), *ct = ck_hexa(ck_desmd5_kat[i].ct, &cl);
        BYTE out[160]; ULONG ol = (ULONG)cl;
        NTSTATUS st = ck_cs_encrypt(ET_DES_MD5, k, 8, 0, p, (ULONG)pl, out, &ol);
        if (st != 0 || ol != cl || memcmp(out, ct, cl)) { printf("des-md5 row %zu failed st=0x%08lx outlen=%lu\n", i, (unsigned long)st, (unsigned long)ol); return __LINE__; }
        free(k); free(p); free(ct);
    }
    for (size_t i = 0; i < CK_DESCRC_KAT_N; i++) {
        size_t kl, pl, cl; BYTE *k = ck_hexa(ck_descrc_kat[i].key, &kl), *p = ck_hexa(ck_descrc_kat[i].plain, &pl), *ct = ck_hexa(ck_descrc_kat[i].ct, &cl);
        BYTE out[160]; ULONG ol = (ULONG)cl;
        NTSTATUS st = ck_cs_encrypt(ET_DES_CRC, k, 8, 0, p, (ULONG)pl, out, &ol);
        if (st != 0 || ol != cl || memcmp(out, ct, cl)) { printf("des-crc row %zu failed st=0x%08lx outlen=%lu\n", i, (unsigned long)st, (unsigned long)ol); return __LINE__; }
        free(k); free(p); free(ct);
    }
    return 0;
}
TEST(ckdes_encrypt_known_answers_with_fixed_confounder) {
    CK_NEED(CDRegisterRng);
    DWORD ec = t_run_child("ck_des_encrypt_kat", "", 30000);
    t_check(ec == 0, __FILE__, __LINE__, "child exit 0", "exit code %lu", (unsigned long)ec);
}

TEST(ckdes_roundtrip_and_padding) {
    CK_NEED(CDLocateCSystem);
    static const LONG ets[] = { ET_DES_MD5, ET_DES_CRC };
    BYTE key[8] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 };
    for (size_t e = 0; e < 2; e++) for (ULONG n = 0; n <= 40; n++) {
        BYTE pt[48], ct[128], back[128]; for (ULONG i = 0; i < n; i++) pt[i] = (BYTE)(i + 1);
        ULONG cks = ets[e] == ET_DES_MD5 ? 16 : 4;
        ULONG total = (n + 8 + cks + 7) & ~7u, cl = 128, bl = 128;
        EXPECT_NS(ck_cs_encrypt(ets[e], key, 8, 0, pt, n, ct, &cl), 0);
        CHECKF(cl == total, "etype %ld len %lu cipher %lu want %lu", (long)ets[e], (unsigned long)n, (unsigned long)cl, (unsigned long)total);
        EXPECT_NS(ck_cs_decrypt(ets[e], key, 8, 0, ct, cl, back, &bl), 0);
        CHECKF(bl == total - 8 - cks && !memcmp(back, pt, n), "etype %ld len %lu", (long)ets[e], (unsigned long)n);
        for (ULONG i = n; i < bl; i++) CHECKF(back[i] == 0, "pad byte %lu", (unsigned long)i);
    }
}

TEST(ckdes_encrypt_output_size_checks) {
    CK_NEED(CDLocateCSystem);
    BYTE key[8] = {1,2,3,4,5,6,7,8}, pt[16] = "0123456789abcde", ct[64];
    ULONG ol = 8 + 16 + 15 - 1;           /* too small even before padding */
    EXPECT_NS(ck_cs_encrypt(ET_DES_MD5, key, 8, 0, pt, 15, ct, &ol), NS_BUF_TOO_SMALL);
    ol = 8 + 16 + 15;                      /* fits unpadded (39) but not padded (40) */
    EXPECT_NS(ck_cs_encrypt(ET_DES_MD5, key, 8, 0, pt, 15, ct, &ol), NS_BUF_TOO_SMALL);
    ol = 40;
    EXPECT_NS(ck_cs_encrypt(ET_DES_MD5, key, 8, 0, pt, 15, ct, &ol), 0);
    EXPECT_EQ(ol, 40);
}

TEST(ckdes_decrypt_output_size_checks) {
    CK_NEED(CDLocateCSystem);
    BYTE key[8] = {1,2,3,4,5,6,7,8}, pt[16] = "0123456789abcde", ct[64], out[64]; ULONG cl = 64;
    EXPECT_NS(ck_cs_encrypt(ET_DES_MD5, key, 8, 0, pt, 15, ct, &cl), 0);
    ULONG ol = cl - 1;
    EXPECT_NS(ck_cs_decrypt(ET_DES_MD5, key, 8, 0, ct, cl, out, &ol), NS_BUF_TOO_SMALL);
    EXPECT_EQ(ol, cl);
    ol = cl;
    EXPECT_NS(ck_cs_decrypt(ET_DES_MD5, key, 8, 0, ct, cl, out, &ol), 0);
}

TEST(ckdes_decrypt_detects_tampering) {
    CK_NEED(CDLocateCSystem);
    static const LONG ets[] = { ET_DES_MD5, ET_DES_CRC };
    BYTE key[8] = {1,2,3,4,5,6,7,8}, pt[24], out[128];
    for (int i = 0; i < 24; i++) pt[i] = (BYTE)i;
    for (size_t e = 0; e < 2; e++) {
        BYTE ct[128]; ULONG cl = 128;
        EXPECT_NS(ck_cs_encrypt(ets[e], key, 8, 0, pt, 24, ct, &cl), 0);
        for (ULONG pos = 0; pos < cl; pos++) {
            BYTE bad[128]; memcpy(bad, ct, cl); bad[pos] ^= 0x10; ULONG ol = 128;
            NTSTATUS st = ck_cs_decrypt(ets[e], key, 8, 0, bad, cl, out, &ol);
            CHECKF(st == NS_MSG_ALTERED, "etype %ld flip at %lu -> 0x%08lx", (long)ets[e], (unsigned long)pos, (unsigned long)st);
        }
    }
}

TEST(ckdes_wrong_key_fails_checksum) {
    CK_NEED(CDLocateCSystem);
    BYTE k1[8] = {1,2,3,4,5,6,7,8}, k2[8] = {8,7,6,5,4,3,2,1}, pt[10] = "123456789", ct[64], out[64]; ULONG cl = 64, ol = 64;
    EXPECT_NS(ck_cs_encrypt(ET_DES_MD5, k1, 8, 0, pt, 10, ct, &cl), 0);
    EXPECT_NS(ck_cs_decrypt(ET_DES_MD5, k2, 8, 0, ct, cl, out, &ol), NS_MSG_ALTERED);
}

TEST(ckdes_control_sets_iv) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_PLAIN);
    CHECK(c != NULL);
    if (!c) return;
    BYTE key[8] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 }, iv[8] = { 1,2,3,4,5,6,7,8 }; PVOID st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st), 0);
    EXPECT_NS(((csx_ctl_fn)c->Control)(1, st, iv, 8), 0);
    BYTE pt[8] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF }, ct[16]; ULONG cl = 16;
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st, pt, 8, ct, &cl), 0);
    ((csx_fin_fn)c->Finish)(&st);
    /* with IV = 0102030405060708: ciphertext = DES(pt xor iv) = DES(0123456789ABCDEF xor 0102030405060708) */
    BYTE x[8]; for (int i = 0; i < 8; i++) x[i] = pt[i] ^ iv[i];
    BYTE ref[8]; ULONG rl = 8; PVOID st2 = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st2), 0);
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st2, x, 8, ref, &rl), 0);
    ((csx_fin_fn)c->Finish)(&st2);
    CHECK(!memcmp(ct, ref, 8));
    st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st), 0);
    EXPECT_NS(((csx_ctl_fn)c->Control)(2, st, iv, 8), NS_INVALID_PARAM);
    EXPECT_NS(((csx_ctl_fn)c->Control)(1, st, iv, 7), NS_INVALID_PARAM);
    ((csx_fin_fn)c->Finish)(&st);
}

static BOOLEAN WINAPI rng_fail(PUCHAR buf, ULONG len) { return FALSE; }
CHILD(ck_enc_rng_failure) {
    CC(CKP(CDRegisterRng) && CKP(CDLocateCSystem));
    RNX r; memset(&r, 0, sizeof r); r.Type = 0x7e57; r.P2 = (void *)rng_fail;
    CC(CKP(CDRegisterRng)(&r) == TRUE);
    BYTE key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, pt[8] = "payload", ct[128]; ULONG cl;
    cl = 128; CC(ck_cs_encrypt(ET_DES_MD5, key, 8, 0, pt, 8, ct, &cl) == (NTSTATUS)0xC00000E5);
    cl = 128; CC(ck_cs_encrypt(ET_DES_CRC, key, 8, 0, pt, 8, ct, &cl) == (NTSTATUS)0xC00000E5);
    cl = 128; CC(ck_cs_encrypt(ET_RC4_HMAC, key, 16, 0, pt, 8, ct, &cl) == (NTSTATUS)0xC00000E5);
    cl = 128; CC(ck_cs_encrypt(ET_RC4_HMAC_OLD, key, 16, 0, pt, 8, ct, &cl) == (NTSTATUS)0xC00000E5);
    /* the AES routine does not look at the generator's result */
    cl = 128; CC(ck_cs_encrypt(ET_AES128, key, 16, 0, pt, 8, ct, &cl) == 0 && cl == 36);
    /* RC4-MD4 and plain DES use no confounder */
    cl = 128; CC(ck_cs_encrypt(ET_RC4_MD4, key, 16, 0, pt, 8, ct, &cl) == 0);
    cl = 128; CC(ck_cs_encrypt(ET_DES_PLAIN, key, 8, 0, pt, 8, ct, &cl) == 0);
    return 0;
}
TEST(ckenc_generator_failure_maps_to_internal_error) {
    CK_NEED(CDRegisterRng);
    DWORD ec = t_run_child("ck_enc_rng_failure", "", 30000);
    t_check(ec == 0, __FILE__, __LINE__, "child exit 0", "exit code %lu (source line)", (unsigned long)ec);
}

TEST(ckdes_cbc_state_chains_across_messages) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_PLAIN);
    CHECK(c != NULL);
    if (!c) return;
    BYTE key[8] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 }, m[16];
    for (int i = 0; i < 16; i++) m[i] = (BYTE)(i * 5 + 1);
    BYTE whole[16]; ULONG wl = 16;
    EXPECT_NS(ck_cs_encrypt(ET_DES_PLAIN, key, 8, 0, m, 16, whole, &wl), 0);
    PVOID st = NULL; BYTE p1[8], p2[8]; ULONG l1 = 8, l2 = 8;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st), 0);
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st, m, 8, p1, &l1), 0);
    EXPECT_NS(((csx_crypt_fn)c->Encrypt)(st, m + 8, 8, p2, &l2), 0);
    ((csx_fin_fn)c->Finish)(&st);
    CHECK(!memcmp(p1, whole, 8));
    CHECK(!memcmp(p2, whole + 8, 8));          /* the second message continues the CBC chain */
    BYTE d1[8], d2[8]; ULONG k1 = 8, k2 = 8; st = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &st), 0);
    EXPECT_NS(((csx_crypt_fn)c->Decrypt)(st, p1, 8, d1, &k1), 0);
    EXPECT_NS(((csx_crypt_fn)c->Decrypt)(st, p2, 8, d2, &k2), 0);
    ((csx_fin_fn)c->Finish)(&st);
    CHECK(!memcmp(d1, m, 8) && !memcmp(d2, m + 8, 8));
}

TEST(ckdes_md5_messages_on_one_state_roundtrip) {
    CK_NEED(CDLocateCSystem);
    const CSX *c = ck_cs(ET_DES_MD5);
    CHECK(c != NULL);
    if (!c) return;
    BYTE key[8] = {1,2,3,4,5,6,7,8}; PVOID e = NULL, d = NULL;
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &e), 0);
    EXPECT_NS(((csx_init_fn)c->Initialize)(key, 8, 0, &d), 0);
    for (int i = 0; i < 4; i++) {
        BYTE pt[16], ct[96], out[96]; ULONG cl = 96, ol = 96;
        memset(pt, 0x40 + i, 16);
        EXPECT_NS(((csx_crypt_fn)c->Encrypt)(e, pt, 16, ct, &cl), 0);
        EXPECT_NS(((csx_crypt_fn)c->Decrypt)(d, ct, cl, out, &ol), 0);
        CHECKF(ol == 16 && !memcmp(out, pt, 16), "message %d", i);
    }
    ((csx_fin_fn)c->Finish)(&e); ((csx_fin_fn)c->Finish)(&d);
}

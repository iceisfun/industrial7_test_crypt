/* HMACwithSHA, PBKDF2 and the checksum function tables (CDLocateCheckSum entries driven through their pointers). */
#include "ck.h"
#include "ck_vec.h"

static NTSTATUS hmac_hex(const char *key, const char *data, BYTE *out20, ULONG outlen, size_t *kl_, size_t *dl_) {
    size_t kl, dl; BYTE *k = ck_hexa(key, &kl), *d = ck_hexa(data, &dl);
    BYTE dummy = 0;
    NTSTATUS st = CKP(HMACwithSHA)(kl ? k : &dummy, (ULONG)kl, dl ? d : &dummy, (ULONG)dl, out20, outlen);
    if (kl_) *kl_ = kl;
    if (dl_) *dl_ = dl;
    free(k); free(d);
    return st;
}

TEST(ckhash_hmacsha_rfc2202_and_extra_vectors) {
    CK_NEED(HMACwithSHA);
    for (size_t i = 0; i < CK_HMACSHA_KAT_N; i++) {
        BYTE out[20]; size_t kl, dl;
        NTSTATUS st = hmac_hex(ck_hmacsha_kat[i].key, ck_hmacsha_kat[i].data, out, 20, &kl, &dl);
        if (kl == 0 || dl == 0) {            /* empty key / empty data: documented only loosely, observe */
            if (st == 0) CHECKF(ck_eqhex(out, 20, ck_hmacsha_kat[i].out), "row %zu (empty input)", i);
            else t_note("HMACwithSHA row %zu (empty key/data) returned 0x%08lx", i, (unsigned long)st);
            continue;
        }
        CHECKF(st == 0, "row %zu status 0x%08lx", i, (unsigned long)st);
        CHECKF(ck_eqhex(out, 20, ck_hmacsha_kat[i].out), "row %zu", i);
    }
}

TEST(ckhash_hmacsha_rfc2202_case1_exact) {
    CK_NEED(HMACwithSHA);
    BYTE key[20]; memset(key, 0x0b, 20); BYTE out[20];
    EXPECT_NS(CKP(HMACwithSHA)(key, 20, (PUCHAR)"Hi There", 8, out, 20), 0);
    CHECK(ck_eqhex(out, 20, "b617318655057264e28bc0b6fb378c8ef146be00"));
}

TEST(ckhash_hmacsha_rfc2202_jefe) {
    CK_NEED(HMACwithSHA);
    BYTE out[20];
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"Jefe", 4, (PUCHAR)"what do ya want for nothing?", 28, out, 20), 0);
    CHECK(ck_eqhex(out, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
}

TEST(ckhash_hmacsha_truncation_returns_prefix) {
    CK_NEED(HMACwithSHA);
    BYTE full[20];
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"Jefe", 4, (PUCHAR)"what do ya want for nothing?", 28, full, 20), 0);
    for (ULONG n = 0; n <= 20; n++) {
        BYTE buf[32]; memset(buf, 0xEE, sizeof buf);
        EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"Jefe", 4, (PUCHAR)"what do ya want for nothing?", 28, buf, n), 0);
        CHECKF(!memcmp(buf, full, n), "prefix %lu", (unsigned long)n);
        for (ULONG i = n; i < 32; i++) CHECKF(buf[i] == 0xEE, "n=%lu wrote byte %lu", (unsigned long)n, (unsigned long)i);
    }
}

TEST(ckhash_hmacsha_output_longer_than_digest_rejected) {
    CK_NEED(HMACwithSHA);
    static const ULONG sizes[] = { 21, 22, 32, 64, 1000 };
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        BYTE buf[1024]; memset(buf, 0xEE, sizeof buf);
        EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"key", 3, (PUCHAR)"data", 4, buf, sizes[i]), NS_INVALID_PARAM);
        BYTE chk[1024]; memset(chk, 0xEE, sizeof chk);
        CHECKF(!memcmp(buf, chk, sizeof buf), "nothing is written on failure (%lu)", (unsigned long)sizes[i]);
    }
}

TEST(ckhash_hmacsha_long_data) {
    CK_NEED(HMACwithSHA);
    static BYTE d[100000]; memset(d, 'a', sizeof d);
    BYTE out[20];
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"k", 1, d, sizeof d, out, 20), 0);
    CHECK(ck_eqhex(out, 20, "f7c563c6bd0d772285b08f18704b922cfb2b2a78"));
    static BYTE e[4096]; memset(e, 'b', sizeof e);
    BYTE k[64]; memset(k, 1, 64);
    EXPECT_NS(CKP(HMACwithSHA)(k, 64, e, sizeof e, out, 20), 0);
    CHECK(ck_eqhex(out, 20, "db9ed531d61bec61053c107fba3b20292c2f5eb4"));
}

TEST(ckhash_hmacsha_key_block_boundaries) {
    CK_NEED(HMACwithSHA);
    /* keys of 63, 64 and 65 bytes straddle the SHA-1 block size (the long key is hashed first) */
    for (size_t i = CK_HMACSHA_KAT_N - 3; i < CK_HMACSHA_KAT_N; i++) {
        BYTE out[20];
        EXPECT_NS(hmac_hex(ck_hmacsha_kat[i].key, ck_hmacsha_kat[i].data, out, 20, NULL, NULL), 0);
        CHECKF(ck_eqhex(out, 20, ck_hmacsha_kat[i].out), "row %zu", i);
    }
}

TEST(ckhash_hmacsha_deterministic_and_input_sensitive) {
    CK_NEED(HMACwithSHA);
    BYTE a[20], b[20], c[20], d[20];
    CKP(HMACwithSHA)((PUCHAR)"key", 3, (PUCHAR)"data", 4, a, 20);
    CKP(HMACwithSHA)((PUCHAR)"key", 3, (PUCHAR)"data", 4, b, 20);
    CKP(HMACwithSHA)((PUCHAR)"key", 3, (PUCHAR)"datb", 4, c, 20);
    CKP(HMACwithSHA)((PUCHAR)"kez", 3, (PUCHAR)"data", 4, d, 20);
    CHECK(!memcmp(a, b, 20)); CHECK(memcmp(a, c, 20)); CHECK(memcmp(a, d, 20));
}

TEST(ckhash_hmacsha_data_length_is_honoured) {
    CK_NEED(HMACwithSHA);
    BYTE a[20], b[20];
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"key", 3, (PUCHAR)"dataXXXX", 4, a, 20), 0);
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"key", 3, (PUCHAR)"data", 4, b, 20), 0);
    CHECK(!memcmp(a, b, 20));
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"keyYYY", 3, (PUCHAR)"data", 4, a, 20), 0);
    CHECK(!memcmp(a, b, 20));
}

/* ------------------------------------------------------------------------------------------------------ */
TEST(ckhash_pbkdf2_rfc6070_and_extra_vectors) {
    CK_NEED(PBKDF2);
    for (size_t i = 0; i < CK_PBKDF2_KAT_N; i++) {
        size_t pl, sl; BYTE *p = ck_hexa(ck_pbkdf2_kat[i].pw, &pl), *s = ck_hexa(ck_pbkdf2_kat[i].salt, &sl);
        BYTE dk[64]; BYTE dummy = 0;
        memset(dk, 0xEE, sizeof dk);
        NTSTATUS st = CKP(PBKDF2)(pl ? p : &dummy, (ULONG)pl, sl ? s : &dummy, (ULONG)sl, ck_pbkdf2_kat[i].iter, ck_pbkdf2_kat[i].dklen, dk);
        if (pl == 0 || sl == 0) {
            if (st == 0) CHECKF(ck_eqhex(dk, ck_pbkdf2_kat[i].dklen, ck_pbkdf2_kat[i].out), "row %zu (empty input)", i);
            else t_note("PBKDF2 row %zu (empty password/salt) returned 0x%08lx", i, (unsigned long)st);
        } else {
            CHECKF(st == 0, "row %zu status 0x%08lx", i, (unsigned long)st);
            CHECKF(ck_eqhex(dk, ck_pbkdf2_kat[i].dklen, ck_pbkdf2_kat[i].out), "row %zu iter %u", i, ck_pbkdf2_kat[i].iter);
            for (ULONG k = ck_pbkdf2_kat[i].dklen; k < 64; k++) CHECKF(dk[k] == 0xEE, "row %zu overrun at %lu", i, (unsigned long)k);
        }
        free(p); free(s);
    }
}

TEST(ckhash_pbkdf2_rfc6070_case1_exact) {
    CK_NEED(PBKDF2);
    BYTE dk[20];
    EXPECT_NS(CKP(PBKDF2)((PUCHAR)"password", 8, (PUCHAR)"salt", 4, 1, 20, dk), 0);
    CHECK(ck_eqhex(dk, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"));
    EXPECT_NS(CKP(PBKDF2)((PUCHAR)"password", 8, (PUCHAR)"salt", 4, 2, 20, dk), 0);
    CHECK(ck_eqhex(dk, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));
    EXPECT_NS(CKP(PBKDF2)((PUCHAR)"password", 8, (PUCHAR)"salt", 4, 4096, 20, dk), 0);
    CHECK(ck_eqhex(dk, 20, "4b007901b765489abead49d926f721d065a429c1"));
}

TEST(ckhash_pbkdf2_rfc6070_long_inputs) {
    CK_NEED(PBKDF2);
    BYTE dk[25];
    EXPECT_NS(CKP(PBKDF2)((PUCHAR)"passwordPASSWORDpassword", 24, (PUCHAR)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 25, dk), 0);
    CHECK(ck_eqhex(dk, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"));
    BYTE d16[16];
    EXPECT_NS(CKP(PBKDF2)((PUCHAR)"pass\0word", 9, (PUCHAR)"sa\0lt", 5, 4096, 16, d16), 0);
    CHECK(ck_eqhex(d16, 16, "56fa6aa75548099dcc37d7f03425e0c3"));
}

TEST(ckhash_pbkdf2_first_block_is_hmac_of_salt_and_counter) {
    CK_NEED(PBKDF2); CK_NEED(HMACwithSHA);
    BYTE s[8] = { 's', 'a', 'l', 't', 0, 0, 0, 1 }, h[20], dk[20];
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"password", 8, s, 8, h, 20), 0);
    EXPECT_NS(CKP(PBKDF2)((PUCHAR)"password", 8, (PUCHAR)"salt", 4, 1, 20, dk), 0);
    CHECK(!memcmp(h, dk, 20));
}

TEST(ckhash_pbkdf2_prefix_property) {
    CK_NEED(PBKDF2);
    BYTE full[64], part[64];
    EXPECT_NS(CKP(PBKDF2)((PUCHAR)"pw", 2, (PUCHAR)"salty", 5, 7, 64, full), 0);
    for (ULONG n = 1; n <= 64; n += 7) {
        EXPECT_NS(CKP(PBKDF2)((PUCHAR)"pw", 2, (PUCHAR)"salty", 5, 7, n, part), 0);
        CHECKF(!memcmp(full, part, n), "dklen %lu", (unsigned long)n);
    }
}

TEST(ckhash_pbkdf2_iteration_count_changes_output) {
    CK_NEED(PBKDF2);
    BYTE a[20], b[20];
    CKP(PBKDF2)((PUCHAR)"pw", 2, (PUCHAR)"salty", 5, 10, 20, a);
    CKP(PBKDF2)((PUCHAR)"pw", 2, (PUCHAR)"salty", 5, 11, 20, b);
    CHECK(memcmp(a, b, 20));
}

TEST(ckhash_pbkdf2_degenerate_arguments_observed) {
    CK_NEED(PBKDF2);
    BYTE dk[20] = {0};
    NTSTATUS st0 = CKP(PBKDF2)((PUCHAR)"pw", 2, (PUCHAR)"salty", 5, 0, 20, dk);
    t_note("PBKDF2 iterations=0 -> 0x%08lx", (unsigned long)st0);
    NTSTATUS st1 = CKP(PBKDF2)((PUCHAR)"pw", 2, (PUCHAR)"salty", 5, 1, 0, dk);
    t_note("PBKDF2 dklen=0 -> 0x%08lx", (unsigned long)st1);
}

/* ------------------------------------------------------------------------------------------------------ */
static void ck_kat_checksum(LONG type, const char *in, const char *out, int ex, const char *label) {
    size_t n; BYTE *m = ck_hexa(in, &n); BYTE o[64]; size_t ol = 0;
    NTSTATUS st = ck_run_checksum(type, ex, NULL, 0, 0, m, n, o, &ol);
    CHECKF(st == 0, "%s type %ld len %zu st=0x%08lx", label, (long)type, n, (unsigned long)st);
    if (st == 0) CHECKF(ck_eqhex(o, ol, out), "%s type %ld len %zu", label, (long)type, n);
    free(m);
}

TEST(ckhash_checksum_md5_initialize_path) {
    CK_NEED(CDLocateCheckSum);
    for (size_t i = 0; i < CK_MD5_KAT_N; i++) ck_kat_checksum(CS_MD5, ck_md5_kat[i].in, ck_md5_kat[i].out, 0, "Initialize");
}
TEST(ckhash_checksum_md5_initializeex_path) {
    CK_NEED(CDLocateCheckSum);
    for (size_t i = 0; i < CK_MD5_KAT_N; i++) ck_kat_checksum(CS_MD5, ck_md5_kat[i].in, ck_md5_kat[i].out, 1, "InitializeEx");
}
TEST(ckhash_checksum_md4_both_paths) {
    CK_NEED(CDLocateCheckSum);
    for (size_t i = 0; i < CK_MD4_KAT_N; i++) {
        ck_kat_checksum(CS_MD4, ck_md4_kat[i].in, ck_md4_kat[i].out, 0, "Initialize");
        ck_kat_checksum(CS_MD4, ck_md4_kat[i].in, ck_md4_kat[i].out, 1, "InitializeEx");
    }
}
TEST(ckhash_checksum_md4_rfc1320_suite) {
    CK_NEED(CDLocateCheckSum);
    static const struct { const char *m, *d; } v[] = {
        { "", "31d6cfe0d16ae931b73c59d7e0c089c0" }, { "a", "bde52cb31de33e46245e05fbdbd6fb24" },
        { "abc", "a448017aaf21d8525fc10ae87aa6729d" }, { "message digest", "d9130a8164549fe818874806e1c7014b" },
        { "abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4" },
        { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536" } };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        BYTE o[16]; size_t ol;
        EXPECT_NS(ck_run_checksum(CS_MD4, 0, NULL, 0, 0, (const BYTE *)v[i].m, strlen(v[i].m), o, &ol), 0);
        CHECKF(ol == 16 && ck_eqhex(o, 16, v[i].d), "vector %zu", i);
    }
}
TEST(ckhash_checksum_sha1_both_paths) {
    CK_NEED(CDLocateCheckSum);
    for (size_t i = 0; i < CK_SHA1_KAT_N; i++) {
        ck_kat_checksum(CS_SHA1, ck_sha1_kat[i].in, ck_sha1_kat[i].out, 0, "Initialize");
        ck_kat_checksum(CS_SHA1, ck_sha1_kat[i].in, ck_sha1_kat[i].out, 1, "InitializeEx");
    }
}
TEST(ckhash_checksum_sha1_fips_vectors) {
    CK_NEED(CDLocateCheckSum);
    BYTE o[20]; size_t ol;
    EXPECT_NS(ck_run_checksum(CS_SHA1, 0, NULL, 0, 0, (const BYTE *)"abc", 3, o, &ol), 0);
    CHECK(ol == 20 && ck_eqhex(o, 20, "a9993e364706816aba3e25717850c26c9cd0d89d"));
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    EXPECT_NS(ck_run_checksum(CS_SHA1, 0, NULL, 0, 0, (const BYTE *)m, strlen(m), o, &ol), 0);
    CHECK(ck_eqhex(o, 20, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"));
}
TEST(ckhash_checksum_kerberos_crc32) {
    CK_NEED(CDLocateCheckSum);
    for (size_t i = 0; i < CK_CRCK_KAT_N; i++) {
        ck_kat_checksum(CS_CRC32, ck_crck_kat[i].in, ck_crck_kat[i].out, 0, "Initialize");
        ck_kat_checksum(CS_CRC32, ck_crck_kat[i].in, ck_crck_kat[i].out, 1, "InitializeEx");
    }
}
TEST(ckhash_checksum_real_crc32_is_ieee) {
    CK_NEED(CDLocateCheckSum);
    for (size_t i = 0; i < CK_CRCR_KAT_N; i++) {
        ck_kat_checksum(CS_REAL_CRC32, ck_crcr_kat[i].in, ck_crcr_kat[i].out, 0, "Initialize");
        ck_kat_checksum(CS_REAL_CRC32, ck_crcr_kat[i].in, ck_crcr_kat[i].out, 1, "InitializeEx");
    }
    BYTE o[4]; size_t ol;
    EXPECT_NS(ck_run_checksum(CS_REAL_CRC32, 0, NULL, 0, 0, (const BYTE *)"123456789", 9, o, &ol), 0);
    CHECK(ol == 4 && ck_eqhex(o, 4, "2639f4cb"));   /* CRC-32 check value 0xCBF43926, stored little-endian */
}
TEST(ckhash_checksum_kerberos_crc32_differs_from_ieee) {
    CK_NEED(CDLocateCheckSum);
    BYTE a[4], b[4]; size_t ol;
    EXPECT_NS(ck_run_checksum(CS_CRC32, 0, NULL, 0, 0, (const BYTE *)"123456789", 9, a, &ol), 0);
    EXPECT_NS(ck_run_checksum(CS_REAL_CRC32, 0, NULL, 0, 0, (const BYTE *)"123456789", 9, b, &ol), 0);
    CHECK(memcmp(a, b, 4));
}
TEST(ckhash_checksum_kerberos_crc32_empty_input_is_zero) {
    CK_NEED(CDLocateCheckSum);
    BYTE a[4] = { 1, 1, 1, 1 }; size_t ol;
    EXPECT_NS(ck_run_checksum(CS_CRC32, 0, NULL, 0, 0, NULL, 0, a, &ol), 0);
    CHECK(a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0);
    EXPECT_NS(ck_run_checksum(CS_REAL_CRC32, 0, NULL, 0, 0, NULL, 0, a, &ol), 0);
    CHECK(a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0);
}

TEST(ckhash_checksum_incremental_sum_equals_one_shot) {
    CK_NEED(CDLocateCheckSum);
    static const LONG types[] = { CS_MD4, CS_MD5, CS_SHA1, CS_CRC32, CS_REAL_CRC32 };
    BYTE msg[333]; for (int i = 0; i < 333; i++) msg[i] = (BYTE)(i * 17 + 3);
    for (size_t t = 0; t < sizeof types / sizeof types[0]; t++) {
        const CKX *c = ck_ck(types[t]);
        CHECK(c != NULL);
        if (!c) continue;
        BYTE ref[64], out[64]; size_t rl = 0;
        EXPECT_NS(ck_run_checksum(types[t], 0, NULL, 0, 0, msg, sizeof msg, ref, &rl), 0);
        PVOID ctx = NULL;
        EXPECT_NS(((ckx_init_fn)c->Initialize)(0, &ctx), 0);
        size_t pos = 0, step = 1;
        while (pos < sizeof msg) { size_t n = step < sizeof msg - pos ? step : sizeof msg - pos; ((ckx_sum_fn)c->Sum)(ctx, (ULONG)n, msg + pos); pos += n; step += 2; }
        memset(out, 0, sizeof out);
        EXPECT_NS(((ckx_final_fn)c->Finalize)(ctx, out), 0);
        EXPECT_NS(((ckx_finish_fn)c->Finish)(&ctx), 0);
        CHECKF(!memcmp(out, ref, rl), "type %ld", (long)types[t]);
    }
}

TEST(ckhash_checksum_finish_clears_context_pointer) {
    CK_NEED(CDLocateCheckSum);
    static const LONG types[] = { CS_MD4, CS_MD5, CS_SHA1, CS_CRC32, CS_REAL_CRC32 };
    for (size_t t = 0; t < sizeof types / sizeof types[0]; t++) {
        const CKX *c = ck_ck(types[t]);
        if (!c) { CHECK(c != NULL); continue; }
        PVOID ctx = NULL; BYTE out[64];
        EXPECT_NS(((ckx_init_fn)c->Initialize)(0, &ctx), 0);
        CHECK(ctx != NULL);
        ((ckx_sum_fn)c->Sum)(ctx, 3, (PUCHAR)"abc");
        ((ckx_final_fn)c->Finalize)(ctx, out);
        EXPECT_NS(((ckx_finish_fn)c->Finish)(&ctx), 0);
        CHECKF(ctx == NULL, "type %ld", (long)types[t]);
    }
}

TEST(ckhash_checksum_finalize_output_size_exact) {
    CK_NEED(CDLocateCheckSum);
    static const struct { LONG t; ULONG n; } k[] = { {CS_MD4, 16}, {CS_MD5, 16}, {CS_SHA1, 20}, {CS_CRC32, 4}, {CS_REAL_CRC32, 4} };
    for (size_t t = 0; t < sizeof k / sizeof k[0]; t++) {
        const CKX *c = ck_ck(k[t].t);
        if (!c) { CHECK(c != NULL); continue; }
        PVOID ctx = NULL; BYTE out[64]; memset(out, 0xEE, sizeof out);
        EXPECT_NS(((ckx_init_fn)c->Initialize)(0, &ctx), 0);
        ((ckx_sum_fn)c->Sum)(ctx, 3, (PUCHAR)"abc");
        EXPECT_NS(((ckx_final_fn)c->Finalize)(ctx, out), 0);
        ((ckx_finish_fn)c->Finish)(&ctx);
        EXPECT_EQ(c->Size, k[t].n);
        for (ULONG i = k[t].n; i < 64; i++) CHECKF(out[i] == 0xEE, "type %ld wrote byte %lu", (long)k[t].t, (unsigned long)i);
    }
}

TEST(ckhash_checksum_sha1_finalize_without_output_buffer) {
    CK_NEED(CDLocateCheckSum);
    const CKX *c = ck_ck(CS_SHA1);
    CHECK(c != NULL);
    if (!c) return;
    PVOID ctx = NULL;
    EXPECT_NS(((ckx_init_fn)c->Initialize)(0, &ctx), 0);
    ((ckx_sum_fn)c->Sum)(ctx, 3, (PUCHAR)"abc");
    EXPECT_NS(((ckx_final_fn)c->Finalize)(ctx, NULL), 0);    /* a NULL destination only releases the hash */
    EXPECT_NS(((ckx_finish_fn)c->Finish)(&ctx), 0);
    CHECK(ctx == NULL);
}

TEST(ckhash_checksum_hmac_md5_rfc4757) {
    CK_NEED(CDLocateCheckSum);
    for (size_t i = 0; i < CK_HMACMD5_KAT_N; i++) {
        size_t kl, dl; BYTE *k = ck_hexa(ck_hmacmd5_kat[i].key, &kl), *d = ck_hexa(ck_hmacmd5_kat[i].data, &dl);
        BYTE o[16]; size_t ol = 0;
        NTSTATUS st = ck_run_checksum(CS_HMAC_MD5, 1, k, (ULONG)kl, ck_hmacmd5_kat[i].usage, d, dl, o, &ol);
        CHECKF(st == 0 && ol == 16 && ck_eqhex(o, 16, ck_hmacmd5_kat[i].sig), "row %zu usage %u st=0x%08lx", i, ck_hmacmd5_kat[i].usage, (unsigned long)st);
        free(k); free(d);
    }
}

TEST(ckhash_checksum_md5_hmac_variant_observed) {
    CK_NEED(CDLocateCheckSum);
    const CKX *c = ck_ck(CS_MD5_HMAC);
    if (!c) { t_note("checksum -137 not registered"); return; }
    int sig = 0, nosig = 0, other = 0;
    for (size_t i = 0; i < CK_HMACMD5_KAT_N; i++) {
        size_t kl, dl; BYTE *k = ck_hexa(ck_hmacmd5_kat[i].key, &kl), *d = ck_hexa(ck_hmacmd5_kat[i].data, &dl);
        BYTE o[16]; size_t ol = 0;
        NTSTATUS st = ck_run_checksum(CS_MD5_HMAC, 1, k, (ULONG)kl, ck_hmacmd5_kat[i].usage, d, dl, o, &ol);
        if (st) other++; else if (ck_eqhex(o, 16, ck_hmacmd5_kat[i].sig)) sig++; else if (ck_eqhex(o, 16, ck_hmacmd5_kat[i].nosig)) nosig++; else other++;
        free(k); free(d);
    }
    t_note("checksum -137: %d rows match the signature-key form, %d the direct-key form, %d neither", sig, nosig, other);
}

TEST(ckhash_checksum_hmac_md5_usage_is_little_endian_prefix) {
    CK_NEED(CDLocateCheckSum);
    /* checksum = HMAC(Ksign, MD5(LE32(usage) || data)): hash the same prefix by hand through the MD5 primitives */
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(i + 1);
    BYTE ksign[16]; ck_hmac_md5(key, 16, (const BYTE *)"signaturekey", 13, NULL, 0, ksign);
    BYTE pre[4 + 5] = { 0x78, 0x56, 0x34, 0x12, 'h', 'e', 'l', 'l', 'o' }, inner[16], want[16], got[16]; size_t ol;
    ck_md5(pre, sizeof pre, inner);
    ck_hmac_md5(ksign, 16, inner, 16, NULL, 0, want);
    EXPECT_NS(ck_run_checksum(CS_HMAC_MD5, 1, key, 16, 0x12345678, (const BYTE *)"hello", 5, got, &ol), 0);
    CHECK(!memcmp(want, got, 16));
}

TEST(ckhash_checksum_aes_hmac_sha96_kat) {
    CK_NEED(CDLocateCheckSum);
    for (size_t i = 0; i < CK_AESCKS_KAT_N; i++) {
        size_t kl, dl; BYTE *k = ck_hexa(ck_aescks_kat[i].key, &kl), *d = ck_hexa(ck_aescks_kat[i].data, &dl);
        BYTE o[32]; size_t ol = 0; BYTE dummy = 0;
        NTSTATUS st = ck_run_checksum((LONG)ck_aescks_kat[i].type, 1, k, (ULONG)kl, ck_aescks_kat[i].usage, dl ? d : &dummy, dl, o, &ol);
        CHECKF(st == 0 && ol == 12 && ck_eqhex(o, 12, ck_aescks_kat[i].out), "row %zu type %ld usage %u st=0x%08lx", i, (long)(LONG)ck_aescks_kat[i].type, ck_aescks_kat[i].usage, (unsigned long)st);
        free(k); free(d);
    }
}

TEST(ckhash_checksum_aes_usage_zero_is_plain_truncated_hmac) {
    CK_NEED(CDLocateCheckSum); CK_NEED(HMACwithSHA);
    BYTE key[32]; for (int i = 0; i < 32; i++) key[i] = (BYTE)(i * 5);
    BYTE want[20], got[16]; size_t ol;
    EXPECT_NS(CKP(HMACwithSHA)(key, 32, (PUCHAR)"some data", 9, want, 20), 0);
    static const LONG types[] = { CS_AES128, CS_AES256, CS_AES128_KI, CS_AES256_KI };
    for (size_t t = 0; t < 4; t++) {
        EXPECT_NS(ck_run_checksum(types[t], 1, key, 32, 0, (const BYTE *)"some data", 9, got, &ol), 0);
        CHECKF(ol == 12 && !memcmp(got, want, 12), "type %ld", (long)types[t]);
    }
}

TEST(ckhash_checksum_aes_nonzero_usage_derives_key) {
    CK_NEED(CDLocateCheckSum); CK_NEED(HMACwithSHA);
    BYTE key[32]; for (int i = 0; i < 32; i++) key[i] = (BYTE)(i * 5);
    BYTE plain[20], a[16], b[16], c[16]; size_t ol;
    CKP(HMACwithSHA)(key, 32, (PUCHAR)"some data", 9, plain, 20);
    EXPECT_NS(ck_run_checksum(CS_AES256, 1, key, 32, 1, (const BYTE *)"some data", 9, a, &ol), 0);
    EXPECT_NS(ck_run_checksum(CS_AES256, 1, key, 32, 2, (const BYTE *)"some data", 9, b, &ol), 0);
    EXPECT_NS(ck_run_checksum(CS_AES256_KI, 1, key, 32, 1, (const BYTE *)"some data", 9, c, &ol), 0);
    CHECK(memcmp(a, plain, 12)); CHECK(memcmp(a, b, 12)); CHECK(memcmp(a, c, 12));
}

TEST(ckhash_checksum_md25_error_paths_observed) {
    CK_NEED(CDLocateCheckSum);
    for (LONG t = -135; t <= -128; t++) {
        const CKX *c = ck_ck(t);
        if (!c || !c->Initialize) continue;
        PVOID ctx = NULL;
        NTSTATUS st = ((ckx_init_fn)c->Initialize)(0, &ctx);
        t_note("checksum %ld: Initialize(0) -> 0x%08lx size=%lu", (long)t, (unsigned long)st, (unsigned long)c->Size);
        if (!st && ctx && c->Finish) ((ckx_finish_fn)c->Finish)(&ctx);
    }
}

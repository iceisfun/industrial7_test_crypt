#include "dp.h"
/* DPAPI blob layout (stable header fields) and tamper detection. Real-Windows blob format: skipped under emulators. */

static const BYTE PT[48] = { 'b','l','o','b',' ','t','e','s','t',' ','p','l','a','i','n','t','e','x','t',' ','0','1','2','3','4','5','6','7','8','9' };
static const WCHAR DESC[] = L"cryptt blob description";

static BOOL mkblob(DATA_BLOB *b, LPCWSTR descr, const void *ent, DWORD entlen, DWORD flags, DWORD ptlen) {
    return dp_protect(PT, ptlen, descr, ent, entlen, flags, b);
}
static const GUID PROVIDER = DP_PROVIDER_GUID;

/* ---- header fields ---- */

TEST(dpapi_blob_parses_to_exact_size) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    CHECK(p.ok);
    CHECK(p.end == b.cbData);           /* no trailing bytes after the signature */
    dp_free(&b);
}
TEST(dpapi_blob_version_is_1) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    EXPECT_EQ(dp_rd(b.pbData, 0), 1);
    dp_free(&b);
}
TEST(dpapi_blob_provider_guid) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    CHECK(!memcmp(b.pbData + 4, &PROVIDER, 16));      /* df9d8cd0-1501-11d1-8c7a-00c04fc297eb */
    dp_free(&b);
}
TEST(dpapi_blob_masterkey_version_is_1) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    EXPECT_EQ(dp_rd(b.pbData, 20), 1);
    dp_free(&b);
}
TEST(dpapi_blob_masterkey_guid_nonzero_and_stable) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB a = { 0 }, c = { 0 };
    BYTE z[16] = { 0 };
    CHECK(mkblob(&a, DESC, NULL, 0, 0, sizeof PT));
    CHECK(mkblob(&c, DESC, NULL, 0, 0, sizeof PT));
    CHECK(a.pbData && memcmp(a.pbData + 24, z, 16) != 0);
    if (a.pbData && c.pbData) {
        int same = !memcmp(a.pbData + 24, c.pbData + 24, 16);
        if (!same) t_note("master key GUID changed between two protects (key rollover?)");
        else CHECK(same);               /* one user master key serves consecutive calls */
    }
    dp_free(&a); dp_free(&c);
}
TEST(dpapi_blob_stable_prefix_between_blobs) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB a = { 0 }, c = { 0 };
    CHECK(mkblob(&a, DESC, NULL, 0, 0, sizeof PT));
    CHECK(mkblob(&c, DESC, NULL, 0, 0, 20));
    if (a.pbData && c.pbData) {
        CHECK(!memcmp(a.pbData, c.pbData, 20));                      /* version + provider */
        CHECK(!memcmp(a.pbData + 40, c.pbData + 40, 4 + 4 + sizeof DESC));  /* flags, descr length, descr */
    }
    dp_free(&a); dp_free(&c);
}
TEST(dpapi_blob_description_field) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    if (b.pbData) {
        EXPECT_EQ(dp_rd(b.pbData, 44), sizeof DESC);                 /* bytes including the terminating NUL */
        CHECK(!memcmp(b.pbData + 48, DESC, sizeof DESC));
    }
    dp_free(&b);
}
TEST(dpapi_blob_description_null_is_two_bytes) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, NULL, NULL, 0, 0, sizeof PT));
    if (b.pbData) { EXPECT_EQ(dp_rd(b.pbData, 44), 2); CHECK(b.pbData[48] == 0 && b.pbData[49] == 0); }
    dp_free(&b);
}
TEST(dpapi_blob_description_empty_same_as_null) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB a = { 0 }, c = { 0 };
    CHECK(mkblob(&a, NULL, NULL, 0, 0, sizeof PT));
    CHECK(mkblob(&c, L"", NULL, 0, 0, sizeof PT));
    CHECK(a.cbData == c.cbData);
    dp_free(&a); dp_free(&c);
}
TEST(dpapi_blob_cipher_alg_aes256) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) { EXPECT_EQ(dp_rd(b.pbData, p.o_algc), CALG_AES_256); EXPECT_EQ(dp_rd(b.pbData, p.o_keylen), 256); }
    dp_free(&b);
}
TEST(dpapi_blob_hash_alg_sha512) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) { EXPECT_EQ(dp_rd(b.pbData, p.o_algh), CALG_SHA_512); EXPECT_EQ(dp_rd(b.pbData, p.o_hashlen), 512); }
    dp_free(&b);
}
TEST(dpapi_blob_salt_16_random) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB a = { 0 }, c = { 0 };
    CHECK(mkblob(&a, DESC, NULL, 0, 0, sizeof PT));
    CHECK(mkblob(&c, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(a.pbData, a.cbData), q = dp_parse(c.pbData, c.cbData);
    if (p.ok && q.ok) {
        EXPECT_EQ(p.saltlen, 16); EXPECT_EQ(q.saltlen, 16);
        CHECK(memcmp(a.pbData + p.o_salt, c.pbData + q.o_salt, 16) != 0);
    }
    dp_free(&a); dp_free(&c);
}
TEST(dpapi_blob_sign_is_sha512_sized) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) EXPECT_EQ(p.signlen, 64);
    dp_free(&b);
}
TEST(dpapi_blob_cipher_length_block_padded) {
    DP_NEED_DATA(); DP_NOT_WINE();
    static const DWORD lens[] = { 0, 1, 15, 16, 17, 31, 32, 33, 48 };
    for (size_t i = 0; i < sizeof lens / sizeof *lens; i++) {
        DATA_BLOB b = { 0 };
        BYTE one = 7;
        BOOL r = dp_protect(lens[i] ? PT : &one, lens[i], NULL, NULL, 0, 0, &b);
        CHECKF(r, "len=%lu", lens[i]);
        if (!r) continue;
        dp_blob_t p = dp_parse(b.pbData, b.cbData);
        CHECKF(p.ok, "len=%lu", lens[i]);
        if (p.ok) {
            CHECKF(p.cipherlen % 16 == 0, "len=%lu cipher=%lu", lens[i], p.cipherlen);
            CHECKF(p.cipherlen > lens[i] && p.cipherlen <= lens[i] + 16, "len=%lu cipher=%lu", lens[i], p.cipherlen);
            CHECKF(p.cipherlen == (lens[i] / 16 + 1) * 16, "len=%lu cipher=%lu", lens[i], p.cipherlen);
        }
        dp_free(&b);
    }
}
TEST(dpapi_blob_total_size_formula) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) {
        DWORD sum = 48 + p.dlen + 8 + 4 + p.saltlen + 4 + p.strlen_ + 12 + p.hmaclen + 4 + p.cipherlen + 4 + p.signlen;
        EXPECT_EQ(sum, b.cbData);
    }
    dp_free(&b);
}
TEST(dpapi_blob_entropy_changes_only_secret_parts) {
    DP_NEED_DATA(); DP_NOT_WINE();
    static const BYTE e[] = "entropy";
    DATA_BLOB a = { 0 }, c = { 0 };
    CHECK(mkblob(&a, DESC, NULL, 0, 0, sizeof PT));
    CHECK(mkblob(&c, DESC, e, sizeof e, 0, sizeof PT));
    dp_blob_t p = dp_parse(a.pbData, a.cbData), q = dp_parse(c.pbData, c.cbData);
    if (p.ok && q.ok) {
        EXPECT_EQ(p.cipherlen, q.cipherlen);
        EXPECT_EQ(p.signlen, q.signlen);
        EXPECT_EQ(dp_rd(a.pbData, p.o_algc), dp_rd(c.pbData, q.o_algc));
        EXPECT_EQ(dp_rd(a.pbData, p.o_algh), dp_rd(c.pbData, q.o_algh));
        t_note("strong/hmac lengths: no-entropy %lu/%lu, entropy %lu/%lu", p.strlen_, p.hmaclen, q.strlen_, q.hmaclen);
    }
    dp_free(&a); dp_free(&c);
}
TEST(dpapi_blob_flags_user_default_note) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    if (b.pbData) t_note("default blob flags 0x%lx", dp_rd(b.pbData, 40));
    dp_free(&b);
}
TEST(dpapi_blob_flags_local_machine_bit4) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, CRYPTPROTECT_LOCAL_MACHINE, sizeof PT));
    if (b.pbData) CHECK((dp_rd(b.pbData, 40) & 4) != 0);
    dp_free(&b);
}
TEST(dpapi_blob_flags_audit_note) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, CRYPTPROTECT_AUDIT, sizeof PT));
    if (b.pbData) t_note("AUDIT blob flags 0x%lx", dp_rd(b.pbData, 40));
    dp_free(&b);
}

/* ---- tamper detection ---- */

static BOOL try_unprotect(const BYTE *blob, DWORD len, DWORD *err) {
    DATA_BLOB p = { 0 };
    LPWSTR d = NULL;
    SET_ERR(0);
    BOOL r = dp_unprotect(blob, len, &d, NULL, 0, 0, &p);
    *err = GetLastError();
    if (r) { /* verify plaintext too */
        if (p.cbData != sizeof PT || memcmp(p.pbData, PT, sizeof PT)) r = 2;
    }
    dp_free(&p); if (d) LocalFree(d);
    return r;
}

TEST(dpapi_tamper_untouched_control) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    DWORD e; CHECK(try_unprotect(b.pbData, b.cbData, &e) == 1);
    dp_free(&b);
}
TEST(dpapi_tamper_every_cipher_byte) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) for (DWORD i = 0; i < p.cipherlen; i++) {
        BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
        c[p.o_cipher + i] ^= 0x01;
        DWORD e; BOOL r = try_unprotect(c, b.cbData, &e);
        CHECKF(r == 0, "cipher byte %lu accepted (r=%d)", i, r);
        CHECKF(r || e == ERROR_INVALID_DATA, "cipher byte %lu err=%lu", i, e);
        free(c);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_every_sign_byte) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) for (DWORD i = 0; i < p.signlen; i += 3) {
        BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
        c[p.o_sign + i] ^= 0x80;
        DWORD e; BOOL r = try_unprotect(c, b.cbData, &e);
        CHECKF(r == 0, "sign byte %lu accepted", i);
        CHECKF(r || e == ERROR_INVALID_DATA, "sign byte %lu err=%lu", i, e);
        free(c);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_every_salt_byte) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) for (DWORD i = 0; i < p.saltlen; i++) {
        BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
        c[p.o_salt + i] ^= 0x01;
        DWORD e; BOOL r = try_unprotect(c, b.cbData, &e);
        CHECKF(r == 0, "salt byte %lu accepted", i);
        CHECKF(r || e == ERROR_INVALID_DATA, "salt byte %lu err=%lu", i, e);
        free(c);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_first_and_last_byte_of_each_region) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) {
        struct { const char *n; DWORD off; int must_fail; } t[] = {
            { "cipher[0]", p.o_cipher, 1 }, { "cipher[last]", p.o_cipher + p.cipherlen - 1, 1 },
            { "sign[0]", p.o_sign, 1 }, { "sign[last]", p.o_sign + p.signlen - 1, 1 },
            { "salt[0]", p.o_salt, 1 }, { "salt[last]", p.o_salt + p.saltlen - 1, 1 },
            { "last blob byte", b.cbData - 1, 1 },
        };
        for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
            BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
            c[t[i].off] ^= 0xff;
            DWORD e; BOOL r = try_unprotect(c, b.cbData, &e);
            CHECKF(r == 0, "%s accepted", t[i].n);
            free(c);
        }
    }
    dp_free(&b);
}
#define HDR_FIELD_FAIL(nm, offexpr, val) \
TEST(dpapi_tamper_##nm) { \
    DP_NEED_DATA(); DP_NOT_WINE(); \
    DATA_BLOB b = { 0 }; \
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT)); \
    dp_blob_t p = dp_parse(b.pbData, b.cbData); \
    if (p.ok) { \
        BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData); \
        dp_wr(c, (offexpr), (val)); \
        DWORD e; BOOL r = try_unprotect(c, b.cbData, &e); \
        CHECK(r == 0); \
        t_note(#nm " -> error %lu", e); \
        free(c); \
    } \
    dp_free(&b); \
}
HDR_FIELD_FAIL(version_2, 0, 2)
HDR_FIELD_FAIL(version_ffffffff, 0, 0xffffffffu)
HDR_FIELD_FAIL(masterkey_version_2, 20, 2)
HDR_FIELD_FAIL(masterkey_version_ffffffff, 20, 0xffffffffu)
HDR_FIELD_FAIL(alg_crypt_unknown, p.o_algc, 0x6699)
HDR_FIELD_FAIL(alg_crypt_zero, p.o_algc, 0)
HDR_FIELD_FAIL(alg_hash_unknown, p.o_algh, 0x8099)
HDR_FIELD_FAIL(alg_hash_zero, p.o_algh, 0)
HDR_FIELD_FAIL(salt_len_zero, p.o_saltlen, 0)
HDR_FIELD_FAIL(salt_len_huge, p.o_saltlen, 0x7fffffff)
HDR_FIELD_FAIL(cipher_len_plus16, p.o_cipherlen, p.cipherlen + 16)
HDR_FIELD_FAIL(cipher_len_minus16, p.o_cipherlen, p.cipherlen - 16)
HDR_FIELD_FAIL(cipher_len_zero, p.o_cipherlen, 0)
HDR_FIELD_FAIL(cipher_len_huge, p.o_cipherlen, 0xffffff00u)
HDR_FIELD_FAIL(sign_len_zero, p.o_signlen, 0)
HDR_FIELD_FAIL(sign_len_huge, p.o_signlen, 0xffffff00u)
HDR_FIELD_FAIL(sign_len_plus_one, p.o_signlen, p.signlen + 1)
HDR_FIELD_FAIL(descr_len_zero, 44, 0)
HDR_FIELD_FAIL(descr_len_odd, 44, sizeof DESC - 1)
HDR_FIELD_FAIL(descr_len_huge, 44, 0x7fffffff)

TEST(dpapi_tamper_provider_guid_every_byte) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    if (b.pbData) for (DWORD i = 4; i < 20; i++) {
        BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
        c[i] ^= 0x01;
        DWORD e; BOOL r = try_unprotect(c, b.cbData, &e);
        CHECKF(r == 0, "provider guid byte %lu accepted", i - 4);
        free(c);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_masterkey_guid_every_byte) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    if (b.pbData) for (DWORD i = 24; i < 40; i++) {
        BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
        c[i] ^= 0x01;
        DWORD e; BOOL r = try_unprotect(c, b.cbData, &e);
        CHECKF(r == 0, "master key guid byte %lu accepted", i - 24);
        if (i == 24) t_note("unknown master key GUID -> error %lu", e);
        free(c);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_truncations) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    static const DWORD cut[] = { 1, 2, 4, 8, 16, 32, 63, 64, 65, 80, 100 };
    for (size_t i = 0; i < sizeof cut / sizeof *cut && b.pbData; i++) {
        if (cut[i] >= b.cbData) continue;
        DWORD e; BOOL r = try_unprotect(b.pbData, b.cbData - cut[i], &e);
        CHECKF(r == 0, "blob truncated by %lu accepted", cut[i]);
        CHECKF(r || DP_IS_BLOB_ERR(e), "truncated by %lu err=%lu", cut[i], e);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_truncate_into_header_sizes) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) {
        DWORD cuts[] = { 0x33, 0x34, 0x35, 48, 48 + p.dlen - 1, 48 + p.dlen, 48 + p.dlen + 4, p.o_salt, p.o_str, p.o_hmac, p.o_cipher, p.o_sign };
        for (size_t i = 0; i < sizeof cuts / sizeof *cuts; i++) {
            DWORD e; BOOL r = try_unprotect(b.pbData, cuts[i], &e);
            CHECKF(r == 0, "truncated to %lu bytes accepted", cuts[i]);
            CHECKF(r || DP_IS_BLOB_ERR(e), "to %lu err=%lu", cuts[i], e);
        }
    }
    dp_free(&b);
}
TEST(dpapi_tamper_trailing_bytes_observed) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    if (b.pbData) {
        BYTE *c = malloc(b.cbData + 16); memcpy(c, b.pbData, b.cbData); memset(c + b.cbData, 0xaa, 16);
        DWORD e; BOOL r = try_unprotect(c, b.cbData + 16, &e);
        t_note("blob with 16 trailing bytes -> r=%d err=%lu", r, e);
        free(c);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_description_bytes_observed) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    if (b.pbData) {
        int accepted = 0;
        for (DWORD i = 0; i < sizeof DESC; i++) {
            BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
            c[48 + i] ^= 0x02;
            DWORD e; BOOL r = try_unprotect(c, b.cbData, &e);
            if (r) accepted++;
            free(c);
        }
        t_note("description byte flips accepted: %d of %u (signature covers description if 0)", accepted, (unsigned)sizeof DESC);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_flags_field_observed) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    if (b.pbData) {
        static const DWORD v[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40 };
        for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
            BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
            dp_wr(c, 40, dp_rd(c, 40) ^ v[i]);
            DWORD e; BOOL r = try_unprotect(c, b.cbData, &e);
            t_note("blob flags ^ 0x%lx -> r=%d err=%lu", v[i], r, e);
            free(c);
        }
    }
    dp_free(&b);
}
TEST(dpapi_tamper_strong_hmac_bytes_observed) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(b.pbData, b.cbData);
    if (p.ok) {
        int acc_s = 0, acc_h = 0;
        for (DWORD i = 0; i < p.strlen_; i++) { BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData); c[p.o_str + i] ^= 1; DWORD e; if (try_unprotect(c, b.cbData, &e)) acc_s++; free(c); }
        for (DWORD i = 0; i < p.hmaclen; i++) { BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData); c[p.o_hmac + i] ^= 1; DWORD e; if (try_unprotect(c, b.cbData, &e)) acc_h++; free(c); }
        t_note("strong field %lu bytes (flips accepted %d), hmac field %lu bytes (flips accepted %d)", p.strlen_, acc_s, p.hmaclen, acc_h);
    }
    dp_free(&b);
}
TEST(dpapi_tamper_swap_signature_between_blobs) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB a = { 0 }, c = { 0 };
    CHECK(mkblob(&a, DESC, NULL, 0, 0, sizeof PT));
    CHECK(mkblob(&c, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(a.pbData, a.cbData), q = dp_parse(c.pbData, c.cbData);
    if (p.ok && q.ok && p.signlen == q.signlen && a.cbData == c.cbData) {
        BYTE *m = malloc(a.cbData); memcpy(m, a.pbData, a.cbData);
        memcpy(m + p.o_sign, c.pbData + q.o_sign, q.signlen);
        DWORD e; BOOL r = try_unprotect(m, a.cbData, &e);
        CHECK(r == 0); CHECKF(r || e == ERROR_INVALID_DATA, "err=%lu", e);
        free(m);
    }
    dp_free(&a); dp_free(&c);
}
TEST(dpapi_tamper_swap_cipher_between_blobs) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB a = { 0 }, c = { 0 };
    CHECK(mkblob(&a, DESC, NULL, 0, 0, sizeof PT));
    CHECK(mkblob(&c, DESC, NULL, 0, 0, sizeof PT));
    dp_blob_t p = dp_parse(a.pbData, a.cbData), q = dp_parse(c.pbData, c.cbData);
    if (p.ok && q.ok && p.cipherlen == q.cipherlen) {
        BYTE *m = malloc(a.cbData); memcpy(m, a.pbData, a.cbData);
        memcpy(m + p.o_cipher, c.pbData + q.o_cipher, q.cipherlen);
        DWORD e; BOOL r = try_unprotect(m, a.cbData, &e);
        CHECK(r == 0); CHECKF(r || e == ERROR_INVALID_DATA, "err=%lu", e);
        free(m);
    }
    dp_free(&a); dp_free(&c);
}
TEST(dpapi_tamper_wrong_entropy_error_is_invalid_data) {
    DP_NEED_DATA(); DP_NOT_WINE();
    static const BYTE e1[] = "right", e2[] = "wrong";
    DATA_BLOB b = { 0 }, p = { 0 };
    CHECK(mkblob(&b, DESC, e1, sizeof e1, 0, sizeof PT));
    SET_ERR(0);
    CHECK(!dp_unprotect(b.pbData, b.cbData, NULL, e2, sizeof e2, 0, &p));
    EXPECT_ERR(ERROR_INVALID_DATA);
    EXPECT_NE(GetLastError(), (DWORD)NTE_BAD_DATA);
    dp_free(&b);
}
TEST(dpapi_tamper_intact_after_failures) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB b = { 0 };
    CHECK(mkblob(&b, DESC, NULL, 0, 0, sizeof PT));
    BYTE *c = malloc(b.cbData); memcpy(c, b.pbData, b.cbData);
    c[b.cbData - 1] ^= 1;
    DWORD e; CHECK(try_unprotect(c, b.cbData, &e) == 0);
    CHECK(try_unprotect(b.pbData, b.cbData, &e) == 1);   /* a failed attempt leaves no residue */
    free(c); dp_free(&b);
}

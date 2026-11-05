/* BCrypt RSA key generation, properties, blob import/export. */
#include "rd.h"

/* ---------- provider ---------- */
TEST(rsa_keys_provider_open_close) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE h = NULL;
    EXPECT_EQ(U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_RSA_ALGORITHM, NULL, 0), ST_SUCCESS);
    CHECK(h != NULL);
    EXPECT_EQ(U(BCryptCloseAlgorithmProvider)(h, 0), ST_SUCCESS);
}
TEST(rsa_keys_provider_open_sign_alg) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE h = NULL;
    EXPECT_EQ(U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_RSA_SIGN_ALGORITHM, NULL, 0), ST_SUCCESS);
    CHECK(h != NULL);
    rd_closealg(h);
}
TEST(rsa_keys_provider_algorithm_name) {
    NEED_BCRYPT();
    struct { LPCWSTR id; } t[] = { { BCRYPT_RSA_ALGORITHM }, { BCRYPT_RSA_SIGN_ALGORITHM }, { BCRYPT_DSA_ALGORITHM } };
    for (int i = 0; i < 3; i++) {
        BCRYPT_ALG_HANDLE a = rd_alg(t[i].id);
        CHECK(a != NULL); if (!a) continue;
        WCHAR name[64] = {0}; ULONG n = 0;
        EXPECT_EQ(U(BCryptGetProperty)(a, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof name, &n, 0), ST_SUCCESS);
        EXPECT_WSTR(name, t[i].id);
        EXPECT_EQ(n, (lstrlenW(t[i].id) + 1) * sizeof(WCHAR));
        rd_closealg(a);
    }
}
TEST(rsa_keys_provider_name_buffer_protocol) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    ULONG n = 0; WCHAR b[8];
    EXPECT_EQ(U(BCryptGetProperty)(a, BCRYPT_ALGORITHM_NAME, NULL, 0, &n, 0), ST_SUCCESS);
    EXPECT_EQ(n, 8);   /* L"RSA" + NUL */
    n = 0;
    EXPECT_EQ(U(BCryptGetProperty)(a, BCRYPT_ALGORITHM_NAME, (PUCHAR)b, 6, &n, 0), ST_BUFFER_TOO_SMALL);
    EXPECT_EQ(n, 8);
    n = 0;
    EXPECT_EQ(U(BCryptGetProperty)(a, BCRYPT_ALGORITHM_NAME, (PUCHAR)b, 8, &n, 0), ST_SUCCESS);
    EXPECT_EQ(n, 8);
    EXPECT_WSTR(b, L"RSA");
    rd_closealg(a);
}
TEST(rsa_keys_provider_key_lengths_rsa) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_LENGTHS_STRUCT kl = {0}; ULONG n = 0;
    EXPECT_EQ(U(BCryptGetProperty)(a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof kl, &n, 0), ST_SUCCESS);
    EXPECT_EQ(n, sizeof kl);
    EXPECT_EQ(kl.dwMinLength, 512);
    EXPECT_EQ(kl.dwMaxLength, 16384);
    EXPECT_EQ(kl.dwIncrement, 8);
    n = 0;
    EXPECT_EQ(U(BCryptGetProperty)(a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof kl - 1, &n, 0), ST_BUFFER_TOO_SMALL);
    EXPECT_EQ(n, sizeof kl);
    rd_closealg(a);
}
TEST(rsa_keys_provider_key_lengths_sign_alg) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_SIGN_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_LENGTHS_STRUCT kl = {0}; ULONG n = 0;
    EXPECT_EQ(U(BCryptGetProperty)(a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof kl, &n, 0), ST_SUCCESS);
    EXPECT_EQ(kl.dwMinLength, 512);
    EXPECT_EQ(kl.dwMaxLength, 16384);
    EXPECT_EQ(kl.dwIncrement, 8);
    rd_closealg(a);
}
TEST(rsa_keys_provider_key_lengths_dsa) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_DSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_LENGTHS_STRUCT kl = {0}; ULONG n = 0;
    EXPECT_EQ(U(BCryptGetProperty)(a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof kl, &n, 0), ST_SUCCESS);
    EXPECT_EQ(kl.dwMinLength, 512);
    EXPECT_EQ(kl.dwMaxLength, 3072);
    EXPECT_EQ(kl.dwIncrement, 64);
    rd_closealg(a);
}
TEST(rsa_keys_provider_padding_schemes) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    ULONG v = 0, n = 0;
    NTSTATUS s = U(BCryptGetProperty)(a, BCRYPT_PADDING_SCHEMES, (PUCHAR)&v, sizeof v, &n, 0);
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(n, 4); EXPECT_EQ(v, 0x1e);  /* probed: PKCS1|OAEP|PSS|(0x10) bits as reported by the provider */
    rd_closealg(a);
    a = rd_alg(BCRYPT_DSA_ALGORITHM); CHECK(a); if (!a) return;
    s = U(BCryptGetProperty)(a, BCRYPT_PADDING_SCHEMES, (PUCHAR)&v, sizeof v, &n, 0);
    EXPECT_EQ(s, ST_NOT_SUPPORTED);
    rd_closealg(a);
}

/* ---------- GenerateKeyPair argument validation ---------- */
TEST(rsa_keys_gen_null_alg) {
    NEED_BCRYPT();
    BCRYPT_KEY_HANDLE k = (BCRYPT_KEY_HANDLE)0x1234;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(NULL, &k, 1024, 0), ST_INVALID_HANDLE);
}
TEST(rsa_keys_gen_null_phkey) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(a, NULL, 1024, 0), ST_INVALID_PARAMETER);
    rd_closealg(a);
}
TEST(rsa_keys_gen_symmetric_alg_not_supported) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_AES_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(a, &k, 1024, 0), ST_NOT_SUPPORTED);
    CHECK(k == NULL);
    rd_closealg(a);
}
TEST(rsa_keys_gen_hash_alg_not_supported) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_SHA256_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(a, &k, 1024, 0), ST_NOT_SUPPORTED);
    rd_closealg(a);
}
TEST(rsa_keys_gen_key_handle_as_alg) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512), k2 = NULL; CHECK(k); if (!k) { rd_closealg(a); return; }
    EXPECT_EQ(U(BCryptGenerateKeyPair)((BCRYPT_ALG_HANDLE)k, &k2, 512, 0), ST_INVALID_HANDLE);
    rd_destroy(k); rd_closealg(a);
}
/* valid lengths: generate + finalize must work, KeyLength/KeyStrength/SignatureLength agree */
static const ULONG g_valid_bits[] = { 512, 576, 640, 704, 768, 1024, 1088, 1536, 2048 };
TEST(rsa_keys_gen_valid_lengths) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    for (size_t i = 0; i < sizeof g_valid_bits / sizeof *g_valid_bits; i++) {
        ULONG bits = g_valid_bits[i];
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = U(BCryptGenerateKeyPair)(a, &k, bits, 0);
        CHECKF(s == 0, "gen %lu -> 0x%lx", bits, (unsigned long)s);
        if (s) continue;
        CHECK(k != NULL);
        s = U(BCryptFinalizeKeyPair)(k, 0);
        CHECKF(s == 0, "finalize %lu -> 0x%lx", bits, (unsigned long)s);
        NTSTATUS ps;
        EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), bits); EXPECT_EQ(ps, 0);
        EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_STRENGTH, &ps), bits); EXPECT_EQ(ps, 0);
        EXPECT_EQ(rd_getdw(k, BCRYPT_SIGNATURE_LENGTH, &ps), bits / 8); EXPECT_EQ(ps, 0);
        rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_gen_4096) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 4096);
    CHECK(k != NULL);
    if (k) { NTSTATUS ps; EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 4096); rd_destroy(k); }
    rd_closealg(a);
}
/* lengths that violate min/increment: the pipeline generate+finalize must fail somewhere */
static const ULONG g_bad_bits[] = { 0, 1, 64, 256, 448, 511, 513, 1023, 1025, 2047, 4097, 16448 };
TEST(rsa_keys_gen_invalid_lengths_fail) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    for (size_t i = 0; i < sizeof g_bad_bits / sizeof *g_bad_bits; i++) {
        ULONG bits = g_bad_bits[i]; BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS sg = U(BCryptGenerateKeyPair)(a, &k, bits, 0), sf = 0;
        if (sg == 0) { sf = U(BCryptFinalizeKeyPair)(k, 0); }
        t_label("bits %lu", bits);
        EXPECT_EQ(sg, ST_INVALID_PARAMETER);
        if (sg == 0) rd_destroy(k);
    }
    rd_closealg(a);
}
/* the key-length increment is 8 bits, so 1000 is a valid size on Win10 */
TEST(rsa_keys_gen_increment_8_bits) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(a, &k, 1000, 0), ST_SUCCESS);
    if (k) {
        EXPECT_EQ(U(BCryptFinalizeKeyPair)(k, 0), ST_SUCCESS);
        NTSTATUS ps; EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 1000);
        UCHAR *b; ULONG l;
        EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &b, &l), ST_SUCCESS);
        if (b) { const BCRYPT_RSAKEY_BLOB *h = (const BCRYPT_RSAKEY_BLOB *)b; EXPECT_EQ(h->BitLength, 1000); EXPECT_EQ(h->cbModulus, 125); free(b); }
        rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_gen_unfinalized_ops_fail) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(a, &k, 512, 0), ST_SUCCESS); CHECK(k);
    if (!k) { rd_closealg(a); return; }
    UCHAR in[16] = {1}, out[64]; ULONG n = 0;
    /* an unfinalized key cannot be used to encrypt */
    NTSTATUS se = U(BCryptEncrypt)(k, in, sizeof in, NULL, NULL, 0, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
    EXPECT_EQ(se, ST_INVALID_HANDLE);
    NTSTATUS s = U(BCryptSignHash)(k, NULL, in, 20, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
    EXPECT_EQ(s, ST_INVALID_HANDLE);
    UCHAR *b; ULONG bl;
    s = rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &b, &bl);
    EXPECT_EQ(s, ST_INVALID_HANDLE); if (!s) free(b);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_finalize_null_handle) {
    NEED_BCRYPT();
    EXPECT_EQ(U(BCryptFinalizeKeyPair)(NULL, 0), ST_INVALID_HANDLE);
}
TEST(rsa_keys_finalize_alg_handle) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    EXPECT_EQ(U(BCryptFinalizeKeyPair)((BCRYPT_KEY_HANDLE)a, 0), ST_INVALID_HANDLE);
    rd_closealg(a);
}
TEST(rsa_keys_finalize_twice) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    NTSTATUS s = U(BCryptFinalizeKeyPair)(k, 0);
    EXPECT_EQ(s, ST_INVALID_HANDLE);  /* probed: a finalized key cannot be finalized again */
    /* key must remain usable */
    NTSTATUS ps; EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 512); EXPECT_EQ(ps, 0);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_destroy_semantics) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    EXPECT_EQ(U(BCryptDestroyKey)(k), ST_SUCCESS);
    EXPECT_EQ(U(BCryptDestroyKey)(NULL), ST_INVALID_HANDLE);
    rd_closealg(a);
}
TEST(rsa_keys_destroy_alg_as_key) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    EXPECT_EQ(U(BCryptDestroyKey)((BCRYPT_KEY_HANDLE)a), ST_INVALID_HANDLE);
    rd_closealg(a);
}
TEST(rsa_keys_key_survives_alg_close) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    rd_closealg(a);
    NTSTATUS ps; ULONG v = rd_getdw(k, BCRYPT_KEY_LENGTH, &ps);
    EXPECT_EQ(ps, 0); EXPECT_EQ(v, 512);
    UCHAR *b; ULONG bl;
    EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &b, &bl), ST_SUCCESS);
    free(b);
    rd_destroy(k);
}
TEST(rsa_keys_gen_keys_are_distinct) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k1 = rd_gen(a, 512), k2 = rd_gen(a, 512);
    CHECK(k1 && k2 && k1 != k2);
    UCHAR *b1 = NULL, *b2 = NULL; ULONG l1 = 0, l2 = 0;
    if (k1 && k2) {
        rd_export(k1, BCRYPT_RSAPUBLIC_BLOB, &b1, &l1); rd_export(k2, BCRYPT_RSAPUBLIC_BLOB, &b2, &l2);
        CHECK(l1 == l2 && b1 && b2 && memcmp(b1, b2, l1) != 0);
    }
    free(b1); free(b2); rd_destroy(k1); rd_destroy(k2); rd_closealg(a);
}
TEST(rsa_keys_set_key_length_before_finalize) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(a, &k, 512, 0), ST_SUCCESS); CHECK(k);
    if (!k) { rd_closealg(a); return; }
    ULONG want = 1024;
    NTSTATUS s = U(BCryptSetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&want, sizeof want, 0);
    NTSTATUS f = U(BCryptFinalizeKeyPair)(k, 0);
    NTSTATUS ps; ULONG got = rd_getdw(k, BCRYPT_KEY_LENGTH, &ps);
    /* probed: the new length is accepted before finalize and takes effect */
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(f, ST_SUCCESS); EXPECT_EQ(ps, 0); EXPECT_EQ(got, 1024);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_set_property_after_finalize) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    ULONG want = 1024;
    NTSTATUS s = U(BCryptSetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&want, sizeof want, 0);
    /* Win10 accepts the set on a finalized key and the property reads back the new value */
    EXPECT_EQ(s, ST_SUCCESS);
    NTSTATUS ps; EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 1024);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_get_property_buffer_protocol) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    ULONG n = 0, v = 0;
    EXPECT_EQ(U(BCryptGetProperty)(k, BCRYPT_KEY_LENGTH, NULL, 0, &n, 0), ST_SUCCESS);
    EXPECT_EQ(n, 4);
    n = 0;
    EXPECT_EQ(U(BCryptGetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 3, &n, 0), ST_BUFFER_TOO_SMALL);
    EXPECT_EQ(n, 4);
    EXPECT_EQ(U(BCryptGetProperty)(k, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, NULL, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptGetProperty)(k, L"NoSuchPropertyXyz", (PUCHAR)&v, 4, &n, 0), ST_NOT_SUPPORTED);
    EXPECT_EQ(U(BCryptGetProperty)(NULL, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, &n, 0), ST_INVALID_HANDLE);
    rd_destroy(k); rd_closealg(a);
}

/* ---------- Export: generated keys ---------- */
static void check_pub_header(const UCHAR *b, ULONG len, ULONG bits) {
    const BCRYPT_RSAKEY_BLOB *h = (const BCRYPT_RSAKEY_BLOB *)b;
    CHECK(len >= sizeof *h); if (len < sizeof *h) return;
    EXPECT_EQ(h->Magic, BCRYPT_RSAPUBLIC_MAGIC);
    EXPECT_EQ(h->BitLength, bits);
    EXPECT_EQ(h->cbPublicExp, 3);
    EXPECT_EQ(h->cbModulus, bits / 8);
    EXPECT_EQ(h->cbPrime1, 0);
    EXPECT_EQ(h->cbPrime2, 0);
    EXPECT_EQ(len, sizeof *h + 3 + bits / 8);
    EXPECT_EQ(sizeof *h, 24);
    if (len >= sizeof *h + 3) { CHECK(b[24] == 1 && b[25] == 0 && b[26] == 1); }
    if (len >= sizeof *h + 3 + 1) CHECK(b[27] & 0x80);   /* modulus is exactly bits long: top bit set, big-endian first */
}
TEST(rsa_keys_export_public_layout) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    static const ULONG sizes[] = { 512, 1024, 2048 };
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = rd_gen(a, sizes[i]); CHECK(k); if (!k) continue;
        UCHAR *b; ULONG l;
        EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &b, &l), ST_SUCCESS);
        if (b) { check_pub_header(b, l, sizes[i]); free(b); }
        rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_export_generic_public_blob) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 1024); CHECK(k); if (!k) { rd_closealg(a); return; }
    UCHAR *b1, *b2; ULONG l1, l2;
    EXPECT_EQ(rd_export(k, BCRYPT_PUBLIC_KEY_BLOB, &b1, &l1), ST_SUCCESS);
    EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &b2, &l2), ST_SUCCESS);
    CHECK(l1 == l2 && b1 && b2 && !memcmp(b1, b2, l1));
    free(b1); free(b2); rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_export_private_layout) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    static const ULONG sizes[] = { 512, 1024, 2048 };
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = rd_gen(a, sizes[i]); CHECK(k); if (!k) continue;
        UCHAR *b; ULONG l; ULONG bits = sizes[i];
        EXPECT_EQ(rd_export(k, BCRYPT_RSAPRIVATE_BLOB, &b, &l), ST_SUCCESS);
        if (b) {
            const BCRYPT_RSAKEY_BLOB *h = (const BCRYPT_RSAKEY_BLOB *)b;
            EXPECT_EQ(h->Magic, BCRYPT_RSAPRIVATE_MAGIC);
            EXPECT_EQ(h->BitLength, bits);
            EXPECT_EQ(h->cbPublicExp, 3);
            EXPECT_EQ(h->cbModulus, bits / 8);
            EXPECT_EQ(h->cbPrime1, bits / 16);
            EXPECT_EQ(h->cbPrime2, bits / 16);
            EXPECT_EQ(l, 24 + 3 + bits / 8 + bits / 8);
            /* P*Q == N (big-endian), compared on the top bytes via a simple check: P and Q have top bit set */
            const UCHAR *p = b + 24 + 3 + bits / 8;
            CHECK(p[0] & 0x80); CHECK(p[bits / 16] & 0x80);
            free(b);
        }
        rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_export_generic_private_blob) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 1024); CHECK(k); if (!k) { rd_closealg(a); return; }
    UCHAR *b1, *b2; ULONG l1 = 0, l2 = 0;
    NTSTATUS s = rd_export(k, BCRYPT_PRIVATE_KEY_BLOB, &b1, &l1);
    EXPECT_EQ(s, ST_SUCCESS);
    EXPECT_EQ(rd_export(k, BCRYPT_RSAPRIVATE_BLOB, &b2, &l2), ST_SUCCESS);
    CHECK(l1 == l2 && b1 && b2 && !memcmp(b1, b2, l1));
    free(b1); free(b2); rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_export_fullprivate_layout) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    static const ULONG sizes[] = { 512, 1024, 2048 };
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = rd_gen(a, sizes[i]); CHECK(k); if (!k) continue;
        UCHAR *b; ULONG l; ULONG bits = sizes[i];
        EXPECT_EQ(rd_export(k, BCRYPT_RSAFULLPRIVATE_BLOB, &b, &l), ST_SUCCESS);
        if (b) {
            const BCRYPT_RSAKEY_BLOB *h = (const BCRYPT_RSAKEY_BLOB *)b;
            EXPECT_EQ(h->Magic, BCRYPT_RSAFULLPRIVATE_MAGIC);
            EXPECT_EQ(h->BitLength, bits);
            EXPECT_EQ(h->cbPublicExp, 3);
            EXPECT_EQ(h->cbModulus, bits / 8);
            EXPECT_EQ(h->cbPrime1, bits / 16);
            EXPECT_EQ(h->cbPrime2, bits / 16);
            /* exp, mod, P, Q, DP, DQ, InvQ, D */
            EXPECT_EQ(l, 24 + 3 + bits / 8 + 5 * (bits / 16) + bits / 8);
            free(b);
        }
        rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_export_size_protocol) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 1024); CHECK(k); if (!k) { rd_closealg(a); return; }
    LPCWSTR types[] = { BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSAPRIVATE_BLOB, BCRYPT_RSAFULLPRIVATE_BLOB, LEGACY_RSAPUBLIC_BLOB, LEGACY_RSAPRIVATE_BLOB };
    for (int i = 0; i < 5; i++) {
        ULONG need = 0, n = 0; UCHAR buf[2048];
        EXPECT_EQ(U(BCryptExportKey)(k, NULL, types[i], NULL, 0, &need, 0), ST_SUCCESS);
        CHECK(need > 0 && need < sizeof buf);
        if (!need || need >= sizeof buf) continue;
        n = 0;
        t_label("%d", i);
        NTSTATUS bts = (i >= 3) ? (NTSTATUS)0x80090028 : ST_BUFFER_TOO_SMALL;   /* legacy CAPI blobs report NTE_BUFFER_TOO_SMALL */   /* pinned per type from the probe */
        NTSTATUS s1 = U(BCryptExportKey)(k, NULL, types[i], buf, need - 1, &n, 0);
        EXPECT_EQ(s1, bts);
        EXPECT_EQ(n, need);
        n = 0;
        s1 = U(BCryptExportKey)(k, NULL, types[i], buf, 0, &n, 0);
        EXPECT_EQ(s1, bts);
        n = 0;
        EXPECT_EQ(U(BCryptExportKey)(k, NULL, types[i], buf, need, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, need);
        n = 0;
        EXPECT_EQ(U(BCryptExportKey)(k, NULL, types[i], buf, sizeof buf, &n, 0), ST_SUCCESS);
        EXPECT_EQ(n, need);
    }
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_export_param_validation) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    ULONG n = 0; UCHAR buf[512];
    EXPECT_EQ(U(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, buf, sizeof buf, NULL, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptExportKey)(k, NULL, NULL, buf, sizeof buf, &n, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptExportKey)(NULL, NULL, BCRYPT_RSAPUBLIC_BLOB, buf, sizeof buf, &n, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(U(BCryptExportKey)(NULL, NULL, NULL, buf, sizeof buf, &n, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptExportKey)((BCRYPT_KEY_HANDLE)a, NULL, BCRYPT_RSAPUBLIC_BLOB, buf, sizeof buf, &n, 0), ST_INVALID_HANDLE);
    NTSTATUS s = U(BCryptExportKey)(k, NULL, L"NoSuchBlobType", buf, sizeof buf, &n, 0);
    EXPECT_EQ(s, ST_NOT_SUPPORTED);
    s = U(BCryptExportKey)(k, NULL, BCRYPT_DSA_PUBLIC_BLOB, buf, sizeof buf, &n, 0);
    EXPECT_EQ(s, ST_NOT_SUPPORTED);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_export_blob_type_case) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    ULONG n = 0;
    NTSTATUS s = U(BCryptExportKey)(k, NULL, L"rsapublicblob", NULL, 0, &n, 0);
    EXPECT_EQ(s, ST_NOT_SUPPORTED);  /* probed: blob type names are case sensitive */
    EXPECT_EQ(U(BCryptExportKey)(k, NULL, L"RSAPUBLICBLOB", NULL, 0, &n, 0), ST_SUCCESS);
    rd_destroy(k); rd_closealg(a);
}

/* ---------- Import / export: fixed key ---------- */
TEST(rsa_keys_import_public_roundtrip) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[RD_RSA_BLOB_MAX]; ULONG il = rd_rsa_blob(in, BCRYPT_RSAPUBLIC_MAGIC, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(a, BCRYPT_RSAPUBLIC_BLOB, in, il, &k), ST_SUCCESS); CHECK(k);
    if (k) {
        UCHAR *o; ULONG ol;
        EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == il && o && !memcmp(o, in, il));
        free(o);
        NTSTATUS ps;
        EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 1024); EXPECT_EQ(ps, 0);
        rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_import_public_as_generic_type) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[RD_RSA_BLOB_MAX]; ULONG il = rd_rsa_blob(in, BCRYPT_RSAPUBLIC_MAGIC, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(a, BCRYPT_PUBLIC_KEY_BLOB, in, il, &k), ST_SUCCESS);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_import_private_as_generic_type) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[RD_RSA_BLOB_MAX]; ULONG il = rd_rsa_blob(in, BCRYPT_RSAPRIVATE_MAGIC, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(a, BCRYPT_PRIVATE_KEY_BLOB, in, il, &k), ST_SUCCESS);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_import_private_export_forms) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_fixed_rsa(a, BCRYPT_RSAPRIVATE_MAGIC); CHECK(k); if (!k) { rd_closealg(a); return; }
    UCHAR in[RD_RSA_BLOB_MAX], *o; ULONG il, ol;
    il = rd_rsa_blob(in, BCRYPT_RSAPRIVATE_MAGIC, 0);
    EXPECT_EQ(rd_export(k, BCRYPT_RSAPRIVATE_BLOB, &o, &ol), ST_SUCCESS);
    CHECK(ol == il);
    if (o) { CHECK(!memcmp(o, in, il)); free(o); }   /* probed: the export reproduces the imported blob byte for byte */
    il = rd_rsa_blob(in, BCRYPT_RSAFULLPRIVATE_MAGIC, 1);
    EXPECT_EQ(rd_export(k, BCRYPT_RSAFULLPRIVATE_BLOB, &o, &ol), ST_SUCCESS);
    CHECK(ol == il);
    if (o && ol == il) {
        CHECK(!memcmp(o, in, il));  /* probed: identical to the authoring-time blob, CRT values included */
        free(o);
    }
    EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &o, &ol), ST_SUCCESS);
    il = rd_rsa_blob(in, BCRYPT_RSAPUBLIC_MAGIC, 0);
    CHECK(ol == il && o && !memcmp(o, in, il));
    free(o);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_import_fullprivate_roundtrip) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_fixed_rsa(a, BCRYPT_RSAFULLPRIVATE_MAGIC); CHECK(k); if (!k) { rd_closealg(a); return; }
    UCHAR in[RD_RSA_BLOB_MAX], *o; ULONG il = rd_rsa_blob(in, BCRYPT_RSAFULLPRIVATE_MAGIC, 1), ol;
    EXPECT_EQ(rd_export(k, BCRYPT_RSAFULLPRIVATE_BLOB, &o, &ol), ST_SUCCESS);
    CHECK(ol == il && o && !memcmp(o, in, il));
    free(o);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_import_private_key_can_export_after_all_blob_types) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    static const ULONG mg[] = { BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_RSAPRIVATE_MAGIC, BCRYPT_RSAFULLPRIVATE_MAGIC };
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = rd_fixed_rsa(a, mg[i]); CHECKF(k != NULL, "import magic %d", i); if (!k) continue;
        UCHAR *o; ULONG ol;
        /* a public-only key can only export public data; private exports require private material */
        NTSTATUS s = rd_export(k, BCRYPT_RSAPRIVATE_BLOB, &o, &ol); if (!s) free(o);
        if (i == 0) EXPECT_EQ(s, ST_INVALID_PARAMETER); else EXPECT_EQ(s, ST_SUCCESS);
        s = rd_export(k, BCRYPT_RSAFULLPRIVATE_BLOB, &o, &ol); if (!s) free(o);
        if (i == 0) EXPECT_EQ(s, ST_INVALID_PARAMETER); else EXPECT_EQ(s, ST_SUCCESS);
        s = rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &o, &ol); if (!s) free(o);
        EXPECT_EQ(s, ST_SUCCESS);
        rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_import_params_validation) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[RD_RSA_BLOB_MAX]; ULONG il = rd_rsa_blob(in, BCRYPT_RSAPUBLIC_MAGIC, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptImportKeyPair)(NULL, NULL, BCRYPT_RSAPUBLIC_BLOB, &k, in, il, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(U(BCryptImportKeyPair)(a, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, in, il, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptImportKeyPair)(a, NULL, NULL, &k, in, il, 0), ST_INVALID_PARAMETER);
    CHECK(k == NULL);
    rd_closealg(a);
}
TEST(rsa_keys_import_truncated_blobs_fail) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    static const ULONG mg[] = { BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_RSAPRIVATE_MAGIC, BCRYPT_RSAFULLPRIVATE_MAGIC };
    static LPCWSTR ty[3];
    ty[0] = BCRYPT_RSAPUBLIC_BLOB; ty[1] = BCRYPT_RSAPRIVATE_BLOB; ty[2] = BCRYPT_RSAFULLPRIVATE_BLOB;
    for (int i = 0; i < 3; i++) {
        UCHAR in[RD_RSA_BLOB_MAX]; ULONG il = rd_rsa_blob(in, mg[i], 0);
        ULONG cuts[] = { 0, 1, 8, 23, 24, 25, 26, 27, 28, 100, il - 1 };
        for (size_t c = 0; c < sizeof cuts / sizeof *cuts; c++) {
            BCRYPT_KEY_HANDLE k = NULL;
            NTSTATUS s = rd_import(a, ty[i], in, cuts[c], &k);
            /* probed: a zero-length blob is INVALID_PARAMETER (NTE_INVALID_PARAMETER for the full private blob, as is any
             * cut shorter than its 24-byte header); every other truncation is NTE_BAD_DATA */
            t_label("type %d cut %lu", i, cuts[c]);
            NTSTATUS want = (cuts[c] == 0 && i < 2) ? ST_INVALID_PARAMETER
                          : (i == 2 && cuts[c] < 24) ? (NTSTATUS)0x80090027 : (NTSTATUS)0x80090005;
            EXPECT_EQ(s, want);
            if (s == 0) rd_destroy(k);
        }
    }
    rd_closealg(a);
}
TEST(rsa_keys_import_wrong_magic_fails) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[RD_RSA_BLOB_MAX]; ULONG il = rd_rsa_blob(in, BCRYPT_RSAPUBLIC_MAGIC, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    /* public magic under the private type and vice versa */
    NTSTATUS s = rd_import(a, BCRYPT_RSAPRIVATE_BLOB, in, il, &k);
    EXPECT_EQ(s, (NTSTATUS)0x80090005); if (!s) rd_destroy(k);
    il = rd_rsa_blob(in, BCRYPT_RSAPRIVATE_MAGIC, 0);
    s = rd_import(a, BCRYPT_RSAPUBLIC_BLOB, in, il, &k);
    EXPECT_EQ(s, (NTSTATUS)0x80090005); if (!s) rd_destroy(k);
    ((BCRYPT_RSAKEY_BLOB *)in)->Magic = 0x41424344;
    s = rd_import(a, BCRYPT_RSAPRIVATE_BLOB, in, il, &k);
    EXPECT_EQ(s, (NTSTATUS)0x80090005); if (!s) rd_destroy(k);
    rd_closealg(a);
}
TEST(rsa_keys_import_to_dsa_alg_fails) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_DSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[RD_RSA_BLOB_MAX]; ULONG il = rd_rsa_blob(in, BCRYPT_RSAPUBLIC_MAGIC, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = rd_import(a, BCRYPT_RSAPUBLIC_BLOB, in, il, &k);
    EXPECT_EQ(s, ST_INVALID_PARAMETER); if (!s) rd_destroy(k);
    rd_closealg(a);
}
TEST(rsa_keys_import_into_sign_alg) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_SIGN_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_fixed_rsa(a, BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    if (k) { UCHAR *o; ULONG ol; EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &o, &ol), ST_SUCCESS); free(o); rd_destroy(k); }
    rd_closealg(a);
}
TEST(rsa_keys_import_rejects_small_exponent_modulus_mismatch) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[RD_RSA_BLOB_MAX]; ULONG il = rd_rsa_blob(in, BCRYPT_RSAPUBLIC_MAGIC, 0);
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)in;
    BCRYPT_KEY_HANDLE k = NULL;
    /* BitLength smaller than the modulus bytes: record observed behaviour */
    h->BitLength = 512;
    NTSTATUS s = rd_import(a, BCRYPT_RSAPUBLIC_BLOB, in, il, &k);
    EXPECT_EQ(s, ST_SUCCESS);  /* probed: accepted, the modulus size wins */
    if (!s) { NTSTATUS ps; EXPECT_EQ(rd_getdw(k, BCRYPT_KEY_LENGTH, &ps), 1024); EXPECT_EQ(ps, 0); rd_destroy(k); }
    /* cbPublicExp zero */
    h->BitLength = 1024; h->cbPublicExp = 0;
    s = rd_import(a, BCRYPT_RSAPUBLIC_BLOB, in, il, &k);
    EXPECT_EQ(s, (NTSTATUS)0x80090005); if (!s) rd_destroy(k);
    /* cbModulus zero */
    h->cbPublicExp = 3; h->cbModulus = 0;
    s = rd_import(a, BCRYPT_RSAPUBLIC_BLOB, in, il, &k);
    EXPECT_EQ(s, (NTSTATUS)0x80090005); if (!s) rd_destroy(k);
    rd_closealg(a);
}
TEST(rsa_keys_import_fixed_exponent_variants) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    /* public exponent 3 (one byte) with the fixed modulus: valid public key, exported exponent keeps its length */
    UCHAR in[RD_RSA_BLOB_MAX], *p = in; BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)p;
    memset(in, 0, sizeof in);
    h->Magic = BCRYPT_RSAPUBLIC_MAGIC; h->BitLength = 1024; h->cbPublicExp = 1; h->cbModulus = 128;
    p += sizeof *h; *p++ = 3; memcpy(p, kRsaN, 128); p += 128;
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = rd_import(a, BCRYPT_RSAPUBLIC_BLOB, in, (ULONG)(p - in), &k);
    EXPECT_EQ(s, ST_SUCCESS);
    if (!s) {
        UCHAR *o; ULONG ol;
        EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &o, &ol), ST_SUCCESS);
        if (o) { CHECK(((BCRYPT_RSAKEY_BLOB *)o)->cbPublicExp == 1 && o[24] == 3); free(o); }
        rd_destroy(k);
    }
    /* exponent with leading zero byte: 00 01 00 01 */
    p = in + sizeof *h; h->cbPublicExp = 4; *p++ = 0; *p++ = 1; *p++ = 0; *p++ = 1; memcpy(p, kRsaN, 128); p += 128;
    s = rd_import(a, BCRYPT_RSAPUBLIC_BLOB, in, (ULONG)(p - in), &k);
    EXPECT_EQ(s, ST_SUCCESS);
    if (!s) {
        UCHAR *o; ULONG ol;
        if (!rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &o, &ol)) { EXPECT_EQ(((BCRYPT_RSAKEY_BLOB *)o)->cbPublicExp, 3); free(o); }  /* leading zero stripped */
        rd_destroy(k);
    }
    rd_closealg(a);
}

/* ---------- Legacy CAPI blobs ---------- */
static void rev_copy(UCHAR *dst, const UCHAR *src, ULONG n) { for (ULONG i = 0; i < n; i++) dst[i] = src[n - 1 - i]; }
static ULONG capi_blob(UCHAR *out, int priv) {
    UCHAR *p = out;
    *p++ = priv ? 7 : 6; *p++ = 2; *p++ = 0; *p++ = 0;
    *(DWORD *)p = 0x0000a400; p += 4;                    /* CALG_RSA_KEYX */
    *(DWORD *)p = priv ? 0x32415352 : 0x31415352; p += 4; /* RSA2 / RSA1 */
    *(DWORD *)p = 1024; p += 4;
    *(DWORD *)p = 65537; p += 4;
    rev_copy(p, kRsaN, 128); p += 128;
    if (priv) {
        rev_copy(p, kRsaP, 64); p += 64; rev_copy(p, kRsaQ, 64); p += 64;
        rev_copy(p, kRsaDP, 64); p += 64; rev_copy(p, kRsaDQ, 64); p += 64;
        rev_copy(p, kRsaIQ, 64); p += 64; rev_copy(p, kRsaD, 128); p += 128;
    }
    return (ULONG)(p - out);
}
TEST(rsa_keys_legacy_public_import_export) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[1024]; ULONG il = capi_blob(in, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    /* Win10 cannot import the legacy public blob type, but exports it */
    EXPECT_EQ(rd_import(a, LEGACY_RSAPUBLIC_BLOB, in, il, &k), ST_NOT_SUPPORTED); CHECK(!k);
    {
        UCHAR cb[RD_RSA_BLOB_MAX]; ULONG cbl = rd_rsa_blob(cb, BCRYPT_RSAPUBLIC_MAGIC, 0);
        EXPECT_EQ(rd_import(a, BCRYPT_RSAPUBLIC_BLOB, cb, cbl, &k), ST_SUCCESS); CHECK(k);
    }
    if (k) {
        UCHAR *o; ULONG ol;
        EXPECT_EQ(rd_export(k, LEGACY_RSAPUBLIC_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == il && o && !memcmp(o, in, il));
        free(o);
        /* equals the CNG public blob of the same key */
        UCHAR cng[RD_RSA_BLOB_MAX]; ULONG cl = rd_rsa_blob(cng, BCRYPT_RSAPUBLIC_MAGIC, 0);
        EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == cl && o && !memcmp(o, cng, cl));
        free(o); rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_legacy_private_import_export) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[1024]; ULONG il = capi_blob(in, 1);
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(rd_import(a, LEGACY_RSAPRIVATE_BLOB, in, il, &k), ST_SUCCESS); CHECK(k);
    if (k) {
        UCHAR *o; ULONG ol;
        EXPECT_EQ(rd_export(k, LEGACY_RSAPRIVATE_BLOB, &o, &ol), ST_SUCCESS);
        CHECK(ol == il);
        if (o && ol == il) { CHECK(!memcmp(o, in, il)); }
        free(o);
        /* signature via the imported legacy key equals the authoring-time PKCS#1 vector */
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        UCHAR sig[128]; ULONG n = 0;
        EXPECT_EQ(U(BCryptSignHash)(k, &pi, (PUCHAR)kHash_sha256, sizeof kHash_sha256, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
        EXPECT_EQ(n, 128);
        CHECK(!memcmp(sig, kSigPkcs1_sha256, 128));
        EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &o, &ol), ST_SUCCESS);
        if (o) { CHECK(((BCRYPT_RSAKEY_BLOB *)o)->cbModulus == 128 && !memcmp(o + 27, kRsaN, 128)); free(o); }
        rd_destroy(k);
    }
    rd_closealg(a);
}
TEST(rsa_keys_legacy_header_fields) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    UCHAR *o; ULONG ol;
    EXPECT_EQ(rd_export(k, LEGACY_RSAPRIVATE_BLOB, &o, &ol), ST_SUCCESS);
    if (o) {
        EXPECT_EQ(o[0], 7);  EXPECT_EQ(o[1], 2);
        EXPECT_EQ(*(DWORD *)(o + 4), 0xa400);
        EXPECT_EQ(*(DWORD *)(o + 8), 0x32415352);
        EXPECT_EQ(*(DWORD *)(o + 12), 512);
        EXPECT_EQ(*(DWORD *)(o + 16), 65537);
        /* 20 + modulus(64) + 2*32 primes... : 20 + 64 + 5*32 + 64 */
        EXPECT_EQ(ol, 20 + 64 + 5 * 32 + 64);
        free(o);
    }
    EXPECT_EQ(rd_export(k, LEGACY_RSAPUBLIC_BLOB, &o, &ol), ST_SUCCESS);
    if (o) {
        EXPECT_EQ(o[0], 6);  EXPECT_EQ(o[1], 2);
        EXPECT_EQ(*(DWORD *)(o + 4), 0xa400);
        EXPECT_EQ(*(DWORD *)(o + 8), 0x31415352);
        EXPECT_EQ(ol, 20 + 64);
        free(o);
    }
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_legacy_import_public_blob_as_private_type_fails) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    UCHAR in[1024]; ULONG il = capi_blob(in, 0);
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = rd_import(a, LEGACY_RSAPRIVATE_BLOB, in, il, &k);
    EXPECT_EQ(s, (NTSTATUS)0x80090005); if (!s) rd_destroy(k);
    rd_closealg(a);
}

/* ---------- Handle used in wrong places ---------- */
TEST(rsa_keys_key_handle_to_closealg_fails) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a = rd_alg(BCRYPT_RSA_ALGORITHM); CHECK(a); if (!a) return;
    BCRYPT_KEY_HANDLE k = rd_gen(a, 512); CHECK(k); if (!k) { rd_closealg(a); return; }
    EXPECT_EQ(U(BCryptCloseAlgorithmProvider)((BCRYPT_ALG_HANDLE)k, 0), ST_INVALID_HANDLE);
    rd_destroy(k); rd_closealg(a);
}
TEST(rsa_keys_gen_from_two_providers_independent) {
    NEED_BCRYPT();
    BCRYPT_ALG_HANDLE a1 = rd_alg(BCRYPT_RSA_ALGORITHM), a2 = rd_alg(BCRYPT_RSA_ALGORITHM);
    CHECK(a1 && a2); if (!a1 || !a2) return;
    BCRYPT_KEY_HANDLE k1 = rd_gen(a1, 512), k2 = rd_gen(a2, 576);
    CHECK(k1 && k2);
    rd_closealg(a1);
    NTSTATUS ps;
    if (k2) EXPECT_EQ(rd_getdw(k2, BCRYPT_KEY_LENGTH, &ps), 576);
    rd_destroy(k1); rd_destroy(k2); rd_closealg(a2);
}

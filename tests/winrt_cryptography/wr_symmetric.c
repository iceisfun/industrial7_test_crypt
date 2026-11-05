/* SymmetricKeyAlgorithmProvider + CryptographicEngine.Encrypt/Decrypt/EncryptAndAuthenticate/DecryptAndAuthenticate. */
#include "wr.h"
#include "wr_vec_sym.h"

#define HR_E_POINTER 0x80004003u
#define HR_E_NOINTERFACE 0x80004002u

static const WCHAR *k_symnames[] = {
    L"AES_CBC", L"AES_CBC_PKCS7", L"AES_CCM", L"AES_ECB", L"AES_ECB_PKCS7", L"AES_GCM",
    L"DES_CBC", L"DES_CBC_PKCS7", L"DES_ECB", L"DES_ECB_PKCS7",
    L"RC2_CBC", L"RC2_CBC_PKCS7", L"RC2_ECB", L"RC2_ECB_PKCS7", L"RC4",
    L"3DES_CBC", L"3DES_CBC_PKCS7", L"3DES_ECB", L"3DES_ECB_PKCS7",
};
#define NSYM (sizeof k_symnames / sizeof *k_symnames)

static void *mk_key(const WCHAR *alg, const char *keyhex) {
    void *p = NULL, *kb = wr_mkbuf_hex(keyhex), *k = NULL;
    HRESULT hr = wr_sym_open(alg, &p);
    if (hr == S_OK) hr = wr_sym_key(p, kb, &k);
    if (hr != S_OK && !t_is_wine()) t_check(0, __FILE__, __LINE__, "create symmetric key", "%ls hr 0x%08lx", alg, (unsigned long)hr);
    wr_release(kb); wr_release(p);
    return k;
}
static int is_aead(const WCHAR *a) { return !lstrcmpW(a, L"AES_GCM") || !lstrcmpW(a, L"AES_CCM"); }

/* ---- names ------------------------------------------------------------------------------------ */
TEST(winrt_sym_names_values) {
    WR_NEED(); void *s = wr_cls_statics(CLS_SYMNAMES); if (!s) return;
    char seen[NSYM] = { 0 }; int ok = 1;
    for (int i = 0; i < (int)NSYM; i++) {
        HSTRING h = NULL; HRESULT hr = VF(s, 6 + i, HSTRING *)(s, &h);
        if (hr != S_OK) ok = 0;
        int found = 0;
        for (size_t k = 0; k < NSYM; k++) if (wr_hs_eq(h, k_symnames[k])) { found = 1; seen[k]++; }
        if (!found) ok = 0;
        wr_hsfree(h);
    }
    for (size_t k = 0; k < NSYM; k++) if (seen[k] != 1) ok = 0;
    CHECK(ok);
    wr_release(s);
}
TEST(winrt_sym_open_all_names) {
    WR_NEED();
    for (size_t i = 0; i < NSYM; i++) {
        void *p = NULL; HRESULT hr = wr_sym_open(k_symnames[i], &p);
        if (FAILED(hr) && t_is_wine()) { t_skip("wine"); return; }
        t_check(hr == S_OK && p, __FILE__, __LINE__, "OpenAlgorithm", "%ls hr 0x%08lx", k_symnames[i], (unsigned long)hr);
        if (!p) continue;
        HSTRING n = NULL; EXPECT_HR(VF(p, 6, HSTRING *)(p, &n), S_OK);
        t_check(wr_hs_eq(n, k_symnames[i]), __FILE__, __LINE__, "AlgorithmName", "%ls", k_symnames[i]);
        wr_hsfree(n); wr_release(p);
    }
}
TEST(winrt_sym_block_length) {
    WR_NEED();
    for (size_t i = 0; i < NSYM; i++) {
        void *p = NULL; if (wr_sym_open(k_symnames[i], &p) != S_OK) { if (t_is_wine()) { t_skip("wine"); return; } continue; }
        UINT32 bl = 0xffff; EXPECT_HR(VF(p, 7, UINT32 *)(p, &bl), S_OK);
        UINT32 want = k_symnames[i][0] == L'A' ? 16 : (k_symnames[i][0] == L'D' || k_symnames[i][0] == L'3' || k_symnames[i][0] == L'R' && k_symnames[i][2] == L'2') ? 8 : 0;
        if (want) t_check(bl == want, __FILE__, __LINE__, "BlockLength", "%ls got %u want %u", k_symnames[i], bl, want);
        else t_note("%ls BlockLength = %u", k_symnames[i], bl);
        wr_release(p);
    }
}
TEST(winrt_sym_open_invalid) {
    WR_NEED();
    static const WCHAR *bad[] = { L"", L"AES", L"AES_CBC_PKCS8", L"AES_CTR", L"AES_CFB", L"SHA256", L"HMAC_SHA256", L"RSA_PKCS1", L"DES", L"3DES", L"RC4_CBC", L"AES_CBC_PKCS7 ", L"PBKDF2_SHA1", L"AES-CBC" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *p = (void *)1; HSTRING h = wr_hs(bad[i]); void *st = wr_cls_statics(CLS_SYMPROV); if (!st) return;
        HRESULT hr = VF(st, 6, HSTRING, void **)(st, h, &p);
        t_check(FAILED(hr) && p == NULL, __FILE__, __LINE__, "OpenAlgorithm(bad)", "'%ls' hr 0x%08lx", bad[i], (unsigned long)hr);
        if (SUCCEEDED(hr)) wr_release(p);
        wr_hsfree(h); wr_release(st);
    }
}
TEST(winrt_sym_provider_getiids) {
    WR_NEED(); void *p = NULL;
    if (wr_sym_open(L"AES_CBC", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    ULONG n = 0; GUID *ids = NULL; EXPECT_HR(wr_getiids(p, &n, &ids), S_OK);
    EXPECT_EQ(n, 2);
    wr_cofree(ids); wr_release(p);
}
TEST(winrt_sym_provider_class_name) {
    WR_NEED(); void *p = NULL;
    if (wr_sym_open(L"AES_CBC", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(p, &n), S_OK);
    CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.SymmetricKeyAlgorithmProvider")); wr_hsfree(n);
    wr_release(p);
}

/* ---- key creation --------------------------------------------------------------------------------- */
TEST(winrt_sym_create_key_sizes_aes) {
    WR_NEED();
    static const struct { UINT32 n; int ok; } v[] = { { 16, 1 }, { 24, 1 }, { 32, 1 }, { 0, 0 }, { 1, 0 }, { 8, 0 }, { 15, 0 }, { 17, 0 }, { 23, 0 }, { 33, 0 }, { 64, 0 } };
    void *p = NULL; if (wr_sym_open(L"AES_CBC_PKCS7", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    BYTE kb[64]; memset(kb, 0x42, sizeof kb);
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *b = wr_mkbuf(kb, v[i].n), *k = (void *)1;
        HRESULT hr = wr_sym_key(p, b, &k);
        if (v[i].ok) t_check(hr == S_OK && k, __FILE__, __LINE__, "CreateSymmetricKey", "size %u hr 0x%08lx", v[i].n, (unsigned long)hr);
        else {
            /* an invalid key size is rejected either at creation or at first use */
            int rejected = FAILED(hr);
            if (!rejected) { void *d = wr_mkbuf(kb, 16), *o = NULL, *iv = wr_mkbuf(kb, 16); rejected = FAILED(wr_encrypt(k, d, iv, &o)); wr_release(d); wr_release(o); wr_release(iv); }
            t_check(rejected, __FILE__, __LINE__, "invalid key size rejected", "size %u", v[i].n);
            t_note("AES key size %u: CreateSymmetricKey -> 0x%08lx", v[i].n, (unsigned long)hr);
        }
        if (SUCCEEDED(hr)) wr_release(k);
        wr_release(b);
    }
    wr_release(p);
}
TEST(winrt_sym_create_key_null_material) {
    WR_NEED(); void *p = NULL;
    if (wr_sym_open(L"AES_CBC", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *k = (void *)1; HRESULT hr = wr_sym_key(p, NULL, &k);
    CHECK(FAILED(hr)); CHECK(k == NULL);
    t_note("CreateSymmetricKey(NULL) -> 0x%08lx", (unsigned long)hr);
    wr_release(p);
}
TEST(winrt_sym_key_size_property) {
    WR_NEED();
    static const struct { const WCHAR *alg; UINT32 bytes, bits; } v[] = {
        { L"AES_CBC", 16, 128 }, { L"AES_CBC", 24, 192 }, { L"AES_CBC", 32, 256 }, { L"AES_GCM", 16, 128 }, { L"AES_ECB", 32, 256 },
        { L"3DES_CBC", 24, 192 }, { L"RC4", 5, 40 }, { L"RC4", 16, 128 },
    };
    BYTE kb[32]; memset(kb, 0x37, sizeof kb);
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *p = NULL, *b = wr_mkbuf(kb, v[i].bytes), *k = NULL;
        if (wr_sym_open(v[i].alg, &p) != S_OK) { if (t_is_wine()) { t_skip("wine"); return; } continue; }
        wr_sym_key(p, b, &k); if (!k) { CHECK(!"key"); continue; }
        UINT32 sz = 0; HRESULT hr = VF(k, 6, UINT32 *)(k, &sz);
        t_check(hr == S_OK && sz == v[i].bits, __FILE__, __LINE__, "KeySize", "%ls %u bytes -> %u bits (hr 0x%08lx)", v[i].alg, v[i].bytes, sz, (unsigned long)hr);
        wr_release(k); wr_release(b); wr_release(p);
    }
}
TEST(winrt_sym_key_object_interfaces) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *o = NULL;
    EXPECT_HR(wr_qi(k, &WR_IID_ICryptographicKey, &o), S_OK); wr_release(o);
    EXPECT_HR(wr_qi(k, &WR_IID_IAgileObject, &o), S_OK); wr_release(o);
    o = (void *)1; EXPECT_HR(wr_qi(k, &WR_IID_IBuffer, &o), HR_E_NOINTERFACE); CHECK(o == NULL);
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(k, &n), S_OK);
    CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.SymmetricKey")); wr_hsfree(n);
    wr_release(k);
}
TEST(winrt_sym_key_outlives_provider) {
    WR_NEED(); void *p = NULL, *b = wr_mkbuf_hex("000102030405060708090a0b0c0d0e0f"), *k = NULL;
    if (wr_sym_open(L"AES_ECB", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    wr_sym_key(p, b, &k); wr_release(p); wr_release(b);
    void *d = wr_mkbuf_hex("00112233445566778899aabbccddeeff"), *o = NULL;
    EXPECT_HR(wr_encrypt(k, d, NULL, &o), S_OK);
    CHECK(wr_buf_is_hex(o, "69c4e0d86a7b0430d8cdb78070b4c55a"));       /* FIPS-197 C.1 */
    wr_release(d); wr_release(o); wr_release(k);
}

/* ---- known-answer vectors -------------------------------------------------------------------------- */
static void run_sym(const char *prefix_filter, int exact) {
    for (size_t i = 0; i < sizeof wr_sym_vecs / sizeof *wr_sym_vecs; i++) {
        const struct wr_sv *v = &wr_sym_vecs[i]; char a[32]; int j = 0;
        for (const WCHAR *w = v->alg; *w; w++) a[j++] = (char)*w; a[j] = 0;
        if (exact ? strcmp(a, prefix_filter) : strncmp(a, prefix_filter, strlen(prefix_filter))) continue;
        void *k = mk_key(v->alg, v->key); if (!k) return;
        void *iv = v->iv[0] ? wr_mkbuf_hex(v->iv) : NULL, *pt = wr_mkbuf_hex(v->pt), *o = NULL, *d = NULL;
        HRESULT hr = wr_encrypt(k, pt, iv, &o);
        t_check(hr == S_OK && wr_buf_is_hex(o, v->ct), __FILE__, __LINE__, "Encrypt vector", "%s #%zu (pt %zu bytes) hr 0x%08lx", a, i, strlen(v->pt) / 2, (unsigned long)hr);
        hr = wr_decrypt(k, o, iv, &d);
        t_check(hr == S_OK && wr_buf_is_hex(d, v->pt), __FILE__, __LINE__, "Decrypt of Encrypt output", "%s #%zu hr 0x%08lx", a, i, (unsigned long)hr);
        void *ct = wr_mkbuf_hex(v->ct), *d2 = NULL;
        if (strcmp(a, "RC4")) {                  /* RC4 keeps keystream state per key; checked separately */
            hr = wr_decrypt(k, ct, iv, &d2);
            t_check(hr == S_OK && wr_buf_is_hex(d2, v->pt), __FILE__, __LINE__, "Decrypt vector", "%s #%zu hr 0x%08lx", a, i, (unsigned long)hr);
        }
        wr_release(k); wr_release(iv); wr_release(pt); wr_release(o); wr_release(d); wr_release(ct); wr_release(d2);
    }
}
TEST(winrt_sym_vectors_aes_cbc) { WR_NEED(); run_sym("AES_CBC", 1); }
TEST(winrt_sym_vectors_aes_ecb) { WR_NEED(); run_sym("AES_ECB", 1); }
TEST(winrt_sym_vectors_aes_cbc_pkcs7) { WR_NEED(); run_sym("AES_CBC_PKCS7", 1); }
TEST(winrt_sym_vectors_aes_ecb_pkcs7) { WR_NEED(); run_sym("AES_ECB_PKCS7", 1); }
TEST(winrt_sym_vectors_des_cbc) { WR_NEED(); run_sym("DES_CBC", 1); }
TEST(winrt_sym_vectors_des_ecb) { WR_NEED(); run_sym("DES_ECB", 1); }
TEST(winrt_sym_vectors_des_pkcs7) { WR_NEED(); run_sym("DES_CBC_PKCS7", 1); run_sym("DES_ECB_PKCS7", 1); }
TEST(winrt_sym_vectors_3des) { WR_NEED(); run_sym("3DES_CBC", 1); run_sym("3DES_ECB", 1); }
TEST(winrt_sym_vectors_3des_pkcs7) { WR_NEED(); run_sym("3DES_CBC_PKCS7", 1); run_sym("3DES_ECB_PKCS7", 1); }
TEST(winrt_sym_vectors_rc4_encrypt) {
    WR_NEED();
    for (size_t i = 0; i < sizeof wr_sym_vecs / sizeof *wr_sym_vecs; i++) {
        const struct wr_sv *v = &wr_sym_vecs[i];
        if (lstrcmpW(v->alg, L"RC4")) continue;
        void *k = mk_key(v->alg, v->key); if (!k) return;
        void *pt = wr_mkbuf_hex(v->pt), *o = NULL;
        HRESULT hr = wr_encrypt(k, pt, NULL, &o);
        t_check(hr == S_OK && wr_buf_is_hex(o, v->ct), __FILE__, __LINE__, "RC4 vector", "#%zu hr 0x%08lx", i, (unsigned long)hr);
        wr_release(k); wr_release(pt); wr_release(o);
    }
}
TEST(winrt_sym_fips197_appendix_c) {
    WR_NEED();
    static const struct { const char *key, *ct; } v[] = {
        { "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a" },
        { "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191" },
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089" },
    };
    for (int i = 0; i < 3; i++) {
        void *k = mk_key(L"AES_ECB", v[i].key); if (!k) return;
        void *pt = wr_mkbuf_hex("00112233445566778899aabbccddeeff"), *o = NULL, *d = NULL;
        EXPECT_HR(wr_encrypt(k, pt, NULL, &o), S_OK); CHECK(wr_buf_is_hex(o, v[i].ct));
        EXPECT_HR(wr_decrypt(k, o, NULL, &d), S_OK);  CHECK(wr_buf_is_hex(d, "00112233445566778899aabbccddeeff"));
        wr_release(k); wr_release(pt); wr_release(o); wr_release(d);
    }
}
TEST(winrt_sym_des_classic_vector) {
    WR_NEED(); void *k = mk_key(L"DES_ECB", "133457799bbcdff1"); if (!k) return;
    void *pt = wr_mkbuf_hex("0123456789abcdef"), *o = NULL;
    EXPECT_HR(wr_encrypt(k, pt, NULL, &o), S_OK);
    CHECK(wr_buf_is_hex(o, "85e813540f0ab405"));
    wr_release(k); wr_release(pt); wr_release(o);
}
TEST(winrt_sym_rc4_rfc6229_keystream) {
    WR_NEED(); void *k = mk_key(L"RC4", "0102030405"); if (!k) return;
    void *z = wr_mkbuf(NULL, 0); BYTE zeros[16] = { 0 }; z = wr_mkbuf(zeros, 16);
    void *o = NULL; EXPECT_HR(wr_encrypt(k, z, NULL, &o), S_OK);
    CHECK(wr_buf_is_hex(o, "b2396305f03dc027ccc3524a0a1118a8"));
    wr_release(k); wr_release(z); wr_release(o);
}

/* ---- behaviour of the Engine for symmetric keys ---------------------------------------------------- */
TEST(winrt_sym_pkcs7_output_length) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *iv = wr_mkbuf_hex("000102030405060708090a0b0c0d0e0f");
    BYTE d[70]; memset(d, 1, sizeof d);
    for (UINT32 n = 0; n <= 70; n++) {
        void *pt = wr_mkbuf(d, n), *o = NULL; HRESULT hr = wr_encrypt(k, pt, iv, &o);
        t_check(hr == S_OK && wr_buf_len(o) == (n / 16 + 1) * 16, __FILE__, __LINE__, "PKCS7 length", "n %u got %u", n, wr_buf_len(o));
        wr_release(pt); wr_release(o);
    }
    wr_release(k); wr_release(iv);
}
TEST(winrt_sym_nopad_requires_block_multiple) {
    WR_NEED(); void *k = mk_key(L"AES_CBC", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *iv = wr_mkbuf_hex("000102030405060708090a0b0c0d0e0f");
    BYTE d[48]; memset(d, 9, sizeof d);
    static const UINT32 bad[] = { 1, 15, 17, 31, 33, 47 };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *pt = wr_mkbuf(d, bad[i]), *o = (void *)1; HRESULT hr = wr_encrypt(k, pt, iv, &o);
        t_check(FAILED(hr) && o == NULL, __FILE__, __LINE__, "unpadded size", "n %u hr 0x%08lx", bad[i], (unsigned long)hr);
        wr_release(pt);
    }
    for (UINT32 n = 16; n <= 48; n += 16) {
        void *pt = wr_mkbuf(d, n), *o = NULL; HRESULT hr = wr_encrypt(k, pt, iv, &o);
        t_check(hr == S_OK && wr_buf_len(o) == n, __FILE__, __LINE__, "unpadded multiple", "n %u", n);
        wr_release(pt); wr_release(o);
    }
    wr_release(k); wr_release(iv);
}
TEST(winrt_sym_decrypt_bad_sizes) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *iv = wr_mkbuf_hex("000102030405060708090a0b0c0d0e0f");
    BYTE d[48]; memset(d, 9, sizeof d);
    static const UINT32 bad[] = { 1, 15, 17, 31, 33 };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *ct = wr_mkbuf(d, bad[i]), *o = (void *)1; HRESULT hr = wr_decrypt(k, ct, iv, &o);
        t_check(FAILED(hr) && o == NULL, __FILE__, __LINE__, "ciphertext size", "n %u hr 0x%08lx", bad[i], (unsigned long)hr);
        wr_release(ct);
    }
    wr_release(k); wr_release(iv);
}
TEST(winrt_sym_decrypt_bad_padding) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "2b7e151628aed2a6abf7158809cf4f3c"); if (!k) return;
    void *iv = wr_mkbuf_hex("000102030405060708090a0b0c0d0e0f");
    void *good = wr_mkbuf_hex("21b68a81b82ed8e55d06658de5bc0351"), *bad = wr_mkbuf_hex("21b68a81b82ed8e55d06658de5bc0350"), *o = NULL;
    EXPECT_HR(wr_decrypt(k, good, iv, &o), S_OK); CHECK(wr_buf_is_hex(o, "030a11181f")); wr_release(o);
    o = (void *)1; HRESULT hr = wr_decrypt(k, bad, iv, &o);       /* tampered final block yields invalid PKCS#7 padding */
    CHECK(FAILED(hr)); CHECK(o == NULL);
    t_note("Decrypt(bad padding) -> 0x%08lx", (unsigned long)hr);
    wr_release(k); wr_release(iv); wr_release(good); wr_release(bad);
}
TEST(winrt_sym_iv_size_must_match_block) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *pt = wr_mkbuf_hex("00112233");
    static const UINT32 bad[] = { 1, 8, 12, 15, 17, 32 };
    BYTE z[32] = { 0 };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *iv = wr_mkbuf(z, bad[i]), *o = (void *)1; HRESULT hr = wr_encrypt(k, pt, iv, &o);
        t_check(FAILED(hr) && o == NULL, __FILE__, __LINE__, "IV size", "iv %u bytes hr 0x%08lx", bad[i], (unsigned long)hr);
        wr_release(iv);
    }
    wr_release(k); wr_release(pt);
}
TEST(winrt_sym_cbc_without_iv_is_defined) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *pt = wr_mkbuf_hex("00112233"), *o = (void *)1, *z = wr_mkbuf_hex("00000000000000000000000000000000"), *o2 = NULL;
    HRESULT hr = wr_encrypt(k, pt, NULL, &o);
    t_note("CBC Encrypt with NULL iv -> 0x%08lx", (unsigned long)hr);
    if (SUCCEEDED(hr)) { wr_encrypt(k, pt, z, &o2); const BYTE *a, *b; UINT32 la, lb;
        if (wr_buf_get(o, &a, &la) && wr_buf_get(o2, &b, &lb)) t_note("NULL iv equals all-zero iv: %d", la == lb && !memcmp(a, b, la)); }
    else CHECK(o == NULL);
    wr_release(k); wr_release(pt); wr_release(z); wr_release(o2);
}
TEST(winrt_sym_iv_buffer_not_modified) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *iv = wr_mkbuf_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), *pt = wr_mkbuf_hex("0011223344556677"), *o = NULL, *d = NULL;
    wr_encrypt(k, pt, iv, &o); wr_decrypt(k, o, iv, &d);
    CHECK(wr_buf_is_hex(iv, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"));
    CHECK(wr_buf_is_hex(pt, "0011223344556677"));
    CHECK(wr_buf_is_hex(d, "0011223344556677"));
    wr_release(k); wr_release(iv); wr_release(pt); wr_release(o); wr_release(d);
}
TEST(winrt_sym_cbc_deterministic_and_iv_dependent) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *iv1 = wr_mkbuf_hex("00000000000000000000000000000001"), *iv2 = wr_mkbuf_hex("00000000000000000000000000000002");
    void *pt = wr_mkbuf_hex("000102030405060708090a0b0c0d0e0f1011121314151617"), *a = NULL, *b = NULL, *c = NULL;
    wr_encrypt(k, pt, iv1, &a); wr_encrypt(k, pt, iv1, &b); wr_encrypt(k, pt, iv2, &c);
    const BYTE *pa, *pb, *pc; UINT32 la, lb, lc;
    if (wr_buf_get(a, &pa, &la) && wr_buf_get(b, &pb, &lb) && wr_buf_get(c, &pc, &lc)) {
        CHECK(la == lb && !memcmp(pa, pb, la));      /* same key + same IV: same ciphertext (call state is not carried over) */
        CHECK(la == lc && memcmp(pa, pc, la) != 0);
    } else CHECK(!"buffers");
    wr_release(k); wr_release(iv1); wr_release(iv2); wr_release(pt); wr_release(a); wr_release(b); wr_release(c);
}
TEST(winrt_sym_ecb_equal_blocks) {
    WR_NEED(); void *k = mk_key(L"AES_ECB", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *pt = wr_mkbuf_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), *o = NULL;
    EXPECT_HR(wr_encrypt(k, pt, NULL, &o), S_OK);
    const BYTE *p; UINT32 n; if (wr_buf_get(o, &p, &n) && n == 32) CHECK(!memcmp(p, p + 16, 16)); else CHECK(!"len");
    wr_release(k); wr_release(pt); wr_release(o);
}
TEST(winrt_sym_ecb_ignores_nothing_with_iv_note) {
    WR_NEED(); void *k = mk_key(L"AES_ECB", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *pt = wr_mkbuf_hex("00112233445566778899aabbccddeeff"), *iv = wr_mkbuf_hex("00000000000000000000000000000000"), *o = NULL;
    HRESULT hr = wr_encrypt(k, pt, iv, &o);
    t_note("ECB Encrypt with 16-byte iv -> 0x%08lx", (unsigned long)hr);
    wr_release(k); wr_release(pt); wr_release(iv); wr_release(o);
}
TEST(winrt_sym_roundtrip_all_lengths_all_modes) {
    WR_NEED();
    static const struct { const WCHAR *alg; const char *key; int iv; UINT32 blk; } v[] = {
        { L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f", 16, 16 }, { L"AES_ECB_PKCS7", "000102030405060708090a0b0c0d0e0f1011121314151617", 0, 16 },
        { L"DES_CBC_PKCS7", "133457799bbcdff1", 8, 8 }, { L"3DES_CBC_PKCS7", "0123456789abcdef23456789abcdef01456789abcdef0123", 8, 8 },
        { L"3DES_ECB_PKCS7", "0123456789abcdef23456789abcdef01456789abcdef0123", 0, 8 },
    };
    BYTE d[200]; for (int i = 0; i < 200; i++) d[i] = (BYTE)(i * 11 + 5);
    for (size_t a = 0; a < sizeof v / sizeof *v; a++) {
        void *k = mk_key(v[a].alg, v[a].key); if (!k) return;
        BYTE ivb[16]; for (int i = 0; i < 16; i++) ivb[i] = (BYTE)(0x80 + i);
        void *iv = v[a].iv ? wr_mkbuf(ivb, v[a].iv) : NULL;
        for (UINT32 n = 0; n <= 130; n += 3) {
            void *pt = wr_mkbuf(d, n), *o = NULL, *r = NULL;
            HRESULT h1 = wr_encrypt(k, pt, iv, &o), h2 = wr_decrypt(k, o, iv, &r);
            t_check(h1 == S_OK && h2 == S_OK && wr_buf_is(r, d, n) && wr_buf_len(o) == (n / v[a].blk + 1) * v[a].blk, __FILE__, __LINE__, "roundtrip", "%ls n %u", v[a].alg, n);
            wr_release(pt); wr_release(o); wr_release(r);
        }
        wr_release(k); wr_release(iv);
    }
}
TEST(winrt_sym_large_roundtrip) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f1011121314151617"); if (!k) return;
    UINT32 n = 1u << 20; BYTE *d = malloc(n); if (!d) return;
    for (UINT32 i = 0; i < n; i++) d[i] = (BYTE)(i ^ (i >> 9));
    void *iv = wr_mkbuf_hex("0f0e0d0c0b0a09080706050403020100"), *pt = wr_mkbuf(d, n), *o = NULL, *r = NULL;
    EXPECT_HR(wr_encrypt(k, pt, iv, &o), S_OK); EXPECT_EQ(wr_buf_len(o), n + 16);
    EXPECT_HR(wr_decrypt(k, o, iv, &r), S_OK); CHECK(wr_buf_is(r, d, n));
    wr_release(k); wr_release(iv); wr_release(pt); wr_release(o); wr_release(r); free(d);
}
TEST(winrt_sym_encrypt_output_is_new_buffer) {
    WR_NEED(); void *k = mk_key(L"AES_ECB", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *pt = wr_mkbuf_hex("00112233445566778899aabbccddeeff"), *o = NULL;
    wr_encrypt(k, pt, NULL, &o);
    CHECK(o != pt && o != NULL); CHECK(wr_buf_is_hex(pt, "00112233445566778899aabbccddeeff"));
    UINT32 cap = 0; if (o) VF(o, 6, UINT32 *)(o, &cap); EXPECT_EQ(cap, 16);
    wr_release(k); wr_release(pt); wr_release(o);
}
TEST(winrt_sym_empty_plaintext_nopad_and_pad) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *iv = wr_mkbuf_hex("000102030405060708090a0b0c0d0e0f"), *pt = wr_mkbuf(NULL, 0), *o = NULL, *d = NULL;
    EXPECT_HR(wr_encrypt(k, pt, iv, &o), S_OK); EXPECT_EQ(wr_buf_len(o), 16);
    EXPECT_HR(wr_decrypt(k, o, iv, &d), S_OK);  EXPECT_EQ(wr_buf_len(d), 0);
    wr_release(k); wr_release(iv); wr_release(pt); wr_release(o); wr_release(d);
}
TEST(winrt_sym_engine_null_arguments) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *pt = wr_mkbuf_hex("0011"), *o = (void *)1;
    EXPECT_HR(wr_encrypt(NULL, pt, NULL, &o), HR_E_POINTER);
    EXPECT_HR(wr_encrypt(k, NULL, NULL, &o), HR_E_POINTER);
    EXPECT_HR(wr_decrypt(NULL, pt, NULL, &o), HR_E_POINTER);
    EXPECT_HR(wr_decrypt(k, NULL, NULL, &o), HR_E_POINTER);
    wr_release(k); wr_release(pt);
}
TEST(winrt_sym_engine_rejects_non_key_object) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *pt = wr_mkbuf_hex("0011"), *o = NULL;
    HRESULT hr = wr_encrypt(pt, pt, NULL, &o);       /* an IBuffer is not an ICryptographicKey */
    CHECK(FAILED(hr)); t_note("Encrypt(IBuffer as key) -> 0x%08lx", (unsigned long)hr);
    wr_release(k); wr_release(pt);
}
TEST(winrt_sym_engine_encrypt_with_mac_key_fails) {
    WR_NEED(); void *p = NULL;
    if (wr_mac_open(L"HMAC_SHA256", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *kb = wr_mkbuf("secret", 6), *key = NULL, *pt = wr_mkbuf("data", 4), *o = (void *)1;
    VF(p, 8, void *, void **)(p, kb, &key);
    HRESULT hr = wr_encrypt(key, pt, NULL, &o);
    CHECK(FAILED(hr)); t_note("Encrypt(MAC key) -> 0x%08lx", (unsigned long)hr);
    wr_release(p); wr_release(kb); wr_release(key); wr_release(pt);
}
TEST(winrt_sym_engine_sign_with_symmetric_key_fails) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *e = wr_engine(), *pt = wr_mkbuf_hex("0011"), *o = (void *)1;
    HRESULT hr = VF(e, EN_Sign, void *, void *, void **)(e, k, pt, &o);
    CHECK(FAILED(hr)); t_note("Sign(AES key) -> 0x%08lx", (unsigned long)hr);
    wr_release(k); wr_release(pt);
}
TEST(winrt_sym_rc4_stateless_keystream_note) {
    WR_NEED(); void *k = mk_key(L"RC4", "0102030405"); if (!k) return;
    BYTE z[16] = { 0 }; void *pt = wr_mkbuf(z, 16), *a = NULL, *b = NULL;
    wr_encrypt(k, pt, NULL, &a); wr_encrypt(k, pt, NULL, &b);
    const BYTE *pa, *pb; UINT32 la, lb;
    if (wr_buf_get(a, &pa, &la) && wr_buf_get(b, &pb, &lb)) t_note("RC4: second Encrypt with same key repeats keystream: %d", la == lb && !memcmp(pa, pb, la));
    wr_release(k); wr_release(pt); wr_release(a); wr_release(b);
}

/* ---- authenticated encryption ----------------------------------------------------------------------- */
static HRESULT eng_ea(void *key, void *data, void *nonce, void *aad, void **res) {
    void *e = wr_engine(); *res = NULL; if (!e) return E_FAIL;
    return VF(e, EN_EncryptAndAuthenticate, void *, void *, void *, void *, void **)(e, key, data, nonce, aad, res);
}
static HRESULT eng_da(void *key, void *data, void *nonce, void *tag, void *aad, void **out) {
    void *e = wr_engine(); *out = NULL; if (!e) return E_FAIL;
    return VF(e, EN_DecryptAndAuthenticate, void *, void *, void *, void *, void *, void **)(e, key, data, nonce, tag, aad, out);
}
static void run_aead(const WCHAR *only) {
    for (size_t i = 0; i < sizeof wr_aead_vecs / sizeof *wr_aead_vecs; i++) {
        const struct wr_av *v = &wr_aead_vecs[i];
        if (lstrcmpW(v->alg, only)) continue;
        void *k = mk_key(v->alg, v->key); if (!k) return;
        void *nonce = wr_mkbuf_hex(v->nonce), *aad = v->aad[0] ? wr_mkbuf_hex(v->aad) : NULL, *pt = wr_mkbuf_hex(v->pt);
        void *res = NULL, *ct = NULL, *tag = NULL, *dec = NULL;
        HRESULT hr = eng_ea(k, pt, nonce, aad, &res);
        int ok = hr == S_OK && res &&
                 SUCCEEDED(VF(res, 6, void **)(res, &ct)) && SUCCEEDED(VF(res, 7, void **)(res, &tag)) &&
                 wr_buf_is_hex(ct, v->ct) && wr_buf_is_hex(tag, v->tag);
        t_check(ok, __FILE__, __LINE__, "EncryptAndAuthenticate", "%ls #%zu hr 0x%08lx", v->alg, i, (unsigned long)hr);
        void *ict = wr_mkbuf_hex(v->ct), *itag = wr_mkbuf_hex(v->tag);
        hr = eng_da(k, ict, nonce, itag, aad, &dec);
        t_check(hr == S_OK && wr_buf_is_hex(dec, v->pt), __FILE__, __LINE__, "DecryptAndAuthenticate", "%ls #%zu hr 0x%08lx", v->alg, i, (unsigned long)hr);
        wr_release(k); wr_release(nonce); wr_release(aad); wr_release(pt); wr_release(res); wr_release(ct); wr_release(tag); wr_release(dec); wr_release(ict); wr_release(itag);
    }
}
TEST(winrt_sym_aead_gcm_vectors) { WR_NEED(); run_aead(L"AES_GCM"); }
TEST(winrt_sym_aead_ccm_vectors) { WR_NEED(); run_aead(L"AES_CCM"); }
TEST(winrt_sym_aead_result_object) {
    WR_NEED(); void *k = mk_key(L"AES_GCM", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *nonce = wr_mkbuf_hex("000000000000000000000000"), *pt = wr_mkbuf_hex("00112233"), *res = NULL;
    EXPECT_HR(eng_ea(k, pt, nonce, NULL, &res), S_OK);
    if (res) {
        HSTRING n = NULL; EXPECT_HR(wr_getclassname(res, &n), S_OK);
        CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.EncryptedAndAuthenticatedData")); wr_hsfree(n);
        void *ct = NULL, *tag = NULL;
        VF(res, 6, void **)(res, &ct); VF(res, 7, void **)(res, &tag);
        EXPECT_EQ(wr_buf_len(ct), 4); EXPECT_EQ(wr_buf_len(tag), 16);
        wr_release(ct); wr_release(tag); wr_release(res);
    }
    wr_release(k); wr_release(nonce); wr_release(pt);
}
TEST(winrt_sym_aead_tamper_detection) {
    WR_NEED(); void *k = mk_key(L"AES_GCM", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *nonce = wr_mkbuf_hex("0b0b0b0b0b0b0b0b0b0b0b0b"), *aad = wr_mkbuf_hex("aabbcc"), *pt = wr_mkbuf_hex("00112233445566778899"), *res = NULL;
    eng_ea(k, pt, nonce, aad, &res); if (!res) { CHECK(!"result"); return; }
    void *ct = NULL, *tag = NULL; VF(res, 6, void **)(res, &ct); VF(res, 7, void **)(res, &tag);
    const BYTE *pc, *pt_; UINT32 lc, lt; wr_buf_get(ct, &pc, &lc); wr_buf_get(tag, &pt_, &lt);
    BYTE c2[64], t2[32], aad2[3] = { 0xaa, 0xbb, 0xcd };
    memcpy(c2, pc, lc); memcpy(t2, pt_, lt);
    void *out = (void *)1; HRESULT hr;
    hr = eng_da(k, ct, nonce, tag, aad, &out); EXPECT_HR(hr, S_OK); CHECK(wr_buf_is_hex(out, "00112233445566778899")); wr_release(out);
    c2[0] ^= 1; { void *b = wr_mkbuf(c2, lc); hr = eng_da(k, b, nonce, tag, aad, &out); CHECK(FAILED(hr)); CHECK(out == NULL); wr_release(b); c2[0] ^= 1; }
    t2[15] ^= 0x80; { void *b = wr_mkbuf(t2, lt); hr = eng_da(k, ct, nonce, b, aad, &out); CHECK(FAILED(hr)); CHECK(out == NULL); t_note("GCM tag mismatch -> 0x%08lx", (unsigned long)hr); wr_release(b); t2[15] ^= 0x80; }
    { void *b = wr_mkbuf(aad2, 3); hr = eng_da(k, ct, nonce, tag, b, &out); CHECK(FAILED(hr)); CHECK(out == NULL); wr_release(b); }
    hr = eng_da(k, ct, nonce, tag, NULL, &out); CHECK(FAILED(hr));     /* missing AAD */
    { void *n2 = wr_mkbuf_hex("0b0b0b0b0b0b0b0b0b0b0b0c"); hr = eng_da(k, ct, n2, tag, aad, &out); CHECK(FAILED(hr)); wr_release(n2); }
    wr_release(k); wr_release(nonce); wr_release(aad); wr_release(pt); wr_release(res); wr_release(ct); wr_release(tag);
}
TEST(winrt_sym_aead_null_arguments) {
    WR_NEED(); void *k = mk_key(L"AES_GCM", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *nonce = wr_mkbuf_hex("000000000000000000000000"), *pt = wr_mkbuf_hex("00"), *tag = wr_mkbuf_hex("00000000000000000000000000000000"), *o = NULL;
    EXPECT_HR(eng_ea(NULL, pt, nonce, NULL, &o), HR_E_POINTER);
    EXPECT_HR(eng_ea(k, NULL, nonce, NULL, &o), HR_E_POINTER);
    EXPECT_HR(eng_ea(k, pt, NULL, NULL, &o), HR_E_POINTER);
    EXPECT_HR(eng_da(NULL, pt, nonce, tag, NULL, &o), HR_E_POINTER);
    EXPECT_HR(eng_da(k, NULL, nonce, tag, NULL, &o), HR_E_POINTER);
    EXPECT_HR(eng_da(k, pt, NULL, tag, NULL, &o), HR_E_POINTER);
    EXPECT_HR(eng_da(k, pt, nonce, NULL, NULL, &o), HR_E_POINTER);
    wr_release(k); wr_release(nonce); wr_release(pt); wr_release(tag);
}
TEST(winrt_sym_aead_on_non_aead_key_fails) {
    WR_NEED(); void *k = mk_key(L"AES_CBC_PKCS7", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *nonce = wr_mkbuf_hex("000000000000000000000000"), *pt = wr_mkbuf_hex("00112233"), *res = (void *)1;
    HRESULT hr = eng_ea(k, pt, nonce, NULL, &res);
    CHECK(FAILED(hr)); t_note("EncryptAndAuthenticate(CBC key) -> 0x%08lx", (unsigned long)hr);
    wr_release(k); wr_release(nonce); wr_release(pt);
}
TEST(winrt_sym_plain_encrypt_on_gcm_key) {
    WR_NEED(); void *k = mk_key(L"AES_GCM", "000102030405060708090a0b0c0d0e0f"); if (!k) return;
    void *pt = wr_mkbuf_hex("00112233"), *iv = wr_mkbuf_hex("000000000000000000000000"), *o = NULL;
    HRESULT hr = wr_encrypt(k, pt, iv, &o);
    t_note("Encrypt(GCM key) -> 0x%08lx", (unsigned long)hr);
    wr_release(k); wr_release(pt); wr_release(iv); wr_release(o);
}
TEST(winrt_sym_aead_empty_plaintext_tag_only) {
    WR_NEED(); void *k = mk_key(L"AES_GCM", "00000000000000000000000000000000"); if (!k) return;
    void *nonce = wr_mkbuf_hex("000000000000000000000000"), *pt = wr_mkbuf(NULL, 0), *res = NULL;
    EXPECT_HR(eng_ea(k, pt, nonce, NULL, &res), S_OK);
    if (res) {
        void *ct = NULL, *tag = NULL; VF(res, 6, void **)(res, &ct); VF(res, 7, void **)(res, &tag);
        EXPECT_EQ(wr_buf_len(ct), 0);
        CHECK(wr_buf_is_hex(tag, "58e2fccefa7e3061367f1d57a4e7455a"));      /* GCM spec test case 1 */
        wr_release(ct); wr_release(tag); wr_release(res);
    }
    wr_release(k); wr_release(nonce); wr_release(pt);
}
TEST(winrt_sym_aead_gcm_spec_test_case2) {
    WR_NEED(); void *k = mk_key(L"AES_GCM", "00000000000000000000000000000000"); if (!k) return;
    void *nonce = wr_mkbuf_hex("000000000000000000000000"), *pt = wr_mkbuf_hex("00000000000000000000000000000000"), *res = NULL;
    EXPECT_HR(eng_ea(k, pt, nonce, NULL, &res), S_OK);
    if (res) {
        void *ct = NULL, *tag = NULL; VF(res, 6, void **)(res, &ct); VF(res, 7, void **)(res, &tag);
        CHECK(wr_buf_is_hex(ct, "0388dace60b6a392f328c2b971b2fe78"));
        CHECK(wr_buf_is_hex(tag, "ab6e47d42cec13bdf53a67b21257bddf"));
        wr_release(ct); wr_release(tag); wr_release(res);
    }
    wr_release(k); wr_release(nonce); wr_release(pt);
}

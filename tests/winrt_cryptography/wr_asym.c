/* AsymmetricKeyAlgorithmProvider, AsymmetricAlgorithmNames and asymmetric keys (RSA, ECDSA) via CryptographicEngine. */
#include "wr.h"
#include "wr_vec_asym.h"

#define HR_E_POINTER 0x80004003u
#define HR_E_NOTIMPL 0x80004001u
#define HR_E_INVALIDARG 0x80070057u

/* CryptographicPrivateKeyBlobType / CryptographicPublicKeyBlobType */
enum { PRIV_PKCS8 = 0, PRIV_PKCS1 = 1, PRIV_BCRYPT = 2, PRIV_CAPI1 = 3, PRIV_BCRYPT_ECC_FULL = 4 };
enum { PUB_X509 = 0, PUB_PKCS1 = 1, PUB_BCRYPT = 2, PUB_CAPI1 = 3, PUB_BCRYPT_ECC_FULL = 4 };

static const WCHAR *k_asym18[] = {
    L"RSA_PKCS1", L"RSA_OAEP_SHA1", L"RSA_OAEP_SHA256", L"RSA_OAEP_SHA384", L"RSA_OAEP_SHA512",
    L"ECDSA_P256_SHA256", L"ECDSA_P384_SHA384", L"ECDSA_P521_SHA512", L"DSA_SHA1", L"DSA_SHA256",
    L"RSASIGN_PKCS1_SHA1", L"RSASIGN_PKCS1_SHA256", L"RSASIGN_PKCS1_SHA384", L"RSASIGN_PKCS1_SHA512",
    L"RSASIGN_PSS_SHA1", L"RSASIGN_PSS_SHA256", L"RSASIGN_PSS_SHA384", L"RSASIGN_PSS_SHA512",
};
static const WCHAR *k_asym3[] = { L"ECDSA_SHA256", L"ECDSA_SHA384", L"ECDSA_SHA512" };

/* provider: 6 get_AlgorithmName, 7 CreateKeyPair, 8 ImportKeyPair, 9 ImportKeyPairWithBlobType, 10 ImportPublicKey, 11 ImportPublicKeyWithBlobType */
static HRESULT a_create(void *p, UINT32 bits, void **k) { *k = NULL; return VF(p, 7, UINT32, void **)(p, bits, k); }
static HRESULT a_imp_priv(void *p, void *b, void **k) { *k = NULL; return VF(p, 8, void *, void **)(p, b, k); }
static HRESULT a_imp_priv_t(void *p, void *b, int t, void **k) { *k = NULL; return VF(p, 9, void *, int, void **)(p, b, t, k); }
static HRESULT a_imp_pub(void *p, void *b, void **k) { *k = NULL; return VF(p, 10, void *, void **)(p, b, k); }
static HRESULT a_imp_pub_t(void *p, void *b, int t, void **k) { *k = NULL; return VF(p, 11, void *, int, void **)(p, b, t, k); }
/* key: 6 KeySize, 7 Export, 8 ExportWithBlobType, 9 ExportPublicKey, 10 ExportPublicKeyWithBlobType */
static UINT32 k_size(void *k) { UINT32 n = 0xffffffff; if (k) VF(k, 6, UINT32 *)(k, &n); return n; }
static HRESULT k_exp(void *k, void **b) { *b = NULL; return VF(k, 7, void **)(k, b); }
static HRESULT k_exp_t(void *k, int t, void **b) { *b = NULL; return VF(k, 8, int, void **)(k, t, b); }
static HRESULT k_pub(void *k, void **b) { *b = NULL; return VF(k, 9, void **)(k, b); }
static HRESULT k_pub_t(void *k, int t, void **b) { *b = NULL; return VF(k, 10, int, void **)(k, t, b); }

static HRESULT e_sign(void *key, void *d, void **sig) {
    void *e = wr_engine(); *sig = NULL; if (!e) return E_FAIL;
    return VF(e, EN_Sign, void *, void *, void **)(e, key, d, sig);
}
static HRESULT e_verify(void *key, void *d, void *sig, BYTE *ok) {
    void *e = wr_engine(); *ok = 0x5a; if (!e) return E_FAIL;
    return VF(e, EN_VerifySignature, void *, void *, void *, BYTE *)(e, key, d, sig, ok);
}
static void *open_a(const WCHAR *alg) {
    void *p = NULL; HRESULT hr = wr_asym_open(alg, &p);
    if (hr != S_OK) { if (t_is_wine()) t_skip("emulator"); else t_check(0, __FILE__, __LINE__, "OpenAlgorithm", "%ls hr 0x%08lx", alg, (unsigned long)hr); return NULL; }
    return p;
}
static void *priv_key(const WCHAR *alg, const char *pkcs8hex) {
    void *p = open_a(alg), *b = wr_mkbuf_hex(pkcs8hex), *k = NULL; if (!p) { wr_release(b); return NULL; }
    HRESULT hr = a_imp_priv(p, b, &k);
    if (hr != S_OK) t_check(0, __FILE__, __LINE__, "ImportKeyPair", "%ls hr 0x%08lx", alg, (unsigned long)hr);
    wr_release(p); wr_release(b); return k;
}
static void *pub_key(const WCHAR *alg, const char *spkihex) {
    void *p = open_a(alg), *b = wr_mkbuf_hex(spkihex), *k = NULL; if (!p) { wr_release(b); return NULL; }
    HRESULT hr = a_imp_pub(p, b, &k);
    if (hr != S_OK) t_check(0, __FILE__, __LINE__, "ImportPublicKey", "%ls hr 0x%08lx", alg, (unsigned long)hr);
    wr_release(p); wr_release(b); return k;
}
static int buf_starts_hex(void *b, const char *prefix_hex) {
    BYTE tmp[256]; UINT32 n = wr_unhex(prefix_hex, tmp); const BYTE *p; UINT32 len;
    return wr_buf_get(b, &p, &len) && len >= n && !memcmp(p, tmp, n);
}

/* ---- names / open --------------------------------------------------------------------------------- */
TEST(winrt_asym_names_values) {
    WR_NEED(); void *s = wr_factory(CLS_ASYMNAMES, 1); if (!s) return;
    char seen[18] = { 0 }; int ok = 1;
    for (int i = 0; i < 18; i++) {
        HSTRING h = NULL; if (VF(s, 6 + i, HSTRING *)(s, &h) != S_OK) ok = 0;
        int f = 0; for (int k = 0; k < 18; k++) if (wr_hs_eq(h, k_asym18[k])) { f = 1; seen[k]++; }
        if (!f) ok = 0;
        wr_hsfree(h);
    }
    for (int k = 0; k < 18; k++) if (seen[k] != 1) ok = 0;
    CHECK(ok); wr_release(s);
}
TEST(winrt_asym_names2_values) {
    WR_NEED(); void *s = wr_factory(CLS_ASYMNAMES, 2); if (!s) return;
    char seen[3] = { 0 }; int ok = 1;
    for (int i = 0; i < 3; i++) {
        HSTRING h = NULL; if (VF(s, 6 + i, HSTRING *)(s, &h) != S_OK) ok = 0;
        int f = 0; for (int k = 0; k < 3; k++) if (wr_hs_eq(h, k_asym3[k])) { f = 1; seen[k]++; }
        if (!f) ok = 0;
        wr_hsfree(h);
    }
    for (int k = 0; k < 3; k++) if (seen[k] != 1) ok = 0;
    CHECK(ok); wr_release(s);
}
TEST(winrt_asym_names_interfaces_same_object) {
    WR_NEED(); void *a = wr_factory(CLS_ASYMNAMES, 1), *b = wr_factory(CLS_ASYMNAMES, 2); if (!a || !b) return;
    void *ua = NULL, *ub = NULL; wr_qi(a, &WR_IID_IUnknown, &ua); wr_qi(b, &WR_IID_IUnknown, &ub);
    CHECK(ua && ua == ub);
    wr_release(ua); wr_release(ub); wr_release(a); wr_release(b);
}
TEST(winrt_asym_open_all_names) {
    WR_NEED();
    for (int i = 0; i < 21; i++) {
        const WCHAR *n = i < 18 ? k_asym18[i] : k_asym3[i - 18];
        void *p = NULL; HRESULT hr = wr_asym_open(n, &p);
        if (FAILED(hr) && t_is_wine()) { t_skip("emulator"); return; }
        t_check(hr == S_OK && p, __FILE__, __LINE__, "OpenAlgorithm", "%ls hr 0x%08lx", n, (unsigned long)hr);
        if (!p) continue;
        HSTRING h = NULL; EXPECT_HR(VF(p, 6, HSTRING *)(p, &h), S_OK);
        t_check(wr_hs_eq(h, n), __FILE__, __LINE__, "AlgorithmName", "%ls", n);
        wr_hsfree(h); wr_release(p);
    }
}
TEST(winrt_asym_open_invalid) {
    WR_NEED();
    static const WCHAR *bad[] = { L"", L"RSA_PKCS", L"RSASIGN_PKCS1_SHA2", L"rsa_pkcs1x", L"RSA_PKCS1 ", L"ECDSA_P256_SHA2560" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *st = wr_cls_statics(CLS_ASYMPROV); if (!st) return;
        void *p = (void *)1; HSTRING h = wr_hs(bad[i]);
        HRESULT hr = VF(st, 6, HSTRING, void **)(st, h, &p);
        t_check(FAILED(hr) && p == NULL, __FILE__, __LINE__, "OpenAlgorithm(bad)", "'%ls' hr 0x%08lx", bad[i], (unsigned long)hr);
        if (SUCCEEDED(hr)) wr_release(p);
        wr_hsfree(h); wr_release(st);
    }
}
TEST(winrt_asym_provider_getiids) {
    WR_NEED(); void *p = open_a(L"RSA_PKCS1"); if (!p) return;
    ULONG n = 0; GUID *ids = NULL; EXPECT_HR(wr_getiids(p, &n, &ids), S_OK);
    EXPECT_EQ(n, 3);
    if (n == 3) {
        static const GUID p2 = { 0x4e322a7e, 0x7c4d, 0x4997, { 0xac, 0x4f, 0x1b, 0x84, 0x8b, 0x36, 0x30, 0x6e } };
        CHECK(IsEqualGUID(&ids[0], &WR_IID_IAsymmetricKeyAlgorithmProvider)); CHECK(IsEqualGUID(&ids[2], &p2));
    }
    wr_cofree(ids);
    HSTRING h = NULL; EXPECT_HR(wr_getclassname(p, &h), S_OK);
    CHECK(wr_hs_eq(h, L"Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider")); wr_hsfree(h);
    wr_release(p);
}

/* ---- RSA key generation / export ------------------------------------------------------------------- */
TEST(winrt_asym_rsa_create_key_sizes) {
    WR_NEED(); void *p = open_a(L"RSA_PKCS1"); if (!p) return;
    static const UINT32 ok[] = { 512, 1024, 2048 };
    for (int i = 0; i < 3; i++) {
        void *k; HRESULT hr = a_create(p, ok[i], &k);
        t_check(hr == S_OK && k && k_size(k) == ok[i], __FILE__, __LINE__, "CreateKeyPair", "%u hr 0x%08lx size %u", ok[i], (unsigned long)hr, k_size(k));
        wr_release(k);
    }
    wr_release(p);
}
TEST(winrt_asym_rsa_create_key_invalid_sizes) {
    WR_NEED(); void *p = open_a(L"RSA_PKCS1"); if (!p) return;
    static const UINT32 bad[] = { 0, 1, 64, 256, 511, 513, 1023, 1025, 2047, 2049 };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *k = (void *)1; HRESULT hr = a_create(p, bad[i], &k);
        t_check(FAILED(hr) && k == NULL, __FILE__, __LINE__, "CreateKeyPair(bad)", "%u hr 0x%08lx", bad[i], (unsigned long)hr);
        if (SUCCEEDED(hr)) wr_release(k);
    }
    wr_release(p);
}
TEST(winrt_asym_rsa_create_key_nonpower_sizes) {
    /* sizes that are a multiple of 8 within the CNG limits are accepted, not only multiples of 64 */
    WR_NEED(); void *p = open_a(L"RSA_PKCS1"); if (!p) return;
    static const UINT32 ok[] = { 1000, 3072, 4096 };
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        void *k = (void *)1; HRESULT hr = a_create(p, ok[i], &k);
        t_check(hr == S_OK && k && k_size(k) == ok[i], __FILE__, __LINE__, "CreateKeyPair", "%u hr 0x%08lx size %u", ok[i], (unsigned long)hr, k_size(k));
        if (SUCCEEDED(hr)) wr_release(k);
    }
    wr_release(p);
}
TEST(winrt_asym_rsa_public_export_formats) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    void *k; if (a_create(p, 2048, &k) != S_OK) { CHECK(!"create"); return; }
    void *b;
    EXPECT_HR(k_pub(k, &b), S_OK);                                /* default: X.509 SubjectPublicKeyInfo */
    EXPECT_EQ(wr_buf_len(b), 294);
    CHECK(buf_starts_hex(b, "30820122300d06092a864886f70d01010105000382010f003082010a0282010100"));
    wr_release(b);
    EXPECT_HR(k_pub_t(k, PUB_X509, &b), S_OK); EXPECT_EQ(wr_buf_len(b), 294); wr_release(b);
    EXPECT_HR(k_pub_t(k, PUB_PKCS1, &b), S_OK);
    EXPECT_EQ(wr_buf_len(b), 270); CHECK(buf_starts_hex(b, "3082010a0282010100")); wr_release(b);
    EXPECT_HR(k_pub_t(k, PUB_BCRYPT, &b), S_OK);
    EXPECT_EQ(wr_buf_len(b), 24 + 3 + 256);
    CHECK(buf_starts_hex(b, "525341310008000003000000000100000000000000000000" "010001"));
    wr_release(b);
    wr_release(k); wr_release(p);
}
TEST(winrt_asym_rsa_capi_public_export) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    void *k, *b; if (a_create(p, 1024, &k) != S_OK) { CHECK(!"create"); return; }
    HRESULT hr = k_pub_t(k, PUB_CAPI1, &b);
    EXPECT_HR(hr, S_OK);
    if (hr == S_OK) {          /* PUBLICKEYBLOB: BLOBHEADER(06 02 0000 00a40000) RSAPUBKEY('RSA1' bitlen exp) + modulus */
        CHECK(buf_starts_hex(b, "06020000"));            /* BLOBHEADER: PUBLICKEYBLOB, version 2 (aiKeyAlg bytes not checked) */
        { const BYTE *pb; UINT32 n; if (wr_buf_get(b, &pb, &n) && n >= 20) { BYTE rest[12]; wr_unhex("52534131" "00040000" "01000100", rest); CHECK(!memcmp(pb + 8, rest, 12)); } }
        EXPECT_EQ(wr_buf_len(b), 20 + 128);
    }
    wr_release(b); wr_release(k); wr_release(p);
}
TEST(winrt_asym_rsa_private_export_formats) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    void *k, *b; if (a_create(p, 2048, &k) != S_OK) { CHECK(!"create"); return; }
    EXPECT_HR(k_exp(k, &b), S_OK);                                 /* default: PKCS#8 PrivateKeyInfo */
    CHECK(buf_starts_hex(b, "308204") && wr_buf_len(b) > 1150 && wr_buf_len(b) < 1300);
    CHECK(buf_starts_hex(b, "30820") ); wr_release(b);
    EXPECT_HR(k_exp_t(k, PRIV_PKCS8, &b), S_OK); CHECK(wr_buf_len(b) > 1150); wr_release(b);
    EXPECT_HR(k_exp_t(k, PRIV_PKCS1, &b), S_OK);
    CHECK(buf_starts_hex(b, "308204") && buf_starts_hex(b, "30820") ); CHECK(wr_buf_len(b) > 1100 && wr_buf_len(b) < 1250); wr_release(b);
    EXPECT_HR(k_exp_t(k, PRIV_BCRYPT, &b), S_OK); CHECK(buf_starts_hex(b, "52534132" "00080000")); wr_release(b);
    HRESULT hr = k_exp_t(k, PRIV_CAPI1, &b);
    EXPECT_HR(hr, S_OK);
    if (hr == S_OK) { CHECK(buf_starts_hex(b, "07020000")); const BYTE *pb; UINT32 n; if (wr_buf_get(b, &pb, &n) && n >= 16) { BYTE rest[8]; wr_unhex("52534132" "00080000", rest); CHECK(!memcmp(pb + 8, rest, 8)); } }
    wr_release(b);
    wr_release(k); wr_release(p);
}
TEST(winrt_asym_rsa_export_roundtrip_all_private_types) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    void *k, *pubspki; if (a_create(p, 1024, &k) != S_OK) { CHECK(!"create"); return; }
    k_pub(k, &pubspki);
    static const int types[] = { PRIV_PKCS8, PRIV_PKCS1, PRIV_BCRYPT, PRIV_CAPI1 };
    for (int i = 0; i < 4; i++) {
        void *b, *k2, *pub2; HRESULT hr = k_exp_t(k, types[i], &b); EXPECT_HR(hr, S_OK);
        hr = a_imp_priv_t(p, b, types[i], &k2);
        t_check(hr == S_OK && k2, __FILE__, __LINE__, "import of exported private key", "type %d hr 0x%08lx", types[i], (unsigned long)hr);
        if (k2) {
            k_pub(k2, &pub2);
            const BYTE *pa, *pb; UINT32 la, lb;
            t_check(wr_buf_get(pubspki, &pa, &la) && wr_buf_get(pub2, &pb, &lb) && la == lb && !memcmp(pa, pb, la), __FILE__, __LINE__, "same public key", "type %d", types[i]);
            EXPECT_EQ(k_size(k2), 1024);
            wr_release(pub2);
        }
        wr_release(b); wr_release(k2);
    }
    wr_release(pubspki); wr_release(k); wr_release(p);
}
TEST(winrt_asym_rsa_known_key_import_formats) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    void *b8 = wr_mkbuf_hex(wr_rsa_pkcs8), *b1 = wr_mkbuf_hex(wr_rsa_pkcs1), *k8, *k1, *pub;
    EXPECT_HR(a_imp_priv(p, b8, &k8), S_OK);
    EXPECT_HR(a_imp_priv_t(p, b8, PRIV_PKCS8, &k1), S_OK); wr_release(k1);
    EXPECT_HR(a_imp_priv_t(p, b1, PRIV_PKCS1, &k1), S_OK);
    EXPECT_EQ(k_size(k8), 2048); EXPECT_EQ(k_size(k1), 2048);
    EXPECT_HR(k_pub(k8, &pub), S_OK); CHECK(wr_buf_is_hex(pub, wr_rsa_spki)); wr_release(pub);
    EXPECT_HR(k_pub_t(k1, PUB_PKCS1, &pub), S_OK); CHECK(wr_buf_is_hex(pub, wr_rsa_pub_pkcs1)); wr_release(pub);
    EXPECT_HR(k_pub_t(k8, PUB_BCRYPT, &pub), S_OK);
    { BYTE exp[283]; memcpy(exp, "\x52\x53\x41\x31\x00\x08\x00\x00\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01", 27); wr_unhex(wr_rsa_n, exp + 27);
      CHECK(wr_buf_is(pub, exp, 283)); }
    wr_release(pub); wr_release(b8); wr_release(b1); wr_release(k8); wr_release(k1); wr_release(p);
}
TEST(winrt_asym_rsa_import_public_formats) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    void *s = wr_mkbuf_hex(wr_rsa_spki), *p1 = wr_mkbuf_hex(wr_rsa_pub_pkcs1), *k, *o;
    EXPECT_HR(a_imp_pub(p, s, &k), S_OK); EXPECT_EQ(k_size(k), 2048);
    EXPECT_HR(k_pub(k, &o), S_OK); CHECK(wr_buf_is_hex(o, wr_rsa_spki)); wr_release(o); wr_release(k);
    EXPECT_HR(a_imp_pub_t(p, s, PUB_X509, &k), S_OK); wr_release(k);
    EXPECT_HR(a_imp_pub_t(p, p1, PUB_PKCS1, &k), S_OK); EXPECT_EQ(k_size(k), 2048);
    EXPECT_HR(k_pub(k, &o), S_OK); CHECK(wr_buf_is_hex(o, wr_rsa_spki)); wr_release(o);
    o = NULL; HRESULT hr = k_exp(k, &o);                            /* a public-only key has no private part to export */
    CHECK(FAILED(hr)); CHECK(o == NULL); t_note("Export(public-only key) -> 0x%08lx", (unsigned long)hr);
    wr_release(k); wr_release(s); wr_release(p1); wr_release(p);
}
TEST(winrt_asym_import_garbage_fails) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    static const char *bad[] = { "00", "3000", "30030201", "0102030405060708090a0b0c0d0e0f10", "308204bd0201000000", "ffffffffffffffffffffffffffffffff" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *b = wr_mkbuf_hex(bad[i]), *k = (void *)1;
        HRESULT hr = a_imp_priv(p, b, &k);
        t_check(FAILED(hr) && k == NULL, __FILE__, __LINE__, "ImportKeyPair(garbage)", "#%zu hr 0x%08lx", i, (unsigned long)hr);
        hr = a_imp_pub(p, b, &k);
        t_check(FAILED(hr) && k == NULL, __FILE__, __LINE__, "ImportPublicKey(garbage)", "#%zu hr 0x%08lx", i, (unsigned long)hr);
        wr_release(b);
    }
    void *e = wr_mkbuf(NULL, 0), *k = (void *)1;
    CHECK(FAILED(a_imp_priv(p, e, &k)) && k == NULL);
    CHECK(FAILED(a_imp_priv(p, NULL, &k)) && k == NULL);
    CHECK(FAILED(a_imp_pub(p, NULL, &k)) && k == NULL);
    wr_release(e); wr_release(p);
}
TEST(winrt_asym_import_truncated_pkcs8) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    size_t n = strlen(wr_rsa_pkcs8) / 2; BYTE *d = malloc(n); wr_unhex(wr_rsa_pkcs8, d);
    static const size_t cut[] = { 10, 100, 600, 1000 };
    for (int i = 0; i < 4; i++) {
        void *b = wr_mkbuf(d, (UINT32)(n - cut[i])), *k = (void *)1;
        HRESULT hr = a_imp_priv(p, b, &k);
        t_check(FAILED(hr) && k == NULL, __FILE__, __LINE__, "truncated PKCS#8", "cut %zu hr 0x%08lx", cut[i], (unsigned long)hr);
        wr_release(b);
    }
    free(d); wr_release(p);
}
TEST(winrt_asym_blob_type_mismatches) {
    WR_NEED();
    void *rsa = open_a(L"RSASIGN_PKCS1_SHA256"), *ec = open_a(L"ECDSA_P256_SHA256"); if (!rsa || !ec) return;
    void *b = wr_mkbuf_hex("3000"), *k;
    EXPECT_HR(a_imp_priv_t(ec, b, PRIV_PKCS1, &k), HR_E_INVALIDARG); CHECK(k == NULL);
    EXPECT_HR(a_imp_priv_t(rsa, b, PRIV_BCRYPT_ECC_FULL, &k), HR_E_INVALIDARG);
    EXPECT_HR(a_imp_priv_t(rsa, b, 5, &k), HR_E_NOTIMPL);
    EXPECT_HR(a_imp_priv_t(rsa, b, 99, &k), HR_E_NOTIMPL);
    EXPECT_HR(a_imp_priv_t(rsa, b, -1, &k), HR_E_NOTIMPL);
    wr_release(b); wr_release(rsa); wr_release(ec);
}
TEST(winrt_asym_export_blob_type_errors) {
    WR_NEED();
    void *rsa = open_a(L"RSASIGN_PKCS1_SHA256"), *ec = open_a(L"ECDSA_P256_SHA256"); if (!rsa || !ec) return;
    void *kr, *ke, *b;
    if (a_create(rsa, 1024, &kr) != S_OK || a_create(ec, 256, &ke) != S_OK) { CHECK(!"create"); return; }
    EXPECT_HR(k_exp_t(kr, 5, &b), HR_E_INVALIDARG); CHECK(b == NULL);
    EXPECT_HR(k_exp_t(kr, 99, &b), HR_E_INVALIDARG);
    EXPECT_HR(k_exp_t(kr, PRIV_BCRYPT_ECC_FULL, &b), HR_E_INVALIDARG);
    EXPECT_HR(k_exp_t(ke, PRIV_PKCS1, &b), HR_E_INVALIDARG);
    EXPECT_HR(k_pub_t(kr, 5, &b), HR_E_NOTIMPL); CHECK(b == NULL);
    EXPECT_HR(k_pub_t(kr, 99, &b), HR_E_NOTIMPL);
    EXPECT_HR(k_pub_t(kr, PUB_BCRYPT_ECC_FULL, &b), HR_E_INVALIDARG);
    EXPECT_HR(k_pub_t(ke, PUB_PKCS1, &b), HR_E_INVALIDARG);
    wr_release(kr); wr_release(ke); wr_release(rsa); wr_release(ec);
}
TEST(winrt_asym_key_object_interfaces) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    void *k; if (a_create(p, 512, &k) != S_OK) { CHECK(!"create"); return; }
    void *o = NULL;
    EXPECT_HR(wr_qi(k, &WR_IID_ICryptographicKey, &o), S_OK); wr_release(o);
    EXPECT_HR(wr_qi(k, &WR_IID_IAgileObject, &o), S_OK); wr_release(o);
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(k, &n), S_OK);
    UINT32 l; const WCHAR *r = wr_raw(n, &l);
    CHECK(!lstrcmpW(r, L"Windows.Security.Cryptography.Core.AsymmetricKey") || !lstrcmpW(r, L"Windows.Security.Cryptography.Core.AsymmetricPersistedKey"));
    t_note("asymmetric key class: %ls", r); wr_hsfree(n);
    wr_release(k); wr_release(p);
}

/* ---- RSA sign / verify ----------------------------------------------------------------------------- */
static void rsa_sign_vec(const WCHAR *alg, const char *sig_hex) {
    void *k = priv_key(alg, wr_rsa_pkcs8); if (!k) return;
    void *m = wr_mkbuf(wr_msg, (UINT32)strlen(wr_msg)), *sig = NULL, *pk = pub_key(alg, wr_rsa_spki);
    HRESULT hr = e_sign(k, m, &sig);
    t_check(hr == S_OK && wr_buf_is_hex(sig, sig_hex), __FILE__, __LINE__, "RSA PKCS#1 v1.5 signature", "%ls hr 0x%08lx", alg, (unsigned long)hr);
    BYTE ok;
    void *os = wr_mkbuf_hex(sig_hex);
    EXPECT_HR(e_verify(pk, m, os, &ok), S_OK); EXPECT_EQ(ok, 1);
    EXPECT_HR(e_verify(k, m, os, &ok), S_OK); EXPECT_EQ(ok, 1);        /* a private key can verify too */
    void *m2 = wr_mkbuf("corpus-messagf", 14);
    EXPECT_HR(e_verify(pk, m2, os, &ok), S_OK); EXPECT_EQ(ok, 0);
    wr_release(k); wr_release(m); wr_release(sig); wr_release(pk); wr_release(os); wr_release(m2);
}
TEST(winrt_asym_rsa_sign_pkcs1_sha1) { WR_NEED(); rsa_sign_vec(L"RSASIGN_PKCS1_SHA1", wr_rsa_sig_pkcs1_sha1); }
TEST(winrt_asym_rsa_sign_pkcs1_sha256) { WR_NEED(); rsa_sign_vec(L"RSASIGN_PKCS1_SHA256", wr_rsa_sig_pkcs1_sha256); }
TEST(winrt_asym_rsa_sign_pkcs1_sha384) { WR_NEED(); rsa_sign_vec(L"RSASIGN_PKCS1_SHA384", wr_rsa_sig_pkcs1_sha384); }
TEST(winrt_asym_rsa_sign_pkcs1_sha512) { WR_NEED(); rsa_sign_vec(L"RSASIGN_PKCS1_SHA512", wr_rsa_sig_pkcs1_sha512); }
static void rsa_pss(const WCHAR *alg, const char *sig_hex, const char *own_sig_hex) {
    void *k = priv_key(alg, wr_rsa_pkcs8); if (!k) return;
    void *m = wr_mkbuf(wr_msg, (UINT32)strlen(wr_msg)), *s1 = NULL, *s2 = NULL, *pk = pub_key(alg, wr_rsa_spki);
    BYTE ok;
    EXPECT_HR(e_sign(k, m, &s1), S_OK); EXPECT_HR(e_sign(k, m, &s2), S_OK);
    EXPECT_EQ(wr_buf_len(s1), 256);
    EXPECT_HR(e_verify(pk, m, s1, &ok), S_OK); EXPECT_EQ(ok, 1);
    const BYTE *a, *b; UINT32 la, lb;
    /* Windows signs with a zero-length salt: the signature is deterministic */
    if (wr_buf_get(s1, &a, &la) && wr_buf_get(s2, &b, &lb)) CHECK(la == lb && memcmp(a, b, la) == 0);
    CHECK(wr_buf_is_hex(s1, own_sig_hex));
    /* a signature made with salt length = hash length by another implementation does not verify */
    void *os = wr_mkbuf_hex(sig_hex); EXPECT_HR(e_verify(pk, m, os, &ok), S_OK); EXPECT_EQ(ok, 0);
    wr_release(k); wr_release(m); wr_release(s1); wr_release(s2); wr_release(pk); wr_release(os);
}
TEST(winrt_asym_rsa_sign_pss_sha1) { WR_NEED(); rsa_pss(L"RSASIGN_PSS_SHA1", wr_rsa_sig_pss_sha1, wr_rsa_sig_pss0_sha1); }
TEST(winrt_asym_rsa_sign_pss_sha256) { WR_NEED(); rsa_pss(L"RSASIGN_PSS_SHA256", wr_rsa_sig_pss_sha256, wr_rsa_sig_pss0_sha256); }
TEST(winrt_asym_rsa_sign_pss_sha384) { WR_NEED(); rsa_pss(L"RSASIGN_PSS_SHA384", wr_rsa_sig_pss_sha384, wr_rsa_sig_pss0_sha384); }
TEST(winrt_asym_rsa_sign_pss_sha512) { WR_NEED(); rsa_pss(L"RSASIGN_PSS_SHA512", wr_rsa_sig_pss_sha512, wr_rsa_sig_pss0_sha512); }
TEST(winrt_asym_rsa_verify_wrong_signature_forms) {
    WR_NEED(); void *pk = pub_key(L"RSASIGN_PKCS1_SHA256", wr_rsa_spki); if (!pk) return;
    void *m = wr_mkbuf(wr_msg, (UINT32)strlen(wr_msg)); BYTE ok;
    void *good = wr_mkbuf_hex(wr_rsa_sig_pkcs1_sha256);
    BYTE sig[256]; wr_unhex(wr_rsa_sig_pkcs1_sha256, sig);
    sig[255] ^= 1; void *bad1 = wr_mkbuf(sig, 256); sig[255] ^= 1; sig[0] ^= 0x80; void *bad2 = wr_mkbuf(sig, 256);
    void *sh = wr_mkbuf(sig, 255), *e = wr_mkbuf(NULL, 0);
    EXPECT_HR(e_verify(pk, m, good, &ok), S_OK); EXPECT_EQ(ok, 1);
    EXPECT_HR(e_verify(pk, m, bad1, &ok), S_OK); EXPECT_EQ(ok, 0);
    EXPECT_HR(e_verify(pk, m, bad2, &ok), S_OK); EXPECT_EQ(ok, 0);
    HRESULT hr = e_verify(pk, m, sh, &ok); CHECK(hr == S_OK ? ok == 0 : 1); t_note("Verify(255-byte signature) -> 0x%08lx ok=%d", (unsigned long)hr, ok);
    hr = e_verify(pk, m, e, &ok); CHECK(hr == S_OK ? ok == 0 : 1); t_note("Verify(empty signature) -> 0x%08lx ok=%d", (unsigned long)hr, ok);
    wr_release(pk); wr_release(m); wr_release(good); wr_release(bad1); wr_release(bad2); wr_release(sh); wr_release(e);
}
TEST(winrt_asym_rsa_sign_cross_hash_mismatch) {
    /* a SHA-256 PKCS#1 signature does not verify under the SHA-1 algorithm */
    WR_NEED(); void *pk = pub_key(L"RSASIGN_PKCS1_SHA1", wr_rsa_spki); if (!pk) return;
    void *m = wr_mkbuf(wr_msg, (UINT32)strlen(wr_msg)), *s = wr_mkbuf_hex(wr_rsa_sig_pkcs1_sha256); BYTE ok;
    EXPECT_HR(e_verify(pk, m, s, &ok), S_OK); EXPECT_EQ(ok, 0);
    wr_release(pk); wr_release(m); wr_release(s);
}
TEST(winrt_asym_rsa_sign_empty_message) {
    WR_NEED(); void *k = priv_key(L"RSASIGN_PKCS1_SHA256", wr_rsa_pkcs8), *pk = pub_key(L"RSASIGN_PKCS1_SHA256", wr_rsa_spki); if (!k || !pk) return;
    void *m = wr_mkbuf(NULL, 0), *sig = NULL; BYTE ok;
    EXPECT_HR(e_sign(k, m, &sig), S_OK); EXPECT_HR(e_verify(pk, m, sig, &ok), S_OK); EXPECT_EQ(ok, 1);
    wr_release(k); wr_release(pk); wr_release(m); wr_release(sig);
}
TEST(winrt_asym_capability_sign_requires_private_signature_key) {
    WR_NEED();
    void *pub = pub_key(L"RSASIGN_PKCS1_SHA256", wr_rsa_spki), *enc = priv_key(L"RSA_PKCS1", wr_rsa_pkcs8); if (!pub || !enc) return;
    void *m = wr_mkbuf("x", 1), *sig = (void *)1, *s2 = wr_mkbuf_hex(wr_rsa_sig_pkcs1_sha256); BYTE ok;
    EXPECT_HR(e_sign(pub, m, &sig), HR_E_NOTIMPL);          /* public key: no Sign capability */
    EXPECT_HR(e_sign(enc, m, &sig), HR_E_NOTIMPL);          /* encryption key: no Sign capability */
    EXPECT_HR(e_verify(enc, m, s2, &ok), HR_E_NOTIMPL);     /* encryption key: no Verify capability */
    wr_release(pub); wr_release(enc); wr_release(m); wr_release(s2);
}
TEST(winrt_asym_engine_null_arguments) {
    WR_NEED(); void *k = priv_key(L"RSASIGN_PKCS1_SHA256", wr_rsa_pkcs8); if (!k) return;
    void *m = wr_mkbuf("x", 1), *s = wr_mkbuf("y", 1), *o; BYTE ok;
    EXPECT_HR(e_sign(NULL, m, &o), HR_E_POINTER); EXPECT_HR(e_sign(k, NULL, &o), HR_E_POINTER);
    EXPECT_HR(e_verify(NULL, m, s, &ok), HR_E_POINTER); EXPECT_HR(e_verify(k, NULL, s, &ok), HR_E_POINTER); EXPECT_HR(e_verify(k, m, NULL, &ok), HR_E_POINTER);
    wr_release(k); wr_release(m); wr_release(s);
}

/* ---- RSA encryption ---------------------------------------------------------------------------------- */
static void rsa_dec_vec(const WCHAR *alg, const char *ct_hex) {
    void *k = priv_key(alg, wr_rsa_pkcs8), *pk = pub_key(alg, wr_rsa_spki); if (!k || !pk) return;
    void *ct = wr_mkbuf_hex(ct_hex), *pt = NULL;
    HRESULT hr = wr_decrypt(k, ct, NULL, &pt);
    t_check(hr == S_OK && wr_buf_is(pt, "secret message", 14), __FILE__, __LINE__, "decrypt of foreign ciphertext", "%ls hr 0x%08lx", alg, (unsigned long)hr);
    void *m = wr_mkbuf("secret message", 14), *e1 = NULL, *e2 = NULL, *d = NULL;
    EXPECT_HR(wr_encrypt(pk, m, NULL, &e1), S_OK); EXPECT_EQ(wr_buf_len(e1), 256);
    EXPECT_HR(wr_decrypt(k, e1, NULL, &d), S_OK); CHECK(wr_buf_is(d, "secret message", 14));
    EXPECT_HR(wr_encrypt(pk, m, NULL, &e2), S_OK);
    const BYTE *a, *b; UINT32 la, lb;
    if (wr_buf_get(e1, &a, &la) && wr_buf_get(e2, &b, &lb)) CHECK(memcmp(a, b, la) != 0);       /* randomized padding */
    wr_release(k); wr_release(pk); wr_release(ct); wr_release(pt); wr_release(m); wr_release(e1); wr_release(e2); wr_release(d);
}
TEST(winrt_asym_rsa_pkcs1_encrypt_decrypt) { WR_NEED(); rsa_dec_vec(L"RSA_PKCS1", wr_rsa_enc_pkcs1); }
TEST(winrt_asym_rsa_oaep_sha1) { WR_NEED(); rsa_dec_vec(L"RSA_OAEP_SHA1", wr_rsa_enc_oaep_sha1); }
TEST(winrt_asym_rsa_oaep_sha256) { WR_NEED(); rsa_dec_vec(L"RSA_OAEP_SHA256", wr_rsa_enc_oaep_sha256); }
TEST(winrt_asym_rsa_oaep_sha384) { WR_NEED(); rsa_dec_vec(L"RSA_OAEP_SHA384", wr_rsa_enc_oaep_sha384); }
TEST(winrt_asym_rsa_oaep_sha512) { WR_NEED(); rsa_dec_vec(L"RSA_OAEP_SHA512", wr_rsa_enc_oaep_sha512); }
TEST(winrt_asym_rsa_encrypt_size_limits) {
    WR_NEED(); void *pk = pub_key(L"RSA_PKCS1", wr_rsa_spki), *k = priv_key(L"RSA_PKCS1", wr_rsa_pkcs8); if (!pk || !k) return;
    BYTE d[300]; memset(d, 0x41, sizeof d);
    static const struct { UINT32 n; int ok; } v[] = { { 1, 1 }, { 245, 1 }, { 246, 0 }, { 256, 0 }, { 300, 0 } };    /* 256 - 11 */
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *m = wr_mkbuf(d, v[i].n), *e = (void *)1; HRESULT hr = wr_encrypt(pk, m, NULL, &e);
        t_check((hr == S_OK) == v[i].ok, __FILE__, __LINE__, "PKCS#1 v1.5 plaintext limit", "n %u hr 0x%08lx", v[i].n, (unsigned long)hr);
        if (!v[i].ok) CHECK(e == NULL);
        if (hr == S_OK) { void *r = NULL; wr_decrypt(k, e, NULL, &r); t_check(wr_buf_is(r, d, v[i].n), __FILE__, __LINE__, "roundtrip", "n %u", v[i].n); wr_release(r); wr_release(e); }
        wr_release(m);
    }
    wr_release(pk); wr_release(k);
}
TEST(winrt_asym_rsa_oaep_size_limits) {
    WR_NEED(); void *pk = pub_key(L"RSA_OAEP_SHA256", wr_rsa_spki); if (!pk) return;
    BYTE d[300]; memset(d, 0x41, sizeof d);
    static const struct { UINT32 n; int ok; } v[] = { { 190, 1 }, { 191, 0 }, { 200, 0 } };     /* 256 - 2*32 - 2 = 190 */
    for (size_t i = 0; i < 3; i++) {
        void *m = wr_mkbuf(d, v[i].n), *e = (void *)1; HRESULT hr = wr_encrypt(pk, m, NULL, &e);
        t_check((hr == S_OK) == v[i].ok, __FILE__, __LINE__, "OAEP plaintext limit", "n %u hr 0x%08lx", v[i].n, (unsigned long)hr);
        if (hr == S_OK) wr_release(e);
        wr_release(m);
    }
    wr_release(pk);
}
TEST(winrt_asym_rsa_encrypt_iv_must_be_null) {
    WR_NEED(); void *pk = pub_key(L"RSA_PKCS1", wr_rsa_spki), *k = priv_key(L"RSA_PKCS1", wr_rsa_pkcs8); if (!pk || !k) return;
    void *m = wr_mkbuf("x", 1), *iv = wr_mkbuf("0123456789abcdef", 16), *o = (void *)1;
    EXPECT_HR(wr_encrypt(pk, m, iv, &o), HR_E_INVALIDARG); CHECK(o == NULL);
    void *ct = wr_mkbuf_hex(wr_rsa_enc_pkcs1);
    HRESULT hr = wr_decrypt(k, ct, iv, &o); CHECK(FAILED(hr)); t_note("Decrypt(asym, iv) -> 0x%08lx", (unsigned long)hr);
    wr_release(pk); wr_release(k); wr_release(m); wr_release(iv); wr_release(ct);
}
TEST(winrt_asym_capability_encrypt_decrypt) {
    WR_NEED();
    void *pub = pub_key(L"RSA_PKCS1", wr_rsa_spki), *sigk = priv_key(L"RSASIGN_PKCS1_SHA256", wr_rsa_pkcs8); if (!pub || !sigk) return;
    void *m = wr_mkbuf("x", 1), *o = (void *)1, *ct = wr_mkbuf_hex(wr_rsa_enc_pkcs1);
    EXPECT_HR(wr_decrypt(pub, ct, NULL, &o), HR_E_NOTIMPL);       /* public key cannot decrypt */
    EXPECT_HR(wr_encrypt(sigk, m, NULL, &o), HR_E_NOTIMPL);       /* signature key cannot encrypt */
    EXPECT_HR(wr_decrypt(sigk, ct, NULL, &o), HR_E_NOTIMPL);
    wr_release(pub); wr_release(sigk); wr_release(m); wr_release(ct);
}
TEST(winrt_asym_rsa_decrypt_wrong_data) {
    WR_NEED(); void *k = priv_key(L"RSA_OAEP_SHA256", wr_rsa_pkcs8); if (!k) return;
    BYTE z[256]; memset(z, 0x5a, sizeof z); z[0] = 0;
    void *bad = wr_mkbuf(z, 256), *shortc = wr_mkbuf(z, 100), *o = (void *)1;
    HRESULT hr = wr_decrypt(k, bad, NULL, &o); CHECK(FAILED(hr)); CHECK(o == NULL);
    hr = wr_decrypt(k, shortc, NULL, &o); CHECK(FAILED(hr)); CHECK(o == NULL);
    void *ct = wr_mkbuf_hex(wr_rsa_enc_oaep_sha1);     /* OAEP-SHA1 ciphertext under a SHA-256 OAEP key */
    hr = wr_decrypt(k, ct, NULL, &o); CHECK(FAILED(hr));
    wr_release(k); wr_release(bad); wr_release(shortc); wr_release(ct);
}

/* ---- ECDSA --------------------------------------------------------------------------------------------- */
static const struct { const WCHAR *alg; UINT32 bits, sz; const char *pkcs8, *spki, *x, *y, *d, *sig, *magic; } k_ec[] = {
    { L"ECDSA_P256_SHA256", 256, 32, wr_p256_pkcs8, wr_p256_spki, wr_p256_x, wr_p256_y, wr_p256_d, wr_p256_sig, "45435331" },
    { L"ECDSA_P384_SHA384", 384, 48, wr_p384_pkcs8, wr_p384_spki, wr_p384_x, wr_p384_y, wr_p384_d, wr_p384_sig, "45435333" },
    { L"ECDSA_P521_SHA512", 521, 66, wr_p521_pkcs8, wr_p521_spki, wr_p521_x, wr_p521_y, wr_p521_d, wr_p521_sig, "45435335" },
};
/* Windows does not import an EC PKCS#8 blob (see winrt_asym_ecdsa_pkcs8_import_rejected); the private key goes in as BCRYPT_ECCPRIVATE_BLOB */
static void *ec_priv_key(int i) {
    BYTE blob[256]; UINT32 sz = k_ec[i].sz;
    UINT32 mg = 0x32534345 + (i == 0 ? 0 : i == 1 ? 0x02000000 : 0x04000000);
    memcpy(blob, &mg, 4); memcpy(blob + 4, &sz, 4);
    wr_unhex(k_ec[i].x, blob + 8); wr_unhex(k_ec[i].y, blob + 8 + sz); wr_unhex(k_ec[i].d, blob + 8 + 2 * sz);
    void *p = open_a(k_ec[i].alg); if (!p) return NULL;
    void *b = wr_mkbuf(blob, 8 + 3 * sz), *k = NULL;
    HRESULT hr = a_imp_priv_t(p, b, PRIV_BCRYPT, &k);
    if (hr != S_OK) t_check(0, __FILE__, __LINE__, "ImportKeyPairWithBlobType(BCrypt)", "%ls hr 0x%08lx", k_ec[i].alg, (unsigned long)hr);
    wr_release(p); wr_release(b); return k;
}
TEST(winrt_asym_ecdsa_pkcs8_import_rejected) {
    WR_NEED();
    for (int i = 0; i < 3; i++) {
        void *p = open_a(k_ec[i].alg); if (!p) return;
        for (int t = PRIV_PKCS8; t <= PRIV_BCRYPT_ECC_FULL; t++) {
            void *b = wr_mkbuf_hex(k_ec[i].pkcs8), *k = (void *)1;
            HRESULT hr = a_imp_priv_t(p, b, t, &k);
            t_check(hr == (HRESULT)HR_E_INVALIDARG && k == NULL, __FILE__, __LINE__, "EC PKCS#8 import", "%ls blob type %d hr 0x%08lx", k_ec[i].alg, t, (unsigned long)hr);
            wr_release(b);
        }
        void *b = wr_mkbuf_hex(k_ec[i].pkcs8), *k = (void *)1;
        HRESULT hr = a_imp_priv(p, b, &k);
        t_check(hr == (HRESULT)HR_E_INVALIDARG && k == NULL, __FILE__, __LINE__, "EC PKCS#8 default import", "%ls hr 0x%08lx", k_ec[i].alg, (unsigned long)hr);
        wr_release(b); wr_release(p);
    }
}
TEST(winrt_asym_ecdsa_create_key_pair) {
    WR_NEED();
    for (int i = 0; i < 3; i++) {
        void *p = open_a(k_ec[i].alg); if (!p) return;
        void *k; HRESULT hr = a_create(p, k_ec[i].bits, &k);
        t_check(hr == S_OK && k && k_size(k) == k_ec[i].bits, __FILE__, __LINE__, "CreateKeyPair(ECDSA)", "%ls hr 0x%08lx size %u", k_ec[i].alg, (unsigned long)hr, k_size(k));
        wr_release(k); wr_release(p);
    }
}
TEST(winrt_asym_ecdsa_create_key_wrong_size_note) {
    WR_NEED(); void *p = open_a(L"ECDSA_P256_SHA256"); if (!p) return;
    void *k; HRESULT hr = a_create(p, 384, &k);
    t_note("ECDSA_P256_SHA256 CreateKeyPair(384) -> 0x%08lx size %u", (unsigned long)hr, k_size(k));
    wr_release(k); wr_release(p);
}
TEST(winrt_asym_ecdsa_import_known_private_blob) {
    WR_NEED();
    for (int i = 0; i < 3; i++) {
        void *k = ec_priv_key(i); if (!k) return;
        EXPECT_EQ(k_size(k), k_ec[i].bits);
        void *b; EXPECT_HR(k_pub(k, &b), S_OK);
        t_check(wr_buf_is_hex(b, k_ec[i].spki), __FILE__, __LINE__, "X.509 export equals reference SPKI", "%ls", k_ec[i].alg);
        wr_release(b);
        /* BCRYPT_ECCKEY_BLOB: magic, cbKey (LE), X, Y */
        BYTE blob[256]; UINT32 sz = k_ec[i].sz;
        UINT32 mg = 0x31534345 + (i == 0 ? 0 : i == 1 ? 0x02000000 : 0x04000000);
        memcpy(blob, &mg, 4); memcpy(blob + 4, &sz, 4);
        wr_unhex(k_ec[i].x, blob + 8); wr_unhex(k_ec[i].y, blob + 8 + sz);
        EXPECT_HR(k_pub_t(k, PUB_BCRYPT, &b), S_OK);
        t_check(wr_buf_is(b, blob, 8 + 2 * sz), __FILE__, __LINE__, "BCrypt ECC public blob", "%ls", k_ec[i].alg);
        wr_release(b);
        /* private magics are 'ECS2' / 'ECS4' / 'ECS6' */
        mg = 0x32534345 + (i == 0 ? 0 : i == 1 ? 0x02000000 : 0x04000000);
        memcpy(blob, &mg, 4); wr_unhex(k_ec[i].d, blob + 8 + 2 * sz);
        EXPECT_HR(k_exp_t(k, PRIV_BCRYPT, &b), S_OK);
        t_check(wr_buf_is(b, blob, 8 + 3 * sz), __FILE__, __LINE__, "BCrypt ECC private blob", "%ls", k_ec[i].alg);
        wr_release(b); wr_release(k);
    }
}
TEST(winrt_asym_ecdsa_import_public_spki) {
    WR_NEED();
    for (int i = 0; i < 3; i++) {
        void *k = pub_key(k_ec[i].alg, k_ec[i].spki); if (!k) return;
        if (k_size(k) != k_ec[i].bits) t_note("%ls imported SPKI KeySize = %u (curve size %u)", k_ec[i].alg, k_size(k), k_ec[i].bits);
        void *b; EXPECT_HR(k_pub(k, &b), S_OK); CHECK(wr_buf_is_hex(b, k_ec[i].spki)); wr_release(b);
        wr_release(k);
    }
}
TEST(winrt_asym_ecdsa_verify_reference_signatures) {
    WR_NEED();
    for (int i = 0; i < 3; i++) {
        void *k = pub_key(k_ec[i].alg, k_ec[i].spki); if (!k) return;
        void *m = wr_mkbuf(wr_msg, (UINT32)strlen(wr_msg)), *s = wr_mkbuf_hex(k_ec[i].sig); BYTE ok;
        HRESULT hr = e_verify(k, m, s, &ok);
        t_check(hr == S_OK && ok == 1, __FILE__, __LINE__, "verify reference r||s signature", "%ls hr 0x%08lx ok %d", k_ec[i].alg, (unsigned long)hr, ok);
        void *m2 = wr_mkbuf("corpus-messagf", 14); hr = e_verify(k, m2, s, &ok);
        t_check(hr == S_OK && ok == 0, __FILE__, __LINE__, "tampered message", "%ls hr 0x%08lx ok %d", k_ec[i].alg, (unsigned long)hr, ok);
        BYTE sg[140]; UINT32 n = wr_unhex(k_ec[i].sig, sg); sg[n - 1] ^= 1; void *s2 = wr_mkbuf(sg, n);
        hr = e_verify(k, m, s2, &ok);
        t_check(hr == S_OK && ok == 0, __FILE__, __LINE__, "tampered signature", "%ls hr 0x%08lx ok %d", k_ec[i].alg, (unsigned long)hr, ok);
        wr_release(k); wr_release(m); wr_release(s); wr_release(m2); wr_release(s2);
    }
}
TEST(winrt_asym_ecdsa_sign_verify_roundtrip) {
    WR_NEED();
    for (int i = 0; i < 3; i++) {
        void *k = ec_priv_key(i); if (!k) return;
        void *pk = pub_key(k_ec[i].alg, k_ec[i].spki);
        void *m = wr_mkbuf(wr_msg, (UINT32)strlen(wr_msg)), *s1 = NULL, *s2 = NULL; BYTE ok;
        EXPECT_HR(e_sign(k, m, &s1), S_OK); EXPECT_HR(e_sign(k, m, &s2), S_OK);
        t_check(wr_buf_len(s1) == 2 * k_ec[i].sz, __FILE__, __LINE__, "signature is r||s", "%ls len %u want %u", k_ec[i].alg, wr_buf_len(s1), 2 * k_ec[i].sz);
        EXPECT_HR(e_verify(pk, m, s1, &ok), S_OK); EXPECT_EQ(ok, 1);
        EXPECT_HR(e_verify(pk, m, s2, &ok), S_OK); EXPECT_EQ(ok, 1);
        const BYTE *a, *b; UINT32 la, lb;
        if (wr_buf_get(s1, &a, &la) && wr_buf_get(s2, &b, &lb)) CHECK(memcmp(a, b, la) != 0);    /* random nonce */
        wr_release(k); wr_release(pk); wr_release(m); wr_release(s1); wr_release(s2);
    }
}
TEST(winrt_asym_ecdsa_sign_new_key_roundtrip) {
    WR_NEED(); void *p = open_a(L"ECDSA_P256_SHA256"); if (!p) return;
    void *k, *m = wr_mkbuf("hello", 5), *s = NULL; BYTE ok;
    if (a_create(p, 256, &k) != S_OK) { CHECK(!"create"); return; }
    EXPECT_HR(e_sign(k, m, &s), S_OK); EXPECT_HR(e_verify(k, m, s, &ok), S_OK); EXPECT_EQ(ok, 1);
    void *pb; k_pub(k, &pb); void *pk = NULL; a_imp_pub(p, pb, &pk);
    EXPECT_HR(e_verify(pk, m, s, &ok), S_OK); EXPECT_EQ(ok, 1);
    void *other; a_create(p, 256, &other); EXPECT_HR(e_verify(other, m, s, &ok), S_OK); EXPECT_EQ(ok, 0);
    wr_release(k); wr_release(m); wr_release(s); wr_release(pb); wr_release(pk); wr_release(other); wr_release(p);
}
TEST(winrt_asym_ecdsa_public_key_cannot_sign) {
    WR_NEED(); void *pk = pub_key(L"ECDSA_P256_SHA256", wr_p256_spki); if (!pk) return;
    void *m = wr_mkbuf("x", 1), *s = (void *)1;
    EXPECT_HR(e_sign(pk, m, &s), HR_E_NOTIMPL);
    wr_release(pk); wr_release(m);
}
TEST(winrt_asym_ecdsa_cross_curve_import_fails) {
    WR_NEED(); void *p = open_a(L"ECDSA_P384_SHA384"); if (!p) return;
    void *b = wr_mkbuf_hex(wr_p256_spki), *k = (void *)1;
    HRESULT hr = a_imp_pub(p, b, &k);
    t_note("import P-256 SPKI into ECDSA_P384_SHA384 -> 0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) CHECK(k == NULL); else wr_release(k);
    void *b2 = wr_mkbuf_hex(wr_p256_pkcs8); hr = a_imp_priv(p, b2, &k);
    t_note("import P-256 PKCS#8 into ECDSA_P384_SHA384 -> 0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) CHECK(k == NULL); else wr_release(k);
    wr_release(p); wr_release(b); wr_release(b2);
}
TEST(winrt_asym_ecdsa_generic_import_into_rsa_fails) {
    WR_NEED(); void *p = open_a(L"RSASIGN_PKCS1_SHA256"); if (!p) return;
    void *b = wr_mkbuf_hex(wr_p256_spki), *k = (void *)1;
    HRESULT hr = a_imp_pub(p, b, &k);
    t_note("import EC SPKI into an RSA provider -> 0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) CHECK(k == NULL); else wr_release(k);
    void *b2 = wr_mkbuf_hex(wr_p256_pkcs8); hr = a_imp_priv(p, b2, &k);
    t_note("import EC PKCS#8 into an RSA provider -> 0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) CHECK(k == NULL); else wr_release(k);
    wr_release(p); wr_release(b); wr_release(b2);
}
TEST(winrt_asym_rsa_into_ecdsa_import_fails) {
    WR_NEED(); void *p = open_a(L"ECDSA_P256_SHA256"); if (!p) return;
    void *b = wr_mkbuf_hex(wr_rsa_spki), *k = (void *)1;
    HRESULT hr = a_imp_pub(p, b, &k);
    t_note("import RSA SPKI into an ECDSA provider -> 0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) CHECK(k == NULL); else wr_release(k);
    void *b2 = wr_mkbuf_hex(wr_rsa_pkcs8); hr = a_imp_priv(p, b2, &k);
    t_note("import RSA PKCS#8 into an ECDSA provider -> 0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) CHECK(k == NULL); else wr_release(k);
    wr_release(p); wr_release(b); wr_release(b2);
}
TEST(winrt_asym_ecdsa_curve_name_creation) {
    WR_NEED(); void *p = open_a(L"ECDSA_SHA256"); if (!p) return;
    static const GUID p2 = { 0x4e322a7e, 0x7c4d, 0x4997, { 0xac, 0x4f, 0x1b, 0x84, 0x8b, 0x36, 0x30, 0x6e } };
    void *q = NULL; HRESULT hr = wr_qi(p, &p2, &q); EXPECT_HR(hr, S_OK);
    if (q) {
        static const struct { const WCHAR *c; UINT32 bits; } v[] = { { L"nistP256", 256 }, { L"nistP384", 384 }, { L"nistP521", 521 } };
        for (int i = 0; i < 3; i++) {
            HSTRING h = wr_hs(v[i].c); void *k = NULL;
            hr = VF(q, 6, HSTRING, void **)(q, h, &k);
            t_check(hr == S_OK && k_size(k) == v[i].bits, __FILE__, __LINE__, "CreateKeyPairWithCurveName", "%ls hr 0x%08lx size %u", v[i].c, (unsigned long)hr, k_size(k));
            wr_release(k); wr_hsfree(h);
        }
        HSTRING bad = wr_hs(L"noSuchCurve"); void *k = (void *)1;
        hr = VF(q, 6, HSTRING, void **)(q, bad, &k); CHECK(FAILED(hr)); CHECK(k == NULL);
        wr_hsfree(bad); wr_release(q);
    }
    wr_release(p);
}

/* KeyDerivationAlgorithmProvider / KeyDerivationParameters / DeriveKeyMaterial and DataProtectionProvider (async). */
#include "wr.h"
#include "wr_vec_kdf.h"

#define HR_E_POINTER 0x80004003u
#define HR_E_NOTIMPL 0x80004001u
#define HR_E_NOINTERFACE 0x80004002u
#define HR_E_INVALIDARG 0x80070057u

static const GUID k_iid_keyderivparams = { 0x7bf05967, 0x047b, 0x4a8c, { 0x96, 0x4a, 0x46, 0x9f, 0xfd, 0x55, 0x22, 0xe2 } };
static const GUID k_iid_asyncinfo = { 0x00000036, 0, 0, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };
static const GUID k_iid_asyncop_buffer = { 0x3bee8834, 0xb9a7, 0x5a80, { 0xa7, 0x46, 0x5e, 0xf0, 0x97, 0x22, 0x78, 0x78 } };
static const GUID k_iid_dpprovider = { 0x09639948, 0xed22, 0x4270, { 0xbd, 0x1c, 0x6d, 0x72, 0xc0, 0x0f, 0x87, 0x87 } };

/* ---- KDF names ------------------------------------------------------------------------------------ */
static const WCHAR *k_kdfnames1[] = {
    L"PBKDF2_MD5", L"PBKDF2_SHA1", L"PBKDF2_SHA256", L"PBKDF2_SHA384", L"PBKDF2_SHA512",
    L"SP800_108_CTR_HMAC_MD5", L"SP800_108_CTR_HMAC_SHA1", L"SP800_108_CTR_HMAC_SHA256", L"SP800_108_CTR_HMAC_SHA384", L"SP800_108_CTR_HMAC_SHA512",
    L"SP800_56A_CONCAT_MD5", L"SP800_56A_CONCAT_SHA1", L"SP800_56A_CONCAT_SHA256", L"SP800_56A_CONCAT_SHA384", L"SP800_56A_CONCAT_SHA512",
};
static const WCHAR *k_kdfnames2[] = { L"CAPI_KDF_MD5", L"CAPI_KDF_SHA1", L"CAPI_KDF_SHA256", L"CAPI_KDF_SHA384", L"CAPI_KDF_SHA512" };
static int names_set(void *s, const WCHAR **w, int n) {
    char seen[32] = { 0 }; int ok = 1;
    for (int i = 0; i < n; i++) {
        HSTRING h = NULL; if (VF(s, 6 + i, HSTRING *)(s, &h) != S_OK) ok = 0;
        int f = 0; for (int k = 0; k < n; k++) if (wr_hs_eq(h, w[k])) { f = 1; seen[k]++; }
        if (!f) ok = 0;
        wr_hsfree(h);
    }
    for (int k = 0; k < n; k++) if (seen[k] != 1) ok = 0;
    return ok;
}
TEST(winrt_kdf_names_values) {
    WR_NEED(); void *s = wr_factory(CLS_KDFNAMES, 1); if (!s) return;
    CHECK(names_set(s, k_kdfnames1, 15)); wr_release(s);
}
TEST(winrt_kdf_names2_capi_values) {
    WR_NEED(); void *s = wr_factory(CLS_KDFNAMES, 2); if (!s) return;
    CHECK(names_set(s, k_kdfnames2, 5)); wr_release(s);
}
TEST(winrt_kdf_open_all_names) {
    WR_NEED();
    for (int i = 0; i < 15; i++) {
        void *p = NULL; HRESULT hr = wr_kdf_open(k_kdfnames1[i], &p);
        if (FAILED(hr) && t_is_wine()) { t_skip("emulator"); return; }
        t_check(hr == S_OK && p, __FILE__, __LINE__, "KeyDerivationAlgorithmProvider.OpenAlgorithm", "%ls hr 0x%08lx", k_kdfnames1[i], (unsigned long)hr);
        if (!p) continue;
        HSTRING n = NULL; EXPECT_HR(VF(p, 6, HSTRING *)(p, &n), S_OK); CHECK(wr_hs_eq(n, k_kdfnames1[i])); wr_hsfree(n);
        wr_release(p);
    }
}
TEST(winrt_kdf_open_capi_names_note) {
    WR_NEED();
    for (int i = 0; i < 5; i++) {
        void *p = NULL; HRESULT hr = wr_kdf_open(k_kdfnames2[i], &p);
        if (FAILED(hr) && t_is_wine()) { t_skip("emulator"); return; }
        t_check(hr == S_OK && p, __FILE__, __LINE__, "OpenAlgorithm(CAPI KDF name)", "%ls hr 0x%08lx", k_kdfnames2[i], (unsigned long)hr); wr_release(p);
    }
}
TEST(winrt_kdf_open_invalid) {
    WR_NEED();
    static const WCHAR *bad[] = { L"", L"PBKDF2_SHA2", L"SP800_108", L"PBKDF2_SHA1 ", L"PBKDF2_SHA2560" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *st = wr_cls_statics(CLS_KDFPROV); if (!st) return;
        void *p = (void *)1; HSTRING h = wr_hs(bad[i]);
        HRESULT hr = VF(st, 6, HSTRING, void **)(st, h, &p);
        t_check(FAILED(hr) && p == NULL, __FILE__, __LINE__, "KDF OpenAlgorithm(bad)", "'%ls' hr 0x%08lx", bad[i], (unsigned long)hr);
        if (SUCCEEDED(hr)) wr_release(p);
        wr_hsfree(h); wr_release(st);
    }
}
TEST(winrt_kdf_provider_class_name) {
    WR_NEED(); void *p = NULL;
    if (wr_kdf_open(L"PBKDF2_SHA1", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(p, &n), S_OK);
    CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.KeyDerivationAlgorithmProvider")); wr_hsfree(n);
    ULONG c = 0; GUID *ids = NULL; EXPECT_HR(wr_getiids(p, &c, &ids), S_OK); EXPECT_EQ(c, 2); wr_cofree(ids);
    wr_release(p);
}

/* ---- KeyDerivationParameters -------------------------------------------------------------------------- */
/* statics: 6 BuildForPbkdf2(salt, iterations, out), 7 BuildForSP800108(label, context, out), 8 BuildForSP80056a(algId, partyU, partyV, suppPub, suppPriv, out) */
static HRESULT p_pbkdf2(void *s, void *salt, UINT32 it, void **o) { *o = NULL; return VF(s, 6, void *, UINT32, void **)(s, salt, it, o); }
static HRESULT p_sp800108(void *s, void *l, void *c, void **o) { *o = NULL; return VF(s, 7, void *, void *, void **)(s, l, c, o); }
/* IKeyDerivationParameters has {get_KdfGenericBinary, put_KdfGenericBinary, get_IterationCount}; probe slot 6 with
 * a 16-byte out area (safe for either getter) before trusting the order. Returns 1 when slot 6 hands back an object. */
static int params_layout_binary_first(void *p) {
    UINT64 out[2] = { 0, 0 };
    HRESULT hr = VF(p, 6, void *)(p, out);
    if (FAILED(hr)) return 0;
    if (out[0] > 0x100000) { wr_release((void *)(ULONG_PTR)out[0]); return 1; }
    return 0;
}
TEST(winrt_kdf_params_pbkdf2_build) {
    WR_NEED(); void *s = wr_cls_statics(CLS_KDFPARAMS); if (!s) return;
    void *salt = wr_mkbuf("salt", 4), *p = NULL;
    EXPECT_HR(p_pbkdf2(s, salt, 1000, &p), S_OK); CHECK(p != NULL);
    if (p) {
        HSTRING n = NULL; EXPECT_HR(wr_getclassname(p, &n), S_OK);
        CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.KeyDerivationParameters")); wr_hsfree(n);
        void *u = NULL; EXPECT_HR(wr_qi(p, &k_iid_keyderivparams, &u), S_OK); wr_release(u);
        if (params_layout_binary_first(p)) {
            void *bin = NULL; EXPECT_HR(VF(p, 6, void **)(p, &bin), S_OK); CHECK(wr_buf_is(bin, "salt", 4));
            UINT32 it = 0; EXPECT_HR(VF(p, 8, UINT32 *)(p, &it), S_OK); EXPECT_EQ(it, 1000);
            wr_release(bin);
        } else CHECK(!"IKeyDerivationParameters slot order is {KdfGenericBinary, IterationCount}");
        wr_release(p);
    }
    wr_release(salt); wr_release(s);
}
TEST(winrt_kdf_params_pbkdf2_null_salt) {
    WR_NEED(); void *s = wr_cls_statics(CLS_KDFPARAMS); if (!s) return;
    void *p = (void *)1; EXPECT_HR(p_pbkdf2(s, NULL, 1, &p), HR_E_POINTER); CHECK(p == NULL);
    wr_release(s);
}
TEST(winrt_kdf_params_pbkdf2_iteration_counts_stored) {
    WR_NEED(); void *s = wr_cls_statics(CLS_KDFPARAMS); if (!s) return;
    void *salt = wr_mkbuf("s", 1); static const UINT32 its[] = { 1000, 1, 2, 4096, 100000, 0xffffffffu };
    for (size_t i = 0; i < sizeof its / sizeof *its; i++) {
        void *p = NULL; HRESULT hr = p_pbkdf2(s, salt, its[i], &p);
        t_check(hr == S_OK && p, __FILE__, __LINE__, "BuildForPbkdf2", "iterations %u hr 0x%08lx", its[i], (unsigned long)hr);
        if (p && i == 0 && !params_layout_binary_first(p)) { wr_release(p); break; }
        if (p) { UINT32 it = 1; VF(p, 8, UINT32 *)(p, &it); t_check(it == its[i], __FILE__, __LINE__, "IterationCount", "want %u got %u", its[i], it); wr_release(p); }
    }
    wr_release(salt); wr_release(s);
}
TEST(winrt_kdf_params_generic_binary_put_get) {
    WR_NEED(); void *s = wr_cls_statics(CLS_KDFPARAMS); if (!s) return;
    void *salt = wr_mkbuf("salt", 4), *p = NULL; p_pbkdf2(s, salt, 1000, &p); if (!p) return;
    if (!params_layout_binary_first(p)) { CHECK(!"parameters slot order"); wr_release(p); wr_release(salt); wr_release(s); return; }
    void *nb = wr_mkbuf("pepper", 6), *got = NULL;
    EXPECT_HR(VF(p, 7, void *)(p, nb), S_OK);
    EXPECT_HR(VF(p, 6, void **)(p, &got), S_OK); CHECK(got == nb);
    wr_release(got);
    EXPECT_HR(VF(p, 7, void *)(p, NULL), S_OK);
    EXPECT_HR(VF(p, 6, void **)(p, &got), S_OK); CHECK(got == NULL);
    wr_release(nb); wr_release(p); wr_release(salt); wr_release(s);
}
TEST(winrt_kdf_params_sp800108_layout) {
    WR_NEED(); void *s = wr_cls_statics(CLS_KDFPARAMS); if (!s) return;
    void *l = wr_mkbuf("lab", 3), *c = wr_mkbuf("ctxt", 4), *p = NULL;
    EXPECT_HR(p_sp800108(s, l, c, &p), S_OK);
    if (p && params_layout_binary_first(p)) {
        void *bin = NULL; VF(p, 6, void **)(p, &bin);
        CHECK(wr_buf_is(bin, "lab\0ctxt", 8));              /* Label || 0x00 || Context */
        wr_release(bin);
    }
    wr_release(p); wr_release(l); wr_release(c); wr_release(s);
}
TEST(winrt_kdf_params_sp800108_argument_errors) {
    WR_NEED(); void *s = wr_cls_statics(CLS_KDFPARAMS); if (!s) return;
    void *l = wr_mkbuf("lab", 3), *c = wr_mkbuf("ctxt", 4), *e = wr_mkbuf(NULL, 0), *p;
    EXPECT_HR(p_sp800108(s, NULL, c, &p), HR_E_POINTER); CHECK(p == NULL);
    EXPECT_HR(p_sp800108(s, l, NULL, &p), HR_E_POINTER);
    EXPECT_HR(p_sp800108(s, NULL, NULL, &p), HR_E_POINTER);
    EXPECT_HR(p_sp800108(s, e, c, &p), HR_E_INVALIDARG);     /* empty label */
    EXPECT_HR(p_sp800108(s, l, e, &p), HR_E_INVALIDARG);     /* empty context */
    EXPECT_HR(p_sp800108(s, e, e, &p), HR_E_INVALIDARG);
    wr_release(l); wr_release(c); wr_release(e); wr_release(s);
}

/* ---- KDF key + DeriveKeyMaterial ------------------------------------------------------------------------- */
static HRESULT kdf_key(void *prov, void *pw, void **k) { *k = NULL; return VF(prov, 7, void *, void **)(prov, pw, k); }
static HRESULT derive(void *key, void *params, UINT32 n, void **o) {
    void *e = wr_engine(); *o = NULL; if (!e) return E_FAIL;
    return VF(e, EN_DeriveKeyMaterial, void *, void *, UINT32, void **)(e, key, params, n, o);
}
TEST(winrt_kdf_pbkdf2_vectors) {
    WR_NEED(); void *ps = wr_cls_statics(CLS_KDFPARAMS); if (!ps) return; void *prov = NULL; const WCHAR *cur = NULL;
    for (size_t i = 0; i < sizeof wr_pbkdf2_vecs / sizeof *wr_pbkdf2_vecs; i++) {
        const struct wr_kv *v = &wr_pbkdf2_vecs[i];
        if (v->alg != cur) { wr_release(prov); prov = NULL; cur = v->alg; if (wr_kdf_open(cur, &prov) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } CHECK(!"open"); return; } }
        void *pw = wr_mkbuf_hex(v->pw), *salt = wr_mkbuf_hex(v->salt), *key = NULL, *par = NULL, *out = NULL;
        HRESULT h1 = kdf_key(prov, pw, &key), h2 = p_pbkdf2(ps, salt, v->iter, &par), h3 = (key && par) ? derive(key, par, v->dklen, &out) : E_FAIL;
        t_check(h1 == S_OK && h2 == S_OK && h3 == S_OK && wr_buf_is_hex(out, v->dk), __FILE__, __LINE__, "PBKDF2", "%ls vector %zu (it %u, len %u) hr 0x%08lx/0x%08lx/0x%08lx", v->alg, i, v->iter, v->dklen, (unsigned long)h1, (unsigned long)h2, (unsigned long)h3);
        wr_release(pw); wr_release(salt); wr_release(key); wr_release(par); wr_release(out);
    }
    wr_release(prov); wr_release(ps);
}
TEST(winrt_kdf_pbkdf2_rfc6070) {
    WR_NEED(); void *ps = wr_cls_statics(CLS_KDFPARAMS), *prov = NULL; if (!ps) return;
    if (wr_kdf_open(L"PBKDF2_SHA1", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    static const struct { UINT32 it, n; const char *dk; } v[] = {
        { 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6" }, { 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957" },
        { 4096, 20, "4b007901b765489abead49d926f721d065a429c1" }, { 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984" },
    };
    void *pw = wr_mkbuf("password", 8), *salt = wr_mkbuf("salt", 4), *key; kdf_key(prov, pw, &key);
    for (int i = 0; i < 3; i++) {                 /* the 16M-iteration vector is too slow for a conformance run */
        void *par, *out = NULL; p_pbkdf2(ps, salt, v[i].it, &par);
        EXPECT_HR(derive(key, par, v[i].n, &out), S_OK); CHECK(wr_buf_is_hex(out, v[i].dk));
        wr_release(par); wr_release(out);
    }
    wr_release(pw); wr_release(salt); wr_release(key); wr_release(prov); wr_release(ps);
}
TEST(winrt_kdf_key_object) {
    WR_NEED(); void *prov = NULL;
    if (wr_kdf_open(L"PBKDF2_SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *pw = wr_mkbuf("password", 8), *key; EXPECT_HR(kdf_key(prov, pw, &key), S_OK); if (!key) return;
    UINT32 sz = 0; EXPECT_HR(VF(key, 6, UINT32 *)(key, &sz), S_OK); EXPECT_EQ(sz, 64);
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(key, &n), S_OK);
    CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.KeyDerivationKey")); wr_hsfree(n);
    void *o = NULL; EXPECT_HR(wr_qi(key, &WR_IID_ICryptographicKey, &o), S_OK); wr_release(o);
    wr_release(pw); wr_release(key); wr_release(prov);
}
TEST(winrt_kdf_deterministic_and_length) {
    WR_NEED(); void *ps = wr_cls_statics(CLS_KDFPARAMS), *prov = NULL; if (!ps) return;
    if (wr_kdf_open(L"PBKDF2_SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *pw = wr_mkbuf("pw", 2), *salt = wr_mkbuf("na", 2), *key, *par; kdf_key(prov, pw, &key); p_pbkdf2(ps, salt, 3, &par);
    for (UINT32 n = 1; n <= 100; n += 9) {
        void *a = NULL, *b = NULL; HRESULT h1 = derive(key, par, n, &a), h2 = derive(key, par, n, &b);
        const BYTE *pa, *pb; UINT32 la, lb;
        t_check(h1 == S_OK && h2 == S_OK && wr_buf_get(a, &pa, &la) && wr_buf_get(b, &pb, &lb) && la == n && lb == n && !memcmp(pa, pb, n), __FILE__, __LINE__, "derive length/determinism", "n %u", n);
        wr_release(a); wr_release(b);
    }
    wr_release(pw); wr_release(salt); wr_release(key); wr_release(par); wr_release(prov); wr_release(ps);
}
TEST(winrt_kdf_prefix_property) {
    /* a shorter derivation is a prefix of a longer one for PBKDF2 */
    WR_NEED(); void *ps = wr_cls_statics(CLS_KDFPARAMS), *prov = NULL; if (!ps) return;
    if (wr_kdf_open(L"PBKDF2_SHA1", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *pw = wr_mkbuf("pw", 2), *salt = wr_mkbuf("na", 2), *key, *par; kdf_key(prov, pw, &key); p_pbkdf2(ps, salt, 5, &par);
    void *a = NULL, *b = NULL; derive(key, par, 10, &a); derive(key, par, 50, &b);
    const BYTE *pa, *pb; UINT32 la, lb;
    CHECK(wr_buf_get(a, &pa, &la) && wr_buf_get(b, &pb, &lb) && la == 10 && lb == 50 && !memcmp(pa, pb, 10));
    wr_release(a); wr_release(b); wr_release(pw); wr_release(salt); wr_release(key); wr_release(par); wr_release(prov); wr_release(ps);
}
TEST(winrt_kdf_password_and_salt_sensitivity) {
    WR_NEED(); void *ps = wr_cls_statics(CLS_KDFPARAMS), *prov = NULL; if (!ps) return;
    if (wr_kdf_open(L"PBKDF2_SHA1", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *pw1 = wr_mkbuf("pw1", 3), *pw2 = wr_mkbuf("pw2", 3), *s1 = wr_mkbuf("n1", 2), *s2 = wr_mkbuf("n2", 2), *k1, *k2, *p1, *p2, *o[4] = { 0 };
    kdf_key(prov, pw1, &k1); kdf_key(prov, pw2, &k2); p_pbkdf2(ps, s1, 2, &p1); p_pbkdf2(ps, s2, 2, &p2);
    derive(k1, p1, 20, &o[0]); derive(k2, p1, 20, &o[1]); derive(k1, p2, 20, &o[2]);
    void *cs = wr_cbs(); BYTE r;
    VF(cs, CB_Compare, void *, void *, BYTE *)(cs, o[0], o[1], &r); EXPECT_EQ(r, 0);
    VF(cs, CB_Compare, void *, void *, BYTE *)(cs, o[0], o[2], &r); EXPECT_EQ(r, 0);
    for (int i = 0; i < 3; i++) wr_release(o[i]);
    wr_release(pw1); wr_release(pw2); wr_release(s1); wr_release(s2); wr_release(k1); wr_release(k2); wr_release(p1); wr_release(p2); wr_release(prov); wr_release(ps);
}
TEST(winrt_kdf_derive_null_arguments) {
    WR_NEED(); void *ps = wr_cls_statics(CLS_KDFPARAMS), *prov = NULL; if (!ps) return;
    if (wr_kdf_open(L"PBKDF2_SHA1", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *pw = wr_mkbuf("pw", 2), *salt = wr_mkbuf("na", 2), *key, *par, *o; kdf_key(prov, pw, &key); p_pbkdf2(ps, salt, 2, &par);
    EXPECT_HR(derive(NULL, par, 8, &o), HR_E_POINTER);
    EXPECT_HR(derive(key, NULL, 8, &o), HR_E_POINTER);
    wr_release(pw); wr_release(salt); wr_release(key); wr_release(par); wr_release(prov); wr_release(ps);
}
TEST(winrt_kdf_derive_with_non_kdf_key) {
    WR_NEED(); void *ps = wr_cls_statics(CLS_KDFPARAMS); if (!ps) return;
    void *p = NULL, *kb = wr_mkbuf("0123456789abcdef", 16), *key = NULL, *salt = wr_mkbuf("na", 2), *par, *o = (void *)1;
    if (wr_sym_open(L"AES_CBC", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    wr_sym_key(p, kb, &key); p_pbkdf2(ps, salt, 2, &par);
    EXPECT_HR(derive(key, par, 8, &o), HR_E_NOINTERFACE); CHECK(o == NULL);
    wr_release(p); wr_release(kb); wr_release(key); wr_release(salt); wr_release(par); wr_release(ps);
}
TEST(winrt_kdf_key_is_not_a_cipher_or_signing_key) {
    WR_NEED(); void *prov = NULL;
    if (wr_kdf_open(L"PBKDF2_SHA1", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *pw = wr_mkbuf("pw", 2), *key, *d = wr_mkbuf("data", 4), *o = (void *)1; kdf_key(prov, pw, &key);
    EXPECT_HR(wr_encrypt(key, d, NULL, &o), HR_E_NOINTERFACE);
    EXPECT_HR(wr_decrypt(key, d, NULL, &o), HR_E_NOINTERFACE);
    void *e = wr_engine();
    EXPECT_HR(VF(e, EN_Sign, void *, void *, void **)(e, key, d, &o), HR_E_NOINTERFACE);
    wr_release(pw); wr_release(key); wr_release(d); wr_release(prov);
}
TEST(winrt_kdf_sp800108_layout_note) {
    WR_NEED(); void *ps = wr_cls_statics(CLS_KDFPARAMS); if (!ps) return;
    for (size_t i = 0; i < sizeof wr_sp800108_vecs / sizeof *wr_sp800108_vecs; i++) {
        const struct wr_kk *v = &wr_sp800108_vecs[i];
        void *prov = NULL; if (wr_kdf_open(v->alg, &prov) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } CHECK(!"open"); continue; }
        void *kb = wr_mkbuf_hex(v->key), *l = wr_mkbuf_hex(v->label), *c = wr_mkbuf_hex(v->ctx), *key = NULL, *par = NULL, *o1 = NULL, *o2 = NULL;
        HRESULT h1 = kdf_key(prov, kb, &key), h2 = p_sp800108(ps, l, c, &par), h3 = (key && par) ? derive(key, par, v->dklen, &o1) : E_FAIL;
        t_check(h1 == S_OK && h2 == S_OK && h3 == S_OK && wr_buf_len(o1) == v->dklen, __FILE__, __LINE__, "SP800-108 derive", "%ls len %u hr 0x%08lx", v->alg, v->dklen, (unsigned long)h3);
        if (h3 == S_OK) {
            derive(key, par, v->dklen, &o2);
            const BYTE *a, *b; UINT32 la, lb; CHECK(wr_buf_get(o1, &a, &la) && wr_buf_get(o2, &b, &lb) && la == lb && !memcmp(a, b, la));
            int w = wr_buf_is_hex(o1, v->dk_with_l), wo = wr_buf_is_hex(o1, v->dk_without_l);
            /* the PRF input is counter||label||0x00||context||[L], with L the output length in bits as a 32-bit big-endian value */
            t_check(w && !wo, __FILE__, __LINE__, "SP800-108 PRF input layout", "%ls len %u with_L %d without_L %d", v->alg, v->dklen, w, wo);
        }
        wr_release(prov); wr_release(kb); wr_release(l); wr_release(c); wr_release(key); wr_release(par); wr_release(o1); wr_release(o2);
    }
    wr_release(ps);
}

/* ---- DataProtectionProvider (async) -------------------------------------------------------------------------------- */
static int wait_async(void *op, int *status, HRESULT *err) {
    void *info = NULL; *status = -1; *err = S_OK;
    if (FAILED(wr_qi(op, &k_iid_asyncinfo, &info))) return 0;
    DWORD t0 = GetTickCount();
    for (;;) {
        int st = 0; if (FAILED(VF(info, 7, int *)(info, &st))) break;
        *status = st;
        if (st != 0) { VF(info, 8, HRESULT *)(info, err); wr_release(info); return 1; }
        if (GetTickCount() - t0 > 5000) break;
        Sleep(10);
    }
    wr_release(info); return 0;
}
static void *dp_provider(const WCHAR *desc) {
    void *f = wr_factory_iid(CLS_DATAPROT, &WR_IID_IDataProtectionProviderFactory); if (!f) return NULL;
    void *p = NULL; HSTRING h = wr_hs(desc);
    HRESULT hr = VF(f, 6, HSTRING, void **)(f, h, &p);
    wr_hsfree(h); wr_release(f);
    t_check(hr == S_OK, __FILE__, __LINE__, "CreateOverloadExplicit", "%ls hr 0x%08lx", desc, (unsigned long)hr);
    if (hr != S_OK) return NULL;
    return p;
}
static HRESULT dp_run(void *prov, int slot, void *in, void **out, int *status, HRESULT *err) {
    void *op = NULL; *out = NULL;
    HRESULT hr = VF(prov, slot, void *, void **)(prov, in, &op);
    if (hr != S_OK) return hr;
    if (!wait_async(op, status, err)) { wr_release(op); return HRESULT_FROM_WIN32(ERROR_TIMEOUT); }
    if (*status == 1) { hr = VF(op, 8, void **)(op, out); }       /* IAsyncOperation<IBuffer>::GetResults */
    wr_release(op); return hr;
}
TEST(winrt_dp_create_descriptor_invalid) {
    WR_NEED(); void *f = wr_factory_iid(CLS_DATAPROT, &WR_IID_IDataProtectionProviderFactory); if (!f) return;
    void *p = (void *)1;
    EXPECT_HR(VF(f, 6, HSTRING, void **)(f, NULL, &p), HR_E_INVALIDARG); CHECK(p == NULL);
    p = (void *)1;
    HSTRING bad = wr_hs(L"NOSUCHRULE=x"); HRESULT hr = VF(f, 6, HSTRING, void **)(f, bad, &p);
    EXPECT_HR(hr, 0xc0000225); CHECK(p == NULL);
    wr_hsfree(bad);
    wr_release(f);
}
TEST(winrt_dp_create_descriptor_ok) {
    WR_NEED(); void *p = dp_provider(L"LOCAL=user"); if (!p) { if (!t_is_wine()) CHECK(!"provider"); return; }
    void *u = NULL; EXPECT_HR(wr_qi(p, &k_iid_dpprovider, &u), S_OK); wr_release(u);
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(p, &n), S_OK);
    CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.DataProtection.DataProtectionProvider")); wr_hsfree(n);
    wr_release(p);
}
TEST(winrt_dp_protect_unprotect_roundtrip_local_user) {
    WR_NEED(); void *p = dp_provider(L"LOCAL=user"); if (!p) { if (!t_is_wine()) CHECK(!"provider"); return; }
    void *in = wr_mkbuf("dp round trip payload", 21), *blob = NULL, *back = NULL; int st; HRESULT err;
    HRESULT hr = dp_run(p, 6, in, &blob, &st, &err);
    if (hr != S_OK || st != 1) { t_check(0, __FILE__, __LINE__, "ProtectAsync(LOCAL=user)", "hr 0x%08lx status %d error 0x%08lx", (unsigned long)hr, st, (unsigned long)err); wr_release(p); wr_release(in); return; }
    CHECK(wr_buf_len(blob) > 21);
    const BYTE *b; UINT32 n; if (wr_buf_get(blob, &b, &n)) CHECK(b[0] == 0x30);               /* DER SEQUENCE (CMS) */
    hr = dp_run(p, 7, blob, &back, &st, &err);
    t_check(hr == S_OK && st == 1 && wr_buf_is(back, "dp round trip payload", 21), __FILE__, __LINE__, "UnprotectAsync", "hr 0x%08lx status %d err 0x%08lx", (unsigned long)hr, st, (unsigned long)err);
    wr_release(p); wr_release(in); wr_release(blob); wr_release(back);
}
TEST(winrt_dp_unprotect_without_descriptor) {
    /* the default-constructed provider can unprotect blobs made by a descriptor-bound provider */
    WR_NEED(); void *p = dp_provider(L"LOCAL=user"); if (!p) { if (!t_is_wine()) CHECK(!"provider"); return; }
    void *f = wr_factory(CLS_DATAPROT, 0), *d = NULL; if (!f) return;
    VF(f, 6, void **)(f, &d);
    void *u = NULL; if (d) wr_qi(d, &k_iid_dpprovider, &u);
    void *in = wr_mkbuf("payload-2", 9), *blob = NULL, *back = NULL; int st; HRESULT err;
    if (!t_require(dp_run(p, 6, in, &blob, &st, &err) == S_OK && st == 1, __FILE__, __LINE__, "ProtectAsync(LOCAL=user)")) { wr_release(p); return; }
    if (u) {
        HRESULT hr = dp_run(u, 7, blob, &back, &st, &err);
        t_check(hr == S_OK && st == 1 && wr_buf_is(back, "payload-2", 9), __FILE__, __LINE__, "Unprotect via default provider", "hr 0x%08lx status %d err 0x%08lx", (unsigned long)hr, st, (unsigned long)err);
    } else CHECK(!"default-constructed object exposes IDataProtectionProvider");
    wr_release(u); wr_release(d); wr_release(f); wr_release(p); wr_release(in); wr_release(blob); wr_release(back);
}
TEST(winrt_dp_protect_distinct_each_time) {
    WR_NEED(); void *p = dp_provider(L"LOCAL=user"); if (!p) { if (!t_is_wine()) CHECK(!"provider"); return; }
    void *in = wr_mkbuf("same", 4), *a = NULL, *b = NULL; int st; HRESULT err;
    if (dp_run(p, 6, in, &a, &st, &err) != S_OK || st != 1) { wr_release(p); return; }
    dp_run(p, 6, in, &b, &st, &err);
    const BYTE *pa, *pb; UINT32 la, lb;
    if (wr_buf_get(a, &pa, &la) && wr_buf_get(b, &pb, &lb)) CHECK(la != lb || memcmp(pa, pb, la) != 0);   /* fresh content-encryption key per call */
    wr_release(p); wr_release(in); wr_release(a); wr_release(b);
}
TEST(winrt_dp_null_buffer_arguments) {
    WR_NEED(); void *p = dp_provider(L"LOCAL=user"); if (!p) { if (!t_is_wine()) CHECK(!"provider"); return; }
    void *op = (void *)1;
    EXPECT_HR(VF(p, 6, void *, void **)(p, NULL, &op), HR_E_INVALIDARG); CHECK(op == NULL);
    op = (void *)1;
    EXPECT_HR(VF(p, 7, void *, void **)(p, NULL, &op), HR_E_INVALIDARG); CHECK(op == NULL);
    wr_release(p);
}
TEST(winrt_dp_unprotect_garbage_fails_async) {
    WR_NEED(); void *p = dp_provider(L"LOCAL=user"); if (!p) { if (!t_is_wine()) CHECK(!"provider"); return; }
    void *g = wr_mkbuf("this is not a protected blob", 28), *o = NULL; int st = -1; HRESULT err = S_OK;
    HRESULT hr = dp_run(p, 7, g, &o, &st, &err);
    /* the call is accepted; the operation completes in the Error state (3) with a decode error */
    EXPECT_HR(hr, S_OK); EXPECT_EQ(st, 3); EXPECT_HR(err, 0x8009310b); CHECK(o == NULL);
    wr_release(p); wr_release(g); wr_release(o);
}
TEST(winrt_dp_async_object_interfaces) {
    WR_NEED(); void *p = dp_provider(L"LOCAL=user"); if (!p) { if (!t_is_wine()) CHECK(!"provider"); return; }
    void *in = wr_mkbuf("x", 1), *op = NULL;
    EXPECT_HR(VF(p, 6, void *, void **)(p, in, &op), S_OK);
    if (op) {
        void *u = NULL;
        EXPECT_HR(wr_qi(op, &k_iid_asyncop_buffer, &u), S_OK); wr_release(u);
        EXPECT_HR(wr_qi(op, &k_iid_asyncinfo, &u), S_OK); wr_release(u);
        HSTRING n = NULL; EXPECT_HR(wr_getclassname(op, &n), S_OK);
        CHECK(wr_hs_eq(n, L"Windows.Foundation.IAsyncOperation`1<Windows.Storage.Streams.IBuffer>")); wr_hsfree(n);
        int st; HRESULT err; wait_async(op, &st, &err); EXPECT_EQ(st, 1);
        wr_release(op);
    }
    wr_release(p); wr_release(in);
}
TEST(winrt_dp_machine_descriptor_creation) {
    WR_NEED(); void *p = dp_provider(L"LOCAL=machine");
    if (!t_require(p != NULL, __FILE__, __LINE__, "LOCAL=machine descriptor")) return;
    void *in = wr_mkbuf("m", 1), *blob = NULL; int st; HRESULT err;
    HRESULT hr = dp_run(p, 6, in, &blob, &st, &err);
    EXPECT_HR(hr, S_OK); EXPECT_EQ(st, 1); EXPECT_HR(err, S_OK); CHECK(blob != NULL);
    wr_release(p); wr_release(in); wr_release(blob);
}
TEST(winrt_dp_default_provider_cannot_protect) {
    WR_NEED(); void *f = wr_factory(CLS_DATAPROT, 0); if (!f) return;
    void *d = NULL; VF(f, 6, void **)(f, &d); void *u = NULL; if (d) wr_qi(d, &k_iid_dpprovider, &u);
    if (u) {
        void *in = wr_mkbuf("x", 1), *o = NULL; int st = -1; HRESULT err = S_OK;
        HRESULT hr = dp_run(u, 6, in, &o, &st, &err);
        /* the call is accepted; the operation completes in the Error state (3) with an invalid-handle error */
        EXPECT_HR(hr, S_OK); EXPECT_EQ(st, 3); EXPECT_HR(err, 0x80090026); CHECK(o == NULL); wr_release(in); wr_release(o);
    }
    wr_release(u); wr_release(d); wr_release(f);
}

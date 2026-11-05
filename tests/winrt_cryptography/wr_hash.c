/* HashAlgorithmProvider / CryptographicHash / HashAlgorithmNames and MacAlgorithmProvider (HMAC, CMAC). */
#include "wr.h"
#include "wr_vec_hash.h"

#define HR_E_POINTER 0x80004003u
#define HR_E_NOINTERFACE 0x80004002u

static const struct { const WCHAR *alg; UINT32 len; } k_hlen[] = {
    { L"MD5", 16 }, { L"SHA1", 20 }, { L"SHA256", 32 }, { L"SHA384", 48 }, { L"SHA512", 64 },
};
#define NH (sizeof k_hlen / sizeof *k_hlen)

static HRESULT h_name(void *p, HSTRING *s) { *s = NULL; return VF(p, 6, HSTRING *)(p, s); }
static HRESULT h_len(void *p, UINT32 *n) { *n = 0xfefefefe; return VF(p, 7, UINT32 *)(p, n); }
static HRESULT h_create(void *p, void **h) { *h = NULL; return VF(p, 9, void **)(p, h); }
static HRESULT h_append(void *h, void *b) { return VF(h, 6, void *)(h, b); }
static HRESULT h_final(void *h, void **o) { *o = NULL; return VF(h, 7, void **)(h, o); }

/* ---- HashAlgorithmNames ------------------------------------------------------------------------- */
static int collect_names(void *st, int first, int count, const WCHAR **want, int nwant, char *seen) {
    int ok = 1;
    for (int i = 0; i < count; i++) {
        HSTRING h = NULL; HRESULT hr = VF(st, first + i, HSTRING *)(st, &h);
        if (hr != S_OK || !h) { ok = 0; }
        else {
            int found = 0;
            for (int k = 0; k < nwant; k++) if (wr_hs_eq(h, want[k])) { found = 1; seen[k]++; }
            if (!found) ok = 0;
        }
        wr_hsfree(h);
    }
    for (int k = 0; k < nwant; k++) if (seen[k] != 1) ok = 0;
    return ok;
}
TEST(winrt_hash_names_values) {
    WR_NEED(); void *s = wr_cls_statics(CLS_HASHNAMES); if (!s) return;
    const WCHAR *w[] = { L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512" }; char seen[5] = { 0 };
    CHECK(collect_names(s, 6, 5, w, 5, seen));
    wr_release(s);
}
TEST(winrt_hash_names_order_md5_to_sha512) {
    /* property order in the interface: Md5, Sha1, Sha256, Sha384, Sha512 */
    WR_NEED(); void *s = wr_cls_statics(CLS_HASHNAMES); if (!s) return;
    const WCHAR *w[] = { L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512" };
    for (int i = 0; i < 5; i++) {
        HSTRING h = NULL; EXPECT_HR(VF(s, 6 + i, HSTRING *)(s, &h), S_OK);
        t_check(wr_hs_eq(h, w[i]), __FILE__, __LINE__, "name order", "slot %d", 6 + i);
        wr_hsfree(h);
    }
    wr_release(s);
}
TEST(winrt_hash_names_fresh_string_each_call) {
    WR_NEED(); void *s = wr_cls_statics(CLS_HASHNAMES); if (!s) return;
    HSTRING a = NULL, b = NULL;
    EXPECT_HR(VF(s, 8, HSTRING *)(s, &a), S_OK); EXPECT_HR(VF(s, 8, HSTRING *)(s, &b), S_OK);
    CHECK(a && b && wr_hs_eq(a, L"SHA256") && wr_hs_eq(b, L"SHA256"));
    wr_hsfree(a); wr_hsfree(b); wr_release(s);
}
TEST(winrt_hash_names_open_every_name) {
    WR_NEED(); void *s = wr_cls_statics(CLS_HASHNAMES); if (!s) return;
    for (int i = 0; i < 5; i++) {
        HSTRING h = NULL; VF(s, 6 + i, HSTRING *)(s, &h);
        void *p = NULL; void *st = wr_cls_statics(CLS_HASHPROV);
        HRESULT hr = st ? VF(st, 6, HSTRING, void **)(st, h, &p) : E_FAIL;
        t_check(hr == S_OK && p, __FILE__, __LINE__, "OpenAlgorithm(name from HashAlgorithmNames)", "slot %d hr 0x%08lx", i, (unsigned long)hr);
        wr_release(p); wr_release(st); wr_hsfree(h);
    }
    wr_release(s);
}

/* ---- OpenAlgorithm -------------------------------------------------------------------------------- */
TEST(winrt_hash_open_supported) {
    WR_NEED();
    for (size_t i = 0; i < NH; i++) {
        void *p = NULL; HRESULT hr = wr_hash_open(k_hlen[i].alg, &p);
        if (FAILED(hr) && t_is_wine()) { t_skip("not available under the emulator"); return; }
        t_check(hr == S_OK && p, __FILE__, __LINE__, "OpenAlgorithm", "%ls hr 0x%08lx", k_hlen[i].alg, (unsigned long)hr);
        wr_release(p);
    }
}
TEST(winrt_hash_algorithm_name_roundtrip) {
    WR_NEED();
    for (size_t i = 0; i < NH; i++) {
        void *p = NULL; if (wr_hash_open(k_hlen[i].alg, &p) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } CHECK(!"open"); continue; }
        HSTRING n; EXPECT_HR(h_name(p, &n), S_OK);
        t_check(wr_hs_eq(n, k_hlen[i].alg), __FILE__, __LINE__, "AlgorithmName", "%ls", k_hlen[i].alg);
        wr_hsfree(n); wr_release(p);
    }
}
TEST(winrt_hash_length_property) {
    WR_NEED();
    for (size_t i = 0; i < NH; i++) {
        void *p = NULL; if (wr_hash_open(k_hlen[i].alg, &p) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } CHECK(!"open"); continue; }
        UINT32 n; EXPECT_HR(h_len(p, &n), S_OK);
        t_check(n == k_hlen[i].len, __FILE__, __LINE__, "HashLength", "%ls got %u want %u", k_hlen[i].alg, n, k_hlen[i].len);
        wr_release(p);
    }
}
TEST(winrt_hash_open_invalid_names) {
    WR_NEED();
    static const WCHAR *bad[] = { L"", L"NOSUCHHASH", L"SHA-256-X", L"AES", L"RSA", L"HMAC_SHA256", L"SHA2560", L"PBKDF2_SHA1", L"RNG" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *p = (void *)1; HSTRING h = wr_hs(bad[i]); void *st = wr_cls_statics(CLS_HASHPROV); if (!st) return;
        HRESULT hr = VF(st, 6, HSTRING, void **)(st, h, &p);
        t_check(FAILED(hr) && p == NULL, __FILE__, __LINE__, "OpenAlgorithm(bad)", "'%ls' hr 0x%08lx p %p", bad[i], (unsigned long)hr, p);
        if (SUCCEEDED(hr)) wr_release(p);
        wr_hsfree(h); wr_release(st);
    }
}
TEST(winrt_hash_open_null_string) {
    WR_NEED(); void *st = wr_cls_statics(CLS_HASHPROV); if (!st) return;
    void *p = (void *)1; HRESULT hr = VF(st, 6, HSTRING, void **)(st, NULL, &p);
    CHECK(FAILED(hr)); CHECK(p == NULL);
    t_note("OpenAlgorithm(NULL) -> 0x%08lx", (unsigned long)hr);
    wr_release(st);
}
TEST(winrt_hash_open_case_and_alias_forms) {
    WR_NEED();
    static const WCHAR *forms[] = { L"sha256", L"Sha256", L"SHA-256", L"SHA_256", L"sha1", L"md5" };
    for (size_t i = 0; i < sizeof forms / sizeof *forms; i++) {
        void *p = NULL; HRESULT hr = wr_hash_open(forms[i], &p);
        if (SUCCEEDED(hr)) { HSTRING n; UINT32 l = 0; h_name(p, &n); h_len(p, &l); UINT32 nl; const WCHAR *r = wr_raw(n, &nl);
            t_note("%ls accepted: AlgorithmName='%ls' HashLength=%u", forms[i], r, l); wr_hsfree(n); wr_release(p); }
        else t_note("%ls rejected 0x%08lx", forms[i], (unsigned long)hr);
    }
}
TEST(winrt_hash_provider_interfaces) {
    WR_NEED(); void *p = NULL;
    if (wr_hash_open(L"SHA256", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *o = NULL;
    EXPECT_HR(wr_qi(p, &WR_IID_IHashAlgorithmProvider, &o), S_OK); wr_release(o);
    EXPECT_HR(wr_qi(p, &WR_IID_IAgileObject, &o), S_OK); wr_release(o);
    EXPECT_HR(wr_qi(p, &WR_IID_IMarshal, &o), S_OK); wr_release(o);
    o = (void *)1; EXPECT_HR(wr_qi(p, &WR_IID_IBuffer, &o), HR_E_NOINTERFACE); CHECK(o == NULL);
    wr_release(p);
}
TEST(winrt_hash_provider_getiids) {
    WR_NEED(); void *p = NULL;
    if (wr_hash_open(L"SHA256", &p) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    ULONG n = 0; GUID *ids = NULL; EXPECT_HR(wr_getiids(p, &n, &ids), S_OK);
    CHECK(n >= 1 && ids && IsEqualGUID(&ids[0], &WR_IID_IHashAlgorithmProvider));
    wr_cofree(ids); wr_release(p);
}
TEST(winrt_hash_provider_independent_instances) {
    WR_NEED(); void *a = NULL, *b = NULL;
    if (wr_hash_open(L"SHA256", &a) != S_OK || wr_hash_open(L"SHA512", &b) != S_OK) { if (!t_is_wine()) CHECK(!"open"); wr_release(a); wr_release(b); return; }
    CHECK(a != b);
    UINT32 la, lb; h_len(a, &la); h_len(b, &lb); EXPECT_EQ(la, 32); EXPECT_EQ(lb, 64);
    wr_release(a); wr_release(b);
}

/* ---- HashData vectors ------------------------------------------------------------------------------ */
TEST(winrt_hash_hashdata_vectors) {
    WR_NEED(); void *prov = NULL; const WCHAR *cur = NULL;
    for (size_t i = 0; i < sizeof wr_hash_vecs / sizeof *wr_hash_vecs; i++) {
        const struct wr_hv *v = &wr_hash_vecs[i];
        if (v->alg != cur) { wr_release(prov); prov = NULL; cur = v->alg; if (wr_hash_open(cur, &prov) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } CHECK(!"open"); return; } }
        void *in = wr_mkbuf_hex(v->msg_hex), *out = NULL;
        HRESULT hr = wr_hash_data(prov, in, &out);
        t_check(hr == S_OK && wr_buf_is_hex(out, v->digest_hex), __FILE__, __LINE__, "HashData", "%ls vector %zu hr 0x%08lx", v->alg, i, (unsigned long)hr);
        wr_release(in); wr_release(out);
    }
    wr_release(prov);
}
TEST(winrt_hash_hashdata_output_properties) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *in = wr_mkbuf("abc", 3), *out = NULL;
    EXPECT_HR(wr_hash_data(prov, in, &out), S_OK);
    EXPECT_EQ(wr_buf_len(out), 32);
    UINT32 cap = 0; VF(out, 6, UINT32 *)(out, &cap); EXPECT_EQ(cap, 32);
    CHECK(wr_buf_is_hex(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    void *o2 = NULL; wr_hash_data(prov, in, &o2); CHECK(o2 != out);
    wr_release(in); wr_release(out); wr_release(o2); wr_release(prov);
}
TEST(winrt_hash_hashdata_known_million_a) {
    WR_NEED();
    static const struct { const WCHAR *a; const char *hex; } v[] = {
        { L"MD5", "7707d6ae4e027c70eea2a935c2296f21" }, { L"SHA1", "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
        { L"SHA256", "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" },
        { L"SHA384", "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985" },
        { L"SHA512", "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b" },
    };
    BYTE *m = malloc(1000000); if (!m) return; memset(m, 'a', 1000000);
    void *in = wr_mkbuf(m, 1000000);
    for (int i = 0; i < 5; i++) {
        void *prov = NULL, *out = NULL;
        if (wr_hash_open(v[i].a, &prov) != S_OK) { if (t_is_wine()) { t_skip("emulator"); break; } CHECK(!"open"); continue; }
        HRESULT hr = wr_hash_data(prov, in, &out);
        t_check(hr == S_OK && wr_buf_is_hex(out, v[i].hex), __FILE__, __LINE__, "million a", "%ls hr 0x%08lx", v[i].a, (unsigned long)hr);
        wr_release(out); wr_release(prov);
    }
    wr_release(in); free(m);
}
TEST(winrt_hash_hashdata_empty_buffer) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *in = wr_mkbuf(NULL, 0), *out = NULL;
    EXPECT_HR(wr_hash_data(prov, in, &out), S_OK);
    CHECK(wr_buf_is_hex(out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    wr_release(in); wr_release(out); wr_release(prov);
}
TEST(winrt_hash_hashdata_null_buffer) {
    /* a NULL IBuffer is treated as an empty message by the helper that unwraps buffers */
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *out = (void *)1; HRESULT hr = wr_hash_data(prov, NULL, &out);
    t_note("HashData(NULL) -> 0x%08lx", (unsigned long)hr);
    if (hr == S_OK) CHECK(wr_buf_is_hex(out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    else CHECK(out == NULL);
    wr_release(out == (void *)1 ? NULL : out); wr_release(prov);
}
TEST(winrt_hash_hashdata_respects_buffer_length) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA1", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *in = wr_mkbuf("abcdef", 6), *out = NULL;
    VF(in, 8, UINT32)(in, 3);
    EXPECT_HR(wr_hash_data(prov, in, &out), S_OK);
    CHECK(wr_buf_is_hex(out, "a9993e364706816aba3e25717850c26c9cd0d89d"));   /* SHA1("abc") */
    wr_release(in); wr_release(out); wr_release(prov);
}
TEST(winrt_hash_hashdata_does_not_modify_input) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    BYTE d[40]; for (int i = 0; i < 40; i++) d[i] = (BYTE)i;
    void *in = wr_mkbuf(d, 40), *out = NULL; wr_hash_data(prov, in, &out);
    CHECK(wr_buf_is(in, d, 40));
    wr_release(in); wr_release(out); wr_release(prov);
}
TEST(winrt_hash_hashdata_all_lengths_vs_incremental) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    BYTE d[300]; for (int i = 0; i < 300; i++) d[i] = (BYTE)(i * 13 + 1);
    for (UINT32 n = 0; n <= 300; n += 11) {
        void *in = wr_mkbuf(d, n), *o1 = NULL, *o2 = NULL, *h = NULL;
        wr_hash_data(prov, in, &o1);
        h_create(prov, &h); h_append(h, in); h_final(h, &o2);
        const BYTE *p1, *p2; UINT32 l1, l2;
        int ok = wr_buf_get(o1, &p1, &l1) && wr_buf_get(o2, &p2, &l2) && l1 == l2 && !memcmp(p1, p2, l1);
        t_check(ok, __FILE__, __LINE__, "HashData == Append+GetValueAndReset", "len %u", n);
        wr_release(in); wr_release(o1); wr_release(o2); wr_release(h);
    }
    wr_release(prov);
}

/* ---- CryptographicHash ------------------------------------------------------------------------------ */
TEST(winrt_hash_object_basic) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *h = NULL; EXPECT_HR(h_create(prov, &h), S_OK); if (!h) return;
    void *b = wr_mkbuf("abc", 3), *o = NULL;
    EXPECT_HR(h_append(h, b), S_OK);
    EXPECT_HR(h_final(h, &o), S_OK);
    CHECK(wr_buf_is_hex(o, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    wr_release(b); wr_release(o); wr_release(h); wr_release(prov);
}
TEST(winrt_hash_object_interfaces) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *h = NULL; h_create(prov, &h); if (!h) return;
    void *o = NULL;
    EXPECT_HR(wr_qi(h, &WR_IID_ICryptographicHash, &o), S_OK); CHECK(o != NULL); wr_release(o);
    EXPECT_HR(wr_qi(h, &WR_IID_IAgileObject, &o), S_OK); wr_release(o);
    o = (void *)1; EXPECT_HR(wr_qi(h, &WR_IID_IHashAlgorithmProvider, &o), HR_E_NOINTERFACE); CHECK(o == NULL);
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(h, &n), S_OK);
    CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.CryptographicHash")); wr_hsfree(n);
    wr_release(h); wr_release(prov);
}
TEST(winrt_hash_object_incremental_split_points) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    const char *msg = "The quick brown fox jumps over the lazy dog";
    UINT32 n = (UINT32)strlen(msg);
    for (UINT32 cut = 0; cut <= n; cut++) {
        void *h = NULL; h_create(prov, &h);
        void *a = wr_mkbuf(msg, cut), *b = wr_mkbuf(msg + cut, n - cut), *o = NULL;
        h_append(h, a); h_append(h, b); h_final(h, &o);
        t_check(wr_buf_is_hex(o, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"), __FILE__, __LINE__, "split hash", "cut %u", cut);
        wr_release(a); wr_release(b); wr_release(o); wr_release(h);
    }
    wr_release(prov);
}
TEST(winrt_hash_object_byte_by_byte) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA1", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *h = NULL; h_create(prov, &h); if (!h) return;
    const char *m = "abc";
    for (int i = 0; i < 3; i++) { void *b = wr_mkbuf(m + i, 1); h_append(h, b); wr_release(b); }
    void *o = NULL; h_final(h, &o);
    CHECK(wr_buf_is_hex(o, "a9993e364706816aba3e25717850c26c9cd0d89d"));
    wr_release(o); wr_release(h); wr_release(prov);
}
TEST(winrt_hash_object_get_value_resets) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *h = NULL; h_create(prov, &h); if (!h) return;
    void *b = wr_mkbuf("abc", 3), *o1 = NULL, *o2 = NULL, *o3 = NULL;
    h_append(h, b); h_final(h, &o1);
    EXPECT_HR(h_final(h, &o2), S_OK);                       /* state was reset: digest of the empty message */
    CHECK(wr_buf_is_hex(o2, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    h_append(h, b); h_final(h, &o3);                         /* usable again after reset */
    CHECK(wr_buf_is_hex(o3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    wr_release(b); wr_release(o1); wr_release(o2); wr_release(o3); wr_release(h); wr_release(prov);
}
TEST(winrt_hash_object_final_without_append_is_empty_digest) {
    WR_NEED(); static const struct { const WCHAR *a; const char *hex; } v[] = {
        { L"MD5", "d41d8cd98f00b204e9800998ecf8427e" }, { L"SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        { L"SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { L"SHA384", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
        { L"SHA512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" } };
    for (int i = 0; i < 5; i++) {
        void *prov = NULL; if (wr_hash_open(v[i].a, &prov) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } continue; }
        void *h = NULL, *o = NULL; h_create(prov, &h);
        EXPECT_HR(h_final(h, &o), S_OK);
        t_check(wr_buf_is_hex(o, v[i].hex), __FILE__, __LINE__, "empty digest", "%ls", v[i].a);
        wr_release(o); wr_release(h); wr_release(prov);
    }
}
TEST(winrt_hash_object_independent_state) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *h1 = NULL, *h2 = NULL; h_create(prov, &h1); h_create(prov, &h2);
    CHECK(h1 != h2);
    void *a = wr_mkbuf("a", 1), *b = wr_mkbuf("b", 1), *o1 = NULL, *o2 = NULL, *ref = NULL, *refb = NULL;
    h_append(h1, a); h_append(h2, b); h_append(h1, a);
    h_final(h2, &o2); h_final(h1, &o1);
    void *aa = wr_mkbuf("aa", 2); wr_hash_data(prov, aa, &ref); wr_hash_data(prov, b, &refb);
    CHECK(wr_buf_is_hex(o1, "961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506"));
    CHECK(wr_buf_is_hex(o2, "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"));
    wr_release(a); wr_release(b); wr_release(aa); wr_release(o1); wr_release(o2); wr_release(ref); wr_release(refb);
    wr_release(h1); wr_release(h2); wr_release(prov);
}
TEST(winrt_hash_object_outlives_provider) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *h = NULL; h_create(prov, &h); wr_release(prov);
    void *b = wr_mkbuf("abc", 3), *o = NULL;
    EXPECT_HR(h_append(h, b), S_OK); EXPECT_HR(h_final(h, &o), S_OK);
    CHECK(wr_buf_is_hex(o, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    wr_release(b); wr_release(o); wr_release(h);
}
TEST(winrt_hash_object_large_incremental) {
    WR_NEED(); void *prov = NULL;
    if (wr_hash_open(L"SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    BYTE blk[1000]; memset(blk, 'a', sizeof blk);
    void *b = wr_mkbuf(blk, 1000), *h = NULL, *o = NULL; h_create(prov, &h);
    for (int i = 0; i < 1000; i++) h_append(h, b);
    h_final(h, &o);
    CHECK(wr_buf_is_hex(o, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    wr_release(b); wr_release(o); wr_release(h); wr_release(prov);
}
TEST(winrt_hash_object_all_algorithms_incremental) {
    WR_NEED();
    for (size_t i = 0; i < sizeof wr_hash_vecs / sizeof *wr_hash_vecs; i += 4) {
        const struct wr_hv *v = &wr_hash_vecs[i];
        void *prov = NULL; if (wr_hash_open(v->alg, &prov) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } continue; }
        void *h = NULL; h_create(prov, &h);
        BYTE m[2048]; UINT32 n = wr_unhex(v->msg_hex, m);
        for (UINT32 k = 0; k < n; k += 5) { UINT32 c = n - k < 5 ? n - k : 5; void *b = wr_mkbuf(m + k, c); h_append(h, b); wr_release(b); }
        void *o = NULL; h_final(h, &o);
        t_check(wr_buf_is_hex(o, v->digest_hex), __FILE__, __LINE__, "chunked digest", "%ls vector %zu", v->alg, i);
        wr_release(o); wr_release(h); wr_release(prov);
    }
}

/* ---- MacAlgorithmNames / provider / HMAC --------------------------------------------------------------- */
static const struct { const WCHAR *alg; UINT32 len; } k_mlen[] = {
    { L"HMAC_MD5", 16 }, { L"HMAC_SHA1", 20 }, { L"HMAC_SHA256", 32 }, { L"HMAC_SHA384", 48 }, { L"HMAC_SHA512", 64 },
};
TEST(winrt_mac_names_values) {
    WR_NEED(); void *s = wr_cls_statics(CLS_MACNAMES); if (!s) return;
    const WCHAR *w[] = { L"HMAC_MD5", L"HMAC_SHA1", L"HMAC_SHA256", L"HMAC_SHA384", L"HMAC_SHA512", L"AES_CMAC" }; char seen[6] = { 0 };
    CHECK(collect_names(s, 6, 6, w, 6, seen));
    wr_release(s);
}
TEST(winrt_mac_open_and_properties) {
    WR_NEED();
    for (size_t i = 0; i < 5; i++) {
        void *p = NULL; HRESULT hr = wr_mac_open(k_mlen[i].alg, &p);
        if (FAILED(hr) && t_is_wine()) { t_skip("emulator"); return; }
        t_check(hr == S_OK && p, __FILE__, __LINE__, "MacAlgorithmProvider.OpenAlgorithm", "%ls hr 0x%08lx", k_mlen[i].alg, (unsigned long)hr);
        if (!p) continue;
        HSTRING n = NULL; UINT32 l = 0;
        EXPECT_HR(VF(p, 6, HSTRING *)(p, &n), S_OK); CHECK(wr_hs_eq(n, k_mlen[i].alg)); wr_hsfree(n);
        EXPECT_HR(VF(p, 7, UINT32 *)(p, &l), S_OK); t_check(l == k_mlen[i].len, __FILE__, __LINE__, "MacLength", "%ls got %u", k_mlen[i].alg, l);
        wr_release(p);
    }
}
TEST(winrt_mac_open_invalid) {
    WR_NEED();
    static const WCHAR *bad[] = { L"", L"HMAC_NOSUCH", L"AES_CBC", L"HMAC_SHA256 ", L"HMAC_SHA2560" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *p = (void *)1; HSTRING h = wr_hs(bad[i]); void *st = wr_cls_statics(CLS_MACPROV); if (!st) return;
        HRESULT hr = VF(st, 6, HSTRING, void **)(st, h, &p);
        t_check(FAILED(hr) && p == NULL, __FILE__, __LINE__, "Mac OpenAlgorithm(bad)", "'%ls' hr 0x%08lx", bad[i], (unsigned long)hr);
        if (SUCCEEDED(hr)) wr_release(p);
        wr_hsfree(h); wr_release(st);
    }
}
static HRESULT mac_key(void *p, void *kb, void **k) { *k = NULL; return VF(p, 8, void *, void **)(p, kb, k); }
static HRESULT eng_sign(void *key, void *data, void **sig) {
    void *e = wr_engine(); *sig = NULL; if (!e) return E_FAIL;
    return VF(e, EN_Sign, void *, void *, void **)(e, key, data, sig);
}
static HRESULT eng_verify(void *key, void *data, void *sig, BYTE *ok) {
    void *e = wr_engine(); *ok = 0x5a; if (!e) return E_FAIL;
    return VF(e, EN_VerifySignature, void *, void *, void *, BYTE *)(e, key, data, sig, ok);
}
TEST(winrt_mac_hmac_vectors) {
    WR_NEED(); void *prov = NULL; const WCHAR *cur = NULL;
    for (size_t i = 0; i < sizeof wr_mac_vecs / sizeof *wr_mac_vecs; i++) {
        const struct wr_mv *v = &wr_mac_vecs[i];
        if (v->alg != cur) { wr_release(prov); prov = NULL; cur = v->alg; if (wr_mac_open(cur, &prov) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } CHECK(!"open"); return; } }
        void *kb = wr_mkbuf_hex(v->key_hex), *msg = wr_mkbuf_hex(v->msg_hex), *key = NULL, *sig = NULL;
        HRESULT hr = mac_key(prov, kb, &key), h2 = key ? eng_sign(key, msg, &sig) : E_FAIL;
        t_check(hr == S_OK && h2 == S_OK && wr_buf_is_hex(sig, v->mac_hex), __FILE__, __LINE__, "HMAC", "%ls vector %zu hr 0x%08lx/0x%08lx", v->alg, i, (unsigned long)hr, (unsigned long)h2);
        wr_release(kb); wr_release(msg); wr_release(key); wr_release(sig);
    }
    wr_release(prov);
}
TEST(winrt_mac_hmac_rfc4231_case1_and_2) {
    WR_NEED(); void *prov = NULL;
    if (wr_mac_open(L"HMAC_SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *k = wr_mkbuf_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), *m = wr_mkbuf("Hi There", 8), *key, *sig;
    mac_key(prov, k, &key); EXPECT_HR(eng_sign(key, m, &sig), S_OK);
    CHECK(wr_buf_is_hex(sig, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    wr_release(k); wr_release(m); wr_release(key); wr_release(sig);
    k = wr_mkbuf("Jefe", 4); m = wr_mkbuf("what do ya want for nothing?", 28);
    mac_key(prov, k, &key); EXPECT_HR(eng_sign(key, m, &sig), S_OK);
    CHECK(wr_buf_is_hex(sig, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    wr_release(k); wr_release(m); wr_release(key); wr_release(sig); wr_release(prov);
}
TEST(winrt_mac_verify_signature) {
    WR_NEED(); void *prov = NULL;
    if (wr_mac_open(L"HMAC_SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *k = wr_mkbuf("Jefe", 4), *m = wr_mkbuf("what do ya want for nothing?", 28), *key = NULL, *sig = NULL;
    mac_key(prov, k, &key); eng_sign(key, m, &sig);
    BYTE ok;
    EXPECT_HR(eng_verify(key, m, sig, &ok), S_OK); EXPECT_EQ(ok, 1);
    void *bad = wr_mkbuf_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3844");
    EXPECT_HR(eng_verify(key, m, bad, &ok), S_OK); EXPECT_EQ(ok, 0);
    void *m2 = wr_mkbuf("what do ya want for nothing!", 28);
    EXPECT_HR(eng_verify(key, m2, sig, &ok), S_OK); EXPECT_EQ(ok, 0);
    wr_release(k); wr_release(m); wr_release(key); wr_release(sig); wr_release(bad); wr_release(m2); wr_release(prov);
}
TEST(winrt_mac_sign_deterministic_and_key_dependent) {
    WR_NEED(); void *prov = NULL;
    if (wr_mac_open(L"HMAC_SHA1", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *k1 = wr_mkbuf("key1", 4), *k2 = wr_mkbuf("key2", 4), *m = wr_mkbuf("msg", 3), *a, *b, *c, *d, *s1, *s2, *s3;
    mac_key(prov, k1, &a); mac_key(prov, k1, &b); mac_key(prov, k2, &c);
    eng_sign(a, m, &s1); eng_sign(b, m, &s2); eng_sign(c, m, &s3);
    BYTE r; void *cs = wr_cbs();
    VF(cs, CB_Compare, void *, void *, BYTE *)(cs, s1, s2, &r); EXPECT_EQ(r, 1);
    VF(cs, CB_Compare, void *, void *, BYTE *)(cs, s1, s3, &r); EXPECT_EQ(r, 0);
    wr_release(k1); wr_release(k2); wr_release(m); wr_release(a); wr_release(b); wr_release(c); wr_release(s1); wr_release(s2); wr_release(s3); wr_release(prov);
}
TEST(winrt_mac_key_object_interfaces) {
    WR_NEED(); void *prov = NULL;
    if (wr_mac_open(L"HMAC_SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *kb = wr_mkbuf("secret", 6), *key = NULL; mac_key(prov, kb, &key); if (!key) return;
    void *o = NULL;
    EXPECT_HR(wr_qi(key, &WR_IID_ICryptographicKey, &o), S_OK); wr_release(o);
    EXPECT_HR(wr_qi(key, &WR_IID_IAgileObject, &o), S_OK); wr_release(o);
    HSTRING n = NULL; EXPECT_HR(wr_getclassname(key, &n), S_OK);
    CHECK(wr_hs_eq(n, L"Windows.Security.Cryptography.Core.MacKey")); wr_hsfree(n);
    UINT32 sz = 0; EXPECT_HR(VF(key, 6, UINT32 *)(key, &sz), S_OK);
    t_note("MAC key KeySize for 6-byte secret: %u", sz);
    wr_release(kb); wr_release(key); wr_release(prov);
}
TEST(winrt_mac_sign_null_arguments) {
    WR_NEED(); void *prov = NULL;
    if (wr_mac_open(L"HMAC_SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    void *kb = wr_mkbuf("secret", 6), *key = NULL, *m = wr_mkbuf("x", 1), *sig = NULL;
    mac_key(prov, kb, &key);
    EXPECT_HR(eng_sign(NULL, m, &sig), HR_E_POINTER);
    EXPECT_HR(eng_sign(key, NULL, &sig), HR_E_POINTER);
    BYTE ok;
    EXPECT_HR(eng_verify(NULL, m, m, &ok), HR_E_POINTER);
    EXPECT_HR(eng_verify(key, NULL, m, &ok), HR_E_POINTER);
    EXPECT_HR(eng_verify(key, m, NULL, &ok), HR_E_POINTER);
    wr_release(kb); wr_release(key); wr_release(m); wr_release(prov);
}
TEST(winrt_mac_create_hash_from_provider) {
    /* IMacAlgorithmProvider2::CreateHash(keyMaterial) yields a keyed incremental hash object */
    WR_NEED(); void *prov = NULL;
    if (wr_mac_open(L"HMAC_SHA256", &prov) != S_OK) { if (!t_is_wine()) CHECK(!"open"); return; }
    ULONG n = 0; GUID *ids = NULL;
    if (wr_getiids(prov, &n, &ids) != S_OK || n != 3) { t_note("MAC provider exposes %lu interfaces", n); wr_cofree(ids); wr_release(prov); return; }
    void *p2 = NULL; HRESULT hr = wr_qi(prov, &ids[2], &p2); wr_cofree(ids);
    EXPECT_HR(hr, S_OK); if (!p2) { wr_release(prov); return; }
    void *kb = wr_mkbuf("Jefe", 4), *h = NULL;
    hr = VF(p2, 6, void *, void **)(p2, kb, &h);
    EXPECT_HR(hr, S_OK);
    if (h) {
        void *a = wr_mkbuf("what do ya want ", 16), *b = wr_mkbuf("for nothing?", 12), *o = NULL;
        h_append(h, a); h_append(h, b); h_final(h, &o);
        CHECK(wr_buf_is_hex(o, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        wr_release(a); wr_release(b); wr_release(o); wr_release(h);
    }
    wr_release(kb); wr_release(p2); wr_release(prov);
}
TEST(winrt_mac_aes_cmac_rfc4493) {
    WR_NEED(); void *prov = NULL;
    if (wr_mac_open(L"AES_CMAC", &prov) != S_OK) { if (t_is_wine()) { t_skip("emulator"); return; } CHECK(!"AES_CMAC open"); return; }
    UINT32 l = 0; VF(prov, 7, UINT32 *)(prov, &l); EXPECT_EQ(l, 16);
    static const struct { const char *msg, *mac; } v[] = {
        { "", "bb1d6929e95937287fa37d129b756746" },
        { "6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c" },
        { "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827" },
        { "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe" },
    };
    void *kb = wr_mkbuf_hex("2b7e151628aed2a6abf7158809cf4f3c"), *key = NULL; mac_key(prov, kb, &key);
    for (int i = 0; key && i < 4; i++) {
        void *m = wr_mkbuf_hex(v[i].msg), *sig = NULL; HRESULT hr = eng_sign(key, m, &sig);
        t_check(hr == S_OK && wr_buf_is_hex(sig, v[i].mac), __FILE__, __LINE__, "AES-CMAC", "vector %d hr 0x%08lx", i, (unsigned long)hr);
        wr_release(m); wr_release(sig);
    }
    wr_release(kb); wr_release(key); wr_release(prov);
}

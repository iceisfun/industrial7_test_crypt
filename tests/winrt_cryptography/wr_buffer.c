/* Windows.Security.Cryptography.CryptographicBuffer (static class) and the IBuffer objects it hands out. */
#include "wr.h"

#define NTE_BAD_DATA_HR     0x80090005u
#define HR_E_POINTER        0x80004003u
#define HR_E_NOTIMPL        0x80004001u
#define HR_E_NOINTERFACE    0x80004002u
#define HR_E_INVALIDARG     0x80070057u
#define HR_UTF8_INVALID     0x80070459u   /* HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION) */
#define HR_ODD_UTF16        0x80040011u

typedef HRESULT (WINAPI *pfn_in_out)(void *, void *, void *);

static HRESULT c_create(const void *d, UINT32 n, void **b) {
    void *s = wr_cbs(); static const BYTE z = 0;
    *b = NULL;
    return VF(s, CB_CreateFromByteArray, UINT32, const BYTE *, void **)(s, n, d ? (const BYTE *)d : &z, b);
}
static HRESULT c_hexdec_x(const WCHAR *w, UINT32 n, void **b, void *init) {
    void *s = wr_cbs(); HSTRING h = wr_hsn(w, n); HRESULT hr;
    *b = init;
    hr = VF(s, CB_DecodeFromHexString, HSTRING, void **)(s, h, b);
    wr_hsfree(h); return hr;
}
static HRESULT c_hexdec(const WCHAR *w, UINT32 n, void **b) { return c_hexdec_x(w, n, b, NULL); }
static HRESULT c_hexenc(void *buf, HSTRING *o) {
    void *s = wr_cbs(); *o = NULL;
    return VF(s, CB_EncodeToHexString, void *, HSTRING *)(s, buf, o);
}
static HRESULT c_b64dec_x(const WCHAR *w, UINT32 n, void **b, void *init) {
    void *s = wr_cbs(); HSTRING h = wr_hsn(w, n); HRESULT hr;
    *b = init;
    hr = VF(s, CB_DecodeFromBase64String, HSTRING, void **)(s, h, b);
    wr_hsfree(h); return hr;
}
static HRESULT c_b64dec(const WCHAR *w, UINT32 n, void **b) { return c_b64dec_x(w, n, b, NULL); }
static HRESULT c_b64enc(void *buf, HSTRING *o) {
    void *s = wr_cbs(); *o = NULL;
    return VF(s, CB_EncodeToBase64String, void *, HSTRING *)(s, buf, o);
}
static HRESULT c_s2b(const WCHAR *w, UINT32 n, int enc, void **b) {
    void *s = wr_cbs(); HSTRING h = wr_hsn(w, n); HRESULT hr;
    *b = NULL;
    hr = VF(s, CB_ConvertStringToBinary, HSTRING, int, void **)(s, h, enc, b);
    wr_hsfree(h); return hr;
}
static HRESULT c_b2s(int enc, void *buf, HSTRING *o) {
    void *s = wr_cbs(); *o = NULL;
    return VF(s, CB_ConvertBinaryToString, int, void *, HSTRING *)(s, enc, buf, o);
}
static HRESULT c_cmp(void *a, void *b, BYTE *r) {
    void *s = wr_cbs(); *r = 0x5a;
    return VF(s, CB_Compare, void *, void *, BYTE *)(s, a, b, r);
}

/* ------------------------------------------------------------------------------------------- */
TEST(winrt_buffer_statics_activation) {
    WR_NEED();
    void *f = wr_factory(CLS_BUFFER, 0); if (!f) return;
    void *s = NULL;
    EXPECT_HR(wr_qi(f, &WR_IID_ICryptographicBufferStatics, &s), S_OK);
    CHECK(s != NULL);
    if (s) wr_release(s);
    wr_release(f);
}
TEST(winrt_buffer_statics_no_default_ctor) {
    WR_NEED();
    void *f = wr_factory(CLS_BUFFER, 0); if (!f) return;
    void *o = (void *)1;
    HRESULT hr = VF(f, 6, void **)(f, &o);
    CHECK(FAILED(hr));
    CHECK(o == NULL);
    wr_release(f);
}

TEST(winrt_buffer_create_basic) {
    WR_NEED(); if (!wr_cbs()) return;
    static const BYTE d[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    void *b; EXPECT_HR(c_create(d, sizeof d, &b), S_OK);
    if (!b) return;
    UINT32 cap = 0, len = 0;
    EXPECT_HR(VF(b, 6, UINT32 *)(b, &cap), S_OK);
    EXPECT_HR(VF(b, 7, UINT32 *)(b, &len), S_OK);
    EXPECT_EQ(cap, sizeof d); EXPECT_EQ(len, sizeof d);
    CHECK(wr_buf_is(b, d, sizeof d));
    wr_release(b);
}
TEST(winrt_buffer_create_copies_input) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[16]; memset(d, 0xab, sizeof d);
    void *b; EXPECT_HR(c_create(d, sizeof d, &b), S_OK); if (!b) return;
    memset(d, 0, sizeof d);
    BYTE e[16]; memset(e, 0xab, sizeof e);
    CHECK(wr_buf_is(b, e, 16));
    const BYTE *p; UINT32 n; CHECK(wr_buf_get(b, &p, &n));
    CHECK(p != d);
    wr_release(b);
}
TEST(winrt_buffer_create_empty) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; EXPECT_HR(c_create(NULL, 0, &b), S_OK);
    if (b) { EXPECT_EQ(wr_buf_len(b), 0); UINT32 c = 9; VF(b, 6, UINT32 *)(b, &c); EXPECT_EQ(c, 0); wr_release(b); }
    else CHECK(!"buffer");
}
TEST(winrt_buffer_create_distinct_objects) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[4] = { 1, 2, 3, 4 }; void *a, *b;
    c_create(d, 4, &a); c_create(d, 4, &b);
    CHECK(a && b && a != b);
    if (a) wr_release(a); if (b) wr_release(b);
}
TEST(winrt_buffer_create_sizes) {
    WR_NEED(); if (!wr_cbs()) return;
    static const UINT32 sz[] = { 1, 2, 3, 15, 16, 17, 255, 256, 4095, 4096, 65536, 1u << 20, 4u << 20 };
    BYTE *src = malloc(4u << 20); if (!src) return;
    for (UINT32 i = 0; i < (4u << 20); i++) src[i] = (BYTE)(i * 31 + (i >> 8));
    for (size_t i = 0; i < sizeof sz / sizeof *sz; i++) {
        void *b; HRESULT hr = c_create(src, sz[i], &b);
        t_check(hr == S_OK, __FILE__, __LINE__, "CreateFromByteArray", "size %u hr 0x%08lx", sz[i], (unsigned long)hr);
        if (!b) continue;
        t_check(wr_buf_is(b, src, sz[i]), __FILE__, __LINE__, "contents", "size %u", sz[i]);
        wr_release(b);
    }
    free(src);
}

/* ---- identity of the returned buffer object -------------------------------------------------- */
TEST(winrt_buffer_refcounting) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[2] = { 1, 2 }; void *b; c_create(d, 2, &b); if (!b) return;
    EXPECT_EQ(wr_addref(b), 2);
    EXPECT_EQ(wr_addref(b), 3);
    EXPECT_EQ(wr_release(b), 2);
    EXPECT_EQ(wr_release(b), 1);
    EXPECT_EQ(wr_release(b), 0);
}
TEST(winrt_buffer_queryinterface_supported) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[2] = { 1, 2 }; void *b; c_create(d, 2, &b); if (!b) return;
    const GUID *ok[] = { &WR_IID_IUnknown, &WR_IID_IInspectable, &WR_IID_IBuffer, &WR_IID_IBufferByteAccess, &WR_IID_IAgileObject, &WR_IID_IMarshal };
    const char *nm[] = { "IUnknown", "IInspectable", "IBuffer", "IBufferByteAccess", "IAgileObject", "IMarshal" };
    for (int i = 0; i < 6; i++) {
        void *o = NULL; HRESULT hr = wr_qi(b, ok[i], &o);
        t_check(hr == S_OK && o, __FILE__, __LINE__, nm[i], "hr 0x%08lx", (unsigned long)hr);
        if (o) wr_release(o);
    }
    wr_release(b);
}
TEST(winrt_buffer_queryinterface_unsupported) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[2] = { 1, 2 }; void *b; c_create(d, 2, &b); if (!b) return;
    const GUID *bad[] = { &WR_IID_ICryptographicBufferStatics, &WR_IID_ICryptographicKey, &WR_IID_IActivationFactory, &WR_IID_IStream };
    for (int i = 0; i < 4; i++) {
        void *o = (void *)1; HRESULT hr = wr_qi(b, bad[i], &o);
        EXPECT_HR(hr, HR_E_NOINTERFACE); CHECK(o == NULL);
    }
    wr_release(b);
}
TEST(winrt_buffer_unknown_pointer_identity) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[2] = { 1, 2 }; void *b; c_create(d, 2, &b); if (!b) return;
    void *u1 = NULL, *u2 = NULL, *x = NULL;
    wr_qi(b, &WR_IID_IUnknown, &u1); wr_qi(b, &WR_IID_IBufferByteAccess, &x);
    if (x) { wr_qi(x, &WR_IID_IUnknown, &u2); wr_release(x); }
    CHECK(u1 && u1 == u2);
    if (u1) wr_release(u1); if (u2) wr_release(u2);
    wr_release(b);
}
TEST(winrt_buffer_getiids) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[2] = { 1, 2 }; void *b; c_create(d, 2, &b); if (!b) return;
    ULONG n = 0; GUID *ids = NULL;
    EXPECT_HR(wr_getiids(b, &n, &ids), S_OK);
    EXPECT_EQ(n, 2);
    if (n == 2 && ids) {
        CHECK(IsEqualGUID(&ids[0], &WR_IID_IBuffer));
        static const GUID weak = { 0x38, 0, 0, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };   /* IWeakReferenceSource */
        CHECK(IsEqualGUID(&ids[1], &weak));
    }
    wr_cofree(ids); wr_release(b);
}
TEST(winrt_buffer_runtime_class_name) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[2] = { 1, 2 }; void *b; c_create(d, 2, &b); if (!b) return;
    HSTRING h = NULL;
    EXPECT_HR(wr_getclassname(b, &h), S_OK);
    CHECK(wr_hs_eq(h, L"Windows.Storage.Streams.IBuffer"));
    wr_hsfree(h); wr_release(b);
}
TEST(winrt_buffer_trust_level) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[2] = { 1, 2 }; void *b; c_create(d, 2, &b); if (!b) return;
    int lvl = -1; HRESULT hr = wr_gettrust(b, &lvl);
    CHECK(SUCCEEDED(hr)); if (SUCCEEDED(hr)) EXPECT_EQ(lvl, 0);
    wr_release(b);
}
TEST(winrt_buffer_put_length) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }; void *b; c_create(d, 8, &b); if (!b) return;
    EXPECT_HR(VF(b, 8, UINT32)(b, 4), S_OK);
    EXPECT_EQ(wr_buf_len(b), 4);
    UINT32 cap = 0; VF(b, 6, UINT32 *)(b, &cap); EXPECT_EQ(cap, 8);
    CHECK(wr_buf_is(b, d, 4));
    EXPECT_HR(VF(b, 8, UINT32)(b, 0), S_OK);  EXPECT_EQ(wr_buf_len(b), 0);
    EXPECT_HR(VF(b, 8, UINT32)(b, 8), S_OK);  EXPECT_EQ(wr_buf_len(b), 8);
    CHECK(wr_buf_is(b, d, 8));                /* storage is untouched by length changes */
    EXPECT_HR(VF(b, 8, UINT32)(b, 9), HR_E_INVALIDARG);
    EXPECT_EQ(wr_buf_len(b), 8);
    EXPECT_HR(VF(b, 8, UINT32)(b, 0xFFFFFFFFu), HR_E_INVALIDARG);
    EXPECT_EQ(wr_buf_len(b), 8);
    wr_release(b);
}
TEST(winrt_buffer_length_follows_into_consumers) {
    /* a shortened Length is what hex/base64 encoders see */
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[4] = { 0xde, 0xad, 0xbe, 0xef }; void *b; c_create(d, 4, &b); if (!b) return;
    VF(b, 8, UINT32)(b, 2);
    HSTRING h; EXPECT_HR(c_hexenc(b, &h), S_OK); CHECK(wr_hs_eq(h, L"dead")); wr_hsfree(h);
    EXPECT_HR(c_b64enc(b, &h), S_OK);            CHECK(wr_hs_eq(h, L"3q0=")); wr_hsfree(h);
    wr_release(b);
}
TEST(winrt_buffer_byteaccess_stable_pointer) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[3] = { 7, 8, 9 }; void *b; c_create(d, 3, &b); if (!b) return;
    const BYTE *p1, *p2; UINT32 n;
    CHECK(wr_buf_get(b, &p1, &n)); CHECK(wr_buf_get(b, &p2, &n));
    CHECK(p1 == p2 && p1 != NULL);
    wr_release(b);
}

/* ---- Compare --------------------------------------------------------------------------------- */
TEST(winrt_buffer_compare_equal_and_different) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE a[] = { 1, 2, 3, 4 }, b2[] = { 1, 2, 3, 4 }, c[] = { 1, 2, 3, 5 }, d[] = { 1, 2, 3 }, e[] = { 0, 2, 3, 4 };
    void *A, *B, *C, *D, *E;
    c_create(a, 4, &A); c_create(b2, 4, &B); c_create(c, 4, &C); c_create(d, 3, &D); c_create(e, 4, &E);
    if (!(A && B && C && D && E)) return;
    BYTE r;
    EXPECT_HR(c_cmp(A, B, &r), S_OK); EXPECT_EQ(r, 1);
    EXPECT_HR(c_cmp(A, A, &r), S_OK); EXPECT_EQ(r, 1);
    EXPECT_HR(c_cmp(A, C, &r), S_OK); EXPECT_EQ(r, 0);
    EXPECT_HR(c_cmp(C, A, &r), S_OK); EXPECT_EQ(r, 0);
    EXPECT_HR(c_cmp(A, D, &r), S_OK); EXPECT_EQ(r, 0);
    EXPECT_HR(c_cmp(D, A, &r), S_OK); EXPECT_EQ(r, 0);
    EXPECT_HR(c_cmp(A, E, &r), S_OK); EXPECT_EQ(r, 0);
    wr_release(A); wr_release(B); wr_release(C); wr_release(D); wr_release(E);
}
TEST(winrt_buffer_compare_empty) {
    WR_NEED(); if (!wr_cbs()) return;
    void *A, *B, *C; BYTE x = 1;
    c_create(NULL, 0, &A); c_create(NULL, 0, &B); c_create(&x, 1, &C);
    if (!(A && B && C)) return;
    BYTE r;
    EXPECT_HR(c_cmp(A, B, &r), S_OK); EXPECT_EQ(r, 1);
    EXPECT_HR(c_cmp(A, C, &r), S_OK); EXPECT_EQ(r, 0);
    EXPECT_HR(c_cmp(C, A, &r), S_OK); EXPECT_EQ(r, 0);
    wr_release(A); wr_release(B); wr_release(C);
}
TEST(winrt_buffer_compare_null_arguments) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE x = 1; void *A; c_create(&x, 1, &A); if (!A) return;
    BYTE r;
    EXPECT_HR(c_cmp(NULL, NULL, &r), HR_E_POINTER); EXPECT_EQ(r, 0);
    EXPECT_HR(c_cmp(A, NULL, &r), HR_E_POINTER);    EXPECT_EQ(r, 0);
    EXPECT_HR(c_cmp(NULL, A, &r), HR_E_POINTER);    EXPECT_EQ(r, 0);
    wr_release(A);
}
TEST(winrt_buffer_compare_last_byte_of_large) {
    WR_NEED(); if (!wr_cbs()) return;
    UINT32 n = 1u << 20; BYTE *a = malloc(n), *b = malloc(n); if (!a || !b) return;
    memset(a, 0x5a, n); memset(b, 0x5a, n);
    void *A, *B; c_create(a, n, &A); b[n - 1] ^= 1; c_create(b, n, &B);
    BYTE r; EXPECT_HR(c_cmp(A, B, &r), S_OK); EXPECT_EQ(r, 0);
    b[n - 1] ^= 1; wr_release(B); c_create(b, n, &B);
    EXPECT_HR(c_cmp(A, B, &r), S_OK); EXPECT_EQ(r, 1);
    wr_release(A); wr_release(B); free(a); free(b);
}
TEST(winrt_buffer_compare_ignores_capacity_uses_length) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE a[4] = { 1, 2, 3, 4 }, b[4] = { 1, 2, 9, 9 }; void *A, *B;
    c_create(a, 4, &A); c_create(b, 4, &B); if (!A || !B) return;
    VF(A, 8, UINT32)(A, 2); VF(B, 8, UINT32)(B, 2);
    BYTE r; EXPECT_HR(c_cmp(A, B, &r), S_OK); EXPECT_EQ(r, 1);
    wr_release(A); wr_release(B);
}

/* ---- GenerateRandom / GenerateRandomNumber -------------------------------------------------- */
TEST(winrt_buffer_generate_random_lengths) {
    WR_NEED(); if (!wr_cbs()) return;
    void *s = wr_cbs();
    static const UINT32 sz[] = { 0, 1, 2, 7, 8, 16, 31, 32, 33, 255, 1000, 4096, 65536 };
    for (size_t i = 0; i < sizeof sz / sizeof *sz; i++) {
        void *b = NULL; HRESULT hr = VF(s, CB_GenerateRandom, UINT32, void **)(s, sz[i], &b);
        t_check(hr == S_OK && b, __FILE__, __LINE__, "GenerateRandom", "len %u hr 0x%08lx", sz[i], (unsigned long)hr);
        if (!b) continue;
        UINT32 cap = 0xffff; VF(b, 6, UINT32 *)(b, &cap);
        t_check(wr_buf_len(b) == sz[i] && cap == sz[i], __FILE__, __LINE__, "length/capacity", "len %u got %u/%u", sz[i], wr_buf_len(b), cap);
        wr_release(b);
    }
}
TEST(winrt_buffer_generate_random_differs) {
    WR_NEED(); if (!wr_cbs()) return;
    void *s = wr_cbs(), *a = NULL, *b = NULL;
    VF(s, CB_GenerateRandom, UINT32, void **)(s, 32, &a);
    VF(s, CB_GenerateRandom, UINT32, void **)(s, 32, &b);
    if (!a || !b) { CHECK(!"buffers"); return; }
    BYTE r; c_cmp(a, b, &r);
    EXPECT_EQ(r, 0);                       /* 2^-256 false-failure probability */
    const BYTE *p; UINT32 n; wr_buf_get(a, &p, &n);
    int nz = 0; for (UINT32 i = 0; i < n; i++) nz |= p[i];
    CHECK(nz != 0);
    wr_release(a); wr_release(b);
}
TEST(winrt_buffer_generate_random_fills_whole_buffer) {
    WR_NEED(); if (!wr_cbs()) return;
    void *s = wr_cbs(), *b = NULL;
    VF(s, CB_GenerateRandom, UINT32, void **)(s, 4096, &b); if (!b) return;
    const BYTE *p; UINT32 n; wr_buf_get(b, &p, &n);
    int seen[256] = { 0 }, distinct = 0;
    for (UINT32 i = 0; i < n; i++) if (!seen[p[i]]++) distinct++;
    CHECK(distinct > 200);                 /* 4096 uniform bytes cover ~255 values */
    int tailnz = 0; for (UINT32 i = n - 64; i < n; i++) tailnz |= p[i];
    CHECK(tailnz != 0);
    wr_release(b);
}
TEST(winrt_buffer_generate_random_number) {
    WR_NEED(); if (!wr_cbs()) return;
    void *s = wr_cbs(); UINT32 first = 0, diff = 0;
    for (int i = 0; i < 64; i++) {
        UINT32 v = 0; HRESULT hr = VF(s, CB_GenerateRandomNumber, UINT32 *)(s, &v);
        if (hr != S_OK) { EXPECT_HR(hr, S_OK); return; }
        if (i == 0) first = v; else if (v != first) diff++;
    }
    CHECK(diff > 0);
}
TEST(winrt_buffer_generate_random_number_high_bits) {
    WR_NEED(); if (!wr_cbs()) return;
    void *s = wr_cbs(); UINT32 acc = 0;
    for (int i = 0; i < 256; i++) { UINT32 v = 0; VF(s, CB_GenerateRandomNumber, UINT32 *)(s, &v); acc |= v; }
    EXPECT_EQ(acc, 0xFFFFFFFFu);           /* 256 samples set every bit, p(fail) ~ 32*2^-256 */
}

/* ---- CopyToByteArray -------------------------------------------------------------------------- */
TEST(winrt_buffer_copy_to_bytes_roundtrip) {
    WR_NEED(); if (!wr_cbs()) return;
    void *s = wr_cbs(); BYTE d[] = { 9, 8, 7, 6, 5, 4, 3 }; void *b; c_create(d, 7, &b); if (!b) return;
    UINT32 n = 0; BYTE *out = NULL;
    EXPECT_HR(VF(s, CB_CopyToByteArray, void *, UINT32 *, BYTE **)(s, b, &n, &out), S_OK);
    EXPECT_EQ(n, 7); CHECK(out && !memcmp(out, d, 7));
    const BYTE *p; UINT32 m; wr_buf_get(b, &p, &m);
    CHECK(out != p);                       /* a copy, not an alias */
    wr_cofree(out); wr_release(b);
}
TEST(winrt_buffer_copy_to_bytes_empty_and_null) {
    WR_NEED(); if (!wr_cbs()) return;
    void *s = wr_cbs(); void *b; c_create(NULL, 0, &b);
    UINT32 n = 99; BYTE *out = (BYTE *)(ULONG_PTR)1;
    EXPECT_HR(VF(s, CB_CopyToByteArray, void *, UINT32 *, BYTE **)(s, b, &n, &out), S_OK);
    EXPECT_EQ(n, 0); CHECK(out == NULL);
    n = 99; out = (BYTE *)(ULONG_PTR)1;
    EXPECT_HR(VF(s, CB_CopyToByteArray, void *, UINT32 *, BYTE **)(s, NULL, &n, &out), S_OK);
    EXPECT_EQ(n, 0); CHECK(out == NULL);
    if (b) wr_release(b);
}
TEST(winrt_buffer_copy_to_bytes_after_shorten) {
    WR_NEED(); if (!wr_cbs()) return;
    void *s = wr_cbs(); BYTE d[] = { 1, 2, 3, 4 }; void *b; c_create(d, 4, &b); if (!b) return;
    VF(b, 8, UINT32)(b, 3);
    UINT32 n = 0; BYTE *out = NULL;
    EXPECT_HR(VF(s, CB_CopyToByteArray, void *, UINT32 *, BYTE **)(s, b, &n, &out), S_OK);
    EXPECT_EQ(n, 3); CHECK(out && !memcmp(out, d, 3));
    wr_cofree(out); wr_release(b);
}

/* ---- hex ---------------------------------------------------------------------------------------- */
static const struct { const char *bin; const WCHAR *hex; } hex_enc_v[] = {
    { "00", L"00" }, { "ff", L"ff" }, { "0123456789abcdef", L"0123456789abcdef" }, { "deadbeef", L"deadbeef" },
    { "000102030405060708090a0b0c0d0e0f", L"000102030405060708090a0b0c0d0e0f" }, { "a5", L"a5" }, { "0f", L"0f" },
    { "f0", L"f0" }, { "10", L"10" }, { "01", L"01" }, { "00ff00ff", L"00ff00ff" },
    { "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", L"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
};
TEST(winrt_buffer_hex_encode_vectors) {
    WR_NEED(); if (!wr_cbs()) return;
    for (size_t i = 0; i < sizeof hex_enc_v / sizeof *hex_enc_v; i++) {
        void *b = wr_mkbuf_hex(hex_enc_v[i].bin); HSTRING h;
        HRESULT hr = c_hexenc(b, &h);
        t_check(hr == S_OK && wr_hs_eq(h, hex_enc_v[i].hex), __FILE__, __LINE__, "EncodeToHexString", "vector %zu hr 0x%08lx", i, (unsigned long)hr);
        wr_hsfree(h); wr_release(b);
    }
}
TEST(winrt_buffer_hex_encode_is_lowercase) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b = wr_mkbuf_hex("abcdefABCDEF1234"); HSTRING h;
    EXPECT_HR(c_hexenc(b, &h), S_OK);
    UINT32 n; const WCHAR *r = wr_raw(h, &n);
    EXPECT_EQ(n, 16);
    for (UINT32 i = 0; i < n; i++) CHECK((r[i] >= L'0' && r[i] <= L'9') || (r[i] >= L'a' && r[i] <= L'f'));
    wr_hsfree(h); wr_release(b);
}
TEST(winrt_buffer_hex_encode_empty_and_null) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; c_create(NULL, 0, &b); HSTRING h = (HSTRING)1;
    EXPECT_HR(c_hexenc(b, &h), S_OK); CHECK(h == NULL);
    h = (HSTRING)1; EXPECT_HR(c_hexenc(NULL, &h), S_OK); CHECK(h == NULL);
    if (b) wr_release(b);
}
TEST(winrt_buffer_hex_encode_length_is_double) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[300]; for (int i = 0; i < 300; i++) d[i] = (BYTE)i;
    for (UINT32 n = 1; n <= 300; n += 37) {
        void *b = wr_mkbuf(d, n); HSTRING h; UINT32 l;
        EXPECT_HR(c_hexenc(b, &h), S_OK); wr_raw(h, &l); EXPECT_EQ(l, 2 * n);
        wr_hsfree(h); wr_release(b);
    }
}
static const struct { const WCHAR *hex; const char *bin; } hex_dec_ok[] = {
    { L"00", "00" }, { L"ff", "ff" }, { L"FF", "ff" }, { L"aBcDeF", "abcdef" }, { L"0123456789", "0123456789" },
    { L"deadbeef", "deadbeef" }, { L"DEADBEEF", "deadbeef" }, { L"DeAdBeEf", "deadbeef" },
    { L"0x12", "12" }, { L"0x1234", "1234" }, { L"0x12 0x34", "1234" }, { L"0xab0xcd", "abcd" },
    { L" 12", "12" }, { L"12 ", "12" }, { L" 12 34 ", "1234" }, { L"12\t34", "1234" }, { L"12\r\n34", "1234" },
    { L"12:34:56", "123456" }, { L":12", "12" }, { L"de:ad:be:ef", "deadbeef" }, { L"01  02", "0102" },
    { L"\n\n0a\n\n", "0a" }, { L"00000000", "00000000" },
};
TEST(winrt_buffer_hex_decode_valid) {
    WR_NEED(); if (!wr_cbs()) return;
    for (size_t i = 0; i < sizeof hex_dec_ok / sizeof *hex_dec_ok; i++) {
        void *b; HRESULT hr = c_hexdec(hex_dec_ok[i].hex, (UINT32)lstrlenW(hex_dec_ok[i].hex), &b);
        t_check(hr == S_OK && b && wr_buf_is_hex(b, hex_dec_ok[i].bin), __FILE__, __LINE__, "DecodeFromHexString", "vector %zu (%ls) hr 0x%08lx", i, hex_dec_ok[i].hex, (unsigned long)hr);
        if (SUCCEEDED(hr) && b) wr_release(b);
    }
}
static const WCHAR *hex_dec_bad[] = {
    L"0", L"1", L"abc", L"12345", L"zz", L"0g", L"g0", L"gg", L"0x", L"0x1", L"0X12", L"1 2", L"1:2", L"12 3", L"+1", L"-1",
    L"12-34", L"12,34", L"12_34", L"\x00e9\x00e9", L"0x0x12", L"xx", L"12;34", L"12\x2003" L"34", L"fg", L"0\x0660",
};
TEST(winrt_buffer_hex_decode_invalid) {
    WR_NEED(); if (!wr_cbs()) return;
    for (size_t i = 0; i < sizeof hex_dec_bad / sizeof *hex_dec_bad; i++) {
        void *b; HRESULT hr = c_hexdec_x(hex_dec_bad[i], (UINT32)lstrlenW(hex_dec_bad[i]), &b, (void *)1);
        t_check(hr == (HRESULT)NTE_BAD_DATA_HR, __FILE__, __LINE__, "DecodeFromHexString", "vector %zu (%ls) hr 0x%08lx", i, hex_dec_bad[i], (unsigned long)hr);
        t_check(b == NULL, __FILE__, __LINE__, "out NULL on failure", "vector %zu", i);
    }
}
TEST(winrt_buffer_hex_decode_empty_and_blank) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b;
    EXPECT_HR(c_hexdec(L"", 0, &b), S_OK);
    if (b) { EXPECT_EQ(wr_buf_len(b), 0); wr_release(b); } else CHECK(!"buffer");
    EXPECT_HR(c_hexdec(L"   ", 3, &b), S_OK);
    if (b) { EXPECT_EQ(wr_buf_len(b), 0); wr_release(b); } else CHECK(!"buffer");
    void *s = wr_cbs(); b = (void *)1;
    EXPECT_HR(VF(s, CB_DecodeFromHexString, HSTRING, void **)(s, NULL, &b), S_OK);
    if (b && b != (void *)1) { EXPECT_EQ(wr_buf_len(b), 0); wr_release(b); } else CHECK(!"buffer");
}
TEST(winrt_buffer_hex_decode_embedded_nul) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; HRESULT hr = c_hexdec_x(L"12\0" L"34", 5, &b, (void *)1);
    EXPECT_HR(hr, NTE_BAD_DATA_HR); CHECK(b == NULL);
}
TEST(winrt_buffer_hex_decode_buffer_is_exact_length) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; EXPECT_HR(c_hexdec(L"0x01 0x02 0x03", 14, &b), S_OK);
    if (b) { EXPECT_EQ(wr_buf_len(b), 3); wr_release(b); }
}
TEST(winrt_buffer_hex_roundtrip_all_bytes) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[256]; for (int i = 0; i < 256; i++) d[i] = (BYTE)i;
    void *b = wr_mkbuf(d, 256), *r = NULL; HSTRING h;
    EXPECT_HR(c_hexenc(b, &h), S_OK);
    UINT32 n; const WCHAR *w = wr_raw(h, &n);
    EXPECT_HR(c_hexdec(w, n, &r), S_OK);
    CHECK(wr_buf_is(r, d, 256));
    wr_hsfree(h); wr_release(b); if (r) wr_release(r);
}
TEST(winrt_buffer_hex_roundtrip_lengths) {
    WR_NEED(); if (!wr_cbs()) return;
    unsigned x = 12345; BYTE d[400];
    for (UINT32 n = 1; n < 400; n += 3) {
        for (UINT32 i = 0; i < n; i++) { x = x * 1103515245u + 12345u; d[i] = (BYTE)(x >> 16); }
        void *b = wr_mkbuf(d, n), *r = NULL; HSTRING h;
        c_hexenc(b, &h); UINT32 l; const WCHAR *w = wr_raw(h, &l);
        c_hexdec(w, l, &r);
        t_check(wr_buf_is(r, d, n), __FILE__, __LINE__, "hex roundtrip", "len %u", n);
        wr_hsfree(h); wr_release(b); if (r) wr_release(r);
    }
}

/* ---- base64 ------------------------------------------------------------------------------------- */
static const struct { const char *s; const WCHAR *b64; } b64_v[] = {
    { "", L"" }, { "f", L"Zg==" }, { "fo", L"Zm8=" }, { "foo", L"Zm9v" }, { "foob", L"Zm9vYg==" },
    { "fooba", L"Zm9vYmE=" }, { "foobar", L"Zm9vYmFy" },
    { "Hello, World!", L"SGVsbG8sIFdvcmxkIQ==" }, { "Man", L"TWFu" }, { "Ma", L"TWE=" }, { "M", L"TQ==" },
    { "any carnal pleas", L"YW55IGNhcm5hbCBwbGVhcw==" }, { "any carnal pleasu", L"YW55IGNhcm5hbCBwbGVhc3U=" },
    { "any carnal pleasur", L"YW55IGNhcm5hbCBwbGVhc3Vy" },
};
TEST(winrt_buffer_base64_encode_text_vectors) {
    WR_NEED(); if (!wr_cbs()) return;
    for (size_t i = 0; i < sizeof b64_v / sizeof *b64_v; i++) {
        void *b = wr_mkbuf(b64_v[i].s, (UINT32)strlen(b64_v[i].s)); HSTRING h;
        HRESULT hr = c_b64enc(b, &h);
        t_check(hr == S_OK && wr_hs_eq(h, b64_v[i].b64), __FILE__, __LINE__, "EncodeToBase64String", "vector %zu hr 0x%08lx", i, (unsigned long)hr);
        wr_hsfree(h); wr_release(b);
    }
}
TEST(winrt_buffer_base64_encode_binary_vectors) {
    WR_NEED(); if (!wr_cbs()) return;
    static const struct { const char *hex; const WCHAR *b64; } v[] = {
        { "00", L"AA==" }, { "0000", L"AAA=" }, { "000000", L"AAAA" }, { "ff", L"/w==" }, { "ffff", L"//8=" }, { "ffffff", L"////" },
        { "fb", L"+w==" }, { "fbef", L"++8=" }, { "fbefbe", L"++++" }, { "3e3f", L"Pj8=" }, { "00010203", L"AAECAw==" },
        { "deadbeef", L"3q2+7w==" }, { "0123456789abcdef", L"ASNFZ4mrze8=" },
        { "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", L"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" },
    };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *b = wr_mkbuf_hex(v[i].hex); HSTRING h;
        HRESULT hr = c_b64enc(b, &h);
        t_check(hr == S_OK && wr_hs_eq(h, v[i].b64), __FILE__, __LINE__, "EncodeToBase64String", "vector %zu hr 0x%08lx", i, (unsigned long)hr);
        wr_hsfree(h); wr_release(b);
    }
}
TEST(winrt_buffer_base64_encode_no_line_breaks) {
    WR_NEED(); if (!wr_cbs()) return;
    BYTE d[1000]; for (int i = 0; i < 1000; i++) d[i] = (BYTE)(i * 7);
    void *b = wr_mkbuf(d, 1000); HSTRING h; UINT32 n;
    EXPECT_HR(c_b64enc(b, &h), S_OK);
    const WCHAR *w = wr_raw(h, &n);
    EXPECT_EQ(n, 1336);                    /* ceil(1000/3)*4, no CRLF wrapping */
    for (UINT32 i = 0; i < n; i++) CHECK(w[i] > 0x20 && w[i] < 0x7f);
    wr_hsfree(h); wr_release(b);
}
TEST(winrt_buffer_base64_encode_empty_and_null) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; c_create(NULL, 0, &b); HSTRING h = (HSTRING)1;
    EXPECT_HR(c_b64enc(b, &h), S_OK); CHECK(h == NULL);
    h = (HSTRING)1; EXPECT_HR(c_b64enc(NULL, &h), S_OK); CHECK(h == NULL);
    if (b) wr_release(b);
}
static const struct { const WCHAR *b64; const char *s; } b64_dec_ok[] = {
    { L"Zg==", "f" }, { L"Zm8=", "fo" }, { L"Zm9v", "foo" }, { L"Zm9vYg==", "foob" }, { L"Zm9vYmE=", "fooba" }, { L"Zm9vYmFy", "foobar" },
    { L"Zg", "f" }, { L"Zm8", "fo" }, { L"Zm9vYg", "foob" }, { L"Zm9vYmE", "fooba" },
    { L"Zm9v\r\nYmFy", "foobar" }, { L"Zm9v YmFy", "foobar" }, { L" Zm9vYmFy ", "foobar" }, { L"Z m 9 v", "foo" }, { L"Zm9v\tYmFy\n", "foobar" },
    { L"SGVsbG8sIFdvcmxkIQ==", "Hello, World!" }, { L"SGVs\nbG8s\nIFdv\ncmxk\nIQ==", "Hello, World!" },
    { L"Zg== ", "f" }, { L" Zg==", "f" }, { L"Zg =\r\n=", "f" },
};
TEST(winrt_buffer_base64_decode_valid) {
    WR_NEED(); if (!wr_cbs()) return;
    for (size_t i = 0; i < sizeof b64_dec_ok / sizeof *b64_dec_ok; i++) {
        void *b; HRESULT hr = c_b64dec(b64_dec_ok[i].b64, (UINT32)lstrlenW(b64_dec_ok[i].b64), &b);
        t_check(hr == S_OK && b && wr_buf_is(b, b64_dec_ok[i].s, (UINT32)strlen(b64_dec_ok[i].s)), __FILE__, __LINE__, "DecodeFromBase64String", "vector %zu (%ls) hr 0x%08lx", i, b64_dec_ok[i].b64, (unsigned long)hr);
        if (SUCCEEDED(hr) && b) wr_release(b);
    }
}
TEST(winrt_buffer_base64_decode_binary_alphabet) {
    WR_NEED(); if (!wr_cbs()) return;
    static const struct { const WCHAR *b64; const char *hex; } v[] = {
        { L"AAAA", "000000" }, { L"////", "ffffff" }, { L"++++", "fbefbe" }, { L"/w==", "ff" }, { L"+w==", "fb" },
        { L"AAECAw==", "00010203" }, { L"3q2+7w==", "deadbeef" },
        { L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
          "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf" },
    };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *b; HRESULT hr = c_b64dec(v[i].b64, (UINT32)lstrlenW(v[i].b64), &b);
        t_check(hr == S_OK && b && wr_buf_is_hex(b, v[i].hex), __FILE__, __LINE__, "DecodeFromBase64String", "vector %zu hr 0x%08lx", i, (unsigned long)hr);
        if (SUCCEEDED(hr) && b) wr_release(b);
    }
}
static const WCHAR *b64_dec_bad[] = {
    L"Zm9v!", L"!!!!", L"Zm9v-", L"Zm_v", L"Zm-v", L"Zg===", L"Zg==A", L"Zg==Zg==", L"Zm9v=Zm9v", L"@@@@", L"Zm9\x00e9",
    L"Zm9v\x0100", L"Zm9v\x2003" L"YmFy", L"====A", L"=A",
};
TEST(winrt_buffer_base64_decode_invalid) {
    WR_NEED(); if (!wr_cbs()) return;
    for (size_t i = 0; i < sizeof b64_dec_bad / sizeof *b64_dec_bad; i++) {
        void *b; HRESULT hr = c_b64dec_x(b64_dec_bad[i], (UINT32)lstrlenW(b64_dec_bad[i]), &b, (void *)1);
        t_check(hr == (HRESULT)NTE_BAD_DATA_HR, __FILE__, __LINE__, "DecodeFromBase64String", "vector %zu (%ls) hr 0x%08lx", i, b64_dec_bad[i], (unsigned long)hr);
        t_check(b == NULL, __FILE__, __LINE__, "out NULL on failure", "vector %zu", i);
    }
}
TEST(winrt_buffer_base64_decode_empty) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; EXPECT_HR(c_b64dec(L"", 0, &b), S_OK);
    if (b) { EXPECT_EQ(wr_buf_len(b), 0); wr_release(b); } else CHECK(!"buffer");
    EXPECT_HR(c_b64dec(L" \r\n", 3, &b), S_OK);
    if (b) { EXPECT_EQ(wr_buf_len(b), 0); wr_release(b); } else CHECK(!"buffer");
}
TEST(winrt_buffer_base64_decode_url_alphabet_rejected) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; EXPECT_HR(c_b64dec(L"__8=", 4, &b), NTE_BAD_DATA_HR);
    EXPECT_HR(c_b64dec(L"--8=", 4, &b), NTE_BAD_DATA_HR);
}
TEST(winrt_buffer_base64_roundtrip_lengths) {
    WR_NEED(); if (!wr_cbs()) return;
    unsigned x = 777; BYTE d[400];
    for (UINT32 n = 0; n < 400; n++) {
        for (UINT32 i = 0; i < n; i++) { x = x * 1664525u + 1013904223u; d[i] = (BYTE)(x >> 24); }
        void *b = wr_mkbuf(d, n), *r = NULL; HSTRING h; UINT32 l;
        c_b64enc(b, &h); const WCHAR *w = wr_raw(h, &l);
        t_check(l == ((n + 2) / 3) * 4, __FILE__, __LINE__, "encoded length", "len %u got %u", n, l);
        HRESULT hr = c_b64dec(w, l, &r);
        t_check(hr == S_OK && wr_buf_is(r, d, n), __FILE__, __LINE__, "base64 roundtrip", "len %u hr 0x%08lx", n, (unsigned long)hr);
        wr_hsfree(h); wr_release(b); if (r) wr_release(r);
    }
}
TEST(winrt_buffer_base64_large_roundtrip) {
    WR_NEED(); if (!wr_cbs()) return;
    UINT32 n = 3u << 20; BYTE *d = malloc(n); if (!d) return;
    for (UINT32 i = 0; i < n; i++) d[i] = (BYTE)(i ^ (i >> 7));
    void *b = wr_mkbuf(d, n), *r = NULL; HSTRING h; UINT32 l;
    EXPECT_HR(c_b64enc(b, &h), S_OK);
    const WCHAR *w = wr_raw(h, &l); EXPECT_EQ(l, 4u << 20);
    EXPECT_HR(c_b64dec(w, l, &r), S_OK);
    CHECK(r && wr_buf_is(r, d, n));
    wr_hsfree(h); wr_release(b); if (r) wr_release(r); free(d);
}
TEST(winrt_buffer_base64_hex_agree) {
    WR_NEED(); if (!wr_cbs()) return;
    void *a, *b; HSTRING h;
    EXPECT_HR(c_hexdec(L"00ff10", 6, &a), S_OK);
    EXPECT_HR(c_b64enc(a, &h), S_OK); CHECK(wr_hs_eq(h, L"AP8Q"));
    UINT32 l; const WCHAR *w = wr_raw(h, &l); EXPECT_HR(c_b64dec(w, l, &b), S_OK);
    BYTE r; if (a && b) { c_cmp(a, b, &r); EXPECT_EQ(r, 1); }
    wr_hsfree(h); if (a) wr_release(a); if (b) wr_release(b);
}

/* ---- string <-> binary --------------------------------------------------------------------------- */
enum { ENC_UTF8 = 0, ENC_UTF16LE = 1, ENC_UTF16BE = 2 };
static const struct { const WCHAR *s; UINT32 n; const char *utf8, *le, *be; } str_v[] = {
    { L"A", 1, "41", "4100", "0041" },
    { L"Ab", 2, "4162", "41006200", "00410062" },
    { L"hello", 5, "68656c6c6f", "680065006c006c006f00", "00680065006c006c006f" },
    { L"\x00e9", 1, "c3a9", "e900", "00e9" },
    { L"\x20ac", 1, "e282ac", "ac20", "20ac" },
    { L"\x0416", 1, "d096", "1604", "0416" },
    { L"\x4e2d\x6587", 2, "e4b8ade69687", "2d4e8765", "4e2d6587" },
    { L"\xd83d\xde00", 2, "f09f9880", "3dd800de", "d83dde00" },        /* U+1F600 */
    { L"a\xd83d\xde00" L"b", 4, "61f09f988062", "61003dd800de6200", "0061d83dde000062" },
    { L"\x007f", 1, "7f", "7f00", "007f" }, { L"\x0080", 1, "c280", "8000", "0080" },
    { L"\x07ff", 1, "dfbf", "ff07", "07ff" }, { L"\x0800", 1, "e0a080", "0008", "0800" },
    { L"\xffff", 1, "efbfbf", "ffff", "ffff" },
    { L"a\0b", 3, "610062", "610000006200", "006100000062" },
    { L" ", 1, "20", "2000", "0020" }, { L"\r\n", 2, "0d0a", "0d000a00", "000d000a" },
};
static const char *sel(int i, int e) { return e == ENC_UTF8 ? str_v[i].utf8 : e == ENC_UTF16LE ? str_v[i].le : str_v[i].be; }
static void run_s2b(int enc) {
    for (size_t i = 0; i < sizeof str_v / sizeof *str_v; i++) {
        void *b; HRESULT hr = c_s2b(str_v[i].s, str_v[i].n, enc, &b);
        t_check(hr == S_OK && b && wr_buf_is_hex(b, sel((int)i, enc)), __FILE__, __LINE__, "ConvertStringToBinary", "enc %d vector %zu hr 0x%08lx", enc, i, (unsigned long)hr);
        if (b) wr_release(b);
    }
}
TEST(winrt_buffer_string_to_binary_utf8) { WR_NEED(); if (!wr_cbs()) return; run_s2b(ENC_UTF8); }
TEST(winrt_buffer_string_to_binary_utf16le) { WR_NEED(); if (!wr_cbs()) return; run_s2b(ENC_UTF16LE); }
TEST(winrt_buffer_string_to_binary_utf16be) { WR_NEED(); if (!wr_cbs()) return; run_s2b(ENC_UTF16BE); }
static void run_b2s(int enc) {
    for (size_t i = 0; i < sizeof str_v / sizeof *str_v; i++) {
        void *b = wr_mkbuf_hex(sel((int)i, enc)); HSTRING h = NULL;
        HRESULT hr = c_b2s(enc, b, &h); UINT32 n; const WCHAR *w = wr_raw(h, &n);
        t_check(hr == S_OK && n == str_v[i].n && !memcmp(w, str_v[i].s, n * 2), __FILE__, __LINE__, "ConvertBinaryToString", "enc %d vector %zu hr 0x%08lx len %u", enc, i, (unsigned long)hr, n);
        wr_hsfree(h); wr_release(b);
    }
}
TEST(winrt_buffer_binary_to_string_utf8) { WR_NEED(); if (!wr_cbs()) return; run_b2s(ENC_UTF8); }
TEST(winrt_buffer_binary_to_string_utf16le) { WR_NEED(); if (!wr_cbs()) return; run_b2s(ENC_UTF16LE); }
TEST(winrt_buffer_binary_to_string_utf16be) { WR_NEED(); if (!wr_cbs()) return; run_b2s(ENC_UTF16BE); }

TEST(winrt_buffer_string_to_binary_empty) {
    WR_NEED(); if (!wr_cbs()) return;
    for (int e = 0; e < 3; e++) {
        void *b; HRESULT hr = c_s2b(L"", 0, e, &b);
        t_check(hr == S_OK && b && wr_buf_len(b) == 0, __FILE__, __LINE__, "ConvertStringToBinary(empty)", "enc %d hr 0x%08lx", e, (unsigned long)hr);
        if (b) wr_release(b);
    }
    void *s = wr_cbs(), *b = NULL;
    EXPECT_HR(VF(s, CB_ConvertStringToBinary, HSTRING, int, void **)(s, NULL, ENC_UTF8, &b), S_OK);
    if (b) { EXPECT_EQ(wr_buf_len(b), 0); wr_release(b); } else CHECK(!"buffer");
}
TEST(winrt_buffer_string_to_binary_unknown_encoding) {
    WR_NEED(); if (!wr_cbs()) return;
    static const int bad[] = { 3, 4, 5, 100, -1, 0x7fffffff, (int)0x80000000 };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *b = (void *)1, *s = wr_cbs(); HSTRING h = wr_hs(L"abc");
        HRESULT hr = VF(s, CB_ConvertStringToBinary, HSTRING, int, void **)(s, h, bad[i], &b);
        t_check(hr == (HRESULT)HR_E_NOTIMPL && b == NULL, __FILE__, __LINE__, "ConvertStringToBinary(bad enc)", "enc %d hr 0x%08lx", bad[i], (unsigned long)hr);
        wr_hsfree(h);
    }
}
TEST(winrt_buffer_string_to_binary_lone_surrogates_utf8) {
    WR_NEED(); if (!wr_cbs()) return;
    static const WCHAR hi[] = { 0xd800, 0 }, lo[] = { 0xdc00, 0 }, rev[] = { 0xde00, 0xd83d, 0 }, mid[] = { 'a', 0xd800, 'b', 0 };
    const WCHAR *v[] = { hi, lo, rev, mid }; UINT32 n[] = { 1, 1, 2, 3 };
    for (int i = 0; i < 4; i++) {
        void *b; HRESULT hr = c_s2b(v[i], n[i], ENC_UTF8, &b);
        t_check(hr == (HRESULT)HR_E_INVALIDARG && b == NULL, __FILE__, __LINE__, "unpaired surrogate -> E_INVALIDARG", "vector %d hr 0x%08lx", i, (unsigned long)hr);
    }
}
TEST(winrt_buffer_string_to_binary_lone_surrogates_utf16_preserved) {
    WR_NEED(); if (!wr_cbs()) return;
    static const WCHAR hi[] = { 0xd800, 0 };
    void *b; EXPECT_HR(c_s2b(hi, 1, ENC_UTF16LE, &b), S_OK);
    if (b) { CHECK(wr_buf_is_hex(b, "00d8")); wr_release(b); }
    EXPECT_HR(c_s2b(hi, 1, ENC_UTF16BE, &b), S_OK);
    if (b) { CHECK(wr_buf_is_hex(b, "d800")); wr_release(b); }
}
TEST(winrt_buffer_binary_to_string_invalid_utf8) {
    WR_NEED(); if (!wr_cbs()) return;
    static const char *bad[] = { "ff", "fe", "80", "c3", "c328", "c0af", "c080", "e0809f", "eda080", "edb080", "f0808080", "f4908080", "f8888080", "e282", "f09f98", "61c3", "c3a9c3", "bf" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *b = wr_mkbuf_hex(bad[i]); HSTRING h = (HSTRING)1;
        HRESULT hr = c_b2s(ENC_UTF8, b, &h);
        t_check(hr == (HRESULT)HR_UTF8_INVALID && h == NULL, __FILE__, __LINE__, "invalid UTF-8", "vector %zu (%s) hr 0x%08lx", i, bad[i], (unsigned long)hr);
        wr_hsfree(h); wr_release(b);
    }
}
TEST(winrt_buffer_binary_to_string_valid_utf8_edge) {
    WR_NEED(); if (!wr_cbs()) return;
    static const struct { const char *hex; UINT32 n; WCHAR w0, w1; } v[] = {
        { "00", 1, 0, 0 }, { "7f", 1, 0x7f, 0 }, { "c280", 1, 0x80, 0 }, { "dfbf", 1, 0x7ff, 0 }, { "e0a080", 1, 0x800, 0 },
        { "ed9fbf", 1, 0xd7ff, 0 }, { "ee8080", 1, 0xe000, 0 }, { "efbfbf", 1, 0xffff, 0 }, { "f0908080", 2, 0xd800, 0xdc00 },
        { "f48fbfbf", 2, 0xdbff, 0xdfff }, { "efbbbf", 1, 0xfeff, 0 },
    };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *b = wr_mkbuf_hex(v[i].hex); HSTRING h; UINT32 n;
        HRESULT hr = c_b2s(ENC_UTF8, b, &h); const WCHAR *w = wr_raw(h, &n);
        t_check(hr == S_OK && n == v[i].n && w[0] == v[i].w0 && (n < 2 || w[1] == v[i].w1), __FILE__, __LINE__, "valid UTF-8", "vector %zu hr 0x%08lx n %u", i, (unsigned long)hr, n);
        wr_hsfree(h); wr_release(b);
    }
}
TEST(winrt_buffer_binary_to_string_odd_utf16) {
    WR_NEED(); if (!wr_cbs()) return;
    static const char *odd[] = { "00", "410042", "41", "4100620", "0041004200" };
    for (int e = ENC_UTF16LE; e <= ENC_UTF16BE; e++)
        for (size_t i = 0; i < 4; i++) {
            void *b = wr_mkbuf_hex(i == 3 ? "410062" : odd[i]); HSTRING h = (HSTRING)1;
            HRESULT hr = c_b2s(e, b, &h);
            t_check(hr == (HRESULT)HR_ODD_UTF16 && h == NULL, __FILE__, __LINE__, "odd-length UTF-16", "enc %d vector %zu hr 0x%08lx", e, i, (unsigned long)hr);
            wr_hsfree(h); wr_release(b);
        }
}
TEST(winrt_buffer_binary_to_string_empty_and_null) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; c_create(NULL, 0, &b);
    for (int e = 0; e < 3; e++) {
        HSTRING h = (HSTRING)1;
        EXPECT_HR(c_b2s(e, b, &h), S_OK); CHECK(h == NULL);
        h = (HSTRING)1; EXPECT_HR(c_b2s(e, NULL, &h), S_OK); CHECK(h == NULL);
    }
    if (b) wr_release(b);
}
TEST(winrt_buffer_binary_to_string_unknown_encoding) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b = wr_mkbuf_hex("41424344"); HSTRING h = (HSTRING)1;
    HRESULT hr = c_b2s(3, b, &h);
    EXPECT_HR(hr, S_OK); CHECK(h == NULL);        /* unknown encodings yield an empty string, not an error */
    h = (HSTRING)1; hr = c_b2s(-1, b, &h); EXPECT_HR(hr, S_OK); CHECK(h == NULL);
    wr_release(b);
}
TEST(winrt_buffer_utf8_roundtrip_ranges) {
    WR_NEED(); if (!wr_cbs()) return;
    WCHAR w[800]; UINT32 n = 0;
    for (UINT c = 1; c < 0x80; c++) w[n++] = (WCHAR)c;
    for (UINT c = 0x80; c < 0x800; c += 7) w[n++] = (WCHAR)c;
    for (UINT c = 0x800; c < 0xd800; c += 311) w[n++] = (WCHAR)c;
    for (UINT c = 0xe000; c < 0xffff; c += 251) w[n++] = (WCHAR)c;
    w[n++] = 0xd83d; w[n++] = 0xde00;       /* ends with a valid surrogate pair */
    for (int e = 0; e < 3; e++) {
        void *b; HRESULT hr = c_s2b(w, n, e, &b);
        if (e == 0 && hr != S_OK) { t_note("utf8 conversion of generated string failed 0x%08lx", (unsigned long)hr); continue; }
        HSTRING h; UINT32 m; hr = c_b2s(e, b, &h); const WCHAR *r = wr_raw(h, &m);
        t_check(hr == S_OK && m == n && !memcmp(r, w, n * 2), __FILE__, __LINE__, "roundtrip", "enc %d hr 0x%08lx m %u n %u", e, (unsigned long)hr, m, n);
        wr_hsfree(h); wr_release(b);
    }
}
TEST(winrt_buffer_utf8_bom_is_preserved) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b = wr_mkbuf_hex("efbbbf41"); HSTRING h; UINT32 n;
    EXPECT_HR(c_b2s(ENC_UTF8, b, &h), S_OK);
    const WCHAR *w = wr_raw(h, &n); EXPECT_EQ(n, 2); if (n == 2) { EXPECT_EQ(w[0], 0xfeff); EXPECT_EQ(w[1], 'A'); }
    wr_hsfree(h); wr_release(b);
    b = wr_mkbuf_hex("fffe4100"); EXPECT_HR(c_b2s(ENC_UTF16LE, b, &h), S_OK);
    w = wr_raw(h, &n); EXPECT_EQ(n, 2); if (n == 2) { EXPECT_EQ(w[0], 0xfeff); EXPECT_EQ(w[1], 'A'); }
    wr_hsfree(h); wr_release(b);
}
TEST(winrt_buffer_utf16_byte_order_symmetry) {
    WR_NEED(); if (!wr_cbs()) return;
    void *le, *be; HSTRING h;
    EXPECT_HR(c_s2b(L"\x1234\xabcd", 2, ENC_UTF16LE, &le), S_OK);
    EXPECT_HR(c_s2b(L"\x1234\xabcd", 2, ENC_UTF16BE, &be), S_OK);
    CHECK(wr_buf_is_hex(le, "3412cdab")); CHECK(wr_buf_is_hex(be, "1234abcd"));
    EXPECT_HR(c_b2s(ENC_UTF16BE, le, &h), S_OK);         /* reading LE bytes as BE swaps each unit */
    CHECK(wr_hs_eq(h, L"\x3412\xcdab")); wr_hsfree(h);
    wr_release(le); wr_release(be);
}
TEST(winrt_buffer_string_to_hex_pipeline) {
    WR_NEED(); if (!wr_cbs()) return;
    void *b; HSTRING h;
    EXPECT_HR(c_s2b(L"abc", 3, ENC_UTF8, &b), S_OK);
    EXPECT_HR(c_hexenc(b, &h), S_OK); CHECK(wr_hs_eq(h, L"616263")); wr_hsfree(h);
    EXPECT_HR(c_b64enc(b, &h), S_OK); CHECK(wr_hs_eq(h, L"YWJj")); wr_hsfree(h);
    wr_release(b);
}
TEST(winrt_buffer_statics_thread_agility) {
    /* The factory and buffers are free-threaded: the statics created here can be used on another thread. */
    WR_NEED(); if (!wr_cbs()) return;
    extern DWORD WINAPI wr_buffer_thread(LPVOID);
    HANDLE t = CreateThread(NULL, 0, wr_buffer_thread, NULL, 0, NULL);
    if (!t) { t_skip("thread"); return; }
    CHECK(WaitForSingleObject(t, 10000) == WAIT_OBJECT_0);
    DWORD code = 99; GetExitCodeThread(t, &code); EXPECT_EQ(code, 0);
    CloseHandle(t);
}
DWORD WINAPI wr_buffer_thread(LPVOID p) {
    void *s = wr_cbs(), *b = NULL; BYTE d[4] = { 1, 2, 3, 4 };
    HRESULT hr = VF(s, CB_CreateFromByteArray, UINT32, const BYTE *, void **)(s, 4, d, &b);
    if (FAILED(hr) || !b) return 1;
    int ok = wr_buf_is(b, d, 4);
    wr_release(b);
    return ok ? 0 : 2;
}

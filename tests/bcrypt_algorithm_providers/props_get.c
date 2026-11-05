/* BCryptGetProperty on algorithm-provider handles (area bcrypt_algorithm_providers). */
#include "ap.h"

/* ------------------------------------------------------------------ helpers */
/* Buffer-size protocol for a property of exactly `want` bytes. Returns the status of the exact-size call. */
static NTSTATUS proto_blob(BCRYPT_HANDLE h, LPCWSTR prop, ULONG want, UCHAR *out /* >= want bytes */) {
    UCHAR buf[512];
    ULONG res;
    if (want == 0 || want > 400) return AP_INVALID_PARAM;
    /* size query */
    res = 0xdeadbeef;
    NT_OK(U(BCryptGetProperty)(h, prop, NULL, 0, &res, 0));
    EXPECT_EQ(res, want);
    res = 0xdeadbeef;
    NT_OK(U(BCryptGetProperty)(h, prop, NULL, 64, &res, 0));
    EXPECT_EQ(res, want);
    /* zero-size buffer */
    memset(buf, 0xA5, sizeof(buf)); res = 0xdeadbeef;
    NT_EQ(U(BCryptGetProperty)(h, prop, buf, 0, &res, 0), AP_BUF_TOO_SMALL);
    EXPECT_EQ(res, want);
    CHECK(buf[0] == 0xA5);
    /* one byte short */
    memset(buf, 0xA5, sizeof(buf)); res = 0xdeadbeef;
    NT_EQ(U(BCryptGetProperty)(h, prop, buf, want - 1, &res, 0), AP_BUF_TOO_SMALL);
    EXPECT_EQ(res, want);
    { int untouched = 1; for (ULONG i = 0; i < want; i++) if (buf[i] != 0xA5) untouched = 0; CHECK(untouched); }
    /* exact */
    memset(buf, 0xA5, sizeof(buf)); res = 0xdeadbeef;
    NTSTATUS s = U(BCryptGetProperty)(h, prop, buf, want, &res, 0);
    NT_OK(s);
    EXPECT_EQ(res, want);
    CHECK(buf[want] == 0xA5);
    if (out) memcpy(out, buf, want);
    /* oversized buffer: result is the true size, bytes past it untouched */
    memset(buf, 0xA5, sizeof(buf)); res = 0xdeadbeef;
    NT_OK(U(BCryptGetProperty)(h, prop, buf, want + 32, &res, 0));
    EXPECT_EQ(res, want);
    CHECK(buf[want] == 0xA5 && buf[want + 31] == 0xA5);
    return s;
}
static NTSTATUS proto_dw(BCRYPT_HANDLE h, LPCWSTR prop, ULONG *val) {
    UCHAR b[4] = { 0 };
    NTSTATUS s = proto_blob(h, prop, 4, b);
    if (val) memcpy(val, b, 4);
    return s;
}
static NTSTATUS getdw_flags(BCRYPT_HANDLE h, LPCWSTR p, ULONG fl) {
    ULONG v = 0, c = 0;
    return U(BCryptGetProperty)(h, p, (PUCHAR)&v, 4, &c, fl);
}
static void with_alg(const struct algd *a, void (*fn)(const struct algd *, BCRYPT_ALG_HANDLE)) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = AP_OPEN(&h, a->id, NULL, 0);
    if (s < 0) { if (a->hard) NT_OK(s); else t_note("%ls not available (0x%08lx)", a->id, (unsigned long)s); return; }
    fn(a, h);
    AP_CLOSE(h);
}

/* ------------------------------------------------------------------ generic, per algorithm */
static void f_name(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG want = (ULONG)(lstrlenW(a->id) + 1) * sizeof(WCHAR), res;
    WCHAR buf[64];
    res = 0;
    NTSTATUS s = AP_GET(h, BCRYPT_ALGORITHM_NAME, NULL, 0, &res);
    NT_OK(s);
    if (a->fam == F_ECDSA || a->fam == F_ECDH || a->fam == F_DH) {
        if (res != want) t_note("%ls AlgorithmName size %lu (expected %lu)", a->id, (unsigned long)res, (unsigned long)want);
        want = res;
    } else EXPECT_EQ(res, want);
    if (want == 0 || want > sizeof(buf)) return;
    memset(buf, 0xAA, sizeof(buf)); res = 0;
    NT_EQ(AP_GET(h, BCRYPT_ALGORITHM_NAME, buf, want - 2, &res), AP_BUF_TOO_SMALL);
    EXPECT_EQ(res, want);
    memset(buf, 0xAA, sizeof(buf)); res = 0;
    NT_OK(AP_GET(h, BCRYPT_ALGORITHM_NAME, buf, want, &res));
    EXPECT_EQ(res, want);
    CHECK(buf[want / 2 - 1] == 0);                  /* terminator is included in the count */
    if (a->fam == F_ECDSA || a->fam == F_ECDH || a->fam == F_DH) { if (lstrcmpW(buf, a->id)) t_note("%ls AlgorithmName is \"%ls\"", a->id, buf); }
    else CHECK(!lstrcmpW(buf, a->id));
    memset(buf, 0xAA, sizeof(buf)); res = 0;
    NT_OK(AP_GET(h, BCRYPT_ALGORITHM_NAME, buf, sizeof(buf), &res));
    EXPECT_EQ(res, want);
}
static void f_ptype(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 0xdeadbeef;
    NTSTATUS s = proto_dw(h, BCRYPT_PRIMITIVE_TYPE, &v);
    NT_OK(s);
    if (a->cls >= 0) EXPECT_EQ(v, a->cls);
    else t_note("%ls PrimitiveType=%lu", a->id, (unsigned long)v);
    CHECK(v >= 1 && v <= 7);
}
static void f_provh(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    UCHAR b[8] = { 0 };
    NT_OK(proto_blob(h, BCRYPT_PROVIDER_HANDLE, 8, b));
    ULONG_PTR p; memcpy(&p, b, 8);
    CHECK(p != 0);
}
static void f_badprop(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    static const WCHAR *const bad[] = { L"NoSuchProperty", L"algorithmname_x", L"ObjectLengthX", L"Object Length" };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        UCHAR buf[64]; ULONG res = 0xdeadbeef;
        NTSTATUS s = AP_GET(h, bad[i], buf, sizeof(buf), &res);
        NT_EQ(s, AP_NOT_SUPPORTED);
        s = AP_GET(h, bad[i], NULL, 0, &res);
        NT_EQ(s, AP_NOT_SUPPORTED);
    }
}
static void f_flags(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    /* a non-zero dwFlags is rejected (bit 0x80 is only meaningful for cipher KeyLengths) */
    static const ULONG fl[] = { 1, 2, 0x100, 0x80000000u };
    for (unsigned i = 0; i < sizeof(fl) / sizeof(fl[0]); i++) {
        NTSTATUS s = getdw_flags(h, BCRYPT_ALGORITHM_NAME, fl[i]);
        if (a->fam == F_DH) { if (s != AP_INVALID_PARAM) t_note("DH flags=0x%lx -> 0x%08lx", (unsigned long)fl[i], (unsigned long)s); }
        else NT_EQ(s, AP_INVALID_PARAM);
    }
}
static void f_keylens(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    if (a->fam == F_RNG || a->fam == F_HASH) {
        UCHAR b[16]; ULONG res = 0;
        NT_EQ(AP_GET(h, BCRYPT_KEY_LENGTHS, b, sizeof(b), &res), AP_NOT_SUPPORTED);
        return;
    }
    UCHAR raw[12];
    NTSTATUS s = proto_blob(h, BCRYPT_KEY_LENGTHS, 12, raw);
    NT_OK(s);
    BCRYPT_KEY_LENGTHS_STRUCT kl; memcpy(&kl, raw, 12);
    if (a->kmin < 0) {
        t_note("%ls KeyLengths min=%lu max=%lu inc=%lu", a->id, (unsigned long)kl.dwMinLength, (unsigned long)kl.dwMaxLength, (unsigned long)kl.dwIncrement);
        CHECK(kl.dwMinLength <= kl.dwMaxLength);
        return;
    }
    EXPECT_EQ(kl.dwMinLength, a->kmin);
    EXPECT_EQ(kl.dwMaxLength, a->kmax);
    EXPECT_EQ(kl.dwIncrement, a->kinc);
}
#define GEN_GEN(tag, ...) \
  TEST(ap_name_##tag)    { with_alg(&g_algs[A_##tag], f_name); } \
  TEST(ap_ptype_##tag)   { with_alg(&g_algs[A_##tag], f_ptype); } \
  TEST(ap_provh_##tag)   { with_alg(&g_algs[A_##tag], f_provh); } \
  TEST(ap_badprop_##tag) { with_alg(&g_algs[A_##tag], f_badprop); } \
  TEST(ap_flags_##tag)   { with_alg(&g_algs[A_##tag], f_flags); } \
  TEST(ap_keylens_##tag) { with_alg(&g_algs[A_##tag], f_keylens); }
ALG_LIST(GEN_GEN)

/* ------------------------------------------------------------------ argument validation of GetProperty */
TEST(ap_getprop_null_handle) {
    NEED_CORE();
    ULONG v = 0xdeadbeef, c = 0xdeadbeef;
    NT_EQ(U(BCryptGetProperty)(NULL, BCRYPT_OBJECT_LENGTH, (PUCHAR)&v, 4, &c, 0), AP_INVALID_HANDLE);
    NT_EQ(U(BCryptGetProperty)(NULL, BCRYPT_ALGORITHM_NAME, NULL, 0, &c, 0), AP_INVALID_HANDLE);
}
TEST(ap_getprop_null_or_empty_property) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0xdeadbeef, c = 0xdeadbeef;
    NT_EQ(U(BCryptGetProperty)(h, NULL, (PUCHAR)&v, 4, &c, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptGetProperty)(h, L"", (PUCHAR)&v, 4, &c, 0), AP_INVALID_PARAM);
    CHECK(v == 0xdeadbeef && c == 0xdeadbeef);
    AP_CLOSE(h);
}
TEST(ap_getprop_null_pcbresult) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0xdeadbeef;
    NT_EQ(U(BCryptGetProperty)(h, BCRYPT_OBJECT_LENGTH, (PUCHAR)&v, 4, NULL, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptGetProperty)(h, BCRYPT_OBJECT_LENGTH, NULL, 0, NULL, 0), AP_INVALID_PARAM);
    CHECK(v == 0xdeadbeef);
    AP_CLOSE(h);
}
TEST(ap_getprop_arg_order_property_before_handle) {
    NEED_CORE();
    /* parameter checks (property, pcbResult) precede handle validation */
    ULONG v = 0, c = 0;
    NT_EQ(U(BCryptGetProperty)(NULL, NULL, (PUCHAR)&v, 4, &c, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptGetProperty)(NULL, BCRYPT_OBJECT_LENGTH, (PUCHAR)&v, 4, NULL, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptGetProperty)(NULL, L"", (PUCHAR)&v, 4, &c, 0), AP_INVALID_PARAM);
}
TEST(ap_getprop_property_name_is_case_sensitive) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0, c = 0;
    NT_EQ(U(BCryptGetProperty)(h, L"objectlength", (PUCHAR)&v, 4, &c, 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptGetProperty)(h, L"OBJECTLENGTH", (PUCHAR)&v, 4, &c, 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptGetProperty)(h, L"blocklength", (PUCHAR)&v, 4, &c, 0), AP_NOT_SUPPORTED);
    NT_OK(U(BCryptGetProperty)(h, L"BlockLength", (PUCHAR)&v, 4, &c, 0));
    AP_CLOSE(h);
}
TEST(ap_getprop_hash_and_key_handle_types_accepted) {
    NEED_CORE(); REQUIRE(U(BCryptCreateHash)); REQUIRE(U(BCryptDestroyHash));
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_HASH_HANDLE hh = NULL;
    NT_OK(AP_OPEN(&a, BCRYPT_SHA256_ALGORITHM, NULL, 0));
    if (!a) return;
    NT_OK(U(BCryptCreateHash)(a, &hh, NULL, 0, NULL, 0, 0));
    if (hh) {
        ULONG v = 0, c = 0;
        NT_OK(ap_getdw(hh, BCRYPT_HASH_LENGTH, &v, &c));       /* hash objects answer the same property */
        EXPECT_EQ(v, 32);
        NT_OK(U(BCryptDestroyHash)(hh));
    }
    AP_CLOSE(a);
}

/* ------------------------------------------------------------------ symmetric ciphers */
#define SYM_TAGS(X) X(aes) X(des) X(des3) X(des3_112) X(desx) X(rc2) X(rc4)

static void f_sym_block(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 0;
    NT_OK(proto_dw(h, BCRYPT_BLOCK_LENGTH, &v));
    if (a->blk >= 0) EXPECT_EQ(v, a->blk); else t_note("%ls BlockLength=%lu", a->id, (unsigned long)v);
    CHECK(v >= 1);
    NT_OK(proto_dw(h, BCRYPT_BLOCK_SIZE_LIST, &v));
    if (a->blk >= 0 && v != (ULONG)a->blk) t_note("%ls BlockSizeList=%lu", a->id, (unsigned long)v);
}
static void f_sym_objlen(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 0;
    NT_OK(proto_dw(h, BCRYPT_OBJECT_LENGTH, &v));
    CHECK(v > 0 && v < 65536);
    t_note("%ls ObjectLength=%lu", a->id, (unsigned long)v);
}
static void f_sym_chain(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    WCHAR buf[64];
    if (t_is_wine()) { t_skip("emulator faults on ChainingMode size queries"); return; }
    /* cbResult is a fixed 64 bytes (a 32-WCHAR field), not the length of the mode string */
    UCHAR raw[64];
    NTSTATUS s = proto_blob(h, BCRYPT_CHAINING_MODE, 64, raw);
    NT_OK(s);
    memcpy(buf, raw, 64);
    buf[31] = 0;
    if (a->fam == F_SYM && a->mok != 0) CHECK(!lstrcmpW(buf, BCRYPT_CHAIN_MODE_CBC));  /* default mode is CBC */
    else t_note("%ls default ChainingMode=\"%ls\"", a->id, buf);
    ULONG res = 0;
    NT_EQ(AP_GET(h, BCRYPT_CHAINING_MODE, raw, 63, &res), AP_BUF_TOO_SMALL);
    EXPECT_EQ(res, 64);
}
static void f_sym_unsupported(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    static const WCHAR *const p[] = { BCRYPT_HASH_LENGTH, BCRYPT_HASH_BLOCK_LENGTH, BCRYPT_KEY_STRENGTH, BCRYPT_KEY_LENGTH, BCRYPT_SIGNATURE_LENGTH,
        BCRYPT_PADDING_SCHEMES, BCRYPT_INITIALIZATION_VECTOR, BCRYPT_IS_KEYED_HASH, BCRYPT_PUBLIC_KEY_LENGTH, NULL };
    for (unsigned i = 0; p[i]; i++) {
        UCHAR b[64]; ULONG res = 0;
        NT_EQ(AP_GET(h, p[i], b, sizeof(b), &res), AP_NOT_SUPPORTED);
    }
}
static void f_sym_msgblock(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 0;
    NT_OK(proto_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, &v));
    t_note("%ls default MessageBlockLength=%lu", a->id, (unsigned long)v);
}
static void f_sym_authtag(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    UCHAR b[12]; ULONG res = 0;
    /* only AES in CCM / GCM mode has an AuthTagLength */
    NTSTATUS s = AP_GET(h, BCRYPT_AUTH_TAG_LENGTH, b, sizeof(b), &res);
    NT_EQ(s, AP_NOT_SUPPORTED);
}
static void f_sym_effkey(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    UCHAR b[4]; ULONG res = 0;
    NTSTATUS s = AP_GET(h, BCRYPT_EFFECTIVE_KEY_LENGTH, b, sizeof(b), &res);
    if (a->id[0] == L'R' && a->id[1] == L'C' && a->id[2] == L'2') {
        NT_OK(s);
        ULONG v = 0; NT_OK(proto_dw(h, BCRYPT_EFFECTIVE_KEY_LENGTH, &v));
        t_note("RC2 default EffectiveKeyLength=%lu", (unsigned long)v);
    } else NT_EQ(s, AP_NOT_SUPPORTED);
}
#define GEN_SYM(tag) \
  TEST(ap_sym_block_##tag)       { with_alg(&g_algs[A_##tag], f_sym_block); } \
  TEST(ap_sym_objlen_##tag)      { with_alg(&g_algs[A_##tag], f_sym_objlen); } \
  TEST(ap_sym_chain_##tag)       { with_alg(&g_algs[A_##tag], f_sym_chain); } \
  TEST(ap_sym_unsupported_##tag) { with_alg(&g_algs[A_##tag], f_sym_unsupported); } \
  TEST(ap_sym_msgblock_##tag)    { with_alg(&g_algs[A_##tag], f_sym_msgblock); } \
  TEST(ap_sym_authtag_##tag)     { with_alg(&g_algs[A_##tag], f_sym_authtag); } \
  TEST(ap_sym_effkey_##tag)      { with_alg(&g_algs[A_##tag], f_sym_effkey); }
SYM_TAGS(GEN_SYM)

/* AES-specific: object length depends on the chaining mode, AuthTagLength is mode dependent. */
TEST(ap_aes_objectlength_by_mode) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG len[5] = { 0 };
    for (int m = 0; m < 5; m++) {
        NT_OK(AP_SET(h, BCRYPT_CHAINING_MODE, (PUCHAR)ap_mode_names[m], (lstrlenW(ap_mode_names[m]) + 1) * 2));
        NT_OK(ap_getdw(h, BCRYPT_OBJECT_LENGTH, &len[m], NULL));
        t_note("AES %ls ObjectLength=%lu", ap_mode_names[m], (unsigned long)len[m]);
    }
    /* only GCM carries the large GHASH tables */
    for (int m = 0; m < 4; m++) CHECK(len[m] == len[1]);
    CHECK(len[4] > len[1]);
    AP_CLOSE(h);
}
TEST(ap_aes_authtaglength_by_mode) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    static const struct { int m; int ok; ULONG mn, mx, inc; } c[] = {
        { 0, 0 }, { 1, 0 }, { 2, 0 }, { 3, 1, 4, 16, 2 }, { 4, 1, 12, 16, 1 } };
    for (unsigned i = 0; i < 5; i++) {
        NT_OK(AP_SET(h, BCRYPT_CHAINING_MODE, (PUCHAR)ap_mode_names[c[i].m], (lstrlenW(ap_mode_names[c[i].m]) + 1) * 2));
        UCHAR raw[12]; ULONG res = 0xdeadbeef;
        NTSTATUS s = AP_GET(h, BCRYPT_AUTH_TAG_LENGTH, raw, sizeof(raw), &res);
        if (!c[i].ok) { NT_EQ(s, AP_NOT_SUPPORTED); continue; }
        NT_OK(s);
        EXPECT_EQ(res, 12);
        BCRYPT_AUTH_TAG_LENGTHS_STRUCT t; memcpy(&t, raw, 12);
        EXPECT_EQ(t.dwMinLength, c[i].mn);
        EXPECT_EQ(t.dwMaxLength, c[i].mx);
        EXPECT_EQ(t.dwIncrement, c[i].inc);
        NT_OK(proto_blob(h, BCRYPT_AUTH_TAG_LENGTH, 12, NULL));
    }
    AP_CLOSE(h);
}
TEST(ap_aes_keylengths_flag_0x80) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    BCRYPT_KEY_LENGTHS_STRUCT kl = { 0 }; ULONG res = 0;
    NTSTATUS s = U(BCryptGetProperty)(h, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof(kl), &res, 0x80);
    t_note("AES KeyLengths flags=0x80 -> 0x%08lx min=%lu max=%lu inc=%lu", (unsigned long)s, (unsigned long)kl.dwMinLength, (unsigned long)kl.dwMaxLength, (unsigned long)kl.dwIncrement);
    CHECK(s == AP_OK || s == AP_INVALID_PARAM);
    AP_CLOSE(h);
}
TEST(ap_aes_variants_share_keylengths_and_block) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0));
    if (!h) return;
    for (int m = 0; m < 5; m++) {
        NT_OK(AP_SET(h, BCRYPT_CHAINING_MODE, (PUCHAR)ap_mode_names[m], (lstrlenW(ap_mode_names[m]) + 1) * 2));
        ULONG v = 0;
        NT_OK(ap_getdw(h, BCRYPT_BLOCK_LENGTH, &v, NULL)); EXPECT_EQ(v, 16);
        BCRYPT_KEY_LENGTHS_STRUCT kl = { 0 }; ULONG res = 0;
        NT_OK(AP_GET(h, BCRYPT_KEY_LENGTHS, &kl, sizeof(kl), &res));
        EXPECT_EQ(kl.dwMinLength, 128); EXPECT_EQ(kl.dwMaxLength, 256); EXPECT_EQ(kl.dwIncrement, 64);
    }
    AP_CLOSE(h);
}

/* ------------------------------------------------------------------ hashes */
#define HASH_TAGS(X) X(md2) X(md4) X(md5) X(sha1) X(sha256) X(sha384) X(sha512)

static void f_hash_len(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 0;
    NT_OK(proto_dw(h, BCRYPT_HASH_LENGTH, &v));
    EXPECT_EQ(v, a->hlen);
    NT_OK(proto_dw(h, BCRYPT_HASH_BLOCK_LENGTH, &v));
    EXPECT_EQ(v, a->hblk);
}
static void f_hash_objlen(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 0;
    NT_OK(proto_dw(h, BCRYPT_OBJECT_LENGTH, &v));
    CHECK(v > 0 && v < 65536);
    t_note("%ls ObjectLength=%lu", a->id, (unsigned long)v);
}
static void f_hash_unsupported(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    static const WCHAR *const p[] = { BCRYPT_BLOCK_LENGTH, BCRYPT_KEY_LENGTHS, BCRYPT_CHAINING_MODE, BCRYPT_KEY_STRENGTH, BCRYPT_SIGNATURE_LENGTH, BCRYPT_PADDING_SCHEMES, BCRYPT_AUTH_TAG_LENGTH, NULL };
    for (unsigned i = 0; p[i]; i++) {
        UCHAR b[64]; ULONG res = 0;
        NT_EQ(AP_GET(h, p[i], b, sizeof(b), &res), AP_NOT_SUPPORTED);
    }
}
static void f_hash_oid(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG res = 0;
    NT_OK(AP_GET(h, BCRYPT_HASH_OID_LIST, NULL, 0, &res));
    CHECK(res >= 16);
    if (res < 16 || res > 2048) return;
    UCHAR buf[2048];
    NT_EQ(AP_GET(h, BCRYPT_HASH_OID_LIST, buf, res - 1, &res), AP_BUF_TOO_SMALL);
    ULONG need = 0; NT_OK(AP_GET(h, BCRYPT_HASH_OID_LIST, NULL, 0, &need));
    EXPECT_EQ(res, need);
    memset(buf, 0, sizeof(buf));
    ULONG got = 0;
    NT_OK(AP_GET(h, BCRYPT_HASH_OID_LIST, buf, need, &got));
    EXPECT_EQ(got, need);
    ULONG cnt; memcpy(&cnt, buf, 4);
    t_note("%ls HashOIDList count=%lu bytes=%lu", a->id, (unsigned long)cnt, (unsigned long)need);
    CHECK(cnt >= 1 && cnt < 8);
    /* BCRYPT_OID_LIST { ULONG dwOIDCount; BCRYPT_OID *pOIDs } where BCRYPT_OID { ULONG cbOID; PUCHAR pbOID } */
    BCRYPT_OID_LIST *l = (BCRYPT_OID_LIST *)buf;
    CHECK((UCHAR *)l->pOIDs >= buf && (UCHAR *)(l->pOIDs + cnt) <= buf + need);
    if ((UCHAR *)l->pOIDs >= buf && (UCHAR *)(l->pOIDs + cnt) <= buf + need) {
        for (ULONG i = 0; i < cnt; i++) {
            if (!wcscmp(a->id, L"MD5") && i == 2) {
                /* observed on Win10: MD5 reports count=3 but the third entry is empty */
                EXPECT_EQ(l->pOIDs[i].cbOID, 0);
                CHECK(l->pOIDs[i].pbOID == NULL);
                continue;
            }
            CHECK(l->pOIDs[i].cbOID >= 2);
            CHECK(l->pOIDs[i].pbOID >= buf && l->pOIDs[i].pbOID + l->pOIDs[i].cbOID <= buf + need);
            if (l->pOIDs[i].pbOID >= buf && l->pOIDs[i].pbOID + l->pOIDs[i].cbOID <= buf + need)
                CHECK(l->pOIDs[i].pbOID[0] == 0x06);                 /* DER OBJECT IDENTIFIER */
        }
    }
}
#define GEN_HASH(tag) \
  TEST(ap_hash_len_##tag)         { with_alg(&g_algs[A_##tag], f_hash_len); } \
  TEST(ap_hash_objlen_##tag)      { with_alg(&g_algs[A_##tag], f_hash_objlen); } \
  TEST(ap_hash_unsupported_##tag) { with_alg(&g_algs[A_##tag], f_hash_unsupported); } \
  TEST(ap_hash_oid_##tag)         { with_alg(&g_algs[A_##tag], f_hash_oid); }
HASH_TAGS(GEN_HASH)

TEST(ap_hash_multiobjectlength) {
    NEED_CORE();
    for (int i = 0; i < 7; i++) {
        static const int idx[7] = { A_md2, A_md4, A_md5, A_sha1, A_sha256, A_sha384, A_sha512 };
        BCRYPT_ALG_HANDLE h = NULL;
        NT_OK(ap_open_alg(&g_algs[idx[i]], &h, 0));
        if (!h) continue;
        UCHAR b[8]; ULONG res = 0xdeadbeef;
        NTSTATUS s = AP_GET(h, L"MultiObjectLength", NULL, 0, &res);
        t_note("%ls MultiObjectLength size query -> 0x%08lx cb=%lu", g_algs[idx[i]].id, (unsigned long)s, (unsigned long)res);
        if (s >= 0) {
            EXPECT_EQ(res, 8);
            NT_EQ(AP_GET(h, L"MultiObjectLength", b, 7, &res), AP_BUF_TOO_SMALL);
            NT_OK(AP_GET(h, L"MultiObjectLength", b, 8, &res));
            ULONG v[2]; memcpy(v, b, 8);
            t_note("  per-object=%lu base=%lu", (unsigned long)v[0], (unsigned long)v[1]);
        }
        AP_CLOSE(h);
    }
}
TEST(ap_hash_hmac_flag_properties_match_plain) {
    NEED_CORE();
    static const int idx[7] = { A_md2, A_md4, A_md5, A_sha1, A_sha256, A_sha384, A_sha512 };
    for (int i = 0; i < 7; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NT_OK(AP_OPEN(&h, g_algs[idx[i]].id, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG));
        if (!h) continue;
        ULONG v;
        NT_OK(proto_dw(h, BCRYPT_HASH_LENGTH, &v)); EXPECT_EQ(v, g_algs[idx[i]].hlen);
        NT_OK(proto_dw(h, BCRYPT_HASH_BLOCK_LENGTH, &v)); EXPECT_EQ(v, g_algs[idx[i]].hblk);
        WCHAR nm[64]; ULONG cb;
        NT_OK(ap_getstr(h, BCRYPT_ALGORITHM_NAME, nm, 64, &cb));
        if (lstrcmpW(nm, g_algs[idx[i]].id)) t_note("HMAC-flag %ls handle reports name \"%ls\"", g_algs[idx[i]].id, nm);
        NT_OK(proto_dw(h, BCRYPT_IS_KEYED_HASH, &v)); EXPECT_EQ(v, 1);
        AP_CLOSE(h);
    }
}
TEST(ap_hash_cmac_gmac_open) {
    NEED_CORE();
    static const WCHAR *const id[] = { BCRYPT_AES_CMAC_ALGORITHM, BCRYPT_AES_GMAC_ALGORITHM };
    for (int i = 0; i < 2; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NTSTATUS s = AP_OPEN(&h, id[i], NULL, 0);
        t_note("%ls open -> 0x%08lx", id[i], (unsigned long)s);
        if (s < 0) continue;
        ULONG v = 0, cb = 0;
        s = ap_getdw(h, BCRYPT_HASH_LENGTH, &v, &cb); t_note("  HashDigestLength 0x%08lx %lu", (unsigned long)s, (unsigned long)v);
        s = ap_getdw(h, BCRYPT_IS_KEYED_HASH, &v, &cb); t_note("  IsKeyedHash 0x%08lx %lu", (unsigned long)s, (unsigned long)v);
        s = ap_getdw(h, BCRYPT_OBJECT_LENGTH, &v, &cb); t_note("  ObjectLength 0x%08lx %lu", (unsigned long)s, (unsigned long)v);
        AP_CLOSE(h);
    }
}

/* ------------------------------------------------------------------ RNG */
TEST(ap_rng_properties_not_supported) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_RNG_ALGORITHM, NULL, 0));
    if (!h) return;
    static const WCHAR *const p[] = { BCRYPT_OBJECT_LENGTH, BCRYPT_HASH_LENGTH, BCRYPT_BLOCK_LENGTH, BCRYPT_KEY_LENGTHS, BCRYPT_CHAINING_MODE, BCRYPT_HASH_BLOCK_LENGTH, BCRYPT_SIGNATURE_LENGTH, NULL };
    for (unsigned i = 0; p[i]; i++) {
        ULONG v = 0xdeadbeef, c = 0xdeadbeef;
        NT_EQ(U(BCryptGetProperty)(h, p[i], (PUCHAR)&v, 4, &c, 0), AP_NOT_SUPPORTED);
        CHECK(v == 0xdeadbeef);
    }
    AP_CLOSE(h);
}
TEST(ap_rng_name_variants) {
    NEED_CORE();
    static const struct { const WCHAR *id; } r[] = { { L"RNG" }, { L"FIPS186DSARNG" }, { L"DUALECRNG" } };
    for (int i = 0; i < 3; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NTSTATUS s = AP_OPEN(&h, r[i].id, NULL, 0);
        if (s < 0) { t_note("%ls unavailable 0x%08lx", r[i].id, (unsigned long)s); continue; }
        WCHAR nm[40]; ULONG cb;
        NT_OK(ap_getstr(h, BCRYPT_ALGORITHM_NAME, nm, 40, &cb));
        CHECK(!lstrcmpW(nm, r[i].id));
        AP_CLOSE(h);
    }
}

/* ------------------------------------------------------------------ asymmetric */
TEST(ap_rsa_paddingschemes_and_keylengths) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL, hs = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_RSA_ALGORITHM, NULL, 0));
    NT_OK(AP_OPEN(&hs, BCRYPT_RSA_SIGN_ALGORITHM, NULL, 0));
    ULONG v = 0;
    if (h) { NT_OK(proto_dw(h, BCRYPT_PADDING_SCHEMES, &v)); EXPECT_EQ(v, 0x1e); }
    if (hs) { NT_OK(proto_dw(hs, BCRYPT_PADDING_SCHEMES, &v)); EXPECT_EQ(v, 0x14); }
    if (h) AP_CLOSE(h);
    if (hs) AP_CLOSE(hs);
}
TEST(ap_rsa_alg_has_no_key_properties) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_RSA_ALGORITHM, NULL, 0));
    if (!h) return;
    static const WCHAR *const p[] = { BCRYPT_KEY_STRENGTH, BCRYPT_KEY_LENGTH, BCRYPT_PUBLIC_KEY_LENGTH, BCRYPT_BLOCK_LENGTH, BCRYPT_SIGNATURE_LENGTH, BCRYPT_OBJECT_LENGTH, BCRYPT_HASH_LENGTH, NULL };
    for (unsigned i = 0; p[i]; i++) {
        ULONG v = 0xdeadbeef, c = 0xdeadbeef;
        NTSTATUS s = U(BCryptGetProperty)(h, p[i], (PUCHAR)&v, 4, &c, 0);
        NT_EQ(s, AP_NOT_SUPPORTED);
    }
    AP_CLOSE(h);
}
TEST(ap_rsa_algname_sizes) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL, hs = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_RSA_ALGORITHM, NULL, 0));
    NT_OK(AP_OPEN(&hs, BCRYPT_RSA_SIGN_ALGORITHM, NULL, 0));
    ULONG c = 0;
    if (h) { NT_OK(AP_GET(h, BCRYPT_ALGORITHM_NAME, NULL, 0, &c)); EXPECT_EQ(c, 8); }
    if (hs) { NT_OK(AP_GET(hs, BCRYPT_ALGORITHM_NAME, NULL, 0, &c)); EXPECT_EQ(c, 18); }
    if (h) AP_CLOSE(h);
    if (hs) AP_CLOSE(hs);
}
TEST(ap_dsa_dh_alg_only_keylengths) {
    NEED_CORE();
    static const WCHAR *const algs[] = { BCRYPT_DSA_ALGORITHM, BCRYPT_DH_ALGORITHM };
    for (int i = 0; i < 2; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NT_OK(AP_OPEN(&h, algs[i], NULL, 0));
        if (!h) continue;
        static const WCHAR *const p[] = { BCRYPT_OBJECT_LENGTH, BCRYPT_BLOCK_LENGTH, BCRYPT_KEY_STRENGTH, BCRYPT_KEY_LENGTH, BCRYPT_HASH_LENGTH, BCRYPT_SIGNATURE_LENGTH, NULL };
        for (unsigned j = 0; p[j]; j++) {
            ULONG v = 0, c = 0;
            NT_EQ(U(BCryptGetProperty)(h, p[j], (PUCHAR)&v, 4, &c, 0), AP_NOT_SUPPORTED);
        }
        AP_CLOSE(h);
    }
}

/* ------------------------------------------------------------------ ECC */
static void f_ecc_curve(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    WCHAR buf[40]; ULONG res = 0;
    NT_OK(AP_GET(h, BCRYPT_ECC_CURVE_NAME, NULL, 0, &res));
    EXPECT_EQ(res, (lstrlenW(a->curve) + 1) * 2);
    if (res == 0 || res > sizeof(buf)) return;
    NT_EQ(AP_GET(h, BCRYPT_ECC_CURVE_NAME, buf, res - 2, &res), AP_BUF_TOO_SMALL);
    memset(buf, 0, sizeof(buf));
    NT_OK(AP_GET(h, BCRYPT_ECC_CURVE_NAME, buf, sizeof(buf), &res));
    CHECK(!lstrcmpW(buf, a->curve));
}
static void f_ecc_params(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG res = 0;
    NT_OK(AP_GET(h, BCRYPT_ECC_PARAMETERS, NULL, 0, &res));
    CHECK(res > 28 && res < 1024);
    if (res <= 28 || res >= 1024) return;
    UCHAR buf[1024];
    NT_EQ(AP_GET(h, BCRYPT_ECC_PARAMETERS, buf, res - 1, &res), AP_BUF_TOO_SMALL);
    ULONG got = 0;
    memset(buf, 0, sizeof(buf));
    NT_OK(AP_GET(h, BCRYPT_ECC_PARAMETERS, buf, res, &got));
    EXPECT_EQ(got, res);
    const ULONG *d = (const ULONG *)buf;   /* ECC_PARAMETER_HEADER: ver, type, genAlg, cbField, cbOrder, cbCofactor, cbSeed */
    EXPECT_EQ(d[0], 1);
    EXPECT_EQ(d[1], 1);                    /* short Weierstrass */
    ULONG cbf = (ULONG)((a->curvebits + 7) / 8);
    EXPECT_EQ(d[3], cbf);
    EXPECT_EQ(d[4], cbf);
    EXPECT_EQ(d[5], 1);
    EXPECT_EQ(res, 28 + 5 * d[3] + d[4] + d[5] + d[6]);
}
static void f_ecc_namelist(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG res = 0;
    NTSTATUS s = AP_GET(h, BCRYPT_ECC_CURVE_NAME_LIST, NULL, 0, &res);
    NT_OK(s);
    if (s < 0 || res < 16 || res > 8192) return;
    UCHAR buf[8192];
    NT_EQ(AP_GET(h, BCRYPT_ECC_CURVE_NAME_LIST, buf, res - 1, &res), AP_BUF_TOO_SMALL);
    ULONG got = 0;
    NT_OK(AP_GET(h, BCRYPT_ECC_CURVE_NAME_LIST, buf, res, &got));
    EXPECT_EQ(got, res);
    ULONG cnt = *(ULONG *)buf;
    CHECK(cnt >= 3 && cnt < 64);
    int seen256 = 0, seen384 = 0, seen521 = 0;
    const WCHAR **names = *(const WCHAR ***)(buf + 8);
    int inside = (UCHAR *)names >= buf && (UCHAR *)(names + cnt) <= buf + got;
    CHECK(inside);
    if (inside) for (ULONG i = 0; i < cnt; i++) {
        const WCHAR *n = names[i];
        if ((UCHAR *)n < buf || (UCHAR *)n >= buf + got) { CHECK(0); continue; }
        if (!lstrcmpW(n, L"nistP256")) seen256 = 1;
        if (!lstrcmpW(n, L"nistP384")) seen384 = 1;
        if (!lstrcmpW(n, L"nistP521")) seen521 = 1;
    }
    CHECK(seen256 && seen384 && seen521);
}
static void f_ecc_unsupported(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    static const WCHAR *const p[] = { BCRYPT_OBJECT_LENGTH, BCRYPT_BLOCK_LENGTH, BCRYPT_SIGNATURE_LENGTH, BCRYPT_KEY_STRENGTH, BCRYPT_KEY_LENGTH, BCRYPT_HASH_LENGTH, NULL };
    for (unsigned i = 0; p[i]; i++) {
        UCHAR b[16]; ULONG c = 0;
        NT_EQ(AP_GET(h, p[i], b, sizeof(b), &c), AP_NOT_SUPPORTED);
    }
}
#define ECC_TAGS(X) X(ecdsa256) X(ecdsa384) X(ecdsa521) X(ecdh256) X(ecdh384) X(ecdh521)
#define GEN_ECC(tag) \
  TEST(ap_ecc_curve_##tag)       { with_alg(&g_algs[A_##tag], f_ecc_curve); } \
  TEST(ap_ecc_params_##tag)      { with_alg(&g_algs[A_##tag], f_ecc_params); } \
  TEST(ap_ecc_namelist_##tag)    { with_alg(&g_algs[A_##tag], f_ecc_namelist); } \
  TEST(ap_ecc_unsupported_##tag) { with_alg(&g_algs[A_##tag], f_ecc_unsupported); }
ECC_TAGS(GEN_ECC)

TEST(ap_ecc_generic_algs) {
    NEED_CORE();
    static const WCHAR *const id[] = { L"ECDSA", L"ECDH" };
    for (int i = 0; i < 2; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NTSTATUS s = AP_OPEN(&h, id[i], NULL, 0);
        t_note("%ls open -> 0x%08lx", id[i], (unsigned long)s);
        if (s < 0) continue;
        BCRYPT_KEY_LENGTHS_STRUCT kl = { 0 }; ULONG res = 0;
        s = AP_GET(h, BCRYPT_KEY_LENGTHS, &kl, sizeof(kl), &res);
        t_note("  KeyLengths 0x%08lx min=%lu max=%lu inc=%lu", (unsigned long)s, (unsigned long)kl.dwMinLength, (unsigned long)kl.dwMaxLength, (unsigned long)kl.dwIncrement);
        WCHAR nm[40];
        s = AP_GET(h, BCRYPT_ECC_CURVE_NAME, nm, sizeof(nm), &res);
        t_note("  ECCCurveName without curve -> 0x%08lx", (unsigned long)s);
        AP_CLOSE(h);
    }
}

/* ------------------------------------------------------------------ key derivation */
#define KD_TAGS(X) X(sp800108) X(sp80056a) X(pbkdf2) X(capikdf) X(hkdf) X(tls11) X(tls12)
static void f_kd_objlen(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 0;
    NT_OK(proto_dw(h, BCRYPT_OBJECT_LENGTH, &v));
    t_note("%ls ObjectLength=%lu", a->id, (unsigned long)v);
}
static void f_kd_unsupported(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    static const WCHAR *const p[] = { BCRYPT_BLOCK_LENGTH, BCRYPT_HASH_LENGTH, BCRYPT_CHAINING_MODE, BCRYPT_KEY_STRENGTH, BCRYPT_SIGNATURE_LENGTH, BCRYPT_PADDING_SCHEMES, NULL };
    for (unsigned i = 0; p[i]; i++) {
        UCHAR b[64]; ULONG res = 0;
        NT_EQ(AP_GET(h, p[i], b, sizeof(b), &res), AP_NOT_SUPPORTED);
    }
}
#define GEN_KD(tag) \
  TEST(ap_kd_objlen_##tag)      { with_alg(&g_algs[A_##tag], f_kd_objlen); } \
  TEST(ap_kd_unsupported_##tag) { with_alg(&g_algs[A_##tag], f_kd_unsupported); }
KD_TAGS(GEN_KD)

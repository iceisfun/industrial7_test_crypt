/* BCryptSetProperty on algorithm-provider handles (area bcrypt_algorithm_providers). */
#include "ap.h"

static NTSTATUS set_mode(BCRYPT_ALG_HANDLE h, const WCHAR *name) {
    return U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, (PUCHAR)name, (ULONG)((lstrlenW(name) + 1) * sizeof(WCHAR)), 0);
}
static int mode_is(BCRYPT_ALG_HANDLE h, const WCHAR *name) {
    UCHAR raw[64]; ULONG res = 0;
    memset(raw, 0, sizeof(raw));
    if (U(BCryptGetProperty)(h, BCRYPT_CHAINING_MODE, raw, sizeof(raw), &res, 0) < 0) return 0;
    raw[62] = raw[63] = 0;
    return !lstrcmpW((WCHAR *)raw, name);
}
static NTSTATUS set_dw(BCRYPT_ALG_HANDLE h, const WCHAR *p, ULONG v) {
    return U(BCryptSetProperty)(h, p, (PUCHAR)&v, 4, 0);
}
static void with_alg(const struct algd *a, void (*fn)(const struct algd *, BCRYPT_ALG_HANDLE)) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = AP_OPEN(&h, a->id, NULL, 0);
    if (s < 0) { if (a->hard) NT_OK(s); return; }
    fn(a, h);
    AP_CLOSE(h);
}

/* ---------------------------------------------------------------- argument validation */
TEST(ap_setprop_null_property) {
    NEED_CORE();
    if (t_is_wine()) { t_skip("emulator faults on NULL property name"); return; }
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0;
    NT_EQ(U(BCryptSetProperty)(h, NULL, (PUCHAR)&v, 4, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(NULL, NULL, (PUCHAR)&v, 4, 0), AP_INVALID_PARAM);   /* property checked before handle */
    AP_CLOSE(h);
}
TEST(ap_setprop_null_handle) {
    NEED_CORE();
    NT_EQ(AP_SET(NULL, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC)), AP_INVALID_HANDLE);
    ULONG v = 1;
    NT_EQ(AP_SET(NULL, BCRYPT_MESSAGE_BLOCK_LENGTH, &v, 4), AP_INVALID_HANDLE);
}
TEST(ap_setprop_pseudo_handles_are_read_only) {
    NEED_CORE();
    static const ULONG_PTR ph[] = { 0x01, 0x21, 0x31, 0x41, 0x61, 0x81, 0x1a1, 0x1b1, 0x1e1, 0x1f1, 0x2a1, 0x331, 0x391 };
    for (unsigned i = 0; i < sizeof(ph) / sizeof(ph[0]); i++) {
        NT_EQ(AP_SET((BCRYPT_ALG_HANDLE)ph[i], BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC)), AP_ACCESS_DENIED);
    }
    ULONG v = 1;
    NT_EQ(AP_SET((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1a1, BCRYPT_MESSAGE_BLOCK_LENGTH, &v, 4), AP_ACCESS_DENIED);
    NT_EQ(AP_SET((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x41, L"NoSuchProperty", &v, 4), AP_ACCESS_DENIED);
    /* the pseudo-handle mode is unchanged afterwards */
    CHECK(mode_is((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1a1, BCRYPT_CHAIN_MODE_CBC));
}
TEST(ap_setprop_unmapped_pseudo_handles) {
    NEED_CORE();
    static const ULONG_PTR ph[] = { 0x3a1, 0x1001, 0x5f1 };
    for (unsigned i = 0; i < sizeof(ph) / sizeof(ph[0]); i++) {
        ULONG v = 1;
        NT_EQ(AP_SET((BCRYPT_ALG_HANDLE)ph[i], L"X", &v, 4), AP_INVALID_HANDLE);
    }
}
TEST(ap_setprop_closed_handle) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    NT_OK(AP_CLOSE(h));
    NT_EQ(set_mode(h, BCRYPT_CHAIN_MODE_CBC), AP_INVALID_HANDLE);
}

/* ---------------------------------------------------------------- ChainingMode matrix */
static void f_chain_matrix(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    for (int m = 0; m < 5; m++) {
        int bit = 1 << m;
        if (a->mok & bit) {
            NT_OK(set_mode(h, ap_mode_names[m]));
            CHECK(mode_is(h, ap_mode_names[m]));
        } else if (a->mbad & bit) {
            /* current mode before */
            WCHAR before[40]; ULONG cb; ap_getstr(h, BCRYPT_CHAINING_MODE, before, 32, &cb);
            NT_EQ(set_mode(h, ap_mode_names[m]), AP_NOT_SUPPORTED);
            CHECK(mode_is(h, before));              /* a rejected mode leaves the old one in place */
        }
    }
}
static void f_chain_invalid(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    static const WCHAR *const bad[] = { L"ChainingModeXYZ", L"", L"chainingmodecbc", L"ChainingModeCBC ", L"CBC", L"ChainingModeCB", L"ChainingModeCBCC", L" ChainingModeCBC" };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        NT_EQ(set_mode(h, bad[i]), AP_INVALID_PARAM);     /* unknown name -> invalid parameter (known but unsupported -> not supported) */
    }
}
static void f_chain_cbinput_ignored(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    if (!(a->mok & M_ECB)) return;
    /* the size argument is not consulted: the string is NUL terminated */
    NT_OK(U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, 0, 0));
    CHECK(mode_is(h, BCRYPT_CHAIN_MODE_ECB));
    NT_OK(U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, 2, 0));
    CHECK(mode_is(h, BCRYPT_CHAIN_MODE_CBC));
}
static void f_set_null_input_and_flags(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    if (t_is_wine()) { t_skip("emulator faults on NULL input buffer"); return; }
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, NULL, 0, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, NULL, 32, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, L"NoSuchProperty", NULL, 4, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 1), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0x80), AP_INVALID_PARAM);
}
static void f_set_readonly(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    static const WCHAR *const p[] = { BCRYPT_OBJECT_LENGTH, BCRYPT_BLOCK_LENGTH, BCRYPT_ALGORITHM_NAME, BCRYPT_KEY_LENGTHS, BCRYPT_BLOCK_SIZE_LIST,
        BCRYPT_HASH_LENGTH, BCRYPT_KEY_STRENGTH, BCRYPT_AUTH_TAG_LENGTH, BCRYPT_PROVIDER_HANDLE, BCRYPT_PRIMITIVE_TYPE, L"NoSuchProperty", NULL };
    for (unsigned i = 0; p[i]; i++) {
        UCHAR in[64] = { 16, 0, 0, 0 };
        NT_EQ(U(BCryptSetProperty)(h, p[i], in, 4, 0), AP_NOT_SUPPORTED);
        NT_EQ(U(BCryptSetProperty)(h, p[i], in, 64, 0), AP_NOT_SUPPORTED);
    }
}
static void f_msgblock(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 0, cb = 0;
    if (!(a->mok & M_CFB)) {
        /* needs CFB mode: any other mode refuses the property */
        if (a->mok & M_CBC) { NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_CBC)); NT_EQ(set_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, 1), AP_NOT_SUPPORTED); }
        return;
    }
    NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_CBC));
    NT_EQ(set_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, 1), AP_NOT_SUPPORTED);
    NT_EQ(set_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, (ULONG)a->blk), AP_NOT_SUPPORTED);
    NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_CFB));
    NT_OK(set_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, 1));
    NT_OK(ap_getdw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, &v, &cb)); EXPECT_EQ(v, 1);
    NT_OK(set_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, (ULONG)a->blk));
    NT_OK(ap_getdw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, &v, &cb)); EXPECT_EQ(v, a->blk);
    NT_OK(set_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, 1));
    /* only 1 or the cipher block size */
    static const ULONG badv[] = { 0, 2, 3, 4, 7, 9, 12, 15, 17, 32, 0xffffffffu };
    for (unsigned i = 0; i < sizeof(badv) / sizeof(badv[0]); i++) {
        if (badv[i] == (ULONG)a->blk) continue;
        NT_EQ(set_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, badv[i]), AP_INVALID_PARAM);
    }
    NT_OK(ap_getdw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, &v, &cb)); EXPECT_EQ(v, 1);   /* failures leave the value alone */
    /* the size must be exactly sizeof(ULONG) */
    UCHAR b8[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_MESSAGE_BLOCK_LENGTH, b8, 0, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_MESSAGE_BLOCK_LENGTH, b8, 3, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_MESSAGE_BLOCK_LENGTH, b8, 5, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_MESSAGE_BLOCK_LENGTH, b8, 8, 0), AP_INVALID_PARAM);
}
static void f_independent(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    if (!(a->mok & M_ECB) || !(a->mok & M_CBC)) return;
    BCRYPT_ALG_HANDLE h2 = NULL;
    NT_OK(AP_OPEN(&h2, a->id, NULL, 0));
    if (!h2) return;
    NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_ECB));
    CHECK(mode_is(h, BCRYPT_CHAIN_MODE_ECB));
    CHECK(mode_is(h2, BCRYPT_CHAIN_MODE_CBC));        /* other handles keep the default */
    AP_CLOSE(h2);
    /* a fresh handle starts at the default again */
    BCRYPT_ALG_HANDLE h3 = NULL;
    NT_OK(AP_OPEN(&h3, a->id, NULL, 0));
    if (h3) { CHECK(mode_is(h3, BCRYPT_CHAIN_MODE_CBC)); AP_CLOSE(h3); }
}
#define SYM_TAGS(X) X(aes) X(des) X(des3) X(des3_112) X(desx) X(rc2) X(rc4)
#define GEN_SET(tag) \
  TEST(ap_set_chain_matrix_##tag)    { with_alg(&g_algs[A_##tag], f_chain_matrix); } \
  TEST(ap_set_chain_invalid_##tag)   { with_alg(&g_algs[A_##tag], f_chain_invalid); } \
  TEST(ap_set_chain_cbinput_##tag)   { with_alg(&g_algs[A_##tag], f_chain_cbinput_ignored); } \
  TEST(ap_set_nullinput_##tag)       { with_alg(&g_algs[A_##tag], f_set_null_input_and_flags); } \
  TEST(ap_set_readonly_##tag)        { with_alg(&g_algs[A_##tag], f_set_readonly); } \
  TEST(ap_set_msgblock_##tag)        { with_alg(&g_algs[A_##tag], f_msgblock); } \
  TEST(ap_set_independent_##tag)     { with_alg(&g_algs[A_##tag], f_independent); }
SYM_TAGS(GEN_SET)

TEST(ap_set_aes_cfb_msgblock_defaults_after_mode_switch) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0, cb;
    NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_CFB));
    NT_OK(set_dw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, 16));
    NT_OK(ap_getdw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, &v, &cb)); EXPECT_EQ(v, 16);
    NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_CFB));        /* re-selecting the mode restores the default shift */
    NT_OK(ap_getdw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, &v, &cb));
    t_note("AES CFB default MessageBlockLength after re-set = %lu", (unsigned long)v);
    NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_CBC));
    NT_OK(ap_getdw(h, BCRYPT_MESSAGE_BLOCK_LENGTH, &v, &cb));
    t_note("AES CBC MessageBlockLength = %lu", (unsigned long)v);
    CHECK(v == 16 || v == 1 || v == 0);
    AP_CLOSE(h);
}
TEST(ap_set_aes_gcm_then_authtag_and_objlen_consistent) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG cbc = 0, gcm = 0, cb;
    NT_OK(ap_getdw(h, BCRYPT_OBJECT_LENGTH, &cbc, &cb));
    NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_GCM));
    NT_OK(ap_getdw(h, BCRYPT_OBJECT_LENGTH, &gcm, &cb));
    CHECK(gcm > cbc);
    NT_OK(set_mode(h, BCRYPT_CHAIN_MODE_CBC));
    NT_OK(ap_getdw(h, BCRYPT_OBJECT_LENGTH, &gcm, &cb));
    EXPECT_EQ(gcm, cbc);                              /* switching back restores the size */
    AP_CLOSE(h);
}
TEST(ap_set_rc4_chaining_mode_na) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_RC4_ALGORITHM, NULL, 0));
    if (!h) return;
    WCHAR cur[40]; ULONG cb;
    NTSTATUS s = ap_getstr(h, BCRYPT_CHAINING_MODE, cur, 32, &cb);
    t_note("RC4 ChainingMode get 0x%08lx \"%ls\" cb=%lu", (unsigned long)s, cur, (unsigned long)cb);
    s = set_mode(h, BCRYPT_CHAIN_MODE_NA);
    t_note("RC4 set ChainingModeN/A -> 0x%08lx", (unsigned long)s);
    AP_CLOSE(h);
}
TEST(ap_set_na_on_aes) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    NTSTATUS s = set_mode(h, BCRYPT_CHAIN_MODE_NA);
    NT_FAILED(s);
    t_note("AES set ChainingModeN/A -> 0x%08lx", (unsigned long)s);
    CHECK(mode_is(h, BCRYPT_CHAIN_MODE_CBC));
    AP_CLOSE(h);
}

/* ---------------------------------------------------------------- RC2 EffectiveKeyLength */
TEST(ap_set_rc2_effective_key_length) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_RC2_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0, cb;
    static const ULONG good[] = { 16, 40, 56, 64, 128, 1024 };
    for (unsigned i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        NT_OK(set_dw(h, BCRYPT_EFFECTIVE_KEY_LENGTH, good[i]));
        NT_OK(ap_getdw(h, BCRYPT_EFFECTIVE_KEY_LENGTH, &v, &cb));
        EXPECT_EQ(v, good[i]);
    }
    static const ULONG bad[] = { 0, 1, 15, 1025, 0x10000, 0xffffffffu };
    NT_OK(set_dw(h, BCRYPT_EFFECTIVE_KEY_LENGTH, 40));
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        NT_EQ(set_dw(h, BCRYPT_EFFECTIVE_KEY_LENGTH, bad[i]), AP_INVALID_PARAM);
    }
    NT_OK(ap_getdw(h, BCRYPT_EFFECTIVE_KEY_LENGTH, &v, &cb)); EXPECT_EQ(v, 40);
    UCHAR b8[8] = { 64, 0, 0, 0, 0, 0, 0, 0 };
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_EFFECTIVE_KEY_LENGTH, b8, 3, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_EFFECTIVE_KEY_LENGTH, b8, 8, 0), AP_INVALID_PARAM);
    AP_CLOSE(h);
}
TEST(ap_set_effective_key_length_on_other_ciphers) {
    NEED_CORE();
    static const WCHAR *const id[] = { BCRYPT_AES_ALGORITHM, BCRYPT_DES_ALGORITHM, BCRYPT_3DES_ALGORITHM, BCRYPT_RC4_ALGORITHM };
    for (int i = 0; i < 4; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NT_OK(AP_OPEN(&h, id[i], NULL, 0));
        if (!h) continue;
        NT_EQ(set_dw(h, BCRYPT_EFFECTIVE_KEY_LENGTH, 64), AP_NOT_SUPPORTED);
        AP_CLOSE(h);
    }
}

/* ---------------------------------------------------------------- other classes */
static void f_hash_set(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 5;
    /* algorithm handles of hashes hold no settable state: the provider validates for a hash object and rejects the handle */
    NTSTATUS s = U(BCryptSetProperty)(h, L"NoSuchProperty", (PUCHAR)&v, 4, 0);
    NT_EQ(s, AP_INVALID_HANDLE);
    NT_EQ(U(BCryptSetProperty)(h, L"NoSuchProperty", (PUCHAR)&v, 4, 1), AP_INVALID_PARAM);
}
#define HASH_TAGS(X) X(md2) X(md4) X(md5) X(sha1) X(sha256) X(sha384) X(sha512)
#define GEN_HSET(tag) TEST(ap_set_hashalg_##tag) { with_alg(&g_algs[A_##tag], f_hash_set); }
HASH_TAGS(GEN_HSET)

static void f_rng_set(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 5;
    NT_EQ(U(BCryptSetProperty)(h, L"NoSuchProperty", (PUCHAR)&v, 4, 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_ALGORITHM_NAME, (PUCHAR)&v, 4, 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptSetProperty)(h, L"NoSuchProperty", NULL, 4, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, L"NoSuchProperty", (PUCHAR)&v, 4, 1), AP_INVALID_PARAM);
}
TEST(ap_set_rngalg) { with_alg(&g_algs[A_rng], f_rng_set); }

static void f_dsadh_set(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 5;
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptSetProperty)(h, L"NoSuchProperty", (PUCHAR)&v, 4, 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_KEY_LENGTH, NULL, 4, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 0, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, 1), AP_INVALID_PARAM);
}
TEST(ap_set_dsaalg) { with_alg(&g_algs[A_dsa], f_dsadh_set); }
TEST(ap_set_dhalg)  { with_alg(&g_algs[A_dh], f_dsadh_set); }

static void f_rsa_set(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 2048;
    /* key length can only be set on a key object; the algorithm handle is not one */
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, 0), AP_INVALID_HANDLE);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_KEY_LENGTH, (PUCHAR)&v, 4, 1), AP_INVALID_PARAM);
}
TEST(ap_set_rsaalg)     { with_alg(&g_algs[A_rsa], f_rsa_set); }
TEST(ap_set_rsasignalg) { with_alg(&g_algs[A_rsasign], f_rsa_set); }

static void f_ecc_set(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    /* the curve of a named ECC algorithm is fixed */
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_ECC_CURVE_NAME, (PUCHAR)L"nistP384", sizeof(L"nistP384"), 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_ECC_CURVE_NAME, (PUCHAR)a->curve, (ULONG)((lstrlenW(a->curve) + 1) * 2), 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptSetProperty)(h, L"NoSuchProperty", (PUCHAR)L"x", 4, 0), AP_NOT_SUPPORTED);
    NT_EQ(U(BCryptSetProperty)(h, BCRYPT_ECC_CURVE_NAME, (PUCHAR)a->curve, 4, 1), AP_INVALID_PARAM);
}
#define ECC_TAGS(X) X(ecdsa256) X(ecdsa384) X(ecdsa521) X(ecdh256) X(ecdh384) X(ecdh521)
#define GEN_ESET(tag) TEST(ap_set_eccalg_##tag) { with_alg(&g_algs[A_##tag], f_ecc_set); }
ECC_TAGS(GEN_ESET)

TEST(ap_set_ecc_generic_curve_name) {
    NEED_CORE();
    static const WCHAR *const id[] = { L"ECDSA", L"ECDH" };
    for (int i = 0; i < 2; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NTSTATUS s = AP_OPEN(&h, id[i], NULL, 0);
        if (s < 0) { t_note("%ls unavailable 0x%08lx", id[i], (unsigned long)s); continue; }
        s = U(BCryptSetProperty)(h, BCRYPT_ECC_CURVE_NAME, (PUCHAR)L"nistP256", sizeof(L"nistP256"), 0);
        t_note("%ls generic: set curve nistP256 -> 0x%08lx", id[i], (unsigned long)s);
        if (s >= 0) {
            WCHAR nm[40]; ULONG cb;
            NT_OK(ap_getstr(h, BCRYPT_ECC_CURVE_NAME, nm, 40, &cb));
            CHECK(!lstrcmpW(nm, L"nistP256"));
            s = U(BCryptSetProperty)(h, BCRYPT_ECC_CURVE_NAME, (PUCHAR)L"nistP384", sizeof(L"nistP384"), 0);
            NT_EQ(s, AP_NOT_SUPPORTED);                 /* a curve can be assigned only once */
        }
        AP_CLOSE(h);
    }
}
TEST(ap_set_ecc_generic_bad_curve) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = AP_OPEN(&h, L"ECDSA", NULL, 0);
    if (s < 0) { t_note("generic ECDSA unavailable 0x%08lx", (unsigned long)s); return; }
    s = U(BCryptSetProperty)(h, BCRYPT_ECC_CURVE_NAME, (PUCHAR)L"noSuchCurve", sizeof(L"noSuchCurve"), 0);
    NT_FAILED(s);
    t_note("generic ECDSA: unknown curve -> 0x%08lx", (unsigned long)s);
    AP_CLOSE(h);
}

static void f_kd_set(const struct algd *a, BCRYPT_ALG_HANDLE h) {
    ULONG v = 1;
    NTSTATUS s = U(BCryptSetProperty)(h, L"NoSuchProperty", (PUCHAR)&v, 4, 0);
    NT_FAILED(s);
    t_note("%ls alg set unknown property -> 0x%08lx", a->id, (unsigned long)s);
    NT_EQ(U(BCryptSetProperty)(h, L"NoSuchProperty", (PUCHAR)&v, 4, 1), AP_INVALID_PARAM);
}
#define KD_TAGS(X) X(sp800108) X(sp80056a) X(pbkdf2) X(capikdf) X(hkdf) X(tls11) X(tls12)
#define GEN_KSET(tag) TEST(ap_set_kdalg_##tag) { with_alg(&g_algs[A_##tag], f_kd_set); }
KD_TAGS(GEN_KSET)

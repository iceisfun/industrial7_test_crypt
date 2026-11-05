/* BCryptImportKey: argument protocol, KeyDataBlob KATs, wrap/opaque blobs, class restrictions. */
#include "gap1.h"

static BCRYPT_ALG_HANDLE open_alg(const WCHAR *name, ULONG flags) {
    BCRYPT_ALG_HANDLE h = NULL;
    if (U(BCryptOpenAlgorithmProvider)(&h, name, NULL, flags) != 0) return NULL;
    return h;
}
static void close_alg(BCRYPT_ALG_HANDLE h) { if (h) U(BCryptCloseAlgorithmProvider)(h, 0); }
static ULONG getprop(BCRYPT_HANDLE h, const WCHAR *prop) {
    ULONG v = 0, n = 0;
    U(BCryptGetProperty)(h, prop, (PUCHAR)&v, sizeof v, &n, 0);
    return v;
}
static BCRYPT_ALG_HANDLE open_aes_ecb(void) {
    BCRYPT_ALG_HANDLE a = open_alg(L"AES", 0);
    if (a) U(BCryptSetProperty)(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    return a;
}
/* KeyDataBlob: header + key bytes */
static ULONG kdblob(BYTE *out, const BYTE *key, ULONG cbkey) {
    BCRYPT_KEY_DATA_BLOB_HEADER *h = (void *)out;
    h->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC; h->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1; h->cbKeyData = cbkey;
    memcpy(out + sizeof *h, key, cbkey);
    return sizeof *h + cbkey;
}
/* encrypt one block with ECB (no padding) and return status */
static NTSTATUS enc_block(BCRYPT_KEY_HANDLE k, const BYTE in[16], BYTE out[16]) {
    ULONG n = 0;
    return U(BCryptEncrypt)(k, (PUCHAR)in, 16, NULL, NULL, 0, out, 16, &n, 0);
}
static void seq(BYTE *p, int n) { for (int i = 0; i < n; i++) p[i] = (BYTE)i; }

TEST(gap1_import_invalid_algorithm_handle) {
    REQUIRE(U(BCryptImportKey));
    BYTE blob[64]; BYTE key[16] = {0}; ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL; BYTE obj[1024];
    EXPECT_EQ(U(BCryptImportKey)(NULL, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, sizeof obj, blob, cb, 0), ST_INVALID_HANDLE);
    CHECK(k == NULL);
    /* an algorithm handle that has been closed */
    if (t_is_wine()) { t_skip("closed algorithm handle crashes the emulator"); return; }
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    CHECK(U(BCryptCloseAlgorithmProvider)(a, 0) == 0);
    EXPECT_EQ(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, sizeof obj, blob, cb, 0), ST_INVALID_HANDLE);
}
TEST(gap1_import_hash_handle_as_algorithm) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h; CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    BYTE blob[64]; BYTE key[16] = {0}; ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL; BYTE obj[1024];
    EXPECT_EQ(U(BCryptImportKey)(h, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, sizeof obj, blob, cb, 0), ST_INVALID_HANDLE);
    U(BCryptDestroyHash)(h); close_alg(a);
}
TEST(gap1_import_null_pointers) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BYTE blob[64]; BYTE key[16] = {0}; ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL; BYTE obj[1024];
    EXPECT_EQ(U(BCryptImportKey)(a, NULL, NULL, &k, obj, sizeof obj, blob, cb, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, NULL, obj, sizeof obj, blob, cb, 0), ST_INVALID_PARAMETER);
    /* caller-supplied size with a NULL object buffer */
    EXPECT_EQ(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 1024, blob, cb, 0), ST_INVALID_PARAMETER);
    /* automatic allocation also needs the output pointer */
    EXPECT_EQ(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, NULL, NULL, 0, blob, cb, 0), ST_INVALID_PARAMETER);
    CHECK(k == NULL);
    close_alg(a);
}
TEST(gap1_import_key_object_size_floor) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BYTE blob[64]; BYTE key[16] = {0}; ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL; BYTE obj[1024];
    EXPECT_EQ(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, 0x3d, blob, cb, 0), ST_BUFFER_TOO_SMALL);
    EXPECT_EQ(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, 1, blob, cb, 0), ST_BUFFER_TOO_SMALL);
    CHECK(k == NULL);
    close_alg(a);
}
TEST(gap1_import_keydata_aes_kat) {
    REQUIRE(U(BCryptImportKey));
    static const struct { int klen; BYTE ct[16]; } v[] = {
        { 16, {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a} },
        { 24, {0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91} },
        { 32, {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89} },
    };
    BYTE pt[16], key[32]; for (int i = 0; i < 16; i++) pt[i] = (BYTE)(i * 0x11); seq(key, 32);
    for (unsigned i = 0; i < 3; i++) {
        BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
        BYTE blob[64]; ULONG cb = kdblob(blob, key, v[i].klen);
        BCRYPT_KEY_HANDLE k = NULL; BYTE o[16];
        EXPECT_EQ(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0), 0);
        if (k) {
            CHECK(enc_block(k, pt, o) == 0);
            CHECKF(!memcmp(o, v[i].ct, 16), "AES-%d", v[i].klen * 8);
            ULONG bl = getprop(k, BCRYPT_KEY_LENGTH);
            CHECKF(bl == (ULONG)v[i].klen * 8, "KeyLength property %lu", bl);
            CHECK(U(BCryptDestroyKey)(k) == 0);
        }
        close_alg(a);
    }
}
TEST(gap1_import_caller_object_buffer) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    ULONG ol = getprop(a, BCRYPT_OBJECT_LENGTH); CHECK(ol >= 0x3e);
    BYTE key[16], blob[64], pt[16] = {0}, o[16];
    seq(key, 16); ULONG cb = kdblob(blob, key, 16);
    BYTE *raw = calloc(1, ol + 64);
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, raw + 3, ol + 32, blob, cb, 0);
    EXPECT_EQ(s, 0);
    if (k) {
        CHECK(enc_block(k, pt, o) == 0);
        static const BYTE ref[16] = {0xc6,0xa1,0x3b,0x37,0x87,0x8f,0x5b,0x82,0x6f,0x4f,0x81,0x62,0xa1,0xc8,0xd8,0x79};
        CHECK(!memcmp(o, ref, 16));
        CHECK(U(BCryptDestroyKey)(k) == 0);
    }
    free(raw); close_alg(a);
}
TEST(gap1_import_independent_handles) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BYTE k1[16], k2[16], b1[64], b2[64], pt[16] = {0}, o1[16], o2[16];
    seq(k1, 16); memset(k2, 0x5a, 16);
    ULONG c1 = kdblob(b1, k1, 16), c2 = kdblob(b2, k2, 16);
    BCRYPT_KEY_HANDLE h1 = NULL, h2 = NULL, h3 = NULL;
    CHECK(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &h1, NULL, 0, b1, c1, 0) == 0);
    CHECK(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &h2, NULL, 0, b2, c2, 0) == 0);
    CHECK(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &h3, NULL, 0, b1, c1, 0) == 0);
    CHECK(h1 && h2 && h3 && h1 != h2 && h1 != h3);
    CHECK(enc_block(h1, pt, o1) == 0 && enc_block(h2, pt, o2) == 0);
    CHECK(memcmp(o1, o2, 16) != 0);
    CHECK(U(BCryptDestroyKey)(h1) == 0);
    BYTE o3[16];
    CHECK(enc_block(h3, pt, o3) == 0);
    CHECK(!memcmp(o1, o3, 16));
    CHECK(U(BCryptDestroyKey)(h2) == 0); CHECK(U(BCryptDestroyKey)(h3) == 0);
    close_alg(a);
}
TEST(gap1_import_bad_keydata_blobs) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BYTE key[40] = {0}, blob[128];
    BCRYPT_KEY_HANDLE k = NULL;
    struct { const char *what; ULONG cb; ULONG magic, ver, cbkey; } t[] = {
        { "wrong magic", 0, 0x12345678, 1, 16 },
        { "wrong version", 0, BCRYPT_KEY_DATA_BLOB_MAGIC, 2, 16 },
        { "version zero", 0, BCRYPT_KEY_DATA_BLOB_MAGIC, 0, 16 },
        { "cbKeyData larger than input", 0, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 24 },
        { "AES key of 15 bytes", 0, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 15 },
        { "AES key of 17 bytes", 0, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 17 },
        { "AES key of 33 bytes", 0, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 33 },
    };
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        BCRYPT_KEY_DATA_BLOB_HEADER *h = (void *)blob;
        memset(blob, 0, sizeof blob);
        h->dwMagic = t[i].magic; h->dwVersion = t[i].ver; h->cbKeyData = t[i].cbkey;
        ULONG cb = sizeof *h + (t[i].cbkey > 24 ? 33 : (i == 3 ? 16 : t[i].cbkey));
        k = NULL;
        NTSTATUS s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0);
        CHECKF(s != 0 && k == NULL, "%s -> 0x%08lx", t[i].what, (unsigned long)s);
        t_note("%s -> 0x%08lx", t[i].what, (unsigned long)s);
        if (k) U(BCryptDestroyKey)(k);
    }
    /* too short to hold the header */
    k = NULL;
    NTSTATUS s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, 8, 0);
    CHECK(s != 0 && k == NULL);
    s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, 0, 0);
    CHECK(s != 0 && k == NULL);
    close_alg(a);
}
TEST(gap1_import_unknown_blob_type) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BYTE blob[64], key[16] = {0}; ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL;
    static const WCHAR *types[] = { L"", L"NoSuchBlob", L"keydatablob", L"RSAPUBLICBLOB", L"ECCPUBLICBLOB" };
    for (unsigned i = 0; i < sizeof types / sizeof *types; i++) {
        NTSTATUS s = U(BCryptImportKey)(a, NULL, types[i], &k, NULL, 0, blob, cb, 0);
        CHECKF(s != 0 && k == NULL, "type '%ls' -> 0x%08lx", types[i], (unsigned long)s);
        t_note("blob type '%ls' -> 0x%08lx", types[i], (unsigned long)s);
        if (k) { U(BCryptDestroyKey)(k); k = NULL; }
    }
    close_alg(a);
}
TEST(gap1_import_class_restrictions) {
    /* only symmetric-cipher (and one more) classes accept BCryptImportKey; hash/HMAC and asymmetric do not */
    REQUIRE(U(BCryptImportKey));
    BYTE blob[64], key[16] = {0}; ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL;
    static const struct { const WCHAR *n; ULONG fl; } c[] = {
        { L"SHA256", 0 }, { L"SHA256", BCRYPT_ALG_HANDLE_HMAC_FLAG }, { L"RSA", 0 }, { L"ECDH_P256", 0 },
        { L"ECDSA_P256", 0 }, { L"DSA", 0 }, { L"RNG", 0 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        BCRYPT_ALG_HANDLE a = open_alg(c[i].n, c[i].fl);
        if (!a) { t_note("%ls: not available", c[i].n); continue; }
        k = NULL;
        BYTE obj[2048];   /* explicit object so the class check is reached without an object-length property */
        EXPECT_EQ(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, sizeof obj, blob, cb, 0), ST_NOT_SUPPORTED);
        CHECK(k == NULL);
        close_alg(a);
    }
}
TEST(gap1_import_other_cipher_algs) {
    REQUIRE(U(BCryptImportKey));
    static const struct { const WCHAR *n; ULONG klen; } c[] = {
        { L"AES", 16 }, { L"3DES", 24 }, { L"3DES_112", 16 }, { L"DES", 8 }, { L"RC2", 16 }, { L"RC4", 16 },
    };
    BYTE key[32]; seq(key, 32);
    for (unsigned i = 0; i < sizeof c / sizeof *c; i++) {
        BCRYPT_ALG_HANDLE a = open_alg(c[i].n, 0);
        if (!a) { t_note("%ls: not available", c[i].n); continue; }
        BYTE blob[64]; ULONG cb = kdblob(blob, key, c[i].klen);
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0);
        CHECKF(s == 0, "%ls -> 0x%08lx", c[i].n, (unsigned long)s);
        if (k) U(BCryptDestroyKey)(k);
        close_alg(a);
    }
}
TEST(gap1_import_hImportKey_validation) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BYTE blob[64], key[16] = {0}; ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL;
    /* an algorithm handle is not a key handle */
    EXPECT_EQ(U(BCryptImportKey)(a, (BCRYPT_KEY_HANDLE)a, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0), ST_INVALID_HANDLE);
    /* key from a different open of the same algorithm: must be a key-wrap blob type, otherwise invalid parameter */
    BCRYPT_ALG_HANDLE b = open_aes_ecb(); REQUIRE(b);
    BCRYPT_KEY_HANDLE kek = NULL;
    CHECK(U(BCryptImportKey)(b, NULL, BCRYPT_KEY_DATA_BLOB, &kek, NULL, 0, blob, cb, 0) == 0);
    NTSTATUS s = U(BCryptImportKey)(a, kek, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0);
    EXPECT_EQ(s, ST_INVALID_PARAMETER);
    CHECK(k == NULL);
    U(BCryptDestroyKey)(kek);
    close_alg(b); close_alg(a);
}
TEST(gap1_import_hImportKey_asymmetric_rejected) {
    REQUIRE(U(BCryptImportKey)); REQUIRE(U(BCryptGenerateKeyPair));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BCRYPT_ALG_HANDLE r = open_alg(L"RSA", 0);
    if (!r) { close_alg(a); t_skip("no RSA"); return; }
    BCRYPT_KEY_HANDLE rk = NULL, k = NULL;
    if (U(BCryptGenerateKeyPair)(r, &rk, 512, 0) == 0 && U(BCryptFinalizeKeyPair)(rk, 0) == 0) {
        BYTE blob[64], key[16] = {0}; ULONG cb = kdblob(blob, key, 16);
        EXPECT_EQ(U(BCryptImportKey)(a, rk, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0), ST_INVALID_HANDLE);
        CHECK(k == NULL);
    } else t_skip("RSA key generation unavailable");
    if (rk) U(BCryptDestroyKey)(rk);
    close_alg(r); close_alg(a);
}
TEST(gap1_import_aes_keywrap_rfc3394) {
    REQUIRE(U(BCryptImportKey)); REQUIRE(U(BCryptExportKey));
    static const BYTE wrapped[24] = {0x1f,0xa6,0x8b,0x0a,0x81,0x12,0xb4,0x47,0xae,0xf3,0x4b,0xd8,0xfb,0x5a,0x7b,0x82,0x9d,0x3e,0x86,0x23,0x71,0xd2,0xcf,0xe5};
    static const BYTE zero_ct[16] = {0xfd,0xe4,0xfb,0xae,0x4a,0x09,0xe0,0x20,0xef,0xf7,0x22,0x96,0x9f,0x83,0x83,0x2b};
    BCRYPT_ALG_HANDLE a = open_aes_ecb(), b = open_aes_ecb(); REQUIRE(a && b);
    BYTE kek[16], blob[64]; seq(kek, 16); ULONG cb = kdblob(blob, kek, 16);
    BCRYPT_KEY_HANDLE hk = NULL, out = NULL;
    CHECK(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &hk, NULL, 0, blob, cb, 0) == 0);
    NTSTATUS s = U(BCryptImportKey)(b, hk, L"Rfc3565KeyWrapBlob", &out, NULL, 0, (PUCHAR)wrapped, sizeof wrapped, 0);
    t_note("unwrap import of RFC 3394 vector -> 0x%08lx", (unsigned long)s);
    if (s == 0 && out) {
        BYTE pt[16] = {0}, o[16];
        CHECK(enc_block(out, pt, o) == 0);
        CHECK(!memcmp(o, zero_ct, 16));
        /* and wrapping again reproduces the vector */
        ULONG need = 0;
        NTSTATUS es = U(BCryptExportKey)(out, hk, L"Rfc3565KeyWrapBlob", NULL, 0, &need, 0);
        t_note("export wrap size query -> 0x%08lx need %lu", (unsigned long)es, need);
        if (es == 0 && need == 24) {
            BYTE w[24]; ULONG got = 0;
            CHECK(U(BCryptExportKey)(out, hk, L"Rfc3565KeyWrapBlob", w, sizeof w, &got, 0) == 0);
            CHECK(got == 24 && !memcmp(w, wrapped, 24));
        }
        U(BCryptDestroyKey)(out);
    } else CHECK(s == 0);
    /* corrupted wrapped key fails the integrity check */
    BYTE bad[24]; memcpy(bad, wrapped, 24); bad[10] ^= 0x40;
    out = NULL;
    s = U(BCryptImportKey)(b, hk, L"Rfc3565KeyWrapBlob", &out, NULL, 0, bad, sizeof bad, 0);
    t_note("unwrap of corrupted key -> 0x%08lx", (unsigned long)s);
    CHECK(s != 0 && out == NULL);
    if (out) U(BCryptDestroyKey)(out);
    U(BCryptDestroyKey)(hk); close_alg(a); close_alg(b);
}
TEST(gap1_import_opaque_roundtrip) {
    REQUIRE(U(BCryptImportKey)); REQUIRE(U(BCryptExportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BYTE key[16], blob[64], pt[16] = {0}, o1[16], o2[16]; seq(key, 16); ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k1 = NULL, k2 = NULL;
    CHECK(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k1, NULL, 0, blob, cb, 0) == 0);
    ULONG need = 0;
    NTSTATUS s = U(BCryptExportKey)(k1, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &need, 0);
    if (s != 0 || need == 0) { t_note("opaque export not available: 0x%08lx", (unsigned long)s); }
    else {
        BYTE *ob = calloc(1, need); ULONG got = 0;
        CHECK(U(BCryptExportKey)(k1, NULL, BCRYPT_OPAQUE_KEY_BLOB, ob, need, &got, 0) == 0);
        CHECK(got <= need);
        s = U(BCryptImportKey)(a, NULL, BCRYPT_OPAQUE_KEY_BLOB, &k2, NULL, 0, ob, got, 0);
        CHECKF(s == 0, "opaque import 0x%08lx", (unsigned long)s);
        if (k2) {
            CHECK(enc_block(k1, pt, o1) == 0 && enc_block(k2, pt, o2) == 0);
            CHECK(!memcmp(o1, o2, 16));
            U(BCryptDestroyKey)(k2);
        }
        free(ob);
    }
    U(BCryptDestroyKey)(k1); close_alg(a);
}
TEST(gap1_import_survives_algorithm_close) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_aes_ecb(); REQUIRE(a);
    BYTE key[16], blob[64], pt[16] = {0}, o[16]; seq(key, 16); ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0) == 0);
    CHECK(U(BCryptCloseAlgorithmProvider)(a, 0) == 0);   /* key holds a reference on the algorithm object */
    static const BYTE ref[16] = {0xc6,0xa1,0x3b,0x37,0x87,0x8f,0x5b,0x82,0x6f,0x4f,0x81,0x62,0xa1,0xc8,0xd8,0x79};
    CHECK(enc_block(k, pt, o) == 0);
    CHECK(!memcmp(o, ref, 16));
    CHECK(U(BCryptDestroyKey)(k) == 0);
}
TEST(gap1_import_hmac_alg_handle_not_supported) {
    REQUIRE(U(BCryptImportKey));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BYTE key[16], blob[64]; seq(key, 16); ULONG cb = kdblob(blob, key, 16);
    BCRYPT_KEY_HANDLE k = NULL; BYTE obj[2048];
    NTSTATUS s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, sizeof obj, blob, cb, 0);
    CHECK(s == ST_NOT_SUPPORTED);
    close_alg(a);
}

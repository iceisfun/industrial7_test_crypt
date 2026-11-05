/* BCryptImportKey / BCryptExportKey for symmetric keys (KeyDataBlob, OpaqueKeyBlob, Rfc3565KeyWrapBlob),
 * BCryptGenerateSymmetricKey flag validation and key-length truncation. Statuses from bcrypt.dll and
 * bcryptprimitives.dll (MSCryptImportKey / MSCryptExportKey / MSCryptGenerateSymmetricKey). */
#include "bsc.h"

#define ECB BCRYPT_CHAIN_MODE_ECB
#define CBC BCRYPT_CHAIN_MODE_CBC
#define SENT ((BCRYPT_KEY_HANDLE)(ULONG_PTR)0xDEADBEEF)

static BYTE *mkblob(const BYTE *key, ULONG n, ULONG magic, ULONG ver, ULONG cbkd, ULONG *total) {
    BYTE *b = (BYTE *)calloc(1, 12 + n + 16);
    BCRYPT_KEY_DATA_BLOB_HEADER *h = (BCRYPT_KEY_DATA_BLOB_HEADER *)b;
    h->dwMagic = magic; h->dwVersion = ver; h->cbKeyData = cbkd;
    memcpy(b + 12, key, n);
    *total = 12 + n;
    return b;
}
static const BYTE KEY[32] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };

/* ---- header layout ------------------------------------------------------------------------ */
TEST(bsc_blob_header_constants) {
    CHECK(BCRYPT_KEY_DATA_BLOB_MAGIC == 0x4d42444b);
    CHECK(BCRYPT_KEY_DATA_BLOB_VERSION1 == 1);
    CHECK(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) == 12);
    CHECK(!wcscmp(BCRYPT_KEY_DATA_BLOB, L"KeyDataBlob"));
    CHECK(!wcscmp(BCRYPT_OPAQUE_KEY_BLOB, L"OpaqueKeyBlob"));
    CHECK(!wcscmp(BCRYPT_AES_WRAP_KEY_BLOB, L"Rfc3565KeyWrapBlob"));
}
TEST(bsc_export_keydata_layout) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    for (ULONG n = 16; n <= 32; n += 8) {
        bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, n), 0);
        ULONG need = 0;
        if (!t_is_wine()) { EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &need, 0), 0); EXPECT_EQ(need, 12 + n); }
        BYTE out[64]; memset(out, 0xEE, sizeof out); ULONG got = 0;
        EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, sizeof out, &got, 0), 0);
        EXPECT_EQ(got, 12 + n);
        BCRYPT_KEY_DATA_BLOB_HEADER *h = (BCRYPT_KEY_DATA_BLOB_HEADER *)out;
        CHECK(h->dwMagic == 0x4d42444b); CHECK(h->dwVersion == 1); CHECK(h->cbKeyData == n);
        CHECK(same(out + 12, KEY, n));
        CHECK(out[12 + n] == 0xEE);                  /* nothing past the blob */
        bsc_free(&k);
    }
    bsc_close(a);
}
TEST(bsc_export_keydata_buffer_protocol) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    BYTE out[64]; ULONG got = 0xAAAA;
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, 0, &got, 0), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 28);
    got = 0xAAAA;
    for (ULONG cb = 1; cb < 28; cb += 9) {
        EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, cb, &got, 0), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 28);
    }
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, 27, &got, 0), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 28);
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, 28, &got, 0), 0); EXPECT_EQ(got, 28);
    got = 0xAAAA;
    if (!t_is_wine()) { EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 1000, &got, 0), 0); EXPECT_EQ(got, 28); }   /* NULL buffer: size query */
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_export_argument_validation_order) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    ULONG got = 0xAAAA; BYTE out[64];
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, NULL, 0), NS_INVALID_PARAM);
    EXPECT_EQ(P_Exp(k.h, NULL, NULL, out, 64, &got, 0), NS_INVALID_PARAM);
    if (!t_is_wine()) {
        EXPECT_EQ(P_Exp(NULL, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, NULL, 0), NS_INVALID_PARAM);    /* params before handle */
        EXPECT_EQ(P_Exp(NULL, NULL, NULL, out, 64, &got, 0), NS_INVALID_PARAM);
    }
    EXPECT_EQ(P_Exp(NULL, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, &got, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Exp((BCRYPT_KEY_HANDLE)a, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, &got, 0), NS_INVALID_HANDLE);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_export_unknown_blob_type) {
    WINE_SKIP("blob type validation differs");
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    ULONG got = 0xAAAA; BYTE out[64];
    EXPECT_EQ(P_Exp(k.h, NULL, L"NoSuchBlob", out, 64, &got, 0), NS_NOT_SUPPORTED);
    EXPECT_EQ(P_Exp(k.h, NULL, L"keydatablob", out, 64, &got, 0), NS_NOT_SUPPORTED);      /* comparison is case sensitive */
    EXPECT_EQ(P_Exp(k.h, NULL, L"RSAPUBLICBLOB", out, 64, &got, 0), NS_NOT_SUPPORTED);
    EXPECT_EQ(P_Exp(k.h, NULL, L"", out, 64, &got, 0), NS_NOT_SUPPORTED);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_export_nonzero_flags) {
    WINE_SKIP("flag validation");
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    ULONG got = 0xAAAA; BYTE out[64];
    ULONG fl[] = { 1, 2, 0x80, 0x80000000 };
    for (int i = 0; i < 4; i++) {
        NTSTATUS s = P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, &got, fl[i]);
        CHECKF(s == NS_INVALID_PARAM, "flags 0x%lx -> 0x%lx", fl[i], s);
    }
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_export_destroyed_key) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    BCRYPT_KEY_HANDLE h = k.h;
    EXPECT_EQ(P_Destroy(h), 0); k.h = NULL;
    ULONG got = 0xAAAA; BYTE out[64];
    EXPECT_EQ(P_Exp(h, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, &got, 0), NS_INVALID_HANDLE);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_export_oversize_secret_exports_truncated_key) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    BYTE sec[48]; for (int i = 0; i < 48; i++) sec[i] = (BYTE)i;
    bkey k; NTSTATUS s = bsc_gen(a, &k, sec, 48);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE out[64]; ULONG got = 0;
        EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, &got, 0), 0);
        EXPECT_EQ(got, 12 + 32);
        BCRYPT_KEY_DATA_BLOB_HEADER *h = (BCRYPT_KEY_DATA_BLOB_HEADER *)out; CHECK(h->cbKeyData == 32);
        bsc_free(&k);
    }
    bsc_close(a);
}

/* ---- import ---------------------------------------------------------------------------------- */
static NTSTATUS import_try(BCRYPT_ALG_HANDLE a, const BYTE *blob, ULONG cb, BCRYPT_KEY_HANDLE *out) {
    *out = SENT;
    ULONG ol = bsc_objlen(a); BYTE *obj = (BYTE *)calloc(1, ol + 64);   /* leaked on purpose for failed calls: tiny */
    NTSTATUS s = P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, out, obj, ol, (PUCHAR)blob, cb, 0);
    return s;
}
TEST(bsc_import_keydata_roundtrip_all_sizes) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    for (ULONG n = 16; n <= 32; n += 8) {
        ULONG cb; BYTE *blob = mkblob(KEY, n, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, n, &cb);
        BCRYPT_KEY_HANDLE k;
        NTSTATUS s = import_try(a, blob, cb, &k);
        CHECKF(s == 0, "n=%lu 0x%lx", n, s);
        if (s == 0) {
            bkey ref; EXPECT_EQ(bsc_gen(a, &ref, KEY, n), 0);
            BYTE pt[16] = {1,2,3}, c1[16], c2[16]; ULONG got = 0;
            EXPECT_EQ(enc(k, pt, 16, NULL, 0, c1, 16, &got, 0), 0);
            EXPECT_EQ(enc(ref.h, pt, 16, NULL, 0, c2, 16, &got, 0), 0);
            CHECK(same(c1, c2, 16));
            ULONG str = 0, r = 0; P_GetProp(k, BCRYPT_KEY_STRENGTH, (PUCHAR)&str, 4, &r, 0);
            if (n == 16) CHECK(str == 128);
            P_Destroy(k); bsc_free(&ref);
        }
        free(blob);
    }
    bsc_close(a);
}
TEST(bsc_import_keydata_bad_magic_and_version) {
    WINE_SKIP("blob validation differs");
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    struct { ULONG magic, ver; } t[] = { {0x4d42444b ^ 1, 1}, {0, 1}, {0x4d42444b, 0}, {0x4d42444b, 2}, {0x4d42444b, 0x01000000}, {0x4b44424d, 1} };
    for (int i = 0; i < 6; i++) {
        ULONG cb; BYTE *blob = mkblob(KEY, 16, t[i].magic, t[i].ver, 16, &cb);
        BCRYPT_KEY_HANDLE k; NTSTATUS s = import_try(a, blob, cb, &k);
        CHECKF(s == NS_INVALID_PARAM, "case %d -> 0x%lx", i, s);
        CHECK(k == SENT);
        free(blob);
    }
    bsc_close(a);
}
TEST(bsc_import_keydata_length_fields) {
    WINE_SKIP("blob validation differs");
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG cb; BYTE *blob; BCRYPT_KEY_HANDLE k; NTSTATUS s;
    /* input shorter than the header */
    blob = mkblob(KEY, 0, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 0, &cb);
    for (ULONG n = 0; n < 12; n++) { s = import_try(a, blob, n, &k); CHECKF(s == NS_INVALID_PARAM, "cbInput=%lu 0x%lx", n, s); }
    free(blob);
    /* cbKeyData larger than the data present */
    blob = mkblob(KEY, 16, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 17, &cb);
    s = import_try(a, blob, cb, &k); EXPECT_EQ(s, NS_INVALID_PARAM); free(blob);
    blob = mkblob(KEY, 16, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 0xFFFFFFFF, &cb);
    s = import_try(a, blob, cb, &k); EXPECT_EQ(s, NS_INVALID_PARAM); free(blob);
    /* cbKeyData smaller than the data present: trailing bytes are ignored, key is the first cbKeyData bytes */
    blob = mkblob(KEY, 32, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 16, &cb);
    s = import_try(a, blob, cb, &k); EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE out[64]; ULONG got = 0;
        EXPECT_EQ(P_Exp(k, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, &got, 0), 0);
        EXPECT_EQ(got, 28);
        P_Destroy(k);
    }
    free(blob);
    /* cbKeyData zero */
    blob = mkblob(KEY, 0, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 0, &cb);
    s = import_try(a, blob, cb, &k); CHECK(s < 0);
    free(blob);
    bsc_close(a);
}
TEST(bsc_import_keydata_invalid_aes_key_size) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG sizes[] = { 1, 15, 17, 20, 31 };
    for (int i = 0; i < 5; i++) {
        ULONG cb; BYTE *blob = mkblob(KEY, sizes[i], BCRYPT_KEY_DATA_BLOB_MAGIC, 1, sizes[i], &cb);
        BCRYPT_KEY_HANDLE k; NTSTATUS s = import_try(a, blob, cb, &k);
        CHECKF(s == NS_INVALID_PARAM, "key bytes %lu -> 0x%lx", sizes[i], s);
        free(blob);
    }
    bsc_close(a);
}
TEST(bsc_import_keydata_oversize_is_not_truncated) {
    WINE_SKIP("blob validation differs");
    /* BCryptGenerateSymmetricKey clamps an over-long secret to the maximum; import (internal flag 0x80) does not. */
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    BYTE big[48]; for (int i = 0; i < 48; i++) big[i] = (BYTE)i;
    ULONG cb; BYTE *blob = mkblob(big, 40, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 40, &cb);
    BCRYPT_KEY_HANDLE k; NTSTATUS s = import_try(a, blob, cb, &k);
    EXPECT_EQ(s, NS_INVALID_PARAM);
    free(blob);
    bkey g; s = bsc_gen(a, &g, big, 40);
    EXPECT_EQ(s, 0);
    if (s == 0) bsc_free(&g);
    bsc_close(a);
}
TEST(bsc_import_null_and_bad_params) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG cb; BYTE *blob = mkblob(KEY, 16, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 16, &cb);
    BCRYPT_KEY_HANDLE k = SENT; ULONG ol = bsc_objlen(a); BYTE *obj = (BYTE *)calloc(1, ol + 64);
    if (!t_is_wine()) {
        EXPECT_EQ(P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, NULL, obj, ol, blob, cb, 0), NS_INVALID_PARAM);
        EXPECT_EQ(P_Imp(a, NULL, NULL, &k, obj, ol, blob, cb, 0), NS_INVALID_PARAM);
        EXPECT_EQ(P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 1000, blob, cb, 0), NS_INVALID_PARAM);
        EXPECT_EQ(P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, ol, blob, cb, 1), NS_INVALID_PARAM);       /* flags must be 0 */
        EXPECT_EQ(P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, ol, blob, cb, 0x80), NS_INVALID_PARAM);
        EXPECT_EQ(P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, 0x3d, blob, cb, 0), NS_BUFFER_TOO_SMALL);
        EXPECT_EQ(P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, 0, blob, cb, 0), NS_BUFFER_TOO_SMALL);
        CHECK(k == SENT);
    }
    EXPECT_EQ(P_Imp(NULL, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, ol, blob, cb, 0), NS_INVALID_HANDLE);
    CHECK(k == SENT);
    EXPECT_EQ(P_Imp(NULL, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, ol, blob, cb, 0), NS_INVALID_HANDLE);
    free(obj); free(blob); bsc_close(a);
}
TEST(bsc_import_unknown_blob_type) {
    WINE_SKIP("blob type validation differs");
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG cb; BYTE *blob = mkblob(KEY, 16, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 16, &cb);
    BCRYPT_KEY_HANDLE k = SENT; ULONG ol = bsc_objlen(a); BYTE *obj = (BYTE *)calloc(1, ol + 64);
    EXPECT_EQ(P_Imp(a, NULL, L"NoSuchBlob", &k, obj, ol, blob, cb, 0), NS_NOT_SUPPORTED);
    EXPECT_EQ(P_Imp(a, NULL, L"keydatablob", &k, obj, ol, blob, cb, 0), NS_NOT_SUPPORTED);
    EXPECT_EQ(P_Imp(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, obj, ol, blob, cb, 0), NS_NOT_SUPPORTED);
    CHECK(k == SENT);
    free(obj); free(blob); bsc_close(a);
}
TEST(bsc_import_internal_object_buffer) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG cb; BYTE *blob = mkblob(KEY, 16, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 16, &cb);
    BCRYPT_KEY_HANDLE k = SENT;
    NTSTATUS s = P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE pt[16] = {0}, o[16]; ULONG got = 0;
        EXPECT_EQ(enc(k, pt, 16, NULL, 0, o, 16, &got, 0), 0);
        EXPECT_EQ(P_Destroy(k), 0);
    }
    free(blob); bsc_close(a);
}
TEST(bsc_import_key_survives_alg_close) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG cb; BYTE *blob = mkblob(KEY, 16, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 16, &cb);
    BCRYPT_KEY_HANDLE k = SENT;
    EXPECT_EQ(P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, cb, 0), 0);
    EXPECT_EQ(P_Close(a, 0), 0);
    BYTE pt[16] = {0}, o[16]; ULONG got = 0;
    EXPECT_EQ(enc(k, pt, 16, NULL, 0, o, 16, &got, 0), 0);
    EXPECT_EQ(P_Destroy(k), 0);
    free(blob);
}
TEST(bsc_import_other_algorithm_key_as_import_key) {
    WINE_SKIP("import-key validation differs");
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    BCRYPT_ALG_HANDLE d = bsc_open(L"DES", ECB);
    if (!d) { bsc_close(a); t_skip("DES"); return; }
    bkey ak; EXPECT_EQ(bsc_gen(a, &ak, KEY, 16), 0);
    ULONG cb; BYTE *blob = mkblob(KEY, 8, BCRYPT_KEY_DATA_BLOB_MAGIC, 1, 8, &cb);
    BCRYPT_KEY_HANDLE k = SENT; ULONG ol = bsc_objlen(d); BYTE *obj = (BYTE *)calloc(1, ol + 64);
    /* hImportKey of a different algorithm than hAlgorithm is only allowed for the AES key wrap blob */
    EXPECT_EQ(P_Imp(d, ak.h, BCRYPT_KEY_DATA_BLOB, &k, obj, ol, blob, cb, 0), NS_INVALID_PARAM);
    CHECK(k == SENT);
    /* hImportKey must be a symmetric key handle */
    EXPECT_EQ(P_Imp(d, (BCRYPT_KEY_HANDLE)a, BCRYPT_KEY_DATA_BLOB, &k, obj, ol, blob, cb, 0), NS_INVALID_HANDLE);
    free(obj); free(blob); bsc_free(&ak); bsc_close(d); bsc_close(a);
}
TEST(bsc_export_with_other_algorithm_export_key) {
    WINE_SKIP("export-key validation differs");
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB), d = bsc_open(L"DES", ECB);
    if (!a || !d) { bsc_close(a); bsc_close(d); t_skip("AES/DES"); return; }
    bkey ak, dk; EXPECT_EQ(bsc_gen(a, &ak, KEY, 16), 0); EXPECT_EQ(bsc_gen(d, &dk, KEY, 8), 0);
    ULONG got = 0xAAAA; BYTE out[64];
    EXPECT_EQ(P_Exp(dk.h, ak.h, BCRYPT_KEY_DATA_BLOB, out, 64, &got, 0), NS_INVALID_PARAM);
    EXPECT_EQ(P_Exp(dk.h, (BCRYPT_KEY_HANDLE)a, BCRYPT_KEY_DATA_BLOB, out, 64, &got, 0), NS_INVALID_HANDLE);
    bsc_free(&ak); bsc_free(&dk); bsc_close(a); bsc_close(d);
}

/* ---- DES-family blobs ------------------------------------------------------------------------------ */
TEST(bsc_keydata_roundtrip_other_algorithms) {
    struct { const wchar_t *alg; ULONG klen; } t[] = { {L"DES", 8}, {L"3DES", 24}, {L"3DES_112", 16}, {L"RC4", 16}, {L"RC2", 16} };
    int any = 0;
    for (int i = 0; i < 5; i++) {
        BCRYPT_ALG_HANDLE a = bsc_open(t[i].alg, NULL); if (!a) continue;
        bkey k; NTSTATUS s = bsc_gen(a, &k, KEY, t[i].klen);
        if (s != 0) { free(k.obj); bsc_close(a); continue; }
        any = 1;
        BYTE out[64]; ULONG got = 0;
        s = P_Exp(k.h, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, &got, 0);
        CHECKF(s == 0 && got == 12 + t[i].klen, "%ls: 0x%lx %lu", t[i].alg, s, got);
        if (s == 0) {
            BCRYPT_KEY_HANDLE k2 = SENT;
            s = P_Imp(a, NULL, BCRYPT_KEY_DATA_BLOB, &k2, NULL, 0, out, got, 0);
            CHECKF(s == 0, "%ls import 0x%lx", t[i].alg, s);
            if (s == 0) P_Destroy(k2);
        }
        bsc_free(&k); bsc_close(a);
    }
    if (!any) t_skip("no legacy ciphers");
}

/* ---- opaque blob (round trip only) -------------------------------------------------------------------- */
TEST(bsc_opaque_roundtrip_encrypts_identically) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, "2b7e151628aed2a6abf7158809cf4f3c"), 0);
    ULONG need = 0;
    BYTE tiny0[4];
    NTSTATUS s = P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, tiny0, 0, &need, 0);
    EXPECT_EQ(s, NS_BUFFER_TOO_SMALL); CHECK(need > 0);
    BYTE *blob = (BYTE *)calloc(1, need + 16); ULONG got = 0;
    s = P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, blob, need, &got, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(got, need);
    BCRYPT_KEY_HANDLE k2 = SENT;
    s = P_Imp(a, NULL, BCRYPT_OPAQUE_KEY_BLOB, &k2, NULL, 0, blob, got, 0);
    if (t_is_wine() && s != 0) { t_skip("emulator opaque import differs"); free(blob); bsc_free(&k); bsc_close(a); return; }
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE pt[16], c[16]; hx("6bc1bee22e409f96e93d7e117393172a", pt);
        EXPECT_EQ(enc(k2, pt, 16, NULL, 0, c, 16, &got, 0), 0);
        CHECK_HEX(c, 16, "3ad77bb40d7a3660a89ecaf32466ef97");
        P_Destroy(k2);
    }
    free(blob); bsc_free(&k); bsc_close(a);
}
TEST(bsc_opaque_buffer_protocol) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    ULONG need = 0; BYTE tiny[4];
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, tiny, 0, &need, 0), NS_BUFFER_TOO_SMALL);
    CHECK(need > 4);
    ULONG got = 0xAAAA;
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, tiny, 4, &got, 0), NS_BUFFER_TOO_SMALL);
    EXPECT_EQ(got, need);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_opaque_import_truncated_blob_fails) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    ULONG need = 0; P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &need, 0);
    BYTE *blob = (BYTE *)calloc(1, need + 16); ULONG got = 0;
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, blob, need, &got, 0), 0);
    BCRYPT_KEY_HANDLE k2 = SENT;
    NTSTATUS s = P_Imp(a, NULL, BCRYPT_OPAQUE_KEY_BLOB, &k2, NULL, 0, blob, got / 2, 0);
    CHECK(s < 0); CHECK(k2 == SENT);
    s = P_Imp(a, NULL, BCRYPT_OPAQUE_KEY_BLOB, &k2, NULL, 0, blob, 0, 0);
    CHECK(s < 0);
    free(blob); bsc_free(&k); bsc_close(a);
}
TEST(bsc_opaque_import_garbage_fails) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    BYTE junk[200]; memset(junk, 0xA5, sizeof junk);
    BCRYPT_KEY_HANDLE k2 = SENT;
    NTSTATUS s = P_Imp(a, NULL, BCRYPT_OPAQUE_KEY_BLOB, &k2, NULL, 0, junk, sizeof junk, 0);
    CHECK(s < 0); CHECK(k2 == SENT);
    bsc_close(a);
}
TEST(bsc_opaque_import_with_pseudo_handle) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    ULONG need = 0; P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &need, 0);
    BYTE *blob = (BYTE *)calloc(1, need + 16); ULONG got = 0;
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, blob, need, &got, 0), 0);
    BCRYPT_KEY_HANDLE k2 = SENT;
    NTSTATUS s = P_Imp(BCRYPT_AES_CBC_ALG_HANDLE, NULL, BCRYPT_OPAQUE_KEY_BLOB, &k2, NULL, 0, blob, got, 0);
    if (t_is_wine() && s != 0) t_skip("emulator");
    else { EXPECT_EQ(s, 0); if (s == 0) P_Destroy(k2); }
    free(blob); bsc_free(&k); bsc_close(a);
}
TEST(bsc_opaque_keeps_chaining_mode) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, KEY, 16), 0);
    ULONG need = 0; P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &need, 0);
    BYTE *blob = (BYTE *)calloc(1, need + 16); ULONG got = 0;
    EXPECT_EQ(P_Exp(k.h, NULL, BCRYPT_OPAQUE_KEY_BLOB, blob, need, &got, 0), 0);
    BCRYPT_ALG_HANDLE e = bsc_open(L"AES", ECB);
    BCRYPT_KEY_HANDLE k2 = SENT;
    NTSTATUS s = P_Imp(e, NULL, BCRYPT_OPAQUE_KEY_BLOB, &k2, NULL, 0, blob, got, 0);
    if (s == 0) {
        WCHAR m[64] = {0}; ULONG r = 0;
        P_GetProp(k2, BCRYPT_CHAINING_MODE, (PUCHAR)m, sizeof m, &r, 0);
        t_note("opaque key exported from a CBC key and imported through an ECB algorithm handle reports mode %ls", m);
        P_Destroy(k2);
    }
    bsc_close(e); free(blob); bsc_free(&k); bsc_close(a);
}

/* ---- AES key wrap (RFC 3394 / BCRYPT_AES_WRAP_KEY_BLOB) ------------------------------------------------ */
static void wrap_case(const char *kek, const char *data, const char *wrapped) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey kk, dk;
    BYTE kekb[32], datab[32], wr[48]; ULONG nk = (ULONG)hx(kek, kekb), nd = (ULONG)hx(data, datab), nw = (ULONG)hx(wrapped, wr);
    EXPECT_EQ(bsc_gen(a, &kk, kekb, nk), 0); EXPECT_EQ(bsc_gen(a, &dk, datab, nd), 0);
    ULONG need = 0xAAAA;
    NTSTATUS s = P_Exp(dk.h, kk.h, BCRYPT_AES_WRAP_KEY_BLOB, NULL, 0, &need, 0);
    if (WINE_UNSUP(s)) { t_skip("AES key wrap unsupported under emulator"); bsc_free(&kk); bsc_free(&dk); bsc_close(a); return; }
    EXPECT_EQ(s, 0); EXPECT_EQ(need, nw);
    BYTE out[64]; memset(out, 0xEE, sizeof out); ULONG got = 0;
    s = P_Exp(dk.h, kk.h, BCRYPT_AES_WRAP_KEY_BLOB, out, nw, &got, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(got, nw);
    CHECK(same(out, wr, nw)); CHECK(out[nw] == 0xEE);
    got = 0;
    EXPECT_EQ(P_Exp(dk.h, kk.h, BCRYPT_AES_WRAP_KEY_BLOB, out, nw - 1, &got, 0), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, nw);
    /* unwrap */
    BCRYPT_KEY_HANDLE k2 = SENT;
    s = P_Imp(a, kk.h, BCRYPT_AES_WRAP_KEY_BLOB, &k2, NULL, 0, wr, nw, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE kd[64]; got = 0;
        EXPECT_EQ(P_Exp(k2, NULL, BCRYPT_KEY_DATA_BLOB, kd, 64, &got, 0), 0);
        EXPECT_EQ(got, 12 + nd);
        CHECK(same(kd + 12, datab, nd));
        P_Destroy(k2);
    }
    bsc_free(&kk); bsc_free(&dk); bsc_close(a);
}
TEST(bsc_wrap_rfc3394_128_in_128) { wrap_case("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"); }
TEST(bsc_wrap_rfc3394_192_in_128) { wrap_case("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"); }
TEST(bsc_wrap_rfc3394_256_in_256) { wrap_case("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"); }
TEST(bsc_wrap_rfc3394_192_in_192) { wrap_case("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"); }
TEST(bsc_wrap_rfc3394_256_in_192) { wrap_case("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1"); }
TEST(bsc_wrap_unwrap_tampered_blob_fails) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    BYTE kekb[16], wr[24]; hx("000102030405060708090A0B0C0D0E0F", kekb); hx("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", wr);
    bkey kk; EXPECT_EQ(bsc_gen(a, &kk, kekb, 16), 0);
    BCRYPT_KEY_HANDLE k2 = SENT;
    for (int i = 0; i < 24; i += 7) {
        BYTE bad[24]; memcpy(bad, wr, 24); bad[i] ^= 1;
        NTSTATUS s = P_Imp(a, kk.h, BCRYPT_AES_WRAP_KEY_BLOB, &k2, NULL, 0, bad, 24, 0);
        CHECKF(s < 0, "tampered byte %d accepted", i);
        if (s == 0) P_Destroy(k2);
        k2 = SENT;
    }
    NTSTATUS s = P_Imp(a, kk.h, BCRYPT_AES_WRAP_KEY_BLOB, &k2, NULL, 0, wr, 23, 0);
    CHECK(s < 0);
    s = P_Imp(a, kk.h, BCRYPT_AES_WRAP_KEY_BLOB, &k2, NULL, 0, wr, 16, 0);
    CHECK(s < 0);
    bsc_free(&kk); bsc_close(a);
}
TEST(bsc_wrap_requires_export_key) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    bkey dk; EXPECT_EQ(bsc_gen(a, &dk, KEY, 16), 0);
    ULONG need = 0xAAAA;
    NTSTATUS s = P_Exp(dk.h, NULL, BCRYPT_AES_WRAP_KEY_BLOB, NULL, 0, &need, 0);
    CHECK(s < 0);
    t_note("AES wrap without wrapping key -> 0x%lx", s);
    bsc_free(&dk); bsc_close(a);
}
TEST(bsc_wrap_blob_type_not_available_to_non_aes) {
    BCRYPT_ALG_HANDLE d = bsc_open(L"DES", ECB); if (!d) { t_skip("DES"); return; }
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB);
    bkey dk, kk; EXPECT_EQ(bsc_gen(d, &dk, KEY, 8), 0); EXPECT_EQ(bsc_gen(a, &kk, KEY, 16), 0);
    ULONG need = 0xAAAA;
    NTSTATUS s = P_Exp(dk.h, kk.h, BCRYPT_AES_WRAP_KEY_BLOB, NULL, 0, &need, 0);
    t_note("wrap of an 8-byte DES key under an AES KEK -> 0x%lx (size %lu)", s, need);
    bsc_free(&dk); bsc_free(&kk); bsc_close(d); bsc_close(a);
}

/* ---- BCryptGenerateSymmetricKey: flags and truncation (MSCryptGenerateSymmetricKey) ---------------------------- */
TEST(bsc_gen_invalid_flag_bits) {
    WINE_SKIP("flag validation");
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG fl[] = { 1, 2, 4, 8, 0x10, 0x40, 0x200, 0x400, 0x10000, 0x80000000, 0xFFFFFFFF };
    for (int i = 0; i < 11; i++) {
        BCRYPT_KEY_HANDLE k = SENT; ULONG ol = bsc_objlen(a); BYTE *obj = (BYTE *)calloc(1, ol + 64);
        NTSTATUS s = P_GenKey(a, &k, obj, ol, (PUCHAR)KEY, 16, fl[i]);
        CHECKF(s == NS_INVALID_PARAM, "dwFlags=0x%lx -> 0x%lx", fl[i], s);
        CHECK(k == SENT);
        free(obj);
    }
    bsc_close(a);
}
TEST(bsc_gen_flag_gcm_only_rejected_for_other_modes) {
    WINE_SKIP("flag validation");
    /* bit 0x20 (generate-IV for GCM) is only valid on an AES-GCM algorithm object */
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    BCRYPT_KEY_HANDLE k = SENT; ULONG ol = bsc_objlen(a); BYTE *obj = (BYTE *)calloc(1, ol + 64);
    EXPECT_EQ(P_GenKey(a, &k, obj, ol, (PUCHAR)KEY, 16, 0x20), NS_INVALID_PARAM);
    EXPECT_EQ(P_GenKey(a, &k, obj, ol, (PUCHAR)KEY, 16, 0x100), NS_INVALID_PARAM);   /* XTS only */
    free(obj); bsc_close(a);
}
TEST(bsc_gen_secret_truncated_to_max_length) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    BYTE big[128]; for (int i = 0; i < 128; i++) big[i] = (BYTE)(i * 3 + 1);
    ULONG lens[] = { 33, 34, 40, 48, 64, 100, 128 };
    bkey ref; EXPECT_EQ(bsc_gen(a, &ref, big, 32), 0);
    BYTE pt[16] = {5}, rc[16]; ULONG got = 0;
    EXPECT_EQ(enc(ref.h, pt, 16, NULL, 0, rc, 16, &got, 0), 0);
    for (int i = 0; i < 7; i++) {
        bkey k; NTSTATUS s = bsc_gen(a, &k, big, lens[i]);
        CHECKF(s == 0, "len %lu -> 0x%lx", lens[i], s);
        if (s == 0) {
            BYTE c[16]; enc(k.h, pt, 16, NULL, 0, c, 16, &got, 0);
            CHECKF(same(c, rc, 16), "len %lu key is not the first 32 bytes", lens[i]);
            ULONG str = 0, r = 0; P_GetProp(k.h, BCRYPT_KEY_STRENGTH, (PUCHAR)&str, 4, &r, 0);
            if (!t_is_wine()) CHECKF(str == 256, "len %lu strength %lu", lens[i], str);
            bsc_free(&k);
        }
    }
    bsc_free(&ref); bsc_close(a);
}
TEST(bsc_gen_key_length_must_follow_increment) {
    WINE_SKIP("key length validation");
    /* AES: min 16, max 32, increment 8 bytes -> 17..23, 25..31 are invalid */
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    for (ULONG n = 1; n <= 32; n++) {
        bkey k; NTSTATUS s = bsc_gen(a, &k, KEY, n);
        int valid = (n == 16 || n == 24 || n == 32);
        CHECKF(valid ? s == 0 : s == NS_INVALID_PARAM, "len %lu -> 0x%lx", n, s);
        if (s == 0) bsc_free(&k); else free(k.obj);
    }
    bsc_close(a);
}
TEST(bsc_gen_des_requires_exactly_8_bytes) {
    BCRYPT_ALG_HANDLE d = bsc_open(L"DES", ECB); if (!d) { t_skip("DES"); return; }
    for (ULONG n = 1; n <= 24; n++) {
        bkey k; NTSTATUS s = bsc_gen(d, &k, KEY, n);
        CHECKF(n == 8 ? s == 0 : s == NS_INVALID_PARAM, "len %lu -> 0x%lx", n, s);
        if (s == 0) bsc_free(&k); else free(k.obj);
    }
    bsc_close(d);
}

/* ---- XTS-AES ------------------------------------------------------------------------------------------------------ */
TEST(bsc_xts_roundtrip) {
    BCRYPT_ALG_HANDLE a = NULL;
    REQUIRE(P_Open);
    if (P_Open(&a, BCRYPT_XTS_AES_ALGORITHM, NULL, 0) != 0) { t_skip("XTS-AES not available on this system"); return; }
    ULONG kl[3] = {0}, r = 0;
    NTSTATUS s = P_GetProp(a, BCRYPT_KEY_LENGTHS, (PUCHAR)kl, 12, &r, 0);
    t_note("XTS key lengths status 0x%lx min=%lu max=%lu incr=%lu", s, kl[0], kl[1], kl[2]);
    bkey k; BYTE sec[64]; for (int i = 0; i < 64; i++) sec[i] = (BYTE)(0x11 * (i / 32 + 1) + i);
    s = bsc_gen(a, &k, sec, 32);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE pt[512], ct[512], back[512], tweak[16] = {1}, tweak2[16] = {1};
        for (int i = 0; i < 512; i++) pt[i] = (BYTE)i;
        ULONG got = 0;
        s = enc(k.h, pt, 512, tweak, 16, ct, 512, &got, 0);
        t_note("XTS encrypt 512 -> 0x%lx (%lu)", s, got);
        if (s == 0) {
            CHECK(!same(ct, pt, 512));
            s = dec(k.h, ct, 512, tweak2, 16, back, 512, &got, 0);
            EXPECT_EQ(s, 0); CHECK(same(back, pt, 512));
        }
        bsc_free(&k);
    }
    bsc_close(a);
}
TEST(bsc_xts_key_halves_must_differ_note) {
    BCRYPT_ALG_HANDLE a = NULL;
    REQUIRE(P_Open);
    if (P_Open(&a, BCRYPT_XTS_AES_ALGORITHM, NULL, 0) != 0) { t_skip("XTS-AES not available on this system"); return; }
    BYTE same_halves[32]; memset(same_halves, 0x33, 32);
    bkey k; NTSTATUS s = bsc_gen(a, &k, same_halves, 32);
    t_note("XTS key with identical halves -> 0x%lx", s);
    if (s == 0) bsc_free(&k); else free(k.obj);
    ULONG n[] = { 16, 24, 48, 64, 128 };
    for (int i = 0; i < 5; i++) {
        BYTE sec[128]; for (int j = 0; j < 128; j++) sec[j] = (BYTE)(j * 7 + 1);
        s = bsc_gen(a, &k, sec, n[i]);
        t_note("XTS %lu-byte secret -> 0x%lx", n[i], s);
        if (s == 0) bsc_free(&k); else free(k.obj);
    }
    bsc_close(a);
}

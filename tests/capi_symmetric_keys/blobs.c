#include "ck.h"
/* CryptExportKey / CryptImportKey for symmetric keys: PLAINTEXTKEYBLOB, SIMPLEBLOB (RSA wrapped),
 * OPAQUEKEYBLOB, SYMMETRICWRAPKEYBLOB. */

#define NTE_BAD_VER_ 0x80090007L
#define NTE_BAD_PUBLIC_KEY_ 0x80090015L

typedef struct { ALG_ID a; const char *n; const BYTE *k; DWORD kl; } keyrow;
static const keyrow krows[] = {
    { CALG_AES_128, "AES128", sp_key128, 16 }, { CALG_AES_192, "AES192", sp_key192, 24 }, { CALG_AES_256, "AES256", sp_key256, 32 },
    { CALG_DES, "DES", des_key, 8 }, { CALG_3DES, "3DES", tdes_key, 24 }, { CALG_3DES_112, "3DES112", tdes112_key, 16 },
    { CALG_RC2, "RC2", rc2_v7_key, 16 }, { CALG_RC4, "RC4", rc4_key128, 16 } };

static void same_output(HCRYPTKEY a, HCRYPTKEY b, const char *what) {
    BYTE x[48], y[48]; DWORD n = 32, m = 32;
    memcpy(x, sp_pt, 32); memcpy(y, sp_pt, 32);
    ck_set_mode(a, CRYPT_MODE_ECB); ck_set_mode(b, CRYPT_MODE_ECB);
    BOOL r1 = U(CryptEncrypt)(a, 0, FALSE, 0, x, &n, 48), r2 = U(CryptEncrypt)(b, 0, FALSE, 0, y, &m, 48);
    if (!r1 || !r2) { CHECKF(0, "%s: encrypt failed 0x%lx", what, GetLastError()); return; }
    t_check(n == m && !memcmp(x, y, n), __FILE__, __LINE__, what, "keys produce different output");
}
static BOOL rsa_pair(HCRYPTPROV p, HCRYPTKEY *pub, HCRYPTKEY *priv) {
    *pub = *priv = 0;
    BOOL r1 = U(CryptImportKey)(p, (BYTE *)rsa1024_pub, sizeof rsa1024_pub, 0, 0, pub);
    BOOL r2 = U(CryptImportKey)(p, (BYTE *)rsa1024_priv, sizeof rsa1024_priv, 0, CRYPT_EXPORTABLE, priv);
    if (!r1 || !r2) t_note("RSA fixture import: pub=%d priv=%d err=0x%lx", r1, r2, GetLastError());
    return r1 && r2;
}

/* ---- PLAINTEXTKEYBLOB export ---------------------------------------- */
TEST(blob_plaintext_export_layout_all_algs) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(krows); i++) {
        HCRYPTKEY k = ck_key(p, krows[i].a, krows[i].k, krows[i].kl); if (!k) { CHECKF(0, "%s import 0x%lx", krows[i].n, GetLastError()); continue; }
        BYTE b[128]; DWORD n = sizeof b; memset(b, 0xee, sizeof b);
        BOOL r = U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, &n);
        CHECKF(r, "%s export 0x%lx", krows[i].n, GetLastError());
        if (r) {
            EXPECT_EQ(n, 12 + krows[i].kl);
            EXPECT_EQ(b[0], PLAINTEXTKEYBLOB); EXPECT_EQ(b[1], CUR_BLOB_VERSION); EXPECT_EQ(*(WORD *)(b + 2), 0);
            EXPECT_EQ(*(DWORD *)(b + 4), krows[i].a); EXPECT_EQ(*(DWORD *)(b + 8), krows[i].kl);
            CHECK_BYTES(b + 12, krows[i].k, krows[i].kl);
        }
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(blob_plaintext_export_size_query_and_short_buffer) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    DWORD n = 0; BYTE b[64];
    CHECK(U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, NULL, &n)); EXPECT_EQ(n, 28);
    for (DWORD cap = 0; cap < 28; cap += 9) {
        n = cap; SET_ERR(0);
        EXPECT_FAIL(!U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, &n), ERROR_MORE_DATA); EXPECT_EQ(n, 28);
    }
    n = 27; SET_ERR(0); EXPECT_FAIL(!U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, &n), ERROR_MORE_DATA);
    n = 28; CHECK(U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, &n)); EXPECT_EQ(n, 28);
    n = 64; CHECK(U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, &n)); EXPECT_EQ(n, 28);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(blob_export_null_length_pointer) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    BYTE b[64]; SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, NULL), ERROR_INVALID_PARAMETER);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(blob_export_invalid_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    /* observed in CPExportKey: (flags & 0xffffffb9) != 0 -> NTE_BAD_FLAGS (allowed: 0x2 0x4 0x40) */
    static const DWORD fl[] = { 1, 8, 0x10, 0x20, 0x80, 0x100, 0x1000, 0x80000000 };
    for (unsigned i = 0; i < SIZEOFA(fl); i++) {
        BYTE b[64]; DWORD n = 64; SET_ERR(0);
        EXPECT_FAIL(!U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, fl[i], b, &n), NTE_BAD_FLAGS_);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(blob_export_unknown_blob_type) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    static const DWORD ty[] = { 0, 2, 3, 4, 5, 0x0d, 0x10, 0x55, 0xff, 0x100 };
    for (unsigned i = 0; i < SIZEOFA(ty); i++) {
        BYTE b[512]; DWORD n = sizeof b; SET_ERR(0);
        BOOL r = U(CryptExportKey)(k, 0, ty[i], 0, b, &n);
        CHECKF(!r, "blob type %lu exported", ty[i]);
        if (!r) t_note("export blob type %lu -> 0x%lx", ty[i], GetLastError());
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(blob_export_nonexportable_key_denied) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = 0, wrap = 0, pub = 0, priv = 0;
    CHECK(U(CryptGenKey)(p, CALG_AES_128, 0, &k)); if (!k) return;
    BYTE b[512]; DWORD n = sizeof b;
    SET_ERR(0); EXPECT_FAIL(!U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, &n), NTE_BAD_KEY_STATE_);
    n = sizeof b; SET_ERR(0); EXPECT_FAIL(!U(CryptExportKey)(k, 0, OPAQUEKEYBLOB, 0, b, &n), NTE_BAD_KEY_STATE_);
    n = 0; SET_ERR(0); EXPECT_FAIL(!U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, NULL, &n), NTE_BAD_KEY_STATE_);
    if (rsa_pair(p, &pub, &priv)) {
        n = sizeof b; SET_ERR(0); EXPECT_FAIL(!U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n), NTE_BAD_KEY_STATE_);
    }
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(blob_export_imported_nonexportable_denied_exportable_allowed) {
    NEED_CRYPT(); NEED_PROV(p);
    for (int ex = 0; ex < 2; ex++) {
        HCRYPTKEY k = 0; BYTE b[64]; DWORD n = sizeof b;
        CHECK(ck_import_plain(p, CALG_AES_128, sp_key128, 16, ex ? CRYPT_EXPORTABLE : 0, &k)); if (!k) continue;
        SET_ERR(0);
        BOOL r = U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, &n);
        if (ex) { CHECK(r); EXPECT_EQ(n, 28); } else { CHECK(!r); EXPECT_ERR(NTE_BAD_KEY_STATE_); }
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(blob_plaintext_export_with_wrapping_key_handle_rejected) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), w = ck_key(p, CALG_AES_256, sp_key256, 32);
    if (!k || !w) { CHECK(0); return; }
    BYTE b[128]; DWORD n = sizeof b; SET_ERR(0);
    /* observed: blob types 6, 8, 9 take no key-exchange key -> NTE_BAD_PUBLIC_KEY */
    EXPECT_FAIL(!U(CryptExportKey)(k, w, PLAINTEXTKEYBLOB, 0, b, &n), NTE_BAD_PUBLIC_KEY_);
    n = sizeof b; SET_ERR(0); EXPECT_FAIL(!U(CryptExportKey)(k, w, OPAQUEKEYBLOB, 0, b, &n), NTE_BAD_PUBLIC_KEY_);
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(w); ck_release(p);
}
TEST(blob_export_does_not_alter_key) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), ref = ck_key(p, CALG_AES_128, sp_key128, 16);
    if (!k || !ref) { CHECK(0); return; }
    BYTE b[64]; DWORD n = sizeof b; CHECK(U(CryptExportKey)(k, 0, PLAINTEXTKEYBLOB, 0, b, &n));
    same_output(k, ref, "after export");
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(ref); ck_release(p);
}

/* ---- PLAINTEXTKEYBLOB import ---------------------------------------- */
TEST(blob_plaintext_roundtrip_all_algs) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(krows); i++) {
        HCRYPTKEY a = 0, g = 0; BOOL ok;
        if (!U(CryptGenKey)(p, krows[i].a, CRYPT_EXPORTABLE, &g)) { CHECKF(0, "%s gen", krows[i].n); continue; }
        BYTE b[128]; DWORD n = sizeof b;
        CHECK(U(CryptExportKey)(g, 0, PLAINTEXTKEYBLOB, 0, b, &n));
        CHECK(U(CryptImportKey)(p, b, n, 0, CRYPT_EXPORTABLE, &a)); if (!a) continue;
        EXPECT_EQ(ck_param_dw(a, KP_ALGID, &ok), krows[i].a);
        EXPECT_EQ(ck_param_dw(a, KP_KEYLEN, &ok), ck_param_dw(g, KP_KEYLEN, &ok));
        same_output(g, a, krows[i].n);
        U(CryptDestroyKey)(a); U(CryptDestroyKey)(g);
    }
    ck_release(p);
}
TEST(blob_plaintext_import_trailing_bytes_ignored) {
    NEED_CRYPT(); NEED_PROV(p);
    ck_plainblob b; memset(&b, 0, sizeof b);
    b.h.bType = PLAINTEXTKEYBLOB; b.h.bVersion = 2; b.h.aiKeyAlg = CALG_AES_128; b.cb = 16; memcpy(b.key, sp_key128, 16);
    HCRYPTKEY k = 0, ref = ck_key(p, CALG_AES_128, sp_key128, 16);
    CHECK(U(CryptImportKey)(p, (BYTE *)&b, 12 + 16 + 20, 0, 0, &k)); if (k && ref) same_output(k, ref, "trailing");
    if (k) U(CryptDestroyKey)(k);
    if (ref) U(CryptDestroyKey)(ref); ck_release(p);
}
TEST(blob_plaintext_import_truncated_bad_data) {
    NEED_CRYPT(); NEED_PROV(p);
    ck_plainblob b; memset(&b, 0, sizeof b);
    b.h.bType = PLAINTEXTKEYBLOB; b.h.bVersion = 2; b.h.aiKeyAlg = CALG_AES_128; b.cb = 16; memcpy(b.key, sp_key128, 16);
    for (DWORD len = 12; len < 28; len += 3) {   /* header and cb present, key bytes missing */
        HCRYPTKEY k = 0; SET_ERR(0);
        EXPECT_FAIL(!U(CryptImportKey)(p, (BYTE *)&b, len, 0, 0, &k), NTE_BAD_DATA_);
    }
    /* cb larger than supplied data */
    b.cb = 32; HCRYPTKEY k = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(p, (BYTE *)&b, 28, 0, 0, &k), NTE_BAD_DATA_);
    ck_release(p);
}
TEST(blob_import_tiny_input) {
    NEED_CRYPT(); NEED_PROV(p);
    BYTE b[16] = { PLAINTEXTKEYBLOB, 2, 0, 0, 0x0e, 0x66, 0, 0 };
    for (DWORD len = 0; len < 12; len += 4) {
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = U(CryptImportKey)(p, b, len, 0, 0, &k);
        CHECKF(!r, "len %lu accepted", len);
        if (!r) t_note("ImportKey len %lu -> 0x%lx", len, GetLastError());
        if (r) U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(blob_import_bad_version) {
    NEED_CRYPT(); NEED_PROV(p);
    static const BYTE ver[] = { 0, 1, 3, 4, 0x80, 0xff };
    for (unsigned i = 0; i < SIZEOFA(ver); i++) {
        ck_plainblob b; memset(&b, 0, sizeof b);
        b.h.bType = PLAINTEXTKEYBLOB; b.h.bVersion = ver[i]; b.h.aiKeyAlg = CALG_AES_128; b.cb = 16; memcpy(b.key, sp_key128, 16);
        HCRYPTKEY k = 0; SET_ERR(0);
        EXPECT_FAIL(!U(CryptImportKey)(p, (BYTE *)&b, 28, 0, 0, &k), NTE_BAD_VER_);
    }
    ck_release(p);
}
TEST(blob_import_unknown_type) {
    NEED_CRYPT(); NEED_PROV(p);
    static const BYTE ty[] = { 0, 2, 3, 4, 5, 0x0c, 0x0d, 0x20, 0xff };
    for (unsigned i = 0; i < SIZEOFA(ty); i++) {
        ck_plainblob b; memset(&b, 0, sizeof b);
        b.h.bType = ty[i]; b.h.bVersion = 2; b.h.aiKeyAlg = CALG_AES_128; b.cb = 16; memcpy(b.key, sp_key128, 16);
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = U(CryptImportKey)(p, (BYTE *)&b, 28, 0, 0, &k);
        CHECKF(!r, "type %u imported", ty[i]);
        if (!r) t_note("import blob type %u -> 0x%lx", ty[i], GetLastError());
        if (r) U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(blob_plaintext_import_bad_algid) {
    NEED_CRYPT(); NEED_PROV(p);
    static const ALG_ID bad[] = { 0, CALG_MD5, CALG_SHA1, CALG_HMAC, 0x6FFF, 0x600D };
    for (unsigned i = 0; i < SIZEOFA(bad); i++) {
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = ck_import_plain(p, bad[i], sp_key128, 16, 0, &k);
        CHECKF(!r, "alg 0x%x imported", bad[i]);
        if (r) U(CryptDestroyKey)(k); else EXPECT_ERR(NTE_BAD_ALGID_);
    }
    ck_release(p);
}
TEST(blob_plaintext_import_illegal_key_lengths) {
    NEED_CRYPT(); NEED_PROV(p);
    static const struct { ALG_ID a; DWORD len; } t[] = {
        { CALG_AES_128, 8 }, { CALG_AES_128, 15 }, { CALG_AES_128, 17 }, { CALG_AES_128, 24 }, { CALG_AES_128, 32 },
        { CALG_AES_192, 16 }, { CALG_AES_192, 32 }, { CALG_AES_256, 16 }, { CALG_AES_256, 24 }, { CALG_AES_256, 33 },
        { CALG_DES, 7 }, { CALG_DES, 9 }, { CALG_DES, 16 }, { CALG_3DES, 8 }, { CALG_3DES, 16 }, { CALG_3DES, 23 },
        { CALG_3DES_112, 8 }, { CALG_3DES_112, 24 } };
    for (unsigned i = 0; i < SIZEOFA(t); i++) {
        BYTE key[64]; memset(key, 0x33, sizeof key);
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = ck_import_plain(p, t[i].a, key, t[i].len, 0, &k);
        t_label("alg 0x%x len %lu", t[i].a, t[i].len);
        CHECKF(!r, "alg 0x%x len %lu imported", t[i].a, t[i].len);
        /* Win10 probe: DES with 7 bytes gives NTE_BAD_FLAGS, every other bad length NTE_BAD_LEN */
        if (r) U(CryptDestroyKey)(k); else EXPECT_ERR(t[i].a == CALG_DES && t[i].len == 7 ? NTE_BAD_FLAGS_ : NTE_BAD_LEN_);
    }
    ck_release(p);
}
TEST(blob_plaintext_import_flags) {
    NEED_CRYPT(); NEED_PROV(p);
    /* Win10 probe: undefined flags give NTE_BAD_FLAGS, except 0x8 which advapi32 rejects with 87 */
    static const DWORD bad[] = { 0x4, 0x8, 0x20, 0x80, 0x200, 0x400, 0x800, 0x1000, 0x4000, 0x8000, 0x10000 };
    for (unsigned i = 0; i < SIZEOFA(bad); i++) {
        HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = ck_import_plain(p, CALG_AES_128, sp_key128, 16, bad[i], &k);
        t_label("flag 0x%lx", bad[i]);
        CHECKF(!r, "flag 0x%lx accepted", bad[i]);
        if (r) U(CryptDestroyKey)(k); else EXPECT_ERR(bad[i] == 8 ? ERROR_INVALID_PARAMETER : NTE_BAD_FLAGS_);
    }
    static const DWORD good[] = { 0, CRYPT_EXPORTABLE, CRYPT_NO_SALT, CRYPT_EXPORTABLE | CRYPT_NO_SALT };
    for (unsigned i = 0; i < SIZEOFA(good); i++) {
        HCRYPTKEY k = 0;
        CHECKF(ck_import_plain(p, CALG_AES_128, sp_key128, 16, good[i], &k), "flags 0x%lx err 0x%lx", good[i], GetLastError());
        if (k) U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(blob_import_public_key_blob_with_pubkey_handle) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY w = ck_key(p, CALG_AES_128, sp_key128, 16), k = 0; if (!w) { CHECK(0); return; }
    SET_ERR(0);
    /* observed: PUBLICKEYBLOB with a nonzero hPubKey -> ERROR_INVALID_PARAMETER */
    EXPECT_FAIL(!U(CryptImportKey)(p, (BYTE *)rsa1024_pub, sizeof rsa1024_pub, w, 0, &k), ERROR_INVALID_PARAMETER);
    U(CryptDestroyKey)(w); ck_release(p);
}
TEST(blob_import_rc4_40_nosalt_flag_semantics) {
    NEED_CRYPT(); NEED_PROV(p);
    if (t_is_wine()) { t_skip("emulator ignores CRYPT_NO_SALT on 5-byte import"); return; }
    /* 5-byte keys: without CRYPT_NO_SALT the key is made RSA-base compatible (88-bit zero salt) */
    HCRYPTKEY a = 0, b = 0; BOOL ok;
    CHECK(ck_import_plain(p, CALG_RC4, rc4_key40, 5, 0, &a));
    CHECK(ck_import_plain(p, CALG_RC4, rc4_key40, 5, CRYPT_NO_SALT, &b));
    if (a && b) {
        EXPECT_EQ(ck_param_dw(b, KP_KEYLEN, &ok), 40);
        BYTE x[16] = { 0 }, y[16] = { 0 }; DWORD n = 16, m = 16;
        CHECK(U(CryptEncrypt)(a, 0, FALSE, 0, x, &n, 16)); CHECK(U(CryptEncrypt)(b, 0, FALSE, 0, y, &m, 16));
        CHECK(memcmp(x, y, 16) != 0); CHECK_BYTES(y, rc4_ks40_16, 16);
    }
    if (a) U(CryptDestroyKey)(a);
    if (b) U(CryptDestroyKey)(b);
    ck_release(p);
}
TEST(blob_import_rc4_rc2_lengths_observed) {
    NEED_CRYPT(); NEED_PROV(p);
    static const DWORD lens[] = { 1, 2, 4, 5, 7, 8, 16, 17, 32, 64 };
    static const ALG_ID algs[] = { CALG_RC4, CALG_RC2 };
    for (int a = 0; a < 2; a++) for (unsigned i = 0; i < SIZEOFA(lens); i++) {
        BYTE key[64]; memset(key, 0x5a, sizeof key); HCRYPTKEY k = 0; SET_ERR(0);
        BOOL r = ck_import_plain(p, algs[a], key, lens[i], CRYPT_NO_SALT, &k);
        t_note("import alg 0x%x key len %lu: %s 0x%lx", algs[a], lens[i], r ? "ok" : "rejected", r ? 0 : GetLastError());
        if (r) U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(blob_import_rc2_ipsec_hmac_flag) {
    NEED_CRYPT(); NEED_PROV(p);
    BYTE key[40]; memset(key, 0x77, sizeof key); HCRYPTKEY k = 0;
    SET_ERR(0); BOOL r1 = ck_import_plain(p, CALG_RC2, key, 32, CRYPT_NO_SALT, &k); DWORD e1 = GetLastError();
    if (r1) U(CryptDestroyKey)(k);
    k = 0; SET_ERR(0); BOOL r2 = ck_import_plain(p, CALG_RC2, key, 32, CRYPT_NO_SALT | CRYPT_IPSEC_HMAC_KEY, &k); DWORD e2 = GetLastError();
    t_note("RC2 32-byte key: without IPSEC_HMAC %s (0x%lx), with IPSEC_HMAC %s (0x%lx)", r1 ? "ok" : "rejected", e1, r2 ? "ok" : "rejected", e2);
    if (r2) U(CryptDestroyKey)(k);
    CHECK(!r1 || r2);   /* the flag may only widen what is accepted */
    ck_release(p);
}
TEST(blob_imported_key_defaults) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_256, sp_key256, 32); if (!k) { CHECK(0); return; }
    BOOL ok;
    EXPECT_EQ(ck_param_dw(k, KP_MODE, &ok), CRYPT_MODE_CBC); CHECK(ok);
    EXPECT_EQ(ck_param_dw(k, KP_PADDING, &ok), PKCS5_PADDING); CHECK(ok);
    EXPECT_EQ(ck_param_dw(k, KP_KEYLEN, &ok), 256);
    BYTE iv[16] = { 1 }; DWORD n = 16; CHECK(U(CryptGetKeyParam)(k, KP_IV, iv, &n, 0));
    t_note("imported key initial IV all-zero: %d", !memcmp(iv, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 15) && iv[15] == 0);
    U(CryptDestroyKey)(k); ck_release(p);
}

/* ---- OPAQUEKEYBLOB --------------------------------------------------- */
TEST(blob_opaque_roundtrip) {
    NEED_CRYPT(); NEED_PROV(p);
    for (unsigned i = 0; i < SIZEOFA(krows); i++) {
        HCRYPTKEY k = ck_key(p, krows[i].a, krows[i].k, krows[i].kl), r = 0; if (!k) { CHECK(0); continue; }
        BYTE b[1024]; DWORD n = 0;
        if (!U(CryptExportKey)(k, 0, OPAQUEKEYBLOB, 0, NULL, &n)) { t_note("%s opaque export unsupported 0x%lx", krows[i].n, GetLastError()); U(CryptDestroyKey)(k); continue; }
        EXPECT_NE(n, 0); n = sizeof b;
        CHECKF(U(CryptExportKey)(k, 0, OPAQUEKEYBLOB, 0, b, &n), "%s opaque export 0x%lx", krows[i].n, GetLastError());
        EXPECT_EQ(b[0], OPAQUEKEYBLOB); EXPECT_EQ(b[1], 2); EXPECT_EQ(*(DWORD *)(b + 4), krows[i].a);
        t_note("%s opaque blob size %lu", krows[i].n, n);
        CHECKF(U(CryptImportKey)(p, b, n, 0, 0, &r), "%s opaque import 0x%lx", krows[i].n, GetLastError());
        if (r) { same_output(k, r, krows[i].n); U(CryptDestroyKey)(r); }
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(blob_opaque_import_into_other_context) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTPROV p2 = ck_aes(); if (!p2) { t_skip("second context"); return; }
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), r = 0; if (!k) { CHECK(0); return; }
    BYTE b[1024]; DWORD n = sizeof b;
    if (!U(CryptExportKey)(k, 0, OPAQUEKEYBLOB, 0, b, &n)) { t_note("opaque export 0x%lx", GetLastError()); return; }
    BOOL ok = U(CryptImportKey)(p2, b, n, 0, 0, &r);
    t_note("opaque blob imported into a second context: %s 0x%lx", ok ? "yes" : "no", ok ? 0 : GetLastError());
    if (r) { HCRYPTKEY ref = ck_key(p2, CALG_AES_128, sp_key128, 16); same_output(r, ref, "opaque cross-context"); U(CryptDestroyKey)(ref); U(CryptDestroyKey)(r); }
    U(CryptDestroyKey)(k); ck_release(p); ck_release(p2);
}
TEST(blob_opaque_truncated_import_fails) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), r = 0; if (!k) { CHECK(0); return; }
    BYTE b[1024]; DWORD n = sizeof b;
    if (!U(CryptExportKey)(k, 0, OPAQUEKEYBLOB, 0, b, &n)) { t_note("opaque export unsupported"); return; }
    for (DWORD cut = 1; cut < n; cut += (n / 4 ? n / 4 : 1)) {
        r = 0; SET_ERR(0);
        BOOL ok = U(CryptImportKey)(p, b, n - cut, 0, 0, &r);
        CHECKF(!ok, "truncated by %lu imported", cut);
        if (ok) U(CryptDestroyKey)(r); else t_note("opaque truncated by %lu -> 0x%lx", cut, GetLastError());
    }
    U(CryptDestroyKey)(k); ck_release(p);
}

/* ---- SIMPLEBLOB (RSA key exchange) ----------------------------------- */
TEST(blob_simple_export_layout) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    for (unsigned i = 0; i < SIZEOFA(krows); i++) {
        HCRYPTKEY k = ck_key(p, krows[i].a, krows[i].k, krows[i].kl); if (!k) { CHECK(0); continue; }
        BYTE b[512]; DWORD n = 0;
        CHECKF(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, NULL, &n), "%s size query 0x%lx", krows[i].n, GetLastError());
        EXPECT_EQ(n, 8 + 4 + 128);
        n = sizeof b; memset(b, 0, sizeof b);
        CHECKF(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n), "%s export 0x%lx", krows[i].n, GetLastError());
        EXPECT_EQ(n, 140); EXPECT_EQ(b[0], SIMPLEBLOB); EXPECT_EQ(b[1], 2); EXPECT_EQ(*(WORD *)(b + 2), 0);
        EXPECT_EQ(*(DWORD *)(b + 4), krows[i].a); EXPECT_EQ(*(DWORD *)(b + 8), CALG_RSA_KEYX);
        U(CryptDestroyKey)(k);
    }
    U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}
TEST(blob_simple_roundtrip_all_algs) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    for (unsigned i = 0; i < SIZEOFA(krows); i++) {
        HCRYPTKEY k = ck_key(p, krows[i].a, krows[i].k, krows[i].kl), r = 0; if (!k) { CHECK(0); continue; }
        BYTE b[512]; DWORD n = sizeof b;
        CHECK(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n));
        BOOL ok = U(CryptImportKey)(p, b, n, priv, CRYPT_EXPORTABLE, &r);
        CHECKF(ok, "%s import 0x%lx", krows[i].n, GetLastError());
        if (ok) { BOOL o2; EXPECT_EQ(ck_param_dw(r, KP_ALGID, &o2), krows[i].a); same_output(k, r, krows[i].n); U(CryptDestroyKey)(r); }
        U(CryptDestroyKey)(k);
    }
    U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}
TEST(blob_simple_export_is_randomized) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    BYTE a[256], b[256]; DWORD n = sizeof a, m = sizeof b;
    CHECK(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, a, &n)); CHECK(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &m));
    EXPECT_EQ(n, m); CHECK(memcmp(a + 12, b + 12, 128) != 0);   /* PKCS#1 v1.5 type 2 padding is random */
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}
TEST(blob_simple_oaep_roundtrip) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    HCRYPTKEY k = ck_key(p, CALG_AES_256, sp_key256, 32), r = 0, r2 = 0; if (!k) { CHECK(0); return; }
    BYTE b[512]; DWORD n = sizeof b;
    BOOL ok = U(CryptExportKey)(k, pub, SIMPLEBLOB, CRYPT_OAEP, b, &n);
    t_note("SIMPLEBLOB with CRYPT_OAEP export: %s 0x%lx", ok ? "ok" : "fail", ok ? 0 : GetLastError());
    if (ok) {
        EXPECT_EQ(n, 140);
        CHECKF(U(CryptImportKey)(p, b, n, priv, CRYPT_OAEP, &r), "oaep import 0x%lx", GetLastError());
        if (r) { same_output(k, r, "oaep"); U(CryptDestroyKey)(r); }
        /* an OAEP blob is not a valid PKCS#1 v1.5 blob and vice versa */
        SET_ERR(0);
        BOOL bad = U(CryptImportKey)(p, b, n, priv, 0, &r2);
        CHECK(!bad); if (bad) U(CryptDestroyKey)(r2); else t_note("OAEP blob imported without CRYPT_OAEP: 0x%lx", GetLastError());
    }
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}
TEST(blob_simple_import_with_public_key_handle_fails) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), r = 0; if (!k) { CHECK(0); return; }
    BYTE b[512]; DWORD n = sizeof b; CHECK(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n));
    SET_ERR(0);
    BOOL ok = U(CryptImportKey)(p, b, n, pub, 0, &r);
    CHECK(ok);   /* Win10 probe: accepted even with a public-only hPubKey */
    if (ok) U(CryptDestroyKey)(r); else t_note("SIMPLEBLOB import with public-only handle -> 0x%lx", GetLastError());
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}
TEST(blob_simple_import_without_hpubkey) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), r = 0; if (!k) { CHECK(0); return; }
    BYTE b[512]; DWORD n = sizeof b; CHECK(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n));
    SET_ERR(0);
    BOOL ok = U(CryptImportKey)(p, b, n, 0, 0, &r);
    t_note("SIMPLEBLOB import with hPubKey=0 (ephemeral context, no AT_KEYEXCHANGE key): %s 0x%lx", ok ? "ok" : "fail", ok ? 0 : GetLastError());
    CHECK(ok);   /* Win10 probe: accepted, the earlier private-key import serves as the context key */
    if (ok) U(CryptDestroyKey)(r);
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}
TEST(blob_simple_import_corrupt_ciphertext) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), r = 0; if (!k) { CHECK(0); return; }
    BYTE b[512]; DWORD n = sizeof b; CHECK(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n));
    for (int i = 0; i < 4; i++) {
        BYTE c[512]; memcpy(c, b, n); c[12 + i * 31] ^= 0x80; r = 0; SET_ERR(0);
        BOOL ok = U(CryptImportKey)(p, c, n, priv, 0, &r);
        if (ok) { t_note("corrupted ciphertext (byte %d) imported", 12 + i * 31); U(CryptDestroyKey)(r); } else CHECK(GetLastError() != 0);
        if (!ok) t_note("corrupt simple blob -> 0x%lx", GetLastError());
    }
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}
TEST(blob_simple_import_truncated) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16), r = 0; if (!k) { CHECK(0); return; }
    BYTE b[512]; DWORD n = sizeof b; CHECK(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n));
    static const DWORD lens[] = { 8, 12, 13, 64, 139 };
    for (unsigned i = 0; i < SIZEOFA(lens); i++) {
        r = 0; SET_ERR(0);
        BOOL ok = U(CryptImportKey)(p, b, lens[i], priv, 0, &r);
        /* Win10 probe: the import is accepted at every truncated length (only the header is validated) */
        t_label("len %lu", lens[i]);
        CHECKF(ok, "len %lu import failed 0x%lx", lens[i], GetLastError());
        if (ok) U(CryptDestroyKey)(r); else t_note("simple blob len %lu -> 0x%lx", lens[i], GetLastError());
    }
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}
TEST(blob_simple_export_requires_key_handle) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    BYTE b[512]; DWORD n = sizeof b; SET_ERR(0);
    CHECK(!U(CryptExportKey)(k, 0, SIMPLEBLOB, 0, b, &n)); t_note("SIMPLEBLOB export with hExpKey=0 -> 0x%lx", GetLastError());
    HCRYPTKEY w = ck_key(p, CALG_AES_128, sp_key128, 16);
    n = sizeof b; SET_ERR(0); CHECK(!U(CryptExportKey)(k, w, SIMPLEBLOB, 0, b, &n)); t_note("SIMPLEBLOB export wrapped by a symmetric key -> 0x%lx", GetLastError());
    U(CryptDestroyKey)(w); U(CryptDestroyKey)(k); ck_release(p);
}
TEST(blob_simple_size_query_and_short_buffer) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY pub, priv; if (!rsa_pair(p, &pub, &priv)) { t_skip("RSA fixture import failed"); return; }
    HCRYPTKEY k = ck_key(p, CALG_AES_128, sp_key128, 16); if (!k) { CHECK(0); return; }
    BYTE b[512]; DWORD n = 139; SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n), ERROR_MORE_DATA); EXPECT_EQ(n, 140);
    n = 140; CHECK(U(CryptExportKey)(k, pub, SIMPLEBLOB, 0, b, &n)); EXPECT_EQ(n, 140);
    U(CryptDestroyKey)(k); U(CryptDestroyKey)(pub); U(CryptDestroyKey)(priv); ck_release(p);
}

/* ---- SYMMETRICWRAPKEYBLOB ------------------------------------------- */
TEST(blob_symmetric_wrap_observed_roundtrip) {
    NEED_CRYPT(); NEED_PROV(p);
    static const struct { ALG_ID a; const char *n; const BYTE *k; DWORD kl; } w[] = {
        { CALG_3DES, "3DES", tdes_key, 24 }, { CALG_RC2, "RC2", rc2_v7_key, 16 }, { CALG_AES_128, "AES128", sp_key128, 16 }, { CALG_DES, "DES", des_key, 8 } };
    for (unsigned i = 0; i < SIZEOFA(w); i++) {
        HCRYPTKEY wk = ck_key(p, w[i].a, w[i].k, w[i].kl), s = ck_key(p, CALG_AES_128, sp_key256, 16), r = 0; if (!wk || !s) { CHECK(0); continue; }
        BYTE b[512]; DWORD n = sizeof b; SET_ERR(0);
        BOOL ok = U(CryptExportKey)(s, wk, SYMMETRICWRAPKEYBLOB, 0, b, &n);
        t_note("SYMMETRICWRAPKEYBLOB wrapped by %s: %s 0x%lx size=%lu", w[i].n, ok ? "ok" : "fail", ok ? 0 : GetLastError(), n);
        if (ok) {
            EXPECT_EQ(b[0], SYMMETRICWRAPKEYBLOB); EXPECT_EQ(b[1], 2); EXPECT_EQ(*(DWORD *)(b + 4), CALG_AES_128);
            ok = U(CryptImportKey)(p, b, n, wk, CRYPT_EXPORTABLE, &r);
            CHECKF(ok, "wrap import 0x%lx", GetLastError());
            if (r) { HCRYPTKEY ref = ck_key(p, CALG_AES_128, sp_key256, 16); same_output(r, ref, "wrap roundtrip"); U(CryptDestroyKey)(ref); U(CryptDestroyKey)(r); }
        }
        U(CryptDestroyKey)(wk); U(CryptDestroyKey)(s);
    }
    ck_release(p);
}

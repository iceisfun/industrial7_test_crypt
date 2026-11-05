#include "cp.h"
#include "vectors.h"
#include "rsa_vectors.h"
/* Key management entry points: CPGenKey, CPDeriveKey, CPDestroyKey, CPDuplicateKey, CPGetKeyParam,
 * CPSetKeyParam, CPImportKey, CPExportKey, CPGenRandom. */

static int hx(const char *s, BYTE *out) {
    int n = 0;
    while (s[0] && s[1]) { unsigned v; char t[3] = { s[0], s[1], 0 }; sscanf(t, "%x", &v); out[n++] = (BYTE)v; s += 2; }
    return n;
}
static ULONG_PTR gen(const cpf *f, ULONG_PTR p, ALG_ID alg, DWORD flags) {
    ULONG_PTR k = 0;
    if (!f->GenKey(p, alg, flags, &k)) return 0;
    return k;
}
static void rc4_ref(const BYTE *key, int kl, const BYTE *in, BYTE *out, int n) {
    BYTE S[256]; int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (BYTE)i;
    for (i = 0; i < 256; i++) { j = (j + S[i] + key[i % kl]) & 255; BYTE t = S[i]; S[i] = S[j]; S[j] = t; }
    i = j = 0;
    for (int x = 0; x < n; x++) {
        i = (i + 1) & 255; j = (j + S[i]) & 255; BYTE t = S[i]; S[i] = S[j]; S[j] = t;
        out[x] = in[x] ^ S[(S[i] + S[j]) & 255];
    }
}

/* ---- CPGenKey -------------------------------------------------------------------------------- */
TEST(cpd_genkey_flags_checked_before_handles) {
    NEED_RSA();
    ULONG_PTR k = 0x1234;
    DWORD bad[] = { 0x8, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.GenKey(0, CALG_RC4, bad[i], &k), CPE_BAD_FLAGS);
}
TEST(cpd_genkey_session_algorithms_enhanced) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ALG_ID algs[] = { CALG_RC2, CALG_RC4, CALG_DES, CALG_3DES, CALG_3DES_112 };
    for (size_t i = 0; i < NELEM(algs); i++) {
        ULONG_PTR k = 0;
        SET_ERR(0);
        BOOL r = R.GenKey(p, algs[i], CRYPT_EXPORTABLE, &k);
        CHECKF(r && k, "alg 0x%x err=0x%lx", algs[i], GetLastError());
        if (r) {
            BOOL ok; EXPECT_EQ(cp_kp_dw(&R, p, k, KP_ALGID, &ok), algs[i]); CHECK(ok);
            R.DestroyKey(p, k);
        }
    }
    cp_rel(&R, p);
}
TEST(cpd_genkey_aes_requires_aes_provider) {
    NEED_RSA(); ULONG_PTR e = rsa_enh(&R), a = rsa_aes(&R); REQUIRE(e && a);
    ALG_ID algs[] = { CALG_AES_128, CALG_AES_192, CALG_AES_256 };
    DWORD bits[] = { 128, 192, 256 };
    for (int i = 0; i < 3; i++) {
        ULONG_PTR k = 0;
        FAILS(R.GenKey(e, algs[i], 0, &k), CPE_BAD_ALGID);
        OKAY(R.GenKey(a, algs[i], 0, &k));
        if (k) {
            BOOL ok; EXPECT_EQ(cp_kp_dw(&R, a, k, KP_KEYLEN, &ok), bits[i]); CHECK(ok);
            EXPECT_EQ(cp_kp_dw(&R, a, k, KP_BLOCKLEN, &ok), 128); CHECK(ok);
            R.DestroyKey(a, k);
        }
    }
    cp_rel(&R, e); cp_rel(&R, a);
}
TEST(cpd_genkey_unsupported_algorithms) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ALG_ID bad[] = { CALG_MD5, CALG_SHA1, CALG_HMAC, CALG_MAC, 0x1234, 0, 3, CALG_SHA_256, 0xffffffff };
    for (size_t i = 0; i < NELEM(bad); i++) {
        ULONG_PTR k = 0x42;
        FAILS(R.GenKey(p, bad[i], 0, &k), CPE_BAD_ALGID);
    }
    cp_rel(&R, p);
}
TEST(cpd_genkey_default_lengths_enhanced) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    struct { ALG_ID a; DWORD bits; } t[] = { { CALG_RC4, 128 }, { CALG_RC2, 128 }, { CALG_DES, 64 }, { CALG_3DES, 192 }, { CALG_3DES_112, 128 } };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR k = gen(&R, p, t[i].a, 0);
        if (!k) { CHECKF(0, "alg 0x%x gen fail 0x%lx", t[i].a, GetLastError()); continue; }
        BOOL ok; DWORD v = cp_kp_dw(&R, p, k, KP_KEYLEN, &ok);
        CHECK(ok); CHECKF(v == t[i].bits, "alg 0x%x KP_KEYLEN %lu want %lu", t[i].a, v, t[i].bits);
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_genkey_default_lengths_base) {
    NEED_RSA(); ULONG_PTR p = rsa_base(&R); REQUIRE(p);
    struct { ALG_ID a; DWORD bits; } t[] = { { CALG_RC4, 40 }, { CALG_RC2, 40 }, { CALG_DES, 64 } };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR k = gen(&R, p, t[i].a, 0);
        if (!k) { CHECKF(0, "alg 0x%x gen fail 0x%lx", t[i].a, GetLastError()); continue; }
        BOOL ok; DWORD v = cp_kp_dw(&R, p, k, KP_KEYLEN, &ok);
        CHECK(ok); CHECKF(v == t[i].bits, "base alg 0x%x KP_KEYLEN %lu want %lu", t[i].a, v, t[i].bits);
        R.DestroyKey(p, k);
    }
    ULONG_PTR k = 0;
    FAILS(R.GenKey(p, CALG_3DES, 0, &k), CPE_BAD_ALGID);
    FAILS(R.GenKey(p, CALG_3DES_112, 0, &k), CPE_BAD_ALGID);
    cp_rel(&R, p);
}
TEST(cpd_genkey_explicit_rc4_lengths) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD sizes[] = { 40, 56, 64, 96, 128 };
    for (size_t i = 0; i < NELEM(sizes); i++) {
        ULONG_PTR k = gen(&R, p, CALG_RC4, sizes[i] << 16);
        if (!k) { CHECKF(0, "RC4 %lu bits: 0x%lx", sizes[i], GetLastError()); continue; }
        BOOL ok; EXPECT_EQ(cp_kp_dw(&R, p, k, KP_KEYLEN, &ok), sizes[i]); CHECK(ok);
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_genkey_des_family_rejects_create_salt) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ALG_ID algs[] = { CALG_DES, CALG_3DES, CALG_3DES_112 };
    for (int i = 0; i < 3; i++) { ULONG_PTR k = 0; FAILS(R.GenKey(p, algs[i], CRYPT_CREATE_SALT, &k), CPE_BAD_FLAGS); }
    cp_rel(&R, p);
}
TEST(cpd_genkey_create_salt_length_by_provider) {
    NEED_RSA(); ULONG_PTR b = rsa_base(&R), e = rsa_enh(&R); REQUIRE(b && e);
    ULONG_PTR kb = gen(&R, b, CALG_RC4, CRYPT_CREATE_SALT), ke = gen(&R, e, CALG_RC4, CRYPT_CREATE_SALT);
    CHECK(kb && ke);
    BYTE salt[32]; DWORD n = sizeof salt;
    if (kb) { OKAY(R.GetKeyParam(b, kb, KP_SALT, salt, &n, 0)); EXPECT_EQ(n, 11); }
    n = sizeof salt;
    if (ke) { OKAY(R.GetKeyParam(e, ke, KP_SALT, salt, &n, 0)); EXPECT_EQ(n, 0); }
    if (kb) R.DestroyKey(b, kb);
    if (ke) R.DestroyKey(e, ke);
    cp_rel(&R, b); cp_rel(&R, e);
}
TEST(cpd_genkey_keys_are_random) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE a[64], b[64]; DWORD na = sizeof a, nb = sizeof b;
    ULONG_PTR ka = gen(&R, p, CALG_RC4, CRYPT_EXPORTABLE), kb = gen(&R, p, CALG_RC4, CRYPT_EXPORTABLE);
    REQUIRE(ka && kb);
    OKAY(R.ExportKey(p, ka, 0, PLAINTEXTKEYBLOB, 0, a, &na));
    OKAY(R.ExportKey(p, kb, 0, PLAINTEXTKEYBLOB, 0, b, &nb));
    CHECK(na == nb && memcmp(a, b, na) != 0);
    R.DestroyKey(p, ka); R.DestroyKey(p, kb);
    cp_rel(&R, p);
}
TEST(cpd_genkey_rsa_keyx_and_sig_properties) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR kx = gen(&R, p, AT_KEYEXCHANGE, (512u << 16) | CRYPT_EXPORTABLE);
    ULONG_PTR ks = gen(&R, p, AT_SIGNATURE, (512u << 16) | CRYPT_EXPORTABLE);
    CHECK(kx && ks);
    BOOL ok;
    if (kx) {
        EXPECT_EQ(cp_kp_dw(&R, p, kx, KP_ALGID, &ok), CALG_RSA_KEYX); CHECK(ok);
        EXPECT_EQ(cp_kp_dw(&R, p, kx, KP_KEYLEN, &ok), 512); CHECK(ok);
        EXPECT_EQ(cp_kp_dw(&R, p, kx, KP_PADDING, &ok), 0); CHECK(ok);
        R.DestroyKey(p, kx);
    }
    if (ks) {
        EXPECT_EQ(cp_kp_dw(&R, p, ks, KP_ALGID, &ok), CALG_RSA_SIGN); CHECK(ok);
        EXPECT_EQ(cp_kp_dw(&R, p, ks, KP_KEYLEN, &ok), 512); CHECK(ok);
        R.DestroyKey(p, ks);
    }
    cp_rel(&R, p);
}
TEST(cpd_genkey_rsa_by_algid_equals_keyspec) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k1 = gen(&R, p, CALG_RSA_KEYX, (512u << 16)), k2 = gen(&R, p, CALG_RSA_SIGN, (512u << 16));
    CHECK(k1 && k2);
    BOOL ok;
    if (k1) { EXPECT_EQ(cp_kp_dw(&R, p, k1, KP_ALGID, &ok), CALG_RSA_KEYX); R.DestroyKey(p, k1); }
    if (k2) { EXPECT_EQ(cp_kp_dw(&R, p, k2, KP_ALGID, &ok), CALG_RSA_SIGN); R.DestroyKey(p, k2); }
    cp_rel(&R, p);
}
TEST(cpd_genkey_rsa_key_sizes) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD sizes[] = { 384, 512, 768, 1024 };
    for (size_t i = 0; i < NELEM(sizes); i++) {
        ULONG_PTR k = gen(&R, p, AT_KEYEXCHANGE, (sizes[i] << 16) | CRYPT_EXPORTABLE);
        if (!k) { CHECKF(0, "RSA %lu: 0x%lx", sizes[i], GetLastError()); continue; }
        BYTE blob[600]; DWORD n = sizeof blob;
        OKAY(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, blob, &n));
        EXPECT_EQ(n, 20 + sizes[i] / 8);
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_genkey_rsa_replaces_user_key) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k1 = gen(&R, p, AT_KEYEXCHANGE, (512u << 16) | CRYPT_EXPORTABLE); REQUIRE(k1);
    BYTE b1[200], b2[200]; DWORD n1 = sizeof b1, n2 = sizeof b2;
    OKAY(R.ExportKey(p, k1, 0, PUBLICKEYBLOB, 0, b1, &n1));
    ULONG_PTR k2 = gen(&R, p, AT_KEYEXCHANGE, (512u << 16) | CRYPT_EXPORTABLE); REQUIRE(k2);
    ULONG_PTR u = 0; OKAY(R.GetUserKey(p, AT_KEYEXCHANGE, &u)); REQUIRE(u);
    OKAY(R.ExportKey(p, u, 0, PUBLICKEYBLOB, 0, b2, &n2));
    EXPECT_EQ(n1, n2);
    CHECK(memcmp(b1, b2, n1) != 0);
    R.DestroyKey(p, u); R.DestroyKey(p, k2); R.DestroyKey(p, k1);
    cp_rel(&R, p);
}
TEST(cpd_genkey_rsa_user_protected_verifycontext) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0;
    SET_ERR(0);
    FAILS(R.GenKey(p, AT_KEYEXCHANGE, (512u << 16) | CRYPT_USER_PROTECTED, &k), 0x80090022L /* NTE_SILENT_CONTEXT */);
    cp_rel(&R, p);
}
TEST(cpd_genkey_wrong_provider_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), h = cp_mkhash(&R, p, CALG_MD5), nk = 0;
    if (k) FAILS(R.GenKey(k, CALG_RC4, 0, &nk), CPE_BAD_UID);
    if (h) FAILS(R.GenKey(h, CALG_RC4, 0, &nk), CPE_BAD_UID);
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_genkey_sig_provider_rejects_session_keys) {
    NEED_RSA(); ULONG_PTR p = rsa_open(&R, PROV_RSA_SIG, N_SIG); REQUIRE(p);
    ULONG_PTR k = 0;
    SET_ERR(0);
    FAILS(R.GenKey(p, CALG_RC4, 0, &k), CPE_BAD_ALGID);
    FAILS(R.GenKey(p, AT_KEYEXCHANGE, (512u << 16), &k), CPE_BAD_ALGID);
    cp_rel(&R, p);
}

/* ---- CPGetUserKey ---------------------------------------------------------------------------- */
TEST(cpd_getuserkey_no_key_yet) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR u = 0;
    FAILS(R.GetUserKey(p, AT_KEYEXCHANGE, &u), CPE_NO_KEY);
    FAILS(R.GetUserKey(p, AT_SIGNATURE, &u), CPE_NO_KEY);
    cp_rel(&R, p);
}
TEST(cpd_getuserkey_bad_keyspec) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR u = 0;
    DWORD bad[] = { 0, 3, 4, 0xa400, 0x2400, 0xffffffff };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.GetUserKey(p, bad[i], &u), CPE_BAD_KEY);
    cp_rel(&R, p);
}
TEST(cpd_getuserkey_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), u = 0;
    if (k) FAILS(R.GetUserKey(k, AT_KEYEXCHANGE, &u), CPE_BAD_UID);
    if (k) R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_getuserkey_after_genkey_signature_and_keyx_independent) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR ks = gen(&R, p, AT_SIGNATURE, (512u << 16) | CRYPT_EXPORTABLE); REQUIRE(ks);
    ULONG_PTR u = 0;
    OKAY(R.GetUserKey(p, AT_SIGNATURE, &u));
    FAILS(R.GetUserKey(p, AT_KEYEXCHANGE, &u), CPE_NO_KEY);
    BOOL ok;
    u = 0; OKAY(R.GetUserKey(p, AT_SIGNATURE, &u));
    if (u) { EXPECT_EQ(cp_kp_dw(&R, p, u, KP_ALGID, &ok), CALG_RSA_SIGN); R.DestroyKey(p, u); }
    R.DestroyKey(p, ks);
    cp_rel(&R, p);
}
TEST(cpd_getuserkey_handles_are_distinct_per_call) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, AT_KEYEXCHANGE, (512u << 16)); REQUIRE(k);
    ULONG_PTR a = 0, b = 0;
    OKAY(R.GetUserKey(p, AT_KEYEXCHANGE, &a));
    OKAY(R.GetUserKey(p, AT_KEYEXCHANGE, &b));
    CHECK(a && b && a != b);
    if (a) OKAY(R.DestroyKey(p, a));
    BOOL ok;
    if (b) { cp_kp_dw(&R, p, b, KP_ALGID, &ok); CHECK(ok); R.DestroyKey(p, b); }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}

/* ---- CPDestroyKey / CPDuplicateKey ------------------------------------------------------------ */
TEST(cpd_destroykey_ok_and_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), h = cp_mkhash(&R, p, CALG_MD5);
    REQUIRE(k && h);
    FAILS(R.DestroyKey(k, k), CPE_BAD_UID);
    FAILS(R.DestroyKey(p, h), CPE_BAD_KEY);
    FAILS(R.DestroyKey(p2, k), CPE_BAD_UID);
    FAILS(R.DestroyKey(h, k), CPE_BAD_UID);
    OKAY(R.DestroyKey(p, k));
    R.DestroyHash(p, h);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_destroykey_many_cycles) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    for (int i = 0; i < 500; i++) {
        ULONG_PTR k = gen(&R, p, CALG_RC4, 0);
        if (!k) { CHECKF(0, "iteration %d", i); break; }
        if (!R.DestroyKey(p, k)) { CHECKF(0, "destroy %d", i); break; }
    }
    cp_rel(&R, p);
}
TEST(cpd_duplicatekey_reserved_flags_order) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), d = 0; REQUIRE(k);
    DWORD reserved = 0;
    FAILS(R.DuplicateKey(p, k, &reserved, 0, &d), ERROR_INVALID_PARAMETER);
    FAILS(R.DuplicateKey(p, k, NULL, 1, &d), CPE_BAD_FLAGS);
    FAILS(R.DuplicateKey(p, k, &reserved, 1, &d), ERROR_INVALID_PARAMETER);
    FAILS(R.DuplicateKey(0, 0, NULL, 0x100, &d), CPE_BAD_FLAGS);
    FAILS(R.DuplicateKey(0, 0, &reserved, 0, &d), ERROR_INVALID_PARAMETER);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_duplicatekey_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), h = cp_mkhash(&R, p, CALG_MD5), d = 0;
    REQUIRE(k && h);
    FAILS(R.DuplicateKey(p, h, NULL, 0, &d), CPE_BAD_KEY);
    FAILS(R.DuplicateKey(p2, k, NULL, 0, &d), CPE_BAD_KEY);
    R.DestroyKey(p, k); R.DestroyHash(p, h);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_duplicatekey_same_material_independent_iv) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)i;
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16); REQUIRE(k);
    ULONG_PTR d = 0; OKAY(R.DuplicateKey(p, k, NULL, 0, &d)); REQUIRE(d);
    CHECK(d != k);
    BYTE iv[16]; for (int i = 0; i < 16; i++) iv[i] = (BYTE)(0x80 + i);
    OKAY(cp_set_iv(&R, p, d, iv));
    BYTE giv[16]; DWORD n = 16;
    OKAY(R.GetKeyParam(p, d, KP_IV, giv, &n, 0));
    SAMEBYTES(giv, iv, 16);
    n = 16; BYTE oiv[16];
    OKAY(R.GetKeyParam(p, k, KP_IV, oiv, &n, 0));
    CHECK(memcmp(oiv, iv, 16) != 0);
    BYTE a[48], b[48]; DWORD la = 16, lb = 16;
    memcpy(a, cp_pt30, 16); memcpy(b, cp_pt30, 16);
    OKAY(cp_set_iv(&R, p, d, oiv));
    OKAY(R.Encrypt(p, k, 0, FALSE, 0, a, &la, sizeof a));
    OKAY(R.Encrypt(p, d, 0, FALSE, 0, b, &lb, sizeof b));
    SAMEBYTES(a, b, 16);
    R.DestroyKey(p, d); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_duplicatekey_survives_original_destroy) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(i + 1);
    ULONG_PTR k = cp_key(&R, p, CALG_RC4, key, 16); REQUIRE(k);
    ULONG_PTR d = 0; OKAY(R.DuplicateKey(p, k, NULL, 0, &d)); REQUIRE(d);
    OKAY(R.DestroyKey(p, k));
    BYTE buf[16], want[16]; memcpy(buf, cp_pt30, 16); DWORD n = 16;
    OKAY(R.Encrypt(p, d, 0, FALSE, 0, buf, &n, sizeof buf));
    rc4_ref(key, 16, cp_pt30, want, 16);
    SAMEBYTES(buf, want, 16);
    R.DestroyKey(p, d);
    cp_rel(&R, p);
}
TEST(cpd_duplicatekey_rsa_public_key) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, AT_KEYEXCHANGE, (512u << 16) | CRYPT_EXPORTABLE); REQUIRE(k);
    ULONG_PTR d = 0; OKAY(R.DuplicateKey(p, k, NULL, 0, &d)); REQUIRE(d);
    BYTE b1[200], b2[200]; DWORD n1 = sizeof b1, n2 = sizeof b2;
    OKAY(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, b1, &n1));
    OKAY(R.ExportKey(p, d, 0, PUBLICKEYBLOB, 0, b2, &n2));
    EXPECT_EQ(n1, n2); SAMEBYTES(b1, b2, n1);
    R.DestroyKey(p, d); R.DestroyKey(p, k);
    cp_rel(&R, p);
}

/* ---- CPGetKeyParam --------------------------------------------------------------------------- */
TEST(cpd_getkeyparam_flags_first) {
    NEED_RSA();
    BYTE b[16]; DWORD n = sizeof b;
    FAILS(R.GetKeyParam(0, 0, KP_ALGID, b, &n, 1), CPE_BAD_FLAGS);
    FAILS(R.GetKeyParam(0, 0, KP_ALGID, b, &n, 0x10000), CPE_BAD_FLAGS);
}
TEST(cpd_getkeyparam_null_pcb) {
    NEED_RSA();
    if (t_is_wine()) { t_skip("emulated provider dereferences a NULL length pointer"); return; } ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0); REQUIRE(k);
    BYTE b[16];
    FAILS(R.GetKeyParam(p, k, KP_ALGID, b, NULL, 0), ERROR_INVALID_PARAMETER);
    FAILS(R.GetKeyParam(p, k, KP_KEYLEN, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_getkeyparam_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), h = cp_mkhash(&R, p, CALG_MD5);
    BYTE b[16]; DWORD n = sizeof b;
    if (k && h) {
        FAILS(R.GetKeyParam(k, k, KP_ALGID, b, &n, 0), CPE_BAD_UID);
        FAILS(R.GetKeyParam(p, h, KP_ALGID, b, &n, 0), CPE_BAD_KEY);
        FAILS(R.GetKeyParam(p2, k, KP_ALGID, b, &n, 0), CPE_BAD_KEY);
    }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_getkeyparam_unknown_bad_type) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0); REQUIRE(k);
    DWORD bad[] = { 0, 0xb, 0xc, 0x14, 0x20, 0x100, 0xffff };
    for (size_t i = 0; i < NELEM(bad); i++) { BYTE b[32]; DWORD n = sizeof b; FAILS(R.GetKeyParam(p, k, bad[i], b, &n, 0), CPE_BAD_TYPE); }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_getkeyparam_dword_protocol) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC2, 0); REQUIRE(k);
    DWORD ps[] = { KP_ALGID, KP_KEYLEN, KP_PERMISSIONS, KP_MODE, KP_MODE_BITS, KP_BLOCKLEN, KP_PADDING, KP_EFFECTIVE_KEYLEN };
    for (size_t i = 0; i < NELEM(ps); i++) {
        DWORD v = 0, n = 0;
        OKAY(R.GetKeyParam(p, k, ps[i], NULL, &n, 0));
        EXPECT_EQ(n, 4);
        for (DWORD l = 0; l < 4; l++) {
            n = l; v = 0x77777777;
            FAILS(R.GetKeyParam(p, k, ps[i], (BYTE *)&v, &n, 0), ERROR_MORE_DATA);
            EXPECT_EQ(n, 4); EXPECT_EQ(v, 0x77777777);
        }
        n = 100;
        OKAY(R.GetKeyParam(p, k, ps[i], (BYTE *)&v, &n, 0));
        EXPECT_EQ(n, 4);
    }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_getkeyparam_block_cipher_defaults) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    struct { ALG_ID a; DWORD blk; DWORD len; } t[] = {
        { CALG_DES, 64, 8 }, { CALG_3DES, 64, 24 }, { CALG_3DES_112, 64, 16 }, { CALG_RC2, 64, 16 },
        { CALG_AES_128, 128, 16 }, { CALG_AES_192, 128, 24 }, { CALG_AES_256, 128, 32 } };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR k = gen(&R, p, t[i].a, 0);
        if (!k) { CHECKF(0, "gen 0x%x: 0x%lx", t[i].a, GetLastError()); continue; }
        BOOL ok;
        EXPECT_EQ(cp_kp_dw(&R, p, k, KP_BLOCKLEN, &ok), t[i].blk); CHECK(ok);
        EXPECT_EQ(cp_kp_dw(&R, p, k, KP_MODE, &ok), CRYPT_MODE_CBC); CHECK(ok);
        EXPECT_EQ(cp_kp_dw(&R, p, k, KP_PADDING, &ok), PKCS5_PADDING); CHECK(ok);
        BYTE iv[32]; DWORD n = sizeof iv;
        OKAY(R.GetKeyParam(p, k, KP_IV, iv, &n, 0));
        EXPECT_EQ(n, t[i].blk / 8);
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_getkeyparam_stream_cipher_defaults) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0); REQUIRE(k);
    BOOL ok;
    EXPECT_EQ(cp_kp_dw(&R, p, k, KP_BLOCKLEN, &ok), 0); CHECK(ok);
    EXPECT_EQ(cp_kp_dw(&R, p, k, KP_PADDING, &ok), 0); CHECK(ok);
    EXPECT_EQ(cp_kp_dw(&R, p, k, KP_ALGID, &ok), CALG_RC4); CHECK(ok);
    BYTE salt[16]; DWORD n = sizeof salt;
    OKAY(R.GetKeyParam(p, k, KP_SALT, salt, &n, 0));
    EXPECT_EQ(n, 0);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_getkeyparam_salt_on_des_is_empty_and_on_rsa_not_found) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR kd = gen(&R, p, CALG_DES, 0), kr = gen(&R, p, AT_KEYEXCHANGE, 512u << 16);
    BYTE b[16]; DWORD n = sizeof b;
    if (kd) { OKAY(R.GetKeyParam(p, kd, KP_SALT, b, &n, 0)); EXPECT_EQ(n, 0); R.DestroyKey(p, kd); }
    n = sizeof b;
    if (kr) { FAILS(R.GetKeyParam(p, kr, KP_SALT, b, &n, 0), 0x80090011L); R.DestroyKey(p, kr); }
    cp_rel(&R, p);
}
TEST(cpd_getkeyparam_keylen_null_buffer_and_small) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_3DES, 0); REQUIRE(k);
    DWORD v, n = 0;
    OKAY(R.GetKeyParam(p, k, KP_KEYLEN, NULL, &n, 0));
    EXPECT_EQ(n, 4);
    n = 2;
    FAILS(R.GetKeyParam(p, k, KP_KEYLEN, (BYTE *)&v, &n, 0), ERROR_MORE_DATA);
    EXPECT_EQ(n, 4);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_getkeyparam_iv_buffer_protocol) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_DES, 0); REQUIRE(k);
    BYTE iv[8]; DWORD n = 0;
    OKAY(R.GetKeyParam(p, k, KP_IV, NULL, &n, 0));
    EXPECT_EQ(n, 8);
    n = 7;
    FAILS(R.GetKeyParam(p, k, KP_IV, iv, &n, 0), ERROR_MORE_DATA);
    EXPECT_EQ(n, 8);
    n = 8;
    OKAY(R.GetKeyParam(p, k, KP_IV, iv, &n, 0));
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}

/* ---- CPSetKeyParam --------------------------------------------------------------------------- */
TEST(cpd_setkeyparam_flags) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_DES, 0); REQUIRE(k);
    DWORD m = CRYPT_MODE_ECB;
    DWORD bad[] = { 1, 2, 4, 8, 0x100, 0x800, 0x8000, 0x10000 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.SetKeyParam(p, k, KP_MODE, (BYTE *)&m, bad[i]), CPE_BAD_FLAGS);
    FAILS(R.SetKeyParam(0, 0, KP_MODE, (BYTE *)&m, 1), CPE_BAD_FLAGS);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_mode_values) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_3DES, 0); REQUIRE(k);
    for (DWORD m = 1; m <= 4; m++) {
        if (m == CRYPT_MODE_OFB) { FAILS(cp_set_mode(&R, p, k, m), 0x54f); continue; }   /* OFB: ERROR_INTERNAL_ERROR */
        OKAY(cp_set_mode(&R, p, k, m));
        BOOL ok; EXPECT_EQ(cp_kp_dw(&R, p, k, KP_MODE, &ok), m); CHECK(ok);
    }
    DWORD bad[] = { 0, 5, 6, 0x100, 0xffffffff };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(cp_set_mode(&R, p, k, bad[i]), CPE_BAD_DATA);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_mode_on_rsa_key_bad_key) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, AT_KEYEXCHANGE, 512u << 16); REQUIRE(k);
    FAILS(cp_set_mode(&R, p, k, CRYPT_MODE_ECB), CPE_BAD_KEY);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_padding_values) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_DES, 0); REQUIRE(k);
    OKAY(cp_set_pad(&R, p, k, PKCS5_PADDING));
    DWORD bad[] = { 0, 2, 3, 0x10, 0xffffffff };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(cp_set_pad(&R, p, k, bad[i]), CPE_BAD_DATA);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_mode_bits_range) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_DES, 0); REQUIRE(k);
    DWORD ok_vals[] = { 1, 8, 16, 32, 64 };
    for (size_t i = 0; i < NELEM(ok_vals); i++) {
        OKAY(R.SetKeyParam(p, k, KP_MODE_BITS, (BYTE *)&ok_vals[i], 0));
        BOOL ok; EXPECT_EQ(cp_kp_dw(&R, p, k, KP_MODE_BITS, &ok), ok_vals[i]); CHECK(ok);
    }
    DWORD bad[] = { 0, 65, 128, 0xffffffff };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.SetKeyParam(p, k, KP_MODE_BITS, (BYTE *)&bad[i], 0), CPE_BAD_DATA);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_iv_roundtrip) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_AES_256, 0); REQUIRE(k);
    BYTE iv[16]; for (int i = 0; i < 16; i++) iv[i] = (BYTE)(0xf0 - i);
    OKAY(cp_set_iv(&R, p, k, iv));
    BYTE g[16]; DWORD n = 16;
    OKAY(R.GetKeyParam(p, k, KP_IV, g, &n, 0));
    EXPECT_EQ(n, 16); SAMEBYTES(g, iv, 16);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_effective_keylen) {
    NEED_RSA(); ULONG_PTR e = rsa_enh(&R), b = rsa_base(&R); REQUIRE(e && b);
    ULONG_PTR ke = gen(&R, e, CALG_RC2, 0), kb = gen(&R, b, CALG_RC2, 0), kr4 = gen(&R, e, CALG_RC4, 0);
    REQUIRE(ke && kb && kr4);
    DWORD v = 64;
    OKAY(R.SetKeyParam(e, ke, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0));
    BOOL ok; EXPECT_EQ(cp_kp_dw(&R, e, ke, KP_EFFECTIVE_KEYLEN, &ok), 64); CHECK(ok);
    v = 0; FAILS(R.SetKeyParam(e, ke, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0), CPE_BAD_DATA);
    v = 1025; FAILS(R.SetKeyParam(e, ke, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0), CPE_BAD_DATA);
    v = 1024; OKAY(R.SetKeyParam(e, ke, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0));
    v = 56; OKAY(R.SetKeyParam(b, kb, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0));
    v = 57; FAILS(R.SetKeyParam(b, kb, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0), CPE_BAD_DATA);
    v = 64; FAILS(R.SetKeyParam(e, kr4, KP_EFFECTIVE_KEYLEN, (BYTE *)&v, 0), CPE_BAD_KEY);
    R.DestroyKey(e, ke); R.DestroyKey(b, kb); R.DestroyKey(e, kr4);
    cp_rel(&R, e); cp_rel(&R, b);
}
TEST(cpd_setkeyparam_salt) {
    NEED_RSA(); ULONG_PTR p = rsa_base(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), kd = gen(&R, p, CALG_DES, 0); REQUIRE(k && kd);
    BYTE salt[11]; for (int i = 0; i < 11; i++) salt[i] = (BYTE)(0x30 + i);
    OKAY(R.SetKeyParam(p, k, KP_SALT, salt, 0));
    BYTE g[16]; DWORD n = sizeof g;
    OKAY(R.GetKeyParam(p, k, KP_SALT, g, &n, 0));
    EXPECT_EQ(n, 11);
    if (n == 11) SAMEBYTES(g, salt, 11);
    FAILS(R.SetKeyParam(p, kd, KP_SALT, salt, 0), CPE_BAD_KEY);
    FAILS(R.SetKeyParam(p, k, KP_SALT, NULL, 0), ERROR_INVALID_PARAMETER);
    R.DestroyKey(p, k); R.DestroyKey(p, kd);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_salt_ex) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), kd = gen(&R, p, CALG_DES, 0); REQUIRE(k && kd);
    BYTE sv[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    CRYPT_INTEGER_BLOB blob; blob.cbData = 8; blob.pbData = sv;
    OKAY(R.SetKeyParam(p, k, KP_SALT_EX, (BYTE *)&blob, 0));
    BYTE g[16]; DWORD n = sizeof g;
    OKAY(R.GetKeyParam(p, k, KP_SALT, g, &n, 0));
    EXPECT_EQ(n, 8);
    if (n == 8) SAMEBYTES(g, sv, 8);
    FAILS(R.SetKeyParam(p, kd, KP_SALT_EX, (BYTE *)&blob, 0), CPE_BAD_KEY);
    BYTE big[40] = { 0 }; blob.cbData = 25; blob.pbData = big;
    FAILS(R.SetKeyParam(p, k, KP_SALT_EX, (BYTE *)&blob, 0), CPE_BAD_DATA);
    FAILS(R.SetKeyParam(p, k, KP_SALT_EX, NULL, 0), ERROR_INVALID_PARAMETER);
    R.DestroyKey(p, k); R.DestroyKey(p, kd);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_permissions) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_DES, CRYPT_EXPORTABLE); REQUIRE(k);
    BOOL ok;
    DWORD perm = cp_kp_dw(&R, p, k, KP_PERMISSIONS, &ok); CHECK(ok);
    EXPECT_EQ(perm, 0x3f);  /* probed: all of ENCRYPT|DECRYPT|EXPORT|READ|WRITE|MAC */
    DWORD bad = 0x1000;
    FAILS(R.SetKeyParam(p, k, KP_PERMISSIONS, (BYTE *)&bad, 0), CPE_BAD_FLAGS);
    bad = 0x10000;
    FAILS(R.SetKeyParam(p, k, KP_PERMISSIONS, (BYTE *)&bad, 0), CPE_BAD_FLAGS);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_unknown_bad_type) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_DES, 0); REQUIRE(k);
    DWORD bad[] = { 0, 0xb, 0xc, 0x14, 0x1a, 0x20, 0x100, 0xffff };
    BYTE b[32] = { 0 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.SetKeyParam(p, k, bad[i], b, 0), CPE_BAD_TYPE);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_setkeyparam_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR k = gen(&R, p, CALG_DES, 0), h = cp_mkhash(&R, p, CALG_MD5);
    DWORD m = CRYPT_MODE_ECB;
    if (k && h) {
        FAILS(R.SetKeyParam(k, k, KP_MODE, (BYTE *)&m, 0), CPE_BAD_UID);
        FAILS(R.SetKeyParam(p, h, KP_MODE, (BYTE *)&m, 0), CPE_BAD_KEY);
        FAILS(R.SetKeyParam(p2, k, KP_MODE, (BYTE *)&m, 0), CPE_BAD_KEY);
    }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p); cp_rel(&R, p2);
}

/* ---- CPImportKey ----------------------------------------------------------------------------- */
TEST(cpd_importkey_flags_checked_first) {
    NEED_RSA();
    BYTE blob[64] = { 0 }; ULONG_PTR k = 0;
    DWORD bad[] = { 0x4, 0x8, 0x20, 0x80, 0x200, 0x400, 0x800, 0x1000, 0x4000, 0x8000, 0x10000, 0x80000000 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.ImportKey(0, blob, sizeof blob, 0, bad[i], &k), CPE_BAD_FLAGS);
}
TEST(cpd_importkey_blob_too_short) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE blob[64] = { 0 }; ULONG_PTR k = 0;
    for (DWORD n = 0; n < 8; n++) FAILS(R.ImportKey(p, blob, n, 0, 0, &k), ERROR_INVALID_PARAMETER);
    cp_rel(&R, p);
}
TEST(cpd_importkey_bad_version) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_plain b; memset(&b, 0, sizeof b);
    b.h.bType = PLAINTEXTKEYBLOB; b.h.aiKeyAlg = CALG_RC4; b.cb = 16;
    ULONG_PTR k = 0;
    BYTE vers[] = { 0, 1, 3, 0x20, 0xff };
    for (size_t i = 0; i < NELEM(vers); i++) {
        b.h.bVersion = vers[i];
        FAILS(R.ImportKey(p, (BYTE *)&b, offsetof(cp_plain, key) + 16, 0, 0, &k), 0x80090007L);
    }
    cp_rel(&R, p);
}
TEST(cpd_importkey_plaintext_roundtrip_export) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    struct { ALG_ID a; DWORD len; } t[] = { { CALG_RC4, 16 }, { CALG_RC4, 5 }, { CALG_DES, 8 }, { CALG_3DES, 24 },
        { CALG_3DES_112, 16 }, { CALG_AES_128, 16 }, { CALG_AES_192, 24 }, { CALG_AES_256, 32 }, { CALG_RC2, 16 } };
    for (size_t i = 0; i < NELEM(t); i++) {
        BYTE key[32]; for (DWORD j = 0; j < t[i].len; j++) key[j] = (BYTE)(0x40 + j * 3);
        ULONG_PTR k = cp_key(&R, p, t[i].a, key, t[i].len);
        if (!k) { CHECKF(0, "import alg 0x%x len %lu: 0x%lx", t[i].a, t[i].len, GetLastError()); continue; }
        BYTE out[80]; DWORD n = sizeof out;
        OKAY(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, out, &n));
        EXPECT_EQ(n, 12 + t[i].len);
        if (n == 12 + t[i].len) {
            CHECK(out[0] == PLAINTEXTKEYBLOB); CHECK(out[1] == 2);
            EXPECT_EQ(*(ALG_ID *)(out + 4), t[i].a);
            EXPECT_EQ(*(DWORD *)(out + 8), t[i].len);
            /* DES-family keys come back with fixed parity; compare ignoring the parity bit. */
            for (DWORD j = 0; j < t[i].len; j++) CHECKF((out[12 + j] & 0xfe) == (key[j] & 0xfe), "alg 0x%x byte %lu", t[i].a, j);
        }
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_importkey_plaintext_bad_algid) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16] = { 1 }; ULONG_PTR k = 0;
    ALG_ID bad[] = { CALG_MD5, CALG_SHA1, CALG_RSA_KEYX, CALG_HMAC, 0x1234, 0, CALG_AES_128 };
    for (size_t i = 0; i < NELEM(bad); i++) {
        SET_ERR(0);
        BOOL r = cp_import_plain(&R, p, bad[i], key, 16, 0, &k);
        CHECKF(!r, "alg 0x%x unexpectedly imported", bad[i]);
        if (!r) {
            /* the RSA ids pass the algorithm switch and then fail on the key length */
            DWORD want = (bad[i] == CALG_RSA_KEYX || bad[i] == CALG_RSA_SIGN) ? (DWORD)CPE_BAD_LEN : (DWORD)CPE_BAD_ALGID;
            t_label("alg 0x%x", bad[i]);
            EXPECT_ERR(want);
            t_label(NULL);
        } else R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_importkey_plaintext_declared_length_exceeds_blob) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_plain b; memset(&b, 0, sizeof b);
    b.h.bType = PLAINTEXTKEYBLOB; b.h.bVersion = 2; b.h.aiKeyAlg = CALG_RC4; b.cb = 16;
    ULONG_PTR k = 0;
    FAILS(R.ImportKey(p, (BYTE *)&b, offsetof(cp_plain, key) + 15, 0, 0, &k), CPE_BAD_DATA);
    FAILS(R.ImportKey(p, (BYTE *)&b, offsetof(cp_plain, key), 0, 0, &k), CPE_BAD_DATA);
    cp_rel(&R, p);
}
TEST(cpd_importkey_plaintext_illegal_lengths) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[64] = { 1 }; ULONG_PTR k = 0;
    struct { ALG_ID a; DWORD len; } bad[] = { { CALG_DES, 7 }, { CALG_DES, 9 }, { CALG_AES_128, 15 }, { CALG_AES_128, 17 },
        { CALG_AES_256, 16 }, { CALG_AES_192, 32 } };
    for (size_t i = 0; i < NELEM(bad); i++) {
        /* a 7-byte DES key is rejected with BAD_FLAGS, every other illegal length with BAD_LEN */
        FAILS(cp_import_plain(&R, p, bad[i].a, key, bad[i].len, 0, &k),
              (bad[i].a == CALG_DES && bad[i].len == 7) ? CPE_BAD_FLAGS : CPE_BAD_LEN);
    }
    cp_rel(&R, p);
}
TEST(cpd_importkey_plaintext_hmac_flag_lifts_limit) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[64]; memset(key, 0x55, 64);
    ULONG_PTR k = 0;
    OKAY(cp_import_plain(&R, p, CALG_RC2, key, 64, CRYPT_IPSEC_HMAC_KEY, &k));
    if (k) R.DestroyKey(p, k);
    k = 0;
    SET_ERR(0);
    BOOL r = cp_import_plain(&R, p, CALG_RC2, key, 64, 0, &k);
    CHECK(!r);
    if (!r) EXPECT_ERR(CPE_BAD_LEN);
    else R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_importkey_exportable_flag_controls_export) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16]; memset(key, 7, 16);
    ULONG_PTR kx = 0, kn = 0;
    OKAY(cp_import_plain(&R, p, CALG_RC4, key, 16, CRYPT_EXPORTABLE, &kx));
    OKAY(cp_import_plain(&R, p, CALG_RC4, key, 16, 0, &kn));
    BYTE out[64]; DWORD n = sizeof out;
    if (kx) OKAY(R.ExportKey(p, kx, 0, PLAINTEXTKEYBLOB, 0, out, &n));
    n = sizeof out;
    if (kn) FAILS(R.ExportKey(p, kn, 0, PLAINTEXTKEYBLOB, 0, out, &n), CPE_BAD_KEY_STATE);
    if (kx) R.DestroyKey(p, kx);
    if (kn) R.DestroyKey(p, kn);
    cp_rel(&R, p);
}
TEST(cpd_importkey_public_blob_with_hpubkey_invalid) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE blob[148]; memset(blob, 0, sizeof blob);
    blob[0] = PUBLICKEYBLOB; blob[1] = 2; *(DWORD *)(blob + 4) = CALG_RSA_KEYX; *(DWORD *)(blob + 8) = 0x31415352; *(DWORD *)(blob + 12) = 1024;
    ULONG_PTR k = 0, any = gen(&R, p, CALG_RC4, 0);
    FAILS(R.ImportKey(p, blob, sizeof blob, any, 0, &k), ERROR_INVALID_PARAMETER);
    if (any) R.DestroyKey(p, any);
    cp_rel(&R, p);
}
TEST(cpd_importkey_unknown_blob_type) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE blob[64]; memset(blob, 0, sizeof blob);
    blob[1] = 2; ULONG_PTR k = 0;
    blob[0] = 0xc;
    FAILS(R.ImportKey(p, blob, sizeof blob, 0, 0, &k), CPE_BAD_TYPE);
    BYTE odd[] = { 0, 2, 3, 4, 5, 0xa, 0xd, 0x55, 0xff };
    for (size_t i = 0; i < NELEM(odd); i++) {
        blob[0] = odd[i]; t_label("blob type 0x%x", odd[i]);
        FAILS(R.ImportKey(p, blob, sizeof blob, 0, 0, &k), CPE_BAD_TYPE);
    }
    cp_rel(&R, p);
}
TEST(cpd_importkey_wrong_provider_handle) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), n = 0;
    cp_plain b; memset(&b, 0, sizeof b);
    b.h.bType = PLAINTEXTKEYBLOB; b.h.bVersion = 2; b.h.aiKeyAlg = CALG_RC4; b.cb = 16;
    if (k) FAILS(R.ImportKey(k, (BYTE *)&b, offsetof(cp_plain, key) + 16, 0, 0, &n), CPE_BAD_UID);
    if (k) R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_importkey_rsa_public_blob_vector) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0;
    OKAY(R.ImportKey(p, rsa_pub_blob, sizeof rsa_pub_blob, 0, 0, &k));
    if (!k) { cp_rel(&R, p); return; }
    BOOL ok;
    EXPECT_EQ(cp_kp_dw(&R, p, k, KP_ALGID, &ok), CALG_RSA_KEYX); CHECK(ok);
    EXPECT_EQ(cp_kp_dw(&R, p, k, KP_KEYLEN, &ok), 1024); CHECK(ok);
    BYTE out[200]; DWORD n = sizeof out;
    OKAY(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, out, &n));
    EXPECT_EQ(n, sizeof rsa_pub_blob);
    if (n == sizeof rsa_pub_blob) SAMEBYTES(out, rsa_pub_blob, n);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_importkey_rsa_private_blob_vector_and_export) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0;
    OKAY(R.ImportKey(p, rsa_priv_blob, sizeof rsa_priv_blob, 0, CRYPT_EXPORTABLE, &k));
    if (!k) { cp_rel(&R, p); return; }
    BYTE out[1024]; DWORD n = sizeof out;
    OKAY(R.ExportKey(p, k, 0, PRIVATEKEYBLOB, 0, out, &n));
    EXPECT_EQ(n, sizeof rsa_priv_blob);
    if (n == sizeof rsa_priv_blob) SAMEBYTES(out, rsa_priv_blob, n);
    n = sizeof out;
    OKAY(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, out, &n));
    EXPECT_EQ(n, sizeof rsa_pub_blob);
    if (n == sizeof rsa_pub_blob) SAMEBYTES(out, rsa_pub_blob, n);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_importkey_rsa_private_blob_not_exportable_without_flag) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0;
    OKAY(R.ImportKey(p, rsa_priv_blob, sizeof rsa_priv_blob, 0, 0, &k));
    if (!k) { cp_rel(&R, p); return; }
    BYTE out[1024]; DWORD n = sizeof out;
    FAILS(R.ExportKey(p, k, 0, PRIVATEKEYBLOB, 0, out, &n), CPE_BAD_KEY_STATE);
    n = sizeof out;
    OKAY(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, out, &n));
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_importkey_rsa_private_blob_truncated) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0;
    SET_ERR(0);
    BOOL r = R.ImportKey(p, rsa_priv_blob, sizeof rsa_priv_blob - 1, 0, 0, &k);
    /* a private blob one byte short still imports */
    CHECK(r);
    if (r) R.DestroyKey(p, k);
    FAILS(R.ImportKey(p, rsa_priv_blob, 20, 0, 0, &k), ERROR_INVALID_DATA);
    cp_rel(&R, p);
}

/* ---- CPExportKey ----------------------------------------------------------------------------- */
TEST(cpd_exportkey_flags_and_pcb_order) {
    NEED_RSA();
    if (t_is_wine()) { t_skip("emulated provider dereferences a NULL length pointer"); return; } ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, CRYPT_EXPORTABLE); REQUIRE(k);
    BYTE out[64]; DWORD n = sizeof out;
    DWORD bad[] = { 0x1, 0x8, 0x10, 0x20, 0x80, 0x100, 0x8000 };
    for (size_t i = 0; i < NELEM(bad); i++) {
        n = sizeof out;
        FAILS(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, bad[i], out, &n), CPE_BAD_FLAGS);
    }
    FAILS(R.ExportKey(0, 0, 0, PLAINTEXTKEYBLOB, 1, out, &n), CPE_BAD_FLAGS);
    FAILS(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, out, NULL), ERROR_INVALID_PARAMETER);
    FAILS(R.ExportKey(0, 0, 0, PLAINTEXTKEYBLOB, 0, out, NULL), ERROR_INVALID_PARAMETER);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_exportkey_expkey_with_public_or_plaintext_blob) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, CRYPT_EXPORTABLE), kx = gen(&R, p, AT_KEYEXCHANGE, 512u << 16); REQUIRE(k && kx);
    BYTE out[256]; DWORD n = sizeof out;
    FAILS(R.ExportKey(p, k, kx, PLAINTEXTKEYBLOB, 0, out, &n), 0x80090015L);
    n = sizeof out;
    FAILS(R.ExportKey(p, kx, kx, PUBLICKEYBLOB, 0, out, &n), 0x80090015L);
    R.DestroyKey(p, k); R.DestroyKey(p, kx);
    cp_rel(&R, p);
}
TEST(cpd_exportkey_plaintext_buffer_protocol) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16]; memset(key, 9, 16);
    ULONG_PTR k = cp_key(&R, p, CALG_RC4, key, 16); REQUIRE(k);
    DWORD need = 0; BYTE out[64];
    OKAY(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, NULL, &need));
    EXPECT_EQ(need, 28);
    DWORD n = need - 1;
    FAILS(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, out, &n), ERROR_MORE_DATA);
    EXPECT_EQ(n, need);
    n = 8;
    FAILS(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, out, &n), ERROR_MORE_DATA);
    n = 0;
    FAILS(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, out, &n), ERROR_MORE_DATA);
    EXPECT_EQ(n, need);
    n = need;
    OKAY(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, out, &n));
    EXPECT_EQ(n, need);
    SAMEBYTES(out + 12, key, 16);
    n = sizeof out;
    OKAY(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, out, &n));
    EXPECT_EQ(n, need);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_exportkey_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR k = gen(&R, p, CALG_RC4, CRYPT_EXPORTABLE), h = cp_mkhash(&R, p, CALG_MD5);
    BYTE out[64]; DWORD n;
    if (k && h) {
        n = sizeof out; FAILS(R.ExportKey(k, k, 0, PLAINTEXTKEYBLOB, 0, out, &n), CPE_BAD_UID);
        n = sizeof out; FAILS(R.ExportKey(p2, k, 0, PLAINTEXTKEYBLOB, 0, out, &n), CPE_BAD_UID);
        n = sizeof out;
        SET_ERR(0);
        FAILS(R.ExportKey(p, h, 0, PLAINTEXTKEYBLOB, 0, out, &n), CPE_BAD_KEY_STATE);
    }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_exportkey_public_blob_layout) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, AT_KEYEXCHANGE, 512u << 16); REQUIRE(k);
    BYTE out[200]; DWORD n = sizeof out, need = 0;
    OKAY(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, NULL, &need));
    EXPECT_EQ(need, 20 + 64);
    OKAY(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, out, &n));
    EXPECT_EQ(n, 84);
    CHECK(out[0] == PUBLICKEYBLOB); CHECK(out[1] == 2);
    EXPECT_EQ(*(ALG_ID *)(out + 4), CALG_RSA_KEYX);
    EXPECT_EQ(*(DWORD *)(out + 8), 0x31415352);
    EXPECT_EQ(*(DWORD *)(out + 12), 512);
    EXPECT_EQ(*(DWORD *)(out + 16), 65537);
    CHECK(out[20 + 63] & 0x80);
    n = 83;
    FAILS(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, out, &n), ERROR_MORE_DATA);
    EXPECT_EQ(n, 84);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_exportkey_public_blob_of_non_exportable_key) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, AT_SIGNATURE, 512u << 16); REQUIRE(k);
    BYTE out[200]; DWORD n = sizeof out;
    OKAY(R.ExportKey(p, k, 0, PUBLICKEYBLOB, 0, out, &n));
    EXPECT_EQ(*(ALG_ID *)(out + 4), CALG_RSA_SIGN);
    n = sizeof out;
    FAILS(R.ExportKey(p, k, 0, PRIVATEKEYBLOB, 0, out, &n), CPE_BAD_KEY_STATE);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_exportkey_private_blob_exportable_layout) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, AT_KEYEXCHANGE, (512u << 16) | CRYPT_EXPORTABLE); REQUIRE(k);
    BYTE out[600]; DWORD n = sizeof out, need = 0;
    OKAY(R.ExportKey(p, k, 0, PRIVATEKEYBLOB, 0, NULL, &need));
    EXPECT_EQ(need, 20 + 64 + 32 * 2 + 32 * 2 + 32 + 64);
    OKAY(R.ExportKey(p, k, 0, PRIVATEKEYBLOB, 0, out, &n));
    EXPECT_EQ(n, need);
    CHECK(out[0] == PRIVATEKEYBLOB);
    EXPECT_EQ(*(DWORD *)(out + 8), 0x32415352);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_exportkey_simpleblob_roundtrip) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR kx = gen(&R, p, AT_KEYEXCHANGE, (1024u << 16)); REQUIRE(kx);
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(i * 5 + 1);
    ULONG_PTR sk = cp_key(&R, p, CALG_RC4, key, 16); REQUIRE(sk);
    BYTE blob[300]; DWORD n = sizeof blob, need = 0;
    OKAY(R.ExportKey(p, sk, kx, SIMPLEBLOB, 0, NULL, &need));
    EXPECT_EQ(need, 12 + 128);
    OKAY(R.ExportKey(p, sk, kx, SIMPLEBLOB, 0, blob, &n));
    EXPECT_EQ(n, 140);
    CHECK(blob[0] == SIMPLEBLOB); CHECK(blob[1] == 2);
    EXPECT_EQ(*(ALG_ID *)(blob + 4), CALG_RC4);
    EXPECT_EQ(*(ALG_ID *)(blob + 8), CALG_RSA_KEYX);
    ULONG_PTR ik = 0;
    OKAY(R.ImportKey(p, blob, n, kx, CRYPT_EXPORTABLE, &ik));
    if (ik) {
        BYTE a[16], b[16]; DWORD la = 16, lb = 16;
        memcpy(a, cp_pt30, 16); memcpy(b, cp_pt30, 16);
        OKAY(R.Encrypt(p, sk, 0, FALSE, 0, a, &la, sizeof a));
        OKAY(R.Encrypt(p, ik, 0, FALSE, 0, b, &lb, sizeof b));
        SAMEBYTES(a, b, 16);
        R.DestroyKey(p, ik);
    }
    n = 139;
    FAILS(R.ExportKey(p, sk, kx, SIMPLEBLOB, 0, blob, &n), ERROR_MORE_DATA);
    EXPECT_EQ(n, 140);
    R.DestroyKey(p, sk); R.DestroyKey(p, kx);
    cp_rel(&R, p);
}
TEST(cpd_exportkey_simpleblob_requires_rsa_keyx) {
    NEED_RSA();
    if (t_is_wine()) { t_skip("emulated CPExportKey faults on a non-RSA wrapping key"); return; } ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR sk = gen(&R, p, CALG_RC4, CRYPT_EXPORTABLE), other = gen(&R, p, CALG_RC4, 0), ks = gen(&R, p, AT_SIGNATURE, 512u << 16);
    REQUIRE(sk && other && ks);
    BYTE blob[300]; DWORD n = sizeof blob;
    SET_ERR(0);
    FAILS(R.ExportKey(p, sk, 0, SIMPLEBLOB, 0, blob, &n), CPE_NO_KEY);
    n = sizeof blob;
    FAILS(R.ExportKey(p, sk, other, SIMPLEBLOB, 0, blob, &n), CPE_BAD_KEY);
    n = sizeof blob;
    FAILS(R.ExportKey(p, sk, ks, SIMPLEBLOB, 0, blob, &n), CPE_BAD_KEY);
    R.DestroyKey(p, sk); R.DestroyKey(p, other); R.DestroyKey(p, ks);
    cp_rel(&R, p);
}
TEST(cpd_exportkey_symmetric_wrap_blob_unsupported) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE wk[16]; for (int i = 0; i < 16; i++) wk[i] = (BYTE)(0x21 + i);
    BYTE sk_[16]; for (int i = 0; i < 16; i++) sk_[i] = (BYTE)(0x61 + i);
    ULONG_PTR wrap = cp_key(&R, p, CALG_AES_128, wk, 16), sess = cp_key(&R, p, CALG_AES_128, sk_, 16); REQUIRE(wrap && sess);
    BYTE blob[100]; DWORD n = sizeof blob;
    /* probed: the provider does not export SYMMETRICWRAPKEYBLOB (the wrapping key kind is rejected) */
    FAILS(R.ExportKey(p, sess, wrap, SYMMETRICWRAPKEYBLOB, 0, blob, &n), CPE_BAD_KEY);
    R.DestroyKey(p, wrap); R.DestroyKey(p, sess);
    cp_rel(&R, p);
}

/* ---- CPDeriveKey ----------------------------------------------------------------------------- */
TEST(cpd_derivekey_flags_first) {
    NEED_RSA();
    ULONG_PTR k = 0;
    DWORD bad[] = { 0x2, 0x8, 0x20, 0x40, 0x80, 0x100, 0x200, 0x800, 0x1000, 0x8000 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.DeriveKey(0, CALG_RC4, 0, bad[i], &k), CPE_BAD_FLAGS);
}
TEST(cpd_derivekey_rc4_md5_known_answer) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(h);
    OKAY(R.HashData(p, h, (const BYTE *)"password", 8, 0));
    BYTE dig[16]; DWORD dn = cp_hash(&R, p, CALG_MD5, "password", 8, dig, 16);
    EXPECT_EQ(dn, 16);
    ULONG_PTR k = 0;
    OKAY(R.DeriveKey(p, CALG_RC4, h, (128u << 16) | CRYPT_NO_SALT, &k));
    if (k) {
        BYTE buf[30], want[30]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
        OKAY(R.Encrypt(p, k, 0, FALSE, 0, buf, &n, sizeof buf));
        rc4_ref(dig, 16, cp_pt30, want, 30);
        SAMEBYTES(buf, want, 30);
        R.DestroyKey(p, k);
    }
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_derivekey_rc4_sha1_uses_digest_prefix) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1); REQUIRE(h);
    OKAY(R.HashData(p, h, (const BYTE *)"password", 8, 0));
    BYTE dig[20]; DWORD dn = cp_hash(&R, p, CALG_SHA1, "password", 8, dig, 20);
    EXPECT_EQ(dn, 20);
    ULONG_PTR k = 0;
    OKAY(R.DeriveKey(p, CALG_RC4, h, (128u << 16) | CRYPT_NO_SALT, &k));
    if (k) {
        BYTE buf[30], want[30]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
        OKAY(R.Encrypt(p, k, 0, FALSE, 0, buf, &n, sizeof buf));
        rc4_ref(dig, 16, cp_pt30, want, 30);
        SAMEBYTES(buf, want, 30);
        R.DestroyKey(p, k);
    }
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_derivekey_finishes_the_hash) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5), k = 0; REQUIRE(h);
    OKAY(R.HashData(p, h, (const BYTE *)"pw", 2, 0));
    OKAY(R.DeriveKey(p, CALG_RC4, h, (128u << 16) | CRYPT_NO_SALT, &k));
    FAILS(R.HashData(p, h, (const BYTE *)"x", 1, 0), CPE_BAD_HASH_STATE);
    if (k) R.DestroyKey(p, k);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_derivekey_same_hash_same_key) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE ct[2][32];
    for (int i = 0; i < 2; i++) {
        ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA_256), k = 0; REQUIRE(h);
        OKAY(R.HashData(p, h, (const BYTE *)"secret", 6, 0));
        OKAY(R.DeriveKey(p, CALG_AES_128, h, 0, &k));
        if (k) {
            memset(ct[i], 0, 32); memcpy(ct[i], cp_pt30, 30); DWORD n = 30;
            OKAY(R.Encrypt(p, k, 0, TRUE, 0, ct[i], &n, 32));
            EXPECT_EQ(n, 32);
            R.DestroyKey(p, k);
        }
        R.DestroyHash(p, h);
    }
    SAMEBYTES(ct[0], ct[1], 32);
    cp_rel(&R, p);
}
TEST(cpd_derivekey_invalid_algorithm) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5), k = 0; REQUIRE(h);
    ALG_ID bad[] = { CALG_MD5, CALG_SHA1, CALG_HMAC, 0, 0x1234, CALG_AES_128 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.DeriveKey(p, bad[i], h, 0, &k), CPE_BAD_ALGID);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_derivekey_wrong_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5), key = gen(&R, p, CALG_RC4, 0), k = 0;
    if (h && key) {
        FAILS(R.DeriveKey(key, CALG_RC4, h, 0, &k), CPE_BAD_UID);
        FAILS(R.DeriveKey(p, CALG_RC4, key, 0, &k), CPE_BAD_HASH);
        FAILS(R.DeriveKey(p2, CALG_RC4, h, 0, &k), CPE_BAD_UID);
    }
    if (h) R.DestroyHash(p, h);
    if (key) R.DestroyKey(p, key);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_derivekey_des_parity_and_length) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5), k = 0; REQUIRE(h);
    OKAY(R.HashData(p, h, (const BYTE *)"password", 8, 0));
    OKAY(R.DeriveKey(p, CALG_DES, h, CRYPT_EXPORTABLE, &k));
    if (k) {
        BYTE out[40]; DWORD n = sizeof out;
        OKAY(R.ExportKey(p, k, 0, PLAINTEXTKEYBLOB, 0, out, &n));
        EXPECT_EQ(n, 20);
        if (n == 20) {
            int odd = 0;
            for (int i = 0; i < 8; i++) {
                int bits = 0; for (int b = 0; b < 8; b++) bits += (out[12 + i] >> b) & 1;
                odd += bits & 1;
            }
            EXPECT_EQ(odd, 8);  /* probed: every derived DES key byte has odd parity */
        }
        R.DestroyKey(p, k);
    }
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}

/* ---- CPGenRandom ----------------------------------------------------------------------------- */
TEST(cpd_genrandom_lengths_and_no_overrun) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD lens[] = { 0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 100, 255, 256, 1000, 4096 };
    for (size_t i = 0; i < NELEM(lens); i++) {
        BYTE *buf = malloc(lens[i] + 16);
        if (!buf) continue;
        memset(buf, 0xA5, lens[i] + 16);
        OKAY(R.GenRandom(p, lens[i], buf));
        for (int j = 0; j < 16; j++) CHECKF(buf[lens[i] + j] == 0xA5, "overrun at len %lu", lens[i]);
        free(buf);
    }
    cp_rel(&R, p);
}
TEST(cpd_genrandom_not_constant_and_differs) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE a[32], b[32];
    OKAY(R.GenRandom(p, 32, a)); OKAY(R.GenRandom(p, 32, b));
    CHECK(memcmp(a, b, 32) != 0);
    int zeros = 0; for (int i = 0; i < 32; i++) zeros += a[i] == 0;
    CHECK(zeros < 16);
    cp_rel(&R, p);
}
TEST(cpd_genrandom_all_providers) {
    NEED_RSA();
    ULONG_PTR ps[] = { rsa_base(&R), rsa_enh(&R), rsa_aes(&R), rsa_open(&R, PROV_RSA_SIG, N_SIG) };
    for (int i = 0; i < 4; i++) {
        if (!ps[i]) { CHECKF(0, "provider %d", i); continue; }
        BYTE b[24];
        OKAY(R.GenRandom(ps[i], sizeof b, b));
        cp_rel(&R, ps[i]);
    }
}
TEST(cpd_genrandom_wrong_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = gen(&R, p, CALG_RC4, 0), h = cp_mkhash(&R, p, CALG_MD5);
    BYTE b[8];
    if (k) FAILS(R.GenRandom(k, 8, b), CPE_BAD_UID);
    if (h) FAILS(R.GenRandom(h, 8, b), CPE_BAD_UID);
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p);
}

/* CryptGenKey for RSA with CRYPT_VERIFYCONTEXT (ephemeral keys), key specs, sizes, flag validation. */
#include "cab.h"

static int bit_length_le(const BYTE *le, DWORD n) {
    for (int i = (int)n - 1; i >= 0; i--)
        if (le[i]) { int b = 7; while (!(le[i] >> b)) b--; return i * 8 + b + 1; }
    return 0;
}

TEST(capiab_rsagen_keyexchange_basic) {
    CAB_NEED();
    for (int p = 0; p < CAB_NRSA; p++) {
        HCRYPTPROV h = cab_acq(CAB_RSA[p].name, CAB_RSA[p].type); if (!h) continue;
        HCRYPTKEY k = 0;
        BOOL r = U(CryptGenKey)(h, AT_KEYEXCHANGE, 512u << 16, &k);
        CHECKF(r, "%s err 0x%lx", CAB_RSA[p].tag, GetLastError());
        if (r) {
            int ok;
            EXPECT_EQ(cab_kp(k, KP_ALGID, &ok), CALG_RSA_KEYX); CHECK(ok);
            EXPECT_EQ(cab_kp(k, KP_KEYLEN, &ok), 512); CHECK(ok);
            EXPECT_EQ(cab_kp(k, KP_BLOCKLEN, &ok), 512); CHECK(ok);
            cab_kd(k);
        }
        cab_rel(h);
    }
}

TEST(capiab_rsagen_signature_basic) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = 0;
    CHECK(U(CryptGenKey)(h, AT_SIGNATURE, 512u << 16, &k));
    if (k) { EXPECT_EQ(cab_algid(k), CALG_RSA_SIGN); EXPECT_EQ(cab_keylen(k), 512); }
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsagen_algid_direct) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = 0;
    CHECK(U(CryptGenKey)(h, CALG_RSA_KEYX, 512u << 16, &k));
    if (k) EXPECT_EQ(cab_algid(k), CALG_RSA_KEYX);
    cab_kd(k); k = 0;
    CHECK(U(CryptGenKey)(h, CALG_RSA_SIGN, 512u << 16, &k));
    if (k) EXPECT_EQ(cab_algid(k), CALG_RSA_SIGN);
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsagen_default_size) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = 0;
    BOOL r = U(CryptGenKey)(h, AT_KEYEXCHANGE, 0, &k);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) EXPECT_EQ(cab_keylen(k), 1024);
    cab_kd(r ? k : 0);
    k = 0;
    r = U(CryptGenKey)(h, AT_SIGNATURE, 0, &k);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) EXPECT_EQ(cab_keylen(k), 1024);
    cab_kd(r ? k : 0);
    cab_rel(h);
}

TEST(capiab_rsagen_size_table_valid) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    DWORD sizes[] = { 384, 392, 400, 512, 520, 768, 1024, 1032, 2048 };
    for (int i = 0; i < 9; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptGenKey)(h, AT_KEYEXCHANGE, sizes[i] << 16, &k);
        CHECKF(r, "RSA %lu err 0x%lx", sizes[i], GetLastError());
        if (r) EXPECT_EQ(cab_keylen(k), sizes[i]);
        cab_kd(r ? k : 0);
    }
    cab_rel(h);
}

TEST(capiab_rsagen_size_table_invalid) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    /* sizes below 384, above 16384, or not a multiple of 8 */
    DWORD sizes[] = { 8, 128, 256, 376, 385, 1001, 1025, 16392, 20000, 32768 };
    for (int i = 0; i < 10; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptGenKey)(h, AT_KEYEXCHANGE, sizes[i] << 16, &k);
        CHECKF(!r, "RSA %lu generated", sizes[i]);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_FLAGS); else cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsagen_base_provider_limit) {
    CAB_NEED();
    HCRYPTPROV h = cab_acq(MS_DEF_PROV_W, PROV_RSA_FULL); if (!h) { t_skip("no base provider"); return; }
    HCRYPTKEY k = 0;
    BOOL r = U(CryptGenKey)(h, AT_KEYEXCHANGE, 512u << 16, &k);
    CHECKF(r, "512 err 0x%lx", GetLastError());
    cab_kd(r ? k : 0); k = 0;
    SET_ERR(0);
    r = U(CryptGenKey)(h, AT_KEYEXCHANGE, 1024u << 16, &k);
    /* the base provider generates up to 1024 bits (probed); 1032 and above are rejected */
    CHECKF(r, "base provider 1024 err 0x%lx", GetLastError());
    cab_kd(r ? k : 0); k = 0;
    DWORD over[] = { 1032, 2048, 4096 };
    for (int i = 0; i < 3; i++) {
        SET_ERR(0);
        r = U(CryptGenKey)(h, AT_KEYEXCHANGE, over[i] << 16, &k);
        CHECKF(!r, "base provider generated %lu bits", over[i]);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_FLAGS); else { cab_kd(k); k = 0; }
    }
    cab_rel(h);
}

TEST(capiab_rsagen_flag_validation) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    /* observed: dwFlags & 0x1fe8 -> NTE_BAD_FLAGS */
    DWORD bad[] = { 0x8, 0x20, CRYPT_PREGEN, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000 };
    for (int i = 0; i < 9; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptGenKey)(h, AT_KEYEXCHANGE, (512u << 16) | bad[i], &k), CAB_NTE_BAD_FLAGS);
    }
    cab_rel(h);
}

TEST(capiab_rsagen_unknown_algid) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = 0;
    ALG_ID bad[] = { 0x7777, CALG_SHA1, CALG_DSS_SIGN, CALG_DH_EPHEM, CALG_ECDSA };
    for (int i = 0; i < 5; i++) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptGenKey)(h, bad[i], 512u << 16, &k), CAB_NTE_BAD_ALGID);
    }
    cab_rel(h);
}

TEST(capiab_rsagen_verifycontext_user_protected) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = 0;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGenKey)(h, AT_KEYEXCHANGE, (512u << 16) | CRYPT_USER_PROTECTED, &k), 0x80090022L);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGenKey)(h, AT_KEYEXCHANGE, (512u << 16) | 0x8000, &k), 0x80090022L);
    cab_rel(h);
}

TEST(capiab_rsagen_null_output_pointer) {
    CAB_NEED();
    CAB_NOWINE("NULL phKey");
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    SET_ERR(0);
    BOOL r = U(CryptGenKey)(h, AT_KEYEXCHANGE, 512u << 16, NULL);
    CHECK(!r);
    t_note("CryptGenKey with NULL phKey: err 0x%lx", r ? 0 : GetLastError());
    cab_rel(h);
}

TEST(capiab_rsagen_export_public_structure) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    DWORD sizes[] = { 384, 512, 1024 };
    for (int i = 0; i < 3; i++) {
        HCRYPTKEY k = 0;
        if (!U(CryptGenKey)(h, AT_KEYEXCHANGE, sizes[i] << 16, &k)) { CHECK(0); continue; }
        BYTE b[512]; DWORD n = sizeof b;
        CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n));
        EXPECT_EQ(n, 20 + sizes[i] / 8);
        DWORD v;
        CHECK(b[0] == PUBLICKEYBLOB && b[1] == CUR_BLOB_VERSION);
        memcpy(&v, b + 4, 4); EXPECT_EQ(v, CALG_RSA_KEYX);
        memcpy(&v, b + 8, 4); EXPECT_EQ(v, MAGIC_RSA1);
        memcpy(&v, b + 12, 4); EXPECT_EQ(v, sizes[i]);
        memcpy(&v, b + 16, 4); EXPECT_EQ(v, 65537);
        EXPECT_EQ(bit_length_le(b + 20, sizes[i] / 8), sizes[i]);   /* modulus uses the full width */
        CHECK(b[20] & 1);                                         /* odd modulus */
        cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsagen_export_private_structure) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = 0;
    CHECK(U(CryptGenKey)(h, AT_KEYEXCHANGE, (512u << 16) | CRYPT_EXPORTABLE, &k));
    BYTE b[1024]; DWORD n = sizeof b;
    BOOL r = k && U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) {
        EXPECT_EQ(n, 20 + 64 * 9 / 2);
        DWORD v; memcpy(&v, b + 8, 4); EXPECT_EQ(v, MAGIC_RSA2);
        memcpy(&v, b + 12, 4); EXPECT_EQ(v, 512);
        /* primes are half-width and have their top bit set */
        const BYTE *pp = b + 20 + 64, *qq = pp + 32;
        EXPECT_EQ(bit_length_le(pp, 32), 256);
        EXPECT_EQ(bit_length_le(qq, 32), 256);
        /* re-import and use it */
        HCRYPTPROV h2 = cab_enh();
        HCRYPTKEY k2 = cab_imp(h2, b, n, 0);
        CHECK(k2 != 0);
        BYTE e[128]; DWORD en;
        HCRYPTKEY pk = cab_imp(h2, b, 0, 0);  /* zero length must fail */
        CHECK(pk == 0);
        BYTE pub[256]; DWORD pn = sizeof pub;
        CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, pub, &pn));
        HCRYPTKEY pk2 = cab_imp(h2, pub, pn, 0);
        memcpy(e, "roundtrip", 9); en = 9;
        CHECK(pk2 && U(CryptEncrypt)(pk2, 0, TRUE, 0, e, &en, sizeof e));
        CHECK(en == 64);
        DWORD dn = en;
        CHECK(k2 && U(CryptDecrypt)(k2, 0, TRUE, 0, e, &dn));
        CHECK(dn == 9 && !memcmp(e, "roundtrip", 9));
        cab_kd(pk2); cab_kd(k2); cab_rel(h2);
    }
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsagen_non_exportable_private) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = 0;
    CHECK(U(CryptGenKey)(h, AT_KEYEXCHANGE, 512u << 16, &k));
    BYTE b[1024]; DWORD n = sizeof b;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n), CAB_NTE_BAD_KEY_STATE);
    n = sizeof b;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n));
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsagen_permissions_exportable_bit) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY a = 0, b = 0;
    CHECK(U(CryptGenKey)(h, AT_KEYEXCHANGE, 512u << 16, &a));
    CHECK(U(CryptGenKey)(h, AT_SIGNATURE, (512u << 16) | CRYPT_EXPORTABLE, &b));
    int ok;
    DWORD pa = cab_kp(a, KP_PERMISSIONS, &ok); CHECK(ok);
    DWORD pb = cab_kp(b, KP_PERMISSIONS, &ok); CHECK(ok);
    CHECKF(!(pa & CRYPT_EXPORT), "non-exportable has CRYPT_EXPORT (0x%lx)", pa);
    CHECKF(pb & CRYPT_EXPORT, "exportable lacks CRYPT_EXPORT (0x%lx)", pb);
    cab_kd(a); cab_kd(b); cab_rel(h);
}

TEST(capiab_rsagen_userkey_matches) {
    CAB_NEED();
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY g = 0, u = 0;
    CHECK(U(CryptGenKey)(h, AT_KEYEXCHANGE, 768u << 16, &g));
    BOOL r = U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &u);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) {
        EXPECT_EQ(cab_keylen(u), 768);
        BYTE b1[512], b2[512]; DWORD n1 = sizeof b1, n2 = sizeof b2;
        CHECK(U(CryptExportKey)(g, 0, PUBLICKEYBLOB, 0, b1, &n1));
        CHECK(U(CryptExportKey)(u, 0, PUBLICKEYBLOB, 0, b2, &n2));
        CHECK(n1 == n2 && !memcmp(b1, b2, n1));
    }
    u = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetUserKey)(h, AT_SIGNATURE, &u), CAB_NTE_NO_KEY);
    cab_kd(u); cab_kd(g); cab_rel(h);
}

TEST(capiab_rsagen_second_gen_replaces_userkey) {
    CAB_NEED();
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY a = 0, b = 0, u = 0;
    CHECK(U(CryptGenKey)(h, AT_KEYEXCHANGE, 512u << 16, &a));
    BYTE pa[256], pb[256], pu[256]; DWORD na = sizeof pa, nb = sizeof pb, nu = sizeof pu;
    CHECK(U(CryptExportKey)(a, 0, PUBLICKEYBLOB, 0, pa, &na));
    CHECK(U(CryptGenKey)(h, AT_KEYEXCHANGE, 512u << 16, &b));
    CHECK(U(CryptExportKey)(b, 0, PUBLICKEYBLOB, 0, pb, &nb));
    CHECK(na == nb && memcmp(pa, pb, na) != 0);
    CHECK(U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &u));
    CHECK(U(CryptExportKey)(u, 0, PUBLICKEYBLOB, 0, pu, &nu));
    CHECK(nu == nb && !memcmp(pu, pb, nb));
    cab_kd(u); cab_kd(a); cab_kd(b); cab_rel(h);
}

TEST(capiab_rsagen_sign_verify_across_contexts) {
    CAB_NEED();
    HCRYPTPROV h = cab_aes(), h2 = cab_aes(); if (!h || !h2) { t_skip("no aes"); return; }
    HCRYPTKEY g = 0;
    CHECK(U(CryptGenKey)(h, AT_SIGNATURE, 1024u << 16, &g));
    HCRYPTHASH x = cab_hash(h, CALG_SHA_256, "payload", 7);
    BYTE sig[256]; DWORD sn = sizeof sig;
    CHECK(x && U(CryptSignHashW)(x, AT_SIGNATURE, NULL, 0, sig, &sn)); EXPECT_EQ(sn, 128);
    BYTE pub[256]; DWORD pn = sizeof pub;
    CHECK(U(CryptExportKey)(g, 0, PUBLICKEYBLOB, 0, pub, &pn));
    HCRYPTKEY pk = cab_imp(h2, pub, pn, 0);
    HCRYPTHASH y = cab_hash(h2, CALG_SHA_256, "payload", 7);
    CHECK(pk && y && U(CryptVerifySignatureW)(y, sig, sn, pk, NULL, 0));
    HCRYPTHASH z = cab_hash(h2, CALG_SHA_256, "payloae", 7);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptVerifySignatureW)(z, sig, sn, pk, NULL, 0), CAB_NTE_BAD_SIGNATURE);
    cab_hd(x); cab_hd(y); cab_hd(z); cab_kd(pk); cab_kd(g); cab_rel(h); cab_rel(h2);
}

TEST(capiab_rsagen_encrypt_decrypt_generated) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY g = 0;
    CHECK(U(CryptGenKey)(h, AT_KEYEXCHANGE, 1024u << 16, &g));
    BYTE b[256]; memcpy(b, "generated key payload", 21); DWORD n = 21;
    CHECK(U(CryptEncrypt)(g, 0, TRUE, 0, b, &n, sizeof b)); EXPECT_EQ(n, 128);
    CHECK(U(CryptDecrypt)(g, 0, TRUE, 0, b, &n));
    CHECK(n == 21 && !memcmp(b, "generated key payload", 21));
    memcpy(b, "oaep payload", 12); n = 12;
    CHECK(U(CryptEncrypt)(g, 0, TRUE, CRYPT_OAEP, b, &n, sizeof b)); EXPECT_EQ(n, 128);
    CHECK(U(CryptDecrypt)(g, 0, TRUE, CRYPT_OAEP, b, &n));
    CHECK(n == 12 && !memcmp(b, "oaep payload", 12));
    cab_kd(g); cab_rel(h);
}

TEST(capiab_rsagen_large_size_4096) {
    CAB_NEED();
    HCRYPTPROV h = cab_aes(); if (!h) { t_skip("no aes"); return; }
    if (t_is_wine()) { t_skip("slow key generation under the emulator"); cab_rel(h); return; }
    HCRYPTKEY k = 0;
    DWORD t0 = GetTickCount();
    BOOL r = U(CryptGenKey)(h, AT_KEYEXCHANGE, 4096u << 16, &k);
    CHECKF(r, "err 0x%lx", GetLastError());
    t_note("4096-bit RSA generation took %lu ms", GetTickCount() - t0);
    if (r) EXPECT_EQ(cab_keylen(k), 4096);
    cab_kd(r ? k : 0); cab_rel(h);
}

TEST(capiab_rsagen_duplicate_key_observe) {
    CAB_NEED();
    REQUIRE(U(CryptDuplicateKey));
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0), d = 0;
    CHECK(k != 0);
    SET_ERR(0);
    BOOL r = U(CryptDuplicateKey)(k, NULL, 0, &d);
    t_note("CryptDuplicateKey of an RSA public key: %d err 0x%lx", r, r ? 0 : GetLastError());
    if (r) {
        cab_kd(k);
        EXPECT_EQ(cab_keylen(d), 1024);
        BYTE b[256]; DWORD n = sizeof b;
        CHECK(U(CryptExportKey)(d, 0, PUBLICKEYBLOB, 0, b, &n));
        CHECK(n == sizeof rsa1024_pub && !memcmp(b, rsa1024_pub, n));
        cab_kd(d);
    } else cab_kd(k);
    cab_rel(h);
}

TEST(capiab_rsagen_sweep_sizes_384_to_768) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    for (DWORD bits = 384; bits <= 768; bits += 8) {
        HCRYPTKEY k = 0;
        BOOL r = U(CryptGenKey)(h, AT_KEYEXCHANGE, bits << 16, &k);
        if (!r) { CHECKF(0, "RSA %lu err 0x%lx", bits, GetLastError()); continue; }
        EXPECT_EQ(cab_keylen(k), bits);
        BYTE b[256]; DWORD n = sizeof b;
        CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n));
        EXPECT_EQ(n, 20 + bits / 8);
        EXPECT_EQ(bit_length_le(b + 20, bits / 8), bits);
        cab_kd(k);
    }
    cab_rel(h);
}

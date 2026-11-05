/* Diffie-Hellman keys (DH1/DH2 blobs, KP_P/G/X, key agreement) in the dssenh providers. VERIFYCONTEXT only. */
#include "cab.h"

#define DH_NOWINE() CAB_NOWINE("dssenh has no Diffie-Hellman support")

static HCRYPTKEY dh_imp_prv(HCRYPTPROV p, DWORD fl) { return cab_imp(p, dh1024_prv_a, sizeof dh1024_prv_a, fl); }

/* agreement: import peer public blob using our private key as hImportKey */
static HCRYPTKEY dh_agree(HCRYPTPROV p, const void *peer, DWORD n, HCRYPTKEY mine) {
    HCRYPTKEY k = 0;
    if (!U(CryptImportKey)(p, (const BYTE *)peer, n, mine, 0, &k)) return 0;
    return k;
}
static BOOL dh_set_algid(HCRYPTKEY k, ALG_ID a) { return U(CryptSetKeyParam)(k, KP_ALGID, (BYTE *)&a, 0); }

TEST(capiab_dh_blob_vectors_layout) {
    DWORD v;
    EXPECT_EQ(sizeof dh1024_prv_a, 8 + 8 + 3 * 128);
    EXPECT_EQ(sizeof dh1024_pub_a, 8 + 8 + 128);
    CHECK(dh1024_pub_a[0] == PUBLICKEYBLOB && dh1024_prv_a[0] == PRIVATEKEYBLOB);
    memcpy(&v, dh1024_pub_a + 4, 4); EXPECT_EQ(v, CALG_DH_EPHEM);
    memcpy(&v, dh1024_pub_a + 8, 4); EXPECT_EQ(v, MAGIC_DH1);
    memcpy(&v, dh1024_prv_a + 8, 4); EXPECT_EQ(v, MAGIC_DH2);
    EXPECT_EQ(CALG_DH_SF, 0xAA01);
    EXPECT_EQ(CALG_DH_EPHEM, 0xAA02);
    EXPECT_EQ(CALG_AGREEDKEY_ANY, 0xAA03);
}

TEST(capiab_dh_acquire_providers) {
    CAB_NEED();
    HCRYPTPROV a = cab_acq(MS_DEF_DSS_DH_PROV_W, PROV_DSS_DH);
    HCRYPTPROV b = cab_dsdh();
    CHECK(a != 0); CHECK(b != 0);
    cab_rel(a); cab_rel(b);
}

TEST(capiab_dh_import_private_ephemeral) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, 0);
    CHECKF(k != 0, "err 0x%lx", GetLastError());
    if (k) {
        int ok;
        EXPECT_EQ(cab_kp(k, KP_ALGID, &ok), CALG_DH_EPHEM); CHECK(ok);
        EXPECT_EQ(cab_kp(k, KP_KEYLEN, &ok), 1024); CHECK(ok);
        EXPECT_EQ(cab_kp(k, KP_BLOCKLEN, &ok), 1024); CHECK(ok);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_keyparam_p_g_bytes) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, 0);
    CHECK(k != 0);
    BYTE b[256]; DWORD n = 0;
    SET_ERR(0);
    CHECK(k && U(CryptGetKeyParam)(k, KP_P, NULL, &n, 0)); EXPECT_EQ(n, 128);
    n = sizeof b;
    CHECK(k && U(CryptGetKeyParam)(k, KP_P, b, &n, 0)); EXPECT_EQ(n, 128);
    CHECK(!memcmp(b, dh1024_p, 128));
    n = 127; SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_P, b, &n, 0), ERROR_MORE_DATA); EXPECT_EQ(n, 128);
    n = sizeof b;
    CHECK(k && U(CryptGetKeyParam)(k, KP_G, b, &n, 0)); EXPECT_EQ(n, 128);
    CHECK(!memcmp(b, dh1024_g, 128));
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_keyparam_x_y_not_gettable) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, CRYPT_EXPORTABLE);
    BYTE b[256]; DWORD n = sizeof b;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_X, b, &n, 0), CAB_NTE_BAD_TYPE);
    n = sizeof b; SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_Y, b, &n, 0), CAB_NTE_BAD_TYPE);
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_export_public_blob) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, 0);
    CHECK(k != 0);
    BYTE b[512]; DWORD n = 0;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, NULL, &n)); EXPECT_EQ(n, sizeof dh1024_pub_a);
    n = sizeof dh1024_pub_a - 1; SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n), ERROR_MORE_DATA); EXPECT_EQ(n, sizeof dh1024_pub_a - 1);   /* length left unchanged (probed) */
    n = sizeof b;
    BOOL r = U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n);
    CHECKF(r, "err 0x%lx", GetLastError());
    CHECK(r && n == sizeof dh1024_pub_a && !memcmp(b, dh1024_pub_a, n));
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_export_private_blob) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, CRYPT_EXPORTABLE);
    CHECK(k != 0);
    BYTE b[512]; DWORD n = 0;
    CHECK(U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, NULL, &n)); EXPECT_EQ(n, sizeof dh1024_prv_a);
    n = sizeof b;
    BOOL r = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n);
    CHECKF(r, "err 0x%lx", GetLastError());
    CHECK(r && n == sizeof dh1024_prv_a && !memcmp(b, dh1024_prv_a, n));
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_export_private_nonexportable) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, 0);
    BYTE b[512]; DWORD n = sizeof b;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n), CAB_NTE_BAD_KEY_STATE);
    /* the public part is still exportable */
    n = sizeof b;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n));
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_export_flag_table) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, CRYPT_EXPORTABLE);
    /* observed: dssenh accepts only 0x04 and 0x80 in CryptExportKey flags */
    DWORD bad[] = { 0x1, 0x2, 0x8, 0x10, 0x20, 0x40, 0x100 };
    for (int i = 0; k && i < 7; i++) {
        BYTE b[512]; DWORD n = sizeof b;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptExportKey)(k, 0, PUBLICKEYBLOB, bad[i], b, &n), CAB_NTE_BAD_FLAGS);
    }
    BYTE b[1024]; DWORD n = sizeof b;
    SET_ERR(0);
    BOOL r = U(CryptExportKey)(k, 0, PUBLICKEYBLOB, CRYPT_BLOB_VER3, b, &n);
    /* probed std and adm: CRYPT_BLOB_VER3 is accepted on a DH public export and the blob is 432 bytes (the VER1 form is 144) */
    EXPECT_EQ(r, 1); EXPECT_EQ(n, 432);
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_export_bad_blobtype) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, CRYPT_EXPORTABLE);
    DWORD bad[] = { 0, 1, 5, 13, 0x55 };
    for (int i = 0; k && i < 5; i++) {
        BYTE b[512]; DWORD n = sizeof b;
        SET_ERR(0);
        BOOL r = U(CryptExportKey)(k, 0, bad[i], 0, b, &n);
        CHECKF(!r, "blob type %lu exported", bad[i]);
        t_label("type %lu", bad[i]);
        EXPECT_ERR(CAB_NTE_BAD_TYPE); /* probed std and adm */
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_import_public_without_importkey) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = 0;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(p, dh1024_pub_b, sizeof dh1024_pub_b, 0, 0, &k), CAB_NTE_BAD_KEY);
    cab_rel(p);
}

TEST(capiab_dh_import_public_in_plain_dss_provider) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = 0;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(p, dh1024_pub_b, sizeof dh1024_pub_b, 0, 0, &k), CAB_NTE_BAD_DATA);
    SET_ERR(0);
    BOOL r = U(CryptImportKey)(p, dh1024_prv_a, sizeof dh1024_prv_a, 0, 0, &k);
    CHECK(!r); if (r) cab_kd(k);
    EXPECT_ERR(CAB_NTE_BAD_ALGID); /* probed std and adm (the public blob above gives NTE_BAD_DATA) */
    cab_rel(p);
}

TEST(capiab_dh_agreement_both_sides_agree) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY a = cab_imp(p, dh1024_prv_a, sizeof dh1024_prv_a, 0);
    HCRYPTKEY b = cab_imp(p, dh1024_prv_b, sizeof dh1024_prv_b, 0);
    CHECK(a && b);
    HCRYPTKEY ka = dh_agree(p, dh1024_pub_b, sizeof dh1024_pub_b, a);
    HCRYPTKEY kb = dh_agree(p, dh1024_pub_a, sizeof dh1024_pub_a, b);
    CHECKF(ka && kb, "agree err 0x%lx", GetLastError());
    if (ka && kb) {
        int ok;
        EXPECT_EQ(cab_kp(ka, KP_ALGID, &ok), CALG_AGREEDKEY_ANY); CHECK(ok);
        EXPECT_EQ(cab_kp(kb, KP_ALGID, &ok), CALG_AGREEDKEY_ANY); CHECK(ok);
        CHECK(dh_set_algid(ka, CALG_RC4));
        CHECK(dh_set_algid(kb, CALG_RC4));
        EXPECT_EQ(cab_kp(ka, KP_ALGID, &ok), CALG_RC4); CHECK(ok);
        BYTE buf[64]; const char *msg = "dh agreement payload";
        DWORD n = (DWORD)strlen(msg);
        memcpy(buf, msg, n);
        CHECK(U(CryptEncrypt)(ka, 0, TRUE, 0, buf, &n, sizeof buf));
        CHECK(memcmp(buf, msg, n) != 0);
        CHECK(U(CryptDecrypt)(kb, 0, TRUE, 0, buf, &n));
        CHECK(n == strlen(msg) && !memcmp(buf, msg, n));
    }
    cab_kd(ka); cab_kd(kb); cab_kd(a); cab_kd(b); cab_rel(p);
}

TEST(capiab_dh_agreement_3des_roundtrip) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY a = cab_imp(p, dh1024_prv_a, sizeof dh1024_prv_a, 0);
    HCRYPTKEY b = cab_imp(p, dh1024_prv_b, sizeof dh1024_prv_b, 0);
    HCRYPTKEY ka = dh_agree(p, dh1024_pub_b, sizeof dh1024_pub_b, a);
    HCRYPTKEY kb = dh_agree(p, dh1024_pub_a, sizeof dh1024_pub_a, b);
    CHECK(ka && kb);
    if (ka && kb) {
        CHECKF(dh_set_algid(ka, CALG_3DES), "err 0x%lx", GetLastError());
        CHECKF(dh_set_algid(kb, CALG_3DES), "err 0x%lx", GetLastError());
        BYTE buf[64]; const char *msg = "0123456789abcdefXYZ";
        DWORD n = (DWORD)strlen(msg);
        memcpy(buf, msg, n);
        CHECK(U(CryptEncrypt)(ka, 0, TRUE, 0, buf, &n, sizeof buf));
        EXPECT_EQ(n, 24);
        CHECK(U(CryptDecrypt)(kb, 0, TRUE, 0, buf, &n));
        CHECK(n == strlen(msg) && !memcmp(buf, msg, n));
    }
    cab_kd(ka); cab_kd(kb); cab_kd(a); cab_kd(b); cab_rel(p);
}

TEST(capiab_dh_agreement_wrong_peer_differs) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY a = cab_imp(p, dh1024_prv_a, sizeof dh1024_prv_a, 0);
    HCRYPTKEY ka = dh_agree(p, dh1024_pub_b, sizeof dh1024_pub_b, a);
    HCRYPTKEY ks = dh_agree(p, dh1024_pub_a, sizeof dh1024_pub_a, a);    /* own public value as peer */
    CHECK(ka && ks);
    if (ka && ks) {
        CHECK(dh_set_algid(ka, CALG_RC4));
        CHECK(dh_set_algid(ks, CALG_RC4));
        BYTE b1[32], b2[32]; memset(b1, 0x61, 16); memset(b2, 0x61, 16);
        DWORD n1 = 16, n2 = 16;
        CHECK(U(CryptEncrypt)(ka, 0, TRUE, 0, b1, &n1, sizeof b1));
        CHECK(U(CryptEncrypt)(ks, 0, TRUE, 0, b2, &n2, sizeof b2));
        CHECK(memcmp(b1, b2, 16) != 0);
    }
    cab_kd(ka); cab_kd(ks); cab_kd(a); cab_rel(p);
}

TEST(capiab_dh_agreement_rejects_malformed_peer) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY a = cab_imp(p, dh1024_prv_a, sizeof dh1024_prv_a, 0);
    CHECK(a != 0);
    BYTE b[512]; HCRYPTKEY k;
    /* observed: bitlen must equal ours, magic must be DH1, and the blob must hold bitlen/8 bytes of Y */
    memcpy(b, dh1024_pub_b, sizeof dh1024_pub_b); { DWORD v = 512; memcpy(b + 12, &v, 4); }
    k = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(p, b, sizeof dh1024_pub_b, a, 0, &k), CAB_NTE_BAD_DATA);
    memcpy(b, dh1024_pub_b, sizeof dh1024_pub_b); cab_setmagic(b, MAGIC_DH2);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(p, b, sizeof dh1024_pub_b, a, 0, &k), CAB_NTE_BAD_DATA);
    memcpy(b, dh1024_pub_b, sizeof dh1024_pub_b); { DWORD v = 1023; memcpy(b + 12, &v, 4); }
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(p, b, sizeof dh1024_pub_b, a, 0, &k), CAB_NTE_BAD_DATA);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(p, dh1024_pub_b, sizeof dh1024_pub_b - 1, a, 0, &k), CAB_NTE_BAD_DATA);
    cab_kd(a); cab_rel(p);
}

TEST(capiab_dh_agreed_key_cannot_export) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY a = cab_imp(p, dh1024_prv_a, sizeof dh1024_prv_a, 0);
    HCRYPTKEY ka = dh_agree(p, dh1024_pub_b, sizeof dh1024_pub_b, a);
    CHECK(ka != 0);
    BYTE b[512]; DWORD n = sizeof b;
    SET_ERR(0);
    BOOL r = U(CryptExportKey)(ka, 0, PUBLICKEYBLOB, 0, b, &n);
    CHECK(!r);
    EXPECT_ERR(CAB_NTE_BAD_ALGID); /* probed std and adm */
    cab_kd(ka); cab_kd(a); cab_rel(p);
}

TEST(capiab_dh_set_algid_unknown_observe) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY a = cab_imp(p, dh1024_prv_a, sizeof dh1024_prv_a, 0);
    HCRYPTKEY ka = dh_agree(p, dh1024_pub_b, sizeof dh1024_pub_b, a);
    ALG_ID algs[] = { 0x1234, CALG_SHA1, CALG_RSA_KEYX, CALG_AES_128, CALG_DH_EPHEM };
    for (int i = 0; ka && i < 5; i++) {
        SET_ERR(0);
        BOOL r = dh_set_algid(ka, algs[i]);
        t_label("algid 0x%x", algs[i]);
        EXPECT_EQ(r, 0); EXPECT_ERR(CAB_NTE_BAD_ALGID); /* probed std and adm: only the RC4 and 3DES style session algorithms used elsewhere are accepted */
    }
    cab_kd(ka); cab_kd(a); cab_rel(p);
}

TEST(capiab_dh_setkeyparam_flag_validation) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY a = cab_imp(p, dh1024_prv_a, sizeof dh1024_prv_a, 0);
    HCRYPTKEY ka = dh_agree(p, dh1024_pub_b, sizeof dh1024_pub_b, a);
    ALG_ID alg = CALG_RC4;
    DWORD bad[] = { 0x2, 0x8, 0x20, 0x40, 0x80, 0x100, 0x8000 };
    for (int i = 0; ka && i < 7; i++) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptSetKeyParam)(ka, KP_ALGID, (BYTE *)&alg, bad[i]), CAB_NTE_BAD_FLAGS);
    }
    cab_kd(ka); cab_kd(a); cab_rel(p);
}

/* ---- CryptGenKey for DH, CRYPT_PREGEN flow ------------------------------ */
static BOOL dh_pregen(HCRYPTPROV p, HCRYPTKEY *k, DWORD fl) {
    *k = 0;
    return U(CryptGenKey)(p, CALG_DH_EPHEM, (1024u << 16) | CRYPT_PREGEN | fl, k);
}
static BOOL dh_set_blob(HCRYPTKEY k, DWORD kp, const void *d, DWORD n) {
    DATA_BLOB b; b.cbData = n; b.pbData = (BYTE *)d;
    return U(CryptSetKeyParam)(k, kp, (BYTE *)&b, 0);
}

TEST(capiab_dh_pregen_set_pg_generate_x) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k;
    BOOL r = dh_pregen(p, &k, CRYPT_EXPORTABLE);
    CHECKF(r, "pregen err 0x%lx", GetLastError());
    if (r) {
        CHECKF(dh_set_blob(k, KP_P, dh1024_p, 128), "KP_P err 0x%lx", GetLastError());
        CHECKF(dh_set_blob(k, KP_G, dh1024_g, 128), "KP_G err 0x%lx", GetLastError());
        SET_ERR(0);
        r = U(CryptSetKeyParam)(k, KP_X, NULL, 0);
        CHECKF(r, "KP_X(NULL) err 0x%lx", GetLastError());
        BYTE b[512]; DWORD n = sizeof b;
        CHECK(U(CryptGetKeyParam)(k, KP_P, b, &n, 0)); CHECK(n == 128 && !memcmp(b, dh1024_p, 128));
        n = sizeof b;
        CHECK(U(CryptGetKeyParam)(k, KP_G, b, &n, 0)); CHECK(n == 128 && !memcmp(b, dh1024_g, 128));
        n = sizeof b;
        r = U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n);
        CHECKF(r, "export err 0x%lx", GetLastError());
        if (r) {
            EXPECT_EQ(n, sizeof dh1024_pub_a);
            DWORD m; memcpy(&m, b + 8, 4); EXPECT_EQ(m, MAGIC_DH1);
            memcpy(&m, b + 4, 4); EXPECT_EQ(m, CALG_DH_EPHEM);
            int nz = 0; for (DWORD i = 16; i < n; i++) nz |= b[i];
            CHECK(nz != 0);
        }
        n = sizeof b;
        r = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n);
        CHECKF(r, "private export err 0x%lx", GetLastError());
        if (r) { EXPECT_EQ(n, sizeof dh1024_prv_a); CHECK(!memcmp(b + 16, dh1024_p, 128)); CHECK(!memcmp(b + 16 + 128, dh1024_g, 128)); }
        cab_kd(k);
    }
    cab_rel(p);
}

TEST(capiab_dh_pregen_agreement_with_imported_peer) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY g;
    if (!dh_pregen(p, &g, 0)) { CHECK(0); cab_rel(p); return; }
    CHECK(dh_set_blob(g, KP_P, dh1024_p, 128));
    CHECK(dh_set_blob(g, KP_G, dh1024_g, 128));
    CHECK(U(CryptSetKeyParam)(g, KP_X, NULL, 0));
    BYTE pub[512]; DWORD pn = sizeof pub;
    CHECK(U(CryptExportKey)(g, 0, PUBLICKEYBLOB, 0, pub, &pn));
    HCRYPTKEY b = cab_imp(p, dh1024_prv_b, sizeof dh1024_prv_b, 0);
    HCRYPTKEY kg = dh_agree(p, dh1024_pub_b, sizeof dh1024_pub_b, g);
    HCRYPTKEY kb = dh_agree(p, pub, pn, b);
    CHECKF(kg && kb, "err 0x%lx", GetLastError());
    if (kg && kb) {
        CHECK(dh_set_algid(kg, CALG_RC4)); CHECK(dh_set_algid(kb, CALG_RC4));
        BYTE buf[32]; memcpy(buf, "generated vs imported", 21); DWORD n = 21;
        CHECK(U(CryptEncrypt)(kg, 0, TRUE, 0, buf, &n, sizeof buf));
        CHECK(U(CryptDecrypt)(kb, 0, TRUE, 0, buf, &n));
        CHECK(n == 21 && !memcmp(buf, "generated vs imported", 21));
    }
    cab_kd(kg); cab_kd(kb); cab_kd(b); cab_kd(g); cab_rel(p);
}

TEST(capiab_dh_pregen_param_size_errors) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k;
    CHECK(dh_pregen(p, &k, 0));
    BYTE shortp[127]; memset(shortp, 0x55, sizeof shortp);
    SET_ERR(0);
    EXPECT_FAIL(!dh_set_blob(k, KP_P, shortp, 127), CAB_NTE_BAD_DATA);
    SET_ERR(0);
    EXPECT_FAIL(!dh_set_blob(k, KP_G, shortp, 127), CAB_NTE_BAD_DATA);
    BYTE longp[132]; memset(longp, 0x55, sizeof longp);
    SET_ERR(0);
    EXPECT_FAIL(!dh_set_blob(k, KP_P, longp, 132), CAB_NTE_BAD_DATA);
    /* KP_X only accepts NULL (generate); a buffer is ERROR_INVALID_PARAMETER */
    BYTE x[128]; memset(x, 1, sizeof x);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_X, x, 0), ERROR_INVALID_PARAMETER);
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dh_genkey_default_512) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = 0;
    BOOL r = U(CryptGenKey)(p, CALG_DH_EPHEM, (512u << 16) | CRYPT_EXPORTABLE, &k);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) {
        int ok;
        EXPECT_EQ(cab_kp(k, KP_ALGID, &ok), CALG_DH_EPHEM); CHECK(ok);
        EXPECT_EQ(cab_kp(k, KP_KEYLEN, &ok), 512); CHECK(ok);
        BYTE b[512]; DWORD n = sizeof b;
        CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n)); EXPECT_EQ(n, 8 + 8 + 64);
        n = sizeof b;
        CHECK(U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n)); EXPECT_EQ(n, 8 + 8 + 3 * 64);
        cab_kd(k);
    }
    cab_rel(p);
}

TEST(capiab_dh_genkey_error_table) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = 0;
    DWORD sz[] = { 64, 256, 448, 8192 };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, CALG_DH_EPHEM, sz[i] << 16, &k);
        CHECKF(!r, "DH size %lu generated", sz[i]);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_FLAGS); else cab_kd(k);
    }
    DWORD bad[] = { 0x8, 0x20, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000 };
    for (int i = 0; i < 9; i++) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptGenKey)(p, CALG_DH_EPHEM, (512u << 16) | bad[i], &k), CAB_NTE_BAD_FLAGS);
    }
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGenKey)(p, CALG_RSA_SIGN, 512u << 16, &k), CAB_NTE_BAD_ALGID);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGenKey)(p, 0x7777, 0, &k), CAB_NTE_BAD_ALGID);
    cab_rel(p);
}

TEST(capiab_dh_genkey_sf_in_verifycontext_observe) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = 0;
    SET_ERR(0);
    BOOL r = U(CryptGenKey)(p, CALG_DH_SF, (512u << 16), &k);
    /* probed std and adm: succeeds, KP_ALGID is CALG_DH_SF */
    EXPECT_EQ(r, 1);
    if (r) { EXPECT_EQ(cab_algid(k), CALG_DH_SF); cab_kd(k); }
    cab_rel(p);
}

TEST(capiab_dh_sizes_table_enhanced) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    /* PREGEN avoids generating parameters; only the size check is exercised */
    DWORD ok[] = { 512, 576, 640, 704, 768, 832, 896, 960, 1024, 2048, 4096 };
    for (int i = 0; i < 11; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, CALG_DH_EPHEM, (ok[i] << 16) | CRYPT_PREGEN, &k);
        CHECKF(r, "DH PREGEN %lu err 0x%lx", ok[i], GetLastError());
        if (r) EXPECT_EQ(cab_keylen(k), ok[i]);
        cab_kd(r ? k : 0);
    }
    DWORD bad[] = { 4160, 8192, 513, 1000 };
    for (int i = 0; i < 4; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, CALG_DH_EPHEM, (bad[i] << 16) | CRYPT_PREGEN, &k);
        CHECKF(!r, "DH PREGEN %lu accepted", bad[i]);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_FLAGS); else cab_kd(k);
    }
    cab_rel(p);
}

TEST(capiab_dh_permissions_set_validation) {
    DH_NOWINE(); CAB_NEED();
    HCRYPTPROV p = cab_dsdh(); if (!p) { t_skip("no dss-dh"); return; }
    HCRYPTKEY k = dh_imp_prv(p, 0);
    CHECK(k != 0);
    DWORD v = 0x80;                                  /* outside 0x13f */
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_PERMISSIONS, (BYTE *)&v, 0), CAB_NTE_BAD_FLAGS);
    v = CRYPT_EXPORT;                                /* cannot be granted after the fact */
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSetKeyParam)(k, KP_PERMISSIONS, (BYTE *)&v, 0), CAB_NTE_BAD_DATA);
    v = CRYPT_ENCRYPT | CRYPT_DECRYPT;
    CHECK(U(CryptSetKeyParam)(k, KP_PERMISSIONS, (BYTE *)&v, 0));
    int ok; DWORD g = cab_kp(k, KP_PERMISSIONS, &ok); CHECK(ok);
    EXPECT_EQ(g & 0x13b, v);
    cab_kd(k); cab_rel(p);
}

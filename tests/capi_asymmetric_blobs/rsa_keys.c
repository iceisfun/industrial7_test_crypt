/* RSA PUBLICKEYBLOB / PRIVATEKEYBLOB import, export and key parameters (VERIFYCONTEXT, ephemeral). */
#include "cab.h"

#define PRVLEN(bits) (20 + (bits) / 8 * 9 / 2)
#define PUBLEN(bits) (20 + (bits) / 8)

TEST(capiab_rsa_blob_vectors_layout) {
    /* sanity of the authoring-time vectors themselves: header, magic, bitlen, pubexp */
    for (int i = 0; i < CAB_NRK; i++) {
        const cab_rsakey_t *k = &CAB_RKS[i];
        DWORD v;
        CHECKF(k->pubn == PUBLEN(k->bits), "%s pub len %zu", k->name, k->pubn);
        CHECKF(k->prvn == PRVLEN(k->bits), "%s prv len %zu", k->name, k->prvn);
        CHECK(k->pub[0] == PUBLICKEYBLOB && k->pub[1] == CUR_BLOB_VERSION);
        CHECK(k->prv[0] == PRIVATEKEYBLOB && k->prv[1] == CUR_BLOB_VERSION);
        memcpy(&v, k->pub + 8, 4); EXPECT_EQ(v, MAGIC_RSA1);
        memcpy(&v, k->prv + 8, 4); EXPECT_EQ(v, MAGIC_RSA2);
        memcpy(&v, k->pub + 12, 4); EXPECT_EQ(v, k->bits);
        memcpy(&v, k->pub + 16, 4); EXPECT_EQ(v, 65537);
    }
}

TEST(capiab_rsa_import_public_all_providers) {
    CAB_NEED();
    for (int p = 0; p < CAB_NRSA; p++)
        for (int i = 0; i < CAB_NRK; i++) {
            HCRYPTPROV h = cab_acq(CAB_RSA[p].name, CAB_RSA[p].type);
            CHECKF(h != 0, "provider %s unavailable", CAB_RSA[p].tag); if (!h) continue;
            HCRYPTKEY k = cab_imp(h, CAB_RKS[i].pub, (DWORD)CAB_RKS[i].pubn, 0);
            CHECKF(k != 0, "%s %s pub import err 0x%lx", CAB_RSA[p].tag, CAB_RKS[i].name, GetLastError());
            if (k) {
                EXPECT_EQ(cab_keylen(k), CAB_RKS[i].bits);
                EXPECT_EQ(cab_algid(k), CALG_RSA_KEYX);
            }
            cab_kd(k); cab_rel(h);
        }
}

TEST(capiab_rsa_import_private_enhanced_aes) {
    CAB_NEED();
    for (int p = 0; p < 2; p++)
        for (int i = 0; i < CAB_NRK; i++) {
            HCRYPTPROV h = cab_acq(CAB_RSA[p].name, CAB_RSA[p].type);
            CHECKF(h != 0, "provider %s unavailable", CAB_RSA[p].tag); if (!h) continue;
            HCRYPTKEY k = cab_imp(h, CAB_RKS[i].prv, (DWORD)CAB_RKS[i].prvn, 0);
            CHECKF(k != 0, "%s %s prv import err 0x%lx", CAB_RSA[p].tag, CAB_RKS[i].name, GetLastError());
            if (k) {
                EXPECT_EQ(cab_keylen(k), CAB_RKS[i].bits);
                EXPECT_EQ(cab_algid(k), CALG_RSA_KEYX);
            }
            cab_kd(k); cab_rel(h);
        }
}

TEST(capiab_rsa_import_private_base_provider_observe) {
    CAB_NEED();
    HCRYPTPROV h = cab_acq(MS_DEF_PROV_W, PROV_RSA_FULL);
    if (!h) { t_skip("base provider unavailable"); return; }
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTKEY k = cab_imp(h, CAB_RKS[i].prv, (DWORD)CAB_RKS[i].prvn, 0);
        /* probed std and adm: the base provider imports 512 and 1024 bit private keys and rejects 2048 with NTE_BAD_DATA */
        t_label("%s", CAB_RKS[i].name);
        if (CAB_RKS[i].bits <= 1024) CHECKF(k != 0, "err 0x%lx", GetLastError());
        else { CHECK(k == 0); EXPECT_ERR(CAB_NTE_BAD_DATA); }
        cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsa_import_signature_keyspec_alg) {
    /* aiKeyAlg CALG_RSA_SIGN in the header is reflected by KP_ALGID */
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    memcpy(b, rsa1024_pub, sizeof rsa1024_pub); cab_setalg(b, CALG_RSA_SIGN);
    HCRYPTKEY k = cab_imp(h, b, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    if (k) { EXPECT_EQ(cab_algid(k), CALG_RSA_SIGN); EXPECT_EQ(cab_keylen(k), 1024); }
    cab_kd(k);
    memcpy(b, rsa1024_prv, sizeof rsa1024_prv); cab_setalg(b, CALG_RSA_SIGN);
    k = cab_imp(h, b, sizeof rsa1024_prv, 0);
    CHECK(k != 0);
    if (k) EXPECT_EQ(cab_algid(k), CALG_RSA_SIGN);
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_keyparam_blocklen_keylen_bits) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTKEY k = cab_imp(h, CAB_RKS[i].pub, (DWORD)CAB_RKS[i].pubn, 0);
        if (!k) { CHECK(0); continue; }
        int ok = 0;
        EXPECT_EQ(cab_kp(k, KP_KEYLEN, &ok), CAB_RKS[i].bits); CHECK(ok);
        EXPECT_EQ(cab_kp(k, KP_BLOCKLEN, &ok), CAB_RKS[i].bits); CHECK(ok);
        cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsa_keyparam_padding_mode_for_rsa) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    if (k) {
        int ok = 0;
        DWORD v = cab_kp(k, KP_PADDING, &ok);
        CHECK(ok); EXPECT_EQ(v, 0);                 /* observed: RSA key types report 0 */
        v = cab_kp(k, KP_ALGID, &ok); CHECK(ok); EXPECT_EQ(v, CALG_RSA_KEYX);
    }
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_keyparam_salt_not_found) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    if (k) {
        BYTE salt[16]; DWORD n = sizeof salt;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_SALT, salt, &n, 0), CAB_NTE_NOT_FOUND);
    } else CHECK(0);
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_keyparam_size_protocol) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    DWORD params[] = { KP_ALGID, KP_KEYLEN, KP_BLOCKLEN, KP_PERMISSIONS };
    for (int i = 0; k && i < 4; i++) {
        DWORD n = 0, v = 0;
        SET_ERR(0);
        BOOL r = U(CryptGetKeyParam)(k, params[i], NULL, &n, 0);
        CHECKF(r && n == 4, "param %lu: NULL buf r=%d n=%lu", params[i], r, n);
        n = 0; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, params[i], (BYTE *)&v, &n, 0), ERROR_MORE_DATA);
        EXPECT_EQ(n, 4);
        n = 3; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, params[i], (BYTE *)&v, &n, 0), ERROR_MORE_DATA);
        EXPECT_EQ(n, 4);
        n = 4; r = U(CryptGetKeyParam)(k, params[i], (BYTE *)&v, &n, 0);
        CHECK(r); EXPECT_EQ(n, 4);
        n = 100; r = U(CryptGetKeyParam)(k, params[i], (BYTE *)&v, &n, 0);
        CHECK(r); EXPECT_EQ(n, 4);
    }
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_keyparam_errors) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    DWORD v = 0, n = 4;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetKeyParam)(k, 0xFFFF, (BYTE *)&v, &n, 0), CAB_NTE_BAD_TYPE);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetKeyParam)(k, 0, (BYTE *)&v, &n, 0), CAB_NTE_BAD_TYPE);
    if (t_is_wine()) t_skip("NULL pdwDataLen faults under this emulator");
    else {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_ALGID, (BYTE *)&v, NULL, 0), ERROR_INVALID_PARAMETER);
    }
    cab_kd(k); cab_rel(h);
}


TEST(capiab_rsa_permissions_default_import) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY kp = cab_imp(h, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTKEY ke = cab_imp(h, rsa1024_prv, sizeof rsa1024_prv, CRYPT_EXPORTABLE);
    HCRYPTKEY kb = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(kp && ke && kb);
    int ok;
    if (kp) { DWORD v = cab_kp(kp, KP_PERMISSIONS, &ok); CHECK(ok);
        CHECKF(!(v & CRYPT_EXPORT), "private non-exportable perms 0x%lx", v);
        EXPECT_EQ(v, 0x3b); /* probed std and adm */ }
    if (ke) { DWORD v = cab_kp(ke, KP_PERMISSIONS, &ok); CHECK(ok);
        CHECKF(v & CRYPT_EXPORT, "exportable perms 0x%lx", v);
        EXPECT_EQ(v, 0x3f); /* probed std and adm */ }
    if (kb) { DWORD v = cab_kp(kb, KP_PERMISSIONS, &ok); CHECK(ok); EXPECT_EQ(v, 0x3b); /* probed std and adm */ }
    cab_kd(kp); cab_kd(ke); cab_kd(kb); cab_rel(h);
}

TEST(capiab_rsa_export_public_from_public) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTKEY k = cab_imp(h, CAB_RKS[i].pub, (DWORD)CAB_RKS[i].pubn, 0);
        if (!k) { CHECK(0); continue; }
        BYTE buf[1024]; DWORD n = 0;
        CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, NULL, &n));
        EXPECT_EQ(n, CAB_RKS[i].pubn);
        n = sizeof buf;
        CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, buf, &n));
        EXPECT_EQ(n, CAB_RKS[i].pubn);
        CHECKF(n == CAB_RKS[i].pubn && !memcmp(buf, CAB_RKS[i].pub, n), "%s export mismatch", CAB_RKS[i].name);
        cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsa_export_public_from_private) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTKEY k = cab_imp(h, CAB_RKS[i].prv, (DWORD)CAB_RKS[i].prvn, 0);   /* non-exportable: public export is still allowed */
        if (!k) { CHECK(0); continue; }
        BYTE buf[1024]; DWORD n = sizeof buf;
        BOOL r = U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, buf, &n);
        CHECKF(r, "%s err 0x%lx", CAB_RKS[i].name, GetLastError());
        CHECKF(r && n == CAB_RKS[i].pubn && !memcmp(buf, CAB_RKS[i].pub, n), "%s public export mismatch", CAB_RKS[i].name);
        cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsa_export_private_roundtrip) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTKEY k = cab_imp(h, CAB_RKS[i].prv, (DWORD)CAB_RKS[i].prvn, CRYPT_EXPORTABLE);
        if (!k) { CHECK(0); continue; }
        BYTE buf[4096]; DWORD n = 0;
        CHECK(U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, NULL, &n));
        EXPECT_EQ(n, CAB_RKS[i].prvn);
        n = sizeof buf;
        BOOL r = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, buf, &n);
        CHECKF(r, "%s err 0x%lx", CAB_RKS[i].name, GetLastError());
        CHECKF(r && n == CAB_RKS[i].prvn && !memcmp(buf, CAB_RKS[i].prv, n), "%s private export mismatch", CAB_RKS[i].name);
        cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsa_export_private_nonexportable) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_prv, sizeof rsa1024_prv, 0);
    CHECK(k != 0);
    BYTE buf[4096]; DWORD n = sizeof buf;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, buf, &n), CAB_NTE_BAD_KEY_STATE);
    n = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, NULL, &n), CAB_NTE_BAD_KEY_STATE);
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_export_buffer_protocol) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_prv, sizeof rsa1024_prv, CRYPT_EXPORTABLE);
    CHECK(k != 0);
    BYTE buf[4096];
    DWORD n;
    DWORD types[] = { PUBLICKEYBLOB, PRIVATEKEYBLOB };
    DWORD want[] = { sizeof rsa1024_pub, sizeof rsa1024_prv };
    for (int i = 0; k && i < 2; i++) {
        n = want[i] - 1; SET_ERR(0);
        EXPECT_FAIL(!U(CryptExportKey)(k, 0, types[i], 0, buf, &n), ERROR_MORE_DATA);
        EXPECT_EQ(n, want[i]);
        n = 0; SET_ERR(0);
        EXPECT_FAIL(!U(CryptExportKey)(k, 0, types[i], 0, buf, &n), ERROR_MORE_DATA);
        EXPECT_EQ(n, want[i]);
        n = want[i]; CHECK(U(CryptExportKey)(k, 0, types[i], 0, buf, &n)); EXPECT_EQ(n, want[i]);
        n = want[i] + 100; CHECK(U(CryptExportKey)(k, 0, types[i], 0, buf, &n)); EXPECT_EQ(n, want[i]);
    }
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_export_errors) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_prv, sizeof rsa1024_prv, CRYPT_EXPORTABLE);
    CHECK(k != 0);
    BYTE buf[4096]; DWORD n = sizeof buf;
    /* PUBLICKEYBLOB must not name an export key (observed: NTE_BAD_PUBLIC_KEY) */
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, k, PUBLICKEYBLOB, 0, buf, &n), CAB_NTE_BAD_PUBLIC_KEY);
    /* a SIMPLEBLOB of an asymmetric key is meaningless */
    n = sizeof buf; SET_ERR(0);
    BOOL r = U(CryptExportKey)(k, 0, SIMPLEBLOB, 0, buf, &n);
    CHECK(!r);
    EXPECT_ERR(CAB_NTE_BAD_KEY); /* probed std and adm */
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_export_bad_blob_types) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(h, rsa1024_prv, sizeof rsa1024_prv, CRYPT_EXPORTABLE);
    CHECK(k != 0);
    DWORD bad[] = { 0, 99, 0xFF };
    for (int i = 0; k && i < 3; i++) {
        BYTE buf[4096]; DWORD n = sizeof buf;
        SET_ERR(0);
        BOOL r = U(CryptExportKey)(k, 0, bad[i], 0, buf, &n);
        CHECKF(!r, "blob type %lu exported", bad[i]);
        t_label("type %lu", bad[i]);
        EXPECT_ERR(CAB_NTE_BAD_TYPE); /* probed std and adm */
    }
    cab_kd(k); cab_rel(h);
}


/* ---- import error table -------------------------------------------- */
TEST(capiab_rsa_import_truncated_blobs) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    /* shorter than a BLOBHEADER: ERROR_INVALID_PARAMETER */
    for (DWORD n = 0; n < 8; n++) {
        HCRYPTKEY k = 1;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptImportKey)(h, rsa1024_pub, n, 0, 0, &k), ERROR_INVALID_PARAMETER);
    }
    /* public blob: dwDataLen < bitlen/8 + 20 gives NTE_BAD_LEN (the header bitlen is read from the buffer) */
    DWORD cuts[] = { 8, 12, 19, 20, 21, 100, (DWORD)sizeof rsa1024_pub - 1 };
    for (int i = 0; i < 7; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(h, rsa1024_pub, cuts[i], 0, 0, &k);
        CHECKF(!r, "truncated public blob len %lu imported", cuts[i]);
        if (!r) { DWORD e = GetLastError(); CHECKF(e == (DWORD)CAB_NTE_BAD_LEN, "len %lu err 0x%lx", cuts[i], e); }
        else cab_kd(k);
    }
    /* private blob: shorter than the header + 8 bytes is NTE_BAD_DATA; longer cuts are not length checked per field */
    for (DWORD n = 8; n < 16; n++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(h, rsa1024_prv, n, 0, 0, &k);
        CHECKF(!r, "private blob len %lu imported", n);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_DATA); else cab_kd(k);
    }
    DWORD pc[] = { 20, 148, 300, (DWORD)sizeof rsa1024_prv - 1 };
    for (int i = 0; i < 4; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(h, rsa1024_prv, pc[i], 0, 0, &k);
        /* probed std and adm: cuts of 20, 148 and 300 bytes fail with ERROR_INVALID_DATA; losing only the last byte still imports */
        t_label("cut %lu", pc[i]);
        if (i < 3) { EXPECT_EQ(r, 0); EXPECT_ERR(ERROR_INVALID_DATA); } else EXPECT_EQ(r, 1);
        cab_kd(r ? k : 0);
    }
    cab_rel(h);
}

TEST(capiab_rsa_import_trailing_bytes_tolerated) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    memset(b, 0xAA, sizeof b);
    memcpy(b, rsa1024_pub, sizeof rsa1024_pub);
    HCRYPTKEY k = cab_imp(h, b, sizeof rsa1024_pub + 32, 0);
    EXPECT_EQ(k != 0, 1); /* probed std and adm: trailing bytes are tolerated */
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_import_bad_header_fields) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    HCRYPTKEY k;
    /* version byte */
    memcpy(b, rsa1024_pub, sizeof rsa1024_pub); b[1] = 3;
    SET_ERR(0); k = 0;
    EXPECT_FAIL(!U(CryptImportKey)(h, b, sizeof rsa1024_pub, 0, 0, &k), CAB_NTE_BAD_VER);
    b[1] = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(h, b, sizeof rsa1024_pub, 0, 0, &k), CAB_NTE_BAD_VER);
    /* blob type byte */
    memcpy(b, rsa1024_pub, sizeof rsa1024_pub); b[0] = 0x55;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(h, b, sizeof rsa1024_pub, 0, 0, &k), CAB_NTE_BAD_TYPE);
    b[0] = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(h, b, sizeof rsa1024_pub, 0, 0, &k), CAB_NTE_BAD_TYPE);
    cab_rel(h);
}

TEST(capiab_rsa_import_bad_magic) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    /* private path demands RSA2 (observed) -> NTE_BAD_DATA */
    struct { DWORD magic; const char *what; } t[] = {
        { MAGIC_RSA1, "prv with RSA1 magic" }, { 0x41414141, "prv bad magic" }, { 0, "prv zero magic" }, { MAGIC_DSS2, "prv with DSS2 magic" },
    };
    for (int i = 0; i < 4; i++) {
        memcpy(b, rsa1024_prv, sizeof rsa1024_prv); cab_setmagic(b, t[i].magic);
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(h, b, sizeof rsa1024_prv, 0, 0, &k);
        CHECKF(!r, "%s imported", t[i].what);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_DATA); else cab_kd(k);
    }
    /* probed std and adm: the public import accepts any magic, but only a key imported with RSA1 can be exported again (NTE_BAD_KEY otherwise) */
    DWORD pm[] = { 0x41414141, MAGIC_RSA2, 0, MAGIC_RSA1 };
    for (int i = 0; i < 4; i++) {
        memcpy(b, rsa1024_pub, sizeof rsa1024_pub); cab_setmagic(b, pm[i]);
        HCRYPTKEY k = cab_imp(h, b, sizeof rsa1024_pub, 0);
        CHECKF(k != 0, "public blob magic 0x%lx err 0x%lx", pm[i], GetLastError());
        if (k) {
            BYTE o[512]; DWORD n = sizeof o;
            t_label("magic 0x%lx", pm[i]);
            SET_ERR(0); BOOL er = U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, o, &n);
            if (pm[i] == MAGIC_RSA1) { EXPECT_EQ(er, 1); EXPECT_EQ(n, sizeof rsa1024_pub); DWORD m = 0; if (er) memcpy(&m, o + 8, 4); EXPECT_EQ(m, MAGIC_RSA1); }
            else { EXPECT_EQ(er, 0); EXPECT_ERR(CAB_NTE_BAD_KEY); }
        }
        cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsa_import_bad_bitlen_fields) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    /* observed: public path runs a key-size check (enhanced: 384..16384 bits) then a data-length check; both give NTE_BAD_LEN */
    DWORD bl[] = { 8, 376, 2048, 4096, 16392 };
    for (int i = 0; i < 5; i++) {
        memcpy(b, rsa1024_pub, sizeof rsa1024_pub);
        memcpy(b + 12, &bl[i], 4);
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(h, b, sizeof rsa1024_pub, 0, 0, &k);
        CHECKF(!r, "public blob claiming bitlen %lu imported", bl[i]);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_LEN); else cab_kd(k);
    }
    /* private path: illegal key size gives NTE_BAD_DATA */
    DWORD pl[] = { 8, 376 };
    for (int i = 0; i < 2; i++) {
        memcpy(b, rsa1024_prv, sizeof rsa1024_prv);
        memcpy(b + 12, &pl[i], 4);
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(h, b, sizeof rsa1024_prv, 0, 0, &k);
        CHECKF(!r, "private blob claiming bitlen %lu imported", pl[i]);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_DATA); else cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsa_import_flag_table) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    /* observed: flags outside 0x2153 give NTE_BAD_FLAGS before anything else is examined */
    DWORD bad[] = { 0x4, 0x8, 0x20, 0x80, 0x200, 0x400, 0x800, 0x1000, 0x4000, 0x8000, 0x10000, 0x80000000 };
    for (int i = 0; i < (int)(sizeof bad / sizeof bad[0]); i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        /* 0x8 is rejected with ERROR_INVALID_PARAMETER, all others with NTE_BAD_FLAGS (probed) */
        EXPECT_FAIL(!U(CryptImportKey)(h, rsa1024_pub, sizeof rsa1024_pub, 0, bad[i], &k),
                    bad[i] == 0x8 ? ERROR_INVALID_PARAMETER : CAB_NTE_BAD_FLAGS);
    }
    DWORD good[] = { CRYPT_EXPORTABLE, CRYPT_NO_SALT, CRYPT_OAEP };
    for (int i = 0; i < 3; i++) {
        HCRYPTKEY k = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, good[i]);
        CHECKF(k != 0, "public import with flag 0x%lx err 0x%lx", good[i], GetLastError());
        cab_kd(k);
    }
    cab_rel(h);
}

TEST(capiab_rsa_import_param_errors) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY k = 0;
    /* hPubKey must be 0 for a PUBLICKEYBLOB (observed: ERROR_INVALID_PARAMETER) */
    HCRYPTKEY other = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(h, rsa1024_pub, sizeof rsa1024_pub, other, 0, &k), ERROR_INVALID_PARAMETER);
    cab_kd(other);
    cab_rel(h);
}


TEST(capiab_rsa_import_twice_independent_handles) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY a = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTKEY b = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(a && b); CHECK(a != b);
    cab_kd(a);
    int ok; DWORD v = cab_kp(b, KP_KEYLEN, &ok); CHECK(ok); EXPECT_EQ(v, 1024);
    cab_kd(b); cab_rel(h);
}

TEST(capiab_rsa_import_zero_exponent_and_small_exponents) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    DWORD exps[] = { 0, 1, 3, 17, 65537 };
    for (int i = 0; i < 5; i++) {
        memcpy(b, rsa1024_pub, sizeof rsa1024_pub);
        memcpy(b + 16, &exps[i], 4);
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(h, b, sizeof rsa1024_pub, 0, 0, &k);
        t_label("pubexp %lu", exps[i]);
        EXPECT_EQ(r, 1); /* probed std and adm: every exponent imports, including 0 and 1 */
        if (r) {
            BYTE o[512]; DWORD n = sizeof o;
            if (U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, o, &n)) {
                DWORD e; memcpy(&e, o + 16, 4);
                EXPECT_EQ(e, exps[i]);
            }
            cab_kd(k);
        }
    }
    cab_rel(h);
}

TEST(capiab_rsa_export_pubexp_3_roundtrip) {
    /* a public key with e=3 survives import/export unchanged */
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    memcpy(b, rsa1024_pub, sizeof rsa1024_pub);
    DWORD e = 3; memcpy(b + 16, &e, 4);
    HCRYPTKEY k = cab_imp(h, b, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    if (k) {
        BYTE o[512]; DWORD n = sizeof o;
        CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, o, &n));
        CHECK(n == sizeof rsa1024_pub && !memcmp(o, b, n));
    }
    cab_kd(k); cab_rel(h);
}

TEST(capiab_rsa_two_private_imports_replace_userkey) {
    /* importing a private key with aiKeyAlg KEYX installs it as the context's AT_KEYEXCHANGE key; a second import replaces it */
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY a = cab_imp(h, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTKEY b = cab_imp(h, rsa2048_prv, sizeof rsa2048_prv, 0);
    CHECK(a && b);
    if (U(CryptGetUserKey)) {
        HCRYPTKEY u = 0;
        BOOL r = U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &u);
        CHECKF(r, "CryptGetUserKey err 0x%lx", GetLastError());
        if (r) EXPECT_EQ(cab_keylen(u), 2048); /* probed std and adm: the second import replaced the first */
        cab_kd(u);
        u = 0; SET_ERR(0);
        r = U(CryptGetUserKey)(h, AT_SIGNATURE, &u);
        CHECK(!r);
        EXPECT_ERR(CAB_NTE_NO_KEY); /* probed std and adm */
        cab_kd(r ? u : 0);
    }
    cab_kd(a); cab_kd(b); cab_rel(h);
}

TEST(capiab_rsa_getuserkey_verifycontext_empty) {
    CAB_NEED();
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY u = 0;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &u), CAB_NTE_NO_KEY);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetUserKey)(h, AT_SIGNATURE, &u), CAB_NTE_NO_KEY);
    SET_ERR(0);
    BOOL r = U(CryptGetUserKey)(h, 3, &u);
    CHECK(!r);
    EXPECT_ERR(CAB_NTE_BAD_KEY); /* probed std and adm */
    cab_rel(h);
}

TEST(capiab_rsa_imported_private_becomes_userkey) {
    CAB_NEED();
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY a = cab_imp(h, rsa1024_prv, sizeof rsa1024_prv, 0);
    CHECK(a != 0);
    HCRYPTKEY u = 0;
    BOOL r = U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &u);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(cab_keylen(u), 1024); EXPECT_EQ(cab_algid(u), CALG_RSA_KEYX); }
    cab_kd(u);
    u = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetUserKey)(h, AT_SIGNATURE, &u), CAB_NTE_NO_KEY);
    cab_kd(a); cab_rel(h);
}

TEST(capiab_rsa_imported_public_not_userkey) {
    CAB_NEED();
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    HCRYPTKEY a = cab_imp(h, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(a != 0);
    HCRYPTKEY u = 0;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &u), CAB_NTE_NO_KEY);
    cab_kd(a); cab_rel(h);
}

TEST(capiab_rsa_signature_private_import_userkey_is_signature) {
    CAB_NEED();
    REQUIRE(U(CryptGetUserKey));
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    memcpy(b, rsa1024_prv, sizeof rsa1024_prv); cab_setalg(b, CALG_RSA_SIGN);
    HCRYPTKEY a = cab_imp(h, b, sizeof rsa1024_prv, 0);
    CHECK(a != 0);
    HCRYPTKEY u = 0;
    BOOL r = U(CryptGetUserKey)(h, AT_SIGNATURE, &u);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) EXPECT_EQ(cab_algid(u), CALG_RSA_SIGN);
    cab_kd(u); u = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetUserKey)(h, AT_KEYEXCHANGE, &u), CAB_NTE_NO_KEY);
    cab_kd(a); cab_rel(h);
}

TEST(capiab_rsa_import_private_bad_crt_fields_observe) {
    CAB_NEED();
    HCRYPTPROV h = cab_enh(); if (!h) { t_skip("no enh"); return; }
    BYTE b[1024];
    /* zeroed private exponent / primes: behaviour recorded, key must not be usable for correct signatures */
    struct { size_t off, len; const char *what; } z[] = {
        { 20 + 128, 64, "prime1" }, { 20 + 128 + 64, 64, "prime2" }, { 20 + 128 + 128, 64, "exponent1" },
        { 20 + 128 + 256, 64, "coefficient" }, { 20 + 128 + 320, 128, "privateExponent" },
    };
    for (int i = 0; i < 5; i++) {
        memcpy(b, rsa1024_prv, sizeof rsa1024_prv);
        memset(b + z[i].off, 0, z[i].len);
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(h, b, sizeof rsa1024_prv, 0, 0, &k);
        /* probed std and adm: zeroed prime1/prime2 are rejected with ERROR_GEN_FAILURE (31); zeroed exponent1, coefficient and private exponent import */
        t_label("zeroed %s", z[i].what);
        if (i < 2) { EXPECT_EQ(r, 0); EXPECT_ERR(ERROR_GEN_FAILURE); } else EXPECT_EQ(r, 1);
        cab_kd(r ? k : 0);
    }
    cab_rel(h);
}

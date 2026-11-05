/* DSS keys (DSS1/DSS2 blobs) in the dssenh providers, VERIFYCONTEXT only. */
#include "cab.h"

#define DSSPUBLEN (sizeof dss1024_pub)
#define DSS_Y_END (8 + 8 + 128 + 20 + 128 + 128)     /* header + DSSPUBKEY + P Q G Y */

typedef struct { const WCHAR *name; DWORD type; const char *tag; } dprov_t;
static const dprov_t DP[] = {
    { MS_DEF_DSS_PROV_W,     PROV_DSS,    "base-dss" },
    { MS_DEF_DSS_DH_PROV_W,  PROV_DSS_DH, "base-dss-dh" },
    { MS_ENH_DSS_DH_PROV_W,  PROV_DSS_DH, "enh-dss-dh" },
};
#define NDP 3

TEST(capiab_dss_blob_vectors_layout) {
    DWORD v;
    CHECK(dss1024_pub[0] == PUBLICKEYBLOB && dss1024_prv[0] == PRIVATEKEYBLOB);
    memcpy(&v, dss1024_pub + 8, 4); EXPECT_EQ(v, MAGIC_DSS1);
    memcpy(&v, dss1024_prv + 8, 4); EXPECT_EQ(v, MAGIC_DSS2);
    memcpy(&v, dss1024_pub + 12, 4); EXPECT_EQ(v, 1024);
    EXPECT_EQ(sizeof dss1024_pub, 8 + 8 + 128 + 20 + 128 + 128 + 24);
    EXPECT_EQ(sizeof dss1024_prv, 8 + 8 + 128 + 20 + 128 + 20 + 24);
    EXPECT_EQ(sizeof dss1024_sig_sha1, 40);
}

TEST(capiab_dss_acquire_verifycontext_all) {
    CAB_NEED();
    for (int i = 0; i < NDP; i++) {
        HCRYPTPROV p = cab_acq(DP[i].name, DP[i].type);
        CHECKF(p != 0, "%s acquire err 0x%lx", DP[i].tag, GetLastError());
        cab_rel(p);
    }
}

TEST(capiab_dss_import_public_all_providers) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    for (int i = 0; i < NDP; i++) {
        HCRYPTPROV p = cab_acq(DP[i].name, DP[i].type); if (!p) continue;
        HCRYPTKEY k = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
        CHECKF(k != 0, "%s err 0x%lx", DP[i].tag, GetLastError());
        if (k) {
            int ok;
            EXPECT_EQ(cab_kp(k, KP_ALGID, &ok), CALG_DSS_SIGN); CHECK(ok);
            EXPECT_EQ(cab_kp(k, KP_KEYLEN, &ok), 1024); CHECK(ok);
            EXPECT_EQ(cab_kp(k, KP_BLOCKLEN, &ok), 1024); CHECK(ok);
        }
        cab_kd(k); cab_rel(p);
    }
}

TEST(capiab_dss_import_private_all_providers) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    for (int i = 0; i < NDP; i++) {
        HCRYPTPROV p = cab_acq(DP[i].name, DP[i].type); if (!p) continue;
        HCRYPTKEY k = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
        CHECKF(k != 0, "%s err 0x%lx", DP[i].tag, GetLastError());
        if (k) { EXPECT_EQ(cab_algid(k), CALG_DSS_SIGN); EXPECT_EQ(cab_keylen(k), 1024); }
        cab_kd(k); cab_rel(p);
    }
}

TEST(capiab_dss_keyparam_pqg_raw_bytes) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    CHECK(k != 0);
    struct { DWORD kp; size_t off, len; const char *n; } t[] = {
        { KP_P, 16, 128, "P" }, { KP_Q, 16 + 128, 20, "Q" }, { KP_G, 16 + 128 + 20, 128, "G" },
    };
    for (int i = 0; k && i < 3; i++) {
        BYTE b[256]; DWORD n = 0;
        SET_ERR(0);
        BOOL r = U(CryptGetKeyParam)(k, t[i].kp, NULL, &n, 0);
        CHECKF(r && n == t[i].len, "%s size r=%d n=%lu err 0x%lx", t[i].n, r, n, GetLastError());
        n = (DWORD)t[i].len - 1; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, t[i].kp, b, &n, 0), ERROR_MORE_DATA);
        EXPECT_EQ(n, t[i].len);
        n = sizeof b;
        r = U(CryptGetKeyParam)(k, t[i].kp, b, &n, 0);
        CHECKF(r && n == t[i].len, "%s get r=%d n=%lu", t[i].n, r, n);
        CHECKF(r && n == t[i].len && !memcmp(b, dss1024_pub + t[i].off, n), "%s bytes differ from blob", t[i].n);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_keyparam_unsupported_params) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_prv, sizeof dss1024_prv, CRYPT_EXPORTABLE);
    CHECK(k != 0);
    DWORD bad[] = { 1, 2, 3, 4, 5, 10, 14, 15, 19, 100 };      /* observed: only 6..9, 11..13 and 40 are handled */
    for (int i = 0; k && i < 10; i++) {
        BYTE b[256]; DWORD n = sizeof b;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, bad[i], b, &n, 0), CAB_NTE_BAD_TYPE);
    }
    BYTE b[16]; DWORD n = 4;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGetKeyParam)(k, KP_ALGID, b, &n, 1), CAB_NTE_BAD_FLAGS);
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_keyparam_size_protocol) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    DWORD params[] = { KP_PERMISSIONS, KP_ALGID, KP_BLOCKLEN, KP_KEYLEN };
    for (int i = 0; k && i < 4; i++) {
        DWORD n = 0, v = 0;
        BOOL r = U(CryptGetKeyParam)(k, params[i], NULL, &n, 0);
        CHECKF(r && n == 4, "param %lu: r=%d n=%lu", params[i], r, n);
        n = 3; SET_ERR(0);
        EXPECT_FAIL(!U(CryptGetKeyParam)(k, params[i], (BYTE *)&v, &n, 0), ERROR_MORE_DATA);
        EXPECT_EQ(n, 4);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_export_public_from_public) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    CHECK(k != 0);
    BYTE b[1024]; DWORD n = 0;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, NULL, &n));
    EXPECT_EQ(n, DSSPUBLEN);
    n = sizeof b;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n));
    EXPECT_EQ(n, DSSPUBLEN);
    CHECK(n == DSSPUBLEN && !memcmp(b, dss1024_pub, DSS_Y_END));
    if (n == DSSPUBLEN && memcmp(b + DSS_Y_END, dss1024_pub + DSS_Y_END, 24))
        t_note("DSSSEED tail of exported public blob differs from the imported (no-seed) one");
    n = (DWORD)DSSPUBLEN - 1; SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n), ERROR_MORE_DATA);
    EXPECT_EQ(n, DSSPUBLEN - 1);   /* dssenh leaves the length unchanged on ERROR_MORE_DATA (probed) */
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_export_public_from_private) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
    CHECK(k != 0);
    BYTE b[1024]; DWORD n = sizeof b;
    BOOL r = U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n);
    CHECKF(r, "err 0x%lx", GetLastError());
    CHECK(r && n == DSSPUBLEN && !memcmp(b, dss1024_pub, DSS_Y_END));
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_export_private_roundtrip) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_prv, sizeof dss1024_prv, CRYPT_EXPORTABLE);
    CHECK(k != 0);
    BYTE b[1024]; DWORD n = sizeof b;
    BOOL r = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) {
        EXPECT_EQ(n, sizeof dss1024_prv);
        size_t head = 8 + 8 + 128 + 20 + 128 + 20;
        CHECK(n == sizeof dss1024_prv && !memcmp(b, dss1024_prv, head));
        DWORD m; memcpy(&m, b + 8, 4); EXPECT_EQ(m, MAGIC_DSS2);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_export_private_nonexportable) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
    BYTE b[1024]; DWORD n = sizeof b;
    SET_ERR(0);
    BOOL r = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n);
    CHECK(!r);
    t_note("non-exportable DSS private export: err 0x%lx", GetLastError());
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_verify_known_answer) {
    CAB_NEED();
    for (int i = 0; i < NDP; i++) {
        HCRYPTPROV p = cab_acq(DP[i].name, DP[i].type); if (!p) continue;
        HCRYPTKEY k = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        CHECK(k && h);
        if (k && h) {
            BOOL r = U(CryptVerifySignatureW)(h, dss1024_sig_sha1, 40, k, NULL, 0);
            CHECKF(r, "%s verify err 0x%lx", DP[i].tag, GetLastError());
        }
        cab_hd(h); cab_kd(k); cab_rel(p);
    }
}

TEST(capiab_dss_verify_negative) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    CHECK(k != 0);
    /* wrong data */
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, "another message", 15);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptVerifySignatureW)(h, dss1024_sig_sha1, 40, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
    cab_hd(h);
    /* bit flips in r and s */
    int pos[] = { 0, 19, 20, 39 };
    for (int i = 0; k && i < 4; i++) {
        BYTE s[40]; memcpy(s, dss1024_sig_sha1, 40); s[pos[i]] ^= 0x01;
        h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, s, 40, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
        cab_hd(h);
    }
    /* r = 0 and s = 0 are invalid */
    BYTE z[40]; memset(z, 0, 40);
    h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptVerifySignatureW)(h, z, 40, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
    cab_hd(h);
    /* swapped r and s */
    BYTE sw[40]; memcpy(sw, dss1024_sig_sha1 + 20, 20); memcpy(sw + 20, dss1024_sig_sha1, 20);
    h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptVerifySignatureW)(h, sw, 40, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_verify_signature_lengths) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    BYTE s[64]; memset(s, 0, sizeof s); memcpy(s, dss1024_sig_sha1, 40);
    DWORD lens[] = { 0, 1, 20, 39, 41, 64 };
    for (int i = 0; k && i < 6; i++) {
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        SET_ERR(0);
        BOOL r = U(CryptVerifySignatureW)(h, s, lens[i], k, NULL, 0);
        CHECKF(!r, "length %lu accepted", lens[i]);
        t_note("DSS verify with signature length %lu: err 0x%lx", lens[i], r ? 0 : GetLastError());
        cab_hd(h);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_verify_flags_nonzero) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    DWORD fl[] = { 1, 2, 4, 0x80000000 };
    for (int i = 0; k && i < 4; i++) {
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, dss1024_sig_sha1, 40, k, NULL, fl[i]), CAB_NTE_BAD_FLAGS);
        cab_hd(h);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_sign_verify_roundtrip) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY sk = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
    HCRYPTKEY pk = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    CHECK(sk && pk && h);
    if (sk && pk && h) {
        BYTE s1[64], s2[64]; DWORD n1 = 0, n2;
        CHECK(U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, NULL, &n1)); EXPECT_EQ(n1, 40);
        n1 = 39; SET_ERR(0);
        BOOL r = U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, s1, &n1);
        CHECK(!r); if (!r) EXPECT_ERR(ERROR_MORE_DATA);
        n1 = sizeof s1; n2 = sizeof s2;
        CHECK(U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, s1, &n1)); EXPECT_EQ(n1, 40);
        CHECK(U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, s2, &n2)); EXPECT_EQ(n2, 40);
        CHECKF(memcmp(s1, s2, 40) != 0, "DSS signatures are randomized");
        CHECK(U(CryptVerifySignatureW)(h, s1, 40, pk, NULL, 0));
        CHECK(U(CryptVerifySignatureW)(h, s2, 40, pk, NULL, 0));
    }
    cab_hd(h); cab_kd(sk); cab_kd(pk); cab_rel(p);
}

TEST(capiab_dss_sign_error_table) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    BYTE s[64]; DWORD n = sizeof s;
    /* no key yet */
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, s, &n), CAB_NTE_NO_KEY);
    HCRYPTKEY sk = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
    CHECK(sk != 0);
    /* observed: flags must be 0, keyspec must be AT_SIGNATURE */
    n = sizeof s; SET_ERR(0);
    EXPECT_FAIL(!U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 1, s, &n), CAB_NTE_BAD_FLAGS);
    n = sizeof s; SET_ERR(0);
    EXPECT_FAIL(!U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, s, &n), CAB_NTE_BAD_ALGID);
    n = sizeof s; SET_ERR(0);
    EXPECT_FAIL(!U(CryptSignHashW)(h, 3, NULL, 0, s, &n), CAB_NTE_BAD_ALGID);
    cab_hd(h); cab_kd(sk); cab_rel(p);
}

TEST(capiab_dss_hash_algs_supported) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    ALG_ID algs[] = { CALG_SHA1, CALG_MD5, CALG_MD2, CALG_SHA_256 };
    const char *nm[] = { "sha1", "md5", "md2", "sha256" };
    for (int i = 0; i < 4; i++) {
        HCRYPTHASH h = 0;
        SET_ERR(0);
        BOOL r = U(CryptCreateHash)(p, algs[i], 0, 0, &h);
        t_note("dssenh CryptCreateHash(%s): %d err 0x%lx", nm[i], r, r ? 0 : GetLastError());
        if (i == 0) CHECK(r);
        cab_hd(r ? h : 0);
    }
    cab_rel(p);
}

TEST(capiab_dss_sign_with_non_sha1_hash) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY sk = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
    HCRYPTHASH h = cab_hash(p, CALG_MD5, rsa_msg, sizeof rsa_msg);
    if (h) {
        BYTE s[64]; DWORD n = sizeof s;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, s, &n), CAB_NTE_BAD_HASH);
    } else t_note("provider rejects MD5 hashes outright (err 0x%lx)", GetLastError());
    cab_hd(h); cab_kd(sk); cab_rel(p);
}

TEST(capiab_dss_import_bad_blobs) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    BYTE b[1024];
    HCRYPTKEY k;
    /* too short for a header */
    for (DWORD n = 0; n < 8; n++) {
        k = 1; SET_ERR(0);
        EXPECT_FAIL(!U(CryptImportKey)(p, dss1024_pub, n, 0, 0, &k), ERROR_INVALID_PARAMETER);
    }
    /* unknown blob type */
    memcpy(b, dss1024_pub, sizeof dss1024_pub); b[0] = 0x55;
    k = 0; SET_ERR(0);
    EXPECT_FAIL(!U(CryptImportKey)(p, b, sizeof dss1024_pub, 0, 0, &k), CAB_NTE_BAD_TYPE);
    /* RSA key algorithm in a DSS provider */
    memcpy(b, dss1024_pub, sizeof dss1024_pub); cab_setalg(b, CALG_RSA_KEYX);
    SET_ERR(0);
    BOOL r = U(CryptImportKey)(p, b, sizeof dss1024_pub, 0, 0, &k);
    CHECK(!r); if (r) cab_kd(k); else EXPECT_ERR(CAB_NTE_BAD_DATA);
    /* wrong magic */
    memcpy(b, dss1024_pub, sizeof dss1024_pub); cab_setmagic(b, MAGIC_DSS2);
    SET_ERR(0);
    r = U(CryptImportKey)(p, b, sizeof dss1024_pub, 0, 0, &k);
    CHECK(!r); if (r) cab_kd(k);
    t_note("DSS public blob with DSS2 magic: err 0x%lx", r ? 0 : GetLastError());
    memcpy(b, dss1024_prv, sizeof dss1024_prv); cab_setmagic(b, MAGIC_DSS1);
    SET_ERR(0);
    r = U(CryptImportKey)(p, b, sizeof dss1024_prv, 0, 0, &k);
    CHECK(!r); if (r) cab_kd(k);
    t_note("DSS private blob with DSS1 magic: err 0x%lx", r ? 0 : GetLastError());
    /* truncated */
    DWORD cuts[] = { 16, 100, 200, (DWORD)sizeof dss1024_pub - 25 };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0);
        r = U(CryptImportKey)(p, dss1024_pub, cuts[i], 0, 0, &k);
        CHECKF(!r, "DSS public blob truncated to %lu imported", cuts[i]);
        t_note("DSS public blob truncated to %lu: err 0x%lx", cuts[i], r ? 0 : GetLastError());
        if (r) cab_kd(k);
    }
    cab_rel(p);
}

TEST(capiab_dss_import_flags) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    DWORD fl[] = { 0x4, 0x8, 0x20, 0x80, 0x400, 0x80000000 };
    for (int i = 0; i < 6; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportKey)(p, dss1024_pub, sizeof dss1024_pub, 0, fl[i], &k);
        t_note("DSS import with flags 0x%lx: %d err 0x%lx", fl[i], r, r ? 0 : GetLastError());
        if (r) cab_kd(k);
    }
    HCRYPTKEY k = cab_imp(p, dss1024_prv, sizeof dss1024_prv, CRYPT_EXPORTABLE);
    CHECK(k != 0);
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_import_public_with_hpubkey) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY other = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    HCRYPTKEY k = 0;
    SET_ERR(0);
    BOOL r = U(CryptImportKey)(p, dss1024_pub, sizeof dss1024_pub, other, 0, &k);
    t_note("DSS public import with nonzero hPubKey: %d err 0x%lx", r, r ? 0 : GetLastError());
    if (r) cab_kd(k);
    cab_kd(other); cab_rel(p);
}

TEST(capiab_dss_keyparam_permissions) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY a = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
    HCRYPTKEY b = cab_imp(p, dss1024_pub, sizeof dss1024_pub, 0);
    int ok;
    DWORD v = cab_kp(a, KP_PERMISSIONS, &ok); CHECK(ok);
    t_note("DSS private key KP_PERMISSIONS = 0x%lx", v);
    v = cab_kp(b, KP_PERMISSIONS, &ok); CHECK(ok);
    t_note("DSS public key KP_PERMISSIONS = 0x%lx", v);
    cab_kd(a); cab_kd(b); cab_rel(p);
}

/* ---- CryptGenKey with DSS --------------------------------------------- */
TEST(capiab_dss_genkey_sizes) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    DWORD sizes[] = { 512, 1024 };
    for (int i = 0; i < 2; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, AT_SIGNATURE, sizes[i] << 16, &k);
        CHECKF(r, "genkey %lu err 0x%lx", sizes[i], GetLastError());
        if (r) {
            EXPECT_EQ(cab_keylen(k), sizes[i]);
            EXPECT_EQ(cab_algid(k), CALG_DSS_SIGN);
            cab_kd(k);
        }
    }
    cab_rel(p);
}

TEST(capiab_dss_genkey_invalid_sizes) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    DWORD sizes[] = { 64, 256, 448, 1088, 2048 };
    for (int i = 0; i < 5; i++) {
        HCRYPTKEY k = 0;
        SET_ERR(0);
        BOOL r = U(CryptGenKey)(p, AT_SIGNATURE, sizes[i] << 16, &k);
        CHECKF(!r, "genkey %lu succeeded", sizes[i]);
        if (!r) EXPECT_ERR(CAB_NTE_BAD_FLAGS); else cab_kd(k);
    }
    cab_rel(p);
}

TEST(capiab_dss_genkey_algid_and_flags) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = 0;
    /* PROV_DSS has no key exchange keys */
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGenKey)(p, AT_KEYEXCHANGE, 512 << 16, &k), CAB_NTE_BAD_ALGID);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGenKey)(p, CALG_DH_EPHEM, 512 << 16, &k), CAB_NTE_BAD_ALGID);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGenKey)(p, CALG_RSA_SIGN, 512 << 16, &k), CAB_NTE_BAD_ALGID);
    /* observed: flags & 0x3fa8 -> NTE_BAD_FLAGS */
    DWORD bad[] = { 0x8, 0x20, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000 };
    for (int i = 0; i < 9; i++) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptGenKey)(p, AT_SIGNATURE, (512 << 16) | bad[i], &k), CAB_NTE_BAD_FLAGS);
    }
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptGenKey)(p, AT_SIGNATURE, 512 << 16, NULL), ERROR_INVALID_PARAMETER);
    cab_rel(p);
}

TEST(capiab_dss_genkey_export_roundtrip) {
    CAB_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = 0;
    BOOL r = U(CryptGenKey)(p, AT_SIGNATURE, (512 << 16) | CRYPT_EXPORTABLE, &k);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) {
        BYTE pub[1024], prv[1024]; DWORD np = sizeof pub, nv = sizeof prv;
        CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, pub, &np));
        CHECK(U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, prv, &nv));
        DWORD m, bits;
        memcpy(&m, pub + 8, 4); EXPECT_EQ(m, MAGIC_DSS1);
        memcpy(&m, prv + 8, 4); EXPECT_EQ(m, MAGIC_DSS2);
        memcpy(&bits, pub + 12, 4); EXPECT_EQ(bits, 512);
        EXPECT_EQ(np, 8 + 8 + 64 + 20 + 64 + 64 + 24);
        EXPECT_EQ(nv, 8 + 8 + 64 + 20 + 64 + 20 + 24);
        /* use as the context signing key */
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, "abc", 3);
        BYTE s[64]; DWORD sn = sizeof s;
        CHECK(U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, s, &sn)); EXPECT_EQ(sn, 40);
        HCRYPTKEY pk = cab_imp(p, pub, np, 0);
        CHECK(pk && U(CryptVerifySignatureW)(h, s, sn, pk, NULL, 0));
        cab_hd(h); cab_kd(pk);
        cab_kd(k);
    }
    cab_rel(p);
}

TEST(capiab_dss_genkey_not_exportable_private) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = 0;
    CHECK(U(CryptGenKey)(p, AT_SIGNATURE, 512 << 16, &k));
    BYTE b[1024]; DWORD n = sizeof b;
    SET_ERR(0);
    BOOL r = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, b, &n);
    CHECK(!r);
    t_note("generated non-exportable DSS private export: err 0x%lx", r ? 0 : GetLastError());
    n = sizeof b;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &n));
    cab_kd(k); cab_rel(p);
}

TEST(capiab_dss_genkey_user_protected_verifycontext) {
    CAB_NEED();
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = 0;
    SET_ERR(0);
    BOOL r = U(CryptGenKey)(p, AT_SIGNATURE, (512 << 16) | CRYPT_USER_PROTECTED, &k);
    t_note("DSS CryptGenKey(CRYPT_USER_PROTECTED) in VERIFYCONTEXT: %d err 0x%lx", r, r ? 0 : GetLastError());
    cab_kd(r ? k : 0);
    cab_rel(p);
}

TEST(capiab_dss_genkey_replaces_context_key) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY a = 0, b = 0;
    CHECK(U(CryptGenKey)(p, AT_SIGNATURE, 512 << 16, &a));
    CHECK(U(CryptGenKey)(p, AT_SIGNATURE, 768 << 16, &b));
    HCRYPTKEY u = 0;
    REQUIRE(U(CryptGetUserKey));
    BOOL r = U(CryptGetUserKey)(p, AT_SIGNATURE, &u);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) EXPECT_EQ(cab_keylen(u), 768);
    cab_kd(u); cab_kd(a); cab_kd(b); cab_rel(p);
}

TEST(capiab_dss_genkey_all_provider_variants) {
    CAB_NEED();
    for (int i = 0; i < NDP; i++) {
        HCRYPTPROV p = cab_acq(DP[i].name, DP[i].type); if (!p) continue;
        HCRYPTKEY k = 0;
        BOOL r = U(CryptGenKey)(p, AT_SIGNATURE, 512 << 16, &k);
        CHECKF(r, "%s err 0x%lx", DP[i].tag, GetLastError());
        cab_kd(r ? k : 0); cab_rel(p);
    }
}

TEST(capiab_dss_sizes_allowed_table) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    for (DWORD bits = 512; bits <= 1024; bits += 64) {
        HCRYPTKEY k = 0;
        BOOL r = U(CryptGenKey)(p, AT_SIGNATURE, bits << 16, &k);
        CHECKF(r, "DSS %lu err 0x%lx", bits, GetLastError());
        if (r) EXPECT_EQ(cab_keylen(k), bits);
        cab_kd(r ? k : 0);
    }
    cab_rel(p);
}

TEST(capiab_dss_default_size_genkey) {
    CAB_NEED();
    CAB_NOWINE("no CPGetKeyParam");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = 0;
    BOOL r = U(CryptGenKey)(p, AT_SIGNATURE, 0, &k);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(cab_keylen(k), 1024); EXPECT_EQ(cab_algid(k), CALG_DSS_SIGN); }
    cab_kd(r ? k : 0); cab_rel(p);
}

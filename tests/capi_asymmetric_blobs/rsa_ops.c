/* RSA sign / verify / encrypt / decrypt with imported ephemeral keys (VERIFYCONTEXT). */
#include "cab.h"

typedef struct {
    const char *name;
    const unsigned char *prv; size_t prvn;
    const unsigned char *pub; size_t pubn;
    ALG_ID alg;
    const unsigned char *sig; size_t sign;
    DWORD flags;           /* sign/verify flags (CRYPT_NOHASHOID) */
    int aes;               /* needs the AES provider (SHA-2) */
} sv_t;

#define SV(nm, k, a, sg, fl, aesp) { nm, rsa##k##_prv, sizeof rsa##k##_prv, rsa##k##_pub, sizeof rsa##k##_pub, a, sg, sizeof sg, fl, aesp }
static const sv_t SVS[] = {
    SV("512/sha1",        512,  CALG_SHA1,    rsa512_sig_sha1,  0, 0),
    SV("1024/md5",        1024, CALG_MD5,     rsa1024_sig_md5,  0, 0),
    SV("1024/sha1",       1024, CALG_SHA1,    rsa1024_sig_sha1, 0, 0),
    SV("1024/sha256",     1024, CALG_SHA_256, rsa1024_sig_sha256, 0, 1),
    SV("1024/md5/nooid",  1024, CALG_MD5,     rsa1024_nooid_md5, CRYPT_NOHASHOID, 0),
    SV("1024/sha1/nooid", 1024, CALG_SHA1,    rsa1024_nooid_sha1, CRYPT_NOHASHOID, 0),
    SV("2048/sha256",     2048, CALG_SHA_256, rsa2048_sig_sha256, 0, 1),
    SV("2048/sha384",     2048, CALG_SHA_384, rsa2048_sig_sha384, 0, 1),
    SV("2048/sha512",     2048, CALG_SHA_512, rsa2048_sig_sha512, 0, 1),
};
#define NSV ((int)(sizeof SVS / sizeof SVS[0]))

static HCRYPTPROV sv_prov(const sv_t *v) { return v->aes ? cab_aes() : cab_enh(); }

/* sign with the imported private key (as keyspec) and return signature length, 0 on failure */
static DWORD sv_sign(HCRYPTPROV p, const sv_t *v, DWORD keyspec, BYTE *sig, DWORD cap) {
    HCRYPTHASH h = cab_hash(p, v->alg, rsa_msg, sizeof rsa_msg);
    if (!h) return 0;
    DWORD n = cap;
    BOOL r = U(CryptSignHashW)(h, keyspec, NULL, v->flags, sig, &n);
    cab_hd(h);
    return r ? n : 0;
}

TEST(capiab_rsa_sign_known_answer_keyexchange) {
    CAB_NEED();
    for (int i = 0; i < NSV; i++) {
        const sv_t *v = &SVS[i];
        HCRYPTPROV p = sv_prov(v); if (!p) { t_note("%s: provider unavailable", v->name); continue; }
        HCRYPTKEY k = cab_imp(p, v->prv, (DWORD)v->prvn, 0);
        CHECKF(k != 0, "%s import err 0x%lx", v->name, GetLastError());
        BYTE sig[512];
        DWORD n = sv_sign(p, v, AT_KEYEXCHANGE, sig, sizeof sig);
        CHECKF(n == v->sign, "%s sig len %lu want %zu (err 0x%lx)", v->name, n, v->sign, GetLastError());
        CHECKF(n == v->sign && !memcmp(sig, v->sig, n), "%s signature mismatch", v->name);
        cab_kd(k); cab_rel(p);
    }
}

TEST(capiab_rsa_sign_known_answer_signature_key) {
    CAB_NEED();
    for (int i = 0; i < NSV; i++) {
        const sv_t *v = &SVS[i];
        HCRYPTPROV p = sv_prov(v); if (!p) continue;
        BYTE b[2048];
        memcpy(b, v->prv, v->prvn); cab_setalg(b, CALG_RSA_SIGN);
        HCRYPTKEY k = cab_imp(p, b, (DWORD)v->prvn, 0);
        CHECKF(k != 0, "%s import err 0x%lx", v->name, GetLastError());
        BYTE sig[512];
        DWORD n = sv_sign(p, v, AT_SIGNATURE, sig, sizeof sig);
        CHECKF(n == v->sign && !memcmp(sig, v->sig, n), "%s signature mismatch (len %lu)", v->name, n);
        cab_kd(k); cab_rel(p);
    }
}

TEST(capiab_rsa_verify_known_answer) {
    CAB_NEED();
    for (int i = 0; i < NSV; i++) {
        const sv_t *v = &SVS[i];
        HCRYPTPROV p = sv_prov(v); if (!p) continue;
        HCRYPTKEY k = cab_imp(p, v->pub, (DWORD)v->pubn, 0);
        HCRYPTHASH h = cab_hash(p, v->alg, rsa_msg, sizeof rsa_msg);
        CHECKF(k && h, "%s setup", v->name);
        if (k && h) {
            BOOL r = U(CryptVerifySignatureW)(h, v->sig, (DWORD)v->sign, k, NULL, v->flags);
            CHECKF(r, "%s verify err 0x%lx", v->name, GetLastError());
        }
        cab_hd(h); cab_kd(k); cab_rel(p);
    }
}

TEST(capiab_rsa_verify_with_private_key_handle) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    CHECK(k && h);
    if (k && h) {
        BOOL r = U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, sizeof rsa1024_sig_sha1, k, NULL, 0);
        CHECKF(r, "err 0x%lx", GetLastError());
    }
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_wrong_data_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, "other message", 13);
    CHECK(k && h);
    if (k && h) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, sizeof rsa1024_sig_sha1, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
    }
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_wrong_hash_alg_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTHASH h = cab_hash(p, CALG_MD5, rsa_msg, sizeof rsa_msg);     /* signature was made with SHA1 */
    CHECK(k && h);
    if (k && h) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, sizeof rsa1024_sig_sha1, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
    }
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_tampered_signature_bytes) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    int pos[] = { 0, 1, 63, 126, 127 };
    for (int i = 0; k && i < 5; i++) {
        BYTE s[128]; memcpy(s, rsa1024_sig_sha1, 128); s[pos[i]] ^= 0x01;
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, s, 128, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
        cab_hd(h);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_signature_ge_modulus_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    BYTE s[128]; memset(s, 0xFF, sizeof s);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    CHECK(k && h);
    if (k && h) {
        SET_ERR(0);
        BOOL r = U(CryptVerifySignatureW)(h, s, 128, k, NULL, 0);
        CHECK(!r);
        t_note("all-ones signature: err 0x%lx", GetLastError());
    }
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_wrong_signature_length) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    BYTE s[256]; memset(s, 0, sizeof s); memcpy(s, rsa1024_sig_sha1, 128);
    DWORD lens[] = { 0, 1, 64, 127, 129, 256 };
    for (int i = 0; k && i < 6; i++) {
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, s, lens[i], k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
        cab_hd(h);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_flag_validation) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    DWORD bad[] = { 0x2, 0x8, 0x10, 0x20, 0x100, 0x80000000 };
    for (int i = 0; k && i < 6; i++) {
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, 128, k, NULL, bad[i]), CAB_NTE_BAD_FLAGS);
        cab_hd(h);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_nohashoid_mismatch) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(k != 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    SET_ERR(0);
    /* a raw (no hash OID) signature also verifies without CRYPT_NOHASHOID on Win10 (probed) */
    EXPECT_SUCCEEDS(U(CryptVerifySignatureW)(h, rsa1024_nooid_sha1, 128, k, NULL, 0));
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, 128, k, NULL, CRYPT_NOHASHOID), CAB_NTE_BAD_SIGNATURE);
    CHECK(U(CryptVerifySignatureW)(h, rsa1024_nooid_sha1, 128, k, NULL, CRYPT_NOHASHOID));
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_sha1_sig_as_md5_oid_hash_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTHASH h = cab_hash(p, CALG_MD5, rsa_msg, sizeof rsa_msg);
    CHECK(k && h);
    if (k && h) {
        CHECK(U(CryptVerifySignatureW)(h, rsa1024_sig_md5, 128, k, NULL, 0));
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, 128, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
    }
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_wrong_key_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa512_pub, sizeof rsa512_pub, 0);    /* different modulus size */
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    CHECK(k && h);
    if (k && h) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, 128, k, NULL, 0), CAB_NTE_BAD_SIGNATURE);
    }
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_verify_key_from_other_provider) {
    CAB_NEED();
    HCRYPTPROV p1 = cab_enh(), p2 = cab_enh(); if (!p1 || !p2) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p2, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTHASH h = cab_hash(p1, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    CHECK(k && h);
    if (k && h) {
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, 128, k, NULL, 0), CAB_NTE_BAD_UID);
    }
    cab_hd(h); cab_kd(k); cab_rel(p1); cab_rel(p2);
}

TEST(capiab_rsa_sign_buffer_protocol) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    CHECK(k && h);
    if (k && h) {
        BYTE sig[256]; DWORD n = 0;
        SET_ERR(0);
        CHECK(U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, NULL, &n)); EXPECT_EQ(n, 128);
        n = 127; SET_ERR(0);
        EXPECT_FAIL(!U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, sig, &n), ERROR_MORE_DATA); EXPECT_EQ(n, 128);
        n = 0; SET_ERR(0);
        EXPECT_FAIL(!U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, sig, &n), ERROR_MORE_DATA); EXPECT_EQ(n, 128);
        n = 128; CHECK(U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, sig, &n)); EXPECT_EQ(n, 128);
        CHECK(!memcmp(sig, rsa1024_sig_sha1, 128));
        n = 200; CHECK(U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, sig, &n)); EXPECT_EQ(n, 128);
    }
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_sign_without_key_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    CHECK(h != 0);
    BYTE sig[256]; DWORD n = sizeof sig;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, sig, &n), CAB_NTE_KEYSET_NOT_DEF);
    n = sizeof sig; SET_ERR(0);
    EXPECT_FAIL(!U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, sig, &n), CAB_NTE_KEYSET_NOT_DEF);
    cab_hd(h); cab_rel(p);
}

TEST(capiab_rsa_sign_wrong_keyspec_for_imported) {
    /* a key imported as KEYX is only reachable through AT_KEYEXCHANGE */
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    BYTE sig[256]; DWORD n = sizeof sig;
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, sig, &n), CAB_NTE_KEYSET_NOT_DEF);
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_sign_bad_keyspec_values) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    DWORD specs[] = { 0, 3, 4, 0x100, 0xFFFFFFFF };
    for (int i = 0; i < 5; i++) {
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        BYTE sig[256]; DWORD n = sizeof sig;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptSignHashW)(h, specs[i], NULL, 0, sig, &n), CAB_NTE_BAD_ALGID);
        cab_hd(h);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_sign_flag_validation) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    DWORD bad[] = { 0x2, 0x8, 0x10, 0x20, 0x100, 0x80000000 };
    for (int i = 0; i < 6; i++) {
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        BYTE sig[256]; DWORD n = sizeof sig;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, bad[i], sig, &n), CAB_NTE_BAD_FLAGS);
        cab_hd(h);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_sign_ansi_wide_parity) {
    CAB_NEED();
    REQUIRE(U(CryptSignHashA)); REQUIRE(U(CryptVerifySignatureA));
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    BYTE a[256], w[256]; DWORD na = sizeof a, nw = sizeof w;
    CHECK(U(CryptSignHashA)(h, AT_KEYEXCHANGE, NULL, 0, a, &na));
    CHECK(U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, w, &nw));
    EXPECT_EQ(na, nw);
    CHECK(na == nw && !memcmp(a, w, na));
    CHECK(na == 128 && !memcmp(a, rsa1024_sig_sha1, 128));
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(U(CryptVerifySignatureA)(h, a, na, pk, NULL, 0));
    /* a description string is accepted and ignored on current systems */
    nw = sizeof w;
    BOOL r = U(CryptSignHashW)(h, AT_KEYEXCHANGE, L"desc", 0, w, &nw);
    t_note("CryptSignHashW with sDescription: %d err 0x%lx", r, r ? 0 : GetLastError());
    cab_hd(h); cab_kd(k); cab_kd(pk); cab_rel(p);
}

TEST(capiab_rsa_sign_deterministic_repeat) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    BYTE a[128], b[128]; DWORD n = 128, m = 128;
    CHECK(U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, a, &n));
    CHECK(U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, b, &m));   /* signing does not finalize the hash again */
    CHECK(n == m && !memcmp(a, b, n));
    cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_sign_hashval_set_matches_data_hash) {
    CAB_NEED();
    REQUIRE(U(CryptGetHashParam)); REQUIRE(U(CryptSetHashParam));
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    BYTE d[20]; DWORD dn = sizeof d;
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dn, 0)); EXPECT_EQ(dn, 20);
    HCRYPTHASH h2 = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h2));
    CHECK(U(CryptSetHashParam)(h2, HP_HASHVAL, d, 0));
    BYTE sig[128]; DWORD n = 128;
    CHECK(U(CryptSignHashW)(h2, AT_KEYEXCHANGE, NULL, 0, sig, &n));
    CHECK(n == 128 && !memcmp(sig, rsa1024_sig_sha1, 128));
    cab_hd(h2); cab_hd(h); cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_sign_verify_roundtrip_sizes) {
    CAB_NEED();
    HCRYPTPROV p = cab_aes(); if (!p) { t_skip("no aes"); return; }
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTKEY k = cab_imp(p, CAB_RKS[i].prv, (DWORD)CAB_RKS[i].prvn, CRYPT_EXPORTABLE);
        HCRYPTKEY pk = cab_imp(p, CAB_RKS[i].pub, (DWORD)CAB_RKS[i].pubn, 0);
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, "round trip", 10);
        BYTE sig[512]; DWORD n = sizeof sig;
        BOOL r = U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, sig, &n);
        CHECKF(r, "%s sign err 0x%lx", CAB_RKS[i].name, GetLastError());
        if (r) {
            EXPECT_EQ(n, CAB_RKS[i].bits / 8);
            CHECK(U(CryptVerifySignatureW)(h, sig, n, pk, NULL, 0));
        }
        cab_hd(h); cab_kd(k); cab_kd(pk);
    }
    cab_rel(p);
}

/* ---- CryptEncrypt / CryptDecrypt with RSA ---------------------------- */
static DWORD rsa_enc(HCRYPTKEY k, const void *pt, DWORD ptn, DWORD flags, BYTE *out, DWORD cap, DWORD *err) {
    memcpy(out, pt, ptn);
    DWORD n = ptn;
    SET_ERR(0);
    BOOL r = U(CryptEncrypt)(k, 0, TRUE, flags, out, &n, cap);
    if (err) *err = r ? 0 : GetLastError();
    return r ? n : 0;
}

TEST(capiab_rsa_decrypt_known_pkcs1) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    CHECK(k != 0);
    BYTE b[256]; memcpy(b, rsa1024_ct_pkcs1, 128); DWORD n = 128;
    BOOL r = U(CryptDecrypt)(k, 0, TRUE, 0, b, &n);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(n, 9); CHECK(!memcmp(b, "hello rsa", 9)); }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_decrypt_known_oaep) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    CHECK(k != 0);
    BYTE b[256]; memcpy(b, rsa1024_ct_oaep, 128); DWORD n = 128;
    BOOL r = U(CryptDecrypt)(k, 0, TRUE, CRYPT_OAEP, b, &n);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(n, 9); CHECK(!memcmp(b, "hello rsa", 9)); }
    /* an OAEP ciphertext is not a valid PKCS1 v1.5 block and vice versa */
    memcpy(b, rsa1024_ct_oaep, 128); n = 128; SET_ERR(0);
    EXPECT_FAIL(!U(CryptDecrypt)(k, 0, TRUE, 0, b, &n), ERROR_INVALID_PARAMETER);
    memcpy(b, rsa1024_ct_pkcs1, 128); n = 128; SET_ERR(0);
    EXPECT_FAIL(!U(CryptDecrypt)(k, 0, TRUE, CRYPT_OAEP, b, &n), ERROR_INVALID_PARAMETER);
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_decrypt_no_padding_check_flag) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    CHECK(k != 0);
    BYTE b[256]; memcpy(b, rsa1024_ct_fixedpad, 128); DWORD n = 128;
    BOOL r = U(CryptDecrypt)(k, 0, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, b, &n);
    t_note("decrypt with CRYPT_DECRYPT_RSA_NO_PADDING_CHECK: r=%d n=%lu err=0x%lx", r, n, r ? 0 : GetLastError());
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_decrypt_tampered_ciphertext_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    int pos[] = { 0, 64, 127 };
    for (int i = 0; k && i < 3; i++) {
        BYTE b[256]; memcpy(b, rsa1024_ct_pkcs1, 128); b[pos[i]] ^= 0x40; DWORD n = 128;
        SET_ERR(0);
        BOOL r = U(CryptDecrypt)(k, 0, TRUE, 0, b, &n);
        CHECKF(!r, "tampered at %d decrypted", pos[i]);
        if (!r) EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_decrypt_wrong_length_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    BYTE b[256]; memset(b, 0, sizeof b); memcpy(b, rsa1024_ct_pkcs1, 128);
    DWORD n = 0;
    SET_ERR(0);
    /* observed: Final with zero length is NTE_BAD_LEN */
    EXPECT_FAIL(!U(CryptDecrypt)(k, 0, TRUE, 0, b, &n), CAB_NTE_BAD_LEN);
    DWORD lens[] = { 1, 64, 127, 129, 256 };
    for (int i = 0; k && i < 5; i++) {
        memset(b, 0, sizeof b); memcpy(b, rsa1024_ct_pkcs1, 128); n = lens[i];
        SET_ERR(0);
        BOOL r = U(CryptDecrypt)(k, 0, TRUE, 0, b, &n);
        t_note("decrypt with ciphertext length %lu: r=%d err 0x%lx", lens[i], r, r ? 0 : GetLastError());
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_decrypt_flag_validation) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    /* observed: only 0x20 and 0x40 are accepted, never both */
    DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x60, 0x80, 0x100, 0x80000000 };
    for (int i = 0; k && i < 9; i++) {
        BYTE b[256]; memcpy(b, rsa1024_ct_pkcs1, 128); DWORD n = 128;
        SET_ERR(0);
        EXPECT_FAIL(!U(CryptDecrypt)(k, 0, TRUE, bad[i], b, &n), CAB_NTE_BAD_FLAGS);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_decrypt_with_public_key_only_fails) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    BYTE b[256]; memcpy(b, rsa1024_ct_pkcs1, 128); DWORD n = 128;
    SET_ERR(0);
    BOOL r = U(CryptDecrypt)(k, 0, TRUE, 0, b, &n);
    CHECK(!r);
    t_note("decrypt with public key only: err 0x%lx", GetLastError());
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_encrypt_roundtrip_lengths) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTKEY sk = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    CHECK(pk && sk);
    DWORD lens[] = { 1, 2, 16, 53, 100, 116, 117 };
    for (int i = 0; pk && sk && i < 7; i++) {
        BYTE pt[128], b[256]; DWORD err;
        for (DWORD j = 0; j < lens[i]; j++) pt[j] = (BYTE)(j * 7 + 1);
        DWORD n = rsa_enc(pk, pt, lens[i], 0, b, sizeof b, &err);
        CHECKF(n == 128, "len %lu: enc n=%lu err 0x%lx", lens[i], n, err);
        if (n != 128) continue;
        DWORD m = n;
        BOOL r = U(CryptDecrypt)(sk, 0, TRUE, 0, b, &m);
        CHECKF(r && m == lens[i] && !memcmp(b, pt, m), "len %lu: dec r=%d m=%lu", lens[i], r, m);
    }
    cab_kd(pk); cab_kd(sk); cab_rel(p);
}

TEST(capiab_rsa_encrypt_roundtrip_oaep_lengths) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTKEY sk = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    DWORD lens[] = { 1, 20, 64, 85, 86 };       /* 128 - 2*20 - 2 = 86 */
    for (int i = 0; pk && sk && i < 5; i++) {
        BYTE pt[128], b[256]; DWORD err;
        for (DWORD j = 0; j < lens[i]; j++) pt[j] = (BYTE)(j * 3 + 5);
        DWORD n = rsa_enc(pk, pt, lens[i], CRYPT_OAEP, b, sizeof b, &err);
        CHECKF(n == 128, "OAEP len %lu: n=%lu err 0x%lx", lens[i], n, err);
        if (n != 128) continue;
        DWORD m = n;
        BOOL r = U(CryptDecrypt)(sk, 0, TRUE, CRYPT_OAEP, b, &m);
        CHECKF(r && m == lens[i] && !memcmp(b, pt, m), "OAEP len %lu: r=%d m=%lu", lens[i], r, m);
    }
    cab_kd(pk); cab_kd(sk); cab_rel(p);
}

TEST(capiab_rsa_encrypt_too_long) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(pk != 0);
    BYTE b[512]; DWORD err;
    memset(b, 0x41, sizeof b);
    EXPECT_EQ(rsa_enc(pk, b, 118, 0, b, sizeof b, &err), 0); EXPECT_EQ(err, CAB_NTE_BAD_LEN);
    memset(b, 0x41, sizeof b);
    EXPECT_EQ(rsa_enc(pk, b, 128, 0, b, sizeof b, &err), 0); EXPECT_EQ(err, CAB_NTE_BAD_LEN);
    memset(b, 0x41, sizeof b);
    /* OAEP capacity of a 1024-bit key is 86 bytes; the next length reports ERROR_INVALID_PARAMETER (probed) */
    EXPECT_EQ(rsa_enc(pk, b, 87, CRYPT_OAEP, b, sizeof b, &err), 0); EXPECT_EQ(err, ERROR_INVALID_PARAMETER);
    cab_kd(pk); cab_rel(p);
}

TEST(capiab_rsa_encrypt_buffer_protocol) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    CHECK(pk != 0);
    BYTE b[256]; DWORD n;
    memset(b, 0x42, 10);
    n = 10; SET_ERR(0);
    CHECK(U(CryptEncrypt)(pk, 0, TRUE, 0, NULL, &n, 0)); EXPECT_EQ(n, 128);
    memset(b, 0x42, 10); n = 10; SET_ERR(0);
    EXPECT_FAIL(!U(CryptEncrypt)(pk, 0, TRUE, 0, b, &n, 127), ERROR_MORE_DATA); EXPECT_EQ(n, 128);
    memset(b, 0x42, 10); n = 10; SET_ERR(0);
    EXPECT_FAIL(!U(CryptEncrypt)(pk, 0, TRUE, 0, b, &n, 10), ERROR_MORE_DATA); EXPECT_EQ(n, 128);
    memset(b, 0x42, 10); n = 10; SET_ERR(0);
    CHECK(U(CryptEncrypt)(pk, 0, TRUE, 0, b, &n, 128)); EXPECT_EQ(n, 128);
    cab_kd(pk); cab_rel(p);
}

TEST(capiab_rsa_encrypt_flag_validation) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x80, 0x100, 0x80000000 };
    for (int i = 0; pk && i < 9; i++) {
        BYTE b[256]; DWORD err;
        memset(b, 0x42, 10);
        DWORD n = rsa_enc(pk, b, 10, bad[i], b, sizeof b, &err);
        CHECKF(n == 0, "encrypt flags 0x%lx succeeded", bad[i]);
        EXPECT_EQ(err, CAB_NTE_BAD_FLAGS);
    }
    cab_kd(pk); cab_rel(p);
}

TEST(capiab_rsa_encrypt_randomized_padding) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    BYTE a[256], b[256]; DWORD e;
    DWORD n1 = rsa_enc(pk, "same", 4, 0, a, sizeof a, &e);
    DWORD n2 = rsa_enc(pk, "same", 4, 0, b, sizeof b, &e);
    CHECK(n1 == 128 && n2 == 128 && memcmp(a, b, 128) != 0);
    n1 = rsa_enc(pk, "same", 4, CRYPT_OAEP, a, sizeof a, &e);
    n2 = rsa_enc(pk, "same", 4, CRYPT_OAEP, b, sizeof b, &e);
    CHECK(n1 == 128 && n2 == 128 && memcmp(a, b, 128) != 0);
    cab_kd(pk); cab_rel(p);
}

TEST(capiab_rsa_encrypt_all_key_sizes) {
    CAB_NEED();
    HCRYPTPROV p = cab_aes(); if (!p) { t_skip("no aes"); return; }
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTKEY pk = cab_imp(p, CAB_RKS[i].pub, (DWORD)CAB_RKS[i].pubn, 0);
        HCRYPTKEY sk = cab_imp(p, CAB_RKS[i].prv, (DWORD)CAB_RKS[i].prvn, 0);
        BYTE b[512]; DWORD e;
        DWORD n = rsa_enc(pk, "payload", 7, 0, b, sizeof b, &e);
        CHECKF(n == CAB_RKS[i].bits / 8, "%s enc n=%lu err 0x%lx", CAB_RKS[i].name, n, e);
        DWORD m = n;
        BOOL r = n && U(CryptDecrypt)(sk, 0, TRUE, 0, b, &m);
        CHECKF(r && m == 7 && !memcmp(b, "payload", 7), "%s dec", CAB_RKS[i].name);
        cab_kd(pk); cab_kd(sk);
    }
    cab_rel(p);
}

TEST(capiab_rsa_encrypt_small_key_max_plaintext) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa512_pub, sizeof rsa512_pub, 0);
    BYTE b[256]; DWORD e;
    memset(b, 0x33, sizeof b);
    EXPECT_EQ(rsa_enc(pk, b, 53, 0, b, sizeof b, &e), 64);   /* 64 - 11 */
    memset(b, 0x33, sizeof b);
    EXPECT_EQ(rsa_enc(pk, b, 54, 0, b, sizeof b, &e), 0); EXPECT_EQ(e, CAB_NTE_BAD_LEN);
    cab_kd(pk); cab_rel(p);
}

TEST(capiab_rsa_encrypt_final_false_observe) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    BYTE b[256]; memset(b, 0x42, 10); DWORD n = 10;
    SET_ERR(0);
    BOOL r = U(CryptEncrypt)(pk, 0, FALSE, 0, b, &n, sizeof b);
    t_note("RSA CryptEncrypt with Final=FALSE: r=%d n=%lu err=0x%lx", r, n, r ? 0 : GetLastError());
    cab_kd(pk); cab_rel(p);
}

TEST(capiab_rsa_encrypt_with_private_handle_ok) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY sk = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    BYTE b[256]; DWORD e;
    DWORD n = rsa_enc(sk, "abc", 3, 0, b, sizeof b, &e);
    CHECKF(n == 128, "n=%lu err=0x%lx", n, e);
    DWORD m = n;
    CHECK(n && U(CryptDecrypt)(sk, 0, TRUE, 0, b, &m)); CHECK(m == 3 && !memcmp(b, "abc", 3));
    cab_kd(sk); cab_rel(p);
}

/* ---- sweeps ------------------------------------------------------------ */
TEST(capiab_rsa_sweep_pkcs1_all_plaintext_lengths) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTKEY sk = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    for (DWORD len = 1; pk && sk && len <= 117; len++) {
        BYTE pt[128], b[256]; DWORD err;
        for (DWORD j = 0; j < len; j++) pt[j] = (BYTE)(j + len);
        DWORD n = rsa_enc(pk, pt, len, 0, b, sizeof b, &err);
        if (n != 128) { CHECKF(0, "len %lu enc err 0x%lx", len, err); continue; }
        DWORD m = n;
        BOOL r = U(CryptDecrypt)(sk, 0, TRUE, 0, b, &m);
        CHECKF(r && m == len && !memcmp(b, pt, len), "len %lu dec r=%d m=%lu", len, r, m);
    }
    cab_kd(pk); cab_kd(sk); cab_rel(p);
}

TEST(capiab_rsa_sweep_oaep_all_plaintext_lengths) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    HCRYPTKEY sk = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    for (DWORD len = 1; pk && sk && len <= 86; len++) {
        BYTE pt[128], b[256]; DWORD err;
        for (DWORD j = 0; j < len; j++) pt[j] = (BYTE)(j * 5 + len);
        DWORD n = rsa_enc(pk, pt, len, CRYPT_OAEP, b, sizeof b, &err);
        if (n != 128) { CHECKF(0, "OAEP len %lu enc err 0x%lx", len, err); continue; }
        DWORD m = n;
        BOOL r = U(CryptDecrypt)(sk, 0, TRUE, CRYPT_OAEP, b, &m);
        CHECKF(r && m == len && !memcmp(b, pt, len), "OAEP len %lu dec r=%d m=%lu", len, r, m);
    }
    cab_kd(pk); cab_kd(sk); cab_rel(p);
}

TEST(capiab_rsa_sweep_every_signature_byte_flip) {
    CAB_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    for (int pos = 0; k && pos < 128; pos++) {
        BYTE s[128]; memcpy(s, rsa1024_sig_sha1, 128); s[pos] ^= 0x80;
        HCRYPTHASH h = cab_hash(p, CALG_SHA1, rsa_msg, sizeof rsa_msg);
        SET_ERR(0);
        BOOL r = U(CryptVerifySignatureW)(h, s, 128, k, NULL, 0);
        CHECKF(!r, "flip at %d verified", pos);
        cab_hd(h);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_rsa_sweep_message_lengths_sign_verify) {
    CAB_NEED();
    HCRYPTPROV p = cab_aes(); if (!p) { t_skip("no aes"); return; }
    HCRYPTKEY sk = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    HCRYPTKEY pk = cab_imp(p, rsa1024_pub, sizeof rsa1024_pub, 0);
    ALG_ID algs[] = { CALG_MD5, CALG_SHA1, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512 };
    BYTE msg[300]; for (int i = 0; i < 300; i++) msg[i] = (BYTE)(i * 31 + 7);
    DWORD lens[] = { 0, 1, 2, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 300 };
    for (int a = 0; sk && pk && a < 5; a++)
        for (int l = 0; l < 15; l++) {
            HCRYPTHASH h = cab_hash(p, algs[a], msg, lens[l]);
            if (!h) { CHECKF(0, "hash alg 0x%x len %lu err 0x%lx", algs[a], lens[l], GetLastError()); continue; }
            BYTE sig[128]; DWORD n = sizeof sig;
            BOOL r = U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, sig, &n);
            CHECKF(r && n == 128, "sign alg 0x%x len %lu err 0x%lx", algs[a], lens[l], GetLastError());
            if (r) CHECKF(U(CryptVerifySignatureW)(h, sig, n, pk, NULL, 0), "verify alg 0x%x len %lu err 0x%lx", algs[a], lens[l], GetLastError());
            cab_hd(h);
        }
    cab_kd(sk); cab_kd(pk); cab_rel(p);
}

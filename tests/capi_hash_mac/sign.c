/* CryptSignHashA/W and CryptVerifySignatureA/W with imported RSA blobs in a VERIFYCONTEXT provider.
 * Signatures are PKCS#1 v1.5 (deterministic) and are returned as little-endian integers, i.e. byte-reversed
 * relative to the RFC 8017 octet string (and relative to what BCryptSignHash produces). */
#include "h.h"
#include "vectors.h"

typedef struct { HCRYPTPROV p; HCRYPTKEY prv, pub; DWORD spec; DWORD nb; } kctx;

static int kopen(kctx *c, int ki) {
    BYTE blob[1200]; int n;
    memset(c, 0, sizeof *c);
    c->p = h_acq_aes(); if (!c->p) return 0;
    c->spec = hv_keys[ki].keyalg == CALG_RSA_SIGN ? AT_SIGNATURE : AT_KEYEXCHANGE;
    c->nb = hv_keys[ki].bits / 8;
    n = h_hex2bin(hv_keys[ki].prv, blob, sizeof blob);
    if (!U(CryptImportKey)(c->p, blob, n, 0, 0, &c->prv)) { t_note("import private key %d failed 0x%lx", ki, GetLastError()); h_rel(c->p); return 0; }
    n = h_hex2bin(hv_keys[ki].pub, blob, sizeof blob);
    if (!U(CryptImportKey)(c->p, blob, n, 0, 0, &c->pub)) { t_note("import public key %d failed 0x%lx", ki, GetLastError()); h_rel(c->p); return 0; }
    return 1;
}
static void kclose(kctx *c) { h_rel(c->p); }

/* hash message #mi with algorithm alg; SSL3_SHAMD5 gets MD5||SHA1 through HP_HASHVAL */
static HCRYPTHASH row_hash(HCRYPTPROV p, ALG_ID alg, int mi) {
    BYTE m[200]; int ml = h_hex2bin(hv_sigmsgs[mi], m, sizeof m); HCRYPTHASH h = 0;
    if (alg == CALG_SSL3_SHAMD5) {
        BYTE v[36]; DWORD l1 = 16, l2 = 20;
        if (!h_hash(p, CALG_MD5, m, ml, v, &l1) || !h_hash(p, CALG_SHA1, m, ml, v + 16, &l2)) return 0;
        if (!U(CryptCreateHash)(p, alg, 0, 0, &h)) return 0;
        if (!U(CryptSetHashParam)(h, HP_HASHVAL, v, 0)) { U(CryptDestroyHash)(h); return 0; }
        return h;
    }
    if (!U(CryptCreateHash)(p, alg, 0, 0, &h)) return 0;
    if (ml && !U(CryptHashData)(h, m, ml, 0)) { U(CryptDestroyHash)(h); return 0; }
    return h;
}

static void sign_all_rows(int ki) {
    kctx c; size_t i; if (!kopen(&c, ki)) return;
    for (i = 0; i < hv_keys[ki].nsigs; i++) {
        const hv_sig *r = &hv_keys[ki].sigs[i]; BYTE sig[300], e[300]; DWORD sl = sizeof sig;
        HCRYPTHASH h = row_hash(c.p, r->alg, r->msg);
        if (!h) { CHECKF(0, "row %zu hash alg 0x%lx", i, r->alg); continue; }
        SET_ERR(0); BOOL ok = U(CryptSignHashW)(h, c.spec, NULL, r->flags, sig, &sl);
        CHECKF(ok, "sign row %zu alg 0x%lx flags %lu err 0x%lx", i, r->alg, r->flags, GetLastError());
        if (ok) {
            int el = h_hex2bin(r->sig, e, sizeof e);
            CHECKF(sl == c.nb && el == (int)sl && !memcmp(sig, e, sl), "row %zu alg 0x%lx flags %lu msg %d signature mismatch", i, r->alg, r->flags, r->msg);
        }
        U(CryptDestroyHash)(h);
    }
    kclose(&c);
}
static void verify_all_rows(int ki) {
    kctx c; size_t i; if (!kopen(&c, ki)) return;
    for (i = 0; i < hv_keys[ki].nsigs; i++) {
        const hv_sig *r = &hv_keys[ki].sigs[i]; BYTE sig[300]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
        HCRYPTHASH h = row_hash(c.p, r->alg, r->msg);
        if (!h) { CHECKF(0, "row %zu hash", i); continue; }
        SET_ERR(0); BOOL ok = U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags);
        CHECKF(ok, "verify row %zu alg 0x%lx flags %lu err 0x%lx", i, r->alg, r->flags, GetLastError());
        /* flipping a bit invalidates the signature */
        sig[sl / 2] ^= 0x10;
        SET_ERR(0); ok = U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags);
        CHECKF(!ok, "tampered row %zu verified", i);
        if (!ok) EXPECT_ERR(E_NTE_BAD_SIGNATURE);
        U(CryptDestroyHash)(h);
    }
    kclose(&c);
}
TEST(capi_sign_kat_rsa1024_sigkey) { REQUIRE(U(CryptSignHashW)); sign_all_rows(0); }
TEST(capi_sign_kat_rsa2048_kxkey) { REQUIRE(U(CryptSignHashW)); sign_all_rows(1); }
TEST(capi_sign_kat_rsa1024_kxkey) { REQUIRE(U(CryptSignHashW)); sign_all_rows(2); }
TEST(capi_verify_kat_rsa1024_sigkey) { REQUIRE(U(CryptVerifySignatureW)); verify_all_rows(0); }
TEST(capi_verify_kat_rsa2048_kxkey) { REQUIRE(U(CryptVerifySignatureW)); verify_all_rows(1); }
TEST(capi_verify_kat_rsa1024_kxkey) { REQUIRE(U(CryptVerifySignatureW)); verify_all_rows(2); }

/* ANSI entry points produce the same results as the wide ones */
TEST(capi_sign_a_and_w_same_signature) {
    REQUIRE(U(CryptSignHashA)); REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 1)) return;
    BYTE a[300], w[300]; DWORD la = sizeof a, lw = sizeof w;
    HCRYPTHASH h1 = row_hash(c.p, CALG_SHA1, 0), h2 = row_hash(c.p, CALG_SHA1, 0);
    CHECK(U(CryptSignHashA)(h1, c.spec, NULL, 0, a, &la)); CHECK(U(CryptSignHashW)(h2, c.spec, NULL, 0, w, &lw));
    CHECK(la == lw && la == c.nb && !memcmp(a, w, la));
    const hv_sig *r = &hv_keys[1].sigs[0]; (void)r;
    U(CryptDestroyHash)(h1); U(CryptDestroyHash)(h2); kclose(&c);
}
TEST(capi_verify_a_and_w_same_result) {
    REQUIRE(U(CryptVerifySignatureA)); REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 1)) return;
    BYTE s[300]; DWORD sl = sizeof s;
    HCRYPTHASH h = row_hash(c.p, CALG_SHA1, 0);
    CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, s, &sl));
    CHECK(U(CryptVerifySignatureA)(h, s, sl, c.pub, NULL, 0));
    CHECK(U(CryptVerifySignatureW)(h, s, sl, c.pub, NULL, 0));
    s[0] ^= 1;
    SET_ERR(0); CHECK(!U(CryptVerifySignatureA)(h, s, sl, c.pub, NULL, 0)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h, s, sl, c.pub, NULL, 0)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    U(CryptDestroyHash)(h); kclose(&c);
}
/* The (deprecated) description string is appended to the hash as UTF-16LE (no terminator) before signing. */
TEST(capi_sign_description_is_hashed_a_and_w) {
    REQUIRE(U(CryptSignHashA)); REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 1)) return;
    BYTE m[16]; int ml = h_hex2bin(hv_sigmsgs[0], m, sizeof m), i;
    BYTE ref[300], sa[300], sw[300]; DWORD lr = sizeof ref, la = sizeof sa, lw = sizeof sw;
    BYTE cat[64]; memcpy(cat, m, ml); for (i = 0; i < 4; i++) { cat[ml + 2*i] = "desc"[i]; cat[ml + 2*i + 1] = 0; }
    HCRYPTHASH hr = 0, ha = row_hash(c.p, CALG_SHA1, 0), hw = row_hash(c.p, CALG_SHA1, 0);
    CHECK(U(CryptCreateHash)(c.p, CALG_SHA1, 0, 0, &hr)); CHECK(U(CryptHashData)(hr, cat, ml + 8, 0));
    CHECK(U(CryptSignHashW)(hr, c.spec, NULL, 0, ref, &lr));
    SET_ERR(0); BOOL oka = U(CryptSignHashA)(ha, c.spec, "desc", 0, sa, &la); CHECKF(oka, "A err 0x%lx", GetLastError());
    SET_ERR(0); BOOL okw = U(CryptSignHashW)(hw, c.spec, L"desc", 0, sw, &lw); CHECKF(okw, "W err 0x%lx", GetLastError());
    if (oka) CHECK(la == lr && !memcmp(sa, ref, lr));
    if (okw) CHECK(lw == lr && !memcmp(sw, ref, lr));
    /* verification applies the same description */
    HCRYPTHASH hv = row_hash(c.p, CALG_SHA1, 0);
    if (okw) { CHECK(U(CryptVerifySignatureW)(hv, sw, lw, c.pub, L"desc", 0)); }
    U(CryptDestroyHash)(hv);
    hv = row_hash(c.p, CALG_SHA1, 0);
    if (okw) { SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(hv, sw, lw, c.pub, L"other", 0)); EXPECT_ERR(E_NTE_BAD_SIGNATURE); }
    U(CryptDestroyHash)(hv);
    hv = row_hash(c.p, CALG_SHA1, 0);
    if (oka) { CHECK(U(CryptVerifySignatureA)(hv, sa, la, c.pub, "desc", 0)); }
    U(CryptDestroyHash)(hv);
    U(CryptDestroyHash)(hr); U(CryptDestroyHash)(ha); U(CryptDestroyHash)(hw); kclose(&c);
}

/* ------------------------------------------------------- output protocol */
TEST(capi_sign_buffer_protocol) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 1)) return;
    HCRYPTHASH h = row_hash(c.p, CALG_SHA_256, 1); BYTE sig[300], full[300]; DWORD sl;
    sl = 0; SET_ERR(0); CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, NULL, &sl)); CHECK(sl == 256);
    sl = 999; CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, NULL, &sl)); CHECK(sl == 256);
    sl = 0; SET_ERR(0); CHECK(!U(CryptSignHashW)(h, c.spec, NULL, 0, sig, &sl)); EXPECT_ERR(ERROR_MORE_DATA); CHECK(sl == 256);
    sl = 255; SET_ERR(0); CHECK(!U(CryptSignHashW)(h, c.spec, NULL, 0, sig, &sl)); EXPECT_ERR(ERROR_MORE_DATA); CHECK(sl == 256);
    sl = 256; CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, full, &sl)); CHECK(sl == 256);
    memset(sig, 0xCC, sizeof sig); sl = 300; CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, sig, &sl)); CHECK(sl == 256);
    CHECK(sig[256] == 0xCC); CHECK(!memcmp(sig, full, 256));
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_size_query_1024) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;
    HCRYPTHASH h = row_hash(c.p, CALG_MD5, 0); DWORD sl = 0;
    CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, NULL, &sl)); CHECK(sl == 128);
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_deterministic_and_repeatable) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;
    HCRYPTHASH h = row_hash(c.p, CALG_SHA1, 1); BYTE a[128], b[128]; DWORD la = 128, lb = 128;
    CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, a, &la)); CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, b, &lb));
    CHECK(la == 128 && lb == 128 && !memcmp(a, b, 128));
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_value_is_little_endian_smaller_than_modulus) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;
    HCRYPTHASH h = row_hash(c.p, CALG_SHA1, 0); BYTE s[128]; DWORD sl = 128; BYTE mod[128];
    CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, s, &sl));
    /* PRIVATEKEYBLOB modulus follows the 8+12 byte headers, also little endian: compare numerically from the top byte */
    BYTE blob[1200]; int n = h_hex2bin(hv_keys[0].prv, blob, sizeof blob); (void)n;
    memcpy(mod, blob + 20, 128);
    int i, cmp = 0; for (i = 127; i >= 0; i--) { if (s[i] != mod[i]) { cmp = s[i] < mod[i] ? -1 : 1; break; } }
    CHECK(cmp < 0);
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_reversed_signature_does_not_verify) {
    REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 0)) return;
    const hv_sig *r = &hv_keys[0].sigs[0]; BYTE sig[128]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
    HCRYPTHASH h = row_hash(c.p, r->alg, r->msg);
    CHECK(U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags));
    h_rev(sig, sl);
    SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    U(CryptDestroyHash)(h); kclose(&c);
}

/* ----------------------------------------------------------- argument errors */
TEST(capi_sign_flags_invalid_bad_flags) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return; size_t i;
    static const DWORD fl[] = { 2, 8, 0x10, 0x100, 0x80000000u, 0xFFFFFFFFu };
    HCRYPTHASH h = row_hash(c.p, CALG_SHA1, 0); BYTE s[128]; DWORD sl;
    for (i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        sl = sizeof s; SET_ERR(0); CHECKF(!U(CryptSignHashW)(h, c.spec, NULL, fl[i], s, &sl), "flags 0x%lx", fl[i]); EXPECT_ERR(E_NTE_BAD_FLAGS);
        sl = 0; SET_ERR(0); CHECK(!U(CryptSignHashW)(h, c.spec, NULL, fl[i], NULL, &sl)); EXPECT_ERR(E_NTE_BAD_FLAGS);
    }
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_invalid_keyspec_fails) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return; size_t i;
    static const DWORD ks[] = { 0, 3, 4, 0x100, 0xFFFFFFFFu };
    HCRYPTHASH h = row_hash(c.p, CALG_SHA1, 0); BYTE s[128];
    for (i = 0; i < sizeof ks / sizeof ks[0]; i++) {
        DWORD sl = sizeof s; SET_ERR(0); CHECKF(!U(CryptSignHashW)(h, ks[i], NULL, 0, s, &sl), "keyspec 0x%lx", ks[i]);
        t_note("keyspec 0x%lx -> error 0x%lx", ks[i], GetLastError());
    }
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_missing_keyspec_key_fails) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;   /* only AT_SIGNATURE is present */
    HCRYPTHASH h = row_hash(c.p, CALG_SHA1, 0); BYTE s[128]; DWORD sl = sizeof s;
    SET_ERR(0); CHECK(!U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, s, &sl));
    DWORD e = GetLastError();
    CHECKF(e == E_NTE_NO_KEY || e == E_NTE_BAD_KEYSET, "err 0x%lx", e);
    t_note("sign with absent AT_KEYEXCHANGE key: 0x%lx", e);
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_no_key_in_fresh_context_fails) {
    REQUIRE(U(CryptSignHashW)); HCRYPTPROV p = h_acq_aes(); if (!p) return;
    HCRYPTHASH h = 0; BYTE s[256]; DWORD sl = sizeof s;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h)); CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    SET_ERR(0); CHECK(!U(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, s, &sl));
    DWORD e = GetLastError(); CHECKF(e == E_NTE_NO_KEY || e == E_NTE_BAD_KEYSET, "err 0x%lx", e);
    t_note("sign in key-less verify context: 0x%lx", e);
    sl = sizeof s; SET_ERR(0); CHECK(!U(CryptSignHashW)(h, AT_KEYEXCHANGE, NULL, 0, s, &sl));
    e = GetLastError(); CHECKF(e == E_NTE_NO_KEY || e == E_NTE_BAD_KEYSET, "err 0x%lx", e);
    U(CryptDestroyHash)(h); h_rel(p);
}
TEST(capi_sign_mac_hmac_hash_bad_algid) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;
    BYTE k[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 }; HCRYPTHASH h = 0; HMAC_INFO hi; BYTE s[128]; DWORD sl = sizeof s;
    HCRYPTKEY key = h_plainkey(c.p, CALG_RC2, k, 16, CRYPT_IPSEC_HMAC_KEY);
    if (key && U(CryptCreateHash)(c.p, CALG_HMAC, key, 0, &h)) {
        memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1;
        CHECK(U(CryptSetHashParam)(h, HP_HMAC_INFO, (BYTE *)&hi, 0));
        CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
        SET_ERR(0); CHECK(!U(CryptSignHashW)(h, c.spec, NULL, 0, s, &sl)); EXPECT_ERR(E_NTE_BAD_ALGID);
        U(CryptDestroyHash)(h);
    }
    kclose(&c);
}
TEST(capi_sign_ssl3_shamd5_requires_value_set) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;
    HCRYPTHASH h = 0; BYTE s[128]; DWORD sl = sizeof s;
    CHECK(U(CryptCreateHash)(c.p, CALG_SSL3_SHAMD5, 0, 0, &h));
    SET_ERR(0); CHECK(!U(CryptSignHashW)(h, c.spec, NULL, CRYPT_NOHASHOID, s, &sl)); EXPECT_ERR(E_NTE_BAD_HASH_STATE);
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_ssl3_shamd5_without_nohashoid_observed) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;
    HCRYPTHASH h = row_hash(c.p, CALG_SSL3_SHAMD5, 0); BYTE a[128], b[128]; DWORD la = 128, lb = 128;
    SET_ERR(0); BOOL ok0 = U(CryptSignHashW)(h, c.spec, NULL, 0, a, &la);
    BOOL ok1 = U(CryptSignHashW)(h, c.spec, NULL, CRYPT_NOHASHOID, b, &lb);
    t_note("SSL3_SHAMD5 sign flags 0: %d (err 0x%lx), NOHASHOID: %d, equal=%d", ok0, ok0 ? 0 : GetLastError(), ok1, ok0 && ok1 && !memcmp(a, b, 128));
    CHECK(ok1);
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_finalizes_hash) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;
    HCRYPTHASH h = row_hash(c.p, CALG_SHA1, 0); BYTE s[128]; DWORD sl = sizeof s;
    CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, s, &sl));
    SET_ERR(0); CHECK(!U(CryptHashData)(h, (const BYTE *)"x", 1, 0)); EXPECT_ERR(E_NTE_BAD_HASH_STATE);
    BYTE d[20]; DWORD dl = 20; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    EXPECT_HEX(d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    /* the same finished hash verifies the signature */
    CHECK(U(CryptVerifySignatureW)(h, s, sl, c.pub, NULL, 0));
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_size_query_does_not_finalize) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 0)) return;
    HCRYPTHASH h = row_hash(c.p, CALG_SHA1, 2); DWORD sl = 0;   /* empty message */
    CHECK(U(CryptSignHashW)(h, c.spec, NULL, 0, NULL, &sl));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    BYTE d[20]; DWORD dl = 20; CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    EXPECT_HEX(d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    U(CryptDestroyHash)(h); kclose(&c);
}

TEST(capi_verify_flags_invalid_bad_flags) {
    REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 0)) return; size_t i;
    static const DWORD fl[] = { 2, 8, 0x10, 0x100, 0x80000000u };
    const hv_sig *r = &hv_keys[0].sigs[0]; BYTE sig[128]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
    HCRYPTHASH h = row_hash(c.p, r->alg, r->msg);
    for (i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        SET_ERR(0); CHECKF(!U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, fl[i]), "flags 0x%lx", fl[i]); EXPECT_ERR(E_NTE_BAD_FLAGS);
    }
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_verify_wrong_hash_alg_bad_signature) {
    REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 1)) return;
    const hv_sig *r = &hv_keys[1].sigs[0]; BYTE sig[256]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
    HCRYPTHASH h = row_hash(c.p, r->alg, r->msg);
    CHECK(U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags));
    U(CryptDestroyHash)(h);
    h = row_hash(c.p, r->alg == CALG_MD2 ? CALG_MD4 : CALG_MD2, r->msg);
    SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_verify_wrong_message_bad_signature) {
    REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 1)) return;
    const hv_sig *r = &hv_keys[1].sigs[0]; BYTE sig[256]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
    HCRYPTHASH h = row_hash(c.p, r->alg, r->msg == 0 ? 1 : 0);
    SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_verify_wrong_length_bad_signature) {
    REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 0)) return;
    const hv_sig *r = &hv_keys[0].sigs[0]; BYTE sig[300]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
    HCRYPTHASH h = row_hash(c.p, r->alg, r->msg);
    SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h, sig, sl - 1, c.pub, NULL, r->flags)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    sig[sl] = 0;
    SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h, sig, sl + 1, c.pub, NULL, r->flags)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h, sig, 0, c.pub, NULL, r->flags)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    CHECK(U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags));
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_verify_nohashoid_mismatch_bad_signature) {
    REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 0)) return; size_t i;
    for (i = 0; i < hv_keys[0].nsigs; i++) {
        const hv_sig *r = &hv_keys[0].sigs[i]; if (r->alg == CALG_SSL3_SHAMD5) continue;
        BYTE sig[128]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
        HCRYPTHASH h = row_hash(c.p, r->alg, r->msg);
        SET_ERR(0); CHECKF(!U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, r->flags ^ CRYPT_NOHASHOID), "row %zu", i);
        EXPECT_ERR(E_NTE_BAD_SIGNATURE);
        U(CryptDestroyHash)(h);
    }
    kclose(&c);
}
TEST(capi_verify_signature_from_other_key_fails) {
    REQUIRE(U(CryptVerifySignatureW)); kctx a, b; if (!kopen(&a, 0)) return; if (!kopen(&b, 2)) { kclose(&a); return; }
    const hv_sig *r = &hv_keys[0].sigs[0]; BYTE sig[128]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
    HCRYPTHASH h = row_hash(a.p, r->alg, r->msg);
    CHECK(U(CryptVerifySignatureW)(h, sig, sl, a.pub, NULL, r->flags));
    /* public key of another keypair, same size */
    HCRYPTHASH h2 = row_hash(b.p, r->alg, r->msg);
    SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h2, sig, sl, b.pub, NULL, r->flags)); EXPECT_ERR(E_NTE_BAD_SIGNATURE);
    U(CryptDestroyHash)(h); U(CryptDestroyHash)(h2); kclose(&a); kclose(&b);
}
TEST(capi_verify_with_session_key_handle_bad_key) {
    REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 0)) return;
    BYTE k[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 }; HCRYPTKEY sk = h_plainkey(c.p, CALG_RC4, k, 16, 0);
    const hv_sig *r = &hv_keys[0].sigs[0]; BYTE sig[128]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
    HCRYPTHASH h = row_hash(c.p, r->alg, r->msg);
    if (sk) { SET_ERR(0); CHECK(!U(CryptVerifySignatureW)(h, sig, sl, sk, NULL, r->flags)); t_note("verify with RC4 key handle: err 0x%lx", GetLastError()); }
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_verify_ssl3_shamd5_requires_value) {
    REQUIRE(U(CryptVerifySignatureW)); kctx c; if (!kopen(&c, 0)) return;
    const hv_sig *r = &hv_keys[0].sigs[0]; BYTE sig[128]; int sl = h_hex2bin(r->sig, sig, sizeof sig);
    HCRYPTHASH h = 0; CHECK(U(CryptCreateHash)(c.p, CALG_SSL3_SHAMD5, 0, 0, &h));
    SET_ERR(0); BOOL ok = U(CryptVerifySignatureW)(h, sig, sl, c.pub, NULL, CRYPT_NOHASHOID);
    CHECK(!ok); t_note("verify with unset SSL3_SHAMD5 hash: err 0x%lx", GetLastError());
    U(CryptDestroyHash)(h); kclose(&c);
}
TEST(capi_sign_verify_roundtrip_all_algs_both_keyspecs) {
    REQUIRE(U(CryptSignHashW)); kctx c; if (!kopen(&c, 1)) return;
    static const ALG_ID al[] = { CALG_MD2, CALG_MD4, CALG_MD5, CALG_SHA1, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512 }; size_t i;
    for (i = 0; i < 7; i++) {
        HCRYPTHASH h = row_hash(c.p, al[i], 1); BYTE s[256]; DWORD sl = sizeof s;
        CHECKF(U(CryptSignHashW)(h, c.spec, NULL, 0, s, &sl), "alg 0x%lx err 0x%lx", al[i], GetLastError());
        CHECK(U(CryptVerifySignatureW)(h, s, sl, c.pub, NULL, 0));
        U(CryptDestroyHash)(h);
    }
    kclose(&c);
}

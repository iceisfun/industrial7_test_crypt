#include "dxc.h"
/* Persisted key pairs in a named container: CryptGenKey / CryptGetUserKey / CryptExportKey /
 * CryptImportKey / CryptSetProvParam(PP_DELETEKEY), and that keys survive release + reacquire.
 * Pinned from rsaenh CPGenKey (flag mask 0x1fe8 -> NTE_BAD_FLAGS, unsupported algid ->
 * NTE_BAD_ALGID), CPGetUserKey (keyspec other than 1/2 -> NTE_BAD_KEY, missing -> NTE_NO_KEY),
 * CPExportKey (non-exportable private blob -> NTE_BAD_KEY_STATE). */

static int pub_blob(HCRYPTKEY k, BYTE *out, DWORD cap) { return dxc_export(k, 0, PUBLICKEYBLOB, 0, out, cap); }

static int magic_of(const BYTE *b) { return *(const DWORD *)(b + sizeof(BLOBHEADER)); }

static BOOL gen(HCRYPTPROV h, DWORD spec, DWORD flags, HCRYPTKEY *k) {
    return U(CryptGenKey)(h, spec, flags, k);
}
static BOOL getk(HCRYPTPROV h, DWORD spec, HCRYPTKEY *k) { return U(CryptGetUserKey)(h, spec, k); }
static void destroy(HCRYPTKEY k) { if (k) U(CryptDestroyKey)(k); }

/* ------------------------------------------------------------------- generation + persistence */
static void k_sig_persist(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("ksig"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0, k2 = 0;
    BYTE b1[1200], b2[1200];
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    BOOL ok = gen(h, AT_SIGNATURE, 0, &k);
    CHECKF(ok, "GenKey err 0x%lx", GetLastError());
    if (!ok) { dxc_rel(h); dxc_del(c, pi, 0); return; }
    CHECK(k != 0);
    int n1 = pub_blob(k, b1, sizeof b1);
    CHECK(n1 > (int)(sizeof(BLOBHEADER) + 8));
    if (n1 > 0) {
        BLOBHEADER *bh = (BLOBHEADER *)b1;
        EXPECT_EQ(bh->bType, PUBLICKEYBLOB);
        EXPECT_EQ(bh->bVersion, 2);
        if (dxc_provs[pi].dss) { EXPECT_EQ(bh->aiKeyAlg, CALG_DSS_SIGN); EXPECT_EQ(magic_of(b1), 0x31535344); }
        else { EXPECT_EQ(bh->aiKeyAlg, CALG_RSA_SIGN); EXPECT_EQ(magic_of(b1), 0x31415352); }
    }
    destroy(k);
    dxc_rel(h);
    /* new context, same container: the same public key comes back */
    h = 0;
    CHECK(dxc_acq(&h, c, pi, 0));
    ok = getk(h, AT_SIGNATURE, &k2);
    CHECKF(ok, "GetUserKey err 0x%lx", GetLastError());
    if (ok) {
        int n2 = pub_blob(k2, b2, sizeof b2);
        EXPECT_EQ(n2, n1);
        CHECK(n1 > 0 && n2 == n1 && !memcmp(b1, b2, n1));
        destroy(k2);
    }
    dxc_rel(h);
    /* ... and still after deleting nothing: a third open sees it too */
    h = 0; k2 = 0;
    CHECK(dxc_acq(&h, c, pi, 0));
    CHECK(getk(h, AT_SIGNATURE, &k2));
    destroy(k2); dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_gen_signature_persists, k_sig_persist)

static void k_keyx_persist(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kkx"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0, k2 = 0;
    BYTE b1[1200], b2[1200];
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    BOOL ok = gen(h, AT_KEYEXCHANGE, 0, &k);
    CHECKF(ok, "GenKey err 0x%lx", GetLastError());
    if (!ok) { dxc_rel(h); dxc_del(c, pi, 0); return; }
    int n1 = pub_blob(k, b1, sizeof b1);
    CHECK(n1 > 0);
    if (n1 > 0) {
        BLOBHEADER *bh = (BLOBHEADER *)b1;
        EXPECT_EQ(bh->bType, PUBLICKEYBLOB);
        EXPECT_EQ(bh->aiKeyAlg, CALG_RSA_KEYX);
        EXPECT_EQ(magic_of(b1), 0x31415352);
    }
    destroy(k); dxc_rel(h); h = 0;
    CHECK(dxc_acq(&h, c, pi, 0));
    ok = getk(h, AT_KEYEXCHANGE, &k2);
    CHECKF(ok, "GetUserKey err 0x%lx", GetLastError());
    if (ok) {
        int n2 = pub_blob(k2, b2, sizeof b2);
        CHECK(n1 > 0 && n2 == n1 && !memcmp(b1, b2, n1));
        destroy(k2);
    }
    /* the signature slot stays empty */
    HCRYPTKEY ks = 0; SET_ERR(0);
    CHECK(!getk(h, AT_SIGNATURE, &ks)); EXPECT_ERR(X_NTE_NO_KEY);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_keys_gen_keyexchange_persists, k_keyx_persist)

static void k_both(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kbo"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY ks = 0, kx = 0, a = 0, b = 0;
    BYTE bs[1200], bx[1200];
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h, AT_SIGNATURE, 0, &ks));
    CHECK(gen(h, AT_KEYEXCHANGE, 0, &kx));
    destroy(ks); destroy(kx); dxc_rel(h); h = 0;
    CHECK(dxc_acq(&h, c, pi, 0));
    CHECK(getk(h, AT_SIGNATURE, &a));
    CHECK(getk(h, AT_KEYEXCHANGE, &b));
    int ns = pub_blob(a, bs, sizeof bs), nx = pub_blob(b, bx, sizeof bx);
    CHECK(ns > 0 && nx > 0);
    CHECK(((BLOBHEADER *)bs)->aiKeyAlg == CALG_RSA_SIGN && ((BLOBHEADER *)bx)->aiKeyAlg == CALG_RSA_KEYX);
    CHECK(ns != nx || memcmp(bs, bx, ns) != 0);
    destroy(a); destroy(b); dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_keys_both_specs_coexist, k_both)

static void k_regen(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("krg"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k1 = 0, k2 = 0, k3 = 0;
    BYTE b1[1200], b2[1200], b3[1200];
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h, AT_SIGNATURE, 0, &k1));
    int n1 = pub_blob(k1, b1, sizeof b1);
    CHECK(gen(h, AT_SIGNATURE, 0, &k2));        /* replaces the stored signature key */
    int n2 = pub_blob(k2, b2, sizeof b2);
    CHECK(n1 > 0 && n2 > 0);
    CHECK(n1 != n2 || memcmp(b1, b2, n1) != 0);   /* new random key pair */
    destroy(k1); destroy(k2); dxc_rel(h); h = 0;
    CHECK(dxc_acq(&h, c, pi, 0));
    CHECK(getk(h, AT_SIGNATURE, &k3));
    int n3 = pub_blob(k3, b3, sizeof b3);
    CHECK(n3 == n2 && !memcmp(b2, b3, n2 > 0 ? n2 : 0));
    destroy(k3); dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_regenerate_replaces_stored, k_regen)

static void k_no_resurrect(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("knr"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h, AT_SIGNATURE, 0, &k)); destroy(k); dxc_rel(h);
    dxc_del(c, pi, 0);
    h = 0; k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));    /* same name, fresh and empty */
    SET_ERR(0);
    CHECK(!getk(h, AT_SIGNATURE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_deleted_container_has_no_keys, k_no_resurrect)

static void k_isolation(int pi) {
    DXC_NEED(pi);
    const char *c1 = dxc_name("ki1"), *c2 = dxc_name("ki2");
    dxc_del(c1, pi, 0); dxc_del(c2, pi, 0);
    HCRYPTPROV h1 = 0, h2 = 0; HCRYPTKEY k = 0, kk = 0;
    CHECK(dxc_acq(&h1, c1, pi, CRYPT_NEWKEYSET));
    CHECK(dxc_acq(&h2, c2, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h1, AT_SIGNATURE, 0, &k)); destroy(k);
    SET_ERR(0);
    CHECK(!getk(h2, AT_SIGNATURE, &kk)); EXPECT_ERR(X_NTE_NO_KEY);
    CHECK(getk(h1, AT_SIGNATURE, &kk)); destroy(kk);
    dxc_rel(h1); dxc_rel(h2);
    dxc_del(c1, pi, 0); dxc_del(c2, pi, 0);
}
DXC_PERPROV(dxc_keys_isolated_between_containers, k_isolation)

/* ------------------------------------------------------------------- GetUserKey errors */
static void k_getuserkey_empty(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kge"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0xdead;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    SET_ERR(0);
    CHECK(!getk(h, AT_SIGNATURE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
    if (!dxc_provs[pi].dss) {
        SET_ERR(0);
        CHECK(!getk(h, AT_KEYEXCHANGE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
    }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_getuserkey_empty_container, k_getuserkey_empty)

static void k_getuserkey_badspec(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kgb"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h, AT_SIGNATURE, 0, &k)); destroy(k);
    static const DWORD bad[] = { 0, 3, 4, 0x2400, 0xa400, 0x10000, 0xffffffff };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        k = 0; SET_ERR(0);
        BOOL ok = getk(h, bad[i], &k);
        CHECKF(!ok, "keyspec 0x%lx accepted", bad[i]);
        EXPECT_ERR(X_NTE_BAD_KEY);
        if (ok) destroy(k);
    }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_getuserkey_invalid_keyspec, k_getuserkey_badspec)

static void k_getuserkey_verify(int pi) {
    DXC_NEED(pi);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, NULL, pi, CRYPT_VERIFYCONTEXT));
    SET_ERR(0);
    CHECK(!getk(h, AT_SIGNATURE, &k)); EXPECT_ERR(X_NTE_NO_KEY);
    dxc_rel(h);
}
DXC_PERPROV(dxc_keys_getuserkey_verifycontext, k_getuserkey_verify)

/* ------------------------------------------------------------------- CryptGenKey flags */
static void k_gen_badflags(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kgf"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    static const DWORD bad[] = { 0x8, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000 };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        k = 0; SET_ERR(0);
        BOOL ok = gen(h, AT_SIGNATURE, bad[i], &k);
        CHECKF(!ok, "flags 0x%lx accepted", bad[i]);
        EXPECT_ERR(X_NTE_BAD_FLAGS);
        if (ok) destroy(k);
    }
    SET_ERR(0);
    CHECK(!getk(h, AT_SIGNATURE, &k)); EXPECT_ERR(X_NTE_NO_KEY);   /* nothing was stored */
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_gen_invalid_flags, k_gen_badflags)

TEST(dxc_keys_gen_keyx_on_dss_base) {
    int pi = 4;
    DXC_NEED(pi);
    const char *c = dxc_name("kdk"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    SET_ERR(0);
    BOOL ok = gen(h, AT_KEYEXCHANGE, 0, &k);
    CHECK(!ok); EXPECT_ERR(0x80090008UL);   /* NTE_BAD_ALGID */
    if (ok) destroy(k);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}

static void k_gen_unknown_spec(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kgu"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    SET_ERR(0);
    BOOL ok = gen(h, 0x7fffff, 0, &k);   /* not a keyspec, not an ALG_ID the provider knows */
    CHECK(!ok); EXPECT_ERR(0x80090008UL);
    if (ok) destroy(k);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_gen_unknown_algid, k_gen_unknown_spec)

static void k_gen_session_not_persisted(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("ksn"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    BOOL ok = gen(h, CALG_RC4, CRYPT_EXPORTABLE, &k);     /* session key: no container storage */
    if (!ok) { t_note("RC4 genkey err 0x%lx", GetLastError()); dxc_rel(h); dxc_del(c, pi, 0); return; }
    destroy(k);
    HCRYPTKEY u = 0; SET_ERR(0);
    CHECK(!getk(h, AT_SIGNATURE, &u)); EXPECT_ERR(X_NTE_NO_KEY);
    SET_ERR(0);
    if (!dxc_provs[pi].dss) { CHECK(!getk(h, AT_KEYEXCHANGE, &u)); EXPECT_ERR(X_NTE_NO_KEY); }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_keys_session_key_not_stored, k_gen_session_not_persisted)

static void k_param_alg_len(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kpl"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0, k2 = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h, AT_SIGNATURE, 0, &k));
    BYTE b[1200]; int n = pub_blob(k, b, sizeof b);
    DWORD bits = 0, sz = 4, alg = 0;
    CHECK(U(CryptGetKeyParam)(k, KP_KEYLEN, (BYTE *)&bits, &sz, 0));
    sz = 4;
    CHECK(U(CryptGetKeyParam)(k, KP_ALGID, (BYTE *)&alg, &sz, 0));
    EXPECT_EQ(alg, dxc_provs[pi].dss ? CALG_DSS_SIGN : CALG_RSA_SIGN);
    if (!dxc_provs[pi].dss && n > 0) EXPECT_EQ(((RSAPUBKEY *)(b + sizeof(BLOBHEADER)))->bitlen, bits);
    destroy(k); dxc_rel(h); h = 0;
    CHECK(dxc_acq(&h, c, pi, 0));
    CHECK(getk(h, AT_SIGNATURE, &k2));
    DWORD bits2 = 0; sz = 4;
    CHECK(U(CryptGetKeyParam)(k2, KP_KEYLEN, (BYTE *)&bits2, &sz, 0));
    EXPECT_EQ(bits2, bits);
    destroy(k2); dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_persisted_algid_and_length, k_param_alg_len)

/* ------------------------------------------------------------------- sign with a persisted key */
static void k_sign(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("ksn2"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0, v = 0; HCRYPTKEY k = 0, pub = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h, AT_SIGNATURE, 0, &k));
    BYTE blob[1200]; int bn = pub_blob(k, blob, sizeof blob);
    destroy(k); dxc_rel(h); h = 0;
    CHECK(dxc_acq(&h, c, pi, 0));            /* reacquire, sign with the stored key */
    HCRYPTHASH hh = 0;
    CHECK(U(CryptCreateHash)(h, CALG_SHA1, 0, 0, &hh));
    static const BYTE msg[] = "persisted key signature test";
    CHECK(U(CryptHashData)(hh, msg, sizeof msg - 1, 0));
    BYTE sig[600], sig2[600]; DWORD sl = sizeof sig, sl2 = sizeof sig2;
    BOOL ok = U(CryptSignHashA)(hh, AT_SIGNATURE, NULL, 0, sig, &sl);
    CHECKF(ok, "sign err 0x%lx", GetLastError());
    if (ok) {
        if (!dxc_provs[pi].dss) {
            CHECK(U(CryptSignHashA)(hh, AT_SIGNATURE, NULL, 0, sig2, &sl2));
            CHECK(sl == sl2 && !memcmp(sig, sig2, sl));   /* PKCS#1 v1.5 is deterministic */
        }
        /* verify in an unrelated verify-only context using only the exported public key */
        CHECK(dxc_acq(&v, NULL, pi, CRYPT_VERIFYCONTEXT));
        CHECK(bn > 0 && U(CryptImportKey)(v, blob, bn, 0, 0, &pub));
        HCRYPTHASH vh = 0;
        CHECK(U(CryptCreateHash)(v, CALG_SHA1, 0, 0, &vh));
        CHECK(U(CryptHashData)(vh, msg, sizeof msg - 1, 0));
        ok = U(CryptVerifySignatureA)(vh, sig, sl, pub, NULL, 0);
        CHECKF(ok, "verify err 0x%lx", GetLastError());
        U(CryptDestroyHash)(vh);
        /* different data fails */
        HCRYPTHASH vh2 = 0;
        CHECK(U(CryptCreateHash)(v, CALG_SHA1, 0, 0, &vh2));
        CHECK(U(CryptHashData)(vh2, msg, sizeof msg - 2, 0));
        SET_ERR(0);
        CHECK(!U(CryptVerifySignatureA)(vh2, sig, sl, pub, NULL, 0)); EXPECT_ERR(0x80090006UL); /* NTE_BAD_SIGNATURE */
        U(CryptDestroyHash)(vh2);
        destroy(pub); dxc_rel(v);
    }
    U(CryptDestroyHash)(hh);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_sign_with_reacquired_key, k_sign)

static void k_sign_no_key(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("ksnk"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTHASH hh = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(U(CryptCreateHash)(h, CALG_SHA1, 0, 0, &hh));
    CHECK(U(CryptHashData)(hh, (const BYTE *)"x", 1, 0));
    BYTE sig[600]; DWORD sl = sizeof sig;
    SET_ERR(0);
    CHECK(!U(CryptSignHashA)(hh, AT_SIGNATURE, NULL, 0, sig, &sl)); EXPECT_ERR(X_NTE_NO_KEY);
    U(CryptDestroyHash)(hh);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_sign_without_stored_key, k_sign_no_key)

/* ------------------------------------------------------------------- export / import */
static void k_export_public(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kex"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h, AT_SIGNATURE, 0, &k));
    DWORD need = 0;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, NULL, &need));
    CHECK(need > 12);
    BYTE buf[1200]; DWORD n = need - 1;
    SET_ERR(0);
    CHECK(!U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, buf, &n)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, need);
    n = need;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, buf, &n));
    EXPECT_EQ(n, need);
    n = sizeof buf;
    CHECK(U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, buf, &n));
    EXPECT_EQ(n, need);
    n = 0; SET_ERR(0);
    CHECK(!U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, buf, &n)); EXPECT_ERR(ERROR_MORE_DATA);
    /* an unknown blob type */
    n = sizeof buf; SET_ERR(0);
    CHECK(!U(CryptExportKey)(k, 0, 0x55, 0, buf, &n)); EXPECT_ERR(X_NTE_BAD_TYPE);
    destroy(k); dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_export_public_protocol, k_export_public)

static void k_nonexportable(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kne"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0, k2 = 0;
    BYTE buf[2400]; DWORD n;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h, AT_SIGNATURE, 0, &k));
    n = sizeof buf; SET_ERR(0);
    CHECK(!U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, buf, &n)); EXPECT_ERR(X_NTE_BAD_KEY_STATE);
    n = 0; SET_ERR(0);
    CHECK(!U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, NULL, &n));
    EXPECT_ERR(X_NTE_BAD_KEY_STATE);
    CHECK(pub_blob(k, buf, sizeof buf) > 0);    /* public part is always exportable */
    destroy(k); dxc_rel(h); h = 0;
    /* the restriction is stored with the key */
    CHECK(dxc_acq(&h, c, pi, 0));
    CHECK(getk(h, AT_SIGNATURE, &k2));
    n = sizeof buf; SET_ERR(0);
    CHECK(!U(CryptExportKey)(k2, 0, PRIVATEKEYBLOB, 0, buf, &n)); EXPECT_ERR(X_NTE_BAD_KEY_STATE);
    destroy(k2); dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_nonexportable_private_denied, k_nonexportable)

static void k_exportable(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kxp"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0, k2 = 0;
    static BYTE priv[3000], pub1[1200], pub2[1200];
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    BOOL ok = gen(h, AT_SIGNATURE, CRYPT_EXPORTABLE, &k);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (!ok) { dxc_rel(h); dxc_del(c, pi, 0); return; }
    int np = dxc_export(k, 0, PRIVATEKEYBLOB, 0, priv, sizeof priv);
    CHECKF(np > 0, "private export err 0x%lx", GetLastError());
    int nb = pub_blob(k, pub1, sizeof pub1);
    if (np > 0) {
        BLOBHEADER *bh = (BLOBHEADER *)priv;
        EXPECT_EQ(bh->bType, PRIVATEKEYBLOB);
        EXPECT_EQ(bh->bVersion, 2);
        CHECK(np > nb);
        if (dxc_provs[pi].dss) EXPECT_EQ(magic_of(priv), 0x32535344);   /* "DSS2" */
        else EXPECT_EQ(magic_of(priv), 0x32415352);                      /* "RSA2" */
    }
    destroy(k); dxc_rel(h); h = 0;
    CHECK(dxc_acq(&h, c, pi, 0));
    CHECK(getk(h, AT_SIGNATURE, &k2));
    int np2 = dxc_export(k2, 0, PRIVATEKEYBLOB, 0, priv + 1500, 1500);
    t_note("prov %d: persisted CRYPT_EXPORTABLE key re-export after reacquire: %d (err 0x%lx)", pi, np2, np2 < 0 ? GetLastError() : 0);
    destroy(k2); dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keys_exportable_private_blob, k_exportable)

static void k_import_into_container(int pi) {
    DXC_NEED(pi);
    const char *c1 = dxc_name("kim1"), *c2 = dxc_name("kim2");
    dxc_del(c1, pi, 0); dxc_del(c2, pi, 0);
    HCRYPTPROV h1 = 0, h2 = 0; HCRYPTKEY k = 0, ki = 0, kr = 0;
    static BYTE priv[3000], pa[1200], pb[1200], pc[1200];
    CHECK(dxc_acq(&h1, c1, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h1, AT_SIGNATURE, CRYPT_EXPORTABLE, &k));
    int np = dxc_export(k, 0, PRIVATEKEYBLOB, 0, priv, sizeof priv);
    int na = pub_blob(k, pa, sizeof pa);
    destroy(k); dxc_rel(h1);
    CHECK(np > 0);
    CHECK(dxc_acq(&h2, c2, pi, CRYPT_NEWKEYSET));
    BOOL ok = np > 0 && U(CryptImportKey)(h2, priv, np, 0, 0, &ki);
    CHECKF(ok, "import err 0x%lx", GetLastError());
    if (ok) {
        int nb = pub_blob(ki, pb, sizeof pb);
        CHECK(na > 0 && nb == na && !memcmp(pa, pb, na));
        /* the imported private key landed in the signature slot of the container */
        destroy(ki); dxc_rel(h2); h2 = 0;
        CHECK(dxc_acq(&h2, c2, pi, 0));
        CHECK(getk(h2, AT_SIGNATURE, &kr));
        int nc = pub_blob(kr, pc, sizeof pc);
        CHECK(nc == na && !memcmp(pa, pc, na > 0 ? na : 0));
        destroy(kr);
        /* imported without CRYPT_EXPORTABLE: private export is refused */
        BYTE tmp[2400]; DWORD tn = sizeof tmp; kr = 0;
        CHECK(getk(h2, AT_SIGNATURE, &kr));
        SET_ERR(0);
        CHECK(!U(CryptExportKey)(kr, 0, PRIVATEKEYBLOB, 0, tmp, &tn)); EXPECT_ERR(X_NTE_BAD_KEY_STATE);
        destroy(kr);
    }
    dxc_rel(h2);
    dxc_del(c1, pi, 0); dxc_del(c2, pi, 0);
}
DXC_PERPROV(dxc_keys_import_private_persists, k_import_into_container)

static void k_import_exportable_flag(int pi) {
    DXC_NEED(pi);
    const char *c1 = dxc_name("kie1"), *c2 = dxc_name("kie2");
    dxc_del(c1, pi, 0); dxc_del(c2, pi, 0);
    HCRYPTPROV h1 = 0, h2 = 0; HCRYPTKEY k = 0, ki = 0;
    static BYTE priv[3000], again[3000];
    CHECK(dxc_acq(&h1, c1, pi, CRYPT_NEWKEYSET));
    CHECK(gen(h1, AT_SIGNATURE, CRYPT_EXPORTABLE, &k));
    int np = dxc_export(k, 0, PRIVATEKEYBLOB, 0, priv, sizeof priv);
    destroy(k); dxc_rel(h1);
    CHECK(dxc_acq(&h2, c2, pi, CRYPT_NEWKEYSET));
    if (np > 0 && U(CryptImportKey)(h2, priv, np, 0, CRYPT_EXPORTABLE, &ki)) {
        int n2 = dxc_export(ki, 0, PRIVATEKEYBLOB, 0, again, sizeof again);
        CHECKF(n2 == np, "re-export %d vs %d err 0x%lx", n2, np, GetLastError());
        if (n2 == np) CHECK(!memcmp(priv, again, np));   /* private blob layout is deterministic */
        destroy(ki);
    } else CHECKF(0, "setup failed np=%d err 0x%lx", np, GetLastError());
    dxc_rel(h2);
    dxc_del(c1, pi, 0); dxc_del(c2, pi, 0);
}
DXC_PERPROV(dxc_keys_import_exportable_roundtrip, k_import_exportable_flag)

/* ------------------------------------------------------------------- PP_DELETEKEY */
static void k_ppdeletekey(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kdl"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    DWORD spec = AT_SIGNATURE;
    SET_ERR(0);
    /* empty slot: GetUserKey's failure is returned */
    CHECK(!U(CryptSetProvParam)(h, PP_DELETEKEY, (const BYTE *)&spec, 0)); EXPECT_ERR(X_NTE_NO_KEY);
    CHECK(gen(h, AT_SIGNATURE, 0, &k)); destroy(k);
    SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_DELETEKEY, (const BYTE *)&spec, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    spec = 3; SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_DELETEKEY, (const BYTE *)&spec, 0)); EXPECT_ERR(X_NTE_BAD_KEY);
    spec = AT_SIGNATURE;
    BOOL ok = U(CryptSetProvParam)(h, PP_DELETEKEY, (const BYTE *)&spec, 0);
    CHECKF(ok, "err 0x%lx", GetLastError());
    k = 0;
    ok = getk(h, AT_SIGNATURE, &k);
    t_note("prov %d: GetUserKey after PP_DELETEKEY ok=%d err 0x%lx", pi, ok, GetLastError());
    destroy(k);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_keys_pp_deletekey, k_ppdeletekey)

static void k_ppdeletekey_verify(int pi) {
    DXC_NEED(pi);
    HCRYPTPROV h = 0; DWORD spec = AT_SIGNATURE;
    CHECK(dxc_acq(&h, NULL, pi, CRYPT_VERIFYCONTEXT));
    SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_DELETEKEY, (const BYTE *)&spec, 0)); EXPECT_ERR(X_NTE_BAD_UID);
    dxc_rel(h);
}
DXC_PERRSA(dxc_keys_pp_deletekey_verifycontext, k_ppdeletekey_verify)

/* ------------------------------------------------------------------- key-size selection */
TEST(dxc_keys_rsa_aes_gen_2048_persists) {
    int pi = 3;
    DXC_NEED(pi);
    const char *c = dxc_name("k2k"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0, k2 = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    BOOL ok = gen(h, AT_KEYEXCHANGE, 2048u << 16, &k);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        DWORD bits = 0, sz = 4;
        CHECK(U(CryptGetKeyParam)(k, KP_KEYLEN, (BYTE *)&bits, &sz, 0));
        EXPECT_EQ(bits, 2048);
        destroy(k); dxc_rel(h); h = 0;
        CHECK(dxc_acq(&h, c, pi, 0));
        CHECK(getk(h, AT_KEYEXCHANGE, &k2));
        sz = 4; bits = 0;
        CHECK(U(CryptGetKeyParam)(k2, KP_KEYLEN, (BYTE *)&bits, &sz, 0));
        EXPECT_EQ(bits, 2048);
        destroy(k2);
    }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}

TEST(dxc_keys_base_provider_key_length_limits) {
    int pi = 0;
    DXC_NEED(pi);
    const char *c = dxc_name("kbl"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    /* Base provider: RSA keys 384..512 bits */
    SET_ERR(0);
    BOOL ok = gen(h, AT_SIGNATURE, 1024u << 16, &k);
    t_note("Base provider 1024-bit RSA: ok=%d err 0x%lx", ok, GetLastError());
    if (ok) destroy(k);
    ok = gen(h, AT_SIGNATURE, 512u << 16, &k);
    CHECKF(ok, "512-bit err 0x%lx", GetLastError());
    if (ok) {
        DWORD bits = 0, sz = 4;
        CHECK(U(CryptGetKeyParam)(k, KP_KEYLEN, (BYTE *)&bits, &sz, 0));
        EXPECT_EQ(bits, 512);
        destroy(k);
    }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}

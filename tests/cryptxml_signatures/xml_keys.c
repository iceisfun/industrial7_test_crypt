/* cryptxml.dll: CryptXmlImportPublicKey and public-key signing through CNG keys. */
#include "xml.h"
#include <stdlib.h>
#include <ncrypt.h>

#define ECC_P256 L"urn:oid:1.2.840.10045.3.1.7"
#define ECC_P384 L"urn:oid:1.3.132.0.34"
#define ECC_P521 L"urn:oid:1.3.132.0.35"

static void rsa_kv(XKEYVALUE *kv, const BYTE *mod, ULONG nm, const BYTE *e, ULONG ne)
{
    memset(kv, 0, sizeof *kv);
    kv->dwType = 2;
    kv->u.RSA.Modulus.cbData = nm; kv->u.RSA.Modulus.pbData = (BYTE *)mod;
    kv->u.RSA.Exponent.cbData = ne; kv->u.RSA.Exponent.pbData = (BYTE *)e;
}
static void ec_kv(XKEYVALUE *kv, const WCHAR *curve, const BYTE *x, ULONG nx, const BYTE *y, ULONG ny)
{
    memset(kv, 0, sizeof *kv);
    kv->dwType = 3;
    kv->u.EC.wszNamedCurve = curve;
    kv->u.EC.X.cbData = nx; kv->u.EC.X.pbData = (BYTE *)x;
    kv->u.EC.Y.cbData = ny; kv->u.EC.Y.pbData = (BYTE *)y;
}
static void dsa_kv(XKEYVALUE *kv)
{
    memset(kv, 0, sizeof *kv);
    kv->dwType = 1;
    kv->u.DSA.P.cbData = X_DSA_P_len; kv->u.DSA.P.pbData = (BYTE *)X_DSA_P;
    kv->u.DSA.Q.cbData = X_DSA_Q_len; kv->u.DSA.Q.pbData = (BYTE *)X_DSA_Q;
    kv->u.DSA.G.cbData = X_DSA_G_len; kv->u.DSA.G.pbData = (BYTE *)X_DSA_G;
    kv->u.DSA.Y.cbData = X_DSA_Y_len; kv->u.DSA.Y.pbData = (BYTE *)X_DSA_Y;
}
static void destroy(void *k) { if (k && U(BCryptDestroyKey)) U(BCryptDestroyKey)(k); }

static BYTE *export_blob(void *key, const WCHAR *type, ULONG *cb)
{
    ULONG n = 0;
    BYTE *b;
    *cb = 0;
    if (!U(BCryptExportKey)) return NULL;
    if (U(BCryptExportKey)(key, NULL, type, NULL, 0, &n, 0) < 0 || !n) return NULL;
    b = malloc(n);
    if (U(BCryptExportKey)(key, NULL, type, b, n, &n, 0) < 0) { free(b); return NULL; }
    *cb = n;
    return b;
}

/* ---- argument handling --------------------------------------------------------------------------- */
TEST(xmlsig_import_null_arguments)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    XKEYVALUE kv;
    void *key = (void *)(ULONG_PTR)0xdeadbeef;
    rsa_kv(&kv, X_RSA1_MOD, X_RSA1_MOD_len, X_RSA_EXP, 3);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, NULL, &key), X_E_INVALIDARG);
    EXPECT_EQ(key, 0xdeadbeef);                                    /* untouched on this path */
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, NULL, NULL), X_E_INVALIDARG);
}

TEST(xmlsig_import_unknown_key_value_types)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    DWORD types[] = { 0, 4, 5, 99, 0xffffffff };
    for (int i = 0; i < 5; i++) {
        XKEYVALUE kv;
        void *key = (void *)(ULONG_PTR)0xdeadbeef;
        rsa_kv(&kv, X_RSA1_MOD, X_RSA1_MOD_len, X_RSA_EXP, 3);
        kv.dwType = types[i];
        HRESULT hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
        CHECKF(hr == X_E_NOTIMPL_ALGO, "type %lu hr=0x%08lx", types[i], (unsigned long)hr);
        CHECK(key == NULL);
    }
}

/* ---- RSA ------------------------------------------------------------------------------------------------ */
TEST(xmlsig_import_rsa_blob_roundtrip)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    XKEYVALUE kv;
    void *key = NULL;
    rsa_kv(&kv, X_RSA1_MOD, X_RSA1_MOD_len, X_RSA_EXP, 3);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &key), S_OK);
    CHECK(key != NULL);
    ULONG cb;
    BYTE *b = key ? export_blob(key, BCRYPT_RSAPUBLIC_BLOB, &cb) : NULL;
    if (!b) { t_skip("BCryptExportKey unavailable"); destroy(key); return; }
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)b;
    EXPECT_EQ(h->Magic, BCRYPT_RSAPUBLIC_MAGIC);
    EXPECT_EQ(h->BitLength, 2048);
    EXPECT_EQ(h->cbPublicExp, 3);
    EXPECT_EQ(h->cbModulus, 256);
    EXPECT_EQ(h->cbPrime1, 0);
    if (cb == sizeof *h + 3 + 256) {
        CHECK(!memcmp(b + sizeof *h, X_RSA_EXP, 3));
        CHECK(!memcmp(b + sizeof *h + 3, X_RSA1_MOD, 256));
    } else CHECKF(0, "blob size %lu", cb);
    free(b);
    destroy(key);
}

TEST(xmlsig_import_rsa_key_verifies_known_signature)
{
    REQUIRE(XFN(CryptXmlImportPublicKey)); REQUIRE(U(BCryptVerifySignature));
    XKEYVALUE kv;
    void *key = NULL;
    BYTE h[32]; ULONG hl;
    rsa_kv(&kv, X_RSA1_MOD, X_RSA1_MOD_len, X_RSA_EXP, 3);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &key), S_OK);
    if (!key) return;
    if (!x_hash(L"SHA256", NULL, 0, X_R256_canon, X_R256_canon_len, h, &hl)) { t_skip("hash"); destroy(key); return; }
    BCRYPT_PKCS1_PADDING_INFO pad = { BCRYPT_SHA256_ALGORITHM };
    NTSTATUS st = U(BCryptVerifySignature)(key, &pad, h, 32, (PUCHAR)X_R256_sig, X_R256_sig_len, BCRYPT_PAD_PKCS1);
    CHECKF(st == 0, "BCryptVerifySignature 0x%08lx", (unsigned long)st);
    h[0] ^= 1;
    st = U(BCryptVerifySignature)(key, &pad, h, 32, (PUCHAR)X_R256_sig, X_R256_sig_len, BCRYPT_PAD_PKCS1);
    CHECK(st != 0);
    destroy(key);
}

TEST(xmlsig_import_rsa_short_exponent)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    static const BYTE e3[1] = { 3 };
    XKEYVALUE kv;
    void *key = NULL;
    rsa_kv(&kv, X_RSA1_MOD, X_RSA1_MOD_len, e3, 1);
    HRESULT hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
    t_note("RSA exponent 3 -> 0x%08lx", (unsigned long)hr);
    if (hr == S_OK) {
        ULONG cb; BYTE *b = export_blob(key, BCRYPT_RSAPUBLIC_BLOB, &cb);
        if (b) { EXPECT_EQ(((BCRYPT_RSAKEY_BLOB *)b)->cbPublicExp, 1); free(b); }
    }
    destroy(key);
}

TEST(xmlsig_import_rsa_unusable_values_map_to_invalid_keyvalue)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    static const BYTE small[3] = { 1, 2, 3 };
    XKEYVALUE kv;
    void *key = (void *)(ULONG_PTR)0xdeadbeef;
    HRESULT hr;
    rsa_kv(&kv, small, 3, X_RSA_EXP, 3);
    hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
    CHECKF(hr == X_E_INVALID_KEYVALUE || hr == S_OK, "3-byte modulus hr=0x%08lx", (unsigned long)hr);
    t_note("3-byte modulus -> 0x%08lx", (unsigned long)hr);
    if (hr == X_E_INVALID_KEYVALUE) CHECK(key == NULL); else destroy(key);
    key = NULL;
    rsa_kv(&kv, X_RSA1_MOD, X_RSA1_MOD_len, X_RSA_EXP, 0);
    kv.u.RSA.Exponent.pbData = NULL;
    hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
    t_note("empty exponent -> 0x%08lx", (unsigned long)hr);
    CHECK(hr == X_E_INVALID_KEYVALUE || hr == S_OK);
    if (hr == S_OK) destroy(key);
    key = NULL;
    rsa_kv(&kv, X_RSA1_MOD, 0, X_RSA_EXP, 3);
    kv.u.RSA.Modulus.pbData = NULL;
    hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
    t_note("empty modulus -> 0x%08lx", (unsigned long)hr);
    CHECK(hr == X_E_INVALID_KEYVALUE || hr == S_OK);
    if (hr == S_OK) destroy(key);
}

TEST(xmlsig_import_flags_accepted)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    DWORD fl[] = { 0, X_FLAG_DISABLE_EXT, X_FLAG_NO_SERIALIZE };
    for (int i = 0; i < 3; i++) {
        XKEYVALUE kv; void *key = NULL;
        rsa_kv(&kv, X_RSA1_MOD, X_RSA1_MOD_len, X_RSA_EXP, 3);
        HRESULT hr = XFN(CryptXmlImportPublicKey)(fl[i], &kv, &key);
        CHECKF(hr == S_OK, "flags 0x%08lx hr=0x%08lx", (unsigned long)fl[i], (unsigned long)hr);
        destroy(key);
    }
}

TEST(xmlsig_import_returns_independent_handles)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    XKEYVALUE kv; void *a = NULL, *b = NULL;
    rsa_kv(&kv, X_RSA1_MOD, X_RSA1_MOD_len, X_RSA_EXP, 3);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &a), S_OK);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &b), S_OK);
    CHECK(a && b && a != b);
    destroy(a);
    ULONG cb; BYTE *blob = export_blob(b, BCRYPT_RSAPUBLIC_BLOB, &cb);       /* b is unaffected by destroying a */
    CHECK(blob != NULL);
    free(blob);
    destroy(b);
}

/* ---- DSA -------------------------------------------------------------------------------------------------- */
TEST(xmlsig_import_dsa_key_verifies_known_signature)
{
    REQUIRE(XFN(CryptXmlImportPublicKey)); REQUIRE(U(BCryptVerifySignature));
    XKEYVALUE kv; void *key = NULL;
    BYTE h[20]; ULONG hl;
    dsa_kv(&kv);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &key), S_OK);
    if (!key) return;
    ULONG cb; BYTE *b = export_blob(key, BCRYPT_DSA_PUBLIC_BLOB, &cb);
    if (b) { EXPECT_EQ(((BCRYPT_DSA_KEY_BLOB *)b)->dwMagic, BCRYPT_DSA_PUBLIC_MAGIC); EXPECT_EQ(((BCRYPT_DSA_KEY_BLOB *)b)->cbKey, 128); free(b); }
    if (x_hash(L"SHA1", NULL, 0, X_D1_canon, X_D1_canon_len, h, &hl)) {
        NTSTATUS st = U(BCryptVerifySignature)(key, NULL, h, 20, (PUCHAR)X_D1_sig, X_D1_sig_len, 0);
        CHECKF(st == 0, "BCryptVerifySignature 0x%08lx", (unsigned long)st);
    }
    destroy(key);
}

TEST(xmlsig_import_dsa_invalid_component_sizes)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    static BYTE big[200];
    memset(big, 0x11, sizeof big);
    struct { const char *what; int which; } t[] = { {"Y empty", 0}, {"Y longer than P", 1}, {"G longer than P", 2},
                                                    {"Counter > 4 bytes", 3}, {"Seed > 20 bytes", 4}, {"Q > 20 bytes", 5} };
    for (int i = 0; i < 6; i++) {
        XKEYVALUE kv; void *key = (void *)(ULONG_PTR)0xdeadbeef;
        dsa_kv(&kv);
        switch (t[i].which) {
        case 0: kv.u.DSA.Y.cbData = 0; break;
        case 1: kv.u.DSA.Y.cbData = 129; kv.u.DSA.Y.pbData = big; break;
        case 2: kv.u.DSA.G.cbData = 129; kv.u.DSA.G.pbData = big; break;
        case 3: kv.u.DSA.Counter.cbData = 5; kv.u.DSA.Counter.pbData = big; break;
        case 4: kv.u.DSA.Seed.cbData = 21; kv.u.DSA.Seed.pbData = big; break;
        case 5: kv.u.DSA.Q.cbData = 21; kv.u.DSA.Q.pbData = big; break;
        }
        HRESULT hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
        CHECKF(hr == X_E_INVALID_KEYVALUE, "%s: hr=0x%08lx", t[i].what, (unsigned long)hr);
        CHECKF(key == NULL, "%s: handle %p", t[i].what, key);
    }
}

TEST(xmlsig_import_dsa_with_seed_and_counter)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    static const BYTE seed[20] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 };
    static const BYTE ctr[4] = { 0, 0, 0, 0x2a };
    XKEYVALUE kv; void *key = NULL;
    dsa_kv(&kv);
    kv.u.DSA.Seed.cbData = 20; kv.u.DSA.Seed.pbData = (BYTE *)seed;
    kv.u.DSA.Counter.cbData = 4; kv.u.DSA.Counter.pbData = (BYTE *)ctr;
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &key), S_OK);
    if (key) {
        ULONG cb; BYTE *b = export_blob(key, BCRYPT_DSA_PUBLIC_BLOB, &cb);
        if (b) {
            BCRYPT_DSA_KEY_BLOB *h = (BCRYPT_DSA_KEY_BLOB *)b;
            CHECK(!memcmp(h->Count, ctr, 4));                         /* counter and seed travel into the blob */
            CHECK(!memcmp(h->Seed, seed, 20));
            free(b);
        }
        destroy(key);
    }
}

/* ---- ECDSA ------------------------------------------------------------------------------------------------ */
typedef struct { const WCHAR *curve; const BYTE *x, *y; ULONG n; DWORD magic; const BYTE *canon; ULONG canonLen; const BYTE *sig; ULONG sigLen; const WCHAR *hash; ULONG hashLen; } ECV;
static const ECV ECS[] = {
    { ECC_P256, X_E256_X, X_E256_Y, 32, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, X_E256_canon, X_E256_canon_len, X_E256_sig, X_E256_sig_len, L"SHA256", 32 },
    { ECC_P384, X_E384_X, X_E384_Y, 48, BCRYPT_ECDSA_PUBLIC_P384_MAGIC, X_E384_canon, X_E384_canon_len, X_E384_sig, X_E384_sig_len, L"SHA384", 48 },
    { ECC_P521, X_E521_X, X_E521_Y, 66, BCRYPT_ECDSA_PUBLIC_P521_MAGIC, X_E521_canon, X_E521_canon_len, X_E521_sig, X_E521_sig_len, L"SHA512", 64 },
};

static void ec_import_checks(const ECV *e)
{
    XKEYVALUE kv; void *key = NULL;
    ec_kv(&kv, e->curve, e->x, e->n, e->y, e->n);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &key), S_OK);
    if (!key) return;
    ULONG cb; BYTE *b = export_blob(key, BCRYPT_ECCPUBLIC_BLOB, &cb);
    if (b) {
        BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)b;
        EXPECT_EQ(h->dwMagic, e->magic);
        EXPECT_EQ(h->cbKey, e->n);
        if (cb == sizeof *h + 2 * e->n) {
            CHECK(!memcmp(b + sizeof *h, e->x, e->n));
            CHECK(!memcmp(b + sizeof *h + e->n, e->y, e->n));
        } else CHECKF(0, "blob size %lu", cb);
        free(b);
    }
    BYTE h[64]; ULONG hl;
    if (U(BCryptVerifySignature) && x_hash(e->hash, NULL, 0, e->canon, e->canonLen, h, &hl)) {
        NTSTATUS st = U(BCryptVerifySignature)(key, NULL, h, hl, (PUCHAR)e->sig, e->sigLen, 0);
        CHECKF(st == 0, "BCryptVerifySignature 0x%08lx", (unsigned long)st);
    }
    destroy(key);
}
TEST(xmlsig_import_ecdsa_p256) { REQUIRE(XFN(CryptXmlImportPublicKey)); ec_import_checks(&ECS[0]); }
TEST(xmlsig_import_ecdsa_p384) { REQUIRE(XFN(CryptXmlImportPublicKey)); ec_import_checks(&ECS[1]); }
TEST(xmlsig_import_ecdsa_p521) { REQUIRE(XFN(CryptXmlImportPublicKey)); ec_import_checks(&ECS[2]); }

TEST(xmlsig_import_ecdsa_curve_name_is_case_insensitive)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    XKEYVALUE kv; void *key = NULL;
    ec_kv(&kv, L"URN:OID:1.2.840.10045.3.1.7", X_E256_X, 32, X_E256_Y, 32);
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &key), S_OK);
    destroy(key);
}

TEST(xmlsig_import_ecdsa_unsupported_curves)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    const WCHAR *bad[] = { L"urn:oid:1.2.3.4", L"", L"secp256r1", L"urn:oid:1.3.132.0.33", L"1.2.840.10045.3.1.7", L" urn:oid:1.2.840.10045.3.1.7" };
    for (int i = 0; i < 6; i++) {
        XKEYVALUE kv; void *key = (void *)(ULONG_PTR)0xdeadbeef;
        ec_kv(&kv, bad[i], X_E256_X, 32, X_E256_Y, 32);
        HRESULT hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
        CHECKF(hr == X_E_NOTIMPL_ALGO, "curve '%ls' hr=0x%08lx", bad[i], (unsigned long)hr);
        CHECK(key == NULL);
    }
}

TEST(xmlsig_import_ecdsa_explicit_parameters_not_supported)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    static BYTE para[4] = { 1, 2, 3, 4 };
    XKEYVALUE kv; void *key = NULL;
    ec_kv(&kv, ECC_P256, X_E256_X, 32, X_E256_Y, 32);
    kv.u.EC.ExplicitPara.cbData = 4; kv.u.EC.ExplicitPara.pbData = para;
    XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &key), X_E_NOTIMPL_ALGO);
}

TEST(xmlsig_import_ecdsa_oversized_coordinates)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    static BYTE big[80];
    memset(big, 0x22, sizeof big);
    struct { const WCHAR *c; ULONG over; } t[] = { { ECC_P256, 33 }, { ECC_P384, 49 }, { ECC_P521, 67 } };
    for (int i = 0; i < 3; i++) for (int which = 0; which < 2; which++) {
        XKEYVALUE kv; void *key = (void *)(ULONG_PTR)0xdeadbeef;
        ec_kv(&kv, t[i].c, ECS[i].x, ECS[i].n, ECS[i].y, ECS[i].n);
        if (which) { kv.u.EC.Y.cbData = t[i].over; kv.u.EC.Y.pbData = big; } else { kv.u.EC.X.cbData = t[i].over; kv.u.EC.X.pbData = big; }
        HRESULT hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
        CHECKF(hr == X_E_INVALID_KEYVALUE, "curve %d coordinate %d hr=0x%08lx", i, which, (unsigned long)hr);
        CHECK(key == NULL);
    }
}

TEST(xmlsig_import_ecdsa_point_not_on_curve)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    BYTE y[32];
    memcpy(y, X_E256_Y, 32);
    y[31] ^= 0x01;                                    /* (x, y') is not a point of the curve */
    XKEYVALUE kv; void *key = NULL;
    ec_kv(&kv, ECC_P256, X_E256_X, 32, y, 32);
    HRESULT hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
    CHECKF(hr == X_E_INVALID_KEYVALUE, "hr=0x%08lx", (unsigned long)hr);
    CHECK(key == NULL);
    destroy(key);
}

TEST(xmlsig_import_ecdsa_short_coordinates_are_right_aligned)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    /* a coordinate with fewer bytes than the curve size is zero-extended on the left; with a different value the
     * resulting point is (almost surely) not on the curve and the import is refused */
    XKEYVALUE kv; void *key = (void *)(ULONG_PTR)0xdeadbeef;
    ec_kv(&kv, ECC_P256, X_E256_X + 1, 31, X_E256_Y, 32);
    HRESULT hr = XFN(CryptXmlImportPublicKey)(0, &kv, &key);
    t_note("31-byte X (leading byte dropped) -> 0x%08lx", (unsigned long)hr);
    if (X_E256_X[0] != 0) CHECK(hr == X_E_INVALID_KEYVALUE);
    if (hr == S_OK) destroy(key);
}

/* ---- signing with a CNG key ---------------------------------------------------------------------------------- */
static NCRYPT_KEY_HANDLE make_key(const WCHAR *alg, DWORD bits)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (!U(NCryptOpenStorageProvider) || U(NCryptOpenStorageProvider)(&prov, MS_KEY_STORAGE_PROVIDER, 0) != 0) return 0;
    /* ephemeral: no key name, nothing is persisted */
    if (U(NCryptCreatePersistedKey)(prov, &key, alg, NULL, 0, 0) != 0) { U(NCryptFreeObject)(prov); return 0; }
    if (bits) U(NCryptSetProperty)(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0);
    if (U(NCryptFinalizeKey)(key, NCRYPT_SILENT_FLAG) != 0) { U(NCryptFreeObject)(key); U(NCryptFreeObject)(prov); return 0; }
    U(NCryptFreeObject)(prov);
    return key;
}

static void sign_with_cng_key(const WCHAR *alg, DWORD bits, const WCHAR *sigmeth, const WCHAR *digmeth, const WCHAR *bcHash,
                              ULONG sigLenWant, DWORD kvType)
{
    NCRYPT_KEY_HANDLE nk = make_key(alg, bits);
    if (!nk) { t_skip("cannot create an ephemeral CNG key for %ls", alg); return; }
    HCX hs = NULL, hr = NULL;
    XALG dig = { sizeof dig, digmeth, {0, 0, NULL} }, sm = { sizeof sm, sigmeth, {0, 0, NULL} }, cn = { sizeof cn, U_C14N, {0, 0, NULL} };
    XMEM m; XPROV pv;
    XBUF b;
    memset(&b, 0, sizeof b);
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"ksig", NULL, 0, NULL, &hs), S_OK);
    if (hs) XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"kref", L"urn:cryptt:data", NULL, &dig, 0, NULL, &hr), S_OK);
    if (hr) { x_prov(&pv, &m, "abc", 3, 0); XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK); }
    if (!hs || !hr) { U(NCryptFreeObject)(nk); if (hs) XFN(CryptXmlClose)(hs); return; }
    XCHK_HR(XFN(CryptXmlSign)(hs, nk, X_NCRYPT_KEY_SPEC, X_SIGN_ADD_KEYVALUE, X_KEYINFO_NONE, NULL, &sm, &cn), S_OK);
    XCHK_HR(XFN(CryptXmlEncode)(hs, X_CS_UTF8, NULL, 0, &b, x_write_cb), S_OK);
    const char *o = x_buf_str(&b);
    t_note("%ls signed document: %.500s", alg, o);
    CHECK(x_find(o, "<KeyInfo"));
    CHECK(x_find(o, "<KeyValue"));
    const XSIG *s = NULL;
    XCHK_HR(XFN(CryptXmlGetSignature)(hs, &s), S_OK);
    if (s) EXPECT_EQ(s->SignatureValue.cbData, sigLenWant);
    XSTATUS st; x_status(hs, &st);
    CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) != 0);
    /* decode our own output, take the public key from the KeyValue and verify */
    HCX hd = NULL;
    XCHK_HR(x_decode(o, NULL, 0, &hd), S_OK);
    const XSIG *ds = hd ? x_first_sig(hd) : NULL;
    if (ds && ds->pKeyInfo && ds->pKeyInfo->cKeyInfo >= 1) {
        EXPECT_EQ(ds->pKeyInfo->rgKeyInfo[0].dwType, 2);
        EXPECT_EQ(ds->pKeyInfo->rgKeyInfo[0].u.KeyValue.dwType, kvType);
        CHECK(ds->pKeyInfo->hVerifyKey != NULL);
        if (ds->pKeyInfo->hVerifyKey) {
            HRESULT v = XFN(CryptXmlVerifySignature)(ds->hSignature, ds->pKeyInfo->hVerifyKey, 0);
            CHECKF(v == S_OK, "verify of own signature: 0x%08lx", (unsigned long)v);
            /* the digest of the external reference is supplied now */
            x_prov(&pv, &m, "abc", 3, 0);
            XCHK_HR(XFN(CryptXmlDigestReference)(ds->SignedInfo.rgpReference[0]->hReference, 0, &pv), S_OK);
            x_status(ds->hSignature, &st);
            EXPECT_EQ(st.dwErrorStatus, 0);
            EXPECT_EQ(st.dwInfoStatus, XS_I_SIGNATURE_VALID | XS_I_DIGEST_VALID | XS_I_KEY_AVAILABLE);
        }
        /* a one-bit change in the signature value must break it */
        char *bad = NULL;
        { char *p = strstr(o, "<SignatureValue>"); if (p) { bad = _strdup(o); bad[p - o + 16] = bad[p - o + 16] == 'A' ? 'B' : 'A'; } }
        HCX hb = NULL;
        if (bad && x_decode(bad, NULL, 0, &hb) == S_OK) {
            const XSIG *bs = x_first_sig(hb);
            if (bs && bs->pKeyInfo && bs->pKeyInfo->hVerifyKey)
                XCHK_HR(XFN(CryptXmlVerifySignature)(bs->hSignature, bs->pKeyInfo->hVerifyKey, 0), X_E_VERIFY_FAILED);
            XFN(CryptXmlClose)(hb);
        }
        free(bad);
    } else CHECKF(0, "decoded signature has no key info");
    if (hd) XFN(CryptXmlClose)(hd);
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
    U(NCryptFreeObject)(nk);
}

TEST(xmlsig_sign_rsa_sha256_with_ephemeral_cng_key)
{
    REQUIRE(XFN(CryptXmlSign)); REQUIRE(U(NCryptCreatePersistedKey));
    if (t_is_wine()) { t_skip("CNG key storage not exercised under emulation"); return; }
    sign_with_cng_key(BCRYPT_RSA_ALGORITHM, 2048, U_RSA256, U_SHA256, L"SHA256", 256, 2);
}
TEST(xmlsig_sign_rsa_sha1_with_ephemeral_cng_key)
{
    REQUIRE(XFN(CryptXmlSign)); REQUIRE(U(NCryptCreatePersistedKey));
    if (t_is_wine()) { t_skip("CNG key storage not exercised under emulation"); return; }
    sign_with_cng_key(BCRYPT_RSA_ALGORITHM, 2048, U_RSA1, U_SHA1, L"SHA1", 256, 2);
}
TEST(xmlsig_sign_ecdsa_p256_with_ephemeral_cng_key)
{
    REQUIRE(XFN(CryptXmlSign)); REQUIRE(U(NCryptCreatePersistedKey));
    if (t_is_wine()) { t_skip("CNG key storage not exercised under emulation"); return; }
    sign_with_cng_key(BCRYPT_ECDSA_P256_ALGORITHM, 0, U_ECDSA256, U_SHA256, L"SHA256", 64, 3);
}
TEST(xmlsig_sign_ecdsa_p384_with_ephemeral_cng_key)
{
    REQUIRE(XFN(CryptXmlSign)); REQUIRE(U(NCryptCreatePersistedKey));
    if (t_is_wine()) { t_skip("CNG key storage not exercised under emulation"); return; }
    sign_with_cng_key(BCRYPT_ECDSA_P384_ALGORITHM, 0, U_ECDSA384, U_SHA384, L"SHA384", 96, 3);
}

TEST(xmlsig_sign_rsa_signature_is_deterministic)
{
    REQUIRE(XFN(CryptXmlSign)); REQUIRE(U(NCryptCreatePersistedKey));
    if (t_is_wine()) { t_skip("CNG key storage not exercised under emulation"); return; }
    NCRYPT_KEY_HANDLE nk = make_key(BCRYPT_RSA_ALGORITHM, 2048);
    if (!nk) { t_skip("cannot create an ephemeral RSA key"); return; }
    BYTE first[256]; int have = 0;
    for (int round = 0; round < 2; round++) {                 /* PKCS#1 v1.5 signing has no randomness */
        HCX hs = NULL, hr = NULL; XMEM m; XPROV pv;
        XALG dig = { sizeof dig, U_SHA256, {0, 0, NULL} }, sm = { sizeof sm, U_RSA256, {0, 0, NULL} }, cn = { sizeof cn, U_C14N, {0, 0, NULL} };
        XFN(CryptXmlOpenToEncode)(NULL, 0, L"s", NULL, 0, NULL, &hs);
        if (!hs) break;
        XFN(CryptXmlCreateReference)(hs, 0, L"r", L"urn:cryptt:data", NULL, &dig, 0, NULL, &hr);
        x_prov(&pv, &m, "abc", 3, 0);
        XFN(CryptXmlDigestReference)(hr, 0, &pv);
        XCHK_HR(XFN(CryptXmlSign)(hs, nk, X_NCRYPT_KEY_SPEC, 0, X_KEYINFO_NONE, NULL, &sm, &cn), S_OK);
        const XSIG *s = NULL;
        XFN(CryptXmlGetSignature)(hs, &s);
        if (s && s->SignatureValue.cbData == 256) {
            if (!have) { memcpy(first, s->SignatureValue.pbData, 256); have = 1; }
            else CHECK(!memcmp(first, s->SignatureValue.pbData, 256));
        } else CHECK(0);
        XFN(CryptXmlClose)(hs);
    }
    U(NCryptFreeObject)(nk);
}

TEST(xmlsig_sign_key_algorithm_must_match_method)
{
    REQUIRE(XFN(CryptXmlSign)); REQUIRE(U(NCryptCreatePersistedKey));
    if (t_is_wine()) { t_skip("CNG key storage not exercised under emulation"); return; }
    NCRYPT_KEY_HANDLE nk = make_key(BCRYPT_RSA_ALGORITHM, 2048);
    if (!nk) { t_skip("cannot create an ephemeral RSA key"); return; }
    const WCHAR *wrong[] = { U_ECDSA256, U_DSA1, U_HMAC256 };
    for (int i = 0; i < 3; i++) {
        HCX hs = NULL, hr = NULL; XMEM m; XPROV pv;
        XALG dig = { sizeof dig, U_SHA256, {0, 0, NULL} }, sm = { sizeof sm, wrong[i], {0, 0, NULL} }, cn = { sizeof cn, U_C14N, {0, 0, NULL} };
        XFN(CryptXmlOpenToEncode)(NULL, 0, L"s", NULL, 0, NULL, &hs);
        if (!hs) break;
        XFN(CryptXmlCreateReference)(hs, 0, L"r", L"urn:cryptt:data", NULL, &dig, 0, NULL, &hr);
        x_prov(&pv, &m, "abc", 3, 0);
        XFN(CryptXmlDigestReference)(hr, 0, &pv);
        HRESULT h = XFN(CryptXmlSign)(hs, nk, X_NCRYPT_KEY_SPEC, 0, X_KEYINFO_NONE, NULL, &sm, &cn);
        CHECKF(h == X_E_ALGORITHM, "RSA key with %ls: hr=0x%08lx", wrong[i], (unsigned long)h);
        XFN(CryptXmlClose)(hs);
    }
    U(NCryptFreeObject)(nk);
}

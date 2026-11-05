/* NCryptExportKey / NCryptImportKey on ephemeral keys (BCRYPT_*_BLOB, opaque, PKCS#8). */
#include "nc.h"

#define NC_BAD_TYPE 0x8009000Au
#define NC_BAD_KEY  0x80090003u
#define OIDW(s) L##s

static int find_bytes(const BYTE *h, size_t hl, const BYTE *n, size_t nl)
{
    if (nl > hl) return 0;
    for (size_t i = 0; i + nl <= hl; i++) if (!memcmp(h + i, n, nl)) return 1;
    return 0;
}
static const BYTE OID_RSA_ENC[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const BYTE OID_P12_3DES[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03 };
static const BYTE OID_EC_PUBKEY[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

/* export helper: size query then fetch; returns malloc'd buffer */
static BYTE *nc_exp(NCRYPT_KEY_HANDLE k, LPCWSTR type, DWORD *pcb, SECURITY_STATUS *ps)
{
    DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptExportKey)(k, 0, type, NULL, NULL, 0, &cb, 0);
    if (ps) *ps = s;
    if (s != 0 || !cb) return NULL;
    BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb + 8);
    s = U(NCryptExportKey)(k, 0, type, NULL, b, cb, &cb, 0);
    if (ps) *ps = s;
    if (s) { HeapFree(GetProcessHeap(), 0, b); return NULL; }
    *pcb = cb;
    return b;
}

/* ---------- argument validation ---------- */
TEST(ncblob_export_arg_validation) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "key");
    BYTE buf[200]; DWORD cb = 0;
    EXPECT_SS(U(NCryptExportKey)(k, 0, NULL, NULL, buf, sizeof buf, &cb, 0), NC_INVALID_PARAMETER);
    /* blob type is validated before the key handle */
    EXPECT_SS(U(NCryptExportKey)(0, 0, NULL, NULL, buf, sizeof buf, &cb, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptExportKey)(0, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptExportKey)(k, p, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_INVALID_HANDLE);
    EXPECT_SS_FAIL(U(NCryptExportKey)(k, 0, L"cryptt-no-such-blob", NULL, buf, sizeof buf, &cb, 0));
    EXPECT_SS_FAIL(U(NCryptExportKey)(k, 0, L"", NULL, buf, sizeof buf, &cb, 0));
    nc_free(k); nc_free(p);
}
TEST(ncblob_export_unfinalized_bad_key_state) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, NC_EXP_ALL, FALSE); NEED(k, "key");
    BYTE buf[200]; DWORD cb = 0;
    EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_BAD_KEY_STATE);
    EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_BAD_KEY_STATE);
    nc_free(k); nc_free(p);
}
TEST(ncblob_export_wrong_blob_type_for_algorithm) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE ec = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, NC_EXP_ALL, TRUE);
    NCRYPT_KEY_HANDLE rsa = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NC_EXP_ALL, TRUE);
    NEED(ec && rsa, "keys");
    BYTE buf[1024]; DWORD cb = 0;
    SECURITY_STATUS s;
    s = U(NCryptExportKey)(ec, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("EC key as RSAPUBLICBLOB -> 0x%08lx (documented NTE_BAD_TYPE)", (DWORD)s);
    s = U(NCryptExportKey)(rsa, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("RSA key as ECCPUBLICBLOB -> 0x%08lx", (DWORD)s);
    s = U(NCryptExportKey)(rsa, 0, BCRYPT_DH_PUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s);
    s = U(NCryptExportKey)(ec, 0, BCRYPT_DSA_PUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s);
    nc_free(ec); nc_free(rsa); nc_free(p);
}

/* ---------- public blobs ---------- */
typedef struct { const WCHAR *alg; DWORD pubmagic, privmagic, cbkey; } eccrow_t;
static const eccrow_t ECCS[] = {
    { L"ECDSA_P256", 0x31534345, 0x32534345, 32 }, { L"ECDSA_P384", 0x33534345, 0x34534345, 48 }, { L"ECDSA_P521", 0x35534345, 0x36534345, 66 },
    { L"ECDH_P256",  0x314B4345, 0x324B4345, 32 }, { L"ECDH_P384",  0x334B4345, 0x344B4345, 48 }, { L"ECDH_P521",  0x354B4345, 0x364B4345, 66 },
};
TEST(ncblob_export_ecc_public_layout) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 0; i < sizeof(ECCS) / sizeof(ECCS[0]); i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ECCS[i].alg, 0, 0, TRUE);
        CHECKF(k != 0, "%ls", ECCS[i].alg); if (!k) continue;
        DWORD cb = 0; SECURITY_STATUS s; BYTE *b = nc_exp(k, BCRYPT_ECCPUBLIC_BLOB, &cb, &s);
        CHECKF(b != NULL, "%ls export public 0x%08lx", ECCS[i].alg, (DWORD)s);
        if (b) {
            BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)b;
            EXPECT_EQ(cb, 8 + 2 * ECCS[i].cbkey);
            EXPECT_EQ(h->dwMagic, ECCS[i].pubmagic);
            EXPECT_EQ(h->cbKey, ECCS[i].cbkey);
            nc_hfree(b);
        }
        nc_free(k);
    }
    nc_free(p);
}
TEST(ncblob_export_generic_public_blob_equals_specific) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P384_ALGORITHM, 0, 0, TRUE), r = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0, TRUE);
    NEED(k && r, "keys");
    DWORD c1 = 0, c2 = 0; SECURITY_STATUS s1, s2;
    BYTE *a = nc_exp(k, BCRYPT_PUBLIC_KEY_BLOB, &c1, &s1), *b = nc_exp(k, BCRYPT_ECCPUBLIC_BLOB, &c2, &s2);
    CHECKF(a && b, "generic 0x%08lx specific 0x%08lx", (DWORD)s1, (DWORD)s2);
    if (a && b) { EXPECT_EQ(c1, c2); CHECK(c1 == c2 && !memcmp(a, b, c1)); }
    nc_hfree(a); nc_hfree(b);
    a = nc_exp(r, BCRYPT_PUBLIC_KEY_BLOB, &c1, &s1); b = nc_exp(r, BCRYPT_RSAPUBLIC_BLOB, &c2, &s2);
    CHECKF(a && b, "generic RSA 0x%08lx specific 0x%08lx", (DWORD)s1, (DWORD)s2);
    if (a && b) { EXPECT_EQ(c1, c2); CHECK(c1 == c2 && !memcmp(a, b, c1)); }
    nc_hfree(a); nc_hfree(b);
    nc_free(k); nc_free(r); nc_free(p);
}
TEST(ncblob_export_rsa_public_layout) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD bits[] = { 512, 1024, 2048 };
    for (size_t i = 0; i < 3; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, bits[i], 0, TRUE);
        CHECKF(k != 0, "RSA %lu", bits[i]); if (!k) continue;
        DWORD cb = 0; SECURITY_STATUS s; BYTE *b = nc_exp(k, BCRYPT_RSAPUBLIC_BLOB, &cb, &s);
        CHECK(b != NULL);
        if (b) {
            BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)b;
            EXPECT_EQ(h->Magic, BCRYPT_RSAPUBLIC_MAGIC);
            EXPECT_EQ(h->BitLength, bits[i]);
            EXPECT_EQ(h->cbPublicExp, 3);
            EXPECT_EQ(h->cbModulus, bits[i] / 8);
            EXPECT_EQ(h->cbPrime1, 0); EXPECT_EQ(h->cbPrime2, 0);
            EXPECT_EQ(cb, sizeof *h + 3 + bits[i] / 8);
            CHECK(b[sizeof *h] == 1 && b[sizeof *h + 1] == 0 && b[sizeof *h + 2] == 1);   /* e = 65537, big-endian */
            CHECK(b[sizeof *h + 3] & 0x80);                                               /* modulus has its top bit set */
            nc_hfree(b);
        }
        nc_free(k);
    }
    nc_free(p);
}
TEST(ncblob_export_public_always_allowed) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "non-exportable key");
    DWORD cb = 0; SECURITY_STATUS s; BYTE *b = nc_exp(k, BCRYPT_ECCPUBLIC_BLOB, &cb, &s);
    EXPECT_SS(s, 0); CHECK(b != NULL); nc_hfree(b);
    nc_free(k); nc_free(p);
}
TEST(ncblob_export_size_protocol) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "key");
    DWORD cb = 0xFFFF;
    EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, 72);
    BYTE buf[128]; memset(buf, 0xEE, sizeof buf);
    static const DWORD small[] = { 0, 1, 8, 71 };
    for (size_t i = 0; i < 4; i++) {
        cb = 0xFFFF;
        EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, small[i], &cb, 0), NC_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, 72);
    }
    cb = 0; EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, 72, &cb, 0), 0); EXPECT_EQ(cb, 72);
    CHECK(buf[72] == 0xEE);
    cb = 0; EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0), 0); EXPECT_EQ(cb, 72);
    nc_free(k); nc_free(p);
}

/* ---------- private blobs and export policy ---------- */
TEST(ncblob_export_private_requires_policy) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "key");
    BYTE buf[200]; DWORD cb = 0;
    EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_NOT_SUPPORTED);
    EXPECT_SS(U(NCryptExportKey)(k, 0, BCRYPT_PRIVATE_KEY_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_NOT_SUPPORTED);
    EXPECT_SS(U(NCryptExportKey)(k, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_NOT_SUPPORTED);
    SECURITY_STATUS s = U(NCryptExportKey)(k, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("opaque export of non-exportable key -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncblob_export_private_policy_matrix) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD pol[] = { NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, NC_EXP_ALL };
    for (size_t i = 0; i < 3; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, pol[i], TRUE);
        CHECKF(k != 0, "policy 0x%lx", pol[i]); if (!k) continue;
        BYTE buf[200]; DWORD cb = 0;
        SECURITY_STATUS s = U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, buf, sizeof buf, &cb, 0);
        if (pol[i] == NC_EXP_ALL) EXPECT_SS(s, 0);
        else t_note("plaintext ECC private export with policy 0x%lx -> 0x%08lx", pol[i], (DWORD)s);
        nc_free(k);
    }
    nc_free(p);
}
TEST(ncblob_export_ecc_private_layout) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 0; i < sizeof(ECCS) / sizeof(ECCS[0]); i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ECCS[i].alg, 0, NC_EXP_ALL, TRUE);
        CHECKF(k != 0, "%ls", ECCS[i].alg); if (!k) continue;
        DWORD cp = 0, cq = 0; SECURITY_STATUS s;
        BYTE *pr = nc_exp(k, BCRYPT_ECCPRIVATE_BLOB, &cp, &s), *pu = nc_exp(k, BCRYPT_ECCPUBLIC_BLOB, &cq, NULL);
        CHECKF(pr && pu, "%ls export 0x%08lx", ECCS[i].alg, (DWORD)s);
        if (pr && pu) {
            BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)pr;
            EXPECT_EQ(cp, 8 + 3 * ECCS[i].cbkey);
            EXPECT_EQ(h->dwMagic, ECCS[i].privmagic);
            EXPECT_EQ(h->cbKey, ECCS[i].cbkey);
            CHECK(!memcmp(pr + 8, pu + 8, 2 * ECCS[i].cbkey));   /* X||Y identical to the public export */
        }
        nc_hfree(pr); nc_hfree(pu); nc_free(k);
    }
    nc_free(p);
}
TEST(ncblob_export_rsa_private_layouts) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NC_EXP_ALL, TRUE); NEED(k, "key");
    DWORD c1 = 0, c2 = 0, c3 = 0;
    BYTE *pub = nc_exp(k, BCRYPT_RSAPUBLIC_BLOB, &c1, NULL), *prv = nc_exp(k, BCRYPT_RSAPRIVATE_BLOB, &c2, NULL), *full = nc_exp(k, BCRYPT_RSAFULLPRIVATE_BLOB, &c3, NULL);
    CHECK(pub && prv && full);
    if (pub && prv && full) {
        BCRYPT_RSAKEY_BLOB *hp = (BCRYPT_RSAKEY_BLOB *)prv, *hf = (BCRYPT_RSAKEY_BLOB *)full;
        EXPECT_EQ(hp->Magic, BCRYPT_RSAPRIVATE_MAGIC);
        EXPECT_EQ(hf->Magic, BCRYPT_RSAFULLPRIVATE_MAGIC);
        EXPECT_EQ(hp->cbPrime1, 64); EXPECT_EQ(hp->cbPrime2, 64);
        EXPECT_EQ(c2, sizeof *hp + 3 + 128 + 64 + 64);
        EXPECT_EQ(c3, sizeof *hf + 3 + 128 + 64 + 64 + 64 + 64 + 64 + 128);
        CHECK(!memcmp(pub + sizeof(BCRYPT_RSAKEY_BLOB), prv + sizeof(BCRYPT_RSAKEY_BLOB), 3 + 128));   /* e||n shared */
        CHECK(!memcmp(pub + sizeof(BCRYPT_RSAKEY_BLOB), full + sizeof(BCRYPT_RSAKEY_BLOB), 3 + 128));
        CHECK(!memcmp(prv + sizeof(BCRYPT_RSAKEY_BLOB), full + sizeof(BCRYPT_RSAKEY_BLOB), 3 + 128 + 128));  /* ... and p||q */
    }
    nc_hfree(pub); nc_hfree(prv); nc_hfree(full);
    nc_free(k); nc_free(p);
}
TEST(ncblob_export_generic_private_blob_note) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NC_EXP_ALL, TRUE); NEED(k, "key");
    DWORD cb = 0; SECURITY_STATUS s; BYTE *b = nc_exp(k, BCRYPT_PRIVATE_KEY_BLOB, &cb, &s);
    t_note("generic PRIVATEBLOB of RSA key: status 0x%08lx size %lu magic 0x%lx", (DWORD)s, b ? cb : 0, b ? ((BCRYPT_RSAKEY_BLOB *)b)->Magic : 0);
    nc_hfree(b);
    b = nc_exp(k, LEGACY_RSAPRIVATE_BLOB, &cb, &s);
    t_note("LEGACY_RSAPRIVATE_BLOB: status 0x%08lx size %lu first=%02x", (DWORD)s, b ? cb : 0, b ? b[0] : 0);
    nc_hfree(b);
    b = nc_exp(k, LEGACY_RSAPUBLIC_BLOB, &cb, &s);
    t_note("LEGACY_RSAPUBLIC_BLOB: status 0x%08lx size %lu", (DWORD)s, b ? cb : 0);
    if (b && cb >= 20) { EXPECT_EQ(b[0], 6); EXPECT_EQ(b[1], 2); EXPECT_EQ(*(DWORD *)(b + 4), 0x0000A400); EXPECT_EQ(*(DWORD *)(b + 8), 0x31415352); }   /* PUBLICKEYBLOB, CALG_RSA_KEYX */
    nc_hfree(b);
    nc_free(k); nc_free(p);
}

/* ---------- import: validation ---------- */
TEST(ncblob_import_arg_validation) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0x1;
    EXPECT_SS(U(NCryptImportKey)(p, 0, NULL, NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0), NC_INVALID_PARAMETER);
    /* NULL provider with a bad pointer set fails on the parameter check first */
    EXPECT_SS(U(NCryptImportKey)(0, 0, NULL, NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptImportKey)(0, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0), NC_INVALID_HANDLE);
    EXPECT_EQ(k, 1);
    nc_free(p);
}
TEST(ncblob_import_malformed_ecc_public) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    BYTE b[72]; NCRYPT_KEY_HANDLE k;
    memcpy(b, k_ec256_pub, 72);
    NCRYPT_KEY_HANDLE good = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, b, 72); CHECK(good != 0); nc_free(good);
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, 71, 0)); EXPECT_EQ(k, 0);   /* truncated */
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, 0, 0));
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, 7, 0));
    memcpy(b, k_ec256_pub, 72); b[0] ^= 0xFF;     /* bad magic */
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, 72, 0));
    memcpy(b, k_ec256_pub, 72); b[4] = 31;        /* cbKey inconsistent with magic */
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, 72, 0));
    memcpy(b, k_ec256_pub, 72); b[8 + 63] ^= 0x01;  /* point no longer on the curve */
    k = 0;
    SECURITY_STATUS s = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, 72, 0);
    EXPECT_SS_FAIL(s); t_note("off-curve public point import -> 0x%08lx", (DWORD)s);
    if (s == 0) nc_free(k);
    nc_free(p);
}
TEST(ncblob_import_wrong_blob_type_string) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptImportKey)(p, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0);
    EXPECT_SS_FAIL(s); EXPECT_EQ(k, 0); t_note("EC blob typed as RSAPUBLICBLOB -> 0x%08lx", (DWORD)s);
    s = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, (PBYTE)k_rsa_pub, sizeof k_rsa_pub, 0);
    EXPECT_SS_FAIL(s); EXPECT_EQ(k, 0); t_note("RSA blob typed as ECCPUBLICBLOB -> 0x%08lx", (DWORD)s);
    s = U(NCryptImportKey)(p, 0, L"cryptt-no-such-blob", NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0);
    EXPECT_SS_FAIL(s); EXPECT_EQ(k, 0);
    nc_free(p);
}
TEST(ncblob_import_malformed_rsa) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    BYTE b[sizeof k_rsa_pub]; NCRYPT_KEY_HANDLE k;
    memcpy(b, k_rsa_pub, sizeof b);
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &k, b, sizeof b - 1, 0)); EXPECT_EQ(k, 0);
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &k, b, 20, 0));
    b[0] ^= 0xFF;
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &k, b, sizeof b, 0));
    memcpy(b, k_rsa_pub, sizeof b); ((BCRYPT_RSAKEY_BLOB *)b)->cbModulus = 127;
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &k, b, sizeof b, 0));
    /* private blob whose primes are cut off */
    k = 0; EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, &k, (PBYTE)k_rsa_priv, sizeof k_rsa_priv - 64, 0));
    nc_free(p);
}
TEST(ncblob_import_flags) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const DWORD f[] = { 0x1, 0x2, 0x100, NCRYPT_SILENT_FLAG, 0x80000000u, NCRYPT_DO_NOT_FINALIZE_FLAG, NCRYPT_OVERWRITE_KEY_FLAG };
    for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++) {
        NCRYPT_KEY_HANDLE k = 0;
        SECURITY_STATUS s = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, f[i]);
        t_note("import ECC public flags=0x%lx -> 0x%08lx", f[i], (DWORD)s);
        if (s == 0) nc_free(k); else EXPECT_EQ(k, 0);
    }
    nc_free(p);
}

/* ---------- import: properties of imported keys ---------- */
TEST(ncblob_import_ecc_public_properties) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ec256_pub)); NEED(k, "imported key");
    CHECK(U(NCryptIsKeyHandle)(k));
    DWORD cb = 0; BYTE *n = nc_getprop(k, NCRYPT_ALGORITHM_PROPERTY, &cb);
    CHECK(n && !lstrcmpW((WCHAR *)n, L"ECDSA_P256")); nc_hfree(n);
    DWORD v; EXPECT_SS(nc_getdw(k, NCRYPT_LENGTH_PROPERTY, &v), 0); EXPECT_EQ(v, 256);
    BYTE *e = nc_exp(k, BCRYPT_ECCPUBLIC_BLOB, &cb, NULL);
    CHECK(e && cb == sizeof k_ec256_pub && !memcmp(e, k_ec256_pub, cb));    /* canonical, lossless public round trip */
    nc_hfree(e);
    nc_free(k); nc_free(p);
}
TEST(ncblob_import_magic_selects_algorithm) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, NCV(k_ecdh256_a_priv));
    NEED(a, "ECDH private import");
    DWORD cb; BYTE *n = nc_getprop(a, NCRYPT_ALGORITHM_PROPERTY, &cb);
    CHECK(n && !lstrcmpW((WCHAR *)n, L"ECDH_P256")); nc_hfree(n);
    n = nc_getprop(a, NCRYPT_ALGORITHM_GROUP_PROPERTY, &cb);
    CHECK(n && !lstrcmpW((WCHAR *)n, L"ECDH")); nc_hfree(n);
    NCRYPT_KEY_HANDLE r = nc_import(p, BCRYPT_RSAPUBLIC_BLOB, NCV(k_rsa_pub)); NEED(r, "RSA public import");
    n = nc_getprop(r, NCRYPT_ALGORITHM_PROPERTY, &cb);
    CHECK(n && !lstrcmpW((WCHAR *)n, L"RSA")); nc_hfree(n);
    DWORD v; EXPECT_SS(nc_getdw(r, NCRYPT_LENGTH_PROPERTY, &v), 0); EXPECT_EQ(v, 1024);
    nc_free(a); nc_free(r); nc_free(p);
}
TEST(ncblob_import_public_cannot_sign) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ec256_pub)); NEED(k, "key");
    BYTE sig[64]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, sizeof sig, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("sign with public-only key -> 0x%08lx", (DWORD)s);
    BYTE buf[200];
    s = U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("private export of public-only key -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncblob_import_public_blob_roundtrip_rsa) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_import(p, BCRYPT_RSAPUBLIC_BLOB, NCV(k_rsa_pub)); NEED(k, "key");
    DWORD cb = 0; BYTE *e = nc_exp(k, BCRYPT_RSAPUBLIC_BLOB, &cb, NULL);
    CHECK(e && cb == sizeof k_rsa_pub && !memcmp(e, k_rsa_pub, cb));
    nc_hfree(e);
    nc_free(k); nc_free(p);
}
TEST(ncblob_import_generic_public_blob) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptImportKey)(p, 0, BCRYPT_PUBLIC_KEY_BLOB, NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0);
    t_note("import ECC public as generic PUBLICBLOB -> 0x%08lx", (DWORD)s);
    if (s == 0) { DWORD cb; BYTE *n = nc_getprop(k, NCRYPT_ALGORITHM_PROPERTY, &cb); t_note("   resulting algorithm %ls", n ? (WCHAR *)n : L"?"); nc_hfree(n); nc_free(k); }
    k = 0;
    s = U(NCryptImportKey)(p, 0, BCRYPT_PRIVATE_KEY_BLOB, NULL, &k, (PBYTE)k_rsa_priv, sizeof k_rsa_priv, 0);
    t_note("import RSA private as generic PRIVATEBLOB -> 0x%08lx", (DWORD)s);
    if (s == 0) nc_free(k);
    nc_free(p);
}
TEST(ncblob_import_private_then_export_matches) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, NCV(k_ec256_priv)); NEED(k, "key");
    DWORD cb = 0; BYTE *e = nc_exp(k, BCRYPT_ECCPUBLIC_BLOB, &cb, NULL);
    CHECK(e && cb == sizeof k_ec256_pub && !memcmp(e, k_ec256_pub, cb));   /* public point derived from the imported scalar */
    nc_hfree(e);
    SECURITY_STATUS s; e = nc_exp(k, BCRYPT_ECCPRIVATE_BLOB, &cb, &s);
    t_note("private export of imported private key (default policy) -> 0x%08lx", (DWORD)s);
    nc_hfree(e);
    nc_free(k); nc_free(p);
}
TEST(ncblob_import_rsa_private_derives_public) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k1 = nc_import(p, BCRYPT_RSAPRIVATE_BLOB, NCV(k_rsa_priv)), k2 = nc_import(p, BCRYPT_RSAFULLPRIVATE_BLOB, NCV(k_rsa_full));
    NEED(k1 && k2, "keys");
    DWORD c1 = 0, c2 = 0; BYTE *a = nc_exp(k1, BCRYPT_RSAPUBLIC_BLOB, &c1, NULL), *b = nc_exp(k2, BCRYPT_RSAPUBLIC_BLOB, &c2, NULL);
    CHECK(a && c1 == sizeof k_rsa_pub && !memcmp(a, k_rsa_pub, c1));
    CHECK(b && c2 == sizeof k_rsa_pub && !memcmp(b, k_rsa_pub, c2));
    nc_hfree(a); nc_hfree(b);
    nc_free(k1); nc_free(k2); nc_free(p);
}

/* ---------- export -> import round trips ---------- */
TEST(ncblob_roundtrip_ecc_private) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (size_t i = 0; i < sizeof(ECCS) / sizeof(ECCS[0]); i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ECCS[i].alg, 0, NC_EXP_ALL, TRUE);
        CHECKF(k != 0, "%ls", ECCS[i].alg); if (!k) continue;
        DWORD c1 = 0, c2 = 0, c3 = 0;
        BYTE *pr = nc_exp(k, BCRYPT_ECCPRIVATE_BLOB, &c1, NULL);
        CHECK(pr != NULL);
        if (pr) {
            NCRYPT_KEY_HANDLE k2 = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, pr, c1);
            CHECKF(k2 != 0, "%ls re-import", ECCS[i].alg);
            if (k2) {
                BYTE *a = nc_exp(k, BCRYPT_ECCPUBLIC_BLOB, &c2, NULL), *b = nc_exp(k2, BCRYPT_ECCPUBLIC_BLOB, &c3, NULL);
                CHECK(a && b && c2 == c3 && !memcmp(a, b, c2));
                nc_hfree(a); nc_hfree(b); nc_free(k2);
            }
            nc_hfree(pr);
        }
        nc_free(k);
    }
    nc_free(p);
}
TEST(ncblob_roundtrip_rsa_private_signature_equal) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NC_EXP_ALL, TRUE); NEED(k, "key");
    DWORD cb = 0; BYTE *full = nc_exp(k, BCRYPT_RSAFULLPRIVATE_BLOB, &cb, NULL);
    CHECK(full != NULL);
    if (full) {
        NCRYPT_KEY_HANDLE k2 = nc_import(p, BCRYPT_RSAFULLPRIVATE_BLOB, full, cb); NEED(k2, "re-imported key");
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        BYTE s1[128], s2[128]; DWORD n1 = 0, n2 = 0;
        EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, s1, 128, &n1, BCRYPT_PAD_PKCS1), 0);
        EXPECT_SS(U(NCryptSignHash)(k2, &pi, (PBYTE)k_dig_sha256, 32, s2, 128, &n2, BCRYPT_PAD_PKCS1), 0);
        EXPECT_EQ(n1, 128); EXPECT_EQ(n2, 128);
        CHECK(!memcmp(s1, s2, 128));   /* PKCS#1 v1.5 is deterministic */
        nc_free(k2); nc_hfree(full);
    }
    nc_free(k); nc_free(p);
}
TEST(ncblob_roundtrip_dh_private) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_DH_ALGORITHM, 1024, NC_EXP_ALL, TRUE); NEED(k, "DH key");
    DWORD c1 = 0, c2 = 0; SECURITY_STATUS s;
    BYTE *pub = nc_exp(k, BCRYPT_DH_PUBLIC_BLOB, &c1, &s);
    EXPECT_SS(s, 0);
    if (pub) {
        BCRYPT_DH_KEY_BLOB *h = (BCRYPT_DH_KEY_BLOB *)pub;
        EXPECT_EQ(h->dwMagic, BCRYPT_DH_PUBLIC_MAGIC); EXPECT_EQ(h->cbKey, 128); EXPECT_EQ(c1, 8 + 3 * 128);
    }
    BYTE *prv = nc_exp(k, BCRYPT_DH_PRIVATE_BLOB, &c2, &s);
    EXPECT_SS(s, 0);
    if (prv) {
        BCRYPT_DH_KEY_BLOB *h = (BCRYPT_DH_KEY_BLOB *)prv;
        EXPECT_EQ(h->dwMagic, BCRYPT_DH_PRIVATE_MAGIC); EXPECT_EQ(c2, 8 + 4 * 128);
        NCRYPT_KEY_HANDLE k2 = nc_import(p, BCRYPT_DH_PRIVATE_BLOB, prv, c2);
        CHECK(k2 != 0);
        if (k2) { DWORD c3 = 0; BYTE *pub2 = nc_exp(k2, BCRYPT_DH_PUBLIC_BLOB, &c3, NULL); CHECK(pub && pub2 && c3 == c1 && !memcmp(pub, pub2, c1)); nc_hfree(pub2); nc_free(k2); }
    }
    nc_hfree(pub); nc_hfree(prv);
    nc_free(k); nc_free(p);
}

/* ---------- opaque transport ---------- */
TEST(ncblob_opaque_roundtrip) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, NCRYPT_ALLOW_EXPORT_FLAG, TRUE); NEED(k, "key");
    DWORD cb = 0; SECURITY_STATUS s;
    BYTE *o = nc_exp(k, NCRYPT_OPAQUETRANSPORT_BLOB, &cb, &s);
    t_note("opaque export (ALLOW_EXPORT only) -> 0x%08lx size %lu", (DWORD)s, cb);
    if (o) {
        NCRYPT_KEY_HANDLE k2 = 0;
        s = U(NCryptImportKey)(p, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, &k2, o, cb, 0);
        EXPECT_SS(s, 0);
        if (k2) {
            DWORD c1 = 0, c2 = 0; BYTE *a = nc_exp(k, BCRYPT_ECCPUBLIC_BLOB, &c1, NULL), *b = nc_exp(k2, BCRYPT_ECCPUBLIC_BLOB, &c2, NULL);
            CHECK(a && b && c1 == c2 && !memcmp(a, b, c1));
            nc_hfree(a); nc_hfree(b);
            nc_free(k2);
        }
        nc_hfree(o);
    }
    nc_free(k); nc_free(p);
}
TEST(ncblob_opaque_import_garbage) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    BYTE junk[64]; for (int i = 0; i < 64; i++) junk[i] = (BYTE)(i * 7 + 1);
    NCRYPT_KEY_HANDLE k = 0;
    EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, &k, junk, sizeof junk, 0));
    EXPECT_EQ(k, 0);
    EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, &k, junk, 0, 0));
    nc_free(p);
}

/* ---------- PKCS#8 ---------- */
static NCryptBufferDesc *pbe_params(NCryptBuffer b[3], CRYPT_PKCS12_PBE_PARAMS *pp, const WCHAR *pw, NCryptBufferDesc *d)
{
    static const WCHAR oid[] = L"1.2.840.113549.1.12.1.3";   /* pbeWithSHAAnd3-KeyTripleDES-CBC */
    pp->iIterations = 2000; pp->cbSalt = 20;
    b[0].cbBuffer = sizeof *pp;                    b[0].BufferType = NCRYPTBUFFER_PKCS_ALG_PARAM; b[0].pvBuffer = pp;
    b[1].cbBuffer = sizeof oid;                    b[1].BufferType = NCRYPTBUFFER_PKCS_ALG_OID;   b[1].pvBuffer = (void *)oid;
    b[2].cbBuffer = (lstrlenW(pw) + 1) * 2;        b[2].BufferType = NCRYPTBUFFER_PKCS_SECRET;    b[2].pvBuffer = (void *)pw;
    d->ulVersion = NCRYPTBUFFER_VERSION; d->cBuffers = 3; d->pBuffers = b;
    return d;
}
TEST(ncblob_pkcs8_plain_export_structure) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NC_EXP_ALL, TRUE); NEED(k, "key");
    DWORD cb = 0; SECURITY_STATUS s; BYTE *b = nc_exp(k, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &cb, &s);
    EXPECT_SS(s, 0);
    if (b) {
        CHECK(cb > 400 && b[0] == 0x30);
        CHECK(find_bytes(b, cb, OID_RSA_ENC, sizeof OID_RSA_ENC));
        CHECK(cb > 4 && b[1] == 0x82 && (DWORD)((b[2] << 8) | b[3]) + 4 == cb);   /* single DER SEQUENCE spanning the whole blob */
        CHECK(find_bytes(b, 12, (const BYTE *)"\x02\x01\x00", 3));                /* PrivateKeyInfo version 0 */
        nc_hfree(b);
    }
    nc_free(k); nc_free(p);
}
TEST(ncblob_pkcs8_plain_export_ec_structure) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, NC_EXP_ALL, TRUE); NEED(k, "key");
    DWORD cb = 0; SECURITY_STATUS s; BYTE *b = nc_exp(k, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &cb, &s);
    EXPECT_SS(s, 0);
    if (b) { CHECK(b[0] == 0x30); CHECK(find_bytes(b, cb, OID_EC_PUBKEY, sizeof OID_EC_PUBKEY)); nc_hfree(b); }
    nc_free(k); nc_free(p);
}
TEST(ncblob_pkcs8_plain_needs_plaintext_policy) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NCRYPT_ALLOW_EXPORT_FLAG, TRUE); NEED(k, "key");
    BYTE buf[2048]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptExportKey)(k, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("unencrypted PKCS8 export with ALLOW_EXPORT only -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncblob_pkcs8_roundtrip_plain) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NC_EXP_ALL, TRUE); NEED(k, "key");
    DWORD cb = 0; BYTE *b = nc_exp(k, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &cb, NULL); NEED(b, "pkcs8 blob");
    NCRYPT_KEY_HANDLE k2 = 0;
    EXPECT_SS(U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &k2, b, cb, 0), 0);
    if (k2) {
        DWORD c1 = 0, c2 = 0; BYTE *x = nc_exp(k, BCRYPT_RSAPUBLIC_BLOB, &c1, NULL), *y = nc_exp(k2, BCRYPT_RSAPUBLIC_BLOB, &c2, NULL);
        CHECK(x && y && c1 == c2 && !memcmp(x, y, c1));
        nc_hfree(x); nc_hfree(y); nc_free(k2);
    }
    BYTE bad[64]; memcpy(bad, b, 64); NCRYPT_KEY_HANDLE k3 = 0;
    EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &k3, b, cb - 1, 0));   /* truncated DER */
    EXPECT_SS_FAIL(U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &k3, bad, 64, 0));
    nc_hfree(b);
    nc_free(k); nc_free(p);
}
TEST(ncblob_pkcs8_import_known_plain) {
    REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0;
    EXPECT_SS(U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &k, (PBYTE)k_rsa_pkcs8_plain, sizeof k_rsa_pkcs8_plain, 0), 0);
    NEED(k, "pkcs8 import");
    DWORD cb = 0; BYTE *e = nc_exp(k, BCRYPT_RSAPUBLIC_BLOB, &cb, NULL);
    CHECK(e && cb == sizeof k_rsa_pub && !memcmp(e, k_rsa_pub, cb)); nc_hfree(e);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    BYTE sig[128]; DWORD n = 0;
    EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), 0);
    EXPECT_EQ(n, 128); CHECK(!memcmp(sig, k_rsa_pkcs1_sha256, 128));
    nc_free(k); nc_free(p);
}
TEST(ncblob_pkcs8_encrypted_roundtrip) {
    REQUIRE(U(NCryptExportKey)); REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NCRYPT_ALLOW_EXPORT_FLAG, TRUE); NEED(k, "key");
    NCryptBuffer nb[3]; NCryptBufferDesc d; CRYPT_PKCS12_PBE_PARAMS pp;
    pbe_params(nb, &pp, L"cryptt-pw", &d);
    DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptExportKey)(k, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &d, NULL, 0, &cb, 0);
    EXPECT_SS(s, 0);
    if (s || !cb) { t_note("encrypted PKCS8 export unsupported here (0x%08lx)", (DWORD)s); nc_free(k); nc_free(p); return; }
    BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cb);
    EXPECT_SS(U(NCryptExportKey)(k, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &d, b, cb, &cb, 0), 0);
    CHECK(b[0] == 0x30);
    CHECK(find_bytes(b, cb, OID_P12_3DES, sizeof OID_P12_3DES));     /* EncryptedPrivateKeyInfo names the PBE algorithm */
    CHECK(!find_bytes(b, cb, OID_RSA_ENC, sizeof OID_RSA_ENC));      /* the inner PrivateKeyInfo is encrypted */
    NCRYPT_KEY_HANDLE k2 = 0;
    EXPECT_SS(U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &d, &k2, b, cb, 0), 0);
    if (k2) {
        DWORD c1 = 0, c2 = 0; BYTE *x = nc_exp(k, BCRYPT_RSAPUBLIC_BLOB, &c1, NULL), *y = nc_exp(k2, BCRYPT_RSAPUBLIC_BLOB, &c2, NULL);
        CHECK(x && y && c1 == c2 && !memcmp(x, y, c1));
        nc_hfree(x); nc_hfree(y); nc_free(k2);
    }
    /* wrong password */
    NCryptBuffer nb2[3]; NCryptBufferDesc d2; CRYPT_PKCS12_PBE_PARAMS pp2;
    pbe_params(nb2, &pp2, L"cryptt-WRONG", &d2);
    NCRYPT_KEY_HANDLE k3 = 0;
    s = U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &d2, &k3, b, cb, 0);
    EXPECT_SS_FAIL(s); EXPECT_EQ(k3, 0); t_note("PKCS8 import with wrong password -> 0x%08lx", (DWORD)s);
    /* no password at all */
    s = U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &k3, b, cb, 0);
    EXPECT_SS_FAIL(s); EXPECT_EQ(k3, 0); t_note("encrypted PKCS8 import without parameters -> 0x%08lx", (DWORD)s);
    HeapFree(GetProcessHeap(), 0, b);
    nc_free(k); nc_free(p);
}
TEST(ncblob_pkcs8_import_known_encrypted_p12pbe) {
    REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const WCHAR pw[] = L"cryptt";
    NCryptBuffer nb = { sizeof pw, NCRYPTBUFFER_PKCS_SECRET, (void *)pw }; NCryptBufferDesc d = { NCRYPTBUFFER_VERSION, 1, &nb };
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &d, &k, (PBYTE)k_rsa_pkcs8_pbe_sha1_3des, sizeof k_rsa_pkcs8_pbe_sha1_3des, 0);
    EXPECT_SS(s, 0);
    NEED(k, "imported key");
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    BYTE sig[128]; DWORD n = 0;
    EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), 0);
    CHECK(!memcmp(sig, k_rsa_pkcs1_sha256, 128));
    nc_free(k); nc_free(p);
}
TEST(ncblob_pkcs8_import_known_encrypted_pbes2) {
    REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const WCHAR pw[] = L"cryptt";
    NCryptBuffer nb = { sizeof pw, NCRYPTBUFFER_PKCS_SECRET, (void *)pw }; NCryptBufferDesc d = { NCRYPTBUFFER_VERSION, 1, &nb };
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &d, &k, (PBYTE)k_rsa_pkcs8_pbes2_aes256, sizeof k_rsa_pkcs8_pbes2_aes256, 0);
    t_note("PBES2 (PBKDF2/HMAC-SHA256/AES-256-CBC) PKCS8 import -> 0x%08lx", (DWORD)s);
    if (s == 0) {
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        BYTE sig[128]; DWORD n = 0;
        EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), 0);
        CHECK(!memcmp(sig, k_rsa_pkcs1_sha256, 128));
        nc_free(k);
    }
    nc_free(p);
}

/* ---------- other blob types ---------- */
TEST(ncblob_pkcs7_envelope_requires_parameters) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NC_EXP_ALL, TRUE); NEED(k, "key");
    BYTE buf[2048]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptExportKey)(k, 0, NCRYPT_PKCS7_ENVELOPE_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("PKCS7 envelope export without cert/alg parameters -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncblob_cipher_key_blob_requires_wrapping_key) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, NC_EXP_ALL, TRUE); NEED(k, "key");
    BYTE buf[2048]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptExportKey)(k, 0, NCRYPT_CIPHER_KEY_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("CIPHER_KEY_BLOB export of an RSA key -> 0x%08lx", (DWORD)s);
    s = U(NCryptExportKey)(k, 0, NCRYPT_PROTECTED_KEY_BLOB, NULL, buf, sizeof buf, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("PROTECTED_KEY_BLOB export without parameters -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}

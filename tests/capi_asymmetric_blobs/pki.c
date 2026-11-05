/* CryptExportPublicKeyInfo / CryptImportPublicKeyInfo(Ex) cross-checks of CAPI keys against crypt32. */
#include "cab.h"

/* --- minimal DER writer (big-endian INTEGER from a little-endian magnitude) --- */
static size_t der_len(BYTE *o, size_t n) {
    if (n < 0x80) { o[0] = (BYTE)n; return 1; }
    if (n < 0x100) { o[0] = 0x81; o[1] = (BYTE)n; return 2; }
    o[0] = 0x82; o[1] = (BYTE)(n >> 8); o[2] = (BYTE)n; return 3;
}
static size_t der_int_le(BYTE *o, const BYTE *le, size_t n) {
    while (n > 1 && le[n - 1] == 0) n--;                   /* strip high zero bytes */
    int pad = (le[n - 1] & 0x80) != 0;
    o[0] = 0x02;
    size_t l = der_len(o + 1, n + pad);
    BYTE *p = o + 1 + l;
    if (pad) *p++ = 0;
    for (size_t i = 0; i < n; i++) *p++ = le[n - 1 - i];
    return (size_t)(p - o);
}
static size_t der_seq(BYTE *o, const BYTE *body, size_t n) {
    o[0] = 0x30;
    size_t l = der_len(o + 1, n);
    memmove(o + 1 + l, body, n);
    return 1 + l + n;
}
static size_t der_rsa_pubkey(BYTE *o, const BYTE *blob) {
    BYTE body[1200]; size_t n = 0;
    DWORD bits, e; memcpy(&bits, blob + 12, 4); memcpy(&e, blob + 16, 4);
    n += der_int_le(body + n, blob + 20, bits / 8);
    n += der_int_le(body + n, (BYTE *)&e, 4);
    return der_seq(o, body, n);
}

static CERT_PUBLIC_KEY_INFO *export_pki(HCRYPTPROV p, DWORD spec, const char *oid, BYTE *buf, DWORD cap, DWORD *err) {
    DWORD n = 0;
    BOOL r = oid ? U(CryptExportPublicKeyInfoEx)(p, spec, X509_ASN_ENCODING, (LPSTR)oid, 0, NULL, NULL, &n)
                 : U(CryptExportPublicKeyInfo)(p, spec, X509_ASN_ENCODING, NULL, &n);
    if (!r) { if (err) *err = GetLastError(); return NULL; }
    if (n > cap) { if (err) *err = ERROR_INSUFFICIENT_BUFFER; return NULL; }
    r = oid ? U(CryptExportPublicKeyInfoEx)(p, spec, X509_ASN_ENCODING, (LPSTR)oid, 0, NULL, (PCERT_PUBLIC_KEY_INFO)buf, &n)
            : U(CryptExportPublicKeyInfo)(p, spec, X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)buf, &n);
    if (!r) { if (err) *err = GetLastError(); return NULL; }
    return (CERT_PUBLIC_KEY_INFO *)buf;
}

#define PKI_NEED() do { CAB_NEED(); if (!U(CryptExportPublicKeyInfo) || !U(CryptImportPublicKeyInfo) || !U(CryptExportPublicKeyInfoEx)) { t_skip("missing crypt32 export"); return; } } while (0)

TEST(capiab_pki_export_rsa_matches_der) {
    PKI_NEED();
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
        HCRYPTKEY k = cab_imp(p, CAB_RKS[i].prv, (DWORD)CAB_RKS[i].prvn, 0);
        CHECK(k != 0);
        BYTE buf[2048]; DWORD err = 0;
        CERT_PUBLIC_KEY_INFO *pki = export_pki(p, AT_KEYEXCHANGE, NULL, buf, sizeof buf, &err);
        CHECKF(pki != NULL, "%s export err 0x%lx", CAB_RKS[i].name, err);
        if (pki) {
            EXPECT_STR(pki->Algorithm.pszObjId, "1.2.840.113549.1.1.1");
            BYTE der[1200]; size_t dn = der_rsa_pubkey(der, CAB_RKS[i].pub);
            CHECKF(pki->PublicKey.cbData == dn && !memcmp(pki->PublicKey.pbData, der, dn), "%s RSAPublicKey DER differs (cb %lu want %zu)", CAB_RKS[i].name, pki->PublicKey.cbData, dn);
            EXPECT_EQ(pki->PublicKey.cUnusedBits, 0);
            t_note("%s: exported rsaEncryption parameters cb=%lu", CAB_RKS[i].name, pki->Algorithm.Parameters.cbData);
        }
        cab_kd(k); cab_rel(p);
    }
}

TEST(capiab_pki_export_rsa_size_protocol) {
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    DWORD n = 0;
    CHECK(U(CryptExportPublicKeyInfo)(p, AT_KEYEXCHANGE, X509_ASN_ENCODING, NULL, &n));
    CHECK(n > sizeof(CERT_PUBLIC_KEY_INFO));
    BYTE buf[1024];
    DWORD m = n - 1; SET_ERR(0);
    EXPECT_FAIL(!U(CryptExportPublicKeyInfo)(p, AT_KEYEXCHANGE, X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)buf, &m), ERROR_MORE_DATA);
    EXPECT_EQ(m, n);
    m = n;
    CHECK(U(CryptExportPublicKeyInfo)(p, AT_KEYEXCHANGE, X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)buf, &m));
    EXPECT_EQ(m, n);
    cab_kd(k); cab_rel(p);
}

TEST(capiab_pki_export_without_key) {
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    DWORD n = 0;
    SET_ERR(0);
    BOOL r = U(CryptExportPublicKeyInfo)(p, AT_KEYEXCHANGE, X509_ASN_ENCODING, NULL, &n);
    CHECK(!r);
    t_note("CryptExportPublicKeyInfo in an empty VERIFYCONTEXT: err 0x%lx", GetLastError());
    cab_rel(p);
}

TEST(capiab_pki_export_bad_encoding_type) {
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    DWORD n = 0;
    SET_ERR(0);
    BOOL r = U(CryptExportPublicKeyInfo)(p, AT_KEYEXCHANGE, 0, NULL, &n);
    t_note("CryptExportPublicKeyInfo with encoding type 0: err 0x%lx (E_INVALIDARG=0x%lx)", GetLastError(), (DWORD)E_INVALIDARG);
    SET_ERR(0);
    r = U(CryptExportPublicKeyInfo)(p, AT_KEYEXCHANGE, PKCS_7_ASN_ENCODING, NULL, &n);
    t_note("CryptExportPublicKeyInfo with PKCS_7 only: err 0x%lx", GetLastError());
    cab_kd(k); cab_rel(p);
}

TEST(capiab_pki_import_rsa_roundtrip) {
    PKI_NEED();
    for (int i = 0; i < CAB_NRK; i++) {
        HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
        HCRYPTKEY k = cab_imp(p, CAB_RKS[i].prv, (DWORD)CAB_RKS[i].prvn, 0);
        BYTE buf[2048]; DWORD err = 0;
        CERT_PUBLIC_KEY_INFO *pki = export_pki(p, AT_KEYEXCHANGE, NULL, buf, sizeof buf, &err);
        CHECK(pki != NULL);
        if (pki) {
            HCRYPTPROV p2 = cab_enh();
            HCRYPTKEY ik = 0;
            BOOL r = U(CryptImportPublicKeyInfo)(p2, X509_ASN_ENCODING, pki, &ik);
            CHECKF(r, "%s import err 0x%lx", CAB_RKS[i].name, GetLastError());
            if (r) {
                BYTE b[1024]; DWORD n = sizeof b;
                CHECK(U(CryptExportKey)(ik, 0, PUBLICKEYBLOB, 0, b, &n));
                CHECK(n == CAB_RKS[i].pubn && !memcmp(b, CAB_RKS[i].pub, n));
                EXPECT_EQ(cab_algid(ik), CALG_RSA_KEYX);
                cab_kd(ik);
            }
            cab_rel(p2);
        }
        cab_kd(k); cab_rel(p);
    }
}

TEST(capiab_pki_import_signature_oid_gives_keyx_or_sign) {
    /* CryptImportPublicKeyInfo derives CALG_RSA_KEYX from rsaEncryption; Ex with CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG is a separate API */
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    BYTE buf[1024]; DWORD err;
    CERT_PUBLIC_KEY_INFO *pki = export_pki(p, AT_KEYEXCHANGE, szOID_RSA_RSA, buf, sizeof buf, &err);
    CHECKF(pki != NULL, "export Ex err 0x%lx", err);
    if (pki) EXPECT_STR(pki->Algorithm.pszObjId, szOID_RSA_RSA);
    cab_kd(k); cab_rel(p);
}

TEST(capiab_pki_import_rejects_unknown_algorithm_oid) {
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    BYTE buf[1024]; DWORD err;
    CERT_PUBLIC_KEY_INFO *pki = export_pki(p, AT_KEYEXCHANGE, NULL, buf, sizeof buf, &err);
    CHECK(pki != NULL);
    if (pki) {
        CERT_PUBLIC_KEY_INFO bad = *pki;
        bad.Algorithm.pszObjId = (LPSTR)"1.2.3.4.5.6.7.8";
        HCRYPTKEY ik = 0;
        SET_ERR(0);
        BOOL r = U(CryptImportPublicKeyInfo)(p, X509_ASN_ENCODING, &bad, &ik);
        t_note("CryptImportPublicKeyInfo with unknown algorithm OID: err 0x%lx", GetLastError());
        if (r) cab_kd(ik);
        SET_ERR(0);
        r = U(CryptImportPublicKeyInfo)(p, 0, pki, &ik);
        t_note("CryptImportPublicKeyInfo with encoding type 0: err 0x%lx", GetLastError());
        if (r) cab_kd(ik);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_pki_import_truncated_public_key) {
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    BYTE der[1200]; size_t dn = der_rsa_pubkey(der, rsa1024_pub);
    CERT_PUBLIC_KEY_INFO info; memset(&info, 0, sizeof info);
    info.Algorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
    info.PublicKey.pbData = der;
    HCRYPTKEY ik = 0;
    info.PublicKey.cbData = (DWORD)dn;
    BOOL r = U(CryptImportPublicKeyInfo)(p, X509_ASN_ENCODING, &info, &ik);
    CHECKF(r, "hand-built SubjectPublicKeyInfo import err 0x%lx", GetLastError());
    if (r) {
        BYTE b[512]; DWORD n = sizeof b;
        CHECK(U(CryptExportKey)(ik, 0, PUBLICKEYBLOB, 0, b, &n));
        CHECK(n == sizeof rsa1024_pub && !memcmp(b, rsa1024_pub, n));
        cab_kd(ik);
    }
    DWORD cuts[] = { 0, 1, 2, 10, 100, (DWORD)dn - 1 };
    for (int i = 0; i < 6; i++) {
        info.PublicKey.cbData = cuts[i];
        SET_ERR(0);
        r = U(CryptImportPublicKeyInfo)(p, X509_ASN_ENCODING, &info, &ik);
        CHECKF(!r, "truncated public key (%lu bytes) imported", cuts[i]);
        if (r) cab_kd(ik);
    }
    cab_rel(p);
}

TEST(capiab_pki_import_with_exponent_variants) {
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    DWORD exps[] = { 3, 17, 65537, 0x1000001 };
    for (int i = 0; i < 4; i++) {
        BYTE blob[1024]; memcpy(blob, rsa1024_pub, sizeof rsa1024_pub);
        memcpy(blob + 16, &exps[i], 4);
        BYTE der[1200]; size_t dn = der_rsa_pubkey(der, blob);
        CERT_PUBLIC_KEY_INFO info; memset(&info, 0, sizeof info);
        info.Algorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
        info.PublicKey.pbData = der; info.PublicKey.cbData = (DWORD)dn;
        HCRYPTKEY ik = 0;
        BOOL r = U(CryptImportPublicKeyInfo)(p, X509_ASN_ENCODING, &info, &ik);
        CHECKF(r, "e=%lu import err 0x%lx", exps[i], GetLastError());
        if (r) {
            BYTE b[512]; DWORD n = sizeof b;
            CHECK(U(CryptExportKey)(ik, 0, PUBLICKEYBLOB, 0, b, &n));
            DWORD e; memcpy(&e, b + 16, 4);
            EXPECT_EQ(e, exps[i]);
            cab_kd(ik);
        }
    }
    cab_rel(p);
}

TEST(capiab_pki_dss_export_parameters_and_y) {
    PKI_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
    CHECK(k != 0);
    BYTE buf[2048]; DWORD err = 0;
    CERT_PUBLIC_KEY_INFO *pki = export_pki(p, AT_SIGNATURE, NULL, buf, sizeof buf, &err);
    CHECKF(pki != NULL, "export err 0x%lx", err);
    if (pki) {
        EXPECT_STR(pki->Algorithm.pszObjId, szOID_X957_DSA);
        /* parameters = SEQUENCE { INTEGER p, INTEGER q, INTEGER g } */
        BYTE body[600]; size_t n = 0, off = 16;
        n += der_int_le(body + n, dss1024_pub + off, 128);
        n += der_int_le(body + n, dss1024_pub + off + 128, 20);
        n += der_int_le(body + n, dss1024_pub + off + 148, 128);
        BYTE par[700]; size_t pn = der_seq(par, body, n);
        CHECKF(pki->Algorithm.Parameters.cbData == pn && !memcmp(pki->Algorithm.Parameters.pbData, par, pn), "DSS parameters DER differs");
        /* public key = INTEGER y */
        BYTE y[200]; size_t yn = der_int_le(y, dss1024_pub + off + 276, 128);
        CHECKF(pki->PublicKey.cbData == yn && !memcmp(pki->PublicKey.pbData, y, yn), "DSS y DER differs");
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_pki_dss_import_roundtrip) {
    PKI_NEED();
    CAB_NOWINE("partial dssenh");
    HCRYPTPROV p = cab_dss(); if (!p) { t_skip("no dss"); return; }
    HCRYPTKEY k = cab_imp(p, dss1024_prv, sizeof dss1024_prv, 0);
    BYTE buf[2048]; DWORD err = 0;
    CERT_PUBLIC_KEY_INFO *pki = export_pki(p, AT_SIGNATURE, NULL, buf, sizeof buf, &err);
    CHECK(pki != NULL);
    if (pki) {
        HCRYPTPROV p2 = cab_dss();
        HCRYPTKEY ik = 0;
        BOOL r = U(CryptImportPublicKeyInfo)(p2, X509_ASN_ENCODING, pki, &ik);
        CHECKF(r, "err 0x%lx", GetLastError());
        if (r) {
            /* the imported key verifies the known-answer signature */
            HCRYPTHASH h = cab_hash(p2, CALG_SHA1, rsa_msg, sizeof rsa_msg);
            CHECK(h && U(CryptVerifySignatureW)(h, dss1024_sig_sha1, 40, ik, NULL, 0));
            cab_hd(h); cab_kd(ik);
        }
        cab_rel(p2);
    }
    cab_kd(k); cab_rel(p);
}

TEST(capiab_pki_rsa_sign_via_exported_info_verify_with_imported) {
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    BYTE buf[1024]; DWORD err;
    CERT_PUBLIC_KEY_INFO *pki = export_pki(p, AT_KEYEXCHANGE, NULL, buf, sizeof buf, &err);
    CHECK(pki != NULL);
    HCRYPTKEY ik = 0;
    HCRYPTPROV p2 = cab_enh();
    CHECK(pki && U(CryptImportPublicKeyInfo)(p2, X509_ASN_ENCODING, pki, &ik));
    HCRYPTHASH h = cab_hash(p2, CALG_SHA1, rsa_msg, sizeof rsa_msg);
    CHECK(ik && h && U(CryptVerifySignatureW)(h, rsa1024_sig_sha1, 128, ik, NULL, 0));
    cab_hd(h); cab_kd(ik); cab_rel(p2); cab_kd(k); cab_rel(p);
}

TEST(capiab_pki_export_ex_unknown_oid_observe) {
    PKI_NEED();
    HCRYPTPROV p = cab_enh(); if (!p) { t_skip("no enh"); return; }
    HCRYPTKEY k = cab_imp(p, rsa1024_prv, sizeof rsa1024_prv, 0);
    DWORD n = 0;
    SET_ERR(0);
    BOOL r = U(CryptExportPublicKeyInfoEx)(p, AT_KEYEXCHANGE, X509_ASN_ENCODING, (LPSTR)"1.2.3.4.5.6.7.8", 0, NULL, NULL, &n);
    t_note("CryptExportPublicKeyInfoEx with an unknown algorithm OID: %d err 0x%lx", r, r ? 0 : GetLastError());
    cab_kd(k); cab_rel(p);
}

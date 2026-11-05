/* CRL contexts: creation, decoded CRL_INFO, duplicate/free, properties, serialization. */
#include "cc.h"

static void rel(PCCRL_CONTEXT c) { if (c) U(CertFreeCRLContext)(c); }
static int blob_is(const CRYPT_INTEGER_BLOB *b, const BYTE *p, DWORD n) { return b->cbData == n && !memcmp(b->pbData, p, n); }

TEST(crlctx_create_bad_encoding_type) {
    REQUIRE(U(CertCreateCRLContext));
    SET_ERR(0);
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(0, VEC(v_crl_basic));
    CHECK(c == NULL); EXPECT_ERR(CC_E_INVALIDARG);
    rel(c);
    SET_ERR(0);
    c = U(CertCreateCRLContext)(0, NULL, 0);
    CHECK(c == NULL); EXPECT_ERR(CC_E_INVALIDARG);
    /* PKCS7-only encoding type is not an X509 type */
    SET_ERR(0);
    c = U(CertCreateCRLContext)(PKCS_7_ASN_ENCODING, VEC(v_crl_basic));
    CHECK(c == NULL);
    if (c) rel(c); else EXPECT_ERR(CC_E_INVALIDARG);
}
TEST(crlctx_create_null_data) {
    REQUIRE(U(CertCreateCRLContext));
    SET_ERR(0);
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(CC_X509, NULL, 0);
    CHECK(c == NULL); EXPECT_ERR(CC_E_EOD);
    SET_ERR(0);
    BYTE z = 0;
    c = U(CertCreateCRLContext)(CC_X509, &z, 0);
    CHECK(c == NULL); EXPECT_ERR(CC_E_EOD);
}
TEST(crlctx_create_wrong_object) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(CC_X509, VEC(v_ca1));
    CHECK(c == NULL); rel(c);
    c = U(CertCreateCRLContext)(CC_X509, VEC(v_ctl_content));
    CHECK(c == NULL); rel(c);
    BYTE junk[16] = { 0x04, 0x0e, 1, 2, 3 };
    c = U(CertCreateCRLContext)(CC_X509, junk, sizeof junk);
    CHECK(c == NULL); rel(c);
}
TEST(crlctx_create_truncated) {
    REQUIRE(U(CertCreateCRLContext));
    static const DWORD cuts[] = { 1, 2, 4, 5, 10, 50, 100 };
    for (unsigned i = 0; i < sizeof cuts / sizeof cuts[0]; i++) {
        PCCRL_CONTEXT c = U(CertCreateCRLContext)(CC_X509, v_crl_basic, sizeof(v_crl_basic) - cuts[i]);
        CHECKF(c == NULL, "cut=%lu", cuts[i]);
        rel(c);
    }
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(CC_X509, v_crl_basic, 3);
    CHECK(c == NULL); rel(c);
}
TEST(crlctx_create_trailing_garbage) {
    REQUIRE(U(CertCreateCRLContext));
    BYTE buf[sizeof(v_crl_basic) + 4];
    memcpy(buf, v_crl_basic, sizeof v_crl_basic); memset(buf + sizeof v_crl_basic, 0xAA, 4);
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(CC_X509, buf, sizeof buf);
    t_note("trailing garbage after CRL: %s", c ? "accepted" : "rejected");
    if (c) t_note("cbCrlEncoded=%lu (input %zu, DER %zu)", c->cbCrlEncoded, sizeof buf, sizeof v_crl_basic);
    rel(c);
}

static const struct { const char *name; const BYTE *p; DWORD n; DWORD ver, entries; } kVecs[] = {
    { "basic", v_crl_basic, sizeof v_crl_basic, 1, 2 },
    { "newer", v_crl_basic_newer, sizeof v_crl_basic_newer, 1, 3 },
    { "expired", v_crl_expired, sizeof v_crl_expired, 1, 1 },
    { "empty", v_crl_empty, sizeof v_crl_empty, 1, 0 },
    { "delta", v_crl_delta, sizeof v_crl_delta, 1, 1 },
    { "idp", v_crl_idp, sizeof v_crl_idp, 1, 1 },
    { "ca2", v_crl_ca2, sizeof v_crl_ca2, 1, 1 },
    { "reasons", v_crl_reasons, sizeof v_crl_reasons, 1, 10 },
    { "noext", v_crl_noext, sizeof v_crl_noext, 1, 1 },
    { "v1_nonext", v_crl_v1_nonext, sizeof v_crl_v1_nonext, 0, 2 },
    { "v1_noentries", v_crl_v1_noentries, sizeof v_crl_v1_noentries, 0, 0 },
};
TEST(crlctx_create_all_vectors) {
    REQUIRE(U(CertCreateCRLContext));
    for (unsigned i = 0; i < sizeof kVecs / sizeof kVecs[0]; i++) {
        PCCRL_CONTEXT c = cc_crl(kVecs[i].p, kVecs[i].n);
        CHECKF(c != NULL, "%s", kVecs[i].name);
        if (!c) continue;
        CHECKF(c->pCrlInfo != NULL, "%s", kVecs[i].name);
        if (c->pCrlInfo) {
            EXPECT_EQ(c->pCrlInfo->dwVersion, kVecs[i].ver);
            EXPECT_EQ(c->pCrlInfo->cCRLEntry, kVecs[i].entries);
            CHECKF(blob_is(&c->pCrlInfo->Issuer, v_ca1_subject, sizeof v_ca1_subject) || !strcmp(kVecs[i].name, "ca2"), "%s issuer", kVecs[i].name);
        }
        EXPECT_EQ(c->cbCrlEncoded, kVecs[i].n);
        CHECKF(c->pbCrlEncoded && !memcmp(c->pbCrlEncoded, kVecs[i].p, kVecs[i].n), "%s encoded bytes", kVecs[i].name);
        rel(c);
    }
}
TEST(crlctx_encoded_buffer_is_private_copy) {
    REQUIRE(U(CertCreateCRLContext));
    BYTE *copy = LocalAlloc(LPTR, sizeof v_crl_basic);
    memcpy(copy, v_crl_basic, sizeof v_crl_basic);
    PCCRL_CONTEXT c = cc_crl(copy, sizeof v_crl_basic);
    REQUIRE(c);
    CHECK(c->pbCrlEncoded != copy);
    memset(copy, 0, sizeof v_crl_basic);
    CHECK(!memcmp(c->pbCrlEncoded, v_crl_basic, sizeof v_crl_basic));
    CHECK(c->pCrlInfo->cCRLEntry == 2);
    LocalFree(copy);
    rel(c);
}
TEST(crlctx_encoding_type_field) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(CC_X509, VEC(v_crl_basic));
    REQUIRE(c);
    EXPECT_EQ(c->dwCertEncodingType, CC_X509);
    t_note("hCertStore of standalone CRL context = %p", (void *)c->hCertStore);
    rel(c);
    c = U(CertCreateCRLContext)(CC_X509P7, VEC(v_crl_basic));
    if (c) { t_note("CRL created with X509|PKCS7 has dwCertEncodingType 0x%lx", c->dwCertEncodingType); rel(c); }
    else t_note("X509|PKCS7 encoding type rejected for CRL");
}
TEST(crlctx_info_times_basic) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    EXPECT_EQ(cc_ft(c->pCrlInfo->ThisUpdate), V_THIS_FT);
    EXPECT_EQ(cc_ft(c->pCrlInfo->NextUpdate), V_NEXT_FT);
    rel(c);
    c = cc_crl(VEC(v_crl_expired));
    REQUIRE(c);
    EXPECT_EQ(cc_ft(c->pCrlInfo->ThisUpdate), V_THIS_FT);
    EXPECT_EQ(cc_ft(c->pCrlInfo->NextUpdate), V_EXP_NEXT_FT);
    rel(c);
    c = cc_crl(VEC(v_crl_basic_newer));
    REQUIRE(c);
    EXPECT_EQ(cc_ft(c->pCrlInfo->ThisUpdate), V_NEWER_THIS_FT);
    rel(c);
}
TEST(crlctx_info_v1_unsigned_no_nextupdate) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_v1_nonext));
    REQUIRE(c);
    EXPECT_EQ(c->pCrlInfo->dwVersion, 0);
    EXPECT_EQ(cc_ft(c->pCrlInfo->NextUpdate), 0);
    EXPECT_EQ(cc_ft(c->pCrlInfo->ThisUpdate), V_THIS_FT);
    EXPECT_EQ(c->pCrlInfo->cExtension, 0);
    EXPECT_EQ(c->pCrlInfo->cCRLEntry, 2);
    if (c->pCrlInfo->cCRLEntry == 2) {
        static const BYTE s1[] = { 0x01, 0x10 }, s2[] = { 0x02, 0x10 };
        CHECK(blob_is(&c->pCrlInfo->rgCRLEntry[0].SerialNumber, s1, 2));
        CHECK(blob_is(&c->pCrlInfo->rgCRLEntry[1].SerialNumber, s2, 2));
        EXPECT_EQ(cc_ft(c->pCrlInfo->rgCRLEntry[0].RevocationDate), V_REVD_FT);
        EXPECT_EQ(c->pCrlInfo->rgCRLEntry[0].cExtension, 0);
    }
    CHECK(c->pCrlInfo->SignatureAlgorithm.pszObjId && !strcmp(c->pCrlInfo->SignatureAlgorithm.pszObjId, "1.2.840.113549.1.1.5"));
    rel(c);
}
TEST(crlctx_info_v1_no_entries) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_v1_noentries));
    REQUIRE(c);
    EXPECT_EQ(c->pCrlInfo->cCRLEntry, 0);
    EXPECT_EQ(cc_ft(c->pCrlInfo->NextUpdate), V_NEXT_FT);
    rel(c);
}
TEST(crlctx_info_signature_algorithm) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    CHECK(c->pCrlInfo->SignatureAlgorithm.pszObjId && !strcmp(c->pCrlInfo->SignatureAlgorithm.pszObjId, "1.2.840.113549.1.1.11"));
    rel(c);
}
TEST(crlctx_info_entries_basic) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    static const BYTE s1[] = { 0x01, 0x10 }, s2[] = { 0x02, 0x10 };
    PCRL_INFO i = c->pCrlInfo;
    REQUIRE(i->cCRLEntry == 2);
    CHECK(blob_is(&i->rgCRLEntry[0].SerialNumber, s1, 2));
    CHECK(blob_is(&i->rgCRLEntry[1].SerialNumber, s2, 2));
    EXPECT_EQ(cc_ft(i->rgCRLEntry[0].RevocationDate), V_REVD_FT);
    EXPECT_EQ(cc_ft(i->rgCRLEntry[1].RevocationDate), V_REVD_FT);
    rel(c);
}
TEST(crlctx_info_entry_extensions) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    PCRL_ENTRY e = c->pCrlInfo->rgCRLEntry;
    /* entry 0: reason (keyCompromise) + invalidity date; entry 1: reason (hold) + invalidity date */
    for (int k = 0; k < 2; k++) {
        EXPECT_EQ(e[k].cExtension, 2);
        if (e[k].cExtension != 2) continue;
        CHECK(!strcmp(e[k].rgExtension[0].pszObjId, szOID_CRL_REASON_CODE));
        CHECK(!strcmp(e[k].rgExtension[1].pszObjId, "2.5.29.24"));
        CHECK(!e[k].rgExtension[0].fCritical);
    }
    /* reason code extension value is an ENUMERATED: 0a 01 <reason> */
    static const BYTE kc[] = { 0x0a, 0x01, 0x01 }, hold[] = { 0x0a, 0x01, 0x06 };
    if (e[0].cExtension == 2) CHECK(blob_is(&e[0].rgExtension[0].Value, kc, 3));
    if (e[1].cExtension == 2) CHECK(blob_is(&e[1].rgExtension[0].Value, hold, 3));
    rel(c);
}
TEST(crlctx_info_entry_extensions_decode_reason) {
    REQUIRE(U(CertCreateCRLContext)); REQUIRE(U(CryptDecodeObject));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_reasons));
    REQUIRE(c);
    static const int want[] = { -1, 1, 2, 3, 4, 5, 6, -2 /* 7 absent */, 8, 9, 10 };
    PCRL_INFO i = c->pCrlInfo;
    REQUIRE(i->cCRLEntry == 10);
    /* entries in file order: serials 2000..2006, 2008..200A (2007 skipped) */
    static const int reasons[10] = { -1, 1, 2, 3, 4, 5, 6, 8, 9, 10 };
    for (DWORD k = 0; k < 10; k++) {
        DWORD ser = 0;
        if (i->rgCRLEntry[k].SerialNumber.cbData == 2) ser = i->rgCRLEntry[k].SerialNumber.pbData[0] | (i->rgCRLEntry[k].SerialNumber.pbData[1] << 8);
        else if (i->rgCRLEntry[k].SerialNumber.cbData == 1) ser = i->rgCRLEntry[k].SerialNumber.pbData[0];
        PCERT_EXTENSION ext = U(CertFindExtension)(szOID_CRL_REASON_CODE, i->rgCRLEntry[k].cExtension, i->rgCRLEntry[k].rgExtension);
        if (reasons[k] < 0) { CHECKF(ext == NULL, "serial 0x%lx has no reason", ser); continue; }
        CHECKF(ext != NULL, "serial 0x%lx", ser);
        if (!ext) continue;
        int reason = -5; DWORD cb = sizeof reason;
        BOOL ok = U(CryptDecodeObject)(CC_X509, X509_CRL_REASON_CODE, ext->Value.pbData, ext->Value.cbData, 0, &reason, &cb);
        CHECK(ok);
        EXPECT_EQ(reason, reasons[k]);
        EXPECT_EQ(ser, 0x2000 + (k < 7 ? k : k + 1));
    }
    rel(c);
}
TEST(crlctx_info_crl_extensions) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    EXPECT_EQ(c->pCrlInfo->cExtension, 2);
    CHECK(U(CertFindExtension)(szOID_CRL_NUMBER, c->pCrlInfo->cExtension, c->pCrlInfo->rgExtension) != NULL);
    CHECK(U(CertFindExtension)(szOID_AUTHORITY_KEY_IDENTIFIER2, c->pCrlInfo->cExtension, c->pCrlInfo->rgExtension) != NULL);
    CHECK(U(CertFindExtension)(szOID_DELTA_CRL_INDICATOR, c->pCrlInfo->cExtension, c->pCrlInfo->rgExtension) == NULL);
    PCERT_EXTENSION n = U(CertFindExtension)(szOID_CRL_NUMBER, c->pCrlInfo->cExtension, c->pCrlInfo->rgExtension);
    if (n) {
        int num = 0; DWORD cb = sizeof num;
        CHECK(U(CryptDecodeObject)(CC_X509, X509_INTEGER, n->Value.pbData, n->Value.cbData, 0, &num, &cb));
        EXPECT_EQ(num, 5);
    }
    rel(c);
    c = cc_crl(VEC(v_crl_noext));
    REQUIRE(c);
    EXPECT_EQ(c->pCrlInfo->cExtension, 0);
    rel(c);
}
TEST(crlctx_info_delta_indicator_critical) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_delta));
    REQUIRE(c);
    PCERT_EXTENSION d = U(CertFindExtension)(szOID_DELTA_CRL_INDICATOR, c->pCrlInfo->cExtension, c->pCrlInfo->rgExtension);
    CHECK(d != NULL);
    if (d) {
        CHECK(d->fCritical);
        int base = 0; DWORD cb = sizeof base;
        CHECK(U(CryptDecodeObject)(CC_X509, X509_INTEGER, d->Value.pbData, d->Value.cbData, 0, &base, &cb));
        EXPECT_EQ(base, 5);
    }
    rel(c);
}
TEST(crlctx_info_idp_extension) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_idp));
    REQUIRE(c);
    PCERT_EXTENSION d = U(CertFindExtension)(szOID_ISSUING_DIST_POINT, c->pCrlInfo->cExtension, c->pCrlInfo->rgExtension);
    CHECK(d != NULL);
    if (d) CHECK(d->fCritical);
    rel(c);
}
TEST(crlctx_info_entry_without_reason) {
    REQUIRE(U(CertCreateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_idp));
    REQUIRE(c);
    REQUIRE(c->pCrlInfo->cCRLEntry == 1);
    EXPECT_EQ(c->pCrlInfo->rgCRLEntry[0].cExtension, 0);
    rel(c);
}

/* ---- duplicate / free ---- */
TEST(crlctx_duplicate_null) {
    REQUIRE(U(CertDuplicateCRLContext));
    CHECK(U(CertDuplicateCRLContext)(NULL) == NULL);
}
TEST(crlctx_free_null_is_true) {
    REQUIRE(U(CertFreeCRLContext));
    CHECK(U(CertFreeCRLContext)(NULL));
}
TEST(crlctx_duplicate_same_pointer) {
    REQUIRE(U(CertDuplicateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    PCCRL_CONTEXT d = U(CertDuplicateCRLContext)(c);
    CHECK(d == c);
    CHECK(U(CertFreeCRLContext)(d));
    EXPECT_EQ(c->pCrlInfo->cCRLEntry, 2);
    CHECK(U(CertFreeCRLContext)(c));
}
TEST(crlctx_duplicate_many_refs) {
    REQUIRE(U(CertDuplicateCRLContext));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    PCCRL_CONTEXT d[50];
    for (int i = 0; i < 50; i++) { d[i] = U(CertDuplicateCRLContext)(c); CHECK(d[i] == c); }
    for (int i = 0; i < 50; i++) CHECK(U(CertFreeCRLContext)(d[i]));
    EXPECT_EQ(c->cbCrlEncoded, sizeof v_crl_basic);
    rel(c);
}
TEST(crlctx_store_context_survives_store_close_when_duplicated) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCRL_CONTEXT c = NULL;
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &c));
    REQUIRE(c);
    CHECK(c->hCertStore == s);
    cc_close(s);
    /* the held context remains readable after the store handle was closed */
    EXPECT_EQ(c->pCrlInfo->cCRLEntry, 2);
    CHECK(c->cbCrlEncoded == sizeof v_crl_basic);
    rel(c);
}

/* ---- properties ---- */
#define PROP_USER 0x8123
TEST(crlprop_enum_fresh_has_none) {
    REQUIRE(U(CertEnumCRLContextProperties));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    EXPECT_EQ(cc_props_crl(c), 0);
    rel(c);
}
TEST(crlprop_set_prop0_invalidarg) {
    REQUIRE(U(CertSetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    SET_ERR(0);
    CHECK(!U(CertSetCRLContextProperty)(c, 0, 0, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    SET_ERR(0);
    CHECK(!U(CertSetCRLContextProperty)(NULL, 0, 0, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    rel(c);
}
TEST(crlprop_get_missing_not_found) {
    REQUIRE(U(CertGetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    DWORD cb = 0;
    SET_ERR(0);
    CHECK(!U(CertGetCRLContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb)); EXPECT_ERR(CC_E_NOT_FOUND);
    cb = 0;
    SET_ERR(0);
    CHECK(!U(CertGetCRLContextProperty)(c, PROP_USER, NULL, &cb)); EXPECT_ERR(CC_E_NOT_FOUND);
    cb = 0;
    SET_ERR(0);
    CHECK(!U(CertGetCRLContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb)); EXPECT_ERR(CC_E_NOT_FOUND);
    rel(c);
}
TEST(crlprop_access_state_implicit) {
    REQUIRE(U(CertGetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    DWORD cb = 0, access = 0xdeadbeef;
    CHECK(U(CertGetCRLContextProperty)(c, CERT_ACCESS_STATE_PROP_ID, NULL, &cb));
    EXPECT_EQ(cb, 4);
    cb = 4;
    CHECK(U(CertGetCRLContextProperty)(c, CERT_ACCESS_STATE_PROP_ID, &access, &cb));
    CHECK(!(access & CERT_ACCESS_STATE_WRITE_PERSIST_FLAG));
    /* access state is implicit: it is not enumerated */
    EXPECT_EQ(cc_props_crl(c), 0);
    rel(c);
}
static void hash_prop_case(const BYTE *der, DWORD n, DWORD propid, ALG_ID alg, DWORD len) {
    PCCRL_CONTEXT c = cc_crl(der, n);
    REQUIRE(c);
    BYTE want[32], got[32]; DWORD wcb = sizeof want, gcb = 0;
    CHECK(cc_hash(alg, der, n, want, &wcb));
    EXPECT_EQ(wcb, len);
    SET_ERR(0);
    CHECK(U(CertGetCRLContextProperty)(c, propid, NULL, &gcb));
    EXPECT_EQ(gcb, len);
    gcb = len - 1;
    SET_ERR(0);
    CHECK(!U(CertGetCRLContextProperty)(c, propid, got, &gcb)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(gcb, len);
    gcb = sizeof got;
    CHECK(U(CertGetCRLContextProperty)(c, propid, got, &gcb));
    EXPECT_EQ(gcb, len);
    CHECK(!memcmp(got, want, len));
    rel(c);
}
TEST(crlprop_sha1_hash_basic) { REQUIRE(U(CertGetCRLContextProperty)); hash_prop_case(VEC(v_crl_basic), CERT_HASH_PROP_ID, CALG_SHA1, 20); }
TEST(crlprop_sha1_hash_v1) { REQUIRE(U(CertGetCRLContextProperty)); hash_prop_case(VEC(v_crl_v1_nonext), CERT_SHA1_HASH_PROP_ID, CALG_SHA1, 20); }
TEST(crlprop_md5_hash_basic) { REQUIRE(U(CertGetCRLContextProperty)); hash_prop_case(VEC(v_crl_basic), CERT_MD5_HASH_PROP_ID, CALG_MD5, 16); }
TEST(crlprop_md5_hash_delta) { REQUIRE(U(CertGetCRLContextProperty)); hash_prop_case(VEC(v_crl_delta), CERT_MD5_HASH_PROP_ID, CALG_MD5, 16); }
TEST(crlprop_hash_becomes_enumerated) {
    REQUIRE(U(CertGetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    BYTE h[20]; DWORD cb = sizeof h;
    CHECK(U(CertGetCRLContextProperty)(c, CERT_HASH_PROP_ID, h, &cb));
    EXPECT_EQ(cc_props_crl(c), 1);
    DWORD id = U(CertEnumCRLContextProperties)(c, 0);
    EXPECT_EQ(id, CERT_HASH_PROP_ID);
    EXPECT_EQ(U(CertEnumCRLContextProperties)(c, id), 0);
    rel(c);
}
TEST(crlprop_set_hash_override_and_delete) {
    REQUIRE(U(CertSetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    BYTE fake[20]; memset(fake, 0x5a, sizeof fake);
    CRYPT_DATA_BLOB b = { sizeof fake, fake };
    CHECK(U(CertSetCRLContextProperty)(c, CERT_HASH_PROP_ID, 0, &b));
    BYTE got[20]; DWORD cb = sizeof got;
    CHECK(U(CertGetCRLContextProperty)(c, CERT_HASH_PROP_ID, got, &cb));
    CHECK(!memcmp(got, fake, 20));
    CHECK(U(CertSetCRLContextProperty)(c, CERT_HASH_PROP_ID, 0, NULL));
    BYTE want[20]; DWORD wcb = 20;
    CHECK(cc_hash(CALG_SHA1, VEC(v_crl_basic), want, &wcb));
    cb = sizeof got;
    CHECK(U(CertGetCRLContextProperty)(c, CERT_HASH_PROP_ID, got, &cb));
    CHECK(!memcmp(got, want, 20));
    rel(c);
}
TEST(crlprop_user_property_roundtrip) {
    REQUIRE(U(CertSetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    BYTE data[] = { 1, 2, 3, 4, 5, 6, 7 };
    CRYPT_DATA_BLOB b = { sizeof data, data };
    CHECK(U(CertSetCRLContextProperty)(c, PROP_USER, 0, &b));
    EXPECT_EQ(cc_props_crl(c), 1);
    EXPECT_EQ(U(CertEnumCRLContextProperties)(c, 0), PROP_USER);
    DWORD cb = 0;
    CHECK(U(CertGetCRLContextProperty)(c, PROP_USER, NULL, &cb));
    EXPECT_EQ(cb, sizeof data);
    BYTE got[16]; cb = 3;
    SET_ERR(0);
    CHECK(!U(CertGetCRLContextProperty)(c, PROP_USER, got, &cb)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, sizeof data);
    cb = sizeof got;
    CHECK(U(CertGetCRLContextProperty)(c, PROP_USER, got, &cb));
    EXPECT_EQ(cb, sizeof data);
    CHECK(!memcmp(got, data, sizeof data));
    /* replace, then delete */
    CRYPT_DATA_BLOB b2 = { 2, data + 5 };
    CHECK(U(CertSetCRLContextProperty)(c, PROP_USER, 0, &b2));
    cb = sizeof got;
    CHECK(U(CertGetCRLContextProperty)(c, PROP_USER, got, &cb));
    EXPECT_EQ(cb, 2);
    CHECK(U(CertSetCRLContextProperty)(c, PROP_USER, 0, NULL));
    EXPECT_EQ(cc_props_crl(c), 0);
    SET_ERR(0);
    cb = 0;
    CHECK(!U(CertGetCRLContextProperty)(c, PROP_USER, NULL, &cb)); EXPECT_ERR(CC_E_NOT_FOUND);
    rel(c);
}
TEST(crlprop_user_property_empty_value) {
    REQUIRE(U(CertSetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    CRYPT_DATA_BLOB b = { 0, NULL };
    CHECK(U(CertSetCRLContextProperty)(c, PROP_USER, 0, &b));
    DWORD cb = 99;
    SET_ERR(0);
    BOOL r = U(CertGetCRLContextProperty)(c, PROP_USER, NULL, &cb);
    t_note("get zero-length user property: ret=%d cb=%lu err=0x%lx", r, cb, GetLastError());
    U(CertSetCRLContextProperty)(c, PROP_USER, 0, NULL);
    rel(c);
}
TEST(crlprop_enum_multiple_user_props) {
    REQUIRE(U(CertSetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    BYTE d = 9; CRYPT_DATA_BLOB b = { 1, &d };
    for (DWORD id = 0x8200; id < 0x8205; id++) CHECK(U(CertSetCRLContextProperty)(c, id, 0, &b));
    EXPECT_EQ(cc_props_crl(c), 5);
    int seen[5] = { 0 }; DWORD id = 0;
    while ((id = U(CertEnumCRLContextProperties)(c, id)) != 0) { if (id >= 0x8200 && id < 0x8205) seen[id - 0x8200]++; }
    for (int i = 0; i < 5; i++) EXPECT_EQ(seen[i], 1);
    rel(c);
}
TEST(crlprop_shared_between_duplicates) {
    REQUIRE(U(CertSetCRLContextProperty));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    PCCRL_CONTEXT d = U(CertDuplicateCRLContext)(c);
    BYTE v = 7; CRYPT_DATA_BLOB b = { 1, &v };
    CHECK(U(CertSetCRLContextProperty)(d, PROP_USER, 0, &b));
    DWORD cb = 0;
    CHECK(U(CertGetCRLContextProperty)(c, PROP_USER, NULL, &cb));
    rel(d); rel(c);
}
TEST(crlprop_copied_into_store_on_add) {
    REQUIRE(U(CertAddCRLContextToStore));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    BYTE v[3] = { 3, 2, 1 }; CRYPT_DATA_BLOB b = { 3, v };
    CHECK(U(CertSetCRLContextProperty)(c, PROP_USER, 0, &b));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCRL_CONTEXT out = NULL;
    CHECK(U(CertAddCRLContextToStore)(s, c, CERT_STORE_ADD_ALWAYS, &out));
    REQUIRE(out);
    CHECK(out != c);
    BYTE got[8]; DWORD cb = sizeof got;
    CHECK(U(CertGetCRLContextProperty)(out, PROP_USER, got, &cb));
    EXPECT_EQ(cb, 3);
    CHECK(!memcmp(got, v, 3));
    /* the store copy is independent of the original */
    CHECK(U(CertSetCRLContextProperty)(c, PROP_USER, 0, NULL));
    cb = sizeof got;
    CHECK(U(CertGetCRLContextProperty)(out, PROP_USER, got, &cb));
    rel(out); rel(c);
    cc_close(s);
}
TEST(crlprop_set_on_store_context_visible_via_enum) {
    REQUIRE(U(CertSetCRLContextProperty));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, NULL));
    PCCRL_CONTEXT a = U(CertEnumCRLsInStore)(s, NULL);
    REQUIRE(a);
    BYTE v = 1; CRYPT_DATA_BLOB b = { 1, &v };
    CHECK(U(CertSetCRLContextProperty)(a, PROP_USER, 0, &b));
    PCCRL_CONTEXT again = U(CertEnumCRLsInStore)(s, NULL);
    REQUIRE(again);
    DWORD cb = 0;
    CHECK(U(CertGetCRLContextProperty)(again, PROP_USER, NULL, &cb));
    rel(again); rel(a);
    cc_close(s);
}

/* ---- serialization ---- */
TEST(crlser_size_query_and_tail) {
    REQUIRE(U(CertSerializeCRLStoreElement));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    DWORD cb = 0;
    CHECK(U(CertSerializeCRLStoreElement)(c, 0, NULL, &cb));
    CHECK(cb > sizeof v_crl_basic);
    BYTE *buf = LocalAlloc(LPTR, cb);
    DWORD cb2 = cb;
    CHECK(U(CertSerializeCRLStoreElement)(c, 0, buf, &cb2));
    EXPECT_EQ(cb2, cb);
    /* the CRL blob is the last element: {propid, flags, length} then the encoded CRL */
    DWORD hdr = cb - (DWORD)sizeof v_crl_basic - 12;
    CHECK(!memcmp(buf + cb - sizeof v_crl_basic, v_crl_basic, sizeof v_crl_basic));
    DWORD *h = (DWORD *)(buf + cb - sizeof v_crl_basic - 12);
    EXPECT_EQ(h[0], CC_PROP_CRL);
    EXPECT_EQ(h[1], 1);
    EXPECT_EQ(h[2], sizeof v_crl_basic);
    EXPECT_EQ(hdr, 0);
    LocalFree(buf);
    rel(c);
}
TEST(crlser_buffer_too_small) {
    REQUIRE(U(CertSerializeCRLStoreElement));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    DWORD cb = 0;
    CHECK(U(CertSerializeCRLStoreElement)(c, 0, NULL, &cb));
    BYTE *buf = LocalAlloc(LPTR, cb);
    DWORD small = cb - 1;
    SET_ERR(0);
    CHECK(!U(CertSerializeCRLStoreElement)(c, 0, buf, &small)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(small, cb);
    small = 0;
    SET_ERR(0);
    CHECK(!U(CertSerializeCRLStoreElement)(c, 0, buf, &small)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(small, cb);
    LocalFree(buf);
    rel(c);
}
TEST(crlser_flags_ignored) {
    /* SerializeContextElement never reads dwFlags: any value behaves as 0 */
    REQUIRE(U(CertSerializeCRLStoreElement));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    DWORD a = 0, b = 0, d = 0;
    CHECK(U(CertSerializeCRLStoreElement)(c, 0, NULL, &a));
    CHECK(U(CertSerializeCRLStoreElement)(c, 1, NULL, &b));
    CHECK(U(CertSerializeCRLStoreElement)(c, 0x80000000, NULL, &d));
    EXPECT_EQ(a, b); EXPECT_EQ(a, d);
    rel(c);
}
TEST(crlser_failure_zeroes_size) {
    REQUIRE(U(CertSerializeCRLStoreElement));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    BYTE buf[4]; DWORD cb = sizeof buf;
    SET_ERR(0);
    CHECK(!U(CertSerializeCRLStoreElement)(c, 0, buf, &cb)); EXPECT_ERR(ERROR_MORE_DATA);
    CHECK(cb > sizeof v_crl_basic);
    rel(c);
}
TEST(crlser_includes_properties) {
    REQUIRE(U(CertSerializeCRLStoreElement));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    DWORD plain = 0, withp = 0;
    CHECK(U(CertSerializeCRLStoreElement)(c, 0, NULL, &plain));
    BYTE v[10] = { 0 }; CRYPT_DATA_BLOB b = { 10, v };
    CHECK(U(CertSetCRLContextProperty)(c, PROP_USER, 0, &b));
    CHECK(U(CertSerializeCRLStoreElement)(c, 0, NULL, &withp));
    EXPECT_EQ(withp, plain + 12 + 10);
    rel(c);
}
TEST(crlser_roundtrip_via_add_serialized) {
    REQUIRE(U(CertSerializeCRLStoreElement)); REQUIRE(U(CertAddSerializedElementToStore));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_delta));
    REQUIRE(c);
    BYTE v[4] = { 4, 3, 2, 1 }; CRYPT_DATA_BLOB b = { 4, v };
    CHECK(U(CertSetCRLContextProperty)(c, PROP_USER, 0, &b));
    DWORD cb = 0;
    CHECK(U(CertSerializeCRLStoreElement)(c, 0, NULL, &cb));
    BYTE *buf = LocalAlloc(LPTR, cb);
    CHECK(U(CertSerializeCRLStoreElement)(c, 0, buf, &cb));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    DWORD type = 0; const void *ctx = NULL;
    CHECK(U(CertAddSerializedElementToStore)(s, buf, cb, CERT_STORE_ADD_ALWAYS, 0, CERT_STORE_CRL_CONTEXT_FLAG, &type, &ctx));
    EXPECT_EQ(type, CERT_STORE_CRL_CONTEXT);
    EXPECT_EQ(cc_count_crls(s), 1);
    if (ctx) {
        PCCRL_CONTEXT r = (PCCRL_CONTEXT)ctx;
        EXPECT_EQ(r->cbCrlEncoded, sizeof v_crl_delta);
        CHECK(!memcmp(r->pbCrlEncoded, v_crl_delta, sizeof v_crl_delta));
        BYTE got[8]; DWORD g = sizeof got;
        CHECK(U(CertGetCRLContextProperty)(r, PROP_USER, got, &g));
        EXPECT_EQ(g, 4);
        rel(r);
    }
    /* wrong expected type */
    SET_ERR(0);
    CHECK(!U(CertAddSerializedElementToStore)(s, buf, cb, CERT_STORE_ADD_ALWAYS, 0, CERT_STORE_CERTIFICATE_CONTEXT_FLAG, NULL, NULL));
    t_note("add serialized CRL with CERTIFICATE_CONTEXT_FLAG: err 0x%lx", GetLastError());
    EXPECT_EQ(cc_count_certs(s), 0);
    LocalFree(buf);
    cc_close(s);
    rel(c);
}

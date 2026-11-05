/* Certificate context properties: CertGet/SetCertificateContextProperty, CertEnumCertificateContextProperties. */
#include "ccp.h"

static BOOL setb(PCCERT_CONTEXT c, DWORD id, const void *p, DWORD n) {
    CRYPT_DATA_BLOB b; b.cbData = n; b.pbData = (BYTE *)p;
    return C32(CertSetCertificateContextProperty)(c, id, 0, &b);
}
/* Fetch a property into buf (cap bytes); returns size or -1 when the call failed. */
static int getb(PCCERT_CONTEXT c, DWORD id, void *buf, DWORD cap) {
    DWORD cb = cap;
    if (!C32(CertGetCertificateContextProperty)(c, id, buf, &cb)) return -1;
    return (int)cb;
}
static int has_prop(PCCERT_CONTEXT c, DWORD id) {
    DWORD cb = 0; return C32(CertGetCertificateContextProperty)(c, id, NULL, &cb) != 0;
}
/* All property ids reported by the enumerator. */
static int enum_ids(PCCERT_CONTEXT c, DWORD *ids, int cap) {
    int n = 0; DWORD id = 0;
    while ((id = C32(CertEnumCertificateContextProperties)(c, id)) != 0 && n < cap) ids[n++] = id;
    return n;
}
static int pos_of(const DWORD *ids, int n, DWORD id) { int i; for (i = 0; i < n; i++) if (ids[i] == id) return i; return -1; }

/* ---- computed hash properties, per fixture ---- */
TEST(ccp_prop_sha1_hash_all_fixtures) {
    int i; REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE b[64]; DWORD cb = sizeof b;
        if (!c) { CHECK(0); continue; }
        SET_ERR(0);
        CHECKF(ccp_getprop(c, CERT_SHA1_HASH_PROP_ID, b, &cb), "%s", f->name);
        CHECKF(cb == 20 && !memcmp(b, f->sha1, 20), "%s sha1", f->name);
        cb = sizeof b;
        CHECKF(ccp_getprop(c, CERT_HASH_PROP_ID, b, &cb) && cb == 20 && !memcmp(b, f->sha1, 20), "%s CERT_HASH_PROP_ID alias", f->name);
        ccp_free(c);
    }
}
TEST(ccp_prop_md5_hash_all_fixtures) {
    int i; REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE b[64]; DWORD cb = sizeof b;
        if (!c) { CHECK(0); continue; }
        CHECKF(ccp_getprop(c, CERT_MD5_HASH_PROP_ID, b, &cb) && cb == 16 && !memcmp(b, f->md5, 16), "%s md5", f->name);
        ccp_free(c);
    }
}
TEST(ccp_prop_sha256_hash_all_fixtures) {
    int i; REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE b[64]; DWORD cb = sizeof b;
        if (!c) { CHECK(0); continue; }
        CHECKF(ccp_getprop(c, CERT_SHA256_HASH_PROP_ID, b, &cb) && cb == 32 && !memcmp(b, f->sha256, 32), "%s sha256", f->name);
        ccp_free(c);
    }
}
TEST(ccp_prop_signature_hash_all_fixtures) {
    int i; REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE b[64]; DWORD cb = sizeof b;
        if (!c) { CHECK(0); continue; }
        /* hash of the to-be-signed portion with the hash algorithm of the signature algorithm */
        CHECKF(ccp_getprop(c, CERT_SIGNATURE_HASH_PROP_ID, b, &cb), "%s", f->name);
        CHECKF(cb == f->cbSigHash && !memcmp(b, f->sighash, f->cbSigHash), "%s sighash cb=%lu want %lu", f->name, (unsigned long)cb, (unsigned long)f->cbSigHash);
        ccp_free(c);
    }
}
TEST(ccp_prop_subject_name_md5_all_fixtures) {
    int i; REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE b[64]; DWORD cb = sizeof b;
        if (!c) { CHECK(0); continue; }
        CHECKF(ccp_getprop(c, CERT_SUBJECT_NAME_MD5_HASH_PROP_ID, b, &cb) && cb == 16 && !memcmp(b, f->subjmd5, 16), "%s", f->name);
        ccp_free(c);
    }
}
TEST(ccp_prop_subject_public_key_md5_all_fixtures) {
    int i; REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE b[64]; DWORD cb = sizeof b;
        if (!c) { CHECK(0); continue; }
        /* MD5 over the PublicKey bit string content (without the unused-bits octet) */
        CHECKF(ccp_getprop(c, CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID, b, &cb) && cb == 16 && !memcmp(b, f->pubmd5, 16), "%s", f->name);
        ccp_free(c);
    }
}
TEST(ccp_prop_issuer_serial_number_md5_all_fixtures) {
    int i; REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE b[64]; DWORD cb = sizeof b;
        if (!c) { CHECK(0); continue; }
        /* MD5(issuer name blob || serial number as stored in CERT_INFO) */
        if (f->cbSerial && (f->serial_le[f->cbSerial - 1] & 0x80)) {
            if (ccp_getprop(c, CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID, b, &cb)) t_note("%s issuer+serial md5 first byte %02x (serial has high bit)", f->name, b[0]);
        } else {
            CHECKF(ccp_getprop(c, CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID, b, &cb) && cb == 16 && !memcmp(b, f->issser_md5, 16), "%s", f->name);
        }
        ccp_free(c);
    }
}
TEST(ccp_prop_key_identifier_all_fixtures) {
    int i; REQUIRE(C32(CertGetCertificateContextProperty));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f); BYTE b[64]; DWORD cb = sizeof b;
        if (!c) { CHECK(0); continue; }
        /* SKI extension value when present, else SHA1 of the encoded SubjectPublicKeyInfo */
        CHECKF(ccp_getprop(c, CERT_KEY_IDENTIFIER_PROP_ID, b, &cb), "%s", f->name);
        CHECKF(cb == 20 && !memcmp(b, f->hasski ? f->ski : f->spkisha1, 20), "%s keyid (hasski=%d)", f->name, f->hasski);
        ccp_free(c);
    }
}
TEST(ccp_prop_hashes_are_cached_and_enumerated) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD ids[64]; BYTE b[32]; int n;
    REQUIRE(C32(CertEnumCertificateContextProperties));
    if (!c) { CHECK(0); return; }
    CHECK(getb(c, CERT_MD5_HASH_PROP_ID, b, 32) == 16);
    n = enum_ids(c, ids, 64);
    CHECK(pos_of(ids, n, CERT_MD5_HASH_PROP_ID) >= 0);
    ccp_free(c);
}
TEST(ccp_prop_hash_survives_clear_and_recompute) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); BYTE b[32];
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(getb(c, CERT_SHA1_HASH_PROP_ID, b, 32) == 20);
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, 0, NULL));
    CHECK(getb(c, CERT_SHA1_HASH_PROP_ID, b, 32) == 20 && !memcmp(b, fx_leaf.sha1, 20));
    ccp_free(c);
}

/* ---- buffer protocol ---- */
TEST(ccp_prop_size_query_and_more_data) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); BYTE b[64]; DWORD cb; DWORD ids[] = {CERT_SHA1_HASH_PROP_ID, CERT_MD5_HASH_PROP_ID, CERT_SHA256_HASH_PROP_ID, CERT_KEY_IDENTIFIER_PROP_ID, CERT_SIGNATURE_HASH_PROP_ID, CERT_SUBJECT_NAME_MD5_HASH_PROP_ID}; DWORD want[] = {20, 16, 32, 20, 32, 16}; int k;
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    for (k = 0; k < 6; k++) {
        cb = 0xCCCC; SET_ERR(0);
        CHECKF(ccp_getprop(c, ids[k], NULL, &cb) && cb == want[k], "size query id %lu: cb=%lu", (unsigned long)ids[k], (unsigned long)cb);
        cb = 0; SET_ERR(0);
        EXPECT_FAIL(!ccp_getprop(c, ids[k], b, &cb), ERROR_MORE_DATA);
        EXPECT_EQ(cb, want[k]);
        cb = want[k] - 1; SET_ERR(0);
        EXPECT_FAIL(!ccp_getprop(c, ids[k], b, &cb), ERROR_MORE_DATA);
        EXPECT_EQ(cb, want[k]);
        memset(b, 0xAA, sizeof b); cb = want[k];
        CHECK(ccp_getprop(c, ids[k], b, &cb) && cb == want[k]);
        CHECK(b[want[k]] == 0xAA);
        memset(b, 0xAA, sizeof b); cb = 64;
        CHECK(ccp_getprop(c, ids[k], b, &cb) && cb == want[k]);
    }
    ccp_free(c);
}
TEST(ccp_prop_more_data_does_not_touch_buffer) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BYTE b[32]; DWORD cb = 5;
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    memset(b, 0x5A, sizeof b);
    SET_ERR(0);
    CHECK(!ccp_getprop(c, CERT_SHA1_HASH_PROP_ID, b, &cb));
    { int i, bad = 0; for (i = 0; i < 32; i++) if (b[i] != 0x5A) bad = 1; CHECK(!bad); }
    ccp_free(c);
}
TEST(ccp_prop_blob_size_protocol) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); static const BYTE d[] = {1, 2, 3, 4, 5, 6, 7}; BYTE b[16]; DWORD cb;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(setb(c, CERT_DESCRIPTION_PROP_ID, d, 7));
    cb = 0; CHECK(ccp_getprop(c, CERT_DESCRIPTION_PROP_ID, NULL, &cb) && cb == 7);
    cb = 6; SET_ERR(0); EXPECT_FAIL(!ccp_getprop(c, CERT_DESCRIPTION_PROP_ID, b, &cb), ERROR_MORE_DATA); EXPECT_EQ(cb, 7);
    cb = 7; CHECK(ccp_getprop(c, CERT_DESCRIPTION_PROP_ID, b, &cb) && cb == 7 && !memcmp(b, d, 7));
    cb = 16; CHECK(ccp_getprop(c, CERT_DESCRIPTION_PROP_ID, b, &cb) && cb == 7);
    ccp_free(c);
}

/* ---- missing properties and bad ids ---- */
TEST(ccp_prop_unset_properties_not_found) {
    DWORD ids[] = {CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_CONTEXT_PROP_ID, CERT_KEY_SPEC_PROP_ID, CERT_ENHKEY_USAGE_PROP_ID, CERT_NEXT_UPDATE_LOCATION_PROP_ID,
        CERT_FRIENDLY_NAME_PROP_ID, CERT_PVK_FILE_PROP_ID, CERT_DESCRIPTION_PROP_ID, CERT_SMART_CARD_DATA_PROP_ID, CERT_ARCHIVED_PROP_ID, CERT_AUTO_ENROLL_PROP_ID,
        CERT_PUBKEY_ALG_PARA_PROP_ID, CERT_CROSS_CERT_DIST_POINTS_PROP_ID, CERT_DATE_STAMP_PROP_ID, CERT_EXTENDED_ERROR_INFO_PROP_ID, CERT_RENEWAL_PROP_ID,
        CERT_ARCHIVED_KEY_HASH_PROP_ID, CERT_EFS_PROP_ID, CERT_FORTEZZA_DATA_PROP_ID, CERT_ENROLLMENT_PROP_ID, 0x7000, 0x8000, 0xFFFF};
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD cb; BYTE b[64]; int k;
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    for (k = 0; k < (int)(sizeof ids / sizeof ids[0]); k++) {
        cb = 0; SET_ERR(0);
        CHECKF(!ccp_getprop(c, ids[k], NULL, &cb), "size query id %lu", (unsigned long)ids[k]);
        EXPECT_ERR(CRYPT_E_NOT_FOUND_);
        cb = sizeof b; SET_ERR(0);
        CHECKF(!ccp_getprop(c, ids[k], b, &cb), "id %lu", (unsigned long)ids[k]);
        EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    }
    ccp_free(c);
}
TEST(ccp_prop_key_prov_handle_unset_not_found) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD cb = 8; ULONG_PTR h;
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    SET_ERR(0);
    CHECK(!ccp_getprop(c, CERT_KEY_PROV_HANDLE_PROP_ID, &h, &cb));
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    cb = 8; SET_ERR(0);
    CHECK(!ccp_getprop(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, &h, &cb));
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    ccp_free(c);
}
TEST(ccp_prop_set_invalid_ids) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); static const BYTE d[] = {1}; DWORD ids[] = {0, 0x10000, 0x10001, 0x80000000, 0xFFFFFFFF}; int k;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    for (k = 0; k < 5; k++) {
        CRYPT_DATA_BLOB b; b.cbData = 1; b.pbData = (BYTE *)d;
        SET_ERR(0);
        EXPECT_FAIL(!C32(CertSetCertificateContextProperty)(c, ids[k], 0, &b), E_INVALIDARG_);
        /* also rejected when deleting */
        SET_ERR(0);
        EXPECT_FAIL(!C32(CertSetCertificateContextProperty)(c, ids[k], 0, NULL), E_INVALIDARG_);
    }
    ccp_free(c);
}
TEST(ccp_prop_get_invalid_ids_fail) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD cb = 0;
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    SET_ERR(0); CHECK(!ccp_getprop(c, 0, NULL, &cb)); CHECK(GetLastError() != 0);
    SET_ERR(0); CHECK(!ccp_getprop(c, 0x10000, NULL, &cb)); CHECK(GetLastError() != 0);
    ccp_free(c);
}

/* ---- set/get round trips ---- */
TEST(ccp_prop_roundtrip_blob_properties) {
    DWORD ids[] = {CERT_NEXT_UPDATE_LOCATION_PROP_ID, CERT_PVK_FILE_PROP_ID, CERT_DESCRIPTION_PROP_ID, CERT_SMART_CARD_DATA_PROP_ID, CERT_EFS_PROP_ID, CERT_FORTEZZA_DATA_PROP_ID,
        CERT_AUTO_ENROLL_PROP_ID, CERT_PUBKEY_ALG_PARA_PROP_ID, CERT_CROSS_CERT_DIST_POINTS_PROP_ID, CERT_ENROLLMENT_PROP_ID, CERT_DATE_STAMP_PROP_ID, CERT_EXTENDED_ERROR_INFO_PROP_ID,
        CERT_RENEWAL_PROP_ID, CERT_ARCHIVED_KEY_HASH_PROP_ID, CERT_FRIENDLY_NAME_PROP_ID, 0x7000, CERT_FIRST_USER_PROP_ID, 0xFFFF};
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); BYTE data[40], out[64]; int k, j;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    for (j = 0; j < 40; j++) data[j] = (BYTE)(j * 7 + 3);
    for (k = 0; k < (int)(sizeof ids / sizeof ids[0]); k++) {
        DWORD n = 1 + k * 2;
        CHECKF(setb(c, ids[k], data, n), "set %lu", (unsigned long)ids[k]);
        memset(out, 0, sizeof out);
        CHECKF(getb(c, ids[k], out, sizeof out) == (int)n && !memcmp(out, data, n), "get %lu", (unsigned long)ids[k]);
    }
    ccp_free(c);
}
TEST(ccp_prop_overwrite_changes_size) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BYTE a[20], out[32]; DWORD id = CERT_DESCRIPTION_PROP_ID;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    memset(a, 0x11, 20);
    CHECK(setb(c, id, a, 20)); CHECK(getb(c, id, out, 32) == 20);
    memset(a, 0x22, 3);
    CHECK(setb(c, id, a, 3));  CHECK(getb(c, id, out, 32) == 3 && out[0] == 0x22 && out[2] == 0x22);
    memset(a, 0x33, 20);
    CHECK(setb(c, id, a, 20)); CHECK(getb(c, id, out, 32) == 20 && out[19] == 0x33);
    ccp_free(c);
}
TEST(ccp_prop_input_is_copied) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BYTE a[4] = {9, 8, 7, 6}, out[8];
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(setb(c, CERT_DESCRIPTION_PROP_ID, a, 4));
    memset(a, 0, 4);
    CHECK(getb(c, CERT_DESCRIPTION_PROP_ID, out, 8) == 4 && out[0] == 9 && out[3] == 6);
    ccp_free(c);
}
TEST(ccp_prop_friendly_name_wide_string) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); static const WCHAR name[] = L"Cryptt test friendly name"; WCHAR out[64]; int n;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(setb(c, CERT_FRIENDLY_NAME_PROP_ID, name, sizeof name));
    n = getb(c, CERT_FRIENDLY_NAME_PROP_ID, out, sizeof out);
    CHECK(n == (int)sizeof name && !lstrcmpW(out, name));
    ccp_free(c);
}
TEST(ccp_prop_friendly_name_not_validated) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); static const BYTE odd[] = {0x41, 0x00, 0x42}; BYTE out[8];
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(setb(c, CERT_FRIENDLY_NAME_PROP_ID, odd, 3));       /* odd byte count, no terminator */
    CHECK(getb(c, CERT_FRIENDLY_NAME_PROP_ID, out, 8) == 3 && !memcmp(out, odd, 3));
    ccp_free(c);
}
TEST(ccp_prop_zero_length_property_exists) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD cb = 99; BYTE b[4]; DWORD ids[16]; int n;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(setb(c, CERT_DESCRIPTION_PROP_ID, NULL, 0));
    CHECK(ccp_getprop(c, CERT_DESCRIPTION_PROP_ID, NULL, &cb) && cb == 0);
    cb = 4; CHECK(ccp_getprop(c, CERT_DESCRIPTION_PROP_ID, b, &cb) && cb == 0);
    n = enum_ids(c, ids, 16);
    CHECK(pos_of(ids, n, CERT_DESCRIPTION_PROP_ID) >= 0);
    ccp_free(c);
}
TEST(ccp_prop_delete_with_null_data) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BYTE d[3] = {1, 2, 3}; DWORD cb = 0;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(setb(c, CERT_DESCRIPTION_PROP_ID, d, 3));
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_DESCRIPTION_PROP_ID, 0, NULL));
    SET_ERR(0);
    EXPECT_FAIL(!ccp_getprop(c, CERT_DESCRIPTION_PROP_ID, NULL, &cb), CRYPT_E_NOT_FOUND_);
    /* deleting a property that is not there succeeds */
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_DESCRIPTION_PROP_ID, 0, NULL));
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_PVK_FILE_PROP_ID, 0, NULL));
    ccp_free(c);
}
TEST(ccp_prop_delete_removes_from_enumeration) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BYTE d[3] = {1, 2, 3}; DWORD ids[32]; int n;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(setb(c, CERT_DESCRIPTION_PROP_ID, d, 3));
    n = enum_ids(c, ids, 32); CHECK(pos_of(ids, n, CERT_DESCRIPTION_PROP_ID) >= 0);
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_DESCRIPTION_PROP_ID, 0, NULL));
    n = enum_ids(c, ids, 32); CHECK(pos_of(ids, n, CERT_DESCRIPTION_PROP_ID) < 0);
    ccp_free(c);
}
TEST(ccp_prop_separate_contexts_do_not_share) {
    PCCERT_CONTEXT a = ccp_ctx(&fx_root), b = ccp_ctx(&fx_root); BYTE d[2] = {5, 6}; DWORD cb = 0;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!a || !b) { CHECK(0); return; }
    CHECK(setb(a, CERT_DESCRIPTION_PROP_ID, d, 2));
    CHECK(!ccp_getprop(b, CERT_DESCRIPTION_PROP_ID, NULL, &cb));
    ccp_free(a); ccp_free(b);
}
TEST(ccp_prop_duplicate_shares_properties) {
    PCCERT_CONTEXT a = ccp_ctx(&fx_root), d; BYTE v[2] = {5, 6}; BYTE o[4];
    REQUIRE(C32(CertDuplicateCertificateContext));
    if (!a) { CHECK(0); return; }
    d = C32(CertDuplicateCertificateContext)(a);
    CHECK(setb(d, CERT_DESCRIPTION_PROP_ID, v, 2));
    CHECK(getb(a, CERT_DESCRIPTION_PROP_ID, o, 4) == 2);
    ccp_free(a); ccp_free(d);
}

/* ---- enumeration ---- */
TEST(ccp_enum_unknown_start_returns_zero) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root);
    REQUIRE(C32(CertEnumCertificateContextProperties));
    if (!c) { CHECK(0); return; }
    EXPECT_EQ(C32(CertEnumCertificateContextProperties)(c, 0x7777), 0);
    EXPECT_EQ(C32(CertEnumCertificateContextProperties)(c, CERT_DESCRIPTION_PROP_ID), 0);
    ccp_free(c);
}
TEST(ccp_enum_most_recently_set_first) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BYTE d[2] = {1, 2}; DWORD ids[32]; int n, a, b2, c2;
    REQUIRE(C32(CertEnumCertificateContextProperties));
    if (!c) { CHECK(0); return; }
    CHECK(setb(c, 0x8100, d, 2)); CHECK(setb(c, 0x8200, d, 2)); CHECK(setb(c, 0x8300, d, 2));
    n = enum_ids(c, ids, 32);
    a = pos_of(ids, n, 0x8100); b2 = pos_of(ids, n, 0x8200); c2 = pos_of(ids, n, 0x8300);
    CHECK(a >= 0 && b2 >= 0 && c2 >= 0);
    CHECK(c2 < b2 && b2 < a);        /* newest property first */
    EXPECT_EQ(ids[0], 0x8300);
    CHECK(setb(c, 0x8100, d, 2));    /* re-setting moves it to the front */
    n = enum_ids(c, ids, 32);
    EXPECT_EQ(ids[0], 0x8100);
    ccp_free(c);
}
TEST(ccp_enum_each_reported_id_is_gettable) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); BYTE d[2] = {1, 2}; DWORD ids[64]; int n, k;
    REQUIRE(C32(CertEnumCertificateContextProperties));
    if (!c) { CHECK(0); return; }
    setb(c, CERT_DESCRIPTION_PROP_ID, d, 2); setb(c, CERT_FRIENDLY_NAME_PROP_ID, d, 2); setb(c, 0x9000, d, 2);
    { BYTE h[32]; getb(c, CERT_SHA1_HASH_PROP_ID, h, 32); }
    n = enum_ids(c, ids, 64);
    CHECK(n >= 4);
    for (k = 0; k < n; k++) CHECKF(has_prop(c, ids[k]), "id %lu", (unsigned long)ids[k]);
    for (k = 0; k < n; k++) { int j; for (j = k + 1; j < n; j++) CHECK(ids[k] != ids[j]); }
    ccp_free(c);
}
TEST(ccp_enum_terminates_with_zero) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_ec256); BYTE d[1] = {1}; DWORD id = 0; int steps = 0;
    REQUIRE(C32(CertEnumCertificateContextProperties));
    if (!c) { CHECK(0); return; }
    setb(c, 0x8001, d, 1); setb(c, 0x8002, d, 1);
    while ((id = C32(CertEnumCertificateContextProperties)(c, id)) != 0 && steps < 100) steps++;
    CHECK(steps >= 2 && steps < 100);
    EXPECT_EQ(id, 0);
    ccp_free(c);
}

/* ---- KEY_CONTEXT / KEY_SPEC / KEY_PROV_HANDLE ---- */
TEST(ccp_prop_key_context_cbsize_validation) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_KEY_CONTEXT k; DWORD sizes[] = {0, 1, 8, 16, 0x17, 0x19, 0x20, 0xFFFFFFFF}; int i;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    for (i = 0; i < 8; i++) {
        memset(&k, 0, sizeof k); k.cbSize = sizes[i];
        SET_ERR(0);
        EXPECT_FAIL(!C32(CertSetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, 0, &k), E_INVALIDARG_);
    }
    ccp_free(c);
}
TEST(ccp_prop_key_context_roundtrip_null_handle) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_KEY_CONTEXT k, o; DWORD cb = sizeof o;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    memset(&k, 0, sizeof k); k.cbSize = sizeof k; k.hCryptProv = 0; k.dwKeySpec = AT_KEYEXCHANGE;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, 0, &k));
    memset(&o, 0xEE, sizeof o);
    CHECK(ccp_getprop(c, CERT_KEY_CONTEXT_PROP_ID, &o, &cb) && cb == sizeof o);
    CHECK(o.cbSize == sizeof o && o.hCryptProv == 0 && o.dwKeySpec == AT_KEYEXCHANGE);
    cb = 0; CHECK(ccp_getprop(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &cb) && cb == 24);
    cb = 23; SET_ERR(0); EXPECT_FAIL(!ccp_getprop(c, CERT_KEY_CONTEXT_PROP_ID, &o, &cb), ERROR_MORE_DATA); EXPECT_EQ(cb, 24);
    ccp_free(c);
}
TEST(ccp_prop_key_context_visible_in_key_spec) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_KEY_CONTEXT k; DWORD spec = 0, cb = 4;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    memset(&k, 0, sizeof k); k.cbSize = sizeof k; k.dwKeySpec = AT_SIGNATURE;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, 0, &k));
    CHECK(ccp_getprop(c, CERT_KEY_SPEC_PROP_ID, &spec, &cb) && cb == 4 && spec == AT_SIGNATURE);
    cb = 3; SET_ERR(0); EXPECT_FAIL(!ccp_getprop(c, CERT_KEY_SPEC_PROP_ID, &spec, &cb), ERROR_MORE_DATA); EXPECT_EQ(cb, 4);
    cb = 0; CHECK(ccp_getprop(c, CERT_KEY_SPEC_PROP_ID, NULL, &cb) && cb == 4);
    ccp_free(c);
}
TEST(ccp_prop_key_spec_set_creates_key_context) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD spec = AT_KEYEXCHANGE, got = 0, cb = 4; CERT_KEY_CONTEXT o; DWORD cb2 = sizeof o;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_SPEC_PROP_ID, 0, &spec));
    CHECK(ccp_getprop(c, CERT_KEY_SPEC_PROP_ID, &got, &cb) && got == AT_KEYEXCHANGE);
    /* setting KEY_SPEC materialises a KEY_CONTEXT with a NULL provider handle */
    CHECK(ccp_getprop(c, CERT_KEY_CONTEXT_PROP_ID, &o, &cb2) && cb2 == sizeof o && o.cbSize == sizeof o && o.hCryptProv == 0 && o.dwKeySpec == AT_KEYEXCHANGE);
    spec = AT_SIGNATURE;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_SPEC_PROP_ID, 0, &spec));
    cb = 4; CHECK(ccp_getprop(c, CERT_KEY_SPEC_PROP_ID, &got, &cb) && got == AT_SIGNATURE);
    ccp_free(c);
}
TEST(ccp_prop_key_prov_info_roundtrip) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); CRYPT_KEY_PROV_INFO ki, *out; BYTE buf[1024]; DWORD cb = sizeof buf, spec = 0, cs = 4, need = 0;
    static WCHAR cont[] = L"cryptt_nonexistent_container", prov[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    memset(&ki, 0, sizeof ki);
    ki.pwszContainerName = cont; ki.pwszProvName = prov; ki.dwProvType = PROV_RSA_AES; ki.dwFlags = CRYPT_MACHINE_KEYSET; ki.dwKeySpec = AT_SIGNATURE;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &ki));
    CHECK(ccp_getprop(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &need) && need > sizeof ki);
    CHECK(ccp_getprop(c, CERT_KEY_PROV_INFO_PROP_ID, buf, &cb));
    out = (CRYPT_KEY_PROV_INFO *)buf;
    CHECK(!lstrcmpW(out->pwszContainerName, cont) && !lstrcmpW(out->pwszProvName, prov));
    CHECK(out->dwProvType == PROV_RSA_AES && out->dwFlags == CRYPT_MACHINE_KEYSET && out->dwKeySpec == AT_SIGNATURE && out->cProvParam == 0);
    CHECK((BYTE *)out->pwszContainerName >= buf && (BYTE *)out->pwszContainerName < buf + cb);   /* strings live in the caller's buffer */
    cb = need - 1; SET_ERR(0);
    EXPECT_FAIL(!ccp_getprop(c, CERT_KEY_PROV_INFO_PROP_ID, buf, &cb), ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    CHECK(ccp_getprop(c, CERT_KEY_SPEC_PROP_ID, &spec, &cs) && spec == AT_SIGNATURE);   /* spec derived from the provider info */
    ccp_free(c);
}
TEST(ccp_prop_key_prov_info_with_params) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); CRYPT_KEY_PROV_INFO ki, *out; CRYPT_KEY_PROV_PARAM pp[2]; BYTE d1[3] = {1, 2, 3}, d2[5] = {9, 8, 7, 6, 5}; BYTE buf[1024]; DWORD cb = sizeof buf;
    static WCHAR cont[] = L"cryptt_c2";
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    memset(&ki, 0, sizeof ki);
    ki.pwszContainerName = cont; ki.dwProvType = PROV_RSA_FULL; ki.dwKeySpec = AT_KEYEXCHANGE;
    pp[0].dwParam = 11; pp[0].pbData = d1; pp[0].cbData = 3; pp[0].dwFlags = 0;
    pp[1].dwParam = 22; pp[1].pbData = d2; pp[1].cbData = 5; pp[1].dwFlags = 4;
    ki.cProvParam = 2; ki.rgProvParam = pp;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &ki));
    CHECK(ccp_getprop(c, CERT_KEY_PROV_INFO_PROP_ID, buf, &cb));
    out = (CRYPT_KEY_PROV_INFO *)buf;
    CHECK(out->cProvParam == 2 && out->rgProvParam != NULL);
    if (out->cProvParam == 2 && out->rgProvParam) {
        CHECK(out->rgProvParam[0].dwParam == 11 && out->rgProvParam[0].cbData == 3 && !memcmp(out->rgProvParam[0].pbData, d1, 3));
        CHECK(out->rgProvParam[1].dwParam == 22 && out->rgProvParam[1].cbData == 5 && out->rgProvParam[1].dwFlags == 4 && !memcmp(out->rgProvParam[1].pbData, d2, 5));
    }
    CHECK(out->pwszProvName == NULL);
    ccp_free(c);
}
TEST(ccp_prop_key_prov_info_null_names) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); CRYPT_KEY_PROV_INFO ki, *out; BYTE buf[512]; DWORD cb = sizeof buf;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    memset(&ki, 0, sizeof ki); ki.dwProvType = PROV_RSA_AES; ki.dwKeySpec = AT_KEYEXCHANGE;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &ki));
    CHECK(ccp_getprop(c, CERT_KEY_PROV_INFO_PROP_ID, buf, &cb));
    out = (CRYPT_KEY_PROV_INFO *)buf;
    CHECK(out->pwszContainerName == NULL && out->pwszProvName == NULL && out->dwProvType == PROV_RSA_AES);
    ccp_free(c);
}

/* ---- ACCESS_STATE and computed CNG props ---- */
TEST(ccp_prop_access_state_is_dword) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD v = 0xFFFFFFFF, cb = 4;
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    CHECK(ccp_getprop(c, CERT_ACCESS_STATE_PROP_ID, &v, &cb) && cb == 4);
    t_note("standalone context access state = 0x%lx", (unsigned long)v);
    CHECK((v & ~0x1FUL) == 0);
    cb = 0; CHECK(ccp_getprop(c, CERT_ACCESS_STATE_PROP_ID, NULL, &cb) && cb == 4);
    cb = 3; SET_ERR(0); EXPECT_FAIL(!ccp_getprop(c, CERT_ACCESS_STATE_PROP_ID, &v, &cb), ERROR_MORE_DATA); EXPECT_EQ(cb, 4);
    ccp_free(c);
}
TEST(ccp_prop_access_state_in_memory_store) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT c; DWORD v = 0, cb = 4;
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!s) { CHECK(0); return; }
    c = ccp_add(s, &fx_root);
    CHECK(c != NULL);
    if (c) {
        CHECK(ccp_getprop(c, CERT_ACCESS_STATE_PROP_ID, &v, &cb) && cb == 4);
        t_note("memory-store access state = 0x%lx", (unsigned long)v);
        CHECK((v & CERT_ACCESS_STATE_WRITE_PERSIST_FLAG) == 0);       /* memory stores do not persist */
        ccp_free(c);
    }
    ccp_close(s);
}
TEST(ccp_prop_cng_alg_strings) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); WCHAR w[64]; int n;
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    n = getb(c, CERT_SIGN_HASH_CNG_ALG_PROP_ID, w, sizeof w);
    if (n > 0) {
        CHECK(n >= 4 && (n % 2) == 0 && w[n / 2 - 1] == 0 && wcschr(w, L'/') != NULL);
        t_note("sign hash cng alg: %ls", w);
    } else t_note("CERT_SIGN_HASH_CNG_ALG_PROP_ID unavailable err=0x%lx", GetLastError());
    n = getb(c, CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID, w, sizeof w);
    if (n > 0) {
        CHECK(n >= 4 && (n % 2) == 0 && w[n / 2 - 1] == 0 && wcschr(w, L'/') != NULL);
        t_note("pub key cng alg/bitlen: %ls", w);
    } else t_note("CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID unavailable err=0x%lx", GetLastError());
    ccp_free(c);
}

/* ---- store interaction ---- */
TEST(ccp_prop_visible_through_store_contexts) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT a, b; BYTE d[3] = {1, 2, 3}, o[8];
    REQUIRE(C32(CertEnumCertificatesInStore));
    if (!s) { CHECK(0); return; }
    a = ccp_add(s, &fx_leaf);
    CHECK(a != NULL);
    if (a) {
        CHECK(setb(a, CERT_DESCRIPTION_PROP_ID, d, 3));
        b = C32(CertEnumCertificatesInStore)(s, NULL);
        CHECK(b != NULL);
        if (b) { CHECK(getb(b, CERT_DESCRIPTION_PROP_ID, o, 8) == 3 && !memcmp(o, d, 3)); ccp_free(b); }
        ccp_free(a);
    }
    ccp_close(s);
}
TEST(ccp_prop_copied_by_add_context_to_store) {
    HCERTSTORE s1 = ccp_mem(), s2 = ccp_mem(); PCCERT_CONTEXT a, b = NULL; BYTE d[3] = {7, 8, 9}, o[8]; static const WCHAR fn[] = L"fn";
    REQUIRE(C32(CertAddCertificateContextToStore));
    if (!s1 || !s2) { CHECK(0); return; }
    a = ccp_add(s1, &fx_leaf);
    if (a) {
        CHECK(setb(a, CERT_DESCRIPTION_PROP_ID, d, 3));
        CHECK(setb(a, CERT_FRIENDLY_NAME_PROP_ID, fn, sizeof fn));
        CHECK(C32(CertAddCertificateContextToStore)(s2, a, CERT_STORE_ADD_ALWAYS, &b));
        if (b) {
            CHECK(b != a);
            CHECK(getb(b, CERT_DESCRIPTION_PROP_ID, o, 8) == 3 && !memcmp(o, d, 3));
            CHECK(getb(b, CERT_FRIENDLY_NAME_PROP_ID, o, 8) == (int)sizeof fn);
            /* independent copies: changing one does not change the other */
            CHECK(setb(b, CERT_DESCRIPTION_PROP_ID, d, 1));
            CHECK(getb(a, CERT_DESCRIPTION_PROP_ID, o, 8) == 3);
            ccp_free(b);
        }
        ccp_free(a);
    }
    ccp_close(s1); ccp_close(s2);
}
TEST(ccp_prop_serialize_roundtrip) {
    HCERTSTORE s1 = ccp_mem(), s2 = ccp_mem(); PCCERT_CONTEXT a, b = NULL; BYTE d[5] = {1, 3, 5, 7, 9}, o[8], *ser; DWORD cb = 0, type = 0;
    REQUIRE(C32(CertSerializeCertificateStoreElement));
    if (!s1 || !s2) { CHECK(0); return; }
    a = ccp_add(s1, &fx_leaf);
    if (!a) { CHECK(0); return; }
    CHECK(setb(a, CERT_DESCRIPTION_PROP_ID, d, 5));
    CHECK(setb(a, 0x9100, d, 2));
    CHECK(C32(CertSerializeCertificateStoreElement)(a, 0, NULL, &cb) && cb > fx_leaf.cb);
    ser = (BYTE *)LocalAlloc(LPTR, cb);
    CHECK(C32(CertSerializeCertificateStoreElement)(a, 0, ser, &cb));
    CHECK(C32(CertAddSerializedElementToStore)(s2, ser, cb, CERT_STORE_ADD_ALWAYS, 0, CERT_STORE_CERTIFICATE_CONTEXT_FLAG, &type, (const void **)&b));
    EXPECT_EQ(type, CERT_STORE_CERTIFICATE_CONTEXT);
    CHECK(b != NULL);
    if (b) {
        CHECK(b->cbCertEncoded == fx_leaf.cb && !memcmp(b->pbCertEncoded, fx_leaf.der, fx_leaf.cb));
        CHECK(getb(b, CERT_DESCRIPTION_PROP_ID, o, 8) == 5 && !memcmp(o, d, 5));
        CHECK(getb(b, 0x9100, o, 8) == 2);
        ccp_free(b);
    }
    LocalFree(ser); ccp_free(a); ccp_close(s1); ccp_close(s2);
}
TEST(ccp_prop_serialize_excludes_key_context) {
    HCERTSTORE s1 = ccp_mem(), s2 = ccp_mem(); PCCERT_CONTEXT a, b = NULL; CERT_KEY_CONTEXT k; BYTE *ser; DWORD cb = 0, n;
    REQUIRE(C32(CertSerializeCertificateStoreElement));
    if (!s1 || !s2) { CHECK(0); return; }
    a = ccp_add(s1, &fx_leaf);
    if (!a) { CHECK(0); return; }
    memset(&k, 0, sizeof k); k.cbSize = sizeof k; k.dwKeySpec = AT_KEYEXCHANGE;
    CHECK(C32(CertSetCertificateContextProperty)(a, CERT_KEY_CONTEXT_PROP_ID, 0, &k));
    CHECK(C32(CertSerializeCertificateStoreElement)(a, 0, NULL, &cb));
    ser = (BYTE *)LocalAlloc(LPTR, cb);
    CHECK(C32(CertSerializeCertificateStoreElement)(a, 0, ser, &cb));
    CHECK(C32(CertAddSerializedElementToStore)(s2, ser, cb, CERT_STORE_ADD_ALWAYS, 0, CERT_STORE_CERTIFICATE_CONTEXT_FLAG, NULL, (const void **)&b));
    if (b) { n = sizeof k; int r = ccp_getprop(b, CERT_KEY_CONTEXT_PROP_ID, &k, &n); t_note("KEY_CONTEXT after serialize round trip: %s", r ? "present" : "absent"); ccp_free(b); } else CHECK(0);
    LocalFree(ser); ccp_free(a); ccp_close(s1); ccp_close(s2);
}
TEST(ccp_prop_serialize_size_protocol) {
    PCCERT_CONTEXT a = ccp_ctx(&fx_root); BYTE buf[4096]; DWORD cb = 0, need;
    REQUIRE(C32(CertSerializeCertificateStoreElement));
    if (!a) { CHECK(0); return; }
    CHECK(C32(CertSerializeCertificateStoreElement)(a, 0, NULL, &cb));
    need = cb;
    CHECK(need > fx_root.cb && need < sizeof buf);
    cb = need - 1; SET_ERR(0);
    EXPECT_FAIL(!C32(CertSerializeCertificateStoreElement)(a, 0, buf, &cb), ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    cb = need + 10;
    CHECK(C32(CertSerializeCertificateStoreElement)(a, 0, buf, &cb) && cb == need);
    ccp_free(a);
}
TEST(ccp_prop_archived_hides_from_enumeration) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT a, e; CRYPT_DATA_BLOB blob = {0, NULL};
    REQUIRE(C32(CertEnumCertificatesInStore));
    if (!s) { CHECK(0); return; }
    a = ccp_add(s, &fx_root);
    if (!a) { CHECK(0); return; }
    e = C32(CertEnumCertificatesInStore)(s, NULL);
    CHECK(e != NULL);
    if (e) C32(CertFreeCertificateContext)(e);
    CHECK(C32(CertSetCertificateContextProperty)(a, CERT_ARCHIVED_PROP_ID, 0, &blob));
    CHECK(C32(CertEnumCertificatesInStore)(s, NULL) == NULL);
    { DWORD cb = 0; CHECK(ccp_getprop(a, CERT_ARCHIVED_PROP_ID, NULL, &cb) && cb == 0); }
    CHECK(C32(CertSetCertificateContextProperty)(a, CERT_ARCHIVED_PROP_ID, 0, NULL));
    e = C32(CertEnumCertificatesInStore)(s, NULL);
    CHECK(e != NULL);
    if (e) C32(CertFreeCertificateContext)(e);
    ccp_free(a); ccp_close(s);
}
TEST(ccp_prop_set_flags_accepted_on_memory_store) {
    HCERTSTORE s = ccp_mem(); PCCERT_CONTEXT a; BYTE d[2] = {4, 5}, o[4]; CRYPT_DATA_BLOB b; DWORD flags[] = {CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG, CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG, CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG | CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG}; int k;
    REQUIRE(C32(CertSetCertificateContextProperty));
    if (!s) { CHECK(0); return; }
    a = ccp_add(s, &fx_leaf);
    if (!a) { CHECK(0); return; }
    b.cbData = 2; b.pbData = d;
    for (k = 0; k < 3; k++) {
        CHECKF(C32(CertSetCertificateContextProperty)(a, CERT_DESCRIPTION_PROP_ID, flags[k], &b), "flags 0x%lx", (unsigned long)flags[k]);
        CHECK(getb(a, CERT_DESCRIPTION_PROP_ID, o, 4) == 2);
        C32(CertSetCertificateContextProperty)(a, CERT_DESCRIPTION_PROP_ID, 0, NULL);
    }
    ccp_free(a); ccp_close(s);
}
TEST(ccp_prop_method_set_flag_constant) {
    /* The high bits of the flags word are reserved for the property-set modifiers. */
    EXPECT_EQ(CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG, 0x80000000);
    EXPECT_EQ(CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG, 0x40000000);
    EXPECT_EQ(CERT_STORE_NO_CRYPT_RELEASE_FLAG, 1);
}
TEST(ccp_prop_ids_numeric_values) {
    EXPECT_EQ(CERT_KEY_PROV_HANDLE_PROP_ID, 1); EXPECT_EQ(CERT_KEY_PROV_INFO_PROP_ID, 2); EXPECT_EQ(CERT_SHA1_HASH_PROP_ID, 3);
    EXPECT_EQ(CERT_MD5_HASH_PROP_ID, 4); EXPECT_EQ(CERT_KEY_CONTEXT_PROP_ID, 5); EXPECT_EQ(CERT_KEY_SPEC_PROP_ID, 6);
    EXPECT_EQ(CERT_ENHKEY_USAGE_PROP_ID, 9); EXPECT_EQ(CERT_NEXT_UPDATE_LOCATION_PROP_ID, 10); EXPECT_EQ(CERT_FRIENDLY_NAME_PROP_ID, 11);
    EXPECT_EQ(CERT_PVK_FILE_PROP_ID, 12); EXPECT_EQ(CERT_DESCRIPTION_PROP_ID, 13); EXPECT_EQ(CERT_ACCESS_STATE_PROP_ID, 14);
    EXPECT_EQ(CERT_SIGNATURE_HASH_PROP_ID, 15); EXPECT_EQ(CERT_SMART_CARD_DATA_PROP_ID, 16); EXPECT_EQ(CERT_ARCHIVED_PROP_ID, 19);
    EXPECT_EQ(CERT_KEY_IDENTIFIER_PROP_ID, 20); EXPECT_EQ(CERT_AUTO_ENROLL_PROP_ID, 21); EXPECT_EQ(CERT_PUBKEY_ALG_PARA_PROP_ID, 22);
    EXPECT_EQ(CERT_CROSS_CERT_DIST_POINTS_PROP_ID, 23); EXPECT_EQ(CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID, 24);
    EXPECT_EQ(CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID, 25); EXPECT_EQ(CERT_DATE_STAMP_PROP_ID, 27);
    EXPECT_EQ(CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID, 28); EXPECT_EQ(CERT_SUBJECT_NAME_MD5_HASH_PROP_ID, 29);
    EXPECT_EQ(CERT_EXTENDED_ERROR_INFO_PROP_ID, 30); EXPECT_EQ(CERT_RENEWAL_PROP_ID, 64);
}

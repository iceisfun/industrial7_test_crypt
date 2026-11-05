/* Alternate names, basic constraints, key usage, EKU, key identifiers, key attributes/restrictions. */
#include "asn.h"

static const WCHAR wdns[] = { 'a','.','c','o','m',0 };
static const WCHAR wrfc[] = { 'a','@','b','.','c',0 };
static const WCHAR wurl[] = { 'h','t','t','p',':','/','/','x',0 };

static void alt1(CERT_ALT_NAME_INFO *i, CERT_ALT_NAME_ENTRY *e) { i->cAltEntry = 1; i->rgAltEntry = e; }

/* ---- X509_ALTERNATE_NAME encode ---------------------------------------- */
TEST(altname_encode_empty) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_INFO i = { 0, NULL };
    ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_empty);
}
TEST(altname_encode_dns) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_DNS_NAME }; e.pwszDNSName = (LPWSTR)wdns;
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_dns);
}
TEST(altname_encode_rfc822) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_RFC822_NAME }; e.pwszRfc822Name = (LPWSTR)wrfc;
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_rfc822);
}
TEST(altname_encode_url) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_URL }; e.pwszURL = (LPWSTR)wurl;
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_url);
}
TEST(altname_encode_ip_addresses) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE ip4[] = { 1, 2, 3, 4 }, ip4m[] = { 10, 0, 0, 0, 255, 0, 0, 0 };
    static BYTE ip6[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_IP_ADDRESS }; CERT_ALT_NAME_INFO i; alt1(&i, &e);
    e.IPAddress.cbData = 4; e.IPAddress.pbData = ip4; ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_ip4);
    e.IPAddress.cbData = 8; e.IPAddress.pbData = ip4m; ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_ip4mask);
    e.IPAddress.cbData = 16; e.IPAddress.pbData = ip6; ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_ip6);
}
TEST(altname_encode_registered_id) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_REGISTERED_ID }; e.pszRegisteredID = (LPSTR)"1.2.3.4";
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_regid);
}
TEST(altname_encode_directory_name) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_DIRECTORY_NAME };
    e.DirectoryName.cbData = sizeof v_name_cn_test; e.DirectoryName.pbData = (BYTE *)v_name_cn_test;
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_dir);
}
TEST(altname_encode_other_name) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE one[] = { 0x02, 0x01, 0x01 };
    CERT_OTHER_NAME on = { (LPSTR)"1.2.3.4", { sizeof one, one } };
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_OTHER_NAME }; e.pOtherName = &on;
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_other);
}
TEST(altname_encode_multiple_entries) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE ip4[] = { 1, 2, 3, 4 };
    CERT_ALT_NAME_ENTRY e[3] = { { CERT_ALT_NAME_DNS_NAME }, { CERT_ALT_NAME_RFC822_NAME }, { CERT_ALT_NAME_IP_ADDRESS } };
    e[0].pwszDNSName = (LPWSTR)wdns; e[1].pwszRfc822Name = (LPWSTR)wrfc; e[2].IPAddress.cbData = 4; e[2].IPAddress.pbData = ip4;
    CERT_ALT_NAME_INFO i = { 3, e };
    ENC_EQ(X509_ALTERNATE_NAME, &i, v_alt_multi);
}
TEST(altname_encode_invalid_choice_zero) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { 0 }; CERT_ALT_NAME_INFO i; alt1(&i, &e);
    ENC_FAIL(X509_ALTERNATE_NAME, &i, HR_INVALIDARG);
}
TEST(altname_encode_invalid_choice_out_of_range) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { 10 }; CERT_ALT_NAME_INFO i; alt1(&i, &e);
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_ALTERNATE_NAME, &i, 0, NULL, NULL, &cb);
    EXPECT_FAIL(!r, HR_INVALIDARG);
}
TEST(altname_encode_non_ia5_characters) {
    REQUIRE(U(CryptEncodeObjectEx));
    static const WCHAR bad[] = { 'a', 'b', 0x00E9, '.', 'c', 0 };
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_DNS_NAME }; e.pwszDNSName = (LPWSTR)bad;
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_ALTERNATE_NAME, &i, 0, NULL, NULL, &cb);
    CHECK(!r); EXPECT_ERR((DWORD)CRYPT_E_INVALID_IA5_STRING);
    CHECK(GET_CERT_ALT_NAME_ENTRY_ERR_INDEX(cb) == 0);
    CHECK(GET_CERT_ALT_NAME_VALUE_ERR_INDEX(cb) == 2);
    /* second entry */
    CERT_ALT_NAME_ENTRY e2[2] = { { CERT_ALT_NAME_DNS_NAME }, { CERT_ALT_NAME_RFC822_NAME } };
    e2[0].pwszDNSName = (LPWSTR)wdns; e2[1].pwszRfc822Name = (LPWSTR)bad;
    CERT_ALT_NAME_INFO i2 = { 2, e2 };
    SET_ERR(0); cb = 0;
    r = U(CryptEncodeObjectEx)(ENC, X509_ALTERNATE_NAME, &i2, 0, NULL, NULL, &cb);
    CHECK(!r); EXPECT_ERR((DWORD)CRYPT_E_INVALID_IA5_STRING);
    CHECK(GET_CERT_ALT_NAME_ENTRY_ERR_INDEX(cb) == 1);
    CHECK(GET_CERT_ALT_NAME_VALUE_ERR_INDEX(cb) == 2);
}
TEST(altname_encode_x400_edi_unsupported_probe) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_X400_ADDRESS }; CERT_ALT_NAME_INFO i; alt1(&i, &e);
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_ALTERNATE_NAME, &i, 0, NULL, NULL, &cb);
    EXPECT_FAIL(!r, HR_INVALIDARG); EXPECT_EQ(cb, 0); /* observed */
    e.dwAltNameChoice = CERT_ALT_NAME_EDI_PARTY_NAME; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, X509_ALTERNATE_NAME, &i, 0, NULL, NULL, &cb);
    EXPECT_FAIL(!r, HR_INVALIDARG); EXPECT_EQ(cb, 0); /* observed */
}

/* ---- decode ----------------------------------------------------------- */
TEST(altname_decode_empty) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_ALT_NAME_INFO *i = DEC(X509_ALTERNATE_NAME, v_alt_empty, 0, NULL);
    if (i) { CHECK(i->cAltEntry == 0); LocalFree(i); }
}
TEST(altname_decode_dns_rfc822_url) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_ALT_NAME_INFO *i = DEC(X509_ALTERNATE_NAME, v_alt_dns, 0, NULL);
    if (i) { CHECK(i->cAltEntry == 1 && i->rgAltEntry[0].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME); CHECK(!lstrcmpW(i->rgAltEntry[0].pwszDNSName, wdns)); LocalFree(i); }
    i = DEC(X509_ALTERNATE_NAME, v_alt_rfc822, 0, NULL);
    if (i) { CHECK(i->rgAltEntry[0].dwAltNameChoice == CERT_ALT_NAME_RFC822_NAME); CHECK(!lstrcmpW(i->rgAltEntry[0].pwszRfc822Name, wrfc)); LocalFree(i); }
    i = DEC(X509_ALTERNATE_NAME, v_alt_url, 0, NULL);
    if (i) { CHECK(i->rgAltEntry[0].dwAltNameChoice == CERT_ALT_NAME_URL); CHECK(!lstrcmpW(i->rgAltEntry[0].pwszURL, wurl)); LocalFree(i); }
}
TEST(altname_decode_ip_and_regid) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_ALT_NAME_INFO *i = DEC(X509_ALTERNATE_NAME, v_alt_ip4, 0, NULL);
    if (i) { CERT_ALT_NAME_ENTRY *e = i->rgAltEntry; CHECK(e->dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS && e->IPAddress.cbData == 4 && !memcmp(e->IPAddress.pbData, "\x01\x02\x03\x04", 4)); LocalFree(i); }
    i = DEC(X509_ALTERNATE_NAME, v_alt_ip4mask, 0, NULL);
    if (i) { CHECK(i->rgAltEntry->IPAddress.cbData == 8); LocalFree(i); }
    i = DEC(X509_ALTERNATE_NAME, v_alt_ip6, 0, NULL);
    if (i) { CHECK(i->rgAltEntry->IPAddress.cbData == 16 && i->rgAltEntry->IPAddress.pbData[15] == 15); LocalFree(i); }
    i = DEC(X509_ALTERNATE_NAME, v_alt_regid, 0, NULL);
    if (i) { CHECK(i->rgAltEntry->dwAltNameChoice == CERT_ALT_NAME_REGISTERED_ID); CHECK(!strcmp(i->rgAltEntry->pszRegisteredID, "1.2.3.4")); LocalFree(i); }
}
TEST(altname_decode_directory_and_other) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_ALT_NAME_INFO *i = DEC(X509_ALTERNATE_NAME, v_alt_dir, 0, NULL);
    if (i) {
        CERT_ALT_NAME_ENTRY *e = i->rgAltEntry;
        CHECK(e->dwAltNameChoice == CERT_ALT_NAME_DIRECTORY_NAME);
        CHECK(e->DirectoryName.cbData == sizeof v_name_cn_test && !memcmp(e->DirectoryName.pbData, v_name_cn_test, sizeof v_name_cn_test));
        LocalFree(i);
    }
    DWORD cb1, cb2;
    i = DEC(X509_ALTERNATE_NAME, v_alt_dir, 0, &cb1);
    CERT_ALT_NAME_INFO *n = DEC(X509_ALTERNATE_NAME, v_alt_dir, CRYPT_DECODE_NOCOPY_FLAG, &cb2);
    if (n) { /* observed: NOCOPY points into the input and needs 24 bytes less */
        CHECK(PTR_IN(n->rgAltEntry->DirectoryName.pbData, v_alt_dir, sizeof v_alt_dir));
        EXPECT_EQ(cb2, 40); EXPECT_EQ(cb1, 64); LocalFree(n); }
    if (i) LocalFree(i);
    i = DEC(X509_ALTERNATE_NAME, v_alt_other, 0, NULL);
    if (i) {
        CERT_ALT_NAME_ENTRY *e = i->rgAltEntry;
        CHECK(e->dwAltNameChoice == CERT_ALT_NAME_OTHER_NAME);
        CHECK(e->pOtherName && !strcmp(e->pOtherName->pszObjId, "1.2.3.4"));
        CHECK(e->pOtherName->Value.cbData == 3 && !memcmp(e->pOtherName->Value.pbData, "\x02\x01\x01", 3));
        LocalFree(i);
    }
}
TEST(altname_decode_multiple_and_roundtrips) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_ALT_NAME_INFO *i = DEC(X509_ALTERNATE_NAME, v_alt_multi, 0, NULL);
    if (i) {
        CHECK(i->cAltEntry == 3);
        if (i->cAltEntry == 3) {
            CHECK(i->rgAltEntry[0].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME);
            CHECK(i->rgAltEntry[1].dwAltNameChoice == CERT_ALT_NAME_RFC822_NAME);
            CHECK(i->rgAltEntry[2].dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS);
        }
        LocalFree(i);
    }
    ROUNDTRIP(X509_ALTERNATE_NAME, v_alt_multi);
    ROUNDTRIP(X509_ALTERNATE_NAME, v_alt_dir);
    ROUNDTRIP(X509_ALTERNATE_NAME, v_alt_other);
    ROUNDTRIP(X509_ALTERNATE_NAME, v_alt_regid);
    ROUNDTRIP(X509_ALTERNATE_NAME, v_alt_ip6);
    ROUNDTRIP(X509_ALTERNATE_NAME, v_alt_url);
}
TEST(altname_decode_unknown_choice) {
    REQUIRE(U(CryptDecodeObjectEx));
    a_dec_fail(__FILE__, __LINE__, X509_ALTERNATE_NAME, v_alt_bad_choice, sizeof v_alt_bad_choice, 0, HR_ASN1_CORRUPT);
}
TEST(altname_decode_x400_edi_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    const BYTE *vs[2] = { v_alt_x400, v_alt_edi }; DWORD ns[2] = { sizeof v_alt_x400, sizeof v_alt_edi };
    for (int k = 0; k < 2; k++) {
        DWORD cb = 0; void *p = NULL; SET_ERR(0);
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_ALTERNATE_NAME, vs[k], ns[k], CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
        CHECKF(r, "%s entry decode failed 0x%lx", k ? "edi" : "x400", GetLastError());
        if (r) { EXPECT_EQ(((CERT_ALT_NAME_INFO *)p)->rgAltEntry[0].dwAltNameChoice, k ? CERT_ALT_NAME_EDI_PARTY_NAME : CERT_ALT_NAME_X400_ADDRESS); LocalFree(p); }
    }
}
TEST(altname_decode_punycode_flag) {
    REQUIRE(U(CryptDecodeObjectEx));
    static const WCHAR plain[] = L"xn--bcher-kva.example", uni[] = { 'b', 0x00FC, 'c', 'h', 'e', 'r', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    CERT_ALT_NAME_INFO *i = DEC(X509_ALTERNATE_NAME, v_alt_dns_puny, 0, NULL);
    if (i) { CHECK(!lstrcmpW(i->rgAltEntry[0].pwszDNSName, plain)); LocalFree(i); }
    i = DEC(X509_ALTERNATE_NAME, v_alt_dns_puny, CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, NULL);
    if (i) { CHECK(!lstrcmpW(i->rgAltEntry[0].pwszDNSName, uni)); LocalFree(i); }
    static const WCHAR rplain[] = L"user@xn--bcher-kva.example", runi[] = { 'u','s','e','r','@','b', 0x00FC, 'c','h','e','r','.','e','x','a','m','p','l','e', 0 };
    i = DEC(X509_ALTERNATE_NAME, v_alt_rfc822_puny, CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, NULL);
    if (i) { CHECK(!lstrcmpW(i->rgAltEntry[0].pwszRfc822Name, runi)); LocalFree(i); } /* observed: converted */
    i = DEC(X509_ALTERNATE_NAME, v_alt_url_puny, CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, NULL);
    static const WCHAR wuni[] = { 'h','t','t','p',':','/','/','b', 0x00FC, 'c','h','e','r','.','e','x','a','m','p','l','e','/','p', 0 };
    if (i) { CHECK(!lstrcmpW(i->rgAltEntry[0].pwszURL, wuni)); LocalFree(i); } /* observed: the host label of a URL is converted too */
}

/* ---- aliases: string OIDs that share the X509_ALTERNATE_NAME encoder ------ */
TEST(altname_string_oid_aliases) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_DNS_NAME }; e.pwszDNSName = (LPWSTR)wdns;
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    static const char *oids[] = { szOID_SUBJECT_ALT_NAME, szOID_ISSUER_ALT_NAME, szOID_SUBJECT_ALT_NAME2, szOID_ISSUER_ALT_NAME2 };
    for (unsigned k = 0; k < 4; k++) {
        t_label("oid %s", oids[k]);
        a_enc_eq(__FILE__, __LINE__, oids[k], &i, 0, v_alt_dns, sizeof v_alt_dns);
        BYTE *p; DWORD cb;
        CERT_ALT_NAME_INFO *d = (CERT_ALT_NAME_INFO *)a_dec(__FILE__, __LINE__, oids[k], v_alt_dns, sizeof v_alt_dns, 0, &cb);
        if (d) { CHECK(d->cAltEntry == 1); LocalFree(d); }
    }
}
TEST(altname_next_update_location_probe) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_URL }; e.pwszURL = (LPWSTR)wurl;
    CERT_ALT_NAME_INFO i; alt1(&i, &e);
    ENC_EQ(szOID_NEXT_UPDATE_LOCATION, &i, v_alt_url); /* observed: registered, same encoder as the alternate name */
}

/* ---- basic constraints 2 ------------------------------------------------ */
struct bc2_row { const char *label; BOOL ca, pl; DWORD len; const BYTE *der; DWORD dn; };
#define BC2(l, ca, pl, len, v) { l, ca, pl, len, v, sizeof(v) }
static const struct bc2_row bc2_rows[] = {
    BC2("empty", 0, 0, 0, v_bc2_empty), BC2("ca", 1, 0, 0, v_bc2_ca), BC2("ca_pl3", 1, 1, 3, v_bc2_ca_pl3),
    BC2("ca_pl0", 1, 1, 0, v_bc2_ca_pl0), BC2("pl3_only", 0, 1, 3, v_bc2_pl3),
};
TEST(bc2_encode_table) {
    REQUIRE(U(CryptEncodeObjectEx));
    for (unsigned i = 0; i < sizeof bc2_rows / sizeof *bc2_rows; i++) {
        const struct bc2_row *r = &bc2_rows[i];
        CERT_BASIC_CONSTRAINTS2_INFO s = { r->ca, r->pl, r->len };
        a_ctx = r->label;
        a_enc_eq(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, &s, 0, r->der, r->dn);
        a_enc_eq(__FILE__, __LINE__, szOID_BASIC_CONSTRAINTS2, &s, 0, r->der, r->dn);
    }
    a_ctx = "";
}
TEST(bc2_decode_table) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (unsigned i = 0; i < sizeof bc2_rows / sizeof *bc2_rows; i++) {
        const struct bc2_row *r = &bc2_rows[i];
        t_label("row %s", r->label);
        DWORD cb; CERT_BASIC_CONSTRAINTS2_INFO *s = a_dec(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, r->der, r->dn, 0, &cb);
        if (!s) continue;
        EXPECT_EQ(cb, 12);
        CHECK(!!s->fCA == !!r->ca); CHECK(!!s->fPathLenConstraint == !!r->pl);
        if (r->pl) CHECK(s->dwPathLenConstraint == r->len);
        LocalFree(s);
    }
}
TEST(bc2_decode_lenient_and_errors) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_BASIC_CONSTRAINTS2_INFO *s = DEC(X509_BASIC_CONSTRAINTS2, v_bc2_nondder_true, 0, NULL);
    if (s) { CHECK(s->fCA); LocalFree(s); }
    s = DEC(X509_BASIC_CONSTRAINTS2, v_bc2_false_explicit, 0, NULL);
    if (s) { CHECK(!s->fCA); LocalFree(s); }
    a_dec_fail(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, v_bc2_inverted, sizeof v_bc2_inverted, 0, HR_ASN1_CORRUPT);
    a_dec_fail(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, v_name_cn_test, sizeof v_name_cn_test, 0, HR_ASN1_CORRUPT);
    a_dec_fail(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, v_ku_ds, sizeof v_ku_ds, 0, HR_ASN1_BADTAG);
}
TEST(bc2_truncated_inputs) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (DWORD cut = 0; cut < sizeof v_bc2_ca_pl3; cut++) {
        DWORD cb = 0; SET_ERR(0);
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, v_bc2_ca_pl3, cut, 0, NULL, NULL, &cb);
        CHECKF(!r, "cut %lu succeeded", cut);
        if (!r) { DWORD e = GetLastError(); CHECKF(e == HR_ASN1_EOD, "cut %lu err 0x%lx", cut, e); }
    }
}
TEST(bc2_trailing_bytes_ignored) {
    REQUIRE(U(CryptDecodeObjectEx));
    BYTE b[16]; memcpy(b, v_bc2_ca, sizeof v_bc2_ca); b[sizeof v_bc2_ca] = 0xFF;
    CERT_BASIC_CONSTRAINTS2_INFO *s = a_dec(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, b, sizeof v_bc2_ca + 1, 0, NULL);
    if (s) { CHECK(s->fCA); LocalFree(s); }
}
TEST(bc2_indefinite_length_accepted) {
    REQUIRE(U(CryptDecodeObjectEx));
    static const BYTE indef[] = { 0x30, 0x80, 0x01, 0x01, 0xFF, 0x00, 0x00 };
    CERT_BASIC_CONSTRAINTS2_INFO *s = DEC(X509_BASIC_CONSTRAINTS2, indef, 0, NULL);
    if (s) { CHECK(s->fCA); LocalFree(s); }
}
TEST(bc2_roundtrips) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (unsigned i = 0; i < sizeof bc2_rows / sizeof *bc2_rows; i++) a_roundtrip(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, bc2_rows[i].der, bc2_rows[i].dn);
}

/* ---- basic constraints (v1 structure) ---------------------------------- */
TEST(bc_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE ca = CERT_CA_SUBJECT_FLAG;
    CERT_BASIC_CONSTRAINTS_INFO s; memset(&s, 0, sizeof s);
    s.SubjectType.cbData = 1; s.SubjectType.pbData = &ca; s.SubjectType.cUnusedBits = 0;
    /* the encoder trims trailing zero bits: a CA flag always has 7 unused bits (Windows 10) */
    ENC_EQ(X509_BASIC_CONSTRAINTS, &s, v_bc_ca_enc);
    ENC_EQ(szOID_BASIC_CONSTRAINTS, &s, v_bc_ca_enc);
    s.fPathLenConstraint = TRUE; s.dwPathLenConstraint = 2;
    ENC_EQ(X509_BASIC_CONSTRAINTS, &s, v_bc_ca_pl2_enc);
    CERT_NAME_BLOB nb = { sizeof v_name_cn_test, (BYTE *)v_name_cn_test };
    s.cSubtreesConstraint = 1; s.rgSubtreesConstraint = &nb;
    ENC_EQ(X509_BASIC_CONSTRAINTS, &s, v_bc_ca_pl2_sub_enc);
    memset(&s, 0, sizeof s);
    ENC_EQ(X509_BASIC_CONSTRAINTS, &s, v_bc_empty);
}
TEST(bc_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_BASIC_CONSTRAINTS_INFO *s = DEC(X509_BASIC_CONSTRAINTS, v_bc_ca_pl2_sub, 0, NULL);
    if (s) {
        CHECK(s->SubjectType.cbData == 1 && s->SubjectType.pbData[0] == CERT_CA_SUBJECT_FLAG && s->SubjectType.cUnusedBits == 0);
        CHECK(s->fPathLenConstraint && s->dwPathLenConstraint == 2);
        CHECK(s->cSubtreesConstraint == 1);
        if (s->cSubtreesConstraint == 1) CHECK(s->rgSubtreesConstraint[0].cbData == sizeof v_name_cn_test && !memcmp(s->rgSubtreesConstraint[0].pbData, v_name_cn_test, sizeof v_name_cn_test));
        LocalFree(s);
    }
    s = DEC(X509_BASIC_CONSTRAINTS, v_bc_empty, 0, NULL);
    if (s) { CHECK(s->SubjectType.cbData == 0 && !s->fPathLenConstraint && s->cSubtreesConstraint == 0); LocalFree(s); }
    ROUNDTRIP_TO(X509_BASIC_CONSTRAINTS, v_bc_ca, v_bc_ca_enc);
    ROUNDTRIP_TO(X509_BASIC_CONSTRAINTS, v_bc_ca_pl2, v_bc_ca_pl2_enc);
    ROUNDTRIP_TO(X509_BASIC_CONSTRAINTS, v_bc_ca_pl2_sub, v_bc_ca_pl2_sub_enc);
}

/* ---- key usage (bit string) -------------------------------------------- */
TEST(keyusage_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE ds = CERT_DIGITAL_SIGNATURE_KEY_USAGE, two[] = { 0xA0, 0x80 }, cc = CERT_KEY_CERT_SIGN_KEY_USAGE | CERT_CRL_SIGN_KEY_USAGE;
    CRYPT_BIT_BLOB b = { 1, &ds, 7 };
    ENC_EQ(X509_KEY_USAGE, &b, v_ku_ds);
    ENC_EQ(szOID_KEY_USAGE, &b, v_ku_ds);
    CRYPT_BIT_BLOB b2 = { 2, two, 7 };
    ENC_EQ(X509_KEY_USAGE, &b2, v_ku_two);
    CRYPT_BIT_BLOB b3 = { 1, &cc, 1 };
    ENC_EQ(X509_KEY_USAGE, &b3, v_ku_cert_crl);
    CRYPT_BIT_BLOB b4 = { 0, NULL, 0 };
    ENC_EQ(X509_KEY_USAGE, &b4, v_ku_empty);
}
TEST(keyusage_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CRYPT_BIT_BLOB *b = DEC(X509_KEY_USAGE, v_ku_ds, 0, NULL);
    if (b) { CHECK(b->cbData == 1 && b->pbData[0] == 0x80 && b->cUnusedBits == 7); LocalFree(b); }
    b = DEC(X509_KEY_USAGE, v_ku_two, 0, NULL);
    if (b) { CHECK(b->cbData == 2 && b->pbData[0] == 0xA0 && b->pbData[1] == 0x80 && b->cUnusedBits == 7); LocalFree(b); }
    b = DEC(X509_KEY_USAGE, v_ku_cert_crl, 0, NULL);
    if (b) { CHECK(b->cbData == 1 && b->pbData[0] == 0x06 && b->cUnusedBits == 1); LocalFree(b); }
    b = DEC(X509_KEY_USAGE, v_ku_empty, 0, NULL);
    if (b) { CHECK(b->cbData == 0 && b->cUnusedBits == 0); LocalFree(b); }
    b = DEC(szOID_KEY_USAGE, v_ku_ds, 0, NULL);
    if (b) { CHECK(b->cbData == 1); LocalFree(b); }
    DWORD c1, c2; b = DEC(X509_KEY_USAGE, v_ku_two, 0, &c1);
    CRYPT_BIT_BLOB *n = DEC(X509_KEY_USAGE, v_ku_two, CRYPT_DECODE_NOCOPY_FLAG, &c2);
    if (n) { /* bit strings are copied even with NOCOPY (probed): same size, not in place */
        CHECKF(!PTR_IN(n->pbData, v_ku_two, sizeof v_ku_two), "ptr %p input %p", n->pbData, v_ku_two); if (b) CHECKF(c2 == c1, "nocopy size %lu copy size %lu", c2, c1); LocalFree(n); }
    if (b) LocalFree(b);
}
TEST(keyusage_decode_errors) {
    REQUIRE(U(CryptDecodeObjectEx));
    { DWORD cb = 0; SET_ERR(0); BOOL r = U(CryptDecodeObjectEx)(ENC, X509_KEY_USAGE, v_ku_bad_unused, sizeof v_ku_bad_unused, 0, NULL, NULL, &cb);
      EXPECT_FAIL(!r, HR_ASN1_CORRUPT); } /* observed */
    a_dec_fail(__FILE__, __LINE__, X509_KEY_USAGE, v_bc2_ca, sizeof v_bc2_ca, 0, HR_ASN1_BADTAG);
    BYTE trunc[] = { 0x03, 0x03, 0x07, 0x80 };
    a_dec_fail(__FILE__, __LINE__, X509_KEY_USAGE, trunc, sizeof trunc, 0, HR_ASN1_EOD);
}
TEST(keyusage_roundtrips_and_netscape_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    ROUNDTRIP(X509_KEY_USAGE, v_ku_ds); ROUNDTRIP(X509_KEY_USAGE, v_ku_two);
    ROUNDTRIP(X509_KEY_USAGE, v_ku_cert_crl); ROUNDTRIP(X509_KEY_USAGE, v_ku_empty);
    ROUNDTRIP(X509_BITS, v_ku_two);
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, szOID_NETSCAPE_CERT_TYPE, v_ns_cert_type, sizeof v_ns_cert_type, CRYPT_DECODE_ALLOC_FLAG, NULL, &(void *){0}, &cb);
    EXPECT_FAIL(!r, ERROR_FILE_NOT_FOUND); /* observed: no decoder registered for this OID */
}

/* ---- enhanced key usage ------------------------------------------------- */
TEST(eku_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ENHKEY_USAGE e = { 0, NULL };
    ENC_EQ(X509_ENHANCED_KEY_USAGE, &e, v_eku_empty);
    LPSTR two[] = { (LPSTR)szOID_PKIX_KP_SERVER_AUTH, (LPSTR)szOID_PKIX_KP_CLIENT_AUTH };
    e.cUsageIdentifier = 2; e.rgpszUsageIdentifier = two;
    ENC_EQ(X509_ENHANCED_KEY_USAGE, &e, v_eku_two);
    ENC_EQ(szOID_ENHANCED_KEY_USAGE, &e, v_eku_two);
    LPSTR any[] = { (LPSTR)szOID_ANY_ENHANCED_KEY_USAGE }; e.cUsageIdentifier = 1; e.rgpszUsageIdentifier = any;
    ENC_EQ(X509_ENHANCED_KEY_USAGE, &e, v_eku_any);
}
TEST(eku_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_ENHKEY_USAGE *e = DEC(X509_ENHANCED_KEY_USAGE, v_eku_two, 0, NULL);
    if (e) { CHECK(e->cUsageIdentifier == 2 && !strcmp(e->rgpszUsageIdentifier[0], szOID_PKIX_KP_SERVER_AUTH) && !strcmp(e->rgpszUsageIdentifier[1], szOID_PKIX_KP_CLIENT_AUTH)); LocalFree(e); }
    e = DEC(X509_ENHANCED_KEY_USAGE, v_eku_empty, 0, NULL);
    if (e) { CHECK(e->cUsageIdentifier == 0); LocalFree(e); }
    e = DEC(szOID_ENHANCED_KEY_USAGE, v_eku_any, 0, NULL);
    if (e) { CHECK(e->cUsageIdentifier == 1 && !strcmp(e->rgpszUsageIdentifier[0], "2.5.29.37.0")); LocalFree(e); }
    DWORD c1, c2; e = DEC(X509_ENHANCED_KEY_USAGE, v_eku_two, 0, &c1);
    CERT_ENHKEY_USAGE *s = DEC(X509_ENHANCED_KEY_USAGE, v_eku_two, CRYPT_DECODE_SHARE_OID_STRING_FLAG, &c2);
    if (s) { CHECK(!strcmp(s->rgpszUsageIdentifier[0], szOID_PKIX_KP_SERVER_AUTH)); 
        /* observed: with SHARE_OID_STRING the registered OID strings are shared, not copied, which saves 48 bytes */
        CHECK(!PTR_IN(s->rgpszUsageIdentifier[0], s, c2)); EXPECT_EQ(c2, 32); EXPECT_EQ(c1, 80); LocalFree(s); }
    if (e) LocalFree(e);
    a_dec_fail(__FILE__, __LINE__, X509_ENHANCED_KEY_USAGE, v_eku_bad_item, sizeof v_eku_bad_item, 0, HR_ASN1_BADTAG);
    ROUNDTRIP(X509_ENHANCED_KEY_USAGE, v_eku_two);
    ROUNDTRIP(X509_ENHANCED_KEY_USAGE, v_eku_empty);
}
TEST(eku_encode_invalid_oid) {
    REQUIRE(U(CryptEncodeObjectEx));
    LPSTR bad[] = { (LPSTR)"1.2.x" }; CERT_ENHKEY_USAGE e = { 1, bad };
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_ENHANCED_KEY_USAGE, &e, 0, NULL, NULL, &cb);
    /* the OID string parser is lenient: a non-numeric arc encodes as 0 (probed on Windows 10) */
    static const BYTE lenient[] = { 0x30, 0x04, 0x06, 0x02, 0x2a, 0x00 };
    CHECKF(r, "ret %d cb %lu err 0x%lx", r, cb, GetLastError());
    ENC_EQ(X509_ENHANCED_KEY_USAGE, &e, lenient);
    LPSTR one[] = { (LPSTR)"1" }; e.rgpszUsageIdentifier = one; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, X509_ENHANCED_KEY_USAGE, &e, 0, NULL, NULL, &cb);
    EXPECT_FAIL(!r, 0x80093109); /* observed: a single-arc OID is rejected */
}

/* ---- authority key identifier ------------------------------------------- */
TEST(authkeyid_v1_encode_decode) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE kid[] = { 1, 2, 3, 4 };
    CERT_AUTHORITY_KEY_ID_INFO s; memset(&s, 0, sizeof s);
    ENC_EQ(X509_AUTHORITY_KEY_ID, &s, v_aki_empty);
    s.KeyId.cbData = 4; s.KeyId.pbData = kid;
    ENC_EQ(X509_AUTHORITY_KEY_ID, &s, v_aki_keyid);
    ENC_EQ(szOID_AUTHORITY_KEY_IDENTIFIER, &s, v_aki_keyid);
    static BYTE ser[] = { 1 }; memset(&s, 0, sizeof s);
    s.CertSerialNumber.cbData = 1; s.CertSerialNumber.pbData = ser;
    ENC_EQ(X509_AUTHORITY_KEY_ID, &s, v_aki_serial1);
    s.CertIssuer.cbData = sizeof v_name_cn_test; s.CertIssuer.pbData = (BYTE *)v_name_cn_test;
    /* the legacy structure puts the issuer name blob straight into [1] (no directoryName wrapper) */
    ENC_EQ(X509_AUTHORITY_KEY_ID, &s, v_aki_issuer_serial_enc);
    CERT_AUTHORITY_KEY_ID_INFO *d = DEC(X509_AUTHORITY_KEY_ID, v_aki_keyid, 0, NULL);
    if (d) { CHECK(d->KeyId.cbData == 4 && !memcmp(d->KeyId.pbData, kid, 4)); CHECK(d->CertIssuer.cbData == 0 && d->CertSerialNumber.cbData == 0); LocalFree(d); }
    d = DEC(X509_AUTHORITY_KEY_ID, v_aki_serial1, 0, NULL);
    if (d) { CHECK(d->KeyId.cbData == 0 && d->CertSerialNumber.cbData == 1 && d->CertSerialNumber.pbData[0] == 1); LocalFree(d); }
    d = DEC(X509_AUTHORITY_KEY_ID, v_aki_empty, 0, NULL);
    if (d) { CHECK(d->KeyId.cbData == 0); LocalFree(d); }
}
TEST(authkeyid_v1_issuer_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb;
    CERT_AUTHORITY_KEY_ID_INFO *d = (CERT_AUTHORITY_KEY_ID_INFO *)a_dec(__FILE__, __LINE__, X509_AUTHORITY_KEY_ID, v_aki_issuer_serial, sizeof v_aki_issuer_serial, 0, &cb);
    if (d) {
        EXPECT_EQ(d->CertIssuer.cbData, 19); /* observed */
        CHECK(d->CertSerialNumber.cbData == 1);
        LocalFree(d);
    }
}
TEST(authkeyid2_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE kid[] = { 1, 2, 3, 4 }, ser1[] = { 1 }, ser3[] = { 1, 2, 3 };
    CERT_AUTHORITY_KEY_ID2_INFO s; memset(&s, 0, sizeof s);
    ENC_EQ(X509_AUTHORITY_KEY_ID2, &s, v_aki_empty);
    s.KeyId.cbData = 4; s.KeyId.pbData = kid;
    ENC_EQ(X509_AUTHORITY_KEY_ID2, &s, v_aki2_keyid);
    ENC_EQ(szOID_AUTHORITY_KEY_IDENTIFIER2, &s, v_aki2_keyid);
    memset(&s, 0, sizeof s);
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_URL }; e.pwszURL = (LPWSTR)wurl;
    s.AuthorityCertIssuer.cAltEntry = 1; s.AuthorityCertIssuer.rgAltEntry = &e;
    ENC_EQ(X509_AUTHORITY_KEY_ID2, &s, v_aki2_issuer_url);
    CERT_ALT_NAME_ENTRY d = { CERT_ALT_NAME_DIRECTORY_NAME }; d.DirectoryName.cbData = sizeof v_name_cn_test; d.DirectoryName.pbData = (BYTE *)v_name_cn_test;
    s.AuthorityCertIssuer.rgAltEntry = &d;
    ENC_EQ(X509_AUTHORITY_KEY_ID2, &s, v_aki2_issuer_dir);
    memset(&s, 0, sizeof s);
    s.AuthorityCertSerialNumber.cbData = 3; s.AuthorityCertSerialNumber.pbData = ser3;
    ENC_EQ(X509_AUTHORITY_KEY_ID2, &s, v_aki2_serial);   /* serial bytes are stored reversed (little-endian blob) */
    s.AuthorityCertSerialNumber.cbData = 1; s.AuthorityCertSerialNumber.pbData = ser1;
    memset(&s.KeyId, 0, sizeof s.KeyId);
    ENC_EQ(X509_AUTHORITY_KEY_ID2, &s, v_aki_serial1);
    s.KeyId.cbData = 4; s.KeyId.pbData = kid;
    s.AuthorityCertIssuer.cAltEntry = 1; s.AuthorityCertIssuer.rgAltEntry = &d;
    ENC_EQ(X509_AUTHORITY_KEY_ID2, &s, v_aki2_all);
}
TEST(authkeyid2_encode_invalid_issuer_entry) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_AUTHORITY_KEY_ID2_INFO s; memset(&s, 0, sizeof s);
    CERT_ALT_NAME_ENTRY e; memset(&e, 0, sizeof e);
    s.AuthorityCertIssuer.cAltEntry = 1; s.AuthorityCertIssuer.rgAltEntry = &e;
    a_enc_fail_x(__FILE__, __LINE__, X509_AUTHORITY_KEY_ID2, &s, 0, HR_INVALIDARG, 1);
}
TEST(authkeyid2_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_AUTHORITY_KEY_ID2_INFO *d = DEC(X509_AUTHORITY_KEY_ID2, v_aki2_all, 0, NULL);
    if (d) {
        CHECK(d->KeyId.cbData == 4 && d->KeyId.pbData[3] == 4);
        CHECK(d->AuthorityCertIssuer.cAltEntry == 1);
        if (d->AuthorityCertIssuer.cAltEntry == 1) {
            CERT_ALT_NAME_ENTRY *e = d->AuthorityCertIssuer.rgAltEntry;
            CHECK(e->dwAltNameChoice == CERT_ALT_NAME_DIRECTORY_NAME);
            CHECK(e->DirectoryName.cbData == sizeof v_name_cn_test && !memcmp(e->DirectoryName.pbData, v_name_cn_test, sizeof v_name_cn_test));
        }
        CHECK(d->AuthorityCertSerialNumber.cbData == 1 && d->AuthorityCertSerialNumber.pbData[0] == 1);
        LocalFree(d);
    }
    d = DEC(X509_AUTHORITY_KEY_ID2, v_aki2_issuer_url, 0, NULL);
    if (d) { CHECK(d->KeyId.cbData == 0); CHECK(d->AuthorityCertIssuer.rgAltEntry[0].dwAltNameChoice == CERT_ALT_NAME_URL); LocalFree(d); }
    d = DEC(szOID_AUTHORITY_KEY_IDENTIFIER2, v_aki2_keyid, 0, NULL);
    if (d) { CHECK(d->KeyId.cbData == 4); LocalFree(d); }
    d = DEC(X509_AUTHORITY_KEY_ID2, v_aki2_serial, 0, NULL);
    if (d) { CHECK(d->AuthorityCertSerialNumber.cbData == 3 && !memcmp(d->AuthorityCertSerialNumber.pbData, "\x01\x02\x03", 3)); LocalFree(d); }
    ROUNDTRIP(X509_AUTHORITY_KEY_ID2, v_aki2_keyid);
    ROUNDTRIP(X509_AUTHORITY_KEY_ID2, v_aki2_issuer_url);
    ROUNDTRIP(X509_AUTHORITY_KEY_ID2, v_aki2_issuer_dir);
    ROUNDTRIP(X509_AUTHORITY_KEY_ID2, v_aki2_all);
    ROUNDTRIP(X509_AUTHORITY_KEY_ID2, v_aki_empty);
}

/* ---- subject key identifier (octet string) ------------------------------ */
TEST(subjectkeyid_octet_string) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE k[] = { 1, 2, 3 };
    CRYPT_DATA_BLOB b = { 3, k };
    ENC_EQ(X509_OCTET_STRING, &b, v_ski_3);
    ENC_EQ(szOID_SUBJECT_KEY_IDENTIFIER, &b, v_ski_3);
    CRYPT_DATA_BLOB z = { 0, NULL };
    ENC_EQ(X509_OCTET_STRING, &z, v_ski_empty);
    CRYPT_DATA_BLOB *d = DEC(szOID_SUBJECT_KEY_IDENTIFIER, v_ski_3, 0, NULL);
    if (d) { CHECK(d->cbData == 3 && !memcmp(d->pbData, k, 3)); LocalFree(d); }
    d = DEC(X509_OCTET_STRING, v_ski_empty, 0, NULL);
    if (d) { CHECK(d->cbData == 0); LocalFree(d); }
    DWORD c1, c2; d = DEC(X509_OCTET_STRING, v_ski_3, 0, &c1);
    CRYPT_DATA_BLOB *n = DEC(X509_OCTET_STRING, v_ski_3, CRYPT_DECODE_NOCOPY_FLAG, &c2);
    if (n) { CHECK(n->pbData == v_ski_3 + 2); if (d) CHECK(c2 < c1); LocalFree(n); }
    if (d) LocalFree(d);
    a_dec_fail(__FILE__, __LINE__, X509_OCTET_STRING, v_bc2_ca, sizeof v_bc2_ca, 0, HR_ASN1_BADTAG);
}

/* ---- key attributes / key usage restriction (legacy) -------------------- */
TEST(keyattributes_encode_decode) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE k[] = { 1, 2, 3 }, ds = 0x80;
    CERT_KEY_ATTRIBUTES_INFO s; memset(&s, 0, sizeof s);
    s.KeyId.cbData = 3; s.KeyId.pbData = k;
    s.IntendedKeyUsage.cbData = 1; s.IntendedKeyUsage.pbData = &ds; s.IntendedKeyUsage.cUnusedBits = 7;
    DWORD cb; BYTE *p = a_enc(X509_KEY_ATTRIBUTES, &s, 0, &cb);
    REQUIRE_NOTNULL(p);
    CHECK(cb == sizeof v_ka_keyid_usage && !memcmp(p, v_ka_keyid_usage, cb)); /* observed: equals the reference encoding */
    CERT_KEY_ATTRIBUTES_INFO *d = a_dec(__FILE__, __LINE__, X509_KEY_ATTRIBUTES, p, cb, 0, NULL);
    if (d) { CHECK(d->KeyId.cbData == 3 && !memcmp(d->KeyId.pbData, k, 3) && d->IntendedKeyUsage.cbData == 1 && d->IntendedKeyUsage.cUnusedBits == 7 && d->pPrivateKeyUsagePeriod == NULL); LocalFree(d); }
    LocalFree(p);
    a_alias(__FILE__, __LINE__, X509_KEY_ATTRIBUTES, szOID_KEY_ATTRIBUTES, &s);
}
TEST(keyattributes_private_key_period_roundtrip) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE k[] = { 1, 2, 3 };
    CERT_PRIVATE_KEY_VALIDITY pv; memset(&pv, 0, sizeof pv);
    pv.NotBefore = a_ft(2000, 1, 1, 0, 0, 0); pv.NotAfter = a_ft(2010, 1, 1, 0, 0, 0);
    CERT_KEY_ATTRIBUTES_INFO s; memset(&s, 0, sizeof s);
    s.KeyId.cbData = 3; s.KeyId.pbData = k; s.pPrivateKeyUsagePeriod = &pv;
    DWORD cb; BYTE *p = a_enc(X509_KEY_ATTRIBUTES, &s, 0, &cb);
    REQUIRE_NOTNULL(p);
    CERT_KEY_ATTRIBUTES_INFO *d = a_dec(__FILE__, __LINE__, X509_KEY_ATTRIBUTES, p, cb, 0, NULL);
    CHECK(d && d->pPrivateKeyUsagePeriod);
    if (d && d->pPrivateKeyUsagePeriod) {
        CHECK(a_ft_eq(d->pPrivateKeyUsagePeriod->NotBefore, pv.NotBefore));
        CHECK(a_ft_eq(d->pPrivateKeyUsagePeriod->NotAfter, pv.NotAfter));
    }
    if (d) LocalFree(d);
    LocalFree(p);
}
TEST(keyusagerestriction_encode_decode) {
    REQUIRE(U(CryptEncodeObjectEx));
    static BYTE ds = 0x80;
    LPSTR el[] = { (LPSTR)"1.2.3" };
    CERT_POLICY_ID pid = { 1, el };
    CERT_KEY_USAGE_RESTRICTION_INFO s; memset(&s, 0, sizeof s);
    s.RestrictedKeyUsage.cbData = 1; s.RestrictedKeyUsage.pbData = &ds; s.RestrictedKeyUsage.cUnusedBits = 7;
    s.cCertPolicyId = 1; s.rgCertPolicyId = &pid;
    DWORD cb; BYTE *p = a_enc(X509_KEY_USAGE_RESTRICTION, &s, 0, &cb);
    REQUIRE_NOTNULL(p);
    CHECK(cb == sizeof v_kur_pol && !memcmp(p, v_kur_pol, cb)); /* observed: equals the reference encoding */
    CERT_KEY_USAGE_RESTRICTION_INFO *d = a_dec(__FILE__, __LINE__, X509_KEY_USAGE_RESTRICTION, p, cb, 0, NULL);
    if (d) {
        CHECK(d->cCertPolicyId == 1 && d->rgCertPolicyId[0].cCertPolicyElementId == 1 && !strcmp(d->rgCertPolicyId[0].rgpszCertPolicyElementId[0], "1.2.3"));
        CHECK(d->RestrictedKeyUsage.cbData == 1 && d->RestrictedKeyUsage.cUnusedBits == 7 && d->RestrictedKeyUsage.pbData[0] == 0x80);
        LocalFree(d);
    }
    LocalFree(p);
    a_alias(__FILE__, __LINE__, X509_KEY_USAGE_RESTRICTION, szOID_KEY_USAGE_RESTRICTION, &s);
}

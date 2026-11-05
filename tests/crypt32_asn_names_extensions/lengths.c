/* DER length forms, string character sets and OID arc encoding. */
#include "asn.h"

/* header for tag+len; returns header size */
static DWORD hdr(BYTE *o, BYTE tag, DWORD n) {
    DWORD i = 0; o[i++] = tag;
    if (n < 128) o[i++] = (BYTE)n;
    else if (n < 256) { o[i++] = 0x81; o[i++] = (BYTE)n; }
    else if (n < 65536) { o[i++] = 0x82; o[i++] = (BYTE)(n >> 8); o[i++] = (BYTE)n; }
    else { o[i++] = 0x83; o[i++] = (BYTE)(n >> 16); o[i++] = (BYTE)(n >> 8); o[i++] = (BYTE)n; }
    return i;
}

static const DWORD lens[] = { 0, 1, 126, 127, 128, 129, 255, 256, 257, 1000, 65535, 65536, 70000 };

TEST(lengths_octet_string_encode_all_length_forms) {
    REQUIRE(U(CryptEncodeObjectEx));
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        DWORD n = lens[i];
        BYTE *data = (BYTE *)LocalAlloc(LPTR, n + 1), *exp = (BYTE *)LocalAlloc(LPTR, n + 8);
        for (DWORD k = 0; k < n; k++) data[k] = (BYTE)(k * 7 + 1);
        DWORD h = hdr(exp, 0x04, n); memcpy(exp + h, data, n);
        CRYPT_DATA_BLOB b = { n, data };
        DWORD cb = 0; BYTE *p = a_enc(X509_OCTET_STRING, &b, 0, &cb);
        CHECKF(p && cb == h + n && !memcmp(p, exp, h + n), "length %lu", n);
        if (p) {
            CRYPT_DATA_BLOB *d = a_dec(__FILE__, __LINE__, X509_OCTET_STRING, p, cb, 0, NULL);
            CHECKF(d && d->cbData == n && !memcmp(d->pbData, data, n), "decode length %lu", n);
            if (d) LocalFree(d);
            LocalFree(p);
        }
        LocalFree(data); LocalFree(exp);
    }
}
TEST(lengths_name_value_all_length_forms) {
    REQUIRE(U(CryptEncodeObjectEx));
    static const DWORD ls[] = { 0, 1, 127, 128, 255, 256, 1000 };
    for (unsigned i = 0; i < sizeof ls / sizeof *ls; i++) {
        DWORD n = ls[i];
        BYTE *s = (BYTE *)LocalAlloc(LPTR, n + 1), *exp = (BYTE *)LocalAlloc(LPTR, n + 8);
        memset(s, 'a', n);
        DWORD h = hdr(exp, 0x16, n); memcpy(exp + h, s, n);
        CERT_NAME_VALUE v = { CERT_RDN_IA5_STRING, { n, s } };
        DWORD cb = 0; BYTE *p = a_enc(X509_NAME_VALUE, &v, 0, &cb);
        CHECKF(p && cb == h + n && !memcmp(p, exp, h + n), "ansi length %lu", n);
        if (p) LocalFree(p);
        LocalFree(s); LocalFree(exp);
    }
}
TEST(lengths_name_with_long_value_nested_headers) {
    REQUIRE(U(CryptEncodeObjectEx));
    DWORD n = 300;
    BYTE *s = (BYTE *)LocalAlloc(LPTR, n); memset(s, 'x', n);
    CERT_RDN_ATTR a = { (LPSTR)"2.5.4.3", CERT_RDN_IA5_STRING, { n, s } };
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    /* value: 0c 82 01 2c <300>; attr: 30 82 01 35 06 03 55 04 03 <value 304>; set: 31 82 01 39; seq: 30 82 01 3d */
    DWORD cb = 0; BYTE *p = a_enc(X509_NAME, &ni, 0, &cb);
    CHECK(p != NULL);
    if (p) {
        static const BYTE head[] = { 0x30, 0x82, 0x01, 0x3d, 0x31, 0x82, 0x01, 0x39, 0x30, 0x82, 0x01, 0x35, 0x06, 0x03, 0x55, 0x04, 0x03, 0x16, 0x82, 0x01, 0x2c };
        CHECK(cb == sizeof head + n && !memcmp(p, head, sizeof head));
        CERT_NAME_INFO *d = a_dec(__FILE__, __LINE__, X509_NAME, p, cb, 0, NULL);
        CHECK(d && d->rgRDN[0].rgRDNAttr[0].Value.cbData == n);
        if (d) LocalFree(d);
        LocalFree(p);
    }
    LocalFree(s);
}
TEST(lengths_ber_leniency_probes) {
    REQUIRE(U(CryptDecodeObjectEx));
    static const BYTE long_form[] = { 0x30, 0x81, 0x03, 0x01, 0x01, 0xFF };      /* non-minimal length */
    static const BYTE long_form2[] = { 0x30, 0x82, 0x00, 0x03, 0x01, 0x01, 0xFF };
    static const BYTE indef_nested[] = { 0x30, 0x80, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x03, 0x00, 0x00 };
    const BYTE *vs[] = { long_form, long_form2, indef_nested }; DWORD ns[] = { sizeof long_form, sizeof long_form2, sizeof indef_nested };
    for (int i = 0; i < 3; i++) {
        DWORD cb = 0; SET_ERR(0);
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, vs[i], ns[i], 0, NULL, NULL, &cb);
        /* observed: non-minimal long-form lengths and an indefinite-length SEQUENCE (with extra trailing members) are all accepted */
        CHECKF(r, "BER form %d err 0x%lx", i, GetLastError());
    }
}
TEST(lengths_decode_oversized_length_field) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_NAME, v_seq_huge_len, sizeof v_seq_huge_len, 0, NULL, NULL, &cb);
    CHECK(!r);
    DWORD e = GetLastError();
    EXPECT_EQ(e, HR_ASN1_EOD); /* observed */
    SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, X509_NAME, v_seq_long_form_len, sizeof v_seq_long_form_len, 0, NULL, NULL, &cb);
    /* "30 81 00" is a long-form zero length: accepted as an empty name (probed) */
    CHECKF(r, "ret %d err 0x%lx", r, GetLastError());
}

/* ---- character sets ------------------------------------------------------ */
static int printable_ok(unsigned c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ' || c == '\'' || c == '(' || c == ')' || c == '+' || c == ',' || c == '-' || c == '.' || c == '/' || c == ':' || c == '=' || c == '?';
}
static BOOL enc1(DWORD type, WCHAR ch, DWORD *loc) {
    WCHAR w[3] = { 'a', ch, 0 };
    CERT_RDN_ATTR a = { (LPSTR)"2.5.4.3", type, { 0, (BYTE *)w } };
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    DWORD cb = 0; BOOL r = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, 0, NULL, NULL, &cb);
    if (loc) *loc = cb;
    return r;
}
TEST(charset_printable_exact_set) {
    REQUIRE(U(CryptEncodeObjectEx));
    unsigned bad = 0, wrong_loc = 0;
    for (unsigned c = 1; c < 512; c++) {
        DWORD loc = 0;
        SET_ERR(0);
        BOOL r = enc1(CERT_RDN_PRINTABLE_STRING, (WCHAR)c, &loc);
        if (!!r != !!printable_ok(c)) { bad++; t_note("printable char 0x%x: ok=%d", c, r); }
        else if (!r && (GET_CERT_UNICODE_VALUE_ERR_INDEX(loc) != 1)) wrong_loc++;
        if (!r && GetLastError() != (DWORD)CRYPT_E_INVALID_PRINTABLE_STRING) bad++;
    }
    CHECK(bad == 0); CHECK(wrong_loc == 0);
}
TEST(charset_numeric_exact_set) {
    REQUIRE(U(CryptEncodeObjectEx));
    unsigned bad = 0;
    /* the first character 'a' of enc1 is itself invalid for a numeric string: use a leading digit instead */
    for (unsigned c = 1; c < 512; c++) {
        WCHAR w[3] = { '1', (WCHAR)c, 0 };
        CERT_RDN_ATTR a = { (LPSTR)"2.5.4.3", CERT_RDN_NUMERIC_STRING, { 0, (BYTE *)w } };
        CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
        DWORD cb = 0; SET_ERR(0);
        BOOL r = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, 0, NULL, NULL, &cb);
        int ok = (c >= '0' && c <= '9') || c == ' ';
        if (!!r != ok) { bad++; t_note("numeric char 0x%x: ok=%d", c, r); }
        if (!r && GetLastError() != (DWORD)CRYPT_E_INVALID_NUMERIC_STRING) bad++;
    }
    CHECK(bad == 0);
}
TEST(charset_ia5_exact_set) {
    REQUIRE(U(CryptEncodeObjectEx));
    unsigned bad = 0;
    for (unsigned c = 1; c < 512; c++) {
        SET_ERR(0);
        BOOL r = enc1(CERT_RDN_IA5_STRING, (WCHAR)c, NULL);
        int ok = c < 128;
        if (!!r != ok) { bad++; t_note("ia5 char 0x%x: ok=%d", c, r); }
        if (!r && GetLastError() != (DWORD)CRYPT_E_INVALID_IA5_STRING) bad++;
    }
    CHECK(bad == 0);
}
TEST(charset_bmp_and_utf8_accept_everything_valid) {
    REQUIRE(U(CryptEncodeObjectEx));
    unsigned bad = 0;
    for (unsigned c = 1; c < 0x3000; c += 1) {
        if (c >= 0xD800 && c <= 0xDFFF) continue;
        if (!enc1(CERT_RDN_BMP_STRING, (WCHAR)c, NULL)) bad++;
        if (!enc1(CERT_RDN_UTF8_STRING, (WCHAR)c, NULL)) bad++;
    }
    CHECK(bad == 0);
}
TEST(charset_lone_surrogate_probe) {
    REQUIRE(U(CryptEncodeObjectEx));
    SET_ERR(0);
    BOOL r = enc1(CERT_RDN_UTF8_STRING, 0xD800, NULL);
    CHECKF(r, "UTF8String from a lone high surrogate: err 0x%lx", GetLastError()); /* observed: accepted */
    SET_ERR(0);
    r = enc1(CERT_RDN_BMP_STRING, 0xD800, NULL);
    CHECK(r); /* observed: accepted */
}
TEST(charset_t61_wide_characters_probe) {
    REQUIRE(U(CryptEncodeObjectEx));
    unsigned acc = 0;
    for (unsigned c = 0x80; c < 0x100; c++) { SET_ERR(0); if (enc1(CERT_RDN_T61_STRING, (WCHAR)c, NULL)) acc++; }
    EXPECT_EQ(acc, 128); /* observed: every Latin-1 character */
    SET_ERR(0);
    BOOL r = enc1(CERT_RDN_T61_STRING, 0x20AC, NULL);
    CHECKF(r, "T61 string with U+20AC: err 0x%lx", GetLastError()); /* observed: accepted */
}

/* ---- OID arc encoding ------------------------------------------------------ */
TEST(oid_arcs_in_name_attributes) {
    REQUIRE(U(CryptEncodeObjectEx));
    for (unsigned i = 0; i < sizeof oid_table / sizeof *oid_table; i++) {
        CERT_RDN_ATTR a = { (LPSTR)oid_table[i].s, CERT_RDN_PRINTABLE_STRING, { 1, (BYTE *)"a" } };
        CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
        DWORD cb = 0; BYTE *p = a_enc(X509_NAME, &ni, 0, &cb);
        t_label("oid %s", oid_table[i].s);
        if (!p) { t_check(0, __FILE__, __LINE__, "encode attribute OID", "%s err 0x%lx", oid_table[i].s, GetLastError()); continue; }
        /* 30 L 31 L 30 L 06 n <oid> 13 01 61 */
        DWORD n = oid_table[i].n;
        CHECK(cb == 2 + 2 + 2 + 2 + n + 3 && p[6] == 0x06 && p[7] == n && !memcmp(p + 8, oid_table[i].d, n));
        CERT_NAME_INFO *d = a_dec(__FILE__, __LINE__, X509_NAME, p, cb, 0, NULL);
        CHECK(d && !strcmp(d->rgRDN[0].rgRDNAttr[0].pszObjId, oid_table[i].s));
        if (d) LocalFree(d);
        LocalFree(p);
    }
}
TEST(oid_arcs_in_enhanced_key_usage) {
    REQUIRE(U(CryptEncodeObjectEx));
    for (unsigned i = 0; i < sizeof oid_table / sizeof *oid_table; i++) {
        LPSTR u[1] = { (LPSTR)oid_table[i].s }; CERT_ENHKEY_USAGE e = { 1, u };
        DWORD cb = 0; BYTE *p = a_enc(X509_ENHANCED_KEY_USAGE, &e, 0, &cb);
        if (!p) { t_check(0, __FILE__, __LINE__, "encode EKU OID", "%s err 0x%lx", oid_table[i].s, GetLastError()); continue; }
        DWORD n = oid_table[i].n;
        CHECK(cb == 2 + 2 + n && p[0] == 0x30 && p[1] == n + 2 && p[2] == 0x06 && p[3] == n && !memcmp(p + 4, oid_table[i].d, n));
        CERT_ENHKEY_USAGE *d = a_dec(__FILE__, __LINE__, X509_ENHANCED_KEY_USAGE, p, cb, 0, NULL);
        CHECK(d && d->cUsageIdentifier == 1 && !strcmp(d->rgpszUsageIdentifier[0], oid_table[i].s));
        if (d) LocalFree(d);
        LocalFree(p);
    }
}
TEST(oid_arcs_in_alt_name_registered_id) {
    REQUIRE(U(CryptEncodeObjectEx));
    for (unsigned i = 0; i < sizeof oid_table / sizeof *oid_table; i++) {
        CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_REGISTERED_ID }; e.pszRegisteredID = (LPSTR)oid_table[i].s;
        CERT_ALT_NAME_INFO an = { 1, &e };
        DWORD cb = 0; BYTE *p = a_enc(X509_ALTERNATE_NAME, &an, 0, &cb);
        if (!p) { t_check(0, __FILE__, __LINE__, "encode registeredID", "%s err 0x%lx", oid_table[i].s, GetLastError()); continue; }
        DWORD n = oid_table[i].n;
        CHECK(cb == 2 + 2 + n && p[2] == 0x88 && p[3] == n && !memcmp(p + 4, oid_table[i].d, n));
        LocalFree(p);
    }
}
TEST(oid_malformed_strings) {
    REQUIRE(U(CryptEncodeObjectEx));
    /* Windows 10 rejects structural errors with ASN1_BADARG and takes non-numeric arcs leniently (they become 0 or wrap). */
    static const struct { const char *s; DWORD err; const char *hex; } rows[] = {
        { "",         HR_INVALIDARG, NULL },
        { "1",        0x80093109, NULL },
        { "1..2",     0x80093109, NULL },
        { "1.2.",     0x80093109, NULL },
        { ".1.2",     0x80093109, NULL },
        { "3.1",      0x80093109, NULL },
        { "1.40",     0x80093109, NULL },
        { "1. 2",     0x80093109, NULL },
        { "1.2.x",    0, "3004" "06022a00" },
        /* an arc that stops at a letter keeps its leading digits; a fresh value is used because crypt32 remembers OID strings it has seen (decoding 2a03 later would return the malformed text) */
        { "1.2.777777x", 0, "3006" "06042aafbc31" },
        { "2.5.4.-3", 0, "300e" "060c550481ffffffffffffffff7d" },
    };
    for (unsigned i = 0; i < sizeof rows / sizeof *rows; i++) {
        LPSTR u[1] = { (LPSTR)rows[i].s }; CERT_ENHKEY_USAGE e = { 1, u };
        DWORD cb = 0; SET_ERR(0);
        BOOL r = U(CryptEncodeObjectEx)(ENC, X509_ENHANCED_KEY_USAGE, &e, 0, NULL, NULL, &cb);
        DWORD err = GetLastError();
        t_label("OID \"%s\"", rows[i].s);
        if (rows[i].hex) {
            BYTE exp[32]; DWORD n = 0; const char *h = rows[i].hex;
            for (; h[0] && h[1]; h += 2) { unsigned v; sscanf(h, "%2x", &v); exp[n++] = (BYTE)v; }
            CHECKF(r, "ret %d err 0x%lx", r, err);
            a_enc_eq(__FILE__, __LINE__, X509_ENHANCED_KEY_USAGE, &e, 0, exp, n);
        } else {
            CHECKF(!r, "ret %d", r);
            CHECKF(err == rows[i].err, "err got 0x%lx want 0x%lx", err, rows[i].err);
        }
    }
    t_label(NULL);
}

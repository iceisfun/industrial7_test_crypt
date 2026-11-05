/* X509_NAME / X509_UNICODE_NAME / X509_NAME_VALUE encode and decode. */
#include "asn.h"

static const BYTE oid_cn_tlv[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };

/* Name { RDN { CN = <tag,content> } } built from parts (all lengths < 128). */
static DWORD mk_name(BYTE *o, BYTE tag, const BYTE *c, DWORD n) {
    DWORD inner = 5 + 2 + n;           /* oid + tlv */
    DWORD i = 0;
    o[i++] = 0x30; o[i++] = (BYTE)(inner + 4 /* set hdr + attr hdr */ - 0 + 0);
    o[i++] = 0x31; o[i++] = (BYTE)(inner + 2);
    o[i++] = 0x30; o[i++] = (BYTE)inner;
    memcpy(o + i, oid_cn_tlv, 5); i += 5;
    o[i++] = tag; o[i++] = (BYTE)n; memcpy(o + i, c, n); i += n;
    return i;
}

static const WCHAR w_bmp[] = { 'T', 0x00E9, 0x20AC, 0 };
static const BYTE be_bmp[] = { 0x00, 'T', 0x00, 0xE9, 0x20, 0xAC };
static const DWORD u4_in[] = { 'A', 0xE9, 0x1F600 };
static const BYTE be_u4[] = { 0,0,0,'A', 0,0,0,0xE9, 0,0x01,0xF6,0x00 };

struct st_row { const char *label; DWORD type; const BYTE *in; DWORD cb; BYTE tag; const BYTE *out; DWORD outn; };
#define R(l, ty, in_, tag_, out_) { l, ty, (const BYTE *)(in_), sizeof(in_) - 1, tag_, (const BYTE *)(out_), sizeof(out_) - 1 }
static const struct st_row ansi_rows[] = {
    R("numeric",   CERT_RDN_NUMERIC_STRING,   "0123 45", 0x12, "0123 45"),
    R("printable", CERT_RDN_PRINTABLE_STRING, "Ab 1'()+,-./:=?", 0x13, "Ab 1'()+,-./:=?"),
    R("t61",       CERT_RDN_T61_STRING,       "T\xe9st", 0x14, "T\xe9st"),
    R("videotex",  CERT_RDN_VIDEOTEX_STRING,  "vt\x01", 0x15, "vt\x01"),
    R("ia5",       CERT_RDN_IA5_STRING,       "a@b.c_~", 0x16, "a@b.c_~"),
    R("graphic",   CERT_RDN_GRAPHIC_STRING,   "gr", 0x19, "gr"),
    R("visible",   CERT_RDN_VISIBLE_STRING,   "vis ible", 0x1a, "vis ible"),
    R("general",   CERT_RDN_GENERAL_STRING,   "gen", 0x1b, "gen"),
    R("utf8",      CERT_RDN_UTF8_STRING,      "h\xc3\xa9", 0x0c, "h\xc3\xa9"),
    R("octet",     CERT_RDN_OCTET_STRING,     "\x01\x02", 0x04, "\x01\x02"),
    R("empty_printable", CERT_RDN_PRINTABLE_STRING, "", 0x13, ""),
    R("empty_utf8", CERT_RDN_UTF8_STRING,     "", 0x0c, ""),
};

static void set_attr(CERT_RDN_ATTR *a, DWORD type, const void *p, DWORD cb) {
    a->pszObjId = (LPSTR)"2.5.4.3"; a->dwValueType = type;
    a->Value.cbData = cb; a->Value.pbData = (BYTE *)p;
}

TEST(names_ansi_string_type_table) {
    REQUIRE(U(CryptEncodeObjectEx));
    for (unsigned i = 0; i < sizeof ansi_rows / sizeof *ansi_rows; i++) {
        const struct st_row *r = &ansi_rows[i];
        BYTE exp[128]; DWORD en = mk_name(exp, r->tag, r->out, r->outn);
        CERT_RDN_ATTR a; set_attr(&a, r->type, r->in, r->cb);
        CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
        t_note("row %s", r->label);
        a_enc_eq(__FILE__, __LINE__, X509_NAME, &ni, 0, exp, en);
    }
}

TEST(names_ansi_bmp_value_is_big_endian) {
    REQUIRE(U(CryptEncodeObjectEx));
    BYTE exp[64]; DWORD en = mk_name(exp, 0x1e, be_bmp, sizeof be_bmp);
    CERT_RDN_ATTR a; set_attr(&a, CERT_RDN_BMP_STRING, w_bmp, 6);
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    a_enc_eq(__FILE__, __LINE__, X509_NAME, &ni, 0, exp, en);
}

TEST(names_ansi_universal_value_is_big_endian_ucs4) {
    REQUIRE(U(CryptEncodeObjectEx));
    BYTE exp[64]; DWORD en = mk_name(exp, 0x1c, be_u4, sizeof be_u4);
    CERT_RDN_ATTR a; set_attr(&a, CERT_RDN_UNIVERSAL_STRING, u4_in, sizeof u4_in);
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    a_enc_eq(__FILE__, __LINE__, X509_NAME, &ni, 0, exp, en);
}

TEST(names_ansi_encoded_blob_is_verbatim) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_RDN_ATTR a; set_attr(&a, CERT_RDN_ENCODED_BLOB, v_name_value_printable, A_SZ(v_name_value_printable));
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    a_enc_eq(__FILE__, __LINE__, X509_NAME, &ni, 0, v_name_cn_test, A_SZ(v_name_cn_test));
    /* an encoded blob may carry any tag, e.g. a NULL */
    BYTE exp[32]; DWORD en = mk_name(exp, 0x05, (const BYTE *)"", 0);
    set_attr(&a, CERT_RDN_ENCODED_BLOB, v_name_value_null, A_SZ(v_name_value_null));
    a_enc_eq(__FILE__, __LINE__, X509_NAME, &ni, 0, exp, en);
}

TEST(names_encode_empty_name) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_INFO ni = { 0, NULL };
    ENC_EQ(X509_NAME, &ni, v_name_empty);
    CERT_NAME_INFO nu = { 0, NULL };
    ENC_EQ(X509_UNICODE_NAME, &nu, v_name_empty);
}

TEST(names_encode_two_rdns_and_multivalued_rdn) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_RDN_ATTR a[2]; set_attr(&a[0], CERT_RDN_PRINTABLE_STRING, "US", 2);
    a[0].pszObjId = (LPSTR)"2.5.4.6";
    set_attr(&a[1], CERT_RDN_PRINTABLE_STRING, "Test", 4);
    CERT_RDN rdn2[2] = { { 1, &a[0] }, { 1, &a[1] } };
    CERT_NAME_INFO ni = { 2, rdn2 };
    ENC_EQ(X509_NAME, &ni, v_name_c_cn);
    CERT_RDN one = { 2, a }; CERT_NAME_INFO nm = { 1, &one };
    ENC_EQ(X509_NAME, &nm, v_name_multi_attr_rdn);
}

TEST(names_decode_empty_and_indefinite) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb; CERT_NAME_INFO *ni = DEC(X509_NAME, v_name_empty, 0, &cb);
    if (ni) { CHECK(ni->cRDN == 0); CHECK(cb >= sizeof(CERT_NAME_INFO)); LocalFree(ni); }
    ni = DEC(X509_NAME, v_name_empty_indef, 0, &cb);   /* BER indefinite length is accepted */
    if (ni) { CHECK(ni->cRDN == 0); LocalFree(ni); }
    ni = DEC(X509_UNICODE_NAME, v_name_empty, 0, &cb);
    if (ni) { CHECK(ni->cRDN == 0); LocalFree(ni); }
}

TEST(names_decode_simple) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb; CERT_NAME_INFO *ni = DEC(X509_NAME, v_name_cn_test, 0, &cb);
    if (!ni) return;
    CHECK(ni->cRDN == 1);
    if (ni->cRDN == 1) {
        CERT_RDN *r = &ni->rgRDN[0]; CHECK(r->cRDNAttr == 1);
        if (r->cRDNAttr == 1) {
            CERT_RDN_ATTR *a = &r->rgRDNAttr[0];
            CHECK(a->pszObjId && !strcmp(a->pszObjId, "2.5.4.3"));
            CHECK(a->dwValueType == CERT_RDN_PRINTABLE_STRING);
            CHECK(a->Value.cbData == 4 && a->Value.pbData && !memcmp(a->Value.pbData, "Test", 4));
        }
    }
    LocalFree(ni);
}

TEST(names_decode_two_rdns) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_NAME_INFO *ni = DEC(X509_NAME, v_name_c_cn, 0, NULL);
    if (!ni) return;
    CHECK(ni->cRDN == 2);
    if (ni->cRDN == 2) {
        CHECK(ni->rgRDN[0].cRDNAttr == 1 && !strcmp(ni->rgRDN[0].rgRDNAttr[0].pszObjId, "2.5.4.6"));
        CHECK(ni->rgRDN[1].cRDNAttr == 1 && !strcmp(ni->rgRDN[1].rgRDNAttr[0].pszObjId, "2.5.4.3"));
        CHECK(ni->rgRDN[0].rgRDNAttr[0].Value.cbData == 2);
    }
    LocalFree(ni);
    ni = DEC(X509_NAME, v_name_multi_attr_rdn, 0, NULL);
    if (!ni) return;
    CHECK(ni->cRDN == 1 && ni->rgRDN[0].cRDNAttr == 2);
    LocalFree(ni);
}

TEST(names_roundtrips) {
    REQUIRE(U(CryptDecodeObjectEx));
    ROUNDTRIP(X509_NAME, v_name_cn_test);
    ROUNDTRIP(X509_NAME, v_name_c_cn);
    ROUNDTRIP(X509_NAME, v_name_multi_attr_rdn);
    ROUNDTRIP(X509_NAME, v_name_empty);
    ROUNDTRIP(X509_UNICODE_NAME, v_name_cn_test);
    ROUNDTRIP(X509_UNICODE_NAME, v_name_c_cn);
    ROUNDTRIP(X509_UNICODE_NAME, v_name_cn_utf8);
}

TEST(names_decode_ansi_tag_table) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (unsigned i = 0; i < sizeof ansi_rows / sizeof *ansi_rows; i++) {
        const struct st_row *r = &ansi_rows[i];
        BYTE der[128]; DWORD n = mk_name(der, r->tag, r->out, r->outn);
        DWORD cb; CERT_NAME_INFO *ni = a_dec(__FILE__, __LINE__, X509_NAME, der, n, 0, &cb);
        t_note("row %s", r->label);
        if (!ni) continue;
        CHECK(ni->cRDN == 1 && ni->rgRDN[0].cRDNAttr == 1);
        if (ni->cRDN == 1 && ni->rgRDN[0].cRDNAttr == 1) {
            CERT_RDN_ATTR *a = &ni->rgRDN[0].rgRDNAttr[0];
            if (r->tag == 0x04) { if (a->dwValueType != CERT_RDN_OCTET_STRING) t_note("octet tag decoded as type %lu", a->dwValueType); }
            else CHECKF(a->dwValueType == r->type, "type %lu want %lu", a->dwValueType, r->type);
            CHECK(a->Value.cbData == r->outn);
            CHECK(r->outn == 0 || (a->Value.pbData && !memcmp(a->Value.pbData, r->out, r->outn)));
        }
        LocalFree(ni);
    }
}

TEST(names_decode_ansi_bmp_value_native_wchars) {
    REQUIRE(U(CryptDecodeObjectEx));
    BYTE der[64]; DWORD n = mk_name(der, 0x1e, be_bmp, sizeof be_bmp);
    CERT_NAME_INFO *ni = a_dec(__FILE__, __LINE__, X509_NAME, der, n, 0, NULL);
    if (!ni) return;
    CERT_RDN_ATTR *a = &ni->rgRDN[0].rgRDNAttr[0];
    CHECK(a->dwValueType == CERT_RDN_BMP_STRING);
    CHECK(a->Value.cbData == 6 && !memcmp(a->Value.pbData, w_bmp, 6));
    LocalFree(ni);
}

TEST(names_decode_ansi_universal_native_dwords) {
    REQUIRE(U(CryptDecodeObjectEx));
    BYTE der[64]; DWORD n = mk_name(der, 0x1c, be_u4, sizeof be_u4);
    CERT_NAME_INFO *ni = a_dec(__FILE__, __LINE__, X509_NAME, der, n, 0, NULL);
    if (!ni) return;
    CERT_RDN_ATTR *a = &ni->rgRDN[0].rgRDNAttr[0];
    CHECK(a->dwValueType == CERT_RDN_UNIVERSAL_STRING);
    CHECK(a->Value.cbData == sizeof u4_in && !memcmp(a->Value.pbData, u4_in, sizeof u4_in));
    LocalFree(ni);
}

TEST(names_decode_unknown_value_tag_is_encoded_blob) {
    REQUIRE(U(CryptDecodeObjectEx));
    BYTE der[32]; DWORD n = mk_name(der, 0x05, (const BYTE *)"", 0);
    CERT_NAME_INFO *ni = a_dec(__FILE__, __LINE__, X509_NAME, der, n, 0, NULL);
    if (!ni) return;
    CERT_RDN_ATTR *a = &ni->rgRDN[0].rgRDNAttr[0];
    t_note("NULL value decodes as dwValueType %lu cb %lu", a->dwValueType, a->Value.cbData);
    CHECK(a->dwValueType == CERT_RDN_ENCODED_BLOB);
    CHECK(a->Value.cbData == 2 && !memcmp(a->Value.pbData, v_name_value_null, 2));
    LocalFree(ni);
}

TEST(names_decode_nocopy_points_into_input) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb1, cb2;
    CERT_NAME_INFO *c = DEC(X509_NAME, v_name_cn_test, 0, &cb1);
    CERT_NAME_INFO *nc = DEC(X509_NAME, v_name_cn_test, CRYPT_DECODE_NOCOPY_FLAG, &cb2);
    if (nc) {
        CERT_RDN_ATTR *a = &nc->rgRDN[0].rgRDNAttr[0];
        CHECK(PTR_IN(a->Value.pbData, v_name_cn_test, sizeof v_name_cn_test));
        CHECK(a->Value.cbData == 4 && !memcmp(a->Value.pbData, "Test", 4));
        if (c) CHECK(cb2 < cb1);
    }
    if (c) { CHECK(!PTR_IN(c->rgRDN[0].rgRDNAttr[0].Value.pbData, v_name_cn_test, sizeof v_name_cn_test)); LocalFree(c); }
    if (nc) LocalFree(nc);
}

TEST(names_decode_share_oid_string) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb1, cb2;
    CERT_NAME_INFO *c = DEC(X509_NAME, v_name_cn_test, 0, &cb1);
    CERT_NAME_INFO *s = DEC(X509_NAME, v_name_cn_test, CRYPT_DECODE_SHARE_OID_STRING_FLAG, &cb2);
    if (s) {
        LPSTR o = s->rgRDN[0].rgRDNAttr[0].pszObjId;
        CHECK(o && !strcmp(o, "2.5.4.3"));
        CHECK(!PTR_IN(o, s, cb2));           /* shared: lives in crypt32, not in the block */
        if (c) CHECK(cb2 <= cb1);
    }
    if (c) { CHECK(PTR_IN(c->rgRDN[0].rgRDNAttr[0].pszObjId, c, cb1)); LocalFree(c); }
    if (s) LocalFree(s);
}

TEST(names_decode_custom_allocator) {
    REQUIRE(U(CryptDecodeObjectEx));
    CRYPT_DECODE_PARA dp = { sizeof dp, as_alloc, as_free };
    void *p = NULL; DWORD cb = 0; AS_RESET();
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_NAME, v_name_cn_test, sizeof v_name_cn_test, CRYPT_DECODE_ALLOC_FLAG, &dp, &p, &cb);
    CHECK(r); CHECK(g_as.allocs >= 1);
    CHECK(p == g_as.last);
    if (r && p) { CHECK(((CERT_NAME_INFO *)p)->cRDN == 1); as_free(p); }
    /* allocation failure */
    AS_RESET(); g_as.fail = 1; p = (void *)(ULONG_PTR)1; cb = 5; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, X509_NAME, v_name_cn_test, sizeof v_name_cn_test, CRYPT_DECODE_ALLOC_FLAG, &dp, &p, &cb);
    CHECK(!r); CHECK(p == NULL);
    DWORD e = GetLastError();
    t_note("alloc failure last error 0x%lx", e);
}

TEST(names_decode_truncated_and_garbage) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (DWORD cut = 0; cut < sizeof v_name_cn_test; cut++) {
        DWORD cb = 0; SET_ERR(0);
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_NAME, v_name_cn_test, cut, 0, NULL, NULL, &cb);
        CHECKF(!r, "cut %lu succeeded", cut);
        if (!r && cut >= 2) { DWORD e = GetLastError(); CHECKF(e == HR_ASN1_EOD || e == HR_ASN1_CORRUPT, "cut %lu err 0x%lx", cut, e); }
    }
    a_dec_fail(__FILE__, __LINE__, X509_NAME, v_name_cn_test, 0, 0, 0);
    BYTE not_seq[] = { 0x02, 0x01, 0x05 };
    a_dec_fail(__FILE__, __LINE__, X509_NAME, not_seq, sizeof not_seq, 0, HR_ASN1_BADTAG);
    BYTE bad_len[] = { 0x30, 0x7f, 0x31 };
    a_dec_fail(__FILE__, __LINE__, X509_NAME, bad_len, sizeof bad_len, 0, 0);
}

TEST(names_decode_trailing_data_ignored) {
    REQUIRE(U(CryptDecodeObjectEx));
    BYTE buf[64]; memcpy(buf, v_name_cn_test, sizeof v_name_cn_test); buf[sizeof v_name_cn_test] = 0xAA; buf[sizeof v_name_cn_test + 1] = 0xBB;
    CERT_NAME_INFO *ni = a_dec(__FILE__, __LINE__, X509_NAME, buf, sizeof v_name_cn_test + 2, 0, NULL);
    if (ni) { CHECK(ni->cRDN == 1); LocalFree(ni); }
}

TEST(names_decode_wrong_structure) {
    REQUIRE(U(CryptDecodeObjectEx));
    a_dec_fail(__FILE__, __LINE__, X509_NAME, v_bc2_ca, A_SZ(v_bc2_ca), 0, 0);
}

/* ---- X509_UNICODE_NAME ------------------------------------------------- */
struct uni_row { const char *label; DWORD type; const WCHAR *in; DWORD flags; BYTE tag; const BYTE *out; DWORD outn; };
static const WCHAR w_t[] = { 'T','e','s','t',0 };
static const WCHAR w_num[] = { '0','1','2','3',' ','4','5',0 };
static const WCHAR w_pr[] = { 'A','b',' ','1','\'','(',')','+',',','-','.','/',':','=','?',0 };
static const WCHAR w_ia5[] = { 'a','@','b','.','c',0 };
static const WCHAR w_e[] = { 'h', 0x00E9, 0 };
static const WCHAR w_euro[] = { 0x20AC, 0 };
static const WCHAR w_astral[] = { 0xD83D, 0xDE00, 0 };
#define B(...) (const BYTE[]){ __VA_ARGS__ }
static const struct uni_row uni_rows[] = {
    { "printable", CERT_RDN_PRINTABLE_STRING, w_t, 0, 0x13, (const BYTE *)"Test", 4 },
    { "printable_all", CERT_RDN_PRINTABLE_STRING, w_pr, 0, 0x13, (const BYTE *)"Ab 1'()+,-./:=?", 15 },
    { "numeric", CERT_RDN_NUMERIC_STRING, w_num, 0, 0x12, (const BYTE *)"0123 45", 7 },
    { "ia5", CERT_RDN_IA5_STRING, w_ia5, 0, 0x16, (const BYTE *)"a@b.c", 5 },
    { "visible", CERT_RDN_VISIBLE_STRING, w_t, 0, 0x1a, (const BYTE *)"Test", 4 },
    { "utf8_ascii", CERT_RDN_UTF8_STRING, w_t, 0, 0x0c, (const BYTE *)"Test", 4 },
    { "utf8_2byte", CERT_RDN_UTF8_STRING, w_e, 0, 0x0c, B('h', 0xC3, 0xA9), 3 },
    { "utf8_3byte", CERT_RDN_UTF8_STRING, w_euro, 0, 0x0c, B(0xE2, 0x82, 0xAC), 3 },
    { "utf8_surrogates", CERT_RDN_UTF8_STRING, w_astral, 0, 0x0c, B(0xF0, 0x9F, 0x98, 0x80), 4 },
    { "bmp", CERT_RDN_BMP_STRING, w_bmp, 0, 0x1e, be_bmp, 6 },
    { "universal", CERT_RDN_UNIVERSAL_STRING, w_e, 0, 0x1c, B(0,0,0,'h', 0,0,0,0xE9), 8 },
    { "universal_astral", CERT_RDN_UNIVERSAL_STRING, w_astral, 0, 0x1c, B(0,1,0xF6,0), 4 },
    { "t61_ascii", CERT_RDN_T61_STRING, w_t, 0, 0x14, (const BYTE *)"Test", 4 },
    { "general", CERT_RDN_GENERAL_STRING, w_t, 0, 0x1b, (const BYTE *)"Test", 4 },
    { "videotex", CERT_RDN_VIDEOTEX_STRING, w_t, 0, 0x15, (const BYTE *)"Test", 4 },
    { "graphic", CERT_RDN_GRAPHIC_STRING, w_t, 0, 0x19, (const BYTE *)"Test", 4 },
    /* flag-driven selection when the caller asks for the generic "unicode" type */
    { "unicode_default_bmp", CERT_RDN_UNICODE_STRING, w_t, 0, 0x1e, B(0,'T',0,'e',0,'s',0,'t'), 8 },
    { "unicode_utf8_flag", CERT_RDN_UNICODE_STRING, w_t, CERT_RDN_ENABLE_UTF8_UNICODE_FLAG, 0x0c, (const BYTE *)"Test", 4 },
    { "unicode_utf8_flag_e", CERT_RDN_UNICODE_STRING, w_e, CERT_RDN_ENABLE_UTF8_UNICODE_FLAG, 0x0c, B('h', 0xC3, 0xA9), 3 },
    { "unicode_t61_flag_latin1", CERT_RDN_UNICODE_STRING, w_e, CERT_RDN_ENABLE_T61_UNICODE_FLAG, 0x14, B('h', 0xE9), 2 },
    { "unicode_t61_flag_euro_stays_bmp", CERT_RDN_UNICODE_STRING, w_euro, CERT_RDN_ENABLE_T61_UNICODE_FLAG, 0x1e, B(0x20, 0xAC), 2 },
    { "unicode_force_utf8", CERT_RDN_UNICODE_STRING, w_bmp, CERT_RDN_FORCE_UTF8_UNICODE_FLAG, 0x0c, B('T', 0xC3, 0xA9, 0xE2, 0x82, 0xAC), 6 },
};

static void uni_attr(CERT_RDN_ATTR *a, DWORD type, const WCHAR *w, DWORD cb) {
    a->pszObjId = (LPSTR)"2.5.4.3"; a->dwValueType = type; a->Value.cbData = cb; a->Value.pbData = (BYTE *)w;
}

TEST(names_unicode_encode_table) {
    REQUIRE(U(CryptEncodeObjectEx));
    for (unsigned i = 0; i < sizeof uni_rows / sizeof *uni_rows; i++) {
        const struct uni_row *r = &uni_rows[i];
        BYTE exp[128]; DWORD en = mk_name(exp, r->tag, r->out, r->outn);
        CERT_RDN_ATTR a; uni_attr(&a, r->type, r->in, 0);      /* cbData 0 => NUL-terminated */
        CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
        t_note("row %s", r->label);
        a_enc_eq(__FILE__, __LINE__, X509_UNICODE_NAME, &ni, r->flags, exp, en);
        /* explicit byte count gives the same result */
        uni_attr(&a, r->type, r->in, (DWORD)(lstrlenW(r->in) * 2));
        a_enc_eq(__FILE__, __LINE__, X509_UNICODE_NAME, &ni, r->flags, exp, en);
        /* the same flags in dwValueType instead of dwFlags */
        if (r->flags) {
            uni_attr(&a, r->type | r->flags, r->in, 0);
            a_enc_try(__FILE__, __LINE__, X509_UNICODE_NAME, &ni, 0, exp, en);
        }
    }
}

TEST(names_unicode_encode_empty_value) {
    REQUIRE(U(CryptEncodeObjectEx));
    static const WCHAR e[] = { 0 };
    BYTE exp[32]; DWORD en = mk_name(exp, 0x13, (const BYTE *)"", 0);
    CERT_RDN_ATTR a; uni_attr(&a, CERT_RDN_PRINTABLE_STRING, e, 0);
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    a_enc_eq(__FILE__, __LINE__, X509_UNICODE_NAME, &ni, 0, exp, en);
}

TEST(names_unicode_encode_value_cb_limits_length) {
    REQUIRE(U(CryptEncodeObjectEx));
    BYTE exp[32]; DWORD en = mk_name(exp, 0x13, (const BYTE *)"Te", 2);
    CERT_RDN_ATTR a; uni_attr(&a, CERT_RDN_PRINTABLE_STRING, w_t, 4);   /* only two characters */
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    a_enc_eq(__FILE__, __LINE__, X509_UNICODE_NAME, &ni, 0, exp, en);
}

struct bad_row { const char *label; DWORD type; const WCHAR *in; DWORD err; DWORD idx; };
static const WCHAR w_n_bad[] = { '1','2','a','4',0 };
static const WCHAR w_p_bad[] = { 'o','k','@',0 };
static const WCHAR w_p_bad2[] = { 'a','*',0 };
static const WCHAR w_ia_bad[] = { 'a','b',0x00E9,0 };
static const WCHAR w_vis_bad[] = { 'a',0x01,0 };
static const WCHAR w_t61_bad[] = { 'a',0x20AC,0 };
static const WCHAR w_num_hi[] = { '1', 0x0661, 0 };
static const struct bad_row bad_rows[] = {
    { "numeric_letter", CERT_RDN_NUMERIC_STRING, w_n_bad, (DWORD)CRYPT_E_INVALID_NUMERIC_STRING, 2 },
    { "numeric_nonascii_digit", CERT_RDN_NUMERIC_STRING, w_num_hi, (DWORD)CRYPT_E_INVALID_NUMERIC_STRING, 1 },
    { "printable_at", CERT_RDN_PRINTABLE_STRING, w_p_bad, (DWORD)CRYPT_E_INVALID_PRINTABLE_STRING, 2 },
    { "printable_star", CERT_RDN_PRINTABLE_STRING, w_p_bad2, (DWORD)CRYPT_E_INVALID_PRINTABLE_STRING, 1 },
    { "ia5_latin1", CERT_RDN_IA5_STRING, w_ia_bad, (DWORD)CRYPT_E_INVALID_IA5_STRING, 2 },
    { "visible_ctl", CERT_RDN_VISIBLE_STRING, w_vis_bad, (DWORD)CRYPT_E_INVALID_IA5_STRING, 1 },
};

TEST(names_unicode_invalid_characters) {
    REQUIRE(U(CryptEncodeObjectEx));
    for (unsigned i = 0; i < sizeof bad_rows / sizeof *bad_rows; i++) {
        const struct bad_row *r = &bad_rows[i];
        CERT_RDN_ATTR a; uni_attr(&a, r->type, r->in, 0);
        CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
        DWORD cb = 0xCAFE; SET_ERR(0);
        BOOL ok = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, 0, NULL, NULL, &cb);
        DWORD e = GetLastError();
        t_note("row %s err=0x%lx loc=0x%lx", r->label, e, cb);
        if (r->type == CERT_RDN_VISIBLE_STRING) { t_note("visible control char: ok=%d err=0x%lx", ok, e); continue; }
        CHECK(!ok);
        CHECK(e == r->err);
        CHECK(GET_CERT_UNICODE_RDN_ERR_INDEX(cb) == 0);
        CHECK(GET_CERT_UNICODE_ATTR_ERR_INDEX(cb) == 0);
        CHECK(GET_CERT_UNICODE_VALUE_ERR_INDEX(cb) == r->idx);
        /* same with a real buffer and with ALLOC */
        BYTE buf[128]; cb = sizeof buf; SET_ERR(0);
        ok = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, 0, NULL, buf, &cb);
        CHECK(!ok); CHECK(GET_CERT_UNICODE_VALUE_ERR_INDEX(cb) == r->idx);
        BYTE *p = NULL; cb = 0; SET_ERR(0);
        ok = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
        CHECK(!ok); if (p) t_note("ALLOC encode failure left pointer %p", p);
        if (ok && p) LocalFree(p);
    }
}

TEST(names_unicode_invalid_character_location_rdn_attr) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_RDN_ATTR a0[1], a1[2];
    uni_attr(&a0[0], CERT_RDN_PRINTABLE_STRING, w_t, 0);
    uni_attr(&a1[0], CERT_RDN_PRINTABLE_STRING, w_t, 0);
    uni_attr(&a1[1], CERT_RDN_NUMERIC_STRING, w_n_bad, 0);
    CERT_RDN rdns[2] = { { 1, a0 }, { 2, a1 } };
    CERT_NAME_INFO ni = { 2, rdns };
    DWORD cb = 0; SET_ERR(0);
    BOOL ok = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, 0, NULL, NULL, &cb);
    CHECK(!ok); EXPECT_ERR((DWORD)CRYPT_E_INVALID_NUMERIC_STRING);
    CHECK(GET_CERT_UNICODE_RDN_ERR_INDEX(cb) == 1);
    CHECK(GET_CERT_UNICODE_ATTR_ERR_INDEX(cb) == 1);
    CHECK(GET_CERT_UNICODE_VALUE_ERR_INDEX(cb) == 2);
    EXPECT_EQ(cb, (1u << CERT_UNICODE_RDN_ERR_INDEX_SHIFT) | (1u << CERT_UNICODE_ATTR_ERR_INDEX_SHIFT) | 2u);
}

TEST(names_unicode_disable_check_type_allows_invalid) {
    REQUIRE(U(CryptEncodeObjectEx));
    BYTE exp[64]; DWORD en = mk_name(exp, 0x12, (const BYTE *)"12a4", 4);
    CERT_RDN_ATTR a; uni_attr(&a, CERT_RDN_NUMERIC_STRING | CERT_RDN_DISABLE_CHECK_TYPE_FLAG, w_n_bad, 0);
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    a_enc_eq(__FILE__, __LINE__, X509_UNICODE_NAME, &ni, 0, exp, en);
    uni_attr(&a, CERT_RDN_NUMERIC_STRING, w_n_bad, 0);
    a_enc_eq(__FILE__, __LINE__, X509_UNICODE_NAME, &ni, CERT_RDN_DISABLE_CHECK_TYPE_FLAG, exp, en);
    BYTE exp2[64]; DWORD en2 = mk_name(exp2, 0x13, (const BYTE *)"ok@", 3);
    uni_attr(&a, CERT_RDN_PRINTABLE_STRING | CERT_RDN_DISABLE_CHECK_TYPE_FLAG, w_p_bad, 0);
    a_enc_eq(__FILE__, __LINE__, X509_UNICODE_NAME, &ni, 0, exp2, en2);
}

TEST(names_unicode_nonchar_types_rejected) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_RDN_ATTR a; uni_attr(&a, 0 /* ANY_TYPE */, w_t, 0);
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    DWORD cb = 0; SET_ERR(0);
    BOOL ok = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, 0, NULL, NULL, &cb);
    DWORD e = GetLastError();
    CHECK(!ok);
    t_note("UNICODE_NAME with dwValueType 0 -> err 0x%lx", e);
    uni_attr(&a, CERT_RDN_OCTET_STRING, w_t, 0);
    SET_ERR(0);
    ok = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, 0, NULL, NULL, &cb);
    CHECK(!ok); EXPECT_ERR((DWORD)CRYPT_E_NOT_CHAR_STRING);
}

TEST(names_unicode_bad_oid_rejected) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_RDN_ATTR a; uni_attr(&a, CERT_RDN_PRINTABLE_STRING, w_t, 0);
    a.pszObjId = (LPSTR)"not.an.oid";
    CERT_RDN rdn = { 1, &a }; CERT_NAME_INFO ni = { 1, &rdn };
    DWORD cb = 0; SET_ERR(0);
    BOOL ok = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME, &ni, 0, NULL, NULL, &cb);
    CHECK(!ok);
    t_note("bad attribute OID -> err 0x%lx", GetLastError());
    a.pszObjId = NULL; SET_ERR(0);
    ok = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, 0, NULL, NULL, &cb);
    t_note("NULL attribute OID: ok=%d err=0x%lx", ok, GetLastError());
}

/* ---- X509_UNICODE_NAME decode ---------------------------------------- */
static void chk_uni_dec(const char *label, BYTE tag, const BYTE *c, DWORD n, DWORD flags, DWORD wtype, const WCHAR *want, DWORD wantc) {
    BYTE der[160]; DWORD dn = mk_name(der, tag, c, n);
    DWORD cb; CERT_NAME_INFO *ni = a_dec(__FILE__, __LINE__, X509_UNICODE_NAME, der, dn, flags, &cb);
    t_note("row %s", label);
    if (!ni) return;
    CHECK(ni->cRDN == 1 && ni->rgRDN[0].cRDNAttr == 1);
    if (ni->cRDN == 1 && ni->rgRDN[0].cRDNAttr == 1) {
        CERT_RDN_ATTR *a = &ni->rgRDN[0].rgRDNAttr[0];
        if (wtype) CHECKF(a->dwValueType == wtype, "type %lu want %lu", a->dwValueType, wtype);
        CHECKF(a->Value.cbData == wantc * 2, "cb %lu want %lu", a->Value.cbData, wantc * 2);
        CHECK(a->Value.cbData == wantc * 2 && !memcmp(a->Value.pbData, want, wantc * 2));
        if (a->Value.cbData) CHECK(*(WCHAR *)(a->Value.pbData + a->Value.cbData) == 0);   /* NUL terminated */
    }
    LocalFree(ni);
}

TEST(names_unicode_decode_table) {
    REQUIRE(U(CryptDecodeObjectEx));
    chk_uni_dec("printable", 0x13, (const BYTE *)"Test", 4, 0, CERT_RDN_PRINTABLE_STRING, w_t, 4);
    chk_uni_dec("numeric", 0x12, (const BYTE *)"0123 45", 7, 0, CERT_RDN_NUMERIC_STRING, w_num, 7);
    chk_uni_dec("ia5", 0x16, (const BYTE *)"a@b.c", 5, 0, CERT_RDN_IA5_STRING, w_ia5, 5);
    chk_uni_dec("visible", 0x1a, (const BYTE *)"Test", 4, 0, CERT_RDN_VISIBLE_STRING, w_t, 4);
    chk_uni_dec("utf8", 0x0c, B('h', 0xC3, 0xA9), 3, 0, CERT_RDN_UTF8_STRING, w_e, 2);
    chk_uni_dec("utf8_euro", 0x0c, B(0xE2, 0x82, 0xAC), 3, 0, CERT_RDN_UTF8_STRING, w_euro, 1);
    chk_uni_dec("utf8_astral", 0x0c, B(0xF0, 0x9F, 0x98, 0x80), 4, 0, CERT_RDN_UTF8_STRING, w_astral, 2);
    chk_uni_dec("bmp", 0x1e, be_bmp, 6, 0, CERT_RDN_BMP_STRING, w_bmp, 3);
    chk_uni_dec("universal", 0x1c, B(0,0,0,'h', 0,0,0,0xE9), 8, 0, CERT_RDN_UNIVERSAL_STRING, w_e, 2);
    chk_uni_dec("universal_astral", 0x1c, B(0,1,0xF6,0), 4, 0, 0, w_astral, 2);
    chk_uni_dec("t61_ascii", 0x14, (const BYTE *)"Test", 4, 0, CERT_RDN_T61_STRING, w_t, 4);
    chk_uni_dec("t61_latin1_fallback", 0x14, B('h', 0xE9), 2, 0, CERT_RDN_T61_STRING, w_e, 2);
    chk_uni_dec("t61_utf8_first", 0x14, B('h', 0xC3, 0xA9), 3, 0, CERT_RDN_T61_STRING, w_e, 2);
    static const WCHAR w_ie4[] = { 'h', 0x00C3, 0x00A9 };
    chk_uni_dec("t61_utf8_disabled", 0x14, B('h', 0xC3, 0xA9), 3, CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG, CERT_RDN_T61_STRING, w_ie4, 3);
    chk_uni_dec("t61_latin1_disabled", 0x14, B('h', 0xE9), 2, CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG, CERT_RDN_T61_STRING, w_e, 2);
    chk_uni_dec("empty_utf8", 0x0c, (const BYTE *)"", 0, 0, CERT_RDN_UTF8_STRING, w_e, 0);
}

TEST(names_unicode_decode_invalid_utf8_rejected) {
    REQUIRE(U(CryptDecodeObjectEx));
    BYTE der[64]; DWORD n = mk_name(der, 0x0c, B(0xC3), 1);
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_UNICODE_NAME, der, n, 0, NULL, NULL, &cb);
    t_note("truncated UTF-8 sequence -> %d err 0x%lx", r, GetLastError());
    n = mk_name(der, 0x1e, B(0x20), 1);          /* odd BMP length */
    SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, X509_UNICODE_NAME, der, n, 0, NULL, NULL, &cb);
    t_note("odd-length BMP -> %d err 0x%lx", r, GetLastError());
}

TEST(names_unicode_decode_punycode_flag_ignored_for_names) {
    REQUIRE(U(CryptDecodeObjectEx));
    chk_uni_dec("ia5_puny_off", 0x16, (const BYTE *)"xn--bcher-kva", 13, 0, CERT_RDN_IA5_STRING, L"xn--bcher-kva", 13);
}

/* ---- X509_NAME_VALUE / X509_UNICODE_NAME_VALUE -------------------------- */
TEST(name_value_encode_ansi) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_VALUE v = { CERT_RDN_PRINTABLE_STRING, { 4, (BYTE *)"Test" } };
    ENC_EQ(X509_NAME_VALUE, &v, v_name_value_printable);
    ENC_EQ(X509_ANY_STRING, &v, v_name_value_printable);
    v.dwValueType = CERT_RDN_BMP_STRING; v.Value.cbData = 6; v.Value.pbData = (BYTE *)w_bmp;
    ENC_EQ(X509_NAME_VALUE, &v, v_name_value_bmp);
    v.dwValueType = CERT_RDN_T61_STRING; v.Value.cbData = 4; v.Value.pbData = (BYTE *)"T\xe9st";
    ENC_EQ(X509_NAME_VALUE, &v, v_name_value_t61_latin1);
    v.dwValueType = CERT_RDN_UTF8_STRING; v.Value.cbData = 3; v.Value.pbData = (BYTE *)"h\xc3\xa9";
    ENC_TRY(X509_NAME_VALUE, &v, v_name_value_utf8);
    v.dwValueType = CERT_RDN_UNIVERSAL_STRING; v.Value.cbData = 8; v.Value.pbData = (BYTE *)u4_in;
    BYTE exp[16]; exp[0] = 0x1c; exp[1] = 8; memcpy(exp + 2, B(0,0,0,'A', 0,0,0,0xE9), 8);
    a_enc_try(__FILE__, __LINE__, X509_NAME_VALUE, &v, 0, exp, 10);
}

TEST(name_value_encode_unicode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_VALUE v = { CERT_RDN_PRINTABLE_STRING, { 0, (BYTE *)w_t } };
    ENC_EQ(X509_UNICODE_NAME_VALUE, &v, v_name_value_printable);
    ENC_EQ(X509_UNICODE_ANY_STRING, &v, v_name_value_printable);
    v.dwValueType = CERT_RDN_UTF8_STRING; v.Value.pbData = (BYTE *)w_e;
    ENC_EQ(X509_UNICODE_NAME_VALUE, &v, v_name_value_utf8);
    v.dwValueType = CERT_RDN_BMP_STRING; v.Value.pbData = (BYTE *)w_bmp;
    ENC_EQ(X509_UNICODE_NAME_VALUE, &v, v_name_value_bmp);
    v.dwValueType = CERT_RDN_NUMERIC_STRING; v.Value.pbData = (BYTE *)w_n_bad;
    { DWORD cb = 0; SET_ERR(0); BOOL ok = U(CryptEncodeObjectEx)(ENC, X509_UNICODE_NAME_VALUE, &v, 0, NULL, NULL, &cb);
      t_note("unicode name value with invalid numeric char: ok=%d err=0x%lx", ok, GetLastError()); }
}

TEST(name_value_decode_ansi) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_NAME_VALUE *v = DEC(X509_NAME_VALUE, v_name_value_printable, 0, NULL);
    if (v) { CHECK(v->dwValueType == CERT_RDN_PRINTABLE_STRING); CHECK(v->Value.cbData == 4 && !memcmp(v->Value.pbData, "Test", 4)); LocalFree(v); }
    v = DEC(X509_NAME_VALUE, v_name_value_utf8, 0, NULL);
    if (v) { CHECK(v->dwValueType == CERT_RDN_UTF8_STRING); CHECK(v->Value.cbData == 3); LocalFree(v); }
    v = DEC(X509_NAME_VALUE, v_name_value_bmp, 0, NULL);
    if (v) { CHECK(v->dwValueType == CERT_RDN_BMP_STRING); CHECK(v->Value.cbData == 6 && !memcmp(v->Value.pbData, w_bmp, 6)); LocalFree(v); }
    v = DEC(X509_NAME_VALUE, v_name_value_null, 0, NULL);
    if (v) { t_note("NULL as name value: type %lu cb %lu", v->dwValueType, v->Value.cbData); LocalFree(v); }
}

TEST(name_value_decode_unicode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_NAME_VALUE *v = DEC(X509_UNICODE_NAME_VALUE, v_name_value_utf8, 0, NULL);
    if (v) { CHECK(v->dwValueType == CERT_RDN_UTF8_STRING); CHECK(v->Value.cbData == 4 && !memcmp(v->Value.pbData, w_e, 4)); LocalFree(v); }
    v = DEC(X509_UNICODE_NAME_VALUE, v_name_value_bmp, 0, NULL);
    if (v) { CHECK(v->Value.cbData == 6 && !memcmp(v->Value.pbData, w_bmp, 6)); LocalFree(v); }
    v = DEC(X509_UNICODE_NAME_VALUE, v_name_value_t61_latin1, 0, NULL);
    if (v) { CHECK(v->dwValueType == CERT_RDN_T61_STRING); CHECK(v->Value.cbData == 8); LocalFree(v); }
    v = DEC(X509_UNICODE_NAME_VALUE, v_name_value_univ, 0, NULL);
    if (v) { CHECK(v->Value.cbData == 4 && ((WCHAR *)v->Value.pbData)[0] == 'A' && ((WCHAR *)v->Value.pbData)[1] == 0xE9); LocalFree(v); }
}

TEST(name_value_decode_failures) {
    REQUIRE(U(CryptDecodeObjectEx));
    BYTE trunc[] = { 0x13, 0x04, 'T', 'e' };
    a_dec_fail(__FILE__, __LINE__, X509_NAME_VALUE, trunc, sizeof trunc, 0, HR_ASN1_EOD);
    a_dec_fail(__FILE__, __LINE__, X509_UNICODE_NAME_VALUE, trunc, sizeof trunc, 0, HR_ASN1_EOD);
    a_dec_fail(__FILE__, __LINE__, X509_NAME_VALUE, trunc, 0, 0, 0);
}

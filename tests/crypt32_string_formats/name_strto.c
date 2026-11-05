/* CertStrToNameA/W: parsing, encoding choice, error reporting and the buffer protocol. */
#include "sf.h"

#define REQ_S2N() \
    BOOL (WINAPI *fa)(DWORD, LPCSTR, DWORD, void*, BYTE*, DWORD*, LPCSTR*) = (void*)t_proc("CertStrToNameA"); \
    BOOL (WINAPI *fw)(DWORD, LPCWSTR, DWORD, void*, BYTE*, DWORD*, LPCWSTR*) = (void*)t_proc("CertStrToNameW"); \
    DWORD (WINAPI *n2sw)(DWORD, PCERT_NAME_BLOB, DWORD, LPWSTR, DWORD) = (void*)t_proc("CertNameToStrW"); \
    REQUIRE(fa); REQUIRE(fw); REQUIRE(n2sw); (void)fa; (void)fw; (void)n2sw

static BYTE g_exp[4096], g_out[4096];

/* Compares CertStrToNameA/W output against the DER built from the attribute list. */
static void chk_s2n(const char *file, int line, const char *s, DWORD flags, const sf_attr *a, int na)
{
    BOOL (WINAPI *fa)(DWORD, LPCSTR, DWORD, void*, BYTE*, DWORD*, LPCSTR*) = (void*)t_proc("CertStrToNameA");
    BOOL (WINAPI *fw)(DWORD, LPCWSTR, DWORD, void*, BYTE*, DWORD*, LPCWSTR*) = (void*)t_proc("CertStrToNameW");
    DWORD en = sf_build_name(g_exp, a, na), n = 0; BOOL r; WCHAR ws[512]; LPCSTR ea = (LPCSTR)1; LPCWSTR ew = (LPCWSTR)1;
    sf_widen(s, ws);
    SET_ERR(0);
    r = fa(X509_ASN_ENCODING, s, flags, NULL, NULL, &n, &ea);
    t_check(r && n == en && ea == NULL, file, line, "A size query", "r=%d n=%lu want %lu err=%lx input '%s'", r, n, en, GetLastError(), s);
    n = 0; r = fw(X509_ASN_ENCODING, ws, flags, NULL, NULL, &n, &ew);
    t_check(r && n == en && ew == NULL, file, line, "W size query", "r=%d n=%lu want %lu input '%s'", r, n, en, s);
    memset(g_out, 0xcc, sizeof g_out); n = sizeof g_out;
    r = fa(X509_ASN_ENCODING, s, flags, NULL, g_out, &n, NULL);
    t_check(r && n == en && !memcmp(g_out, g_exp, en), file, line, "A encoding", "r=%d n=%lu want %lu input '%s'", r, n, en, s);
    memset(g_out, 0xcc, sizeof g_out); n = sizeof g_out;
    r = fw(X509_ASN_ENCODING, ws, flags, NULL, g_out, &n, NULL);
    t_check(r && n == en && !memcmp(g_out, g_exp, en), file, line, "W encoding", "r=%d n=%lu want %lu input '%s'", r, n, en, s);
}
#define S2N(s, flags, ...) do { const sf_attr a__[] = { __VA_ARGS__ }; chk_s2n(__FILE__, __LINE__, (s), (flags), a__, (int)NELEM(a__)); } while (0)

static void chk_s2n_fail(const char *file, int line, const char *s, DWORD flags, DWORD err, int errofs)
{
    BOOL (WINAPI *fa)(DWORD, LPCSTR, DWORD, void*, BYTE*, DWORD*, LPCSTR*) = (void*)t_proc("CertStrToNameA");
    BOOL (WINAPI *fw)(DWORD, LPCWSTR, DWORD, void*, BYTE*, DWORD*, LPCWSTR*) = (void*)t_proc("CertStrToNameW");
    DWORD n = sizeof g_out; BOOL r; WCHAR ws[512]; LPCSTR ea = NULL; LPCWSTR ew = NULL;
    sf_widen(s, ws);
    SET_ERR(0);
    r = fa(X509_ASN_ENCODING, s, flags, NULL, g_out, &n, &ea);
    t_check(!r && GetLastError() == err, file, line, "A must fail", "r=%d err=%#lx want %#lx input '%s'", r, GetLastError(), err, s);
    if (errofs >= 0) t_check(ea == s + errofs, file, line, "A error pointer", "got offset %td want %d input '%s'", ea ? ea - s : -1, errofs, s);
    n = sizeof g_out; SET_ERR(0);
    r = fw(X509_ASN_ENCODING, ws, flags, NULL, g_out, &n, &ew);
    t_check(!r && GetLastError() == err, file, line, "W must fail", "r=%d err=%#lx want %#lx input '%s'", r, GetLastError(), err, s);
    if (errofs >= 0) t_check(ew == ws + errofs, file, line, "W error pointer", "got offset %td want %d input '%s'", ew ? ew - ws : -1, errofs, s);
}
#define S2N_FAIL(s, flags, err, ofs) chk_s2n_fail(__FILE__, __LINE__, (s), (flags), (err), (ofs))

static const BYTE bm_dq1dq[] = { 0, '"', 0, '1', 0, '"' };

TEST(sf_s2n_simple_cn) {
    REQ_S2N();
    S2N("CN=1", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("CN=1", 0, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("CN=1", CERT_OID_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("cn=1", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("Cn=1", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
}
TEST(sf_s2n_quoted_value_equals_unquoted) {
    REQ_S2N();
    S2N("CN=\"1\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("CN=\"abc\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "abc", -1 });
}
TEST(sf_s2n_printable_vs_bmp_choice) {
    REQ_S2N();
    S2N("CN='1'", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "'1'", -1 });
    S2N("CN=\" 1 \"", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, " 1 ", -1 });
    S2N("CN=\"\"\"1\"\"\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", BM, bm_dq1dq, 6 });
    S2N("CN=\"1+2\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "1+2", -1 });
    S2N("CN=\"a,b\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a,b", -1 });
    S2N("CN=\"a=b\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a=b", -1 });
    static const BYTE lt[] = { 0, '<' }, gt[] = { 0, '>' }, hs[] = { 0, '#' }, sc[] = { 0, ';' };
    S2N("CN=\"<\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", BM, lt, 2 });
    S2N("CN=\">\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", BM, gt, 2 });
    S2N("CN=\"#\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", BM, hs, 2 });
    S2N("CN=\";\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", BM, sc, 2 });
}
TEST(sf_s2n_printable_character_set_boundaries) {
    REQ_S2N();
    S2N("CN=abcXYZ019 '()+,-./:=?", CERT_X500_NAME_STR | CERT_NAME_STR_NO_QUOTING_FLAG | CERT_NAME_STR_SEMICOLON_FLAG | CERT_NAME_STR_NO_PLUS_FLAG,
        { 1, "2.5.4.3", PS, "abcXYZ019 '()+,-./:=?", -1 });
}
TEST(sf_s2n_multiple_rdns) {
    REQ_S2N();
    S2N("CN=dummy,T=test", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "dummy", -1 }, { 1, "2.5.4.12", PS, "test", -1 });
    S2N("C=US, S=Minnesota, L=Minneapolis, O=Corp, OU=Dev, CN=localhost", CERT_X500_NAME_STR,
        { 1, "2.5.4.6", PS, "US", -1 }, { 1, "2.5.4.8", PS, "Minnesota", -1 }, { 1, "2.5.4.7", PS, "Minneapolis", -1 },
        { 1, "2.5.4.10", PS, "Corp", -1 }, { 1, "2.5.4.11", PS, "Dev", -1 }, { 1, "2.5.4.3", PS, "localhost", -1 });
}
TEST(sf_s2n_separators_comma_and_semicolon) {
    REQ_S2N();
    S2N("CN=a;O=b", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
    S2N("CN=a,O=b", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
    S2N("CN=a ; O=b", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
}
TEST(sf_s2n_comma_flag_semicolon_is_data) {
    REQ_S2N(); static const BYTE ab[] = { 0, 'a', 0, ';', 0, 'b' };
    S2N("CN=a;b", CERT_X500_NAME_STR | CERT_NAME_STR_COMMA_FLAG, { 1, "2.5.4.3", BM, ab, 6 });
    S2N("CN=a,O=b", CERT_X500_NAME_STR | CERT_NAME_STR_COMMA_FLAG, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
}
TEST(sf_s2n_semicolon_flag_comma_is_data) {
    REQ_S2N();
    S2N("CN=a,b", CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG, { 1, "2.5.4.3", PS, "a,b", -1 });
    S2N("CN=a;O=b", CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
}
TEST(sf_s2n_crlf_flag_line_separated) {
    REQ_S2N();
    S2N("CN=a\r\nO=b", CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
    S2N("CN=a, b\r\nO=c", CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG, { 1, "2.5.4.3", PS, "a, b", -1 }, { 1, "2.5.4.10", PS, "c", -1 });
}
TEST(sf_s2n_reverse_flag_reverses_rdn_order) {
    REQ_S2N();
    S2N("CN=a,O=b,C=US", CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        { 1, "2.5.4.6", PS, "US", -1 }, { 1, "2.5.4.10", PS, "b", -1 }, { 1, "2.5.4.3", PS, "a", -1 });
    S2N("CN=a,O=b,C=US", CERT_X500_NAME_STR | CERT_NAME_STR_FORWARD_FLAG,
        { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 }, { 1, "2.5.4.6", PS, "US", -1 });
}
TEST(sf_s2n_oid_key_forms) {
    REQ_S2N();
    S2N("2.5.4.3=1", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("OID.2.5.4.3=1", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("oid.2.5.4.3=1", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("2.5.4.3=1", CERT_OID_NAME_STR, { 1, "2.5.4.3", PS, "1", -1 });
    S2N("1.2.3.4=v", CERT_X500_NAME_STR, { 1, "1.2.3.4", PS, "v", -1 });
    S2N("OID.1.2.840.113549.1.9.2=v", CERT_X500_NAME_STR, { 1, "1.2.840.113549.1.9.2", PS, "v", -1 });
}
TEST(sf_s2n_key_aliases) {
    REQ_S2N();
    S2N("C=US", CERT_X500_NAME_STR, { 1, "2.5.4.6", PS, "US", -1 });
    S2N("S=x", CERT_X500_NAME_STR, { 1, "2.5.4.8", PS, "x", -1 });
    S2N("L=x", CERT_X500_NAME_STR, { 1, "2.5.4.7", PS, "x", -1 });
    S2N("O=x", CERT_X500_NAME_STR, { 1, "2.5.4.10", PS, "x", -1 });
    S2N("OU=x", CERT_X500_NAME_STR, { 1, "2.5.4.11", PS, "x", -1 });
    S2N("T=x", CERT_X500_NAME_STR, { 1, "2.5.4.12", PS, "x", -1 });
}
TEST(sf_s2n_whitespace_handling) {
    REQ_S2N();
    S2N("  CN  =  a  ,  O = b  ", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
    S2N("CN=\ta\t", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a", -1 });
    S2N("CN=\" a \"", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, " a ", -1 });
    S2N("CN=\"a\"   ,O=b", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
    S2N("CN=a b", CERT_X500_NAME_STR, { 1, "2.5.4.3", PS, "a b", -1 });
}
TEST(sf_s2n_quoted_value_with_separators) {
    REQ_S2N();
    S2N("O=\"Acme, Inc.\", CN=x", CERT_X500_NAME_STR, { 1, "2.5.4.10", PS, "Acme, Inc.", -1 }, { 1, "2.5.4.3", PS, "x", -1 });
    /* ';' is not a PrintableString character, so the value is encoded as BMPString (probed) */
    S2N("O=\"a;b\", CN=x", CERT_X500_NAME_STR, { 1, "2.5.4.10", BM, "\0a\0;\0b", 6 }, { 1, "2.5.4.3", PS, "x", -1 });
}
TEST(sf_s2n_doubled_quote_inside_quotes) {
    REQ_S2N(); static const BYTE v[] = { 0, 'a', 0, '"', 0, 'b' };
    S2N("CN=\"a\"\"b\"", CERT_X500_NAME_STR, { 1, "2.5.4.3", BM, v, 6 });
}
TEST(sf_s2n_no_quoting_flag_keeps_quotes) {
    REQ_S2N();
    S2N("CN=\"abc\"", CERT_X500_NAME_STR | CERT_NAME_STR_NO_QUOTING_FLAG, { 1, "2.5.4.3", BM, "\0\"\0a\0b\0c\0\"", 10 });
    S2N("CN=1,2", CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG | CERT_NAME_STR_NO_QUOTING_FLAG, { 1, "2.5.4.3", PS, "1,2", -1 });
}
TEST(sf_s2n_plus_makes_multivalued_rdn) {
    REQ_S2N(); WCHAR out[128]; CERT_NAME_BLOB nb; DWORD n = sizeof g_out, k;
    CHECK(fa(X509_ASN_ENCODING, "CN=a+OU=b, O=c", CERT_X500_NAME_STR, NULL, g_out, &n, NULL));
    nb.cbData = n; nb.pbData = g_out;
    k = n2sw(X509_ASN_ENCODING, &nb, CERT_X500_NAME_STR, out, 128);
    CHECK(!lstrcmpW(out, L"CN=a + OU=b, O=c"));
    n = sizeof g_out;
    CHECK(fa(X509_ASN_ENCODING, "CN=a + OU=b + O=c", CERT_X500_NAME_STR, NULL, g_out, &n, NULL));
    nb.cbData = n; nb.pbData = g_out;
    k = n2sw(X509_ASN_ENCODING, &nb, CERT_X500_NAME_STR, out, 128);
    /* the attributes of a multi-valued RDN are stored in DER SET OF order (O before OU) (probed) */
    CHECK(!lstrcmpW(out, L"CN=a + O=c + OU=b"));
}
TEST(sf_s2n_no_plus_flag_plus_is_data) {
    REQ_S2N();
    S2N("CN=1+2", CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, { 1, "2.5.4.3", PS, "1+2", -1 });
    S2N("CN=1+2,O=x", CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, { 1, "2.5.4.3", PS, "1+2", -1 }, { 1, "2.5.4.10", PS, "x", -1 });
}
TEST(sf_s2n_utf8_flags) {
    REQ_S2N(); static const BYTE lt[] = { '<' };
    S2N("CN=\"<\"", CERT_X500_NAME_STR | CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG, { 1, "2.5.4.3", U8, lt, 1 });
    S2N("CN=abc", CERT_X500_NAME_STR | CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG, { 1, "2.5.4.3", PS, "abc", -1 });
    S2N("CN=abc", CERT_X500_NAME_STR | CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG, { 1, "2.5.4.3", U8, "abc", -1 });
}
TEST(sf_s2n_unicode_values) {
    REQ_S2N(); WCHAR in[] = L"CN=\x65e5\x672c"; BYTE out[64]; DWORD n = sizeof out; static const BYTE bm[] = { 0x65, 0xe5, 0x67, 0x2c };
    static const BYTE bmjp[] = { 0x65, 0xe5, 0x67, 0x2c };
    BYTE exp[64]; DWORD en;
    sf_attr a = { 1, "2.5.4.3", BM, bmjp, 4 };
    en = sf_build_name(exp, &a, 1);
    SET_ERR(0);
    BOOL r = fw(X509_ASN_ENCODING, in, CERT_X500_NAME_STR, NULL, out, &n, NULL);
    CHECK(r); EXPECT_EQ(n, en); CHECK(!memcmp(out, exp, en));
    static const BYTE u8jp[] = { 0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac };
    a.tag = U8; a.v = u8jp; a.n = 6; en = sf_build_name(exp, &a, 1);
    n = sizeof out;
    r = fw(X509_ASN_ENCODING, in, CERT_X500_NAME_STR | CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG, NULL, out, &n, NULL);
    CHECK(r); EXPECT_EQ(n, en); CHECK(!memcmp(out, exp, en));
}
TEST(sf_s2n_latin1_value_default_and_t61_flag) {
    REQ_S2N(); WCHAR in[] = L"CN=\x00e9"; BYTE out[64]; DWORD n = sizeof out;
    BOOL r = fw(X509_ASN_ENCODING, in, CERT_X500_NAME_STR, NULL, out, &n, NULL);
    CHECK(r);
    if (r) { t_note("CN=U+00E9 default encoding tag %#x len %u", out[11], out[12]); EXPECT_EQ(out[11], BM); }
    n = sizeof out;
    r = fw(X509_ASN_ENCODING, in, CERT_X500_NAME_STR | CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG, NULL, out, &n, NULL);
    if (r) t_note("CN=U+00E9 with ENABLE_T61_UNICODE tag %#x", out[11]);
}

/* ---------------- empty input ---------------- */
TEST(sf_s2n_empty_string_is_empty_sequence) {
    REQ_S2N(); BYTE out[8]; DWORD n = sizeof out; LPCSTR ea = (LPCSTR)1; LPCWSTR ew = (LPCWSTR)1;
    SET_ERR(0);
    CHECK(fa(X509_ASN_ENCODING, "", CERT_X500_NAME_STR, NULL, out, &n, &ea));
    EXPECT_EQ(n, 2); EXPECT_EQ(out[0], 0x30); EXPECT_EQ(out[1], 0); CHECK(ea == NULL);
    n = sizeof out;
    CHECK(fw(X509_ASN_ENCODING, L"", CERT_X500_NAME_STR, NULL, out, &n, &ew));
    EXPECT_EQ(n, 2); CHECK(ew == NULL);
}
TEST(sf_s2n_null_string_is_empty_sequence) {
    REQ_S2N(); BYTE out[8]; DWORD n = sizeof out;
    /* A rejects a NULL string (probed: FALSE, *pcbEncoded 0, last error left at 0); W treats it as the empty name */
    memset(out, 0xAA, sizeof out); SET_ERR(0);
    CHECK(!fa(X509_ASN_ENCODING, NULL, CERT_X500_NAME_STR, NULL, out, &n, NULL));
    EXPECT_ERR(0); EXPECT_EQ(n, 0); EXPECT_EQ(out[0], 0xAA);
    n = 0xabcd; SET_ERR(0); CHECK(!fa(X509_ASN_ENCODING, NULL, CERT_X500_NAME_STR, NULL, NULL, &n, NULL)); EXPECT_ERR(0); EXPECT_EQ(n, 0);
    n = sizeof out; CHECK(fw(X509_ASN_ENCODING, NULL, CERT_X500_NAME_STR, NULL, out, &n, NULL));
    EXPECT_EQ(n, 2); EXPECT_EQ(out[0], 0x30); EXPECT_EQ(out[1], 0);
}
TEST(sf_s2n_empty_string_ignores_invalid_type) {
    REQ_S2N(); BYTE out[8]; DWORD n = sizeof out;
    CHECK(fa(X509_ASN_ENCODING, "", CERT_XML_NAME_STR, NULL, out, &n, NULL)); EXPECT_EQ(n, 2);
    n = sizeof out; CHECK(fa(X509_ASN_ENCODING, "", CERT_SIMPLE_NAME_STR, NULL, out, &n, NULL)); EXPECT_EQ(n, 2);
}
TEST(sf_s2n_empty_string_bogus_encoding) {
    REQ_S2N(); BYTE out[8]; DWORD n = sizeof out;
    SET_ERR(0);
    CHECK(!fa(0, "", CERT_X500_NAME_STR, NULL, out, &n, NULL)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}

/* ---------------- protocol & failures ---------------- */
TEST(sf_s2n_short_buffer_more_data) {
    REQ_S2N(); BYTE out[16]; DWORD n = 5; memset(out, 0xcc, sizeof out);
    SET_ERR(0);
    CHECK(!fa(X509_ASN_ENCODING, "CN=1", CERT_X500_NAME_STR, NULL, out, &n, NULL));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 14);
    n = 0; SET_ERR(0);
    CHECK(!fa(X509_ASN_ENCODING, "CN=1", CERT_X500_NAME_STR, NULL, out, &n, NULL)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 14);
    n = 13; SET_ERR(0);
    CHECK(!fw(X509_ASN_ENCODING, L"CN=1", CERT_X500_NAME_STR, NULL, out, &n, NULL)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 14);
    n = 14; CHECK(fw(X509_ASN_ENCODING, L"CN=1", CERT_X500_NAME_STR, NULL, out, &n, NULL)); EXPECT_EQ(n, 14);
    n = 100; CHECK(fw(X509_ASN_ENCODING, L"CN=1", CERT_X500_NAME_STR, NULL, out, &n, NULL)); EXPECT_EQ(n, 14);
}
TEST(sf_s2n_known_der_cn1) {
    REQ_S2N(); BYTE out[32]; DWORD n = sizeof out;
    static const BYTE exp[] = { 0x30,0x0c,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x13,0x01,0x31 };
    CHECK(fa(X509_ASN_ENCODING, "CN=1", CERT_X500_NAME_STR, NULL, out, &n, NULL));
    EXPECT_EQ(n, sizeof exp); CHECK(!memcmp(out, exp, sizeof exp));
}
TEST(sf_s2n_bogus_encoding_type) {
    REQ_S2N(); DWORD n = 0;
    SET_ERR(0);
    CHECK(!fa(0, "CN=1", CERT_X500_NAME_STR, NULL, NULL, &n, NULL)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    SET_ERR(0);
    CHECK(!fw(0, L"CN=1", 0, NULL, NULL, &n, NULL)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    SET_ERR(0);
    /* PKCS_7_ASN_ENCODING alone is accepted and encodes like X509 (probed: 14 bytes) */
    CHECK(fa(PKCS_7_ASN_ENCODING, "CN=1", 0, NULL, NULL, &n, NULL)); EXPECT_EQ(n, 14);
}
TEST(sf_s2n_syntax_errors_report_position) {
    REQ_S2N();
    S2N_FAIL("bogus", 0, CRYPT_E_INVALID_X500_STRING, 0);
    S2N_FAIL("foo=1", 0, CRYPT_E_INVALID_X500_STRING, 0);
    S2N_FAIL("CN=1,foo=2", 0, CRYPT_E_INVALID_X500_STRING, 5);
    S2N_FAIL("CN=1, foo=2", 0, CRYPT_E_INVALID_X500_STRING, 6);
    S2N_FAIL("CN=1+2", 0, CRYPT_E_INVALID_X500_STRING, 5);
    S2N_FAIL("CN=1,2", CERT_NAME_STR_NO_QUOTING_FLAG, CRYPT_E_INVALID_X500_STRING, 5);
    S2N_FAIL("=1", 0, CRYPT_E_INVALID_X500_STRING, 0);
    S2N_FAIL("CN=1,=2", 0, CRYPT_E_INVALID_X500_STRING, 5);
}
TEST(sf_s2n_quote_errors) {
    REQ_S2N();
    S2N_FAIL("CN=\"\"1\"\"", 0, CRYPT_E_INVALID_X500_STRING, -1);
    S2N_FAIL("CN=\"abc", 0, CRYPT_E_INVALID_X500_STRING, -1);
    S2N_FAIL("CN=\"abc\"x", 0, CRYPT_E_INVALID_X500_STRING, -1);
    S2N_FAIL("CN=\"1,2;3,4\"", CERT_NAME_STR_NO_QUOTING_FLAG, CRYPT_E_INVALID_X500_STRING, -1);
}
TEST(sf_s2n_unknown_keys) {
    REQ_S2N();
    S2N_FAIL("XYZZY=1", 0, CRYPT_E_INVALID_X500_STRING, 0);
    S2N_FAIL("CN=1,XYZZY=2", 0, CRYPT_E_INVALID_X500_STRING, 5);
    S2N_FAIL("OID.=1", 0, CRYPT_E_INVALID_X500_STRING, 0);
    S2N_FAIL("1..2=1", 0, CRYPT_E_INVALID_X500_STRING, 0);
    S2N_FAIL("1.a=1", 0, CRYPT_E_INVALID_X500_STRING, 0);
}
TEST(sf_s2n_invalid_string_types) {
    REQ_S2N(); BYTE out[64]; DWORD n; LPCSTR ea = (LPCSTR)1; DWORD t;
    DWORD types[] = { CERT_SIMPLE_NAME_STR, CERT_XML_NAME_STR, 5, 6, 7, 8, 0x10 };
    for (t = 0; t < NELEM(types); t++) {
        n = sizeof out; ea = (LPCSTR)1; SET_ERR(0);
        BOOL r = fa(X509_ASN_ENCODING, "CN=1", types[t], NULL, out, &n, &ea);
        CHECKF(!r, "type %lu", types[t]); EXPECT_LE(SF_E_INVALIDARG); CHECKF(ea == NULL, "type %lu error ptr", types[t]);
    }
}
TEST(sf_s2n_valid_string_types) {
    REQ_S2N(); BYTE out[64]; DWORD n; DWORD types[] = { 0, CERT_OID_NAME_STR, CERT_X500_NAME_STR }, t;
    for (t = 0; t < NELEM(types); t++) { n = sizeof out; CHECKF(fa(X509_ASN_ENCODING, "CN=1", types[t], NULL, out, &n, NULL), "type %lu", types[t]); EXPECT_EQ(n, 14); }
}
TEST(sf_s2n_error_pointer_cleared_on_success) {
    REQ_S2N(); BYTE out[64]; DWORD n = sizeof out; LPCSTR ea = "stale"; LPCWSTR ew = L"stale";
    CHECK(fa(X509_ASN_ENCODING, "CN=1", CERT_X500_NAME_STR, NULL, out, &n, &ea)); CHECK(ea == NULL);
    n = sizeof out; CHECK(fw(X509_ASN_ENCODING, L"CN=1", CERT_X500_NAME_STR, NULL, out, &n, &ew)); CHECK(ew == NULL);
}
TEST(sf_s2n_error_pointer_on_buffer_too_small_is_null) {
    REQ_S2N(); BYTE out[4]; DWORD n = 4; LPCSTR ea = (LPCSTR)1;
    SET_ERR(0);
    CHECK(!fa(X509_ASN_ENCODING, "CN=1", CERT_X500_NAME_STR, NULL, out, &n, &ea));
    EXPECT_ERR(ERROR_MORE_DATA); CHECK(ea == NULL);
}

/* ---------------- round trips ---------------- */
static const char *rt_names[] = {
    "CN=a", "C=US, CN=a", "C=US, S=State, L=City, O=Org, OU=Unit, CN=Name", "O=\"Acme, Inc.\", CN=x",
    "CN=a + OU=b, O=c", "CN=\"a=b\"", "CN=\"1+2\"", "CN=\" lead\"", "CN=\"trail \"", "CN=\"say \"\"hi\"\"\"", "DC=com, DC=example, CN=Users",
    "T=Boss, CN=x", "OID.1.2.3.4=v, CN=x", "CN=a b c", "CN=x-y.z/w",
};
TEST(sf_s2n_roundtrip_through_nametostr) {
    REQ_S2N(); size_t i;
    for (i = 0; i < NELEM(rt_names); i++) {
        BYTE enc[1024]; DWORD n = sizeof enc; WCHAR out[512], exp[512]; CERT_NAME_BLOB nb;
        BOOL r = fa(X509_ASN_ENCODING, rt_names[i], CERT_X500_NAME_STR, NULL, enc, &n, NULL);
        CHECKF(r, "encode '%s' err %lx", rt_names[i], GetLastError());
        if (!r) continue;
        nb.cbData = n; nb.pbData = enc;
        n2sw(X509_ASN_ENCODING, &nb, CERT_X500_NAME_STR, out, 512);
        sf_widen(rt_names[i], exp);
        CHECKF(!lstrcmpW(out, exp), "roundtrip '%s' -> '%ls'", rt_names[i], out);
    }
}
TEST(sf_s2n_roundtrip_reverse_flags_cancel) {
    REQ_S2N(); BYTE enc[256]; DWORD n = sizeof enc; WCHAR out[256]; CERT_NAME_BLOB nb;
    CHECK(fa(X509_ASN_ENCODING, "C=US, O=Org, CN=Name", CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, NULL, enc, &n, NULL));
    nb.cbData = n; nb.pbData = enc;
    n2sw(X509_ASN_ENCODING, &nb, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, out, 256);
    CHECK(!lstrcmpW(out, L"C=US, O=Org, CN=Name"));
    n2sw(X509_ASN_ENCODING, &nb, CERT_X500_NAME_STR, out, 256);
    CHECK(!lstrcmpW(out, L"CN=Name, O=Org, C=US"));
}
TEST(sf_s2n_a_and_w_agree_on_ascii_table) {
    REQ_S2N(); size_t i;
    for (i = 0; i < NELEM(rt_names); i++) {
        BYTE ea[1024], ew[1024]; DWORD na = sizeof ea, nw = sizeof ew; WCHAR ws[512];
        sf_widen(rt_names[i], ws);
        BOOL ra = fa(X509_ASN_ENCODING, rt_names[i], CERT_X500_NAME_STR, NULL, ea, &na, NULL);
        BOOL rw = fw(X509_ASN_ENCODING, ws, CERT_X500_NAME_STR, NULL, ew, &nw, NULL);
        CHECKF(ra == rw && na == nw && !memcmp(ea, ew, na), "A/W differ for '%s'", rt_names[i]);
    }
}

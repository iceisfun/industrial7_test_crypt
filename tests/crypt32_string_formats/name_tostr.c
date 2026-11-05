/* CertNameToStrA/W: output layout for every string type and flag. */
#include "sf.h"

#define REQ_N2S() DWORD (WINAPI *fa)(DWORD, PCERT_NAME_BLOB, DWORD, LPSTR, DWORD) = (void*)t_proc("CertNameToStrA"); \
                  DWORD (WINAPI *fw)(DWORD, PCERT_NAME_BLOB, DWORD, LPWSTR, DWORD) = (void*)t_proc("CertNameToStrW"); \
                  REQUIRE(fa); REQUIRE(fw); (void)fa; (void)fw

static void widen_s(const char *s, WCHAR *w) { sf_widen(s, w); }

/* Full size/content/truncation protocol for one (name, type) pair. */
static void chk_n2s(const char *file, int line, PCERT_NAME_BLOB nb, DWORD type, const char *exp)
{
    DWORD (WINAPI *fa)(DWORD, PCERT_NAME_BLOB, DWORD, LPSTR, DWORD) = (void*)t_proc("CertNameToStrA");
    DWORD (WINAPI *fw)(DWORD, PCERT_NAME_BLOB, DWORD, LPWSTR, DWORD) = (void*)t_proc("CertNameToStrW");
    size_t el = strlen(exp); DWORD n; char abuf[4096]; WCHAR wbuf[4096], wexp[4096];
    widen_s(exp, wexp);
    SET_ERR(0);
    n = fw(X509_ASN_ENCODING, nb, type, NULL, 0);
    t_check(n == el + 1, file, line, "W size query", "got %lu want %zu type %#lx", n, el + 1, type);
    n = fa(X509_ASN_ENCODING, nb, type, NULL, 0);
    t_check(n == el + 1, file, line, "A size query", "got %lu want %zu type %#lx", n, el + 1, type);
    memset(wbuf, 0xcc, sizeof wbuf);
    n = fw(X509_ASN_ENCODING, nb, type, wbuf, 4096);
    t_check(n == el + 1, file, line, "W full length", "got %lu want %zu", n, el + 1);
    t_check(!lstrcmpW(wbuf, wexp), file, line, "W content", "type %#lx", type);
    memset(abuf, 0xcc, sizeof abuf);
    n = fa(X509_ASN_ENCODING, nb, type, abuf, 4096);
    t_check(n == el + 1, file, line, "A full length", "got %lu want %zu", n, el + 1);
    t_check(!strcmp(abuf, exp), file, line, "A content", "type %#lx got '%s' want '%s'", type, abuf, exp);
    /* exact-size buffer */
    memset(wbuf, 0xcc, sizeof wbuf);
    n = fw(X509_ASN_ENCODING, nb, type, wbuf, (DWORD)el + 1);
    t_check(n == el + 1 && !lstrcmpW(wbuf, wexp), file, line, "W exact buffer", "n=%lu", n);
    memset(abuf, 0xcc, sizeof abuf);
    n = fa(X509_ASN_ENCODING, nb, type, abuf, (DWORD)el + 1);
    t_check(n == el + 1 && !strcmp(abuf, exp), file, line, "A exact buffer", "n=%lu", n);
    if (el > 0) {
        /* one short: W truncates and terminates, A fails the narrowing and returns an empty string */
        memset(wbuf, 0xcc, sizeof wbuf);
        n = fw(X509_ASN_ENCODING, nb, type, wbuf, (DWORD)el);
        t_check(n == el, file, line, "W one-short return", "got %lu want %zu", n, el);
        t_check(!wcsncmp(wbuf, wexp, el - 1) && wbuf[el - 1] == 0, file, line, "W one-short content", NULL);
        memset(abuf, 0xcc, sizeof abuf);
        n = fa(X509_ASN_ENCODING, nb, type, abuf, (DWORD)el);
        t_check(n == 1 && abuf[0] == 0, file, line, "A one-short return", "got %lu first=%#x", n, (unsigned char)abuf[0]);
        /* size 1 */
        memset(wbuf, 0xcc, sizeof wbuf);
        n = fw(X509_ASN_ENCODING, nb, type, wbuf, 1);
        t_check(n == 1 && wbuf[0] == 0, file, line, "W cch=1", "n=%lu", n);
        /* csz = 0 with a buffer behaves as a size query and leaves the buffer alone */
        memset(wbuf, 0xcc, sizeof wbuf);
        n = fw(X509_ASN_ENCODING, nb, type, wbuf, 0);
        t_check(n == el + 1 && wbuf[0] == 0xcccc, file, line, "W cch=0 with buffer", "n=%lu", n);
        memset(abuf, 0xcc, sizeof abuf);
        n = fa(X509_ASN_ENCODING, nb, type, abuf, 0);
        t_check(n == el + 1 && (unsigned char)abuf[0] == 0xcc, file, line, "A cch=0 with buffer", "n=%lu", n);
    }
}
#define N2S(nb, type, exp) chk_n2s(__FILE__, __LINE__, &(nb), (type), (exp))

static BYTE g_nb[4096];

#define FULLNAME \
    { 1, "2.5.4.6", PS, "US", -1 }, { 1, "2.5.4.8", PS, "Minnesota", -1 }, { 1, "2.5.4.7", PS, "Minneapolis", -1 }, \
    { 1, "2.5.4.10", U8, "Corp", -1 }, { 1, "2.5.4.11", U8, "Dev", -1 }, { 1, "2.5.4.3", U8, "localhost", -1 }, \
    { 1, "1.2.840.113549.1.9.1", IA, "a@b.c", -1 }

TEST(sf_n2s_x500_default_order) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, FULLNAME);
    N2S(b, CERT_X500_NAME_STR, "C=US, S=Minnesota, L=Minneapolis, O=Corp, OU=Dev, CN=localhost, E=a@b.c");
}
TEST(sf_n2s_oid_names) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, FULLNAME);
    N2S(b, CERT_OID_NAME_STR, "2.5.4.6=US, 2.5.4.8=Minnesota, 2.5.4.7=Minneapolis, 2.5.4.10=Corp, 2.5.4.11=Dev, 2.5.4.3=localhost, 1.2.840.113549.1.9.1=a@b.c");
}
TEST(sf_n2s_simple_values_only) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, FULLNAME);
    N2S(b, CERT_SIMPLE_NAME_STR, "US, Minnesota, Minneapolis, Corp, Dev, localhost, a@b.c");
}
TEST(sf_n2s_type_zero_behaves_like_simple) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, FULLNAME);
    N2S(b, 0, "US, Minnesota, Minneapolis, Corp, Dev, localhost, a@b.c");
}
TEST(sf_n2s_semicolon) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, FULLNAME);
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG, "C=US; S=Minnesota; L=Minneapolis; O=Corp; OU=Dev; CN=localhost; E=a@b.c");
    N2S(b, CERT_SIMPLE_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG, "US; Minnesota; Minneapolis; Corp; Dev; localhost; a@b.c");
    N2S(b, CERT_OID_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG, "2.5.4.6=US; 2.5.4.8=Minnesota; 2.5.4.7=Minneapolis; 2.5.4.10=Corp; 2.5.4.11=Dev; 2.5.4.3=localhost; 1.2.840.113549.1.9.1=a@b.c");
}
TEST(sf_n2s_crlf) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, FULLNAME);
    N2S(b, CERT_SIMPLE_NAME_STR | CERT_NAME_STR_CRLF_FLAG, "US\r\nMinnesota\r\nMinneapolis\r\nCorp\r\nDev\r\nlocalhost\r\na@b.c");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG, "C=US\r\nS=Minnesota\r\nL=Minneapolis\r\nO=Corp\r\nOU=Dev\r\nCN=localhost\r\nE=a@b.c");
}
TEST(sf_n2s_semicolon_wins_over_crlf) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, { 1, "2.5.4.6", PS, "US", -1 }, { 1, "2.5.4.3", U8, "x", -1 });
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG | CERT_NAME_STR_CRLF_FLAG, "C=US; CN=x");
}
TEST(sf_n2s_comma_flag_is_default) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, { 1, "2.5.4.6", PS, "US", -1 }, { 1, "2.5.4.3", U8, "x", -1 });
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_COMMA_FLAG, "C=US, CN=x");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_FORWARD_FLAG, "C=US, CN=x");
}
TEST(sf_n2s_crlf_wins_over_comma) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, { 1, "2.5.4.6", PS, "US", -1 }, { 1, "2.5.4.3", U8, "x", -1 });
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_COMMA_FLAG | CERT_NAME_STR_CRLF_FLAG, "C=US\r\nCN=x");
}
TEST(sf_n2s_reverse) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, FULLNAME);
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, "E=a@b.c, CN=localhost, OU=Dev, O=Corp, L=Minneapolis, S=Minnesota, C=US");
    N2S(b, CERT_SIMPLE_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, "a@b.c, localhost, Dev, Corp, Minneapolis, Minnesota, US");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG | CERT_NAME_STR_REVERSE_FLAG, "E=a@b.c; CN=localhost; OU=Dev; O=Corp; L=Minneapolis; S=Minnesota; C=US");
    N2S(b, CERT_OID_NAME_STR | CERT_NAME_STR_CRLF_FLAG | CERT_NAME_STR_REVERSE_FLAG, "1.2.840.113549.1.9.1=a@b.c\r\n2.5.4.3=localhost\r\n2.5.4.11=Dev\r\n2.5.4.10=Corp\r\n2.5.4.7=Minneapolis\r\n2.5.4.8=Minnesota\r\n2.5.4.6=US");
}
TEST(sf_n2s_single_rdn_no_separators) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "1", -1 });
    N2S(b, CERT_X500_NAME_STR, "CN=1");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG, "CN=1");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, "CN=1");
}
TEST(sf_n2s_multivalued_rdn) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "a", -1 }, { 0, "2.5.4.11", PS, "b", -1 }, { 1, "2.5.4.10", PS, "c", -1 });
    N2S(b, CERT_X500_NAME_STR, "CN=a + OU=b, O=c");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, "CN=a OU=b, O=c");
    N2S(b, CERT_SIMPLE_NAME_STR, "a + b, c");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, "O=c, CN=a + OU=b");
}
TEST(sf_n2s_multivalued_all_in_one_rdn) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "a", -1 }, { 0, "2.5.4.11", PS, "b", -1 }, { 0, "2.5.4.10", PS, "c", -1 });
    N2S(b, CERT_X500_NAME_STR, "CN=a + OU=b + O=c");
    N2S(b, CERT_OID_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG, "2.5.4.3=a 2.5.4.11=b 2.5.4.10=c");
}
TEST(sf_n2s_unknown_oid_forms) {
    REQ_N2S(); CERT_NAME_BLOB b; NAME_OF(g_nb, b, { 1, "1.2.3.4", PS, "v", -1 });
    N2S(b, CERT_X500_NAME_STR, "OID.1.2.3.4=v");
    N2S(b, CERT_OID_NAME_STR, "1.2.3.4=v");
    N2S(b, CERT_SIMPLE_NAME_STR, "v");
}
TEST(sf_n2s_known_attribute_names) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.12", PS, "t", -1 });
    N2S(b, CERT_X500_NAME_STR, "T=t");
    NAME_OF(g_nb, b, { 1, "0.9.2342.19200300.100.1.25", IA, "com", -1 });
    N2S(b, CERT_X500_NAME_STR, "DC=com");
}

/* ---------------- quoting ---------------- */
static const struct { BYTE tag; const char *val; int n; const char *x500; const char *simple; } quote_cases[] = {
    { PS, "1", -1, "CN=1", "1" },
    { PS, "'1'", -1, "CN='1'", "'1'" },
    { PS, " 1 ", -1, "CN=\" 1 \"", "\" 1 \"" },
    { PS, " 1", -1, "CN=\" 1\"", "\" 1\"" },
    { PS, "1 ", -1, "CN=\"1 \"", "\"1 \"" },
    { PS, "a b", -1, "CN=a b", "a b" },
    { PS, "1+2", -1, "CN=\"1+2\"", "\"1+2\"" },
    { PS, "a,b", -1, "CN=\"a,b\"", "\"a,b\"" },
    { PS, "a=b", -1, "CN=\"a=b\"", "\"a=b\"" },
    { U8, "a<b", -1, "CN=\"a<b\"", "\"a<b\"" },
    { U8, "a>b", -1, "CN=\"a>b\"", "\"a>b\"" },
    { U8, "a#b", -1, "CN=\"a#b\"", "\"a#b\"" },
    { U8, "a;b", -1, "CN=\"a;b\"", "\"a;b\"" },
    { U8, "a\nb", -1, "CN=\"a\nb\"", "\"a\nb\"" },
    { U8, "a\"b", -1, "CN=\"a\"\"b\"", "\"a\"\"b\"" },
    { U8, "\"1\"", -1, "CN=\"\"\"1\"\"\"", "\"\"\"1\"\"\"" },
    { U8, "a-b.c/d:e?f(g)h", -1, "CN=a-b.c/d:e?f(g)h", "a-b.c/d:e?f(g)h" },
    { U8, "a'b", -1, "CN=a'b", "a'b" },
    { U8, "a\\b", -1, "CN=a\\b", "a\\b" },
    { U8, "a@b", -1, "CN=a@b", "a@b" },
    { U8, "a&b", -1, "CN=a&b", "a&b" },
    { U8, "a%b", -1, "CN=a%b", "a%b" },
    { U8, "a$b", -1, "CN=a$b", "a$b" },
    { U8, "a*b", -1, "CN=a*b", "a*b" },
    { U8, "a!b", -1, "CN=a!b", "a!b" },
    { U8, "a[b]", -1, "CN=a[b]", "a[b]" },
    { U8, "a{b}", -1, "CN=a{b}", "a{b}" },
    { U8, "a|b", -1, "CN=a|b", "a|b" },
    { U8, "a~b", -1, "CN=a~b", "a~b" },
    { U8, "a_b", -1, "CN=a_b", "a_b" },
    { U8, "a\tb", -1, "CN=a\tb", "a\tb" },
    { U8, "\xc3\xa9", -1, "CN=\xc3\xa9", "\xc3\xa9" },
};
TEST(sf_n2s_quoting_table_x500) {
    REQ_N2S(); size_t i;
    for (i = 0; i < NELEM(quote_cases); i++) {
        CERT_NAME_BLOB b; WCHAR wexp[64], wout[64]; DWORD n; int k;
        sf_attr a = { 1, "2.5.4.3", quote_cases[i].tag, quote_cases[i].val, quote_cases[i].n };
        b.cbData = sf_build_name(g_nb, &a, 1); b.pbData = g_nb;
        if (quote_cases[i].val[0] == (char)0xc3) {
            /* non-ASCII: compare as wide */
            const WCHAR w[] = L"CN=\x00e9";
            n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, wout, 64);
            CHECKF(n == 5 && !lstrcmpW(wout, w), "case %zu n=%lu", i, n);
            continue;
        }
        widen_s(quote_cases[i].x500, wexp);
        n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, wout, 64);
        CHECKF(n == strlen(quote_cases[i].x500) + 1 && !lstrcmpW(wout, wexp), "x500 case %zu n=%lu", i, n);
        widen_s(quote_cases[i].simple, wexp);
        n = fw(X509_ASN_ENCODING, &b, CERT_SIMPLE_NAME_STR, wout, 64);
        CHECKF(n == strlen(quote_cases[i].simple) + 1 && !lstrcmpW(wout, wexp), "simple case %zu n=%lu", i, n);
        N2S(b, CERT_X500_NAME_STR, quote_cases[i].x500);
    }
}
TEST(sf_n2s_quoting_bmp_value_types) {
    REQ_N2S(); CERT_NAME_BLOB b;
    static const BYTE q[] = { 0x00, 0x22, 0x00, '1', 0x00, 0x22 };  /* "1" as BMPString */
    NAME_OF(g_nb, b, { 1, "2.5.4.3", BM, q, 6 });
    N2S(b, CERT_X500_NAME_STR, "CN=\"\"\"1\"\"\"");
    static const BYTE lt[] = { 0x00, '<' };
    NAME_OF(g_nb, b, { 1, "2.5.4.3", BM, lt, 2 });
    N2S(b, CERT_X500_NAME_STR, "CN=\"<\"");
}
TEST(sf_n2s_no_quoting_flag) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "a,b", -1 });
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_NO_QUOTING_FLAG, "CN=a,b");
    NAME_OF(g_nb, b, { 1, "2.5.4.3", U8, "\"1\"", -1 });
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_NO_QUOTING_FLAG, "CN=\"1\"");
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, " 1 ", -1 });
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_NO_QUOTING_FLAG, "CN= 1 ");
    N2S(b, CERT_SIMPLE_NAME_STR | CERT_NAME_STR_NO_QUOTING_FLAG, " 1 ");
}
TEST(sf_n2s_quoted_values_in_multi_rdn_name) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.10", U8, "Acme, Inc.", -1 }, { 1, "2.5.4.3", U8, "x", -1 });
    N2S(b, CERT_X500_NAME_STR, "O=\"Acme, Inc.\", CN=x");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG, "O=\"Acme, Inc.\"; CN=x");
}

/* ---------------- string types and escapes ---------------- */
TEST(sf_n2s_value_string_types) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "ps", -1 }); N2S(b, CERT_X500_NAME_STR, "CN=ps");
    NAME_OF(g_nb, b, { 1, "2.5.4.3", U8, "u8", -1 }); N2S(b, CERT_X500_NAME_STR, "CN=u8");
    NAME_OF(g_nb, b, { 1, "2.5.4.3", IA, "ia", -1 }); N2S(b, CERT_X500_NAME_STR, "CN=ia");
    NAME_OF(g_nb, b, { 1, "2.5.4.3", T6, "t6", -1 }); N2S(b, CERT_X500_NAME_STR, "CN=t6");
    NAME_OF(g_nb, b, { 1, "2.5.4.3", NM, "123", -1 }); N2S(b, CERT_X500_NAME_STR, "CN=123");
    static const BYTE bm[] = { 0x00, 'b', 0x00, 'm' };
    NAME_OF(g_nb, b, { 1, "2.5.4.3", BM, bm, 4 }); N2S(b, CERT_X500_NAME_STR, "CN=bm");
}
TEST(sf_n2s_utf8_value_decoded_to_wide) {
    REQ_N2S(); CERT_NAME_BLOB b; WCHAR w[32]; DWORD n;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", U8, "\xe6\x97\xa5\xe6\x9c\xac", -1 });
    n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, w, 32);
    EXPECT_EQ(n, 6); CHECK(!lstrcmpW(w, L"CN=\x65e5\x672c"));
    n = fw(X509_ASN_ENCODING, &b, CERT_SIMPLE_NAME_STR, w, 32);
    EXPECT_EQ(n, 3); CHECK(!lstrcmpW(w, L"\x65e5\x672c"));
}
TEST(sf_n2s_bmp_surrogates_pass_through) {
    REQ_N2S(); CERT_NAME_BLOB b; WCHAR w[32]; DWORD n;
    static const BYTE bm[] = { 0xd8, 0x3d, 0xde, 0x00 };
    NAME_OF(g_nb, b, { 1, "2.5.4.3", BM, bm, 4 });
    n = fw(X509_ASN_ENCODING, &b, CERT_SIMPLE_NAME_STR, w, 32);
    EXPECT_EQ(n, 3); CHECK(w[0] == 0xd83d && w[1] == 0xde00);
}
TEST(sf_n2s_a_converts_through_ansi_code_page) {
    REQ_N2S(); CERT_NAME_BLOB b; char s[64];
    NAME_OF(g_nb, b, { 1, "2.5.4.3", U8, "plain", -1 });
    DWORD n = fa(X509_ASN_ENCODING, &b, CERT_SIMPLE_NAME_STR, s, 64);
    EXPECT_EQ(n, 6); EXPECT_STR(s, "plain");
}
TEST(sf_n2s_non_string_values_hex) {
    REQ_N2S(); CERT_NAME_BLOB b; WCHAR w[64]; DWORD n;
    static const BYTE oct[] = { 0xab, 0xcd };
    NAME_OF(g_nb, b, { 1, "2.5.4.3", 0x04, oct, 2 });
    n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, w, 64);
    t_note("CN as OCTET STRING {ab cd}, X500: '%ls' (%lu)", w, n);
    static const BYTE intv[] = { 0x05 };
    NAME_OF(g_nb, b, { 1, "2.5.4.3", 0x02, intv, 1 });
    n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, w, 64);
    t_note("CN as INTEGER 5, X500: '%ls' (%lu)", w, n);
}

/* ---------------- XML ---------------- */
TEST(sf_n2s_xml_basic) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "a", -1 }, { 1, "2.5.4.10", PS, "b", -1 });
    N2S(b, CERT_XML_NAME_STR, "<CN>a</CN><O>b</O>");
    N2S(b, CERT_XML_NAME_STR | CERT_NAME_STR_CRLF_FLAG, "<CN>a</CN>\r\n<O>b</O>\r\n");
}
TEST(sf_n2s_xml_escapes) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", U8, "a&b<c>d\"e'f", -1 });
    N2S(b, CERT_XML_NAME_STR, "<CN>a&amp;b&lt;c&gt;d&quot;e&apos;f</CN>");
}
TEST(sf_n2s_xml_multivalued_marks_second_attribute) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "a", -1 }, { 0, "2.5.4.11", PS, "b", -1 });
    N2S(b, CERT_XML_NAME_STR, "<CN>a</CN><OU rDNAttribute=\"true\">b</OU>");
}
TEST(sf_n2s_xml_unknown_oid) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "1.2.3.4", PS, "v", -1 });
    N2S(b, CERT_XML_NAME_STR, "<RDN oid=\"1.2.3.4\" type=\"string\">v</RDN>");
}

/* ---------------- failure modes ---------------- */
TEST(sf_n2s_bogus_encoding_type) {
    REQ_N2S(); CERT_NAME_BLOB b; WCHAR w[8]; char s[8]; DWORD n;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "1", -1 });
    SET_ERR(0);
    n = fw(0, &b, CERT_X500_NAME_STR, NULL, 0);
    EXPECT_EQ(n, 1); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    SET_ERR(0);
    n = fa(0, &b, CERT_X500_NAME_STR, NULL, 0);
    EXPECT_EQ(n, 1); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    w[0] = 0x7777; n = fw(0, &b, CERT_X500_NAME_STR, w, 8); EXPECT_EQ(n, 1); EXPECT_EQ(w[0], 0);
    s[0] = 0x77; n = fa(0, &b, CERT_X500_NAME_STR, s, 8); EXPECT_EQ(n, 1); EXPECT_EQ(s[0], 0);
}
TEST(sf_n2s_combined_encoding_types) {
    REQ_N2S(); CERT_NAME_BLOB b; WCHAR w[16];
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "1", -1 });
    DWORD n = fw(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &b, CERT_X500_NAME_STR, w, 16);
    t_note("X509|PKCS7 encoding type: n=%lu '%ls'", n, w);
    n = fw(PKCS_7_ASN_ENCODING, &b, CERT_X500_NAME_STR, w, 16);
    t_note("PKCS7 only encoding type: n=%lu err=%lu", n, GetLastError());
}
TEST(sf_n2s_empty_name) {
    REQ_N2S(); CERT_NAME_BLOB b; static const BYTE empty[] = { 0x30, 0x00 }; WCHAR w[8]; char s[8]; DWORD n;
    b.cbData = 2; b.pbData = (BYTE*)empty;
    SET_ERR(0);
    n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, NULL, 0);
    EXPECT_EQ(n, 1); t_note("empty name last error = %#lx (decomp sets CRYPT_E_NOT_FOUND)", GetLastError());
    w[0] = 0x7777; n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, w, 8); EXPECT_EQ(n, 1); EXPECT_EQ(w[0], 0);
    s[0] = 0x77; n = fa(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, s, 8); EXPECT_EQ(n, 1); EXPECT_EQ(s[0], 0);
}
TEST(sf_n2s_garbage_blob) {
    REQ_N2S(); CERT_NAME_BLOB b; static const BYTE junk[] = { 0x01, 0x02, 0x03 }; WCHAR w[8]; DWORD n;
    b.cbData = 3; b.pbData = (BYTE*)junk;
    SET_ERR(0);
    n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, w, 8);
    EXPECT_EQ(n, 1); EXPECT_EQ(w[0], 0);
    CHECK(GetLastError() != 0);
    t_note("garbage name blob last error: %#lx", GetLastError());
}
TEST(sf_n2s_truncated_der) {
    REQ_N2S(); CERT_NAME_BLOB b; WCHAR w[8]; DWORD n;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "abc", -1 });
    b.cbData -= 2;
    SET_ERR(0);
    n = fw(X509_ASN_ENCODING, &b, CERT_X500_NAME_STR, w, 8);
    EXPECT_EQ(n, 1);
    CHECK(GetLastError() != 0);
}
TEST(sf_n2s_unicode_flags_do_not_change_ascii) {
    REQ_N2S(); CERT_NAME_BLOB b;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", PS, "abc", -1 });
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG, "CN=abc");
    N2S(b, CERT_X500_NAME_STR | CERT_NAME_STR_ENABLE_PUNYCODE_FLAG, "CN=abc");
}
TEST(sf_n2s_long_name) {
    REQ_N2S(); CERT_NAME_BLOB b; char val[400], exp[600]; int i;
    for (i = 0; i < 300; i++) val[i] = (char)('a' + i % 26);
    val[300] = 0;
    NAME_OF(g_nb, b, { 1, "2.5.4.3", U8, val, -1 });
    sprintf(exp, "CN=%s", val);
    N2S(b, CERT_X500_NAME_STR, exp);
}
TEST(sf_n2s_many_rdns) {
    REQ_N2S(); CERT_NAME_BLOB b; sf_attr a[20]; char vals[20][4], exp[600]; int i; size_t o = 0;
    for (i = 0; i < 20; i++) { sprintf(vals[i], "v%d", i); a[i].nrdn = 1; a[i].oid = "2.5.4.11"; a[i].tag = PS; a[i].v = vals[i]; a[i].n = -1; }
    b.cbData = sf_build_name(g_nb, a, 20); b.pbData = g_nb;
    for (i = 0; i < 20; i++) o += sprintf(exp + o, "%sOU=%s", i ? ", " : "", vals[i]);
    N2S(b, CERT_X500_NAME_STR, exp);
}

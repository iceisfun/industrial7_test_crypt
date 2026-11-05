/* CertCompareIntegerBlob, CertCompareCertificateName, CryptFormatObject, export resolution. */
#include "sf.h"

/* ---------------- CertCompareIntegerBlob ---------------- */
static BOOL cmp_int(const BYTE *a, DWORD an, const BYTE *b, DWORD bn)
{
    BOOL (WINAPI *f)(PCRYPT_INTEGER_BLOB, PCRYPT_INTEGER_BLOB) = (void*)t_proc("CertCompareIntegerBlob");
    CRYPT_INTEGER_BLOB x, y; x.cbData = an; x.pbData = (BYTE*)a; y.cbData = bn; y.pbData = (BYTE*)b;
    return f(&x, &y);
}
#define EQ_(a, b)  CHECK(cmp_int(a, sizeof a, b, sizeof b) && cmp_int(b, sizeof b, a, sizeof a))
#define NE_(a, b)  CHECK(!cmp_int(a, sizeof a, b, sizeof b) && !cmp_int(b, sizeof b, a, sizeof a))
#define REQ_CI() REQUIRE(t_proc("CertCompareIntegerBlob"))

TEST(sf_cib_identical) {
    REQ_CI(); static const BYTE a[] = { 1, 2, 3 }, b[] = { 0x23, 0xff }, c[] = { 0 }, d[] = { 0x80 };
    EQ_(a, a); EQ_(b, b); EQ_(c, c); EQ_(d, d);
}
TEST(sf_cib_trailing_zero_is_sign_extension_of_positive) {
    REQ_CI(); static const BYTE a[] = { 0x7f, 0x00 }, b[] = { 0x7f }, c[] = { 0x01, 0x00, 0x00 }, d[] = { 0x01 };
    EQ_(a, b); EQ_(c, d);
}
TEST(sf_cib_trailing_zero_after_high_bit_is_significant) {
    REQ_CI(); static const BYTE a[] = { 0x80, 0x00 }, b[] = { 0x80 }, c[] = { 0xff, 0x00 }, d[] = { 0xff };
    NE_(a, b); NE_(c, d);
}
TEST(sf_cib_multiple_redundant_bytes) {
    REQ_CI(); static const BYTE a[] = { 0x80, 0x00, 0x00, 0x00 }, b[] = { 0x80, 0x00 }, c[] = { 0x80 };
    EQ_(a, b); NE_(a, c); NE_(b, c);
}
TEST(sf_cib_negative_sign_extension) {
    REQ_CI(); static const BYTE a[] = { 0x88, 0xff, 0xff, 0xff }, b[] = { 0x88, 0xff }, c[] = { 0x88 }, d[] = { 0x23, 0xff }, e[] = { 0x23 };
    EQ_(a, b); EQ_(a, c); EQ_(b, c); NE_(d, e);
}
TEST(sf_cib_ff_after_positive_is_significant) {
    REQ_CI(); static const BYTE a[] = { 0x7f, 0xff }, b[] = { 0x7f };
    NE_(a, b);
}
TEST(sf_cib_minus_one_forms) {
    REQ_CI(); static const BYTE a[] = { 0xff }, b[] = { 0xff, 0xff }, c[] = { 0xff, 0xff, 0xff };
    EQ_(a, b); EQ_(b, c); EQ_(a, c);
}
TEST(sf_cib_zero_forms) {
    REQ_CI(); static const BYTE a[] = { 0 }, b[] = { 0, 0 }, c[] = { 0, 0, 0, 0 };
    EQ_(a, b); EQ_(b, c); EQ_(a, c);
}
TEST(sf_cib_different_values) {
    REQ_CI(); static const BYTE a[] = { 1 }, b[] = { 2 }, c[] = { 1, 2 }, d[] = { 2, 1 };
    NE_(a, b); NE_(a, c); NE_(c, d);
}
TEST(sf_cib_byte_order_is_little_endian) {
    REQ_CI(); static const BYTE a[] = { 0x01, 0x02 }, b[] = { 0x02, 0x01 };
    NE_(a, b);
}
TEST(sf_cib_positive_vs_negative) {
    REQ_CI(); static const BYTE a[] = { 0x80 }, b[] = { 0x80, 0x00 }, c[] = { 0x7f };
    NE_(a, b); NE_(a, c);
}
TEST(sf_cib_empty_blobs) {
    REQ_CI(); static const BYTE z[] = { 0 }, one[] = { 1 };
    CHECK(cmp_int(NULL, 0, NULL, 0));
    CHECK(cmp_int(z, 0, one, 0));
    CHECK(!cmp_int(z, 0, one, 1));
    CHECK(!cmp_int(one, 1, z, 0));
    CHECK(!cmp_int(z, 0, z, 1));
}
TEST(sf_cib_serial_numbers_of_test_certs) {
    REQ_CI();
    PCCERT_CONTEXT (WINAPI *cc)(DWORD, const BYTE*, DWORD) = (void*)t_proc("CertCreateCertificateContext");
    BOOL (WINAPI *fc)(PCCERT_CONTEXT) = (void*)t_proc("CertFreeCertificateContext");
    REQUIRE(cc); REQUIRE(fc);
    PCCERT_CONTEXT l = cc(X509_ASN_ENCODING, sf_cert_leaf, sf_cert_leaf_len), o = cc(X509_ASN_ENCODING, sf_cert_ou, sf_cert_ou_len);
    CHECK(l && o);
    if (l && o) {
        BOOL (WINAPI *f)(PCRYPT_INTEGER_BLOB, PCRYPT_INTEGER_BLOB) = (void*)t_proc("CertCompareIntegerBlob");
        CHECK(f(&l->pCertInfo->SerialNumber, &l->pCertInfo->SerialNumber));
        CHECK(!f(&l->pCertInfo->SerialNumber, &o->pCertInfo->SerialNumber));
        /* serial 0x123456 is stored little-endian */
        EXPECT_EQ(l->pCertInfo->SerialNumber.cbData, 3);
        EXPECT_EQ(l->pCertInfo->SerialNumber.pbData[0], 0x56); EXPECT_EQ(l->pCertInfo->SerialNumber.pbData[2], 0x12);
    }
    if (l) fc(l);
    if (o) fc(o);
}

/* ---------------- CertCompareCertificateName ---------------- */
static BOOL cmp_name(DWORD enc, PCERT_NAME_BLOB a, PCERT_NAME_BLOB b)
{
    BOOL (WINAPI *f)(DWORD, PCERT_NAME_BLOB, PCERT_NAME_BLOB) = (void*)t_proc("CertCompareCertificateName");
    return f(enc, a, b);
}
static BYTE nb1[2048], nb2[2048];
#define REQ_CN() REQUIRE(t_proc("CertCompareCertificateName"))

TEST(sf_ccn_identical_names) {
    REQ_CN(); CERT_NAME_BLOB a, b;
    NAME_OF(nb1, a, { 1, "2.5.4.3", PS, "x", -1 });
    NAME_OF(nb2, b, { 1, "2.5.4.3", PS, "x", -1 });
    CHECK(cmp_name(X509_ASN_ENCODING, &a, &b));
    CHECK(cmp_name(X509_ASN_ENCODING, &a, &a));
}
TEST(sf_ccn_different_value) {
    REQ_CN(); CERT_NAME_BLOB a, b;
    NAME_OF(nb1, a, { 1, "2.5.4.3", PS, "x", -1 });
    NAME_OF(nb2, b, { 1, "2.5.4.3", PS, "y", -1 });
    CHECK(!cmp_name(X509_ASN_ENCODING, &a, &b));
}
TEST(sf_ccn_different_length) {
    REQ_CN(); CERT_NAME_BLOB a, b;
    NAME_OF(nb1, a, { 1, "2.5.4.3", PS, "x", -1 });
    NAME_OF(nb2, b, { 1, "2.5.4.3", PS, "xx", -1 });
    CHECK(!cmp_name(X509_ASN_ENCODING, &a, &b));
}
TEST(sf_ccn_comparison_is_encoding_exact) {
    REQ_CN(); CERT_NAME_BLOB a, b;
    NAME_OF(nb1, a, { 1, "2.5.4.3", PS, "x", -1 });
    NAME_OF(nb2, b, { 1, "2.5.4.3", U8, "x", -1 });
    CHECK(!cmp_name(X509_ASN_ENCODING, &a, &b));
    NAME_OF(nb2, b, { 1, "2.5.4.3", PS, "X", -1 });
    CHECK(!cmp_name(X509_ASN_ENCODING, &a, &b));
}
TEST(sf_ccn_order_matters) {
    REQ_CN(); CERT_NAME_BLOB a, b;
    NAME_OF(nb1, a, { 1, "2.5.4.3", PS, "x", -1 }, { 1, "2.5.4.10", PS, "y", -1 });
    NAME_OF(nb2, b, { 1, "2.5.4.10", PS, "y", -1 }, { 1, "2.5.4.3", PS, "x", -1 });
    CHECK(!cmp_name(X509_ASN_ENCODING, &a, &b));
}
TEST(sf_ccn_encoding_type_not_validated) {
    REQ_CN(); CERT_NAME_BLOB a, b;
    NAME_OF(nb1, a, { 1, "2.5.4.3", PS, "x", -1 });
    NAME_OF(nb2, b, { 1, "2.5.4.3", PS, "x", -1 });
    CHECK(cmp_name(0, &a, &b));
    CHECK(cmp_name(PKCS_7_ASN_ENCODING, &a, &b));
    CHECK(cmp_name(0xdead, &a, &b));
}
TEST(sf_ccn_empty_blobs) {
    REQ_CN(); CERT_NAME_BLOB a, b; static const BYTE x[1] = { 0 };
    a.cbData = 0; a.pbData = (BYTE*)x; b.cbData = 0; b.pbData = (BYTE*)x;
    CHECK(cmp_name(X509_ASN_ENCODING, &a, &b));
    b.cbData = 1; CHECK(!cmp_name(X509_ASN_ENCODING, &a, &b));
}
TEST(sf_ccn_not_validated_as_asn1) {
    REQ_CN(); CERT_NAME_BLOB a, b; static const BYTE j1[] = { 1, 2, 3 }, j2[] = { 1, 2, 3 }, j3[] = { 1, 2, 4 };
    a.cbData = 3; a.pbData = (BYTE*)j1; b.cbData = 3; b.pbData = (BYTE*)j2;
    CHECK(cmp_name(X509_ASN_ENCODING, &a, &b));
    b.pbData = (BYTE*)j3; CHECK(!cmp_name(X509_ASN_ENCODING, &a, &b));
}
TEST(sf_ccn_cert_issuer_equals_ca_subject) {
    REQ_CN();
    PCCERT_CONTEXT (WINAPI *cc)(DWORD, const BYTE*, DWORD) = (void*)t_proc("CertCreateCertificateContext");
    BOOL (WINAPI *fc)(PCCERT_CONTEXT) = (void*)t_proc("CertFreeCertificateContext");
    REQUIRE(cc); REQUIRE(fc);
    PCCERT_CONTEXT l = cc(X509_ASN_ENCODING, sf_cert_leaf, sf_cert_leaf_len), c = cc(X509_ASN_ENCODING, sf_cert_ca, sf_cert_ca_len);
    CHECK(l && c);
    if (l && c) {
        CHECK(cmp_name(X509_ASN_ENCODING, &l->pCertInfo->Issuer, &c->pCertInfo->Subject));
        CHECK(!cmp_name(X509_ASN_ENCODING, &l->pCertInfo->Subject, &c->pCertInfo->Subject));
        CHECK(!cmp_name(X509_ASN_ENCODING, &l->pCertInfo->Subject, &l->pCertInfo->Issuer));
        CHECK(cmp_name(X509_ASN_ENCODING, &c->pCertInfo->Subject, &c->pCertInfo->Subject));
    }
    if (l) fc(l);
    if (c) fc(c);
}

/* ---------------- CryptFormatObject ---------------- */
TEST(sf_cfo_basic_constraints_size_protocol) {
    BOOL (WINAPI *f)(DWORD, DWORD, DWORD, void*, LPCSTR, const BYTE*, DWORD, void*, DWORD*) = (void*)t_proc("CryptFormatObject");
    REQUIRE(f);
    static const BYTE bc[] = { 0x30, 0x03, 0x01, 0x01, 0xff };  /* CA = TRUE */
    DWORD cb = 0; WCHAR buf[256]; BOOL r;
    SET_ERR(0);
    r = f(X509_ASN_ENCODING, 0, 0, NULL, szOID_BASIC_CONSTRAINTS2, bc, sizeof bc, NULL, &cb);
    CHECK(r); CHECK(cb >= 2 * sizeof(WCHAR));
    if (r) {
        DWORD cb2 = cb;
        memset(buf, 0xcc, sizeof buf);
        r = f(X509_ASN_ENCODING, 0, 0, NULL, szOID_BASIC_CONSTRAINTS2, bc, sizeof bc, buf, &cb2);
        CHECK(r);
        if (r) {
            CHECK(cb2 <= cb); CHECK(cb2 % 2 == 0);
            CHECK(buf[cb2 / 2 - 1] == 0 || lstrlenW(buf) == (int)(cb2 / 2) - 1);
            t_note("BasicConstraints2 CA=TRUE formatted (locale dependent): '%ls' cb=%lu", buf, cb2);
        }
        DWORD small = 4; SET_ERR(0);
        r = f(X509_ASN_ENCODING, 0, 0, NULL, szOID_BASIC_CONSTRAINTS2, bc, sizeof bc, buf, &small);
        CHECK(!r); EXPECT_ERR(ERROR_MORE_DATA);
        t_note("short buffer: *pcb=%lu (needed %lu)", small, cb);
    }
}
TEST(sf_cfo_multiline_uses_crlf) {
    BOOL (WINAPI *f)(DWORD, DWORD, DWORD, void*, LPCSTR, const BYTE*, DWORD, void*, DWORD*) = (void*)t_proc("CryptFormatObject");
    REQUIRE(f);
    static const BYTE bc[] = { 0x30, 0x03, 0x01, 0x01, 0xff };
    DWORD c1 = 0, c2 = 0; WCHAR a[256], b[256];
    CHECK(f(X509_ASN_ENCODING, 0, 0, NULL, szOID_BASIC_CONSTRAINTS2, bc, sizeof bc, NULL, &c1));
    CHECK(f(X509_ASN_ENCODING, 0, CRYPT_FORMAT_STR_MULTI_LINE, NULL, szOID_BASIC_CONSTRAINTS2, bc, sizeof bc, NULL, &c2));
    if (c1 && c2 && c1 < sizeof a && c2 < sizeof b) {
        CHECK(f(X509_ASN_ENCODING, 0, 0, NULL, szOID_BASIC_CONSTRAINTS2, bc, sizeof bc, a, &c1));
        CHECK(f(X509_ASN_ENCODING, 0, CRYPT_FORMAT_STR_MULTI_LINE, NULL, szOID_BASIC_CONSTRAINTS2, bc, sizeof bc, b, &c2));
        CHECK(wcschr(a, L'\n') == NULL);
        CHECK(wcsstr(b, L"\r\n") != NULL);
        t_note("single line: '%ls'", a);
    }
}
TEST(sf_cfo_key_usage) {
    BOOL (WINAPI *f)(DWORD, DWORD, DWORD, void*, LPCSTR, const BYTE*, DWORD, void*, DWORD*) = (void*)t_proc("CryptFormatObject");
    REQUIRE(f);
    static const BYTE ku[] = { 0x03, 0x02, 0x05, 0xa0 }; /* digitalSignature, keyEncipherment */
    DWORD cb = 0; WCHAR buf[256];
    CHECK(f(X509_ASN_ENCODING, 0, 0, NULL, szOID_KEY_USAGE, ku, sizeof ku, NULL, &cb));
    if (cb && cb < sizeof buf) {
        CHECK(f(X509_ASN_ENCODING, 0, 0, NULL, szOID_KEY_USAGE, ku, sizeof ku, buf, &cb));
        CHECK(wcsstr(buf, L"(a0)") != NULL);
        t_note("KeyUsage formatted: '%ls'", buf);
    }
}
TEST(sf_cfo_unknown_oid_hex_fallback) {
    BOOL (WINAPI *f)(DWORD, DWORD, DWORD, void*, LPCSTR, const BYTE*, DWORD, void*, DWORD*) = (void*)t_proc("CryptFormatObject");
    REQUIRE(f);
    static const BYTE v[] = { 0x30, 0x03, 0x02, 0x01, 0x05 }; DWORD cb = 0; WCHAR buf[256];
    SET_ERR(0);
    BOOL r = f(X509_ASN_ENCODING, 0, 0, NULL, "1.2.3.4.5", v, sizeof v, NULL, &cb);
    t_note("unknown OID: ok=%d cb=%lu err=%lu", r, cb, GetLastError());
    if (r && cb && cb < sizeof buf) {
        r = f(X509_ASN_ENCODING, 0, 0, NULL, "1.2.3.4.5", v, sizeof v, buf, &cb);
        if (r) t_note("unknown OID formatted as '%ls'", buf);
    }
}
TEST(sf_cfo_bad_arguments) {
    BOOL (WINAPI *f)(DWORD, DWORD, DWORD, void*, LPCSTR, const BYTE*, DWORD, void*, DWORD*) = (void*)t_proc("CryptFormatObject");
    REQUIRE(f);
    static const BYTE bc[] = { 0x30, 0x03, 0x01, 0x01, 0xff };
    DWORD cb = 0; WCHAR buf[64];
    SET_ERR(0);
    BOOL r = f(0, 0, 0, NULL, szOID_BASIC_CONSTRAINTS2, bc, sizeof bc, NULL, &cb);
    t_note("encoding type 0: ok=%d err=%lu", r, GetLastError());
    SET_ERR(0);
    r = f(X509_ASN_ENCODING, 0, 0, NULL, szOID_BASIC_CONSTRAINTS2, NULL, 0, NULL, &cb);
    t_note("no data: ok=%d err=%lu cb=%lu", r, GetLastError(), cb);
    cb = sizeof buf; SET_ERR(0);
    static const BYTE junk[] = { 0xde, 0xad };
    r = f(X509_ASN_ENCODING, 0, 0, NULL, szOID_BASIC_CONSTRAINTS2, junk, sizeof junk, buf, &cb);
    t_note("undecodable basic constraints: ok=%d err=%#lx", r, GetLastError());
}

/* ---------------- export resolution ---------------- */
TEST(sf_exports_resolve_in_crypt32) {
    static const char *names[] = { "CryptBinaryToStringA", "CryptBinaryToStringW", "CryptStringToBinaryA", "CryptStringToBinaryW",
        "CertNameToStrA", "CertNameToStrW", "CertStrToNameA", "CertStrToNameW", "CertRDNValueToStrA", "CertRDNValueToStrW",
        "CertGetNameStringA", "CertGetNameStringW", "CryptFormatObject", "CertCompareIntegerBlob", "CertCompareCertificateName" };
    size_t i;
    for (i = 0; i < NELEM(names); i++) CHECKF(t_proc_in("crypt32.dll", names[i]) != NULL, "%s", names[i]);
}
TEST(sf_exports_getprocaddress_negative) {
    SET_ERR(0);
    CHECK(GetProcAddress(t_module("crypt32.dll"), "CryptBinaryToStringX") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(t_module("crypt32.dll"), "cryptbinarytostringa") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}

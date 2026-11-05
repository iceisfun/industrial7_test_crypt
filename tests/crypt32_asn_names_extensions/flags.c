/* CryptEncodeObject(Ex) / CryptDecodeObject(Ex) dispatch, flags, allocators and the size protocol. */
#include "asn.h"

static const WCHAR wdns[] = { 'a','.','c','o','m',0 };

/* ---- allocator parameters ---------------------------------------------- */
static void enc_name_cn(CERT_NAME_INFO *ni, CERT_RDN *rdn, CERT_RDN_ATTR *a) {
    a->pszObjId = (LPSTR)"2.5.4.3"; a->dwValueType = CERT_RDN_PRINTABLE_STRING; a->Value.cbData = 4; a->Value.pbData = (BYTE *)"Test";
    rdn->cRDNAttr = 1; rdn->rgRDNAttr = a; ni->cRDN = 1; ni->rgRDN = rdn;
}

TEST(flags_encode_custom_allocator) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_INFO ni; CERT_RDN rdn; CERT_RDN_ATTR a; enc_name_cn(&ni, &rdn, &a);
    CRYPT_ENCODE_PARA ep = { sizeof ep, as_alloc, as_free };
    BYTE *p = NULL; DWORD cb = 0; AS_RESET();
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, CRYPT_ENCODE_ALLOC_FLAG, &ep, &p, &cb);
    CHECK(r); CHECK(g_as.allocs >= 1); CHECK(p != NULL && p == g_as.last);
    CHECK(cb == sizeof v_name_cn_test); CHECK(p && !memcmp(p, v_name_cn_test, sizeof v_name_cn_test));
    CHECK(g_as.lastsz >= cb);
    if (p) { as_free(p); CHECK(g_as.frees == 1); }
}
TEST(flags_encode_allocator_failure) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_INFO ni; CERT_RDN rdn; CERT_RDN_ATTR a; enc_name_cn(&ni, &rdn, &a);
    CRYPT_ENCODE_PARA ep = { sizeof ep, as_alloc, as_free };
    BYTE *p = (BYTE *)(ULONG_PTR)1; DWORD cb = 77; AS_RESET(); g_as.fail = 1; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, CRYPT_ENCODE_ALLOC_FLAG, &ep, &p, &cb);
    CHECK(!r); CHECK(g_as.allocs >= 1);
    t_note("encode with failing allocator: err 0x%lx, p=%p, cb=%lu", GetLastError(), p, cb);
}
TEST(flags_encode_default_allocator_is_localalloc) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_INFO ni; CERT_RDN rdn; CERT_RDN_ATTR a; enc_name_cn(&ni, &rdn, &a);
    BYTE *p = NULL; DWORD cb = 0;
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    CHECK(r && p);
    if (p) { CHECK(LocalSize(p) >= cb); CHECK(LocalFree(p) == NULL); }
    /* a PCRYPT_ENCODE_PARA with NULL callbacks also means LocalAlloc/LocalFree */
    CRYPT_ENCODE_PARA ep = { sizeof ep, NULL, NULL }; p = NULL;
    r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, CRYPT_ENCODE_ALLOC_FLAG, &ep, &p, &cb);
    CHECK(r && p);
    if (p) { CHECK(LocalSize(p) >= cb); LocalFree(p); }
}
TEST(flags_encode_allocator_across_structures) {
    REQUIRE(U(CryptEncodeObjectEx));
    CRYPT_ENCODE_PARA ep = { sizeof ep, as_alloc, as_free };
    BYTE *p; DWORD cb;
    CERT_BASIC_CONSTRAINTS2_INFO bc = { TRUE, FALSE, 0 };
    AS_RESET(); p = NULL;
    CHECK(U(CryptEncodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, &bc, CRYPT_ENCODE_ALLOC_FLAG, &ep, &p, &cb));
    CHECK(p == g_as.last && cb == sizeof v_bc2_ca && !memcmp(p, v_bc2_ca, cb)); as_free(p);
    CERT_ALT_NAME_ENTRY e = { CERT_ALT_NAME_DNS_NAME }; e.pwszDNSName = (LPWSTR)wdns;
    CERT_ALT_NAME_INFO an = { 1, &e };
    AS_RESET(); p = NULL;
    CHECK(U(CryptEncodeObjectEx)(ENC, X509_ALTERNATE_NAME, &an, CRYPT_ENCODE_ALLOC_FLAG, &ep, &p, &cb));
    CHECK(p == g_as.last && cb == sizeof v_alt_dns && !memcmp(p, v_alt_dns, cb)); as_free(p);
    FILETIME ft = a_ft(2000, 1, 1, 0, 0, 0);
    AS_RESET(); p = NULL;
    CHECK(U(CryptEncodeObjectEx)(ENC, X509_CHOICE_OF_TIME, &ft, CRYPT_ENCODE_ALLOC_FLAG, &ep, &p, &cb));
    CHECK(p == g_as.last && cb == sizeof v_time_2000 && !memcmp(p, v_time_2000, cb)); as_free(p);
    int en = 5;
    AS_RESET(); p = NULL;
    CHECK(U(CryptEncodeObjectEx)(ENC, X509_ENUMERATED, &en, CRYPT_ENCODE_ALLOC_FLAG, &ep, &p, &cb));
    CHECK(p == g_as.last && cb == sizeof v_enum_5 && !memcmp(p, v_enum_5, cb)); as_free(p);
}
TEST(flags_encode_allocator_not_used_without_alloc_flag) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_INFO ni; CERT_RDN rdn; CERT_RDN_ATTR a; enc_name_cn(&ni, &rdn, &a);
    CRYPT_ENCODE_PARA ep = { sizeof ep, as_alloc, as_free };
    BYTE buf[64]; DWORD cb = sizeof buf; AS_RESET();
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, 0, &ep, buf, &cb);
    CHECK(r); CHECK(g_as.allocs == 0); CHECK(cb == sizeof v_name_cn_test && !memcmp(buf, v_name_cn_test, cb));
}
TEST(flags_encode_zero_length_buffer_protocol) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_INFO ni; CERT_RDN rdn; CERT_RDN_ATTR a; enc_name_cn(&ni, &rdn, &a);
    BYTE buf[64]; DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, 0, NULL, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_MORE_DATA); CHECK(cb == sizeof v_name_cn_test);
    cb = 1; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, 0, NULL, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_MORE_DATA); CHECK(cb == sizeof v_name_cn_test);
    cb = sizeof v_name_cn_test - 1; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, 0, NULL, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_MORE_DATA); CHECK(cb == sizeof v_name_cn_test);
    /* legacy entry point behaves the same */
    cb = 0; SET_ERR(0);
    r = U(CryptEncodeObject)(ENC, X509_NAME, &ni, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_MORE_DATA); CHECK(cb == sizeof v_name_cn_test);
    cb = 0; SET_ERR(0);
    r = U(CryptEncodeObject)(ENC, X509_NAME, &ni, NULL, &cb);
    CHECK(r); CHECK(cb == sizeof v_name_cn_test);
}
TEST(flags_encode_buffer_untouched_on_more_data) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_INFO ni; CERT_RDN rdn; CERT_RDN_ATTR a; enc_name_cn(&ni, &rdn, &a);
    BYTE buf[64]; memset(buf, 0xA5, sizeof buf); DWORD cb = 4; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_NAME, &ni, 0, NULL, buf, &cb);
    CHECK(!r);
    int touched = 0; for (int i = 8; i < 64; i++) if (buf[i] != 0xA5) touched = 1;
    CHECK(!touched);
}

/* ---- decode allocator parameters ----------------------------------------- */
TEST(flags_decode_custom_allocator_across_structures) {
    REQUIRE(U(CryptDecodeObjectEx));
    CRYPT_DECODE_PARA dp = { sizeof dp, as_alloc, as_free };
    void *p; DWORD cb;
    AS_RESET(); p = NULL;
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, v_bc2_ca_pl3, sizeof v_bc2_ca_pl3, CRYPT_DECODE_ALLOC_FLAG, &dp, &p, &cb));
    CHECK(p != NULL && p == g_as.last && ((CERT_BASIC_CONSTRAINTS2_INFO *)p)->dwPathLenConstraint == 3);
    if (p) { CHECK(g_as.lastsz >= cb); as_free(p); }
    AS_RESET(); p = NULL;
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_ALTERNATE_NAME, v_alt_multi, sizeof v_alt_multi, CRYPT_DECODE_ALLOC_FLAG, &dp, &p, &cb));
    CHECK(p != NULL && g_as.allocs >= 1 && p == g_as.last);
    if (p) as_free(p);
    AS_RESET(); p = NULL;
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_CERT_TO_BE_SIGNED, v_tbs_v3_ext, sizeof v_tbs_v3_ext, CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_TO_BE_SIGNED_FLAG, &dp, &p, &cb));
    CHECK(p != NULL && p == g_as.last && ((CERT_INFO *)p)->cExtension == 1);
    if (p) as_free(p);
    AS_RESET(); p = NULL;
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_CHOICE_OF_TIME, v_time_2000, sizeof v_time_2000, CRYPT_DECODE_ALLOC_FLAG, &dp, &p, &cb));
    CHECK(p != NULL && p == g_as.last && cb >= sizeof(FILETIME));
    if (p) as_free(p);
}
TEST(flags_decode_allocator_failure) {
    REQUIRE(U(CryptDecodeObjectEx));
    CRYPT_DECODE_PARA dp = { sizeof dp, as_alloc, as_free };
    void *p = (void *)(ULONG_PTR)1; DWORD cb = 77; AS_RESET(); g_as.fail = 1; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, v_bc2_ca, sizeof v_bc2_ca, CRYPT_DECODE_ALLOC_FLAG, &dp, &p, &cb);
    CHECK(!r); CHECK(p == NULL); CHECK(g_as.allocs >= 1);
    t_note("decode with failing allocator: err 0x%lx cb=%lu", GetLastError(), cb);
}
TEST(flags_decode_default_allocator_is_localalloc) {
    REQUIRE(U(CryptDecodeObjectEx));
    void *p = NULL; DWORD cb = 0;
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, v_bc2_ca, sizeof v_bc2_ca, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb));
    if (p) { CHECK(LocalSize(p) >= cb); CHECK(LocalFree(p) == NULL); }
    CRYPT_DECODE_PARA dp = { sizeof dp, NULL, NULL }; p = NULL;
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, v_bc2_ca, sizeof v_bc2_ca, CRYPT_DECODE_ALLOC_FLAG, &dp, &p, &cb));
    if (p) { CHECK(LocalSize(p) >= cb); LocalFree(p); }
}
TEST(flags_decode_allocator_not_used_without_alloc_flag) {
    REQUIRE(U(CryptDecodeObjectEx));
    CRYPT_DECODE_PARA dp = { sizeof dp, as_alloc, as_free };
    CERT_BASIC_CONSTRAINTS2_INFO bc; DWORD cb = sizeof bc; AS_RESET();
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, v_bc2_ca, sizeof v_bc2_ca, 0, &dp, &bc, &cb));
    CHECK(g_as.allocs == 0); CHECK(bc.fCA);
}
TEST(flags_decode_alloc_failure_clears_pointer) {
    REQUIRE(U(CryptDecodeObjectEx));
    void *p = (void *)(ULONG_PTR)0x1234; DWORD cb = 99; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, v_bc2_inverted, sizeof v_bc2_inverted, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    CHECK(!r); CHECK(p == NULL); EXPECT_ERR(HR_ASN1_CORRUPT);
}
TEST(flags_decode_protocol_exact_and_oversized) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD need = 0; SET_ERR(0);
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, 0, NULL, NULL, &need));
    CHECK(need > sizeof(CERT_NAME_INFO));
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need + 64); DWORD cb = need + 64;
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, 0, NULL, buf, &cb));
    CHECK(cb <= need + 64 && cb >= sizeof(CERT_NAME_INFO));
    CERT_NAME_INFO *ni = (CERT_NAME_INFO *)buf;
    CHECK(ni->cRDN == 2);
    if (ni->cRDN == 2) {
        /* the nested pointers refer into the caller's buffer */
        CHECK(PTR_IN(ni->rgRDN, buf, need) && PTR_IN(ni->rgRDN[0].rgRDNAttr, buf, need) && PTR_IN(ni->rgRDN[0].rgRDNAttr[0].pszObjId, buf, need));
    }
    cb = need; memset(buf, 0, need + 64);
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, 0, NULL, buf, &cb));
    cb = 0; SET_ERR(0);
    CHECK(!U(CryptDecodeObjectEx)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, 0, NULL, buf, &cb));
    EXPECT_ERR(ERROR_MORE_DATA); CHECK(cb == need || cb > 0);
    LocalFree(buf);
}
TEST(flags_decode_legacy_matches_ex) {
    REQUIRE(U(CryptDecodeObject));
    DWORD need = 0, need2 = 0;
    CHECK(U(CryptDecodeObject)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, 0, NULL, &need));
    CHECK(U(CryptDecodeObjectEx)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, 0, NULL, NULL, &need2));
    CHECK(need == need2);
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need);
    CHECK(U(CryptDecodeObject)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, 0, buf, &need));
    CHECK(((CERT_NAME_INFO *)buf)->cRDN == 2);
    DWORD small_ = need / 2; SET_ERR(0);
    CHECK(!U(CryptDecodeObject)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, 0, buf, &small_));
    EXPECT_ERR(ERROR_MORE_DATA);
    LocalFree(buf);
    /* the legacy entry point cannot allocate: it has no way to hand back the pointer; the flag goes through */
    CERT_NAME_INFO *ni = NULL; DWORD cb = 0;
    BOOL r = U(CryptDecodeObject)(ENC, X509_NAME, v_name_c_cn, sizeof v_name_c_cn, CRYPT_DECODE_ALLOC_FLAG, &ni, &cb);
    CHECK(r && ni); if (r && ni) LocalFree(ni);
}

/* ---- OID / encoding type dispatch --------------------------------------- */
TEST(flags_unknown_oid_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    BYTE buf[16]; DWORD cb = 5; SET_ERR(0);
    int dummy = 0;
    BOOL r = U(CryptEncodeObjectEx)(ENC, "1.2.3.4.5.6.7.8.9", &dummy, 0, NULL, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_FILE_NOT_FOUND); CHECK(cb == 0);
    cb = 5; SET_ERR(0);
    r = U(CryptEncodeObject)(ENC, "1.2.3.4.5.6.7.8.9", &dummy, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_FILE_NOT_FOUND); CHECK(cb == 0);
    BYTE *p = (BYTE *)(ULONG_PTR)1; cb = 5; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, "1.2.3.4.5.6.7.8.9", &dummy, CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_FILE_NOT_FOUND); CHECK(p == NULL); CHECK(cb == 0);
    cb = 5; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, (LPCSTR)(ULONG_PTR)1000, &dummy, 0, NULL, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_FILE_NOT_FOUND); CHECK(cb == 0);
}
TEST(flags_unknown_oid_encode_extra_flags_invalidarg) {
    REQUIRE(U(CryptEncodeObjectEx));
    BYTE buf[16]; DWORD cb = 5; int dummy = 0; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, "1.2.3.4.5.6.7.8.9", &dummy, 1, NULL, buf, &cb);
    CHECK(!r); EXPECT_ERR(HR_INVALIDARG); CHECK(cb == 0);
    BYTE *p = (BYTE *)(ULONG_PTR)1; cb = 5; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, "1.2.3.4.5.6.7.8.9", &dummy, CRYPT_ENCODE_ALLOC_FLAG | 4, NULL, &p, &cb);
    CHECK(!r); EXPECT_ERR(HR_INVALIDARG); CHECK(p == NULL); CHECK(cb == 0);
}
TEST(flags_unknown_oid_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    BYTE buf[16]; DWORD cb = 5; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, "1.2.3.4.5.6.7.8.9", v_bc2_ca, sizeof v_bc2_ca, 0, NULL, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_FILE_NOT_FOUND); CHECK(cb == 0);
    cb = 5; SET_ERR(0);
    r = U(CryptDecodeObject)(ENC, "1.2.3.4.5.6.7.8.9", v_bc2_ca, sizeof v_bc2_ca, 0, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_FILE_NOT_FOUND); CHECK(cb == 0);
    void *p = (void *)(ULONG_PTR)1; cb = 5; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, "1.2.3.4.5.6.7.8.9", v_bc2_ca, sizeof v_bc2_ca, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_FILE_NOT_FOUND); CHECK(p == NULL); CHECK(cb == 0);
    cb = 5; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, (LPCSTR)(ULONG_PTR)1000, v_bc2_ca, sizeof v_bc2_ca, 0, NULL, buf, &cb);
    CHECK(!r); EXPECT_ERR(ERROR_FILE_NOT_FOUND); CHECK(cb == 0);
}
TEST(flags_integer_oid_equals_string_oid_where_registered) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_BASIC_CONSTRAINTS2_INFO bc = { TRUE, TRUE, 3 };
    a_alias(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, szOID_BASIC_CONSTRAINTS2, &bc);
    CRYPT_BIT_BLOB kb = { 1, (BYTE[]){ 0x80 }, 7 };
    a_alias(__FILE__, __LINE__, X509_KEY_USAGE, szOID_KEY_USAGE, &kb);
    LPSTR u[] = { (LPSTR)szOID_PKIX_KP_SERVER_AUTH }; CERT_ENHKEY_USAGE eku = { 1, u };
    a_alias(__FILE__, __LINE__, X509_ENHANCED_KEY_USAGE, szOID_ENHANCED_KEY_USAGE, &eku);
    int reason = 1;
    a_alias(__FILE__, __LINE__, X509_CRL_REASON_CODE, szOID_CRL_REASON_CODE, &reason);
    a_alias(__FILE__, __LINE__, X509_ENUMERATED, szOID_CRL_REASON_CODE, &reason);
}
TEST(flags_decode_hash_prefixed_integer_oid) {
    REQUIRE(U(CryptDecodeObjectEx));
    /* the decode dispatcher accepts "#<number>" as an integer structure type */
    DWORD cb = 0; void *p = NULL; SET_ERR(0);
    char oid[16]; wsprintfA(oid, "#%u", (unsigned)(ULONG_PTR)X509_BASIC_CONSTRAINTS2);
    BOOL r = U(CryptDecodeObjectEx)(ENC, oid, v_bc2_ca, sizeof v_bc2_ca, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    t_note("decode with type \"%s\": ok=%d err=0x%lx", oid, r, GetLastError());
    if (r) { CHECK(((CERT_BASIC_CONSTRAINTS2_INFO *)p)->fCA); LocalFree(p); }
    wsprintfA(oid, "#%u", (unsigned)(ULONG_PTR)X509_NAME);
    cb = 0; p = NULL;
    r = U(CryptDecodeObjectEx)(ENC, oid, v_name_cn_test, sizeof v_name_cn_test, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    t_note("decode with type \"%s\": ok=%d err=0x%lx", oid, r, GetLastError());
    if (r) { CHECK(((CERT_NAME_INFO *)p)->cRDN == 1); LocalFree(p); }
}
TEST(flags_encoding_type_variants) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_BASIC_CONSTRAINTS2_INFO bc = { TRUE, FALSE, 0 };
    DWORD cb = 0; BYTE *p = NULL;
    BOOL r = U(CryptEncodeObjectEx)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, &bc, CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    CHECK(r && p && cb == sizeof v_bc2_ca && !memcmp(p, v_bc2_ca, cb));
    if (p) LocalFree(p);
    p = NULL; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(0, X509_BASIC_CONSTRAINTS2, &bc, CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    t_note("encoding type 0: ok=%d err=0x%lx", r, GetLastError());
    CHECK(!r); if (r && p) LocalFree(p);
    p = NULL; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(PKCS_7_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, &bc, CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    t_note("PKCS_7_ASN_ENCODING only: ok=%d err=0x%lx", r, GetLastError());
    if (r && p) { CHECK(cb == sizeof v_bc2_ca); LocalFree(p); }
}
TEST(flags_decode_encoding_type_variants) {
    REQUIRE(U(CryptDecodeObjectEx));
    void *p = NULL; DWORD cb = 0;
    BOOL r = U(CryptDecodeObjectEx)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, v_bc2_ca, sizeof v_bc2_ca, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    CHECK(r && p && ((CERT_BASIC_CONSTRAINTS2_INFO *)p)->fCA);
    if (p) LocalFree(p);
    p = NULL; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(0, X509_BASIC_CONSTRAINTS2, v_bc2_ca, sizeof v_bc2_ca, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    t_note("decode encoding type 0: ok=%d err=0x%lx", r, GetLastError());
    CHECK(!r); CHECK(p == NULL);
    p = NULL; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(PKCS_7_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, v_bc2_ca, sizeof v_bc2_ca, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    t_note("decode PKCS_7_ASN_ENCODING only: ok=%d err=0x%lx", r, GetLastError());
    if (r && p) LocalFree(p);
}
TEST(flags_decode_null_input) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, NULL, 0, 0, NULL, NULL, &cb);
    CHECK(!r);
    t_note("NULL input, length 0: err 0x%lx", GetLastError());
    BYTE zero = 0; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, &zero, 1, 0, NULL, NULL, &cb);
    CHECK(!r);
    t_note("1 byte of input: err 0x%lx", GetLastError());
    BYTE bad_tag[] = { 0x31, 0x00 };
    a_dec_fail(__FILE__, __LINE__, X509_BASIC_CONSTRAINTS2, bad_tag, sizeof bad_tag, 0, HR_ASN1_BADTAG);
}

/* ---- sweeps over many structures ----------------------------------------- */
struct vec { const char *label; LPCSTR oid; const BYTE *der; DWORD n; DWORD flags; };
#define VEC(l, oid, v) { l, oid, v, sizeof(v), 0 }
static const struct vec sweep[] = {
    VEC("name", X509_NAME, v_name_cn_test), VEC("name2", X509_NAME, v_name_c_cn), VEC("uname", X509_UNICODE_NAME, v_name_cn_utf8),
    VEC("namevalue", X509_NAME_VALUE, v_name_value_printable), VEC("alt", X509_ALTERNATE_NAME, v_alt_multi), VEC("altdir", X509_ALTERNATE_NAME, v_alt_dir),
    VEC("bc2", X509_BASIC_CONSTRAINTS2, v_bc2_ca_pl3), VEC("bc", X509_BASIC_CONSTRAINTS, v_bc_ca_pl2_sub), VEC("ku", X509_KEY_USAGE, v_ku_two),
    VEC("eku", X509_ENHANCED_KEY_USAGE, v_eku_two), VEC("aki2", X509_AUTHORITY_KEY_ID2, v_aki2_all), VEC("pol", X509_CERT_POLICIES, v_pol_two_q),
    VEC("pmap", X509_POLICY_MAPPINGS, v_pmap_one), VEC("pcon", X509_POLICY_CONSTRAINTS, v_pcon_req2_inh1), VEC("cdp", X509_CRL_DIST_POINTS, v_cdp_two),
    VEC("aia", X509_AUTHORITY_INFO_ACCESS, v_aia_two), VEC("idp", X509_ISSUING_DIST_POINT, v_idp_url), VEC("nc", X509_NAME_CONSTRAINTS, v_nc_both),
    VEC("enum", X509_ENUMERATED, v_enum_256), VEC("time", X509_CHOICE_OF_TIME, v_time_2000), VEC("timegen", X509_CHOICE_OF_TIME, v_time_2050),
    VEC("ext", X509_EXTENSIONS, v_ext_two), VEC("cert", X509_CERT, v_x509_cert), VEC("ski", X509_OCTET_STRING, v_ski_3), VEC("spki", X509_PUBLIC_KEY_INFO, v_spki_rsa_tiny),
    { "tbs", X509_CERT_TO_BE_SIGNED, v_tbs_v3_uid, sizeof v_tbs_v3_uid, CRYPT_DECODE_TO_BE_SIGNED_FLAG },
    { "crl", X509_CERT_CRL_TO_BE_SIGNED, v_crl_v2_entry_ext, sizeof v_crl_v2_entry_ext, CRYPT_DECODE_TO_BE_SIGNED_FLAG },
};
#define NSWEEP (sizeof sweep / sizeof *sweep)

TEST(sweep_every_truncation_fails) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (unsigned i = 0; i < NSWEEP; i++) {
        const struct vec *v = &sweep[i];
        DWORD cb = 0; SET_ERR(0);
        BOOL ok = U(CryptDecodeObjectEx)(ENC, v->oid, v->der, v->n, v->flags, NULL, NULL, &cb);
        CHECKF(ok, "%s: intact vector failed 0x%lx", v->label, GetLastError());
        for (DWORD cut = 0; cut < v->n; cut++) {
            cb = 0; SET_ERR(0);
            ok = U(CryptDecodeObjectEx)(ENC, v->oid, v->der, cut, v->flags, NULL, NULL, &cb);
            if (ok) { t_check(0, __FILE__, __LINE__, "truncated decode must fail", "%s cut %lu of %lu succeeded", v->label, cut, v->n); continue; }
            DWORD e = GetLastError();
            /* the name-value decoder leaves the last error untouched (0) */
            if (!strcmp(v->label, "namevalue")) t_check(e == 0, __FILE__, __LINE__, "name-value truncation leaves last error 0", "cut %lu err 0x%lx", cut, e);
            else if ((e >> 16) != 0x8009) t_check(0, __FILE__, __LINE__, "truncation error is a CRYPT_E code", "%s cut %lu err 0x%lx", v->label, cut, e);
            else t_check(1, __FILE__, __LINE__, "", NULL);
        }
    }
}
TEST(sweep_truncated_error_is_eod_or_corrupt) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (unsigned i = 0; i < NSWEEP; i++) {
        const struct vec *v = &sweep[i];
        if (v->n < 4) continue;
        DWORD cb = 0; SET_ERR(0);
        BOOL ok = U(CryptDecodeObjectEx)(ENC, v->oid, v->der, v->n - 1, v->flags, NULL, NULL, &cb);
        DWORD e = GetLastError();
        if (!strcmp(v->label, "namevalue")) { CHECKF(!ok && e == 0, "namevalue: ok=%d err=0x%lx", ok, e); continue; }
        CHECKF(!ok && (e == HR_ASN1_EOD || e == HR_ASN1_CORRUPT), "%s: ok=%d err=0x%lx", v->label, ok, e);
    }
}
TEST(sweep_decode_all_with_alloc_and_nocopy) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (unsigned i = 0; i < NSWEEP; i++) {
        const struct vec *v = &sweep[i];
        DWORD c1 = 0, c2 = 0; void *a = NULL, *n = NULL;
        BOOL r1 = U(CryptDecodeObjectEx)(ENC, v->oid, v->der, v->n, v->flags | CRYPT_DECODE_ALLOC_FLAG, NULL, &a, &c1);
        BOOL r2 = U(CryptDecodeObjectEx)(ENC, v->oid, v->der, v->n, v->flags | CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL, &n, &c2);
        CHECKF(r1 && r2, "%s: %d %d", v->label, r1, r2);
        if (r1 && r2) CHECKF(c2 <= c1, "%s: nocopy size %lu > copy size %lu", v->label, c2, c1);
        if (a) LocalFree(a);
        if (n) LocalFree(n);
    }
}
TEST(sweep_decode_into_user_buffer_matches_alloc) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (unsigned i = 0; i < NSWEEP; i++) {
        const struct vec *v = &sweep[i];
        DWORD need = 0;
        BOOL ok = U(CryptDecodeObjectEx)(ENC, v->oid, v->der, v->n, v->flags, NULL, NULL, &need);
        CHECKF(ok && need > 0, "%s", v->label);
        if (!ok) continue;
        BYTE *buf = (BYTE *)LocalAlloc(LPTR, need);
        DWORD cb = need;
        ok = U(CryptDecodeObjectEx)(ENC, v->oid, v->der, v->n, v->flags, NULL, buf, &cb);
        CHECKF(ok && cb <= need, "%s: cb %lu need %lu", v->label, cb, need);
        LocalFree(buf);
    }
}
TEST(sweep_trailing_bytes_accepted_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    unsigned accepted = 0;
    for (unsigned i = 0; i < NSWEEP; i++) {
        const struct vec *v = &sweep[i];
        BYTE *buf = (BYTE *)LocalAlloc(LPTR, v->n + 3);
        memcpy(buf, v->der, v->n); buf[v->n] = 0xAA; buf[v->n + 1] = 0xBB; buf[v->n + 2] = 0xCC;
        DWORD cb = 0; SET_ERR(0);
        BOOL ok = U(CryptDecodeObjectEx)(ENC, v->oid, buf, v->n + 3, v->flags, NULL, NULL, &cb);
        if (ok) accepted++; else t_note("%s: trailing bytes rejected err 0x%lx", v->label, GetLastError());
        LocalFree(buf);
    }
    t_note("%u of %u structures accept trailing bytes", accepted, (unsigned)NSWEEP);
}
TEST(sweep_encode_buffer_protocol_all_vectors) {
    REQUIRE(U(CryptDecodeObjectEx));
    /* decode -> encode again with every buffer size from 0 to n+1: only n and n+1 succeed */
    for (unsigned i = 0; i < NSWEEP; i++) {
        const struct vec *v = &sweep[i];
        if (v->flags & CRYPT_DECODE_TO_BE_SIGNED_FLAG) continue;
        if (v->oid == X509_CERT) continue;
        void *st = NULL; DWORD sc = 0;
        if (!U(CryptDecodeObjectEx)(ENC, v->oid, v->der, v->n, CRYPT_DECODE_ALLOC_FLAG, NULL, &st, &sc)) continue;
        DWORD n = 0;
        if (!U(CryptEncodeObjectEx)(ENC, v->oid, st, 0, NULL, NULL, &n)) { t_note("%s: re-encode unsupported 0x%lx", v->label, GetLastError()); LocalFree(st); continue; }
        BYTE *buf = (BYTE *)LocalAlloc(LPTR, n + 2);
        for (DWORD sz = 0; sz < n; sz++) {
            DWORD cb = sz; SET_ERR(0);
            BOOL ok = U(CryptEncodeObjectEx)(ENC, v->oid, st, 0, NULL, buf, &cb);
            if (ok || GetLastError() != ERROR_MORE_DATA || cb != n) t_check(0, __FILE__, __LINE__, "short buffer => ERROR_MORE_DATA with required size", "%s size %lu/%lu ok=%d err=0x%lx cb=%lu", v->label, sz, n, ok, GetLastError(), cb);
            else t_check(1, __FILE__, __LINE__, "", NULL);
        }
        DWORD cb = n; CHECKF(U(CryptEncodeObjectEx)(ENC, v->oid, st, 0, NULL, buf, &cb) && cb == n, "%s exact", v->label);
        LocalFree(buf); LocalFree(st);
    }
}

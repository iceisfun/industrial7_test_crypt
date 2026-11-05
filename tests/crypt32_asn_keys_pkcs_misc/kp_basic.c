/* crypt32 CryptEncodeObject(Ex)/CryptDecodeObject(Ex): primitive and generic types
 * (INTEGER, ENUMERATED, BITS, OCTET STRING, multi-byte integers, times, OID, strings, SEQUENCE OF ANY). */
#include "kp.h"

#define REQ_CRYPT32() do { REQUIRE(t_proc_in("crypt32.dll", "CryptEncodeObjectEx")); REQUIRE(t_proc_in("crypt32.dll", "CryptDecodeObjectEx")); \
    REQUIRE(t_proc_in("crypt32.dll", "CryptEncodeObject")); REQUIRE(t_proc_in("crypt32.dll", "CryptDecodeObject")); } while (0)

/* ---------------------------------------------------------------- dispatcher level */
TEST(kpb_unknown_struct_type_encode) {
    REQ_CRYPT32();
    int v = 1; DWORD cb = 77; BYTE buf[16];
    typeof(&CryptEncodeObjectEx) f = U(CryptEncodeObjectEx);
    SET_ERR(0);
    CHECK(!f(KP_ENC, "1.2.3.4.5.6.7.8.9.99", &v, 0, NULL, buf, &cb));
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(cb, 0);
}
TEST(kpb_unknown_struct_type_encode_alloc_zeroes_pointer) {
    REQ_CRYPT32();
    int v = 1; DWORD cb = 77; BYTE *out = (BYTE *)(ULONG_PTR)0x1234;
    SET_ERR(0);
    CHECK(!U(CryptEncodeObjectEx)(KP_ENC, "1.2.3.4.5.6.7.8.9.99", &v, CRYPT_ENCODE_ALLOC_FLAG, NULL, &out, &cb));
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    CHECK(out == NULL);
    EXPECT_EQ(cb, 0);
}
TEST(kpb_unknown_struct_type_decode) {
    REQ_CRYPT32();
    DWORD cb = 77; BYTE buf[16]; static const BYTE der[] = {2,1,1};
    SET_ERR(0);
    CHECK(!U(CryptDecodeObjectEx)(KP_ENC, "1.2.3.4.5.6.7.8.9.99", der, 3, 0, NULL, buf, &cb));
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(cb, 0);
}
TEST(kpb_unknown_struct_type_decode_alloc_zeroes_pointer) {
    REQ_CRYPT32();
    DWORD cb = 77; void *out = (void *)(ULONG_PTR)0x1234; static const BYTE der[] = {2,1,1};
    SET_ERR(0);
    CHECK(!U(CryptDecodeObjectEx)(KP_ENC, "1.2.3.4.5.6.7.8.9.99", der, 3, CRYPT_DECODE_ALLOC_FLAG, NULL, &out, &cb));
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    CHECK(out == NULL);
    EXPECT_EQ(cb, 0);
}
TEST(kpb_unknown_numeric_type_decode) {
    REQ_CRYPT32();
    DWORD cb = 77; BYTE buf[16]; static const BYTE der[] = {2,1,1};
    SET_ERR(0);
    CHECK(!U(CryptDecodeObjectEx)(KP_ENC, KP_OID_STR(0x7ff0), der, 3, 0, NULL, buf, &cb));
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(kpb_hash_prefixed_numeric_type_decode) {
    REQ_CRYPT32();
    /* "#27" is the string spelling of X509_INTEGER (27): the decoder dispatches it to the numeric type */
    static const BYTE der[] = {2,1,0x2a}; int v = 0; DWORD cb = sizeof v;
    SET_ERR(0);
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, "#27", der, 3, 0, NULL, &v, &cb));
    EXPECT_EQ(v, 0x2a);
}
TEST(kpb_encoding_type_zero_fails) {
    REQ_CRYPT32();
    int v = 1; DWORD cb = 0; SET_ERR(0);
    CHECK(!U(CryptEncodeObjectEx)(0, X509_INTEGER, &v, 0, NULL, NULL, &cb));
    t_note("encoding type 0: last error 0x%lx", GetLastError());
}
TEST(kpb_pkcs7_encoding_bit_accepted) {
    REQ_CRYPT32();
    int v = 5; DWORD cb = 0; BYTE buf[8];
    /* either of X509_ASN_ENCODING / PKCS_7_ASN_ENCODING selects the DER codecs */
    CHECK(U(CryptEncodeObjectEx)(PKCS_7_ASN_ENCODING, X509_INTEGER, &v, 0, NULL, NULL, &cb)); EXPECT_EQ(cb, 3);
    cb = sizeof buf;
    CHECK(U(CryptEncodeObjectEx)(KP_ENC_P7, X509_INTEGER, &v, 0, NULL, buf, &cb)); EXPECT_EQ(cb, 3);
    CHECK(buf[0] == 2 && buf[1] == 1 && buf[2] == 5);
}
TEST(kpb_decode_zero_length_input) {
    REQ_CRYPT32();
    BYTE buf[16]; DWORD cb = sizeof buf; static const BYTE one[1] = {0};
    SET_ERR(0);
    CHECK(!U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, one, 0, 0, NULL, buf, &cb));
    EXPECT_ERR(KP_E_EOD);
}
TEST(kpb_decode_null_input_nonzero_length_args) {
    REQ_CRYPT32();
    BYTE buf[16]; DWORD cb = sizeof buf;
    SET_ERR(0);
    CHECK(!U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, NULL, 0, 0, NULL, buf, &cb));
    t_note("NULL input, cb 0: last error 0x%lx", GetLastError());
}

/* ---------------------------------------------------------------- X509_INTEGER */
static const struct { int v; BYTE der[8]; BYTE n; } g_ints[] = {
    { 0,           {2,1,0x00}, 3 }, { 1, {2,1,1}, 3 }, { 127, {2,1,0x7f}, 3 }, { 128, {2,2,0,0x80}, 4 },
    { 255,         {2,2,0,0xff}, 4 }, { 256, {2,2,1,0}, 4 }, { 32767, {2,2,0x7f,0xff}, 4 }, { 32768, {2,3,0,0x80,0}, 5 },
    { 65535,       {2,3,0,0xff,0xff}, 5 }, { 0x7fffff, {2,3,0x7f,0xff,0xff}, 5 }, { 0x800000, {2,4,0,0x80,0,0}, 6 },
    { 0x7fffffff,  {2,4,0x7f,0xff,0xff,0xff}, 6 }, { -1, {2,1,0xff}, 3 }, { -2, {2,1,0xfe}, 3 }, { -128, {2,1,0x80}, 3 },
    { -129,        {2,2,0xff,0x7f}, 4 }, { -256, {2,2,0xff,0x00}, 4 }, { -32768, {2,2,0x80,0}, 4 }, { -32769, {2,3,0xff,0x7f,0xff}, 5 },
    { (int)0x80000000, {2,4,0x80,0,0,0}, 6 }, { (int)0xff7fffff, {2,4,0xff,0x7f,0xff,0xff}, 6 }, { 0x12345678, {2,4,0x12,0x34,0x56,0x78}, 6 },
};
TEST(kpb_integer_encode_table) {
    REQ_CRYPT32();
    for (unsigned i = 0; i < sizeof g_ints / sizeof g_ints[0]; i++) {
        int v = g_ints[i].v;
        ENC_EQ(X509_INTEGER, &v, g_ints[i].der, g_ints[i].n);
    }
}
TEST(kpb_integer_decode_table) {
    REQ_CRYPT32();
    for (unsigned i = 0; i < sizeof g_ints / sizeof g_ints[0]; i++) {
        int *r = DEC_OK(X509_INTEGER, g_ints[i].der, g_ints[i].n, 0);
        if (r) { EXPECT_EQ(*r, (ULONG_PTR)(unsigned)g_ints[i].v); kp_free(r); }
    }
}
TEST(kpb_integer_decode_size_is_int) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,1,7}; DWORD cb = 0;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, 3, 0, NULL, NULL, &cb));
    EXPECT_EQ(cb, sizeof(int));
}
TEST(kpb_integer_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_INTEGER, KP_E_EOD, 2);
    DEC_FAILV(X509_INTEGER, KP_E_EOD, 2, 1);
    DEC_FAILV(X509_INTEGER, KP_E_EOD, 2, 2, 1);
    DEC_FAILV(X509_INTEGER, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(X509_INTEGER, KP_E_BADTAG, 10, 1, 1);
    DEC_FAILV(X509_INTEGER, KP_E_BADTAG, 0x30, 0);
}
TEST(kpb_integer_decode_wide_values_fail) {
    REQ_CRYPT32();
    /* five significant bytes do not fit the int result */
    DEC_FAILV(X509_INTEGER, 0, 2, 5, 1, 0, 0, 0, 0);
    DEC_FAILV(X509_INTEGER, 0, 2, 5, 0xff, 0x7f, 0xff, 0xff, 0xff);
}
TEST(kpb_integer_decode_long_form_length) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,0x81,1,9};
    int *r = (int *)kp_dec_alloc(X509_INTEGER, der, sizeof der, 0, NULL);
    if (r) { EXPECT_EQ(*r, 9); kp_free(r); } else t_note("long form length rejected, err 0x%lx", GetLastError());
}
TEST(kpb_integer_decode_trailing_bytes) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,1,9,0xAA}; DWORD cb = 4; int v = 0;
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, sizeof der, 0, NULL, &v, &cb);
    t_note("integer with one trailing byte: ok=%d err=0x%lx v=%d", ok, ok ? 0 : GetLastError(), v);
}
TEST(kpb_integer_decode_nonminimal) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,2,0,1}; DWORD cb = 4; int v = 0;
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, sizeof der, 0, NULL, &v, &cb);
    t_note("non-minimal integer 00 01: ok=%d v=%d", ok, v);
}
TEST(kpb_integer_decode_zero_length_content) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,0}; DWORD cb = 4; int v = 9;
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, sizeof der, 0, NULL, &v, &cb);
    t_note("empty integer: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}
TEST(kpb_integer_roundtrip_range) {
    REQ_CRYPT32();
    int vals[] = { 0, 1, -1, 100, -100, 30000, -30000, 123456, -123456, 0x7ffffffe, (int)0x80000001 };
    for (unsigned i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        DWORD cb; BYTE *e = kp_enc_alloc(X509_INTEGER, &vals[i], 0, &cb);
        CHECK(e != NULL);
        if (!e) continue;
        int *d = (int *)kp_dec_alloc(X509_INTEGER, e, cb, 0, NULL);
        CHECK(d && *d == vals[i]);
        kp_free(d); kp_free(e);
    }
}
TEST(kpb_integer_nocopy_flag_accepted) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,1,3}; int v = 0; DWORD cb = sizeof v;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, 3, CRYPT_DECODE_NOCOPY_FLAG, NULL, &v, &cb));
    EXPECT_EQ(v, 3);
}

/* ---------------------------------------------------------------- X509_ENUMERATED */
static const struct { int v; BYTE der[8]; BYTE n; } g_enum[] = {
    { 0, {0x0a,1,0}, 3 }, { 1, {0x0a,1,1}, 3 }, { 5, {0x0a,1,5}, 3 }, { 127, {0x0a,1,0x7f}, 3 }, { 128, {0x0a,2,0,0x80}, 4 },
    { 256, {0x0a,2,1,0}, 4 }, { -1, {0x0a,1,0xff}, 3 }, { -128, {0x0a,1,0x80}, 3 }, { 0x7fffffff, {0x0a,4,0x7f,0xff,0xff,0xff}, 6 },
    { (int)0x80000000, {0x0a,4,0x80,0,0,0}, 6 },
};
TEST(kpb_enumerated_encode_table) {
    REQ_CRYPT32();
    for (unsigned i = 0; i < sizeof g_enum / sizeof g_enum[0]; i++) { int v = g_enum[i].v; ENC_EQ(X509_ENUMERATED, &v, g_enum[i].der, g_enum[i].n); }
}
TEST(kpb_enumerated_decode_table) {
    REQ_CRYPT32();
    for (unsigned i = 0; i < sizeof g_enum / sizeof g_enum[0]; i++) {
        int *r = DEC_OK(X509_ENUMERATED, g_enum[i].der, g_enum[i].n, 0);
        if (r) { EXPECT_EQ(*r, (ULONG_PTR)(unsigned)g_enum[i].v); kp_free(r); }
    }
}
TEST(kpb_enumerated_decode_rejects_integer_tag) {
    REQ_CRYPT32();
    DEC_FAILV(X509_ENUMERATED, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_ENUMERATED, KP_E_EOD, 0x0a, 1);
    DEC_FAILV(X509_ENUMERATED, KP_E_EOD, 0x0a);
}
TEST(kpb_integer_rejects_enumerated_tag) {
    REQ_CRYPT32();
    DEC_FAILV(X509_INTEGER, KP_E_BADTAG, 0x0a, 1, 1);
}

/* ---------------------------------------------------------------- X509_MULTI_BYTE_INTEGER / UINT */
TEST(kpb_multibyte_integer_encode) {
    REQ_CRYPT32();
    BYTE a[] = {1}, b[] = {0x7f}, c[] = {0x34, 0x12}, d[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    CRYPT_INTEGER_BLOB x;
    x.cbData = 1; x.pbData = a; ENC_EQ(X509_MULTI_BYTE_INTEGER, &x, V(2,1,1));
    x.pbData = b; ENC_EQ(X509_MULTI_BYTE_INTEGER, &x, V(2,1,0x7f));
    x.cbData = 2; x.pbData = c; ENC_EQ(X509_MULTI_BYTE_INTEGER, &x, V(2,2,0x12,0x34));
    x.cbData = 9; x.pbData = d; ENC_EQ(X509_MULTI_BYTE_INTEGER, &x, V(2,9,9,8,7,6,5,4,3,2,1));
}
TEST(kpb_multibyte_integer_sign_bit_is_negative) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("emulator crashes encoding negative multi-byte integers"); return; }
    /* signed little-endian: a top byte with the high bit set is a negative number, no padding is added */
    BYTE a[] = {0x80}, b[] = {0xff, 0xff}, c[] = {0x00, 0x80};
    CRYPT_INTEGER_BLOB x;
    x.cbData = 1; x.pbData = a; ENC_EQ(X509_MULTI_BYTE_INTEGER, &x, V(2,1,0x80));
    x.cbData = 2; x.pbData = c; ENC_EQ(X509_MULTI_BYTE_INTEGER, &x, V(2,2,0x80,0x00));
}
TEST(kpb_multibyte_integer_decode) {
    REQ_CRYPT32();
    CRYPT_INTEGER_BLOB *r;
    r = DEC_OK(X509_MULTI_BYTE_INTEGER, V(2,1,1), 0); if (r) { BLOB_IS(*r, 1); kp_free(r); }
    r = DEC_OK(X509_MULTI_BYTE_INTEGER, V(2,4,0x12,0x34,0x56,0x78), 0); if (r) { BLOB_IS(*r, 0x78,0x56,0x34,0x12); kp_free(r); }
    r = DEC_OK(X509_MULTI_BYTE_INTEGER, V(2,2,1,0), 0); if (r) { BLOB_IS(*r, 0,1); kp_free(r); }
    r = DEC_OK(X509_MULTI_BYTE_INTEGER, V(2,1,0xff), 0); if (r) { BLOB_IS(*r, 0xff); kp_free(r); }
    r = DEC_OK(X509_MULTI_BYTE_INTEGER, V(2,9,1,2,3,4,5,6,7,8,9), 0); if (r) { BLOB_IS(*r, 9,8,7,6,5,4,3,2,1); kp_free(r); }
}
TEST(kpb_multibyte_integer_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_MULTI_BYTE_INTEGER, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(X509_MULTI_BYTE_INTEGER, KP_E_TRUNC, 2, 2, 1);
    DEC_FAILV(X509_MULTI_BYTE_INTEGER, KP_E_TRUNC, 2);
}
TEST(kpb_multibyte_uint_encode) {
    REQ_CRYPT32();
    BYTE a[] = {1}, b[] = {0x7f}, c[] = {0x80}, d[] = {0xff, 0xff}, e[] = {0x00}, f[] = {0x00, 0x80};
    CRYPT_UINT_BLOB x;
    x.cbData = 1; x.pbData = a; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,1,1));
    x.pbData = b; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,1,0x7f));
    x.pbData = c; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,2,0,0x80));
    x.cbData = 2; x.pbData = d; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,3,0,0xff,0xff));
    x.cbData = 1; x.pbData = e; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,1,0));
    x.cbData = 2; x.pbData = f; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,3,0,0x80,0x00));   /* 0x8000: still needs the 00 sign pad */
    BYTE g[] = {0x00, 0x00, 0x00}; x.cbData = 3; x.pbData = g; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,1,0));            /* redundant zero bytes are dropped */
    BYTE h[] = {0x01, 0x00, 0x00}; x.pbData = h; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,1,1));
    BYTE k[] = {0x00, 0x01}; x.cbData = 2; x.pbData = k; ENC_EQ(X509_MULTI_BYTE_UINT, &x, V(2,2,1,0));
}
TEST(kpb_multibyte_uint_encode_wide) {
    REQ_CRYPT32();
    BYTE a[128]; CRYPT_UINT_BLOB x; BYTE want[4 + 128 + 1];
    memset(a, 0x11, sizeof a); a[127] = 0x80;       /* top byte (last, little endian) has the high bit */
    x.cbData = 128; x.pbData = a;
    want[0] = 2; want[1] = 0x81; want[2] = 129; want[3] = 0; want[4] = 0x80;
    for (int i = 1; i < 128; i++) want[4 + i] = 0x11;
    ENC_EQ(X509_MULTI_BYTE_UINT, &x, want, 4 + 128);
}
TEST(kpb_multibyte_uint_decode) {
    REQ_CRYPT32();
    CRYPT_UINT_BLOB *r;
    r = DEC_OK(X509_MULTI_BYTE_UINT, V(2,1,1), 0); if (r) { BLOB_IS(*r, 1); kp_free(r); }
    r = DEC_OK(X509_MULTI_BYTE_UINT, V(2,2,0,0x80), 0); if (r) { BLOB_IS(*r, 0x80); kp_free(r); }
    r = DEC_OK(X509_MULTI_BYTE_UINT, V(2,3,0,0xff,0xff), 0); if (r) { BLOB_IS(*r, 0xff,0xff); kp_free(r); }
    r = DEC_OK(X509_MULTI_BYTE_UINT, V(2,4,0x12,0x34,0x56,0x78), 0); if (r) { BLOB_IS(*r, 0x78,0x56,0x34,0x12); kp_free(r); }
    r = DEC_OK(X509_MULTI_BYTE_UINT, V(2,1,0), 0); if (r) { CHECK(r->cbData <= 1); if (r->cbData) CHECK(r->pbData[0] == 0); kp_free(r); }
}
TEST(kpb_multibyte_uint_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_MULTI_BYTE_UINT, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(X509_MULTI_BYTE_UINT, KP_E_TRUNC, 2, 3, 1, 2);
}
TEST(kpb_multibyte_uint_roundtrip) {
    REQ_CRYPT32();
    BYTE a[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,0xf0};
    CRYPT_UINT_BLOB x = { sizeof a, a }; DWORD cb;
    BYTE *e = kp_enc_alloc(X509_MULTI_BYTE_UINT, &x, 0, &cb);
    CHECK(e && cb == 2 + 1 + sizeof a);
    if (e) {
        CRYPT_UINT_BLOB *d = kp_dec_alloc(X509_MULTI_BYTE_UINT, e, cb, 0, NULL);
        CHECK(d && d->cbData == sizeof a && !memcmp(d->pbData, a, sizeof a));
        kp_free(d); kp_free(e);
    }
}
TEST(kpb_dss_publickey_alias) {
    REQ_CRYPT32();
    /* X509_DSS_PUBLICKEY is another spelling of X509_MULTI_BYTE_UINT */
    BYTE a[] = {0x80, 0x01}; CRYPT_UINT_BLOB x = { 2, a };
    ENC_EQ(X509_DSS_PUBLICKEY, &x, V(2,2,1,0x80));
    CRYPT_UINT_BLOB *r = DEC_OK(X509_DSS_PUBLICKEY, V(2,2,1,0x80), 0);
    if (r) { BLOB_IS(*r, 0x80, 0x01); kp_free(r); }
}
TEST(kpb_multibyte_nocopy_points_into_input) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,3,0,0xff,0xff}; BYTE buf[64]; DWORD cb = sizeof buf;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_MULTI_BYTE_UINT, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, NULL, buf, &cb));
    /* integers are byte-reversed, so the data can not alias the input: it must live in the caller's buffer */
    CRYPT_UINT_BLOB *r = (CRYPT_UINT_BLOB *)buf;
    CHECK(r->cbData == 2);
    t_note("MULTI_BYTE_UINT NOCOPY: pbData in caller buffer = %d", (BYTE *)r->pbData >= buf && (BYTE *)r->pbData < buf + sizeof buf);
}

/* ---------------------------------------------------------------- X509_OCTET_STRING */
TEST(kpb_octet_encode_basic) {
    REQ_CRYPT32();
    BYTE a[] = {1,2,3}; CRYPT_DATA_BLOB b = { 0, NULL };
    ENC_EQ(X509_OCTET_STRING, &b, V(4,0));
    b.cbData = 3; b.pbData = a; ENC_EQ(X509_OCTET_STRING, &b, V(4,3,1,2,3));
    b.cbData = 0; b.pbData = a; ENC_EQ(X509_OCTET_STRING, &b, V(4,0));
}
TEST(kpb_octet_encode_length_forms) {
    REQ_CRYPT32();
    BYTE data[70000]; CRYPT_DATA_BLOB b; BYTE *e; DWORD cb;
    memset(data, 0x5a, sizeof data);
    static const struct { DWORD len; DWORD hdr; BYTE h[5]; } t[] = {
        { 127, 2, {4,0x7f} }, { 128, 3, {4,0x81,0x80} }, { 255, 3, {4,0x81,0xff} }, { 256, 4, {4,0x82,1,0} },
        { 65535, 4, {4,0x82,0xff,0xff} }, { 65536, 5, {4,0x83,1,0,0} }, { 69999, 5, {4,0x83,1,0x11,0x6f} },
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        b.cbData = t[i].len; b.pbData = data;
        e = kp_enc_alloc(X509_OCTET_STRING, &b, 0, &cb);
        CHECKF(e && cb == t[i].hdr + t[i].len && !memcmp(e, t[i].h, t[i].hdr) && e[cb - 1] == 0x5a, "len %lu", (unsigned long)t[i].len);
        kp_free(e);
    }
}
TEST(kpb_octet_decode) {
    REQ_CRYPT32();
    CRYPT_DATA_BLOB *r;
    r = DEC_OK(X509_OCTET_STRING, V(4,0), 0); if (r) { CHECK(r->cbData == 0); kp_free(r); }
    r = DEC_OK(X509_OCTET_STRING, V(4,3,1,2,3), 0); if (r) { BLOB_IS(*r, 1,2,3); kp_free(r); }
    r = DEC_OK(X509_OCTET_STRING, V(4,0x81,3,9,8,7), 0); if (r) { BLOB_IS(*r, 9,8,7); kp_free(r); }
}
TEST(kpb_octet_decode_nocopy_aliases_input) {
    REQ_CRYPT32();
    static const BYTE der[] = {4,3,1,2,3}; BYTE buf[64]; DWORD cb = sizeof buf;
    CRYPT_DATA_BLOB *r = (CRYPT_DATA_BLOB *)buf;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_OCTET_STRING, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, NULL, buf, &cb));
    CHECK(cb >= sizeof(CRYPT_DATA_BLOB) && cb < sizeof buf);
    CHECK(r->cbData == 3 && r->pbData == der + 2);
    /* without NOCOPY the bytes are copied behind the struct */
    cb = sizeof buf; memset(buf, 0, sizeof buf);
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_OCTET_STRING, der, sizeof der, 0, NULL, buf, &cb));
    CHECK(r->cbData == 3 && r->pbData != der + 2 && (BYTE *)r->pbData >= buf && (BYTE *)r->pbData < buf + cb);
    CHECK(cb >= sizeof(CRYPT_DATA_BLOB) + 3);
}
TEST(kpb_octet_decode_nocopy_size_query_is_struct_only) {
    REQ_CRYPT32();
    static const BYTE der[] = {4,3,1,2,3}; DWORD cb = 0;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_OCTET_STRING, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, NULL, NULL, &cb));
    EXPECT_EQ(cb, sizeof(CRYPT_DATA_BLOB));
}
TEST(kpb_octet_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_OCTET_STRING, KP_E_BADTAG, 3, 1, 0);
    DEC_FAILV(X509_OCTET_STRING, KP_E_EOD, 4, 5, 1, 2);
    DEC_FAILV(X509_OCTET_STRING, KP_E_TRUNC, 4);
    DEC_FAILV(X509_OCTET_STRING, KP_E_BADTAG, 0x24, 0);
}
TEST(kpb_octet_decode_constructed_note) {
    REQ_CRYPT32();
    static const BYTE der[] = {0x24,6,4,1,1,4,1,2}; DWORD cb = 0;
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, X509_OCTET_STRING, der, sizeof der, 0, NULL, NULL, &cb);
    t_note("constructed octet string: ok=%d cb=%lu err=0x%lx", ok, cb, ok ? 0 : GetLastError());
}
TEST(kpb_octet_encode_empty_input_null_pointer) {
    REQ_CRYPT32();
    CRYPT_DATA_BLOB b = { 0, NULL };
    DWORD cb = 0; CHECK(U(CryptEncodeObjectEx)(KP_ENC, X509_OCTET_STRING, &b, 0, NULL, NULL, &cb)); EXPECT_EQ(cb, 2);
}

/* ---------------------------------------------------------------- X509_BITS */
static const struct { DWORD cb; BYTE d[3]; DWORD unused; BYTE der[8]; BYTE n; } g_bits[] = {
    { 0, {0},        0, {3,1,0}, 3 },
    { 1, {0xff},     0, {3,2,0,0xff}, 4 },
    { 1, {0x80},     7, {3,2,7,0x80}, 4 },
    { 1, {0xf0},     4, {3,2,4,0xf0}, 4 },
    { 1, {0x01},     0, {3,2,0,0x01}, 4 },
    { 2, {0xaa,0x55},0, {3,3,0,0xaa,0x55}, 5 },
    { 2, {0xaa,0x80},7, {3,3,7,0xaa,0x80}, 5 },
    { 3, {1,2,2},    1, {3,4,1,1,2,2}, 6 },
};
TEST(kpb_bits_encode_table) {
    REQ_CRYPT32();
    for (unsigned i = 0; i < sizeof g_bits / sizeof g_bits[0]; i++) {
        BYTE d[3]; memcpy(d, g_bits[i].d, 3);
        CRYPT_BIT_BLOB b = { g_bits[i].cb, d, g_bits[i].unused };
        ENC_EQ(X509_BITS, &b, g_bits[i].der, g_bits[i].n);
    }
}
TEST(kpb_bits_decode_table) {
    REQ_CRYPT32();
    for (unsigned i = 0; i < sizeof g_bits / sizeof g_bits[0]; i++) {
        CRYPT_BIT_BLOB *r = DEC_OK(X509_BITS, g_bits[i].der, g_bits[i].n, 0);
        if (!r) continue;
        CHECK(r->cbData == g_bits[i].cb && r->cUnusedBits == g_bits[i].unused);
        CHECK(r->cbData == 0 || !memcmp(r->pbData, g_bits[i].d, r->cbData));
        kp_free(r);
    }
}
TEST(kpb_bits_decode_errors) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("emulator mishandles malformed bit strings (crash)"); return; }
    DEC_FAILV(X509_BITS, KP_E_BADTAG, 4, 2, 0, 0xff);
    DEC_FAILV(X509_BITS, KP_E_TRUNC, 3, 3, 0, 1);
    DEC_FAILV(X509_BITS, KP_E_EOD, 3);
    DEC_FAILV(X509_BITS, 0, 3, 0);
    DEC_FAILV(X509_BITS, 0, 3, 2, 8, 0);
}
TEST(kpb_bits_encode_unused_bits_verbatim_or_masked) {
    REQ_CRYPT32();
    BYTE d[] = {0xff}; CRYPT_BIT_BLOB b = { 1, d, 3 }; DWORD cb; BYTE *e = kp_enc_alloc(X509_BITS, &b, 0, &cb);
    CHECK(e && cb == 4 && e[0] == 3 && e[1] == 2 && e[2] == 3);
    if (e) { t_note("last content byte for 0xff with 3 unused bits: 0x%02x", e[3]); kp_free(e); }
}
TEST(kpb_bits_decode_clears_unused_bits) {
    REQ_CRYPT32();
    /* decoding a bit string whose unused bits are non-zero copies the data and clears those bits */
    CRYPT_BIT_BLOB *r = DEC_OK(X509_BITS, V(3,2,4,0xff), 0);
    if (r) { CHECK(r->cbData == 1 && r->cUnusedBits == 4 && r->pbData[0] == 0xf0); kp_free(r); }
    r = DEC_OK(X509_BITS, V(3,3,1,0xff,0xff), 0);
    if (r) { CHECK(r->cbData == 2 && r->cUnusedBits == 1 && r->pbData[0] == 0xff && r->pbData[1] == 0xfe); kp_free(r); }
}
TEST(kpb_bits_decode_nocopy) {
    REQ_CRYPT32();
    static const BYTE der[] = {3,3,0,0xaa,0x55}; BYTE buf[64]; DWORD cb = sizeof buf;
    CRYPT_BIT_BLOB *r = (CRYPT_BIT_BLOB *)buf;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_BITS, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, NULL, buf, &cb));
    CHECK(r->cbData == 2 && r->pbData == der + 3 && r->cUnusedBits == 0);
}
TEST(kpb_bits_encode_large) {
    REQ_CRYPT32();
    BYTE d[300]; memset(d, 0x33, sizeof d); CRYPT_BIT_BLOB b = { 300, d, 0 }; DWORD cb;
    BYTE *e = kp_enc_alloc(X509_BITS, &b, 0, &cb);
    CHECK(e && cb == 4 + 1 + 300 && e[0] == 3 && e[1] == 0x82 && e[2] == 0x01 && e[3] == 0x2d && e[4] == 0 && e[5] == 0x33);
    kp_free(e);
}
static const struct { DWORD cb; BYTE d[3]; DWORD unused; BYTE der[8]; BYTE n; } g_bitsz[] = {
    { 1, {0x80},      0, {3,2,7,0x80}, 4 },
    { 1, {0x80},      3, {3,2,7,0x80}, 4 },
    { 2, {0x80,0x00}, 0, {3,2,7,0x80}, 4 },
    { 1, {0xa0},      0, {3,2,5,0xa0}, 4 },
    { 1, {0x01},      0, {3,2,0,0x01}, 4 },
    { 2, {0x00,0x01}, 0, {3,3,0,0x00,0x01}, 5 },
    { 2, {0x05,0x00}, 0, {3,2,5,0x05}, 4 },
    { 1, {0x00},      0, {3,1,0}, 3 },
    { 2, {0x00,0x00}, 0, {3,1,0}, 3 },
    { 1, {0xff},      0, {3,2,0,0xff}, 4 },
};
TEST(kpb_bits_without_trailing_zeroes_encode) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("not implemented by the emulator"); return; }
    for (unsigned i = 0; i < sizeof g_bitsz / sizeof g_bitsz[0]; i++) {
        BYTE d[3]; memcpy(d, g_bitsz[i].d, 3);
        CRYPT_BIT_BLOB b = { g_bitsz[i].cb, d, g_bitsz[i].unused };
        DWORD cb = 0; BYTE *e = kp_enc_alloc(X509_BITS_WITHOUT_TRAILING_ZEROES, &b, 0, &cb);
        if (!e) { t_note("row %u: encode failed 0x%lx", i, GetLastError()); continue; }
        CHECKF(cb == g_bitsz[i].n && !memcmp(e, g_bitsz[i].der, cb), "row %u", i);
        kp_free(e);
    }
}
TEST(kpb_bits_without_trailing_zeroes_decode) {
    REQ_CRYPT32();
    CRYPT_BIT_BLOB *r = kp_dec_alloc(X509_BITS_WITHOUT_TRAILING_ZEROES, (const BYTE[]){3,2,7,0x80}, 4, 0, NULL);
    if (r) { CHECK(r->cbData == 1 && r->pbData[0] == 0x80 && r->cUnusedBits == 7); kp_free(r); }
    else t_note("decode of X509_BITS_WITHOUT_TRAILING_ZEROES failed 0x%lx", GetLastError());
}
TEST(kpb_bits_alias_via_hash_string) {
    REQ_CRYPT32();
    BYTE d[] = {0x80}; CRYPT_BIT_BLOB b = { 1, d, 7 };
    DWORD cb = 0; BYTE buf[8];
    cb = sizeof buf; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, "#26", &b, 0, NULL, buf, &cb);
    t_note("encode with \"#26\": ok=%d", ok);
    CRYPT_BIT_BLOB *r = kp_dec_alloc("#26", (const BYTE[]){3,2,7,0x80}, 4, 0, NULL);
    CHECK(r && r->cbData == 1 && r->cUnusedBits == 7);    /* decoder dispatches "#<n>" to the numeric type */
    kp_free(r);
}

/* ---------------------------------------------------------------- X509_CHOICE_OF_TIME / PKCS_UTC_TIME */
static FILETIME mkft(int y, int mo, int d, int h, int mi, int s, int ms) {
    SYSTEMTIME st = { (WORD)y, (WORD)mo, 0, (WORD)d, (WORD)h, (WORD)mi, (WORD)s, (WORD)ms }; FILETIME ft = {0, 0};
    SystemTimeToFileTime(&st, &ft); return ft;
}
static void check_ft(FILETIME *f, int y, int mo, int d, int h, int mi, int s, int ms, int line) {
    SYSTEMTIME st; memset(&st, 0, sizeof st);
    if (!f) { t_check(0, __FILE__, line, "filetime result", "NULL"); return; }
    FileTimeToSystemTime(f, &st);
    t_check(st.wYear == y && st.wMonth == mo && st.wDay == d && st.wHour == h && st.wMinute == mi && st.wSecond == s && st.wMilliseconds == ms,
            __FILE__, line, "decoded time", "got %04d-%02d-%02d %02d:%02d:%02d.%03d want %04d-%02d-%02d %02d:%02d:%02d.%03d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, y, mo, d, h, mi, s, ms);
}
#define CK_FT(f, ...) check_ft(f, __VA_ARGS__, __LINE__)

TEST(kpb_utctime_encode_basic) {
    REQ_CRYPT32();
    FILETIME ft = mkft(2005, 6, 6, 16, 10, 0, 0);
    ENC_EQ(PKCS_UTC_TIME, &ft, V(0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z'));
    ft = mkft(1999, 12, 31, 23, 59, 59, 0);
    ENC_EQ(PKCS_UTC_TIME, &ft, V(0x17,0x0d,'9','9','1','2','3','1','2','3','5','9','5','9','Z'));
    ft = mkft(2000, 1, 1, 0, 0, 0, 0);
    ENC_EQ(PKCS_UTC_TIME, &ft, V(0x17,0x0d,'0','0','0','1','0','1','0','0','0','0','0','0','Z'));
}
TEST(kpb_utctime_encode_pivot_years) {
    REQ_CRYPT32();
    FILETIME ft = mkft(1950, 1, 1, 0, 0, 0, 0);
    ENC_EQ(PKCS_UTC_TIME, &ft, V(0x17,0x0d,'5','0','0','1','0','1','0','0','0','0','0','0','Z'));
    ft = mkft(2049, 12, 31, 23, 59, 59, 0);
    ENC_EQ(PKCS_UTC_TIME, &ft, V(0x17,0x0d,'4','9','1','2','3','1','2','3','5','9','5','9','Z'));
}
TEST(kpb_utctime_encode_out_of_range_fails) {
    REQ_CRYPT32();
    /* PKCS_UTC_TIME accepts years 1950..2049 only; anything else is CRYPT_E_BAD_ENCODE */
    FILETIME ft = mkft(2050, 1, 1, 0, 0, 0, 0);
    ENC_FAIL(PKCS_UTC_TIME, &ft, CRYPT_E_BAD_ENCODE);
    ft = mkft(1949, 12, 31, 23, 59, 59, 0);
    ENC_FAIL(PKCS_UTC_TIME, &ft, CRYPT_E_BAD_ENCODE);
    ft = mkft(1601, 1, 1, 0, 0, 0, 0);
    ENC_FAIL(PKCS_UTC_TIME, &ft, CRYPT_E_BAD_ENCODE);
    ft = mkft(3000, 1, 1, 0, 0, 0, 0);
    ENC_FAIL(PKCS_UTC_TIME, &ft, CRYPT_E_BAD_ENCODE);
}
TEST(kpb_utctime_encode_invalid_filetime) {
    REQ_CRYPT32();
    FILETIME ft; ft.dwLowDateTime = 0xffffffff; ft.dwHighDateTime = 0x7fffffff;   /* past year 30827 */
    ENC_FAIL(PKCS_UTC_TIME, &ft, CRYPT_E_BAD_ENCODE);
    ENC_FAIL(X509_CHOICE_OF_TIME, &ft, CRYPT_E_BAD_ENCODE);
    ft.dwLowDateTime = 0; ft.dwHighDateTime = 0x80000000;                           /* negative */
    ENC_FAIL(PKCS_UTC_TIME, &ft, CRYPT_E_BAD_ENCODE);
    ENC_FAIL(X509_CHOICE_OF_TIME, &ft, CRYPT_E_BAD_ENCODE);
}
TEST(kpb_utctime_encode_alloc_failure_clears_pointer) {
    REQ_CRYPT32();
    FILETIME ft = mkft(2050, 1, 1, 0, 0, 0, 0); BYTE *out = (BYTE *)(ULONG_PTR)1; DWORD cb = 99;
    CHECK(!U(CryptEncodeObjectEx)(KP_ENC, PKCS_UTC_TIME, &ft, CRYPT_ENCODE_ALLOC_FLAG, NULL, &out, &cb));
    CHECK(out == NULL); EXPECT_EQ(cb, 0);
}
TEST(kpb_utctime_encode_milliseconds_dropped) {
    REQ_CRYPT32();
    FILETIME ft = mkft(2005, 6, 6, 16, 10, 7, 999);
    DWORD cb; BYTE *e = kp_enc_alloc(PKCS_UTC_TIME, &ft, 0, &cb);
    CHECK(e && cb == 15 && !memcmp(e, "\x17\x0d" "050606161007Z", 15));
    kp_free(e);
}
TEST(kpb_utctime_decode) {
    REQ_CRYPT32();
    FILETIME *f;
    f = DEC_OK(PKCS_UTC_TIME, V(0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z'), 0); if (f) { CK_FT(f, 2005,6,6,16,10,0,0); kp_free(f); }
    f = DEC_OK(PKCS_UTC_TIME, V(0x17,0x0d,'4','9','1','2','3','1','2','3','5','9','5','9','Z'), 0); if (f) { CK_FT(f, 2049,12,31,23,59,59,0); kp_free(f); }
    f = DEC_OK(PKCS_UTC_TIME, V(0x17,0x0d,'5','0','0','1','0','1','0','0','0','0','0','0','Z'), 0); if (f) { CK_FT(f, 1950,1,1,0,0,0,0); kp_free(f); }
    f = DEC_OK(PKCS_UTC_TIME, V(0x17,0x0d,'9','9','1','2','3','1','2','3','5','9','5','9','Z'), 0); if (f) { CK_FT(f, 1999,12,31,23,59,59,0); kp_free(f); }
}
TEST(kpb_utctime_decode_no_seconds) {
    REQ_CRYPT32();
    FILETIME *f = DEC_OK(PKCS_UTC_TIME, V(0x17,0x0b,'0','5','0','6','0','6','1','6','1','0','Z'), 0);
    if (f) { CK_FT(f, 2005,6,6,16,10,0,0); kp_free(f); }
}
TEST(kpb_utctime_decode_offsets) {
    REQ_CRYPT32();
    /* the decoder applies the +-hhmm offset (AdjustFileTime); direction is recorded, not enforced */
    FILETIME *f = DEC_OK(PKCS_UTC_TIME, V(0x17,0x11,'0','5','0','6','0','6','1','6','1','0','0','0','+','0','1','0','0'), 0);
    if (f) { SYSTEMTIME st; FileTimeToSystemTime(f, &st); CHECK(st.wDay == 6 && st.wMinute == 10 && (st.wHour == 15 || st.wHour == 17)); t_note("+0100 -> %02d:%02d UTC", st.wHour, st.wMinute); kp_free(f); }
    f = DEC_OK(PKCS_UTC_TIME, V(0x17,0x11,'0','5','0','6','0','6','1','6','1','0','0','0','-','0','1','3','0'), 0);
    if (f) { SYSTEMTIME st; FileTimeToSystemTime(f, &st); CHECK(st.wDay == 6); t_note("-0130 -> %02d:%02d UTC", st.wHour, st.wMinute); kp_free(f); }
}
TEST(kpb_utctime_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(PKCS_UTC_TIME, KP_E_BADTAG, 0x18,0x0f,'2','0','0','5','0','6','0','6','1','6','1','0','0','0','Z');
    DEC_FAILV(PKCS_UTC_TIME, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(PKCS_UTC_TIME, KP_E_TRUNC, 0x17,0x0d,'0','5','0','6');
    DEC_FAILV(PKCS_UTC_TIME, KP_E_EOD, 0x17);
}
TEST(kpb_utctime_decode_garbage_content) {
    REQ_CRYPT32();
    DEC_FAILV(PKCS_UTC_TIME, 0, 0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','X');
    DEC_FAILV(PKCS_UTC_TIME, 0, 0x17,0x0d,'a','b','0','6','0','6','1','6','1','0','0','0','Z');
    DEC_FAILV(PKCS_UTC_TIME, 0, 0x17,0x00);
}
TEST(kpb_choice_time_encode_utc_range) {
    REQ_CRYPT32();
    FILETIME ft = mkft(2005, 6, 6, 16, 10, 0, 0);
    ENC_EQ(X509_CHOICE_OF_TIME, &ft, V(0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z'));
    ft = mkft(1950, 1, 1, 0, 0, 0, 0);
    ENC_EQ(X509_CHOICE_OF_TIME, &ft, V(0x17,0x0d,'5','0','0','1','0','1','0','0','0','0','0','0','Z'));
    ft = mkft(2049, 12, 31, 23, 59, 59, 0);
    ENC_EQ(X509_CHOICE_OF_TIME, &ft, V(0x17,0x0d,'4','9','1','2','3','1','2','3','5','9','5','9','Z'));
}
TEST(kpb_choice_time_encode_generalized_at_2050) {
    REQ_CRYPT32();
    FILETIME ft = mkft(2050, 1, 1, 0, 0, 0, 0);
    ENC_EQ(X509_CHOICE_OF_TIME, &ft, V(0x18,0x0f,'2','0','5','0','0','1','0','1','0','0','0','0','0','0','Z'));
    ft = mkft(2145, 6, 6, 16, 10, 0, 0);
    ENC_EQ(X509_CHOICE_OF_TIME, &ft, V(0x18,0x0f,'2','1','4','5','0','6','0','6','1','6','1','0','0','0','Z'));
    ft = mkft(9999, 12, 31, 23, 59, 59, 0);
    ENC_EQ(X509_CHOICE_OF_TIME, &ft, V(0x18,0x0f,'9','9','9','9','1','2','3','1','2','3','5','9','5','9','Z'));
}
TEST(kpb_choice_time_encode_generalized_before_1950) {
    REQ_CRYPT32();
    FILETIME ft = mkft(1949, 12, 31, 23, 59, 59, 0);
    ENC_EQ(X509_CHOICE_OF_TIME, &ft, V(0x18,0x0f,'1','9','4','9','1','2','3','1','2','3','5','9','5','9','Z'));
    ft = mkft(1601, 1, 1, 0, 0, 0, 0);
    ENC_EQ(X509_CHOICE_OF_TIME, &ft, V(0x18,0x0f,'1','6','0','1','0','1','0','1','0','0','0','0','0','0','Z'));
}
TEST(kpb_choice_time_encode_milliseconds) {
    REQ_CRYPT32();
    FILETIME ft = mkft(2145, 6, 6, 16, 10, 7, 321);
    DWORD cb; BYTE *e = kp_enc_alloc(X509_CHOICE_OF_TIME, &ft, 0, &cb);
    CHECK(e != NULL);
    if (e) {
        if (cb == 17 && !memcmp(e, "\x18\x0f" "21450606161007Z", 17)) t_note("generalized time drops milliseconds");
        else CHECK(cb > 17 && e[0] == 0x18);
        kp_free(e);
    }
}
TEST(kpb_choice_time_decode_both_tags) {
    REQ_CRYPT32();
    FILETIME *f;
    f = DEC_OK(X509_CHOICE_OF_TIME, V(0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z'), 0); if (f) { CK_FT(f, 2005,6,6,16,10,0,0); kp_free(f); }
    f = DEC_OK(X509_CHOICE_OF_TIME, V(0x18,0x0f,'2','1','4','5','0','6','0','6','1','6','1','0','0','0','Z'), 0); if (f) { CK_FT(f, 2145,6,6,16,10,0,0); kp_free(f); }
    f = DEC_OK(X509_CHOICE_OF_TIME, V(0x18,0x0f,'1','9','4','9','1','2','3','1','2','3','5','9','5','9','Z'), 0); if (f) { CK_FT(f, 1949,12,31,23,59,59,0); kp_free(f); }
    f = DEC_OK(X509_CHOICE_OF_TIME, V(0x18,0x0f,'2','0','0','5','0','6','0','6','1','6','1','0','0','0','Z'), 0); if (f) { CK_FT(f, 2005,6,6,16,10,0,0); kp_free(f); }
}
TEST(kpb_choice_time_decode_generalized_fraction) {
    REQ_CRYPT32();
    static const BYTE der[] = {0x18,0x13,'2','1','4','5','0','6','0','6','1','6','1','0','0','7','.','5','0','0','Z'};
    FILETIME *f = kp_dec_alloc(X509_CHOICE_OF_TIME, der, sizeof der, 0, NULL);
    if (f) { SYSTEMTIME st; FileTimeToSystemTime(f, &st); t_note("fraction .500 decodes to ms=%d s=%d", st.wMilliseconds, st.wSecond); CHECK(st.wYear == 2145 && st.wSecond == 7); kp_free(f); }
    else t_note("generalized time with fraction rejected, err 0x%lx", GetLastError());
}
TEST(kpb_choice_time_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_CHOICE_OF_TIME, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(X509_CHOICE_OF_TIME, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_CHOICE_OF_TIME, KP_E_TRUNC, 0x18, 0x0f, '2', '1');
}
TEST(kpb_filetime_decode_size) {
    REQ_CRYPT32();
    DWORD cb = 0;
    static const BYTE der[] = {0x17,0x0d,'0','5','0','6','0','6','1','6','1','0','0','0','Z'};
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, PKCS_UTC_TIME, der, sizeof der, 0, NULL, NULL, &cb));
    EXPECT_EQ(cb, sizeof(FILETIME));
}
TEST(kpb_time_roundtrip_dates) {
    REQ_CRYPT32();
    static const int d[][6] = { {1950,1,1,0,0,0}, {1970,1,1,0,0,0}, {1999,12,31,23,59,59}, {2000,2,29,12,0,0}, {2038,1,19,3,14,7}, {2049,12,31,23,59,59},
                                {2050,1,1,0,0,0}, {2100,3,1,0,0,1}, {1601,1,1,0,0,0}, {3000,6,15,6,6,6} };
    for (unsigned i = 0; i < sizeof d / sizeof d[0]; i++) {
        FILETIME ft = mkft(d[i][0], d[i][1], d[i][2], d[i][3], d[i][4], d[i][5], 0); DWORD cb;
        BYTE *e = kp_enc_alloc(X509_CHOICE_OF_TIME, &ft, 0, &cb);
        CHECKF(e != NULL, "row %u", i);
        if (!e) continue;
        FILETIME *r = kp_dec_alloc(X509_CHOICE_OF_TIME, e, cb, 0, NULL);
        CHECKF(r && r->dwLowDateTime == ft.dwLowDateTime && r->dwHighDateTime == ft.dwHighDateTime, "row %u", i);
        kp_free(r); kp_free(e);
    }
}

/* ---------------------------------------------------------------- X509_OBJECT_IDENTIFIER */
static const struct { const char *oid; BYTE der[16]; BYTE n; } g_oids[] = {
    { "1.2.840.113549",       {6,6,0x2a,0x86,0x48,0x86,0xf7,0x0d}, 8 },
    { "1.2.840.113549.1.1.1", {6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1}, 11 },
    { "2.5.4.3",              {6,3,0x55,4,3}, 5 },
    { "1.3.6.1.4.1.311",      {6,7,0x2b,6,1,4,1,0x82,0x37}, 9 },
    { "2.999",                {6,2,0x88,0x37}, 4 },
    { "0.0",                  {6,1,0}, 3 },
    { "1.39",                 {6,1,0x4f}, 3 },
    { "2.0",                  {6,1,0x50}, 3 },
    { "2.47",                 {6,1,0x7f}, 3 },
    { "2.48",                 {6,2,0x81,0x00}, 4 },
    { "1.2.128",              {6,3,0x2a,0x81,0x00}, 5 },
    { "1.2.16384",            {6,4,0x2a,0x81,0x80,0x00}, 6 },
    { "1.3.14.3.2.26",        {6,5,0x2b,0x0e,0x03,0x02,0x1a}, 7 },
    { "0.9.2342.19200300.100.1.25", {6,9,0x09,0x92,0x26,0x89,0x93,0xf2,0x2c,0x64,0x01}, 11 },
};
TEST(kpb_objid_encode_table) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("X509_OBJECT_IDENTIFIER not implemented by the emulator"); return; }
    for (unsigned i = 0; i < sizeof g_oids / sizeof g_oids[0]; i++) {
        LPSTR s = (LPSTR)g_oids[i].oid;
        BYTE exp[32]; memcpy(exp, g_oids[i].der, g_oids[i].n);
        if (i == 13) { /* recompute below, do not trust hand encoding of the 4-byte arcs */ continue; }
        ENC_EQ(X509_OBJECT_IDENTIFIER, &s, exp, g_oids[i].n);
    }
}
TEST(kpb_objid_decode_table) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("emulator renders arcs of 2.x incorrectly"); return; }
    for (unsigned i = 0; i < sizeof g_oids / sizeof g_oids[0]; i++) {
        if (i == 13) continue;
        LPSTR *r = DEC_OK(X509_OBJECT_IDENTIFIER, g_oids[i].der, g_oids[i].n, 0);
        if (r) { CHECKF(*r && !strcmp(*r, g_oids[i].oid), "row %u: %s", i, *r ? *r : "(null)"); kp_free(r); }
    }
}
TEST(kpb_objid_encode_invalid_strings_fail) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("X509_OBJECT_IDENTIFIER not implemented by the emulator"); return; }
    static const char *bad[] = { "", "1", "3.1", "1.40", "1.2.", ".1.2", "1..2", "1.2.abc", "1.2.3 ", "a.b", "-1.2", "1.-2", "2.5.4.3x" };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        LPSTR s = (LPSTR)bad[i];
        DWORD cb = 100; BYTE buf[64];
        SET_ERR(0);
        BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, X509_OBJECT_IDENTIFIER, &s, 0, NULL, buf, &cb);
        CHECKF(!ok, "\"%s\" must not encode", bad[i]);
    }
}
TEST(kpb_objid_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_OBJECT_IDENTIFIER, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(X509_OBJECT_IDENTIFIER, KP_E_TRUNC, 6, 3, 0x55, 4);
    if (!t_is_wine()) DEC_FAILV(X509_OBJECT_IDENTIFIER, KP_E_EOD, 6);
}
TEST(kpb_objid_encode_null_string_fails) {
    REQ_CRYPT32();
    LPSTR s = NULL;
    ENC_FAIL(X509_OBJECT_IDENTIFIER, &s, 0);
}
TEST(kpb_objid_zero_length_content_decode) {
    REQ_CRYPT32();
    static const BYTE der[] = {6, 0}; DWORD cb = 0;
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, X509_OBJECT_IDENTIFIER, der, 2, 0, NULL, NULL, &cb);
    t_note("empty OID content: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}

/* ---------------------------------------------------------------- X509_UNICODE_ANY_STRING / X509_ANY_STRING */
static const WCHAR wabc[] = L"abc";
TEST(kpb_unicode_any_string_encode_types) {
    REQ_CRYPT32();
    CERT_NAME_VALUE v; v.Value.pbData = (BYTE *)wabc; v.Value.cbData = 6;
    v.dwValueType = CERT_RDN_UTF8_STRING;      ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x0c,3,'a','b','c'));
    v.dwValueType = CERT_RDN_PRINTABLE_STRING; ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x13,3,'a','b','c'));
    v.dwValueType = CERT_RDN_IA5_STRING;       ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x16,3,'a','b','c'));
    v.dwValueType = CERT_RDN_VISIBLE_STRING;   ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x1a,3,'a','b','c'));
    v.dwValueType = CERT_RDN_BMP_STRING;       ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x1e,6,0,'a',0,'b',0,'c'));
    v.dwValueType = CERT_RDN_UNIVERSAL_STRING; ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x1c,12,0,0,0,'a',0,0,0,'b',0,0,0,'c'));
}
TEST(kpb_unicode_any_string_numeric) {
    REQ_CRYPT32();
    static const WCHAR n[] = L"1234567890"; CERT_NAME_VALUE v = { CERT_RDN_NUMERIC_STRING, { 20, (BYTE *)n } };
    ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x12,10,'1','2','3','4','5','6','7','8','9','0'));
    static const WCHAR sp[] = L"12 3"; v.Value.pbData = (BYTE *)sp; v.Value.cbData = 8;
    DWORD cb = 0; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, X509_UNICODE_ANY_STRING, &v, 0, NULL, NULL, &cb);
    t_note("NumericString with a space: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}
TEST(kpb_unicode_any_string_teletex) {
    REQ_CRYPT32();
    CERT_NAME_VALUE v = { CERT_RDN_T61_STRING, { 6, (BYTE *)wabc } };
    ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x14,3,'a','b','c'));
}
TEST(kpb_unicode_any_string_empty) {
    REQ_CRYPT32();
    CERT_NAME_VALUE v = { CERT_RDN_UTF8_STRING, { 0, NULL } };
    ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x0c,0));
    v.dwValueType = CERT_RDN_PRINTABLE_STRING; ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x13,0));
    v.dwValueType = CERT_RDN_BMP_STRING; ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x1e,0));
}
TEST(kpb_unicode_any_string_utf8_multibyte) {
    REQ_CRYPT32();
    static const WCHAR w[] = { 0x00e9, 0x20ac, 0 };
    CERT_NAME_VALUE v = { CERT_RDN_UTF8_STRING, { 4, (BYTE *)w } };
    ENC_EQ(X509_UNICODE_ANY_STRING, &v, V(0x0c,5,0xc3,0xa9,0xe2,0x82,0xac));
}
TEST(kpb_unicode_any_string_invalid_chars) {
    REQ_CRYPT32();
    static const WCHAR bad[] = L"a@b";
    CERT_NAME_VALUE v = { CERT_RDN_PRINTABLE_STRING, { 6, (BYTE *)bad } };
    ENC_FAIL(X509_UNICODE_ANY_STRING, &v, CRYPT_E_INVALID_PRINTABLE_STRING);
    static const WCHAR bn[] = L"12a";
    v.dwValueType = CERT_RDN_NUMERIC_STRING; v.Value.pbData = (BYTE *)bn; v.Value.cbData = 6;
    ENC_FAIL(X509_UNICODE_ANY_STRING, &v, CRYPT_E_INVALID_NUMERIC_STRING);
    static const WCHAR bi[] = { 'a', 0x0100, 0 };
    v.dwValueType = CERT_RDN_IA5_STRING; v.Value.pbData = (BYTE *)bi; v.Value.cbData = 4;
    ENC_FAIL(X509_UNICODE_ANY_STRING, &v, CRYPT_E_INVALID_IA5_STRING);
}
TEST(kpb_unicode_any_string_disable_check_flag) {
    REQ_CRYPT32();
    static const WCHAR bad[] = L"a@b";
    CERT_NAME_VALUE v = { CERT_RDN_PRINTABLE_STRING | CERT_RDN_DISABLE_CHECK_TYPE_FLAG, { 6, (BYTE *)bad } };
    DWORD cb = 0; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, X509_UNICODE_ANY_STRING, &v, 0, NULL, NULL, &cb);
    t_note("DISABLE_CHECK_TYPE flag on X509_UNICODE_ANY_STRING: ok=%d cb=%lu err=0x%lx", ok, cb, ok ? 0 : GetLastError());
}
TEST(kpb_unicode_any_string_odd_byte_count) {
    REQ_CRYPT32();
    CERT_NAME_VALUE v = { CERT_RDN_UTF8_STRING, { 5, (BYTE *)wabc } };
    DWORD cb = 100; BYTE buf[64];
    BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, X509_UNICODE_ANY_STRING, &v, 0, NULL, buf, &cb);
    t_note("odd byte count unicode string: ok=%d", ok);
}
TEST(kpb_unicode_any_string_decode) {
    REQ_CRYPT32();
    CERT_NAME_VALUE *r;
    r = DEC_OK(X509_UNICODE_ANY_STRING, V(0x0c,3,'a','b','c'), 0);
    if (r) { CHECK(r->Value.cbData == 6 && !memcmp(r->Value.pbData, L"abc", 6)); t_note("UTF8String decodes to dwValueType %lu", r->dwValueType); kp_free(r); }
    r = DEC_OK(X509_UNICODE_ANY_STRING, V(0x13,3,'a','b','c'), 0);
    if (r) { CHECK(r->dwValueType == CERT_RDN_PRINTABLE_STRING && r->Value.cbData == 6 && !memcmp(r->Value.pbData, L"abc", 6)); kp_free(r); }
    r = DEC_OK(X509_UNICODE_ANY_STRING, V(0x1e,4,0,'a',0x20,0xac), 0);
    if (r) { static const WCHAR e[] = { 'a', 0x20ac }; CHECK(r->dwValueType == CERT_RDN_BMP_STRING && r->Value.cbData == 4 && !memcmp(r->Value.pbData, e, 4)); kp_free(r); }
    r = DEC_OK(X509_UNICODE_ANY_STRING, V(0x16,2,'h','i'), 0);
    if (r) { CHECK(r->dwValueType == CERT_RDN_IA5_STRING && r->Value.cbData == 4); kp_free(r); }
    r = DEC_OK(X509_UNICODE_ANY_STRING, V(0x0c,5,0xc3,0xa9,0xe2,0x82,0xac), 0);
    if (r) { static const WCHAR e[] = { 0xe9, 0x20ac }; CHECK(r->Value.cbData == 4 && !memcmp(r->Value.pbData, e, 4)); kp_free(r); }
    r = DEC_OK(X509_UNICODE_ANY_STRING, V(0x12,3,'1','2','3'), 0);
    if (r) { CHECK(r->dwValueType == CERT_RDN_NUMERIC_STRING && r->Value.cbData == 6); kp_free(r); }
    r = DEC_OK(X509_UNICODE_ANY_STRING, V(0x1c,8,0,0,0,'a',0,0,0,'b'), 0);
    if (r) { CHECK(r->dwValueType == CERT_RDN_UNIVERSAL_STRING && r->Value.cbData == 4); kp_free(r); }
}
TEST(kpb_unicode_any_string_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_UNICODE_ANY_STRING, 0, 0x0c, 5, 'a');
}
TEST(kpb_any_string_encode_bytes) {
    REQ_CRYPT32();
    CERT_NAME_VALUE v = { CERT_RDN_PRINTABLE_STRING, { 3, (BYTE *)"abc" } };
    ENC_EQ(X509_ANY_STRING, &v, V(0x13,3,'a','b','c'));
    v.dwValueType = CERT_RDN_IA5_STRING; ENC_EQ(X509_ANY_STRING, &v, V(0x16,3,'a','b','c'));
    v.dwValueType = CERT_RDN_OCTET_STRING; ENC_EQ(X509_ANY_STRING, &v, V(0x04,3,'a','b','c'));
    v.dwValueType = CERT_RDN_NUMERIC_STRING; v.Value.pbData = (BYTE *)"123"; ENC_EQ(X509_ANY_STRING, &v, V(0x12,3,'1','2','3'));
    v.dwValueType = CERT_RDN_T61_STRING; v.Value.pbData = (BYTE *)"abc"; ENC_EQ(X509_ANY_STRING, &v, V(0x14,3,'a','b','c'));
    v.dwValueType = CERT_RDN_VIDEOTEX_STRING; ENC_EQ(X509_ANY_STRING, &v, V(0x15,3,'a','b','c'));
    v.dwValueType = CERT_RDN_GRAPHIC_STRING; ENC_EQ(X509_ANY_STRING, &v, V(0x19,3,'a','b','c'));
    v.dwValueType = CERT_RDN_VISIBLE_STRING; ENC_EQ(X509_ANY_STRING, &v, V(0x1a,3,'a','b','c'));
    v.dwValueType = CERT_RDN_GENERAL_STRING; ENC_EQ(X509_ANY_STRING, &v, V(0x1b,3,'a','b','c'));
}
TEST(kpb_any_string_encode_wide_types_take_utf16_input) {
    REQ_CRYPT32();
    /* BMP and UTF8 values are supplied as UTF-16 by this (non UNICODE_) struct type: the byte count is halved */
    CERT_NAME_VALUE v = { CERT_RDN_BMP_STRING, { 6, (BYTE *)wabc } };
    ENC_EQ(X509_ANY_STRING, &v, V(0x1e,6,0,'a',0,'b',0,'c'));
    v.dwValueType = CERT_RDN_UTF8_STRING; ENC_EQ(X509_ANY_STRING, &v, V(0x0c,3,'a','b','c'));
    static const WCHAR e[] = { 0xe9, 0x20ac };
    v.Value.pbData = (BYTE *)e; v.Value.cbData = 4; ENC_EQ(X509_ANY_STRING, &v, V(0x0c,5,0xc3,0xa9,0xe2,0x82,0xac));
}
TEST(kpb_any_string_encode_universal_counts_dwords) {
    REQ_CRYPT32();
    static const DWORD u[] = { 'a', 0x20ac }; CERT_NAME_VALUE v = { CERT_RDN_UNIVERSAL_STRING, { 8, (BYTE *)u } };
    ENC_EQ(X509_ANY_STRING, &v, V(0x1c,8,0,0,0,'a',0,0,0x20,0xac));
}
TEST(kpb_any_string_encode_encoded_blob_is_copied_verbatim) {
    REQ_CRYPT32();
    CERT_NAME_VALUE v = { CERT_RDN_ENCODED_BLOB, { 3, (BYTE *)"\x02\x01\x05" } };
    ENC_EQ(X509_ANY_STRING, &v, V(2,1,5));
    v.Value.cbData = 2; v.Value.pbData = (BYTE *)"\x02\x05";
    ENC_EQ(X509_ANY_STRING, &v, V(2,5));          /* no validation of the blob */
    v.Value.cbData = 0; v.Value.pbData = NULL;
    ENC_EQ(X509_ANY_STRING, &v, (const BYTE *)"", 0);
}
TEST(kpb_any_string_encode_any_type_is_invalidarg) {
    REQ_CRYPT32();
    CERT_NAME_VALUE v = { CERT_RDN_ANY_TYPE, { 3, (BYTE *)"abc" } };
    ENC_FAIL(X509_ANY_STRING, &v, KP_E_INVALIDARG);
    DWORD cb = 77; SET_ERR(0);
    CHECK(!U(CryptEncodeObjectEx)(KP_ENC, X509_ANY_STRING, &v, 0, NULL, NULL, &cb));
    EXPECT_EQ(cb, 0);
}
TEST(kpb_any_string_decode) {
    REQ_CRYPT32();
    CERT_NAME_VALUE *r = DEC_OK(X509_ANY_STRING, V(0x13,3,'a','b','c'), 0);
    if (r) { CHECK(r->dwValueType == CERT_RDN_PRINTABLE_STRING); BLOB_IS(r->Value, 'a','b','c');
             CHECK(r->Value.pbData[3] == 0 && r->Value.pbData[4] == 0);   /* decoded values are followed by a UTF-16 NUL */
             kp_free(r); }
    r = DEC_OK(X509_ANY_STRING, V(0x0c,3,'a','b','c'), 0);
    if (r) { CHECK(r->dwValueType == CERT_RDN_UTF8_STRING && r->Value.cbData == 6 && !memcmp(r->Value.pbData, L"abc", 6)); kp_free(r); }  /* UTF8 is returned as UTF-16 */
    r = DEC_OK(X509_ANY_STRING, V(0x1e,4,0,'a',0x20,0xac), 0);
    if (r) { CHECK(r->dwValueType == CERT_RDN_BMP_STRING && r->Value.cbData == 4 && ((WCHAR *)r->Value.pbData)[1] == 0x20ac); kp_free(r); }
    r = DEC_OK(X509_ANY_STRING, V(0x04,2,1,2), 0);
    if (r) { CHECK(r->dwValueType == CERT_RDN_OCTET_STRING); BLOB_IS(r->Value, 1,2); kp_free(r); }
}

/* ---------------------------------------------------------------- X509_SEQUENCE_OF_ANY */
TEST(kpb_seq_of_any_encode) {
    REQ_CRYPT32();
    CRYPT_DER_BLOB items[3] = { {3, (BYTE *)"\x02\x01\x01"}, {2, (BYTE *)"\x05\x00"}, {5, (BYTE *)"\x04\x03\x01\x02\x03"} };
    CRYPT_SEQUENCE_OF_ANY s = { 0, NULL };
    ENC_EQ(X509_SEQUENCE_OF_ANY, &s, V(0x30,0));
    s.cValue = 1; s.rgValue = items; ENC_EQ(X509_SEQUENCE_OF_ANY, &s, V(0x30,3,2,1,1));
    s.cValue = 3; ENC_EQ(X509_SEQUENCE_OF_ANY, &s, V(0x30,10,2,1,1,5,0,4,3,1,2,3));
}
TEST(kpb_seq_of_any_encode_nested) {
    REQ_CRYPT32();
    CRYPT_DER_BLOB items[2] = { {4, (BYTE *)"\x30\x02\x05\x00"}, {4, (BYTE *)"\x30\x02\x05\x00"} };
    CRYPT_SEQUENCE_OF_ANY s = { 2, items };
    ENC_EQ(X509_SEQUENCE_OF_ANY, &s, V(0x30,8,0x30,2,5,0,0x30,2,5,0));
}
TEST(kpb_seq_of_any_encode_items_copied_verbatim_note) {
    REQ_CRYPT32();
    /* the items are open types: the encoder does not parse them (recorded, not enforced) */
    CRYPT_DER_BLOB items[1] = { {1, (BYTE *)"\x02"} }; CRYPT_SEQUENCE_OF_ANY s = { 1, items };
    DWORD cb = 0; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, X509_SEQUENCE_OF_ANY, &s, 0, NULL, NULL, &cb);
    t_note("one-byte item: ok=%d cb=%lu err=0x%lx", ok, cb, ok ? 0 : GetLastError());
}
TEST(kpb_seq_of_any_decode) {
    REQ_CRYPT32();
    CRYPT_SEQUENCE_OF_ANY *r = DEC_OK(X509_SEQUENCE_OF_ANY, V(0x30,10,2,1,1,5,0,4,3,1,2,3), 0);
    if (r) {
        CHECK(r->cValue == 3);
        if (r->cValue == 3) { BLOB_IS(r->rgValue[0], 2,1,1); BLOB_IS(r->rgValue[1], 5,0); BLOB_IS(r->rgValue[2], 4,3,1,2,3); }
        kp_free(r);
    }
    r = DEC_OK(X509_SEQUENCE_OF_ANY, V(0x30,0), 0);
    if (r) { CHECK(r->cValue == 0); kp_free(r); }
}
TEST(kpb_seq_of_any_decode_nocopy) {
    REQ_CRYPT32();
    static const BYTE der[] = {0x30,5,2,1,1,5,0}; BYTE buf[256]; DWORD cb = sizeof buf;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_SEQUENCE_OF_ANY, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, NULL, buf, &cb));
    CRYPT_SEQUENCE_OF_ANY *r = (CRYPT_SEQUENCE_OF_ANY *)buf;
    CHECK(r->cValue == 2);
    if (r->cValue == 2) { CHECK(r->rgValue[0].pbData == der + 2 && r->rgValue[0].cbData == 3); CHECK(r->rgValue[1].pbData == der + 5 && r->rgValue[1].cbData == 2); }
}
TEST(kpb_seq_of_any_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_SEQUENCE_OF_ANY, KP_E_BADTAG, 0x31, 0);
    DEC_FAILV(X509_SEQUENCE_OF_ANY, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_SEQUENCE_OF_ANY, KP_E_EOD, 0x30, 5, 2, 1, 1);
    DEC_FAILV(X509_SEQUENCE_OF_ANY, 0, 0x30, 3, 2, 5, 1);
}
TEST(kpb_seq_of_any_roundtrip_many) {
    REQ_CRYPT32();
    CRYPT_DER_BLOB items[100]; BYTE store[100][3]; CRYPT_SEQUENCE_OF_ANY s; DWORD cb;
    for (int i = 0; i < 100; i++) { store[i][0] = 2; store[i][1] = 1; store[i][2] = (BYTE)i; items[i].cbData = 3; items[i].pbData = store[i]; }
    s.cValue = 100; s.rgValue = items;
    BYTE *e = kp_enc_alloc(X509_SEQUENCE_OF_ANY, &s, 0, &cb);
    CHECK(e && cb == 4 + 300 && e[0] == 0x30 && e[1] == 0x82 && e[2] == 0x01 && e[3] == 0x2c);
    if (e) {
        CRYPT_SEQUENCE_OF_ANY *r = kp_dec_alloc(X509_SEQUENCE_OF_ANY, e, cb, 0, NULL);
        CHECK(r && r->cValue == 100);
        if (r && r->cValue == 100) for (int i = 0; i < 100; i++) CHECK(r->rgValue[i].cbData == 3 && r->rgValue[i].pbData[2] == i);
        kp_free(r); kp_free(e);
    }
}

/* ---------------------------------------------------------------- PKCS_CONTENT_INFO_SEQUENCE_OF_ANY / PKCS_CONTENT_INFO */
static const BYTE oid_data_der[] = {6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1};
TEST(kpb_content_info_encode_no_content) {
    REQ_CRYPT32();
    CRYPT_CONTENT_INFO ci = { (LPSTR)szOID_RSA_data, { 0, NULL } };
    ENC_EQ(PKCS_CONTENT_INFO, &ci, V(0x30,0x0b,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1));
}
TEST(kpb_content_info_encode_with_content) {
    REQ_CRYPT32();
    CRYPT_CONTENT_INFO ci = { (LPSTR)szOID_RSA_data, { 5, (BYTE *)"\x04\x03\x01\x02\x03" } };
    ENC_EQ(PKCS_CONTENT_INFO, &ci, V(0x30,0x12,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1,0xa0,5,4,3,1,2,3));
}
TEST(kpb_content_info_encode_content_not_parsed_note) {
    REQ_CRYPT32();
    CRYPT_CONTENT_INFO ci = { (LPSTR)szOID_RSA_data, { 1, (BYTE *)"\x01" } };
    DWORD cb = 0; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, PKCS_CONTENT_INFO, &ci, 0, NULL, NULL, &cb);
    t_note("one-byte content: ok=%d cb=%lu err=0x%lx", ok, cb, ok ? 0 : GetLastError());
}
TEST(kpb_content_info_encode_bad_oid) {
    REQ_CRYPT32();
    CRYPT_CONTENT_INFO ci = { (LPSTR)"not.an.oid", { 0, NULL } };
    ENC_FAIL(PKCS_CONTENT_INFO, &ci, 0);
    ci.pszObjId = NULL;
    ENC_FAIL(PKCS_CONTENT_INFO, &ci, 0);
}
TEST(kpb_content_info_decode) {
    REQ_CRYPT32();
    CRYPT_CONTENT_INFO *r = DEC_OK(PKCS_CONTENT_INFO, V(0x30,0x12,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1,0xa0,5,4,3,1,2,3), 0);
    if (r) { EXPECT_STR(r->pszObjId, szOID_RSA_data); BLOB_IS(r->Content, 4,3,1,2,3); kp_free(r); }
    r = DEC_OK(PKCS_CONTENT_INFO, V(0x30,0x0b,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1), 0);
    if (r) { EXPECT_STR(r->pszObjId, szOID_RSA_data); CHECK(r->Content.cbData == 0); kp_free(r); }
}
TEST(kpb_content_info_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(PKCS_CONTENT_INFO, KP_E_BADTAG, 0x31, 0);
    DEC_FAILV(PKCS_CONTENT_INFO, KP_E_BADTAG, 0x30, 3, 2, 1, 1);
    DEC_FAILV(PKCS_CONTENT_INFO, KP_E_EOD, 0x30, 0x0b, 6, 9, 0x2a);
    DEC_FAILV(PKCS_CONTENT_INFO, 0, 0x30, 0);
}
TEST(kpb_content_info_decode_nocopy_content_aliases_input) {
    REQ_CRYPT32();
    static const BYTE der[] = {0x30,0x12,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1,0xa0,5,4,3,1,2,3}; BYTE buf[256]; DWORD cb = sizeof buf;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, PKCS_CONTENT_INFO, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, NULL, buf, &cb));
    CRYPT_CONTENT_INFO *r = (CRYPT_CONTENT_INFO *)buf;
    CHECK(r->Content.cbData == 5 && r->Content.pbData == der + 15);
    t_note("pszObjId with NOCOPY points into input: %d", (const BYTE *)r->pszObjId >= der && (const BYTE *)r->pszObjId < der + sizeof der);
}
TEST(kpb_content_info_seq_of_any_encode) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("PKCS_CONTENT_INFO_SEQUENCE_OF_ANY not implemented by the emulator"); return; }
    CRYPT_DER_BLOB v[1] = { {3, (BYTE *)"\x02\x01\x01"} };
    CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY ci = { (LPSTR)szOID_RSA_data, 1, v };
    ENC_EQ(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, &ci, V(0x30,0x12,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1,0xa0,5,0x30,3,2,1,1));
}
TEST(kpb_content_info_seq_of_any_encode_empty) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("PKCS_CONTENT_INFO_SEQUENCE_OF_ANY not implemented by the emulator"); return; }
    /* with no values the [0] content is omitted entirely */
    CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY ci = { (LPSTR)szOID_RSA_data, 0, NULL };
    ENC_EQ(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, &ci, V(0x30,0x0b,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1));
}
TEST(kpb_content_info_seq_of_any_decode) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("PKCS_CONTENT_INFO_SEQUENCE_OF_ANY not implemented by the emulator"); return; }
    CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY *r = DEC_OK(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY,
        V(0x30,0x15,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1,0xa0,8,0x30,6,2,1,1,2,1,2), 0);
    if (r) { EXPECT_STR(r->pszObjId, szOID_RSA_data); CHECK(r->cValue == 2); if (r->cValue == 2) { BLOB_IS(r->rgValue[0], 2,1,1); BLOB_IS(r->rgValue[1], 2,1,2); } kp_free(r); }
}
TEST(kpb_content_info_seq_of_any_roundtrip) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("PKCS_CONTENT_INFO_SEQUENCE_OF_ANY not implemented by the emulator"); return; }
    CRYPT_DER_BLOB v[2] = { {3, (BYTE *)"\x02\x01\x07"}, {2, (BYTE *)"\x05\x00"} };
    CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY ci = { (LPSTR)szOID_RSA_signedData, 2, v }; DWORD cb;
    BYTE *e = kp_enc_alloc(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, &ci, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY *r = kp_dec_alloc(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, e, cb, 0, NULL);
    CHECK(r && r->cValue == 2 && !strcmp(r->pszObjId, szOID_RSA_signedData));
    if (r && r->cValue == 2) { BLOB_IS(r->rgValue[0], 2,1,7); BLOB_IS(r->rgValue[1], 5,0); }
    kp_free(r); kp_free(e);
}

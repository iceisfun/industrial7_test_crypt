/* CryptMsgCalculateEncodedLength and CryptBinaryToStringA. */
#include "gap1.h"

/* DER length-octets size (header bytes after the tag) for a content length */
static DWORD lenoct(DWORD n) { return n < 128 ? 1 : n < 256 ? 2 : n < 65536 ? 3 : n < 16777216 ? 4 : 5; }
static DWORD tlv_total(DWORD content) { return 1 + lenoct(content) + content; }
/* expected CMSG_DATA ContentInfo size for cbData payload bytes */
static DWORD data_bare(DWORD cb) { return tlv_total(cb); }
static DWORD data_contentinfo_content(DWORD cb) { DWORD oct = tlv_total(cb); return 11 + tlv_total(oct); }
static DWORD data_contentinfo(DWORD cb) { return tlv_total(data_contentinfo_content(cb)); }

TEST(gap1_msglen_data_exact_sizes) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    static const DWORD sizes[] = { 0, 1, 5, 126, 127, 128, 129, 255, 256, 257, 1000, 65535, 65536, 100000 };
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        DWORD n = sizes[i];
        SET_ERR(0);
        DWORD r = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_DATA, NULL, NULL, n);
        CHECKF(r == data_contentinfo(n), "cbData %lu: got %lu want %lu", n, r, data_contentinfo(n));
        r = U(CryptMsgCalculateEncodedLength)(ENC, CMSG_BARE_CONTENT_FLAG, CMSG_DATA, NULL, NULL, n);
        CHECKF(r == data_bare(n), "bare cbData %lu: got %lu want %lu", n, r, data_bare(n));
    }
}
TEST(gap1_msglen_data_contents_octets_flag) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    /* CMSG_CONTENTS_OCTETS_FLAG returns the length of the contents of the outermost element, not its header */
    for (DWORD n = 0; n < 300; n += 37) {
        DWORD r = U(CryptMsgCalculateEncodedLength)(ENC, CMSG_CONTENTS_OCTETS_FLAG, CMSG_DATA, NULL, NULL, n);
        CHECKF(r == data_contentinfo_content(n), "cbData %lu: got %lu want %lu", n, r, data_contentinfo_content(n));
        r = U(CryptMsgCalculateEncodedLength)(ENC, CMSG_CONTENTS_OCTETS_FLAG | CMSG_BARE_CONTENT_FLAG, CMSG_DATA, NULL, NULL, n);
        CHECKF(r == n, "bare cbData %lu: got %lu", n, r);
    }
}
TEST(gap1_msglen_data_monotonic) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    DWORD prev = 0;
    for (DWORD n = 0; n < 2000; n += 7) {
        DWORD r = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_DATA, NULL, NULL, n);
        CHECK(r >= prev && r > n);
        prev = r;
    }
}
TEST(gap1_msglen_encoding_type_validation) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    static const DWORD bad[] = { 0, X509_ASN_ENCODING, 0x20000, 0x00010000 << 1, 0x80000000 };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        SET_ERR(0);
        DWORD r = U(CryptMsgCalculateEncodedLength)(bad[i], 0, CMSG_DATA, NULL, NULL, 10);
        CHECKF(r == 0, "type %lx -> %lu", bad[i], r);
        EXPECT_ERR(E_INVALIDARG_);
    }
    /* only the upper word is examined */
    static const DWORD good[] = { PKCS_7_ASN_ENCODING, ENC, PKCS_7_ASN_ENCODING | 0x1234 };
    for (unsigned i = 0; i < sizeof good / sizeof *good; i++)
        CHECKF(U(CryptMsgCalculateEncodedLength)(good[i], 0, CMSG_DATA, NULL, NULL, 10) == data_contentinfo(10), "good type %lx", good[i]);
}
TEST(gap1_msglen_data_rejects_encode_info) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    int dummy = 0;
    SET_ERR(0);
    CHECK(U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_DATA, &dummy, NULL, 10) == 0);
    EXPECT_ERR(E_INVALIDARG_);
}
TEST(gap1_msglen_invalid_message_types) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    static const DWORD types[] = { 0, 4, 6, 7, 100, 0xFFFFFFFF };
    int dummy[16] = {0};
    for (unsigned i = 0; i < sizeof types / sizeof *types; i++) {
        SET_ERR(0);
        DWORD r = U(CryptMsgCalculateEncodedLength)(ENC, 0, types[i], dummy, NULL, 10);
        CHECKF(r == 0, "type %lu -> %lu", types[i], r);
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE_);
    }
    /* CMSG_SIGNED_AND_ENVELOPED (4) is not encodable */
    SET_ERR(0);
    CHECK(U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_SIGNED_AND_ENVELOPED, NULL, NULL, 10) == 0);
    EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE_);
}
TEST(gap1_msglen_encoding_checked_before_type) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    SET_ERR(0);
    CHECK(U(CryptMsgCalculateEncodedLength)(0, 0, 4, NULL, NULL, 10) == 0);
    EXPECT_ERR(E_INVALIDARG_);
}
static BOOL setup_signed(CMSG_SIGNER_ENCODE_INFO *si, CMSG_SIGNED_ENCODE_INFO *ei, CERT_BLOB *cb) {
    memset(si, 0, sizeof *si); memset(ei, 0, sizeof *ei);
    si->cbSize = sizeof *si; si->pCertInfo = g1_A.cert->pCertInfo; si->hCryptProv = g1_A.prov; si->dwKeySpec = AT_KEYEXCHANGE;
    si->HashAlgorithm.pszObjId = OID_SHA256;
    ei->cbSize = sizeof *ei; ei->cSigners = 1; ei->rgSigners = si;
    if (cb) { cb->cbData = g1_A.cert->cbCertEncoded; cb->pbData = g1_A.cert->pbCertEncoded; ei->cCertEncoded = 1; ei->rgCertEncoded = cb; }
    return TRUE;
}
static DWORD actual_signed(CMSG_SIGNED_ENCODE_INFO *ei, DWORD flags, const BYTE *data, DWORD n) {
    HCRYPTMSG m = U(CryptMsgOpenToEncode)(ENC, flags, CMSG_SIGNED, ei, NULL, NULL);
    if (!m) return 0;
    DWORD out = 0;
    if (U(CryptMsgUpdate)(m, data, n, TRUE)) {
        DWORD cb = 0;
        if (U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, NULL, &cb)) out = cb;
    }
    U(CryptMsgClose)(m);
    return out;
}
TEST(gap1_msglen_signed_is_upper_bound_of_actual) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB(); REQUIRE(U(CryptMsgOpenToEncode)); G1_INIT();
    CMSG_SIGNER_ENCODE_INFO si; CMSG_SIGNED_ENCODE_INFO ei; CERT_BLOB cb;
    static const DWORD ns[] = { 0, 10, 100, 500, 5000 };
    BYTE *data = calloc(1, 5000); memset(data, 'x', 5000);
    for (int withcert = 0; withcert < 2; withcert++)
        for (unsigned i = 0; i < 5; i++) {
            setup_signed(&si, &ei, withcert ? &cb : NULL);
            DWORD calc = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_SIGNED, &ei, NULL, ns[i]);
            DWORD act = actual_signed(&ei, 0, data, ns[i]);
            t_note("signed cert=%d n=%lu: calculated %lu actual %lu", withcert, ns[i], calc, act);
            CHECKF(calc != 0, "n=%lu", ns[i]);
            if (act) CHECKF(calc >= act, "calc %lu < actual %lu (n=%lu cert=%d)", calc, act, ns[i], withcert);
        }
    free(data);
}
TEST(gap1_msglen_signed_flags_shrink_result) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB(); G1_INIT();
    CMSG_SIGNER_ENCODE_INFO si; CMSG_SIGNED_ENCODE_INFO ei; CERT_BLOB cb;
    setup_signed(&si, &ei, &cb);
    DWORD full = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_SIGNED, &ei, NULL, 1000);
    DWORD det = U(CryptMsgCalculateEncodedLength)(ENC, CMSG_DETACHED_FLAG, CMSG_SIGNED, &ei, NULL, 1000);
    DWORD bare = U(CryptMsgCalculateEncodedLength)(ENC, CMSG_BARE_CONTENT_FLAG, CMSG_SIGNED, &ei, NULL, 1000);
    t_note("signed 1000: full %lu detached %lu bare %lu", full, det, bare);
    CHECK(full > 1000);
    CHECK(bare > 0 && bare < full);
    CHECK(det > 0 && det < full);
    SET_ERR(0);
    DWORD more = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_SIGNED, &ei, NULL, 2000);
    CHECK(more > full);
}
TEST(gap1_msglen_signed_null_encode_info) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    SET_ERR(0);
    DWORD r = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_SIGNED, NULL, NULL, 10);
    CHECK(r == 0);
    DWORD e = GetLastError();
    t_note("signed with NULL encode info -> err 0x%08lx", e);
    r = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_ENVELOPED, NULL, NULL, 10);
    CHECK(r == 0);
    r = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_HASHED, NULL, NULL, 10);
    CHECK(r == 0);
}
TEST(gap1_msglen_hashed_is_upper_bound_of_actual) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB(); REQUIRE(U(CryptMsgOpenToEncode));
    CMSG_HASHED_ENCODE_INFO hi; memset(&hi, 0, sizeof hi);
    hi.cbSize = sizeof hi; hi.HashAlgorithm.pszObjId = OID_SHA256;
    static const DWORD ns[] = { 0, 1, 33, 127, 128, 300 };
    BYTE data[300]; memset(data, 'h', sizeof data);
    for (unsigned i = 0; i < 6; i++) {
        DWORD calc = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_HASHED, &hi, NULL, ns[i]);
        HCRYPTMSG m = U(CryptMsgOpenToEncode)(ENC, 0, CMSG_HASHED, &hi, NULL, NULL);
        DWORD act = 0;
        if (m) {
            if (U(CryptMsgUpdate)(m, data, ns[i], TRUE)) U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, NULL, &act);
            U(CryptMsgClose)(m);
        }
        t_note("hashed n=%lu calc %lu actual %lu", ns[i], calc, act);
        CHECKF(calc > ns[i], "n=%lu calc %lu", ns[i], calc);
        if (act) CHECKF(calc >= act, "calc %lu < actual %lu", calc, act);
    }
}
TEST(gap1_msglen_hashed_unknown_algorithm) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB();
    CMSG_HASHED_ENCODE_INFO hi; memset(&hi, 0, sizeof hi);
    hi.cbSize = sizeof hi; hi.HashAlgorithm.pszObjId = (LPSTR)"1.2.3.4.5.6";
    SET_ERR(0);
    DWORD r = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_HASHED, &hi, NULL, 10);
    t_note("hashed with unknown algorithm OID -> %lu, err 0x%08lx", r, GetLastError());
}
TEST(gap1_msglen_enveloped_is_upper_bound_of_actual) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB(); REQUIRE(U(CryptMsgOpenToEncode)); G1_INIT();
    CMSG_ENVELOPED_ENCODE_INFO ei; memset(&ei, 0, sizeof ei);
    PCERT_INFO rcpt[1] = { g1_A.cert->pCertInfo };
    ei.cbSize = sizeof ei; ei.ContentEncryptionAlgorithm.pszObjId = (LPSTR)"2.16.840.1.101.3.4.1.42";   /* aes256-CBC */
    ei.cRecipients = 1; ei.rgpRecipients = rcpt;
    static const DWORD ns[] = { 0, 1, 15, 16, 17, 100 };
    BYTE data[128]; memset(data, 'e', sizeof data);
    for (unsigned i = 0; i < 6; i++) {
        DWORD calc = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_ENVELOPED, &ei, NULL, ns[i]);
        HCRYPTMSG m = U(CryptMsgOpenToEncode)(ENC, 0, CMSG_ENVELOPED, &ei, NULL, NULL);
        DWORD act = 0;
        if (m) {
            if (U(CryptMsgUpdate)(m, data, ns[i], TRUE)) U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, NULL, &act);
            U(CryptMsgClose)(m);
        }
        t_note("enveloped n=%lu calc %lu actual %lu", ns[i], calc, act);
        CHECKF(calc != 0, "n=%lu", ns[i]);
        if (act) CHECKF(calc >= act, "calc %lu < actual %lu (n=%lu)", calc, act, ns[i]);
    }
}
TEST(gap1_msglen_enveloped_grows_with_recipients) {
    REQUIRE(U(CryptMsgCalculateEncodedLength)); NOWINE_STUB(); G1_INIT();
    CMSG_ENVELOPED_ENCODE_INFO ei; memset(&ei, 0, sizeof ei);
    PCERT_INFO rcpt[2] = { g1_A.cert->pCertInfo, g1_B.cert->pCertInfo };
    ei.cbSize = sizeof ei; ei.ContentEncryptionAlgorithm.pszObjId = (LPSTR)"2.16.840.1.101.3.4.1.42";
    ei.cRecipients = 1; ei.rgpRecipients = rcpt;
    DWORD one = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_ENVELOPED, &ei, NULL, 100);
    ei.cRecipients = 2;
    DWORD two = U(CryptMsgCalculateEncodedLength)(ENC, 0, CMSG_ENVELOPED, &ei, NULL, 100);
    t_note("enveloped 1 recipient %lu, 2 recipients %lu", one, two);
    CHECK(one > 0 && two > one);
}

/* ---------------- CryptBinaryToStringA ---------------- */
static char *b2s(const BYTE *p, DWORD cb, DWORD fl, DWORD *pn) {
    DWORD n = 0;
    if (!U(CryptBinaryToStringA)(p, cb, fl, NULL, &n)) return NULL;
    char *s = malloc(n + 8);
    DWORD m = n;
    if (!U(CryptBinaryToStringA)(p, cb, fl, s, &m)) { free(s); return NULL; }
    if (pn) *pn = m;
    return s;
}
TEST(gap1_b2s_argument_validation) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[4] = {1, 2, 3, 4}; char s[64]; DWORD n = sizeof s;
    SET_ERR(0); CHECK(!U(CryptBinaryToStringA)(NULL, 4, CRYPT_STRING_BASE64, s, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); n = sizeof s; CHECK(!U(CryptBinaryToStringA)(b, 0, CRYPT_STRING_BASE64, s, &n)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptBinaryToStringA)(b, 4, CRYPT_STRING_BASE64, s, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptBinaryToStringA)(b, 4, CRYPT_STRING_BASE64, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(gap1_b2s_unknown_formats_rejected) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[4] = {1, 2, 3, 4}; char s[128];
    static const DWORD bad[] = { 0xE, 0xF, 0x10, 0x20, 0xFF };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        DWORD n = sizeof s;
        SET_ERR(0);
        CHECKF(!U(CryptBinaryToStringA)(b, 4, bad[i], s, &n), "format %lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}
TEST(gap1_b2s_size_query_then_exact_buffer) {
    REQUIRE(U(CryptBinaryToStringA));
    static const DWORD fl[] = { CRYPT_STRING_BASE64HEADER, CRYPT_STRING_BASE64, CRYPT_STRING_BASE64REQUESTHEADER, CRYPT_STRING_HEX,
                                CRYPT_STRING_HEXASCII, CRYPT_STRING_HEXADDR, CRYPT_STRING_HEXASCIIADDR, CRYPT_STRING_HEXRAW, CRYPT_STRING_BINARY };
    BYTE b[37]; for (int i = 0; i < 37; i++) b[i] = (BYTE)(i * 7 + 1);
    for (unsigned i = 0; i < sizeof fl / sizeof *fl; i++) {
        DWORD need = 0;
        SET_ERR(0);
        CHECKF(U(CryptBinaryToStringA)(b, sizeof b, fl[i], NULL, &need), "fmt %lx size query", fl[i]);
        CHECKF(need > 0, "fmt %lx need %lu", fl[i], need);
        char *s = malloc(need + 16); memset(s, 0x7E, need + 16);
        DWORD n = need;
        CHECKF(U(CryptBinaryToStringA)(b, sizeof b, fl[i], s, &n), "fmt %lx exact buffer", fl[i]);
        if (fl[i] != CRYPT_STRING_BINARY) {
            CHECKF(n == need - 1, "fmt %lx: *pcch %lu after success, size query said %lu", fl[i], n, need);
            CHECKF(strlen(s) == n, "fmt %lx: strlen %zu vs %lu", fl[i], strlen(s), n);
        } else CHECKF(n == need, "binary: %lu vs %lu", n, need);
        /* generous buffer gives the same text */
        char *s2 = malloc(need + 100); DWORD n2 = need + 100;
        CHECK(U(CryptBinaryToStringA)(b, sizeof b, fl[i], s2, &n2));
        CHECKF(n2 == n, "fmt %lx: *pcch %lu vs %lu", fl[i], n2, n);
        CHECK(!memcmp(s, s2, n));
        free(s); free(s2);
    }
}
TEST(gap1_b2s_one_char_short_is_more_data) {
    REQUIRE(U(CryptBinaryToStringA));
    static const DWORD fl[] = { CRYPT_STRING_BASE64, CRYPT_STRING_BASE64HEADER, CRYPT_STRING_HEX, CRYPT_STRING_HEXRAW };
    BYTE b[20]; for (int i = 0; i < 20; i++) b[i] = (BYTE)(0xA0 + i);
    for (unsigned i = 0; i < 4; i++) {
        DWORD need = 0; U(CryptBinaryToStringA)(b, sizeof b, fl[i], NULL, &need);
        char *s = malloc(need + 8);
        for (DWORD cap = 1; cap < need; cap += (need > 40 ? need / 7 : 1)) {
            DWORD n = cap; SET_ERR(0);
            BOOL r = U(CryptBinaryToStringA)(b, sizeof b, fl[i], s, &n);
            CHECKF(!r, "fmt %lx cap %lu/%lu unexpectedly succeeded", fl[i], cap, need);
            EXPECT_ERR(ERROR_MORE_DATA);
        }
        DWORD n = need - 1; SET_ERR(0);
        CHECKF(!U(CryptBinaryToStringA)(b, sizeof b, fl[i], s, &n), "fmt %lx cap need-1", fl[i]);
        EXPECT_ERR(ERROR_MORE_DATA);
        t_note("fmt %lx: need %lu, *pcch after ERROR_MORE_DATA at need-1 = %lu", fl[i], need, n);
        free(s);
    }
}
TEST(gap1_b2s_base64_known_answers) {
    REQUIRE(U(CryptBinaryToStringA));
    static const struct { const char *in; const char *out; } v[] = {
        { "M", "TQ==" }, { "Ma", "TWE=" }, { "Man", "TWFu" }, { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" },
    };
    for (unsigned i = 0; i < 6; i++) {
        DWORD n = 0;
        char *s = b2s((const BYTE *)v[i].in, (DWORD)strlen(v[i].in), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &n);
        CHECK(s != NULL);
        if (s) { CHECKF(!strcmp(s, v[i].out), "got '%s' want '%s'", s, v[i].out); free(s); }
        s = b2s((const BYTE *)v[i].in, (DWORD)strlen(v[i].in), CRYPT_STRING_BASE64, &n);
        char want[32]; snprintf(want, sizeof want, "%s\r\n", v[i].out);
        if (s) { CHECKF(!strcmp(s, want), "CRLF form of '%s'", v[i].in); free(s); }
        s = b2s((const BYTE *)v[i].in, (DWORD)strlen(v[i].in), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, &n);
        snprintf(want, sizeof want, "%s\n", v[i].out);
        if (s) { CHECKF(!strcmp(s, want), "LF form of '%s'", v[i].in); free(s); }
    }
}
TEST(gap1_b2s_base64_headers) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[3] = { 'M', 'a', 'n' };
    DWORD n; char *s;
    s = b2s(b, 3, CRYPT_STRING_BASE64HEADER, &n);
    if (s) { CHECK(!strcmp(s, "-----BEGIN CERTIFICATE-----\r\nTWFu\r\n-----END CERTIFICATE-----\r\n")); free(s); } else CHECK(s);
    s = b2s(b, 3, CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCR, &n);
    if (s) { CHECK(!strcmp(s, "-----BEGIN CERTIFICATE-----\nTWFu\n-----END CERTIFICATE-----\n")); free(s); } else CHECK(s);
    s = b2s(b, 3, CRYPT_STRING_BASE64REQUESTHEADER, &n);
    if (s) { CHECK(!strcmp(s, "-----BEGIN NEW CERTIFICATE REQUEST-----\r\nTWFu\r\n-----END NEW CERTIFICATE REQUEST-----\r\n")); free(s); } else CHECK(s);
    s = b2s(b, 3, CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCRLF, &n);
    if (s) { t_note("BASE64HEADER|NOCRLF -> '%s'", s); CHECK(strstr(s, "TWFu") != NULL); free(s); } else CHECK(s);
}
TEST(gap1_b2s_base64_line_wrapping) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[100]; for (int i = 0; i < 100; i++) b[i] = (BYTE)i;
    DWORD n; char *s = b2s(b, 100, CRYPT_STRING_BASE64, &n); REQUIRE(s);
    /* 64 characters per line, each line ended by CRLF */
    int lines = 0; const char *p = s; int ok = 1;
    while (*p) {
        const char *e = strstr(p, "\r\n"); if (!e) { ok = 0; break; }
        size_t len = (size_t)(e - p); lines++;
        if (len > 64 || (*(e + 2) != 0 && len != 64)) ok = 0;
        p = e + 2;
    }
    CHECK(ok); CHECKF(lines == 3, "lines %d", lines);   /* ceil(136/64) */
    free(s);
}
TEST(gap1_b2s_binary_format_copies_bytes) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[10] = { 0, 1, 2, 3, 0, 0xFF, 0x80, 0x7F, 9, 0 };
    DWORD need = 0; CHECK(U(CryptBinaryToStringA)(b, 10, CRYPT_STRING_BINARY, NULL, &need));
    EXPECT_EQ(need, 10);
    BYTE out[16]; memset(out, 0x55, sizeof out); DWORD n = 10;
    CHECK(U(CryptBinaryToStringA)(b, 10, CRYPT_STRING_BINARY, (LPSTR)out, &n));
    EXPECT_EQ(n, 10); CHECK(!memcmp(out, b, 10)); CHECK(out[10] == 0x55);
    n = 9; SET_ERR(0);
    CHECK(!U(CryptBinaryToStringA)(b, 10, CRYPT_STRING_BINARY, (LPSTR)out, &n)); EXPECT_ERR(ERROR_MORE_DATA);
}
TEST(gap1_b2s_alias_formats_follow_decomp) {
    /* formats 6 (BASE64_ANY) and 7 (ANY) encode as plain base64; 8 (HEX_ANY) as hex; 3 as a request header */
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[5] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01 };
    DWORD n; char *ref64 = b2s(b, 5, CRYPT_STRING_BASE64, &n), *ref16 = b2s(b, 5, CRYPT_STRING_HEX, &n);
    REQUIRE(ref64 && ref16);
    char *s = b2s(b, 5, CRYPT_STRING_BASE64_ANY, &n); CHECK(s && !strcmp(s, ref64)); free(s);
    s = b2s(b, 5, CRYPT_STRING_ANY, &n); CHECK(s && !strcmp(s, ref64)); free(s);
    s = b2s(b, 5, CRYPT_STRING_HEX_ANY, &n); CHECK(s && !strcmp(s, ref16)); free(s);
    free(ref64); free(ref16);
}
TEST(gap1_b2s_hex_layouts) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[3] = { 0x01, 0xAB, 0xFF }; DWORD n; char *s;
    s = b2s(b, 3, CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF, &n);
    if (s) { t_note("HEX|NOCRLF = '%s'", s); CHECK(!_stricmp(s, "01 ab ff ") || !_stricmp(s, "01 ab ff")); free(s); } else CHECK(s);
    s = b2s(b, 3, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, &n);
    if (s) { t_note("HEXRAW|NOCRLF = '%s'", s); CHECK(!_stricmp(s, "01abff")); free(s); } else CHECK(s);
    s = b2s(b, 3, CRYPT_STRING_HEXRAW, &n);
    if (s) { CHECK(!_stricmp(s, "01abff\r\n")); free(s); } else CHECK(s);
}
TEST(gap1_b2s_hashdata_flag) {
    /* flag 0x10000000: the input is hashed with SHA-1 first and the 20-byte digest is encoded */
    REQUIRE(U(CryptBinaryToStringA));
    const BYTE abc[3] = { 'a', 'b', 'c' };
    DWORD n; char *s = b2s(abc, 3, CRYPT_STRING_HEXRAW | 0x10000000 | CRYPT_STRING_NOCRLF, &n);
    REQUIRE(s);
    CHECK(!_stricmp(s, "a9993e364706816aba3e25717850c26c9cd0d89d"));
    CHECK(n == 40);
    free(s);
    s = b2s(abc, 3, CRYPT_STRING_BINARY | 0x10000000, &n);
    if (s) { static const BYTE sha1abc[20] = {0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d};
        CHECK(n == 20 && !memcmp(s, sha1abc, 20)); free(s); } else CHECK(s);
    s = b2s(abc, 3, CRYPT_STRING_BASE64 | 0x10000000 | CRYPT_STRING_NOCRLF, &n);
    if (s) { CHECK(!strcmp(s, "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=")); free(s); } else CHECK(s);
}
TEST(gap1_b2s_binary_input_with_embedded_zero) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[6] = { 0, 0, 0, 0, 0, 0 };
    DWORD n; char *s = b2s(b, 6, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &n);
    REQUIRE(s); CHECK(!strcmp(s, "AAAAAAAA")); free(s);
}
TEST(gap1_b2s_nocrlf_precedence) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[3] = { 'M', 'a', 'n' };
    DWORD n; char *s = b2s(b, 3, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF | CRYPT_STRING_NOCR, &n);
    if (s) { CHECK(!strcmp(s, "TWFu")); free(s); } else CHECK(s);
}
TEST(gap1_b2s_base64uri_note) {
    REQUIRE(U(CryptBinaryToStringA));
    BYTE b[4] = { 0xFB, 0xFF, 0xBF, 0xFE };
    DWORD n; char *s = b2s(b, 4, CRYPT_STRING_BASE64URI | CRYPT_STRING_NOCRLF, &n);
    if (s) { t_note("BASE64URI(fb ff bf fe) = '%s'", s); CHECK(!strchr(s, '+') && !strchr(s, '/')); free(s); }
    else t_note("BASE64URI encode unsupported: err %lu", GetLastError());
}

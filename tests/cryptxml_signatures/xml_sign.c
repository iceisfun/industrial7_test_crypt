/* cryptxml.dll: CryptXmlSign (HMAC), CryptXmlEncode and the produced Signature XML. */
#include "xml.h"
#include <stdlib.h>

static const XALG A_SHA1   = { sizeof(XALG), U_SHA1,   {0, 0, NULL} };
static const XALG A_SHA256 = { sizeof(XALG), U_SHA256, {0, 0, NULL} };
static const XALG A_C14N   = { sizeof(XALG), U_C14N,   {0, 0, NULL} };
static const XALG A_EXC    = { sizeof(XALG), U_EXC,    {0, 0, NULL} };
static const XALG A_HMAC256 = { sizeof(XALG), U_HMAC256, {0, 0, NULL} };

typedef struct { const WCHAR *sigmeth, *digmeth; const WCHAR *bcDig; const char *name; ULONG dlen; } HROW;
static const HROW HROWS[] = {
    { U_HMAC1, U_SHA1, L"SHA1", "hmac-sha1", 20 }, { U_HMAC256, U_SHA256, L"SHA256", "hmac-sha256", 32 },
    { U_HMAC384, U_SHA384, L"SHA384", "hmac-sha384", 48 }, { U_HMAC512, U_SHA512, L"SHA512", "hmac-sha512", 64 } };

static HCX open_enc(const WCHAR *id)
{
    HCX h = NULL;
    if (XFN(CryptXmlOpenToEncode)(NULL, 0, id, NULL, 0, NULL, &h) != S_OK) return NULL;
    return h;
}

/* one external reference (URI urn:cryptt:data, data digested by us), HMAC secret set; not yet signed */
static HCX prepare(const WCHAR *digmeth, const char *data, const WCHAR *sigId, const WCHAR *refId, const WCHAR *type)
{
    HCX hs = open_enc(sigId), hr = NULL;
    XALG d = { sizeof d, digmeth, {0, 0, NULL} };
    XMEM m; XPROV pv;
    if (!hs) return NULL;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, refId, L"urn:cryptt:data", type, &d, 0, NULL, &hr), S_OK);
    x_prov(&pv, &m, data, strlen(data), 0);
    if (hr) XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, X_SECRET, X_SECRET_len), S_OK);
    return hs;
}
static HRESULT sign_hmac(HCX hs, const WCHAR *sigmeth, const WCHAR *canon)
{
    XALG sm = { sizeof sm, sigmeth, {0, 0, NULL} }, cn = { sizeof cn, canon, {0, 0, NULL} };
    return XFN(CryptXmlSign)(hs, 0, 0, 0, X_KEYINFO_NONE, NULL, &sm, &cn);
}
static HRESULT encode_to(HCX hs, DWORD cs, const XPROP *p, ULONG cp, XBUF *b)
{
    memset(b, 0, sizeof *b);
    return XFN(CryptXmlEncode)(hs, cs, p, cp, b, x_write_cb);
}
/* sign + encode with the standard flow; returns output text in b (caller frees) */
static int signed_text(const HROW *row, const WCHAR *canon, const char *data, XBUF *b)
{
    HCX hs = prepare(row->digmeth, data, L"sig1", L"ref1", NULL);
    int ok = 0;
    memset(b, 0, sizeof *b);
    if (!hs) return 0;
    XCHK_HR(sign_hmac(hs, row->sigmeth, canon), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, b), S_OK);
    ok = b->n > 0;
    XFN(CryptXmlClose)(hs);
    return ok;
}

/* ---- CryptXmlSign argument validation --------------------------------------------------------- */
TEST(xmlsig_sign_null_arguments)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = open_enc(L"s");
    XALG nullalg = { sizeof(XALG), NULL, {0, 0, NULL} };
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlSign)(NULL, 0, 0, 0, 0, NULL, &A_HMAC256, &A_C14N), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, 0, 0, NULL, NULL, &A_C14N), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, 0, 0, NULL, &A_HMAC256, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, 0, 0, NULL, &nullalg, &A_C14N), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, 0, 0, NULL, &A_HMAC256, &nullalg), X_E_INVALIDARG);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_wrong_handle_type)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XSIG *s = x_first_sig(h);
    XCHK_HR(XFN(CryptXmlSign)(h, 0, 0, 0, 0, NULL, &A_HMAC256, &A_C14N), X_E_HANDLE);          /* document */
    if (s) {
        XCHK_HR(XFN(CryptXmlSign)(s->hSignature, 0, 0, 0, 0, NULL, &A_HMAC256, &A_C14N), X_E_HANDLE);   /* decoded signature */
        XCHK_HR(XFN(CryptXmlSign)(s->SignedInfo.rgpReference[0]->hReference, 0, 0, 0, 0, NULL, &A_HMAC256, &A_C14N), X_E_HANDLE);
    }
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_sign_unsupported_signature_methods)
{
    REQUIRE(XFN(CryptXmlSign));
    const WCHAR *bad[] = { U_SHA256, U_C14N, U_ENVELOPED, L"urn:cryptt:unknown", L"http://www.w3.org/2001/04/xmldsig-more#hmac-md5",
                           L"http://www.w3.org/2001/04/xmldsig-more#rsa-sha224" };
    for (int i = 0; i < 6; i++) {
        HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
        if (!hs) return;
        XALG sm = { sizeof sm, bad[i], {0, 0, NULL} };
        HRESULT hr = XFN(CryptXmlSign)(hs, 0, 0, 0, 0, NULL, &sm, &A_C14N);
        CHECKF(hr == X_E_ALGORITHM, "method %ls hr=0x%08lx", bad[i], (unsigned long)hr);
        XFN(CryptXmlClose)(hs);
    }
}

TEST(xmlsig_sign_none_keyinfo_rejects_parameter)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    int dummy = 0;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, 0, X_KEYINFO_NONE, &dummy, &A_HMAC256, &A_C14N), X_E_INVALIDARG);
    /* the failed attempt has already marked the signature as failed: it cannot be signed any more */
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), X_E_OPERATION);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_add_keyvalue_conflicts_with_encoded_keyinfo)
{
    REQUIRE(XFN(CryptXmlSign));
    static const char ki[] = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>k</KeyName></KeyInfo>";
    XBLOB b = { X_CS_UTF8, (ULONG)sizeof(ki) - 1, (BYTE *)ki };
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, X_SIGN_ADD_KEYVALUE, X_KEYINFO_ENCODED, &b, &A_HMAC256, &A_C14N), X_E_INVALIDARG);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_requires_digested_external_references)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = open_enc(L"s"), hr = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:cryptt:data", NULL, &A_SHA256, 0, NULL, &hr), S_OK);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, X_SECRET, X_SECRET_len), S_OK);
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), X_E_UNRESOLVED_REF);     /* no digest was supplied for the external URI */
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_null_uri_reference_is_unresolved)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = open_enc(L"s"), hr = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, NULL, NULL, &A_SHA256, 0, NULL, &hr), S_OK);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, X_SECRET, X_SECRET_len), S_OK);
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), X_E_UNRESOLVED_REF);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_twice_is_refused)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), X_E_OPERATION);
    XCHK_HR(sign_hmac(hs, U_HMAC1, U_C14N), X_E_OPERATION);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_status_after_signing)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    if (!hs) return;
    XSTATUS st; x_status(hs, &st);
    EXPECT_EQ(st.dwInfoStatus, XS_I_OPENED_TO_ENCODE | XS_I_DIGEST_VALID);      /* digest done, not signed yet */
    EXPECT_EQ(st.dwErrorStatus, 0);
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    x_status(hs, &st);
    EXPECT_EQ(st.dwInfoStatus, XS_I_OPENED_TO_ENCODE | XS_I_DIGEST_VALID | XS_I_SIGNATURE_VALID);
    EXPECT_EQ(st.dwErrorStatus, 0);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_populates_signature_struct)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_EXC), S_OK);
    const XSIG *s = NULL;
    XCHK_HR(XFN(CryptXmlGetSignature)(hs, &s), S_OK);
    if (s) {
        CHECK(s->SignedInfo.Canonicalization.wszAlgorithm && !lstrcmpW(s->SignedInfo.Canonicalization.wszAlgorithm, U_EXC));
        CHECK(s->SignedInfo.SignatureMethod.wszAlgorithm && !lstrcmpW(s->SignedInfo.SignatureMethod.wszAlgorithm, U_HMAC256));
        EXPECT_EQ(s->SignedInfo.cReference, 1);
        EXPECT_EQ(s->SignatureValue.cbData, 32);          /* HMAC-SHA256 is not truncated */
        CHECK(s->SignatureValue.pbData != NULL);
    }
    XFN(CryptXmlClose)(hs);
}

/* ---- HMAC signing, all four methods ------------------------------------------------------------- */
#define HMAC_TESTS(IDX) \
TEST(xmlsig_sign_hmac_known_values_##IDX) \
{ \
    REQUIRE(XFN(CryptXmlSign)); \
    const HROW *row = &HROWS[IDX]; \
    XBUF b; \
    t_note("method %s", row->name); \
    if (!signed_text(row, U_C14N, "abc", &b)) { x_buf_free(&b); return; } \
    const char *out = x_buf_str(&b); \
    BYTE want[64]; ULONG wl = 0; \
    char *dv = x_elem_text(out, "DigestValue"), *sv = x_elem_text(out, "SignatureValue"); \
    CHECK(dv != NULL); CHECK(sv != NULL); \
    if (x_hash(row->bcDig, NULL, 0, "abc", 3, want, &wl) && dv) { \
        char *e = x_b64(want, wl); \
        CHECKF(!strcmp(dv, e), "DigestValue %s want %s", dv, e); free(e); } \
    char *canon = x_canon_signedinfo(out); \
    CHECK(canon != NULL); \
    if (canon && sv && x_hash(row->bcDig, X_SECRET, X_SECRET_len, canon, strlen(canon), want, &wl)) { \
        char *e = x_b64(want, wl); \
        CHECKF(!strcmp(sv, e), "SignatureValue %s want %s (canonical SignedInfo %s)", sv, e, canon); \
        EXPECT_EQ(wl, row->dlen); free(e); } \
    free(canon); free(dv); free(sv); x_buf_free(&b); \
}
HMAC_TESTS(0)
HMAC_TESTS(1)
HMAC_TESTS(2)
HMAC_TESTS(3)

TEST(xmlsig_sign_hmac_depends_on_secret)
{
    REQUIRE(XFN(CryptXmlSign));
    static const BYTE k2[] = "another-secret";
    XBUF a, b;
    HCX h1 = prepare(U_SHA256, "abc", L"s", L"r", NULL), h2 = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    if (!h1 || !h2) return;
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(h2, k2, 14), S_OK);
    XCHK_HR(sign_hmac(h1, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(sign_hmac(h2, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(encode_to(h1, X_CS_UTF8, NULL, 0, &a), S_OK);
    XCHK_HR(encode_to(h2, X_CS_UTF8, NULL, 0, &b), S_OK);
    char *s1 = x_elem_text(x_buf_str(&a), "SignatureValue"), *s2 = x_elem_text(x_buf_str(&b), "SignatureValue");
    CHECK(s1 && s2 && strcmp(s1, s2) != 0);
    char *d1 = x_elem_text(x_buf_str(&a), "DigestValue"), *d2 = x_elem_text(x_buf_str(&b), "DigestValue");
    CHECK(d1 && d2 && !strcmp(d1, d2));
    free(s1); free(s2); free(d1); free(d2); x_buf_free(&a); x_buf_free(&b);
    XFN(CryptXmlClose)(h1); XFN(CryptXmlClose)(h2);
}

TEST(xmlsig_sign_hmac_secret_is_referenced_not_copied)
{
    REQUIRE(XFN(CryptXmlSign));
    /* CryptXmlSetHMACSecret keeps the caller's pointer: the buffer must stay valid and is read at sign time */
    static BYTE sec[16];
    memcpy(sec, "0123456789abcdef", 16);
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, sec, 16), S_OK);
    memcpy(sec, "FEDCBA9876543210", 16);                    /* changed after the call, before signing */
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XBUF b;
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    char *canon = x_canon_signedinfo(x_buf_str(&b)), *sv = x_elem_text(x_buf_str(&b), "SignatureValue");
    BYTE want[32]; ULONG wl;
    if (canon && sv && x_hash(L"SHA256", sec, 16, canon, strlen(canon), want, &wl)) {
        char *e = x_b64(want, wl);
        CHECKF(!strcmp(sv, e), "signature does not use the current buffer contents");
        free(e);
    }
    free(canon); free(sv); x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_canonicalization_methods)
{
    REQUIRE(XFN(CryptXmlSign));
    const WCHAR *cn[] = { U_C14N, U_EXC };
    const char *want[] = { "http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"", "http://www.w3.org/2001/10/xml-exc-c14n#\"" };
    for (int i = 0; i < 2; i++) {
        XBUF b;
        if (!signed_text(&HROWS[1], cn[i], "abc", &b)) { x_buf_free(&b); continue; }
        CHECKF(x_find(x_buf_str(&b), want[i]), "canonicalization URI %d missing", i);
        char *canon = x_canon_signedinfo(x_buf_str(&b)), *sv = x_elem_text(x_buf_str(&b), "SignatureValue");
        BYTE h[32]; ULONG hl;
        if (canon && sv && x_hash(L"SHA256", X_SECRET, X_SECRET_len, canon, strlen(canon), h, &hl)) {
            char *e = x_b64(h, hl);
            CHECKF(!strcmp(sv, e), "canonicalization %d: SignatureValue mismatch", i);
            free(e);
        }
        free(canon); free(sv); x_buf_free(&b);
    }
}

TEST(xmlsig_sign_two_references)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = open_enc(L"s"), h1 = NULL, h2 = NULL;
    XMEM m; XPROV pv;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"r1", L"urn:cryptt:one", NULL, &A_SHA256, 0, NULL, &h1), S_OK);
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"r2", L"urn:cryptt:two", NULL, &A_SHA1, 0, NULL, &h2), S_OK);
    x_prov(&pv, &m, "abc", 3, 0); XCHK_HR(XFN(CryptXmlDigestReference)(h1, 0, &pv), S_OK);
    x_prov(&pv, &m, "abc", 3, 0); XCHK_HR(XFN(CryptXmlDigestReference)(h2, 0, &pv), S_OK);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, X_SECRET, X_SECRET_len), S_OK);
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XBUF b;
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    const char *o = x_buf_str(&b);
    char *e1 = x_b64(X_ABC_SHA256, 32), *e2 = x_b64(X_ABC_SHA1, 20);
    const char *p1 = strstr(o, "urn:cryptt:one"), *p2 = strstr(o, "urn:cryptt:two");
    CHECK(p1 && p2 && p1 < p2);                    /* creation order is preserved */
    CHECK(strstr(o, e1) != NULL); CHECK(strstr(o, e2) != NULL);
    free(e1); free(e2);
    char *canon = x_canon_signedinfo(o), *sv = x_elem_text(o, "SignatureValue");
    BYTE h[32]; ULONG hl;
    if (canon && sv && x_hash(L"SHA256", X_SECRET, X_SECRET_len, canon, strlen(canon), h, &hl)) {
        char *e = x_b64(h, hl); CHECK(!strcmp(sv, e)); free(e);
    }
    free(canon); free(sv); x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

/* ---- CryptXmlEncode ----------------------------------------------------------------------------- */
TEST(xmlsig_encode_argument_validation)
{
    REQUIRE(XFN(CryptXmlEncode));
    XBUF b = {0};
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlEncode)(NULL, X_CS_UTF8, NULL, 0, &b, x_write_cb), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlEncode)(hs, X_CS_UTF8, NULL, 0, &b, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlEncode)(hs, X_CS_UTF8, NULL, 1, &b, x_write_cb), X_E_INVALIDARG);
    EXPECT_EQ(b.calls, 0);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_wrong_handle_type)
{
    REQUIRE(XFN(CryptXmlEncode));
    XBUF b = {0};
    HCX h = NULL, hs = open_enc(L"s"), hr = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (h) XCHK_HR(XFN(CryptXmlEncode)(h, X_CS_UTF8, NULL, 0, &b, x_write_cb), X_E_HANDLE);   /* a document handle */
    if (hs) {
        XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:x", NULL, &A_SHA256, 0, NULL, &hr), S_OK);
        if (hr) XCHK_HR(XFN(CryptXmlEncode)(hr, X_CS_UTF8, NULL, 0, &b, x_write_cb), X_E_HANDLE);
        XFN(CryptXmlClose)(hs);
    }
    EXPECT_EQ(b.calls, 0);
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_encode_output_structure)
{
    REQUIRE(XFN(CryptXmlEncode));
    XBUF b;
    if (!signed_text(&HROWS[1], U_C14N, "abc", &b)) { x_buf_free(&b); return; }
    const char *o = x_buf_str(&b);
    CHECK(b.calls >= 1);
    t_note("encoded signature (%zu bytes): %.600s", b.n, o);
    const char *seq[] = { "<Signature", "http://www.w3.org/2000/09/xmldsig#", "<SignedInfo", "<CanonicalizationMethod",
                          "<SignatureMethod", "<Reference", "<DigestMethod", "<DigestValue", "</Reference>", "</SignedInfo>",
                          "<SignatureValue", "</Signature>" };
    const char *pos = o;
    for (int i = 0; i < 12; i++) {
        const char *q = strstr(pos, seq[i]);
        CHECKF(q != NULL, "element %s not found after previous element", seq[i]);
        if (!q) break;
        pos = q + 1;
    }
    CHECK(x_find(o, "Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\""));
    CHECK(x_find(o, "Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\""));
    CHECK(x_find(o, "Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\""));
    CHECK(x_find(o, "URI=\"urn:cryptt:data\""));
    CHECK(x_find(o, "Id=\"sig1\""));
    CHECK(x_find(o, "Id=\"ref1\""));
    CHECK(!x_find(o, "<KeyInfo"));
    char *dv = x_elem_text(o, "DigestValue");
    char *want = x_b64(X_ABC_SHA256, 32);
    CHECKF(dv && !strcmp(dv, want), "DigestValue %s", dv ? dv : "(none)");
    free(dv); free(want); x_buf_free(&b);
}

TEST(xmlsig_encode_output_is_stable)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XBUF a, b;
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &a), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    CHECK(a.n > 0 && a.n == b.n && !memcmp(a.p, b.p, a.n));
    x_buf_free(&a); x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_reference_type_attribute)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", L"urn:cryptt:type");
    XBUF b;
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    CHECK(x_find(x_buf_str(&b), "Type=\"urn:cryptt:type\""));
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_empty_signature_id_omits_attribute)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", L"", L"r", NULL);
    XBUF b;
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    const char *o = x_buf_str(&b), *sig = strstr(o, "<Signature"), *gt = sig ? strchr(sig, '>') : NULL;
    CHECK(sig && gt);
    if (sig && gt) {
        char start[512]; size_t l = (size_t)(gt - sig + 1);
        if (l >= sizeof start) l = sizeof start - 1;
        memcpy(start, sig, l); start[l] = 0;
        CHECKF(!x_find(start, " Id="), "Signature start tag has an Id: %s", start);
    }
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_null_signature_id)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", NULL, L"r", NULL);
    XBUF b;
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    const char *sig = strstr(x_buf_str(&b), "<Signature"), *gt = sig ? strchr(sig, '>') : NULL;
    if (sig && gt) t_note("start tag with NULL Id: %.*s", (int)(gt - sig + 1), sig);
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_document_declaration_property)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XBUF b;
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    BOOL no = FALSE, yes = TRUE;
    XPROP pno = { X_PROP_DOC_DECL, &no, 4 }, pyes = { X_PROP_DOC_DECL, &yes, 4 };
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    t_note("default output starts with: %.40s", x_buf_str(&b));
    x_buf_free(&b);
    XCHK_HR(encode_to(hs, X_CS_UTF8, &pno, 1, &b), S_OK);
    CHECK(strncmp(x_buf_str(&b), "<?xml", 5) != 0);
    CHECK(x_find(x_buf_str(&b), "<Signature"));
    x_buf_free(&b);
    XCHK_HR(encode_to(hs, X_CS_UTF8, &pyes, 1, &b), S_OK);
    CHECK(strncmp(x_buf_str(&b), "<?xml", 5) == 0);
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_utf16_charsets)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XBUF u8, u16;
    BOOL no = FALSE;
    XPROP pno = { X_PROP_DOC_DECL, &no, 4 };
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, &pno, 1, &u8), S_OK);
    for (int be = 0; be < 2; be++) {
        XCHK_HR(encode_to(hs, be ? X_CS_UTF16BE : X_CS_UTF16LE, &pno, 1, &u16), S_OK);
        size_t off = 0, i;
        if (u16.n >= 2 && ((u16.p[0] == 0xFF && u16.p[1] == 0xFE) || (u16.p[0] == 0xFE && u16.p[1] == 0xFF))) { off = 2; t_note("UTF-16 output starts with a BOM"); }
        CHECKF(u16.n - off == u8.n * 2, "utf16 %zu bytes vs utf8 %zu", u16.n - off, u8.n);
        if (u16.n - off == u8.n * 2) {
            int same = 1;
            for (i = 0; i < u8.n; i++) {
                BYTE hi = u16.p[off + i * 2 + (be ? 0 : 1)], lo = u16.p[off + i * 2 + (be ? 1 : 0)];
                if (hi != 0 || lo != u8.p[i]) { same = 0; break; }
            }
            CHECKF(same, "utf16%s text differs from utf8 text", be ? "be" : "le");
        }
        x_buf_free(&u16);
    }
    x_buf_free(&u8);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_charset_property_overrides_nothing)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XBUF a, b;
    BOOL no = FALSE;
    XPROP pno = { X_PROP_DOC_DECL, &no, 4 };
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    XCHK_HR(encode_to(hs, X_CS_AUTO, &pno, 1, &a), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, &pno, 1, &b), S_OK);
    t_note("charset AUTO output: %zu bytes, UTF8 output: %zu bytes, identical=%d", a.n, b.n, a.n == b.n && !memcmp(a.p, b.p, a.n));
    x_buf_free(&a); x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_write_callback_failure_is_propagated)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XBUF b = {0};
    if (!hs) return;
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);
    b.fail_with = 0x80004005;
    HRESULT hr = XFN(CryptXmlEncode)(hs, X_CS_UTF8, NULL, 0, &b, x_write_cb);
    CHECK(FAILED(hr));
    CHECK(b.calls >= 1);
    t_note("encode with failing writer -> 0x%08lx after %d calls", (unsigned long)hr, b.calls);
    b.fail_with = 0;
    XBUF c;
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &c), S_OK);       /* the handle is still usable afterwards */
    x_buf_free(&c);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_before_sign)
{
    REQUIRE(XFN(CryptXmlEncode));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XBUF b;
    if (!hs) return;
    HRESULT hr = encode_to(hs, X_CS_UTF8, NULL, 0, &b);
    t_note("encode of an unsigned signature -> 0x%08lx, %zu bytes, SignatureValue present=%d", (unsigned long)hr, b.n, x_find(x_buf_str(&b), "SignatureValue"));
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

/* ---- encode -> decode -> verify round trips ------------------------------------------------------ */
TEST(xmlsig_roundtrip_decode_fields)
{
    REQUIRE(XFN(CryptXmlEncode));
    XBUF b;
    if (!signed_text(&HROWS[1], U_C14N, "abc", &b)) { x_buf_free(&b); return; }
    HCX h = NULL;
    XCHK_HR(x_decode(x_buf_str(&b), NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    CHECK(s != NULL);
    if (s) {
        CHECK(s->wszId && !lstrcmpW(s->wszId, L"sig1"));
        CHECK(!lstrcmpW(s->SignedInfo.Canonicalization.wszAlgorithm, U_C14N));
        CHECK(!lstrcmpW(s->SignedInfo.SignatureMethod.wszAlgorithm, U_HMAC256));
        EXPECT_EQ(s->SignedInfo.cReference, 1);
        EXPECT_EQ(s->SignatureValue.cbData, 32);
        const XREF *r = s->SignedInfo.rgpReference[0];
        CHECK(r->wszId && !lstrcmpW(r->wszId, L"ref1"));
        CHECK(r->wszUri && !lstrcmpW(r->wszUri, L"urn:cryptt:data"));
        CHECK(!lstrcmpW(r->DigestMethod.wszAlgorithm, U_SHA256));
        EXPECT_EQ(r->DigestValue.cbData, 32);
        if (r->DigestValue.cbData == 32) CHECK(!memcmp(r->DigestValue.pbData, X_ABC_SHA256, 32));
        EXPECT_EQ(s->pKeyInfo, NULL);
        EXPECT_EQ(s->cObject, 0);
    }
    if (h) XFN(CryptXmlClose)(h);
    x_buf_free(&b);
}

TEST(xmlsig_roundtrip_verify_hmac_and_external_digest)
{
    REQUIRE(XFN(CryptXmlEncode));
    XBUF b;
    if (!signed_text(&HROWS[1], U_C14N, "abc", &b)) { x_buf_free(&b); return; }
    HCX h = NULL;
    XCHK_HR(x_decode(x_buf_str(&b), NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (!s) { x_buf_free(&b); if (h) XFN(CryptXmlClose)(h); return; }
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, X_SECRET, X_SECRET_len), S_OK);
    XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
    XSTATUS st; x_status(s->hSignature, &st);
    /* the external reference was not resolved by Verify: only the signature itself is validated */
    CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) != 0);
    EXPECT_EQ(st.dwErrorStatus, XS_E_NOT_RESOLVED);
    /* now supply the referenced data ourselves */
    HCX hr = s->SignedInfo.rgpReference[0]->hReference;
    XMEM m; XPROV pv;
    x_prov(&pv, &m, "abc", 3, 0);
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
    x_status(hr, &st);
    EXPECT_EQ(st.dwErrorStatus, 0);
    CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) != 0);
    x_status(s->hSignature, &st);
    EXPECT_EQ(st.dwErrorStatus, 0);
    EXPECT_EQ(st.dwInfoStatus, XS_I_SIGNATURE_VALID | XS_I_DIGEST_VALID);
    x_status(h, &st);
    EXPECT_EQ(st.dwErrorStatus, 0);
    EXPECT_EQ(st.dwInfoStatus, XS_I_SIGNATURE_VALID);
    XFN(CryptXmlClose)(h);
    x_buf_free(&b);
}

TEST(xmlsig_roundtrip_wrong_external_data_flags_digest)
{
    REQUIRE(XFN(CryptXmlEncode));
    XBUF b;
    if (!signed_text(&HROWS[1], U_C14N, "abc", &b)) { x_buf_free(&b); return; }
    HCX h = NULL;
    XCHK_HR(x_decode(x_buf_str(&b), NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (!s) { x_buf_free(&b); if (h) XFN(CryptXmlClose)(h); return; }
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, X_SECRET, X_SECRET_len), S_OK);
    XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
    HCX hr = s->SignedInfo.rgpReference[0]->hReference;
    XMEM m; XPROV pv;
    x_prov(&pv, &m, "abd", 3, 0);                      /* not the data that was signed */
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);   /* a mismatch is reported through the status */
    XSTATUS st; x_status(hr, &st);
    EXPECT_EQ(st.dwErrorStatus, XS_E_DIGEST_INVALID);
    CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) == 0);
    x_status(s->hSignature, &st);
    EXPECT_EQ(st.dwErrorStatus, XS_E_DIGEST_INVALID);
    CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) != 0);
    XFN(CryptXmlClose)(h);
    x_buf_free(&b);
}

TEST(xmlsig_roundtrip_wrong_secret_fails)
{
    REQUIRE(XFN(CryptXmlEncode));
    static const BYTE bad[] = "not-the-secret";
    XBUF b;
    if (!signed_text(&HROWS[1], U_C14N, "abc", &b)) { x_buf_free(&b); return; }
    HCX h = NULL;
    XCHK_HR(x_decode(x_buf_str(&b), NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s) {
        XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, bad, 14), S_OK);
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), X_E_VERIFY_FAILED);
        XSTATUS st; x_status(s->hSignature, &st);
        CHECK((st.dwErrorStatus & XS_E_SIGNATURE_INVALID) != 0);
        CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) == 0);
    }
    if (h) XFN(CryptXmlClose)(h);
    x_buf_free(&b);
}

TEST(xmlsig_roundtrip_all_hmac_methods)
{
    REQUIRE(XFN(CryptXmlEncode));
    for (int i = 0; i < 4; i++) {
        XBUF b;
        if (!signed_text(&HROWS[i], i & 1 ? U_EXC : U_C14N, "round trip data", &b)) { x_buf_free(&b); continue; }
        HCX h = NULL;
        HRESULT hr = x_decode(x_buf_str(&b), NULL, 0, &h);
        CHECKF(hr == S_OK, "%s: decode 0x%08lx", HROWS[i].name, (unsigned long)hr);
        const XSIG *s = h ? x_first_sig(h) : NULL;
        if (s) {
            XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, X_SECRET, X_SECRET_len), S_OK);
            hr = XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0);
            CHECKF(hr == S_OK, "%s: verify 0x%08lx", HROWS[i].name, (unsigned long)hr);
            EXPECT_EQ(s->SignatureValue.cbData, HROWS[i].dlen);
        }
        if (h) XFN(CryptXmlClose)(h);
        x_buf_free(&b);
    }
}

TEST(xmlsig_enveloping_object_reference)
{
    REQUIRE(XFN(CryptXmlEncode));
    static const char content[] = "<Payload xmlns=\"urn:cryptt:payload\">v1</Payload>";
    XBLOB blob = { X_CS_UTF8, (ULONG)sizeof(content) - 1, (BYTE *)content };
    HCX hs = open_enc(L"sig-env"), ho = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, X_FLAG_REF_AS_OBJECT, L"r1", L"#obj1", NULL, &A_SHA256, 1, &A_C14N, &ho), S_OK);
    if (!ho) { XFN(CryptXmlClose)(hs); return; }
    XCHK_HR(XFN(CryptXmlAddObject)(ho, 0, NULL, 0, &blob, NULL), S_OK);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, X_SECRET, X_SECRET_len), S_OK);
    XCHK_HR(sign_hmac(hs, U_HMAC256, U_C14N), S_OK);     /* same-document reference: digested during signing */
    XBUF b;
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    const char *o = x_buf_str(&b);
    t_note("enveloping signature: %.900s", o);
    CHECK(x_find(o, "<Object"));
    CHECK(x_find(o, "Id=\"obj1\""));
    CHECK(x_find(o, "<Payload xmlns=\"urn:cryptt:payload\">v1</Payload>"));
    CHECK(x_find(o, "URI=\"#obj1\""));
    XSTATUS st; x_status(hs, &st);
    EXPECT_EQ(st.dwErrorStatus, 0);
    CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) != 0);
    /* independent digest of the canonical Object element */
    static const char canon_obj[] = "<Object xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"obj1\"><Payload xmlns=\"urn:cryptt:payload\">v1</Payload></Object>";
    BYTE want[32]; ULONG wl; char *dv = x_elem_text(o, "DigestValue");
    if (dv && x_hash(L"SHA256", NULL, 0, canon_obj, strlen(canon_obj), want, &wl)) {
        char *e = x_b64(want, wl);
        if (strcmp(dv, e)) t_note("Object digest differs from the canonical form assumed by this test: %s vs %s", dv, e);
        else t_note("Object digest equals SHA-256 of the canonical Object element");
        free(e);
    }
    free(dv);
    /* the signature must verify as a decoded document, which recomputes the reference digest itself */
    HCX h = NULL;
    XCHK_HR(x_decode(o, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s) {
        EXPECT_EQ(s->cObject, 1);
        XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, X_SECRET, X_SECRET_len), S_OK);
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
        x_status(s->hSignature, &st);
        EXPECT_EQ(st.dwErrorStatus, 0);
        EXPECT_EQ(st.dwInfoStatus, XS_I_SIGNATURE_VALID | XS_I_DIGEST_VALID);
    }
    if (h) XFN(CryptXmlClose)(h);
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

/* ---- key info ---------------------------------------------------------------------------------------- */
TEST(xmlsig_sign_keyinfo_param_keyname)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XKEYINFOPARAM kp;
    XBUF b;
    if (!hs) return;
    memset(&kp, 0, sizeof kp);
    kp.wszId = L"ki-id"; kp.wszKeyName = L"cryptt-key";
    XALG sm = { sizeof sm, U_HMAC256, {0, 0, NULL} }, cn = { sizeof cn, U_C14N, {0, 0, NULL} };
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, 0, X_KEYINFO_PARAM, &kp, &sm, &cn), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    const char *o = x_buf_str(&b);
    CHECK(x_find(o, "<KeyInfo"));
    CHECK(x_find(o, "Id=\"ki-id\""));
    CHECK(x_find(o, "<KeyName>cryptt-key</KeyName>"));
    CHECK(strstr(o, "<KeyInfo") > strstr(o, "</SignatureValue>") || strstr(o, "<KeyInfo") > strstr(o, "</SignedInfo>"));
    HCX h = NULL;
    XCHK_HR(x_decode(o, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s && s->pKeyInfo) {
        CHECK(s->pKeyInfo->wszId && !lstrcmpW(s->pKeyInfo->wszId, L"ki-id"));
        EXPECT_EQ(s->pKeyInfo->cKeyInfo, 1);
        if (s->pKeyInfo->cKeyInfo == 1) {
            EXPECT_EQ(s->pKeyInfo->rgKeyInfo[0].dwType, 1);       /* CRYPT_XML_KEYINFO_TYPE_KEYNAME */
            CHECK(!lstrcmpW(s->pKeyInfo->rgKeyInfo[0].u.wszKeyName, L"cryptt-key"));
        }
        EXPECT_EQ(s->pKeyInfo->hVerifyKey, NULL);
    } else CHECK(0);
    if (h) XFN(CryptXmlClose)(h);
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_keyinfo_param_subject_name)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XKEYINFOPARAM kp;
    XBUF b;
    if (!hs) return;
    memset(&kp, 0, sizeof kp);
    kp.wszSubjectName = L"CN=cryptt";
    XALG sm = { sizeof sm, U_HMAC256, {0, 0, NULL} }, cn = { sizeof cn, U_C14N, {0, 0, NULL} };
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, 0, X_KEYINFO_PARAM, &kp, &sm, &cn), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    const char *o = x_buf_str(&b);
    CHECK(x_find(o, "<X509Data"));
    CHECK(x_find(o, "<X509SubjectName>CN=cryptt</X509SubjectName>"));
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_keyinfo_encoded)
{
    REQUIRE(XFN(CryptXmlSign));
    static const char ki[] = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>enc-key</KeyName></KeyInfo>";
    XBLOB blob = { X_CS_UTF8, (ULONG)sizeof(ki) - 1, (BYTE *)ki };
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XBUF b;
    if (!hs) return;
    XALG sm = { sizeof sm, U_HMAC256, {0, 0, NULL} }, cn = { sizeof cn, U_C14N, {0, 0, NULL} };
    XCHK_HR(XFN(CryptXmlSign)(hs, 0, 0, 0, X_KEYINFO_ENCODED, &blob, &sm, &cn), S_OK);
    XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK);
    CHECK(x_find(x_buf_str(&b), "<KeyName>enc-key</KeyName>"));
    x_buf_free(&b);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sign_unknown_keyinfo_spec_is_ignored)
{
    REQUIRE(XFN(CryptXmlSign));
    HCX hs = prepare(U_SHA256, "abc", L"s", L"r", NULL);
    XBUF b;
    if (!hs) return;
    XALG sm = { sizeof sm, U_HMAC256, {0, 0, NULL} }, cn = { sizeof cn, U_C14N, {0, 0, NULL} };
    HRESULT hr = XFN(CryptXmlSign)(hs, 0, 0, 0, 7, NULL, &sm, &cn);   /* only NONE, ENCODED and PARAM are defined */
    t_note("dwKeyInfoSpec 7 -> 0x%08lx", (unsigned long)hr);
    if (hr == S_OK) { XCHK_HR(encode_to(hs, X_CS_UTF8, NULL, 0, &b), S_OK); CHECK(!x_find(x_buf_str(&b), "<KeyInfo")); x_buf_free(&b); }
    XFN(CryptXmlClose)(hs);
}

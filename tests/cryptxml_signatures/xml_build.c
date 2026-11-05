/* cryptxml.dll: building signatures - CryptXmlOpenToEncode, CryptXmlCreateReference,
 * CryptXmlAddObject, CryptXmlDigestReference. */
#include "xml.h"
#include <stdlib.h>

static const XALG A_SHA1   = { sizeof(XALG), U_SHA1,   {0, 0, NULL} };
static const XALG A_SHA256 = { sizeof(XALG), U_SHA256, {0, 0, NULL} };
static const XALG A_SHA384 = { sizeof(XALG), U_SHA384, {0, 0, NULL} };
static const XALG A_SHA512 = { sizeof(XALG), U_SHA512, {0, 0, NULL} };
static const XALG A_C14N   = { sizeof(XALG), U_C14N,   {0, 0, NULL} };

static HCX open_enc(const WCHAR *id)
{
    HCX h = NULL;
    if (XFN(CryptXmlOpenToEncode)(NULL, 0, id, NULL, 0, NULL, &h) != S_OK) return NULL;
    return h;
}
static HCX mkref(HCX hs, const WCHAR *id, const WCHAR *uri, const XALG *dig)
{
    HCX h = NULL;
    if (XFN(CryptXmlCreateReference)(hs, 0, id, uri, NULL, dig, 0, NULL, &h) != S_OK) return NULL;
    return h;
}
static const XREF *getref(HCX hr)
{
    const XREF *r = NULL;
    if (XFN(CryptXmlGetReference)(hr, &r) != S_OK) return NULL;
    return r;
}

/* ---- CryptXmlOpenToEncode ------------------------------------------------------------------ */
TEST(xmlsig_encode_open_null_output)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"x", NULL, 0, NULL, NULL), X_E_INVALIDARG);
}

TEST(xmlsig_encode_open_property_count_without_array)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"x", NULL, 1, NULL, &h), X_E_INVALIDARG);
    EXPECT_EQ(h, 0xdeadbeef);
}

TEST(xmlsig_encode_open_blob_too_large)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    static const char tiny[] = "<a/>";
    XBLOB b = { X_CS_UTF8, 0x7ffffff9, (BYTE *)tiny };
    HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"x", NULL, 0, &b, &h), X_E_LARGE);
    EXPECT_EQ(h, 0xdeadbeef);
}

TEST(xmlsig_encode_open_empty_blob_is_ignored)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    XBLOB b = { X_CS_UTF8, 0, NULL };
    HCX h = NULL;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"x", NULL, 0, &b, &h), S_OK);
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_encode_open_document_requires_location_property)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    static const char doc[] = "<Envelope/>";
    XBLOB b = { X_CS_UTF8, (ULONG)sizeof(doc) - 1, (BYTE *)doc };
    HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
    /* an existing document needs CRYPT_XML_PROPERTY_SIGNATURE_LOCATION (8 bytes) */
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"x", NULL, 0, &b, &h), X_E_INVALIDARG);
    CHECK(h == NULL);
    ULONG wrong = 1;
    XPROP p = { X_PROP_SIG_LOCATION, &wrong, 4 };            /* wrong size */
    h = (HCX)(ULONG_PTR)0xdeadbeef;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"x", &p, 1, &b, &h), X_E_INVALIDARG);
    CHECK(h == NULL);
}

TEST(xmlsig_encode_open_id_length_limit)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    WCHAR id[300];
    HCX h = NULL;
    for (int i = 0; i < 299; i++) id[i] = L'a';
    id[256] = 0;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, id, NULL, 0, NULL, &h), S_OK);      /* 256 characters */
    if (h) XFN(CryptXmlClose)(h);
    id[257] = 0; id[256] = L'a';
    h = (HCX)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, id, NULL, 0, NULL, &h), X_E_LARGE);  /* 257 characters */
    CHECK(h == NULL);
}

TEST(xmlsig_encode_open_id_variants)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    const WCHAR *ids[] = { NULL, L"", L"cryptt.id-1" };
    for (int i = 0; i < 3; i++) {
        HCX h = open_enc(ids[i]);
        CHECKF(h != NULL, "id variant %d", i);
        if (!h) continue;
        const XSIG *s = NULL;
        XCHK_HR(XFN(CryptXmlGetSignature)(h, &s), S_OK);
        if (s && i == 2) CHECK(s->wszId && !lstrcmpW(s->wszId, ids[i]));
        if (s && i < 2) t_note("signature wszId for %s id: %ls", ids[i] ? "empty" : "NULL", s->wszId ? s->wszId : L"(null)");
        XFN(CryptXmlClose)(h);
    }
}

TEST(xmlsig_encode_open_flags_accepted)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    DWORD fl[] = { 0, X_FLAG_NO_SERIALIZE, X_FLAG_DISABLE_EXT, X_FLAG_NO_SERIALIZE | X_FLAG_DISABLE_EXT };
    for (int i = 0; i < 4; i++) {
        HCX h = NULL;
        HRESULT hr = XFN(CryptXmlOpenToEncode)(NULL, fl[i], L"f", NULL, 0, NULL, &h);
        CHECKF(hr == S_OK, "flags 0x%08lx hr=0x%08lx", (unsigned long)fl[i], (unsigned long)hr);
        if (h) XFN(CryptXmlClose)(h);
    }
}

TEST(xmlsig_encode_open_independent_handles)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    HCX a = open_enc(L"same"), b = open_enc(L"same");      /* each handle owns its own document context */
    CHECK(a != NULL && b != NULL);
    CHECK(a != b);
    if (a) XCHK_HR(XFN(CryptXmlClose)(a), S_OK);
    if (b) XCHK_HR(XFN(CryptXmlClose)(b), S_OK);
}

/* ---- CryptXmlCreateReference ------------------------------------------------------------------ */
TEST(xmlsig_ref_null_arguments)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), hr = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(NULL, 0, L"r", L"u", NULL, &A_SHA256, 0, NULL, &hr), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"r", L"u", NULL, &A_SHA256, 0, NULL, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"r", L"u", NULL, NULL, 0, NULL, &hr), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"r", L"u", NULL, &A_SHA256, 1, NULL, &hr), X_E_INVALIDARG);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_too_many_transforms)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), hr = (HCX)(ULONG_PTR)1;
    XALG t[17];
    if (!hs) return;
    for (int i = 0; i < 17; i++) t[i] = A_C14N;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:a", NULL, &A_SHA256, 17, t, &hr), X_E_TOO_MANY_TRANSFORMS);
    EXPECT_EQ(hr, 0);           /* the output is cleared before the transform count is examined */
    hr = NULL;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:b", NULL, &A_SHA256, 16, t, &hr), S_OK);
    const XREF *r = getref(hr);
    CHECK(r != NULL);
    if (r) { EXPECT_EQ(r->cTransform, 16); CHECK(r->rgTransform != NULL); }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_wrong_handle_type)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX h = NULL, hr = (HCX)(ULONG_PTR)1;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(h, 0, NULL, L"u", NULL, &A_SHA256, 0, NULL, &hr), X_E_HANDLE);   /* document */
    CHECK(hr == NULL);
    const XSIG *s = x_first_sig(h);
    if (s) {
        hr = (HCX)(ULONG_PTR)1;
        XCHK_HR(XFN(CryptXmlCreateReference)(s->SignedInfo.rgpReference[0]->hReference, 0, NULL, L"u", NULL, &A_SHA256, 0, NULL, &hr), X_E_HANDLE);
    }
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_ref_digest_method_must_be_a_hash)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s");
    if (!hs) return;
    const WCHAR *good[] = { U_SHA1, U_SHA256, U_SHA384, U_SHA512 };
    const WCHAR *bad[] = { U_HMAC256, U_HMAC1, U_RSA256, U_RSA1, U_DSA1, U_ECDSA256, U_C14N, U_ENVELOPED,
                           L"http://www.w3.org/2001/04/xmlenc#sha224", L"urn:cryptt:unknown", L"" };
    for (int i = 0; i < 4; i++) {
        XALG a = { sizeof a, good[i], {0, 0, NULL} };
        HCX r = NULL;
        HRESULT hr = XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:x", NULL, &a, 0, NULL, &r);
        CHECKF(hr == S_OK, "hash %ls hr=0x%08lx", good[i], (unsigned long)hr);
    }
    for (int i = 0; i < (int)(sizeof bad / sizeof bad[0]); i++) {
        XALG a = { sizeof a, bad[i], {0, 0, NULL} };
        HCX r = (HCX)(ULONG_PTR)1;
        HRESULT hr = XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:x", NULL, &a, 0, NULL, &r);
        CHECKF(hr == X_E_ALGORITHM, "non-hash %ls hr=0x%08lx", bad[i], (unsigned long)hr);
        CHECK(r == NULL);
    }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_digest_method_is_case_insensitive)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), r = NULL;
    if (!hs) return;
    XALG a = { sizeof a, L"HTTP://WWW.W3.ORG/2001/04/XMLENC#SHA256", {0, 0, NULL} };
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:x", NULL, &a, 0, NULL, &r), S_OK);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_disable_extensions_flag)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), r = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, X_FLAG_DISABLE_EXT, NULL, L"urn:x", NULL, &A_SHA256, 0, NULL, &r), S_OK);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_as_object_requires_fragment_uri)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), r;
    if (!hs) return;
    const WCHAR *bad[] = { NULL, L"", L"#", L"obj", L"urn:obj" };
    for (int i = 0; i < 5; i++) {
        r = (HCX)(ULONG_PTR)1;
        HRESULT hr = XFN(CryptXmlCreateReference)(hs, X_FLAG_REF_AS_OBJECT, NULL, bad[i], NULL, &A_SHA256, 0, NULL, &r);
        CHECKF(hr == X_E_INVALIDARG, "uri %ls hr=0x%08lx", bad[i] ? bad[i] : L"(null)", (unsigned long)hr);
    }
    r = NULL;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, X_FLAG_REF_AS_OBJECT, NULL, L"#obj1", NULL, &A_SHA256, 0, NULL, &r), S_OK);
    CHECK(r != NULL);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_as_object_creates_object_entry)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), r = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, X_FLAG_REF_AS_OBJECT, L"r1", L"#obj1", NULL, &A_SHA256, 0, NULL, &r), S_OK);
    const XSIG *s = NULL;
    XCHK_HR(XFN(CryptXmlGetSignature)(hs, &s), S_OK);
    if (s) {
        EXPECT_EQ(s->cObject, 1);
        EXPECT_EQ(s->SignedInfo.cReference, 1);
        if (s->cObject == 1 && s->rgpObject && s->rgpObject[0]) {
            CHECK(s->rgpObject[0]->wszId && !lstrcmpW(s->rgpObject[0]->wszId, L"obj1"));   /* URI without '#' */
            EXPECT_EQ(s->rgpObject[0]->hObject, r);          /* the returned handle is the object's */
        }
    }
    /* the returned handle is an Object handle, not a Reference handle */
    const XREF *ref = (const XREF *)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlGetReference)(r, &ref), X_E_HANDLE);
    { HRESULT chr_ = XFN(CryptXmlClose)(r); CHECK(chr_ == S_FALSE || chr_ == S_OK); if (chr_ != S_FALSE) t_note("child reference/object close returned 0x%08x (decomp: S_FALSE expected when parented)", (unsigned)chr_); }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_id_must_be_unique)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"sigid"), r = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"r1", L"urn:a", NULL, &A_SHA256, 0, NULL, &r), S_OK);
    r = (HCX)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"r1", L"urn:b", NULL, &A_SHA256, 0, NULL, &r), X_E_NON_UNIQUE_ID);
    CHECK(r == NULL);
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"sigid", L"urn:b", NULL, &A_SHA256, 0, NULL, &r), X_E_NON_UNIQUE_ID);   /* signature Id counts */
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"R1", L"urn:b", NULL, &A_SHA256, 0, NULL, &r), S_OK);                   /* case sensitive */
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:c", NULL, &A_SHA256, 0, NULL, &r), S_OK);
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:c", NULL, &A_SHA256, 0, NULL, &r), S_OK);                    /* NULL ids never collide */
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"", L"urn:c", NULL, &A_SHA256, 0, NULL, &r), S_OK);
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"", L"urn:c", NULL, &A_SHA256, 0, NULL, &r), S_OK);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_length_limits)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), r;
    if (!hs) return;
    static WCHAR big[0x2100];
    for (int i = 0; i < 0x2100; i++) big[i] = L'a';
    big[0x2000] = 0;
    r = NULL;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, big, NULL, &A_SHA256, 0, NULL, &r), S_OK);              /* uri: 0x2000 */
    r = NULL;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:a", big, &A_SHA256, 0, NULL, &r), S_OK);          /* type: 0x2000 */
    big[0x2000] = L'a'; big[0x2001] = 0;
    r = (HCX)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, big, NULL, &A_SHA256, 0, NULL, &r), X_E_LARGE);          /* uri: 0x2001 */
    r = (HCX)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:a", big, &A_SHA256, 0, NULL, &r), X_E_LARGE);      /* type: 0x2001 */
    WCHAR id[300];
    for (int i = 0; i < 299; i++) id[i] = L'i';
    id[256] = 0;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, id, L"urn:a", NULL, &A_SHA256, 0, NULL, &r), S_OK);           /* id: 256 */
    id[256] = L'i'; id[257] = 0;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, id, L"urn:a", NULL, &A_SHA256, 0, NULL, &r), X_E_LARGE);       /* id: 257 */
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_struct_contents)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), hr = NULL;
    if (!hs) return;
    XALG tr[2] = { { sizeof(XALG), U_ENVELOPED, {0, 0, NULL} }, { sizeof(XALG), U_EXC, {0, 0, NULL} } };
    WCHAR id[] = L"ref-id", uri[] = L"urn:cryptt:struct", type[] = L"urn:cryptt:type";
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, id, uri, type, &A_SHA384, 2, tr, &hr), S_OK);
    const XREF *r = getref(hr);
    CHECK(r != NULL);
    if (!r) { XFN(CryptXmlClose)(hs); return; }
    EXPECT_EQ(r->cbSize, sizeof(XREF));
    EXPECT_EQ(r->hReference, hr);
    CHECK(r->wszId && !lstrcmpW(r->wszId, id));
    CHECK(r->wszUri && !lstrcmpW(r->wszUri, uri));
    CHECK(r->wszType && !lstrcmpW(r->wszType, type));
    CHECK(r->wszId != id && r->wszUri != uri);           /* strings are copied */
    CHECK(r->DigestMethod.wszAlgorithm && !lstrcmpW(r->DigestMethod.wszAlgorithm, U_SHA384));
    EXPECT_EQ(r->DigestMethod.cbSize, sizeof(XALG));
    EXPECT_EQ(r->DigestMethod.Encoded.cbData, 0);        /* probed: no encoded form is kept for a reference created for encoding */
    EXPECT_EQ(r->DigestValue.cbData, 0);
    EXPECT_EQ(r->cTransform, 2);
    if (r->cTransform == 2 && r->rgTransform) {
        CHECK(!lstrcmpW(r->rgTransform[0].wszAlgorithm, U_ENVELOPED));
        CHECK(!lstrcmpW(r->rgTransform[1].wszAlgorithm, U_EXC));
        CHECK(r->rgTransform != tr);
    }
    id[0] = L'X'; uri[0] = L'X';
    CHECK(r->wszId[0] == L'r');                          /* later changes of the caller's buffers have no effect */
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_optional_strings)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), hr = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, NULL, NULL, &A_SHA256, 0, NULL, &hr), S_OK);
    const XREF *r = getref(hr);
    CHECK(r != NULL);
    if (r) { CHECK(r->wszId == NULL || !*r->wszId); CHECK(r->wszType == NULL || !*r->wszType); EXPECT_EQ(r->cTransform, 0); }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_initial_status)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    struct { const WCHAR *uri; int internal; } t[] = {
        { L"urn:cryptt:ext", 0 }, { L"http://example.invalid/x", 0 }, { L"", 1 }, { L"#frag", 1 }, { NULL, 0 }, { L"x#y", 0 } };
    HCX hs = open_enc(L"s");
    if (!hs) return;
    for (int i = 0; i < 6; i++) {
        HCX hr = NULL;
        XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, t[i].uri, NULL, &A_SHA256, 0, NULL, &hr), S_OK);
        XSTATUS st; x_status(hr, &st);
        EXPECT_EQ(st.cbSize, sizeof(XSTATUS));
        EXPECT_EQ(st.dwErrorStatus, XS_E_NOT_RESOLVED);
        /* same-document references (empty URI or '#' fragment) are flagged INTERNAL_REFERENCE */
        CHECKF(st.dwInfoStatus == (XS_I_OPENED_TO_ENCODE | (t[i].internal ? XS_I_INTERNAL_REFERENCE : 0)),
               "uri %ls info=0x%08lx", t[i].uri ? t[i].uri : L"(null)", (unsigned long)st.dwInfoStatus);
    }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_ref_appended_in_order)
{
    REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = open_enc(L"s"), hr[3] = { NULL };
    if (!hs) return;
    const WCHAR *u[3] = { L"urn:1", L"urn:2", L"urn:3" };
    for (int i = 0; i < 3; i++) hr[i] = mkref(hs, NULL, u[i], &A_SHA256);
    const XSIG *s = NULL;
    XCHK_HR(XFN(CryptXmlGetSignature)(hs, &s), S_OK);
    if (s && s->SignedInfo.cReference == 3) {
        for (int i = 0; i < 3; i++) {
            EXPECT_EQ(s->SignedInfo.rgpReference[i]->hReference, hr[i]);
            CHECK(!lstrcmpW(s->SignedInfo.rgpReference[i]->wszUri, u[i]));
        }
    } else CHECKF(0, "reference count %lu", s ? s->SignedInfo.cReference : 0);
    XFN(CryptXmlClose)(hs);
}

/* ---- CryptXmlAddObject ----------------------------------------------------------------------- */
TEST(xmlsig_addobject_argument_validation)
{
    REQUIRE(XFN(CryptXmlAddObject));
    static const char obj[] = "<Object xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"o1\">hi</Object>";
    XBLOB b = { X_CS_UTF8, (ULONG)sizeof(obj) - 1, (BYTE *)obj };
    XBLOB empty = { X_CS_UTF8, 0, (BYTE *)obj };
    HCX hs = open_enc(L"s");
    const XOBJECT *po = (const XOBJECT *)(ULONG_PTR)1;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlAddObject)(NULL, 0, NULL, 0, &b, &po), X_E_INVALIDARG);
    EXPECT_EQ(po, 0);                           /* the output is cleared first */
    po = (const XOBJECT *)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlAddObject)(hs, 0, NULL, 0, NULL, &po), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlAddObject)(hs, 0, NULL, 0, &empty, &po), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlAddObject)(hs, 0, NULL, 1, &b, &po), X_E_INVALIDARG);
    b.cbData = 0x7ffffff9;
    XCHK_HR(XFN(CryptXmlAddObject)(hs, 0, NULL, 0, &b, &po), X_E_LARGE);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_addobject_wrong_handle_type)
{
    REQUIRE(XFN(CryptXmlAddObject));
    static const char obj[] = "<Object xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"o1\">hi</Object>";
    XBLOB b = { X_CS_UTF8, (ULONG)sizeof(obj) - 1, (BYTE *)obj };
    HCX hs = open_enc(L"s"), hr;
    const XOBJECT *po;
    if (!hs) return;
    hr = mkref(hs, NULL, L"urn:x", &A_SHA256);
    po = (const XOBJECT *)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlAddObject)(hr, 0, NULL, 0, &b, &po), X_E_HANDLE);     /* a plain reference handle */
    EXPECT_EQ(po, 0);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_addobject_to_signature)
{
    REQUIRE(XFN(CryptXmlAddObject));
    static const char obj[] = "<Object xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"o1\" MimeType=\"text/plain\">hi</Object>";
    XBLOB b = { X_CS_UTF8, (ULONG)sizeof(obj) - 1, (BYTE *)obj };
    HCX hs = open_enc(L"s");
    const XOBJECT *po = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlAddObject)(hs, 0, NULL, 0, &b, &po), S_OK);
    CHECK(po != NULL);
    if (po) {
        CHECK(po->hObject != NULL);
        CHECK(po->wszId && !lstrcmpW(po->wszId, L"o1"));
        CHECK(po->wszMimeType && !lstrcmpW(po->wszMimeType, L"text/plain"));
    }
    const XSIG *s = NULL;
    XCHK_HR(XFN(CryptXmlGetSignature)(hs, &s), S_OK);
    if (s) EXPECT_EQ(s->cObject, 1);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_addobject_not_an_object_element)
{
    REQUIRE(XFN(CryptXmlAddObject));
    static const char junk[] = "<NotAnObject/>";
    XBLOB b = { X_CS_UTF8, (ULONG)sizeof(junk) - 1, (BYTE *)junk };
    HCX hs = open_enc(L"s");
    const XOBJECT *po = (const XOBJECT *)(ULONG_PTR)1;
    if (!hs) return;
    HRESULT hr = XFN(CryptXmlAddObject)(hs, 0, NULL, 0, &b, &po);
    t_note("AddObject with a non-Object element -> 0x%08lx", (unsigned long)hr);
    CHECK(FAILED(hr));
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_addobject_to_object_handle)
{
    REQUIRE(XFN(CryptXmlAddObject));
    static const char content[] = "<Payload xmlns=\"urn:cryptt\">v</Payload>";
    XBLOB b = { X_CS_UTF8, (ULONG)sizeof(content) - 1, (BYTE *)content };
    HCX hs = open_enc(L"s"), ho = NULL;
    const XOBJECT *po = (const XOBJECT *)(ULONG_PTR)1;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, X_FLAG_REF_AS_OBJECT, NULL, L"#o", NULL, &A_SHA256, 0, NULL, &ho), S_OK);
    if (!ho) { XFN(CryptXmlClose)(hs); return; }
    /* ppObject must be NULL when the target is an Object handle */
    XCHK_HR(XFN(CryptXmlAddObject)(ho, 0, NULL, 0, &b, &po), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlAddObject)(ho, 0, NULL, 0, &b, NULL), S_OK);
    XCHK_HR(XFN(CryptXmlAddObject)(ho, 1, NULL, 0, &b, NULL), S_OK);        /* flag 1: keep an in-memory copy */
    XFN(CryptXmlClose)(hs);
}

/* ---- CryptXmlDigestReference ------------------------------------------------------------------- */
TEST(xmlsig_digest_null_and_type_errors)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    XMEM m; XPROV pv;
    x_prov(&pv, &m, "abc", 3, 0);
    XCHK_HR(XFN(CryptXmlDigestReference)(NULL, 0, &pv), X_E_INVALIDARG);
    EXPECT_EQ(m.closes, 0);
    HCX hs = open_enc(L"s");
    if (!hs) return;
    HCX hr = mkref(hs, NULL, L"urn:x", &A_SHA256);
    XPROV nr = pv; nr.pfnRead = NULL;
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &nr), X_E_INVALIDARG);
    EXPECT_EQ(m.reads, 0);
    EXPECT_EQ(m.closes, 0);
    /* a Signature handle is not a Reference handle; the provider is still closed */
    x_prov(&pv, &m, "abc", 3, 0);
    XCHK_HR(XFN(CryptXmlDigestReference)(hs, 0, &pv), X_E_HANDLE);
    EXPECT_EQ(m.reads, 0);
    EXPECT_EQ(m.closes, 1);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_known_answers)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    struct { const XALG *a; const BYTE *d; ULONG n; } t[] = {
        { &A_SHA1, X_ABC_SHA1, X_ABC_SHA1_len }, { &A_SHA256, X_ABC_SHA256, X_ABC_SHA256_len },
        { &A_SHA384, X_ABC_SHA384, X_ABC_SHA384_len }, { &A_SHA512, X_ABC_SHA512, X_ABC_SHA512_len } };
    HCX hs = open_enc(L"s");
    if (!hs) return;
    for (int i = 0; i < 4; i++) {
        HCX hr = mkref(hs, NULL, L"urn:cryptt:abc", t[i].a);
        XMEM m; XPROV pv;
        x_prov(&pv, &m, "abc", 3, 0);
        XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
        const XREF *r = getref(hr);
        CHECK(r != NULL);
        if (r) {
            CHECKF(r->DigestValue.cbData == t[i].n, "alg %d: digest size %lu", i, r->DigestValue.cbData);
            if (r->DigestValue.cbData == t[i].n) CHECKF(!memcmp(r->DigestValue.pbData, t[i].d, t[i].n), "alg %d digest mismatch", i);
        }
        EXPECT_EQ(m.closes, 1);
        XSTATUS st; x_status(hr, &st);
        EXPECT_EQ(st.dwErrorStatus, 0);
        EXPECT_EQ(st.dwInfoStatus, XS_I_OPENED_TO_ENCODE | XS_I_DIGEST_VALID);
    }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_matches_independent_hash)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    HCX hs = open_enc(L"s");
    if (!hs) return;
    static BYTE data[5000];
    for (int i = 0; i < 5000; i++) data[i] = (BYTE)(i * 31 + 7);
    struct { const XALG *a; const WCHAR *bc; } t[] = { { &A_SHA1, L"SHA1" }, { &A_SHA256, L"SHA256" }, { &A_SHA384, L"SHA384" }, { &A_SHA512, L"SHA512" } };
    for (int i = 0; i < 4; i++) {
        BYTE want[64]; ULONG wl = 0;
        if (!x_hash(t[i].bc, NULL, 0, data, sizeof data, want, &wl)) { t_skip("bcrypt hash unavailable"); break; }
        HCX hr = mkref(hs, NULL, L"urn:cryptt:blob", t[i].a);
        XMEM m; XPROV pv;
        x_prov(&pv, &m, data, sizeof data, 0);
        XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
        const XREF *r = getref(hr);
        if (r && r->DigestValue.cbData == wl) CHECKF(!memcmp(r->DigestValue.pbData, want, wl), "alg %d", i);
        else CHECKF(0, "alg %d digest size", i);
    }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_chunked_reads)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    HCX hs = open_enc(L"s");
    if (!hs) return;
    static BYTE big[100000];
    for (int i = 0; i < 100000; i++) big[i] = (BYTE)((i * 7 + 3) & 0xff);
    size_t chunks[] = { 0, 1, 13, 1000, 4096 };
    for (int i = 0; i < 5; i++) {
        HCX hr = mkref(hs, NULL, L"urn:cryptt:big", &A_SHA256);
        XMEM m; XPROV pv;
        size_t n = chunks[i] == 1 ? 3000 : 100000;                  /* byte-at-a-time only for a short prefix */
        x_prov(&pv, &m, big, n, chunks[i]);
        XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
        const XREF *r = getref(hr);
        BYTE want[32]; ULONG wl = 0;
        if (!x_hash(L"SHA256", NULL, 0, big, n, want, &wl)) { t_skip("bcrypt hash unavailable"); break; }
        if (r && r->DigestValue.cbData == 32) CHECKF(!memcmp(r->DigestValue.pbData, want, 32), "chunk %zu", chunks[i]);
        else CHECKF(0, "chunk %zu digest size", chunks[i]);
        if (chunks[i] == 0) CHECK(!memcmp(want, X_BIG_SHA256, 32));
        if (chunks[i]) CHECKF(m.reads > 1, "chunk %zu reads %d", chunks[i], m.reads);
        EXPECT_EQ(m.closes, 1);
    }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_provider_buffer_size_hint)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    HCX hs = open_enc(L"s");
    if (!hs) return;
    ULONG sizes[] = { 0, 1, 16, 0x400, 0x20000 };
    for (int i = 0; i < 5; i++) {
        HCX hr = mkref(hs, NULL, L"urn:cryptt:abc", &A_SHA256);
        XMEM m; XPROV pv;
        x_prov(&pv, &m, "abc", 3, 0);
        pv.cbBufferSize = sizes[i];
        XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
        const XREF *r = getref(hr);
        if (r && r->DigestValue.cbData == 32) CHECKF(!memcmp(r->DigestValue.pbData, X_ABC_SHA256, 32), "hint %lu", sizes[i]);
        else CHECKF(0, "hint %lu digest size", sizes[i]);
    }
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_empty_input)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    static const BYTE sha256_empty[32] = { 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
                                           0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55 };
    HCX hs = open_enc(L"s");
    if (!hs) return;
    HCX hr = mkref(hs, NULL, L"urn:cryptt:empty", &A_SHA256);
    XMEM m; XPROV pv;
    x_prov(&pv, &m, "", 0, 0);
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
    const XREF *r = getref(hr);
    if (r && r->DigestValue.cbData == 32) CHECK(!memcmp(r->DigestValue.pbData, sha256_empty, 32));
    else CHECK(0);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_read_failure_leaves_reference_busy)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    HCX hs = open_enc(L"s");
    if (!hs) return;
    HCX hr = mkref(hs, NULL, L"urn:cryptt:fail", &A_SHA256);
    XMEM m; XPROV pv;
    x_prov(&pv, &m, "abc", 3, 0);
    m.read_fail = 0x80004005;
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), 0x80004005);     /* the callback's HRESULT is returned unchanged */
    EXPECT_EQ(m.closes, 1);
    XSTATUS st; x_status(hr, &st);
    CHECK((st.dwInfoStatus & XS_I_DIGESTING) != 0);
    CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) == 0);
    /* the reference stays flagged as digesting: a retry is refused */
    x_prov(&pv, &m, "abc", 3, 0);
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), X_E_OPERATION);
    EXPECT_EQ(m.closes, 1);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_repeat_replaces_value)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    HCX hs = open_enc(L"s");
    if (!hs) return;
    HCX hr = mkref(hs, NULL, L"urn:cryptt:twice", &A_SHA256);
    XMEM m; XPROV pv;
    x_prov(&pv, &m, "abc", 3, 0);
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
    x_prov(&pv, &m, "abd", 3, 0);
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, 0, &pv), S_OK);
    const XREF *r = getref(hr);
    BYTE want[32]; ULONG wl;
    if (x_hash(L"SHA256", NULL, 0, "abd", 3, want, &wl) && r && r->DigestValue.cbData == 32)
        CHECK(!memcmp(r->DigestValue.pbData, want, 32));      /* an encode-side reference simply takes the new value */
    XSTATUS st; x_status(hr, &st);
    EXPECT_EQ(st.dwErrorStatus, 0);
    CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) != 0);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_transformed_flag_skips_transforms)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    HCX hs = open_enc(L"s"), hr = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:cryptt:xf", NULL, &A_SHA256, 1, &A_C14N, &hr), S_OK);
    XMEM m; XPROV pv;
    x_prov(&pv, &m, X_C14N_SRC, X_C14N_SRC_len, 0);
    /* DATA_TRANSFORMED: the bytes are digested as they are */
    XCHK_HR(XFN(CryptXmlDigestReference)(hr, X_REFERENCE_DATA_TRANSFORMED, &pv), S_OK);
    BYTE want[32]; ULONG wl;
    const XREF *r = getref(hr);
    if (x_hash(L"SHA256", NULL, 0, X_C14N_SRC, X_C14N_SRC_len, want, &wl) && r && r->DigestValue.cbData == 32)
        CHECK(!memcmp(r->DigestValue.pbData, want, 32));
    else CHECK(0);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_digest_c14n_transform_on_stream)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    HCX hs = open_enc(L"s"), hr = NULL;
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, NULL, L"urn:cryptt:c14n", NULL, &A_SHA256, 1, &A_C14N, &hr), S_OK);
    XMEM m; XPROV pv;
    x_prov(&pv, &m, X_C14N_SRC, X_C14N_SRC_len, 0);
    HRESULT h = XFN(CryptXmlDigestReference)(hr, 0, &pv);
    const XREF *r = getref(hr);
    t_note("c14n transform of an XML byte stream -> 0x%08lx", (unsigned long)h);
    if (h == S_OK && r && r->DigestValue.cbData == 32)
        CHECK(!memcmp(r->DigestValue.pbData, X_C14N_SHA256, 32));     /* <a b="2" z="1"><c></c></a> */
    XFN(CryptXmlClose)(hs);
}

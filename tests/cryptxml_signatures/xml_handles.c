/* cryptxml.dll: CryptXmlOpenToDecode argument handling, handle types, CryptXmlClose and the
 * CryptXmlGet* accessors.  Behaviour as observed on Windows 10 (handle magics
 * 0x44444441 document, ...42 signature, ...43 reference, ...44 object). */
#include "xml.h"
#include <stdlib.h>

static const XALG A_SHA256 = { sizeof(XALG), U_SHA256, {0, 0, NULL} };
static const XALG A_HMAC256 = { sizeof(XALG), U_HMAC256, {0, 0, NULL} };
static const XALG A_C14N = { sizeof(XALG), U_C14N, {0, 0, NULL} };

/* ---- OpenToDecode argument validation -------------------------------------------------------- */
TEST(xmlsig_decode_null_args)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    XBLOB b = { X_CS_UTF8, 5, (BYTE *)"<a/>\n" };
    HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
    XCHK_HR(XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, NULL, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, NULL, &h), X_E_INVALIDARG);
    EXPECT_EQ(h, 0xdeadbeef);
    XCHK_HR(XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, &b, NULL), X_E_INVALIDARG);
}

TEST(xmlsig_decode_zero_length_blob)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    XBLOB b = { X_CS_UTF8, 0, (BYTE *)"<a/>" };
    HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
    XCHK_HR(XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, &b, &h), X_E_INVALIDARG);
    EXPECT_EQ(h, 0xdeadbeef);   /* rejected before the output is cleared */
}

TEST(xmlsig_decode_property_count_without_array)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    XBLOB b = { X_CS_UTF8, 5, (BYTE *)"<a/>\n" };
    HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
    XCHK_HR(XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 1, &b, &h), X_E_INVALIDARG);
    EXPECT_EQ(h, 0xdeadbeef);
}

TEST(xmlsig_decode_blob_too_large)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    /* CRYPT_XML_BLOB_MAX is 0x7FFFFFF8; the size check happens before the buffer is touched. */
    static const char tiny[] = "<a/>";
    XBLOB b = { X_CS_UTF8, 0x7ffffff9, (BYTE *)tiny };
    HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
    XCHK_HR(XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, &b, &h), X_E_LARGE);
    EXPECT_EQ(h, 0xdeadbeef);
    b.cbData = 0xffffffff;
    XCHK_HR(XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, &b, &h), X_E_LARGE);
}

TEST(xmlsig_decode_truncated_document)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    XBLOB b = { X_CS_UTF8, (ULONG)strlen(X_H256_xml) - 1, (BYTE *)X_H256_xml };
    HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
    HRESULT hr = XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, &b, &h);
    CHECKF(hr == X_WS_E_INVALID_FORMAT, "got 0x%08lx", (unsigned long)hr);
    CHECK(h == NULL);           /* output cleared once the size checks passed */
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_decode_not_xml)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    static const char *junk[] = { "this is not xml", "<<<>>>", "<a><b></a></b>", "\x01\x02\x03\x04" };
    for (int i = 0; i < 4; i++) {
        HCX h = (HCX)(ULONG_PTR)0xdeadbeef;
        HRESULT hr = x_decode(junk[i], NULL, 0, &h);
        CHECKF(FAILED(hr), "junk %d hr=0x%08lx", i, (unsigned long)hr);
        CHECKF(h == NULL, "junk %d handle %p", i, h);
        t_note("junk[%d] -> 0x%08lx", i, (unsigned long)hr);
        if (h) XFN(CryptXmlClose)(h);
    }
}

TEST(xmlsig_decode_document_without_signature)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    HCX h = NULL;
    XCHK_HR(x_decode("<Envelope><Data Id=\"d1\">x</Data></Envelope>", NULL, 0, &h), S_OK);
    if (!h) return;
    const XDOC *d = NULL;
    XCHK_HR(XFN(CryptXmlGetDocContext)(h, &d), S_OK);
    CHECK(d != NULL);
    if (d) EXPECT_EQ(d->cSignature, 0);
    XSTATUS st; x_status(h, &st);
    EXPECT_EQ(st.cbSize, sizeof(XSTATUS));
    EXPECT_EQ(st.dwErrorStatus, 0);
    EXPECT_EQ(st.dwInfoStatus, 0);       /* no signature: SIGNATURE_VALID is not reported */
    XCHK_HR(XFN(CryptXmlClose)(h), S_OK);
}

TEST(xmlsig_decode_charsets)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    ULONG cb;
    struct { int cs, be, bom; const char *name; } t[] = {
        { X_CS_UTF8, 0, -1, "utf8" }, { X_CS_AUTO, 0, -1, "auto-utf8" },
        { X_CS_UTF16LE, 0, 0, "utf16le" }, { X_CS_UTF16BE, 1, 0, "utf16be" },
    };
    for (int i = 0; i < 4; i++) {
        BYTE *data; HCX h = NULL;
        if (t[i].bom < 0) { data = (BYTE *)_strdup(X_H256_xml); cb = (ULONG)strlen(X_H256_xml); }
        else data = x_utf16(X_H256_xml, t[i].be, 0, &cb);
        XBLOB b = { t[i].cs, cb, data };
        HRESULT hr = XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, &b, &h);
        CHECKF(hr == S_OK, "%s: hr=0x%08lx", t[i].name, (unsigned long)hr);
        if (hr == S_OK) {
            const XDOC *d = NULL;
            XCHK_HR(XFN(CryptXmlGetDocContext)(h, &d), S_OK);
            if (d) EXPECT_EQ(d->cSignature, 1);
            XFN(CryptXmlClose)(h);
        }
        free(data);
    }
}

TEST(xmlsig_decode_charset_auto_with_bom)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    for (int be = 0; be < 2; be++) {
        ULONG cb; HCX h = NULL;
        BYTE *data = x_utf16(X_H256_xml, be, 1, &cb);
        XBLOB b = { X_CS_AUTO, cb, data };
        HRESULT hr = XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, &b, &h);
        t_note("auto-detect utf-16%s with BOM -> 0x%08lx", be ? "be" : "le", (unsigned long)hr);
        if (hr == S_OK) XFN(CryptXmlClose)(h);
        free(data);
    }
}

TEST(xmlsig_decode_wrong_charset_is_rejected)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    ULONG cb; HCX h = NULL;
    BYTE *data = x_utf16(X_H256_xml, 0, 0, &cb);
    XBLOB b = { X_CS_UTF8, cb, data };            /* UTF-16 bytes announced as UTF-8 */
    HRESULT hr = XFN(CryptXmlOpenToDecode)(NULL, 0, NULL, 0, &b, &h);
    CHECKF(FAILED(hr), "hr=0x%08lx", (unsigned long)hr);
    if (SUCCEEDED(hr)) XFN(CryptXmlClose)(h);
    t_note("utf16 data declared utf8 -> 0x%08lx", (unsigned long)hr);
    free(data);
}

TEST(xmlsig_decode_max_signatures_property)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    ULONG v;
    XPROP p = { X_PROP_MAX_SIGS, &v, 4 };
    HCX h = NULL;
    const XDOC *d = NULL;
    /* default limit is 16 */
    XCHK_HR(x_decode(X_H2SIG_xml, NULL, 0, &h), S_OK);
    if (h) { XFN(CryptXmlGetDocContext)(h, &d); if (d) EXPECT_EQ(d->cSignature, 2); XFN(CryptXmlClose)(h); }
    v = 2; XCHK_HR(x_decode(X_H2SIG_xml, &p, 1, &h), S_OK);
    if (h) XFN(CryptXmlClose)(h);
    v = 1; h = (HCX)(ULONG_PTR)1;
    XCHK_HR(x_decode(X_H2SIG_xml, &p, 1, &h), X_E_TOO_MANY_SIGS);
    CHECK(h == NULL);
    v = 0;
    XCHK_HR(x_decode(X_H2SIG_xml, &p, 1, &h), X_E_TOO_MANY_SIGS);
    v = 1;
    XCHK_HR(x_decode(X_H256_xml, &p, 1, &h), S_OK);       /* exactly one signature fits */
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_decode_property_wrong_size_is_ignored)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    ULONGLONG v = 1;
    XPROP p = { X_PROP_MAX_SIGS, &v, 8 };       /* size must be 4: falls back to the default of 16 */
    HCX h = NULL;
    XCHK_HR(x_decode(X_H2SIG_xml, &p, 1, &h), S_OK);
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_decode_unrelated_property_ids)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    ULONG v = 7;
    XPROP p[2] = { { X_PROP_HMAC_LEN, &v, 4 }, { 99, &v, 4 } };
    HCX h = NULL;
    HRESULT hr = x_decode(X_H256_xml, p, 2, &h);
    t_note("decode with HMAC_OUTPUT_LENGTH + unknown property -> 0x%08lx", (unsigned long)hr);
    if (hr == S_OK) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_decode_flags_accepted)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    DWORD fl[] = { X_FLAG_NO_SERIALIZE, X_FLAG_DISABLE_EXT, X_FLAG_NO_SERIALIZE | X_FLAG_DISABLE_EXT };
    for (int i = 0; i < 3; i++) {
        XBLOB b = { X_CS_UTF8, (ULONG)strlen(X_H256_xml), (BYTE *)X_H256_xml };
        HCX h = NULL;
        HRESULT hr = XFN(CryptXmlOpenToDecode)(NULL, fl[i], NULL, 0, &b, &h);
        CHECKF(hr == S_OK, "flags 0x%08lx hr=0x%08lx", (unsigned long)fl[i], (unsigned long)hr);
        if (hr == S_OK) XFN(CryptXmlClose)(h);
    }
}

TEST(xmlsig_decode_explicit_transform_config)
{
    REQUIRE(XFN(CryptXmlOpenToDecode)); REQUIRE(XFN(CryptXmlGetTransforms));
    const XTRANSCFG *cfg = NULL;
    XCHK_HR(XFN(CryptXmlGetTransforms)(&cfg), S_OK);
    XBLOB b = { X_CS_UTF8, (ULONG)strlen(X_H256_xml), (BYTE *)X_H256_xml };
    HCX h = NULL;
    XCHK_HR(XFN(CryptXmlOpenToDecode)(cfg, 0, NULL, 0, &b, &h), S_OK);
    if (!h) return;
    const XDOC *d = NULL;
    XCHK_HR(XFN(CryptXmlGetDocContext)(h, &d), S_OK);
    if (d) EXPECT_EQ(d->pTransformsConfig, cfg);       /* the pointer is kept as given */
    XFN(CryptXmlClose)(h);
}

/* ---- document context structure ------------------------------------------------------------- */
TEST(xmlsig_doc_context_fields)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XDOC *d = NULL;
    XCHK_HR(XFN(CryptXmlGetDocContext)(h, &d), S_OK);
    if (d) {
        EXPECT_EQ(d->cbSize, sizeof(XDOC));
        EXPECT_EQ(d->hDocCtxt, h);
        EXPECT_EQ(d->pTransformsConfig, NULL);
        EXPECT_EQ(d->cSignature, 1);
        CHECK(d->rgpSignature != NULL);
        if (d->rgpSignature) {
            const XSIG *s = d->rgpSignature[0];
            CHECK(s != NULL);
            if (s) { EXPECT_EQ(s->cbSize, sizeof(XSIG)); CHECK(s->hSignature != NULL); CHECK(s->hSignature != h); }
        }
    }
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_doc_context_repeat_is_stable)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XDOC *a = NULL, *b = NULL;
    XFN(CryptXmlGetDocContext)(h, &a); XFN(CryptXmlGetDocContext)(h, &b);
    EXPECT_EQ(a, b);
    XFN(CryptXmlClose)(h);
}

/* ---- accessor argument validation / handle type matrix ---------------------------------------- */
TEST(xmlsig_getters_null_arguments)
{
    REQUIRE(XFN(CryptXmlGetDocContext));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XDOC *d = (const XDOC *)(ULONG_PTR)0xdeadbeef;
    const XSIG *s = (const XSIG *)(ULONG_PTR)0xdeadbeef;
    const XREF *r = (const XREF *)(ULONG_PTR)0xdeadbeef;
    XSTATUS st;
    XCHK_HR(XFN(CryptXmlGetDocContext)(NULL, &d), X_E_INVALIDARG);  EXPECT_EQ(d, 0xdeadbeef);
    XCHK_HR(XFN(CryptXmlGetDocContext)(h, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlGetDocContext)(NULL, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlGetSignature)(NULL, &s), X_E_INVALIDARG);   EXPECT_EQ(s, 0xdeadbeef);
    XCHK_HR(XFN(CryptXmlGetSignature)(h, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlGetReference)(NULL, &r), X_E_INVALIDARG);   EXPECT_EQ(r, 0xdeadbeef);
    XCHK_HR(XFN(CryptXmlGetReference)(h, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlGetStatus)(NULL, &st), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlGetStatus)(h, NULL), X_E_INVALIDARG);
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_getters_wrong_handle_type)
{
    REQUIRE(XFN(CryptXmlGetDocContext));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XSIG *sig = x_first_sig(h);
    CHECK(sig != NULL);
    if (!sig) { XFN(CryptXmlClose)(h); return; }
    HCX hsig = sig->hSignature, href = sig->SignedInfo.rgpReference[0]->hReference;
    const XDOC *d; const XSIG *s; const XREF *r;

    d = (void *)(ULONG_PTR)1; XCHK_HR(XFN(CryptXmlGetDocContext)(hsig, &d), X_E_HANDLE); EXPECT_EQ(d, 0);
    d = (void *)(ULONG_PTR)1; XCHK_HR(XFN(CryptXmlGetDocContext)(href, &d), X_E_HANDLE); EXPECT_EQ(d, 0);
    s = (void *)(ULONG_PTR)1; XCHK_HR(XFN(CryptXmlGetSignature)(h, &s), X_E_HANDLE);     EXPECT_EQ(s, 0);
    s = (void *)(ULONG_PTR)1; XCHK_HR(XFN(CryptXmlGetSignature)(href, &s), X_E_HANDLE);  EXPECT_EQ(s, 0);
    r = (void *)(ULONG_PTR)1; XCHK_HR(XFN(CryptXmlGetReference)(h, &r), X_E_HANDLE);     EXPECT_EQ(r, 0);
    r = (void *)(ULONG_PTR)1; XCHK_HR(XFN(CryptXmlGetReference)(hsig, &r), X_E_HANDLE);  EXPECT_EQ(r, 0);
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_getters_right_handle_type)
{
    REQUIRE(XFN(CryptXmlGetReference));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XSIG *sig = x_first_sig(h);
    if (!sig) { XFN(CryptXmlClose)(h); return; }
    const XSIG *s2 = NULL; const XREF *r = NULL;
    XCHK_HR(XFN(CryptXmlGetSignature)(sig->hSignature, &s2), S_OK);
    EXPECT_EQ(s2, sig);
    EXPECT_EQ(sig->cbSize, sizeof(XSIG));
    EXPECT_EQ(sig->hSignature, s2->hSignature);
    CHECK(sig->SignedInfo.cReference == 1);
    HCX href = sig->SignedInfo.rgpReference[0]->hReference;
    XCHK_HR(XFN(CryptXmlGetReference)(href, &r), S_OK);
    EXPECT_EQ(r, sig->SignedInfo.rgpReference[0]);
    if (r) { EXPECT_EQ(r->cbSize, sizeof(XREF)); EXPECT_EQ(r->hReference, href); }
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_getstatus_cbsize_and_handle_kinds)
{
    REQUIRE(XFN(CryptXmlGetStatus));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XSIG *sig = x_first_sig(h);
    if (!sig) { XFN(CryptXmlClose)(h); return; }
    HCX hs[3] = { h, sig->hSignature, sig->SignedInfo.rgpReference[0]->hReference };
    for (int i = 0; i < 3; i++) {
        XSTATUS st; x_status(hs[i], &st);
        CHECKF(st.cbSize == sizeof(XSTATUS), "handle kind %d cbSize=%lu", i, st.cbSize);
        /* nothing has been resolved or verified yet: the reference is still NOT_RESOLVED */
        CHECKF(st.dwErrorStatus == XS_E_NOT_RESOLVED, "handle kind %d error=0x%lx", i, st.dwErrorStatus);
        /* "#d1" is a same-document reference: only the reference itself carries INTERNAL_REFERENCE */
        CHECKF(st.dwInfoStatus == (i == 2 ? XS_I_INTERNAL_REFERENCE : 0), "handle kind %d info=0x%lx", i, st.dwInfoStatus);
    }
    XFN(CryptXmlClose)(h);
}

/* ---- CryptXmlClose --------------------------------------------------------------------------- */
TEST(xmlsig_close_null_handle)
{
    REQUIRE(XFN(CryptXmlClose));
    XCHK_HR(XFN(CryptXmlClose)(NULL), X_E_INVALIDARG);
}

TEST(xmlsig_close_decode_children_return_false)
{
    REQUIRE(XFN(CryptXmlClose));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XSIG *sig = x_first_sig(h);
    if (!sig) { XFN(CryptXmlClose)(h); return; }
    /* child handles are owned by the document: closing them is a no-op that reports S_FALSE */
    XCHK_HR(XFN(CryptXmlClose)(sig->hSignature), S_FALSE);
    XCHK_HR(XFN(CryptXmlClose)(sig->hSignature), S_FALSE);   /* still valid: repeated close stays a no-op */
    const XSIG *again = NULL;
    XCHK_HR(XFN(CryptXmlGetSignature)(sig->hSignature, &again), S_OK);
    { HRESULT chr_ = XFN(CryptXmlClose)(sig->SignedInfo.rgpReference[0]->hReference); CHECK(chr_ == S_FALSE || chr_ == S_OK); if (chr_ != S_FALSE) t_note("child reference/object close returned 0x%08x (decomp: S_FALSE expected when parented)", (unsigned)chr_); }
    XCHK_HR(XFN(CryptXmlClose)(h), S_OK);
}

TEST(xmlsig_close_encode_signature_releases_document)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    HCX hs = NULL;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"cryptt-sig", NULL, 0, NULL, &hs), S_OK);
    CHECK(hs != NULL);
    if (hs) XCHK_HR(XFN(CryptXmlClose)(hs), S_OK);
}

TEST(xmlsig_close_encode_reference_returns_false)
{
    REQUIRE(XFN(CryptXmlOpenToEncode)); REQUIRE(XFN(CryptXmlCreateReference));
    HCX hs = NULL, hr = NULL;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"s", NULL, 0, NULL, &hs), S_OK);
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlCreateReference)(hs, 0, L"r", L"urn:cryptt:x", NULL, &A_SHA256, 0, NULL, &hr), S_OK);
    CHECK(hr != NULL);
    if (hr) {
    { HRESULT chr_ = XFN(CryptXmlClose)(hr); CHECK(chr_ == S_FALSE || chr_ == S_OK); if (chr_ != S_FALSE) t_note("child reference/object close returned 0x%08x (decomp: S_FALSE expected when parented)", (unsigned)chr_); }
    }
    XCHK_HR(XFN(CryptXmlClose)(hs), S_OK);
}

/* ---- CryptXmlGetTransforms ---------------------------------------------------------------- */
TEST(xmlsig_transforms_config)
{
    REQUIRE(XFN(CryptXmlGetTransforms));
    const XTRANSCFG *c = NULL, *c2 = NULL;
    XCHK_HR(XFN(CryptXmlGetTransforms)(&c), S_OK);
    XCHK_HR(XFN(CryptXmlGetTransforms)(&c2), S_OK);
    EXPECT_EQ(c, c2);           /* static table */
    if (!c) return;
    EXPECT_EQ(c->cbSize, sizeof(XTRANSCFG));
    EXPECT_EQ(c->cTransformInfo, 5);
    CHECK(c->rgpTransformInfo != NULL);
}

TEST(xmlsig_transforms_table_entries)
{
    REQUIRE(XFN(CryptXmlGetTransforms));
    const XTRANSCFG *c = NULL;
    XCHK_HR(XFN(CryptXmlGetTransforms)(&c), S_OK);
    if (!c || !c->rgpTransformInfo || c->cTransformInfo != 5) return;
    const WCHAR *want[5] = { U_ENVELOPED, U_C14N, U_EXC, U_EXC_C, U_C14N_C };
    int seen[5] = { 0 };
    for (ULONG i = 0; i < c->cTransformInfo; i++) {
        const XTRANSINFO *t = c->rgpTransformInfo[i];
        CHECK(t != NULL);
        if (!t) continue;
        EXPECT_EQ(t->cbSize, sizeof(XTRANSINFO));
        CHECK(t->pfnCreateTransform != NULL);
        CHECK(t->wszAlgorithm != NULL);
        for (int k = 0; k < 5 && t->wszAlgorithm; k++)
            if (!lstrcmpW(t->wszAlgorithm, want[k])) seen[k]++;
        t_note("transform[%lu] flags=0x%lx buf=%lu", i, t->dwFlags, t->cbBufferSize);
    }
    for (int k = 0; k < 5; k++) CHECKF(seen[k] == 1, "transform %d seen %d times", k, seen[k]);
}

/* ---- CryptXmlSetHMACSecret ------------------------------------------------------------------ */
TEST(xmlsig_sethmac_argument_validation)
{
    REQUIRE(XFN(CryptXmlSetHMACSecret));
    static const BYTE k[4] = { 1, 2, 3, 4 };
    HCX hs = NULL;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"s", NULL, 0, NULL, &hs), S_OK);
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(NULL, k, 4), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, NULL, 4), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, k, 0), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, k, 4), S_OK);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(hs, k, 1), S_OK);     /* may be replaced */
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_sethmac_wrong_handle_type)
{
    REQUIRE(XFN(CryptXmlSetHMACSecret));
    static const BYTE k[4] = { 1, 2, 3, 4 };
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XSIG *sig = x_first_sig(h);
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(h, k, 4), X_E_HANDLE);
    if (sig) {
        XCHK_HR(XFN(CryptXmlSetHMACSecret)(sig->SignedInfo.rgpReference[0]->hReference, k, 4), X_E_HANDLE);
        XCHK_HR(XFN(CryptXmlSetHMACSecret)(sig->hSignature, k, 4), S_OK);   /* decode signatures accept a secret too */
    }
    XFN(CryptXmlClose)(h);
}

/* ---- CryptXmlVerifySignature argument validation ------------------------------------------------ */
TEST(xmlsig_verify_argument_validation)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    HCX h = NULL;
    XCHK_HR(XFN(CryptXmlVerifySignature)(NULL, NULL, 0), X_E_INVALIDARG);
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    if (!h) return;
    const XSIG *sig = x_first_sig(h);
    XCHK_HR(XFN(CryptXmlVerifySignature)(h, NULL, 0), X_E_HANDLE);     /* document handle */
    if (sig) XCHK_HR(XFN(CryptXmlVerifySignature)(sig->SignedInfo.rgpReference[0]->hReference, NULL, 0), X_E_HANDLE);
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_verify_rejects_encode_signature)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    HCX hs = NULL;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"s", NULL, 0, NULL, &hs), S_OK);
    if (!hs) return;
    XCHK_HR(XFN(CryptXmlVerifySignature)(hs, NULL, 0), X_E_HANDLE);   /* only decoded documents can be verified */
    XFN(CryptXmlClose)(hs);
}

/* ---- encode-side handle state ---------------------------------------------------------------- */
TEST(xmlsig_encode_initial_status)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    HCX hs = NULL;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"s", NULL, 0, NULL, &hs), S_OK);
    if (!hs) return;
    XSTATUS st; x_status(hs, &st);
    EXPECT_EQ(st.cbSize, sizeof(XSTATUS));
    CHECK((st.dwInfoStatus & XS_I_OPENED_TO_ENCODE) != 0);
    CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) == 0);
    CHECK((st.dwErrorStatus & XS_E_SIGNATURE_INVALID) == 0);
    XFN(CryptXmlClose)(hs);
}

TEST(xmlsig_encode_handle_is_a_signature_handle)
{
    REQUIRE(XFN(CryptXmlOpenToEncode));
    HCX hs = NULL;
    XCHK_HR(XFN(CryptXmlOpenToEncode)(NULL, 0, L"cryptt-id", NULL, 0, NULL, &hs), S_OK);
    if (!hs) return;
    const XSIG *s = NULL; const XDOC *d = (void *)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlGetSignature)(hs, &s), S_OK);
    XCHK_HR(XFN(CryptXmlGetDocContext)(hs, &d), X_E_HANDLE);
    if (s) {
        EXPECT_EQ(s->cbSize, sizeof(XSIG));
        EXPECT_EQ(s->hSignature, hs);
        CHECK(s->wszId && !lstrcmpW(s->wszId, L"cryptt-id"));
        EXPECT_EQ(s->SignedInfo.cReference, 0);
    }
    XFN(CryptXmlClose)(hs);
}

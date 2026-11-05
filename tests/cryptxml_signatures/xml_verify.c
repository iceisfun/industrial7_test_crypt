/* cryptxml.dll: decoding fixed signed documents and verifying them (HMAC and public-key). */
#include "xml.h"
#include <stdlib.h>

typedef struct {
    const char *name, *xml;
    const BYTE *digest; ULONG dlen; const BYTE *sig; ULONG slen;
    const WCHAR *sigUri, *digUri, *canonUri, *transUri;
    const WCHAR *bcHash;
} VEC;
#define V(n, s, d, c, t, bc) { #n, n##_xml, n##_digest, n##_digest_len, n##_sig, n##_sig_len, s, d, c, t, bc }
static const VEC HV[] = {
    V(X_H256, U_HMAC256, U_SHA256, U_C14N, U_C14N, L"SHA256"),
    V(X_H1,   U_HMAC1,   U_SHA1,   U_EXC,  U_EXC,  L"SHA1"),
    V(X_H384, U_HMAC384, U_SHA384, U_C14N, U_C14N, L"SHA384"),
    V(X_H512, U_HMAC512, U_SHA512, U_EXC,  U_EXC,  L"SHA512"),
    V(X_HDS,  U_HMAC256, U_SHA256, U_C14N, NULL,   L"SHA256"),
};

static void decode_checks(const VEC *v)
{
    HCX h = NULL;
    HRESULT hr = x_decode(v->xml, NULL, 0, &h);
    CHECKF(hr == S_OK, "%s: decode 0x%08lx", v->name, (unsigned long)hr);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    CHECKF(s != NULL, "%s: no signature", v->name);
    if (!s) { if (h) XFN(CryptXmlClose)(h); return; }
    CHECK(s->wszId == NULL || !*s->wszId);
    CHECK(s->SignedInfo.Canonicalization.wszAlgorithm && !lstrcmpW(s->SignedInfo.Canonicalization.wszAlgorithm, v->canonUri));
    CHECK(s->SignedInfo.SignatureMethod.wszAlgorithm && !lstrcmpW(s->SignedInfo.SignatureMethod.wszAlgorithm, v->sigUri));
    EXPECT_EQ(s->SignedInfo.cReference, 1);
    if (s->SignedInfo.cReference == 1) {
        const XREF *r = s->SignedInfo.rgpReference[0];
        EXPECT_EQ(r->cbSize, sizeof(XREF));
        CHECK(r->wszUri && !lstrcmpW(r->wszUri, L"#d1"));
        CHECK(r->wszId == NULL || !*r->wszId);
        CHECK(r->wszType == NULL || !*r->wszType);
        CHECK(r->DigestMethod.wszAlgorithm && !lstrcmpW(r->DigestMethod.wszAlgorithm, v->digUri));
        CHECKF(r->DigestValue.cbData == v->dlen, "%s: digest size %lu", v->name, r->DigestValue.cbData);
        if (r->DigestValue.cbData == v->dlen) CHECK(!memcmp(r->DigestValue.pbData, v->digest, v->dlen));
        if (v->transUri) {
            EXPECT_EQ(r->cTransform, 1);
            if (r->cTransform == 1) CHECK(!lstrcmpW(r->rgTransform[0].wszAlgorithm, v->transUri));
        } else EXPECT_EQ(r->cTransform, 0);
        EXPECT_EQ(r->hReference != NULL, 1);
    }
    CHECKF(s->SignatureValue.cbData == v->slen, "%s: signature size %lu", v->name, s->SignatureValue.cbData);
    if (s->SignatureValue.cbData == v->slen) CHECK(!memcmp(s->SignatureValue.pbData, v->sig, v->slen));
    EXPECT_EQ(s->pKeyInfo, NULL);
    EXPECT_EQ(s->cObject, 0);
    XFN(CryptXmlClose)(h);
}

static void verify_checks(const VEC *v)
{
    HCX h = NULL;
    XCHK_HR(x_decode(v->xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (!s) { if (h) XFN(CryptXmlClose)(h); return; }
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, X_SECRET, X_SECRET_len), S_OK);
    XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
    XSTATUS st;
    x_status(s->hSignature, &st);
    CHECKF(st.dwErrorStatus == 0, "%s: sig error 0x%lx", v->name, st.dwErrorStatus);
    CHECKF(st.dwInfoStatus == (XS_I_SIGNATURE_VALID | XS_I_DIGEST_VALID), "%s: sig info 0x%lx", v->name, st.dwInfoStatus);
    x_status(s->SignedInfo.rgpReference[0]->hReference, &st);
    CHECKF(st.dwErrorStatus == 0, "%s: ref error 0x%lx", v->name, st.dwErrorStatus);
    CHECKF((st.dwInfoStatus & XS_I_DIGEST_VALID) != 0, "%s: ref info 0x%lx", v->name, st.dwInfoStatus);
    x_status(h, &st);
    CHECKF(st.dwErrorStatus == 0 && st.dwInfoStatus == XS_I_SIGNATURE_VALID, "%s: doc status %lx/%lx", v->name, st.dwErrorStatus, st.dwInfoStatus);
    XFN(CryptXmlClose)(h);
}

static void wrong_secret_checks(const VEC *v)
{
    static const BYTE bad[] = "cryptxml-test-secret-012345678X";      /* one byte different from the real secret */
    HCX h = NULL;
    XCHK_HR(x_decode(v->xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (!s) { if (h) XFN(CryptXmlClose)(h); return; }
    XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, bad, X_SECRET_len), S_OK);
    HRESULT hr = XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0);
    CHECKF(hr == X_E_VERIFY_FAILED, "%s: wrong secret hr=0x%08lx", v->name, (unsigned long)hr);
    XSTATUS st; x_status(s->hSignature, &st);
    CHECK((st.dwErrorStatus & XS_E_SIGNATURE_INVALID) != 0);
    CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) == 0);
    x_status(h, &st);
    CHECK((st.dwErrorStatus & XS_E_SIGNATURE_INVALID) != 0);
    CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) == 0);
    XFN(CryptXmlClose)(h);
}

#define VEC_TESTS(I, NAME) \
TEST(xmlsig_hmac_doc_decode_##NAME) { REQUIRE(XFN(CryptXmlOpenToDecode)); decode_checks(&HV[I]); } \
TEST(xmlsig_hmac_doc_verify_##NAME) { REQUIRE(XFN(CryptXmlVerifySignature)); verify_checks(&HV[I]); } \
TEST(xmlsig_hmac_doc_wrong_secret_##NAME) { REQUIRE(XFN(CryptXmlVerifySignature)); wrong_secret_checks(&HV[I]); }
VEC_TESTS(0, hmac_sha256)
VEC_TESTS(1, hmac_sha1_exc)
VEC_TESTS(2, hmac_sha384)
VEC_TESTS(3, hmac_sha512_exc)
VEC_TESTS(4, prefixed_default_c14n)

/* ---- vector self check: independent of the DLL ---------------------------------------------------- */
TEST(xmlsig_vectors_selfcheck)
{
    BYTE h[64]; ULONG hl;
    if (!x_hash(L"SHA256", NULL, 0, "abc", 3, h, &hl)) { t_skip("bcrypt hashing unavailable"); return; }
    CHECK(hl == 32 && !memcmp(h, X_ABC_SHA256, 32));
    for (int i = 0; i < 5; i++) {
        const VEC *v = &HV[i];
        CHECKF(x_hash(v->bcHash, NULL, 0, "<Data Id=\"d1\">hello world</Data>", 32, h, &hl) && hl == v->dlen && !memcmp(h, v->digest, hl),
               "%s: embedded digest is not the hash of the canonical Data element", v->name);
        /* the signature value is the HMAC of the canonical SignedInfo */
        const BYTE *canon = NULL; ULONG cl = 0;
        switch (i) { case 0: canon = X_H256_canon; cl = X_H256_canon_len; break; case 1: canon = X_H1_canon; cl = X_H1_canon_len; break;
                     case 2: canon = X_H384_canon; cl = X_H384_canon_len; break; case 3: canon = X_H512_canon; cl = X_H512_canon_len; break;
                     default: canon = X_HDS_canon; cl = X_HDS_canon_len; }
        CHECKF(x_hash(v->bcHash, X_SECRET, X_SECRET_len, canon, cl, h, &hl) && hl == v->slen && !memcmp(h, v->sig, hl), "%s: embedded HMAC", v->name);
        /* the canonical form is what our own canonicalizer derives from the document text */
        char *c = x_canon_signedinfo(v->xml);
        CHECKF(c && strlen(c) == cl && !memcmp(c, canon, cl), "%s: mini canonicalizer disagrees: %s", v->name, c ? c : "(null)");
        free(c);
    }
}

/* ---- tampering ---------------------------------------------------------------------------------------- */
static HCX decode_hmac(const char *xml, const XSIG **ps)
{
    HCX h = NULL;
    XCHK_HR(x_decode(xml, NULL, 0, &h), S_OK);
    *ps = h ? x_first_sig(h) : NULL;
    if (*ps) XCHK_HR(XFN(CryptXmlSetHMACSecret)((*ps)->hSignature, X_SECRET, X_SECRET_len), S_OK);
    return h;
}

TEST(xmlsig_verify_tampered_referenced_data)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    char *t = x_tamper(X_H256_xml, "hello world", "hello worlD");
    const XSIG *s;
    HCX h = t ? decode_hmac(t, &s) : NULL;
    CHECK(t != NULL);
    if (h && s) {
        /* the signature is intact, the referenced content is not: reported through the status only */
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
        XSTATUS st; x_status(s->hSignature, &st);
        EXPECT_EQ(st.dwErrorStatus, XS_E_DIGEST_INVALID);
        EXPECT_EQ(st.dwInfoStatus, XS_I_SIGNATURE_VALID);
        x_status(s->SignedInfo.rgpReference[0]->hReference, &st);
        EXPECT_EQ(st.dwErrorStatus, XS_E_DIGEST_INVALID);
        CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) == 0);
        x_status(h, &st);
        EXPECT_EQ(st.dwErrorStatus, XS_E_DIGEST_INVALID);
        EXPECT_EQ(st.dwInfoStatus, XS_I_SIGNATURE_VALID);
    }
    if (h) XFN(CryptXmlClose)(h);
    free(t);
}

static char *flip_after(const char *xml, const char *marker)
{
    char *c = _strdup(xml);
    char *p = strstr(c, marker);
    if (!p) { free(c); return NULL; }
    p += strlen(marker);
    *p = (*p == 'A') ? 'B' : 'A';
    return c;
}

TEST(xmlsig_verify_tampered_digest_value_breaks_signature)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    char *t = flip_after(X_H256_xml, "<DigestValue>");        /* part of SignedInfo, so the HMAC no longer matches */
    const XSIG *s;
    HCX h = t ? decode_hmac(t, &s) : NULL;
    CHECK(t != NULL);
    if (h && s) XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), X_E_VERIFY_FAILED);
    if (h) XFN(CryptXmlClose)(h);
    free(t);
}

TEST(xmlsig_verify_tampered_signature_value)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    char *t = flip_after(X_H256_xml, "<SignatureValue>");
    const XSIG *s;
    HCX h = t ? decode_hmac(t, &s) : NULL;
    CHECK(t != NULL);
    if (h && s) XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), X_E_VERIFY_FAILED);
    if (h) XFN(CryptXmlClose)(h);
    free(t);
}

TEST(xmlsig_verify_tampered_signed_info_attributes)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    struct { const char *from, *to; } t[] = {
        { "hmac-sha256", "hmac-sha512" },                         /* other HMAC: different key stream and size */
        { "URI=\"#d1\"", "URI=\"#d2\"" } };
    for (int i = 0; i < 2; i++) {
        char *x = x_tamper(X_H256_xml, t[i].from, t[i].to);
        const XSIG *s;
        HCX h = x ? decode_hmac(x, &s) : NULL;
        CHECKF(x != NULL, "case %d not applicable", i);
        if (h && s) {
            HRESULT hr = XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0);
            CHECKF(hr == X_E_VERIFY_FAILED, "case %d hr=0x%08lx", i, (unsigned long)hr);
        }
        if (h) XFN(CryptXmlClose)(h);
        free(x);
    }
}

TEST(xmlsig_verify_whitespace_in_signed_info_is_canonicalized_away)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    /* attribute quoting and empty-element syntax do not matter to the canonical form; the HMAC still matches */
    char *x = malloc(strlen(X_H256_xml) + 16);
    char *p;
    strcpy(x, X_H256_xml);
    p = strstr(x, "\"/>");
    CHECK(p != NULL);
    if (p) {                                             /* a="v"/>  ->  a="v"  /> : insignificant whitespace inside the tag */
        memmove(p + 3, p + 1, strlen(p + 1) + 1);
        p[1] = ' '; p[2] = ' ';
    }
    const XSIG *s;
    HCX h = decode_hmac(x, &s);
    if (h && s) XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
    if (h) XFN(CryptXmlClose)(h);
    free(x);
}

TEST(xmlsig_verify_missing_reference_target)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    const XSIG *s;
    HCX h = decode_hmac(X_HMISS_xml, &s);
    if (h && s) {
        /* the HMAC is valid; resolving "#nosuch" fails afterwards */
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), X_E_UNRESOLVED_REF);
    }
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_verify_unknown_signature_method_without_key)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    char *x = x_tamper(X_H256_xml, "hmac-sha256", "hmac-sha2xx");
    HCX h = NULL;
    CHECK(x != NULL);
    if (x) XCHK_HR(x_decode(x, NULL, 0, &h), S_OK);      /* unknown algorithms are accepted by the decoder */
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s) {
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), X_E_ALGORITHM);
        XSTATUS st; x_status(h, &st);
        t_note("status after unsupported signature method: error 0x%lx info 0x%lx", st.dwErrorStatus, st.dwInfoStatus);
    }
    if (h) XFN(CryptXmlClose)(h);
    free(x);
}

TEST(xmlsig_verify_is_repeatable)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    const XSIG *s;
    HCX h = decode_hmac(X_H256_xml, &s);
    if (h && s) {
        for (int i = 0; i < 3; i++) XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
        XSTATUS st; x_status(s->hSignature, &st);
        EXPECT_EQ(st.dwInfoStatus, XS_I_SIGNATURE_VALID | XS_I_DIGEST_VALID);
    }
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_verify_failure_then_success_with_corrected_secret)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    static const BYTE bad[] = "zzzzzzzz";
    const XSIG *s;
    HCX h = decode_hmac(X_H256_xml, &s);
    if (h && s) {
        XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, bad, 8), S_OK);
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), X_E_VERIFY_FAILED);
        XCHK_HR(XFN(CryptXmlSetHMACSecret)(s->hSignature, X_SECRET, X_SECRET_len), S_OK);
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
        XSTATUS st; x_status(s->hSignature, &st);
        EXPECT_EQ(st.dwErrorStatus, 0);
        CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) != 0);
    }
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_verify_without_secret_does_not_succeed)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H256_xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s) {
        HRESULT hr = XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0);
        CHECKF(FAILED(hr), "verify with no secret returned 0x%08lx", (unsigned long)hr);
        t_note("HMAC verify without a secret -> 0x%08lx", (unsigned long)hr);
    }
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_two_signatures_document_status)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    HCX h = NULL;
    XCHK_HR(x_decode(X_H2SIG_xml, NULL, 0, &h), S_OK);
    const XDOC *d = NULL;
    if (!h) return;
    XCHK_HR(XFN(CryptXmlGetDocContext)(h, &d), S_OK);
    if (d && d->cSignature == 2) {
        const XSIG *a = d->rgpSignature[0], *b = d->rgpSignature[1];
        CHECK(!lstrcmpW(a->SignedInfo.SignatureMethod.wszAlgorithm, U_HMAC256));
        CHECK(!lstrcmpW(b->SignedInfo.SignatureMethod.wszAlgorithm, U_HMAC1));
        CHECK(a->hSignature != b->hSignature);
        XCHK_HR(XFN(CryptXmlSetHMACSecret)(a->hSignature, X_SECRET, X_SECRET_len), S_OK);
        XCHK_HR(XFN(CryptXmlSetHMACSecret)(b->hSignature, X_SECRET, X_SECRET_len), S_OK);
        XSTATUS st; x_status(h, &st);
        EXPECT_EQ(st.dwInfoStatus, 0);
        XCHK_HR(XFN(CryptXmlVerifySignature)(a->hSignature, NULL, 0), S_OK);
        x_status(h, &st);
        EXPECT_EQ(st.dwInfoStatus & XS_I_SIGNATURE_VALID, 0);    /* only one of two signatures verified */
        XCHK_HR(XFN(CryptXmlVerifySignature)(b->hSignature, NULL, 0), S_OK);
        x_status(h, &st);
        EXPECT_EQ(st.dwErrorStatus, 0);
        EXPECT_EQ(st.dwInfoStatus, XS_I_SIGNATURE_VALID);
    } else CHECK(0);
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_two_signatures_one_secret_wrong)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    static const BYTE bad[] = "wrong";
    HCX h = NULL;
    XCHK_HR(x_decode(X_H2SIG_xml, NULL, 0, &h), S_OK);
    const XDOC *d = NULL;
    if (!h) return;
    XFN(CryptXmlGetDocContext)(h, &d);
    if (d && d->cSignature == 2) {
        XFN(CryptXmlSetHMACSecret)(d->rgpSignature[0]->hSignature, X_SECRET, X_SECRET_len);
        XFN(CryptXmlSetHMACSecret)(d->rgpSignature[1]->hSignature, bad, 5);
        XCHK_HR(XFN(CryptXmlVerifySignature)(d->rgpSignature[0]->hSignature, NULL, 0), S_OK);
        XCHK_HR(XFN(CryptXmlVerifySignature)(d->rgpSignature[1]->hSignature, NULL, 0), X_E_VERIFY_FAILED);
        XSTATUS st; x_status(h, &st);
        CHECK((st.dwErrorStatus & XS_E_SIGNATURE_INVALID) != 0);
        CHECK((st.dwInfoStatus & XS_I_SIGNATURE_VALID) == 0);
    }
    XFN(CryptXmlClose)(h);
}

TEST(xmlsig_decoded_reference_status_resolves_on_verify)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    const XSIG *s;
    HCX h = decode_hmac(X_H256_xml, &s);
    if (h && s) {
        HCX hr = s->SignedInfo.rgpReference[0]->hReference;
        XSTATUS st; x_status(hr, &st);
        EXPECT_EQ(st.dwErrorStatus, XS_E_NOT_RESOLVED);
        EXPECT_EQ(st.dwInfoStatus, XS_I_INTERNAL_REFERENCE);      /* "#d1" is a same-document reference */
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0), S_OK);
        x_status(hr, &st);
        EXPECT_EQ(st.dwErrorStatus, 0);
        EXPECT_EQ(st.dwInfoStatus, XS_I_INTERNAL_REFERENCE | XS_I_DIGEST_VALID);
    }
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_decoded_reference_digest_by_provider)
{
    REQUIRE(XFN(CryptXmlDigestReference));
    const XSIG *s;
    HCX h = decode_hmac(X_H256_xml, &s);
    if (h && s) {
        /* feeding the same-document reference manually: no transform chain is needed when the data is flagged as transformed */
        HCX hr = s->SignedInfo.rgpReference[0]->hReference;
        XMEM m; XPROV pv;
        x_prov(&pv, &m, "<Data Id=\"d1\">hello world</Data>", 32, 0);
        XCHK_HR(XFN(CryptXmlDigestReference)(hr, X_REFERENCE_DATA_TRANSFORMED, &pv), S_OK);
        XSTATUS st; x_status(hr, &st);
        EXPECT_EQ(st.dwErrorStatus, 0);
        CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) != 0);
        x_prov(&pv, &m, "<Data Id=\"d1\">hello worlD</Data>", 32, 0);
        XCHK_HR(XFN(CryptXmlDigestReference)(hr, X_REFERENCE_DATA_TRANSFORMED, &pv), S_OK);
        x_status(hr, &st);
        EXPECT_EQ(st.dwErrorStatus, XS_E_DIGEST_INVALID);
        CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) == 0);
        /* a matching digest afterwards restores the valid state */
        x_prov(&pv, &m, "<Data Id=\"d1\">hello world</Data>", 32, 0);
        XCHK_HR(XFN(CryptXmlDigestReference)(hr, X_REFERENCE_DATA_TRANSFORMED, &pv), S_OK);
        x_status(hr, &st);
        EXPECT_EQ(st.dwErrorStatus, 0);
        CHECK((st.dwInfoStatus & XS_I_DIGEST_VALID) != 0);
    }
    if (h) XFN(CryptXmlClose)(h);
}

/* ---- public-key signed documents ----------------------------------------------------------------------- */
typedef struct { const char *name, *xml; DWORD kvType; const BYTE *sig; ULONG slen; int rsa_like; } KVEC;
static const KVEC KV[] = {
    { "rsa-sha256", X_R256_xml, 2, X_R256_sig, X_R256_sig_len, 1 },
    { "rsa-sha1",   X_R1_xml,   2, X_R1_sig,   X_R1_sig_len,   1 },
    { "rsa-sha512-exc", X_R512_xml, 2, X_R512_sig, X_R512_sig_len, 1 },
    { "dsa-sha1",   X_D1_xml,   1, X_D1_sig,   X_D1_sig_len,   0 },
    { "ecdsa-p256-sha256", X_E256_xml, 3, X_E256_sig, X_E256_sig_len, 0 },
    { "ecdsa-p384-sha384", X_E384_xml, 3, X_E384_sig, X_E384_sig_len, 0 },
    { "ecdsa-p521-sha512", X_E521_xml, 3, X_E521_sig, X_E521_sig_len, 0 },
};

static void key_decode_checks(const KVEC *k)
{
    HCX h = NULL;
    XCHK_HR(x_decode(k->xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (!s) { if (h) XFN(CryptXmlClose)(h); return; }
    CHECKF(s->SignatureValue.cbData == k->slen, "%s: signature size %lu", k->name, s->SignatureValue.cbData);
    if (s->SignatureValue.cbData == k->slen) CHECK(!memcmp(s->SignatureValue.pbData, k->sig, k->slen));
    CHECKF(s->pKeyInfo != NULL, "%s: no KeyInfo", k->name);
    if (s->pKeyInfo) {
        EXPECT_EQ(s->pKeyInfo->cbSize, sizeof(XKEYINFO));
        EXPECT_EQ(s->pKeyInfo->cKeyInfo, 1);
        if (s->pKeyInfo->cKeyInfo == 1) {
            const XKEYINFOITEM *it = &s->pKeyInfo->rgKeyInfo[0];
            EXPECT_EQ(it->dwType, 2);                   /* CRYPT_XML_KEYINFO_TYPE_KEYVALUE */
            if (it->dwType == 2) {
                if (k->kvType == 3 && it->u.KeyValue.dwType != 3) t_note("%s: KeyValue type %lu (EC form not recognised)", k->name, it->u.KeyValue.dwType);
                else EXPECT_EQ(it->u.KeyValue.dwType, k->kvType);
            }
        }
        if (k->kvType == 3 && !s->pKeyInfo->hVerifyKey) t_note("%s: no verify key imported from the EC KeyValue", k->name);
        else CHECKF(s->pKeyInfo->hVerifyKey != NULL, "%s: no hVerifyKey", k->name);
    }
    XSTATUS st; x_status(s->hSignature, &st);
    if (s->pKeyInfo && s->pKeyInfo->hVerifyKey) CHECKF((st.dwInfoStatus & XS_I_KEY_AVAILABLE) != 0, "%s: KEY_AVAILABLE missing (0x%lx)", k->name, st.dwInfoStatus);
    CHECK((st.dwErrorStatus & XS_E_KEYINFO_NOT_PARSED) == 0 || k->kvType == 3);
    XFN(CryptXmlClose)(h);
}

static void key_verify_checks(const KVEC *k)
{
    HCX h = NULL;
    XCHK_HR(x_decode(k->xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (!s || !s->pKeyInfo || !s->pKeyInfo->hVerifyKey) {
        t_note("%s: no imported key, verification skipped", k->name);
        if (h) XFN(CryptXmlClose)(h);
        return;
    }
    XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, s->pKeyInfo->hVerifyKey, 0), S_OK);
    XSTATUS st; x_status(s->hSignature, &st);
    CHECKF(st.dwErrorStatus == 0, "%s: error 0x%lx", k->name, st.dwErrorStatus);
    CHECKF(st.dwInfoStatus == (XS_I_SIGNATURE_VALID | XS_I_DIGEST_VALID | XS_I_KEY_AVAILABLE), "%s: info 0x%lx", k->name, st.dwInfoStatus);
    /* no key at all: the CNG verifier fails and everything is reported as a verify failure */
    HRESULT hr = XFN(CryptXmlVerifySignature)(s->hSignature, NULL, 0);
    CHECKF(hr == X_E_VERIFY_FAILED, "%s: verify with NULL key hr=0x%08lx", k->name, (unsigned long)hr);
    /* and the failure is not sticky */
    XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, s->pKeyInfo->hVerifyKey, 0), S_OK);
    XFN(CryptXmlClose)(h);
}

static void key_tamper_checks(const KVEC *k)
{
    /* modified referenced content: signature fine, digest flagged; modified SignedInfo: signature fails */
    char *t1 = x_tamper(k->xml, "hello world", "hello worlD");
    char *t2 = flip_after(k->xml, "<DigestValue>");
    char *t3 = flip_after(k->xml, "<SignatureValue>");
    char *docs[3] = { t1, t2, t3 };
    for (int i = 0; i < 3; i++) {
        HCX h = NULL;
        CHECKF(docs[i] != NULL, "%s: tamper %d", k->name, i);
        if (!docs[i]) continue;
        XCHK_HR(x_decode(docs[i], NULL, 0, &h), S_OK);
        const XSIG *s = h ? x_first_sig(h) : NULL;
        if (s && s->pKeyInfo && s->pKeyInfo->hVerifyKey) {
            HRESULT hr = XFN(CryptXmlVerifySignature)(s->hSignature, s->pKeyInfo->hVerifyKey, 0);
            if (i == 0) {
                CHECKF(hr == S_OK, "%s: tampered data hr=0x%08lx", k->name, (unsigned long)hr);
                XSTATUS st; x_status(s->hSignature, &st);
                CHECKF(st.dwErrorStatus == XS_E_DIGEST_INVALID, "%s: error 0x%lx", k->name, st.dwErrorStatus);
            } else CHECKF(hr == X_E_VERIFY_FAILED, "%s: tamper %d hr=0x%08lx", k->name, i, (unsigned long)hr);
        }
        if (h) XFN(CryptXmlClose)(h);
    }
    free(t1); free(t2); free(t3);
}

#define KEY_TESTS(I, NAME) \
TEST(xmlsig_key_doc_decode_##NAME) { REQUIRE(XFN(CryptXmlOpenToDecode)); key_decode_checks(&KV[I]); } \
TEST(xmlsig_key_doc_verify_##NAME) { REQUIRE(XFN(CryptXmlVerifySignature)); key_verify_checks(&KV[I]); } \
TEST(xmlsig_key_doc_tamper_##NAME) { REQUIRE(XFN(CryptXmlVerifySignature)); key_tamper_checks(&KV[I]); }
KEY_TESTS(0, rsa_sha256)
KEY_TESTS(1, rsa_sha1)
KEY_TESTS(2, rsa_sha512_exc)
KEY_TESTS(3, dsa_sha1)
KEY_TESTS(4, ecdsa_p256)
KEY_TESTS(5, ecdsa_p384)
KEY_TESTS(6, ecdsa_p521)

TEST(xmlsig_key_doc_rsa_keyvalue_fields)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    HCX h = NULL;
    XCHK_HR(x_decode(X_R256_xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s && s->pKeyInfo && s->pKeyInfo->cKeyInfo == 1) {
        const XRSAKV *rk = &s->pKeyInfo->rgKeyInfo[0].u.KeyValue.u.RSA;
        EXPECT_EQ(rk->Modulus.cbData, X_RSA1_MOD_len);
        if (rk->Modulus.cbData == X_RSA1_MOD_len) CHECK(!memcmp(rk->Modulus.pbData, X_RSA1_MOD, X_RSA1_MOD_len));
        EXPECT_EQ(rk->Exponent.cbData, 3);
        if (rk->Exponent.cbData == 3) CHECK(!memcmp(rk->Exponent.pbData, X_RSA_EXP, 3));
    } else CHECK(0);
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_key_doc_dsa_keyvalue_fields)
{
    REQUIRE(XFN(CryptXmlOpenToDecode));
    HCX h = NULL;
    XCHK_HR(x_decode(X_D1_xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s && s->pKeyInfo && s->pKeyInfo->cKeyInfo == 1) {
        const XDSAKV *dk = &s->pKeyInfo->rgKeyInfo[0].u.KeyValue.u.DSA;
        EXPECT_EQ(dk->P.cbData, X_DSA_P_len); EXPECT_EQ(dk->Q.cbData, X_DSA_Q_len);
        EXPECT_EQ(dk->G.cbData, X_DSA_G_len); EXPECT_EQ(dk->Y.cbData, X_DSA_Y_len);
        if (dk->P.cbData == X_DSA_P_len) CHECK(!memcmp(dk->P.pbData, X_DSA_P, X_DSA_P_len));
        if (dk->Q.cbData == X_DSA_Q_len) CHECK(!memcmp(dk->Q.pbData, X_DSA_Q, X_DSA_Q_len));
        if (dk->G.cbData == X_DSA_G_len) CHECK(!memcmp(dk->G.pbData, X_DSA_G, X_DSA_G_len));
        if (dk->Y.cbData == X_DSA_Y_len) CHECK(!memcmp(dk->Y.pbData, X_DSA_Y, X_DSA_Y_len));
        EXPECT_EQ(dk->J.cbData, 0); EXPECT_EQ(dk->Seed.cbData, 0); EXPECT_EQ(dk->Counter.cbData, 0);
    } else CHECK(0);
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_key_doc_wrong_rsa_key_fails)
{
    REQUIRE(XFN(CryptXmlImportPublicKey));
    HCX h = NULL;
    XCHK_HR(x_decode(X_R256_xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s) {
        XKEYVALUE kv;
        void *key = NULL;
        memset(&kv, 0, sizeof kv);
        kv.dwType = 2;
        kv.u.RSA.Modulus.cbData = X_RSA2_MOD_len; kv.u.RSA.Modulus.pbData = (BYTE *)X_RSA2_MOD;
        kv.u.RSA.Exponent.cbData = 3; kv.u.RSA.Exponent.pbData = (BYTE *)X_RSA_EXP;
        XCHK_HR(XFN(CryptXmlImportPublicKey)(0, &kv, &key), S_OK);
        if (key) {
            XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, key, 0), X_E_VERIFY_FAILED);
            U(BCryptDestroyKey)(key);
        }
    }
    if (h) XFN(CryptXmlClose)(h);
}

TEST(xmlsig_key_doc_rsa_signature_is_rejected_for_other_hash)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    /* same signature bytes, but SignatureMethod rewritten to rsa-sha384: the digest differs, verification must fail */
    char *x = x_tamper(X_R256_xml, "rsa-sha256", "rsa-sha384");
    HCX h = NULL;
    CHECK(x != NULL);
    if (x) XCHK_HR(x_decode(x, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s && s->pKeyInfo && s->pKeyInfo->hVerifyKey)
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, s->pKeyInfo->hVerifyKey, 0), X_E_VERIFY_FAILED);
    if (h) XFN(CryptXmlClose)(h);
    free(x);
}

TEST(xmlsig_key_doc_disable_extensions_flag_on_verify)
{
    REQUIRE(XFN(CryptXmlVerifySignature));
    HCX h = NULL;
    XCHK_HR(x_decode(X_R256_xml, NULL, 0, &h), S_OK);
    const XSIG *s = h ? x_first_sig(h) : NULL;
    if (s && s->pKeyInfo && s->pKeyInfo->hVerifyKey)
        XCHK_HR(XFN(CryptXmlVerifySignature)(s->hSignature, s->pKeyInfo->hVerifyKey, X_FLAG_DISABLE_EXT), S_OK);
    if (h) XFN(CryptXmlClose)(h);
}

/* CTL signing (CryptMsgSignCTL / CryptMsgEncodeAndSignCTL), subject lookup, sorted CTLs, entry/property mapping,
 * CertVerifyCTLUsage (offline). */
#include "cc.h"

static void rel(PCCTL_CONTEXT c) { if (c) U(CertFreeCTLContext)(c); }
static void relc(PCCERT_CONTEXT c) { if (c) U(CertFreeCertificateContext)(c); }

#define NOWINE(why) do { if (t_is_wine()) { t_skip(why); return; } } while (0)
#define NIDS 6
typedef struct {
    CTL_INFO info;
    CTL_ENTRY ent[NIDS];
    BYTE ids[NIDS][20];
    LPSTR usage[2];
    char listid[16];
} MK;

static void mk_info(MK *m, int n, const char *alg) {
    memset(m, 0, sizeof *m);
    for (int i = 0; i < NIDS; i++) {
        char seed[8]; wsprintfA(seed, "id%d", i);
        DWORD cb = 20;
        cc_hash(CALG_SHA1, (const BYTE *)seed, (DWORD)strlen(seed), m->ids[i], &cb);
        m->ent[i].SubjectIdentifier.cbData = 20;
        m->ent[i].SubjectIdentifier.pbData = m->ids[i];
    }
    m->usage[0] = (LPSTR)"1.3.6.1.5.5.7.3.3"; m->usage[1] = (LPSTR)"1.3.6.1.5.5.7.3.4";
    strcpy(m->listid, "mk-list");
    m->info.dwVersion = 0;
    m->info.SubjectUsage.cUsageIdentifier = 2; m->info.SubjectUsage.rgpszUsageIdentifier = m->usage;
    m->info.ListIdentifier.cbData = 7; m->info.ListIdentifier.pbData = (BYTE *)m->listid;
    static BYTE seq[] = { 0x2a };
    m->info.SequenceNumber.cbData = 1; m->info.SequenceNumber.pbData = seq;
    m->info.ThisUpdate.dwLowDateTime = (DWORD)V_THIS_FT; m->info.ThisUpdate.dwHighDateTime = (DWORD)(V_THIS_FT >> 32);
    m->info.NextUpdate.dwLowDateTime = (DWORD)V_NEXT_FT; m->info.NextUpdate.dwHighDateTime = (DWORD)(V_NEXT_FT >> 32);
    m->info.SubjectAlgorithm.pszObjId = (LPSTR)(alg ? alg : "1.3.14.3.2.26");
    m->info.cCTLEntry = n; m->info.rgCTLEntry = m->ent;
}

/* ---- CryptMsgEncodeAndSignCTL argument handling ---- */
TEST(ctlsign_requires_pkcs7_encoding_bit) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL));
    MK m; mk_info(&m, 3, NULL);
    HCRYPTPROV prov; PCCERT_CONTEXT sc;
    REQUIRE(cc_signer(&prov, &sc));
    CMSG_SIGNER_ENCODE_INFO si; memset(&si, 0, sizeof si);
    si.cbSize = sizeof si; si.pCertInfo = sc->pCertInfo; si.hCryptProv = prov; si.dwKeySpec = AT_SIGNATURE;
    si.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;
    CMSG_SIGNED_ENCODE_INFO se; memset(&se, 0, sizeof se);
    se.cbSize = sizeof se; se.cSigners = 1; se.rgSigners = &si;
    static const DWORD bad[] = { 0, X509_ASN_ENCODING, 1, 0xffff };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        DWORD cb = 0xdead;
        SET_ERR(0);
        CHECKF(!U(CryptMsgEncodeAndSignCTL)(bad[i], &m.info, &se, 0, NULL, &cb), "type 0x%lx", bad[i]);
        EXPECT_ERR(CC_E_INVALIDARG);
        EXPECT_EQ(cb, 0);
    }
    cc_signer_free(prov, sc);
}
TEST(ctlsign_size_query_and_exact_buffer) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL));
    MK m; mk_info(&m, 3, NULL);
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    CHECK(b != NULL && cb > 100);
    if (b) {
        CHECK(b[0] == 0x30);
        LocalFree(b);
    }
}
TEST(ctlsign_small_buffer_more_data) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL));
    MK m; mk_info(&m, 3, NULL);
    HCRYPTPROV prov; PCCERT_CONTEXT sc;
    REQUIRE(cc_signer(&prov, &sc));
    CMSG_SIGNER_ENCODE_INFO si; memset(&si, 0, sizeof si);
    si.cbSize = sizeof si; si.pCertInfo = sc->pCertInfo; si.hCryptProv = prov; si.dwKeySpec = AT_SIGNATURE;
    si.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;
    CMSG_SIGNED_ENCODE_INFO se; memset(&se, 0, sizeof se);
    se.cbSize = sizeof se; se.cSigners = 1; se.rgSigners = &si;
    DWORD need = 0;
    CHECK(U(CryptMsgEncodeAndSignCTL)(CC_X509P7, &m.info, &se, 0, NULL, &need));
    CHECK(need > 0);
    BYTE *buf = LocalAlloc(LPTR, need + 16);
    DWORD cb = need - 1;
    SET_ERR(0);
    CHECK(!U(CryptMsgEncodeAndSignCTL)(CC_X509P7, &m.info, &se, 0, buf, &cb)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    cb = need;
    CHECK(U(CryptMsgEncodeAndSignCTL)(CC_X509P7, &m.info, &se, 0, buf, &cb));
    t_note("size query %lu, actual %lu", need, cb);
    CHECK(cb <= need);
    LocalFree(buf);
    cc_signer_free(prov, sc);
}
TEST(ctlsign_roundtrip_into_context) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL));
    MK m; mk_info(&m, 3, NULL);
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    REQUIRE(b);
    PCCTL_CONTEXT c = cc_ctl(b, cb);
    CHECK(c != NULL);
    if (c) {
        PCTL_INFO i = c->pCtlInfo;
        EXPECT_EQ(i->dwVersion, 0);
        EXPECT_EQ(i->SubjectUsage.cUsageIdentifier, 2);
        if (i->SubjectUsage.cUsageIdentifier == 2) {
            EXPECT_STR(i->SubjectUsage.rgpszUsageIdentifier[0], "1.3.6.1.5.5.7.3.3");
            EXPECT_STR(i->SubjectUsage.rgpszUsageIdentifier[1], "1.3.6.1.5.5.7.3.4");
        }
        CHECK(i->ListIdentifier.cbData == 7 && !memcmp(i->ListIdentifier.pbData, "mk-list", 7));
        CHECK(i->SequenceNumber.cbData == 1 && i->SequenceNumber.pbData[0] == 0x2a);
        EXPECT_EQ(cc_ft(i->ThisUpdate), V_THIS_FT);
        EXPECT_EQ(cc_ft(i->NextUpdate), V_NEXT_FT);
        EXPECT_STR(i->SubjectAlgorithm.pszObjId, "1.3.14.3.2.26");
        EXPECT_EQ(i->cCTLEntry, 3);
        for (DWORD k = 0; k < i->cCTLEntry && k < 3; k++)
            CHECK(i->rgCTLEntry[k].SubjectIdentifier.cbData == 20 && !memcmp(i->rgCTLEntry[k].SubjectIdentifier.pbData, m.ids[k], 20));
        EXPECT_EQ(c->dwMsgAndCertEncodingType, CC_X509P7);
        rel(c);
    }
    LocalFree(b);
}
TEST(ctlsign_message_structure) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL)); REQUIRE(U(CryptMsgOpenToDecode));
    MK m; mk_info(&m, 2, NULL);
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    REQUIRE(b);
    HCRYPTMSG h = U(CryptMsgOpenToDecode)(CC_X509P7, 0, 0, 0, NULL, NULL);
    REQUIRE(h);
    CHECK(U(CryptMsgUpdate)(h, b, cb, TRUE));
    DWORD v = 0, n = sizeof v;
    CHECK(U(CryptMsgGetParam)(h, CMSG_TYPE_PARAM, 0, &v, &n)); EXPECT_EQ(v, CMSG_SIGNED);
    n = sizeof v; v = 0;
    CHECK(U(CryptMsgGetParam)(h, CMSG_SIGNER_COUNT_PARAM, 0, &v, &n)); EXPECT_EQ(v, 1);
    n = sizeof v; v = 0;
    CHECK(U(CryptMsgGetParam)(h, CMSG_CERT_COUNT_PARAM, 0, &v, &n)); EXPECT_EQ(v, 1);
    char oid[64]; n = sizeof oid;
    CHECK(U(CryptMsgGetParam)(h, CMSG_INNER_CONTENT_TYPE_PARAM, 0, oid, &n));
    EXPECT_STR(oid, "1.3.6.1.4.1.311.10.1");
    /* the signature verifies against the signer certificate */
    PCCERT_CONTEXT sc = cc_cert(VEC(v_signer));
    REQUIRE(sc);
    CHECK(U(CryptMsgControl)(h, 0, CMSG_CTRL_VERIFY_SIGNATURE, sc->pCertInfo));
    relc(sc);
    U(CryptMsgClose)(h);
    LocalFree(b);
}
TEST(ctlsign_signed_vector_verifies) {
    /* the fixed signed-CTL vectors carry a valid PKCS#7 signature by the signer certificate */
    REQUIRE(U(CryptMsgOpenToDecode));
    const struct { const BYTE *p; DWORD n; } vv[] = { { VEC(v_ctl_signed) }, { VEC(v_ctl_signed_nocerts) }, { VEC(v_ctl_signed_expired) }, { VEC(v_ctl_signed_min) } };
    PCCERT_CONTEXT sc = cc_cert(VEC(v_signer));
    REQUIRE(sc);
    for (unsigned i = 0; i < 4; i++) {
        HCRYPTMSG h = U(CryptMsgOpenToDecode)(CC_X509P7, 0, 0, 0, NULL, NULL);
        REQUIRE(h);
        CHECKF(U(CryptMsgUpdate)(h, vv[i].p, vv[i].n, TRUE), "vector %u", i);
        SET_ERR(0);
        BOOL ok = U(CryptMsgControl)(h, 0, CMSG_CTRL_VERIFY_SIGNATURE, sc->pCertInfo);
        CHECKF(ok, "vector %u verify (err 0x%lx)", i, GetLastError());
        U(CryptMsgClose)(h);
    }
    relc(sc);
}
TEST(ctlsign_bad_signature_vector_fails_verification) {
    REQUIRE(U(CryptMsgOpenToDecode));
    PCCERT_CONTEXT sc = cc_cert(VEC(v_signer));
    REQUIRE(sc);
    HCRYPTMSG h = U(CryptMsgOpenToDecode)(CC_X509P7, 0, 0, 0, NULL, NULL);
    REQUIRE(h);
    CHECK(U(CryptMsgUpdate)(h, VEC(v_ctl_signed_badsig), TRUE));
    SET_ERR(0);
    BOOL ok = U(CryptMsgControl)(h, 0, CMSG_CTRL_VERIFY_SIGNATURE, sc->pCertInfo);
    CHECK(!ok);
    t_note("bad signature verify error 0x%lx", GetLastError());
    U(CryptMsgClose)(h);
    relc(sc);
}
TEST(ctlsign_wrong_signer_cert_fails_verification) {
    REQUIRE(U(CryptMsgOpenToDecode));
    PCCERT_CONTEXT other = cc_cert(VEC(v_ca2));
    REQUIRE(other);
    HCRYPTMSG h = U(CryptMsgOpenToDecode)(CC_X509P7, 0, 0, 0, NULL, NULL);
    REQUIRE(h);
    CHECK(U(CryptMsgUpdate)(h, VEC(v_ctl_signed), TRUE));
    SET_ERR(0);
    CHECK(!U(CryptMsgControl)(h, 0, CMSG_CTRL_VERIFY_SIGNATURE, other->pCertInfo));
    t_note("verify with unrelated cert error 0x%lx", GetLastError());
    U(CryptMsgClose)(h);
    relc(other);
}
TEST(ctlsign_raw_content_variant) {
    REQUIRE(U(CryptMsgSignCTL));
    HCRYPTPROV prov; PCCERT_CONTEXT sc;
    REQUIRE(cc_signer(&prov, &sc));
    CMSG_SIGNER_ENCODE_INFO si; memset(&si, 0, sizeof si);
    si.cbSize = sizeof si; si.pCertInfo = sc->pCertInfo; si.hCryptProv = prov; si.dwKeySpec = AT_SIGNATURE;
    si.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;
    CMSG_SIGNED_ENCODE_INFO se; memset(&se, 0, sizeof se);
    se.cbSize = sizeof se; se.cSigners = 1; se.rgSigners = &si;
    DWORD cb = 0;
    CHECK(U(CryptMsgSignCTL)(CC_X509P7, (BYTE *)v_ctl_content, sizeof v_ctl_content, &se, 0, NULL, &cb));
    CHECK(cb > sizeof v_ctl_content);
    BYTE *buf = LocalAlloc(LPTR, cb);
    DWORD cb2 = cb;
    CHECK(U(CryptMsgSignCTL)(CC_X509P7, (BYTE *)v_ctl_content, sizeof v_ctl_content, &se, 0, buf, &cb2));
    PCCTL_CONTEXT c = cc_ctl(buf, cb2);
    CHECK(c != NULL);
    if (c) {
        EXPECT_EQ(c->cbCtlContent, sizeof v_ctl_content);
        CHECK(!memcmp(c->pbCtlContent, v_ctl_content, sizeof v_ctl_content));
        EXPECT_EQ(c->pCtlInfo->cCTLEntry, 3);
        rel(c);
    }
    LocalFree(buf);
    cc_signer_free(prov, sc);
}
TEST(ctlsign_raw_content_not_validated_as_ctl) {
    /* CryptMsgSignCTL wraps any bytes: they only fail later when loaded as a CTL */
    REQUIRE(U(CryptMsgSignCTL));
    HCRYPTPROV prov; PCCERT_CONTEXT sc;
    REQUIRE(cc_signer(&prov, &sc));
    CMSG_SIGNER_ENCODE_INFO si; memset(&si, 0, sizeof si);
    si.cbSize = sizeof si; si.pCertInfo = sc->pCertInfo; si.hCryptProv = prov; si.dwKeySpec = AT_SIGNATURE;
    si.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;
    CMSG_SIGNED_ENCODE_INFO se; memset(&se, 0, sizeof se);
    se.cbSize = sizeof se; se.cSigners = 1; se.rgSigners = &si;
    BYTE junk[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    DWORD cb = 0;
    BOOL ok = U(CryptMsgSignCTL)(CC_X509P7, junk, sizeof junk, &se, 0, NULL, &cb);
    t_note("sign junk content: ret=%d cb=%lu", ok, cb);
    if (ok) {
        BYTE *buf = LocalAlloc(LPTR, cb);
        if (U(CryptMsgSignCTL)(CC_X509P7, junk, sizeof junk, &se, 0, buf, &cb)) {
            SET_ERR(0);
            PCCTL_CONTEXT c = cc_ctl(buf, cb);
            CHECK(c == NULL);
            t_note("load of signed junk content: err 0x%lx", GetLastError());
            rel(c);
        }
        LocalFree(buf);
    }
    cc_signer_free(prov, sc);
}
TEST(ctlsign_ctlinfo_invalid_encoding_fails) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL));
    MK m; mk_info(&m, 3, NULL);
    m.info.SubjectAlgorithm.pszObjId = NULL;
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    t_note("CTL_INFO with a NULL SubjectAlgorithm OID: %s", b ? "encoded" : "failed");
    if (b) LocalFree(b);
    mk_info(&m, 3, NULL);
    m.info.SubjectUsage.rgpszUsageIdentifier[0] = (LPSTR)"not an oid";
    b = cc_sign_ctl(&m.info, 0, &cb);
    CHECK(b == NULL);
    EXPECT_EQ(cb, 0);
    if (b) LocalFree(b);
}
TEST(ctlsign_no_entries) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL));
    MK m; mk_info(&m, 0, NULL);
    m.info.rgCTLEntry = NULL;
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    t_note("sign a CTL with no entries: %s", b ? "ok" : "failed");
    if (b) {
        SET_ERR(0);
        PCCTL_CONTEXT c = cc_ctl(b, cb);
        t_note("load CTL with no entries: %s err 0x%lx", c ? "ok" : "failed", c ? 0 : GetLastError());
        rel(c);
        LocalFree(b);
    }
}
TEST(ctlsign_entry_attributes_roundtrip) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL));
    MK m; mk_info(&m, 2, NULL);
    static const BYTE v1[] = { 0x04, 0x03, 'a', 'b', 'c' }, v2[] = { 0x04, 0x01, 'z' };
    CRYPT_ATTR_BLOB vals[2] = { { sizeof v1, (BYTE *)v1 }, { sizeof v2, (BYTE *)v2 } };
    CRYPT_ATTRIBUTE at[2] = { { (LPSTR)"1.3.6.1.4.1.311.10.11.13", 1, &vals[0] }, { (LPSTR)"1.2.3.4.5", 1, &vals[1] } };
    m.ent[0].cAttribute = 2; m.ent[0].rgAttribute = at;
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    REQUIRE(b);
    PCCTL_CONTEXT c = cc_ctl(b, cb);
    REQUIRE(c);
    REQUIRE(c->pCtlInfo->cCTLEntry == 2);
    PCTL_ENTRY e = &c->pCtlInfo->rgCTLEntry[0];
    EXPECT_EQ(e->cAttribute, 2);
    if (e->cAttribute == 2) {
        /* SET OF is DER-sorted on the wire, so the order of the two attributes is not the input order */
        int a13 = -1, a5 = -1;
        for (int k = 0; k < 2; k++) {
            if (!strcmp(e->rgAttribute[k].pszObjId, "1.3.6.1.4.1.311.10.11.13")) a13 = k;
            if (!strcmp(e->rgAttribute[k].pszObjId, "1.2.3.4.5")) a5 = k;
        }
        CHECK(a13 >= 0 && a5 >= 0);
        if (a13 >= 0) CHECK(e->rgAttribute[a13].cValue == 1 && e->rgAttribute[a13].rgValue[0].cbData == sizeof v1 && !memcmp(e->rgAttribute[a13].rgValue[0].pbData, v1, sizeof v1));
        if (a5 >= 0) CHECK(e->rgAttribute[a5].cValue == 1 && e->rgAttribute[a5].rgValue[0].cbData == sizeof v2);
    }
    t_note("entry without attributes round-trips with cAttribute=%lu", c->pCtlInfo->rgCTLEntry[1].cAttribute);
    rel(c);
    LocalFree(b);
}

/* ---- sorted CTLs ---- */
static PCCTL_CONTEXT sorted_ctl(MK *m, DWORD flags, BYTE **keep) {
    DWORD cb = 0;
    *keep = cc_sign_ctl(&m->info, flags, &cb);
    if (!*keep) return NULL;
    return cc_ctl(*keep, cb);
}
TEST(ctlsorted_extension_present) {
    REQUIRE(U(CryptMsgEncodeAndSignCTL));
    MK m; mk_info(&m, NIDS, NULL);
    BYTE *b;
    PCCTL_CONTEXT c = sorted_ctl(&m, CMSG_ENCODE_SORTED_CTL_FLAG, &b);
    REQUIRE(c);
    EXPECT_EQ(c->pCtlInfo->cCTLEntry, NIDS);
    PCERT_EXTENSION e = U(CertFindExtension)(szOID_SORTED_CTL, c->pCtlInfo->cExtension, c->pCtlInfo->rgExtension);
    CHECK(e != NULL);
    rel(c); LocalFree(b);
    c = sorted_ctl(&m, 0, &b);
    REQUIRE(c);
    CHECK(U(CertFindExtension)(szOID_SORTED_CTL, c->pCtlInfo->cExtension, c->pCtlInfo->rgExtension) == NULL);
    rel(c); LocalFree(b);
}
TEST(ctlsorted_find_each_subject) {
    REQUIRE(U(CertFindSubjectInSortedCTL));
    for (int hashed = 0; hashed < 2; hashed++) {
        MK m; mk_info(&m, NIDS, NULL);
        BYTE *b;
        PCCTL_CONTEXT c = sorted_ctl(&m, CMSG_ENCODE_SORTED_CTL_FLAG | (hashed ? CMSG_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG : 0), &b);
        CHECKF(c != NULL, "hashed=%d", hashed);
        if (!c) continue;
        for (int i = 0; i < NIDS; i++) {
            CRYPT_DATA_BLOB id = { 20, m.ids[i] };
            CRYPT_DER_BLOB attrs = { 7, (BYTE *)7 };
            SET_ERR(0);
            BOOL ok = U(CertFindSubjectInSortedCTL)(&id, c, 0, NULL, &attrs);
            CHECKF(ok, "hashed=%d id %d err 0x%lx", hashed, i, GetLastError());
        }
        BYTE other[20]; memset(other, 0xee, sizeof other);
        CRYPT_DATA_BLOB id = { 20, other };
        CRYPT_DER_BLOB attrs = { 7, (BYTE *)7 };
        SET_ERR(0);
        CHECK(!U(CertFindSubjectInSortedCTL)(&id, c, 0, NULL, &attrs)); EXPECT_ERR(CC_E_NOT_FOUND);
        CHECK(attrs.cbData == 0 && attrs.pbData == NULL); /* cleared on entry */
        rel(c); LocalFree(b);
    }
}
TEST(ctlsorted_find_returns_attributes) {
    REQUIRE(U(CertFindSubjectInSortedCTL));
    MK m; mk_info(&m, NIDS, NULL);
    static const BYTE v1[] = { 0x04, 0x03, 'a', 'b', 'c' };
    CRYPT_ATTR_BLOB val = { sizeof v1, (BYTE *)v1 };
    CRYPT_ATTRIBUTE at = { (LPSTR)"1.2.3.4.5", 1, &val };
    m.ent[2].cAttribute = 1; m.ent[2].rgAttribute = &at;
    BYTE *b;
    PCCTL_CONTEXT c = sorted_ctl(&m, CMSG_ENCODE_SORTED_CTL_FLAG, &b);
    REQUIRE(c);
    CRYPT_DATA_BLOB id = { 20, m.ids[2] };
    CRYPT_DER_BLOB attrs = { 0, NULL };
    CHECK(U(CertFindSubjectInSortedCTL)(&id, c, 0, NULL, &attrs));
    CHECK(attrs.cbData > 0 && attrs.pbData != NULL);
    if (attrs.cbData) CHECK(attrs.pbData[0] == 0x31); /* SET OF Attribute */
    id.pbData = m.ids[3];
    CHECK(U(CertFindSubjectInSortedCTL)(&id, c, 0, NULL, &attrs));
    CHECK(attrs.cbData == 0);
    CHECK(U(CertFindSubjectInSortedCTL)(&id, c, 0, NULL, NULL));
    rel(c); LocalFree(b);
}
TEST(ctlsorted_enum_all) {
    REQUIRE(U(CertEnumSubjectInSortedCTL));
    for (int hashed = 0; hashed < 2; hashed++) {
        MK m; mk_info(&m, NIDS, NULL);
        BYTE *b;
        PCCTL_CONTEXT c = sorted_ctl(&m, CMSG_ENCODE_SORTED_CTL_FLAG | (hashed ? CMSG_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG : 0), &b);
        CHECK(c != NULL);
        if (!c) continue;
        int seen[NIDS] = { 0 }, n = 0;
        void *next = NULL;
        CRYPT_DER_BLOB id, at;
        while (U(CertEnumSubjectInSortedCTL)(c, &next, &id, &at)) {
            n++;
            CHECK(id.cbData == 0x14 || id.cbData == 20 || id.cbData > 0);
            for (int i = 0; i < NIDS; i++) {
                if (id.cbData == 20 && !memcmp(id.pbData, m.ids[i], 20)) seen[i]++;
            }
            if (n > 20) break;
        }
        EXPECT_EQ(n, NIDS);
        CHECK(next == NULL);
        if (!hashed) for (int i = 0; i < NIDS; i++) EXPECT_EQ(seen[i], 1);
        else t_note("hashed subject identifiers: %d of %d enumerated ids equal the plain ids", seen[0] + seen[1] + seen[2] + seen[3] + seen[4] + seen[5], NIDS);
        rel(c); LocalFree(b);
    }
}
TEST(ctlsorted_enum_requires_sorted_ctl) {
    REQUIRE(U(CertEnumSubjectInSortedCTL));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    void *next = NULL;
    CRYPT_DER_BLOB id, at;
    SET_ERR(0);
    CHECK(!U(CertEnumSubjectInSortedCTL)(c, &next, &id, &at)); EXPECT_ERR(CC_E_INVALIDARG);
    rel(c);
}
TEST(ctlsorted_find_on_unsorted_ctl) {
    REQUIRE(U(CertFindSubjectInSortedCTL));
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    CRYPT_DATA_BLOB id = { 20, (BYTE *)v_sha1_1001 };
    CRYPT_DER_BLOB at; memset(&at, 0, sizeof at); at.cbData = 5;
    SET_ERR(0);
    BOOL ok = U(CertFindSubjectInSortedCTL)(&id, c, 0, NULL, &at);
    t_note("CertFindSubjectInSortedCTL on an unsorted CTL: ret=%d err=0x%lx", ok, GetLastError());
    CHECK(at.cbData == 0 && at.pbData == NULL);
    rel(c);
}
TEST(ctlsorted_enum_truncated_cursor_rejected) {
    REQUIRE(U(CertEnumSubjectInSortedCTL));
    MK m; mk_info(&m, NIDS, NULL);
    BYTE *b;
    PCCTL_CONTEXT c = sorted_ctl(&m, CMSG_ENCODE_SORTED_CTL_FLAG, &b);
    REQUIRE(c);
    void *next = (void *)(ULONG_PTR)0x10; /* not inside the sorted subject area */
    CRYPT_DER_BLOB id, at;
    SET_ERR(0);
    CHECK(!U(CertEnumSubjectInSortedCTL)(c, &next, &id, &at)); EXPECT_ERR(CC_E_NOT_FOUND);
    CHECK(next == NULL);
    rel(c); LocalFree(b);
}

/* ---- CertFindSubjectInCTL ---- */
TEST(ctlsubj_find_by_cert) {
    REQUIRE(U(CertFindSubjectInCTL));
    NOWINE("unimplemented in the emulator");
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001)), l2 = cc_cert(VEC(v_cert_1002)), l3 = cc_cert(VEC(v_cert_1003));
    REQUIRE(c && l1 && l2 && l3);
    PCTL_ENTRY e = U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, c, 0);
    CHECK(e == &c->pCtlInfo->rgCTLEntry[0]);
    e = U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l2, c, 0);
    CHECK(e == &c->pCtlInfo->rgCTLEntry[1]);
    e = U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l3, c, 0);
    CHECK(e == &c->pCtlInfo->rgCTLEntry[2]);
    relc(l1); relc(l2); relc(l3); rel(c);
}
TEST(ctlsubj_find_by_cert_not_found) {
    REQUIRE(U(CertFindSubjectInCTL));
    NOWINE("unimplemented in the emulator");
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    PCCERT_CONTEXT r0 = cc_cert(VEC(v_cert_r0));
    REQUIRE(c && r0);
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)r0, c, 0) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    relc(r0); rel(c);
}
TEST(ctlsubj_find_by_cert_other_ctl_entries) {
    REQUIRE(U(CertFindSubjectInCTL));
    NOWINE("unimplemented in the emulator");
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed_expired));
    PCCERT_CONTEXT l3 = cc_cert(VEC(v_cert_1003)), l2 = cc_cert(VEC(v_cert_1002));
    REQUIRE(c && l3 && l2);
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l3, c, 0) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l2, c, 0) == &c->pCtlInfo->rgCTLEntry[1]);
    relc(l3); relc(l2); rel(c);
}
TEST(ctlsubj_find_any_subject_type) {
    REQUIRE(U(CertFindSubjectInCTL));
    NOWINE("unimplemented in the emulator");
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    REQUIRE(c);
    CTL_ANY_SUBJECT_INFO info; memset(&info, 0, sizeof info);
    info.SubjectIdentifier.cbData = 20; info.SubjectIdentifier.pbData = (BYTE *)v_sha1_1002;
    /* NULL algorithm: identifier only */
    PCTL_ENTRY e = U(CertFindSubjectInCTL)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, c, 0);
    CHECK(e == &c->pCtlInfo->rgCTLEntry[1]);
    info.SubjectAlgorithm.pszObjId = (LPSTR)"1.3.14.3.2.26";
    e = U(CertFindSubjectInCTL)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, c, 0);
    CHECK(e == &c->pCtlInfo->rgCTLEntry[1]);
    /* different algorithm: not found */
    info.SubjectAlgorithm.pszObjId = (LPSTR)"1.2.840.113549.2.5";
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, c, 0) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    info.SubjectAlgorithm.pszObjId = NULL;
    info.SubjectIdentifier.pbData = (BYTE *)v_sha1_r0;
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, c, 0) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    info.SubjectIdentifier.cbData = 19;
    info.SubjectIdentifier.pbData = (BYTE *)v_sha1_1002;
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, c, 0) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    rel(c);
}
TEST(ctlsubj_find_bad_subject_type) {
    REQUIRE(U(CertFindSubjectInCTL));
    NOWINE("unimplemented in the emulator");
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(c && l1);
    static const DWORD bad[] = { 0, 3, 4, 0xffffffff };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        CHECKF(U(CertFindSubjectInCTL)(CC_X509P7, bad[i], (void *)l1, c, 0) == NULL, "type %lu", bad[i]);
        EXPECT_ERR(CC_E_INVALIDARG);
    }
    relc(l1); rel(c);
}
TEST(ctlsubj_find_in_ctl_without_entries) {
    REQUIRE(U(CertFindSubjectInCTL));
    NOWINE("unimplemented in the emulator");
    PCCTL_CONTEXT c = cc_ctl(VEC(v_ctl_signed_usage_only));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(l1);
    if (!c) { t_skip("CTL without entries cannot be loaded"); return; }
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, c, 0) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    relc(l1); rel(c);
}
TEST(ctlsubj_cert_subject_unsupported_algorithm) {
    REQUIRE(U(CertFindSubjectInCTL));
    NOWINE("unimplemented in the emulator");
    MK m; mk_info(&m, 2, "2.16.840.1.101.3.4.2.1"); /* sha256: cert type only supports sha1/md5 */
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    REQUIRE(b);
    PCCTL_CONTEXT c = cc_ctl(b, cb);
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(c && l1);
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, c, 0) == NULL); EXPECT_ERR((DWORD)0x80090008);
    relc(l1); rel(c); LocalFree(b);
}
TEST(ctlsubj_cert_subject_md5_algorithm) {
    REQUIRE(U(CertFindSubjectInCTL));
    NOWINE("unimplemented in the emulator");
    MK m; mk_info(&m, 2, "1.2.840.113549.2.5");
    BYTE md5[16]; DWORD mcb = 16;
    CHECK(cc_hash(CALG_MD5, VEC(v_cert_1001), md5, &mcb));
    /* md5 identifier is 16 bytes */
    m.ent[0].SubjectIdentifier.cbData = 16; m.ent[0].SubjectIdentifier.pbData = md5;
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    REQUIRE(b);
    PCCTL_CONTEXT c = cc_ctl(b, cb);
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001)), l2 = cc_cert(VEC(v_cert_1002));
    REQUIRE(c && l1 && l2);
    PCTL_ENTRY e = U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, c, 0);
    CHECK(e != NULL && e == U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, c, 0));
    if (e) EXPECT_EQ(e->SubjectIdentifier.cbData, 16);
    SET_ERR(0);
    CHECK(U(CertFindSubjectInCTL)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l2, c, 0) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    relc(l1); relc(l2); rel(c); LocalFree(b);
}

/* ---- CertCreateCTLEntryFromCertificateContextProperties ---- */
static const BYTE kOct3[] = { 0x04, 0x03, 'x', 'y', 'z' };
TEST(ctlentry_create_no_properties) {
    REQUIRE(U(CertCreateCTLEntryFromCertificateContextProperties));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r0));
    REQUIRE(cert);
    DWORD cb = 0;
    SET_ERR(0);
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, NULL, &cb));
    CHECK(cb >= sizeof(CTL_ENTRY) + 20);
    BYTE *buf = LocalAlloc(LPTR, cb);
    DWORD cb2 = cb;
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, (PCTL_ENTRY)buf, &cb2));
    PCTL_ENTRY e = (PCTL_ENTRY)buf;
    BYTE h[20]; DWORD hcb = 20;
    CHECK(cc_hash(CALG_SHA1, VEC(v_cert_r0), h, &hcb));
    EXPECT_EQ(e->SubjectIdentifier.cbData, 20);
    CHECK(e->SubjectIdentifier.cbData == 20 && !memcmp(e->SubjectIdentifier.pbData, h, 20));
    CHECK(!memcmp(e->SubjectIdentifier.pbData, v_sha1_r0, 20));
    EXPECT_EQ(e->cAttribute, 0);
    LocalFree(buf); relc(cert);
}
TEST(ctlentry_create_small_buffer) {
    REQUIRE(U(CertCreateCTLEntryFromCertificateContextProperties));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r0));
    REQUIRE(cert);
    DWORD need = 0;
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, NULL, &need));
    BYTE *buf = LocalAlloc(LPTR, need + 8);
    DWORD cb = need - 1;
    SET_ERR(0);
    CHECK(!U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, (PCTL_ENTRY)buf, &cb)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    cb = 0;
    SET_ERR(0);
    CHECK(!U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, (PCTL_ENTRY)buf, &cb)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    cb = need;
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, (PCTL_ENTRY)buf, &cb));
    EXPECT_EQ(cb, need);
    LocalFree(buf); relc(cert);
}
TEST(ctlentry_create_with_properties_and_optional_attrs) {
    REQUIRE(U(CertCreateCTLEntryFromCertificateContextProperties));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r1));
    REQUIRE(cert);
    BYTE d1[] = { 'a', 0, 0, 0 }, d2[] = { 'b', 0, 'c', 0, 0, 0 };
    CRYPT_DATA_BLOB b1 = { sizeof d1, d1 }, b2 = { sizeof d2, d2 };
    CHECK(U(CertSetCertificateContextProperty)(cert, CERT_FRIENDLY_NAME_PROP_ID, 0, &b1));
    CHECK(U(CertSetCertificateContextProperty)(cert, CERT_DESCRIPTION_PROP_ID, 0, &b2));
    CRYPT_ATTR_BLOB ov = { sizeof kOct3, (BYTE *)kOct3 };
    CRYPT_ATTRIBUTE opt = { (LPSTR)"1.2.3.4.5.6", 1, &ov };
    DWORD cb = 0;
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 1, &opt, 0, NULL, NULL, &cb));
    BYTE *buf = LocalAlloc(LPTR, cb);
    DWORD cb2 = cb;
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 1, &opt, 0, NULL, (PCTL_ENTRY)buf, &cb2));
    PCTL_ENTRY e = (PCTL_ENTRY)buf;
    EXPECT_EQ(e->cAttribute, 3);
    if (e->cAttribute == 3) {
        /* optional attributes come first, then one attribute per certificate property */
        EXPECT_STR(e->rgAttribute[0].pszObjId, "1.2.3.4.5.6");
        CHECK(e->rgAttribute[0].cValue == 1 && e->rgAttribute[0].rgValue[0].cbData == sizeof kOct3 && !memcmp(e->rgAttribute[0].rgValue[0].pbData, kOct3, sizeof kOct3));
        int fn = 0, ds = 0;
        for (int i = 1; i < 3; i++) {
            PCRYPT_ATTRIBUTE a = &e->rgAttribute[i];
            if (!strcmp(a->pszObjId, "1.3.6.1.4.1.311.10.11.11")) {
                fn++;
                CHECK(a->cValue == 1 && a->rgValue[0].cbData == 2 + sizeof d1 && a->rgValue[0].pbData[0] == 4 && a->rgValue[0].pbData[1] == sizeof d1 && !memcmp(a->rgValue[0].pbData + 2, d1, sizeof d1));
            } else if (!strcmp(a->pszObjId, "1.3.6.1.4.1.311.10.11.13")) {
                ds++;
                CHECK(a->cValue == 1 && a->rgValue[0].cbData == 2 + sizeof d2 && !memcmp(a->rgValue[0].pbData + 2, d2, sizeof d2));
            }
        }
        EXPECT_EQ(fn, 1); EXPECT_EQ(ds, 1);
    }
    LocalFree(buf); relc(cert);
}
TEST(ctlentry_create_ignores_hash_property_as_attribute) {
    REQUIRE(U(CertCreateCTLEntryFromCertificateContextProperties));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r2));
    REQUIRE(cert);
    BYTE h[20]; DWORD hcb = 20;
    CHECK(U(CertGetCertificateContextProperty)(cert, CERT_HASH_PROP_ID, h, &hcb)); /* caches the hash property */
    DWORD cb = 0;
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, NULL, &cb));
    BYTE *buf = LocalAlloc(LPTR, cb);
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, (PCTL_ENTRY)buf, &cb));
    EXPECT_EQ(((PCTL_ENTRY)buf)->cAttribute, 0);
    LocalFree(buf); relc(cert);
}
TEST(ctlentry_create_hash_property_overrides_identifier) {
    REQUIRE(U(CertCreateCTLEntryFromCertificateContextProperties));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r3));
    REQUIRE(cert);
    BYTE fake[20]; memset(fake, 0x42, 20);
    CRYPT_DATA_BLOB b = { 20, fake };
    CHECK(U(CertSetCertificateContextProperty)(cert, CERT_HASH_PROP_ID, 0, &b));
    DWORD cb = 0;
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, NULL, &cb));
    BYTE *buf = LocalAlloc(LPTR, cb);
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, 0, NULL, (PCTL_ENTRY)buf, &cb));
    PCTL_ENTRY e = (PCTL_ENTRY)buf;
    CHECK(e->SubjectIdentifier.cbData == 20 && !memcmp(e->SubjectIdentifier.pbData, fake, 20));
    LocalFree(buf); relc(cert);
}
TEST(ctlentry_create_chain_flag_needs_name_hashes) {
    REQUIRE(U(CertCreateCTLEntryFromCertificateContextProperties));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r4));
    REQUIRE(cert);
    DWORD cb = 0;
    SET_ERR(0);
    BOOL ok = U(CertCreateCTLEntryFromCertificateContextProperties)(cert, 0, NULL, CTL_ENTRY_FROM_PROP_CHAIN_FLAG, NULL, NULL, &cb);
    t_note("CTL_ENTRY_FROM_PROP_CHAIN_FLAG on a cert without chain properties: ret=%d cb=%lu err=0x%lx", ok, cb, GetLastError());
    relc(cert);
}

/* ---- CertSetCertificateContextPropertiesFromCTLEntry ---- */
static PCCTL_CONTEXT ctl_with_props(BYTE **keep) {
    /* entry 0 carries a friendly-name property attribute */
    MK m; mk_info(&m, 1, NULL);
    static const BYTE name[] = { 'n', 0, 'a', 0, 'm', 0, 'e', 0, 0, 0 };
    static BYTE oct[2 + sizeof name];
    oct[0] = 4; oct[1] = sizeof name; memcpy(oct + 2, name, sizeof name);
    static CRYPT_ATTR_BLOB val; val.cbData = sizeof oct; val.pbData = oct;
    static CRYPT_ATTRIBUTE at; at.pszObjId = (LPSTR)"1.3.6.1.4.1.311.10.11.11"; at.cValue = 1; at.rgValue = &val;
    m.ent[0].cAttribute = 1; m.ent[0].rgAttribute = &at;
    DWORD cb = 0;
    *keep = cc_sign_ctl(&m.info, 0, &cb);
    return *keep ? cc_ctl(*keep, cb) : NULL;
}
TEST(ctlentry_set_props_applies_hash_and_attributes) {
    REQUIRE(U(CertSetCertificateContextPropertiesFromCTLEntry));
    BYTE *keep; PCCTL_CONTEXT c = ctl_with_props(&keep);
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r5));
    REQUIRE(c && cert);
    SET_ERR(0);
    CHECK(U(CertSetCertificateContextPropertiesFromCTLEntry)(cert, &c->pCtlInfo->rgCTLEntry[0], 0));
    BYTE h[20]; DWORD hcb = 20;
    CHECK(U(CertGetCertificateContextProperty)(cert, CERT_HASH_PROP_ID, h, &hcb));
    CHECK(!memcmp(h, c->pCtlInfo->rgCTLEntry[0].SubjectIdentifier.pbData, 20));
    CHECK(memcmp(h, v_sha1_r0, 20) != 0);
    WCHAR fn[16]; DWORD fcb = sizeof fn;
    CHECK(U(CertGetCertificateContextProperty)(cert, CERT_FRIENDLY_NAME_PROP_ID, fn, &fcb));
    EXPECT_EQ(fcb, 10);
    CHECK(fcb == 10 && !memcmp(fn, L"name", 10));
    relc(cert); rel(c); LocalFree(keep);
}
TEST(ctlentry_set_props_requires_20_byte_identifier) {
    REQUIRE(U(CertSetCertificateContextPropertiesFromCTLEntry));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r6));
    REQUIRE(cert);
    BYTE id[32] = { 0 };
    static const DWORD sizes[] = { 0, 1, 16, 19, 21, 32 };
    for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        CTL_ENTRY e; memset(&e, 0, sizeof e);
        e.SubjectIdentifier.cbData = sizes[i]; e.SubjectIdentifier.pbData = id;
        SET_ERR(0);
        CHECKF(!U(CertSetCertificateContextPropertiesFromCTLEntry)(cert, &e, 0), "cb %lu", sizes[i]);
        EXPECT_ERR(CC_E_INVALIDARG);
    }
    DWORD n = 0;
    CHECK(!U(CertGetCertificateContextProperty)(cert, CERT_FRIENDLY_NAME_PROP_ID, NULL, &n));
    relc(cert);
}
TEST(ctlentry_set_props_bad_property_attribute) {
    REQUIRE(U(CertSetCertificateContextPropertiesFromCTLEntry));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r8));
    REQUIRE(cert);
    BYTE id[20]; memset(id, 0x33, 20);
    /* property attribute whose value is not an OCTET STRING */
    static BYTE bad[] = { 0x02, 0x01, 0x05 };
    CRYPT_ATTR_BLOB bv = { sizeof bad, bad };
    CRYPT_ATTRIBUTE at = { (LPSTR)"1.3.6.1.4.1.311.10.11.13", 1, &bv };
    CTL_ENTRY e; memset(&e, 0, sizeof e);
    e.SubjectIdentifier.cbData = 20; e.SubjectIdentifier.pbData = id;
    e.cAttribute = 1; e.rgAttribute = &at;
    SET_ERR(0);
    CHECK(!U(CertSetCertificateContextPropertiesFromCTLEntry)(cert, &e, 0)); EXPECT_ERR(13);
    /* the hash property was already applied before the attribute was rejected */
    BYTE h[20]; DWORD hcb = 20;
    CHECK(U(CertGetCertificateContextProperty)(cert, CERT_HASH_PROP_ID, h, &hcb));
    CHECK(!memcmp(h, id, 20));
    relc(cert);
}
TEST(ctlentry_set_props_ignores_foreign_attributes) {
    REQUIRE(U(CertSetCertificateContextPropertiesFromCTLEntry));
    PCCERT_CONTEXT cert = cc_cert(VEC(v_cert_r9));
    REQUIRE(cert);
    BYTE id[20]; memset(id, 0x44, 20);
    static BYTE v[] = { 0x02, 0x01, 0x05 };
    CRYPT_ATTR_BLOB bv = { sizeof v, v };
    CRYPT_ATTRIBUTE at[3] = {
        { (LPSTR)"1.2.3.4", 1, &bv },
        { (LPSTR)"1.3.6.1.4.1.311.10.10", 1, &bv },     /* prefix-like but not a property OID */
        { (LPSTR)"1.3.6.1.4.1.311.10.11.0", 1, &bv },   /* property id 0: ignored */
    };
    CTL_ENTRY e; memset(&e, 0, sizeof e);
    e.SubjectIdentifier.cbData = 20; e.SubjectIdentifier.pbData = id;
    e.cAttribute = 3; e.rgAttribute = at;
    SET_ERR(0);
    CHECK(U(CertSetCertificateContextPropertiesFromCTLEntry)(cert, &e, 0));
    relc(cert);
}
TEST(ctlentry_roundtrip_create_then_set) {
    REQUIRE(U(CertCreateCTLEntryFromCertificateContextProperties)); REQUIRE(U(CertSetCertificateContextPropertiesFromCTLEntry));
    PCCERT_CONTEXT src = cc_cert(VEC(v_cert_r10)), dst = cc_cert(VEC(v_cert_r10));
    REQUIRE(src && dst);
    BYTE d[] = { 'q', 0, 'r', 0, 0, 0 };
    CRYPT_DATA_BLOB b = { sizeof d, d };
    CHECK(U(CertSetCertificateContextProperty)(src, CERT_FRIENDLY_NAME_PROP_ID, 0, &b));
    DWORD cb = 0;
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(src, 0, NULL, 0, NULL, NULL, &cb));
    BYTE *buf = LocalAlloc(LPTR, cb);
    CHECK(U(CertCreateCTLEntryFromCertificateContextProperties)(src, 0, NULL, 0, NULL, (PCTL_ENTRY)buf, &cb));
    CHECK(U(CertSetCertificateContextPropertiesFromCTLEntry)(dst, (PCTL_ENTRY)buf, 0));
    WCHAR fn[8]; DWORD fcb = sizeof fn;
    CHECK(U(CertGetCertificateContextProperty)(dst, CERT_FRIENDLY_NAME_PROP_ID, fn, &fcb));
    EXPECT_EQ(fcb, sizeof d);
    CHECK(fcb == sizeof d && !memcmp(fn, d, sizeof d));
    LocalFree(buf); relc(src); relc(dst);
}

/* ---- CertVerifyCTLUsage ---- */
typedef struct {
    HCERTSTORE ctls, signers;
    CTL_VERIFY_USAGE_PARA para;
    CTL_VERIFY_USAGE_STATUS st;
    PCCTL_CONTEXT ctl; PCCERT_CONTEXT signer;
    LPSTR oid[1]; CTL_USAGE usage;
} VU;
static int vu_init(VU *v, const BYTE *ctl, DWORD n) {
    memset(v, 0, sizeof *v);
    v->ctls = cc_store(); v->signers = cc_store();
    if (!v->ctls || !v->signers) return 0;
    if (ctl) cc_add_ctl(v->ctls, ctl, n, CERT_STORE_ADD_ALWAYS, NULL);
    U(CertAddEncodedCertificateToStore)(v->signers, CC_X509, VEC(v_signer), CERT_STORE_ADD_ALWAYS, NULL);
    v->para.cbSize = sizeof v->para;
    v->para.cCtlStore = 1; v->para.rghCtlStore = &v->ctls;
    v->para.cSignerStore = 1; v->para.rghSignerStore = &v->signers;
    v->st.cbSize = sizeof v->st; v->st.ppCtl = &v->ctl; v->st.ppSigner = &v->signer;
    v->oid[0] = (LPSTR)"1.3.6.1.5.5.7.3.3";
    v->usage.cUsageIdentifier = 1; v->usage.rgpszUsageIdentifier = v->oid;
    return 1;
}
static void vu_done(VU *v) { if (v->ctl) rel(v->ctl); if (v->signer) relc(v->signer); cc_close(v->ctls); cc_close(v->signers); }
#define VF (CERT_VERIFY_INHIBIT_CTL_UPDATE_FLAG | CERT_VERIFY_TRUSTED_SIGNERS_FLAG | CERT_VERIFY_NO_TIME_CHECK_FLAG)
TEST(ctlverify_bad_status_size) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed)));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(l1);
    SET_ERR(0);
    CHECK(!U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, VF, &v.para, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    v.st.cbSize = 0x2f;
    SET_ERR(0);
    CHECK(!U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, VF, &v.para, &v.st)); EXPECT_ERR(CC_E_INVALIDARG);
    v.st.cbSize = sizeof v.st;
    v.para.cbSize = 0x37;
    SET_ERR(0);
    CHECK(!U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, VF, &v.para, &v.st)); EXPECT_ERR(CC_E_INVALIDARG);
    relc(l1); vu_done(&v);
}
TEST(ctlverify_trusted_signer_success) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed)));
    PCCERT_CONTEXT l2 = cc_cert(VEC(v_cert_1002));
    REQUIRE(l2);
    SET_ERR(0);
    BOOL ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l2, &v.usage, VF, &v.para, &v.st);
    CHECKF(ok, "err 0x%lx status.dwError 0x%lx", GetLastError(), v.st.dwError);
    if (ok) {
        EXPECT_EQ(v.st.dwError, 0);
        EXPECT_EQ(v.st.dwCtlEntryIndex, 1);
        CHECK(v.ctl != NULL);
        if (v.ctl) EXPECT_EQ(v.ctl->cbCtlEncoded, sizeof v_ctl_signed);
        CHECK(v.signer != NULL);
        if (v.signer) CHECK(v.signer->cbCertEncoded == sizeof v_signer && !memcmp(v.signer->pbCertEncoded, v_signer, sizeof v_signer));
        EXPECT_EQ(v.st.dwSignerIndex, 0);
    }
    relc(l2); vu_done(&v);
}
TEST(ctlverify_entry_index_per_subject) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    const BYTE *certs[3] = { v_cert_1001, v_cert_1002, v_cert_1003 };
    const DWORD ns[3] = { sizeof v_cert_1001, sizeof v_cert_1002, sizeof v_cert_1003 };
    for (DWORD i = 0; i < 3; i++) {
        VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed)));
        PCCERT_CONTEXT c = cc_cert(certs[i], ns[i]);
        BOOL ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)c, &v.usage, VF, &v.para, &v.st);
        CHECKF(ok, "subject %lu", i);
        if (ok) EXPECT_EQ(v.st.dwCtlEntryIndex, i);
        relc(c); vu_done(&v);
    }
}
TEST(ctlverify_subject_not_in_ctl) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed)));
    PCCERT_CONTEXT r0 = cc_cert(VEC(v_cert_r0));
    REQUIRE(r0);
    SET_ERR(0);
    BOOL ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)r0, &v.usage, VF, &v.para, &v.st);
    CHECK(!ok);
    t_note("subject not listed: last error 0x%lx status.dwError 0x%lx", GetLastError(), v.st.dwError);
    CHECK(v.st.dwError != 0);
    CHECK(v.ctl == NULL);
    relc(r0); vu_done(&v);
}
TEST(ctlverify_empty_ctl_store) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, NULL, 0));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(l1);
    SET_ERR(0);
    CHECK(!U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, VF, &v.para, &v.st));
    t_note("no CTL in store: last error 0x%lx status.dwError 0x%lx", GetLastError(), v.st.dwError);
    CHECK(v.st.dwError != 0);
    relc(l1); vu_done(&v);
}
TEST(ctlverify_usage_not_in_ctl) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed)));
    v.oid[0] = (LPSTR)"1.3.6.1.5.5.7.3.9";
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(l1);
    SET_ERR(0);
    CHECK(!U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, VF, &v.para, &v.st));
    t_note("usage not covered: last error 0x%lx status.dwError 0x%lx", GetLastError(), v.st.dwError);
    CHECK(v.st.dwError != 0);
    relc(l1); vu_done(&v);
}
TEST(ctlverify_untrusted_signer_store) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed)));
    /* a signer store that does not contain the signer: with the trusted-signers flag the CTL cannot be trusted */
    HCERTSTORE empty = cc_store();
    v.para.rghSignerStore = &empty;
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(l1);
    SET_ERR(0);
    BOOL ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, VF, &v.para, &v.st);
    CHECK(!ok);
    t_note("signer not in signer store: last error 0x%lx status.dwError 0x%lx", GetLastError(), v.st.dwError);
    CHECK(v.st.dwError != 0);
    relc(l1); cc_close(empty); vu_done(&v);
}
TEST(ctlverify_bad_signature_ctl) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed_badsig)));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(l1);
    SET_ERR(0);
    BOOL ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, VF, &v.para, &v.st);
    CHECK(!ok);
    t_note("CTL with a corrupt signature: last error 0x%lx status.dwError 0x%lx", GetLastError(), v.st.dwError);
    CHECK(v.st.dwError != 0);
    relc(l1); vu_done(&v);
}
TEST(ctlverify_expired_ctl_time_check) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed_expired)));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(l1);
    SET_ERR(0);
    BOOL ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, CERT_VERIFY_INHIBIT_CTL_UPDATE_FLAG | CERT_VERIFY_TRUSTED_SIGNERS_FLAG, &v.para, &v.st);
    t_note("expired CTL with time check: ret=%d last error 0x%lx status.dwError 0x%lx dwFlags 0x%lx", ok, GetLastError(), v.st.dwError, v.st.dwFlags);
    if (v.ctl) { rel(v.ctl); v.ctl = NULL; }
    if (v.signer) { relc(v.signer); v.signer = NULL; }
    SET_ERR(0);
    ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_CERT_SUBJECT_TYPE, (void *)l1, &v.usage, VF, &v.para, &v.st);
    CHECKF(ok, "no-time-check: err 0x%lx status 0x%lx", GetLastError(), v.st.dwError);
    relc(l1); vu_done(&v);
}
TEST(ctlverify_any_subject_type) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    VU v; REQUIRE(vu_init(&v, VEC(v_ctl_signed)));
    CTL_ANY_SUBJECT_INFO info; memset(&info, 0, sizeof info);
    info.SubjectAlgorithm.pszObjId = (LPSTR)"1.3.14.3.2.26";
    info.SubjectIdentifier.cbData = 20; info.SubjectIdentifier.pbData = (BYTE *)v_sha1_1003;
    SET_ERR(0);
    BOOL ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, &v.usage, VF, &v.para, &v.st);
    CHECKF(ok, "err 0x%lx status 0x%lx", GetLastError(), v.st.dwError);
    if (ok) EXPECT_EQ(v.st.dwCtlEntryIndex, 2);
    vu_done(&v);
}
TEST(ctlverify_runtime_signed_ctl) {
    REQUIRE(U(CertVerifyCTLUsage));
    NOWINE("unimplemented in the emulator");
    MK m; mk_info(&m, 4, NULL);
    DWORD cb = 0;
    BYTE *b = cc_sign_ctl(&m.info, 0, &cb);
    REQUIRE(b);
    VU v; REQUIRE(vu_init(&v, b, cb));
    CTL_ANY_SUBJECT_INFO info; memset(&info, 0, sizeof info);
    info.SubjectIdentifier.cbData = 20; info.SubjectIdentifier.pbData = m.ids[3];
    SET_ERR(0);
    BOOL ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, &v.usage, VF, &v.para, &v.st);
    CHECKF(ok, "err 0x%lx status 0x%lx", GetLastError(), v.st.dwError);
    if (ok) {
        EXPECT_EQ(v.st.dwError, 0);
        EXPECT_EQ(v.st.dwCtlEntryIndex, 3);
        CHECK(v.signer != NULL);
    }
    /* list identifier restriction */
    if (v.ctl) { rel(v.ctl); v.ctl = NULL; }
    if (v.signer) { relc(v.signer); v.signer = NULL; }
    v.para.ListIdentifier.cbData = 7; v.para.ListIdentifier.pbData = (BYTE *)"mk-list";
    ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, &v.usage, VF, &v.para, &v.st);
    CHECK(ok);
    if (v.ctl) { rel(v.ctl); v.ctl = NULL; }
    if (v.signer) { relc(v.signer); v.signer = NULL; }
    v.para.ListIdentifier.pbData = (BYTE *)"other-l";
    SET_ERR(0);
    ok = U(CertVerifyCTLUsage)(CC_X509P7, CTL_ANY_SUBJECT_TYPE, &info, &v.usage, VF, &v.para, &v.st);
    CHECK(!ok);
    vu_done(&v); LocalFree(b);
}

TEST(ctlsign_computed_hash_covers_whole_ctl) {
    /* the message digest of a CTL SignedData is taken over the complete DER of the CTL */
    REQUIRE(U(CryptMsgOpenToDecode));
    HCRYPTMSG h = U(CryptMsgOpenToDecode)(CC_X509P7, 0, 0, 0, NULL, NULL);
    REQUIRE(h);
    CHECK(U(CryptMsgUpdate)(h, VEC(v_ctl_signed), TRUE));
    BYTE got[64]; DWORD cb = sizeof got;
    BOOL ok = U(CryptMsgGetParam)(h, CMSG_COMPUTED_HASH_PARAM, 0, got, &cb);
    CHECK(ok);
    if (ok) {
        BYTE want[64]; DWORD wcb = sizeof want;
        CHECK(cc_hash(CALG_SHA_256, VEC(v_ctl_content), want, &wcb));
        EXPECT_EQ(cb, 32);
        CHECK(cb == wcb && !memcmp(got, want, cb));
    }
    U(CryptMsgClose)(h);
}

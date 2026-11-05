/* CertCompareCertificate, CertVerifyTimeValidity, CryptImportPublicKeyInfoEx2, CryptMsgDuplicate. */
#include "gap1.h"

static PCCERT_CONTEXT mkctx(const BYTE *der, DWORD cb) { return U(CertCreateCertificateContext)(ENC, der, cb); }

/* ---------------- CertCompareCertificate ---------------- */
TEST(gap1_cmpcert_same_cert) {
    REQUIRE(U(CertCompareCertificate)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)); REQUIRE(a);
    PCCERT_CONTEXT a2 = mkctx(BLOB(v_certA)); REQUIRE(a2);
    CHECK(U(CertCompareCertificate)(ENC, a->pCertInfo, a->pCertInfo) == TRUE);
    CHECK(U(CertCompareCertificate)(ENC, a->pCertInfo, a2->pCertInfo) == TRUE);
    U(CertFreeCertificateContext)(a); U(CertFreeCertificateContext)(a2);
}
TEST(gap1_cmpcert_different_serial_and_issuer) {
    REQUIRE(U(CertCompareCertificate)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)), b = mkctx(BLOB(v_certB)); REQUIRE(a && b);
    CHECK(U(CertCompareCertificate)(ENC, a->pCertInfo, b->pCertInfo) == FALSE);
    CHECK(U(CertCompareCertificate)(ENC, b->pCertInfo, a->pCertInfo) == FALSE);
    U(CertFreeCertificateContext)(a); U(CertFreeCertificateContext)(b);
}
TEST(gap1_cmpcert_only_serial_and_issuer_matter) {
    /* certC has A's serial and issuer but another key, validity and signature: still "the same certificate id" */
    REQUIRE(U(CertCompareCertificate)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)), c = mkctx(BLOB(v_certC)); REQUIRE(a && c);
    CHECK(a->cbCertEncoded != c->cbCertEncoded || memcmp(a->pbCertEncoded, c->pbCertEncoded, a->cbCertEncoded));
    CHECK(U(CertCompareCertificate)(ENC, a->pCertInfo, c->pCertInfo) == TRUE);
    CHECK(U(CertCompareCertificate)(ENC, c->pCertInfo, a->pCertInfo) == TRUE);
    U(CertFreeCertificateContext)(a); U(CertFreeCertificateContext)(c);
}
TEST(gap1_cmpcert_encoding_type_ignored) {
    REQUIRE(U(CertCompareCertificate)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)), b = mkctx(BLOB(v_certB)); REQUIRE(a && b);
    static const DWORD types[] = { 0, 1, 0x10000, 0x10001, 0xFFFFFFFF };
    for (unsigned i = 0; i < 5; i++) {
        CHECKF(U(CertCompareCertificate)(types[i], a->pCertInfo, a->pCertInfo) == TRUE, "type %lx", types[i]);
        CHECKF(U(CertCompareCertificate)(types[i], a->pCertInfo, b->pCertInfo) == FALSE, "type %lx", types[i]);
    }
    U(CertFreeCertificateContext)(a); U(CertFreeCertificateContext)(b);
}
TEST(gap1_cmpcert_synthetic_serials) {
    REQUIRE(U(CertCompareCertificate));
    static const BYTE issuer[] = { 0x30, 0x00 };
    static const BYTE issuer2[] = { 0x30, 0x01 };
    struct { BYTE s1[4]; DWORD n1; BYTE s2[4]; DWORD n2; int equal; const char *what; } t[] = {
        { {1}, 1, {1}, 1, 1, "equal one byte" },
        { {1}, 1, {2}, 1, 0, "different one byte" },
        { {1,2}, 2, {1,2}, 2, 1, "equal two bytes" },
        { {1,2}, 2, {2,1}, 2, 0, "byte order matters" },
        { {1}, 1, {1,2}, 2, 0, "different lengths" },
        { {0x80,0x00}, 2, {0x80}, 1, 0, "0x80 with zero pad is positive, 0x80 alone negative" },
        { {0}, 1, {1}, 1, 0, "zero vs one" },
    };
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        CERT_INFO a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
        a.SerialNumber.cbData = t[i].n1; a.SerialNumber.pbData = t[i].s1;
        b.SerialNumber.cbData = t[i].n2; b.SerialNumber.pbData = t[i].s2;
        a.Issuer.cbData = b.Issuer.cbData = sizeof issuer; a.Issuer.pbData = b.Issuer.pbData = (BYTE *)issuer;
        BOOL r = U(CertCompareCertificate)(ENC, &a, &b);
        CHECKF(r == t[i].equal, "%s (got %d)", t[i].what, r);
        r = U(CertCompareCertificate)(ENC, &b, &a);
        CHECKF(r == t[i].equal, "%s swapped (got %d)", t[i].what, r);
    }
    /* issuer: length and bytes must both match */
    CERT_INFO a, b; static BYTE s1[1] = {5};
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.SerialNumber.cbData = b.SerialNumber.cbData = 1; a.SerialNumber.pbData = b.SerialNumber.pbData = s1;
    a.Issuer.cbData = 2; a.Issuer.pbData = (BYTE *)issuer; b.Issuer.cbData = 2; b.Issuer.pbData = (BYTE *)issuer2;
    CHECK(U(CertCompareCertificate)(ENC, &a, &b) == FALSE);
    b.Issuer.cbData = 1; b.Issuer.pbData = (BYTE *)issuer;
    CHECK(U(CertCompareCertificate)(ENC, &a, &b) == FALSE);
    b.Issuer.cbData = 2; b.Issuer.pbData = (BYTE *)issuer;
    CHECK(U(CertCompareCertificate)(ENC, &a, &b) == TRUE);
}
TEST(gap1_cmpcert_padded_serial_note) {
    REQUIRE(U(CertCompareCertificate));
    static BYTE issuer[] = { 0x30, 0x00 };
    static const BYTE p1[] = {1}, p2[] = {1, 0}, n1[] = {0xFF}, n2[] = {0xFF, 0xFF};
    CERT_INFO a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.Issuer.cbData = b.Issuer.cbData = 2; a.Issuer.pbData = b.Issuer.pbData = issuer;
    a.SerialNumber.cbData = 1; a.SerialNumber.pbData = (BYTE *)p1; b.SerialNumber.cbData = 2; b.SerialNumber.pbData = (BYTE *)p2;
    t_note("serial {01} vs {01,00} (redundant positive pad): %d", U(CertCompareCertificate)(ENC, &a, &b));
    a.SerialNumber.pbData = (BYTE *)n1; b.SerialNumber.pbData = (BYTE *)n2;
    t_note("serial {FF} vs {FF,FF} (redundant negative pad): %d", U(CertCompareCertificate)(ENC, &a, &b));
}

/* ---------------- CertVerifyTimeValidity ---------------- */
static ULONGLONG ft2u(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }
static FILETIME u2ft(ULONGLONG u) { FILETIME f; f.dwLowDateTime = (DWORD)u; f.dwHighDateTime = (DWORD)(u >> 32); return f; }
TEST(gap1_timevalid_boundaries) {
    REQUIRE(U(CertVerifyTimeValidity));
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    ULONGLONG nb = 132000000000000000ULL, na = 133000000000000000ULL;
    ci.NotBefore = u2ft(nb); ci.NotAfter = u2ft(na);
    struct { ULONGLONG t; LONG want; const char *w; } t[] = {
        { nb - 1, -1, "one tick before NotBefore" }, { nb, 0, "exactly NotBefore" }, { nb + 1, 0, "just after NotBefore" },
        { (nb + na) / 2, 0, "middle" }, { na - 1, 0, "just before NotAfter" }, { na, 0, "exactly NotAfter (inclusive)" },
        { na + 1, 1, "one tick after NotAfter" }, { 0, -1, "time zero" }, { 0xFFFFFFFFFFFFFFFFULL, 1, "max time" },
    };
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        FILETIME f = u2ft(t[i].t);
        LONG r = U(CertVerifyTimeValidity)(&f, &ci);
        CHECKF(r == t[i].want, "%s: got %ld want %ld", t[i].w, r, t[i].want);
    }
}
TEST(gap1_timevalid_returns_exactly_minus_one_zero_one) {
    REQUIRE(U(CertVerifyTimeValidity));
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    ci.NotBefore = u2ft(1000000000000ULL); ci.NotAfter = u2ft(1000000100000ULL);
    FILETIME lo = u2ft(5), hi = u2ft(0x7000000000000000ULL), in = u2ft(1000000050000ULL);
    EXPECT_EQ((DWORD)U(CertVerifyTimeValidity)(&lo, &ci), 0xFFFFFFFFu);   /* never a magnitude */
    EXPECT_EQ((DWORD)U(CertVerifyTimeValidity)(&hi, &ci), 1);
    EXPECT_EQ((DWORD)U(CertVerifyTimeValidity)(&in, &ci), 0);
}
TEST(gap1_timevalid_inverted_window) {
    /* NotAfter earlier than NotBefore: the NotBefore test is made first */
    REQUIRE(U(CertVerifyTimeValidity));
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    ci.NotBefore = u2ft(2000000000000ULL); ci.NotAfter = u2ft(1000000000000ULL);
    FILETIME mid = u2ft(1500000000000ULL), before = u2ft(900000000000ULL), after = u2ft(2500000000000ULL);
    CHECK(U(CertVerifyTimeValidity)(&mid, &ci) == -1);
    CHECK(U(CertVerifyTimeValidity)(&before, &ci) == -1);
    CHECK(U(CertVerifyTimeValidity)(&after, &ci) == 1);
}
TEST(gap1_timevalid_zero_not_after) {
    REQUIRE(U(CertVerifyTimeValidity));
    CERT_INFO ci; memset(&ci, 0, sizeof ci);   /* NotBefore = NotAfter = 0 */
    FILETIME z = u2ft(0), one = u2ft(1);
    CHECK(U(CertVerifyTimeValidity)(&z, &ci) == 0);
    CHECK(U(CertVerifyTimeValidity)(&one, &ci) == 1);
}
TEST(gap1_timevalid_null_time_uses_now) {
    REQUIRE(U(CertVerifyTimeValidity));
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    SYSTEMTIME st; GetSystemTime(&st);
    FILETIME now; SystemTimeToFileTime(&st, &now);
    ULONGLONG n = ft2u(now), day = 864000000000ULL;
    ci.NotBefore = u2ft(n - day); ci.NotAfter = u2ft(n + day);
    CHECK(U(CertVerifyTimeValidity)(NULL, &ci) == 0);
    ci.NotBefore = u2ft(n + day); ci.NotAfter = u2ft(n + 2 * day);
    CHECK(U(CertVerifyTimeValidity)(NULL, &ci) == -1);
    ci.NotBefore = u2ft(n - 3 * day); ci.NotAfter = u2ft(n - 2 * day);
    CHECK(U(CertVerifyTimeValidity)(NULL, &ci) == 1);
}
TEST(gap1_timevalid_real_cert_window) {
    REQUIRE(U(CertVerifyTimeValidity)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)); REQUIRE(a);
    FILETIME nb = a->pCertInfo->NotBefore, na = a->pCertInfo->NotAfter;
    SYSTEMTIME st;
    CHECK(FileTimeToSystemTime(&nb, &st) && st.wYear == 2020 && st.wMonth == 1 && st.wDay == 1 && st.wHour == 0);
    CHECK(FileTimeToSystemTime(&na, &st) && st.wYear == 2060 && st.wMonth == 1 && st.wDay == 1);
    FILETIME t = u2ft(ft2u(nb) - 1);
    CHECK(U(CertVerifyTimeValidity)(&t, a->pCertInfo) == -1);
    CHECK(U(CertVerifyTimeValidity)(&nb, a->pCertInfo) == 0);
    CHECK(U(CertVerifyTimeValidity)(&na, a->pCertInfo) == 0);
    t = u2ft(ft2u(na) + 1);
    CHECK(U(CertVerifyTimeValidity)(&t, a->pCertInfo) == 1);
    PCCERT_CONTEXT c = mkctx(BLOB(v_certC)); REQUIRE(c);
    nb = c->pCertInfo->NotBefore; na = c->pCertInfo->NotAfter;
    CHECK(FileTimeToSystemTime(&nb, &st) && st.wYear == 2021 && st.wMonth == 6);
    t = u2ft(ft2u(nb) - 1);
    CHECK(U(CertVerifyTimeValidity)(&t, c->pCertInfo) == -1);
    CHECK(U(CertVerifyTimeValidity)(&na, c->pCertInfo) == 0);
    U(CertFreeCertificateContext)(a); U(CertFreeCertificateContext)(c);
}

/* ---------------- CryptImportPublicKeyInfoEx2 ---------------- */
static void rev(BYTE *d, const BYTE *s, DWORD n) { for (DWORD i = 0; i < n; i++) d[i] = s[n - 1 - i]; }
TEST(gap1_importpub_rsa_modulus_matches) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = NULL;
    BOOL r = U(CryptImportPublicKeyInfoEx2)(ENC, &a->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &k);
    CHECKF(r, "err %lu", GetLastError());
    if (r && k) {
        BYTE blob[512]; ULONG got = 0;
        NTSTATUS s = U(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, blob, sizeof blob, &got, 0);
        CHECK(s == 0);
        if (s == 0) {
            BCRYPT_RSAKEY_BLOB *h = (void *)blob;
            CHECK(h->Magic == BCRYPT_RSAPUBLIC_MAGIC);
            CHECK(h->BitLength == 1024 && h->cbModulus == 128 && h->cbPublicExp == 3);
            BYTE exp[3] = {1, 0, 1}, mod[128];
            CHECK(!memcmp(blob + sizeof *h, exp, 3));
            rev(mod, v_keyA + 20, 128);          /* CAPI private blob: header(8) RSAPUBKEY(12) then little-endian modulus */
            CHECK(!memcmp(blob + sizeof *h + 3, mod, 128));
        }
        U(BCryptDestroyKey)(k);
    }
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_importpub_rsa_verifies_pkcs1_signature) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2)); REQUIRE(U(CertCreateCertificateContext)); REQUIRE(U(BCryptVerifySignature));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK(U(CryptImportPublicKeyInfoEx2)(ENC, &a->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &k));
    if (k) {
        BCRYPT_ALG_HANDLE h = NULL; BYTE dg[32]; ULONG hl = 0;
        CHECK(U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0);
        BCRYPT_HASH_HANDLE hh;
        CHECK(U(BCryptCreateHash)(h, &hh, NULL, 0, NULL, 0, 0) == 0);
        U(BCryptHashData)(hh, (PUCHAR)v_payload, sizeof v_payload, 0); U(BCryptFinishHash)(hh, dg, 32, 0); U(BCryptDestroyHash)(hh);
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        EXPECT_EQ(U(BCryptVerifySignature)(k, &pi, dg, 32, (PUCHAR)v_sigA, sizeof v_sigA, BCRYPT_PAD_PKCS1), 0);
        BYTE bad[128]; memcpy(bad, v_sigA, 128); bad[5] ^= 1;
        EXPECT_EQ(U(BCryptVerifySignature)(k, &pi, dg, 32, bad, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
        dg[0] ^= 1;
        EXPECT_EQ(U(BCryptVerifySignature)(k, &pi, dg, 32, (PUCHAR)v_sigA, sizeof v_sigA, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
        U(BCryptCloseAlgorithmProvider)(h, 0);
        U(BCryptDestroyKey)(k);
    }
    U(CertFreeCertificateContext)(a);
}
static void ec_case(const BYTE *cert, DWORD ccb, const BYTE *x, const BYTE *y, const BYTE *sig, DWORD cbk, ULONG magic, const WCHAR *hashalg, DWORD hlen) {
    PCCERT_CONTEXT c = mkctx(cert, ccb); if (!c) { CHECK(c != NULL); return; }
    BCRYPT_KEY_HANDLE k = NULL;
    BOOL r = U(CryptImportPublicKeyInfoEx2)(ENC, &c->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &k);
    CHECKF(r, "err %lu", GetLastError());
    if (r && k) {
        BYTE blob[256]; ULONG got = 0;
        NTSTATUS s = U(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &got, 0);
        CHECK(s == 0);
        if (s == 0) {
            BCRYPT_ECCKEY_BLOB *h = (void *)blob;
            CHECKF(h->dwMagic == magic, "magic %08lx", h->dwMagic);
            CHECK(h->cbKey == cbk);
            CHECK(!memcmp(blob + sizeof *h, x, cbk));
            CHECK(!memcmp(blob + sizeof *h + cbk, y, cbk));
        }
        BCRYPT_ALG_HANDLE ha = NULL; BCRYPT_HASH_HANDLE hh; BYTE dg[64];
        if (U(BCryptOpenAlgorithmProvider)(&ha, hashalg, NULL, 0) == 0 && U(BCryptCreateHash)(ha, &hh, NULL, 0, NULL, 0, 0) == 0) {
            U(BCryptHashData)(hh, (PUCHAR)v_payload, sizeof v_payload, 0); U(BCryptFinishHash)(hh, dg, hlen, 0); U(BCryptDestroyHash)(hh);
            EXPECT_EQ(U(BCryptVerifySignature)(k, NULL, dg, hlen, (PUCHAR)sig, 2 * cbk, 0), 0);
            BYTE bad[96]; memcpy(bad, sig, 2 * cbk); bad[3] ^= 0x10;
            EXPECT_EQ(U(BCryptVerifySignature)(k, NULL, dg, hlen, bad, 2 * cbk, 0), ST_INVALID_SIGNATURE);
        }
        if (ha) U(BCryptCloseAlgorithmProvider)(ha, 0);
        U(BCryptDestroyKey)(k);
    }
    U(CertFreeCertificateContext)(c);
}
TEST(gap1_importpub_ecc_p256) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2)); REQUIRE(U(BCryptExportKey));
    ec_case(BLOB(v_certE256), v_e256x, v_e256y, v_e256sig, 32, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_SHA256_ALGORITHM, 32);
}
TEST(gap1_importpub_ecc_p384) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2)); REQUIRE(U(BCryptExportKey));
    ec_case(BLOB(v_certE384), v_e384x, v_e384y, v_e384sig, 48, BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_SHA384_ALGORITHM, 48);
}
TEST(gap1_importpub_failure_clears_handle) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2));
    static BYTE pk[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    CERT_PUBLIC_KEY_INFO pki; memset(&pki, 0, sizeof pki);
    char oid[] = "1.2.3.4.5.6.7.8.9";
    pki.Algorithm.pszObjId = oid; pki.PublicKey.cbData = 8; pki.PublicKey.pbData = pk;
    BCRYPT_KEY_HANDLE k = (BCRYPT_KEY_HANDLE)(ULONG_PTR)0x1234;
    SET_ERR(0);
    BOOL r = U(CryptImportPublicKeyInfoEx2)(ENC, &pki, 0, NULL, &k);
    CHECK(r == FALSE);
    CHECK(k == NULL);
    t_note("unknown public key algorithm OID -> error %lu / 0x%08lx", GetLastError(), GetLastError());
    CHECK(GetLastError() != 0);
}
TEST(gap1_importpub_garbage_rsa_key_bits) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2));
    static BYTE pk[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    CERT_PUBLIC_KEY_INFO pki; memset(&pki, 0, sizeof pki);
    char oid[] = "1.2.840.113549.1.1.1";
    static BYTE nullparams[2] = {5, 0};
    pki.Algorithm.pszObjId = oid; pki.Algorithm.Parameters.cbData = 2; pki.Algorithm.Parameters.pbData = nullparams;
    pki.PublicKey.cbData = 8; pki.PublicKey.pbData = pk;
    BCRYPT_KEY_HANDLE k = (BCRYPT_KEY_HANDLE)(ULONG_PTR)0x1234;
    SET_ERR(0);
    CHECK(U(CryptImportPublicKeyInfoEx2)(ENC, &pki, 0, NULL, &k) == FALSE);
    DWORD e = GetLastError();
    t_note("rsa algorithm with undecodable key bits -> 0x%08lx", e);
    CHECK(e != 0);
}
TEST(gap1_importpub_bad_encoding_type) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = (BCRYPT_KEY_HANDLE)(ULONG_PTR)0x1234;
    SET_ERR(0);
    BOOL r = U(CryptImportPublicKeyInfoEx2)(0, &a->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &k);
    t_note("encoding type 0 -> ret %d, err 0x%08lx", r, GetLastError());
    if (r && k) U(BCryptDestroyKey)(k);
    k = (BCRYPT_KEY_HANDLE)(ULONG_PTR)0x1234;
    r = U(CryptImportPublicKeyInfoEx2)(PKCS_7_ASN_ENCODING, &a->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &k);
    t_note("encoding type PKCS_7 only -> ret %d, err 0x%08lx", r, GetLastError());
    if (r && k) U(BCryptDestroyKey)(k);
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_importpub_two_imports_distinct_handles) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)); REQUIRE(a);
    BCRYPT_KEY_HANDLE k1 = NULL, k2 = NULL;
    CHECK(U(CryptImportPublicKeyInfoEx2)(ENC, &a->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &k1));
    CHECK(U(CryptImportPublicKeyInfoEx2)(ENC, &a->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &k2));
    CHECK(k1 && k2 && k1 != k2);
    if (k1) CHECK(U(BCryptDestroyKey)(k1) == 0);
    if (k2) {   /* independent lifetime */
        BYTE blob[512]; ULONG got;
        CHECK(U(BCryptExportKey)(k2, NULL, BCRYPT_RSAPUBLIC_BLOB, blob, sizeof blob, &got, 0) == 0);
        CHECK(U(BCryptDestroyKey)(k2) == 0);
    }
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_importpub_key_is_public_only) {
    REQUIRE(U(CryptImportPublicKeyInfoEx2)); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = mkctx(BLOB(v_certA)); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK(U(CryptImportPublicKeyInfoEx2)(ENC, &a->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &k));
    if (k) {
        BYTE blob[1024]; ULONG got = 0;
        NTSTATUS s = U(BCryptExportKey)(k, NULL, BCRYPT_RSAPRIVATE_BLOB, blob, sizeof blob, &got, 0);
        CHECK(s != 0);
        t_note("private export of an imported public key -> 0x%08lx", (unsigned long)s);
        U(BCryptDestroyKey)(k);
    }
    U(CertFreeCertificateContext)(a);
}

/* ---------------- CryptMsgDuplicate ---------------- */
TEST(gap1_msgdup_null) {
    REQUIRE(U(CryptMsgDuplicate));
    CHECK(U(CryptMsgDuplicate)(NULL) == NULL);
}
TEST(gap1_msgdup_returns_same_handle) {
    REQUIRE(U(CryptMsgDuplicate)); REQUIRE(U(CryptMsgOpenToDecode));
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL); REQUIRE(m);
    HCRYPTMSG d = U(CryptMsgDuplicate)(m);
    CHECK(d == m);
    HCRYPTMSG d2 = U(CryptMsgDuplicate)(d);
    CHECK(d2 == m);
    CHECK(U(CryptMsgClose)(d2)); CHECK(U(CryptMsgClose)(d)); CHECK(U(CryptMsgClose)(m));
}
TEST(gap1_msgdup_survives_original_close) {
    REQUIRE(U(CryptMsgDuplicate)); REQUIRE(U(CryptMsgOpenToDecode));
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL); REQUIRE(m);
    CHECK(U(CryptMsgUpdate)(m, BLOB(v_dig_sha256), TRUE));
    HCRYPTMSG d = U(CryptMsgDuplicate)(m);
    CHECK(U(CryptMsgClose)(m));
    DWORD type = 0, cb = sizeof type;
    CHECK(U(CryptMsgGetParam)(d, CMSG_TYPE_PARAM, 0, &type, &cb));
    EXPECT_EQ(type, CMSG_HASHED);
    BYTE content[128]; cb = sizeof content;
    CHECK(U(CryptMsgGetParam)(d, CMSG_CONTENT_PARAM, 0, content, &cb));
    CHECK(cb == sizeof v_payload && !memcmp(content, v_payload, cb));
    CHECK(U(CryptMsgClose)(d));
}
TEST(gap1_msgdup_many_references) {
    REQUIRE(U(CryptMsgDuplicate)); REQUIRE(U(CryptMsgOpenToDecode));
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL); REQUIRE(m);
    CHECK(U(CryptMsgUpdate)(m, BLOB(v_sig_att), TRUE));
    for (int i = 0; i < 100; i++) CHECK(U(CryptMsgDuplicate)(m) == m);
    for (int i = 0; i < 100; i++) CHECK(U(CryptMsgClose)(m));
    DWORD type = 0, cb = sizeof type;
    CHECK(U(CryptMsgGetParam)(m, CMSG_TYPE_PARAM, 0, &type, &cb));   /* the original reference is still open */
    EXPECT_EQ(type, CMSG_SIGNED);
    CHECK(U(CryptMsgClose)(m));
}
TEST(gap1_msgdup_shares_state) {
    REQUIRE(U(CryptMsgDuplicate)); REQUIRE(U(CryptMsgOpenToDecode));
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL); REQUIRE(m);
    HCRYPTMSG d = U(CryptMsgDuplicate)(m);
    CHECK(U(CryptMsgUpdate)(d, BLOB(v_sig_att), TRUE));   /* update through the duplicate ... */
    DWORD n = 0, cb = sizeof n;
    CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_COUNT_PARAM, 0, &n, &cb));   /* ... is visible through the original */
    EXPECT_EQ(n, 1);
    U(CryptMsgClose)(d); U(CryptMsgClose)(m);
}

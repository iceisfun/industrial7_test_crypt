#include "cnet.h"
/* CryptRetrieveObjectByUrlA/W against file:/// URLs of local scratch files. */

#define SENTINEL ((LPVOID)(ULONG_PTR)0x1234500)

typedef struct { const char *name; const unsigned char *p; size_t n; } ob;
#define OB(x) { #x, x, sizeof(x) }

/* ---- certificate contexts ------------------------------------------------ */
static void one_cert(const ob *v, int timeout, int ansi) {
    char path[MAX_PATH]; WCHAR wurl[1200]; char aurl[1200];
    if (!cn_mkfile("c.cer", v->p, v->n, path, sizeof path)) { CHECKF(0, "write %s", v->name); return; }
    cn_url_w(path, wurl, 1200); cn_url_a(path, aurl, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = ansi ? cn_retrieve_a(aurl, CONTEXT_OID_CERTIFICATE, 0, timeout, &obj, NULL)
                   : cn_retrieve_w(wurl, CONTEXT_OID_CERTIFICATE, 0, timeout, &obj, NULL);
    CHECKF(ok, "%s ansi=%d timeout=%d err=0x%lx", v->name, ansi, timeout, GetLastError());
    if (ok) {
        PCCERT_CONTEXT c = obj;
        CHECK(c != NULL && c != (PCCERT_CONTEXT)SENTINEL);
        if (c && c != (PCCERT_CONTEXT)SENTINEL) {
            EXPECT_EQ(c->cbCertEncoded, v->n);
            if (c->cbCertEncoded == v->n) CHECK(!memcmp(c->pbCertEncoded, v->p, v->n));
            EXPECT_EQ(c->dwCertEncodingType, X509_ASN_ENCODING);
            CHECK(c->hCertStore != NULL);
            U(CertFreeCertificateContext)(c);
        }
    } else {
        CHECKF(obj == NULL, "object %p after failure", obj);
    }
}
TEST(cnrfile_cert_w_sync) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    static const ob v[] = { OB(v_cert_a), OB(v_cert_b), OB(v_cert_c), OB(v_cert_d), OB(v_cert_e) };
    for (size_t i = 0; i < 5; i++) one_cert(&v[i], 0, 0);
}
TEST(cnrfile_cert_a_sync) {
    REQUIRE(U(CryptRetrieveObjectByUrlA));
    static const ob v[] = { OB(v_cert_a), OB(v_cert_b), OB(v_cert_c) };
    for (size_t i = 0; i < 3; i++) one_cert(&v[i], 0, 1);
}
TEST(cnrfile_cert_w_timeout) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    static const ob v[] = { OB(v_cert_a), OB(v_cert_d) };
    for (size_t i = 0; i < 2; i++) one_cert(&v[i], 5000, 0);
}
TEST(cnrfile_cert_a_timeout) {
    REQUIRE(U(CryptRetrieveObjectByUrlA));
    static const ob v[] = { OB(v_cert_b), OB(v_cert_e) };
    for (size_t i = 0; i < 2; i++) one_cert(&v[i], 5000, 1);
}
TEST(cnrfile_leading_spaces_trimmed) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200], sp[1300];
    CHECK(cn_mkfile("sp.cer", v_cert_b, sizeof v_cert_b, path, sizeof path));
    cn_url_w(path, u, 1200);
    wcscpy(sp, L"   "); wcscat(sp, u);
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_w(sp, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}
TEST(cnrfile_scheme_case_insensitive) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("case.cer", v_cert_b, sizeof v_cert_b, path, sizeof path));
    cn_url_w(path, u, 1200);
    memcpy(u, L"FILE", 8);
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    t_note("upper-case FILE scheme: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}
TEST(cnrfile_ppv_cleared_on_entry) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    /* *ppvObject is zeroed before anything else happens, even when the retrieval is rejected */
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_w(L"file:///no/such/dir/none.cer", CONTEXT_OID_CERTIFICATE, CRYPT_ASYNC_RETRIEVAL, 0, &obj, NULL);
    CHECK(!ok);
    CHECK(obj == NULL);
    obj = SENTINEL;
    ok = cn_retrieve_w(L"zzcn-unknown://x", CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok);
    CHECK(obj == NULL);
}

/* ---- CRL / CTL / PKCS7 / any --------------------------------------------- */
TEST(cnrfile_crl_context) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("a.crl", v_crl_a, sizeof v_crl_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    for (int t = 0; t < 2; t++) {
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CRL, 0, t ? 5000 : 0, &obj, NULL);
        CHECKF(ok, "timeout=%d err=0x%lx", t, GetLastError());
        if (!ok) continue;
        PCCRL_CONTEXT c = obj;
        EXPECT_EQ(c->cbCrlEncoded, sizeof v_crl_a);
        if (c->cbCrlEncoded == sizeof v_crl_a) CHECK(!memcmp(c->pbCrlEncoded, v_crl_a, sizeof v_crl_a));
        EXPECT_EQ(c->dwCertEncodingType, X509_ASN_ENCODING);
        U(CertFreeCRLContext)(c);
    }
}
TEST(cnrfile_crl_context_a) {
    REQUIRE(U(CryptRetrieveObjectByUrlA));
    char path[MAX_PATH], u[1200];
    CHECK(cn_mkfile("a2.crl", v_crl_a, sizeof v_crl_a, path, sizeof path));
    cn_url_a(path, u, sizeof u);
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_a(u, CONTEXT_OID_CRL, 0, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) U(CertFreeCRLContext)(obj);
}
TEST(cnrfile_ctl_context) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("l.stl", v_ctl_signed, sizeof v_ctl_signed, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CTL, 0, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) {
        PCCTL_CONTEXT c = obj;
        EXPECT_EQ(c->cbCtlEncoded, sizeof v_ctl_signed);
        if (c->cbCtlEncoded == sizeof v_ctl_signed) CHECK(!memcmp(c->pbCtlEncoded, v_ctl_signed, sizeof v_ctl_signed));
        U(CertFreeCTLContext)(c);
    }
}
TEST(cnrfile_pkcs7_store) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("ab.p7b", v_p7_ab, sizeof v_p7_ab, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_PKCS7, 0, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) {
        HCERTSTORE s = obj;
        EXPECT_EQ(cn_count_certs(s), 2);
        EXPECT_EQ(cn_count_crls(s), 0);
        U(CertCloseStore)(s, 0);
    }
    CHECK(cn_mkfile("a.p7b", v_p7_a, sizeof v_p7_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    obj = SENTINEL;
    ok = cn_retrieve_w(u, CONTEXT_OID_PKCS7, 0, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) { EXPECT_EQ(cn_count_certs(obj), 1); U(CertCloseStore)(obj, 0); }
}
TEST(cnrfile_capi2_any_store) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    struct { const char *n; const unsigned char *p; size_t len; int certs, crls, ctls; } rows[] = {
        { "cert", v_cert_a, sizeof v_cert_a, 1, 0, 0 },
        { "crl", v_crl_a, sizeof v_crl_a, 0, 1, 0 },
        { "ctl", v_ctl_signed, sizeof v_ctl_signed, -1, 0, 1 },
        { "p7b", v_p7_ab, sizeof v_p7_ab, 2, 0, 0 },
    };
    for (size_t i = 0; i < 4; i++) {
        char path[MAX_PATH]; WCHAR u[1200];
        CHECK(cn_mkfile("any.bin", rows[i].p, rows[i].len, path, sizeof path));
        cn_url_w(path, u, 1200);
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CAPI2_ANY, 0, 0, &obj, NULL);
        CHECKF(ok, "%s err=0x%lx", rows[i].n, GetLastError());
        if (!ok) continue;
        HCERTSTORE s = obj;
        if (rows[i].certs >= 0) EXPECT_EQ(cn_count_certs(s), rows[i].certs);
        EXPECT_EQ(cn_count_crls(s), rows[i].crls);
        EXPECT_EQ(cn_count_ctls(s), rows[i].ctls);
        U(CertCloseStore)(s, 0);
    }
}
TEST(cnrfile_cert_multiple_objects) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("m.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, CRYPT_RETRIEVE_MULTIPLE_OBJECTS, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) {
        /* with MULTIPLE_OBJECTS the result is a store */
        EXPECT_EQ(cn_count_certs(obj), 1);
        U(CertCloseStore)(obj, 0);
    }
    CHECK(cn_mkfile("m.p7b", v_p7_ab, sizeof v_p7_ab, path, sizeof path));
    cn_url_w(path, u, 1200);
    obj = SENTINEL;
    ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, CRYPT_RETRIEVE_MULTIPLE_OBJECTS, 0, &obj, NULL);
    CHECKF(ok, "p7b err=0x%lx", GetLastError());
    if (ok) { EXPECT_EQ(cn_count_certs(obj), 2); U(CertCloseStore)(obj, 0); }
}
TEST(cnrfile_crl_multiple_objects) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("m.crl", v_crl_a, sizeof v_crl_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CRL, CRYPT_RETRIEVE_MULTIPLE_OBJECTS, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) { EXPECT_EQ(cn_count_crls(obj), 1); U(CertCloseStore)(obj, 0); }
}
TEST(cnrfile_cert_from_p7_single) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    /* a certificate request against a PKCS7 file: observed behaviour only */
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("s.p7b", v_p7_a, sizeof v_p7_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    t_note("CERT oid on PKCS7 file: ok=%d err=0x%lx obj=%p", ok, ok ? 0 : GetLastError(), obj);
    if (ok) U(CertFreeCertificateContext)(obj);
}

/* ---- raw blob array ------------------------------------------------------- */
TEST(cnrfile_raw_blob) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    static const ob v[] = { OB(v_cert_a), OB(v_crl_a), OB(v_ctl_signed), OB(v_p7_ab) };
    for (size_t i = 0; i < 4; i++) {
        char path[MAX_PATH]; WCHAR u[1200];
        CHECK(cn_mkfile("raw.bin", v[i].p, v[i].n, path, sizeof path));
        cn_url_w(path, u, 1200);
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(u, NULL, 0, 0, &obj, NULL);
        CHECKF(ok, "%s err=0x%lx", v[i].name, GetLastError());
        if (!ok) continue;
        PCRYPT_BLOB_ARRAY a = obj;
        EXPECT_EQ(a->cBlob, 1);
        if (a->cBlob == 1) {
            /* single allocation: header, blob table, then data */
            CHECK((BYTE *)a->rgBlob == (BYTE *)a + 16);
            CHECK(a->rgBlob[0].pbData == (BYTE *)a + 16 + 16);
            EXPECT_EQ(a->rgBlob[0].cbData, v[i].n);
            if (a->rgBlob[0].cbData == v[i].n) CHECK(!memcmp(a->rgBlob[0].pbData, v[i].p, v[i].n));
        }
        U(CryptMemFree)(obj);
    }
}
TEST(cnrfile_raw_blob_any_bytes) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    /* the raw form does not parse the content */
    BYTE junk[300]; for (int i = 0; i < 300; i++) junk[i] = (BYTE)(i * 7 + 3);
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("junk.bin", junk, sizeof junk, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_w(u, NULL, 0, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) {
        PCRYPT_BLOB_ARRAY a = obj;
        EXPECT_EQ(a->cBlob, 1);
        EXPECT_EQ(a->rgBlob[0].cbData, 300);
        CHECK(!memcmp(a->rgBlob[0].pbData, junk, 300));
        U(CryptMemFree)(obj);
    }
}
TEST(cnrfile_raw_blob_sizes) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    static const DWORD sizes[] = { 1, 2, 15, 16, 17, 255, 256, 4095, 4096, 4097, 65535, 65536, 200000 };
    BYTE *big = HeapAlloc(GetProcessHeap(), 0, 200000);
    REQUIRE(big);
    for (int i = 0; i < 200000; i++) big[i] = (BYTE)(i ^ (i >> 8));
    for (size_t k = 0; k < sizeof sizes / sizeof *sizes; k++) {
        char path[MAX_PATH]; WCHAR u[1200];
        CHECK(cn_mkfile("sz.bin", big, sizes[k], path, sizeof path));
        cn_url_w(path, u, 1200);
        LPVOID obj = SENTINEL;
        BOOL ok = cn_retrieve_w(u, NULL, 0, 0, &obj, NULL);
        CHECKF(ok, "size %lu err=0x%lx", sizes[k], GetLastError());
        if (!ok) continue;
        PCRYPT_BLOB_ARRAY a = obj;
        CHECKF(a->cBlob == 1 && a->rgBlob[0].cbData == sizes[k], "size %lu got %lu", sizes[k], a->rgBlob[0].cbData);
        if (a->cBlob == 1 && a->rgBlob[0].cbData == sizes[k]) CHECK(!memcmp(a->rgBlob[0].pbData, big, sizes[k]));
        U(CryptMemFree)(obj);
    }
    HeapFree(GetProcessHeap(), 0, big);
}
TEST(cnrfile_raw_blob_a_variant) {
    REQUIRE(U(CryptRetrieveObjectByUrlA));
    char path[MAX_PATH], u[1200];
    CHECK(cn_mkfile("rawa.bin", v_cert_b, sizeof v_cert_b, path, sizeof path));
    cn_url_a(path, u, sizeof u);
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_a(u, NULL, 0, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) {
        PCRYPT_BLOB_ARRAY a = obj;
        EXPECT_EQ(a->rgBlob[0].cbData, sizeof v_cert_b);
        U(CryptMemFree)(obj);
    }
}
TEST(cnrfile_raw_blob_timeout_path) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("rawt.bin", v_crl_a, sizeof v_crl_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_w(u, NULL, 0, 3000, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) { EXPECT_EQ(((PCRYPT_BLOB_ARRAY)obj)->rgBlob[0].cbData, sizeof v_crl_a); U(CryptMemFree)(obj); }
}
TEST(cnrfile_ocsp_resp_oid_is_raw) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    /* CONTEXT_OID_OCSP_RESP skips the context creation provider and, like NULL, hands back the blob array */
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("ocsp.bin", v_crl_a, sizeof v_crl_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_OCSP_RESP, 0, 0, &obj, NULL);
    t_note("OCSP_RESP oid with file: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) {
        PCRYPT_BLOB_ARRAY a = obj;
        EXPECT_EQ(a->cBlob, 1);
        EXPECT_EQ(a->rgBlob[0].cbData, sizeof v_crl_a);
        U(CryptMemFree)(obj);
    }
}

/* ---- wrong object type / bad content -------------------------------------- */
TEST(cnrfile_wrong_type_table) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    struct { const char *n; const unsigned char *p; size_t len; LPCSTR oid; } rows[] = {
        { "cert as CRL", v_cert_a, sizeof v_cert_a, CONTEXT_OID_CRL },
        { "cert as CTL", v_cert_a, sizeof v_cert_a, CONTEXT_OID_CTL },
        { "crl as cert", v_crl_a, sizeof v_crl_a, CONTEXT_OID_CERTIFICATE },
        { "crl as ctl", v_crl_a, sizeof v_crl_a, CONTEXT_OID_CTL },
        { "ctl as cert", v_ctl_signed, sizeof v_ctl_signed, CONTEXT_OID_CERTIFICATE },
        { "ctl as crl", v_ctl_signed, sizeof v_ctl_signed, CONTEXT_OID_CRL },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        char path[MAX_PATH]; WCHAR u[1200];
        CHECK(cn_mkfile("wt.bin", rows[i].p, rows[i].len, path, sizeof path));
        cn_url_w(path, u, 1200);
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(u, rows[i].oid, 0, 0, &obj, NULL);
        CHECKF(!ok, "%s unexpectedly succeeded", rows[i].n);
        CHECKF(obj == NULL, "%s: object %p", rows[i].n, obj);
        t_note("%s: error 0x%lx", rows[i].n, GetLastError());
        if (ok && obj) U(CertFreeCertificateContext)(obj);
    }
}
TEST(cnrfile_garbage_content) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    static const LPCSTR oids[] = { CONTEXT_OID_CERTIFICATE, CONTEXT_OID_CRL, CONTEXT_OID_CTL, CONTEXT_OID_PKCS7, CONTEXT_OID_CAPI2_ANY };
    BYTE junk[64]; for (int i = 0; i < 64; i++) junk[i] = (BYTE)(0x41 + i % 7);
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("garb.bin", junk, sizeof junk, path, sizeof path));
    cn_url_w(path, u, 1200);
    for (size_t i = 0; i < 5; i++) {
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(u, oids[i], 0, 0, &obj, NULL);
        CHECKF(!ok, "oid %p accepted garbage", oids[i]);
        CHECKF(obj == NULL, "oid %p: object %p", oids[i], obj);
        t_note("garbage with oid %p: error 0x%lx", oids[i], GetLastError());
    }
}
TEST(cnrfile_truncated_cert) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    size_t cuts[] = { 1, 2, 10, sizeof v_cert_a / 2, sizeof v_cert_a - 1 };
    for (size_t i = 0; i < 5; i++) {
        CHECK(cn_mkfile("trunc.cer", v_cert_a, cuts[i], path, sizeof path));
        cn_url_w(path, u, 1200);
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
        CHECKF(!ok, "truncated at %zu accepted", cuts[i]);
        CHECK(obj == NULL);
        t_note("cert truncated to %zu: error 0x%lx", cuts[i], GetLastError());
    }
}
TEST(cnrfile_empty_file) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("empty.bin", "", 0, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok);
    t_note("empty file as cert: error 0x%lx", GetLastError());
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(u, NULL, 0, 0, &obj, NULL);
    t_note("empty file raw: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok && obj) U(CryptMemFree)(obj);
}
TEST(cnrfile_cert_with_trailing_bytes) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    BYTE buf[sizeof v_cert_a + 8];
    memcpy(buf, v_cert_a, sizeof v_cert_a); memset(buf + sizeof v_cert_a, 0, 8);
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("trail.cer", buf, sizeof buf, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    t_note("cert with 8 trailing zero bytes: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}

/* ---- missing files, bad schemes ------------------------------------------- */
TEST(cnrfile_missing_file) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200]; char au[1200];
    t_tmpfile(path, sizeof path, "does_not_exist.cer");
    cn_url_w(path, u, 1200); cn_url_a(path, au, sizeof au);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    DWORD ew = GetLastError();
    t_note("missing file (W): error 0x%lx", ew);
    CHECK(ew != 0);
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_a(au, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    EXPECT_ERR(ew);
    /* same for the raw form and the timeout path */
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(u, NULL, 0, 0, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    EXPECT_ERR(ew);
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 3000, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    t_note("missing file (timeout path): error 0x%lx", GetLastError());
}
TEST(cnrfile_missing_directory) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    t_tmpfile(path, sizeof path, "nodir\\deeper\\x.cer");
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    t_note("missing directory: error 0x%lx", GetLastError());
}
TEST(cnrfile_directory_as_file) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    WCHAR u[1200];
    cn_url_w(t_tmpdir(), u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    t_note("directory url: error 0x%lx", GetLastError());
}
TEST(cnrfile_unknown_schemes) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    static const WCHAR *urls[] = { L"zzcn-unknown://host/x.cer", L"ftp://host.example.test/x.cer", L"gopher://h/x", L"mailto:a@example.test",
        L"urn:x:y", L"x://", L"a-b.c+d://z/q", L"data:text/plain,abc", L"javascript:0", L"res://nowhere/1" };
    for (size_t i = 0; i < sizeof urls / sizeof *urls; i++) {
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(urls[i], CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
        CHECKF(!ok, "%ls accepted", urls[i]);
        CHECKF(obj == NULL, "%ls: object %p", urls[i], obj);
        DWORD e = GetLastError();
        t_note("%ls: error 0x%lx", urls[i], e);
        CHECK(e != 0);
    }
}
TEST(cnrfile_unknown_scheme_a_matches_w) {
    REQUIRE(U(CryptRetrieveObjectByUrlA));
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_a("zzcn-unknown://host/x.cer", NULL, 0, 0, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    DWORD ea = GetLastError();
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(L"zzcn-unknown://host/x.cer", NULL, 0, 0, &obj, NULL);
    CHECK(!ok);
    EXPECT_ERR(ea);
    /* a non-zero timeout takes the thread path, the failure must be the same */
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(L"zzcn-unknown://host/x.cer", NULL, 0, 3000, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    t_note("unknown scheme: sync 0x%lx, timeout path 0x%lx", ea, GetLastError());
}
TEST(cnrfile_no_scheme_with_colon_len) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    /* scheme longer than 32 characters cannot name a provider */
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(L"abcdefghijklmnopqrstuvwxyz0123456789://host/x", NULL, 0, 0, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    t_note("40-char scheme: error 0x%lx", GetLastError());
}

/* ---- ANSI conversion buffer: 0x801 wide characters ------------------------- */
TEST(cnrfile_ansi_url_length_limit) {
    REQUIRE(U(CryptRetrieveObjectByUrlA));
    static char url[4200];
    /* 2048 characters + NUL fit the 2049-wchar conversion buffer; 2049 do not */
    memset(url, 'x', sizeof url);
    memcpy(url, "zzcn:", 5);
    url[2048] = 0;
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_a(url, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok);
    CHECK(GetLastError() != ERROR_INSUFFICIENT_BUFFER);
    CHECK(obj == NULL);
    url[2048] = 'x'; url[2049] = 0;
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_a(url, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    /* the conversion failure returns before *ppvObject is touched */
    CHECK(obj == SENTINEL);
    url[3000] = 0;
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_a(url, NULL, 0, 0, &obj, NULL);
    CHECK(!ok);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    CHECK(obj == SENTINEL);
}

/* ---- flag validation (verified in the decompilation) ------------------------ */
typedef struct { const char *n; DWORD flags; DWORD err; } flag_row;
TEST(cnrfile_invalid_flag_combos) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("fl.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    static const flag_row rows[] = {
        { "ASYNC", CRYPT_ASYNC_RETRIEVAL, ERR_INVALIDARG },
        { "ASYNC|CACHE_ONLY", CRYPT_ASYNC_RETRIEVAL | CRYPT_CACHE_ONLY_RETRIEVAL, ERR_INVALIDARG },
        { "CACHE_ONLY|WIRE_ONLY", CRYPT_CACHE_ONLY_RETRIEVAL | CRYPT_WIRE_ONLY_RETRIEVAL, ERR_INVALIDARG },
        { "VERIFY_DATA_HASH", CRYPT_VERIFY_DATA_HASH, ERR_NOTIMPL },
        { "VERIFY_SIG|VERIFY_HASH", CRYPT_VERIFY_CONTEXT_SIGNATURE | CRYPT_VERIFY_DATA_HASH, ERR_INVALIDARG },
        { "VERIFY_SIG without pvVerify", CRYPT_VERIFY_CONTEXT_SIGNATURE, ERR_INVALIDARG },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        for (int ansi = 0; ansi < 2; ansi++) {
            char au[1200]; cn_url_a(path, au, sizeof au);
            LPVOID obj = SENTINEL; SET_ERR(0);
            BOOL ok = ansi ? cn_retrieve_a(au, CONTEXT_OID_CERTIFICATE, rows[i].flags, 0, &obj, NULL)
                           : cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, rows[i].flags, 0, &obj, NULL);
            CHECKF(!ok, "%s ansi=%d succeeded", rows[i].n, ansi);
            DWORD e = GetLastError();
            CHECKF(e == rows[i].err, "%s ansi=%d: error 0x%lx want 0x%lx", rows[i].n, ansi, e, rows[i].err);
            CHECKF(obj == NULL, "%s: object %p", rows[i].n, obj);
            if (ok && obj) U(CertFreeCertificateContext)(obj);
        }
    }
}
TEST(cnrfile_verify_sig_with_multiple) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("vm.crl", v_crl_a, sizeof v_crl_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    PCCERT_CONTEXT issuer = U(CertCreateCertificateContext)(X509_ASN_ENCODING, v_cert_a, sizeof v_cert_a);
    REQUIRE(issuer);
    LPVOID obj = SENTINEL; SET_ERR(0);
    /* signature verification cannot be combined with multiple-object retrieval */
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CRL, CRYPT_VERIFY_CONTEXT_SIGNATURE | CRYPT_RETRIEVE_MULTIPLE_OBJECTS, 0, &obj, (LPVOID)issuer);
    CHECK(!ok);
    EXPECT_ERR(ERR_INVALIDARG);
    CHECK(obj == NULL);
    U(CertFreeCertificateContext)(issuer);
}
TEST(cnrfile_verify_signature_good_issuer) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("vs.crl", v_crl_a, sizeof v_crl_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    PCCERT_CONTEXT issuer = U(CertCreateCertificateContext)(X509_ASN_ENCODING, v_cert_a, sizeof v_cert_a);
    REQUIRE(issuer);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CRL, CRYPT_VERIFY_CONTEXT_SIGNATURE, 0, &obj, (LPVOID)issuer);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) U(CertFreeCRLContext)(obj);
    U(CertFreeCertificateContext)(issuer);
}
TEST(cnrfile_verify_signature_wrong_issuer) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("vw.crl", v_crl_a, sizeof v_crl_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    PCCERT_CONTEXT issuer = U(CertCreateCertificateContext)(X509_ASN_ENCODING, v_cert_b, sizeof v_cert_b);
    REQUIRE(issuer);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CRL, CRYPT_VERIFY_CONTEXT_SIGNATURE, 0, &obj, (LPVOID)issuer);
    CHECK(!ok);
    CHECK(obj == NULL);
    t_note("CRL signature check against unrelated cert: error 0x%lx", GetLastError());
    if (ok && obj) U(CertFreeCRLContext)(obj);
    U(CertFreeCertificateContext)(issuer);
}

/* ---- benign flags with a local file ------------------------------------------ */
TEST(cnrfile_flags_ignored_by_file_scheme) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("fi.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    static const struct { const char *n; DWORD f; int hard; } rows[] = {
        { "DONT_CACHE_RESULT", CRYPT_DONT_CACHE_RESULT, 1 },
        { "OFFLINE_CHECK", CRYPT_OFFLINE_CHECK_RETRIEVAL, 1 },
        { "NO_AUTH", CRYPT_NO_AUTH_RETRIEVAL, 1 },
        { "STICKY_CACHE", CRYPT_STICKY_CACHE_RETRIEVAL, 0 },
        { "LDAP_SCOPE_BASE_ONLY", CRYPT_LDAP_SCOPE_BASE_ONLY_RETRIEVAL, 0 },
        { "LDAP_INSERT_ENTRY_ATTRIBUTE", CRYPT_LDAP_INSERT_ENTRY_ATTRIBUTE, 0 },
        { "LDAP_SIGN", CRYPT_LDAP_SIGN_RETRIEVAL, 0 },
        { "LDAP_AREC_EXCLUSIVE", CRYPT_LDAP_AREC_EXCLUSIVE_RETRIEVAL, 0 },
        { "AIA_RETRIEVAL", CRYPT_AIA_RETRIEVAL, 0 },
        { "all benign", CRYPT_DONT_CACHE_RESULT | CRYPT_NO_AUTH_RETRIEVAL | CRYPT_STICKY_CACHE_RETRIEVAL, 0 },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, rows[i].f, 0, &obj, NULL);
        if (rows[i].hard) CHECKF(ok, "%s err=0x%lx", rows[i].n, GetLastError());
        else t_note("%s: ok=%d err=0x%lx", rows[i].n, ok, ok ? 0 : GetLastError());
        if (ok) U(CertFreeCertificateContext)(obj);
    }
}
TEST(cnrfile_offline_check_repeat) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("oc.cer", v_cert_b, sizeof v_cert_b, path, sizeof path));
    cn_url_w(path, u, 1200);
    for (int i = 0; i < 5; i++) {
        LPVOID obj = SENTINEL;
        BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, CRYPT_OFFLINE_CHECK_RETRIEVAL, 0, &obj, NULL);
        CHECKF(ok, "iteration %d err=0x%lx", i, GetLastError());
        if (ok) U(CertFreeCertificateContext)(obj);
    }
}
TEST(cnrfile_cache_only_file) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("co.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL);
    t_note("CACHE_ONLY with file url: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(u, NULL, CRYPT_CACHE_ONLY_RETRIEVAL | CRYPT_STICKY_CACHE_RETRIEVAL, 0, &obj, NULL);
    t_note("CACHE_ONLY|STICKY raw with file url: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok && obj) U(CryptMemFree)(obj);
}
TEST(cnrfile_wire_only_file) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("wo.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, CRYPT_WIRE_ONLY_RETRIEVAL, 0, &obj, NULL);
    t_note("WIRE_ONLY with file url: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}

/* ---- cache-only retrieval of network URLs never leaves the machine -------------- */
TEST(cnrfile_net_urls_cache_only_miss) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    static const WCHAR *urls[] = {
        L"http://cryptt-offline.invalid/a.cer", L"https://cryptt-offline.invalid/b.crl",
        L"ldap://cryptt-offline.invalid/CN=x?cACertificate?base" };
    static const LPCSTR oids[] = { CONTEXT_OID_CERTIFICATE, CONTEXT_OID_CRL, NULL };
    for (size_t i = 0; i < 3; i++) {
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = cn_retrieve_w(urls[i], oids[i], CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL);
        CHECKF(!ok, "%ls cache-only hit", urls[i]);
        CHECKF(obj == NULL, "%ls: object %p", urls[i], obj);
        t_note("%ls cache-only: error 0x%lx", urls[i], GetLastError());
    }
}
TEST(cnrfile_net_urls_cache_only_miss_a) {
    REQUIRE(U(CryptRetrieveObjectByUrlA));
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_a("http://cryptt-offline.invalid/a.crl", CONTEXT_OID_CRL, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL);
    CHECK(!ok); CHECK(obj == NULL);
    DWORD ea = GetLastError();
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(L"http://cryptt-offline.invalid/a.crl", CONTEXT_OID_CRL, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL);
    CHECK(!ok);
    EXPECT_ERR(ea);
}

/* ---- aux info ---------------------------------------------------------------- */
TEST(cnrfile_aux_info_last_sync) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("ax_info.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    FILETIME ft = { 0xAAAAAAAA, 0x55555555 };
    CRYPT_RETRIEVE_AUX_INFO aux; memset(&aux, 0, sizeof aux);
    aux.cbSize = sizeof aux; aux.pLastSyncTime = &ft;
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = U(CryptRetrieveObjectByUrlW)(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL, NULL, NULL, &aux);
    CHECKF(ok, "err=0x%lx", GetLastError());
    t_note("pLastSyncTime after file retrieval: %08lx%08lx", ft.dwHighDateTime, ft.dwLowDateTime);
    if (ok) U(CertFreeCertificateContext)(obj);
}
TEST(cnrfile_aux_info_max_bytes) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("ax_max.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    CRYPT_RETRIEVE_AUX_INFO aux; memset(&aux, 0, sizeof aux);
    aux.cbSize = sizeof aux; aux.dwMaxUrlRetrievalByteCount = 16;
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = U(CryptRetrieveObjectByUrlW)(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL, NULL, NULL, &aux);
    t_note("max 16 bytes on %zu-byte file: ok=%d err=0x%lx", sizeof v_cert_a, ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
    aux.dwMaxUrlRetrievalByteCount = sizeof v_cert_a;
    obj = SENTINEL;
    ok = U(CryptRetrieveObjectByUrlW)(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL, NULL, NULL, &aux);
    t_note("max == size: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}
TEST(cnrfile_aux_info_small_cbsize) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("ax_small.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    CRYPT_RETRIEVE_AUX_INFO aux; memset(&aux, 0, sizeof aux);
    aux.cbSize = 4;
    LPVOID obj = SENTINEL;
    BOOL ok = U(CryptRetrieveObjectByUrlW)(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL, NULL, NULL, &aux);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}

/* ---- cancel callbacks ---------------------------------------------------------- */
static volatile LONG g_cancel_calls;
static BOOL WINAPI cancel_cb(DWORD flags, void *arg) { InterlockedIncrement(&g_cancel_calls); return FALSE; }
TEST(cnrfile_install_cancel_validation) {
    if (t_is_wine()) { t_skip("cancel-retrieval exports are unimplemented in the emulator"); return; }
    REQUIRE(U(CryptInstallCancelRetrieval));
    REQUIRE(U(CryptUninstallCancelRetrieval));
    SET_ERR(0);
    BOOL ok = U(CryptInstallCancelRetrieval)(NULL, NULL, 0, NULL);
    CHECK(!ok);
    EXPECT_ERR(ERR_INVALIDARG);
    ok = U(CryptInstallCancelRetrieval)(NULL, (void *)1, 0, NULL);
    CHECK(!ok);
    EXPECT_ERR(ERR_INVALIDARG);
}
TEST(cnrfile_install_uninstall_cycle) {
    if (t_is_wine()) { t_skip("cancel-retrieval exports are unimplemented in the emulator"); return; }
    REQUIRE(U(CryptInstallCancelRetrieval));
    REQUIRE(U(CryptUninstallCancelRetrieval));
    /* uninstall with nothing installed still succeeds */
    CHECK(U(CryptUninstallCancelRetrieval)(0, NULL));
    CHECK(U(CryptUninstallCancelRetrieval)(0, NULL));
    CHECK(U(CryptInstallCancelRetrieval)(cancel_cb, NULL, 0, NULL));
    /* installing again replaces the previous one */
    CHECK(U(CryptInstallCancelRetrieval)(cancel_cb, (void *)0x10, 0, NULL));
    CHECK(U(CryptUninstallCancelRetrieval)(0, NULL));
    CHECK(U(CryptUninstallCancelRetrieval)(0, NULL));
    for (int i = 0; i < 50; i++) {
        CHECK(U(CryptInstallCancelRetrieval)(cancel_cb, NULL, 0, NULL));
        CHECK(U(CryptUninstallCancelRetrieval)(0, NULL));
    }
}
TEST(cnrfile_retrieve_with_cancel_installed) {
    if (t_is_wine()) { t_skip("cancel-retrieval exports are unimplemented in the emulator"); return; }
    REQUIRE(U(CryptInstallCancelRetrieval));
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("cc.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    g_cancel_calls = 0;
    CHECK(U(CryptInstallCancelRetrieval)(cancel_cb, NULL, 0, NULL));
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 5000, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
    t_note("cancel callback invoked %ld times during a file retrieval", (long)g_cancel_calls);
    CHECK(U(CryptUninstallCancelRetrieval)(0, NULL));
}
static BOOL WINAPI cancel_yes(DWORD flags, void *arg) { InterlockedIncrement(&g_cancel_calls); return TRUE; }
TEST(cnrfile_cancel_returning_true_file) {
    if (t_is_wine()) { t_skip("cancel-retrieval exports are unimplemented in the emulator"); return; }
    REQUIRE(U(CryptInstallCancelRetrieval));
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("cy.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    g_cancel_calls = 0;
    CHECK(U(CryptInstallCancelRetrieval)(cancel_yes, NULL, 0, NULL));
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 5000, &obj, NULL);
    t_note("always-cancel callback with file url: ok=%d err=0x%lx calls=%ld", ok, ok ? 0 : GetLastError(), (long)g_cancel_calls);
    if (ok) U(CertFreeCertificateContext)(obj);
    CHECK(U(CryptUninstallCancelRetrieval)(0, NULL));
    obj = SENTINEL;
    ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 5000, &obj, NULL);
    CHECKF(ok, "after uninstall err=0x%lx", GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}
TEST(cnrfile_cancel_async_retrieval) {
    if (t_is_wine()) { t_skip("export is unimplemented in the emulator"); return; }
    REQUIRE(U(CryptCancelAsyncRetrieval));
    SET_ERR(0);
    CHECK(!U(CryptCancelAsyncRetrieval)(NULL));
    EXPECT_ERR(ERR_NOTIMPL);
    SET_ERR(0);
    CHECK(!U(CryptCancelAsyncRetrieval)((HCRYPTASYNC)(ULONG_PTR)0x1234));
    EXPECT_ERR(ERR_NOTIMPL);
}
static DWORD WINAPI cancel_thread(LPVOID p) {
    /* cancel registration is per thread: installing here must not disturb the caller */
    BOOL a = U(CryptInstallCancelRetrieval)(cancel_cb, NULL, 0, NULL);
    BOOL b = U(CryptUninstallCancelRetrieval)(0, NULL);
    return (a && b) ? 0 : 1;
}
TEST(cnrfile_cancel_in_other_thread) {
    if (t_is_wine()) { t_skip("cancel-retrieval exports are unimplemented in the emulator"); return; }
    REQUIRE(U(CryptInstallCancelRetrieval));
    HANDLE h = CreateThread(NULL, 0, cancel_thread, NULL, 0, NULL);
    REQUIRE(h);
    CHECK(WaitForSingleObject(h, 5000) == WAIT_OBJECT_0);
    DWORD code = 99; GetExitCodeThread(h, &code); CloseHandle(h);
    EXPECT_EQ(code, 0);
}

/* ---- threads and processes ------------------------------------------------------- */
static WCHAR g_thr_url[1200];
static volatile LONG g_thr_ok;
static DWORD WINAPI retr_thread(LPVOID p) {
    for (int i = 0; i < 25; i++) {
        LPVOID obj = NULL;
        if (!cn_retrieve_w(g_thr_url, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL)) return 1;
        PCCERT_CONTEXT c = obj;
        int good = c->cbCertEncoded == sizeof v_cert_a && !memcmp(c->pbCertEncoded, v_cert_a, sizeof v_cert_a);
        U(CertFreeCertificateContext)(c);
        if (!good) return 2;
    }
    InterlockedIncrement(&g_thr_ok);
    return 0;
}
TEST(cnrfile_parallel_threads) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH];
    CHECK(cn_mkfile("thr.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, g_thr_url, 1200);
    g_thr_ok = 0;
    HANDLE h[4];
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, retr_thread, NULL, 0, NULL);
    for (int i = 0; i < 4; i++) {
        if (!h[i]) { CHECKF(0, "thread %d", i); continue; }
        CHECK(WaitForSingleObject(h[i], 20000) == WAIT_OBJECT_0);
        CloseHandle(h[i]);
    }
    EXPECT_EQ(g_thr_ok, 4);
}
CHILD(cnrfile_child) {
    if (argc < 2) return 10;
    WCHAR u[1200];
    cn_url_w(argv[1], u, 1200);
    LPVOID obj = NULL;
    if (!cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL)) return 11;
    PCCERT_CONTEXT c = obj;
    int good = c->cbCertEncoded == sizeof v_cert_b && !memcmp(c->pbCertEncoded, v_cert_b, sizeof v_cert_b);
    U(CertFreeCertificateContext)(c);
    return good ? 0 : 12;
}
TEST(cnrfile_other_process) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH], args[MAX_PATH + 4];
    CHECK(cn_mkfile("child.cer", v_cert_b, sizeof v_cert_b, path, sizeof path));
    wsprintfA(args, "%s", path);
    EXPECT_EQ(t_run_child("cnrfile_child", args, 30000), 0);
}
TEST(cnrfile_context_outlives_file) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("gone.cer", v_cert_a, sizeof v_cert_a, path, sizeof path));
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL;
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    REQUIRE(ok);
    DeleteFileA(path);
    PCCERT_CONTEXT c = obj;
    CHECK(!memcmp(c->pbCertEncoded, v_cert_a, sizeof v_cert_a));
    PCCERT_CONTEXT d = U(CertDuplicateCertificateContext)(c);
    CHECK(d == c);
    U(CertFreeCertificateContext)(d);
    U(CertFreeCertificateContext)(c);
    /* and the file is really gone now */
    obj = SENTINEL;
    ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECK(!ok);
}
TEST(cnrfile_percent_encoded_path) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200];
    CHECK(cn_mkfile("with space.cer", v_cert_b, sizeof v_cert_b, path, sizeof path));
    cn_url_w(path, u, 1200);   /* the helper escapes the space as %20 */
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    CHECKF(ok, "err=0x%lx", GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}
TEST(cnrfile_localhost_authority) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200], v[1300];
    CHECK(cn_mkfile("lh.cer", v_cert_b, sizeof v_cert_b, path, sizeof path));
    cn_url_w(path, u, 1200);
    wcscpy(v, L"file://localhost/"); wcscat(v, u + 8);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(v, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    t_note("file://localhost/ form: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}
TEST(cnrfile_two_slash_form) {
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    char path[MAX_PATH]; WCHAR u[1200], v[1300];
    CHECK(cn_mkfile("ts.cer", v_cert_b, sizeof v_cert_b, path, sizeof path));
    cn_url_w(path, u, 1200);
    wcscpy(v, L"file://"); wcscat(v, u + 8);   /* file://C:/... */
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(v, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    t_note("file://C:/ form: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
    wcscpy(v, L"file:"); wcscat(v, u + 8);
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(v, CONTEXT_OID_CERTIFICATE, 0, 0, &obj, NULL);
    t_note("file:C:/ form: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (ok) U(CertFreeCertificateContext)(obj);
}

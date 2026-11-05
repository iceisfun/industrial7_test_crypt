/* CertCreateCertificateContext / CertCreateContext / CERT_INFO field exposure. */
#include "ccp.h"

static FILETIME ft_arr(const int *a) {
    SYSTEMTIME st; FILETIME ft;
    memset(&st, 0, sizeof st);
    st.wYear = a[0]; st.wMonth = a[1]; st.wDay = a[2]; st.wHour = a[3]; st.wMinute = a[4]; st.wSecond = a[5];
    SystemTimeToFileTime(&st, &ft); return ft;
}
static BYTE *dup_bytes(const FX *f, DWORD extra) { BYTE *p = (BYTE *)LocalAlloc(LPTR, f->cb + extra + 1); memcpy(p, f->der, f->cb); return p; }

TEST(ccp_create_every_fixture_decodes) {
    int i;
    REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i];
        PCCERT_CONTEXT c = ccp_ctx(f);
        CHECKF(c != NULL, "%s", f->name);
        if (!c) continue;
        EXPECT_EQ(c->dwCertEncodingType, ENC);
        EXPECT_EQ(c->cbCertEncoded, f->cb);
        CHECK(c->pbCertEncoded && !memcmp(c->pbCertEncoded, f->der, f->cb));
        CHECK(c->pCertInfo != NULL);
        ccp_free(c);
    }
}
TEST(ccp_create_copies_input) {
    const FX *f = &fx_root; PCCERT_CONTEXT c;
    BYTE *buf;
    REQUIRE(C32(CertCreateCertificateContext));
    buf = dup_bytes(f, 0);
    c = C32(CertCreateCertificateContext)(ENC, buf, f->cb);
    CHECK(c != NULL);
    if (c) {
        CHECK(c->pbCertEncoded != buf);
        memset(buf, 0, f->cb);   /* the context keeps its own copy */
        CHECK(!memcmp(c->pbCertEncoded, f->der, f->cb));
        CHECK(c->pCertInfo->Subject.cbData == f->cbSubj);
        ccp_free(c);
    }
    LocalFree(buf);
}
TEST(ccp_create_encoding_type_p7_bit_is_masked) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    c = C32(CertCreateCertificateContext)(ENC_P7, fx_root.der, fx_root.cb);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->dwCertEncodingType, ENC); ccp_free(c); }
}
TEST(ccp_create_encoding_type_zero_is_invalidarg) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(0, fx_root.der, fx_root.cb);
    EXPECT_FAIL(c == NULL, E_INVALIDARG_);
    ccp_free(c);
}
TEST(ccp_create_encoding_type_pkcs7_only_is_invalidarg) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(PKCS_7_ASN_ENCODING, fx_root.der, fx_root.cb);
    EXPECT_FAIL(c == NULL, E_INVALIDARG_);
    ccp_free(c);
}
TEST(ccp_create_encoding_type_unknown_fails) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(0x4, fx_root.der, fx_root.cb);
    CHECK(c == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    ccp_free(c);
}
TEST(ccp_create_trailing_bytes_are_trimmed) {
    const FX *f = &fx_leaf; PCCERT_CONTEXT c; BYTE *buf;
    REQUIRE(C32(CertCreateCertificateContext));
    buf = dup_bytes(f, 16);
    memset(buf + f->cb, 0xAB, 16);
    c = C32(CertCreateCertificateContext)(ENC, buf, f->cb + 16);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->cbCertEncoded, f->cb); CHECK(!memcmp(c->pbCertEncoded, f->der, f->cb)); ccp_free(c); }
    LocalFree(buf);
}
TEST(ccp_create_trailing_zero_bytes_are_trimmed) {
    const FX *f = &fx_ec256; PCCERT_CONTEXT c; BYTE *buf;
    REQUIRE(C32(CertCreateCertificateContext));
    buf = dup_bytes(f, 4);
    c = C32(CertCreateCertificateContext)(ENC, buf, f->cb + 4);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->cbCertEncoded, f->cb); ccp_free(c); }
    LocalFree(buf);
}
TEST(ccp_create_null_and_empty_fail_with_asn1_error) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(ENC, NULL, 0);
    CHECK(c == NULL); EXPECT_ASN1_ERR();
    ccp_free(c);
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(ENC, fx_root.der, 0);
    CHECK(c == NULL); EXPECT_ASN1_ERR();
    ccp_free(c);
}
TEST(ccp_create_every_truncation_fails) {
    int i; PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i];
        DWORD cuts[] = {1, 2, 3, 4, 5, 10, f->cb / 2, f->cb - 1};
        int k;
        for (k = 0; k < 8; k++) {
            DWORD n = cuts[k];
            if (n >= f->cb) continue;
            SET_ERR(0);
            c = C32(CertCreateCertificateContext)(ENC, f->der, n);
            CHECKF(c == NULL, "%s len %lu", f->name, (unsigned long)n);
            EXPECT_ASN1_ERR();
            ccp_free(c);
        }
    }
}
TEST(ccp_create_truncated_by_one_is_eod) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(ENC, fx_root.der, fx_root.cb - 1);
    CHECK(c == NULL);
    EXPECT_ASN1_ERR();
    ccp_free(c);
}
TEST(ccp_create_wrong_outer_tag_fails) {
    BYTE *buf; PCCERT_CONTEXT c; BYTE tags[] = {0x31, 0x02, 0x04, 0x05, 0xA0, 0x00};
    int k;
    REQUIRE(C32(CertCreateCertificateContext));
    buf = dup_bytes(&fx_root, 0);
    for (k = 0; k < (int)sizeof tags; k++) {
        buf[0] = tags[k];
        SET_ERR(0);
        c = C32(CertCreateCertificateContext)(ENC, buf, fx_root.cb);
        CHECKF(c == NULL, "tag 0x%02x", tags[k]);
        EXPECT_ASN1_ERR();
        ccp_free(c);
    }
    LocalFree(buf);
}
TEST(ccp_create_corrupt_tbs_tag_fails) {
    BYTE *buf; PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    buf = dup_bytes(&fx_root, 0);
    /* The first child of the outer SEQUENCE (the TBS) starts after the outer header (4 bytes for a 2-byte length). */
    CHECK(buf[0] == 0x30 && buf[1] == 0x82 && buf[4] == 0x30);
    buf[4] = 0x04;
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(ENC, buf, fx_root.cb);
    CHECK(c == NULL); EXPECT_ASN1_ERR();
    ccp_free(c);
    LocalFree(buf);
}
TEST(ccp_create_outer_length_too_long_fails) {
    BYTE *buf; PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    buf = dup_bytes(&fx_root, 0);
    buf[3] += 1;      /* declared length one more than present */
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(ENC, buf, fx_root.cb);
    CHECK(c == NULL); EXPECT_ASN1_ERR();
    ccp_free(c);
    LocalFree(buf);
}
TEST(ccp_create_garbage_input_fails) {
    static const BYTE g1[] = {0x30, 0x00}, g2[] = {0x30, 0x03, 0x02, 0x01, 0x01}, g3[] = {0xff, 0xff, 0xff, 0xff}, g4[] = {0x30, 0x80, 0x00, 0x00};
    const BYTE *tab[] = {g1, g2, g3, g4}; DWORD len[] = {sizeof g1, sizeof g2, sizeof g3, sizeof g4};
    int k; PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    for (k = 0; k < 4; k++) {
        SET_ERR(0);
        c = C32(CertCreateCertificateContext)(ENC, tab[k], len[k]);
        CHECKF(c == NULL, "garbage %d", k);
        EXPECT_ASN1_ERR();
        ccp_free(c);
    }
}
TEST(ccp_create_pem_text_is_not_accepted) {
    static const char pem[] = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    SET_ERR(0);
    c = C32(CertCreateCertificateContext)(ENC, (const BYTE *)pem, sizeof pem - 1);
    CHECK(c == NULL); EXPECT_ASN1_ERR();
    ccp_free(c);
}
TEST(ccp_create_independent_contexts) {
    PCCERT_CONTEXT a, b;
    REQUIRE(C32(CertCreateCertificateContext));
    a = ccp_ctx(&fx_root); b = ccp_ctx(&fx_root);
    CHECK(a && b && a != b);
    if (a && b) {
        CHECK(a->pbCertEncoded != b->pbCertEncoded);
        CHECK(a->pCertInfo != b->pCertInfo);
    }
    ccp_free(a); ccp_free(b);
}
TEST(ccp_duplicate_returns_same_pointer) {
    PCCERT_CONTEXT a, d;
    REQUIRE(C32(CertDuplicateCertificateContext));
    a = ccp_ctx(&fx_leaf);
    CHECK(a != NULL);
    if (!a) return;
    d = C32(CertDuplicateCertificateContext)(a);
    CHECK(d == a);
    ccp_free(a);                 /* still usable through the duplicate */
    CHECK(d->cbCertEncoded == fx_leaf.cb && !memcmp(d->pbCertEncoded, fx_leaf.der, fx_leaf.cb));
    CHECK(C32(CertFreeCertificateContext)(d));
}
TEST(ccp_duplicate_null_returns_null) {
    REQUIRE(C32(CertDuplicateCertificateContext));
    CHECK(C32(CertDuplicateCertificateContext)(NULL) == NULL);
}
TEST(ccp_free_always_returns_true) {
    PCCERT_CONTEXT a;
    REQUIRE(C32(CertFreeCertificateContext));
    CHECK(C32(CertFreeCertificateContext)(NULL) != 0);
    a = ccp_ctx(&fx_root);
    CHECK(C32(CertFreeCertificateContext)(a) != 0);
}
TEST(ccp_duplicate_keeps_properties_visible) {
    PCCERT_CONTEXT a, d; BYTE v = 0; DWORD cb = 1;
    static const BYTE data[] = {1, 2, 3};
    CRYPT_DATA_BLOB blob = {3, (BYTE *)data}; BYTE out[8]; DWORD ocb = sizeof out;
    REQUIRE(C32(CertDuplicateCertificateContext));
    a = ccp_ctx(&fx_leaf); d = C32(CertDuplicateCertificateContext)(a);
    CHECK(C32(CertSetCertificateContextProperty)(a, CERT_DESCRIPTION_PROP_ID, 0, &blob));
    CHECK(ccp_getprop(d, CERT_DESCRIPTION_PROP_ID, out, &ocb) && ocb == 3 && !memcmp(out, data, 3));
    ccp_free(d); ccp_free(a);
}

/* ---- CertCreateContext ---- */
static int g_free_calls; static void *g_free_arg;
static void WINAPI free_cb(void *pv) { g_free_calls++; g_free_arg = pv; }

TEST(ccp_createcontext_cert_basic) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateContext));
    c = (PCCERT_CONTEXT)C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, fx_root.der, fx_root.cb, 0, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->cbCertEncoded, fx_root.cb); CHECK(c->pbCertEncoded != fx_root.der); ccp_free(c); }
}
TEST(ccp_createcontext_bad_context_type) {
    DWORD t[] = {0, 4, 5, 0x100, 0xFFFFFFFF}; int k; const void *c;
    REQUIRE(C32(CertCreateContext));
    for (k = 0; k < 5; k++) {
        SET_ERR(0);
        c = C32(CertCreateContext)(t[k], ENC, fx_root.der, fx_root.cb, 0, NULL);
        CHECKF(c == NULL, "type %lu", (unsigned long)t[k]);
        EXPECT_ERR(E_INVALIDARG_);
    }
}
TEST(ccp_createcontext_encoding_zero) {
    const void *c;
    REQUIRE(C32(CertCreateContext));
    SET_ERR(0);
    c = C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, 0, fx_root.der, fx_root.cb, 0, NULL);
    EXPECT_FAIL(c == NULL, E_INVALIDARG_);
}
TEST(ccp_createcontext_bad_encoded_asn1) {
    const void *c;
    REQUIRE(C32(CertCreateContext));
    SET_ERR(0);
    c = C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, fx_root.der, 10, 0, NULL);
    CHECK(c == NULL); EXPECT_ASN1_ERR();
    SET_ERR(0);
    c = C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, fx_root.der, 10, CERT_CREATE_CONTEXT_NOCOPY_FLAG, NULL);
    CHECK(c == NULL); EXPECT_ASN1_ERR();
}
TEST(ccp_createcontext_nocopy_aliases_buffer) {
    BYTE *buf; PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateContext));
    buf = dup_bytes(&fx_leaf, 0);
    c = (PCCERT_CONTEXT)C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, buf, fx_leaf.cb, CERT_CREATE_CONTEXT_NOCOPY_FLAG, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(c->pbCertEncoded == buf); ccp_free(c); }
    LocalFree(buf);
}
TEST(ccp_createcontext_nocopy_free_callback_default_arg) {
    BYTE *buf; PCCERT_CONTEXT c; CERT_CREATE_CONTEXT_PARA p;
    REQUIRE(C32(CertCreateContext));
    buf = dup_bytes(&fx_leaf, 0);
    memset(&p, 0, sizeof p); p.cbSize = 16; p.pfnFree = free_cb;
    g_free_calls = 0; g_free_arg = (void *)1;
    c = (PCCERT_CONTEXT)C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, buf, fx_leaf.cb, CERT_CREATE_CONTEXT_NOCOPY_FLAG, &p);
    CHECK(c != NULL);
    EXPECT_EQ(g_free_calls, 0);
    if (c) { CHECK(c->pbCertEncoded == buf); ccp_free(c); }
    EXPECT_EQ(g_free_calls, 1);
    CHECK(g_free_arg == buf);         /* cbSize < 24: the callback receives the encoded pointer */
    LocalFree(buf);
}
TEST(ccp_createcontext_nocopy_free_callback_custom_arg) {
    BYTE *buf; PCCERT_CONTEXT c, d; CERT_CREATE_CONTEXT_PARA p; static int token;
    REQUIRE(C32(CertCreateContext));
    buf = dup_bytes(&fx_root, 0);
    memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.pfnFree = free_cb; p.pvFree = &token;
    g_free_calls = 0; g_free_arg = NULL;
    c = (PCCERT_CONTEXT)C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, buf, fx_root.cb, CERT_CREATE_CONTEXT_NOCOPY_FLAG, &p);
    CHECK(c != NULL);
    if (c) {
        d = C32(CertDuplicateCertificateContext)(c);
        ccp_free(c);
        EXPECT_EQ(g_free_calls, 0);   /* still referenced */
        ccp_free(d);
    }
    EXPECT_EQ(g_free_calls, 1);
    CHECK(g_free_arg == &token);
    LocalFree(buf);
}
TEST(ccp_createcontext_copy_does_not_call_free_callback) {
    PCCERT_CONTEXT c; CERT_CREATE_CONTEXT_PARA p;
    REQUIRE(C32(CertCreateContext));
    memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.pfnFree = free_cb; p.pvFree = &p;
    g_free_calls = 0;
    c = (PCCERT_CONTEXT)C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, fx_root.der, fx_root.cb, 0, &p);
    CHECK(c != NULL); ccp_free(c);
    EXPECT_EQ(g_free_calls, 0);
}
TEST(ccp_createcontext_sorted_and_noentry_flags_accepted_for_certs) {
    PCCERT_CONTEXT c; DWORD flags[] = {CERT_CREATE_CONTEXT_SORTED_FLAG, CERT_CREATE_CONTEXT_NO_ENTRY_FLAG, CERT_CREATE_CONTEXT_SORTED_FLAG | CERT_CREATE_CONTEXT_NO_ENTRY_FLAG}; int k;
    REQUIRE(C32(CertCreateContext));
    for (k = 0; k < 3; k++) {
        c = (PCCERT_CONTEXT)C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, fx_root.der, fx_root.cb, flags[k], NULL);
        CHECKF(c != NULL, "flags 0x%lx", (unsigned long)flags[k]);
        if (c) { EXPECT_EQ(c->cbCertEncoded, fx_root.cb); ccp_free(c); }
    }
}
TEST(ccp_createcontext_crl_and_ctl_reject_cert_bytes) {
    const void *c;
    REQUIRE(C32(CertCreateContext));
    SET_ERR(0);
    c = C32(CertCreateContext)(CERT_STORE_CRL_CONTEXT, ENC, fx_root.der, fx_root.cb, 0, NULL);
    CHECK(c == NULL); EXPECT_ERR(CRYPT_E_ASN1_BADTAG_);
    SET_ERR(0);
    c = C32(CertCreateContext)(CERT_STORE_CTL_CONTEXT, ENC_P7, fx_root.der, fx_root.cb, 0, NULL);
    CHECK(c == NULL); EXPECT_ERR(ERROR_INVALID_DATA);
}
TEST(ccp_createcontext_certs_not_in_any_store) {
    PCCERT_CONTEXT c; HCERTSTORE s;
    REQUIRE(C32(CertCreateContext));
    s = ccp_mem();
    c = (PCCERT_CONTEXT)C32(CertCreateContext)(CERT_STORE_CERTIFICATE_CONTEXT, ENC, fx_root.der, fx_root.cb, 0, NULL);
    CHECK(c != NULL && s != NULL);
    if (c && s) CHECK(C32(CertEnumCertificatesInStore)(s, NULL) == NULL);
    ccp_free(c); ccp_close(s);
}

/* ---- CERT_INFO fields ---- */
TEST(ccp_info_version) {
    int i; REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        PCCERT_CONTEXT c = ccp_ctx(ccp_all[i]);
        if (!c) { CHECK(0); continue; }
        CHECKF(c->pCertInfo->dwVersion == (DWORD)(ccp_all[i]->version == 3 ? CERT_V3 : CERT_V1), "%s", ccp_all[i]->name);
        ccp_free(c);
    }
}
TEST(ccp_info_serial_numbers) {
    int i; REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        PCCERT_CONTEXT c = ccp_ctx(ccp_all[i]);
        if (!c) { CHECK(0); continue; }
        CHECKF(ccp_serial_ok(&c->pCertInfo->SerialNumber, ccp_all[i]), "%s", ccp_all[i]->name);
        ccp_free(c);
    }
}
TEST(ccp_info_serial_is_little_endian) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    c = ccp_ctx(&fx_root);       /* DER integer 0x0100 */
    if (c) { CHECK(c->pCertInfo->SerialNumber.cbData == 2 && c->pCertInfo->SerialNumber.pbData[0] == 0x00 && c->pCertInfo->SerialNumber.pbData[1] == 0x01); ccp_free(c); }
    c = ccp_ctx(&fx_ec256);      /* DER integer 0x1234 */
    if (c) { CHECK(c->pCertInfo->SerialNumber.cbData == 2 && c->pCertInfo->SerialNumber.pbData[0] == 0x34 && c->pCertInfo->SerialNumber.pbData[1] == 0x12); ccp_free(c); }
    c = ccp_ctx(&fx_inter);      /* DER integer 0x0201 */
    if (c) { CHECK(c->pCertInfo->SerialNumber.cbData == 2 && c->pCertInfo->SerialNumber.pbData[0] == 0x01 && c->pCertInfo->SerialNumber.pbData[1] == 0x02); ccp_free(c); }
}
TEST(ccp_info_high_bit_serial_form_observed) {
    PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateCertificateContext));
    c = ccp_ctx(&fx_negserial);  /* DER integer 00 ff 80 aa 55 */
    if (c) {
        const CRYPT_INTEGER_BLOB *s = &c->pCertInfo->SerialNumber;
        static const BYTE want[5] = {0x55, 0xaa, 0x80, 0xff, 0x00};      /* the DER pad octet is kept, little endian */
        CHECK(ccp_serial_ok(s, &fx_negserial));
        EXPECT_EQ(s->cbData, 5); if (s->cbData == 5) CHECK(!memcmp(s->pbData, want, 5));
        ccp_free(c);
    }
}
TEST(ccp_info_signature_algorithm) {
    int i; REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f);
        if (!c) { CHECK(0); continue; }
        CHECKF(c->pCertInfo->SignatureAlgorithm.pszObjId && !strcmp(c->pCertInfo->SignatureAlgorithm.pszObjId, f->sigoid), "%s: %s", f->name, c->pCertInfo->SignatureAlgorithm.pszObjId);
        CHECKF(c->pCertInfo->SignatureAlgorithm.Parameters.cbData == (DWORD)f->cbSigPara, "%s: sigpara cb %lu want %d", f->name, (unsigned long)c->pCertInfo->SignatureAlgorithm.Parameters.cbData, f->cbSigPara);
        if (f->cbSigPara == 2) CHECK(c->pCertInfo->SignatureAlgorithm.Parameters.pbData[0] == 5 && c->pCertInfo->SignatureAlgorithm.Parameters.pbData[1] == 0);
        ccp_free(c);
    }
}
TEST(ccp_info_issuer_and_subject_blobs) {
    int i; REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f);
        if (!c) { CHECK(0); continue; }
        CHECKF(blob_eq(&c->pCertInfo->Issuer, f->iss, f->cbIss), "%s issuer", f->name);
        CHECKF(blob_eq(&c->pCertInfo->Subject, f->subj, f->cbSubj), "%s subject", f->name);
        ccp_free(c);
    }
}
TEST(ccp_info_name_blobs_point_into_encoded_cert) {
    int i; REQUIRE(C32(CertCreateCertificateContext));
    /* The CERT_INFO is decoded with CRYPT_DECODE_NOCOPY_FLAG over the context's own copy of the encoding. */
    if (t_is_wine()) { t_skip("emulator copies the blobs"); return; }
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f);
        const BYTE *lo, *hi;
        if (!c) { CHECK(0); continue; }
        lo = c->pbCertEncoded; hi = lo + c->cbCertEncoded;
        CHECKF(c->pCertInfo->Issuer.pbData >= lo && c->pCertInfo->Issuer.pbData + c->pCertInfo->Issuer.cbData <= hi, "%s issuer", f->name);
        CHECKF(c->pCertInfo->Subject.pbData >= lo && c->pCertInfo->Subject.pbData + c->pCertInfo->Subject.cbData <= hi, "%s subject", f->name);
        CHECKF(c->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData >= lo && c->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData < hi, "%s pubkey", f->name);
        ccp_free(c);
    }
}
TEST(ccp_info_validity) {
    int i; REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f);
        FILETIME nb, na;
        if (!c) { CHECK(0); continue; }
        nb = ft_arr(f->nb); na = ft_arr(f->na);
        CHECKF(!memcmp(&c->pCertInfo->NotBefore, &nb, sizeof nb), "%s notBefore", f->name);
        CHECKF(!memcmp(&c->pCertInfo->NotAfter, &na, sizeof na), "%s notAfter", f->name);
        ccp_free(c);
    }
}
TEST(ccp_info_public_key_info) {
    int i; REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f);
        const CERT_PUBLIC_KEY_INFO *k;
        if (!c) { CHECK(0); continue; }
        k = &c->pCertInfo->SubjectPublicKeyInfo;
        CHECKF(k->Algorithm.pszObjId && !strcmp(k->Algorithm.pszObjId, f->keyoid), "%s alg %s", f->name, k->Algorithm.pszObjId);
        CHECKF(k->Algorithm.Parameters.cbData == (DWORD)f->cbKeyPara, "%s keypara %lu", f->name, (unsigned long)k->Algorithm.Parameters.cbData);
        if (f->cbKeyPara) CHECKF(!memcmp(k->Algorithm.Parameters.pbData, f->keypara, f->cbKeyPara), "%s keypara bytes", f->name);
        CHECKF(blob_eq((const CRYPT_DATA_BLOB *)&k->PublicKey, f->pub, f->cbPub), "%s pubkey bytes", f->name);
        CHECKF(k->PublicKey.cUnusedBits == 0, "%s unused bits", f->name);
        ccp_free(c);
    }
}
TEST(ccp_info_extension_counts) {
    int i; REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i]; PCCERT_CONTEXT c = ccp_ctx(f);
        if (!c) { CHECK(0); continue; }
        CHECKF(c->pCertInfo->cExtension == (DWORD)f->cext, "%s ext %lu want %d", f->name, (unsigned long)c->pCertInfo->cExtension, f->cext);
        CHECKF((c->pCertInfo->rgExtension == NULL) == (f->cext == 0), "%s rgExtension %s", f->name, c->pCertInfo->rgExtension ? "set" : "NULL");
        ccp_free(c);
    }
}
TEST(ccp_info_v1_has_no_extensions_or_unique_ids) {
    const FX *v1[] = {&fx_ec384v1, &fx_expired, &fx_rsa1024, &fx_utf8}; int i;
    REQUIRE(C32(CertCreateCertificateContext));
    for (i = 0; i < 4; i++) {
        PCCERT_CONTEXT c = ccp_ctx(v1[i]);
        if (!c) { CHECK(0); continue; }
        EXPECT_EQ(c->pCertInfo->dwVersion, CERT_V1);
        EXPECT_EQ(c->pCertInfo->cExtension, 0);
        EXPECT_EQ(c->pCertInfo->IssuerUniqueId.cbData, 0);
        EXPECT_EQ(c->pCertInfo->SubjectUniqueId.cbData, 0);
        ccp_free(c);
    }
}
TEST(ccp_info_extension_oids_present) {
    PCCERT_CONTEXT c; DWORD k;
    struct { const FX *f; const char *oid; int present; } tab[] = {
        {&fx_leaf, szOID_BASIC_CONSTRAINTS2, 1}, {&fx_leaf, szOID_KEY_USAGE, 1}, {&fx_leaf, szOID_ENHANCED_KEY_USAGE, 1},
        {&fx_leaf, szOID_SUBJECT_ALT_NAME2, 1}, {&fx_leaf, szOID_SUBJECT_KEY_IDENTIFIER, 1}, {&fx_leaf, szOID_AUTHORITY_KEY_IDENTIFIER2, 1},
        {&fx_root, szOID_BASIC_CONSTRAINTS2, 1}, {&fx_root, szOID_KEY_USAGE, 1}, {&fx_root, szOID_ENHANCED_KEY_USAGE, 0},
        {&fx_root, szOID_SUBJECT_ALT_NAME2, 0}, {&fx_ec256, szOID_ENHANCED_KEY_USAGE, 1}, {&fx_ec256, szOID_BASIC_CONSTRAINTS2, 0},
        {&fx_leafi, szOID_ENHANCED_KEY_USAGE, 1}, {&fx_inter, szOID_AUTHORITY_KEY_IDENTIFIER2, 1},
    };
    REQUIRE(C32(CertFindExtension));
    for (k = 0; k < sizeof tab / sizeof tab[0]; k++) {
        c = ccp_ctx(tab[k].f);
        if (!c) { CHECK(0); continue; }
        CHECKF((C32(CertFindExtension)(tab[k].oid, c->pCertInfo->cExtension, c->pCertInfo->rgExtension) != NULL) == tab[k].present, "%s %s", tab[k].f->name, tab[k].oid);
        ccp_free(c);
    }
}
TEST(ccp_info_critical_flags) {
    PCCERT_CONTEXT c; PCERT_EXTENSION e;
    REQUIRE(C32(CertFindExtension));
    c = ccp_ctx(&fx_root);
    if (c) {
        e = C32(CertFindExtension)(szOID_BASIC_CONSTRAINTS2, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECK(e && e->fCritical);
        e = C32(CertFindExtension)(szOID_KEY_USAGE, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECK(e && e->fCritical);
        e = C32(CertFindExtension)(szOID_SUBJECT_KEY_IDENTIFIER, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECK(e && !e->fCritical);
        ccp_free(c);
    }
    c = ccp_ctx(&fx_leaf);
    if (c) {
        e = C32(CertFindExtension)(szOID_BASIC_CONSTRAINTS2, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECK(e && !e->fCritical);
        e = C32(CertFindExtension)(szOID_ENHANCED_KEY_USAGE, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECK(e && !e->fCritical);
        ccp_free(c);
    }
}
TEST(ccp_info_ski_extension_value) {
    PCCERT_CONTEXT c; PCERT_EXTENSION e;
    int i;
    REQUIRE(C32(CertFindExtension));
    for (i = 0; i < ccp_nall; i++) {
        const FX *f = ccp_all[i];
        if (!f->hasski) continue;
        c = ccp_ctx(f);
        if (!c) { CHECK(0); continue; }
        e = C32(CertFindExtension)(szOID_SUBJECT_KEY_IDENTIFIER, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECKF(e != NULL, "%s", f->name);
        if (e) {   /* OCTET STRING { OCTET STRING keyid } */
            CHECKF(e->Value.cbData == 22 && e->Value.pbData[0] == 4 && e->Value.pbData[1] == 20 && !memcmp(e->Value.pbData + 2, f->ski, 20), "%s ski value", f->name);
        }
        ccp_free(c);
    }
}
TEST(ccp_info_cert_info_stable_across_calls) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf);
    const CERT_INFO *p;
    REQUIRE(C32(CertCreateCertificateContext));
    if (!c) { CHECK(0); return; }
    p = c->pCertInfo;
    {   BYTE b[32]; DWORD cb = sizeof b; ccp_getprop(c, CERT_SHA1_HASH_PROP_ID, b, &cb); }
    CHECK(c->pCertInfo == p);
    ccp_free(c);
}

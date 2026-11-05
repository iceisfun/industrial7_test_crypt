#include "sm.h"
/* CertSaveStore, serialized/PKCS7/PKCS12/message/file providers, serialized elements, CertControlStore, store properties. */

static HCERTSTORE full_store(void) {
    HCERTSTORE h = sm_abc();
    sm_addcrl(h, VEC(v_crl_1a), DISP_NEW, NULL);
    U(CertAddEncodedCTLToStore)(h, ENC, VEC(v_ctl_1a), DISP_NEW, NULL);
    return h;
}
static BYTE *save_mem(HCERTSTORE h, DWORD enc, DWORD as, DWORD *cb, DWORD flags) {
    CRYPT_DATA_BLOB b = { 0, NULL };
    if (!U(CertSaveStore)(h, enc, as, CERT_STORE_SAVE_TO_MEMORY, &b, flags)) return NULL;
    BYTE *p = (BYTE *)LocalAlloc(LPTR, b.cbData + 1);
    b.pbData = p;
    if (!U(CertSaveStore)(h, enc, as, CERT_STORE_SAVE_TO_MEMORY, &b, flags)) { LocalFree(p); return NULL; }
    *cb = b.cbData;
    return p;
}
static HCERTSTORE open_blob(LPCSTR prov, DWORD enc, DWORD flags, const BYTE *p, DWORD n) {
    CRYPT_DATA_BLOB b = { n, (BYTE *)p };
    return U(CertOpenStore)(prov, enc, 0, flags, &b);
}
static void wpath(const char *a, WCHAR *w, int n) { MultiByteToWideChar(CP_ACP, 0, a, -1, w, n); }

/* ---------------- CertSaveStore to memory ---------------- */
TEST(css_save_store_memory_size_protocol) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_DATA_BLOB b = { 0, NULL };
    CHECK(U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    CHECK(b.cbData > 3 * 400);
    DWORD need = b.cbData;
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need);
    b.pbData = buf; b.cbData = need - 1;
    SET_ERR(0);
    CHECK(!U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(b.cbData, need);
    b.cbData = need;
    CHECK(U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    EXPECT_EQ(b.cbData, need);
    LocalFree(buf); sm_close(h);
}
TEST(css_save_store_header_magic) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    DWORD cb = 0; BYTE *p = save_mem(h, 0, CERT_STORE_SAVE_AS_STORE, &cb, 0);
    CHECK(p != NULL);
    if (p) {
        static const BYTE hdr[8] = { 0, 0, 0, 0, 'C', 'E', 'R', 'T' };
        CHECK(cb >= 8 && !memcmp(p, hdr, 8));
        LocalFree(p);
    }
    sm_close(h);
}
TEST(css_save_store_empty) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    DWORD cb = 0; BYTE *p = save_mem(h, 0, CERT_STORE_SAVE_AS_STORE, &cb, 0);
    CHECK(p != NULL);
    if (p) {
        t_note("empty serialized store is %lu bytes", cb);
        HCERTSTORE r = open_blob(CERT_STORE_PROV_SERIALIZED, ENC, 0, p, cb);
        CHECK(r != NULL);
        if (r) { EXPECT_EQ(sm_ncerts(r), 0); sm_close(r); }
        LocalFree(p);
    }
    sm_close(h);
}
TEST(css_roundtrip_store_all_types) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = full_store(); if (!h) return;
    DWORD cb = 0; BYTE *p = save_mem(h, 0, CERT_STORE_SAVE_AS_STORE, &cb, 0);
    CHECK(p != NULL); if (!p) return;
    HCERTSTORE r = open_blob(CERT_STORE_PROV_SERIALIZED, ENC, 0, p, cb);
    CHECK(r != NULL);
    if (r) {
        EXPECT_EQ(sm_ncerts(r), 3); EXPECT_EQ(sm_ncrls(r), 1); EXPECT_EQ(sm_nctls(r), 1);
        CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_b };
        PCCERT_CONTEXT c = U(CertFindCertificateInStore)(r, ENC, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
        CHECK(sm_same_enc(c, VEC(v_cert_b)));
        sm_freec(c);
        sm_close(r);
    }
    LocalFree(p); sm_close(h);
}
TEST(css_roundtrip_properties_preserved) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_b };
    PCCERT_CONTEXT c = U(CertFindCertificateInStore)(h, ENC, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
    static const WCHAR fn[] = L"saved name";
    CRYPT_DATA_BLOB nb = { sizeof fn, (BYTE *)fn };
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &nb));
    sm_freec(c);
    DWORD cb = 0; BYTE *p = save_mem(h, 0, CERT_STORE_SAVE_AS_STORE, &cb, 0);
    HCERTSTORE r = p ? open_blob(CERT_STORE_PROV_SERIALIZED, ENC, 0, p, cb) : NULL;
    CHECK(r != NULL);
    if (r) {
        c = U(CertFindCertificateInStore)(r, ENC, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
        WCHAR buf[32]; DWORD n = sizeof buf;
        CHECK(c && U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, buf, &n));
        EXPECT_EQ(n, sizeof fn); EXPECT_WSTR(buf, fn);
        sm_freec(c); sm_close(r);
    }
    if (p) LocalFree(p);
    sm_close(h);
}
TEST(css_roundtrip_archived_cert_not_saved) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_a };
    PCCERT_CONTEXT c = U(CertFindCertificateInStore)(h, ENC, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
    static BYTE d[1]; CRYPT_DATA_BLOB ab = { 0, d };
    if (!U(CertSetCertificateContextProperty)(c, CERT_ARCHIVED_PROP_ID, 0, &ab)) { sm_freec(c); sm_close(h); t_skip("cannot archive here"); return; }
    sm_freec(c);
    DWORD cb = 0; BYTE *p = save_mem(h, 0, CERT_STORE_SAVE_AS_STORE, &cb, 0);
    HCERTSTORE r1 = open_blob(CERT_STORE_PROV_SERIALIZED, ENC, 0, p, cb);
    HCERTSTORE r2 = open_blob(CERT_STORE_PROV_SERIALIZED, ENC, CERT_STORE_ENUM_ARCHIVED_FLAG, p, cb);
    if (r1) { EXPECT_EQ(sm_ncerts(r1), 2); sm_close(r1); }
    if (r2) { EXPECT_EQ(sm_ncerts(r2), 2); sm_close(r2); }   /* Win10 probed: archived certs are not serialized by CertSaveStore */
    if (p) LocalFree(p);
    sm_close(h);
}
TEST(css_save_store_to_filename_w_and_reopen) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = full_store(); if (!h) return;
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "save1.sst"); wpath(path, w, MAX_PATH);
    CHECK(U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, w, 0));
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
    CHECK(r != NULL);
    if (r) { EXPECT_EQ(sm_ncerts(r), 3); EXPECT_EQ(sm_ncrls(r), 1); EXPECT_EQ(sm_nctls(r), 1); sm_close(r); }
    DeleteFileA(path); sm_close(h);
}
TEST(css_save_store_to_filename_a_and_reopen) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    char path[MAX_PATH];
    t_tmpfile(path, sizeof path, "save2.sst");
    CHECK(U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_A, path, 0));
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_A, ENC, 0, CERT_STORE_READONLY_FLAG, path);
    CHECK(r != NULL);
    if (r) { EXPECT_EQ(sm_ncerts(r), 3); sm_close(r); }
    DeleteFileA(path); sm_close(h);
}
TEST(css_save_store_to_file_handle_and_prov_file) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "save3.sst");
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    if (f == INVALID_HANDLE_VALUE) { sm_close(h); return; }
    CHECK(U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILE, f, 0));
    DWORD pos = SetFilePointer(f, 0, NULL, FILE_CURRENT);
    CHECK(pos > 1000);                                 /* the handle's file pointer advanced */
    SetFilePointer(f, 0, NULL, FILE_BEGIN);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILE, ENC, 0, CERT_STORE_READONLY_FLAG, f);
    CHECK(r != NULL);
    if (r) { EXPECT_EQ(sm_ncerts(r), 3); sm_close(r); }
    CloseHandle(f); DeleteFileA(path); sm_close(h);
}
TEST(css_save_invalid_save_as_or_to) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_DATA_BLOB b = { 0, NULL };
    SET_ERR(0);
    CHECK(!U(CertSaveStore)(h, 0, 99, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    t_note("save as 99 gle=0x%lx", GetLastError());
    SET_ERR(0);
    CHECK(!U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, 99, &b, 0));
    t_note("save to 99 gle=0x%lx", GetLastError());
    SET_ERR(0);
    CHECK(!U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, 0, &b, 0));
    sm_close(h);
}
TEST(css_save_to_missing_directory_fails) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "nodir\\x\\y.sst");
    SET_ERR(0);
    CHECK(!U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_A, path, 0));
    t_note("save into a missing directory gle=%lu (CreateFile gives 3)", GetLastError());
    sm_close(h);
}

/* ---------------- PKCS7 ---------------- */
TEST(css_save_pkcs7_roundtrip_certs) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    DWORD cb = 0; BYTE *p = save_mem(h, ENC, CERT_STORE_SAVE_AS_PKCS7, &cb, 0);
    CHECK(p != NULL);
    if (p) {
        CHECK(cb > 1200 && p[0] == 0x30);
        HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS7, ENC, 0, p, cb);
        CHECK(r != NULL);
        if (r) { EXPECT_EQ(sm_ncerts(r), 3); EXPECT_EQ(sm_ncrls(r), 0); sm_close(r); }
        LocalFree(p);
    }
    sm_close(h);
}
TEST(css_save_pkcs7_includes_crls) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = full_store(); if (!h) return;
    DWORD cb = 0; BYTE *p = save_mem(h, ENC, CERT_STORE_SAVE_AS_PKCS7, &cb, 0);
    CHECK(p != NULL);
    if (p) {
        HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS7, ENC, 0, p, cb);
        CHECK(r != NULL);
        if (r) { EXPECT_EQ(sm_ncerts(r), 3); EXPECT_EQ(sm_ncrls(r), 1); t_note("CTLs in PKCS7 round trip: %d", sm_nctls(r)); sm_close(r); }
        LocalFree(p);
    }
    sm_close(h);
}
TEST(css_save_pkcs7_without_pkcs7_encoding) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CRYPT_DATA_BLOB b = { 0, NULL };
    SET_ERR(0);
    BOOL r = U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &b, 0);
    t_note("PKCS7 save with encoding 0 -> %d gle=0x%lx", r, GetLastError());
    SET_ERR(0);
    r = U(CertSaveStore)(h, X509_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &b, 0);
    t_note("PKCS7 save with X509 encoding only -> %d gle=0x%lx", r, GetLastError());
    sm_close(h);
}
TEST(css_save_pkcs7_empty_store) {
    REQUIRE(U(CertSaveStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    CRYPT_DATA_BLOB b = { 0, NULL };
    SET_ERR(0);
    BOOL r = U(CertSaveStore)(h, ENC, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &b, 0);
    t_note("PKCS7 save of empty store -> %d size=%lu gle=0x%lx", r, b.cbData, GetLastError());
    sm_close(h);
}
TEST(css_open_pkcs7_vector) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS7, ENC, 0, VEC(v_p7_certs));
    CHECK(r != NULL);
    if (r) {
        EXPECT_EQ(sm_ncerts(r), 3); EXPECT_EQ(sm_ncrls(r), 0);
        CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_c };
        PCCERT_CONTEXT c = U(CertFindCertificateInStore)(r, ENC, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
        CHECK(sm_same_enc(c, VEC(v_cert_c)));
        sm_freec(c); sm_close(r);
    }
}
TEST(css_open_pkcs7_vector_with_crl) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS7, ENC, 0, VEC(v_p7_certs_crl));
    CHECK(r != NULL);
    if (r) { EXPECT_EQ(sm_ncerts(r), 3); EXPECT_EQ(sm_ncrls(r), 1); sm_close(r); }
}
TEST(css_open_pkcs7_without_pkcs7_encoding_flag) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS7, X509_ASN_ENCODING, 0, VEC(v_p7_certs));
    t_note("PKCS7 open with X509-only encoding -> %p gle=0x%lx", r, GetLastError());
    sm_close(r);
}
TEST(css_open_pkcs7_garbage) {
    REQUIRE(U(CertOpenStore));
    static const BYTE junk[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    SET_ERR(0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS7, ENC, 0, VEC(junk));
    CHECK(r == NULL);
    t_note("PKCS7 open garbage gle=0x%lx", GetLastError());
    SET_ERR(0);
    r = open_blob(CERT_STORE_PROV_PKCS7, ENC, 0, VEC(v_cert_a));
    CHECK(r == NULL);
    t_note("PKCS7 open of a plain certificate gle=0x%lx", GetLastError());
}
TEST(css_open_pkcs7_truncated) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS7, ENC, 0, v_p7_certs, sizeof v_p7_certs - 30);
    CHECK(r == NULL);
    t_note("PKCS7 open truncated gle=0x%lx", GetLastError());
}
TEST(css_open_msg_provider) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CryptMsgOpenToDecode)); REQUIRE(U(CryptMsgUpdate)); REQUIRE(U(CryptMsgClose));
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL);
    CHECK(m != NULL); if (!m) return;
    CHECK(U(CryptMsgUpdate)(m, VEC(v_p7_certs_crl), TRUE));
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_MSG, ENC, 0, 0, m);
    CHECK(r != NULL);
    if (r) { EXPECT_EQ(sm_ncerts(r), 3); EXPECT_EQ(sm_ncrls(r), 1); sm_close(r); }
    CHECK(U(CryptMsgClose)(m));
}
TEST(css_open_msg_provider_keeps_message_alive) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CryptMsgOpenToDecode)); REQUIRE(U(CryptMsgClose));
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL);
    if (!m) return;
    U(CryptMsgUpdate)(m, VEC(v_p7_certs), TRUE);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_MSG, ENC, 0, 0, m);
    CHECK(U(CryptMsgClose)(m));                        /* the store holds its own message reference */
    if (r) { EXPECT_EQ(sm_ncerts(r), 3); sm_close(r); }
}
TEST(css_msg_get_store_from_p7_via_cryptqueryobject_equivalent) {
    REQUIRE(U(CertOpenStore));
    /* PROV_PKCS7 over the same bytes gives the same set of hashes as PROV_MSG */
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS7, ENC, 0, VEC(v_p7_certs));
    if (!r) return;
    CRYPT_HASH_BLOB h1 = { 20, (BYTE *)v_sha1_a }, h2 = { 20, (BYTE *)v_sha1_b }, h3 = { 20, (BYTE *)v_sha1_c };
    CRYPT_HASH_BLOB *hs[3] = { &h1, &h2, &h3 };
    for (int i = 0; i < 3; i++) {
        PCCERT_CONTEXT c = U(CertFindCertificateInStore)(r, ENC, 0, CERT_FIND_SHA1_HASH, hs[i], NULL);
        CHECKF(c != NULL, "hash %d", i); sm_freec(c);
    }
    sm_close(r);
}

/* ---------------- PKCS12 ---------------- */
TEST(css_open_pkcs12_empty_password) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS12, 0, PKCS12_NO_PERSIST_KEY, VEC(v_p12));
    t_note("PKCS12 empty-password open -> %p gle=0x%lx", r, GetLastError());
    if (r) { CHECK(sm_ncerts(r) >= 1); t_note("certs in pfx store: %d", sm_ncerts(r)); sm_close(r); }
}
TEST(css_open_pkcs12_password_protected_fails) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS12, 0, PKCS12_NO_PERSIST_KEY, VEC(v_p12pw));
    CHECK(r == NULL);                                  /* no way to pass a password through CertOpenStore */
    t_note("PKCS12 password-protected gle=0x%lx", GetLastError());
    sm_close(r);
}
TEST(css_open_pkcs12_garbage) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_PKCS12, 0, PKCS12_NO_PERSIST_KEY, VEC(v_cert_a));
    CHECK(r == NULL);
    t_note("PKCS12 garbage gle=0x%lx", GetLastError());
}

/* ---------------- SERIALIZED provider ---------------- */
TEST(css_open_serialized_garbage) {
    REQUIRE(U(CertOpenStore));
    static const BYTE junk[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    SET_ERR(0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_SERIALIZED, ENC, 0, VEC(junk));
    CHECK(r == NULL);
    t_note("serialized garbage gle=0x%lx", GetLastError());
}
TEST(css_open_serialized_wrong_magic) {
    REQUIRE(U(CertOpenStore));
    static const BYTE bad[8] = { 0, 0, 0, 0, 'X', 'E', 'R', 'T' };
    SET_ERR(0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_SERIALIZED, ENC, 0, VEC(bad));
    CHECK(r == NULL);
    t_note("serialized wrong magic gle=0x%lx", GetLastError());
}
TEST(css_open_serialized_truncated) {
    REQUIRE(U(CertOpenStore));
    if (t_is_wine()) { t_skip("emulator asserts on a truncated serialized store"); return; }
    HCERTSTORE h = sm_abc(); if (!h) return;
    DWORD cb = 0; BYTE *p = save_mem(h, 0, CERT_STORE_SAVE_AS_STORE, &cb, 0);
    if (p) {
        SET_ERR(0);
        HCERTSTORE r = open_blob(CERT_STORE_PROV_SERIALIZED, ENC, 0, p, cb - 100);
        t_note("serialized truncated by 100 -> %p gle=0x%lx", r, GetLastError());
        if (r) t_note("certs: %d", sm_ncerts(r));
        sm_close(r); LocalFree(p);
    }
    sm_close(h);
}
TEST(css_open_serialized_is_snapshot) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    DWORD cb = 0; BYTE *p = save_mem(h, 0, CERT_STORE_SAVE_AS_STORE, &cb, 0);
    HCERTSTORE r = open_blob(CERT_STORE_PROV_SERIALIZED, ENC, 0, p, cb);
    if (r) {
        memset(p, 0, cb);                              /* the store copied the data */
        EXPECT_EQ(sm_ncerts(r), 3);
        CHECK(sm_addc(r, VEC(v_cert_ca), DISP_NEW, NULL));
        EXPECT_EQ(sm_ncerts(r), 4);
        sm_close(r);
    }
    if (p) LocalFree(p);
    sm_close(h);
}

/* ---------------- file providers ---------------- */
TEST(css_file_open_missing_with_open_existing) {
    REQUIRE(U(CertOpenStore));
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "missing.sst"); wpath(path, w, MAX_PATH);
    SET_ERR(0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_OPEN_EXISTING_FLAG, w);
    CHECK(r == NULL);
    t_note("FILENAME_W OPEN_EXISTING missing gle=%lu", GetLastError());
    CHECK(GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES);   /* nothing was created */
    sm_close(r);
}
TEST(css_file_open_missing_without_flags) {
    REQUIRE(U(CertOpenStore));
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "missing2.sst"); wpath(path, w, MAX_PATH);
    SET_ERR(0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, 0, w);
    t_note("FILENAME_W no flags missing -> %p gle=%lu", r, GetLastError());
    sm_close(r);
    DeleteFileA(path);
}
TEST(css_file_create_new_then_commit) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "new.sst"); wpath(path, w, MAX_PATH);
    DeleteFileA(path);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_CREATE_NEW_FLAG | CERT_FILE_STORE_COMMIT_ENABLE_FLAG, w);
    t_note("FILENAME_W CREATE_NEW -> %p gle=%lu exists=%d", r, GetLastError(), GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES);
    if (r) {
        CHECK(sm_addc(r, VEC(v_cert_a), DISP_NEW, NULL));
        CHECK(sm_addc(r, VEC(v_cert_b), DISP_NEW, NULL));
        CHECK(U(CertControlStore)(r, 0, CERT_STORE_CTRL_COMMIT, NULL));
        sm_close(r);
        HCERTSTORE q = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
        CHECK(q != NULL);
        if (q) { EXPECT_EQ(sm_ncerts(q), 2); sm_close(q); }
    }
    DeleteFileA(path);
}
TEST(css_file_create_new_on_existing_file_fails) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "exists.sst"); wpath(path, w, MAX_PATH);
    U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, w, 0);
    SET_ERR(0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_CREATE_NEW_FLAG, w);
    t_note("FILENAME_W CREATE_NEW on existing file -> %p gle=%lu", r, GetLastError());
    sm_close(r); sm_close(h); DeleteFileA(path);
}
TEST(css_file_commit_enable_flag_adds_persist) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "commit.sst"); wpath(path, w, MAX_PATH);
    U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, w, 0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_FILE_STORE_COMMIT_ENABLE_FLAG, w);
    CHECK(r != NULL);
    if (r) {
        EXPECT_EQ(sm_ncerts(r), 1);
        CHECK(sm_addc(r, VEC(v_cert_b), DISP_NEW, NULL));
        CHECK(U(CertControlStore)(r, 0, CERT_STORE_CTRL_COMMIT, NULL));
        sm_close(r);
        HCERTSTORE q = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
        if (q) { EXPECT_EQ(sm_ncerts(q), 2); sm_close(q); }
    }
    sm_close(h); DeleteFileA(path);
}
TEST(css_file_without_commit_flag_does_not_persist) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "nocommit.sst"); wpath(path, w, MAX_PATH);
    U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, w, 0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, 0, w);
    CHECK(r != NULL);
    if (r) {
        sm_addc(r, VEC(v_cert_b), DISP_NEW, NULL);
        SET_ERR(0);
        BOOL c = U(CertControlStore)(r, 0, CERT_STORE_CTRL_COMMIT, NULL);
        t_note("COMMIT without COMMIT_ENABLE_FLAG -> %d gle=0x%lx", c, GetLastError());
        sm_close(r);
        HCERTSTORE q = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
        if (q) { EXPECT_EQ(sm_ncerts(q), 1); sm_close(q); }
    }
    sm_close(h); DeleteFileA(path);
}
TEST(css_file_readonly_store_loads_and_blocks_writes) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "ro.sst"); wpath(path, w, MAX_PATH);
    U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, w, 0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
    CHECK(r != NULL);
    if (r) {
        EXPECT_EQ(sm_ncerts(r), 3);
        SET_ERR(0);
        BOOL a = sm_addc(r, VEC(v_cert_ca), DISP_NEW, NULL);
        t_note("add to READONLY file store -> %d gle=0x%lx", a, GetLastError());
        sm_close(r);
    }
    sm_close(h); DeleteFileA(path);
}
TEST(css_file_open_pkcs7_file) {
    REQUIRE(U(CertOpenStore));
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "p7.p7b"); wpath(path, w, MAX_PATH);
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD wr = 0; WriteFile(f, v_p7_certs, sizeof v_p7_certs, &wr, NULL); CloseHandle(f);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
    CHECK(r != NULL);
    if (r) { EXPECT_EQ(sm_ncerts(r), 3); sm_close(r); }
    DeleteFileA(path);
}
TEST(css_file_open_single_certificate_file) {
    REQUIRE(U(CertOpenStore));
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "one.cer"); wpath(path, w, MAX_PATH);
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD wr = 0; WriteFile(f, v_cert_a, sizeof v_cert_a, &wr, NULL); CloseHandle(f);
    SET_ERR(0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
    t_note("FILENAME_W of a bare DER certificate -> %p gle=0x%lx", r, GetLastError());
    if (r) t_note("certs: %d", sm_ncerts(r));
    sm_close(r);
    DeleteFileA(path);
}
TEST(css_file_open_garbage_file) {
    REQUIRE(U(CertOpenStore));
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "junk.bin"); wpath(path, w, MAX_PATH);
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD wr = 0; WriteFile(f, "this is not a certificate store", 31, &wr, NULL); CloseHandle(f);
    SET_ERR(0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
    CHECK(r == NULL);
    t_note("FILENAME_W garbage file gle=0x%lx", GetLastError());
    sm_close(r); DeleteFileA(path);
}
TEST(css_file_open_empty_file) {
    REQUIRE(U(CertOpenStore));
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "empty.bin"); wpath(path, w, MAX_PATH);
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); CloseHandle(f);
    SET_ERR(0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
    t_note("FILENAME_W zero-length file -> %p gle=0x%lx", r, GetLastError());
    if (r) EXPECT_EQ(sm_ncerts(r), 0);
    sm_close(r); DeleteFileA(path);
}
TEST(css_file_empty_name_and_bad_handle) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, 0, L"");
    t_note("FILENAME_W empty name -> %p gle=0x%lx", r, GetLastError());
    sm_close(r);
    SET_ERR(0);
    r = U(CertOpenStore)(CERT_STORE_PROV_FILE, ENC, 0, 0, INVALID_HANDLE_VALUE);
    t_note("PROV_FILE INVALID_HANDLE_VALUE -> %p gle=0x%lx", r, GetLastError()); sm_close(r);
}
TEST(css_file_a_and_w_equivalent) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "aw.sst"); wpath(path, w, MAX_PATH);
    U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, w, 0);
    HCERTSTORE a = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_A, ENC, 0, CERT_STORE_READONLY_FLAG, path);
    HCERTSTORE b = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
    CHECK(a && b);
    if (a && b) EXPECT_EQ(sm_ncerts(a), sm_ncerts(b));
    sm_close(a); sm_close(b); sm_close(h); DeleteFileA(path);
}
/* ---------------- serialized elements ---------------- */
TEST(css_serialize_cert_size_protocol) {
    REQUIRE(U(CertSerializeCertificateStoreElement));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_a));
    DWORD cb = 0;
    CHECK(U(CertSerializeCertificateStoreElement)(c, 0, NULL, &cb));
    CHECK(cb > sizeof v_cert_a);
    DWORD need = cb;
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need);
    cb = need - 1; SET_ERR(0);
    CHECK(!U(CertSerializeCertificateStoreElement)(c, 0, buf, &cb)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, need);
    cb = need;
    CHECK(U(CertSerializeCertificateStoreElement)(c, 0, buf, &cb)); EXPECT_EQ(cb, need);
    /* last element: property 0x20 (0x20), flags 1, the encoded certificate */
    DWORD off = need - (12 + sizeof v_cert_a);
    DWORD id, fl, len;
    memcpy(&id, buf + off, 4); memcpy(&fl, buf + off + 4, 4); memcpy(&len, buf + off + 8, 4);
    EXPECT_EQ(id, 0x20); EXPECT_EQ(fl, 1); EXPECT_EQ(len, sizeof v_cert_a);
    CHECK(!memcmp(buf + off + 12, v_cert_a, sizeof v_cert_a));
    t_note("serialized plain cert element = %lu bytes (cert %zu)", need, sizeof v_cert_a);
    LocalFree(buf); sm_freec(c);
}
TEST(css_serialize_cert_add_roundtrip) {
    REQUIRE(U(CertSerializeCertificateStoreElement)); REQUIRE(U(CertAddSerializedElementToStore));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_b));
    static const WCHAR fn[] = L"elem name";
    CRYPT_DATA_BLOB nb = { sizeof fn, (BYTE *)fn };
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &nb));
    DWORD cb = 0;
    U(CertSerializeCertificateStoreElement)(c, 0, NULL, &cb);
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, cb);
    CHECK(U(CertSerializeCertificateStoreElement)(c, 0, buf, &cb));
    HCERTSTORE h = sm_mem(); if (!h) return;
    DWORD type = 0; const void *ctx = NULL;
    CHECK(U(CertAddSerializedElementToStore)(h, buf, cb, DISP_NEW, 0, CERT_STORE_ALL_CONTEXT_FLAG, &type, &ctx));
    EXPECT_EQ(type, CERT_STORE_CERTIFICATE_CONTEXT);
    CHECK(sm_same_enc((PCCERT_CONTEXT)ctx, VEC(v_cert_b)));
    WCHAR out[32]; DWORD n = sizeof out;
    CHECK(ctx && U(CertGetCertificateContextProperty)((PCCERT_CONTEXT)ctx, CERT_FRIENDLY_NAME_PROP_ID, out, &n));
    EXPECT_EQ(n, sizeof fn);
    EXPECT_EQ(sm_ncerts(h), 1);
    SET_ERR(0);
    CHECK(!U(CertAddSerializedElementToStore)(h, buf, cb, DISP_NEW, 0, CERT_STORE_ALL_CONTEXT_FLAG, NULL, NULL));
    EXPECT_ERR(HR_EXISTS);
    sm_freec((PCCERT_CONTEXT)ctx); LocalFree(buf); sm_freec(c); sm_close(h);
}
TEST(css_serialized_element_context_type_filter) {
    REQUIRE(U(CertSerializeCertificateStoreElement)); REQUIRE(U(CertAddSerializedElementToStore));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_b));
    DWORD cb = 0;
    U(CertSerializeCertificateStoreElement)(c, 0, NULL, &cb);
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, cb);
    U(CertSerializeCertificateStoreElement)(c, 0, buf, &cb);
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertAddSerializedElementToStore)(h, buf, cb, DISP_NEW, 0, CERT_STORE_CRL_CONTEXT_FLAG, NULL, NULL);
    CHECK(!r);
    t_note("cert element with CRL-only context filter gle=0x%lx", GetLastError());
    EXPECT_EQ(sm_ncerts(h), 0);
    LocalFree(buf); sm_freec(c); sm_close(h);
}
TEST(css_serialize_crl_ctl_roundtrip) {
    REQUIRE(U(CertSerializeCRLStoreElement)); REQUIRE(U(CertSerializeCTLStoreElement));
    HCERTSTORE s = sm_mem(), d = sm_mem(); if (!s || !d) return;
    PCCRL_CONTEXT crl = NULL; PCCTL_CONTEXT ctl = NULL;
    sm_addcrl(s, VEC(v_crl_1a), DISP_NEW, &crl);
    U(CertAddEncodedCTLToStore)(s, ENC, VEC(v_ctl_1a), DISP_NEW, &ctl);
    DWORD cb = 0;
    CHECK(U(CertSerializeCRLStoreElement)(crl, 0, NULL, &cb)); CHECK(cb > sizeof v_crl_1a);
    BYTE *b1 = (BYTE *)LocalAlloc(LPTR, cb);
    CHECK(U(CertSerializeCRLStoreElement)(crl, 0, b1, &cb));
    DWORD t = 0; const void *x = NULL;
    CHECK(U(CertAddSerializedElementToStore)(d, b1, cb, DISP_NEW, 0, CERT_STORE_ALL_CONTEXT_FLAG, &t, &x));
    EXPECT_EQ(t, CERT_STORE_CRL_CONTEXT);
    CHECK(x && ((PCCRL_CONTEXT)x)->cbCrlEncoded == sizeof v_crl_1a);
    if (x) U(CertFreeCRLContext)((PCCRL_CONTEXT)x);
    if (ctl) {
        cb = 0;
        CHECK(U(CertSerializeCTLStoreElement)(ctl, 0, NULL, &cb));
        BYTE *b2 = (BYTE *)LocalAlloc(LPTR, cb);
        CHECK(U(CertSerializeCTLStoreElement)(ctl, 0, b2, &cb));
        x = NULL;
        CHECK(U(CertAddSerializedElementToStore)(d, b2, cb, DISP_NEW, 0, CERT_STORE_ALL_CONTEXT_FLAG, &t, &x));
        EXPECT_EQ(t, CERT_STORE_CTL_CONTEXT);
        if (x) U(CertFreeCTLContext)((PCCTL_CONTEXT)x);
        LocalFree(b2);
    }
    EXPECT_EQ(sm_ncrls(d), 1); EXPECT_EQ(sm_nctls(d), ctl ? 1 : 0);
    LocalFree(b1);
    if (crl) U(CertFreeCRLContext)(crl);
    if (ctl) U(CertFreeCTLContext)(ctl);
    sm_close(s); sm_close(d);
}
TEST(css_add_serialized_garbage) {
    REQUIRE(U(CertAddSerializedElementToStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    static const BYTE junk[12] = { 0x20, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0, 0 };
    SET_ERR(0);
    CHECK(!U(CertAddSerializedElementToStore)(h, VEC(junk), DISP_NEW, 0, CERT_STORE_ALL_CONTEXT_FLAG, NULL, NULL));
    t_note("serialized element with bogus length gle=0x%lx", GetLastError());
    SET_ERR(0);
    CHECK(!U(CertAddSerializedElementToStore)(h, junk, 3, DISP_NEW, 0, CERT_STORE_ALL_CONTEXT_FLAG, NULL, NULL));
    t_note("serialized element too short gle=0x%lx", GetLastError());
    EXPECT_EQ(sm_ncerts(h), 0);
    sm_close(h);
}
TEST(css_add_serialized_nonzero_flags) {
    REQUIRE(U(CertAddSerializedElementToStore)); REQUIRE(U(CertSerializeCertificateStoreElement));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_b));
    DWORD cb = 0; U(CertSerializeCertificateStoreElement)(c, 0, NULL, &cb);
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, cb); U(CertSerializeCertificateStoreElement)(c, 0, buf, &cb);
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertAddSerializedElementToStore)(h, buf, cb, DISP_NEW, 0x1234, CERT_STORE_ALL_CONTEXT_FLAG, NULL, NULL);
    t_note("dwFlags=0x1234 -> %d gle=0x%lx", r, GetLastError());
    LocalFree(buf); sm_freec(c); sm_close(h);
}
TEST(css_serialize_nonzero_flags_and_null) {
    REQUIRE(U(CertSerializeCertificateStoreElement));
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, VEC(v_cert_b));
    DWORD cb = 0;
    SET_ERR(0);
    BOOL r = U(CertSerializeCertificateStoreElement)(c, 1, NULL, &cb);
    t_note("serialize dwFlags=1 -> %d gle=0x%lx", r, GetLastError());
    sm_freec(c);
}

/* ---------------- CertControlStore ---------------- */
TEST(css_control_memory_store) {
    REQUIRE(U(CertControlStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    DWORD ctl[] = { CERT_STORE_CTRL_COMMIT, CERT_STORE_CTRL_RESYNC, CERT_STORE_CTRL_AUTO_RESYNC, CERT_STORE_CTRL_NOTIFY_CHANGE, CERT_STORE_CTRL_CANCEL_NOTIFY };
    const char *nm[] = { "COMMIT", "RESYNC", "AUTO_RESYNC", "NOTIFY_CHANGE", "CANCEL_NOTIFY" };
    for (int i = 0; i < 5; i++) {
        SET_ERR(0);
        BOOL r = U(CertControlStore)(h, 0, ctl[i], NULL);
        t_note("memory CertControlStore %s -> %d gle=0x%lx", nm[i], r, GetLastError());
    }
    EXPECT_EQ(sm_ncerts(h), 3);
    sm_close(h);
}
TEST(css_control_invalid_type) {
    REQUIRE(U(CertControlStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, 99, NULL);
    CHECK(!r);
    t_note("CertControlStore(99) gle=0x%lx", GetLastError());
    sm_close(h);
}
TEST(css_control_notify_change_with_event) {
    REQUIRE(U(CertControlStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    HANDLE ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev);
    t_note("memory NOTIFY_CHANGE -> %d gle=0x%lx", r, GetLastError());
    if (r) {
        sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
        DWORD w = WaitForSingleObject(ev, 500);
        t_note("event signalled after add: %d", w == WAIT_OBJECT_0);
        U(CertControlStore)(h, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
    }
    CloseHandle(ev); sm_close(h);
}
TEST(css_control_resync_file_store) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, "resync.sst"); wpath(path, w, MAX_PATH);
    U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, w, 0);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, ENC, 0, CERT_STORE_READONLY_FLAG, w);
    if (r) {
        EXPECT_EQ(sm_ncerts(r), 1);
        sm_addc(h, VEC(v_cert_b), DISP_NEW, NULL);
        U(CertSaveStore)(h, 0, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, w, 0);
        SET_ERR(0);
        BOOL c = U(CertControlStore)(r, 0, CERT_STORE_CTRL_RESYNC, NULL);
        t_note("RESYNC on file store -> %d gle=0x%lx count=%d", c, GetLastError(), sm_ncerts(r));
        sm_close(r);
    }
    sm_close(h); DeleteFileA(path);
}

/* ---------------- store properties ---------------- */
TEST(css_store_property_localized_name_roundtrip) {
    REQUIRE(U(CertSetStoreProperty)); REQUIRE(U(CertGetStoreProperty));
    HCERTSTORE h = sm_mem(); if (!h) return;
    static const WCHAR nm[] = L"Local Name";
    CRYPT_DATA_BLOB b = { sizeof nm, (BYTE *)nm };
    SET_ERR(0);
    BOOL r = U(CertSetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, 0, &b);
    t_note("CertSetStoreProperty(LOCALIZED_NAME) -> %d gle=0x%lx", r, GetLastError());
    if (r) {
        DWORD cb = 0;
        CHECK(U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, NULL, &cb));
        EXPECT_EQ(cb, sizeof nm);
        WCHAR buf[32]; cb = sizeof buf;
        CHECK(U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, buf, &cb));
        EXPECT_WSTR(buf, nm);
        cb = sizeof nm - 2; SET_ERR(0);
        CHECK(!U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, buf, &cb)); EXPECT_ERR(ERROR_MORE_DATA);
        CHECK(U(CertSetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, 0, NULL));
        cb = 0; SET_ERR(0);
        CHECK(!U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, NULL, &cb)); EXPECT_ERR(HR_NOT_FOUND);
    }
    sm_close(h);
}
TEST(css_store_property_unset_not_found) {
    REQUIRE(U(CertGetStoreProperty));
    HCERTSTORE h = sm_mem(); if (!h) return;
    DWORD cb = 0;
    SET_ERR(0);
    CHECK(!U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, NULL, &cb)); EXPECT_ERR(HR_NOT_FOUND);
    SET_ERR(0);
    CHECK(!U(CertGetStoreProperty)(h, 0x7777, NULL, &cb));
    t_note("unknown store property gle=0x%lx", GetLastError());
    sm_close(h);
}
TEST(css_store_property_access_state) {
    REQUIRE(U(CertGetStoreProperty));
    HCERTSTORE h = sm_mem(); if (!h) return;
    DWORD st = 0xdeadbeef, cb = sizeof st;
    SET_ERR(0);
    BOOL r = U(CertGetStoreProperty)(h, CERT_ACCESS_STATE_PROP_ID, &st, &cb);
    t_note("ACCESS_STATE on memory store -> %d state=0x%lx cb=%lu gle=0x%lx", r, st, cb, GetLastError());
    if (r) EXPECT_EQ(cb, 4);
    sm_close(h);
}
TEST(css_store_property_set_with_flags) {
    REQUIRE(U(CertSetStoreProperty));
    HCERTSTORE h = sm_mem(); if (!h) return;
    static const WCHAR nm[] = L"x";
    CRYPT_DATA_BLOB b = { sizeof nm, (BYTE *)nm };
    SET_ERR(0);
    BOOL r = U(CertSetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, 0x55, &b);
    t_note("CertSetStoreProperty with dwFlags=0x55 -> %d gle=0x%lx", r, GetLastError());
    sm_close(h);
}

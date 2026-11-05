/* WVTAsn1* encode/decode exports against hand-derived DER vectors (vectors.h, produced by gen_vectors.py). */
#include "wvt.h"
#include "vectors.h"

#define ENC_FLAGS (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
typedef struct { DWORD dwLinkChoice; union { LPWSTR pwsz; struct { BYTE classId[16]; CRYPT_DATA_BLOB data; } mon; }; } WLINK;
typedef struct { LPWSTR name; WLINK *more; WLINK *pub; } WOPUS;
typedef struct { CRYPT_BIT_BLOB flags; WLINK *file; } WPEIMG;
typedef struct { LPSTR type; CRYPT_OBJID_BLOB val; CRYPT_ALGORITHM_IDENTIFIER alg; CRYPT_HASH_BLOB digest; } WINDIRECT;
typedef struct { DWORD c; LPSTR *oids; } WSTMT;
typedef struct { DWORD ver; GUID guid; DWORD r[5]; } WSIGINFO;
typedef struct { LPWSTR tag; DWORD flags; CRYPT_DATA_BLOB val; } WCATNV;
typedef struct { LPWSTR guid; DWORD ver; } WCATMEM;

static BOOL (WINAPI *enc_fn(const char *n))(DWORD, LPCSTR, const void *, BYTE *, DWORD *) { return (void *)t_proc_in("wintrust.dll", n); }
static BOOL (WINAPI *dec_fn(const char *n))(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *) { return (void *)t_proc_in("wintrust.dll", n); }

/* full encode-buffer protocol + known answer */
static void enc_kat(const char *fn, const void *st, const BYTE *want, DWORD nwant, const char *what) {
    BOOL (WINAPI *f)(DWORD, LPCSTR, const void *, BYTE *, DWORD *) = enc_fn(fn);
    if (!f) { CHECKF(0, "missing %s", fn); return; }
    DWORD cb = 0; BYTE buf[512]; memset(buf, 0xCD, sizeof buf);
    SET_ERR(0xdeadbeef);
    BOOL r = f(ENC_FLAGS, "x", st, NULL, &cb);
    CHECKF(r && cb == nwant, "%s size query: ret=%d cb=%lu want %lu", what, r, (unsigned long)cb, (unsigned long)nwant);
    if (nwant > 0) {
        cb = nwant - 1; SET_ERR(0);
        r = f(ENC_FLAGS, "x", st, buf, &cb);
        CHECKF(!r && GetLastError() == ERROR_MORE_DATA && cb == nwant, "%s too small: ret=%d err=%lu cb=%lu", what, r, (unsigned long)GetLastError(), (unsigned long)cb);
        cb = 0; SET_ERR(0);
        r = f(ENC_FLAGS, "x", st, buf, &cb);
        CHECKF(!r && GetLastError() == ERROR_MORE_DATA && cb == nwant, "%s zero size: ret=%d err=%lu cb=%lu", what, r, (unsigned long)GetLastError(), (unsigned long)cb);
    }
    memset(buf, 0xCD, sizeof buf); cb = nwant;
    r = f(ENC_FLAGS, "x", st, buf, &cb);
    CHECKF(r && cb == nwant && !memcmp(buf, want, nwant), "%s exact: ret=%d cb=%lu", what, r, (unsigned long)cb);
    if (nwant) CHECK(buf[nwant] == 0xCD);
    memset(buf, 0xCD, sizeof buf); cb = nwant + 16;
    r = f(ENC_FLAGS, "x", st, buf, &cb);
    CHECKF(r && cb == nwant && !memcmp(buf, want, nwant), "%s oversize buffer: cb=%lu", what, (unsigned long)cb);
    char hx[600]; if (r && !(cb == nwant && !memcmp(buf, want, nwant))) t_note("%s got %s", what, wvt_hex(buf, cb, hx, sizeof hx));
}
/* decode: returns heap copy (caller frees) or NULL */
static void *dec_ok(const char *fn, const BYTE *der, DWORD n, DWORD flags, const char *what, DWORD *pcb) {
    BOOL (WINAPI *f)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *) = dec_fn(fn);
    if (!f) { CHECKF(0, "missing %s", fn); return NULL; }
    DWORD cb = 0; SET_ERR(0xdeadbeef);
    BOOL r = f(ENC_FLAGS, "x", der, n, flags, NULL, &cb);
    CHECKF(r && cb > 0, "%s size query: ret=%d cb=%lu err=0x%08lx", what, r, (unsigned long)cb, (unsigned long)GetLastError());
    if (!r || !cb) return NULL;
    DWORD need = cb; BYTE *p = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need + 64);
    cb = need - 1; SET_ERR(0);
    r = f(ENC_FLAGS, "x", der, n, flags, p, &cb);
    CHECKF(!r && GetLastError() == ERROR_MORE_DATA, "%s too small: ret=%d err=0x%08lx", what, r, (unsigned long)GetLastError());
    cb = need;
    r = f(ENC_FLAGS, "x", der, n, flags, p, &cb);
    CHECKF(r && cb <= need && cb > 0, "%s decode: ret=%d cb=%lu err=0x%08lx", what, r, (unsigned long)cb, (unsigned long)GetLastError());
    if (!r) { HeapFree(GetProcessHeap(), 0, p); return NULL; }
    if (pcb) *pcb = cb;
    return p;
}
static int is_asn1_err(DWORD e) { return (e & 0xFFFFFF00) == 0x80093100 || (e & 0xFFFFFF00) == 0x80093200 || e == 0x80093133 || e == 0x80093134; }
/* every proper prefix of a valid encoding, and an altered tag, must be rejected with a CRYPT_E_ASN1_* error */
static void dec_reject(const char *fn, const BYTE *der, DWORD n, const char *what) {
    BOOL (WINAPI *f)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *) = dec_fn(fn);
    if (!f) { CHECKF(0, "missing %s", fn); return; }
    BYTE buf[1024];
    for (DWORD k = 0; k < n; k++) {
        DWORD cb = sizeof buf; SET_ERR(0);
        BOOL r = f(ENC_FLAGS, "x", der, k, 0, buf, &cb);
        CHECKF(!r, "%s: prefix of %lu/%lu bytes decoded", what, (unsigned long)k, (unsigned long)n);
        if (!r) CHECKF(is_asn1_err(GetLastError()), "%s prefix %lu: err 0x%08lx", what, (unsigned long)k, (unsigned long)GetLastError());
    }
    BYTE bad[256]; memcpy(bad, der, n); bad[0] = 0x04;      /* OCTET STRING where a SEQUENCE/choice tag is expected */
    DWORD cb = sizeof buf; SET_ERR(0);
    BOOL r = f(ENC_FLAGS, "x", bad, n, 0, buf, &cb);
    CHECKF(!r, "%s: wrong outer tag decoded", what);
    if (!r) CHECKF(is_asn1_err(GetLastError()), "%s wrong tag: err 0x%08lx", what, (unsigned long)GetLastError());
}
#define HEAPFREE(p) do { if (p) HeapFree(GetProcessHeap(), 0, (p)); } while (0)

/* ---- SpcLink ------------------------------------------------------------------------------ */
TEST(wvt_asn1_spclink_encode_url) {
    WLINK l = { 1 }; l.pwsz = L"http://a.b"; enc_kat("WVTAsn1SpcLinkEncode", &l, vec_link_url, sizeof vec_link_url, "url");
}
TEST(wvt_asn1_spclink_encode_file) {
    WLINK l = { 3 }; l.pwsz = L"x.exe"; enc_kat("WVTAsn1SpcLinkEncode", &l, vec_link_file, sizeof vec_link_file, "file");
}
TEST(wvt_asn1_spclink_encode_moniker) {
    static BYTE d[5] = { 1, 2, 3, 4, 5 };
    WLINK l; memset(&l, 0, sizeof l); l.dwLinkChoice = 2;
    for (int i = 0; i < 16; i++) l.mon.classId[i] = (BYTE)i;
    l.mon.data.cbData = 5; l.mon.data.pbData = d;
    enc_kat("WVTAsn1SpcLinkEncode", &l, vec_link_moniker, sizeof vec_link_moniker, "moniker");
}
TEST(wvt_asn1_spclink_decode_url) {
    WLINK *l = dec_ok("WVTAsn1SpcLinkDecode", vec_link_url, sizeof vec_link_url, 0, "url", NULL);
    if (l) { EXPECT_EQ(l->dwLinkChoice, 1); CHECK(l->pwsz && !lstrcmpW(l->pwsz, L"http://a.b")); }
    HEAPFREE(l);
}
TEST(wvt_asn1_spclink_decode_file) {
    WLINK *l = dec_ok("WVTAsn1SpcLinkDecode", vec_link_file, sizeof vec_link_file, 0, "file", NULL);
    if (l) { EXPECT_EQ(l->dwLinkChoice, 3); CHECK(l->pwsz && !lstrcmpW(l->pwsz, L"x.exe")); }
    HEAPFREE(l);
}
TEST(wvt_asn1_spclink_decode_moniker) {
    WLINK *l = dec_ok("WVTAsn1SpcLinkDecode", vec_link_moniker, sizeof vec_link_moniker, 0, "moniker", NULL);
    if (l) {
        EXPECT_EQ(l->dwLinkChoice, 2);
        for (int i = 0; i < 16; i++) CHECK(l->mon.classId[i] == i);
        EXPECT_EQ(l->mon.data.cbData, 5);
        if (l->mon.data.cbData == 5 && l->mon.data.pbData) { static const BYTE d[5] = { 1, 2, 3, 4, 5 }; CHECK(!memcmp(l->mon.data.pbData, d, 5)); }
    }
    HEAPFREE(l);
}
TEST(wvt_asn1_spclink_decode_nocopy_flag) {
    /* CRYPT_DECODE_NOCOPY_FLAG is passed to the decoder as flags; the decoded struct is still produced */
    WLINK *l = dec_ok("WVTAsn1SpcLinkDecode", vec_link_url, sizeof vec_link_url, CRYPT_DECODE_NOCOPY_FLAG, "url nocopy", NULL);
    if (l) { EXPECT_EQ(l->dwLinkChoice, 1); CHECK(l->pwsz != NULL); }
    HEAPFREE(l);
}
TEST(wvt_asn1_spclink_roundtrip) {
    static const struct { const BYTE *d; DWORD n; } v[] = { { vec_link_url, sizeof vec_link_url }, { vec_link_file, sizeof vec_link_file }, { vec_link_moniker, sizeof vec_link_moniker } };
    for (int i = 0; i < 3; i++) {
        WLINK *l = dec_ok("WVTAsn1SpcLinkDecode", v[i].d, v[i].n, 0, "rt", NULL);
        if (l) enc_kat("WVTAsn1SpcLinkEncode", l, v[i].d, v[i].n, "roundtrip");
        HEAPFREE(l);
    }
}
TEST(wvt_asn1_spclink_encode_bad_choice) {
    BOOL (WINAPI *f)(DWORD, LPCSTR, const void *, BYTE *, DWORD *) = enc_fn("WVTAsn1SpcLinkEncode"); REQUIRE(f);
    static const DWORD bad[] = { 0, 4, 5, 255, 0x10000, 0xffffffff };
    for (int i = 0; i < 6; i++) {
        WLINK l; memset(&l, 0, sizeof l); l.dwLinkChoice = bad[i]; l.pwsz = L"x"; DWORD cb = 77; BYTE b[64];
        SET_ERR(0); CHECKF(!f(ENC_FLAGS, "x", &l, b, &cb), "choice %lu", (unsigned long)bad[i]);
        EXPECT_ERR((DWORD)0x80070057); EXPECT_EQ(cb, 0);
    }
}
TEST(wvt_asn1_spclink_decode_rejects) {
    dec_reject("WVTAsn1SpcLinkDecode", vec_link_url, sizeof vec_link_url, "url");
    dec_reject("WVTAsn1SpcLinkDecode", vec_link_file, sizeof vec_link_file, "file");
    dec_reject("WVTAsn1SpcLinkDecode", vec_link_moniker, sizeof vec_link_moniker, "moniker");
}
TEST(wvt_asn1_spclink_decode_empty_input) {
    BOOL (WINAPI *f)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *) = dec_fn("WVTAsn1SpcLinkDecode"); REQUIRE(f);
    BYTE b[64]; DWORD cb = sizeof b; BYTE z = 0;
    SET_ERR(0); CHECK(!f(ENC_FLAGS, "x", &z, 0, 0, b, &cb)); CHECK(is_asn1_err(GetLastError()));
    cb = 0; SET_ERR(0); CHECK(!f(ENC_FLAGS, "x", &z, 0, 0, NULL, &cb)); CHECK(is_asn1_err(GetLastError()));
}

/* ---- SpcSpOpusInfo ------------------------------------------------------------------------- */
TEST(wvt_asn1_opus_encode_variants) {
    WLINK more = { 1 }, pub = { 3 }; more.pwsz = L"http://m"; pub.pwsz = L"p.exe";
    WOPUS o = { NULL, NULL, NULL };
    enc_kat("WVTAsn1SpcSpOpusInfoEncode", &o, vec_opus_empty, sizeof vec_opus_empty, "empty");
    o.name = L"App"; enc_kat("WVTAsn1SpcSpOpusInfoEncode", &o, vec_opus_name, sizeof vec_opus_name, "name");
    o.more = &more; o.pub = &pub; enc_kat("WVTAsn1SpcSpOpusInfoEncode", &o, vec_opus_all, sizeof vec_opus_all, "all");
    o.name = NULL; o.pub = NULL; enc_kat("WVTAsn1SpcSpOpusInfoEncode", &o, vec_opus_links_only, sizeof vec_opus_links_only, "more-info only");
}
TEST(wvt_asn1_opus_decode_variants) {
    WOPUS *o = dec_ok("WVTAsn1SpcSpOpusInfoDecode", vec_opus_empty, sizeof vec_opus_empty, 0, "empty", NULL);
    if (o) { CHECK(o->name == NULL && o->more == NULL && o->pub == NULL); } HEAPFREE(o);
    o = dec_ok("WVTAsn1SpcSpOpusInfoDecode", vec_opus_name, sizeof vec_opus_name, 0, "name", NULL);
    if (o) { CHECK(o->name && !lstrcmpW(o->name, L"App")); CHECK(o->more == NULL && o->pub == NULL); } HEAPFREE(o);
    o = dec_ok("WVTAsn1SpcSpOpusInfoDecode", vec_opus_all, sizeof vec_opus_all, 0, "all", NULL);
    if (o) {
        CHECK(o->name && !lstrcmpW(o->name, L"App"));
        CHECK(o->more && o->more->dwLinkChoice == 1 && !lstrcmpW(o->more->pwsz, L"http://m"));
        CHECK(o->pub && o->pub->dwLinkChoice == 3 && !lstrcmpW(o->pub->pwsz, L"p.exe"));
    }
    HEAPFREE(o);
    o = dec_ok("WVTAsn1SpcSpOpusInfoDecode", vec_opus_links_only, sizeof vec_opus_links_only, 0, "more only", NULL);
    if (o) { CHECK(o->name == NULL); CHECK(o->more && o->more->dwLinkChoice == 1); CHECK(o->pub == NULL); } HEAPFREE(o);
}
TEST(wvt_asn1_opus_roundtrip) {
    static const struct { const BYTE *d; DWORD n; } v[] = { { vec_opus_empty, 2 }, { vec_opus_name, sizeof vec_opus_name }, { vec_opus_all, sizeof vec_opus_all }, { vec_opus_links_only, sizeof vec_opus_links_only } };
    for (int i = 0; i < 4; i++) {
        WOPUS *o = dec_ok("WVTAsn1SpcSpOpusInfoDecode", v[i].d, v[i].n, 0, "rt", NULL);
        if (o) enc_kat("WVTAsn1SpcSpOpusInfoEncode", o, v[i].d, v[i].n, "roundtrip");
        HEAPFREE(o);
    }
}
TEST(wvt_asn1_opus_decode_rejects) {
    dec_reject("WVTAsn1SpcSpOpusInfoDecode", vec_opus_all, sizeof vec_opus_all, "all");
    dec_reject("WVTAsn1SpcSpOpusInfoDecode", vec_opus_name, sizeof vec_opus_name, "name");
}
TEST(wvt_asn1_opus_buffer_exactly_struct_size) {
    /* the struct plus its out-of-line data are packed into one caller buffer */
    DWORD cb = 0; WOPUS *o = dec_ok("WVTAsn1SpcSpOpusInfoDecode", vec_opus_all, sizeof vec_opus_all, 0, "all", &cb);
    if (o) {
        CHECK(cb >= sizeof(WOPUS) + sizeof(WLINK) * 2);
        BYTE *lo = (BYTE *)o, *hi = lo + cb;
        CHECK((BYTE *)o->name >= lo && (BYTE *)o->name < hi);
        CHECK((BYTE *)o->more >= lo && (BYTE *)o->more < hi);
        CHECK((BYTE *)o->pub >= lo && (BYTE *)o->pub < hi);
    }
    HEAPFREE(o);
}

/* ---- SpcPeImageData ------------------------------------------------------------------------- */
TEST(wvt_asn1_peimage_encode) {
    WLINK f = { 3 }; f.pwsz = L"<<<Obsolete>>>"; WPEIMG p; memset(&p, 0, sizeof p); p.file = &f;
    enc_kat("WVTAsn1SpcPeImageDataEncode", &p, vec_peimg_file_only, sizeof vec_peimg_file_only, "file only");
    static BYTE fl[1] = { 0x80 }; p.flags.cbData = 1; p.flags.pbData = fl; p.flags.cUnusedBits = 7;
    /* Win10 does not encode the flags member */
    enc_kat("WVTAsn1SpcPeImageDataEncode", &p, vec_peimg_file_only, sizeof vec_peimg_file_only, "flags+file");
    memset(&p, 0, sizeof p);
    enc_kat("WVTAsn1SpcPeImageDataEncode", &p, vec_peimg_empty, sizeof vec_peimg_empty, "empty");
}
TEST(wvt_asn1_peimage_decode) {
    WPEIMG *p = dec_ok("WVTAsn1SpcPeImageDataDecode", vec_peimg_file_only, sizeof vec_peimg_file_only, 0, "file only", NULL);
    if (p) { EXPECT_EQ(p->flags.cbData, 0); CHECK(p->file && p->file->dwLinkChoice == 3 && !lstrcmpW(p->file->pwsz, L"<<<Obsolete>>>")); } HEAPFREE(p);
    p = dec_ok("WVTAsn1SpcPeImageDataDecode", vec_peimg_flags, sizeof vec_peimg_flags, 0, "flags", NULL);
    if (p) { EXPECT_EQ(p->flags.cbData, 1); EXPECT_EQ(p->flags.cUnusedBits, 7); if (p->flags.cbData == 1) EXPECT_EQ(p->flags.pbData[0], 0x80); CHECK(p->file != NULL); } HEAPFREE(p);
    p = dec_ok("WVTAsn1SpcPeImageDataDecode", vec_peimg_empty, sizeof vec_peimg_empty, 0, "empty", NULL);
    if (p) { EXPECT_EQ(p->flags.cbData, 0); CHECK(p->file == NULL); } HEAPFREE(p);
}
TEST(wvt_asn1_peimage_roundtrip_and_rejects) {
    WPEIMG *p = dec_ok("WVTAsn1SpcPeImageDataDecode", vec_peimg_flags, sizeof vec_peimg_flags, 0, "flags", NULL);
    if (p) enc_kat("WVTAsn1SpcPeImageDataEncode", p, vec_peimg_file_only, sizeof vec_peimg_file_only, "roundtrip");
    HEAPFREE(p);
    dec_reject("WVTAsn1SpcPeImageDataDecode", vec_peimg_flags, sizeof vec_peimg_flags, "peimage");
}

/* ---- SpcStatementType ------------------------------------------------------------------------ */
TEST(wvt_asn1_statement_type) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    LPSTR o[2] = { "1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.2.1.22" };
    WSTMT s = { 1, o };
    enc_kat("WVTAsn1SpcStatementTypeEncode", &s, vec_stmt_one, sizeof vec_stmt_one, "one");
    s.c = 2; enc_kat("WVTAsn1SpcStatementTypeEncode", &s, vec_stmt_two, sizeof vec_stmt_two, "two");
    WSTMT *d = dec_ok("WVTAsn1SpcStatementTypeDecode", vec_stmt_two, sizeof vec_stmt_two, 0, "two", NULL);
    if (d) { EXPECT_EQ(d->c, 2); if (d->c == 2) { EXPECT_STR(d->oids[0], "1.3.6.1.5.5.7.3.3"); EXPECT_STR(d->oids[1], "1.3.6.1.4.1.311.2.1.22"); } }
    HEAPFREE(d);
    d = dec_ok("WVTAsn1SpcStatementTypeDecode", vec_stmt_one, sizeof vec_stmt_one, 0, "one", NULL);
    if (d) { EXPECT_EQ(d->c, 1); if (d->c == 1) EXPECT_STR(d->oids[0], "1.3.6.1.5.5.7.3.3"); }
    HEAPFREE(d);
    dec_reject("WVTAsn1SpcStatementTypeDecode", vec_stmt_two, sizeof vec_stmt_two, "stmt");
}
TEST(wvt_asn1_statement_type_bad_oid) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    BOOL (WINAPI *f)(DWORD, LPCSTR, const void *, BYTE *, DWORD *) = enc_fn("WVTAsn1SpcStatementTypeEncode"); REQUIRE(f);
    LPSTR o[1] = { "not.an.oid" }; WSTMT s = { 1, o }; BYTE b[64]; DWORD cb = sizeof b;
    SET_ERR(0); BOOL r = f(ENC_FLAGS, "x", &s, b, &cb);
    t_note("statement type with malformed OID string: ret=%d err=0x%08lx cb=%lu", r, (unsigned long)GetLastError(), (unsigned long)cb);
    CHECK(!r);
}

/* ---- SpcSigInfo ------------------------------------------------------------------------------- */
TEST(wvt_asn1_siginfo) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    WSIGINFO s; memset(&s, 0, sizeof s); s.ver = 0x100; memcpy(&s.guid, vec_pe_guid_mem, 16);
    enc_kat("WVTAsn1SpcSigInfoEncode", &s, vec_siginfo, sizeof vec_siginfo, "siginfo");
    WSIGINFO *d = dec_ok("WVTAsn1SpcSigInfoDecode", vec_siginfo, sizeof vec_siginfo, 0, "siginfo", NULL);
    if (d) { EXPECT_EQ(d->ver, 0x100); CHECK(IsEqualGUID(&d->guid, &WVT_PE_SIP)); for (int i = 0; i < 5; i++) EXPECT_EQ(d->r[i], 0); }
    HEAPFREE(d);
    dec_reject("WVTAsn1SpcSigInfoDecode", vec_siginfo, sizeof vec_siginfo, "siginfo");
}
TEST(wvt_asn1_siginfo_reserved_values) {
    if (t_is_wine()) { t_skip("unimplemented stub aborts under emulation"); return; }
    WSIGINFO s; memset(&s, 0, sizeof s); s.ver = 1; memcpy(&s.guid, vec_pe_guid_mem, 16);
    for (int i = 0; i < 5; i++) s.r[i] = 0x7fff0000u + i;
    BYTE buf[128]; DWORD cb = sizeof buf;
    BOOL (WINAPI *f)(DWORD, LPCSTR, const void *, BYTE *, DWORD *) = enc_fn("WVTAsn1SpcSigInfoEncode"); REQUIRE(f);
    CHECK(f(ENC_FLAGS, "x", &s, buf, &cb));
    WSIGINFO *d = dec_ok("WVTAsn1SpcSigInfoDecode", buf, cb, 0, "rt", NULL);
    if (d) { EXPECT_EQ(d->ver, 1); for (int i = 0; i < 5; i++) EXPECT_EQ(d->r[i], 0x7fff0000u + i); }
    HEAPFREE(d);
}

/* ---- catalog attribute / member info ------------------------------------------------------------ */
TEST(wvt_asn1_catnamevalue) {
    static BYTE v[3] = { 1, 2, 3 };
    WCATNV n; memset(&n, 0, sizeof n); n.tag = L"Tag"; n.flags = 0x10010001; n.val.cbData = 3; n.val.pbData = v;
    enc_kat("WVTAsn1CatNameValueEncode", &n, vec_catnv, sizeof vec_catnv, "catnv");
    n.tag = L"N"; n.flags = 1; n.val.cbData = 0; n.val.pbData = NULL;
    enc_kat("WVTAsn1CatNameValueEncode", &n, vec_catnv_empty_value, sizeof vec_catnv_empty_value, "catnv empty value");
}
TEST(wvt_asn1_catnamevalue_decode) {
    WCATNV *d = dec_ok("WVTAsn1CatNameValueDecode", vec_catnv, sizeof vec_catnv, 0, "catnv", NULL);
    if (d) { CHECK(d->tag && !lstrcmpW(d->tag, L"Tag")); EXPECT_EQ(d->flags, 0x10010001); EXPECT_EQ(d->val.cbData, 3);
             if (d->val.cbData == 3) { static const BYTE v[3] = { 1, 2, 3 }; CHECK(!memcmp(d->val.pbData, v, 3)); } }
    HEAPFREE(d);
    d = dec_ok("WVTAsn1CatNameValueDecode", vec_catnv_empty_value, sizeof vec_catnv_empty_value, 0, "empty", NULL);
    if (d) { CHECK(d->tag && !lstrcmpW(d->tag, L"N")); EXPECT_EQ(d->flags, 1); EXPECT_EQ(d->val.cbData, 0); }
    HEAPFREE(d);
    dec_reject("WVTAsn1CatNameValueDecode", vec_catnv, sizeof vec_catnv, "catnv");
}
TEST(wvt_asn1_catnamevalue_roundtrip_nocopy) {
    WCATNV *d = dec_ok("WVTAsn1CatNameValueDecode", vec_catnv, sizeof vec_catnv, CRYPT_DECODE_NOCOPY_FLAG, "nocopy", NULL);
    if (d) { CHECK(d->tag && !lstrcmpW(d->tag, L"Tag")); EXPECT_EQ(d->val.cbData, 3); enc_kat("WVTAsn1CatNameValueEncode", d, vec_catnv, sizeof vec_catnv, "rt"); }
    HEAPFREE(d);
}
TEST(wvt_asn1_catmemberinfo) {
    WCATMEM m = { L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", 0x200 };
    enc_kat("WVTAsn1CatMemberInfoEncode", &m, vec_catmember, sizeof vec_catmember, "catmember");
    WCATMEM *d = dec_ok("WVTAsn1CatMemberInfoDecode", vec_catmember, sizeof vec_catmember, 0, "catmember", NULL);
    if (d) { CHECK(d->guid && !lstrcmpW(d->guid, L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}")); EXPECT_EQ(d->ver, 0x200); }
    HEAPFREE(d);
    dec_reject("WVTAsn1CatMemberInfoDecode", vec_catmember, sizeof vec_catmember, "catmember");
}

/* ---- SpcIndirectDataContent ----------------------------------------------------------------------- */
TEST(wvt_asn1_indirect_data_encode) {
    static const BYTE nullp[2] = { 5, 0 };
    WINDIRECT c; memset(&c, 0, sizeof c);
    c.type = "1.3.6.1.4.1.311.2.1.15"; c.val.cbData = sizeof vec_peimg_file_only; c.val.pbData = (BYTE *)vec_peimg_file_only;
    c.alg.pszObjId = "2.16.840.1.101.3.4.2.1"; c.alg.Parameters.cbData = 2; c.alg.Parameters.pbData = (BYTE *)nullp;
    c.digest.cbData = sizeof vec_digest32; c.digest.pbData = (BYTE *)vec_digest32;
    enc_kat("WVTAsn1SpcIndirectDataContentEncode", &c, vec_indirect, sizeof vec_indirect, "indirect");
    c.val.cbData = 0; c.val.pbData = NULL;
    enc_kat("WVTAsn1SpcIndirectDataContentEncode", &c, vec_indirect_noval, sizeof vec_indirect_noval, "indirect no value");
}
TEST(wvt_asn1_indirect_data_decode) {
    WINDIRECT *d = dec_ok("WVTAsn1SpcIndirectDataContentDecode", vec_indirect, sizeof vec_indirect, 0, "indirect", NULL);
    if (d) {
        EXPECT_STR(d->type, "1.3.6.1.4.1.311.2.1.15");
        EXPECT_EQ(d->val.cbData, sizeof vec_peimg_file_only);
        if (d->val.cbData == sizeof vec_peimg_file_only) CHECK(!memcmp(d->val.pbData, vec_peimg_file_only, d->val.cbData));
        EXPECT_STR(d->alg.pszObjId, "2.16.840.1.101.3.4.2.1");
        EXPECT_EQ(d->digest.cbData, 32);
        if (d->digest.cbData == 32) CHECK(!memcmp(d->digest.pbData, vec_digest32, 32));
    }
    HEAPFREE(d);
    d = dec_ok("WVTAsn1SpcIndirectDataContentDecode", vec_indirect_noval, sizeof vec_indirect_noval, 0, "no value", NULL);
    if (d) { EXPECT_STR(d->type, "1.3.6.1.4.1.311.2.1.15"); EXPECT_EQ(d->val.cbData, 0); EXPECT_EQ(d->digest.cbData, 32); }
    HEAPFREE(d);
}
TEST(wvt_asn1_indirect_data_roundtrip_rejects) {
    WINDIRECT *d = dec_ok("WVTAsn1SpcIndirectDataContentDecode", vec_indirect, sizeof vec_indirect, 0, "indirect", NULL);
    if (d) enc_kat("WVTAsn1SpcIndirectDataContentEncode", d, vec_indirect, sizeof vec_indirect, "roundtrip");
    HEAPFREE(d);
    dec_reject("WVTAsn1SpcIndirectDataContentDecode", vec_indirect, sizeof vec_indirect, "indirect");
}
TEST(wvt_asn1_indirect_data_bad_objid) {
    BOOL (WINAPI *f)(DWORD, LPCSTR, const void *, BYTE *, DWORD *) = enc_fn("WVTAsn1SpcIndirectDataContentEncode"); REQUIRE(f);
    WINDIRECT c; memset(&c, 0, sizeof c); BYTE b[256]; DWORD cb = sizeof b;
    c.type = "bad oid"; c.alg.pszObjId = "2.16.840.1.101.3.4.2.1"; c.digest.cbData = 32; c.digest.pbData = (BYTE *)vec_digest32;
    SET_ERR(0); CHECK(!f(ENC_FLAGS, "x", &c, b, &cb)); EXPECT_EQ(cb, 0);
    t_note("indirect data with malformed type OID: err=0x%08lx", (unsigned long)GetLastError());
}
TEST(wvt_asn1_indirect_matches_embedded_signature) {
    /* the SpcIndirectData inside the embedded signed PE decodes to the PE image digest */
    BOOL (WINAPI *c)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *) = (void *)t_proc("CryptMsgOpenToDecode"); (void)c;
    HCRYPTMSG (WINAPI *open)(DWORD, DWORD, DWORD, HCRYPTPROV_LEGACY, PCERT_INFO, PCMSG_STREAM_INFO) = (void *)t_proc("CryptMsgOpenToDecode");
    if (!open || !U(CryptMsgUpdate) || !U(CryptMsgGetParam)) { t_skip("crypt32 message API missing"); return; }
    HCRYPTMSG m = open(ENC_FLAGS, 0, 0, 0, NULL, NULL); CHECK(m != NULL); if (!m) return;
    CHECK(U(CryptMsgUpdate)(m, fix_p7_signed, sizeof fix_p7_signed, TRUE));
    DWORD cb = 0; CHECK(U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, NULL, &cb));
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cb + 1);
    CHECK(U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, buf, &cb));
    WINDIRECT *d = dec_ok("WVTAsn1SpcIndirectDataContentDecode", buf, cb, 0, "embedded", NULL);
    if (d) {
        EXPECT_STR(d->type, "1.3.6.1.4.1.311.2.1.15");
        EXPECT_STR(d->alg.pszObjId, "2.16.840.1.101.3.4.2.1");
        EXPECT_EQ(d->digest.cbData, 32);
        if (d->digest.cbData == 32) CHECK(!memcmp(d->digest.pbData, fix_pe_sha256, 32));
        WPEIMG *pe = dec_ok("WVTAsn1SpcPeImageDataDecode", d->val.pbData, d->val.cbData, 0, "peimg", NULL);
        if (pe) { CHECK(pe->file && pe->file->dwLinkChoice == 3 && !lstrcmpW(pe->file->pwsz, L"<<<Obsolete>>>")); }
        HEAPFREE(pe);
    }
    HEAPFREE(d); HeapFree(GetProcessHeap(), 0, buf); U(CryptMsgClose)(m);
}

/* ---- intent to seal (decomp-verified fixed 8-byte struct) -------------------------------------------- */
TEST(wvt_asn1_intent_to_seal_size_protocol) {
    BOOL (WINAPI *f)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *) = dec_fn("WVTAsn1IntentToSealAttributeDecode"); REQUIRE(f);
    BYTE garbage[4] = { 0xff, 0xff, 0xff, 0xff }, out[16]; DWORD cb = 0;
    SET_ERR(0); CHECK(f(ENC_FLAGS, "x", garbage, 4, 0, NULL, &cb)); EXPECT_EQ(cb, 8);   /* size query never parses the input */
    cb = 7; SET_ERR(0); CHECK(!f(ENC_FLAGS, "x", garbage, 4, 0, out, &cb)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, 8);
    cb = 0; SET_ERR(0); CHECK(!f(ENC_FLAGS, "x", garbage, 4, 0, out, &cb)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, 8);
    cb = 8; SET_ERR(0); CHECK(!f(ENC_FLAGS, "x", garbage, 4, 0, out, &cb)); CHECK(is_asn1_err(GetLastError())); EXPECT_EQ(cb, 0);
}
TEST(wvt_asn1_intent_to_seal_roundtrip) {
    BOOL (WINAPI *e)(DWORD, LPCSTR, const void *, BYTE *, DWORD *) = enc_fn("WVTAsn1IntentToSealAttributeEncode");
    BOOL (WINAPI *d)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *) = dec_fn("WVTAsn1IntentToSealAttributeDecode");
    if (!e || !d) { t_skip("missing export"); return; }
    struct { DWORD a; BYTE b; BYTE pad[3]; } in = { 1, 1 }, out;
    BYTE enc[64]; DWORD cb = 0;
    CHECK(e(ENC_FLAGS, "x", &in, NULL, &cb)); CHECK(cb > 0 && cb < sizeof enc);
    cb = sizeof enc; CHECK(e(ENC_FLAGS, "x", &in, enc, &cb));
    DWORD ocb = sizeof out; memset(&out, 0, sizeof out);
    CHECK(d(ENC_FLAGS, "x", enc, cb, 0, &out, &ocb)); EXPECT_EQ(ocb, 8);
    EXPECT_EQ(out.a, 1); EXPECT_EQ(out.b, 1);
    in.a = 7; in.b = 0; cb = sizeof enc; CHECK(e(ENC_FLAGS, "x", &in, enc, &cb));
    ocb = sizeof out; CHECK(d(ENC_FLAGS, "x", enc, cb, 0, &out, &ocb)); EXPECT_EQ(out.a, 7); EXPECT_EQ(out.b, 0);
}
TEST(wvt_asn1_exports_signature_by_ordinal_independent) {
    /* every WVTAsn1 export is a distinct entry point */
    HMODULE m = t_module("wintrust.dll"); REQUIRE(m);
    static const char *n[] = { "WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode", "WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode",
        "WVTAsn1SpcPeImageDataEncode", "WVTAsn1SpcPeImageDataDecode", "WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode",
        "WVTAsn1CatNameValueEncode", "WVTAsn1CatNameValueDecode", "WVTAsn1CatMemberInfoEncode", "WVTAsn1CatMemberInfoDecode",
        "WVTAsn1SpcStatementTypeEncode", "WVTAsn1SpcStatementTypeDecode", "WVTAsn1SpcSigInfoEncode", "WVTAsn1SpcSigInfoDecode" };
    for (int i = 0; i < 16; i++) for (int j = i + 1; j < 16; j++) {
        FARPROC a = GetProcAddress(m, n[i]), b = GetProcAddress(m, n[j]);
        CHECKF(a && b && a != b, "%s vs %s", n[i], n[j]);
    }
}

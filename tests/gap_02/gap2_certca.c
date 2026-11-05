/* certca.dll / certcli.dll certificate-template and CA helper entry points that are reached only by
 * ordinal in certca (certcli names them).  Parameter validation and trivial accessors, no directory
 * service access. */
#include "gap2.h"
#include <string.h>

#define E_POINTER_  ((LONG)0x80004003)
#define E_INVALIDARG_ ((LONG)0x80070057)
#define E_NOTIMPL_  ((LONG)0x80004001)
typedef LONG (WINAPI *pf_isvalid)(void *h, DWORD *out);
typedef LONG (WINAPI *pf_rights)(void *h, int which, DWORD *out);
typedef void *(WINAPI *pf_getdn)(void *h);
typedef LONG (WINAPI *pf_findbyname2)(const WCHAR *name, void *scope, DWORD flags, DWORD a, DWORD b, void **out);
typedef LONG (WINAPI *pf_regq)(DWORD flags, void *ld, void **out);
typedef LONG (WINAPI *pf_unregq)(void *h, void *a, void *b, DWORD c);
typedef LONG (WINAPI *pf_iscur)(DWORD flags, const WCHAR *dn);

static void *cli(const char *n) { return (void *)t_proc_in("certcli.dll", n); }

/* Opaque handle stand-in: the accessors read DWORD fields at fixed offsets of the handle block. */
static void setf(BYTE *b, size_t off, DWORD v) { memcpy(b + off, &v, 4); }

TEST(gap2_certca_isvalid_null_args) {
    pf_isvalid f = (pf_isvalid)cli("CAIsValid"); REQUIRE(f);
    DWORD d = 0x1234;
    BYTE blk[0x100] = {0};
    EXPECT_EQ(f(NULL, &d), E_POINTER_); EXPECT_EQ(d, 0x1234);
    EXPECT_EQ(f(blk, NULL), E_POINTER_);
    EXPECT_EQ(f(NULL, NULL), E_POINTER_);
}
TEST(gap2_certca_isvalid_reads_validity_field) {
    pf_isvalid f = (pf_isvalid)cli("CAIsValid"); REQUIRE(f);
    BYTE blk[0x100] = {0}; DWORD d = 0xdead;
    EXPECT_EQ(f(blk, &d), 0); EXPECT_EQ(d, 0);
    setf(blk, 0x40, 1); EXPECT_EQ(f(blk, &d), 0); EXPECT_EQ(d, 1);
    setf(blk, 0x40, 0xCAFEF00D); EXPECT_EQ(f(blk, &d), 0); EXPECT_EQ(d, 0xCAFEF00D);
}
TEST(gap2_certca_certtype_isvalid_null_args) {
    pf_isvalid f = (pf_isvalid)cli("CAIsCertTypeValid"); REQUIRE(f);
    DWORD d = 0x77; BYTE blk[0x100] = {0};
    EXPECT_EQ(f(NULL, &d), E_POINTER_); EXPECT_EQ(d, 0x77);
    EXPECT_EQ(f(blk, NULL), E_POINTER_);
}
TEST(gap2_certca_certtype_isvalid_reads_validity_field) {
    pf_isvalid f = (pf_isvalid)cli("CAIsCertTypeValid"); REQUIRE(f);
    BYTE blk[0x100] = {0}; DWORD d = 5;
    EXPECT_EQ(f(blk, &d), 0); EXPECT_EQ(d, 0);
    setf(blk, 0xa8, 1); EXPECT_EQ(f(blk, &d), 0); EXPECT_EQ(d, 1);
    setf(blk, 0x40, 9);  /* the CA validity slot is not consulted */
    EXPECT_EQ(f(blk, &d), 0); EXPECT_EQ(d, 1);
}

static void rights_null(const char *name) {
    pf_rights f = (pf_rights)cli(name); REQUIRE(f);
    DWORD d = 0x55; BYTE blk[0x100] = {0};
    EXPECT_EQ(f(NULL, 1, &d), E_POINTER_); EXPECT_EQ(d, 0x55);
    EXPECT_EQ(f(blk, 1, NULL), E_POINTER_);
    EXPECT_EQ(f(NULL, 2, NULL), E_POINTER_);
}
TEST(gap2_certca_getaccessrights_null_args) { rights_null("CAGetAccessRights"); }
TEST(gap2_certca_getcerttypeaccessrights_null_args) { rights_null("CAGetCertTypeAccessRights"); }

static void rights_semantics(const char *name, size_t off_t1, size_t off_flag, size_t off_t2) {
    pf_rights f = (pf_rights)cli(name); REQUIRE(f);
    BYTE blk[0x100] = {0}; DWORD d;
    /* type 1: always available */
    setf(blk, off_t1, 0x11111111); d = 9; EXPECT_EQ(f(blk, 1, &d), 0); EXPECT_EQ(d, 0x11111111);
    /* type 2: needs the availability flag, otherwise E_NOTIMPL with the output zeroed */
    setf(blk, off_t2, 0x22222222); d = 9; EXPECT_EQ(f(blk, 2, &d), E_NOTIMPL_); EXPECT_EQ(d, 0);
    setf(blk, off_flag, 1); d = 9; EXPECT_EQ(f(blk, 2, &d), 0); EXPECT_EQ(d, 0x22222222);
    /* every other selector is invalid and still zeroes the output */
    int bad[] = { 0, 3, -1, 4, 0x100, (int)0x80000000 };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) { d = 9; EXPECT_EQ(f(blk, bad[i], &d), E_INVALIDARG_); EXPECT_EQ(d, 0); }
}
TEST(gap2_certca_getaccessrights_selectors) { rights_semantics("CAGetAccessRights", 0x48, 0x44, 0x4c); }
TEST(gap2_certca_getcerttypeaccessrights_selectors) { rights_semantics("CAGetCertTypeAccessRights", 0xb0, 0xac, 0xb4); }

TEST(gap2_certca_getdn_gated_by_validity) {
    pf_getdn f = (pf_getdn)cli("CAGetDN"); REQUIRE(f);
    BYTE blk[0x100] = {0};
    void *dn = (void *)(ULONG_PTR)0x1122334455667788ULL;
    memcpy(blk + 0x20, &dn, sizeof dn);
    EXPECT_EQ(f(blk), 0);                 /* not valid -> no DN */
    setf(blk, 0x40, 1);
    CHECK(f(blk) == dn);                  /* returned verbatim, not dereferenced */
}

TEST(gap2_certca_findcerttypebyname2_validation) {
    pf_findbyname2 f = (pf_findbyname2)t_proc_in("certca.dll", "CAFindCertTypeByName2"); REQUIRE_NOTNULL(f);
    void *out = (void *)(ULONG_PTR)1;
    EXPECT_EQ(f(NULL, NULL, 0, 0, 0, &out), E_POINTER_);
    EXPECT_EQ(f(L"User", NULL, 0, 0, 0, NULL), E_POINTER_);
    EXPECT_EQ(f(NULL, NULL, 0, 0, 0, NULL), E_POINTER_);
    /* bit 0x1000 is rejected before any directory access */
    EXPECT_EQ(f(L"User", NULL, 0x1000, 0, 0, &out), E_NOTIMPL_);
    EXPECT_EQ(f(L"User", NULL, 0x1000 | 0x10000, 0, 0, &out), E_NOTIMPL_);
    CHECK(out == (void *)(ULONG_PTR)1);
}

TEST(gap2_certca_registerquery_validation) {
    pf_regq f = (pf_regq)cli("CACertTypeRegisterQuery"); REQUIRE(f);
    void *h = (void *)(ULONG_PTR)1;
    /* only bits 0 and 1 are defined */
    DWORD bad[] = { 4, 8, 0x10, 0x100, 0x80000000, 0xFFFFFFFC };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) { h = (void *)(ULONG_PTR)1; EXPECT_EQ(f(bad[i], NULL, &h), E_INVALIDARG_); }
    EXPECT_EQ(f(0, NULL, NULL), E_INVALIDARG_);
    EXPECT_EQ(f(1, NULL, NULL), E_INVALIDARG_);
    EXPECT_EQ(f(3, NULL, NULL), E_INVALIDARG_);
}
TEST(gap2_certca_unregisterquery_null_handle) {
    pf_unregq f = (pf_unregq)cli("CACertTypeUnregisterQuery"); REQUIRE(f);
    EXPECT_EQ(f(NULL, NULL, NULL, 0), E_INVALIDARG_);
}

/* The forwarded names must be callable through certcli exactly like the certca originals. */
TEST(gap2_certca_certcli_forward_isvalid_matches_ordinal) {
    HMODULE ca = t_module("certca.dll"); REQUIRE(ca);
    pf_isvalid a = (pf_isvalid)cli("CAIsValid");
    pf_isvalid b = (pf_isvalid)GetProcAddress(ca, (LPCSTR)844);
    CHECK(a != NULL && a == b);
    DWORD d = 3; EXPECT_EQ(b(NULL, &d), E_POINTER_);
}

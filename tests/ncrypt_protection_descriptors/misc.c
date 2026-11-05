#include "npd.h"
/* Key protectors, claims, and the read-only part of the named-descriptor registry API */

/* ---- NCryptOpenKeyProtector ---------------------------------------------------------- */

TEST(npd_kp_open_null_args) {
    NREQ(UN(NCryptOpenKeyProtector));
    void *h = (void *)(ULONG_PTR)5;
    EXPECT_SS(UN(NCryptOpenKeyProtector)(NULL, L"LOCAL", 0), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptOpenKeyProtector)(&h, NULL, 0), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptOpenKeyProtector)(&h, L"", 0), NPD_NTE_INVALID_PARAM);
    CHECK(h == (void *)(ULONG_PTR)5);    /* not written when the arguments are rejected */
}

TEST(npd_kp_open_unknown_name) {
    NREQ(UN(NCryptOpenKeyProtector));
    void *h = (void *)(ULONG_PTR)5;
    LONG rc = UN(NCryptOpenKeyProtector)(&h, L"CRYPTTNOSUCHPROTECTOR", 0);
    EXPECT_SS(rc, 0xC0000225);           /* probed: STATUS_NOT_FOUND */
    CHECK(h == NULL);                    /* cleared before the provider lookup */
}

TEST(npd_kp_open_local) {
    NREQ(UN(NCryptOpenKeyProtector));
    void *h = NULL;
    LONG rc = UN(NCryptOpenKeyProtector)(&h, L"LOCAL", 0);
    EXPECT_SS(rc, 0);
    CHECK(h != NULL);
    if (h) EXPECT_SS(UN(NCryptCloseKeyProtector)(h), 0);
}

TEST(npd_kp_open_two_handles_distinct) {
    NREQ(UN(NCryptOpenKeyProtector));
    void *a = NULL, *b = NULL;
    EXPECT_SS(UN(NCryptOpenKeyProtector)(&a, L"LOCAL", 0), 0);
    EXPECT_SS(UN(NCryptOpenKeyProtector)(&b, L"LOCAL", 0), 0);
    CHECK(a && b && a != b);
    if (a) UN(NCryptCloseKeyProtector)(a);
    if (b) UN(NCryptCloseKeyProtector)(b);
}

TEST(npd_kp_open_names_observed) {
    NREQ(UN(NCryptOpenKeyProtector));
    static const wchar_t *const n[] = { L"LOCAL", L"local", L"SID", L"SDDL", L"CERTIFICATE", L"WEBCREDENTIALS", L"KEY", L"LOCAL=user", L"LOCAL ", L" LOCAL" };
    for (size_t i = 0; i < sizeof n / sizeof *n; i++) {
        void *h = NULL;
        LONG rc = UN(NCryptOpenKeyProtector)(&h, n[i], 0);
        t_label("%ls", n[i]);
        /* probed: the six provider names (case-insensitive) open; anything else is NOT_FOUND */
        EXPECT_SS(rc, i < 6 ? 0 : 0xC0000225);
        if (rc == 0) { CHECK(h != NULL); UN(NCryptCloseKeyProtector)(h); } else CHECK(h == NULL);
    }
}

/* ---- Close / Duplicate ----------------------------------------------------------------- */

TEST(npd_kp_close_null) {
    NREQ(UN(NCryptCloseKeyProtector));
    EXPECT_SS(UN(NCryptCloseKeyProtector)(NULL), NPD_NTE_INVALID_HANDLE);
}

TEST(npd_kp_close_rejects_descriptor_handle) {
    NREQ(UN(NCryptCloseKeyProtector));
    void *d = npd_desc(L"LOCAL=user");
    REQUIRE_NOTNULL(d);
    EXPECT_SS(UN(NCryptCloseKeyProtector)(d), NPD_NTE_INVALID_HANDLE);
    npd_desc_close(d);
}

TEST(npd_kp_duplicate_null_args) {
    NREQ(UN(NCryptDuplicateKeyProtectorHandle));
    void *dup = (void *)(ULONG_PTR)5;
    EXPECT_SS(UN(NCryptDuplicateKeyProtectorHandle)(NULL, &dup, 0), NPD_NTE_INVALID_HANDLE);
    CHECK(dup == (void *)(ULONG_PTR)5);
}

TEST(npd_kp_duplicate_null_output) {
    NREQ(UN(NCryptDuplicateKeyProtectorHandle));
    void *h = NULL;
    REQUIRE_EQ(UN(NCryptOpenKeyProtector)(&h, L"LOCAL", 0), 0);
    EXPECT_SS(UN(NCryptDuplicateKeyProtectorHandle)(h, NULL, 0), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptCloseKeyProtector)(h), 0);   /* the failed duplicate must not have added a reference */
}

TEST(npd_kp_duplicate_wrong_type) {
    NREQ(UN(NCryptDuplicateKeyProtectorHandle));
    void *d = npd_desc(L"LOCAL=user");
    REQUIRE_NOTNULL(d);
    void *dup = (void *)(ULONG_PTR)5;
    EXPECT_SS(UN(NCryptDuplicateKeyProtectorHandle)(d, &dup, 0), NPD_NTE_INVALID_HANDLE);
    CHECK(dup == (void *)(ULONG_PTR)5);
    npd_desc_close(d);
}

TEST(npd_kp_duplicate_is_refcount) {
    NREQ(UN(NCryptDuplicateKeyProtectorHandle));
    void *h = NULL;
    REQUIRE_EQ(UN(NCryptOpenKeyProtector)(&h, L"LOCAL", 0), 0);
    void *dup = NULL;
    EXPECT_SS(UN(NCryptDuplicateKeyProtectorHandle)(h, &dup, 0), 0);
    CHECK(dup == h);                                 /* duplicate adds a reference to the same object */
    EXPECT_SS(UN(NCryptCloseKeyProtector)(h), 0);    /* first close only drops a reference */
    void *dup2 = NULL;
    EXPECT_SS(UN(NCryptDuplicateKeyProtectorHandle)(dup, &dup2, 0), 0);   /* still usable after the first close */
    CHECK(dup2 == dup);
    EXPECT_SS(UN(NCryptCloseKeyProtector)(dup), 0);
    EXPECT_SS(UN(NCryptCloseKeyProtector)(dup2), 0); /* last reference frees it */
}

/* ---- NCryptProtectKey / NCryptUnprotectKey: handle validation only ------------------------ */

TEST(npd_kp_protectkey_null_handle) {
    NREQ(UN(NCryptProtectKey));
    EXPECT_SS(UN(NCryptProtectKey)(NULL, NULL, NULL, 0, NULL, NULL, NULL, 0), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptProtectKey)(NULL, NULL, NULL, 0, NULL, NULL, NULL, 0x40), NPD_NTE_INVALID_HANDLE);
}

TEST(npd_kp_unprotectkey_null_handle) {
    NREQ(UN(NCryptUnprotectKey));
    EXPECT_SS(UN(NCryptUnprotectKey)(NULL, NULL, NULL, NULL, NULL, NULL, 0), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptUnprotectKey)(NULL, NULL, NULL, NULL, NULL, NULL, 0x40), NPD_NTE_INVALID_HANDLE);
}

TEST(npd_kp_protectkey_wrong_handle_type) {
    NREQ(UN(NCryptProtectKey));
    NREQ(UN(NCryptUnprotectKey));
    void *d = npd_desc(L"LOCAL=user");
    REQUIRE_NOTNULL(d);
    EXPECT_SS(UN(NCryptProtectKey)(d, NULL, NULL, 0, NULL, NULL, NULL, 0), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptUnprotectKey)(d, NULL, NULL, NULL, NULL, NULL, 0), NPD_NTE_INVALID_HANDLE);
    npd_desc_close(d);
}

/* ---- claims ------------------------------------------------------------------------------ */

TEST(npd_claim_create_null_keys) {
    NREQ(UN(NCryptCreateClaim));
    DWORD cb = 77;
    EXPECT_SS(UN(NCryptCreateClaim)(0, 0, 1, NULL, NULL, 0, &cb, 0), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptCreateClaim)(0, 0, 0, NULL, NULL, 0, NULL, 0), NPD_NTE_INVALID_HANDLE);
    CHECK(cb == 77);
}

TEST(npd_claim_create_non_key_handles) {
    NREQ(UN(NCryptCreateClaim));
    void *d = npd_desc(L"LOCAL=user");
    REQUIRE_NOTNULL(d);
    DWORD cb = 0;
    EXPECT_SS(UN(NCryptCreateClaim)((ULONG_PTR)d, 0, 1, NULL, NULL, 0, &cb, 0), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptCreateClaim)(0, (ULONG_PTR)d, 1, NULL, NULL, 0, &cb, 0), NPD_NTE_INVALID_HANDLE);
    npd_desc_close(d);
}

TEST(npd_claim_verify_null_subject) {
    NREQ(UN(NCryptVerifyClaim));
    char out[32] = {0};
    EXPECT_SS(UN(NCryptVerifyClaim)(0, 0, 1, NULL, NULL, 0, out, 0), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptVerifyClaim)(0, 0, 1, NULL, NULL, 0, NULL, 0), NPD_NTE_INVALID_HANDLE);   /* handle checked before output */
}

TEST(npd_claim_verify_non_key_handles) {
    NREQ(UN(NCryptVerifyClaim));
    void *d = npd_desc(L"LOCAL=user");
    REQUIRE_NOTNULL(d);
    char out[32] = {0};
    EXPECT_SS(UN(NCryptVerifyClaim)((ULONG_PTR)d, 0, 1, NULL, NULL, 0, out, 0), NPD_NTE_INVALID_HANDLE);
    npd_desc_close(d);
}

typedef struct { ULONG_PTR prov, key; } ephem;
static int ephem_open(ephem *e) {
    memset(e, 0, sizeof *e);
    if (!UN(NCryptOpenStorageProvider) || !UN(NCryptCreatePersistedKey)) return 0;
    if (UN(NCryptOpenStorageProvider)(&e->prov, NULL, 0) != 0) return 0;
    if (UN(NCryptCreatePersistedKey)(e->prov, &e->key, L"RSA", NULL, 0, 0) != 0) { UN(NCryptFreeObject)(e->prov); e->prov = 0; return 0; }
    return 1;
}
static void ephem_close(ephem *e) {
    if (e->key) UN(NCryptFreeObject)(e->key);
    if (e->prov) UN(NCryptFreeObject)(e->prov);
}

TEST(npd_claim_create_software_ksp_unsupported) {
    NREQ(UN(NCryptCreateClaim));
    ephem e;
    if (!t_require(ephem_open(&e), __FILE__, __LINE__, "ephemeral key created")) return;
    DWORD cb = 0;
    EXPECT_SS(UN(NCryptCreateClaim)(e.key, 0, 1, NULL, NULL, 0, &cb, 0), NPD_NTE_NOT_SUPPORTED);
    EXPECT_SS(UN(NCryptCreateClaim)(0, e.key, 1, NULL, NULL, 0, &cb, 0), NPD_NTE_INVALID_HANDLE);  /* NULL authority key is rejected first */
    EXPECT_SS(UN(NCryptCreateClaim)(e.key, e.key, 1, NULL, NULL, 0, &cb, 0), NPD_NTE_NOT_SUPPORTED);
    ephem_close(&e);
}

TEST(npd_claim_verify_software_ksp_unsupported) {
    NREQ(UN(NCryptVerifyClaim));
    ephem e;
    if (!t_require(ephem_open(&e), __FILE__, __LINE__, "ephemeral key created")) return;
    BYTE claim[8] = {0};
    struct { ULONG v, c; void *p; } outbuf = { 0, 0, NULL };
    EXPECT_SS(UN(NCryptVerifyClaim)(e.key, 0, 1, NULL, claim, 8, &outbuf, 0), NPD_NTE_NOT_SUPPORTED);
    ephem_close(&e);
}

TEST(npd_claim_verify_null_output_with_valid_key) {
    NREQ(UN(NCryptVerifyClaim));
    ephem e;
    if (!t_require(ephem_open(&e), __FILE__, __LINE__, "ephemeral key created")) return;
    EXPECT_SS(UN(NCryptVerifyClaim)(e.key, 0, 1, NULL, NULL, 0, NULL, 0), NPD_NTE_INVALID_PARAM);
    ephem_close(&e);
}

TEST(npd_claim_verify_bad_authority_handle) {
    NREQ(UN(NCryptVerifyClaim));
    ephem e;
    if (!t_require(ephem_open(&e), __FILE__, __LINE__, "ephemeral key created")) return;
    void *d = npd_desc(L"LOCAL=user");
    if (d) {
        char out[32] = {0};
        EXPECT_SS(UN(NCryptVerifyClaim)(e.key, (ULONG_PTR)d, 1, NULL, NULL, 0, out, 0), NPD_NTE_INVALID_HANDLE);
        EXPECT_SS(UN(NCryptCreateClaim)(e.key, (ULONG_PTR)d, 1, NULL, NULL, 0, &(DWORD){0}, 0), NPD_NTE_INVALID_HANDLE);
        npd_desc_close(d);
    }
    ephem_close(&e);
}

/* ---- read-only named-descriptor registry queries ------------------------------------------------ */

TEST(npd_query_null_name) {
    NREQ(UN(NCryptQueryProtectionDescriptorName));
    SIZE_T cch = 99; wchar_t buf[8];
    EXPECT_SS(UN(NCryptQueryProtectionDescriptorName)(NULL, buf, &cch, 0), NPD_NTE_INVALID_PARAM);
    CHECK(cch == 0);    /* the size is zeroed on entry */
    cch = 99;
    EXPECT_SS(UN(NCryptQueryProtectionDescriptorName)(L"", buf, &cch, 0), NPD_NTE_INVALID_PARAM);
    CHECK(cch == 0);
}

TEST(npd_query_bad_flags) {
    NREQ(UN(NCryptQueryProtectionDescriptorName));
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x40, 0x80, 0x100, 0x80000000u };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        SIZE_T cch = 99;
        LONG rc = UN(NCryptQueryProtectionDescriptorName)(L"cryptt_npd_none", NULL, &cch, bad[i]);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx: 0x%lx", (unsigned long)bad[i], (unsigned long)SS(rc));
        CHECK(cch == 0);
    }
}

TEST(npd_query_name_checked_before_flags) {
    NREQ(UN(NCryptQueryProtectionDescriptorName));
    SIZE_T cch = 1;
    EXPECT_SS(UN(NCryptQueryProtectionDescriptorName)(NULL, NULL, &cch, 0x100), NPD_NTE_INVALID_PARAM);
}

TEST(npd_query_unregistered_name) {
    NREQ(UN(NCryptQueryProtectionDescriptorName));
    SIZE_T cch = 99; wchar_t buf[8];
    EXPECT_SS(UN(NCryptQueryProtectionDescriptorName)(L"cryptt_npd_none_registered", buf, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    CHECK(cch == 0);
    cch = 99;
    EXPECT_SS(UN(NCryptQueryProtectionDescriptorName)(L"cryptt_npd_none_registered", NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    CHECK(cch == 0);
    cch = 99;
    EXPECT_SS(UN(NCryptQueryProtectionDescriptorName)(L"cryptt_npd_none_registered", NULL, &cch, NPD_MACHINE_FLAG), NPD_HR_FILE_NOT_FOUND);
}

TEST(npd_register_validation_without_registry_effects) {
    /* argument errors are returned before the registry is touched */
    NREQ(UN(NCryptRegisterProtectionDescriptorName));
    EXPECT_SS(UN(NCryptRegisterProtectionDescriptorName)(NULL, L"LOCAL=user", 0), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptRegisterProtectionDescriptorName)(L"", L"LOCAL=user", 0), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptRegisterProtectionDescriptorName)(NULL, NULL, 0x100), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptRegisterProtectionDescriptorName)(L"cryptt_npd_x", L"LOCAL=user", 0x1), NPD_NTE_BAD_FLAGS);
    EXPECT_SS(UN(NCryptRegisterProtectionDescriptorName)(L"cryptt_npd_x", L"LOCAL=user", 0x40), NPD_NTE_BAD_FLAGS);
    EXPECT_SS(UN(NCryptRegisterProtectionDescriptorName)(L"cryptt_npd_x", NULL, 0x80000000u), NPD_NTE_BAD_FLAGS);
}

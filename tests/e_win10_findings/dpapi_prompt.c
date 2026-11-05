/* DPAPI prompt-policy rows (all with CRYPTPROTECT_UI_FORBIDDEN so no window can appear) and the blob layout facts they rely on. */
#include "ew.h"
static void blob_free(DATA_BLOB *b) { if (b->pbData) LocalFree(b->pbData); b->pbData = NULL; b->cbData = 0; }
static BOOL prot(DATA_BLOB *in, DWORD pflags, DWORD cbsize, DWORD flags, DATA_BLOB *out, int use_ps) {
    CRYPTPROTECT_PROMPTSTRUCT ps = { cbsize, pflags, NULL, L"cryptt e_win10" };
    return C32(CryptProtectData)(in, L"d", NULL, NULL, use_ps ? &ps : NULL, flags, out);
}
static BOOL unprot(DATA_BLOB *in, DWORD pflags, DWORD cbsize, DWORD flags, DATA_BLOB *out, int use_ps) {
    CRYPTPROTECT_PROMPTSTRUCT ps = { cbsize, pflags, NULL, L"cryptt e_win10" };
    return C32(CryptUnprotectData)(in, NULL, NULL, NULL, use_ps ? &ps : NULL, flags, out);
}
TEST(ew_dpapi_prompt_policy_conflicts) {
    BYTE d[4] = {1, 2, 3, 4}; DATA_BLOB in = {4, d}, o = {0};
    DWORD e;
    REQUIRE(C32(CryptProtectData));
    /* prompt requested AND UI forbidden -> ERROR_PASSWORD_RESTRICTION */
    SET_ERR(0); CHECK(!prot(&in, CRYPTPROTECT_PROMPT_ON_PROTECT, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); e = GetLastError(); EXPECT_EQ(e, ERR_PASSWORD_RESTRICTION);
    SET_ERR(0); CHECK(!prot(&in, CRYPTPROTECT_PROMPT_ON_UNPROTECT, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); e = GetLastError(); EXPECT_EQ(e, ERR_PASSWORD_RESTRICTION);
    SET_ERR(0); CHECK(!prot(&in, CRYPTPROTECT_PROMPT_ON_PROTECT | CRYPTPROTECT_PROMPT_ON_UNPROTECT, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); e = GetLastError(); EXPECT_EQ(e, ERR_PASSWORD_RESTRICTION);
    CHECK(o.pbData == NULL);
    /* controls: no prompt flag, or REQUIRE_STRONG alone, with UI forbidden is a plain success */
    CHECK(prot(&in, 0, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); blob_free(&o);
    CHECK(prot(&in, CRYPTPROTECT_PROMPT_REQUIRE_STRONG, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); blob_free(&o);
    CHECK(prot(&in, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, &o, 0)); blob_free(&o);
}
TEST(ew_dpapi_prompt_struct_validation) {
    BYTE d[4] = {1, 2, 3, 4}; DATA_BLOB in = {4, d}, o = {0}; DWORD e;
    REQUIRE(C32(CryptProtectData));
    SET_ERR(0); CHECK(!prot(&in, CRYPTPROTECT_PROMPT_STRONG, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); e = GetLastError(); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!prot(&in, 0x100, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); e = GetLastError(); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!prot(&in, CRYPTPROTECT_PROMPT_ON_UNPROTECT, 4, CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); e = GetLastError(); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);   /* size is checked before the policy conflict */
    CHECK(prot(&in, 0, 4, CRYPTPROTECT_UI_FORBIDDEN, &o, 1)); blob_free(&o);                       /* observed: cbSize is not validated when no prompt flag is set */
    CHECK(prot(&in, 0, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &o, 1));          /* control */
    blob_free(&o);
}
TEST(ew_dpapi_unprotect_side_prompt_flags_not_enforced) {
    /* On a plain blob the unprotect-side prompt struct is not checked against UI_FORBIDDEN (unlike the protect side). */
    BYTE d[4] = {1, 2, 3, 4}; DATA_BLOB in = {4, d}, blob = {0}, p = {0};
    REQUIRE(C32(CryptProtectData));
    REQUIRE_OK(prot(&in, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, &blob, 0));
    CHECK(unprot(&blob, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, &p, 0)); EXPECT_EQ(p.cbData, 4); blob_free(&p);
    CHECK(unprot(&blob, CRYPTPROTECT_PROMPT_ON_UNPROTECT, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &p, 1)); blob_free(&p);
    CHECK(unprot(&blob, CRYPTPROTECT_PROMPT_ON_PROTECT | CRYPTPROTECT_PROMPT_ON_UNPROTECT, sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_UI_FORBIDDEN, &p, 1)); blob_free(&p);
    CHECK(unprot(&blob, CRYPTPROTECT_PROMPT_ON_UNPROTECT, 0, CRYPTPROTECT_UI_FORBIDDEN, &p, 1)); blob_free(&p);
    blob_free(&blob);
}
TEST(ew_dpapi_blob_layout_and_tampered_flags) {
    /* blob: version 1, provider GUID {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}, flags dword at offset 40 (1 = prompt on unprotect, 2 = on protect).
     * A tampered flags field turns a UI_FORBIDDEN unprotect into ERROR_PASSWORD_RESTRICTION without ever showing a window. */
    static const BYTE guid[16] = {0xd0,0x8c,0x9d,0xdf,0x01,0x15,0xd1,0x11,0x8c,0x7a,0x00,0xc0,0x4f,0xc2,0x97,0xeb};
    BYTE d[4] = {1, 2, 3, 4}, d20[20] = {0}; DATA_BLOB in = {4, d}, in20 = {20, d20}, b = {0}, b20 = {0}, p = {0}; BYTE *t; DWORD fl, e;
    REQUIRE(C32(CryptProtectData));
    REQUIRE_OK(prot(&in, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, &b, 0));
    REQUIRE_OK(prot(&in20, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, &b20, 0));
    EXPECT_EQ(b.cbData, 232); EXPECT_EQ(b20.cbData, 248);                                                /* size: one extra AES block for 20 bytes */
    REQUIRE_SANE_SIZE(b.cbData);
    EXPECT_EQ(*(DWORD *)b.pbData, 1);
    CHECK(!memcmp(b.pbData + 4, guid, 16));
    EXPECT_EQ(*(DWORD *)(b.pbData + 40), 0);
    t = (BYTE *)LocalAlloc(LPTR, b.cbData); REQUIRE_NOTNULL(t);
    for (fl = 0; fl < 4; fl++) {
        DATA_BLOB tb = {b.cbData, t};
        t_label("flags %lu", fl);
        memcpy(t, b.pbData, b.cbData); *(DWORD *)(t + 40) = fl;
        SET_ERR(0); p.pbData = NULL; p.cbData = 0;
        if (fl == 0) { CHECK(unprot(&tb, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, &p, 0)); EXPECT_EQ(p.cbData, 4); }   /* control: untouched */
        else { CHECK(!unprot(&tb, 0, 0, CRYPTPROTECT_UI_FORBIDDEN, &p, 0)); e = GetLastError(); EXPECT_EQ(e, ERR_PASSWORD_RESTRICTION); }
        blob_free(&p);
    }
    LocalFree(t); blob_free(&b); blob_free(&b20);
}

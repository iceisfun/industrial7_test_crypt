#include "../ncrypt_protection_descriptors/npd.h"
/* State-changing: NCryptRegisterProtectionDescriptorName writes REG_SZ values under
 *   HKCU\Software\Microsoft\Cryptography\NProtect\NamedDescriptors   (HKLM with NCRYPT_MACHINE_KEY_FLAG, admin only)
 * Every value this area creates is named cryptt_npr_<pid>_*; leftovers from earlier runs (cryptt_npr_*) are swept at
 * the start of each test and at exit, and the key is removed again only when it was created here and is empty. */

#define KEYPATH L"Software\\Microsoft\\Cryptography\\NProtect\\NamedDescriptors"
#define NPR_PREFIX L"cryptt_npr_"

static int g_key_preexisted[2] = { -1, -1 };   /* HKCU, HKLM */
static int g_atexit_set;

static HKEY root_of(int machine) { return machine ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER; }

static void npr_name(wchar_t *out, size_t cap, const wchar_t *tag) {
    _snwprintf(out, cap, NPR_PREFIX L"%lu_%ls", GetCurrentProcessId(), tag);
}

static int is_elevated(void) {
    HANDLE tok; TOKEN_ELEVATION el; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

static void sweep_one(int machine) {
    HKEY k;
    if (RegOpenKeyExW(root_of(machine), KEYPATH, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &k) != 0) return;
    for (;;) {
        wchar_t names[64][256]; int n = 0; DWORD i = 0;
        for (;;) {
            DWORD len = 256;
            LONG rc = RegEnumValueW(k, i++, names[n], &len, NULL, NULL, NULL, NULL);
            if (rc != 0) break;
            if (!wcsncmp(names[n], NPR_PREFIX, wcslen(NPR_PREFIX)) && ++n == 64) break;
        }
        if (!n) break;
        for (int j = 0; j < n; j++) RegDeleteValueW(k, names[j]);
    }
    RegCloseKey(k);
}

static void remove_key_if_ours_and_empty(int machine) {
    if (g_key_preexisted[machine] != 0) return;
    HKEY k; DWORD nv = 1, ns = 1;
    if (RegOpenKeyExW(root_of(machine), KEYPATH, 0, KEY_QUERY_VALUE, &k) != 0) return;
    RegQueryInfoKeyW(k, NULL, NULL, NULL, &ns, NULL, NULL, &nv, NULL, NULL, NULL, NULL);
    RegCloseKey(k);
    if (nv == 0 && ns == 0) {
        RegDeleteKeyW(root_of(machine), KEYPATH);
        /* parents NProtect (and Cryptography) are left alone unless empty */
        if (RegOpenKeyExW(root_of(machine), L"Software\\Microsoft\\Cryptography\\NProtect", 0, KEY_QUERY_VALUE, &k) == 0) {
            nv = ns = 1;
            RegQueryInfoKeyW(k, NULL, NULL, NULL, &ns, NULL, NULL, &nv, NULL, NULL, NULL, NULL);
            RegCloseKey(k);
            if (nv == 0 && ns == 0) RegDeleteKeyW(root_of(machine), L"Software\\Microsoft\\Cryptography\\NProtect");
        }
    }
}

static void npr_atexit(void) {
    sweep_one(0); remove_key_if_ours_and_empty(0);
    if (is_elevated()) { sweep_one(1); remove_key_if_ours_and_empty(1); }
}

static void npr_begin(void) {
    for (int m = 0; m < 2; m++) {
        if (g_key_preexisted[m] < 0) {
            HKEY k;
            if (RegOpenKeyExW(root_of(m), KEYPATH, 0, KEY_QUERY_VALUE, &k) == 0) { g_key_preexisted[m] = 1; RegCloseKey(k); }
            else g_key_preexisted[m] = 0;
        }
    }
    if (!g_atexit_set) { atexit(npr_atexit); g_atexit_set = 1; }
    sweep_one(0);
    if (is_elevated()) sweep_one(1);
}
/* Runs "exe --child <child>" with a LUA (standard user) restricted copy of this process token: Administrators become
 * deny-only and the privileges are dropped, so the child is not elevated. Returns the child's exit code, or
 * 0xDEAD0010..13 when the token / process could not be created, 0xDEAD0001 on timeout (killed). */
static DWORD npr_run_unelevated(const char *child, DWORD ms) {
    HANDLE tok = NULL, rt = NULL; char cmd[2048]; STARTUPINFOA si; PROCESS_INFORMATION pi; DWORD code = 0xDEAD0013;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tok)) return 0xDEAD0010;
    if (!CreateRestrictedToken(tok, LUA_TOKEN | DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &rt)) { CloseHandle(tok); return 0xDEAD0011; }
    CloseHandle(tok);
    memset(&si, 0, sizeof si); si.cb = sizeof si; memset(&pi, 0, sizeof pi);
    snprintf(cmd, sizeof cmd, "\"%s\" --child %s", t_self_path(), child);
    if (!CreateProcessAsUserA(rt, NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { CloseHandle(rt); return 0xDEAD0012; }
    CloseHandle(rt);
    if (WaitForSingleObject(pi.hProcess, ms) != WAIT_OBJECT_0) { TerminateProcess(pi.hProcess, 1); WaitForSingleObject(pi.hProcess, 5000); code = 0xDEAD0001; }
    else GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return code;
}
static void npr_end(void) { sweep_one(0); if (is_elevated()) sweep_one(1); }

#define NPR_GUARD() do { if (!UN(NCryptRegisterProtectionDescriptorName) || !UN(NCryptQueryProtectionDescriptorName)) { t_skip("missing export"); return; } \
    if (t_is_wine()) { t_skip("not implemented under wine"); return; } npr_begin(); } while (0)

static LONG reg(const wchar_t *n, const wchar_t *d, DWORD f) { return UN(NCryptRegisterProtectionDescriptorName)(n, d, f); }
static LONG query(const wchar_t *n, wchar_t *b, SIZE_T *c, DWORD f) { return UN(NCryptQueryProtectionDescriptorName)(n, b, c, f); }

/* raw read of the registered value (scaffolding) */
static LONG raw_get(int machine, const wchar_t *name, DWORD *type, BYTE *buf, DWORD *cb) {
    HKEY k; LONG rc = RegOpenKeyExW(root_of(machine), KEYPATH, 0, KEY_QUERY_VALUE, &k);
    if (rc) return rc;
    rc = RegQueryValueExW(k, name, NULL, type, buf, cb);
    RegCloseKey(k);
    return rc;
}
static LONG raw_set(int machine, const wchar_t *name, DWORD type, const void *data, DWORD cb) {
    HKEY k; DWORD disp;
    LONG rc = RegCreateKeyExW(root_of(machine), KEYPATH, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, &disp);
    if (rc) return rc;
    rc = RegSetValueExW(k, name, 0, type, (const BYTE *)data, cb);
    RegCloseKey(k);
    return rc;
}

TEST(dxnpr_register_creates_reg_sz_value) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"sz");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    DWORD type = 0, cb = 0;
    EXPECT_EQ(raw_get(0, n, &type, NULL, &cb), 0);
    EXPECT_EQ(type, REG_SZ);
    EXPECT_EQ(cb, sizeof(L"LOCAL=user"));   /* terminator included */
    npr_end();
}

TEST(dxnpr_register_query_roundtrip) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"rt");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), 0);
    EXPECT_EQ(cch, 11);                     /* characters including the NUL */
    wchar_t buf[32]; memset(buf, 0x7f, sizeof buf);
    cch = 32;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_EQ(cch, 11);
    EXPECT_WSTR(buf, L"LOCAL=user");
    npr_end();
}

TEST(dxnpr_query_buffer_protocol) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"bp");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    wchar_t buf[32];
    for (SIZE_T cap = 0; cap <= 12; cap++) {
        memset(buf, 0x55, sizeof buf);
        SIZE_T cch = cap;
        LONG rc = query(n, buf, &cch, 0);
        if (cap < 11) {
            CHECKF(SS(rc) == NPD_HR_MORE_DATA, "cap %lu: 0x%lx", (unsigned long)cap, (unsigned long)SS(rc));
            CHECKF(cch == 0, "cap %lu: size %lu (want 0 on failure)", (unsigned long)cap, (unsigned long)cch);
        } else {
            CHECKF(rc == 0, "cap %lu: 0x%lx", (unsigned long)cap, (unsigned long)SS(rc));
            CHECKF(cch == 11, "cap %lu: size %lu", (unsigned long)cap, (unsigned long)cch);
            CHECKF(!lstrcmpW(buf, L"LOCAL=user"), "cap %lu: content", (unsigned long)cap);
        }
    }
    npr_end();
}

TEST(dxnpr_query_null_buffer_ignores_capacity) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"nb");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    SIZE_T caps[] = { 0, 1, 5, 11, 1000 };
    for (size_t i = 0; i < 5; i++) {
        SIZE_T cch = caps[i];
        EXPECT_SS(query(n, NULL, &cch, 0), 0);
        CHECKF(cch == 11, "cap %lu -> %lu", (unsigned long)caps[i], (unsigned long)cch);
    }
    npr_end();
}

TEST(dxnpr_query_name_case_insensitive) {
    NPR_GUARD();
    wchar_t n[128], up[128]; npr_name(n, 128, L"case");
    lstrcpyW(up, n); CharUpperW(up);
    EXPECT_SS(reg(n, L"LOCAL=machine", 0), 0);
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(up, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, L"LOCAL=machine");
    npr_end();
}

TEST(dxnpr_register_overwrites) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"ow");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(n, L"LOCAL=machine OR LOCAL=user", 0), 0);
    wchar_t buf[64]; SIZE_T cch = 64;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, L"LOCAL=machine OR LOCAL=user");
    EXPECT_EQ(cch, lstrlenW(L"LOCAL=machine OR LOCAL=user") + 1);
    EXPECT_SS(reg(n, L"LOCAL=logon", 0), 0);     /* shrinking works too */
    cch = 64;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, L"LOCAL=logon");
    npr_end();
}

TEST(dxnpr_register_null_descriptor_deletes) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"del1");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(n, NULL, 0), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    EXPECT_EQ(cch, 0);
    DWORD cb = 0;
    EXPECT_NE(raw_get(0, n, NULL, NULL, &cb), 0);
    npr_end();
}

TEST(dxnpr_register_empty_descriptor_deletes) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"del2");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(n, L"", 0), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_delete_nonexistent) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"del3");
    EXPECT_SS(reg(n, NULL, 0), NPD_HR_FILE_NOT_FOUND);
    EXPECT_SS(reg(n, L"", 0), NPD_HR_FILE_NOT_FOUND);
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(n, NULL, 0), 0);
    EXPECT_SS(reg(n, NULL, 0), NPD_HR_FILE_NOT_FOUND);   /* second delete */
    npr_end();
}

TEST(dxnpr_register_does_not_validate_descriptor) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"nv");
    EXPECT_SS(reg(n, L"this is not a descriptor", 0), 0);
    wchar_t buf[64]; SIZE_T cch = 64;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, L"this is not a descriptor");
    void *h = (void *)(ULONG_PTR)1;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h);
    /* the garbage is only judged when the name is used: the descriptor parser reports NTE_BAD_DATA */
    EXPECT_SS(rc, 0x80090005u);
    CHECK(h == NULL);
    npr_end();
}

TEST(dxnpr_named_descriptor_create_and_info) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"nd");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), 0);
    CHECK(h != NULL);
    if (h) {
        void *s = NULL;
        EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1, &s), 0);
        if (s) { EXPECT_WSTR((wchar_t *)s, L"LOCAL=user"); LocalFree(s); }
        npd_desc_close(h);
    }
    npr_end();
}

TEST(dxnpr_named_descriptor_resolved_at_create_time) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"rc");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), 0);
    EXPECT_SS(reg(n, NULL, 0), 0);           /* unregister while the handle is open */
    if (h) {
        void *s = NULL;
        EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1, &s), 0);
        if (s) { EXPECT_WSTR((wchar_t *)s, L"LOCAL=user"); LocalFree(s); }
        npd_desc_close(h);
    }
    void *h2 = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h2), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_named_descriptor_protect_roundtrip) {
    NPR_GUARD();
    REQUIRE_WORKING();
    wchar_t n[128]; npr_name(n, 128, L"pr");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), 0);
    if (h) {
        BYTE in[32]; npd_fill(in, 32, 3);
        BYTE *blob = NULL, *out = NULL; ULONG cb = 0, co = 0;
        EXPECT_SS(UN(NCryptProtectSecret)(h, NPD_SILENT_FLAG, in, 32, NULL, NULL, &blob, &cb), 0);
        EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, NPD_SILENT_FLAG, blob, cb, NULL, NULL, &out, &co), 0);
        CHECK(co == 32 && out && !memcmp(out, in, 32));
        if (out) LocalFree(out);
        if (blob) LocalFree(blob);
        npd_desc_close(h);
    }
    npr_end();
}

TEST(dxnpr_named_empty_value_not_found) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"emp");
    EXPECT_EQ(raw_set(0, n, REG_SZ, L"", sizeof(wchar_t)), 0);
    wchar_t buf[8]; SIZE_T cch = 8; buf[0] = 0x55;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_EQ(cch, 1);
    EXPECT_EQ(buf[0], 0);
    void *h = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), NPD_NTE_NOT_FOUND);
    CHECK(h == NULL);
    npr_end();
}

TEST(dxnpr_query_forces_terminator_on_unterminated_value) {
    /* a REG_SZ stored without its NUL is returned terminated */
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"unt");
    EXPECT_EQ(raw_set(0, n, REG_SZ, L"LOCAL=user", 10 * sizeof(wchar_t)), 0);
    wchar_t buf[16]; memset(buf, 0x55, sizeof buf); SIZE_T cch = 16;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_EQ(cch, 11);          /* the 10 stored characters plus the terminator that is added */
    EXPECT_EQ(buf[10], 0);
    npr_end();
}

TEST(dxnpr_query_ignores_value_type_observed) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"dw");
    DWORD v = 0x00410042;   /* "BA" */
    EXPECT_EQ(raw_set(0, n, REG_DWORD, &v, 4), 0);
    wchar_t buf[8]; SIZE_T cch = 8;
    LONG rc = query(n, buf, &cch, 0);
    /* the value type is ignored: the 4 data bytes make 2 wide characters, and the final slot is forced to NUL */
    EXPECT_SS(rc, 0);
    EXPECT_EQ(cch, 2);
    EXPECT_EQ(buf[0], 0x42);
    EXPECT_EQ(buf[1], 0);
    npr_end();
}

TEST(dxnpr_unicode_and_odd_names) {
    NPR_GUARD();
    wchar_t base[128]; npr_name(base, 128, L"odd");
    const wchar_t *suffix[] = { L" with spaces", L"\\back\\slash", L"/fwd", L"\x00e9\x4e2d\x6587", L"=eq" };
    for (size_t i = 0; i < 5; i++) {
        wchar_t n[200]; lstrcpyW(n, base); lstrcatW(n, suffix[i]);
        LONG rc = reg(n, L"LOCAL=user", 0);
        CHECKF(rc == 0, "name #%u register 0x%lx", (unsigned)i, (unsigned long)SS(rc));
        wchar_t buf[16]; SIZE_T cch = 16;
        rc = query(n, buf, &cch, 0);
        CHECKF(rc == 0 && !lstrcmpW(buf, L"LOCAL=user"), "name #%u query 0x%lx", (unsigned)i, (unsigned long)SS(rc));
    }
    npr_end();
}

TEST(dxnpr_long_descriptor_roundtrip) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"long");
    static wchar_t big[4096], buf[4096];
    big[0] = 0;
    for (int i = 0; i < 200; i++) { if (i) lstrcatW(big, L" OR "); lstrcatW(big, L"LOCAL=user"); }
    EXPECT_SS(reg(n, big, 0), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), 0);
    EXPECT_EQ(cch, lstrlenW(big) + 1);
    cch = 4096;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, big);
    npr_end();
}

TEST(dxnpr_independent_names) {
    NPR_GUARD();
    wchar_t a[128], b[128]; npr_name(a, 128, L"ia"); npr_name(b, 128, L"ib");
    EXPECT_SS(reg(a, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(b, L"LOCAL=logon", 0), 0);
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(a, buf, &cch, 0), 0); EXPECT_WSTR(buf, L"LOCAL=user");
    cch = 32;
    EXPECT_SS(query(b, buf, &cch, 0), 0); EXPECT_WSTR(buf, L"LOCAL=logon");
    EXPECT_SS(reg(a, NULL, 0), 0);
    cch = 32;
    EXPECT_SS(query(b, buf, &cch, 0), 0);           /* deleting one leaves the other */
    EXPECT_SS(query(a, buf, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_user_registration_not_visible_to_machine_query) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"scope");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, NPD_MACHINE_FLAG), NPD_HR_FILE_NOT_FOUND);
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG | NPD_MACHINE_FLAG, &h), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_register_validation_leaves_no_value) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"val");
    EXPECT_SS(reg(n, L"LOCAL=user", 0x2), NPD_NTE_BAD_FLAGS);
    EXPECT_SS(reg(n, L"LOCAL=user", NPD_NAMED_FLAG), NPD_NTE_BAD_FLAGS);
    EXPECT_SS(reg(NULL, L"LOCAL=user", 0), NPD_NTE_INVALID_PARAM);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_machine_register_elevated_roundtrip) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"mach");
    REQUIRE_ELEVATED();   /* the unelevated outcome is pinned by dxnpr_register_machine_flag_not_elevated_denied */
    EXPECT_SS(reg(n, L"LOCAL=machine", NPD_MACHINE_FLAG), 0);
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(n, buf, &cch, NPD_MACHINE_FLAG), 0);
    EXPECT_WSTR(buf, L"LOCAL=machine");
    cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);   /* not in HKCU */
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG | NPD_MACHINE_FLAG, &h), 0);
    npd_desc_close(h);
    h = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), NPD_HR_FILE_NOT_FOUND);
    EXPECT_SS(reg(n, NULL, NPD_MACHINE_FLAG), 0);
    cch = 0;
    EXPECT_SS(query(n, NULL, &cch, NPD_MACHINE_FLAG), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

#include "more_validation.inc"
#include "more_state.inc"
#include "more_extra.inc"

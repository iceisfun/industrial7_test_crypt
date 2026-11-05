/* Context and context-function lifecycle in HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration.
 * Needs elevation; everything created uses the "cryptt_" prefix plus the pid and is removed at the end of each
 * test (and again at exit / next run's sweep). Only the CRYPT_LOCAL table is modified. */
#include "cfg.h"
#include <wchar.h>

static NTSTATUS mkctx(WCHAR *name, const char *tag, ULONG flags) {
    CRYPT_CONTEXT_CONFIG c = {flags, 0};
    cfg_name(name, 96, tag, 0);
    return U(BCryptCreateContext)(CRYPT_LOCAL, name, &c);
}
static int names_eq(WCHAR (*l)[96], int n, const WCHAR *const *want, int nw) {
    if (n != nw) return 0;
    for (int i = 0; i < n; i++) if (lstrcmpiW(l[i], want[i])) return 0;
    return 1;
}
static int find(WCHAR (*l)[96], int n, const WCHAR *w) {
    for (int i = 0; i < n; i++) if (!lstrcmpiW(l[i], w)) return i;
    return -1;
}

/* ---- contexts ---------------------------------------------------------- */
TEST(dxctx_ctx_create_delete_roundtrip) {
    if (!cfg_begin()) return;
    WCHAR n[96]; NTSTATUS st = mkctx(n, "rt", 0);
    ST_OK(st);
    CHECK(cfg_has_ctx(CRYPT_LOCAL, n));
    ST_OK(U(BCryptDeleteContext)(CRYPT_LOCAL, n));
    CHECK(!cfg_has_ctx(CRYPT_LOCAL, n));
    cfg_cleanup_all();
}
TEST(dxctx_ctx_create_duplicate_collides) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "dup", 0));
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ST_EQ(U(BCryptCreateContext)(CRYPT_LOCAL, n, &c), S_NAME_COLLISION);
    /* the failed duplicate must not have damaged the original */
    CHECK(cfg_has_ctx(CRYPT_LOCAL, n));
    ST_OK(U(BCryptDeleteContext)(CRYPT_LOCAL, n));
    cfg_cleanup_all();
}
TEST(dxctx_ctx_create_duplicate_other_case) {
    if (!cfg_begin()) return;
    WCHAR n[96], up[96]; ST_OK(mkctx(n, "dupcase", 0));
    wcscpy(up, n); CharUpperW(up);
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ULONG st = (ULONG)U(BCryptCreateContext)(CRYPT_LOCAL, up, &c);
    t_note("create of case-variant name -> 0x%lx (registry keys are case-insensitive)", st);
    CHECK(st == S_NAME_COLLISION);
    if (NT_OK(st)) U(BCryptDeleteContext)(CRYPT_LOCAL, up);
    cfg_cleanup_all();
}
TEST(dxctx_ctx_delete_nonexistent_fails) {
    if (!cfg_begin()) return;
    WCHAR n[96]; cfg_name(n, 96, "nx", 0);
    ULONG st = (ULONG)U(BCryptDeleteContext)(CRYPT_LOCAL, n);
    CHECKF(!NT_OK(st), "delete of a context that does not exist returned 0x%lx", st);
    t_note("delete of nonexistent context -> 0x%lx", st);
    CHECKF(st == S_NOT_FOUND || st == S_OBJECT_NAME_NOT_FOUND || st == 0xC0000001, "status 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_ctx_delete_twice) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "del2", 0));
    ST_OK(U(BCryptDeleteContext)(CRYPT_LOCAL, n));
    ULONG st = (ULONG)U(BCryptDeleteContext)(CRYPT_LOCAL, n);
    CHECKF(!NT_OK(st), "second delete returned 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_ctx_recreate_after_delete) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "recr", 0));
    ST_OK(U(BCryptDeleteContext)(CRYPT_LOCAL, n));
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ST_OK(U(BCryptCreateContext)(CRYPT_LOCAL, n, &c));
    CHECK(cfg_has_ctx(CRYPT_LOCAL, n));
    cfg_cleanup_all();
}
TEST(dxctx_ctx_create_null_config) {
    if (!cfg_begin()) return;
    WCHAR n[96]; cfg_name(n, 96, "nullcfg", 0);
    ULONG st = (ULONG)U(BCryptCreateContext)(CRYPT_LOCAL, n, NULL);
    t_note("BCryptCreateContext with NULL config -> 0x%lx", st);
    if (NT_OK(st)) CHECK(cfg_has_ctx(CRYPT_LOCAL, n));
    cfg_cleanup_all();
}
TEST(dxctx_ctx_create_visible_in_enum_and_counted) {
    if (!cfg_begin()) return;
    static WCHAR before[512][96], after[512][96];
    NTSTATUS s1, s2;
    int nb = cfg_enum_ctx(CRYPT_LOCAL, before, 512, &s1);
    CHECKF(nb >= 0, "enum status 0x%lx", (ULONG)s1);
    WCHAR n[96]; ST_OK(mkctx(n, "enum", 0));
    int na = cfg_enum_ctx(CRYPT_LOCAL, after, 512, &s2);
    CHECK(na == nb + 1);
    CHECK(find(after, na, n) >= 0);
    CHECK(find(before, nb, n) < 0);
    /* contexts that existed before are all still there */
    for (int i = 0; i < nb && nb < 512; i++) CHECKF(find(after, na, before[i]) >= 0, "%ls disappeared", before[i]);
    cfg_cleanup_all();
    int nf = cfg_enum_ctx(CRYPT_LOCAL, after, 512, &s2);
    CHECK(nf == nb);
}
TEST(dxctx_ctx_enum_builtin_default) {
    if (!cfg_begin()) return;
    static WCHAR l[512][96]; NTSTATUS st;
    int n = cfg_enum_ctx(CRYPT_LOCAL, l, 512, &st);
    ST_OK(st);
    CHECK(n > 0);
    int d = find(l, n, L"Default");
    t_note("%d local contexts; \"Default\" %s", n, d >= 0 ? "present" : "absent");
}
TEST(dxctx_ctx_enum_allocates_via_cng) {
    if (!cfg_begin()) return;
    ULONG cb = 0; PCRYPT_CONTEXTS p = NULL;
    ST_OK(U(BCryptEnumContexts)(CRYPT_LOCAL, &cb, &p));
    CHECK(p != NULL);
    CHECK(cb >= sizeof(CRYPT_CONTEXTS));
    if (p) {
        /* the pointer array and the strings live inside the single returned block */
        CHECK((PBYTE)p->rgpszContexts >= (PBYTE)p && (PBYTE)p->rgpszContexts < (PBYTE)p + cb);
        for (ULONG i = 0; i < p->cContexts && i < 1000; i++)
            CHECK((PBYTE)p->rgpszContexts[i] >= (PBYTE)p && (PBYTE)p->rgpszContexts[i] < (PBYTE)p + cb);
        U(BCryptFreeBuffer)(p);
    }
}
TEST(dxctx_ctx_query_config_flags_roundtrip) {
    if (!cfg_begin()) return;
    static const ULONG fl[] = {0, CRYPT_EXCLUSIVE, CRYPT_OVERRIDE, CRYPT_EXCLUSIVE | CRYPT_OVERRIDE};
    for (int i = 0; i < 4; i++) {
        WCHAR n[96]; NTSTATUS st = mkctx(n, "flags", fl[i]);
        if (!NT_OK(st)) { t_note("create with flags 0x%lx -> 0x%lx", fl[i], (ULONG)st); continue; }
        ULONG cb = 0; PCRYPT_CONTEXT_CONFIG q = NULL;
        st = U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, n, &cb, &q);
        ST_OK(st);
        if (NT_OK(st) && q) {
            CHECK(cb >= sizeof *q);
            EXPECT_EQ(q->dwFlags, fl[i]);
            U(BCryptFreeBuffer)(q);
        }
    }
    cfg_cleanup_all();
}
TEST(dxctx_ctx_configure_changes_flags) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "cfg", 0));
    CRYPT_CONTEXT_CONFIG c = {CRYPT_EXCLUSIVE, 0};
    ST_OK(U(BCryptConfigureContext)(CRYPT_LOCAL, n, &c));
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG q = NULL;
    ST_OK(U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, n, &cb, &q));
    if (q) { EXPECT_EQ(q->dwFlags, CRYPT_EXCLUSIVE); U(BCryptFreeBuffer)(q); }
    c.dwFlags = 0;
    ST_OK(U(BCryptConfigureContext)(CRYPT_LOCAL, n, &c));
    q = NULL; cb = 0;
    ST_OK(U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, n, &cb, &q));
    if (q) { EXPECT_EQ(q->dwFlags, 0); U(BCryptFreeBuffer)(q); }
    cfg_cleanup_all();
}
TEST(dxctx_ctx_configure_nonexistent_fails) {
    if (!cfg_begin()) return;
    WCHAR n[96]; cfg_name(n, 96, "cfgnx", 0);
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ULONG st = (ULONG)U(BCryptConfigureContext)(CRYPT_LOCAL, n, &c);
    CHECKF(!NT_OK(st), "configure of a missing context returned 0x%lx", st);
    t_note("configure nonexistent -> 0x%lx", st);
    CHECK(!cfg_has_ctx(CRYPT_LOCAL, n));
    cfg_cleanup_all();
}
TEST(dxctx_ctx_query_config_nonexistent_fails) {
    if (!cfg_begin()) return;
    WCHAR n[96]; cfg_name(n, 96, "qnx", 0);
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG q = NULL;
    ULONG st = (ULONG)U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, n, &cb, &q);
    CHECKF(!NT_OK(st), "query of a missing context returned 0x%lx", st);
    CHECK(q == NULL);
    t_note("query nonexistent -> 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_ctx_query_config_reserved_zero) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "rsv", 0));
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG q = NULL;
    ST_OK(U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, n, &cb, &q));
    if (q) { EXPECT_EQ(q->dwReserved, 0); U(BCryptFreeBuffer)(q); }
    cfg_cleanup_all();
}
TEST(dxctx_ctx_names_with_spaces_and_unicode) {
    if (!cfg_begin()) return;
    WCHAR base[96], n[96];
    cfg_name(base, 80, "sp", 0);
    swprintf(n, 96, L"%ls x y", base);
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ULONG st = (ULONG)U(BCryptCreateContext)(CRYPT_LOCAL, n, &c);
    t_note("context name with spaces -> 0x%lx", st);
    if (NT_OK(st)) { CHECK(cfg_has_ctx(CRYPT_LOCAL, n)); ST_OK(U(BCryptDeleteContext)(CRYPT_LOCAL, n)); }
    swprintf(n, 96, L"%ls_é中", base);
    st = (ULONG)U(BCryptCreateContext)(CRYPT_LOCAL, n, &c);
    t_note("context name with non-ASCII -> 0x%lx", st);
    if (NT_OK(st)) { CHECK(cfg_has_ctx(CRYPT_LOCAL, n)); ST_OK(U(BCryptDeleteContext)(CRYPT_LOCAL, n)); }
    cfg_cleanup_all();
}
TEST(dxctx_ctx_name_with_backslash) {
    if (!cfg_begin()) return;
    WCHAR base[96], n[96];
    cfg_name(base, 80, "bs", 0);
    swprintf(n, 96, L"%ls\\sub", base);
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ULONG st = (ULONG)U(BCryptCreateContext)(CRYPT_LOCAL, n, &c);
    t_note("context name containing a backslash -> 0x%lx", st);
    if (NT_OK(st)) U(BCryptDeleteContext)(CRYPT_LOCAL, n);
    /* nothing may be left behind under the base name either */
    U(BCryptDeleteContext)(CRYPT_LOCAL, base);
    cfg_cleanup_all();
}
TEST(dxctx_ctx_many_contexts) {
    if (!cfg_begin()) return;
    WCHAR n[20][96]; int made = 0;
    for (int i = 0; i < 20; i++) if (NT_OK(mkctx(n[i], "many", 0))) made++;
    CHECK(made == 20);
    for (int i = 0; i < made; i++) CHECK(cfg_has_ctx(CRYPT_LOCAL, n[i]));
    for (int i = 0; i < 20; i++) U(BCryptDeleteContext)(CRYPT_LOCAL, n[i]);
    for (int i = 0; i < 20; i++) CHECK(!cfg_has_ctx(CRYPT_LOCAL, n[i]));
    cfg_cleanup_all();
}
TEST(dxctx_ctx_delete_context_with_functions) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "delfn", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_fn_a", CRYPT_PRIORITY_BOTTOM));
    ST_OK(U(BCryptDeleteContext)(CRYPT_LOCAL, n));
    CHECK(!cfg_has_ctx(CRYPT_LOCAL, n));
    /* a recreated context of the same name starts empty */
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ST_OK(U(BCryptCreateContext)(CRYPT_LOCAL, n, &c));
    static WCHAR l[16][96]; NTSTATUS st;
    int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 16, &st);
    CHECKF(k <= 0, "recreated context still lists %d functions", k);
    cfg_cleanup_all();
}

/* ---- context functions ------------------------------------------------- */
static void fn_name(WCHAR *o, const char *s) { int i = 0; for (; s[i]; i++) o[i] = s[i]; o[i] = 0; }

TEST(dxctx_fn_add_enum_remove_roundtrip) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "fn", 0));
    static WCHAR l[16][96]; NTSTATUS st;
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_CIPHER_INTERFACE, L"cryptt_fn_one", CRYPT_PRIORITY_BOTTOM));
    int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_CIPHER_INTERFACE, l, 16, &st);
    CHECK(k == 1);
    if (k == 1) EXPECT_WSTR(l[0], L"cryptt_fn_one");
    ST_OK(U(BCryptRemoveContextFunction)(CRYPT_LOCAL, n, BCRYPT_CIPHER_INTERFACE, L"cryptt_fn_one"));
    k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_CIPHER_INTERFACE, l, 16, &st);
    CHECKF(k <= 0, "%d functions remain", k);
    cfg_cleanup_all();
}
TEST(dxctx_fn_priority_top_bottom) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "prio", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f2", CRYPT_PRIORITY_BOTTOM));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f3", CRYPT_PRIORITY_TOP));
    static WCHAR l[16][96]; NTSTATUS st;
    int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 16, &st);
    const WCHAR *w[] = {L"cryptt_f3", L"cryptt_f1", L"cryptt_f2"};
    CHECK(names_eq(l, k, w, 3));
    cfg_cleanup_all();
}
TEST(dxctx_fn_priority_index_insert) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "idx", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f2", CRYPT_PRIORITY_BOTTOM));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f3", 1));
    static WCHAR l[16][96]; NTSTATUS st;
    int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 16, &st);
    const WCHAR *w[] = {L"cryptt_f1", L"cryptt_f3", L"cryptt_f2"};
    CHECK(names_eq(l, k, w, 3));
    cfg_cleanup_all();
}
TEST(dxctx_fn_priority_index_zero_is_top) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "idx0", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_SIGNATURE_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_SIGNATURE_INTERFACE, L"cryptt_f2", 0));
    static WCHAR l[16][96]; NTSTATUS st;
    int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_SIGNATURE_INTERFACE, l, 16, &st);
    const WCHAR *w[] = {L"cryptt_f2", L"cryptt_f1"};
    CHECK(names_eq(l, k, w, 2));
    cfg_cleanup_all();
}
TEST(dxctx_fn_priority_index_beyond_end) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "far", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f2", 500);
    t_note("add at position 500 of a 1 element list -> 0x%lx", st);
    static WCHAR l[16][96]; NTSTATUS s2;
    int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 16, &s2);
    if (NT_OK(st)) { CHECK(k == 2); if (k == 2) EXPECT_WSTR(l[1], L"cryptt_f2"); }
    else CHECK(k == 1);
    cfg_cleanup_all();
}
TEST(dxctx_fn_add_duplicate_fails) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "fdup", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM);
    CHECKF(!NT_OK(st), "duplicate add returned 0x%lx", st);
    t_note("duplicate function add -> 0x%lx", st);
    CHECKF(st == S_NAME_COLLISION, "0x%lx", st);
    static WCHAR l[16][96]; NTSTATUS s2;
    CHECK(cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 16, &s2) == 1);
    cfg_cleanup_all();
}
TEST(dxctx_fn_add_case_insensitive_duplicate) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "fcase", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_Fn", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"CRYPTT_FN", CRYPT_PRIORITY_BOTTOM);
    t_note("case-variant function add -> 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_fn_remove_nonexistent_function) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "frmnx", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)U(BCryptRemoveContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_other");
    CHECKF(!NT_OK(st), "remove of unknown function returned 0x%lx", st);
    t_note("remove unknown function -> 0x%lx", st);
    static WCHAR l[16][96]; NTSTATUS s2;
    CHECK(cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 16, &s2) == 1);
    cfg_cleanup_all();
}
TEST(dxctx_fn_remove_from_wrong_interface) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "fwrongif", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)U(BCryptRemoveContextFunction)(CRYPT_LOCAL, n, BCRYPT_CIPHER_INTERFACE, L"cryptt_f1");
    CHECKF(!NT_OK(st), "remove via another interface returned 0x%lx", st);
    static WCHAR l[16][96]; NTSTATUS s2;
    CHECK(cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 16, &s2) == 1);
    cfg_cleanup_all();
}
TEST(dxctx_fn_add_to_nonexistent_context) {
    if (!cfg_begin()) return;
    WCHAR n[96]; cfg_name(n, 96, "fnoctx", 0);
    ULONG st = (ULONG)U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM);
    CHECKF(!NT_OK(st), "add into a missing context returned 0x%lx", st);
    t_note("add function to nonexistent context -> 0x%lx", st);
    CHECK(!cfg_has_ctx(CRYPT_LOCAL, n));
    cfg_cleanup_all();
}
TEST(dxctx_fn_enum_nonexistent_context) {
    if (!cfg_begin()) return;
    WCHAR n[96]; cfg_name(n, 96, "enoctx", 0);
    static WCHAR l[4][96]; NTSTATUS st;
    int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 4, &st);
    CHECK(k < 0 || k == 0);
    t_note("enum functions of nonexistent context -> k=%d status 0x%lx", k, (ULONG)st);
    cfg_cleanup_all();
}
TEST(dxctx_fn_per_interface_isolation) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "iso", 0));
    for (int i = 0; i < 11; i++) {
        WCHAR f[32]; swprintf(f, 32, L"cryptt_if%d", i);
        ULONG st = (ULONG)U(BCryptAddContextFunction)(CRYPT_LOCAL, n, cfg_valid_ifaces[i], f, CRYPT_PRIORITY_BOTTOM);
        if (!NT_OK(st)) t_note("add to interface 0x%lx -> 0x%lx", cfg_valid_ifaces[i], st);
    }
    for (int i = 0; i < 7; i++) {   /* the seven public interface ids must all work */
        WCHAR f[32]; swprintf(f, 32, L"cryptt_if%d", i);
        static WCHAR l[16][96]; NTSTATUS s;
        int k = cfg_enum_funcs(CRYPT_LOCAL, n, cfg_valid_ifaces[i], l, 16, &s);
        CHECKF(k == 1, "interface %lu lists %d functions (status 0x%lx)", cfg_valid_ifaces[i], k, (ULONG)s);
        if (k == 1) EXPECT_WSTR(l[0], f);
    }
    cfg_cleanup_all();
}
TEST(dxctx_fn_kernel_mode_interfaces) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "kmif", 0));
    static const ULONG km[] = {0x10001, 0x10002, 0x10003, 0x10004};
    for (int i = 0; i < 4; i++) {
        ULONG st = (ULONG)U(BCryptAddContextFunction)(CRYPT_LOCAL, n, km[i], L"cryptt_kmf", CRYPT_PRIORITY_BOTTOM);
        t_note("add to interface 0x%lx -> 0x%lx", km[i], st);
        if (NT_OK(st)) {
            static WCHAR l[4][96]; NTSTATUS s;
            CHECK(cfg_enum_funcs(CRYPT_LOCAL, n, km[i], l, 4, &s) == 1);
        }
    }
    cfg_cleanup_all();
}
TEST(dxctx_fn_many_functions_order) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "many", 0));
    for (int i = 0; i < 30; i++) {
        WCHAR f[32]; swprintf(f, 32, L"cryptt_m%02d", i);
        ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, f, CRYPT_PRIORITY_BOTTOM));
    }
    static WCHAR l[64][96]; NTSTATUS s;
    int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 64, &s);
    CHECK(k == 30);
    for (int i = 0; i < k && i < 30; i++) {
        WCHAR f[32]; swprintf(f, 32, L"cryptt_m%02d", i);
        CHECKF(!lstrcmpiW(l[i], f), "slot %d is %ls", i, l[i]);
    }
    /* remove from the middle and make sure order is preserved */
    ST_OK(U(BCryptRemoveContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_m10"));
    k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 64, &s);
    CHECK(k == 29);
    CHECK(find(l, k, L"cryptt_m10") < 0);
    CHECK(k == 29 && !lstrcmpiW(l[10], L"cryptt_m11"));
    cfg_cleanup_all();
}
TEST(dxctx_fn_long_function_name) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "long", 0));
    WCHAR f[200]; for (int i = 0; i < 150; i++) f[i] = L'a' + (i % 26); f[150] = 0;
    ULONG st = (ULONG)U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, f, CRYPT_PRIORITY_BOTTOM);
    t_note("150 character function name -> 0x%lx", st);
    if (NT_OK(st)) {
        static WCHAR l[4][96]; NTSTATUS s;
        int k = cfg_enum_funcs(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, l, 4, &s);
        CHECK(k == 1);
    }
    cfg_cleanup_all();
}

/* ---- function configuration ------------------------------------------- */
TEST(dxctx_fn_config_roundtrip) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "fcfg", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    static const ULONG fl[] = {0, CRYPT_MIN_DEPENDENCIES, CRYPT_PROCESS_ISOLATE, CRYPT_MIN_DEPENDENCIES | CRYPT_PROCESS_ISOLATE};
    for (int i = 0; i < 4; i++) {
        CRYPT_CONTEXT_FUNCTION_CONFIG c = {fl[i], 0};
        ULONG st = (ULONG)U(BCryptConfigureContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", &c);
        if (!NT_OK(st)) { t_note("configure function flags 0x%lx -> 0x%lx", fl[i], st); continue; }
        ULONG cb = 0; PCRYPT_CONTEXT_FUNCTION_CONFIG q = NULL;
        ST_OK(U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", &cb, &q));
        if (q) { CHECK(cb >= sizeof *q); EXPECT_EQ(q->dwFlags, fl[i]); U(BCryptFreeBuffer)(q); }
    }
    cfg_cleanup_all();
}
TEST(dxctx_fn_config_unknown_function_fails) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "fcfgnx", 0));
    CRYPT_CONTEXT_FUNCTION_CONFIG c = {0, 0};
    ULONG st = (ULONG)U(BCryptConfigureContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_missing", &c);
    CHECKF(!NT_OK(st), "configure of a function that was never added returned 0x%lx", st);
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTION_CONFIG q = NULL;
    st = (ULONG)U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_missing", &cb, &q);
    CHECKF(!NT_OK(st), "query of a missing function returned 0x%lx", st);
    CHECK(q == NULL);
    cfg_cleanup_all();
}

/* ---- function properties ---------------------------------------------- */
TEST(dxctx_prop_set_query_roundtrip) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "prop", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    UCHAR v[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    ULONG st = (ULONG)U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttProp", sizeof v, v);
    ST_OK(st);
    if (NT_OK(st)) {
        ULONG cb = 0; PUCHAR out = NULL;
        ST_OK(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttProp", &cb, &out));
        EXPECT_EQ(cb, sizeof v);
        if (out) { CHECK(cb == sizeof v && !memcmp(out, v, sizeof v)); U(BCryptFreeBuffer)(out); }
    }
    cfg_cleanup_all();
}
TEST(dxctx_prop_overwrite_changes_size) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "propow", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    UCHAR big[300]; for (int i = 0; i < 300; i++) big[i] = (UCHAR)i;
    UCHAR small[2] = {0xAA, 0x55};
    if (NT_OK(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttProp", sizeof big, big))) {
        ST_OK(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttProp", sizeof small, small));
        ULONG cb = 0; PUCHAR out = NULL;
        ST_OK(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttProp", &cb, &out));
        CHECK(cb == 2);
        if (out && cb == 2) CHECK(!memcmp(out, small, 2));
        if (out) U(BCryptFreeBuffer)(out);
    }
    cfg_cleanup_all();
}
TEST(dxctx_prop_sizes) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "propsz", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    static const ULONG sizes[] = {1, 2, 3, 4, 7, 16, 255, 256, 257, 1000, 4096};
    static UCHAR buf[4096], out_cmp[4096];
    for (int i = 0; i < 4096; i++) buf[i] = (UCHAR)(i * 7 + 3);
    for (int i = 0; i < 11; i++) {
        ULONG st = (ULONG)U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttSz", sizes[i], buf);
        if (!NT_OK(st)) { t_note("set property of %lu bytes -> 0x%lx", sizes[i], st); continue; }
        ULONG cb = 0; PUCHAR out = NULL;
        ST_OK(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttSz", &cb, &out));
        CHECKF(cb == sizes[i], "size %lu came back as %lu", sizes[i], cb);
        if (out && cb == sizes[i]) CHECK(!memcmp(out, buf, cb));
        if (out) U(BCryptFreeBuffer)(out);
    }
    cfg_cleanup_all();
}
TEST(dxctx_prop_zero_length_value) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "prop0", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttZero", 0, NULL);
    t_note("set property with cbValue 0 / NULL value -> 0x%lx", st);
    UCHAR one = 1;
    st = (ULONG)U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"CrypttZero2", 0, &one);
    t_note("set property with cbValue 0 / non-NULL value -> 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_prop_query_unset_property) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "propunset", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG cb = 0; PUCHAR out = NULL;
    ULONG st = (ULONG)U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"NeverSet", &cb, &out);
    CHECKF(!NT_OK(st), "query of an unset property returned 0x%lx", st);
    CHECK(out == NULL);
    t_note("query unset property -> 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_prop_set_unknown_function) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "propnofn", 0));
    UCHAR v[2] = {1, 2};
    ULONG st = (ULONG)U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_none", L"CrypttProp", 2, v);
    CHECKF(!NT_OK(st), "set on a function that is not in the context returned 0x%lx", st);
    t_note("set property on unknown function -> 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_prop_two_properties_independent) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "prop2", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    UCHAR a[3] = {1, 2, 3}, b[5] = {9, 8, 7, 6, 5};
    if (NT_OK(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"PropA", 3, a))) {
        ST_OK(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"PropB", 5, b));
        ULONG cb = 0; PUCHAR o = NULL;
        ST_OK(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"PropA", &cb, &o));
        CHECK(cb == 3 && o && !memcmp(o, a, 3)); if (o) U(BCryptFreeBuffer)(o);
        o = NULL; cb = 0;
        ST_OK(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"PropB", &cb, &o));
        CHECK(cb == 5 && o && !memcmp(o, b, 5)); if (o) U(BCryptFreeBuffer)(o);
    }
    cfg_cleanup_all();
}
TEST(dxctx_prop_removed_with_function) {
    if (!cfg_begin()) return;
    WCHAR n[96]; ST_OK(mkctx(n, "proprm", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    UCHAR a[3] = {1, 2, 3};
    if (NT_OK(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"PropA", 3, a))) {
        ST_OK(U(BCryptRemoveContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1"));
        ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
        ULONG cb = 0; PUCHAR o = NULL;
        ULONG st = (ULONG)U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"PropA", &cb, &o);
        CHECKF(!NT_OK(st), "property survived removal of its function (0x%lx)", st);
        if (o) U(BCryptFreeBuffer)(o);
    }
    cfg_cleanup_all();
}

/* ---- function providers ------------------------------------------------ */
TEST(dxctx_fprov_add_enum_remove) {
    if (!cfg_begin()) return;
    if (!UN(BCryptAddContextFunctionProvider)) { t_skip("missing export"); return; }
    WCHAR n[96]; ST_OK(mkctx(n, "fprov", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)UN(BCryptAddContextFunctionProvider)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"Microsoft Primitive Provider", CRYPT_PRIORITY_BOTTOM);
    ST_OK(st);
    if (NT_OK(st)) {
        static WCHAR l[8][96]; NTSTATUS s;
        int k = cfg_enum_fprov(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", l, 8, &s);
        CHECK(k == 1);
        if (k == 1) EXPECT_WSTR(l[0], L"Microsoft Primitive Provider");
        ST_OK(UN(BCryptRemoveContextFunctionProvider)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"Microsoft Primitive Provider"));
        k = cfg_enum_fprov(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", l, 8, &s);
        CHECKF(k <= 0, "%d providers remain", k);
    }
    cfg_cleanup_all();
}
TEST(dxctx_fprov_priority_order) {
    if (!cfg_begin()) return;
    if (!UN(BCryptAddContextFunctionProvider)) { t_skip("missing export"); return; }
    WCHAR n[96]; ST_OK(mkctx(n, "fprio", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    BCryptAddContextFunctionProvider_pfn add = UN(BCryptAddContextFunctionProvider);
    ULONG a = (ULONG)add(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"Microsoft Primitive Provider", CRYPT_PRIORITY_BOTTOM);
    ULONG b = (ULONG)add(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"Microsoft Software Key Storage Provider", CRYPT_PRIORITY_TOP);
    t_note("add providers -> 0x%lx 0x%lx", a, b);
    if (NT_OK(a) && NT_OK(b)) {
        static WCHAR l[8][96]; NTSTATUS s;
        int k = cfg_enum_fprov(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", l, 8, &s);
        const WCHAR *w[] = {L"Microsoft Software Key Storage Provider", L"Microsoft Primitive Provider"};
        CHECK(names_eq(l, k, w, 2));
    }
    cfg_cleanup_all();
}
TEST(dxctx_fprov_duplicate_and_missing) {
    if (!cfg_begin()) return;
    if (!UN(BCryptAddContextFunctionProvider)) { t_skip("missing export"); return; }
    WCHAR n[96]; ST_OK(mkctx(n, "fprovdup", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)UN(BCryptAddContextFunctionProvider)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"Microsoft Primitive Provider", CRYPT_PRIORITY_BOTTOM);
    if (NT_OK(st)) {
        ULONG d = (ULONG)UN(BCryptAddContextFunctionProvider)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"Microsoft Primitive Provider", CRYPT_PRIORITY_BOTTOM);
        CHECKF(!NT_OK(d), "duplicate provider add returned 0x%lx", d);
        t_note("duplicate provider add -> 0x%lx", d);
    }
    ULONG r = (ULONG)UN(BCryptRemoveContextFunctionProvider)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"cryptt_no_such_provider");
    CHECKF(!NT_OK(r), "remove of a provider that was never added returned 0x%lx", r);
    t_note("remove unknown provider -> 0x%lx", r);
    cfg_cleanup_all();
}
TEST(dxctx_fprov_unregistered_provider_name) {
    if (!cfg_begin()) return;
    if (!UN(BCryptAddContextFunctionProvider)) { t_skip("missing export"); return; }
    WCHAR n[96]; ST_OK(mkctx(n, "fprovun", 0));
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    ULONG st = (ULONG)UN(BCryptAddContextFunctionProvider)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", L"cryptt_not_registered", CRYPT_PRIORITY_BOTTOM);
    t_note("add of an unregistered provider name -> 0x%lx", st);
    cfg_cleanup_all();
}

/* ---- change notification ----------------------------------------------- */
TEST(dxctx_notify_fires_on_change) {
    if (!cfg_begin()) return;
    if (!U(BCryptRegisterConfigChangeNotify) || !U(BCryptUnregisterConfigChangeNotify)) { t_skip("missing export"); return; }
    HANDLE ev = NULL;
    ULONG st = (ULONG)U(BCryptRegisterConfigChangeNotify)(&ev);
    ST_OK(st);
    if (!NT_OK(st) || !ev) { cfg_cleanup_all(); return; }
    /* drain a possibly pending signal from earlier tests / other processes */
    WaitForSingleObject(ev, 0);
    WCHAR n[96]; ST_OK(mkctx(n, "notify", 0));
    DWORD w = WaitForSingleObject(ev, 5000);
    CHECKF(w == WAIT_OBJECT_0, "event not signaled after context creation (wait=%lu)", w);
    WaitForSingleObject(ev, 0);
    ST_OK(U(BCryptDeleteContext)(CRYPT_LOCAL, n));
    w = WaitForSingleObject(ev, 5000);
    CHECKF(w == WAIT_OBJECT_0, "event not signaled after context deletion (wait=%lu)", w);
    ST_OK(U(BCryptUnregisterConfigChangeNotify)(ev));
    cfg_cleanup_all();
}
TEST(dxctx_notify_function_change) {
    if (!cfg_begin()) return;
    if (!U(BCryptRegisterConfigChangeNotify) || !U(BCryptUnregisterConfigChangeNotify)) { t_skip("missing export"); return; }
    WCHAR n[96]; ST_OK(mkctx(n, "notify2", 0));
    HANDLE ev = NULL;
    if (!NT_OK(U(BCryptRegisterConfigChangeNotify)(&ev)) || !ev) { cfg_cleanup_all(); return; }
    WaitForSingleObject(ev, 200); WaitForSingleObject(ev, 0);
    ST_OK(U(BCryptAddContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1", CRYPT_PRIORITY_BOTTOM));
    CHECK(WaitForSingleObject(ev, 5000) == WAIT_OBJECT_0);
    WaitForSingleObject(ev, 0);
    ST_OK(U(BCryptRemoveContextFunction)(CRYPT_LOCAL, n, BCRYPT_HASH_INTERFACE, L"cryptt_f1"));
    CHECK(WaitForSingleObject(ev, 5000) == WAIT_OBJECT_0);
    ST_OK(U(BCryptUnregisterConfigChangeNotify)(ev));
    cfg_cleanup_all();
}
TEST(dxctx_notify_unregister_twice) {
    if (!cfg_begin()) return;
    if (!U(BCryptRegisterConfigChangeNotify) || !U(BCryptUnregisterConfigChangeNotify)) { t_skip("missing export"); return; }
    HANDLE ev = NULL;
    if (!NT_OK(U(BCryptRegisterConfigChangeNotify)(&ev)) || !ev) return;
    ST_OK(U(BCryptUnregisterConfigChangeNotify)(ev));
    ULONG st = (ULONG)U(BCryptUnregisterConfigChangeNotify)(ev);
    t_note("second BCryptUnregisterConfigChangeNotify -> 0x%lx", st);
}
TEST(dxctx_notify_register_returns_distinct_events) {
    if (!cfg_begin()) return;
    if (!U(BCryptRegisterConfigChangeNotify) || !U(BCryptUnregisterConfigChangeNotify)) { t_skip("missing export"); return; }
    HANDLE a = NULL, b = NULL;
    ST_OK(U(BCryptRegisterConfigChangeNotify)(&a));
    ST_OK(U(BCryptRegisterConfigChangeNotify)(&b));
    CHECK(a != NULL && b != NULL);
    CHECK(a != b);
    if (a) U(BCryptUnregisterConfigChangeNotify)(a);
    if (b) U(BCryptUnregisterConfigChangeNotify)(b);
}

/* ---- elevation ---------------------------------------------------------- */
TEST(dxctx_noadmin_create_access_denied) {
    REQUIRE(U(BCryptCreateContext));
    if (t_is_wine()) { t_skip("emulator"); return; }
    if (cfg_is_elevated()) { t_skip("process is elevated; this test only runs unelevated"); return; }
    WCHAR n[96]; cfg_name(n, 96, "noadm", 0);
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ULONG st = (ULONG)U(BCryptCreateContext)(CRYPT_LOCAL, n, &c);
    CHECK(st == S_ACCESS_DENIED);
    if (NT_OK(st)) U(BCryptDeleteContext)(CRYPT_LOCAL, n);
    st = (ULONG)U(BCryptDeleteContext)(CRYPT_LOCAL, L"Default");
    CHECKF(st == S_ACCESS_DENIED, "unelevated delete of a system context returned 0x%lx", st);
    cfg_cleanup_all();
}
TEST(dxctx_noadmin_register_provider_access_denied) {
    REQUIRE(UN(BCryptRegisterProvider));
    if (t_is_wine()) { t_skip("emulator"); return; }
    if (cfg_is_elevated()) { t_skip("process is elevated; this test only runs unelevated"); return; }
    WCHAR n[96], img[MAX_PATH]; cfg_name(n, 96, "noadmprov", 1);
    cfg_sysdll(img, MAX_PATH, L"bcryptprimitives.dll");
    PWSTR fns[1] = {L"AES"};
    CRYPT_INTERFACE_REG ir = {BCRYPT_CIPHER_INTERFACE, 0, 1, fns};
    PCRYPT_INTERFACE_REG irs[1] = {&ir};
    CRYPT_IMAGE_REG im = {img, 1, irs};
    CRYPT_PROVIDER_REG reg = {0, NULL, &im, NULL};
    ULONG st = (ULONG)UN(BCryptRegisterProvider)(n, 0, &reg);
    CHECK(st == S_ACCESS_DENIED);
    if (NT_OK(st)) UN(BCryptUnregisterProvider)(n);
    cfg_cleanup_all();
}

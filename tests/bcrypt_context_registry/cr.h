/* Shared helpers for the bcrypt_context_registry area (read-only CNG configuration queries). */
#ifndef CR_H
#define CR_H
#include "t.h"
#include <bcrypt.h>
#include <ctype.h>

/* NTSTATUS values used by the configuration APIs (spelled out: the tests must not depend on header macros). */
#define CRS_OK                0x00000000L
#define CRS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#define CRS_BUFFER_TOO_SMALL  ((NTSTATUS)0xC0000023L)
#define CRS_NOT_FOUND         ((NTSTATUS)0xC0000225L)
#define CRS_OBJ_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define CRS_NOT_IMPLEMENTED   ((NTSTATUS)0xC0000002L)
#define CRS_PRIV_NOT_HELD     ((NTSTATUS)0xC0000061L)
#define CRS_NTE_NOT_FOUND     ((NTSTATUS)0x80090011L)

/* Interface identifiers: bcrypt.h ones plus the NCrypt ones (hard-coded; they are public constants). */
#define CRI_CIPHER     0x00000001u
#define CRI_HASH       0x00000002u
#define CRI_ASYM       0x00000003u
#define CRI_SECRET     0x00000004u
#define CRI_SIGNATURE  0x00000005u
#define CRI_RNG        0x00000006u
#define CRI_KDF        0x00000007u
#define CRI_KEYSTORE   0x00010001u
#define CRI_SCHANNEL   0x00010002u   /* configuration only: the registry view of the interface, never schannel itself */
#define CRI_SCH_SIG    0x00010003u
#define CRI_KEYPROT    0x00010004u

#define CR_TABLE_LOCAL  1u
#define CR_TABLE_DOMAIN 2u

#define CR_PROVIDER_PRIM L"Microsoft Primitive Provider"

static const ULONG cr_good_ifaces[] = { 1, 2, 3, 4, 5, 6, 7, 0x10001, 0x10002, 0x10003, 0x10004 };
#define CR_N_GOOD_IFACES (sizeof cr_good_ifaces / sizeof cr_good_ifaces[0])
/* Interface ids rejected by ValidateInterfaceId (0 is separately allowed only by QueryProviderRegistration / ResolveProviders). */
static const ULONG cr_bad_ifaces_nz[] = { 8, 9, 0x10, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0x10005, 0x10006,
                                          0x10007, 0x1000F, 0x20001, 0x1000001, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu };
#define CR_N_BAD_IFACES_NZ (sizeof cr_bad_ifaces_nz / sizeof cr_bad_ifaces_nz[0])
static const ULONG cr_bad_tables[] = { 0, 3, 4, 5, 8, 0x10, 0x100, 0x10001, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu };
#define CR_N_BAD_TABLES (sizeof cr_bad_tables / sizeof cr_bad_tables[0])

/* All the string-array result structures share the layout { ULONG count; PWSTR *array; }. */
typedef struct { ULONG c; WCHAR **v; } cr_strlist;

static const char *cr_iface_name(ULONG i) {
    switch (i) {
    case 1: return "CIPHER"; case 2: return "HASH"; case 3: return "ASYMMETRIC_ENCRYPTION"; case 4: return "SECRET_AGREEMENT";
    case 5: return "SIGNATURE"; case 6: return "RNG"; case 7: return "KEY_DERIVATION";
    case 0x10001: return "KEY_STORAGE"; case 0x10002: return "SCHANNEL"; case 0x10003: return "SCHANNEL_SIGNATURE";
    case 0x10004: return "KEY_PROTECTION"; }
    return "?";
}

static void cr_w2a(const WCHAR *w, char *out, size_t cap) {
    size_t i = 0;
    if (!w) { snprintf(out, cap, "(null)"); return; }
    for (; w[i] && i + 1 < cap; i++) out[i] = w[i] < 0x80 ? (char)w[i] : '?';
    out[i] = 0;
}

/* Is [p, p+n) inside [base, base+cb)? */
static int cr_inside(const void *base, ULONG cb, const void *p, size_t n) {
    const BYTE *b = base, *q = p;
    if (!base || !p) return 0;
    if (q < b) return 0;
    if ((size_t)(q - b) > cb) return 0;
    return n <= (size_t)cb - (size_t)(q - b);
}

/* A wide string pointer that lies inside the returned block, is 2-aligned and NUL terminated inside it. */
static int cr_str_inside(const void *base, ULONG cb, const WCHAR *s) {
    if (!s || ((ULONG_PTR)s & 1)) return 0;
    if (!cr_inside(base, cb, s, 2)) return 0;
    const BYTE *end = (const BYTE *)base + cb;
    for (const WCHAR *q = s; (const BYTE *)(q + 1) <= end; q++) if (!*q) return 1;
    return 0;
}

/* Verify a { count, array } result: array and every non-empty string live inside the single returned block. */
static int cr_walk_list(const void *base, ULONG cb, ULONG count, WCHAR **arr, const char *what) {
    int ok = 1;
    if (count == 0) return 1;
    if (!cr_inside(base, cb, arr, (size_t)count * sizeof(WCHAR *))) {
        t_check(0, __FILE__, __LINE__, "array inside block", "%s: array %p not inside block %p+%lu (count %lu)", what, (void *)arr, base, cb, count);
        return 0;
    }
    for (ULONG i = 0; i < count; i++) {
        if (!cr_str_inside(base, cb, arr[i])) {
            t_check(0, __FILE__, __LINE__, "string inside block", "%s[%lu] = %p outside/unterminated (block %p+%lu)", what, i, (void *)arr[i], base, cb);
            ok = 0;
        } else if (!arr[i][0]) {
            t_check(0, __FILE__, __LINE__, "string non-empty", "%s[%lu] is empty", what, i);
            ok = 0;
        }
    }
    return ok;
}

static int cr_list_has(const cr_strlist *l, const WCHAR *s) {
    for (ULONG i = 0; i < l->c; i++) if (l->v[i] && !lstrcmpiW(l->v[i], s)) return 1;
    return 0;
}

/* ---- wrappers that fetch a block and free it again --------------------------------------------- */
typedef struct { void *p; ULONG cb; NTSTATUS st; } cr_blk;

static void cr_free(void *p) { if (p) { typeof(&BCryptFreeBuffer) f = U(BCryptFreeBuffer); if (f) f(p); } }

static cr_blk cr_enum_contexts(ULONG table) {
    cr_blk b = {0}; PCRYPT_CONTEXTS p = NULL; ULONG cb = 0;
    b.st = U(BCryptEnumContexts)(table, &cb, &p); b.p = p; b.cb = cb; return b;
}
static cr_blk cr_enum_providers(void) {
    cr_blk b = {0}; PCRYPT_PROVIDERS p = NULL; ULONG cb = 0;
    b.st = U(BCryptEnumRegisteredProviders)(&cb, &p); b.p = p; b.cb = cb; return b;
}
static cr_blk cr_enum_funcs(ULONG table, const WCHAR *ctx, ULONG iface) {
    cr_blk b = {0}; PCRYPT_CONTEXT_FUNCTIONS p = NULL; ULONG cb = 0;
    b.st = U(BCryptEnumContextFunctions)(table, ctx, iface, &cb, &p); b.p = p; b.cb = cb; return b;
}
static cr_blk cr_enum_func_providers(ULONG table, const WCHAR *ctx, ULONG iface, const WCHAR *fn) {
    cr_blk b = {0}; PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = NULL; ULONG cb = 0;
    b.st = U(BCryptEnumContextFunctionProviders)(table, ctx, iface, fn, &cb, &p); b.p = p; b.cb = cb; return b;
}
static cr_blk cr_query_reg(const WCHAR *prov, ULONG mode, ULONG iface) {
    cr_blk b = {0}; PCRYPT_PROVIDER_REG p = NULL; ULONG cb = 0;
    b.st = U(BCryptQueryProviderRegistration)(prov, mode, iface, &cb, &p); b.p = p; b.cb = cb; return b;
}
static cr_blk cr_resolve(const WCHAR *ctx, ULONG iface, const WCHAR *fn, const WCHAR *prov, ULONG mode, ULONG flags) {
    cr_blk b = {0}; PCRYPT_PROVIDER_REFS p = NULL; ULONG cb = 0;
    b.st = U(BCryptResolveProviders)(ctx, iface, fn, prov, mode, flags, &cb, &p); b.p = p; b.cb = cb; return b;
}

/* ---- structure validators used by several files ------------------------------------------------ */
static int cr_check_reg_image(const cr_blk *b, const CRYPT_IMAGE_REG *img, const char *what) {
    int ok = 1;
    if (!cr_inside(b->p, b->cb, img, sizeof *img)) { t_check(0, __FILE__, __LINE__, "image inside block", "%s image %p outside block", what, (void *)img); return 0; }
    if (!cr_str_inside(b->p, b->cb, img->pszImage)) { t_check(0, __FILE__, __LINE__, "pszImage inside block", "%s pszImage %p", what, (void *)img->pszImage); ok = 0; }
    if (img->cInterfaces) {
        if (!cr_inside(b->p, b->cb, img->rgpInterfaces, (size_t)img->cInterfaces * sizeof(void *))) {
            t_check(0, __FILE__, __LINE__, "rgpInterfaces inside block", "%s", what); return 0;
        }
        for (ULONG i = 0; i < img->cInterfaces; i++) {
            const CRYPT_INTERFACE_REG *ir = img->rgpInterfaces[i];
            if (!cr_inside(b->p, b->cb, ir, sizeof *ir)) { t_check(0, __FILE__, __LINE__, "interface reg inside block", "%s[%lu]", what, i); ok = 0; continue; }
            char nm[64]; snprintf(nm, sizeof nm, "%s.if[%lu].funcs", what, i);
            if (!cr_walk_list(b->p, b->cb, ir->cFunctions, ir->rgpszFunctions, nm)) ok = 0;
        }
    }
    return ok;
}

static int cr_image_has_func(const CRYPT_IMAGE_REG *img, ULONG iface, const WCHAR *fn) {
    if (!img) return 0;
    for (ULONG i = 0; i < img->cInterfaces; i++) {
        const CRYPT_INTERFACE_REG *ir = img->rgpInterfaces[i];
        if (ir->dwInterface != iface) continue;
        for (ULONG j = 0; j < ir->cFunctions; j++) if (!lstrcmpiW(ir->rgpszFunctions[j], fn)) return 1;
    }
    return 0;
}

/* Walk CRYPT_PROVIDER_REFS: every pointer inside the one block. Returns 1 when well formed. */
static int cr_check_refs(const cr_blk *b, const char *what) {
    const CRYPT_PROVIDER_REFS *r = b->p; int ok = 1;
    if (!r) return 0;
    if (b->cb < sizeof *r) { t_check(0, __FILE__, __LINE__, "refs header size", "%s cb=%lu", what, b->cb); return 0; }
    if (r->cProviders == 0) return 1;
    if (!cr_inside(b->p, b->cb, r->rgpProviders, (size_t)r->cProviders * sizeof(void *))) { t_check(0, __FILE__, __LINE__, "rgpProviders inside block", "%s", what); return 0; }
    for (ULONG i = 0; i < r->cProviders; i++) {
        const CRYPT_PROVIDER_REF *pr = r->rgpProviders[i];
        if (!cr_inside(b->p, b->cb, pr, sizeof *pr)) { t_check(0, __FILE__, __LINE__, "provider ref inside block", "%s[%lu] %p", what, i, (void *)pr); ok = 0; continue; }
        if (!cr_str_inside(b->p, b->cb, pr->pszProvider)) { t_check(0, __FILE__, __LINE__, "pszProvider inside block", "%s[%lu]", what, i); ok = 0; }
        if (pr->pszFunction && !cr_str_inside(b->p, b->cb, pr->pszFunction)) { t_check(0, __FILE__, __LINE__, "pszFunction inside block", "%s[%lu]", what, i); ok = 0; }
        if (pr->pUM) {
            if (!cr_inside(b->p, b->cb, pr->pUM, sizeof *pr->pUM) || !cr_str_inside(b->p, b->cb, pr->pUM->pszImage)) { t_check(0, __FILE__, __LINE__, "pUM inside block", "%s[%lu]", what, i); ok = 0; }
        }
        if (pr->pKM) {
            if (!cr_inside(b->p, b->cb, pr->pKM, sizeof *pr->pKM) || !cr_str_inside(b->p, b->cb, pr->pKM->pszImage)) { t_check(0, __FILE__, __LINE__, "pKM inside block", "%s[%lu]", what, i); ok = 0; }
        }
        if (pr->cProperties) {
            if (!cr_inside(b->p, b->cb, pr->rgpProperties, (size_t)pr->cProperties * sizeof(void *))) { t_check(0, __FILE__, __LINE__, "rgpProperties inside block", "%s[%lu]", what, i); ok = 0; continue; }
            for (ULONG k = 0; k < pr->cProperties; k++) {
                const CRYPT_PROPERTY_REF *pp = pr->rgpProperties[k];
                if (!cr_inside(b->p, b->cb, pp, sizeof *pp) || !cr_str_inside(b->p, b->cb, pp->pszProperty)) { t_check(0, __FILE__, __LINE__, "property ref inside block", "%s[%lu].prop[%lu]", what, i, k); ok = 0; continue; }
                if (pp->cbValue && !cr_inside(b->p, b->cb, pp->pbValue, pp->cbValue)) { t_check(0, __FILE__, __LINE__, "property value inside block", "%s[%lu].prop[%lu]", what, i, k); ok = 0; }
            }
        }
    }
    return ok;
}

/* Wide string made of n 'A' characters plus a terminating NUL (caller frees). */
static WCHAR *cr_longstr(size_t n, WCHAR ch) {
    WCHAR *s = HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR));
    if (!s) return NULL;
    for (size_t i = 0; i < n; i++) s[i] = ch;
    s[n] = 0;
    return s;
}
#endif

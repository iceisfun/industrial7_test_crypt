#ifndef EXPORTS_COMMON_H
#define EXPORTS_COMMON_H
#include "t.h"
typedef struct { const char *name; unsigned ord; const char *fwd; } XE;   /* name NULL = ordinal-only */
typedef struct { const char *dll; const XE *e; int n; } XM;
extern const XM ex_mods[];                       /* NULL-terminated by dll == NULL */
const XM *ex_find(const char *dll);
HMODULE ex_mod(const char *dll);

/* Parsed export directory of a loaded image (reads the mapped PE headers; trivial scaffolding). */
typedef struct {
    HMODULE base; DWORD size_of_image; WORD machine, file_chars;
    const IMAGE_EXPORT_DIRECTORY *dir; DWORD dir_rva, dir_size;
} XDIR;
int  ex_dir(HMODULE h, XDIR *d);
/* find by name (binary search not assumed): returns 1 and fills ordinal (biased), rva, forwarder string or NULL */
int  ex_dir_find(const XDIR *d, const char *name, DWORD *ord, DWORD *rva, const char **fwd);
int  ex_in_image(const XDIR *d, const void *p);
void ex_target_of(const char *fwd, char *dll, size_t cap, char *sym, size_t scap); /* "BCRYPT.Foo" -> bcrypt.dll, Foo */

/* sweeps */
void ex_family(const char *dll, const char *const *names, int n);
#define FAIL_BUDGET 20
#endif
void sw_loads(const char *dll);
void sw_names_resolve(const char *dll);
void sw_name_via_t_proc_in(const char *dll);
void sw_pe_headers(const char *dll);
void sw_addr_in_image(const char *dll);
void sw_listed_in_dir(const char *dll);
void sw_dir_ordinal_roundtrip(const char *dll);
void sw_json_ordinals(const char *dll);
void sw_ordinal_only(const char *dll);
void sw_fwd_strings(const char *dll);
void sw_fwd_same_address(const char *dll);
void sw_nonfwd_not_forwarder(const char *dll);
void sw_counts(const char *dll);
void sw_unlisted(const char *dll);
void sw_case_sensitive(const char *dll);
void sw_bad_names(const char *dll);
void sw_bad_ordinals(const char *dll);
void sw_aw_pairs(const char *dll);
void sw_stable(const char *dll);
void sw_refcount(const char *dll);
void sw_sorted(const char *dll);
void sw_no_dup_names(const char *dll);
void sw_distinct_addrs(const char *dll);
void sw_getmodulehandle(const char *dll);
void sw_name_len_limits(const char *dll);
#define MODTESTS(mod, dll) \
 TEST(exports_cng_capi_##mod##_module_loads) { sw_loads(dll); } \
 TEST(exports_cng_capi_##mod##_pe_headers) { sw_pe_headers(dll); } \
 TEST(exports_cng_capi_##mod##_named_exports_resolve) { sw_names_resolve(dll); } \
 TEST(exports_cng_capi_##mod##_t_proc_in_matches) { sw_name_via_t_proc_in(dll); } \
 TEST(exports_cng_capi_##mod##_listed_names_in_export_dir) { sw_listed_in_dir(dll); } \
 TEST(exports_cng_capi_##mod##_address_location) { sw_addr_in_image(dll); } \
 TEST(exports_cng_capi_##mod##_ordinal_roundtrip) { sw_dir_ordinal_roundtrip(dll); } \
 TEST(exports_cng_capi_##mod##_ordinals_match_snapshot) { sw_json_ordinals(dll); } \
 TEST(exports_cng_capi_##mod##_ordinal_only_exports) { sw_ordinal_only(dll); } \
 TEST(exports_cng_capi_##mod##_forwarders_strings) { sw_fwd_strings(dll); } \
 TEST(exports_cng_capi_##mod##_forwarders_same_address_as_target) { sw_fwd_same_address(dll); } \
 TEST(exports_cng_capi_##mod##_non_forwarders_are_code) { sw_nonfwd_not_forwarder(dll); } \
 TEST(exports_cng_capi_##mod##_export_counts) { sw_counts(dll); } \
 TEST(exports_cng_capi_##mod##_unlisted_exports) { sw_unlisted(dll); } \
 TEST(exports_cng_capi_##mod##_names_case_sensitive) { sw_case_sensitive(dll); } \
 TEST(exports_cng_capi_##mod##_unknown_names_fail) { sw_bad_names(dll); } \
 TEST(exports_cng_capi_##mod##_unknown_ordinals_fail) { sw_bad_ordinals(dll); } \
 TEST(exports_cng_capi_##mod##_aw_pairs) { sw_aw_pairs(dll); } \
 TEST(exports_cng_capi_##mod##_addresses_stable) { sw_stable(dll); } \
 TEST(exports_cng_capi_##mod##_load_refcount_keeps_exports) { sw_refcount(dll); } \
 TEST(exports_cng_capi_##mod##_export_names_sorted) { sw_sorted(dll); } \
 TEST(exports_cng_capi_##mod##_no_duplicate_names) { sw_no_dup_names(dll); } \
 TEST(exports_cng_capi_##mod##_distinct_exports_distinct_addresses) { sw_distinct_addrs(dll); } \
 TEST(exports_cng_capi_##mod##_get_module_handle_agrees) { sw_getmodulehandle(dll); } \
 TEST(exports_cng_capi_##mod##_name_length_boundaries) { sw_name_len_limits(dll); }

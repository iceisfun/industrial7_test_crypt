/* GENERATED */
#ifndef EXP_H
#define EXP_H
#include "t.h"
typedef struct { const char *name; unsigned ord; const char *fwd; } exp_ent;
void exp_run(const char *dll, const char *which, const exp_ent *tab, int n);
#define EXP_DECL(m) extern const exp_ent exp_tab_##m[]; extern const int exp_cnt_##m;
EXP_DECL(crypt32)
EXP_DECL(cryptnet)
EXP_DECL(cryptui)
EXP_DECL(cryptdlg)
EXP_DECL(cryptext)
EXP_DECL(cryptxml)
EXP_DECL(cryptowinrt)
EXP_DECL(cryptcatsvc)
EXP_DECL(cryptngc)
EXP_DECL(wintrust)
EXP_DECL(mssign32)
EXP_DECL(mssip32)
EXP_DECL(capisp)
EXP_DECL(tbs)
EXP_DECL(keyiso)
EXP_DECL(certenc)
EXP_DECL(certprop)
EXP_DECL(msasn1)
EXP_DECL(ntasn1)
EXP_DECL(certca)
EXP_DECL(certcli)
#define EXP_SUITE(m, dll) \
 TEST(exp_##m##_module_loads)       { exp_run(dll, "load", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_names_resolve)      { exp_run(dll, "names", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_ordinals_resolve)   { exp_run(dll, "ords", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_name_matches_ordinal) { exp_run(dll, "nameord", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_local_in_image)     { exp_run(dll, "inimg", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_forwarders)         { exp_run(dll, "fwd", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_bogus_name)         { exp_run(dll, "bogusname", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_bogus_ordinal)      { exp_run(dll, "bogusord", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_case_sensitive)     { exp_run(dll, "case", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_table_sanity)       { exp_run(dll, "sanity", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_aw_pairs)           { exp_run(dll, "awpairs", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_dll_entry_points)   { exp_run(dll, "dllentry", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_no_unlisted_ordinals) { exp_run(dll, "extras", exp_tab_##m, exp_cnt_##m); } \
 TEST(exp_##m##_getprocaddress_null_name) { exp_run(dll, "nullname", exp_tab_##m, exp_cnt_##m); }
#endif

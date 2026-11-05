/* CDRegisterCSystem / CDRegisterCheckSum / CDRegisterRng. The tables are process-global and there is no way to
 * unregister, so every registration scenario runs in its own child process (CHILD() + t_run_child()). A child
 * reports the source line of its first failed condition as the exit code. */
#include "ck.h"

#define RUN_CHILD(name) do { DWORD ec_ = t_run_child(name, "", 30000); \
    t_check(ec_ == 0, __FILE__, __LINE__, "child " name " exit 0", "exit code %lu (line number in ck_register.c if < 100000)", (unsigned long)ec_); } while (0)

static CSX mk_cs(LONG et, ULONG keysz) {
    CSX c; memset(&c, 0, sizeof c);
    c.EncryptionType = (ULONG)et; c.BlockSize = 1; c.ExportableEncryptionType = (ULONG)et; c.KeySize = keysz;
    c.HeaderSize = 5; c.PreferredCheckSum = 9; c.Attributes = 0; c.Name = L"ck test system";
    return c;
}

/* ---- crypto systems ---- */
CHILD(ck_reg_cs_basic) {
    CC(CKP(CDRegisterCSystem) && CKP(CDLocateCSystem) && CKP(CDBuildVect));
    CSX m = mk_cs(0x7e57, 16);
    m.Attributes = 0x24; m.Initialize = (void *)0x1001; m.Encrypt = (void *)0x1002; m.Decrypt = (void *)0x1003;
    m.Finish = (void *)0x1004; m.HashPassword = (void *)0x1005; m.RandomKey = (void *)0x1006; m.Control = (void *)0x1007;
    m.Rsv60 = (void *)0x1008; m.Rsv68 = (void *)0x1009; m.Rsv70 = (void *)0x100a; m.PrfPlus = (void *)0x100b;
    CSX *p = NULL;
    CC(CKP(CDLocateCSystem)(0x7e57, &p) == NS_NO_CSYSTEM);
    CC(CKP(CDRegisterCSystem)(&m) == 0);
    CC(CKP(CDLocateCSystem)(0x7e57, &p) == 0);
    CC(p != NULL && p != &m);
    CC(memcmp(p, &m, sizeof m) == 0);
    ULONG n = 0; LONG v[40];
    CC(CKP(CDBuildVect)(&n, v) == 0);
    CC(n == 17 && v[16] == 0x7e57 && v[0] == 18);
    CC(CKP(CDLocateCSystem)(0x7e58, &p) == NS_NO_CSYSTEM);
    return 0;
}
TEST(ckreg_csystem_register_and_locate) { CK_NEED(CDRegisterCSystem); RUN_CHILD("ck_reg_cs_basic"); }

CHILD(ck_reg_cs_snapshot) {
    CC(CKP(CDRegisterCSystem) && CKP(CDLocateCSystem));
    CSX m = mk_cs(0x7e57, 16);
    CC(CKP(CDRegisterCSystem)(&m) == 0);
    m.KeySize = 999; m.Name = NULL; m.EncryptionType = 0x7e99;
    CSX *p = NULL;
    CC(CKP(CDLocateCSystem)(0x7e57, &p) == 0);
    CC(p->KeySize == 16 && p->Name != NULL && p->EncryptionType == 0x7e57);
    CC(CKP(CDLocateCSystem)(0x7e99, &p) == NS_NO_CSYSTEM);
    return 0;
}
TEST(ckreg_csystem_registration_copies_the_entry) { CK_NEED(CDRegisterCSystem); RUN_CHILD("ck_reg_cs_snapshot"); }

CHILD(ck_reg_cs_override) {
    CC(CKP(CDRegisterCSystem) && CKP(CDLocateCSystem) && CKP(CDBuildVect));
    CSX *orig = NULL, *p = NULL;
    CC(CKP(CDLocateCSystem)(ET_AES128, &orig) == 0);
    CC(orig->KeySize == 16);
    CSX m = mk_cs(ET_AES128, 77);
    CC(CKP(CDRegisterCSystem)(&m) == 0);
    CC(CKP(CDLocateCSystem)(ET_AES128, &p) == 0);
    CC(p != orig && p->KeySize == 77);              /* the most recent registration wins */
    CC(CKP(CDLocateCSystem)(ET_AES256, &p) == 0 && p->KeySize == 32);
    ULONG n = 0; LONG v[40];
    CC(CKP(CDBuildVect)(&n, v) == 0 && n == 17);
    int cnt = 0; for (ULONG i = 0; i < n; i++) cnt += v[i] == ET_AES128;
    CC(cnt == 2 && v[1] == ET_AES128 && v[16] == ET_AES128);
    return 0;
}
TEST(ckreg_csystem_duplicate_etype_last_registration_wins) { CK_NEED(CDRegisterCSystem); RUN_CHILD("ck_reg_cs_override"); }

CHILD(ck_reg_cs_capacity) {
    CC(CKP(CDRegisterCSystem) && CKP(CDLocateCSystem) && CKP(CDBuildVect));
    for (int i = 0; i < 7; i++) { CSX m = mk_cs(0x7e00 + i, 8); CC(CKP(CDRegisterCSystem)(&m) == 0); }
    ULONG n = 0; CC(CKP(CDBuildVect)(&n, NULL) == 0 && n == 23);
    CSX m = mk_cs(0x7e10, 8);
    CC(CKP(CDRegisterCSystem)(&m) == NS_INSUFF_RES);
    CC(CKP(CDRegisterCSystem)(&m) == NS_INSUFF_RES);
    CC(CKP(CDBuildVect)(&n, NULL) == 0 && n == 23);
    CSX *p;
    for (int i = 0; i < 7; i++) CC(CKP(CDLocateCSystem)(0x7e00 + i, &p) == 0 && p->KeySize == 8);
    CC(CKP(CDLocateCSystem)(0x7e10, &p) == NS_NO_CSYSTEM);
    CC(CKP(CDLocateCSystem)(ET_AES256, &p) == 0);
    return 0;
}
TEST(ckreg_csystem_capacity_is_23_entries) { CK_NEED(CDRegisterCSystem); RUN_CHILD("ck_reg_cs_capacity"); }

CHILD(ck_reg_cs_integrity) {
    CC(CKP(CDRegisterCSystem) && CKP(CDBuildIntegrityVect) && CKP(CDGetIntegrityVect));
    CSX a = mk_cs(0x7e01, 8), b = mk_cs(0x7e02, 8);
    a.Attributes = CSYS_INTEGRITY; b.Attributes = 0x3;
    CC(CKP(CDRegisterCSystem)(&a) == 0 && CKP(CDRegisterCSystem)(&b) == 0);
    ULONG m = 0; CC(CKP(CDGetIntegrityVect)(&m) == 0);
    LONG v[40]; ULONG n = 40;
    CC(CKP(CDBuildIntegrityVect)(&n, v) == 0);
    int ha = 0, hb = 0; for (ULONG i = 0; i < n; i++) { ha += v[i] == 0x7e01; hb += v[i] == 0x7e02; }
    CC(ha == 1 && hb == 0);
    CC(v[n - 1] == 0x7e01);                                   /* appended after the built-ins, table order */
    CSX *p; CC(CKP(CDLocateCSystem)(0x7e01, &p) == 0 && (p->Attributes & CSYS_INTEGRITY));
    CC(CKP(CDLocateCSystem)(0x7e02, &p) == 0 && p->Attributes == 0x3);   /* other attribute bits are not touched */
    return 0;
}
TEST(ckreg_csystem_integrity_attribute_drives_integrity_vector) { CK_NEED(CDRegisterCSystem); RUN_CHILD("ck_reg_cs_integrity"); }

CHILD(ck_reg_cs_findcommon) {
    CC(CKP(CDRegisterCSystem) && CKP(CDFindCommonCSystem) && CKP(CDFindCommonCSystemWithKey));
    CSX a = mk_cs(0x7e01, 8);
    LONG out = 0, t[] = { 0x7e01, 0x7e02 };
    CC(CKP(CDFindCommonCSystem)(2, t, &out) == NS_NO_CSYSTEM && out == 0);
    CC(CKP(CDRegisterCSystem)(&a) == 0);
    CC(CKP(CDFindCommonCSystem)(2, t, &out) == 0 && out == 0x7e01);
    LONG k[] = { 0x7e01 };
    CC(CKP(CDFindCommonCSystemWithKey)(2, t, 1, k, &out) == 0 && out == 0x7e01);
    LONG k2[] = { 0x7e02 };
    CC(CKP(CDFindCommonCSystemWithKey)(2, t, 1, k2, &out) == NS_NO_CSYSTEM && out == 0);
    return 0;
}
TEST(ckreg_csystem_registered_system_visible_to_findcommon) { CK_NEED(CDRegisterCSystem); RUN_CHILD("ck_reg_cs_findcommon"); }

static NTSTATUS WINAPI fk_init(PUCHAR k, ULONG ks, ULONG u, PVOID *st) { *st = (PVOID)(ULONG_PTR)(0x1000 + ks + u); return 0x1234; }
CHILD(ck_reg_cs_callable_pointers) {
    CC(CKP(CDRegisterCSystem) && CKP(CDLocateCSystem));
    CSX m = mk_cs(0x7e57, 16); m.Initialize = (void *)fk_init;
    CC(CKP(CDRegisterCSystem)(&m) == 0);
    CSX *p; CC(CKP(CDLocateCSystem)(0x7e57, &p) == 0);
    PVOID st = NULL;
    CC(((csx_init_fn)p->Initialize)(NULL, 5, 7, &st) == 0x1234);
    CC(st == (PVOID)(ULONG_PTR)(0x1000 + 5 + 7));
    return 0;
}
TEST(ckreg_csystem_function_pointers_survive_copy) { CK_NEED(CDRegisterCSystem); RUN_CHILD("ck_reg_cs_callable_pointers"); }

/* ---- KRBFXCF2 against fake crypto systems: documents the exact call protocol ---- */
static struct { int pa, pb, rk; PUCHAR ka, kb; ULONG kla, klb; PUCHAR sa, sb; ULONG sla, slb, olda, oldb; PUCHAR outa, outb; PUCHAR rkseed; ULONG rklen; PUCHAR rkout; BYTE seed[16]; NTSTATUS fail_a, fail_b, fail_r; } g;
static NTSTATUS WINAPI prf_a(PUCHAR k, ULONG kl, PUCHAR s, ULONG sl, PUCHAR out, ULONG ol) {
    g.pa++; g.ka = k; g.kla = kl; g.sa = s; g.sla = sl; g.olda = ol; g.outa = out;
    if (g.fail_a) return g.fail_a;
    for (ULONG i = 0; i < ol; i++) out[i] = (BYTE)(k[0] + (sl ? s[0] : 0) + i);
    return 0;
}
static NTSTATUS WINAPI prf_b(PUCHAR k, ULONG kl, PUCHAR s, ULONG sl, PUCHAR out, ULONG ol) {
    g.pb++; g.kb = k; g.klb = kl; g.sb = s; g.slb = sl; g.oldb = ol; g.outb = out;
    if (g.fail_b) return g.fail_b;
    for (ULONG i = 0; i < ol; i++) out[i] = (BYTE)(k[0] * 3 + (sl ? s[0] : 0) + i);
    return 0;
}
static NTSTATUS WINAPI rk_fake(PUCHAR seed, ULONG len, PUCHAR key) {
    g.rk++; g.rkseed = seed; g.rklen = len; g.rkout = key;
    if (g.fail_r) return g.fail_r;
    for (ULONG i = 0; i < len; i++) { g.seed[i] = seed[i]; key[i] = (BYTE)(seed[i] ^ 0xFF); }
    return 0;
}
static int reg3(void) {
    CSX a = mk_cs(0x7e01, 4), b = mk_cs(0x7e02, 4), c = mk_cs(0x7e03, 4), d = mk_cs(0x7e04, 6);
    a.PrfPlus = (void *)prf_a; a.RandomKey = (void *)rk_fake;
    b.PrfPlus = (void *)prf_b;                         /* no RandomKey: only the first system's is used */
    c.RandomKey = (void *)rk_fake;                     /* no PrfPlus */
    d.PrfPlus = (void *)prf_b; d.RandomKey = (void *)rk_fake;
    return CKP(CDRegisterCSystem)(&a) == 0 && CKP(CDRegisterCSystem)(&b) == 0 && CKP(CDRegisterCSystem)(&c) == 0 &&
           CKP(CDRegisterCSystem)(&d) == 0;
}
CHILD(ck_reg_cf2_protocol) {
    CC(CKP(CDRegisterCSystem) && CKP(KRBFXCF2));
    CC(reg3());
    BYTE k1[4] = { 1, 2, 3, 4 }, k2[4] = { 9, 8, 7, 6 }, out[8] = { 0 };
    BYTE p1[2] = { 'a', 'b' }, p2[3] = { 'x', 'y', 'z' };
    memset(&g, 0, sizeof g);
    NTSTATUS st = CKP(KRBFXCF2)(0x7e01, k1, 4, p1, 2, 0x7e02, k2, 4, p2, 3, out);
    CC(st == 0);
    CC(g.pa == 1 && g.pb == 1 && g.rk == 1);
    CC(g.ka == k1 && g.kla == 4 && g.sa == p1 && g.sla == 2 && g.olda == 4);
    CC(g.kb == k2 && g.klb == 4 && g.sb == p2 && g.slb == 3 && g.oldb == 4);
    CC(g.rkseed == g.outa && g.outa != g.outb);         /* the first PRF+ buffer receives the XOR and is the seed */
    CC(g.rklen == 4 && g.rkout == out);
    for (int i = 0; i < 4; i++) {
        BYTE a = (BYTE)(1 + 'a' + i), b = (BYTE)(9 * 3 + 'x' + i);
        CC(g.seed[i] == (BYTE)(a ^ b));
        CC(out[i] == (BYTE)((a ^ b) ^ 0xFF));
    }
    CC(out[4] == 0);
    return 0;
}
TEST(ckreg_cf2_calls_prfplus_twice_xors_then_randomkey) { CK_NEED(KRBFXCF2); RUN_CHILD("ck_reg_cf2_protocol"); }

CHILD(ck_reg_cf2_errors) {
    CC(CKP(CDRegisterCSystem) && CKP(KRBFXCF2));
    CC(reg3());
    BYTE k[6] = { 1, 2, 3, 4, 5, 6 }, p[1] = { 'p' }, out[8];
    memset(&g, 0, sizeof g);
    /* unknown systems */
    CC(CKP(KRBFXCF2)(0x7e99, k, 4, p, 1, 0x7e02, k, 4, p, 1, out) == NS_NO_CSYSTEM);
    CC(CKP(KRBFXCF2)(0x7e01, k, 4, p, 1, 0x7e99, k, 4, p, 1, out) == NS_NO_CSYSTEM);
    /* missing PRF+ on either system, or missing RandomKey on the first */
    CC(CKP(KRBFXCF2)(0x7e03, k, 4, p, 1, 0x7e02, k, 4, p, 1, out) == NS_NOT_SUPPORTED);
    CC(CKP(KRBFXCF2)(0x7e01, k, 4, p, 1, 0x7e03, k, 4, p, 1, out) == NS_NOT_SUPPORTED);
    CC(CKP(KRBFXCF2)(0x7e02, k, 4, p, 1, 0x7e01, k, 4, p, 1, out) == NS_NOT_SUPPORTED);
    CC(CKP(KRBFXCF2)(0x7e01, k, 4, p, 1, 0x7e02, k, 4, p, 1, out) == 0);   /* second system needs no RandomKey */
    /* the "not supported" check precedes the key length check */
    CC(CKP(KRBFXCF2)(0x7e03, k, 99, p, 1, 0x7e02, k, 4, p, 1, out) == NS_NOT_SUPPORTED);
    memset(&g, 0, sizeof g);
    /* key lengths must equal each system's KeySize, otherwise nothing is called */
    CC(CKP(KRBFXCF2)(0x7e01, k, 3, p, 1, 0x7e02, k, 4, p, 1, out) == NS_INVALID_PARAM);
    CC(CKP(KRBFXCF2)(0x7e01, k, 4, p, 1, 0x7e02, k, 5, p, 1, out) == NS_INVALID_PARAM);
    CC(CKP(KRBFXCF2)(0x7e01, k, 5, p, 1, 0x7e02, k, 4, p, 1, out) == NS_INVALID_PARAM);
    CC(g.pa == 0 && g.pb == 0 && g.rk == 0);
    /* systems with different key sizes: the output length follows the first system's key length */
    memset(&g, 0, sizeof g);
    CC(CKP(KRBFXCF2)(0x7e04, k, 6, p, 1, 0x7e01, k, 4, p, 1, out) == 0);
    CC(g.oldb == 6 && g.olda == 6 && g.rklen == 6);
    return 0;
}
TEST(ckreg_cf2_parameter_validation_order) { CK_NEED(KRBFXCF2); RUN_CHILD("ck_reg_cf2_errors"); }

CHILD(ck_reg_cf2_failure_propagation) {
    CC(CKP(CDRegisterCSystem) && CKP(KRBFXCF2));
    CC(reg3());
    BYTE k[4] = { 1, 2, 3, 4 }, p[1] = { 'p' }, out[4] = { 0xEE, 0xEE, 0xEE, 0xEE };
    memset(&g, 0, sizeof g); g.fail_a = (NTSTATUS)0xC0001234;
    CC(CKP(KRBFXCF2)(0x7e01, k, 4, p, 1, 0x7e02, k, 4, p, 1, out) == (NTSTATUS)0xC0001234);
    CC(g.pa == 1 && g.pb == 0 && g.rk == 0);
    memset(&g, 0, sizeof g); g.fail_b = (NTSTATUS)0xC0004321;
    CC(CKP(KRBFXCF2)(0x7e01, k, 4, p, 1, 0x7e02, k, 4, p, 1, out) == (NTSTATUS)0xC0004321);
    CC(g.pa == 1 && g.pb == 1 && g.rk == 0);
    memset(&g, 0, sizeof g); g.fail_r = (NTSTATUS)0xC0005678;
    CC(CKP(KRBFXCF2)(0x7e01, k, 4, p, 1, 0x7e02, k, 4, p, 1, out) == (NTSTATUS)0xC0005678);
    CC(g.pa == 1 && g.pb == 1 && g.rk == 1);
    CC(out[0] == 0xEE && out[1] == 0xEE);
    return 0;
}
TEST(ckreg_cf2_failure_status_propagates_and_short_circuits) { CK_NEED(KRBFXCF2); RUN_CHILD("ck_reg_cf2_failure_propagation"); }

/* ---- checksums ---- */
static struct { int init, initex, sum, fin, finish; PVOID ctxs; ULONG slen; PUCHAR sbuf; ULONG usage, keylen; PUCHAR key; } gc;
static NTSTATUS WINAPI c_init(ULONG seed, PVOID *ctx) { gc.init++; *ctx = (PVOID)(ULONG_PTR)0x77; return 0; }
static NTSTATUS WINAPI c_initex(PUCHAR key, ULONG kl, ULONG usage, PVOID *ctx) { gc.initex++; gc.key = key; gc.keylen = kl; gc.usage = usage; *ctx = (PVOID)(ULONG_PTR)0x78; return 0; }
static NTSTATUS WINAPI c_sum(PVOID ctx, ULONG len, PUCHAR buf) { gc.sum++; gc.ctxs = ctx; gc.slen = len; gc.sbuf = buf; return 0; }
static NTSTATUS WINAPI c_fin(PVOID ctx, PUCHAR out) { gc.fin++; memset(out, 0xA5, 5); return 0; }
static NTSTATUS WINAPI c_finish(PVOID *ctx) { gc.finish++; *ctx = NULL; return 0; }
static CKX mk_ck(LONG type, ULONG size) {
    CKX c; memset(&c, 0, sizeof c);
    c.Type = (ULONG)type; c.Size = size; c.Attributes = 0x11;
    c.Initialize = (void *)c_init; c.Sum = (void *)c_sum; c.Finalize = (void *)c_fin; c.Finish = (void *)c_finish; c.InitializeEx = (void *)c_initex;
    return c;
}
CHILD(ck_reg_ck_basic) {
    CC(CKP(CDRegisterCheckSum) && CKP(CDLocateCheckSum));
    CKX *p = NULL;
    CC(CKP(CDLocateCheckSum)(0x7e57, &p) == NS_NO_CHECKSUM);
    CKX m = mk_ck(0x7e57, 5);
    CC(CKP(CDRegisterCheckSum)(&m) == 0);
    CC(CKP(CDLocateCheckSum)(0x7e57, &p) == 0);
    CC(p != &m && memcmp(p, &m, sizeof m) == 0);
    BYTE out[16]; size_t ol = 0; BYTE data[3] = { 1, 2, 3 }, key[2] = { 9, 9 };
    memset(&gc, 0, sizeof gc);
    CC(ck_run_checksum(0x7e57, 0, NULL, 0, 0, data, 3, out, &ol) == 0);
    CC(gc.init == 1 && gc.sum == 1 && gc.fin == 1 && gc.finish == 1 && gc.initex == 0);
    CC(gc.ctxs == (PVOID)(ULONG_PTR)0x77 && gc.slen == 3 && gc.sbuf == data);
    CC(ol == 5 && out[0] == 0xA5 && out[4] == 0xA5);
    CC(ck_run_checksum(0x7e57, 1, key, 2, 42, data, 3, out, &ol) == 0);
    CC(gc.initex == 1 && gc.key == key && gc.keylen == 2 && gc.usage == 42 && gc.ctxs == (PVOID)(ULONG_PTR)0x78);
    return 0;
}
TEST(ckreg_checksum_register_and_dispatch) { CK_NEED(CDRegisterCheckSum); RUN_CHILD("ck_reg_ck_basic"); }

CHILD(ck_reg_ck_override) {
    CC(CKP(CDRegisterCheckSum) && CKP(CDLocateCheckSum));
    CKX *orig = NULL, *p = NULL;
    CC(CKP(CDLocateCheckSum)(CS_MD5, &orig) == 0 && orig->Size == 16);
    CKX m = mk_ck(CS_MD5, 5);
    CC(CKP(CDRegisterCheckSum)(&m) == 0);
    CC(CKP(CDLocateCheckSum)(CS_MD5, &p) == 0);
    CC(p != orig && p->Size == 5);                    /* checksum lookup scans from the newest entry backwards */
    CC(CKP(CDLocateCheckSum)(CS_MD4, &p) == 0 && p->Size == 16);
    return 0;
}
TEST(ckreg_checksum_duplicate_type_last_registration_wins) { CK_NEED(CDRegisterCheckSum); RUN_CHILD("ck_reg_ck_override"); }

CHILD(ck_reg_ck_capacity) {
    CC(CKP(CDRegisterCheckSum) && CKP(CDLocateCheckSum));
    for (int i = 0; i < 8; i++) { CKX m = mk_ck(0x7e00 + i, 4); CC(CKP(CDRegisterCheckSum)(&m) == 0); }
    CKX m = mk_ck(0x7e20, 4);
    CC(CKP(CDRegisterCheckSum)(&m) == NS_INSUFF_RES);
    CC(CKP(CDRegisterCheckSum)(&m) == NS_INSUFF_RES);
    CKX *p;
    CC(CKP(CDLocateCheckSum)(0x7e20, &p) == NS_NO_CHECKSUM);
    for (int i = 0; i < 8; i++) CC(CKP(CDLocateCheckSum)(0x7e00 + i, &p) == 0);
    CC(CKP(CDLocateCheckSum)(CS_MD5, &p) == 0);
    return 0;
}
TEST(ckreg_checksum_capacity_is_24_entries) { CK_NEED(CDRegisterCheckSum); RUN_CHILD("ck_reg_ck_capacity"); }

CHILD(ck_reg_ck_snapshot) {
    CC(CKP(CDRegisterCheckSum) && CKP(CDLocateCheckSum));
    CKX m = mk_ck(0x7e57, 5);
    CC(CKP(CDRegisterCheckSum)(&m) == 0);
    m.Size = 99; m.Type = 0x7e58;
    CKX *p; CC(CKP(CDLocateCheckSum)(0x7e57, &p) == 0 && p->Size == 5);
    CC(CKP(CDLocateCheckSum)(0x7e58, &p) == NS_NO_CHECKSUM);
    return 0;
}
TEST(ckreg_checksum_registration_copies_the_entry) { CK_NEED(CDRegisterCheckSum); RUN_CHILD("ck_reg_ck_snapshot"); }

CHILD(ck_reg_cs_uses_registered_checksum_for_aes_prf) {
    /* the AES PRF hashes through the registered SHA-1 checksum entry (-131): overriding it changes PRF+ output */
    CC(CKP(CDRegisterCheckSum) && CKP(CDLocateCSystem));
    CSX *c; CC(CKP(CDLocateCSystem)(ET_AES128, &c) == 0 && c->PrfPlus);
    BYTE key[16] = { 0 }, s[1] = { 'a' }, o1[16], o2[16];
    CC(((csx_prf_fn)c->PrfPlus)(key, 16, s, 1, o1, 16) == 0);
    CKX m = mk_ck(CS_SHA1, 20);
    memset(&gc, 0, sizeof gc);
    CC(CKP(CDRegisterCheckSum)(&m) == 0);
    NTSTATUS st = ((csx_prf_fn)c->PrfPlus)(key, 16, s, 1, o2, 16);
    CC(gc.initex == 1 && gc.sum == 1 && gc.fin == 1 && gc.finish == 1);   /* called through InitializeEx/Sum/Finalize/Finish */
    CC(gc.slen == 2);                                                      /* counter byte + pepper */
    (void)st;
    return 0;
}
TEST(ckreg_checksum_override_is_used_by_aes_prf) { CK_NEED(CDRegisterCheckSum); RUN_CHILD("ck_reg_cs_uses_registered_checksum_for_aes_prf"); }

/* ---- rng ---- */
static struct { int a, b; PUCHAR abuf, bbuf; ULONG alen, blen; BYTE bret; } gr;
static BOOLEAN WINAPI rng_a(PUCHAR buf, ULONG len) { gr.a++; gr.abuf = buf; gr.alen = len; memset(buf, 0xA5, len); return TRUE; }
static BOOLEAN WINAPI rng_b(PUCHAR buf, ULONG len) { gr.b++; gr.bbuf = buf; gr.blen = len; return gr.bret; }
CHILD(ck_reg_rng_basic) {
    CC(CKP(CDRegisterRng) && CKP(CDLocateRng) && CKP(CDGenerateRandomBits));
    RNX r = { 0x7e57, 0, (void *)0x5151, (void *)rng_a };
    RNX *p = NULL;
    CC(CKP(CDLocateRng)(0x7e57, &p) == FALSE && p == NULL);
    CC(CKP(CDRegisterRng)(&r) == TRUE);
    CC(CKP(CDLocateRng)(0x7e57, &p) == TRUE);
    CC(p != &r && p->Type == 0x7e57 && p->P1 == (void *)0x5151 && p->P2 == (void *)rng_a);
    BYTE buf[8] = { 0 };
    CC(CKP(CDGenerateRandomBits)(buf, 8) == TRUE);        /* the newest registration is the active generator */
    CC(gr.a == 1 && gr.abuf == buf && gr.alen == 8);
    for (int i = 0; i < 8; i++) CC(buf[i] == 0xA5);
    return 0;
}
TEST(ckreg_rng_register_and_generate_via_newest) { CK_NEED(CDRegisterRng); RUN_CHILD("ck_reg_rng_basic"); }

CHILD(ck_reg_rng_newest_wins_and_passthrough) {
    CC(CKP(CDRegisterRng) && CKP(CDGenerateRandomBits));
    RNX a = { 0x7e57, 0, NULL, (void *)rng_a }, b = { 0x7e58, 0, NULL, (void *)rng_b };
    CC(CKP(CDRegisterRng)(&a) == TRUE && CKP(CDRegisterRng)(&b) == TRUE);
    BYTE buf[4] = { 1, 2, 3, 4 };
    gr.bret = 0;
    CC(CKP(CDGenerateRandomBits)(buf, 4) == FALSE);        /* failure of the generator is returned unchanged */
    CC(gr.b == 1 && gr.a == 0 && gr.bbuf == buf && gr.blen == 4 && buf[0] == 1);
    gr.bret = 0x7f;
    CC(CKP(CDGenerateRandomBits)(buf, 4) == 0x7f);         /* the call is a tail jump: the generator's AL comes back */
    return 0;
}
TEST(ckreg_rng_newest_generator_result_passes_through) { CK_NEED(CDRegisterRng); RUN_CHILD("ck_reg_rng_newest_wins_and_passthrough"); }

CHILD(ck_reg_rng_capacity) {
    CC(CKP(CDRegisterRng) && CKP(CDLocateRng) && CKP(CDGenerateRandomBits));
    RNX r[5];
    for (int i = 0; i < 5; i++) { r[i].Type = 0x7e00 + i; r[i].Pad = 0; r[i].P1 = NULL; r[i].P2 = (void *)(i == 2 ? rng_a : rng_b); }
    gr.bret = 1;
    CC(CKP(CDRegisterRng)(&r[0]) == TRUE);
    CC(CKP(CDRegisterRng)(&r[1]) == TRUE);
    CC(CKP(CDRegisterRng)(&r[2]) == TRUE);
    CC(CKP(CDRegisterRng)(&r[3]) == FALSE);                /* four slots in total, one is taken by the default */
    CC(CKP(CDRegisterRng)(&r[4]) == FALSE);
    RNX *p;
    CC(CKP(CDLocateRng)(0x7e03, &p) == FALSE && p == NULL);
    CC(CKP(CDLocateRng)(0x7e02, &p) == TRUE);
    BYTE buf[3];
    CC(CKP(CDGenerateRandomBits)(buf, 3) == TRUE && gr.a == 1 && gr.b == 0);   /* generator #3 (r[2]) is the active one */
    return 0;
}
TEST(ckreg_rng_capacity_is_four_slots) { CK_NEED(CDRegisterRng); RUN_CHILD("ck_reg_rng_capacity"); }

CHILD(ck_reg_rng_duplicate_type) {
    CC(CKP(CDRegisterRng) && CKP(CDLocateRng) && CKP(CDGenerateRandomBits));
    RNX a = { 0x7e57, 0, NULL, (void *)rng_a }, b = { 0x7e57, 0, NULL, (void *)rng_b };
    gr.bret = 1;
    CC(CKP(CDRegisterRng)(&a) == TRUE && CKP(CDRegisterRng)(&b) == TRUE);
    RNX *p; CC(CKP(CDLocateRng)(0x7e57, &p) == TRUE);
    CC(p->P2 == (void *)rng_a);                            /* locate scans from the first slot, unlike the crypto-system lookup */
    BYTE buf[2];
    CC(CKP(CDGenerateRandomBits)(buf, 2) == TRUE && gr.b == 1 && gr.a == 0);   /* generate uses the newest */
    return 0;
}
TEST(ckreg_rng_duplicate_type_locate_first_generate_last) { CK_NEED(CDRegisterRng); RUN_CHILD("ck_reg_rng_duplicate_type"); }

CHILD(ck_reg_rng_snapshot) {
    CC(CKP(CDRegisterRng) && CKP(CDLocateRng));
    RNX a = { 0x7e57, 0, (void *)0x11, (void *)rng_a };
    CC(CKP(CDRegisterRng)(&a) == TRUE);
    a.Type = 0x7e58; a.P1 = NULL;
    RNX *p; CC(CKP(CDLocateRng)(0x7e57, &p) == TRUE && p->P1 == (void *)0x11);
    CC(CKP(CDLocateRng)(0x7e58, &p) == FALSE);
    return 0;
}
TEST(ckreg_rng_registration_copies_the_entry) { CK_NEED(CDRegisterRng); RUN_CHILD("ck_reg_rng_snapshot"); }

CHILD(ck_reg_rng_used_by_random_key) {
    /* the DES / AES / RC4 RandomKey(seed length 0) paths draw their randomness from the active generator */
    CC(CKP(CDRegisterRng) && CKP(CDLocateCSystem));
    RNX a = { 0x7e57, 0, NULL, (void *)rng_a };
    CC(CKP(CDRegisterRng)(&a) == TRUE);
    CSX *c;
    BYTE key[32];
    gr.a = 0;
    CC(CKP(CDLocateCSystem)(ET_AES128, &c) == 0);
    memset(key, 0, sizeof key);
    NTSTATUS st = ((csx_rndkey_fn)c->RandomKey)(NULL, 0, key);
    CC(st == 0);
    int hit128 = gr.a;
    for (int i = 0; i < 16; i++) CC(key[i] == 0xA5);
    CC(CKP(CDLocateCSystem)(ET_AES256, &c) == 0);
    CC(((csx_rndkey_fn)c->RandomKey)(NULL, 0, key) == 0);
    for (int i = 0; i < 32; i++) CC(key[i] == 0xA5);
    CC(CKP(CDLocateCSystem)(ET_RC4_HMAC, &c) == 0);
    memset(key, 0, sizeof key);
    CC(((csx_rndkey_fn)c->RandomKey)(NULL, 0, key) == 0);
    for (int i = 0; i < 16; i++) CC(key[i] == 0xA5);
    CC(CKP(CDLocateCSystem)(ET_RC4_MD4, &c) == 0);
    memset(key, 0, sizeof key);
    CC(((csx_rndkey_fn)c->RandomKey)(NULL, 0, key) == 0);
    for (int i = 0; i < 5; i++) CC(key[i] == 0xA5);                /* 40 random bits ... */
    for (int i = 5; i < 16; i++) CC(key[i] == 0xAB);               /* ... padded with 0xAB */
    return hit128 == 1 ? 0 : 1;
}
TEST(ckreg_rng_replacement_feeds_random_key_generation) { CK_NEED(CDRegisterRng); RUN_CHILD("ck_reg_rng_used_by_random_key"); }

CHILD(ck_reg_rng_failure_reported_by_random_key) {
    CC(CKP(CDRegisterRng) && CKP(CDLocateCSystem));
    RNX b = { 0x7e57, 0, NULL, (void *)rng_b };
    gr.bret = 0;
    CC(CKP(CDRegisterRng)(&b) == TRUE);
    CSX *c; BYTE key[32];
    CC(CKP(CDLocateCSystem)(ET_RC4_HMAC, &c) == 0);
    CC(((csx_rndkey_fn)c->RandomKey)(NULL, 0, key) == (NTSTATUS)0xC00000E5);   /* STATUS_INTERNAL_ERROR */
    CC(CKP(CDLocateCSystem)(ET_DES_MD5, &c) == 0);
    CC(((csx_rndkey_fn)c->RandomKey)(NULL, 0, key) == (NTSTATUS)0xC00000E5);
    CC(CKP(CDLocateCSystem)(ET_RC4_MD4, &c) == 0);
    CC(((csx_rndkey_fn)c->RandomKey)(NULL, 0, key) == (NTSTATUS)0xC00000E5);
    /* the AES RandomKey routines ignore the generator's result and always report success */
    CC(CKP(CDLocateCSystem)(ET_AES128, &c) == 0);
    CC(((csx_rndkey_fn)c->RandomKey)(NULL, 0, key) == 0);
    CC(CKP(CDLocateCSystem)(ET_AES256, &c) == 0);
    CC(((csx_rndkey_fn)c->RandomKey)(NULL, 0, key) == 0);
    return 0;
}
TEST(ckreg_rng_failure_maps_to_internal_error_in_random_key) { CK_NEED(CDRegisterRng); RUN_CHILD("ck_reg_rng_failure_reported_by_random_key"); }

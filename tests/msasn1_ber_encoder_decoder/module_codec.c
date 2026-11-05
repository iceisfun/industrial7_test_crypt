/* msasn1.dll: module / encoder / decoder object lifecycle, ASN1_Encode / ASN1_Decode, options. */
#include "asn1t.h"

#define MAGIC_ENC 0x44434e45u   /* "ENCD" */
#define MAGIC_DEC 0x44434544u   /* "DECD" */

/* ---------------------------------------------------------------- ASN1_CreateModule */
TEST(mc_createmodule_null_tables) {
    REQUIRE(A.ASN1_CreateModule); NEED(ASN1_CloseModule);
    static const void *tab[1] = { NULL };
    static const DWORD sz[1] = { 4 };
    CHECK(A.ASN1_CreateModule(0x10000, R_DER, 0, 1, NULL, tab, tab, sz, 1) == NULL);
    CHECK(A.ASN1_CreateModule(0x10000, R_DER, 0, 1, tab, NULL, tab, sz, 1) == NULL);
    CHECK(A.ASN1_CreateModule(0x10000, R_DER, 0, 1, tab, tab, NULL, sz, 1) == NULL);
    CHECK(A.ASN1_CreateModule(0x10000, R_DER, 0, 1, tab, tab, tab, NULL, 1) == NULL);
    CHECK(A.ASN1_CreateModule(0, 0, 0, 0, NULL, NULL, NULL, NULL, 0) == NULL);
}
TEST(mc_createmodule_fields_der) {
    REQUIRE(A.ASN1_CreateModule); NEED(ASN1_CloseModule);
    static const void *e[2] = { NULL, NULL }, *d[2] = { NULL, NULL }, *f[2] = { NULL, NULL };
    static const DWORD sz[2] = { 4, 8 };
    MOD *m = A.ASN1_CreateModule(0x10000, R_DER, FLG_NOASSERT, 2, e, d, f, sz, 0x61736e31);
    CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(m->name, 0x61736e31); EXPECT_EQ(m->rule, R_DER); EXPECT_EQ(m->flags, FLG_NOASSERT); EXPECT_EQ(m->cPDUs, 2);
    CHECK(m->freefn == f); CHECK(m->sizes == sz); CHECK(m->encfn == e); CHECK(m->decfn == d);
    A.ASN1_CloseModule(m);
}
TEST(mc_createmodule_each_ber_rule_stores_tables) {
    REQUIRE(A.ASN1_CreateModule); NEED(ASN1_CloseModule);
    static const void *e[1] = { NULL }, *d[1] = { NULL }, *f[1] = { NULL };
    static const DWORD sz[1] = { 4 };
    static const int rules[] = { R_BER, R_CER, R_DER, R_BER | R_DER };
    for (int i = 0; i < 4; i++) {
        MOD *m = A.ASN1_CreateModule(0x10000, rules[i], 0, 1, e, d, f, sz, 7);
        CHECK(m != NULL); if (!m) continue;
        EXPECT_EQ(m->rule, rules[i]); CHECK(m->encfn == e); CHECK(m->decfn == d);
        A.ASN1_CloseModule(m);
    }
}
TEST(mc_createmodule_per_rule_does_not_store_coders) {
    /* The encoder/decoder tables are only recorded when a BER-family rule bit (0x700) is set. */
    REQUIRE(A.ASN1_CreateModule); NEED(ASN1_CloseModule);
    static const void *e[1] = { NULL }, *d[1] = { NULL }, *f[1] = { NULL };
    static const DWORD sz[1] = { 4 };
    static const int rules[] = { R_PER_ALIGNED, R_PER_UNALIGNED, 0 };
    for (int i = 0; i < 3; i++) {
        MOD *m = A.ASN1_CreateModule(0x10000, rules[i], 0, 1, e, d, f, sz, 7);
        CHECK(m != NULL); if (!m) continue;
        EXPECT_EQ(m->rule, rules[i]); CHECK(m->freefn == f); CHECK(m->sizes == sz);
        if (!t_is_wine()) { CHECK(m->encfn == NULL); CHECK(m->decfn == NULL); }
        A.ASN1_CloseModule(m);
    }
}
TEST(mc_createmodule_version_argument_ignored) {
    REQUIRE(A.ASN1_CreateModule); NEED(ASN1_CloseModule);
    static const void *e[1] = { NULL }, *d[1] = { NULL }, *f[1] = { NULL };
    static const DWORD sz[1] = { 4 };
    static const DWORD vers[] = { 0, 0x10000, 0x20005, 0xdeadbeef };
    for (int i = 0; i < 4; i++) {
        MOD *m = A.ASN1_CreateModule(vers[i], R_DER, 0, 1, e, d, f, sz, 9);
        CHECK(m != NULL); if (!m) continue;
        EXPECT_EQ(m->name, 9); EXPECT_EQ(m->rule, R_DER); EXPECT_EQ(m->cPDUs, 1);
        A.ASN1_CloseModule(m);
    }
}
TEST(mc_createmodule_zero_pdus_ok) {
    REQUIRE(A.ASN1_CreateModule); NEED(ASN1_CloseModule);
    static const void *e[1] = { NULL }, *d[1] = { NULL }, *f[1] = { NULL };
    static const DWORD sz[1] = { 0 };
    MOD *m = A.ASN1_CreateModule(0, 0, 0, 0, e, d, f, sz, 0);
    CHECK(m != NULL);
    if (m) { EXPECT_EQ(m->cPDUs, 0); EXPECT_EQ(m->name, 0); A.ASN1_CloseModule(m); }
}
TEST(mc_closemodule_null_is_harmless) {
    NEED(ASN1_CloseModule);
    A.ASN1_CloseModule(NULL);
    CHECK(1);
}

/* ---------------------------------------------------------------- ASN1_CreateEncoder */
TEST(mc_createencoder_badargs) {
    REQUIRE(A.ASN1_CreateEncoder); NEED(ASN1_CreateModule);
    ENC *e = (ENC *)(ULONG_PTR)0x1234;
    EXPECT_EQ(A.ASN1_CreateEncoder(NULL, &e, NULL, 0, NULL), E_BADARGS);
    CHECK(e == (ENC *)(ULONG_PTR)0x1234);       /* untouched when the module is NULL */
    MOD *m = rig_module(R_DER, 0); CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateEncoder(m, NULL, NULL, 0, NULL), E_BADARGS);
    A.ASN1_CloseModule(m);
}
TEST(mc_createencoder_fields_default) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    ENC *e = r.e;
    EXPECT_EQ(e->magic, MAGIC_ENC); EXPECT_EQ(e->version, 0); CHECK(e->module == r.m);
    CHECK(e->buf == NULL); EXPECT_EQ(e->size, 0); EXPECT_EQ(e->len, 0); EXPECT_EQ(e->err, 0); EXPECT_EQ(e->bit, 0);
    CHECK(e->pos == NULL); EXPECT_EQ(e->cbExtra, 0); EXPECT_EQ(e->rule, R_DER); EXPECT_EQ(e->flags, 0);
    CHECK(e->parent == e); CHECK(e->child == NULL);
    rig_done(&r);
}
TEST(mc_createencoder_rule_comes_from_module) {
    NEED(ASN1_CreateEncoder); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    static const int rules[] = { R_BER, R_CER, R_DER, R_PER_ALIGNED };
    for (int i = 0; i < 4; i++) {
        MOD *m = rig_module(rules[i], 0); ENC *e = NULL;
        CHECK(m != NULL); if (!m) continue;
        EXPECT_EQ(A.ASN1_CreateEncoder(m, &e, NULL, 0, NULL), 0);
        CHECK(e != NULL);
        if (e) { EXPECT_EQ(e->rule, rules[i]); A.ASN1_CloseEncoder(e); }
        A.ASN1_CloseModule(m);
    }
}
TEST(mc_createencoder_module_flags_inherited) {
    NEED(ASN1_CreateEncoder); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, FLG_NOASSERT); ENC *e = NULL;
    CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateEncoder(m, &e, NULL, 0, NULL), 0);
    CHECK(e != NULL);
    if (e) { EXPECT_EQ(e->flags, FLG_NOASSERT); A.ASN1_CloseEncoder(e); }
    A.ASN1_CloseModule(m);
}
TEST(mc_createencoder_buffer_requires_nonzero_size) {
    NEED(ASN1_CreateEncoder); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, 0); ENC *e = NULL; BYTE buf[8];
    CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateEncoder(m, &e, buf, 0, NULL), 0);
    CHECK(e != NULL);
    if (e) { CHECK(e->buf == NULL); EXPECT_EQ(e->size, 0); CHECK(e->pos == NULL); EXPECT_EQ(e->flags & 8, 0); A.ASN1_CloseEncoder(e); }
    e = NULL;
    EXPECT_EQ(A.ASN1_CreateEncoder(m, &e, NULL, 8, NULL), 0);   /* size without buffer */
    CHECK(e != NULL);
    if (e) { CHECK(e->buf == NULL); EXPECT_EQ(e->size, 0); EXPECT_EQ(e->flags & 8, 0); A.ASN1_CloseEncoder(e); }
    A.ASN1_CloseModule(m);
}
TEST(mc_createencoder_with_buffer) {
    NEED(ASN1_CreateEncoder); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, FLG_NOASSERT); ENC *e = NULL; BYTE buf[16];
    CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateEncoder(m, &e, buf, sizeof buf, NULL), 0);
    CHECK(e != NULL);
    if (e) {
        CHECK(e->buf == buf); CHECK(e->pos == buf); EXPECT_EQ(e->size, sizeof buf); EXPECT_EQ(e->len, 0);
        EXPECT_EQ(e->flags, FLG_NOASSERT | 8);
        A.ASN1_CloseEncoder(e);
    }
    A.ASN1_CloseModule(m);
}
TEST(mc_closeencoder_null_variants) {
    NEED(ASN1_CloseEncoder); NEED(ASN1_CloseEncoder2);
    A.ASN1_CloseEncoder(NULL);
    A.ASN1_CloseEncoder2(NULL);
    CHECK(1);
}

/* ---------------------------------------------------------------- ASN1_CreateDecoder(Ex) */
TEST(mc_createdecoder_badargs) {
    REQUIRE(A.ASN1_CreateDecoder); NEED(ASN1_CreateModule);
    DEC *d = (DEC *)(ULONG_PTR)0x1234;
    EXPECT_EQ(A.ASN1_CreateDecoder(NULL, &d, NULL, 0, NULL), E_BADARGS);
    CHECK(d == (DEC *)(ULONG_PTR)0x1234);
    MOD *m = rig_module(R_DER, 0); CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateDecoder(m, NULL, NULL, 0, NULL), E_BADARGS);
    A.ASN1_CloseModule(m);
}
TEST(mc_createdecoder_fields_default) {
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    DEC *d = r.d;
    EXPECT_EQ(d->magic, MAGIC_DEC); EXPECT_EQ(d->version, 0); CHECK(d->module == r.m);
    CHECK(d->buf == NULL); EXPECT_EQ(d->size, 0); EXPECT_EQ(d->len, 0); EXPECT_EQ(d->err, 0); EXPECT_EQ(d->bit, 0);
    CHECK(d->pos == NULL); EXPECT_EQ(d->rule, R_DER); EXPECT_EQ(d->flags, 0);
    CHECK(d->parent == d); CHECK(d->child == NULL); EXPECT_EQ(d->level, 0); EXPECT_EQ(d->usesbuf, 0);
    rig_done(&r);
}
TEST(mc_createdecoder_with_buffer) {
    static BYTE buf[4] = { 2, 1, 5, 0 };
    Rig r; if (!rig_dec(&r, R_BER, buf, 3)) return;
    DEC *d = r.d;
    CHECK(d->buf == buf); CHECK(d->pos == buf); EXPECT_EQ(d->size, 3); EXPECT_EQ(d->flags, 8); EXPECT_EQ(d->rule, R_BER);
    rig_done(&r);
}
TEST(mc_createdecoder_zero_size_buffer_still_set) {
    /* unlike the encoder, a non-NULL buffer with size 0 is accepted by the decoder */
    static BYTE buf[2];
    Rig r; if (!rig_dec(&r, R_DER, buf, 0)) return;
    CHECK(r.d->buf == buf); EXPECT_EQ(r.d->size, 0); EXPECT_EQ(r.d->flags & 8, 8);
    rig_done(&r);
}
TEST(mc_createdecoder_module_flags_inherited) {
    NEED(ASN1_CreateDecoder); NEED(ASN1_CloseDecoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, FLG_NOASSERT); DEC *d = NULL;
    CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateDecoder(m, &d, NULL, 0, NULL), 0);
    CHECK(d != NULL);
    if (d) { EXPECT_EQ(d->flags, FLG_NOASSERT); A.ASN1_CloseDecoder(d); }
    A.ASN1_CloseModule(m);
}
TEST(mc_createdecoderex_autofree_flag) {
    NEED(ASN1_CreateDecoderEx); NEED(ASN1_CloseDecoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, 0); DEC *d = NULL;
    CHECK(m != NULL); if (!m) return;
    BYTE *heap = LocalAlloc(LPTR, 16);       /* released by ASN1_CloseDecoder when the autofree bit is recorded */
    CHECK(heap != NULL); if (!heap) { A.ASN1_CloseModule(m); return; }
    EXPECT_EQ(A.ASN1_CreateDecoderEx(m, &d, heap, 16, NULL, DEC_AUTOFREE), 0);
    CHECK(d != NULL);
    if (d) {
        EXPECT_EQ(d->flags, 8 | 0x10); CHECK(d->buf == heap);
        A.ASN1_CloseDecoder(d);              /* frees heap */
    } else LocalFree(heap);
    /* without a buffer the autofree request is dropped */
    d = NULL;
    EXPECT_EQ(A.ASN1_CreateDecoderEx(m, &d, NULL, 0, NULL, DEC_AUTOFREE), 0);
    CHECK(d != NULL);
    if (d) { EXPECT_EQ(d->flags & 0x18, 0); A.ASN1_CloseDecoder(d); }
    /* the plain CreateDecoder never requests it */
    static BYTE sb[4]; d = NULL;
    EXPECT_EQ(A.ASN1_CreateDecoder(m, &d, sb, 4, NULL), 0);
    if (d) { EXPECT_EQ(d->flags & 0x18, 8); A.ASN1_CloseDecoder(d); }
    A.ASN1_CloseModule(m);
}
TEST(mc_createdecoderex_badargs) {
    REQUIRE(A.ASN1_CreateDecoderEx);
    DEC *d = NULL;
    EXPECT_EQ(A.ASN1_CreateDecoderEx(NULL, &d, NULL, 0, NULL, 0), E_BADARGS);
}
TEST(mc_closedecoder_null) {
    NEED(ASN1_CloseDecoder);
    A.ASN1_CloseDecoder(NULL);
    CHECK(1);
}

/* ---------------------------------------------------------------- ASN1_Encode */
static void enc_seq2(Rig *r, DWORD id, const BYTE *os, DWORD n, DWORD flags, int *rc)
{
    struct { DWORD id; DWORD pad; LV os; } s;
    s.id = id; s.pad = 0; s.os.length = n; s.os.value = (BYTE *)os;
    *rc = A.ASN1_Encode(r->e, &s, 2, flags, NULL, 0);
}
TEST(mc_encode_null_encoder) {
    REQUIRE(A.ASN1_Encode);
    DWORD v = 5;
    EXPECT_EQ(A.ASN1_Encode(NULL, &v, 0, ENC_ALLOC, NULL, 0), E_BADARGS);
}
TEST(mc_encode_pdu0_allocated) {
    NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5; static const BYTE want[] = { 2, 1, 5 };
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_ALLOC, NULL, 0), 0);
    CHECK(r.e->buf != NULL); EXPECT_EQ(r.e->len, 3); EXPECT_EQ(r.e->err, 0);
    EXPECT_BYTES(r.e->buf, r.e->len, want, 3);
    A.ASN1_FreeEncoded(r.e, r.e->buf); r.e->buf = NULL;
    rig_done(&r);
}
static const struct { DWORD v; BYTE b[8]; DWORD n; } k_u32[] = {
    { 0, { 2, 1, 0 }, 3 }, { 127, { 2, 1, 0x7f }, 3 }, { 128, { 2, 2, 0, 0x80 }, 4 }, { 255, { 2, 2, 0, 0xff }, 4 },
    { 256, { 2, 2, 1, 0 }, 4 }, { 0x7fff, { 2, 2, 0x7f, 0xff }, 4 }, { 0x8000, { 2, 3, 0, 0x80, 0 }, 5 },
    { 0x7fffff, { 2, 3, 0x7f, 0xff, 0xff }, 5 }, { 0x800000, { 2, 4, 0, 0x80, 0, 0 }, 6 },
    { 0x7fffffff, { 2, 4, 0x7f, 0xff, 0xff, 0xff }, 6 }, { 0x80000000, { 2, 5, 0, 0x80, 0, 0, 0 }, 7 },
    { 0xffffffff, { 2, 5, 0, 0xff, 0xff, 0xff, 0xff }, 7 },
};
TEST(mc_encode_pdu0_table) {
    NEED(ASN1_FreeEncoded);
    for (unsigned i = 0; i < sizeof k_u32 / sizeof k_u32[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        DWORD v = k_u32[i].v;
        EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_ALLOC, NULL, 0), 0);
        EXPECT_BYTES(r.e->buf, r.e->len, k_u32[i].b, k_u32[i].n);
        A.ASN1_FreeEncoded(r.e, r.e->buf); r.e->buf = NULL;
        rig_done(&r);
    }
}
TEST(mc_encode_pdu_out_of_range) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5;
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 4, ENC_ALLOC, NULL, 0), E_BADPDU);
    EXPECT_EQ(r.e->err, E_BADPDU);
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0xffffffff, ENC_ALLOC, NULL, 0), E_BADPDU);
    rig_done(&r);
}
TEST(mc_encode_pdu_without_encoder) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5;
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 3, ENC_ALLOC, NULL, 0), E_BADPDU);     /* NULL slot in the table */
    rig_done(&r);
}
TEST(mc_encode_stub_failure_maps_to_corrupt) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5;
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 1, ENC_ALLOC, NULL, 0), E_CORRUPT);
    EXPECT_EQ(r.e->err, E_CORRUPT);
    rig_done(&r);
}
TEST(mc_encode_per_module_rule_error) {
    NEED(ASN1_CreateEncoder); NEED(ASN1_Encode); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_PER_ALIGNED, 0); ENC *e = NULL; DWORD v = 5;
    CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateEncoder(m, &e, NULL, 0, NULL), 0);
    if (e) {
        EXPECT_EQ(A.ASN1_Encode(e, &v, 0, ENC_ALLOC, NULL, 0), E_RULE);
        A.ASN1_CloseEncoder(e);
    }
    A.ASN1_CloseModule(m);
}
TEST(mc_encode_clears_previous_error) {
    NEED(ASN1EncSetError); NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5;
    EXPECT_EQ(A.ASN1EncSetError(r.e, E_CORRUPT), E_CORRUPT);
    EXPECT_EQ(r.e->err, E_CORRUPT);
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_ALLOC, NULL, 0), 0);
    EXPECT_EQ(r.e->err, 0);
    A.ASN1_FreeEncoded(r.e, r.e->buf); r.e->buf = NULL;
    rig_done(&r);
}
TEST(mc_encode_setbuffer_exact_fit) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5; BYTE out[3] = { 0xee, 0xee, 0xee }; static const BYTE want[] = { 2, 1, 5 };
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_SETBUFFER, out, sizeof out), 0);
    CHECK(r.e->buf == out); EXPECT_EQ(r.e->len, 3);
    EXPECT_BYTES(out, 3, want, 3);
    rig_done(&r);
}
TEST(mc_encode_setbuffer_too_small_overflows) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5; BYTE out[2];
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_SETBUFFER, out, sizeof out), E_OVERFLOW);
    EXPECT_EQ(r.e->err, E_OVERFLOW);
    rig_done(&r);
}
TEST(mc_encode_setbuffer_tail_untouched) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5; BYTE out[8]; memset(out, 0xcc, sizeof out);
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_SETBUFFER, out, sizeof out), 0);
    EXPECT_EQ(r.e->len, 3);
    for (int i = 3; i < 8; i++) EXPECT_EQ(out[i], 0xcc);
    rig_done(&r);
}
TEST(mc_encode_setbuffer_overrides_existing_buffer) {
    NEED(ASN1_CreateEncoder); NEED(ASN1_Encode); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, 0); ENC *e = NULL; BYTE a[8], b[8]; DWORD v = 9;
    CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateEncoder(m, &e, a, sizeof a, NULL), 0);
    if (e) {
        EXPECT_EQ(A.ASN1_Encode(e, &v, 0, ENC_SETBUFFER, b, sizeof b), 0);
        CHECK(e->buf == b); EXPECT_EQ(e->len, 3); EXPECT_EQ(b[2], 9);
        A.ASN1_CloseEncoder(e);
    }
    A.ASN1_CloseModule(m);
}
TEST(mc_encode_encoder_owned_buffer_reused) {
    /* without ALLOCATEBUFFER the encoder keeps using the buffer it allocated: a second call rewinds it */
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5, w = 7; static const BYTE want[] = { 2, 1, 7 };
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, 0, NULL, 0), 0);
    BYTE *first = r.e->buf; CHECK(first != NULL); EXPECT_EQ(r.e->len, 3);
    EXPECT_EQ(A.ASN1_Encode(r.e, &w, 0, 0, NULL, 0), 0);
    CHECK(r.e->buf == first); EXPECT_EQ(r.e->len, 3);
    EXPECT_BYTES(r.e->buf, 3, want, 3);
    rig_done(&r);
}
TEST(mc_encode_append_continues_after_previous_output) {
    NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5, w = 6; static const BYTE want[] = { 2, 1, 5, 2, 1, 6 };
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_ALLOC, NULL, 0), 0);
    EXPECT_EQ(A.ASN1_Encode(r.e, &w, 0, ENC_APPEND, NULL, 0), 0);
    EXPECT_EQ(r.e->len, 6);
    EXPECT_BYTES(r.e->buf, r.e->len, want, 6);
    A.ASN1_FreeEncoded(r.e, r.e->buf); r.e->buf = NULL;
    rig_done(&r);
}
TEST(mc_encode_reuse_overrides_append) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5, w = 6; static const BYTE want[] = { 2, 1, 6 };
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_ALLOC, NULL, 0), 0);
    EXPECT_EQ(A.ASN1_Encode(r.e, &w, 0, ENC_APPEND | ENC_REUSE, NULL, 0), 0);
    EXPECT_EQ(r.e->len, 3);
    EXPECT_BYTES(r.e->buf, r.e->len, want, 3);
    rig_done(&r);
}
TEST(mc_encode_alloc_gives_a_fresh_buffer_each_call) {
    NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5, w = 6; static const BYTE w1[] = { 2, 1, 5 }, w2[] = { 2, 1, 6 };
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, ENC_ALLOC, NULL, 0), 0);
    BYTE *p1 = r.e->buf; EXPECT_BYTES(p1, 3, w1, 3);
    A.ASN1_FreeEncoded(r.e, p1);                    /* the caller owns the output of an ALLOCATEBUFFER encode */
    EXPECT_EQ(A.ASN1_Encode(r.e, &w, 0, ENC_ALLOC, NULL, 0), 0);
    EXPECT_BYTES(r.e->buf, r.e->len, w2, 3);
    A.ASN1_FreeEncoded(r.e, r.e->buf); r.e->buf = NULL;
    rig_done(&r);
}
TEST(mc_encode_sequence_short) {
    NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    static const BYTE os[] = { 'a', 'b', 'c' };
    static const BYTE want[] = { 0x30, 8, 2, 1, 1, 4, 3, 'a', 'b', 'c' };
    int rc; enc_seq2(&r, 1, os, 3, ENC_ALLOC, &rc);
    EXPECT_EQ(rc, 0); EXPECT_BYTES(r.e->buf, r.e->len, want, sizeof want);
    A.ASN1_FreeEncoded(r.e, r.e->buf); r.e->buf = NULL;
    rig_done(&r);
}
TEST(mc_encode_sequence_long_length_form) {
    NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    BYTE os[200]; for (int i = 0; i < 200; i++) os[i] = (BYTE)i;
    int rc; enc_seq2(&r, 1, os, 200, ENC_ALLOC, &rc);
    EXPECT_EQ(rc, 0);
    /* content = 3 (INTEGER) + 3 (OCTET STRING header 04 81 C8) + 200 = 206 = 0xCE */
    BYTE want[2 + 1 + 3 + 3 + 200] = { 0x30, 0x81, 0xce, 2, 1, 1, 4, 0x81, 200 };
    memcpy(want + 9, os, 200);
    EXPECT_BYTES(r.e->buf, r.e->len, want, sizeof want);
    A.ASN1_FreeEncoded(r.e, r.e->buf); r.e->buf = NULL;
    rig_done(&r);
}
TEST(mc_encode_sequence_two_byte_length_form) {
    NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    BYTE *os = malloc(300); memset(os, 0x5a, 300);
    int rc; enc_seq2(&r, 0x12345, os, 300, ENC_ALLOC, &rc);
    EXPECT_EQ(rc, 0);
    /* INTEGER 02 03 01 23 45 (5) + OCTET 04 82 01 2C (4) + 300 = 309 = 0x135 -> 30 82 01 35 */
    static const BYTE head[] = { 0x30, 0x82, 0x01, 0x35, 2, 3, 0x01, 0x23, 0x45, 4, 0x82, 0x01, 0x2c };
    EXPECT_EQ(r.e->len, 4 + 309);
    EXPECT_BYTES(r.e->buf, sizeof head, head, sizeof head);
    CHECK(memcmp(r.e->buf + sizeof head, os, 300) == 0);
    A.ASN1_FreeEncoded(r.e, r.e->buf); r.e->buf = NULL;
    free(os);
    rig_done(&r);
}
TEST(mc_encode_failure_with_alloc_releases_buffer) {
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5;
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 1, ENC_ALLOC, NULL, 0), E_CORRUPT);
    CHECK(r.e->buf == NULL); EXPECT_EQ(r.e->size, 0);          /* buffer dropped when the encode failed */
    rig_done(&r);
}

/* ---------------------------------------------------------------- ASN1_Decode */
TEST(mc_decode_badargs) {
    REQUIRE(A.ASN1_Decode);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    void *out = (void *)(ULONG_PTR)0x1111;
    EXPECT_EQ(A.ASN1_Decode(NULL, &out, 0, 0, NULL, 0), E_BADARGS);
    CHECK(out == NULL);                                          /* the output slot is cleared */
    EXPECT_EQ(A.ASN1_Decode(r.d, NULL, 0, 0, NULL, 0), E_BADARGS);
    EXPECT_EQ(A.ASN1_Decode(NULL, NULL, 0, 0, NULL, 0), E_BADARGS);
    rig_done(&r);
}
TEST(mc_decode_pdu0) {
    NEED(ASN1_FreeDecoded);
    static const BYTE in[] = { 2, 1, 5 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DWORD *v = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&v, 0, 0, NULL, 0), 0);
    CHECK(v != NULL); if (v) EXPECT_EQ(*v, 5);
    EXPECT_EQ(r.d->len, 3); EXPECT_EQ(r.d->err, 0);
    A.ASN1_FreeDecoded(r.d, v, 0);
    rig_done(&r);
}
static const struct { BYTE b[8]; DWORD n; DWORD v; } k_dec_u32[] = {
    { { 2, 1, 0 }, 3, 0 }, { { 2, 1, 0x7f }, 3, 127 }, { { 2, 2, 0, 0x80 }, 4, 128 }, { { 2, 2, 1, 0 }, 4, 256 },
    { { 2, 3, 0, 0x80, 0 }, 5, 0x8000 }, { { 2, 4, 0x7f, 0xff, 0xff, 0xff }, 6, 0x7fffffff },
    { { 2, 5, 0, 0xff, 0xff, 0xff, 0xff }, 7, 0xffffffff }, { { 2, 4, 0xde, 0xad, 0xbe, 0xef }, 6, 0xdeadbeef },
};
TEST(mc_decode_pdu0_table) {
    NEED(ASN1_FreeDecoded);
    for (unsigned i = 0; i < sizeof k_dec_u32 / sizeof k_dec_u32[0]; i++) {
        Rig r; if (!rig_dec(&r, R_DER, k_dec_u32[i].b, k_dec_u32[i].n)) return;
        DWORD *v = NULL;
        EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&v, 0, 0, NULL, 0), 0);
        CHECK(v != NULL); if (v) EXPECT_EQ(*v, k_dec_u32[i].v);
        A.ASN1_FreeDecoded(r.d, v, 0);
        rig_done(&r);
    }
}
TEST(mc_decode_trailing_data_is_a_warning) {
    NEED(ASN1_FreeDecoded);
    static const BYTE in[] = { 2, 1, 5, 0, 0 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DWORD *v = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&v, 0, 0, NULL, 0), W_NOEOD);
    CHECK(v != NULL); if (v) EXPECT_EQ(*v, 5);                  /* output is still delivered */
    EXPECT_EQ(r.d->len, 3); EXPECT_EQ(r.d->err, W_NOEOD);
    A.ASN1_FreeDecoded(r.d, v, 0);
    rig_done(&r);
}
TEST(mc_decode_truncated_content) {
    static const BYTE in[] = { 2, 2, 5 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DWORD *v = (DWORD *)(ULONG_PTR)1;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&v, 0, 0, NULL, 0), E_EOD);
    CHECK(v == NULL); EXPECT_EQ(r.d->err, E_EOD);
    rig_done(&r);
}
TEST(mc_decode_wrong_tag) {
    static const BYTE in[] = { 4, 1, 5 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DWORD *v = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&v, 0, 0, NULL, 0), E_BADTAG);
    CHECK(v == NULL);
    rig_done(&r);
}
TEST(mc_decode_empty_input) {
    static BYTE in[1];
    Rig r; if (!rig_dec(&r, R_DER, in, 0)) return;
    DWORD *v = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&v, 0, 0, NULL, 0), E_EOD);
    CHECK(v == NULL);
    rig_done(&r);
}
TEST(mc_decode_pdu_range_and_missing_decoder) {
    static const BYTE in[] = { 2, 1, 5 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    void *v = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, &v, 4, 0, NULL, 0), E_BADPDU); CHECK(v == NULL);
    EXPECT_EQ(A.ASN1_Decode(r.d, &v, 3, 0, NULL, 0), E_BADPDU); CHECK(v == NULL);   /* NULL decoder slot */
    rig_done(&r);
}
TEST(mc_decode_stub_failure_maps_to_corrupt) {
    static const BYTE in[] = { 2, 1, 5 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    void *v = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, &v, 1, 0, NULL, 0), E_CORRUPT); CHECK(v == NULL);
    rig_done(&r);
}
TEST(mc_decode_per_module_rule_error) {
    NEED(ASN1_CreateDecoder); NEED(ASN1_Decode); NEED(ASN1_CloseDecoder); NEED(ASN1_CloseModule);
    static const BYTE in[] = { 2, 1, 5 };
    MOD *m = rig_module(R_PER_ALIGNED, 0); DEC *d = NULL; void *v = NULL;
    CHECK(m != NULL); if (!m) return;
    EXPECT_EQ(A.ASN1_CreateDecoder(m, &d, (BYTE *)in, sizeof in, NULL), 0);
    if (d) { EXPECT_EQ(A.ASN1_Decode(d, &v, 0, 0, NULL, 0), E_RULE); CHECK(v == NULL); A.ASN1_CloseDecoder(d); }
    A.ASN1_CloseModule(m);
}
TEST(mc_decode_setbuffer) {
    NEED(ASN1_FreeDecoded);
    static const BYTE in[] = { 2, 1, 9 };
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    DWORD *v = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&v, 0, DEC_SETBUFFER, (BYTE *)in, sizeof in), 0);
    CHECK(v != NULL); if (v) EXPECT_EQ(*v, 9);
    CHECK(r.d->buf == in); EXPECT_EQ(r.d->size, 3); EXPECT_EQ(r.d->flags & 8, 8);
    A.ASN1_FreeDecoded(r.d, v, 0);
    rig_done(&r);
}
TEST(mc_decode_setbuffer_requires_buffer_and_size) {
    static BYTE in[] = { 2, 1, 9 };
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    void *v = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, &v, 0, DEC_SETBUFFER, NULL, 3), E_BADARGS);
    EXPECT_EQ(A.ASN1_Decode(r.d, &v, 0, DEC_SETBUFFER, in, 0), E_BADARGS);
    EXPECT_EQ(r.d->err, E_BADARGS); CHECK(v == NULL);
    rig_done(&r);
}
TEST(mc_decode_twice_rewinds) {
    NEED(ASN1_FreeDecoded);
    static const BYTE in[] = { 2, 1, 5 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DWORD *a = NULL, *b = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&a, 0, 0, NULL, 0), 0);
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&b, 0, 0, NULL, 0), 0);
    CHECK(a && b && a != b); if (a && b) { EXPECT_EQ(*a, 5); EXPECT_EQ(*b, 5); }
    A.ASN1_FreeDecoded(r.d, a, 0); A.ASN1_FreeDecoded(r.d, b, 0);
    rig_done(&r);
}
TEST(mc_decode_appended_continues_at_position) {
    NEED(ASN1_FreeDecoded);
    static const BYTE in[] = { 2, 1, 5, 2, 1, 6 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DWORD *a = NULL, *b = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&a, 0, 0, NULL, 0), W_NOEOD);       /* 3 of 6 bytes consumed */
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&b, 0, DEC_APPENDED, NULL, 0), 0);  /* picks up at byte 3 */
    CHECK(a && b); if (a && b) { EXPECT_EQ(*a, 5); EXPECT_EQ(*b, 6); }
    EXPECT_EQ(r.d->len, 6);
    A.ASN1_FreeDecoded(r.d, a, 0); A.ASN1_FreeDecoded(r.d, b, 0);
    rig_done(&r);
}
TEST(mc_decode_rewind_flag_beats_appended) {
    NEED(ASN1_FreeDecoded);
    static const BYTE in[] = { 2, 1, 5, 2, 1, 6 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DWORD *a = NULL, *b = NULL;
    A.ASN1_Decode(r.d, (void **)&a, 0, 0, NULL, 0);
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&b, 0, DEC_APPENDED | DEC_REWIND, NULL, 0), W_NOEOD);
    CHECK(b != NULL); if (b) EXPECT_EQ(*b, 5);
    A.ASN1_FreeDecoded(r.d, a, 0); A.ASN1_FreeDecoded(r.d, b, 0);
    rig_done(&r);
}
TEST(mc_decode_sequence) {
    NEED(ASN1_FreeDecoded);
    static const BYTE in[] = { 0x30, 8, 2, 1, 1, 4, 3, 'a', 'b', 'c' };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    struct { DWORD id; DWORD pad; LV os; } *s = NULL;
    int g0 = g_freecalls[2];
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&s, 2, 0, NULL, 0), 0);
    CHECK(s != NULL);
    if (s) {
        EXPECT_EQ(s->id, 1); EXPECT_EQ(s->os.length, 3);
        CHECK(s->os.value != NULL); if (s->os.value) EXPECT_BYTES(s->os.value, 3, "abc", 3);
    }
    A.ASN1_FreeDecoded(r.d, s, 2);
    EXPECT_EQ(g_freecalls[2], g0 + 1);                          /* module free routine invoked */
    rig_done(&r);
}
TEST(mc_decode_sequence_long_form) {
    NEED(ASN1_FreeDecoded);
    BYTE *in = malloc(4 + 3 + 4 + 300); int n = 0;
    in[n++] = 0x30; in[n++] = 0x82; in[n++] = 0x01; in[n++] = 0x34;      /* 308 bytes of content */
    in[n++] = 2; in[n++] = 1; in[n++] = 7;
    in[n++] = 4; in[n++] = 0x82; in[n++] = 0x01; in[n++] = 0x2c;
    memset(in + n, 0x77, 300); n += 300;
    Rig r; if (!rig_dec(&r, R_DER, in, n)) { free(in); return; }
    struct { DWORD id; DWORD pad; LV os; } *s = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&s, 2, 0, NULL, 0), 0);
    CHECK(s != NULL);
    if (s) { EXPECT_EQ(s->id, 7); EXPECT_EQ(s->os.length, 300); CHECK(s->os.value && s->os.value[299] == 0x77 && s->os.value[0] == 0x77); }
    A.ASN1_FreeDecoded(r.d, s, 2);
    rig_done(&r); free(in);
}
TEST(mc_decode_sequence_inner_length_mismatch) {
    /* SEQUENCE claims 7 content bytes but the members only fill 6 -> the inner decoder did not reach the end */
    static const BYTE in[] = { 0x30, 7, 2, 1, 1, 4, 2, 'a', 'b' };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    void *s = NULL;
    int rc = A.ASN1_Decode(r.d, &s, 2, 0, NULL, 0);
    CHECKF(rc < 0, "rc=%d", rc);
    CHECK(s == NULL);
    rig_done(&r);
}
TEST(mc_decode_sequence_truncated) {
    static const BYTE in[] = { 0x30, 8, 2, 1, 1, 4, 3, 'a' };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    void *s = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, &s, 2, 0, NULL, 0), E_EOD);
    CHECK(s == NULL);
    rig_done(&r);
}
TEST(mc_decode_into_decoded_buffer_arena) {
    NEED(ASN1_SetDecoderOption);
    static const BYTE in[] = { 2, 1, 5 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    BYTE arena[16]; OPTP o; memset(&o, 0, sizeof o);
    o.opt = OPT_SET_DECODED_BUFFER; o.u.b.buf = arena; o.u.b.size = sizeof arena;
    EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), 0);
    EXPECT_EQ(r.d->usesbuf, 1); CHECK(r.d->pbuf == arena); EXPECT_EQ(r.d->pbufsize, 16);
    DWORD *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&a, 0, 0, NULL, 0), 0);
    CHECK((BYTE *)a == arena);                                   /* 8-byte PDU object carved from the arena */
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&b, 0, 0, NULL, 0), 0);
    CHECK((BYTE *)b == arena + 8);
    EXPECT_EQ(A.ASN1_Decode(r.d, (void **)&c, 0, 0, NULL, 0), E_MEMORY);   /* arena exhausted */
    CHECK(c == NULL);
    if (a) EXPECT_EQ(*a, 5);
    A.ASN1_FreeDecoded(r.d, a, 0);                                /* must not LocalFree arena memory */
    A.ASN1_FreeDecoded(r.d, b, 0);
    o.opt = OPT_DEL_DECODED_BUFFER;
    EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), 0);
    EXPECT_EQ(r.d->usesbuf, 0); CHECK(r.d->pbuf == NULL);
    rig_done(&r);
}

/* ---------------------------------------------------------------- ASN1_FreeEncoded / ASN1_FreeDecoded */
TEST(mc_freeencoded_null_encoder_is_noop) {
    NEED(ASN1_FreeEncoded);
    void *p = LocalAlloc(LPTR, 32);
    CHECK(p != NULL); if (!p) return;
    A.ASN1_FreeEncoded(NULL, p);
    CHECK(LocalSize(p) >= 32);                                   /* still allocated */
    LocalFree(p);
}
TEST(mc_freeencoded_frees_block) {
    NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    void *p = LocalAlloc(LPTR, 32);
    CHECK(p != NULL);
    if (p) A.ASN1_FreeEncoded(r.e, p);
    A.ASN1_FreeEncoded(r.e, NULL);                               /* NULL block tolerated */
    rig_done(&r);
}
TEST(mc_freedecoded_guards) {
    NEED(ASN1_FreeDecoded);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    void *p = LocalAlloc(LPTR, 32);
    CHECK(p != NULL); if (!p) { rig_done(&r); return; }
    int c0 = g_freecalls[0];
    A.ASN1_FreeDecoded(NULL, p, 0);                              /* no decoder: nothing happens */
    CHECK(LocalSize(p) >= 32); EXPECT_EQ(g_freecalls[0], c0);
    A.ASN1_FreeDecoded(r.d, NULL, 0);                            /* no block: nothing happens */
    EXPECT_EQ(g_freecalls[0], c0);
    A.ASN1_FreeDecoded(r.d, p, 99);                              /* pdu out of range: returns, block kept */
    CHECK(LocalSize(p) >= 32); EXPECT_EQ(g_freecalls[0], c0);
    A.ASN1_FreeDecoded(r.d, p, 0);                               /* module routine + LocalFree */
    EXPECT_EQ(g_freecalls[0], c0 + 1);
    rig_done(&r);
}
TEST(mc_freedecoded_non_pdu_id_skips_module_routine) {
    NEED(ASN1_FreeDecoded);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    void *p = LocalAlloc(LPTR, 32);
    CHECK(p != NULL); if (!p) { rig_done(&r); return; }
    int c0 = g_freecalls[0] + g_freecalls[1] + g_freecalls[2] + g_freecalls[3];
    A.ASN1_FreeDecoded(r.d, p, 0xffffffff);                      /* ASN1DECFREE_NON_PDU_ID */
    EXPECT_EQ(g_freecalls[0] + g_freecalls[1] + g_freecalls[2] + g_freecalls[3], c0);
    rig_done(&r);
}
TEST(mc_freedecoded_pdu_without_free_routine) {
    NEED(ASN1_FreeDecoded);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    void *p = LocalAlloc(LPTR, 32);
    CHECK(p != NULL); if (!p) { rig_done(&r); return; }
    int c3 = g_freecalls[3];
    A.ASN1_FreeDecoded(r.d, p, 3);                               /* slot 3 holds NULL: block still released */
    EXPECT_EQ(g_freecalls[3], c3);
    rig_done(&r);
}
TEST(mc_freedecoded_arena_block_not_released) {
    NEED(ASN1_FreeDecoded); NEED(ASN1_SetDecoderOption);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    BYTE arena[64]; OPTP o; memset(&o, 0, sizeof o);
    o.opt = OPT_SET_DECODED_BUFFER; o.u.b.buf = arena; o.u.b.size = sizeof arena;
    EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), 0);
    void *p = LocalAlloc(LPTR, 32);
    CHECK(p != NULL); if (!p) { rig_done(&r); return; }
    int c0 = g_freecalls[0];
    A.ASN1_FreeDecoded(r.d, p, 0);                               /* routine runs, LocalFree is skipped */
    EXPECT_EQ(g_freecalls[0], c0 + 1);
    CHECK(LocalSize(p) >= 32);
    LocalFree(p);
    rig_done(&r);
}

/* ---------------------------------------------------------------- options */
TEST(mc_encoder_option_badargs) {
    REQUIRE(A.ASN1_SetEncoderOption); NEED(ASN1_GetEncoderOption);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    OPTP o; memset(&o, 0, sizeof o); o.opt = OPT_GET_RULE;
    EXPECT_EQ(A.ASN1_SetEncoderOption(NULL, &o), E_BADARGS);
    EXPECT_EQ(A.ASN1_SetEncoderOption(r.e, NULL), E_BADARGS);
    EXPECT_EQ(A.ASN1_GetEncoderOption(NULL, &o), E_BADARGS);
    EXPECT_EQ(A.ASN1_GetEncoderOption(r.e, NULL), E_BADARGS);
    rig_done(&r);
}
TEST(mc_encoder_option_get_rule) {
    NEED(ASN1_GetEncoderOption);
    static const int rules[] = { R_BER, R_CER, R_DER };
    for (int i = 0; i < 3; i++) {
        Rig r; if (!rig_enc(&r, rules[i])) return;
        OPTP o; memset(&o, 0x55, sizeof o); o.opt = OPT_GET_RULE;
        EXPECT_EQ(A.ASN1_GetEncoderOption(r.e, &o), 0);
        EXPECT_EQ(o.u.rule, rules[i]);
        rig_done(&r);
    }
}
TEST(mc_encoder_option_change_rule) {
    NEED(ASN1_SetEncoderOption); NEED(ASN1_GetEncoderOption);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    OPTP o; memset(&o, 0, sizeof o); o.opt = OPT_CHANGE_RULE; o.u.rule = R_BER;
    EXPECT_EQ(A.ASN1_SetEncoderOption(r.e, &o), 0);
    EXPECT_EQ(r.e->rule, R_BER);
    memset(&o, 0, sizeof o); o.opt = OPT_GET_RULE;
    EXPECT_EQ(A.ASN1_GetEncoderOption(r.e, &o), 0);
    EXPECT_EQ(o.u.rule, R_BER);
    rig_done(&r);
}
TEST(mc_encoder_option_unknown_is_badargs_and_recorded) {
    NEED(ASN1_SetEncoderOption); NEED(ASN1_GetEncoderOption);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    OPTP o; memset(&o, 0, sizeof o);
    static const int bad[] = { 0, 0x100, 0x102, 0x200, 0x202, 0x303, 0x501, 0x601, 0x7fffffff };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        o.opt = bad[i];
        EXPECT_EQ(A.ASN1_SetEncoderOption(r.e, &o), E_BADARGS);
        EXPECT_EQ(r.e->err, E_BADARGS);
    }
    o.opt = OPT_CHANGE_RULE; o.u.rule = R_DER;
    EXPECT_EQ(A.ASN1_SetEncoderOption(r.e, &o), 0);               /* a valid call clears the error */
    EXPECT_EQ(r.e->err, 0);
    o.opt = OPT_SET_DECODED_BUFFER;                               /* decoder-only option */
    EXPECT_EQ(A.ASN1_GetEncoderOption(r.e, &o), E_BADARGS);
    o.opt = OPT_CHANGE_RULE;                                      /* Get only understands GET_RULE */
    EXPECT_EQ(A.ASN1_GetEncoderOption(r.e, &o), E_BADARGS);
    rig_done(&r);
}
TEST(mc_encoder_option_rewind_buffer) {
    NEED(ASN1_SetEncoderOption);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5, w = 6; static const BYTE want[] = { 2, 1, 6 };
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, 0, NULL, 0), 0);
    BYTE *b = r.e->buf; CHECK(b != NULL); EXPECT_EQ(r.e->len, 3);
    OPTP o; memset(&o, 0, sizeof o); o.opt = OPT_REWIND_BUFFER;
    EXPECT_EQ(A.ASN1_SetEncoderOption(r.e, &o), 0);
    CHECK(r.e->pos == b); EXPECT_EQ(r.e->len, 0); CHECK(r.e->buf == b);
    EXPECT_EQ(A.ASN1_Encode(r.e, &w, 0, ENC_APPEND, NULL, 0), 0);  /* append after a rewind starts at 0 */
    EXPECT_BYTES(r.e->buf, r.e->len, want, 3);
    rig_done(&r);
}
TEST(mc_encoder_option_not_reuse_buffer_forgets_buffer) {
    NEED(ASN1_SetEncoderOption); NEED(ASN1_FreeEncoded);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD v = 5;
    EXPECT_EQ(A.ASN1_Encode(r.e, &v, 0, 0, NULL, 0), 0);
    BYTE *b = r.e->buf; CHECK(b != NULL);
    OPTP o; memset(&o, 0, sizeof o); o.opt = OPT_NOT_REUSE_BUFFER;
    EXPECT_EQ(A.ASN1_SetEncoderOption(r.e, &o), 0);
    CHECK(r.e->buf == NULL); CHECK(r.e->pos == NULL); EXPECT_EQ(r.e->size, 0); EXPECT_EQ(r.e->flags & 8, 0);
    A.ASN1_FreeEncoded(r.e, b);                                   /* ownership passed to the caller */
    rig_done(&r);
}
TEST(mc_decoder_option_badargs) {
    REQUIRE(A.ASN1_GetDecoderOption); NEED(ASN1_SetDecoderOption);
    OPTP o; memset(&o, 0, sizeof o); o.opt = OPT_GET_RULE;
    EXPECT_EQ(A.ASN1_GetDecoderOption(NULL, &o), E_BADARGS);
    EXPECT_EQ(A.ASN1_SetDecoderOption(NULL, &o), E_BADARGS);
}
TEST(mc_decoder_option_get_and_change_rule) {
    NEED(ASN1_GetDecoderOption); NEED(ASN1_SetDecoderOption);
    Rig r; if (!rig_dec(&r, R_CER, NULL, 0)) return;
    OPTP o; memset(&o, 0x55, sizeof o); o.opt = OPT_GET_RULE;
    EXPECT_EQ(A.ASN1_GetDecoderOption(r.d, &o), 0);
    EXPECT_EQ(o.u.rule, R_CER);
    memset(&o, 0, sizeof o); o.opt = OPT_CHANGE_RULE; o.u.rule = R_DER;
    EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), 0);
    EXPECT_EQ(r.d->rule, R_DER);
    memset(&o, 0, sizeof o); o.opt = OPT_GET_RULE;
    EXPECT_EQ(A.ASN1_GetDecoderOption(r.d, &o), 0);
    EXPECT_EQ(o.u.rule, R_DER);
    rig_done(&r);
}
TEST(mc_decoder_option_unknown_values) {
    NEED(ASN1_GetDecoderOption); NEED(ASN1_SetDecoderOption);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    OPTP o; memset(&o, 0, sizeof o);
    static const int bad[] = { 0, 0x301, 0x302, 0x601, 0x7fffffff };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        o.opt = bad[i];
        EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), E_BADARGS);
        EXPECT_EQ(r.d->err, E_BADARGS);
    }
    o.opt = OPT_GET_DECODED_BUFFER_SIZE;                          /* defined by the SDK, but Get does not implement it */
    EXPECT_EQ(A.ASN1_GetDecoderOption(r.d, &o), E_BADARGS);
    rig_done(&r);
}
TEST(mc_decoder_option_set_decoded_buffer_needs_buffer_and_size) {
    NEED(ASN1_SetDecoderOption);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    BYTE arena[8]; OPTP o; memset(&o, 0, sizeof o); o.opt = OPT_SET_DECODED_BUFFER;
    o.u.b.buf = NULL; o.u.b.size = 8;
    EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), E_BADARGS);
    o.u.b.buf = arena; o.u.b.size = 0;
    EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), E_BADARGS);
    EXPECT_EQ(r.d->usesbuf, 0);
    rig_done(&r);
}

/* ---------------------------------------------------------------- error helpers / allocation helpers */
TEST(mc_encsetseterror_records_and_returns_code) {
    REQUIRE(A.ASN1EncSetError);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    EXPECT_EQ(A.ASN1EncSetError(r.e, E_LARGE), E_LARGE); EXPECT_EQ(r.e->err, E_LARGE);
    EXPECT_EQ(A.ASN1EncSetError(r.e, 0), 0); EXPECT_EQ(r.e->err, 0);
    EXPECT_EQ(A.ASN1EncSetError(r.e, W_NOEOD), W_NOEOD); EXPECT_EQ(r.e->err, W_NOEOD);
    EXPECT_EQ(A.ASN1EncSetError(NULL, E_MEMORY), E_MEMORY);       /* NULL encoder: value returned, nothing stored */
    rig_done(&r);
}
TEST(mc_decsetseterror_records_and_returns_code) {
    REQUIRE(A.ASN1DecSetError);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    EXPECT_EQ(A.ASN1DecSetError(r.d, E_CORRUPT), E_CORRUPT); EXPECT_EQ(r.d->err, E_CORRUPT);
    EXPECT_EQ(A.ASN1DecSetError(r.d, 0), 0); EXPECT_EQ(r.d->err, 0);
    EXPECT_EQ(A.ASN1DecSetError(NULL, E_EOD), E_EOD);
    rig_done(&r);
}
TEST(mc_errors_propagate_to_the_root_of_a_decoder_chain) {
    /* a sub-decoder created by DecExplicitTag reports its errors on its parent too */
    NEED(ASN1BERDecExplicitTag); NEED(ASN1DecSetError); NEED(ASN1BERDecEndOfContents);
    static const BYTE in[] = { 0x30, 3, 2, 1, 5 };
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DEC *sub = NULL; const BYTE *end = NULL;
    CHECK(OK8(A.ASN1BERDecExplicitTag(r.d, T_SEQ, &sub, &end)));
    CHECK(sub != NULL && sub != r.d); if (!sub) { rig_done(&r); return; }
    CHECK(sub->parent == r.d); CHECK(r.d->child == sub); EXPECT_EQ(sub->level, 1);
    A.ASN1DecSetError(sub, E_LARGE);
    EXPECT_EQ(r.d->err, E_LARGE);
    CHECK(end == in + 5);
    A.ASN1DecSetError(sub, 0);
    sub->pos = (BYTE *)end;
    CHECK(OK8(A.ASN1BERDecEndOfContents(r.d, sub, end)));
    CHECK(r.d->pos == in + 5);
    rig_done(&r);
}
TEST(mc_decalloc_returns_zeroed_memory) {
    REQUIRE(A.ASN1DecAlloc);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    BYTE *p = A.ASN1DecAlloc(r.d, 13);
    CHECK(p != NULL);
    if (p) { for (int i = 0; i < 13; i++) EXPECT_EQ(p[i], 0); CHECK(LocalSize(p) >= 13); A.ASN1Free(p); }
    rig_done(&r);
}
TEST(mc_decalloc_arena_rounds_up_to_four) {
    NEED(ASN1DecAlloc); NEED(ASN1_SetDecoderOption);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    BYTE arena[16]; OPTP o; memset(&o, 0, sizeof o);
    o.opt = OPT_SET_DECODED_BUFFER; o.u.b.buf = arena; o.u.b.size = sizeof arena;
    EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), 0);
    BYTE *a = A.ASN1DecAlloc(r.d, 1), *b = A.ASN1DecAlloc(r.d, 5), *c = A.ASN1DecAlloc(r.d, 4);
    CHECK(a == arena); CHECK(b == arena + 4); CHECK(c == arena + 12);
    BYTE *d = A.ASN1DecAlloc(r.d, 1);                              /* 0 bytes left */
    CHECK(d == NULL); EXPECT_EQ(r.d->err, E_MEMORY);
    rig_done(&r);
}
TEST(mc_decrealloc_behaviour) {
    REQUIRE(A.ASN1DecRealloc); NEED(ASN1DecAlloc);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    BYTE *p = A.ASN1DecRealloc(r.d, NULL, 8);                      /* NULL old block acts like alloc */
    CHECK(p != NULL); if (!p) { rig_done(&r); return; }
    memcpy(p, "ABCDEFGH", 8);
    BYTE *q = A.ASN1DecRealloc(r.d, p, 64);
    CHECK(q != NULL);
    if (q) { CHECK(memcmp(q, "ABCDEFGH", 8) == 0); CHECK(LocalSize(q) >= 64); A.ASN1Free(q); } else A.ASN1Free(p);
    rig_done(&r);
}
TEST(mc_decrealloc_arena_rejects_existing_block) {
    NEED(ASN1DecRealloc); NEED(ASN1_SetDecoderOption);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    BYTE arena[32]; OPTP o; memset(&o, 0, sizeof o);
    o.opt = OPT_SET_DECODED_BUFFER; o.u.b.buf = arena; o.u.b.size = sizeof arena;
    EXPECT_EQ(A.ASN1_SetDecoderOption(r.d, &o), 0);
    BYTE *p = A.ASN1DecRealloc(r.d, NULL, 8);
    CHECK(p == arena);
    BYTE *q = A.ASN1DecRealloc(r.d, p, 16);                        /* growing an arena block is not supported */
    CHECK(q == NULL); EXPECT_EQ(r.d->err, E_MEMORY);
    rig_done(&r);
}
TEST(mc_asn1free_null_and_block) {
    REQUIRE(A.ASN1Free);
    A.ASN1Free(NULL);
    void *p = LocalAlloc(LPTR, 8);
    CHECK(p != NULL); if (p) A.ASN1Free(p);
}

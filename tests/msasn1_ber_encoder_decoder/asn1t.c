#include "asn1t.h"

api_t A;
HMODULE g_msasn1;

static void __attribute__((constructor)) asn1_bind(void)
{
    g_msasn1 = LoadLibraryA("msasn1.dll");
    if (!g_msasn1) return;
#define X(n, r, a) A.n = (void *)GetProcAddress(g_msasn1, #n);
    API_LIST(X)
#undef X
    if (t_is_wine() && !getenv("ASN1T_NOGUARD")) {
        /* The emulator exports the rest of the table as aborting stubs: expose only what it implements. */
        api_t keep = A;
        memset(&A, 0, sizeof A);
        A.ASN1_CreateModule = keep.ASN1_CreateModule; A.ASN1_CloseModule = keep.ASN1_CloseModule;
        A.ASN1_CreateEncoder = keep.ASN1_CreateEncoder; A.ASN1_CloseEncoder = keep.ASN1_CloseEncoder;
        A.ASN1_CreateDecoder = keep.ASN1_CreateDecoder; A.ASN1_CloseDecoder = keep.ASN1_CloseDecoder;
    }
}

/* ---- the PDU stubs of the hand-built module -------------------------------------------
 * PDU 0: INTEGER (unsigned 32 bit)         data = DWORD
 * PDU 1: always fails (returns 0 without setting an error)
 * PDU 2: SEQUENCE { INTEGER id, OCTET STRING } data = SEQ2
 * PDU 3: no encoder / decoder registered (NULL entries)
 */
typedef struct { DWORD id; DWORD pad; LV os; } SEQ2;
int g_freecalls[4];
const DWORD pdu_sizes[4] = { 8, 16, sizeof(SEQ2), 16 };

static int WINAPI enc0(ENC *e, DWORD tag, void *data) { return OK8(A.ASN1BEREncU32(e, T_INT, *(DWORD *)data)); }
static int WINAPI dec0(DEC *d, DWORD tag, void *out) { return OK8(A.ASN1BERDecU32Val(d, T_INT, (DWORD *)out)); }
static int WINAPI enc1(ENC *e, DWORD tag, void *data) { return 0; }
static int WINAPI dec1(DEC *d, DWORD tag, void *out) { return 0; }
static int WINAPI enc2(ENC *e, DWORD tag, void *data)
{
    SEQ2 *s = data; DWORD lenpos;
    if (!OK8(A.ASN1BEREncExplicitTag(e, T_SEQ, &lenpos))) return 0;
    if (!OK8(A.ASN1BEREncU32(e, T_INT, s->id))) return 0;
    if (!OK8(A.ASN1BEREncOctetString(e, T_OCT, s->os.length, s->os.value))) return 0;
    return OK8(A.ASN1BEREncEndOfContents(e, lenpos));
}
static int WINAPI dec2(DEC *d, DWORD tag, void *out)
{
    SEQ2 *s = out; DEC *sub; const BYTE *end;
    if (!OK8(A.ASN1BERDecExplicitTag(d, T_SEQ, &sub, &end))) return 0;
    if (!OK8(A.ASN1BERDecU32Val(sub, T_INT, &s->id))) return 0;
    if (!OK8(A.ASN1BERDecOctetString(sub, T_OCT, &s->os))) return 0;
    return OK8(A.ASN1BERDecEndOfContents(d, sub, end));
}
static void WINAPI free0(void *p) { g_freecalls[0]++; }
static void WINAPI free1(void *p) { g_freecalls[1]++; }
static void WINAPI free2(void *p) { g_freecalls[2]++; if (A.ASN1octetstring_free) A.ASN1octetstring_free(&((SEQ2 *)p)->os); }
static void WINAPI free3(void *p) { g_freecalls[3]++; }

static const void *const enc_tab[4] = { (void *)enc0, (void *)enc1, (void *)enc2, NULL };
static const void *const dec_tab[4] = { (void *)dec0, (void *)dec1, (void *)dec2, NULL };
static const void *const free_tab[4] = { (void *)free0, (void *)free1, (void *)free2, NULL };

MOD *rig_module(int rule, DWORD flags)
{
    if (!A.ASN1_CreateModule) return NULL;
    return A.ASN1_CreateModule(0x10000, rule, flags, 4, enc_tab, dec_tab, free_tab, pdu_sizes, 0x6d6f6431);
}

int rig_enc(Rig *r, int rule)
{
    memset(r, 0, sizeof *r);
    if (!A.ASN1_CreateModule || !A.ASN1_CreateEncoder || !A.ASN1_Encode) { t_skip("missing export: ASN1_CreateModule/ASN1_CreateEncoder/ASN1_Encode"); return 0; }
    r->m = rig_module(rule, 0);
    CHECK(r->m != NULL);
    if (!r->m) return 0;
    int rc = A.ASN1_CreateEncoder(r->m, &r->e, NULL, 0, NULL);
    CHECK(rc == 0 && r->e != NULL);
    if (rc != 0 || !r->e) { rig_done(r); return 0; }
    return 1;
}

int rig_dec(Rig *r, int rule, const void *data, DWORD n)
{
    memset(r, 0, sizeof *r);
    if (!A.ASN1_CreateModule || !A.ASN1_CreateDecoder || !A.ASN1_Decode) { t_skip("missing export: ASN1_CreateModule/ASN1_CreateDecoder/ASN1_Decode"); return 0; }
    r->m = rig_module(rule, 0);
    CHECK(r->m != NULL);
    if (!r->m) return 0;
    int rc = A.ASN1_CreateDecoder(r->m, &r->d, (BYTE *)data, n, NULL);
    CHECK(rc == 0 && r->d != NULL);
    if (rc != 0 || !r->d) { rig_done(r); return 0; }
    return 1;
}

void rig_done(Rig *r)
{
    if (r->e) {
        /* CloseEncoder2 also frees the buffer; a caller-supplied buffer (flag 8) must not be freed */
        if (r->e->buf && !(r->e->flags & 8) && A.ASN1_CloseEncoder2) A.ASN1_CloseEncoder2(r->e);
        else if (A.ASN1_CloseEncoder) A.ASN1_CloseEncoder(r->e);
    }
    if (r->d && A.ASN1_CloseDecoder) A.ASN1_CloseDecoder(r->d);
    if (r->m && A.ASN1_CloseModule) A.ASN1_CloseModule(r->m);
    memset(r, 0, sizeof *r);
}

void expect_bytes(const char *file, int line, const void *got, size_t gl, const void *want, size_t wl)
{
    int ok = gl == wl && (gl == 0 || memcmp(got, want, gl) == 0);
    if (ok) { t_check(1, file, line, "bytes", NULL); return; }
    char gs[160] = "", ws[160] = "";
    for (size_t i = 0; i < gl && i < 24; i++) sprintf(gs + strlen(gs), "%02X ", ((const BYTE *)got)[i]);
    for (size_t i = 0; i < wl && i < 24; i++) sprintf(ws + strlen(ws), "%02X ", ((const BYTE *)want)[i]);
    t_check(0, file, line, "encoded bytes", "got[%u] %s want[%u] %s", (unsigned)gl, gs, (unsigned)wl, ws);
}

void expect_enc(const char *file, int line, Rig *r, const void *want, size_t wl)
{
    if (!A.ASN1BEREncFlush) { t_skip("missing export: ASN1BEREncFlush"); return; }
    U64 rc = A.ASN1BEREncFlush(r->e);
    t_check(OK8(rc), file, line, "ASN1BEREncFlush", NULL);
    expect_bytes(file, line, r->e->buf, r->e->len, want, wl);
}

/* OBJECT IDENTIFIER vectors shared by the encoder and decoder tests */
const OIDV k_oid[] = {
    { { 2, 5, 4, 3 }, 4, { 0x06, 0x03, 0x55, 0x04, 0x03 }, 5 },
    { { 1, 2, 840, 113549 }, 4, { 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d }, 8 },
    { { 1, 2, 840, 113549, 1, 1, 11 }, 7, { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b }, 11 },
    { { 1, 3, 6, 1, 5, 5, 7, 3, 1 }, 9, { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }, 10 },
    { { 2, 16, 840, 1, 101, 3, 4, 2, 1 }, 9, { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 }, 11 },
    { { 2, 100, 3 }, 3, { 0x06, 0x03, 0x81, 0x34, 0x03 }, 5 },
    { { 0, 0 }, 2, { 0x06, 0x01, 0x00 }, 3 }, { { 1, 39 }, 2, { 0x06, 0x01, 0x4f }, 3 }, { { 0, 39 }, 2, { 0x06, 0x01, 0x27 }, 3 },
    { { 2, 999 }, 2, { 0x06, 0x02, 0x88, 0x37 }, 4 }, { { 2, 47 }, 2, { 0x06, 0x01, 0x7f }, 3 },
    { { 2, 48 }, 2, { 0x06, 0x02, 0x81, 0x00 }, 4 },
    { { 1, 2, 127 }, 3, { 0x06, 0x02, 0x2a, 0x7f }, 4 }, { { 1, 2, 128 }, 3, { 0x06, 0x03, 0x2a, 0x81, 0x00 }, 5 },
    { { 1, 2, 16383 }, 3, { 0x06, 0x03, 0x2a, 0xff, 0x7f }, 5 }, { { 1, 2, 16384 }, 3, { 0x06, 0x04, 0x2a, 0x81, 0x80, 0x00 }, 6 },
    { { 1, 2, 0x1fffff }, 3, { 0x06, 0x04, 0x2a, 0xff, 0xff, 0x7f }, 6 },
    { { 1, 2, 0x200000 }, 3, { 0x06, 0x05, 0x2a, 0x81, 0x80, 0x80, 0x00 }, 7 },
    { { 1, 2, 0xfffffff }, 3, { 0x06, 0x05, 0x2a, 0xff, 0xff, 0xff, 0x7f }, 7 },
    { { 1, 2, 0x10000000 }, 3, { 0x06, 0x06, 0x2a, 0x81, 0x80, 0x80, 0x80, 0x00 }, 8 },
    { { 1, 2, 0xffffffff }, 3, { 0x06, 0x06, 0x2a, 0x8f, 0xff, 0xff, 0xff, 0x7f }, 8 },
    { { 1 }, 1, { 0x06, 0x01, 0x01 }, 3 }, { { 0 }, 1, { 0x06, 0x01, 0x00 }, 3 },
    { { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, 16,
      { 0x06, 0x0f, 0x2a, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, 17 },
    { { 2, 5, 29, 15 }, 4, { 0x06, 0x03, 0x55, 0x1d, 0x0f }, 5 },
};
const unsigned k_oid_n = sizeof k_oid / sizeof k_oid[0];

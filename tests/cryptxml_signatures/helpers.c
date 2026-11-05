#include "xml.h"
#include <stdlib.h>

HRESULT CALLBACK x_write_cb(void *state, const BYTE *pb, ULONG cb)
{
    XBUF *b = state;
    b->calls++;
    if (b->fail_with) return b->fail_with;
    if (b->n + cb + 1 > b->cap) {
        size_t nc = (b->cap ? b->cap * 2 : 4096);
        while (nc < b->n + cb + 1) nc *= 2;
        b->p = realloc(b->p, nc);
        b->cap = nc;
    }
    memcpy(b->p + b->n, pb, cb);
    b->n += cb;
    b->p[b->n] = 0;
    return S_OK;
}
void x_buf_free(XBUF *b) { free(b->p); memset(b, 0, sizeof *b); }
const char *x_buf_str(XBUF *b) { return b->p ? (const char *)b->p : ""; }

HRESULT CALLBACK x_read_cb(void *state, BYTE *pb, ULONG cb, ULONG *pcb)
{
    XMEM *m = state;
    m->reads++;
    if (m->read_fail) return m->read_fail;
    size_t want = m->n - m->pos;
    if (want > cb) want = cb;
    if (m->chunk && want > m->chunk) want = m->chunk;
    memcpy(pb, m->p + m->pos, want);
    m->pos += want;
    *pcb = (ULONG)want;
    return S_OK;
}
HRESULT CALLBACK x_close_cb(void *state) { ((XMEM *)state)->closes++; return S_OK; }
void x_prov(XPROV *pv, XMEM *m, const void *data, size_t n, size_t chunk)
{
    memset(m, 0, sizeof *m);
    m->p = data; m->n = n; m->chunk = chunk;
    pv->pvCallbackState = m;
    pv->cbBufferSize = 0x400;
    pv->pfnRead = x_read_cb;
    pv->pfnClose = x_close_cb;
}

int x_hash(const WCHAR *alg, const BYTE *secret, ULONG cbSecret, const void *data, size_t n, BYTE *out, ULONG *cbOut)
{
    BCRYPT_ALG_HANDLE h = NULL;
    ULONG len = 0, got = 0;
    if (!U(BCryptOpenAlgorithmProvider) || !U(BCryptHash) || !U(BCryptGetProperty)) return 0;
    if (U(BCryptOpenAlgorithmProvider)(&h, alg, NULL, secret ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0) < 0) return 0;
    if (U(BCryptGetProperty)(h, BCRYPT_HASH_LENGTH, (PUCHAR)&len, 4, &got, 0) < 0) { U(BCryptCloseAlgorithmProvider)(h, 0); return 0; }
    NTSTATUS st = U(BCryptHash)(h, (PUCHAR)secret, cbSecret, (PUCHAR)data, (ULONG)n, out, len);
    U(BCryptCloseAlgorithmProvider)(h, 0);
    if (st < 0) return 0;
    if (cbOut) *cbOut = len;
    return 1;
}

BYTE *x_utf16(const char *s, int be, int bom, ULONG *cb)
{
    size_t n = strlen(s), i, o = 0;
    BYTE *r = malloc((n + 2) * 2);
    if (bom) { if (be) { r[o++] = 0xFE; r[o++] = 0xFF; } else { r[o++] = 0xFF; r[o++] = 0xFE; } }
    for (i = 0; i < n; i++) {
        if (be) { r[o++] = 0; r[o++] = (BYTE)s[i]; } else { r[o++] = (BYTE)s[i]; r[o++] = 0; }
    }
    *cb = (ULONG)o;
    return r;
}

char *x_tamper(const char *s, const char *from, const char *to)
{
    char *c = _strdup(s);
    char *p = strstr(c, from);
    if (p && strlen(from) == strlen(to)) memcpy(p, to, strlen(to)); else { free(c); return NULL; }
    return c;
}

HRESULT x_decode(const char *xml, const XPROP *props, ULONG cprops, HCX *ph)
{
    XBLOB b;
    b.dwCharset = X_CS_UTF8; b.cbData = (ULONG)strlen(xml); b.pbData = (BYTE *)xml;
    *ph = NULL;
    return XFN(CryptXmlOpenToDecode)(NULL, 0, props, cprops, &b, ph);
}

const XSIG *x_first_sig(HCX hDoc)
{
    const XDOC *d = NULL;
    const XSIG *s = NULL;
    if (XFN(CryptXmlGetDocContext)(hDoc, &d) != S_OK || !d || !d->cSignature) return NULL;
    if (XFN(CryptXmlGetSignature)(d->rgpSignature[0]->hSignature, &s) != S_OK) return NULL;
    return s;
}
int x_find(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }
void x_status(HCX h, XSTATUS *s)
{
    memset(s, 0xCC, sizeof *s);
    s->cbSize = 0xCCCCCCCC;
    XFN(CryptXmlGetStatus)(h, s);
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *x_b64(const BYTE *p, size_t n)
{
    char *r = malloc(n * 4 / 3 + 8), *o = r;
    size_t i;
    for (i = 0; i + 2 < n; i += 3) {
        *o++ = B64[p[i] >> 2]; *o++ = B64[((p[i] & 3) << 4) | (p[i+1] >> 4)];
        *o++ = B64[((p[i+1] & 15) << 2) | (p[i+2] >> 6)]; *o++ = B64[p[i+2] & 63];
    }
    if (n - i == 1) { *o++ = B64[p[i] >> 2]; *o++ = B64[(p[i] & 3) << 4]; *o++ = '='; *o++ = '='; }
    else if (n - i == 2) { *o++ = B64[p[i] >> 2]; *o++ = B64[((p[i] & 3) << 4) | (p[i+1] >> 4)]; *o++ = B64[(p[i+1] & 15) << 2]; *o++ = '='; }
    *o = 0;
    return r;
}
BYTE *x_unb64(const char *s, size_t *n)
{
    BYTE *r = malloc(strlen(s) + 4);
    size_t o = 0; unsigned acc = 0; int bits = 0;
    for (; *s; s++) {
        const char *q;
        if (*s == '=' || *s == ' ' || *s == '\r' || *s == '\n' || *s == '\t') continue;
        q = strchr(B64, *s);
        if (!q) { free(r); return NULL; }
        acc = (acc << 6) | (unsigned)(q - B64); bits += 6;
        if (bits >= 8) { bits -= 8; r[o++] = (BYTE)(acc >> bits); acc &= (1u << bits) - 1; }
    }
    *n = o;
    return r;
}

char *x_elem_text(const char *xml, const char *name)
{
    const char *p = xml;
    size_t nl = strlen(name);
    while ((p = strchr(p, '<')) != NULL) {
        const char *q = p + 1, *c;
        const char *colon = q;
        while (*colon && *colon != ':' && *colon != '>' && *colon != ' ' && *colon != '/') colon++;
        if (*colon == ':') q = colon + 1;
        if (!strncmp(q, name, nl) && (q[nl] == '>' || q[nl] == ' ' || q[nl] == '/')) {
            c = strchr(q, '>');
            if (!c || c[-1] == '/') return _strdup("");
            c++;
            {
                const char *e = strchr(c, '<');
                char *r;
                if (!e) return NULL;
                r = malloc((size_t)(e - c) + 1);
                memcpy(r, c, (size_t)(e - c)); r[e - c] = 0;
                return r;
            }
        }
        p++;
    }
    return NULL;
}

typedef struct { char name[64]; char val[1024]; } ATTR;
static int attr_cmp(const void *a, const void *b) { return strcmp(((const ATTR *)a)->name, ((const ATTR *)b)->name); }

char *x_canon_signedinfo(const char *xml)
{
    /* namespace declaration of the Signature start tag */
    const char *sig = strstr(xml, "<Signature"), *dsig = strstr(xml, "<ds:Signature");
    char nsdecl[256] = "";
    const char *start, *end, *p;
    char *out, *o;
    int depth = 0;
    if (!sig && !dsig) return NULL;
    {
        const char *st = sig ? sig : dsig, *gt = strchr(st, '>');
        const char *x = st;
        while (gt && (x = strstr(x, "xmlns")) != NULL && x < gt) {
            const char *vq = strchr(x, '"');
            const char *vq2 = vq ? strchr(vq + 1, '"') : NULL;
            if (vq && vq2 && vq2 < gt + 1) {
                size_t l = (size_t)(vq2 - x + 1);
                if (l < sizeof nsdecl) { memcpy(nsdecl, x, l); nsdecl[l] = 0; }
                break;
            }
            x++;
        }
    }
    start = strstr(xml, "<SignedInfo");
    if (!start) start = strstr(xml, "<ds:SignedInfo");
    if (!start) return NULL;
    end = strstr(start, "</SignedInfo>");
    if (!end) end = strstr(start, "</ds:SignedInfo>");
    if (!end) return NULL;
    end = strchr(end, '>') + 1;
    out = o = malloc((size_t)(end - start) * 2 + 512);
    p = start;
    while (p < end) {
        if (*p != '<') { *o++ = *p++; continue; }
        if (p[1] == '/') { const char *g = strchr(p, '>'); memcpy(o, p, (size_t)(g - p + 1)); o += g - p + 1; p = g + 1; depth--; continue; }
        {
            const char *q = p + 1; char nm[64]; size_t nl = 0; ATTR at[16]; int na = 0, selfclose = 0;
            while (*q && *q != ' ' && *q != '>' && *q != '/') nm[nl++] = *q++;
            nm[nl] = 0;
            for (;;) {
                while (*q == ' ') q++;
                if (*q == '/') { selfclose = 1; q++; continue; }
                if (*q == '>') { q++; break; }
                { size_t k = 0; char qc;
                  while (*q && *q != '=') at[na].name[k++] = *q++;
                  at[na].name[k] = 0; q++; qc = *q++; k = 0;
                  while (*q && *q != qc) at[na].val[k++] = *q++;
                  at[na].val[k] = 0; q++; na++; }
            }
            { int i, keep = 0; ATTR kept[16];
              for (i = 0; i < na; i++) {
                  if (!strncmp(at[i].name, "xmlns", 5)) continue;     /* redeclarations of the in-scope namespace are dropped */
                  kept[keep++] = at[i];
              }
              qsort(kept, (size_t)keep, sizeof(ATTR), attr_cmp);
              o += sprintf(o, "<%s", nm);
              if (depth == 0 && nsdecl[0]) o += sprintf(o, " %s", nsdecl);
              for (i = 0; i < keep; i++) o += sprintf(o, " %s=\"%s\"", kept[i].name, kept[i].val);
              *o++ = '>';
              if (selfclose) o += sprintf(o, "</%s>", nm); else depth++;
            }
            p = q;
        }
    }
    *o = 0;
    return out;
}

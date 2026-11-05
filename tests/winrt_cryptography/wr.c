#include "wr.h"

#define G(n, a, b, c, d0,d1,d2,d3,d4,d5,d6,d7) const GUID n = { a, b, c, { d0,d1,d2,d3,d4,d5,d6,d7 } }
G(WR_IID_IActivationFactory, 0x00000035, 0, 0, 0xc0,0,0,0,0,0,0,0x46);
G(WR_IID_IUnknown, 0x00000000, 0, 0, 0xc0,0,0,0,0,0,0,0x46);
G(WR_IID_IStream, 0x0000000c, 0, 0, 0xc0,0,0,0,0,0,0,0x46);
G(WR_IID_IMarshal, 0x00000003, 0, 0, 0xc0,0,0,0,0,0,0,0x46);
G(WR_IID_IInspectable, 0xaf86e2e0, 0xb12d, 0x4c6a, 0x9c,0x5a,0xd7,0xaa,0x65,0x10,0x1e,0x90);
G(WR_IID_IAgileObject, 0x94ea2b94, 0xe9cc, 0x49e0, 0xc0,0xff,0xee,0x64,0xca,0x8f,0x5b,0x90);
G(WR_IID_IBuffer, 0x905a0fe0, 0xbc53, 0x11df, 0x8c,0x49,0x00,0x1e,0x4f,0xc6,0x86,0xda);
G(WR_IID_IBufferByteAccess, 0x905a0fef, 0xbc53, 0x11df, 0x8c,0x49,0x00,0x1e,0x4f,0xc6,0x86,0xda);
G(WR_IID_ICryptographicBufferStatics, 0x320b7e22, 0x3cb0, 0x4cdf, 0x86,0x63,0x1d,0x28,0x91,0x00,0x65,0xeb);
G(WR_IID_IHashAlgorithmProviderStatics, 0x9fac9741, 0x5cc4, 0x4336, 0xae,0x38,0x62,0x12,0xb7,0x5a,0x91,0x5a);
G(WR_IID_IHashAlgorithmProvider, 0xbe9b3080, 0xb2c3, 0x422b, 0xbc,0xe1,0xec,0x90,0xef,0xb5,0xd7,0xb5);
G(WR_IID_ICryptographicHash, 0x5904d1b6, 0xad31, 0x4603, 0xa3,0xa4,0xb1,0xbd,0xa9,0x8e,0x25,0x62);
G(WR_IID_IHashAlgorithmNamesStatics, 0x6b5e0516, 0xde96, 0x4f0a, 0x8d,0x57,0xdc,0xc9,0xda,0xe3,0x6c,0x76);
G(WR_IID_ICryptographicEngineStatics, 0x9fea0639, 0x6ff7, 0x4c85, 0xa0,0x95,0x95,0xeb,0x31,0x71,0x5e,0xb9);
G(WR_IID_ICryptographicEngineStatics2, 0x675948fe, 0xdf9f, 0x4191, 0x92,0xc7,0x6c,0xe6,0xf5,0x84,0x20,0xe0);
G(WR_IID_IAsymmetricKeyAlgorithmProviderStatics, 0x425bde18, 0xa7f3, 0x47a6, 0xa8,0xd2,0xc4,0x8d,0x60,0x33,0xa6,0x5c);
G(WR_IID_IAsymmetricKeyAlgorithmProvider, 0xe8d2ff37, 0x6259, 0x4e88, 0xb7,0xe0,0x94,0x19,0x1f,0xde,0x69,0x9e);
G(WR_IID_IAsymmetricAlgorithmNamesStatics, 0xcaf6fce4, 0x67c0, 0x46aa, 0x84,0xf9,0x75,0x2e,0x77,0x44,0x9f,0x9b);
G(WR_IID_IAsymmetricAlgorithmNamesStatics2, 0xf141c0d6, 0x4bff, 0x4f23, 0xba,0x66,0x60,0x45,0xb1,0x37,0xd5,0xdf);
G(WR_IID_ICryptographicKey, 0xed2a3b70, 0x8e7b, 0x4009, 0x84,0x01,0xff,0xd1,0xa6,0x2e,0xeb,0x27);
G(WR_IID_IDataProtectionProviderFactory, 0xadf33dac, 0x4932, 0x4cdf, 0xac,0x41,0x72,0x14,0x33,0x35,0x14,0xca);

void wr_cofree(void *p) { if (p) UIN("combase.dll", CoTaskMemFree)(p); }
static int g_ready = -1;
int wr_init(void) {
    if (g_ready >= 0) return g_ready;
    g_ready = 0;
    if (!UIN("combase.dll", RoInitialize) || !UIN("combase.dll", RoGetActivationFactory) ||
        !UIN("combase.dll", WindowsCreateString) || !UIN("combase.dll", WindowsDeleteString)) return 0;
    HRESULT hr = UIN("combase.dll", RoInitialize)(RO_INIT_MULTITHREADED);
    if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) g_ready = 1;
    return g_ready;
}

HSTRING wr_hsn(const WCHAR *s, UINT32 n) {
    HSTRING h = NULL;
    if (!s) return NULL;
    UIN("combase.dll", WindowsCreateString)(s, n, &h);
    return h;
}
HSTRING wr_hs(const WCHAR *s) { return s ? wr_hsn(s, (UINT32)lstrlenW(s)) : NULL; }
void wr_hsfree(HSTRING h) { if (h) UIN("combase.dll", WindowsDeleteString)(h); }
const WCHAR *wr_raw(HSTRING h, UINT32 *len) {
    static const WCHAR empty[1] = { 0 };
    const WCHAR *r = h ? UIN("combase.dll", WindowsGetStringRawBuffer)(h, len) : NULL;
    if (!r) { if (len) *len = 0; return empty; }
    return r;
}
int wr_hs_eq(HSTRING h, const WCHAR *s) {
    UINT32 n; const WCHAR *r = wr_raw(h, &n);
    return n == (UINT32)lstrlenW(s) && !memcmp(r, s, n * 2);
}

HRESULT wr_activate(const WCHAR *cls, void **fac) {
    HSTRING h = wr_hs(cls); *fac = NULL;
    HRESULT hr = UIN("combase.dll", RoGetActivationFactory)(h, &WR_IID_IActivationFactory, fac);
    wr_hsfree(h);
    return hr;
}

static int act_failed(const WCHAR *cls, HRESULT hr) {
    if (t_is_wine()) { t_skip("class not activatable under the emulator (0x%08lx)", (unsigned long)hr); return 1; }
    t_check(0, __FILE__, __LINE__, "RoGetActivationFactory", "0x%08lx for %ls", (unsigned long)hr, cls);
    return 1;
}

void *wr_factory(const WCHAR *cls, ULONG idx) {
    void *f = NULL;
    HRESULT hr = wr_activate(cls, &f);
    if (FAILED(hr) || !f) { act_failed(cls, hr); return NULL; }
    if (idx == 0) return f;
    ULONG n = 0; GUID *ids = NULL;
    hr = wr_getiids(f, &n, &ids);
    if (hr == E_NOTIMPL && t_is_wine()) { t_skip("GetIids is a stub under the emulator"); wr_release(f); return NULL; }
    if (FAILED(hr) || idx >= n) {
        t_check(0, __FILE__, __LINE__, "GetIids", "hr=0x%08lx n=%lu want index %lu", (unsigned long)hr, n, idx);
        if (ids) wr_cofree(ids);
        wr_release(f); return NULL;
    }
    GUID iid = ids[idx]; wr_cofree(ids);
    void *s = NULL;
    hr = wr_qi(f, &iid, &s);
    wr_release(f);
    if (FAILED(hr)) { t_check(0, __FILE__, __LINE__, "QueryInterface(GetIids[idx])", "hr=0x%08lx", (unsigned long)hr); return NULL; }
    return s;
}
void *wr_cls_statics(const WCHAR *cls) { return wr_factory(cls, 1); }
void *wr_factory_iid(const WCHAR *cls, const GUID *iid) {
    void *f = NULL, *s = NULL;
    HRESULT hr = wr_activate(cls, &f);
    if (FAILED(hr) || !f) { act_failed(cls, hr); return NULL; }
    hr = wr_qi(f, iid, &s); wr_release(f);
    if (FAILED(hr)) { t_check(0, __FILE__, __LINE__, "QueryInterface", "hr=0x%08lx for %ls", (unsigned long)hr, cls); return NULL; }
    return s;
}

/* ---- buffers ---------------------------------------------------------------------- */
static void *g_cbs;
void *wr_cbs(void) {
    if (!g_cbs) g_cbs = wr_factory_iid(CLS_BUFFER, &WR_IID_ICryptographicBufferStatics);
    if (g_cbs && t_is_wine()) {   /* the emulator ships CryptographicBuffer as stubs */
        void *b = NULL; BYTE z = 0;
        HRESULT hr = VF(g_cbs, CB_CreateFromByteArray, UINT32, const BYTE *, void **)(g_cbs, 1, &z, &b);
        if (hr == E_NOTIMPL) { t_skip("CryptographicBuffer is stubbed under the emulator"); return NULL; }
        wr_release(b);
    }
    return g_cbs;
}
void *wr_mkbuf(const void *data, UINT32 n) {
    void *s = wr_cbs(), *b = NULL;
    if (!s) return NULL;
    static const BYTE one = 0;
    HRESULT hr = VF(s, CB_CreateFromByteArray, UINT32, const BYTE *, void **)(s, n, n ? (const BYTE *)data : &one, &b);
    if (FAILED(hr)) { t_check(0, __FILE__, __LINE__, "CreateFromByteArray", "hr=0x%08lx", (unsigned long)hr); return NULL; }
    return b;
}
UINT32 wr_unhex(const char *hex, BYTE *out) {
    UINT32 n = 0;
    while (hex[0] && hex[1]) {
        unsigned v; sscanf(hex, "%2x", &v); out[n++] = (BYTE)v; hex += 2;
    }
    return n;
}
void *wr_mkbuf_hex(const char *hex) {
    BYTE tmp[8192]; UINT32 n = wr_unhex(hex, tmp);
    return wr_mkbuf(tmp, n);
}
int wr_buf_get(void *buf, const BYTE **p, UINT32 *n) {
    void *ba = NULL; BYTE *d = NULL; UINT32 len = 0;
    if (!buf) return 0;
    if (FAILED(wr_qi(buf, &WR_IID_IBufferByteAccess, &ba))) return 0;
    if (FAILED(VF(buf, 7, UINT32 *)(buf, &len))) { wr_release(ba); return 0; }
    HRESULT hr = VF(ba, 3, BYTE **)(ba, &d);
    wr_release(ba);
    if (FAILED(hr)) return 0;
    *p = d; *n = len; return 1;
}
UINT32 wr_buf_len(void *buf) { UINT32 n = 0xFFFFFFFF; if (buf) VF(buf, 7, UINT32 *)(buf, &n); return n; }
int wr_buf_is(void *buf, const void *exp, UINT32 n) {
    const BYTE *p; UINT32 len;
    if (!wr_buf_get(buf, &p, &len)) return 0;
    return len == n && (n == 0 || !memcmp(p, exp, n));
}
int wr_buf_is_hex(void *buf, const char *hex) {
    BYTE tmp[8192]; UINT32 n = wr_unhex(hex, tmp);
    return wr_buf_is(buf, tmp, n);
}
void wr_hex(const void *p, UINT32 n, char *out) {
    static const char d[] = "0123456789abcdef";
    for (UINT32 i = 0; i < n; i++) { out[2*i] = d[((const BYTE *)p)[i] >> 4]; out[2*i+1] = d[((const BYTE *)p)[i] & 15]; }
    out[2*n] = 0;
}

/* ---- thin wrappers ------------------------------------------------------------------ */
static HRESULT open_alg(const WCHAR *cls, const WCHAR *alg, void **prov) {
    void *s = wr_cls_statics(cls); HRESULT hr; *prov = NULL;
    if (!s) return E_FAIL;
    HSTRING h = wr_hs(alg);
    hr = VF(s, 6, HSTRING, void **)(s, h, prov);
    wr_hsfree(h); wr_release(s);
    return hr;
}
HRESULT wr_hash_open(const WCHAR *a, void **p) { return open_alg(CLS_HASHPROV, a, p); }
HRESULT wr_mac_open(const WCHAR *a, void **p) { return open_alg(CLS_MACPROV, a, p); }
HRESULT wr_sym_open(const WCHAR *a, void **p) { return open_alg(CLS_SYMPROV, a, p); }
HRESULT wr_asym_open(const WCHAR *a, void **p) { return open_alg(CLS_ASYMPROV, a, p); }
HRESULT wr_kdf_open(const WCHAR *a, void **p) { return open_alg(CLS_KDFPROV, a, p); }
HRESULT wr_hash_data(void *prov, void *buf, void **out) { *out = NULL; return VF(prov, 8, void *, void **)(prov, buf, out); }
/* ISymmetricKeyAlgorithmProvider: get_AlgorithmName 6, get_BlockLength 7, CreateSymmetricKey 8 */
HRESULT wr_sym_key(void *prov, void *kb, void **key) { *key = NULL; return VF(prov, 8, void *, void **)(prov, kb, key); }

static void *g_eng;
void *wr_engine(void) {
    if (!g_eng) g_eng = wr_factory_iid(CLS_ENGINE, &WR_IID_ICryptographicEngineStatics);
    return g_eng;
}
HRESULT wr_encrypt(void *key, void *data, void *iv, void **out) {
    void *e = wr_engine(); *out = NULL;
    if (!e) return E_FAIL;
    return VF(e, EN_Encrypt, void *, void *, void *, void **)(e, key, data, iv, out);
}
HRESULT wr_decrypt(void *key, void *data, void *iv, void **out) {
    void *e = wr_engine(); *out = NULL;
    if (!e) return E_FAIL;
    return VF(e, EN_Decrypt, void *, void *, void *, void **)(e, key, data, iv, out);
}

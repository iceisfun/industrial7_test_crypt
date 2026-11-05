/* Shared helpers for the winrt_cryptography area.
 * WinRT is reached only through combase.dll exports resolved with GetProcAddress and through hand-written
 * vtable calls; the Windows.Security.Cryptography classes live in cryptowinrt.dll and are activated
 * via RoGetActivationFactory (or DllGetActivationFactory pinned to cryptowinrt.dll). */
#ifndef WR_H
#define WR_H
#include "t.h"
#include <objbase.h>
#include <hstring.h>
#include <winstring.h>
#include <roapi.h>

/* ---- raw COM vtable calls ------------------------------------------------ */
#define WR_VT(p)        (*(void ***)(p))
#define VF(p, slot, ...) ((HRESULT (WINAPI *)(void *, __VA_ARGS__))WR_VT(p)[slot])
#define VF0(p, slot)    ((HRESULT (WINAPI *)(void *))WR_VT(p)[slot])

#define EXPECT_HR(a, b) t_check((DWORD)(a) == (DWORD)(b), __FILE__, __LINE__, #a " == " #b, "got 0x%08lx want 0x%08lx", (unsigned long)(DWORD)(a), (unsigned long)(DWORD)(b))
#define HR_OK(hr)       SUCCEEDED(hr)

static inline HRESULT wr_qi(void *p, const GUID *iid, void **out) { if (out) *out = NULL; if (!p) return E_POINTER; return VF(p, 0, const GUID *, void **)(p, iid, out); }
static inline ULONG wr_addref(void *p) { if (!p) return 0; return ((ULONG (WINAPI *)(void *))WR_VT(p)[1])(p); }
static inline ULONG wr_release(void *p) { if (!p) return 0; return ((ULONG (WINAPI *)(void *))WR_VT(p)[2])(p); }
static inline HRESULT wr_getiids(void *p, ULONG *n, GUID **ids) { if (!p) return E_POINTER; return VF(p, 3, ULONG *, GUID **)(p, n, ids); }
static inline HRESULT wr_getclassname(void *p, HSTRING *s) { if (!p) return E_POINTER; return VF(p, 4, HSTRING *)(p, s); }
static inline HRESULT wr_gettrust(void *p, int *lvl) { if (!p) return E_POINTER; return VF(p, 5, int *)(p, lvl); }

/* ---- IIDs (verified in cryptowinrt.dll) ----------------------------------- */
extern const GUID WR_IID_IUnknown, WR_IID_IStream, WR_IID_IActivationFactory, WR_IID_IAgileObject, WR_IID_IMarshal, WR_IID_IInspectable,
    WR_IID_IBuffer, WR_IID_IBufferByteAccess, WR_IID_ICryptographicBufferStatics,
    WR_IID_IHashAlgorithmProviderStatics, WR_IID_IHashAlgorithmProvider, WR_IID_ICryptographicHash,
    WR_IID_IHashAlgorithmNamesStatics, WR_IID_ICryptographicEngineStatics, WR_IID_ICryptographicEngineStatics2,
    WR_IID_IAsymmetricKeyAlgorithmProviderStatics, WR_IID_IAsymmetricKeyAlgorithmProvider,
    WR_IID_IAsymmetricAlgorithmNamesStatics, WR_IID_IAsymmetricAlgorithmNamesStatics2,
    WR_IID_ICryptographicKey, WR_IID_IDataProtectionProviderFactory;

/* ---- runtime ----------------------------------------------------------------- */
void     wr_cofree(void *p);                   /* CoTaskMemFree via combase */
int      wr_init(void);                       /* RoInitialize(MTA) once; 0 if the runtime is unusable */
HSTRING  wr_hs(const WCHAR *s);               /* NULL for "" / NULL */
HSTRING  wr_hsn(const WCHAR *s, UINT32 n);    /* exact length (embedded NULs allowed) */
void     wr_hsfree(HSTRING h);
const WCHAR *wr_raw(HSTRING h, UINT32 *len);  /* never NULL */
int      wr_hs_eq(HSTRING h, const WCHAR *s); /* compare with a literal; consumes nothing */
HRESULT  wr_activate(const WCHAR *cls, void **fac);                  /* RoGetActivationFactory(IActivationFactory) */
/* Activate cls and return the interface at GetIids()[idx] (idx 0 = IActivationFactory).
 * Skips the test (and returns NULL) when the class is not activatable; on genuine Windows that is a failure. */
void    *wr_factory(const WCHAR *cls, ULONG idx);
void    *wr_factory_iid(const WCHAR *cls, const GUID *iid);          /* by explicit IID */
void    *wr_cls_statics(const WCHAR *cls);                           /* first non-IActivationFactory interface */

/* ---- buffers -------------------------------------------------------------------- */
void    *wr_mkbuf(const void *data, UINT32 n);          /* CryptographicBuffer.CreateFromByteArray */
void    *wr_mkbuf_hex(const char *hex);                 /* local hex -> IBuffer (via CreateFromByteArray) */
int      wr_buf_get(void *buf, const BYTE **p, UINT32 *n);  /* IBuffer.Length + IBufferByteAccess.Buffer */
int      wr_buf_is(void *buf, const void *exp, UINT32 n);   /* contents equal */
int      wr_buf_is_hex(void *buf, const char *hex);
UINT32   wr_buf_len(void *buf);
void     wr_hex(const void *p, UINT32 n, char *out);   /* lower-case hex into out (2n+1) */
UINT32   wr_unhex(const char *hex, BYTE *out);         /* local helper */

#define WR_NEED() do { if (!wr_init()) { t_skip("RoInitialize / combase unavailable"); return; } } while (0)
#define WR_STATICS(var, cls) void *var = wr_cls_statics(cls); if (!var) return
#define CLS_BUFFER  L"Windows.Security.Cryptography.CryptographicBuffer"
#define CLS_HASHPROV L"Windows.Security.Cryptography.Core.HashAlgorithmProvider"
#define CLS_HASHNAMES L"Windows.Security.Cryptography.Core.HashAlgorithmNames"
#define CLS_MACPROV L"Windows.Security.Cryptography.Core.MacAlgorithmProvider"
#define CLS_MACNAMES L"Windows.Security.Cryptography.Core.MacAlgorithmNames"
#define CLS_SYMPROV L"Windows.Security.Cryptography.Core.SymmetricKeyAlgorithmProvider"
#define CLS_SYMNAMES L"Windows.Security.Cryptography.Core.SymmetricAlgorithmNames"
#define CLS_ASYMPROV L"Windows.Security.Cryptography.Core.AsymmetricKeyAlgorithmProvider"
#define CLS_ASYMNAMES L"Windows.Security.Cryptography.Core.AsymmetricAlgorithmNames"
#define CLS_KDFPROV L"Windows.Security.Cryptography.Core.KeyDerivationAlgorithmProvider"
#define CLS_KDFNAMES L"Windows.Security.Cryptography.Core.KeyDerivationAlgorithmNames"
#define CLS_KDFPARAMS L"Windows.Security.Cryptography.Core.KeyDerivationParameters"
#define CLS_ENGINE  L"Windows.Security.Cryptography.Core.CryptographicEngine"
#define CLS_ECCNAMES L"Windows.Security.Cryptography.Core.EccCurveNames"
#define CLS_PERSISTED L"Windows.Security.Cryptography.Core.PersistedKeyProvider"
#define CLS_DATAPROT L"Windows.Security.Cryptography.DataProtection.DataProtectionProvider"

/* ---- typed wrappers for the interfaces used by several files ------------------------ */
/* ICryptographicBufferStatics (slots after IInspectable) */
enum { CB_Compare = 6, CB_GenerateRandom, CB_GenerateRandomNumber, CB_CreateFromByteArray, CB_CopyToByteArray,
       CB_DecodeFromHexString, CB_EncodeToHexString, CB_DecodeFromBase64String, CB_EncodeToBase64String,
       CB_ConvertStringToBinary, CB_ConvertBinaryToString };
void *wr_cbs(void);   /* cached ICryptographicBufferStatics */
HRESULT wr_hash_open(const WCHAR *alg, void **prov);   /* HashAlgorithmProvider.OpenAlgorithm */
HRESULT wr_hash_data(void *prov, void *buf, void **out);
HRESULT wr_mac_open(const WCHAR *alg, void **prov);
HRESULT wr_sym_open(const WCHAR *alg, void **prov);
HRESULT wr_sym_key(void *prov, void *keybuf, void **key);
HRESULT wr_asym_open(const WCHAR *alg, void **prov);
HRESULT wr_kdf_open(const WCHAR *alg, void **prov);
void   *wr_engine(void);       /* ICryptographicEngineStatics */
enum { EN_Encrypt = 6, EN_Decrypt, EN_EncryptAndAuthenticate, EN_DecryptAndAuthenticate, EN_Sign, EN_VerifySignature, EN_DeriveKeyMaterial };
HRESULT wr_encrypt(void *key, void *data, void *iv, void **out);
HRESULT wr_decrypt(void *key, void *data, void *iv, void **out);
#endif

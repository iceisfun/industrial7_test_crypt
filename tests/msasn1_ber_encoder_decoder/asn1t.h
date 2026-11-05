/* Shared definitions for the msasn1.dll / ntasn1.dll tests.
 * msasn1.h is not part of the mingw headers, so every structure is declared here from the
 * observed layouts of the Windows 10 x64 DLL.  All entry points are reached through
 * GetProcAddress (see asn1t.c); nothing is linked. */
#ifndef ASN1T_H
#define ASN1T_H
#include "t.h"

typedef unsigned long long U64;

/* ---- error codes (ASN1error_e) ---- */
#define E_OK          0
#define E_INTERNAL    (-1001)
#define E_EOD         (-1002)
#define E_CORRUPT     (-1003)
#define E_LARGE       (-1004)
#define E_CONSTRAINT  (-1005)
#define E_MEMORY      (-1006)
#define E_OVERFLOW    (-1007)
#define E_BADPDU      (-1008)
#define E_BADARGS     (-1009)
#define E_BADREAL     (-1010)
#define E_BADTAG      (-1011)
#define E_CHOICE      (-1012)
#define E_RULE        (-1013)
#define E_UTF8        (-1014)
#define E_NYI         (-1052)
#define W_EXTENDED    1001
#define W_NOEOD       1002

/* encoding rules */
#define R_BER 0x100
#define R_CER 0x200
#define R_DER 0x400
#define R_PER_ALIGNED 0x1
#define R_PER_UNALIGNED 0x2

/* ASN1_Encode / ASN1_Decode flags */
#define ENC_APPEND 1
#define ENC_REUSE 4
#define ENC_SETBUFFER 8
#define ENC_ALLOC 0x10
#define DEC_APPENDED 1
#define DEC_REWIND 4
#define DEC_SETBUFFER 8
#define DEC_AUTOFREE 0x10
#define FLG_NOASSERT 0x1000

/* ASN1_Set/Get*Option */
#define OPT_CHANGE_RULE 0x101
#define OPT_GET_RULE 0x201
#define OPT_NOT_REUSE_BUFFER 0x301
#define OPT_REWIND_BUFFER 0x302
#define OPT_SET_DECODED_BUFFER 0x501
#define OPT_DEL_DECODED_BUFFER 0x502
#define OPT_GET_DECODED_BUFFER_SIZE 0x601

/* tag values as taken by the primitives: class in bits 31..30, constructed 29, number in 28..0 */
#define TG_UNIV(n)  ((DWORD)(n))
#define TG_APP(n)   (0x40000000u | (n))
#define TG_CTX(n)   (0x80000000u | (n))
#define TG_PRIV(n)  (0xC0000000u | (n))
#define TG_CONS     0x20000000u
#define T_BOOL 1
#define T_INT 2
#define T_BITS 3
#define T_OCT 4
#define T_NULL 5
#define T_OID 6
#define T_ENUM 10
#define T_UTF8 12
#define T_SEQ 0x10
#define T_SET 0x11
#define T_PRINT 19
#define T_IA5 22
#define T_UTC 23
#define T_GEN 24
#define T_BMP 30

/* ---- structures ---- */
typedef struct { DWORD length; BYTE *value; } LV;          /* bit/octet/char/intx/open string */
typedef struct { DWORD length; char *value; } CSTR;
typedef struct { DWORD length; WORD *value; } C16STR;
typedef struct { DWORD length; DWORD *value; } C32STR;
typedef struct OIDN { struct OIDN *next; DWORD value; } OIDN;   /* ASN1objectidentifier_s */
typedef struct { WORD count; DWORD value[16]; } OID2;
typedef struct { WORD length; BYTE *value; } EOID;              /* ASN1encodedOID_t */
typedef struct {
    WORD year; BYTE month, day, hour, minute, second; WORD millisecond; BYTE universal; short diff;
} GTIME;
typedef struct { BYTE year, month, day, hour, minute, second, universal; short diff; } UTIME;

typedef struct MOD {              /* ASN1module_t, 0x30 bytes */
    DWORD name; int rule; DWORD flags; DWORD cPDUs;
    const void *freefn; const DWORD *sizes; const void *encfn; const void *decfn;
} MOD;
typedef struct ENC {              /* ASN1encoding_t, 0x50 bytes */
    DWORD magic, version; MOD *module; BYTE *buf; DWORD size, len; int err; DWORD bit;
    BYTE *pos; DWORD cbExtra; int rule; DWORD flags; DWORD pad1; struct ENC *parent; struct ENC *child;
} ENC;
typedef struct DEC {              /* ASN1decoding_t, 0x70 bytes */
    DWORD magic, version; MOD *module; BYTE *buf; DWORD size, len; int err; DWORD bit;
    BYTE *pos; int rule; DWORD flags; struct DEC *parent; struct DEC *child; DWORD level, usesbuf;
    void *pbuf; DWORD pbufsize, pad0; void *pcur; DWORD pleft, pad1;
} DEC;
typedef struct { int opt; int pad; union { int rule; DWORD size; struct { BYTE *buf; DWORD size; } b; } u; } OPTP;

C_ASSERT(sizeof(MOD) == 0x30);
C_ASSERT(sizeof(ENC) == 0x50);
C_ASSERT(sizeof(DEC) == 0x70);
C_ASSERT(offsetof(ENC, pos) == 0x28 && offsetof(ENC, rule) == 0x34 && offsetof(ENC, parent) == 0x40);
C_ASSERT(offsetof(DEC, pos) == 0x28 && offsetof(DEC, rule) == 0x30 && offsetof(DEC, parent) == 0x38 && offsetof(DEC, usesbuf) == 0x4c);
C_ASSERT(offsetof(GTIME, millisecond) == 8 && offsetof(GTIME, diff) == 12);
C_ASSERT(offsetof(UTIME, diff) == 8);

/* ---- API table: X(name, return type, (arguments)) ---- */
#define H void *
#define API_LIST(X) \
 X(ASN1_CreateModule, MOD *, (DWORD, int, DWORD, DWORD, const void *, const void *, const void *, const DWORD *, DWORD)) \
 X(ASN1_CloseModule, void, (MOD *)) \
 X(ASN1_CreateEncoder, int, (MOD *, ENC **, BYTE *, DWORD, ENC *)) \
 X(ASN1_CreateDecoder, int, (MOD *, DEC **, BYTE *, DWORD, DEC *)) \
 X(ASN1_CreateDecoderEx, int, (MOD *, DEC **, BYTE *, DWORD, DEC *, DWORD)) \
 X(ASN1_CloseEncoder, void, (ENC *)) \
 X(ASN1_CloseEncoder2, void, (ENC *)) \
 X(ASN1_CloseDecoder, void, (DEC *)) \
 X(ASN1_Encode, int, (ENC *, void *, DWORD, DWORD, BYTE *, DWORD)) \
 X(ASN1_Decode, int, (DEC *, void **, DWORD, DWORD, BYTE *, DWORD)) \
 X(ASN1_FreeEncoded, void, (ENC *, void *)) \
 X(ASN1_FreeDecoded, void, (DEC *, void *, DWORD)) \
 X(ASN1_SetEncoderOption, int, (ENC *, OPTP *)) \
 X(ASN1_GetEncoderOption, int, (ENC *, OPTP *)) \
 X(ASN1_SetDecoderOption, int, (DEC *, OPTP *)) \
 X(ASN1_GetDecoderOption, int, (DEC *, OPTP *)) \
 X(ASN1EncSetError, int, (ENC *, int)) \
 X(ASN1DecSetError, int, (DEC *, int)) \
 X(ASN1DecAlloc, void *, (DEC *, DWORD)) \
 X(ASN1DecRealloc, void *, (DEC *, void *, DWORD)) \
 X(ASN1Free, void, (void *)) \
 X(ASN1BEREncCheck, U64, (ENC *, DWORD)) \
 X(ASN1BEREncFlush, U64, (ENC *)) \
 X(ASN1BEREncLength, U64, (ENC *, DWORD)) \
 X(ASN1BEREncTag, U64, (ENC *, DWORD)) \
 X(ASN1BEREncEndOfContents, U64, (ENC *, DWORD)) \
 X(ASN1BEREncExplicitTag, U64, (ENC *, DWORD, DWORD *)) \
 X(ASN1BEREncBool, U64, (ENC *, DWORD, int)) \
 X(ASN1BEREncNull, U64, (ENC *, DWORD)) \
 X(ASN1BEREncS32, U64, (ENC *, DWORD, int)) \
 X(ASN1BEREncU32, U64, (ENC *, DWORD, DWORD)) \
 X(ASN1BEREncSX, U64, (ENC *, DWORD, LV *)) \
 X(ASN1BEREncBitString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1BEREncOctetString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1BEREncCharString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1BEREncChar16String, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1BEREncChar32String, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1BEREncUTF8String, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1BEREncMultibyteString, U64, (ENC *, DWORD, CSTR *)) \
 X(ASN1BEREncZeroMultibyteString, U64, (ENC *, DWORD, const char *)) \
 X(ASN1BEREncObjectIdentifier, U64, (ENC *, DWORD, OIDN **)) \
 X(ASN1BEREncObjectIdentifier2, U64, (ENC *, DWORD, OID2 *)) \
 X(ASN1BEREncEoid, U64, (ENC *, DWORD, EOID *)) \
 X(ASN1BEREncOpenType, U64, (ENC *, LV *)) \
 X(ASN1BEREncGeneralizedTime, U64, (ENC *, DWORD, GTIME *)) \
 X(ASN1BEREncUTCTime, U64, (ENC *, DWORD, UTIME *)) \
 X(ASN1BEREncDouble, U64, (ENC *, DWORD, double)) \
 X(ASN1BEREncRemoveZeroBits, U64, (DWORD *, const BYTE *)) \
 X(ASN1BEREncRemoveZeroBits2, U64, (DWORD *, const BYTE *, DWORD)) \
 X(ASN1BERDotVal2Eoid, U64, (ENC *, const char *, EOID *)) \
 X(ASN1BEREoid2DotVal, U64, (DEC *, EOID *, char **)) \
 X(ASN1BEREoid_free, void, (EOID *)) \
 X(ASN1DEREncBitString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1DEREncOctetString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1DEREncCharString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1DEREncChar16String, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1DEREncChar32String, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1DEREncUTF8String, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1DEREncMultibyteString, U64, (ENC *, DWORD, CSTR *)) \
 X(ASN1DEREncZeroMultibyteString, U64, (ENC *, DWORD, const char *)) \
 X(ASN1DEREncGeneralizedTime, U64, (ENC *, DWORD, GTIME *)) \
 X(ASN1DEREncUTCTime, U64, (ENC *, DWORD, UTIME *)) \
 X(ASN1DEREncBeginBlk, U64, (ENC *, int, void **)) \
 X(ASN1DEREncNewBlkElement, U64, (void *, ENC **)) \
 X(ASN1DEREncFlushBlkElement, U64, (void *)) \
 X(ASN1DEREncEndBlk, U64, (void *)) \
 X(ASN1CEREncBeginBlk, U64, (ENC *, int, void **)) \
 X(ASN1CEREncNewBlkElement, U64, (void *, ENC **)) \
 X(ASN1CEREncFlushBlkElement, U64, (void *)) \
 X(ASN1CEREncEndBlk, U64, (void *)) \
 X(ASN1CEREncBitString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1CEREncOctetString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1CEREncCharString, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1CEREncChar16String, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1CEREncChar32String, U64, (ENC *, DWORD, DWORD, const void *)) \
 X(ASN1CEREncMultibyteString, U64, (ENC *, DWORD, CSTR *)) \
 X(ASN1CEREncZeroMultibyteString, U64, (ENC *, DWORD, const char *)) \
 X(ASN1CEREncGeneralizedTime, U64, (ENC *, DWORD, GTIME *)) \
 X(ASN1CEREncUTCTime, U64, (ENC *, DWORD, UTIME *)) \
 X(ASN1BERDecCheck, U64, (DEC *, DWORD)) \
 X(ASN1BERDecFlush, U64, (DEC *)) \
 X(ASN1BERDecLength, U64, (DEC *, DWORD *, int *)) \
 X(ASN1BERDecTag, U64, (DEC *, DWORD, DWORD *)) \
 X(ASN1BERDecPeekTag, U64, (DEC *, DWORD *)) \
 X(ASN1BERDecEndOfContents, U64, (DEC *, DEC *, const BYTE *)) \
 X(ASN1BERDecNotEndOfContents, U64, (DEC *, const BYTE *)) \
 X(ASN1BERDecExplicitTag, U64, (DEC *, DWORD, DEC **, const BYTE **)) \
 X(ASN1BERDecSkip, U64, (DEC *)) \
 X(ASN1BERDecBool, U64, (DEC *, DWORD, BYTE *)) \
 X(ASN1BERDecNull, U64, (DEC *, DWORD)) \
 X(ASN1BERDecU8Val, U64, (DEC *, DWORD, BYTE *)) \
 X(ASN1BERDecS8Val, U64, (DEC *, DWORD, signed char *)) \
 X(ASN1BERDecU16Val, U64, (DEC *, DWORD, WORD *)) \
 X(ASN1BERDecS16Val, U64, (DEC *, DWORD, short *)) \
 X(ASN1BERDecU32Val, U64, (DEC *, DWORD, DWORD *)) \
 X(ASN1BERDecS32Val, U64, (DEC *, DWORD, int *)) \
 X(ASN1BERDecSXVal, U64, (DEC *, DWORD, LV *)) \
 X(ASN1BERDecBitString, U64, (DEC *, DWORD, LV *)) \
 X(ASN1BERDecBitString2, U64, (DEC *, DWORD, LV *)) \
 X(ASN1BERDecOctetString, U64, (DEC *, DWORD, LV *)) \
 X(ASN1BERDecOctetString2, U64, (DEC *, DWORD, LV *)) \
 X(ASN1BERDecOpenType, U64, (DEC *, LV *)) \
 X(ASN1BERDecOpenType2, U64, (DEC *, LV *)) \
 X(ASN1BERDecObjectIdentifier, U64, (DEC *, DWORD, OIDN **)) \
 X(ASN1BERDecObjectIdentifier2, U64, (DEC *, DWORD, OID2 *)) \
 X(ASN1BERDecEoid, U64, (DEC *, DWORD, EOID *)) \
 X(ASN1BERDecUTF8String, U64, (DEC *, DWORD, LV *)) \
 X(ASN1BERDecCharString, U64, (DEC *, DWORD, CSTR *)) \
 X(ASN1BERDecChar16String, U64, (DEC *, DWORD, C16STR *)) \
 X(ASN1BERDecChar32String, U64, (DEC *, DWORD, C32STR *)) \
 X(ASN1BERDecMultibyteString, U64, (DEC *, DWORD, CSTR *)) \
 X(ASN1BERDecZeroCharString, U64, (DEC *, DWORD, char **)) \
 X(ASN1BERDecZeroChar16String, U64, (DEC *, DWORD, WORD **)) \
 X(ASN1BERDecZeroChar32String, U64, (DEC *, DWORD, DWORD **)) \
 X(ASN1BERDecZeroMultibyteString, U64, (DEC *, DWORD, char **)) \
 X(ASN1BERDecGeneralizedTime, U64, (DEC *, DWORD, GTIME *)) \
 X(ASN1BERDecUTCTime, U64, (DEC *, DWORD, UTIME *)) \
 X(ASN1BERDecDouble, U64, (DEC *, DWORD, double *)) \
 X(ASN1bitstring_cmp, int, (LV *, LV *, int)) \
 X(ASN1bitstring_free, void, (LV *)) \
 X(ASN1octetstring_cmp, int, (LV *, LV *)) \
 X(ASN1octetstring_free, void, (LV *)) \
 X(ASN1open_cmp, int, (LV *, LV *)) \
 X(ASN1open_free, void, (LV *)) \
 X(ASN1charstring_cmp, int, (CSTR *, CSTR *)) \
 X(ASN1charstring_free, void, (CSTR *)) \
 X(ASN1char16string_cmp, int, (C16STR *, C16STR *)) \
 X(ASN1char16string_free, void, (C16STR *)) \
 X(ASN1char32string_cmp, int, (C32STR *, C32STR *)) \
 X(ASN1char32string_free, void, (C32STR *)) \
 X(ASN1ztcharstring_cmp, int, (char **, char **)) \
 X(ASN1ztcharstring_free, void, (char **)) \
 X(ASN1ztchar16string_cmp, int, (WCHAR **, WCHAR **)) \
 X(ASN1ztchar16string_free, void, (WCHAR **)) \
 X(ASN1ztchar32string_cmp, int, (DWORD **, DWORD **)) \
 X(ASN1ztchar32string_free, void, (DWORD **)) \
 X(ASN1utf8string_free, void, (LV *)) \
 X(ASN1generalizedtime_cmp, int, (GTIME *, GTIME *)) \
 X(ASN1utctime_cmp, int, (UTIME *, UTIME *)) \
 X(ASN1objectidentifier_cmp, int, (OIDN **, OIDN **)) \
 X(ASN1objectidentifier_free, void, (OIDN **)) \
 X(ASN1objectidentifier2_cmp, int, (OID2 *, OID2 *)) \
 X(ASN1intx_cmp, int, (LV *, LV *)) \
 X(ASN1intx_free, void, (LV *)) \
 X(ASN1intx_add, void, (LV *, LV *, LV *)) \
 X(ASN1intx_sub, void, (LV *, LV *, LV *)) \
 X(ASN1intx_setuint32, void, (LV *, DWORD)) \
 X(ASN1intx_uoctets, DWORD, (LV *)) \
 X(ASN1intx2int32, int, (LV *)) \
 X(ASN1intx2uint32, DWORD, (LV *)) \
 X(ASN1intxisuint32, int, (LV *)) \
 X(ASN1uint32_uoctets, DWORD, (DWORD))

typedef struct {
#define X(n, r, a) r (WINAPI *n) a;
    API_LIST(X)
#undef X
} api_t;
extern api_t A;                 /* filled before any test runs; members are NULL when the export is absent */
extern HMODULE g_msasn1;

/* ---- test rig ---- */
typedef struct { MOD *m; ENC *e; DEC *d; } Rig;
MOD *rig_module(int rule, DWORD flags);                    /* 4-PDU module, see asn1t.c */
int  rig_enc(Rig *r, int rule);                            /* module + allocating encoder */
int  rig_dec(Rig *r, int rule, const void *data, DWORD n); /* module + decoder over data */
void rig_done(Rig *r);
void expect_bytes(const char *file, int line, const void *got, size_t gl, const void *want, size_t wl);
#define EXPECT_BYTES(g, gl, w, wl) expect_bytes(__FILE__, __LINE__, (g), (gl), (w), (wl))
/* check the encoder content (after BEREncFlush) */
void expect_enc(const char *file, int line, Rig *r, const void *want, size_t wl);
#define EXPECT_ENC(r, w, wl) expect_enc(__FILE__, __LINE__, (r), (w), (wl))
#define OK8(v) (((U64)(v) & 0xff) != 0)
#define NEED(fn) do { if (!A.fn) { t_skip("missing export: " #fn); return; } } while (0)

/* counters / hooks used by the PDU stubs */
extern int g_freecalls[4];
extern const DWORD pdu_sizes[4];

/* ntasn1 context views (see ntasn1.c) */
#endif

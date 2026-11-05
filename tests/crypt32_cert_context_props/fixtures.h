#ifndef FIXTURES_H
#define FIXTURES_H
#include "t.h"
#include <wincrypt.h>
typedef struct { const char *name; const BYTE *der; DWORD cb; int version; const BYTE *serial_le; DWORD cbSerial;
  BYTE sha1[20], md5[16], sha256[32], sighash[48]; DWORD cbSigHash; BYTE subjmd5[16], issmd5[16], pubmd5[16], issser_md5[16]; BYTE spkisha1[20]; BYTE ski[20]; int hasski; BYTE aki[20]; int hasaki;
  const BYTE *subj; DWORD cbSubj; const BYTE *iss; DWORD cbIss; const BYTE *pub; DWORD cbPub; const BYTE *spki; DWORD cbSpki;
  const char *sigoid, *keyoid; int cbSigPara, cbKeyPara; BYTE keypara[16]; int cext; int nb[6], na[6]; } FX;
extern const FX fx_ec256;
extern const FX fx_ec384v1;
extern const FX fx_expired;
extern const FX fx_future;
extern const FX fx_inter;
extern const FX fx_leaf;
extern const FX fx_leaf2;
extern const FX fx_leafexp;
extern const FX fx_leaffut;
extern const FX fx_leafi;
extern const FX fx_negserial;
extern const FX fx_nestbad;
extern const FX fx_nestbad2;
extern const FX fx_root;
extern const FX fx_root2;
extern const FX fx_rsa1024;
extern const FX fx_sha1leaf;
extern const FX fx_utf8;
#endif

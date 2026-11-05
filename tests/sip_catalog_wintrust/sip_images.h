/* Hand-built deterministic subject images (PE32+, CAB). Pure C, no Windows dependency, so the same
 * builder can be compiled natively at authoring time to compute reference digests with python. */
#ifndef SIP_IMAGES_H
#define SIP_IMAGES_H
#include <stddef.h>
#include <string.h>

typedef unsigned char u8;
static void sipi_w16(u8 *p, unsigned v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }
static void sipi_w32(u8 *p, unsigned v) { sipi_w16(p, v & 0xffff); sipi_w16(p + 2, v >> 16); }
static void sipi_w64(u8 *p, unsigned long long v) { sipi_w32(p, (unsigned)v); sipi_w32(p + 4, (unsigned)(v >> 32)); }

#define SIPI_PE_LFANEW      0x80
#define SIPI_PE_OH          (SIPI_PE_LFANEW + 4 + 20)          /* optional header */
#define SIPI_PE_CHKSUM_OFF  (SIPI_PE_OH + 64)
#define SIPI_PE_CERTDIR_OFF (SIPI_PE_OH + 112 + 4 * 8)
#define SIPI_PE_SECT_OFF    (SIPI_PE_OH + 240)

/* variants: 0 = one .text section (file 0x400)       1 = variant 0 + 32 trailing bytes
 *           2 = .text + .data sections (file 0x600)  3 = variant 0 with non-zero CheckSum field */
enum { SIPI_PE_BASE = 0, SIPI_PE_TRAILER = 1, SIPI_PE_TWOSECT = 2, SIPI_PE_CHECKSUM = 3, SIPI_PE_NVARIANTS = 4 };

static size_t sipi_pe(unsigned variant, u8 *b, size_t cap)
{
    unsigned nsec = variant == SIPI_PE_TWOSECT ? 2 : 1;
    size_t size = 0x200 + 0x200 * nsec + (variant == SIPI_PE_TRAILER ? 32 : 0), i;
    if (cap < size) return 0;
    memset(b, 0, size);
    b[0] = 'M'; b[1] = 'Z';
    sipi_w32(b + 0x3c, SIPI_PE_LFANEW);
    for (i = 2; i < 0x3c; i++) b[i] = (u8)(i * 5 + 1);           /* deterministic DOS stub bytes */
    for (i = 0x40; i < SIPI_PE_LFANEW; i++) b[i] = (u8)(i * 3);
    u8 *p = b + SIPI_PE_LFANEW;
    memcpy(p, "PE\0\0", 4);
    sipi_w16(p + 4, 0x8664);                  /* Machine */
    sipi_w16(p + 6, nsec);
    sipi_w32(p + 8, 0x5F000000);              /* TimeDateStamp */
    sipi_w16(p + 20, 240);                    /* SizeOfOptionalHeader */
    sipi_w16(p + 22, 0x0022);                 /* EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE */
    u8 *o = b + SIPI_PE_OH;
    sipi_w16(o, 0x20b);
    o[2] = 14;
    sipi_w32(o + 4, 0x200);                   /* SizeOfCode */
    sipi_w32(o + 16, 0x1000);                 /* AddressOfEntryPoint */
    sipi_w32(o + 20, 0x1000);                 /* BaseOfCode */
    sipi_w64(o + 24, 0x140000000ULL);         /* ImageBase */
    sipi_w32(o + 32, 0x1000);                 /* SectionAlignment */
    sipi_w32(o + 36, 0x200);                  /* FileAlignment */
    sipi_w16(o + 40, 6); sipi_w16(o + 48, 6); /* OS / subsystem versions */
    sipi_w32(o + 56, 0x1000 + 0x1000 * nsec); /* SizeOfImage */
    sipi_w32(o + 60, 0x200);                  /* SizeOfHeaders */
    sipi_w32(o + 64, variant == SIPI_PE_CHECKSUM ? 0x12345678u : 0);
    sipi_w16(o + 68, 3);                      /* console subsystem */
    sipi_w16(o + 70, 0x8120);                 /* DllCharacteristics */
    sipi_w64(o + 72, 0x100000); sipi_w64(o + 80, 0x1000);
    sipi_w64(o + 88, 0x100000); sipi_w64(o + 96, 0x1000);
    sipi_w32(o + 108, 16);                    /* NumberOfRvaAndSizes */
    u8 *s = b + SIPI_PE_SECT_OFF;
    memcpy(s, ".text\0\0\0", 8);
    sipi_w32(s + 8, 0x10); sipi_w32(s + 12, 0x1000); sipi_w32(s + 16, 0x200); sipi_w32(s + 20, 0x200);
    sipi_w32(s + 36, 0x60000020);
    if (nsec == 2) {
        s += 40;
        memcpy(s, ".data\0\0\0", 8);
        sipi_w32(s + 8, 0x40); sipi_w32(s + 12, 0x2000); sipi_w32(s + 16, 0x200); sipi_w32(s + 20, 0x400);
        sipi_w32(s + 36, 0xC0000040);
    }
    for (i = 0; i < 0x200 * nsec; i++) b[0x200 + i] = (u8)(i * 7 + 3);
    b[0x200] = 0x31; b[0x201] = 0xC0; b[0x202] = 0xC3;           /* xor eax,eax ; ret */
    if (variant == SIPI_PE_TRAILER) for (i = 0; i < 32; i++) b[0x400 + i] = (u8)(0xA0 + i);
    return size;
}

/* A minimal valid cabinet: one folder (stored), one file "a.txt" holding "hello", no reserve area. */
#define SIPI_CAB_SIZE 79
static size_t sipi_cab(u8 *b, size_t cap)
{
    if (cap < SIPI_CAB_SIZE) return 0;
    memset(b, 0, SIPI_CAB_SIZE);
    memcpy(b, "MSCF", 4);
    sipi_w32(b + 8, SIPI_CAB_SIZE);           /* cbCabinet */
    sipi_w32(b + 16, 44);                     /* coffFiles */
    b[24] = 3; b[25] = 1;                     /* version 1.3 */
    sipi_w16(b + 26, 1);                      /* cFolders */
    sipi_w16(b + 28, 1);                      /* cFiles */
    sipi_w16(b + 30, 0);                      /* flags */
    sipi_w16(b + 32, 0x1234);                 /* setID */
    /* CFFOLDER at 36 */
    sipi_w32(b + 36, 66); sipi_w16(b + 40, 1); sipi_w16(b + 42, 0);
    /* CFFILE at 44 */
    sipi_w32(b + 44, 5); sipi_w32(b + 48, 0); sipi_w16(b + 52, 0);
    sipi_w16(b + 54, 0x5821); sipi_w16(b + 56, 0x6000); sipi_w16(b + 58, 0x20);
    memcpy(b + 60, "a.txt", 6);
    /* CFDATA at 66 */
    sipi_w32(b + 66, 0); sipi_w16(b + 70, 5); sipi_w16(b + 72, 5);
    memcpy(b + 74, "hello", 5);
    return SIPI_CAB_SIZE;
}
#endif

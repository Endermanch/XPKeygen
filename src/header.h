//
// Created by Andrew on 09/04/2023.
//

#ifndef KEYGEN_HEADER_H
#define KEYGEN_HEADER_H

#include <cstdio>
#include <cstring>
#include <cassert>

#include <windows.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#pragma warning(disable: 6387)

// Arithmetic macros
#define PK_LENGTH                       25
#define NULL_TERMINATOR                 1

#define FIELD_BITS                      384
#define FIELD_BYTES                     (FIELD_BITS / 8)

#define FIELD_BITS_2003                 512
#define FIELD_BYTES_2003                (FIELD_BITS_2003 / 8)

#define FIELD_BITS_MAX                  FIELD_BITS_2003
#define FIELD_BYTES_MAX                 FIELD_BYTES_2003

#define SHA_MSG_LENGTH_XP               (4 + 2 * FIELD_BYTES)
#define SHA_MSG_LENGTH_2003             (3 + 2 * FIELD_BYTES_2003)

#define FIELD_LENGTH_MAX                (FIELD_BYTES_MAX * 2 + NULL_TERMINATOR)

#define NEXTSNBITS(field, n, offset)    (((QWORD)(field) >> (offset)) & ((1ULL << (n)) - 1))
#define FIRSTNBITS(field, n)            NEXTSNBITS((field), (n), 0)

#define HIBYTES(field, bytes)           NEXTSNBITS((QWORD)(field), ((bytes) * 8), ((bytes) * 8))
#define LOBYTES(field, bytes)           FIRSTNBITS((QWORD)(field), ((bytes) * 8))

#define BYDWORD(n)                      (DWORD)(*((n) + 0) | *((n) + 1) << 8 | *((n) + 2) << 16 | *((n) + 3) << 24)
#define BYDWORDBE(n)                    (DWORD)(*((n) + 3) | *((n) + 2) << 8 | *((n) + 1) << 16 | *((n) + 0) << 24)
#define BITMASK(n)                      ((1ULL << (n)) - 1)

// Control macros
#define IDC_BUTTON1 1000
#define IDC_BUTTON2 1001
#define IDC_BUTTON3 1002
#define IDC_BUTTON4 1003

#define IDC_COMBO1  1020

#define IDC_RADIO1  1030
#define IDC_RADIO2  1031

#define IDC_CHECK1  1036

#define IDC_EDIT1   1040

#define IDC_INPUT1  1060
#define IDC_INPUT2  1061
#define IDC_INPUT3  1062

#define IDC_IMAGE1  1080
#define IDC_IMAGE2  1081

#define IDC_LABEL1  1105
#define IDC_LABEL2  1106
#define IDC_LABEL3  1107
#define IDC_LABEL4  1108
#define IDC_LABEL5  1109
#define IDC_LABEL6  1110

// Resource macros
#define BINK_RETAIL     MAKEINTRESOURCEW(1)
#define BINK_OEM        MAKEINTRESOURCEW(2)

#define RT_BINK         TEXT("BINK")

// Type definitions
typedef uint64_t QWORD;

// Structures
typedef struct _EC_BYTE_POINT {
    CHAR x[FIELD_LENGTH_MAX];   // x-coordinate of the point on the elliptic curve.
    CHAR y[FIELD_LENGTH_MAX];   // y-coordinate of the point on the elliptic curve.
} EC_BYTE_POINT;

typedef struct _BINKHDR {
    // Original BINK header.
    ULONG32 dwSize;
    ULONG32 dwHeaderLength;
    ULONG32 dwChecksum;
    ULONG32 dwVersion;
    ULONG32 dwKeySizeInDWORDs;
    ULONG32 dwHashLength;
    ULONG32 dwSignatureLength;

    // Extended BINK header. (Windows Server 2003+)
    ULONG32 dwAuthCodeLength;
    ULONG32 dwProductIDLength;
} BINKHDR, *PBINKHDR;

typedef struct _BINKDATA {
    CHAR p[FIELD_LENGTH_MAX];   // Finite Field order p.
    CHAR a[FIELD_LENGTH_MAX];   // Elliptic Curve parameter a.
    CHAR b[FIELD_LENGTH_MAX];   // Elliptic Curve parameter b.

    EC_BYTE_POINT G;            // Base point (Generator) G.
    EC_BYTE_POINT K;            // Public key K.
} BINKDATA, *PBINKDATA;

typedef struct _BINKEY {
    BINKHDR  header;
    BINKDATA data;
} BINKEY, *PBINKEY;

typedef struct _BINKEYEX {
    // ID of the BINK. (Separate from the BINKEY structure per spec)
    ULONG32 dwID;

    // BINKEY structure.
    BINKEY binKey;

    // Calculated values.
    EC_BYTE_POINT I;            // Inverse of the public key K.
    QWORD n;                    // Order of the generator G.
    QWORD k;                    // Private Key k.
} BINKEYEX, *PBINKEYEX;

extern BINKEYEX  pBINKPreset;
extern CHAR      pCharset[];


// xp.cpp
VOID unpackXP(
    QWORD (&pRaw)[2],
     BOOL &pUpgrade,
    DWORD &pChannelID,
    DWORD &pSequence,
    DWORD &pHash,
    QWORD &pSignature
);

VOID packXP(
    QWORD (&pRaw)[2],
     BOOL pUpgrade,
    DWORD pChannelID,
    DWORD pSequence,
    DWORD pHash,
    QWORD pSignature
);

VOID generateXPKey(
    EC_GROUP *eCurve,
    EC_POINT *basePoint,
      BIGNUM *genOrder,
      BIGNUM *privateKey,
       DWORD pChannelID,
       DWORD pSequence,
        BOOL pUpgrade,
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]
);

BOOL keyXP(
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR],
    BINKEYEX &pBINK,
       DWORD nChannelID,
       DWORD nSequence,
        BOOL bUpgrade
);


// server.cpp
VOID unpackServer(
    QWORD (&pRaw)[2],
     BOOL &pUpgrade,
    DWORD &pChannelID,
    DWORD &pHash,
    QWORD &pSignature,
    DWORD &pAuthInfo
);

VOID packServer(
    QWORD (&pRaw)[2],
     BOOL pUpgrade,
    DWORD pChannelID,
    DWORD pHash,
    QWORD pSignature,
    DWORD pAuthInfo
);

BOOL verifyServerKey(
    EC_GROUP *eCurve,
    EC_POINT *basePoint,
    EC_POINT *publicKey,
        CHAR (&cdKey)[PK_LENGTH + NULL_TERMINATOR]
);

VOID generateServerKey(
    EC_GROUP *eCurve,
    EC_POINT *basePoint,
      BIGNUM *genOrder,
      BIGNUM *privateKey,
       DWORD pChannelID,
       DWORD pAuthInfo,
        BOOL pUpgrade,
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]
);

BOOL keyServer(
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR],
    BINKEYEX &pBINK,
       DWORD nChannelID,
       DWORD nAuthInfo,
        BOOL bUpgrade
);


// utilities.cpp
void endian(byte *data, int length);
DWORD randomRange(DWORD dwLow, DWORD dwHigh);

void stopAudio();
bool playAudio(HINSTANCE hInstance, WCHAR *lpName, UINT bFlags);

EC_GROUP *initializeEllipticCurve(
    CONST CHAR *pSel,
    CONST CHAR *aSel,
    CONST CHAR *bSel,
    CONST CHAR *generatorXSel,
    CONST CHAR *generatorYSel,
    CONST CHAR *publicKeyXSel,
    CONST CHAR *publicKeyYSel,
      EC_POINT **genPoint,
      EC_POINT **pubPoint
);

int BN_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);


// key.cpp
bool unbase24(BYTE *byteSeq, CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]);
void base24(BYTE *byteSeq, CHAR(&pKey)[PK_LENGTH + NULL_TERMINATOR]);

VOID formatXP(BOOL bUpgrade, WCHAR *pBSection, WCHAR *pCSection, WCHAR *pText);
VOID formatServer(BOOL bUpgrade, WCHAR *pBSection, WCHAR *pAuthSection, WCHAR *pText);


// windows.cpp
bool InitializeWindow(HINSTANCE hInstance);


// bink.cpp
VOID InitializePreset(UINT nIndex, BINKEYEX *pBINK);
UINT countResources(WCHAR *pName);

#endif //KEYGEN_HEADER_H

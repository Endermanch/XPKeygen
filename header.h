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

#define PK_LENGTH                       25
#define NULL_TERMINATOR                 1

#define FIELD_BITS                      384
#define FIELD_BYTES                     (FIELD_BITS / 8)

#define FIELD_BITS_2003                 512
#define FIELD_BYTES_2003                (FIELD_BITS_2003 / 8)

#define SHA_MSG_LENGTH_XP               (4 + 2 * FIELD_BYTES)
#define SHA_MSG_LENGTH_2003             (3 + 2 * FIELD_BYTES_2003)

#define NEXTSNBITS(field, n, offset)    (((QWORD)(field) >> (offset)) & ((1ULL << (n)) - 1))
#define FIRSTNBITS(field, n)            NEXTSNBITS((field), (n), 0)

#define HIBYTES(field, bytes)           NEXTSNBITS((QWORD)(field), ((bytes) * 8), ((bytes) * 8))
#define LOBYTES(field, bytes)           FIRSTNBITS((QWORD)(field), ((bytes) * 8))

#define BYDWORD(n)                      (DWORD)(*((n) + 0) | *((n) + 1) << 8 | *((n) + 2) << 16 | *((n) + 3) << 24)
#define BITMASK(n)                      ((1ULL << (n)) - 1)

#define IDC_BUTTON1 1000
#define IDC_BUTTON2 1001
#define IDC_BUTTON3 1002
#define IDC_BUTTON4 1003

#define IDC_RADIO1  1005
#define IDC_RADIO2  1006

#define IDC_EDIT1   1010

#define IDC_INPUT1  1020
#define IDC_INPUT2  1021

#define IDC_IMAGE1  1050
#define IDC_IMAGE2  1051

#define IDC_LABEL1  1055
#define IDC_LABEL2  1056
#define IDC_LABEL3  1057
#define IDC_LABEL4  1058
#define IDC_LABEL5  1059

typedef uint64_t QWORD;

extern char pCharset[];

extern const char pXP[];
extern const long aXP;
extern const long bXP;


// xp.cpp
VOID unpackXP(
    QWORD (&pRaw)[2],
     BOOL &pUpgrade,
    DWORD &pSerial,
    DWORD &pHash,
    QWORD &pSignature
);

VOID packXP(
    QWORD (&pRaw)[2],
     BOOL pUpgrade,
    DWORD pSerial,
    DWORD pHash,
    QWORD pSignature
);

BOOL verifyXPKey(
    EC_GROUP *eCurve,
    EC_POINT *basePoint,
    EC_POINT *publicKey,
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]
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
    CHAR(&pKey)[PK_LENGTH + NULL_TERMINATOR],
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
    const char *pSel,
    long aSel,
    long bSel,
    const char *generatorXSel,
    const char *generatorYSel,
    const char *publicKeyXSel,
    const char *publicKeyYSel,
    BIGNUM *genOrderSel,
    BIGNUM *privateKeySel,
    EC_POINT **genPoint,
    EC_POINT **pubPoint
);

int BN_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);


// key.cpp
bool unbase24(BYTE *byteSeq, CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]);
void base24(BYTE *byteSeq, CHAR(&pKey)[PK_LENGTH + NULL_TERMINATOR]);

void formatXP(WCHAR *pBSection, WCHAR *pCSection, WCHAR *pText);
void formatServer(WCHAR *pText);


// windows.cpp
bool InitializeWindow(HINSTANCE hInstance);


// bink.cpp
void base(WCHAR *pPath);

#endif //KEYGEN_HEADER_H

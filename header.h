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

#define FIELD_BITS 384
#define FIELD_BYTES (FIELD_BITS / 8)

#define FIELD_BITS_2003 512
#define FIELD_BYTES_2003 (FIELD_BITS_2003 / 8)

#define PK_LENGTH 25
#define NULL_TERMINATOR 1

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

typedef unsigned long ul32;

extern byte charset[];

extern const char pXP[];
extern const long aXP;
extern const long bXP;

// xp.cpp
bool keyXP(
        char *pKey,
        ul32 nRaw
);

void unpackXP(
        ul32 *serial,
        ul32 *hash,
        ul32 *sig,
        ul32 *raw
);

void packXP(
        ul32 *raw,
        ul32 *serial,
        ul32 *hash,
        ul32 *sig
);

bool verifyXPKey(
        EC_GROUP    *eCurve,
        EC_POINT    *generator,
        EC_POINT    *publicKey,
        char        *cdKey
);

void generateXPKey(
        char        *pKey,
        EC_GROUP    *eCurve,
        EC_POINT    *generator,
        BIGNUM      *order,
        BIGNUM      *privateKey,
        ul32        *pRaw
);

// server.cpp
bool keyServer(
        char *pKey
);

void unpackServer(
        ul32 *osFamily,
        ul32 *hash,
        ul32 *sig,
        ul32 *prefix,
        ul32 *raw
);

void packServer(
        ul32 *raw,
        ul32 *osFamily,
        ul32 *hash,
        ul32 *sig,
        ul32 *prefix
);

bool verifyServerKey(
        EC_GROUP    *eCurve,
        EC_POINT    *generator,
        EC_POINT    *public_key,
        char        *cdKey
);

void generateServerKey(
        char        *pKey,
        EC_GROUP    *eCurve,
        EC_POINT    *generator,
        BIGNUM      *order,
        BIGNUM      *privateKey,
        ul32        *osFamily,
        ul32        *prefix
);

// utilities.cpp
void endiannessConvert(byte *data, int length);
ul32 randomRange(ul32 dwLow, ul32 dwHigh);

void stopAudio();
bool playAudio(HINSTANCE hInstance, WCHAR *lpName, UINT bFlags);

EC_GROUP *initializeEllipticCurve(
        const char  *pSel,
        long        aSel,
        long        bSel,
        const char  *generatorXSel,
        const char  *generatorYSel,
        const char  *publicKeyXSel,
        const char  *publicKeyYSel,
        BIGNUM      *genOrderSel,
        BIGNUM      *privateKeySel,
        EC_POINT    **genPoint,
        EC_POINT    **pubPoint
        );

// key.cpp
void unbase24(ul32 *byteSeq, const char *cdKey);
void base24(char *cdKey, ul32 *byteSeq);

void formatXP(WCHAR *pBSection, WCHAR *pCSection, WCHAR *pText);
void formatServer(WCHAR *pText);

// windows.cpp
bool InitializeWindow(HINSTANCE hInstance);

#endif //KEYGEN_HEADER_H

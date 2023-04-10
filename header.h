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

typedef unsigned long ul32;

extern HANDLE hConsole;
extern byte charset[];

extern const char pXP[];
extern const long aXP;
extern const long bXP;

// xp.cpp
int keyXP(
    char *pKey,
    ul32 *hash,
    ul32 *sig,
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

void verifyXPKey(
        EC_GROUP    *eCurve,
        EC_POINT    *generator,
        EC_POINT    *publicKey,
        char        *cdKey
        );

void generateXPKey(
        byte        *pKey,
        EC_GROUP    *eCurve,
        EC_POINT    *generator,
        BIGNUM      *order,
        BIGNUM      *privateKey,
        ul32        *pRaw
        );

// server.cpp
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

void verifyServerKey(
        EC_GROUP    *eCurve,
        EC_POINT    *generator,
        EC_POINT    *public_key,
        char        *cdKey
        );

void generateServerKey(
        byte        *pKey,
        EC_GROUP    *eCurve,
        EC_POINT    *generator,
        BIGNUM      *order,
        BIGNUM      *privateKey,
        ul32        *osFamily,
        ul32        *prefix
        );

// utilities.cpp
void cprintf(const char *Format, int nColor, ...);
void endiannessConvert(byte *data, int length);

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
void unbase24(ul32 *byteSeq, byte *cdKey);
void base24(byte *cdKey, ul32 *byteSeq);
void printProductKey(const char *pKey);
void printProductID(const ul32 *pRaw);

// windows.cpp
bool InitializeWindow(HINSTANCE hInstance);

#endif //KEYGEN_HEADER_H

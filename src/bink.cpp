//
// Created by Andrew on 24/05/2023.
//

#include "header.h"

#define BINK_RETAIL MAKEINTRESOURCEW(1)
#define BINK_OEM    MAKEINTRESOURCEW(2)

#define RT_BINK     L"BINK"

/*
    Bink resource doesn't exist
    The file you selected isn't a library
    Bink resource is invalid
*/
typedef struct _EC_BYTE_POINT {
    CHAR x[256];    // x-coordinate of the point on the elliptic curve.
    CHAR y[256];    // y-coordinate of the point on the elliptic curve.
} EC_BYTE_POINT;

typedef struct _BINKHDR {
    // BINK version - not stored in the resource.
    ULONG32 dwVersion;

    // Original BINK header.
    ULONG32 dwID;
    ULONG32 dwSize;
    ULONG32 dwHeaderLength;
    ULONG32 dwChecksum;
    ULONG32 dwDate;
    ULONG32 dwKeySizeInDWORDs;
    ULONG32 dwHashLength;
    ULONG32 dwSignatureLength;
    
    // Extended BINK header. (Windows Server 2003+)
    ULONG32 dwAuthCodeLength;
    ULONG32 dwProductIDLength;
} BINKHDR;

typedef struct _BINKDATA {
    CHAR p[256];        // Finite Field order p.
    CHAR a[256];        // Elliptic Curve parameter a.
    CHAR b[256];        // Elliptic Curve parameter b.

    EC_BYTE_POINT G;    // Base point (Generator) G.
    EC_BYTE_POINT K;    // Public key K.
    EC_BYTE_POINT I;    // Inverse of the public key K.
} BINKDATA;

typedef struct _BINKEY {
    BINKHDR  header;
    BINKDATA data;
} BINKEY;

DWORD extractBINKResource(HMODULE hLibrary, BYTE **pData) {
    HRSRC hRes = FindResourceW(hLibrary, BINK_OEM, RT_BINK);
    DWORD dwSize = 0;

    if (hRes != NULL) {
        dwSize = SizeofResource(hLibrary, hRes);
        *pData = (BYTE *)LoadResource(hLibrary, hRes);
    }

    return dwSize;
}

BYTE hexToDecDigit(CHAR nDigit) {
    nDigit = toupper(nDigit);

    if (nDigit >= '0' && nDigit <= '9')
        return nDigit - '0';

    else
        return nDigit - 'A' + 10;
}

ULONG32 byteToInteger(BYTE *pByte) {
    return hexToDecDigit(pByte[0]) << 4 + hexToDecDigit(pByte[1]);
}

void reverseBytes(CONST BYTE *pBytes, ULONG32 nBytes, BYTE *pReversed) {
    for (int i = nBytes - 1; i >= 0; i--) {
        memcpy((BYTE *)&pBytes[i * 2], (BYTE *)&pReversed[(nBytes - i + 1) * 2], 2 * sizeof(BYTE));
    }
}

ULONG32 ulToInteger(BYTE *pUL, BOOL bLittleEndian) {
    BYTE    pULCopy[8] = { 0 };
    ULONG32 nUL = 0;
    
    if (pUL == NULL)
        return 0;

    if (bLittleEndian)
        reverseBytes(pUL, 4, pULCopy);

    for (int i = 0; i < 4; i++) {
        nUL += byteToInteger(&pULCopy[i * 2]);
    }

    return nUL;
}

void decodeBINKResource(BYTE *pData, ULONG32 nLength, BINKEY *pBINK) {
    ULONG32 nBlockBytes = 4;

    // If BINK is incomplete, return.
    if (nLength < 0x170) return;

    ulToInteger(pData, TRUE);

    /*/ Read BINK header.
    for (ULONG32 nOffset = 0; nOffset < sizeof(BINKHDR); nOffset += nBlockBytes) {
        pBINK[nOffset] = 
    }*/

}

void base(WCHAR *pPath) {
    HMODULE pIDgen = LoadLibraryExW(pPath, NULL, LOAD_LIBRARY_AS_DATAFILE);

    if (pIDgen == NULL)
        return;

    BYTE   *pBuffer = NULL;
    ULONG32 nLength = extractBINKResource(pIDgen, &pBuffer);

    if (nLength == 0) {
        return;
    }

    BINKEY pBINK = { 0 };

    decodeBINKResource(pBuffer, nLength, &pBINK);

    FreeLibrary(pIDgen);
}
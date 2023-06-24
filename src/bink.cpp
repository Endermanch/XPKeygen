//
// Created by Andrew on 24/05/2023.
//

#include "header.h"
#include "resource.h"
#include "presets.h"

/*
    Bink resource doesn't exist
    The file you selected isn't a library
    Bink resource is invalid
*/

/*BOOL SelectPreset(int nIndex) {
    if (nIndex >= WCOUNT) return false;
    
    strcpy(pBINKPreset.p, p[nIndex]);
    strcpy(pBINKPreset.a, a);
    strcpy(pBINKPreset.b, b);
    strcpy(pBINKPreset.G.x, gx[nIndex]);
    strcpy(pBINKPreset.G.y, gy[nIndex]);
    strcpy(pBINKPreset.K.x, kx[nIndex]);
    strcpy(pBINKPreset.K.y, ky[nIndex]);

    pBINKPreset.I.x;
    pBINKPreset.I.y;
        
    pBINKPreset.n = n[nIndex];
    pBINKPreset.k = k[nIndex];

    return true;
}*/

BOOL CALLBACK EnumResourceProc(HMODULE hModule, CONST WCHAR *lpType, WCHAR *lpName, LONG_PTR lParam) {
    (*(UINT *)lParam)++;

    return TRUE;
}

UINT countResources(WCHAR *pName) {
    UINT nResources = 0;

    EnumResourceNamesW(NULL, pName, EnumResourceProc, (LONG_PTR)&nResources);

    return nResources;
}

DWORD extractBINKResource(HMODULE hModule, UINT nPreset, BYTE **pMemory) {
    HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(nPreset), RT_BINK);
    DWORD dwSize = 0;

    if (hRes != NULL) {
        dwSize = SizeofResource(hModule, hRes);
        *pMemory = (BYTE *)LoadResource(hModule, hRes);
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

void reverseBytes(BYTE *pBytes) {
    UINT nBytes = strlen((CHAR *)pBytes) / 2;
    CHAR *pBytesCopy = strdup((CHAR *)pBytes);

    for (int i = 0; i < nBytes; i++) {
        memcpy(&pBytes[(nBytes - (i + 1)) * 2], &pBytesCopy[i * 2], 2 * sizeof(BYTE));
    }

    free(pBytesCopy);
}

VOID byteToHex(BYTE *pDestination, BYTE pByte) {
    BYTE loByte = pByte % 16,
         hiByte = pByte / 16;

    pDestination[0] = hiByte < 10 ? hiByte + '0' : hiByte + 'A' - 10;
    pDestination[1] = loByte < 10 ? loByte + '0' : loByte + 'A' - 10;
}

VOID formatBytes(BYTE *pDestination, BYTE *pSource, UINT nLength) {
    for (int i = 0; i < nLength; i++) {
        byteToHex(pDestination + i * 2, pSource[i]);
    }
}

BOOL decodeBINKResource(BYTE *pData, ULONG32 nLength, BINKEYEX *pBINK) {
    ULONG32 nStructOffset,
            nCurveOffset,
            nCurveField = FIELD_BYTES_2003;

    // If BINK is incomplete or the containers are null pointers, return.
    if (pData == nullptr || pBINK == nullptr || nLength < 0x170) return false;

    // Reset structure to 0.
    memset(pBINK, 0, sizeof(BINKEYEX));

    // Read ID and the BINK header.
    for (nStructOffset = 0; nStructOffset < sizeof(ULONG32) + sizeof(BINKHDR); nStructOffset += sizeof(ULONG32)) {
        *(ULONG32 *)((BYTE *)pBINK + nStructOffset) = BYDWORD(pData + nStructOffset);
    }

    // If it's an older BINK, there are only 7 arguments.
    if (pBINK->binKey.header.dwVersion == 19980206) {
        pBINK->binKey.header.dwProductIDLength = 0;
        pBINK->binKey.header.dwAuthCodeLength = 0;

        nCurveField = FIELD_BYTES;
    }

    for (nCurveOffset = (pBINK->binKey.header.dwHeaderLength + 1) * sizeof(ULONG32); nStructOffset < sizeof(ULONG32) + sizeof(BINKDATA); nStructOffset += FIELD_LENGTH_MAX, nCurveOffset += nCurveField) {
        BYTE *pCurveParameter = (BYTE *)pBINK + nStructOffset;

        formatBytes(pCurveParameter, pData + nCurveOffset, nCurveField);
        reverseBytes(pCurveParameter);
    }



    // Calculate the inverse of the public key.
    // The elliptic curve is symmetric about the x axis, so we only need to calculate the y-coordinate.
    // I.y = p - K.y
    BIGNUM *fieldOrder = BN_new(),
           *publicKeyY = BN_new();

    BN_hex2bn(&fieldOrder, pBINK->binKey.data.p);
    BN_hex2bn(&publicKeyY, pBINK->binKey.data.K.y);

    BN_sub(publicKeyY, fieldOrder, publicKeyY);

    CHAR *pInverse = BN_bn2hex(publicKeyY);
   
    strcpy(pBINK->I.x, pBINK->binKey.data.K.x);
    strcpy(pBINK->I.y, pInverse);
    
    free(pInverse);



    // Additional calculations (not implemented yet)
    BIGNUM *derivative = BN_new();
    BIGNUM *generatorx = BN_new();
    BIGNUM *generatory = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_hex2bn(&generatorx, pBINK->binKey.data.G.x);
    BN_hex2bn(&generatory, pBINK->binKey.data.G.y);

    /*EC_POINT *genPoint, *pubPoint, *genDerivative;
    EC_GROUP *eCurve = initializeEllipticCurve(
        pBINK->data.p,
        pBINK->data.a,
        pBINK->data.b,
        pBINK->data.G.x,
        pBINK->data.G.y,
        pBINK->data.K.x,
        pBINK->data.K.y,
        &genPoint,
        &pubPoint
    );

    genDerivative = EC_POINT_new(eCurve);
    EC_POINT_copy(genDerivative, genPoint);

    for (ULONG64 iter = 0; iter != 65153636961774397; iter++) {
        printf("iter: %llu\n", iter);
        EC_POINT_add(eCurve, genDerivative, genPoint, genDerivative, ctx);
    }*/

    return true;
}

VOID InitializePreset(UINT nIndex, BINKEYEX *pBINK) {
   /* HMODULE pIDgen = LoadLibraryExW(pPath, NULL, LOAD_LIBRARY_AS_DATAFILE);

    if (pIDgen == NULL)
        return;*/

    BYTE   *pMemory = NULL;
    ULONG32 nLength = extractBINKResource(NULL, IDR_BINK1 + nIndex, &pMemory);

    if (nLength == 0) {
        return;
    }

    decodeBINKResource(pMemory, nLength, pBINK);

    pBINK->n = generatorOrderArr[nIndex];
    pBINK->k = privateKeyArr[nIndex];

    // FreeLibrary(pIDgen);
    return;
} 
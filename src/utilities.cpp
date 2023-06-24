//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

/* Convert data between endianness types. */
void endian(byte *data, int length) {
    for (int i = 0; i < length / 2; i++) {
        byte temp = data[i];
        data[i] = data[length - i - 1];
        data[length - i - 1] = temp;
    }
}

/* Generates a random 32-bit integer in range. */
DWORD randomRange(DWORD dwLow, DWORD dwHigh) {
    return rand() % (dwHigh - dwLow) + dwLow;
}

/* Stops current asynchronously played audio. */
void stopAudio() {
    PlaySoundW(nullptr, nullptr, 0);
}

/* Plays audio stored as a resource. */
bool playAudio(HINSTANCE hInstance, WCHAR *lpName, UINT bFlags) {
    HANDLE hResInfo = FindResourceW(hInstance, lpName, L"WAVE");

    if (hResInfo == nullptr)
        return false;

    HANDLE hRes = LoadResource(hInstance, (HRSRC)hResInfo);

    if (hRes == nullptr)
        return false;

    WCHAR *lpRes = (WCHAR *)LockResource(hRes);
    FreeResource(hRes);

    return sndPlaySoundW(lpRes, SND_MEMORY | bFlags);
}

/* Initializes the elliptic curve. */
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
) {
    // Initialize BIGNUM and BIGNUMCTX structures.
    // BIGNUM - Large numbers
    // BN_CTX - Context variables (allow concurrency)
    BIGNUM *a, *b, *p, *generatorX, *generatorY, *publicKeyX, *publicKeyY;
    BN_CTX *context;

    // Microsoft Product Key identification program uses a public key stored in pidgen.dll's BINK resource,
    // which is an Elliptic Curve Cryptography (ECC) public key. It can be decomposed into a following mathematical task:

    // We're presented with an elliptic curve, a multivariable function F(y; x; p; a; b), where
    // y^2 = x^3 + ax + b (mod p).
    a = BN_new();
    b = BN_new();
    p = BN_new();

    // K(x; y) is the resulting point.
    publicKeyX = BN_new();
    publicKeyY = BN_new();

    // G(x; y) is the base point.
    generatorX = BN_new();
    generatorY = BN_new();

    // Context variable.
    context = BN_CTX_new();

    // Initialize public data from the BINK resource. 
    BN_hex2bn(&p, pSel);
    BN_hex2bn(&a, aSel);
    BN_hex2bn(&b, bSel);
    BN_hex2bn(&generatorX, generatorXSel);
    BN_hex2bn(&generatorY, generatorYSel);

    BN_hex2bn(&publicKeyX, publicKeyXSel);
    BN_hex2bn(&publicKeyY, publicKeyYSel);

    // Elliptic Curve calculations.
    // The abelian group is defined via Galois field Fp - all integers [0; p - 1], where p is prime.
    EC_GROUP *eCurve = EC_GROUP_new_curve_GFp(p, a, b, context);

    // Create new point for the generator on the elliptic curve and set its coordinates to (genX; genY).
    *genPoint = EC_POINT_new(eCurve);
    EC_POINT_set_affine_coordinates(eCurve, *genPoint, generatorX, generatorY, context);

    // Create new point for the public key on the elliptic curve and set its coordinates to (pubX; pubY).
    *pubPoint = EC_POINT_new(eCurve);
    EC_POINT_set_affine_coordinates(eCurve, *pubPoint, publicKeyX, publicKeyY, context);

    // If generator and public key points are not on the elliptic curve, either the generator or the public key values are incorrect.
    assert(EC_POINT_is_on_curve(eCurve, *genPoint, context) == 1);
    assert(EC_POINT_is_on_curve(eCurve, *pubPoint, context) == 1);

    // Cleanup.
    BN_CTX_free(context);

    return eCurve;
}

int BN_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen) {
    if (a == nullptr || to == nullptr)
        return 0;

    int len = BN_bn2bin(a, to);

    if (len > tolen)
        return -1;

    // Choke point inside BN_bn2lebinpad: OpenSSL uses len instead of tolen.
    endian(to, tolen);

    return len;
}
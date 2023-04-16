//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

/* Converts from byte sequence to the CD-key. */
void base24(char *cdKey, ul32 *byteSeq) {
    byte rbs[16];
    BIGNUM *z;

    // Copy byte sequence to the reversed byte sequence.
    memcpy(rbs, byteSeq, sizeof(rbs));

    // Skip trailing zeroes and reverse y.
    int length;

    for (length = 15; rbs[length] == 0; length--);
    endiannessConvert(rbs, ++length);

    // Convert reversed byte sequence to BigNum z.
    z = BN_bin2bn(rbs, length, nullptr);

    // Divide z by 24 and convert the remainder to a CD-key char.
    cdKey[25] = 0;

    for (int i = 24; i >= 0; i--)
        cdKey[i] = charset[BN_div_word(z, 24)];

    BN_free(z);
}

/* Converts from CD-key to a byte sequence. */
void unbase24(ul32 *byteSeq, const char *cdKey) {
    byte pDecodedKey[PK_LENGTH + NULL_TERMINATOR]{};
    BIGNUM *y = BN_new();

    BN_zero(y);

    // Remove dashes from the CD-key and put it into a Base24 byte array.
    for (int i = 0, k = 0; i < strlen(cdKey) && k < PK_LENGTH; i++) {
        for (int j = 0; j < 24; j++) {
            if (cdKey[i] != '-' && cdKey[i] == charset[j]) {
                pDecodedKey[k++] = j;
                break;
            }
        }
    }

    // Empty byte sequence.
    memset(byteSeq, 0, 16);

    // Calculate the weighed sum of byte array elements.
    for (int i = 0; i < PK_LENGTH; i++) {
        BN_mul_word(y, PK_LENGTH - 1);
        BN_add_word(y, pDecodedKey[i]);
    }

    // Acquire length.
    int n = BN_num_bytes(y);

    // Place the generated code into the byte sequence.
    BN_bn2bin(y, (byte *)byteSeq);
    BN_free(y);

    // Reverse the byte sequence.
    endiannessConvert((byte *) byteSeq, n);
}

/* Formats Windows XP key output. */
void formatXP(WCHAR *pBSection, WCHAR *pCSection, WCHAR *pText) {
    WCHAR pFPK[32]{};

    int pSSection = 0;

    for (int i = 0; i < wcslen(pCSection); i++)
        pSSection -= pCSection[i] - '0';

    while (pSSection < 0)
        pSSection += 7;

    char pKey[PK_LENGTH + NULL_TERMINATOR]{};
    ul32 msDigits = _wtoi(pBSection),
        lsDigits = _wtoi(pCSection);

    ul32 nRPK = msDigits * 1'000'000 + lsDigits,
        hash = 0,
        bKey[4]{},
        bSig[2]{};

    bool bValid = keyXP(pKey, nRPK);

    unbase24(bKey, pKey);
    unpackXP(nullptr, &hash, bSig, bKey);

    for (int i = 0; i < 5; i++)
        wsprintfW(pFPK, L"%s%s%.5S", pFPK, i != 0 ? L"-" : L"", &pKey[5 * i]);

    wsprintfW(
        pText,
        L"Product ID:\tPPPPP-%03d-%06d%d-23XXX\r\n\r\nBytecode:\t%08lX %08lX %08lX %08lX\r\nHash:\t\t%08lX\r\nSignature:\t%08lX %08lX\r\nCurve Point:\t%s\r\n\r\n%s\r\n",
        nRPK / 1'000'000,
        nRPK % 1'000'000,
        pSSection,
        bKey[3], bKey[2], bKey[1], bKey[0],
        hash,
        bSig[1], bSig[0],
        bValid ? L"True" : L"False",
        pFPK
    );
}

/* Formats Windows Server 2003 key output. */
void formatServer(WCHAR *pText) {
    WCHAR pFPK[32]{};

    char pKey[PK_LENGTH + NULL_TERMINATOR]{};
    ul32 hash = 0,
        osFamily = 0,
        prefix = 0,
        bKey[4]{},
        bSig[2]{};

    bool bValid = keyServer(pKey);

    unbase24(bKey, pKey);
    unpackServer(&osFamily, &hash, bSig, &prefix, bKey);

    for (int i = 0; i < 5; i++)
        wsprintfW(pFPK, L"%s%s%.5S", pFPK, i != 0 ? L"-" : L"", &pKey[5 * i]);

    wsprintfW(
        pText,
        L"Bytecode:\t%08lX %08lX %08lX %08lX\r\nOS Family:\t%d\r\nHash:\t\t%08lX\r\nSignature:\t%08lX %08lX\r\nPrefix:\t\t%04lX\r\nCurve Point:\t%s\r\n\r\n%s\r\n",
        bKey[3], bKey[2], bKey[1], bKey[0],
        osFamily,
        hash,
        bSig[1], bSig[0],
        prefix,
        bValid ? L"True" : L"False",
        pFPK
    );
}

//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

/* Converts from CD-key to a byte sequence. */
bool unbase24(BYTE *byteSeq, CHAR(&pKey)[PK_LENGTH + NULL_TERMINATOR]) {
    BYTE pDecodedKey[PK_LENGTH + NULL_TERMINATOR]{};
    BIGNUM *y = BN_new();

    BN_zero(y);

    // Remove dashes from the CD-key and put it into a Base24 byte array.
    for (int i = 0, k = 0; i < strlen(pKey) && k < PK_LENGTH; i++) {
        for (int j = 0; j < strlen(pCharset); j++) {
            if (pKey[i] == pCharset[j]) {
                pDecodedKey[k++] = j;
                break;
            }
        }

        // If the k-index hasn't been incremented, and it's due to the key being garbage, quit.
        if (pKey[i] != '-' && k == i) return false;
    }

    // Empty byte sequence.
    memset(byteSeq, 0, 16);

    // Calculate the weighed sum of byte array elements.
    for (int i = 0; i < PK_LENGTH; i++) {
        BN_mul_word(y, strlen(pCharset));
        BN_add_word(y, pDecodedKey[i]);
    }

    // Acquire length.
    int n = BN_num_bytes(y);

    // Place the generated code into the byte sequence.
    BN_bn2bin(y, byteSeq);
    BN_free(y);

    // Reverse the byte sequence.
    endian(byteSeq, n);

    return true;
}

/* Converts from byte sequence to the CD-key. */
void base24(BYTE *byteSeq, CHAR(&pKey)[PK_LENGTH + NULL_TERMINATOR]) {
    BYTE rbyteSeq[16];
    BIGNUM *z;

    // Copy byte sequence to the reversed byte sequence.
    memcpy(rbyteSeq, byteSeq, sizeof(rbyteSeq));

    // Skip trailing zeroes and reverse y.
    int length;

    for (length = 15; rbyteSeq[length] == 0; length--);
    endian(rbyteSeq, ++length);

    // Convert reversed byte sequence to BigNum z.
    z = BN_bin2bn(rbyteSeq, length, nullptr);

    // Divide z by 24 and convert the remainder to a CD-key char.
    pKey[PK_LENGTH] = '\0';

    for (int i = PK_LENGTH - 1; i >= 0; i--)
        pKey[i] = pCharset[BN_div_word(z, 24)];

    BN_free(z);
}

/* Formats Windows XP key output. */
void formatXP(WCHAR *pBSection, WCHAR *pCSection, WCHAR *pText) {
    WCHAR pDashedKey[PK_LENGTH + 4 + NULL_TERMINATOR]{};

    int pSSection = 0;

    for (int i = 0; i < wcslen(pCSection); i++)
        pSSection -= pCSection[i] - '0';

    while (pSSection < 0)
        pSSection += 7;

    CHAR pKey[PK_LENGTH + NULL_TERMINATOR]{};
    DWORD pChannelID = _wtoi(pBSection),
        pSequence = _wtoi(pCSection);

    DWORD pHash;
    QWORD pRaw[2]{},
          pSignature;

    bool bValid = keyXP(pKey, pChannelID, pSequence, false);

    DWORD pSerial;
    BOOL pUpgrade = false;

    unbase24((BYTE *)pRaw, pKey);
    unpackXP(pRaw, pUpgrade, pSerial, pHash, pSignature);

    for (int i = 0; i < 5; i++)
        wsprintfW(pDashedKey, L"%s%s%.5S", pDashedKey, i != 0 ? L"-" : L"", &pKey[5 * i]);

    swprintf(
        pText,
        L"Product ID:\tPPPPP-%03d-%06d%d-23XXX\r\n\r\nBytecode:\t%016llX %016llX\r\nHash:\t\t%lX\r\nSignature:\t%llX\r\nCurve Point:\t%s\r\n\r\n%s\r\n",
        pSerial / 1'000'000,
        pSerial % 1'000'000,
        pSSection,
        pRaw[1], pRaw[0],
        pHash,
        pSignature,
        bValid ? L"True" : L"False",
        pDashedKey
    );
}

/* Formats Windows Server 2003 key output. */
void formatServer(WCHAR *pText) {
    WCHAR pDashedKey[32]{};

    char pKey[PK_LENGTH + NULL_TERMINATOR]{};
    DWORD pHash = 0,
        pChannelID = 0,
        pAuthInfo = 0;

    QWORD pRaw[2]{},
        pSignature;

    BOOL pUpgrade = false;
    bool bValid = keyServer(pKey, 640, 0, pUpgrade);

    unbase24((BYTE *)pRaw, pKey);
    unpackServer(pRaw, pUpgrade, pChannelID, pHash, pSignature, pAuthInfo);

    for (int i = 0; i < 5; i++)
        wsprintfW(pDashedKey, L"%s%s%.5S", pDashedKey, i != 0 ? L"-" : L"", &pKey[5 * i]);

    swprintf(
        pText,
        L"Bytecode:\t%016llX %016llX\r\nChannel ID:\t%d\r\nHash:\t\t%lX\r\nSignature:\t%llX\r\nAuthInfo:\t%d\r\nCurve Point:\t%s\r\n\r\n%s\r\n",
        pRaw[1], pRaw[0],
        pChannelID,
        pHash,
        pSignature,
        pAuthInfo,
        bValid ? L"True" : L"False",
        pDashedKey
    );
}

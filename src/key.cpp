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
void formatXP(BOOL bUpgrade, WCHAR *pBSection, WCHAR *pCSection, WCHAR *pText) {
    WCHAR pDashedKey[PK_LENGTH + 4 + NULL_TERMINATOR]{};
    INT   pSSection = 0;

    for (int i = 0; i < wcslen(pCSection); i++)
        pSSection -= pCSection[i] - '0';

    while (pSSection < 0)
        pSSection += 7;

    CHAR  pKey[PK_LENGTH + NULL_TERMINATOR]{};
    DWORD nChannelID = wcstoul(pBSection, nullptr, 10),
          nSequence = wcstoul(pCSection, nullptr, 10);

    BOOL  bValid = keyXP(pKey, pBINKPreset, nChannelID, nSequence, bUpgrade);

    QWORD pRaw[2]{},
          pSignature;

    DWORD pChannelID,
          pSequence,
          pSerial,
          pHash;

    BOOL  pUpgrade;

    unbase24((BYTE *)pRaw, pKey);
    unpackXP(pRaw, pUpgrade, pChannelID, pSequence, pHash, pSignature);

    pSerial = pChannelID * 1'000'000 + pSequence;

    for (int i = 0; i < 5; i++)
        wsprintfW(pDashedKey, L"%s%s%.5S", pDashedKey, i != 0 ? L"-" : L"", &pKey[5 * i]);

    swprintf(
        pText,
        L"PRODUCT ID:\tPPPPP-%03d-%06d%d-23XXX\r\n\r\nBYTECODE:\t%016llX %016llX\r\nUPGRADE:\t%s\r\nSERIAL:\t\t0x%lX (%d)\r\nHASH:\t\t0x%lX\r\nSIGNATURE:\t0x%llX\r\nCURVE POINT:\t%s\r\n\r\n\r\n%s\r\n",
        pChannelID,
        pSequence,
        pSSection,
        pRaw[1], pRaw[0],
        pUpgrade ? L"TRUE" : L"FALSE",
        pSerial, pSerial,
        pHash,
        pSignature,
        bValid ? L"TRUE" : L"FALSE",
        pDashedKey
    );
}

/* Formats Windows Server 2003 key output. */
void formatServer(BOOL bUpgrade, WCHAR *pBSection, WCHAR *pAuthSection, WCHAR *pText) {
    WCHAR pDashedKey[32]{};

    CHAR  pKey[PK_LENGTH + NULL_TERMINATOR]{};
    DWORD nChannelID = wcstoul(pBSection, nullptr, 10);
    DWORD nAuthInfo = wcstoul(pAuthSection, nullptr, 0) % 0x400;

    BOOL  bValid = keyServer(pKey, pBINKPreset, nChannelID, nAuthInfo, bUpgrade);

    QWORD pRaw[2]{},
          pSignature;

    DWORD pHash,
          pChannelID,
          pAuthInfo;

    BOOL  pUpgrade;

    unbase24((BYTE *)pRaw, pKey);
    unpackServer(pRaw, pUpgrade, pChannelID, pHash, pSignature, pAuthInfo);

    for (int i = 0; i < 5; i++)
        swprintf(pDashedKey, L"%s%s%.5S", pDashedKey, i != 0 ? L"-" : L"", &pKey[5 * i]);

    swprintf(
        pText,
        L"PRODUCT ID:\tPPPPP-%03d-CCCCCCS-45XXX\r\n\r\nBYTECODE:\t%016llX %016llX\r\nUPGRADE:\t%s\r\nCHANNEL ID:\t0x%lX (%d)\r\nHASH:\t\t0x%lX\r\nSIGNATURE:\t0x%llX\r\nAUTHINFO:\t0x%03lX\r\nCURVE POINT:\t%s\r\n\r\n%s\r\n",
        pChannelID,
        pRaw[1], pRaw[0],
        pUpgrade ? L"TRUE" : L"FALSE",
        pChannelID, pChannelID,
        pHash,
        pSignature,
        pAuthInfo,
        bValid ? L"TRUE" : L"FALSE",
        pDashedKey
    );
}

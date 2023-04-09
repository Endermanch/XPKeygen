//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

/* Convert from byte sequence to the CD-key. */
void base24(byte *cdKey, ul32 *byteSeq) {
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

/* Convert from CD-key to a byte sequence. */
void unbase24(ul32 *byteSeq, byte *cdKey) {
    BIGNUM *y = BN_new();
    BN_zero(y);

    // Empty byte sequence.
    memset(byteSeq, 0, 16);

    // For each character in product key, place its ASCII-code.
    for (int i = 0; i < 25; i++) {
        BN_mul_word(y, 24);
        BN_add_word(y, cdKey[i]);
    }

    // Acquire length.
    int n = BN_num_bytes(y);

    // Place the generated code into the byte sequence.
    BN_bn2bin(y, (unsigned char *)byteSeq);
    BN_free(y);

    // Reverse the byte sequence.
    endiannessConvert((unsigned char *) byteSeq, n);
}

/* Print Product Key. */
void printProductKey(const char *pKey) {
    assert(strlen((const char *)pKey) == 25);

    SetConsoleTextAttribute(hConsole, 0x0A);

    for (int i = 0; i < 25; i++) {
        putchar(pKey[i]);
        if (i != 24 && i % 5 == 4) putchar('-');
    }

    SetConsoleTextAttribute(hConsole, 0x0F);
}

/* Print Product ID using a Product Key. */
void printProductID(const ul32 *pRaw) {
    char raw[12];
    char b[6], c[8];

    // Cut away last bit of the product key and convert it to an ASCII-number (=raw)
    sprintf(raw, "%lu", pRaw[0] >> 1);

    // Make B-part {...-640-...} -> most significant 3 digits of Raw Product Key
    strncpy(b, raw, 3);
    b[3] = 0;

    // Make C-part {...-123456X-...} -> least significant 6 digits of Raw Product Key
    strcpy(c, raw + 3);

    // Make checksum digit-part {...56X-}
    assert(strlen(c) == 6);

    int digit = 0;

    // Reverse sum algorithm to find a check digit that would add to the rest to form a sum divisible by 7.
    for (int i = 0; i < 6; i++)
        digit -= c[i] - '0';

    while (digit < 0)
        digit += 7;

    // Append check digit + null terminate.
    c[6] = digit + '0';
    c[7] = 0;

    printf("Product ID: ");
    cprintf("PPPPP-%s-%s-23XXX\n", 0x0E, b, c);
}
/*
	Windows XP CD Key Verification/Generator by z22
	Rewritten by Endermanch
*/

#include "header.h"

HANDLE hConsole;
byte charset[] = "BCDFGHJKMPQRTVWXY2346789";

int mainServer() {
    BIGNUM *a, *b, *p, *generatorX, *generatorY, *publicKeyX, *publicKeyY, *genOrder, *privateKey;
    BN_CTX *context = BN_CTX_new();

    a = BN_new();
    b = BN_new();
    p = BN_new();

    generatorX = BN_new();
    generatorY = BN_new();

    publicKeyX = BN_new();
    publicKeyY = BN_new();

    genOrder = BN_new();

    privateKey = BN_new();

    /* Public data */
    // Data taken from pidgen.dll BINK-resources
    BN_hex2bn(&p, "C9AE7AED19F6A7E100AADE98134111AD8118E59B8264734327940064BC675A0C682E19C89695FBFA3A4653E47D47FD7592258C7E3C3C61BBEA07FE5A7E842379");

    BN_set_word(a, 1);
    BN_set_word(b, 0);

    // Base point G (Generator)
    BN_hex2bn(&generatorX, "85ACEC9F9F9B456A78E43C3637DC88D21F977A9EC15E5225BD5060CE5B892F24FEDEE574BF5801F06BC232EEF2161074496613698D88FAC4B397CE3B475406A7");
    BN_hex2bn(&generatorY, "66B7D1983F5D4FE43E8B4F1E28685DE0E22BBE6576A1A6B86C67533BF72FD3D082DBA281A556A16E593DB522942C8DD7120BA50C9413DF944E7258BDDF30B3C4");

    // Inverse of the public key
    BN_hex2bn(&publicKeyX, "90BF6BD980C536A8DB93B52AA9AEBA640BABF1D31BEC7AA345BB7510194A9B07379F552DA7B4A3EF81A9B87E0B85B5118E1E20A098641EE4CCF2045558C98C0E");
    BN_hex2bn(&publicKeyY, "6B87D1E658D03868362945CDD582E2CF33EE4BA06369E0EFE9E4851F6DCBEC7F15081E250D171EA0CC4CB06435BCFCFEA8F438C9766743A06CBD06E7EFB4C3AE");

    /* Computed data */
    // Order of G <- from MSKey 4-in-1
    BN_hex2bn(&genOrder, "4CC5C56529F0237D");

    // Computed private key
    BN_hex2bn(&privateKey, "2606120F59C05118");

    /* Elliptical Curve calculations. */
    // The group is defined via Fp = all integers [0; p - 1], where p is prime.
    // The function EC_POINT_set_affine_coordinates() sets the x and y coordinates for the point p defined over the curve given in group.
    EC_GROUP *eCurve = EC_GROUP_new_curve_GFp(p, a, b, context);

    // Create new point for the generator on the elliptic curve and set its coordinates to (genX; genY).
    EC_POINT *genPoint = EC_POINT_new(eCurve);
    EC_POINT_set_affine_coordinates(eCurve, genPoint, generatorX, generatorY, context);

    // Create new point for the public key on the elliptic curve and set its coordinates to (pubX; pubY).
    EC_POINT *pubPoint = EC_POINT_new(eCurve);
    EC_POINT_set_affine_coordinates(eCurve, pubPoint, publicKeyX, publicKeyY, context);

    // If generator and public key points are not on the elliptic curve, either the generator or the public key values are incorrect.
    assert(EC_POINT_is_on_curve(eCurve, genPoint, context) == 1);
    assert(EC_POINT_is_on_curve(eCurve, pubPoint, context) == 1);

    char pkey[25]{};
    ul32 osfamily[1], prefix[1];

    osfamily[0] = 1280;
    RAND_bytes((byte *)prefix, 4);

    prefix[0] &= 0x3ff;
    generateServerKey((byte *)pkey, eCurve, genPoint, genOrder, privateKey, osfamily, prefix);
    printProductKey(pkey);
    printf("\n\n");
    verifyServerKey(eCurve, genPoint, pubPoint, (char *) pkey);

    BN_CTX_free(context);

    return 0;
}

/*
 * PK: VX8CG-8KC6V-PVPMD-GKPPH-GC7W8
 *
 * The Windows XP product key is composed of 25 characters. The dashes store no information.
 * The product key is encoded in Base24 with an alphabet of "BCDFGHJKMPQRTVWXY2346789" in order
 * to avoid ambiguous characters (e.g. "I" and "1", "0" and "O").
 *
 * To convert a 25-digit key to binary data, we need to:
 * 1. Think of the key as of an array of bytes. Then convert the concatenated key VX8CG8KC6VPVPMDGKPPHGC7W8
 *    into its Base24 representation ('B' = 0, 'C' = 1, 'D' = 2, ...) -> [ 13, 15, 22, 1, 4, ... ].
 * 2. Compute the decoded array in little-endiannessConvert.
 * 3. The decoded result is divided into sections:
 *    - 12 bits -> OS Family
 *    - 31 bits -> Hash
 *    - 62 bits -> Signature
 *    -  9 bits -> Prefix
 *
 * Product ID: AAAAA-BBB-CCCCCCC-DDEEE
 *
 *  digits |  length | encoding
 * --------+---------+---------------------------------------
 *   AAAAA | 17 bits | bit  0 to bit 16 of P1
 *     BBB | 10 bits | bit 17 to bit 26 of P1
 * CCCCCCC | 28 bits | bit 27 to bit 31 of P1 (lower  5 bits)
 *         |         | bit  0 to bit 22 of P2 (upper 23 bits)
 *   DDEEE | 17 bits | bit 23 to bit 31 of P2 (lower  9 bits)
 *         |         | bit  0 to bit  7 of P3 (upper  8 bits)
 *
 *  digits | meaning
 * --------+-------------------------------------------------
 *   AAAAA | apparently always 55034 (in Windows XP RC1)
 *     BBB | most significant three digits of Raw Product Key
 *         | (see below)
 * CCCCCCC | least significant six digits of Raw Product Key
 *         | plus check digit (see below)
 *      DD | index of the public key used to verify the
 *         | Product Key. Example: 22 for Professional keys; 23 for VLK keys
 *     EEE | random value (used for phone activation, different installation IDs are generated)
 */

/*
 * Decoding the Product Key results in an example byte sequence.
 *
 * 0x6F 0xFA 0x95 0x45 0xFC 0x75 0xB5 0x52 0xBB 0xEF 0xB1 0x17 0xDA 0xCD 0x00
 *
 * Of these 15 bytes the least significant four bytes contain the Raw
 * Product Key in little endian byte order. The least significant bit is
 * removed by shifting this 32-bit value (0x4595FA6F - remember the
 * little endiannessConvert byte order) to the left by one bit position, resulting
 * in a Raw Product Key of 0x22CAFD37, or
 *
 *      583728439
 *
 * in decimal notation.
 */

int main() {
    ul32 nAmount = 1;

    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    HINSTANCE hInstance = GetModuleHandleW(nullptr);

    int p = InitializeWindow(hInstance);

    SetConsoleTitleA("Windows XP VLK Keygen");

    system("cls");
    cprintf("Windows XP VLK Keygen\n\n", 0x08);

    cprintf("Principle of Operation:\n", 0x0C);
    printf("We need a valid Raw Product Key to generate a Product ID in form of AAAAA-BBB-CCCCCCS-DDEEE.\n\n");
    printf("AAAAA is the Windows XP Series constant - different for each version.\n");
    printf("Raw Product Key directly represents the BBB-CCCCCC part of the Product ID.\n");
    printf("S is a \"check bit\": it's picked so that the sum of all C digits with it added makes a number divisible by 7.\n");
    printf("DD is the index of the public key used to verify the Product Key.\n");
    printf("EEE is a random number used to generate a different Installation ID each time.\n\n");

    printf("The Product Key itself can at most contain 114 bits of information, as per the alphabet capacity formula.\n");
    printf("Based on that, we unpack the 114-bit Raw Product Key into 3 ordered segments:\n");
    printf("\tData (31 bits), Hash (28 bits) and Signature (55 bits).\n\n");
    printf("Microsoft uses a really elegant Elliptic Curve Algorithm to validate the product keys.\n");
    printf("It is a public-key cryptographic system, thus Microsoft had to share the public key,\nand it's, in fact, stored within pidgen.dll.\n");
    printf("To crack the CD-key generation algorithm we must find the corresponding private key from the public key,\nwhich was conveniently computed before us.\n");
    printf("In general, there are 2 special cases for the Elliptic Curve leveraged in cryptography - F2m and Fp.\nMicrosoft used the latter.\n");
    printf("\ty^2 = x^3 + ax + b %% p.\n");
    printf("The task boils down to generating a valid Hash/Signature pair for the Raw Key we provided:\n");
    printf("\t1. We need to generate a random 384-bit number r, and define C = R(r.x, r.y) = rG.\n");
    printf("\t2. Hash = (First32Bits(SHA1(pRaw, r.x, r.y)) >> 4.\n");
    printf("\t3. Signature = privateKey * Hash + (C %% Order)\n");
    printf("Finally, we pack these components together, convert them to Base24 and get a valid Windows XP key.\n");

    cprintf("Input Raw Product Key BBB-CCCCCC WITHOUT DASHES in range [100-000000; 999-999999]: ", 0x0E);
}

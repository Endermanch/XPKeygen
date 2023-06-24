/*
	Windows XP CD Key Verification/Generator by z22
	Rewritten by Endermanch
*/

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

#include "header.h"

BINKEYEX  pBINKPreset;
CHAR      pCharset[] = "BCDFGHJKMPQRTVWXY2346789";

INT wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ WCHAR *pCmdLine, _In_ INT nCmdShow) {
    srand(GetTickCount64());

    InitializePreset(2, &pBINKPreset);

    return InitializeWindow(hInstance);

    // don't forget to free bink presets (I Forgor)
}

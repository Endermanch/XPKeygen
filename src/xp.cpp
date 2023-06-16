//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

/* Windows XP */
const char pXP[] = "92ddcf14cb9e71f4489a2e9ba350ae29454d98cb93bdbcc07d62b502ea12238ee904a8b20d017197aae0c103b32713a9";
const long aXP = 1;
const long bXP = 0;

// Base point G (Generator)
const char genXXP[] = "46E3775ECE21B0898D39BEA57050D422A0AF989E497962BAEE2CB17E0A28D5360D5476B8DC966443E37A14F1AEF37742";
const char genYXP[] = "7C8E741D2C34F4478E325469CD491603D807222C9C4AC09DDB2B31B3CE3F7CC191B3580079932BC6BEF70BE27604F65E";

// The public key
const char pubXXP[] = "5D8DBE75198015EC41C45AAB6143542EB098F6A5CC9CE4178A1B8A1E7ABBB5BC64DF64FAF6177DC1B0988AB00BA94BF8";
const char pubYXP[] = "23A2909A0B4803C89F910C7191758B48746CEA4D5FF07667444ACDB9512080DBCA55E6EBF30433672B894F44ACE92BFA";

// The order of G was computed in 18 hours using a Pentium III 450
const char genOrderXP[] = "DB6B4C58EFBAFD";

// The private key was computed in 10 hours using a Pentium III 450
const char privateKeyXP[] = "565B0DFF8496C8";


/* Windows 98
const char pXP[] = "ec224ff2613a9fe1411b51e89634643f79a272402ee146b012a3f71098c7e75df4bf8b3713c4f0ce56691ce56b9b5029";
const long aXP = 1;
const long bXP = 0;

// Base point G (Generator)
const char genXXP[] = "b5e1957b19951b5523204a62fd83ab22056f59a13bf8aaaf16ac10b7540f8ea92ba28dbfa68996fa12510c024f912340";
const char genYXP[] = "a84fbc02f311b1fd4521773e01821bd047f067c496ad54ce1504315cb88667d69130caa25efb2cb1e479ed50efb40d6b";

// The public key
const char pubXXP[] = "26ea9efe57ab6da485225a13ed66533c143f81b7b9528e38c8568bb726a8f0f5607da0e8d85aebf2e1425758b409e811";
const char pubYXP[] = "1a7c4cebe5f3919e96876a447a813efcd920979e9610d2b2146a04fab1041b31ae65e24efa3e0b0d61622483655716c2";

// The order of G was computed in 18 hours using a Pentium III 450
const char genOrderXP[] = "E778E33AEE6B3D";

// The private key was computed in 10 hours using a Pentium III 450
const char privateKeyXP[] = "B9E99B9BB9812E"; // "677A485D4BE4A0";*/


/* Unpacks a Windows XP-like Product Key. */
VOID unpackXP(
    QWORD (&pRaw)[2],
     BOOL &pUpgrade,
    DWORD &pChannelID,
    DWORD &pSequence,
    DWORD &pHash,
    QWORD &pSignature
) {
    // We're assuming that the quantity of information within the product key is at most 114 bits.
    // log2(24^25) = 114.

    // Upgrade = Bit 0
    pUpgrade = FIRSTNBITS(pRaw[0], 1);

    // Serial = Bits [1..30] -> 30 bits
    pChannelID = NEXTSNBITS(pRaw[0], 30, 1) / 1'000'000;
    pSequence = NEXTSNBITS(pRaw[0], 30, 1) % 1'000'000;

    // Hash = Bits [31..58] -> 28 bits
    pHash = NEXTSNBITS(pRaw[0], 28, 31);

    // Signature = Bits [59..113] -> 56 bits
    pSignature = FIRSTNBITS(pRaw[1], 51) << 5 | NEXTSNBITS(pRaw[0], 5, 59);
}

/* Packs a Windows XP-like Product Key. */
VOID packXP(
    QWORD (&pRaw)[2],
     BOOL pUpgrade,
    DWORD pChannelID,
    DWORD pSequence,
    DWORD pHash,
    QWORD pSignature
) {
    // The quantity of information the key provides is 114 bits.
    // We're storing it in 2 64-bit quad-words with 14 trailing bits.
    // 64 * 2 = 128

    // Signature [114..59] <- Hash [58..31] <- Serial [30..1] <- Upgrade [0]
    pRaw[0] = FIRSTNBITS(pSignature, 5) << 59 | FIRSTNBITS(pHash, 28) << 31 | (QWORD)(pChannelID * 1'000'000 + pSequence) << 1 | pUpgrade;
    pRaw[1] = NEXTSNBITS(pSignature, 51, 5);
}

/* Verifies a Windows XP-like Product Key. */
BOOL verifyXPKey(
    EC_GROUP *eCurve,
    EC_POINT *basePoint,
    EC_POINT *publicKey,
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]
) {
    BN_CTX *numContext = BN_CTX_new();

    QWORD pRaw[2]{},
          pSignature;

    DWORD pData,
          pChannelID,
          pSequence,
          pHash;

    BOOL  pUpgrade;

    // Convert Base24 CD-key to bytecode.
    unbase24((BYTE *)pRaw, pKey);

    // Extract RPK, hash and signature from bytecode.
    unpackXP(pRaw, pUpgrade, pChannelID, pSequence, pHash, pSignature);

    pData = (pChannelID * 1'000'000 + pSequence) << 1 | pUpgrade;

    /*
     *
     * Scalars:
     *  e = Hash
     *  s = Schnorr Signature
     *
     * Points:
     *  G(x, y) = Generator (Base Point)
     *  K(x, y) = Public Key
     *
     * Equation:
     *  P = sG + eK
     *
     */

    BIGNUM *e = BN_lebin2bn((BYTE *)&pHash, sizeof(pHash), nullptr),
           *s = BN_lebin2bn((BYTE *)&pSignature, sizeof(pSignature), nullptr),
           *x = BN_new(),
           *y = BN_new();

    // Create 2 points on the elliptic curve.
    EC_POINT *t = EC_POINT_new(eCurve);
    EC_POINT *p = EC_POINT_new(eCurve);

    // t = sG
    EC_POINT_mul(eCurve, t, nullptr, basePoint, s, numContext);

    // P = eK
    EC_POINT_mul(eCurve, p, nullptr, publicKey, e, numContext);

    // P += t
    EC_POINT_add(eCurve, p, t, p, numContext);

    // x = P.x; y = P.y;
    EC_POINT_get_affine_coordinates(eCurve, p, x, y, numContext);

    BYTE msgDigest[SHA_DIGEST_LENGTH]{},
         msgBuffer[SHA_MSG_LENGTH_XP]{},
         xBin[FIELD_BYTES]{},
         yBin[FIELD_BYTES]{};

    // Convert resulting point coordinates to bytes.
    BN_bn2lebin(x, xBin, FIELD_BYTES);
    BN_bn2lebin(y, yBin, FIELD_BYTES);

    // Assemble the SHA message.
    memcpy((void *)&msgBuffer[0], (void *)&pData, 4);
    memcpy((void *)&msgBuffer[4], (void *)xBin, FIELD_BYTES);
    memcpy((void *)&msgBuffer[4 + FIELD_BYTES], (void *)yBin, FIELD_BYTES);

    // compHash = SHA1(pSerial || P.x || P.y)
    SHA1(msgBuffer, SHA_MSG_LENGTH_XP, msgDigest);

    // Translate the byte digest into a 32-bit integer - this is our computed hash.
    // Truncate the hash to 28 bits.
    DWORD compHash = BYDWORD(msgDigest) >> 4 & BITMASK(28);

    BN_free(e);
    BN_free(s);
    BN_free(x);
    BN_free(y);

    BN_CTX_free(numContext);

    EC_POINT_free(t);
    EC_POINT_free(p);

    // If the computed hash checks out, the key is valid.
    return compHash == pHash;
}

/* Generates a Windows XP-like Product Key. */
VOID generateXPKey(
    EC_GROUP *eCurve,
    EC_POINT *basePoint,
      BIGNUM *genOrder,
      BIGNUM *privateKey,
       DWORD pChannelID,
       DWORD pSequence,
        BOOL pUpgrade,
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]
) {
    BN_CTX *numContext = BN_CTX_new();

    BIGNUM *c = BN_new(),
           *s = BN_new(),
           *x = BN_new(),
           *y = BN_new();

    QWORD pRaw[2]{},
          pSignature = 0;

    // Data segment of the RPK (first 31 bits).
    DWORD pData = (pChannelID * 1'000'000 + pSequence) << 1 | pUpgrade;

    do {
        EC_POINT *r = EC_POINT_new(eCurve);

        // Generate a random number c consisting of 384 bits without any constraints.
        BN_rand(c, FIELD_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

        // Pick a random derivative of the base point on the elliptic curve.
        // R = cG;
        EC_POINT_mul(eCurve, r, nullptr, basePoint, c, numContext);

        // Acquire its coordinates.
        // x = R.x; y = R.y;
        EC_POINT_get_affine_coordinates(eCurve, r, x, y, numContext);

        BYTE msgDigest[SHA_DIGEST_LENGTH]{},
             msgBuffer[SHA_MSG_LENGTH_XP]{},
             xBin[FIELD_BYTES]{},
             yBin[FIELD_BYTES]{};

        // Convert coordinates to bytes.
        BN_bn2lebin(x, xBin, FIELD_BYTES);
        BN_bn2lebin(y, yBin, FIELD_BYTES);

        // Assemble the SHA message.
        memcpy((void *)&msgBuffer[0], (void *)&pData, 4);
        memcpy((void *)&msgBuffer[4], (void *)xBin, FIELD_BYTES);
        memcpy((void *)&msgBuffer[4 + FIELD_BYTES], (void *)yBin, FIELD_BYTES);

        // pHash = SHA1(pSerial || R.x || R.y)
        SHA1(msgBuffer, SHA_MSG_LENGTH_XP, msgDigest);

        // Translate the byte digest into a 32-bit integer - this is our computed pHash.
        // Truncate the pHash to 28 bits.
        DWORD pHash = BYDWORD(msgDigest) >> 4 & BITMASK(28);

        /*
         *
         * Scalars:
         *  c = Random multiplier
         *  e = Hash
         *  s = Signature
         *  n = Order of G
         *  k = Private Key
         *
         * Points:
         *  G(x, y) = Generator (Base Point)
         *  R(x, y) = Random derivative of the generator
         *  K(x, y) = Public Key
         *
         * We need to find the signature s that satisfies the equation with a given hash:
         *  P = sG + eK
         *  s = ek + c (mod n) <- computation optimization
         */

         // s = ek;
        BN_copy(s, privateKey);
        BN_mul_word(s, pHash);

        // s += c (mod n)
        BN_mod_add(s, s, c, genOrder, numContext);

        // Translate resulting scalar into a 64-bit integer (the byte order is little-endian).
        BN_bn2lebinpad(s, (BYTE *)&pSignature, BN_num_bytes(s));

        // Pack product key.
        packXP(pRaw, pUpgrade, pChannelID, pSequence, pHash, pSignature);

        EC_POINT_free(r);
    } while (pSignature > BITMASK(55));
    // ↑ ↑ ↑
    // The signature can't be longer than 55 bits, else it will
    // make the CD-key longer than 25 characters.

    // Convert bytecode to Base24 CD-key.
    base24((BYTE *)pRaw, pKey);

    BN_free(c);
    BN_free(s);
    BN_free(x);
    BN_free(y);

    BN_CTX_free(numContext);
}

BOOL keyXP(
     CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR],
    DWORD nChannelID,
    DWORD nSequence,
     BOOL bUpgrade
) {
    // If the Channel ID or the random sequence aren't valid, quit.
    if (nChannelID >= 1'000 || nSequence >= 1'000'000)
        return false;

    BIGNUM *privateKey = BN_new();
    BIGNUM *genOrder = BN_new();

    BN_hex2bn(&privateKey, privateKeyXP);
    BN_hex2bn(&genOrder, genOrderXP);

    EC_POINT *genPoint, *pubPoint;
    EC_GROUP *eCurve = initializeEllipticCurve(
        pXP,
        aXP,
        bXP,
        genXXP,
        genYXP,
        pubXXP,
        pubYXP,
        genOrder,
        privateKey,
        &genPoint,
        &pubPoint
    );

    do {
        generateXPKey(eCurve, genPoint, genOrder, privateKey, nChannelID, nSequence, bUpgrade, pKey);
    } while (!verifyXPKey(eCurve, genPoint, pubPoint, pKey));

    return true;
}
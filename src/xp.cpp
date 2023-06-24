//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

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

#ifdef _DEBUG
    printf(
        "Validating an XP-like key using following values:\n\n         Upgrade: %s\n      Channel ID: %d\n        Sequence: %d\n\n            Hash: 0x%08lX\n   Computed Hash: 0x%08lX\n       Signature: 0x%s\n\n",
        pUpgrade ? "True" : "False",
        pChannelID,
        pSequence,
        pHash,
        compHash,
        BN_bn2hex(s)
    );

    printf(
        " K(x; y) = {\n    0x%s,\n    0x%s\n }\n\n",
        BN_bn2hex(x),
        BN_bn2hex(y)
    );

    printf(
        " compHash %s pHash (%s)\n\n\n",
        compHash == pHash ? "==" : "!=",
        compHash == pHash ? "VALID" : "INVALID"
    );
#endif

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

#ifdef _DEBUG
        printf(
            "Generating an XP-like key using following values:\n\n         Upgrade: %s\n      Channel ID: %d\n        Sequence: %d\n\n Generator Order: 0x%s\n     Private Key: 0x%s\n            Seed: 0x%s\n\n",
            pUpgrade ? "True" : "False",
            pChannelID,
            pSequence,
            BN_bn2hex(genOrder),
            BN_bn2hex(privateKey),
            BN_bn2hex(c)
        );

        printf(
            " R(x; y) = {\n    0x%s,\n    0x%s\n }\n\nSignature bits: %02d (%s)\n\n\n",
            BN_bn2hex(x),
            BN_bn2hex(y),
            BN_num_bits(s),
            BN_num_bits(s) <= 55 ? "GOOD" : "BAD"
        );
#endif

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
    BINKEYEX &pBINK,
       DWORD nChannelID,
       DWORD nSequence,
        BOOL bUpgrade
) {
    // If the Channel ID or the random sequence aren't valid, quit.
    if (nChannelID >= 1'000 || nSequence >= 1'000'000)
        return false;

    if (pBINK.n == 0 ||
        pBINK.k == 0) {
#ifdef _DEBUG
        printf("!! NOT IMPLEMENTED !!\n\n");
#endif
        return false;
    }

    BIGNUM *privateKey = BN_new();
    BIGNUM *genOrder = BN_new();

    BN_set_word(privateKey, pBINK.k);
    BN_set_word(genOrder, pBINK.n);

    EC_POINT *genPoint, *pubPoint;
    EC_GROUP *eCurve = initializeEllipticCurve(
        pBINK.binKey.data.p,
        pBINK.binKey.data.a,
        pBINK.binKey.data.b,
        pBINK.binKey.data.G.x,
        pBINK.binKey.data.G.y,
        pBINK.binKey.data.K.x,
        pBINK.binKey.data.K.y,
        &genPoint,
        &pubPoint
    );

#ifdef _DEBUG
    printf(
        "Created elliptic curve:\n\n E = EllipticCurve(\n  GF(0x%s),\n  [0, 0, 0, %d, %d]\n ) => y^2 = x^3 + %dx + %d;\n\n G(x; y) = {\n    0x%s,\n    0x%s\n }\n\n K(x; y) = {\n    0x%s,\n    0x%s\n }\n\n\n",
        pBINK.binKey.data.p,
        atoi(pBINK.binKey.data.a),
        atoi(pBINK.binKey.data.b),
        atoi(pBINK.binKey.data.a),
        atoi(pBINK.binKey.data.b),
        pBINK.binKey.data.G.x,
        pBINK.binKey.data.G.y,
        pBINK.binKey.data.K.x,
        pBINK.binKey.data.K.y
    );
#endif

    generateXPKey(eCurve, genPoint, genOrder, privateKey, nChannelID, nSequence, bUpgrade, pKey);

    return verifyXPKey(eCurve, genPoint, pubPoint, pKey);
}
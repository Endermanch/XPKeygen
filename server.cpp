//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

/* Windows Server 2003 */
const char pSv[] = "C9AE7AED19F6A7E100AADE98134111AD8118E59B8264734327940064BC675A0C682E19C89695FBFA3A4653E47D47FD7592258C7E3C3C61BBEA07FE5A7E842379";
const long aSv = 1;
const long bSv = 0;

// Base point G (Generator)
const char genXSv[] = "85ACEC9F9F9B456A78E43C3637DC88D21F977A9EC15E5225BD5060CE5B892F24FEDEE574BF5801F06BC232EEF2161074496613698D88FAC4B397CE3B475406A7";
const char genYSv[] = "66B7D1983F5D4FE43E8B4F1E28685DE0E22BBE6576A1A6B86C67533BF72FD3D082DBA281A556A16E593DB522942C8DD7120BA50C9413DF944E7258BDDF30B3C4";

// Inverse of the public key
const char pubXSv[] = "90BF6BD980C536A8DB93B52AA9AEBA640BABF1D31BEC7AA345BB7510194A9B07379F552DA7B4A3EF81A9B87E0B85B5118E1E20A098641EE4CCF2045558C98C0E";
const char pubYSv[] = "6B87D1E658D03868362945CDD582E2CF33EE4BA06369E0EFE9E4851F6DCBEC7F15081E250D171EA0CC4CB06435BCFCFEA8F438C9766743A06CBD06E7EFB4C3AE";

// Order of G <- from MSKey 4-in-1
const char genOrderSv[] = "4CC5C56529F0237D";

// Computed private key
const char privateKeySv[] = "2606120F59C05118";

/* Windows XP x64 
Public key (-K) = (1989960177638374390878377737764297057685259206834686428253479199374616869742150776410973898745805799780071536831208959469038333664656928533078897351495263; 2680493145252003995204016438404731303203625133293449171132691660710342616258476835192643732221910418645447349019141673820306444587247165566828458285756618)
Order of base point G (n) = 4710798293276956193
Private key (k) = 4699066967014190092 for INVERSE. 11731326262766101


const char pSv[] = "D4B49D04A01EF209121C370DCF0D6292569EC65B8F147A8C62319B6B90DEA2D1CD45199B93582732BFEE27F40BF62D7EB2559BCD08041E301E0D14037A25D989";
const long aSv = 1;
const long bSv = 0;

const char genXSv[] = "828A23E65A03F2CE12342DC2B3AA4089C1447DD5C4DC36C0470885A4662F10187037F72B2216C3F671B434267A329BD3363BB27055F0EBBA8A0ABEF451D3F6A3";
const char genYSv[] = "23B0823295C9CB669E1643B298624083F68C58F14FEEC55D0B247EF37B353A1066F502D7BC71050056C7D006156A26CC9222F5135FB8B255D7773AE0CDCA31E2";

const char pubXSv[] = "25FEB90513F63C0833F1096369149E65C9359F4BCC8DE9A8F647030F96485BC71929594FF369DB967910B8F0A59BC7C30CF0D38311486293BA0B2952EE648E5F";
const char pubYSv[] = "A186A2C2913E5584F05E97D3CD49E354E6C41BE329877D7FCC7B2BF877A0B00C9298901D305D7FF012FF7902B4202D4ED64D6A90C6AD05960253BAB8F69D68BF";

// Order of G <- CALCULATED ON MY i7-12700K in 20 seconds
const char genOrderSv[] = "41601E16BF4A1621";

// Computed private key <- CALCULATED ON MY i7-12700K in 5 minutes 40 seconds
const char privateKeySv[] = "29AD943EA2EA15"; */


/* Windows XP x64 OEM
const char pSv[] = "A6FEDE9568C7863685F783F864A5943D34DED45EC460EEB2EC0455B01BC3C4D21FE081E479F2338BAAF7B10903AC89D23774938F41FDBFB6F16A615ECE5A04A1";
const long aSv = 1;
const long bSv = 0;

const char genXSv[] = "3CCFE20244697894A5CF8F8A57F335462C8C7C4935E171A373C2C1BA85C304D121A48931A99E4DD911945B410E10DEF21C00B2ED33FEF4E8F6FCBE16014E0AA8";
const char genYSv[] = "7D3F4583D6A45EF6547532B2AE6AC83281317A212223A47ADA92FB48DF055A225DD3E8DF17850EBFAD744780C8166B14F0A39C96B3D216E2247A89518985F6F8";

const char pubXSv[] = "19D3C8A75DACEAB3CE42970BCF3097F712FD3F6D3B171BE55D7AEF6210C48194480E998AFAC181935DCB9E66BD23769AF5E7ABB8ED2A7E5FAABD4FD1F8D24F7C";
const char pubYSv[] = "47A138CDB3C51BEB5443A00FD24734C6DE5DCE6DBA3B2EC337984C09B1CB108E45E8B50F78AEE5FBCA068C0B285576AC26099BD4D52AE2AF9F32A30A340705AF";

// Order of G <- CALCULATED ON MY i7-12700K in 2 hours (single threaded).
const char genOrderSv[] = "4782F84242B0A5E1";

// Computed private key <- CALCULATED ON MY i7-12700K in 5 minutes 40 seconds
const char privateKeySv[] = "15F9B7336005CB82";// or "3189410EE2AADA5F";
*/

/* Unpacks the Windows Server 2003-like Product Key. */
VOID unpackServer(
    QWORD (&pRaw)[2],
     BOOL &pUpgrade,
    DWORD &pChannelID,
    DWORD &pHash,
    QWORD &pSignature,
    DWORD &pAuthInfo
) {
    // We're assuming that the quantity of information within the product key is at most 114 bits.
    // log2(24^25) = 114.

    // Upgrade = Bit 0
    pUpgrade = FIRSTNBITS(pRaw[0], 1);

    // Channel ID = Bits [1..10] -> 10 bits
    pChannelID = NEXTSNBITS(pRaw[0], 10, 1);

    // Hash = Bits [11..41] -> 31 bits
    pHash = NEXTSNBITS(pRaw[0], 31, 11);

    // Signature = Bits [42..103] -> 62 bits
    // The quad-word signature overlaps AuthInfo in bits 104 and 105,
    // hence Microsoft employs a secret technique called: Signature = HIDWORD(Signature) >> 2 | LODWORD(Signature)
    pSignature = NEXTSNBITS(pRaw[1], 30, 10) << 32 | FIRSTNBITS(pRaw[1], 10) << 22 | NEXTSNBITS(pRaw[0], 22, 42);

    // AuthInfo = Bits [104..113] -> 10 bits
    pAuthInfo = NEXTSNBITS(pRaw[1], 10, 40);
}

/* Packs the Windows Server 2003-like Product Key. */
VOID packServer(
    QWORD (&pRaw)[2],
     BOOL pUpgrade,
    DWORD pChannelID,
    DWORD pHash,
    QWORD pSignature,
    DWORD pAuthInfo
) {
    // AuthInfo [113..104] <- Signature [103..42] <- Hash [41..11] <- Channel ID [10..1] <- Upgrade [0]
    pRaw[0] = FIRSTNBITS(pSignature, 22) << 42 | (QWORD)pHash << 11 | (QWORD)pChannelID << 1 | pUpgrade;
    pRaw[1] = FIRSTNBITS(pAuthInfo, 10) << 40 | NEXTSNBITS(pSignature, 40, 22);
}


/* Verifies the Windows Server 2003-like Product Key. */
BOOL verifyServerKey(
    EC_GROUP *eCurve,
    EC_POINT *basePoint,
    EC_POINT *publicKey,
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]
) {
    BN_CTX *context = BN_CTX_new();

    QWORD bKey[2]{},
          pSignature = 0;

    DWORD pData,
          pChannelID,
          pHash,
          pAuthInfo;

    BOOL  pUpgrade;

    // Convert Base24 CD-key to bytecode.
    unbase24((BYTE *)bKey, pKey);

    // Extract product key segments from bytecode.
    unpackServer(bKey, pUpgrade, pChannelID, pHash, pSignature, pAuthInfo);

    pData = pChannelID << 1 | pUpgrade;

    BYTE msgDigest[SHA_DIGEST_LENGTH]{},
         msgBuffer[SHA_MSG_LENGTH_2003]{},
         xBin[FIELD_BYTES_2003]{},
         yBin[FIELD_BYTES_2003]{};

    // Assemble the first SHA message.
    msgBuffer[0x00] = 0x5D;
    msgBuffer[0x01] = (pData & 0x00FF);
    msgBuffer[0x02] = (pData & 0xFF00) >> 8;
    msgBuffer[0x03] = (pHash & 0x000000FF);
    msgBuffer[0x04] = (pHash & 0x0000FF00) >> 8;
    msgBuffer[0x05] = (pHash & 0x00FF0000) >> 16;
    msgBuffer[0x06] = (pHash & 0xFF000000) >> 24;
    msgBuffer[0x07] = (pAuthInfo & 0x00FF);
    msgBuffer[0x08] = (pAuthInfo & 0xFF00) >> 8;
    msgBuffer[0x09] = 0x00;
    msgBuffer[0x0A] = 0x00;

    // newSignature = SHA1(5D || Channel ID || Hash || AuthInfo || 00 00)
    SHA1(msgBuffer, 11, msgDigest);

    // Translate the byte digest into a 64-bit integer - this is our computed intermediate signature.
    // As the signature is only 62 bits long at most, we have to truncate it by shifting the high DWORD right 2 bits (per spec).
    QWORD iSignature = NEXTSNBITS(BYDWORD(&msgDigest[4]), 30, 2) << 32 | BYDWORD(msgDigest);

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
     *  P = s(sG + eK)
     *
     */

    BIGNUM *e = BN_lebin2bn((BYTE *)&iSignature, sizeof(iSignature), nullptr),
           *s = BN_lebin2bn((BYTE *)&pSignature, sizeof(pSignature), nullptr),
           *x = BN_new(),
           *y = BN_new();

    // Create 2 points on the elliptic curve.
    EC_POINT *p = EC_POINT_new(eCurve);
    EC_POINT *t = EC_POINT_new(eCurve);

    // t = sG
    EC_POINT_mul(eCurve, t, nullptr, basePoint, s, context);

    // p = eK
    EC_POINT_mul(eCurve, p, nullptr, publicKey, e, context);

    // p += t
    EC_POINT_add(eCurve, p, t, p, context);

    // p *= s
    EC_POINT_mul(eCurve, p, nullptr, p, s, context);

    // x = p.x; y = p.y;
    EC_POINT_get_affine_coordinates(eCurve, p, x, y, context);

    // Convert resulting point coordinates to bytes.
    BN_bn2lebin(x, xBin, FIELD_BYTES_2003);
    BN_bn2lebin(y, yBin, FIELD_BYTES_2003);

    // Assemble the second SHA message.
    msgBuffer[0x00] = 0x79;
    msgBuffer[0x01] = (pData & 0x00FF);
    msgBuffer[0x02] = (pData & 0xFF00) >> 8;

    memcpy((void *)&msgBuffer[3], (void *)xBin, FIELD_BYTES_2003);
    memcpy((void *)&msgBuffer[3 + FIELD_BYTES_2003], (void *)yBin, FIELD_BYTES_2003);

    // compHash = SHA1(79 || Channel ID || p.x || p.y)
    SHA1(msgBuffer, SHA_MSG_LENGTH_2003, msgDigest);

    // Translate the byte digest into a 32-bit integer - this is our computed hash.
    // Truncate the hash to 31 bits.
    DWORD compHash = BYDWORD(msgDigest) & BITMASK(31);

    BN_free(s);
    BN_free(e);
    BN_free(x);
    BN_free(y);

    BN_CTX_free(context);

    EC_POINT_free(p);
    EC_POINT_free(t);

    // If the computed hash checks out, the key is valid.
    return compHash == pHash;
}

/* Generates the Windows Server 2003-like Product Key. */
VOID generateServerKey(
    EC_GROUP *eCurve,
    EC_POINT *basePoint,
      BIGNUM *genOrder,
      BIGNUM *privateKey,
       DWORD pChannelID,
       DWORD pAuthInfo,
        BOOL pUpgrade,
        CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR]
) {
    BN_CTX *numContext = BN_CTX_new();

    BIGNUM *c = BN_new(),
           *e = BN_new(),
           *s = BN_new(),
           *x = BN_new(),
           *y = BN_new();

    QWORD pRaw[2]{},
          pSignature = 0;

    // Data segment of the RPK.
    DWORD pData = pChannelID << 1 | pUpgrade;
    BOOL  noSquare;

    do {
        EC_POINT *r = EC_POINT_new(eCurve);

        // Generate a random number c consisting of 512 bits without any constraints.
        BN_rand(c, FIELD_BITS_2003, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

        // R = cG
        EC_POINT_mul(eCurve, r, nullptr, basePoint, c, numContext);

        // Acquire its coordinates.
        // x = R.x; y = R.y;
        EC_POINT_get_affine_coordinates(eCurve, r, x, y, numContext);

        BYTE msgDigest[SHA_DIGEST_LENGTH]{},
             msgBuffer[SHA_MSG_LENGTH_2003]{},
             xBin[FIELD_BYTES_2003]{},
             yBin[FIELD_BYTES_2003]{};

        // Convert resulting point coordinates to bytes.
        BN_bn2lebin(x, xBin, FIELD_BYTES_2003);
        BN_bn2lebin(y, yBin, FIELD_BYTES_2003);

        // Assemble the first SHA message.
        msgBuffer[0x00] = 0x79;
        msgBuffer[0x01] = (pData & 0x00FF);
        msgBuffer[0x02] = (pData & 0xFF00) >> 8;

        memcpy((void *)&msgBuffer[3], (void *)xBin, FIELD_BYTES_2003);
        memcpy((void *)&msgBuffer[3 + FIELD_BYTES_2003], (void *)yBin, FIELD_BYTES_2003);

        // pHash = SHA1(79 || Channel ID || R.x || R.y)
        SHA1(msgBuffer, SHA_MSG_LENGTH_2003, msgDigest);

        // Translate the byte digest into a 32-bit integer - this is our computed hash.
        // Truncate the hash to 31 bits.
        DWORD pHash = BYDWORD(msgDigest) & BITMASK(31);

        // Assemble the second SHA message.
        msgBuffer[0x00] = 0x5D;
        msgBuffer[0x01] = (pData & 0x00FF);
        msgBuffer[0x02] = (pData & 0xFF00) >> 8;
        msgBuffer[0x03] = (pHash & 0x000000FF);
        msgBuffer[0x04] = (pHash & 0x0000FF00) >> 8;
        msgBuffer[0x05] = (pHash & 0x00FF0000) >> 16;
        msgBuffer[0x06] = (pHash & 0xFF000000) >> 24;
        msgBuffer[0x07] = (pAuthInfo & 0x00FF);
        msgBuffer[0x08] = (pAuthInfo & 0xFF00) >> 8;
        msgBuffer[0x09] = 0x00;
        msgBuffer[0x0A] = 0x00;

        // newSignature = SHA1(5D || Channel ID || Hash || AuthInfo || 00 00)
        SHA1(msgBuffer, 11, msgDigest);

        // Translate the byte digest into a 64-bit integer - this is our computed intermediate signature.
        // As the signature is only 62 bits long at most, we have to truncate it by shifting the high DWORD right 2 bits (per spec).
        QWORD iSignature = NEXTSNBITS(BYDWORD(&msgDigest[4]), 30, 2) << 32 | BYDWORD(msgDigest);

        BN_lebin2bn((BYTE *)&iSignature, sizeof(iSignature), e);

        /*
         *
         * Scalars:
         *  c = Random multiplier
         *  e = Intermediate Signature
         *  s = Signature
         *  n = Order of G
         *  k = Private Key
         *
         * Points:
         *  G(x, y) = Generator (Base Point)
         *  R(x, y) = Random derivative of the generator
         *  K(x, y) = Public Key
         *
         * Equation:
         *  s(sG + eK) = R (mod p)
         *  ↓ K = kG; R = cG ↓
         *
         *  s(sG + ekG) = cG (mod p)
         *  s(s + ek)G = cG (mod p)
         *  ↓ G cancels out, the scalar arithmetic shrinks to order n ↓
         *
         *  s(s + ek) = c (mod n)
         *  s² + (ek)s - c = 0 (mod n)
         *  ↓ This is a quadratic equation in respect to the signature ↓
         *
         *  s = (-ek ± √((ek)² + 4c)) / 2 (mod n)
         */

         // e = ek (mod n)
        BN_mod_mul(e, e, privateKey, genOrder, numContext);

        // s = e
        BN_copy(s, e);

        // s = (ek (mod n))²
        BN_mod_sqr(s, s, genOrder, numContext);

        // c *= 4 (c <<= 2)
        BN_lshift(c, c, 2);

        // s += c
        BN_add(s, s, c);

        // Around half of numbers modulo a prime are not squares -> BN_sqrt_mod fails about half of the times,
        // hence if BN_sqrt_mod returns NULL, we need to restart with a different seed.
        // s = √((ek)² + 4c (mod n))
        noSquare = BN_mod_sqrt(s, s, genOrder, numContext) == nullptr;

        // s = -ek + √((ek)² + 4c) (mod n)
        BN_mod_sub(s, s, e, genOrder, numContext);

        // If s is odd, add order to it.
        // The order is a prime, so it can't be even.
        if (BN_is_odd(s))

            // s = -ek + √((ek)² + 4c) + n
            BN_add(s, s, genOrder);

        // s /= 2 (s >>= 1)
        BN_rshift1(s, s);

        // Translate resulting scalar into a 64-bit integer (the byte order is little-endian).
        BN_bn2lebinpad(s, (BYTE *)&pSignature, BN_num_bytes(s));

        // Pack product key.
        packServer(pRaw, pUpgrade, pChannelID, pHash, pSignature, pAuthInfo);

        EC_POINT_free(r);
    } while (pSignature > BITMASK(62) || noSquare);
    // ↑ ↑ ↑
    // The signature can't be longer than 62 bits, else it will
    // overlap with the AuthInfo segment next to it.

    // Convert bytecode to Base24 CD-key.
    base24((BYTE *)pRaw, pKey);

    BN_free(c);
    BN_free(s);
    BN_free(x);
    BN_free(y);
    BN_free(e);

    BN_CTX_free(numContext);
}

BOOL keyServer(
     CHAR (&pKey)[PK_LENGTH + NULL_TERMINATOR],
    DWORD nChannelID,
    DWORD nAuthInfo,
     BOOL bUpgrade
) {
    // If the Channel ID isn't valid, quit.
    if (nChannelID >= 1'000)
        return false;

    BIGNUM *privateKey = BN_new();
    BIGNUM *genOrder = BN_new();

    BN_hex2bn(&privateKey, privateKeySv);
    BN_hex2bn(&genOrder, genOrderSv);

    EC_POINT *genPoint, *pubPoint;
    EC_GROUP *eCurve = initializeEllipticCurve(
        pSv,
        aSv,
        bSv,
        genXSv,
        genYSv,
        pubXSv,
        pubYSv,
        genOrder,
        privateKey,
        &genPoint,
        &pubPoint
    );

    // Generate a stub 10-bit AuthInfo segment if none is specified.
    if (nAuthInfo == 0) {
        RAND_bytes((byte *)&nAuthInfo, 4);
        nAuthInfo &= 0x3FF;
    }

    do {
        generateServerKey(eCurve, genPoint, genOrder, privateKey, nChannelID, nAuthInfo, bUpgrade, pKey);
    } while (!verifyServerKey(eCurve, genPoint, pubPoint, pKey));

    return true;
}
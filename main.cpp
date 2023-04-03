/*
	Windows XP CD Key Verification/Generator v0.03
	by z22
	
	Compile with OpenSSL libs, modify to suit your needs.
	http://gnuwin32.sourceforge.net/packages/openssl.htm

	History:
	0.03	Stack corruptionerror on exit fixed (now pkey is large enough)
			More Comments added
	0.02	Changed name the *.cpp;
			Fixed minor bugs & Make it compilable on VC++
	0.01	First version compilable MingW


*/

#include <cstdio>
#include <cstring>
#include <cassert>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <windows.h>

#define FIELD_BITS 384
#define FIELD_BYTES 48

typedef unsigned char U8;
typedef unsigned long U32;

HANDLE hConsole;
unsigned char charset[] = "BCDFGHJKMPQRTVWXY2346789";

/* Colored output */
VOID cprintf(CONST CHAR *Format, INT nColor, ...) {
    va_list vList;

    va_start(vList, nColor);

    SetConsoleTextAttribute(hConsole, nColor);
    vprintf(Format, vList);
    SetConsoleTextAttribute(hConsole, 0x0F);

    va_end(vList);

    return;
}

/* Unpacks the Product Key. */
void extract(unsigned long *serial, unsigned long *hash, unsigned long *sig, unsigned long *raw) {

    // We're assuming that the quantity of information within the product key is at most 114 bits.
    // log2(24^25) = 114.

    // Serial = Bits [0..30] -> 31 bits
	serial[0] = raw[0] & 0x7fffffff;
 
    // Hash (e) = Bits [31..58] -> 28 bits
	hash[0] = ((raw[0] >> 31) | (raw[1] << 1)) & 0xfffffff;
 
    // Signature (s) = Bits [59..113] -> 55 bits
	sig[0] = (raw[1] >> 27) | (raw[2] << 5);
	sig[1] = (raw[2] >> 27) | (raw[3] << 5);
}

/* Repacks the Product Key. */
void pack(unsigned long *raw, unsigned long *serial, unsigned long *hash, unsigned long *sig) {
	raw[0] = serial[0] | ((hash[0] & 1) << 31);
	raw[1] = (hash[0] >> 1) | ((sig[0] & 0x1f) << 27);
	raw[2] = (sig[0] >> 5) | (sig[1] << 27);
	raw[3] = sig[1] >> 5;
}

/* Convert data between endianness types. */
void endiannessConvert(unsigned char *data, int length) {
	for (int i = 0; i < length / 2; i++) {
        unsigned char temp = data[i];
		data[i] = data[length - i - 1];
		data[length - i - 1] = temp;
	}
}

/* Convert from byte sequence to the CD-key. */
void base24(unsigned char *cdKey, unsigned long *byteSeq) {
    unsigned char rbs[16];
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
void unbase24(unsigned long *byteSeq, unsigned char *cdKey) {
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

/* Print Product ID using a Product Key. */
void printProductID(unsigned long *pKey) {
	char raw[12];
	char b[6], c[8];
	
    // Cut away last bit of the product key and convert it to an ASCII-number (=raw)
	sprintf(raw, "%lu", pKey[0] >> 1);
 
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

/* Print Product Key. */
void printProductKey(unsigned char *pKey) {
	assert(strlen((const char *)pKey) == 25);

    SetConsoleTextAttribute(hConsole, 0x0A);

	for (int i = 0; i < 25; i++) {
		putchar(pKey[i]);
		if (i != 24 && i % 5 == 4) putchar('-');
	}

    SetConsoleTextAttribute(hConsole, 0x0F);
}

/* Verify Product Key */
void verifyKey(EC_GROUP *ec, EC_POINT *generator, EC_POINT *publicKey, char *cdKey) {
	unsigned char key[25];

	BN_CTX *ctx = BN_CTX_new();

    // Remove dashes from the CD-key.
	for (int i = 0, k = 0; i < strlen(cdKey) && k < 25; i++) {
		for (int j = 0; j < 24; j++) {
			if (cdKey[i] != '-' && cdKey[i] == charset[j]) {
				key[k++] = j;
				break;
			}

            // Make sure the CD-key passes the verification procedure.
			assert(j < 24);
		}
	}
	
    // Convert Base24 CD-key to bytecode.
	unsigned long bKey[4]{};
	unsigned long pID[1], hash[1], sig[2];

	unbase24(bKey, key);
 
    // Output CD-key bytecode.
	printf("Bytecode: %.8lX %.8lX %.8lX %.8lX\n", bKey[3], bKey[2], bKey[1], bKey[0]);

    // Extract pid_data, hash and signature from the bytecode.
    extract(pID, hash, sig, bKey);
    printProductID(pID);
	
	printf("PID: %.8lX\nHash: %.8lX\nSignature: %.8lX %.8lX\n", pID[0], hash[0], sig[1], sig[0]);

    // e = Hash
    // s = Signature
	BIGNUM *e, *s;

    // Put hash word into BigNum e.
	e = BN_new();
	BN_set_word(e, hash[0]);

    // Reverse signature and create a new BigNum s.
    endiannessConvert((unsigned char *) sig, sizeof(sig));
	s = BN_bin2bn((unsigned char *)sig, sizeof(sig), nullptr);

    // Create x and y.
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

    // Create 2 new points on the existing elliptic curve.
	EC_POINT *u = EC_POINT_new(ec);
	EC_POINT *v = EC_POINT_new(ec);


    // EC_POINT_mul calculates r = generator * n + q * m.
	// v = s * generator + e * (-publicKey)

    // u = generator * s
	EC_POINT_mul(ec, u, nullptr, generator, s, ctx);

    // v = publicKey * e
	EC_POINT_mul(ec, v, nullptr, publicKey, e, ctx);

    // v += u
	EC_POINT_add(ec, v, u, v, ctx);

    // EC_POINT_get_affine_coordinates() sets x and y, either of which may be NULL, to the corresponding coordinates of p.
    // x = v.x; y = v.y;
	EC_POINT_get_affine_coordinates(ec, v, x, y, ctx);


	unsigned char buf[FIELD_BYTES], md[SHA_DIGEST_LENGTH], t[4];
	unsigned long h;

	SHA_CTX hContext;
	
	/* h = (first 32 bits of SHA1(pID || v.x, v.y)) >> 4 */
	SHA1_Init(&hContext);

    // Chop Product ID into 4 bytes.
	t[0] = pID[0] & 0xff;                   // First 8 bits
	t[1] = (pID[0] & 0xff00) >> 8;          // Second 8 bits
	t[2] = (pID[0] & 0xff0000) >> 16;       // Third 8 bits
	t[3] = (pID[0] & 0xff000000) >> 24;     // Fourth 8 bits

    // Hash chunk of data.
	SHA1_Update(&hContext, t, sizeof(t));

    // Empty buffer, place v.x in little-endian.
	memset(buf, 0, sizeof(buf));
	BN_bn2bin(x, buf);
    endiannessConvert((unsigned char *) buf, sizeof(buf));

    // Hash chunk of data.
	SHA1_Update(&hContext, buf, sizeof(buf));

    // Empty buffer, place v.y in little-endian.
	memset(buf, 0, sizeof(buf));
	BN_bn2bin(y, buf);
    endiannessConvert((unsigned char *) buf, sizeof(buf));

    // Hash chunk of data.
	SHA1_Update(&hContext, buf, sizeof(buf));

    // Store the final message from hContext in md.
	SHA1_Final(md, &hContext);

    // h = (first 32 bits of SHA1(pID || v.x, v.y)) >> 4
	h = (md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24)) >> 4;
	h &= 0xfffffff;
	
	printf("Calculated hash: %.8lX\n", h);

    // If we managed to generateKey a key with the same hash, the key is correct.
	if (h == hash[0]) cprintf("Key valid\n", 0x0A);
	else cprintf("Key invalid\n", 0x0C);

	putchar('\n');
	
	BN_free(e);
	BN_free(s);
	BN_free(x);
	BN_free(y);

    BN_CTX_free(ctx);

	EC_POINT_free(u);
	EC_POINT_free(v);
}

/* Generate a valid Product Key. */
void generateKey(unsigned char *pKey, EC_GROUP *eCurve, EC_POINT *generator, BIGNUM *order, BIGNUM *privateKey, unsigned long *pRaw) {
    EC_POINT *r = EC_POINT_new(eCurve);
    BN_CTX *ctx = BN_CTX_new();

	BIGNUM *c = BN_new();
	BIGNUM *s = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	unsigned long bKey[4];

	do {
        // Generate a random number c consisting of 384 bits without any constraints.
		BN_rand(c, FIELD_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

        // r = generator * c;
		EC_POINT_mul(eCurve, r, NULL, generator, c, ctx);

        // x = r.x; y = r.y;
		EC_POINT_get_affine_coordinates(eCurve, r, x, y, ctx);
		
		SHA_CTX hContext;
		unsigned char md[SHA_DIGEST_LENGTH], buf[FIELD_BYTES], t[4];
		unsigned long hash[1];

        /* h = (fist 32 bits of SHA1(pRaw || r.x, r.y)) >> 4 */
		SHA1_Init(&hContext);

        // Chop Raw Product Key into 4 bytes.
		t[0] = pRaw[0] & 0xff;
		t[1] = (pRaw[0] & 0xff00) >> 8;
		t[2] = (pRaw[0] & 0xff0000) >> 16;
		t[3] = (pRaw[0] & 0xff000000) >> 24;

        // Hash chunk of data.
		SHA1_Update(&hContext, t, sizeof(t));

        // Empty buffer, place r.x in little-endian.
		memset(buf, 0, sizeof(buf));
		BN_bn2bin(x, buf);
        endiannessConvert((unsigned char *) buf, sizeof(buf));

        // Hash chunk of data.
		SHA1_Update(&hContext, buf, sizeof(buf));

        // Empty buffer, place r.y in little-endian.
		memset(buf, 0, sizeof(buf));
		BN_bn2bin(y, buf);
        endiannessConvert((unsigned char *) buf, sizeof(buf));

        // Hash chunk of data.
		SHA1_Update(&hContext, buf, sizeof(buf));

        // Store the final message from hContext in md.
		SHA1_Final(md, &hContext);

        // h = (First-32(SHA1(pRaw, r.x, r.y)) >> 4
		hash[0] = (md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24)) >> 4;
		hash[0] &= 0xfffffff;
		
		/* s = privateKey * hash + c; */
        // s = privateKey;
		BN_copy(s, privateKey);

        // s *= hash;
        BN_mul_word(s, hash[0]);

        // BN_mod_add() adds a to b % m and places the non-negative result in r.
        // s = |s + c % order|;
		BN_mod_add(s, s, c, order, ctx);

        // Convert s from BigNum back to bytecode and reverse the endianness.
		unsigned long sig[2]{};

		BN_bn2bin(s, (unsigned char *)sig);
        endiannessConvert((unsigned char *) sig, BN_num_bytes(s));

        // Pack product key.
		pack(bKey, pRaw, hash, sig);

		printf("PID: %.8lX\nHash: %.8lX\nSignature: %.8lX %.8lX\n\n", pRaw[0], hash[0], sig[1], sig[0]);
	} while (bKey[3] >= 0x62A32); // Loop in case signature part will make the CD-key longer than 25 characters.

    // Convert the key to Base24.
	base24(pKey, bKey);
	
	BN_free(c);
	BN_free(s);
	BN_free(x);
	BN_free(y);

    BN_CTX_free(ctx);
	EC_POINT_free(r);
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
 * 2. Compute the decoded array in little-endian.
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
 *         | Product Key. Example: 22 for PRO version and 23 for VLK version
 *     EEE | random value (used for phone activation, different installation IDs are generated)
 */


int main() {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Initialize BIGNUM and BIGNUMCTX structures.
    // BIGNUM - Large numbers
    // BIGNUMCTX - Context large numbers (temporary)
	BIGNUM *a, *b, *p, *generatorX, *generatorY, *publicKeyX, *publicKeyY, *genOrder, *privateKey;
	BN_CTX *context;

    // Microsoft Product Key identification program uses a public key stored in pidgen.dll's BINK resource,
    // which is an Elliptic Curve Cryptography (ECC) public key. It can be decomposed into a following mathematical task:

    // We're presented with an elliptic curve, a multivariable function y(x; p; a; b), where
    // y^2 % p = x^3 + ax + b % p.
	a = BN_new();
	b = BN_new();
	p = BN_new();

    // Public key will consist of the resulting (x; y) values.
    publicKeyX = BN_new();
    publicKeyY = BN_new();

    // G(x; y) is a generator function, its return value represents a point on the elliptic curve.
    generatorX = BN_new();
    generatorY = BN_new();

    // We cannot produce a valid key without knowing the private key k. The reason for this is that
    // we need the result of the function K(x; y) = kG(x; y).
    privateKey = BN_new();

    // We can, however, validate any given key using the available public key: {p, a, b, G, K}.
    // genOrder the order of the generator G, a value we have to reverse -> Schoof's Algorithm.
	genOrder = BN_new();

    // Context variable
    context = BN_CTX_new();


    /* Public data */
    // Data taken from pidgen.dll BINK-resources
	BN_hex2bn(&p, "92ddcf14cb9e71f4489a2e9ba350ae29454d98cb93bdbcc07d62b502ea12238ee904a8b20d017197aae0c103b32713a9");

    BN_set_word(a, 1);
	BN_set_word(b, 0);

	// Base point G (Generator)
	BN_hex2bn(&generatorX, "46E3775ECE21B0898D39BEA57050D422A0AF989E497962BAEE2CB17E0A28D5360D5476B8DC966443E37A14F1AEF37742");
	BN_hex2bn(&generatorY, "7C8E741D2C34F4478E325469CD491603D807222C9C4AC09DDB2B31B3CE3F7CC191B3580079932BC6BEF70BE27604F65E");

	// Inverse of the public key
	BN_hex2bn(&publicKeyX, "5D8DBE75198015EC41C45AAB6143542EB098F6A5CC9CE4178A1B8A1E7ABBB5BC64DF64FAF6177DC1B0988AB00BA94BF8");
	BN_hex2bn(&publicKeyY, "23A2909A0B4803C89F910C7191758B48746CEA4D5FF07667444ACDB9512080DBCA55E6EBF30433672B894F44ACE92BFA");


    /* Computed data */
	// The order of G was computed in 18 hours using a Pentium III 450
	BN_hex2bn(&genOrder, "DB6B4C58EFBAFD");

	// The private key was computed in 10 hours using a Pentium III 450
	BN_hex2bn(&privateKey, "565B0DFF8496C8");


    /* Elliptical Curve calculations. */
    // The group is defined via Fp = all integers [0; p - 1], where p is prime.
    // The function EC_POINT_set_affine_coordinates() sets the x and y coordinates for the point p defined over the curve given in group.
	EC_GROUP *eCurve = EC_GROUP_new_curve_GFp(p, a, b, context);

    // Create new point for the generator on the elliptic curve and set its coordinates to (genX; genY).
	EC_POINT *genPoint = EC_POINT_new(eCurve);
    EC_POINT_set_affine_coordinates(eCurve, genPoint, generatorX, generatorY, context);

    // Create new point for the public key on the elliptic curve and set its coordinates to (pubX; pubY).
	EC_POINT *pub = EC_POINT_new(eCurve);
	EC_POINT_set_affine_coordinates(eCurve, pub, publicKeyX, publicKeyY, context);


    /* Generate a key. */
	unsigned char pKey[26]{};
	unsigned long pRaw[1]{};

    /*
     * Decoding the Product Key results in an example byte sequence.
     *
     * 0x6F 0xFA 0x95 0x45 0xFC 0x75 0xB5 0x52 0xBB 0xEF 0xB1 0x17 0xDA 0xCD 0x00
     *
     * Of these 15 bytes the least significant four bytes contain the Raw
     * Product Key in little endian byte order. The least significant bit is
     * removed by shifting this 32-bit value (0x4595FA6F - remember the
     * little endian byte order) to the left by one bit position, resulting
     * in a Raw Product Key of 0x22CAFD37, or
     *
     *      583728439
     *
     * in decimal notation.
     */

    SetConsoleTitleA("Windows XP VLK Keygen");

    system("cls");
    cprintf("Windows XP VLK Keygen\n\n", 0x08);

    cprintf("Principle of Operation:\n", 0x0C);
    printf("We need a valid Raw Product Key to generate the Product ID in form of AAAAA-BBB-CCCCCCS-DDEEE.\n\n");
    printf("AAAAA is the Windows XP Series constant - different for each version.\n");
    printf("Raw Product Key directly represents the BBB-CCCCCC part of the Product ID.\n");
    printf("S is a \"check bit\": it's picked so that the sum of all C digits with it added makes a number divisble by 7.\n");
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
    scanf_s("%lu", pRaw);

    printf("\n");

    pRaw[0] <<= 1;


    for (int i = 0; i < 10; i++) {
        cprintf("Product Key %d:\n", 0x08, i + 1);

        generateKey(pKey, eCurve, genPoint, genOrder, privateKey, pRaw);
        printProductKey(pKey);

        printf("\n\n");

        // Verify the key
        verifyKey(eCurve, genPoint, pub, (char *) pKey);
    }

	
    // Cleanup
	BN_CTX_free(context);
	
	return 0;
}

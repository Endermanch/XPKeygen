//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

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

void unpackServer(ul32 *osFamily, ul32 *hash, ul32 *sig, ul32 *prefix, ul32 *raw) {
    osFamily[0] = raw[0] & 0x7ff;

	hash[0] = ((raw[0] >> 11) | (raw[1] << 21)) & 0x7fffffff;
	
	sig[0] = (raw[1] >> 10) | (raw[2] << 22);
	sig[1] = ((raw[2] >> 10) | (raw[3] << 22)) & 0x3fffffff;
	
	prefix[0] = (raw[3] >> 8) & 0x3ff;
}

void packServer(ul32 *raw, ul32 *osFamily, ul32 *hash, ul32 *sig, ul32 *prefix) {
	raw[0] = osFamily[0] | (hash[0] << 11);
	raw[1] = (hash[0] >> 21) | (sig[0] << 10);
	raw[2] = (sig[0] >> 22) | (sig[1] << 10);
	raw[3] = (sig[1] >> 22) | (prefix[0] << 8);
}

bool verifyServerKey(EC_GROUP *eCurve, EC_POINT *generator, EC_POINT *public_key, char *cdKey) {
	int i, j, k;

	BN_CTX *ctx = BN_CTX_new();
	
	ul32 bkey[4] = {0};
	ul32 osfamily[1], hash[1], sig[2], prefix[1];
	unbase24(bkey, cdKey);
	printf("%.8x %.8x %.8x %.8x\n", bkey[3], bkey[2], bkey[1], bkey[0]);
    unpackServer(osfamily, hash, sig, prefix, bkey);
	
	printf("OS Family: %u\nHash: %.8x\nSig: %.8x %.8x\nPrefix: %.8x\n", osfamily[0], hash[0], sig[1], sig[0], prefix[0]);
	
	byte buf[FIELD_BYTES_2003], md[SHA_DIGEST_LENGTH];
	ul32 h1[2];
	SHA_CTX h_ctx;
	
	/* h1 = SHA-1(5D || OS Family || Hash || Prefix || 00 00) */
	SHA1_Init(&h_ctx);
	buf[0] = 0x5d;
	buf[1] = osfamily[0] & 0xff;
	buf[2] = (osfamily[0] & 0xff00) >> 8;
	buf[3] = hash[0] & 0xff;
	buf[4] = (hash[0] & 0xff00) >> 8;
	buf[5] = (hash[0] & 0xff0000) >> 16;
	buf[6] = (hash[0] & 0xff000000) >> 24;
	buf[7] = prefix[0] & 0xff;
	buf[8] = (prefix[0] & 0xff00) >> 8;
	buf[9] = buf[10] = 0;
	SHA1_Update(&h_ctx, buf, 11);
	SHA1_Final(md, &h_ctx);
	h1[0] = md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24);
	h1[1] = (md[4] | (md[5] << 8) | (md[6] << 16) | (md[7] << 24)) >> 2;
	h1[1] &= 0x3FFFFFFF;
	printf("h1: %.8x %.8x\n", h1[1], h1[0]);
	
	BIGNUM *s, *h, *x, *y;
	x = BN_new();
	y = BN_new();
    endiannessConvert((byte *) sig, 8);
    endiannessConvert((byte *) h1, 8);
	s = BN_bin2bn((byte *)sig, 8, nullptr);
	h = BN_bin2bn((byte *)h1, 8, nullptr);

	EC_POINT *r = EC_POINT_new(eCurve);
	EC_POINT *t = EC_POINT_new(eCurve);
	/* r = sig*(sig*generator + h1*public_key) */
	EC_POINT_mul(eCurve, t, nullptr, generator, s, ctx);
	EC_POINT_mul(eCurve, r, nullptr, public_key, h, ctx);
	EC_POINT_add(eCurve, r, r, t, ctx);
	EC_POINT_mul(eCurve, r, nullptr, r, s, ctx);
	EC_POINT_get_affine_coordinates_GFp(eCurve, r, x, y, ctx);
	
	ul32 h2[1];
	/* h2 = SHA-1(79 || OS Family || r.x || r.y) */
	SHA1_Init(&h_ctx);
	buf[0] = 0x79;
	buf[1] = osfamily[0] & 0xff;
	buf[2] = (osfamily[0] & 0xff00) >> 8;
	SHA1_Update(&h_ctx, buf, 3);
	
	memset(buf, 0, FIELD_BYTES_2003);
	BN_bn2bin(x, buf);
    endiannessConvert((byte *) buf, FIELD_BYTES_2003);
	SHA1_Update(&h_ctx, buf, FIELD_BYTES_2003);
	
	memset(buf, 0, FIELD_BYTES_2003);
	BN_bn2bin(y, buf);
    endiannessConvert((byte *) buf, FIELD_BYTES_2003);
	SHA1_Update(&h_ctx, buf, FIELD_BYTES_2003);
	
	SHA1_Final(md, &h_ctx);
	h2[0] = (md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24)) & 0x7fffffff;
	printf("Calculated hash: %.8x\n", h2[0]);
		
	BN_free(s);
	BN_free(h);
	BN_free(x);
	BN_free(y);
	EC_POINT_free(r);
	EC_POINT_free(t);
	BN_CTX_free(ctx);

	if (h2[0] == hash[0]) return true;
	else return false;
}

void generateServerKey(char *pKey, EC_GROUP *eCurve, EC_POINT *generator, BIGNUM *order, BIGNUM *privateKey, ul32 *osFamily, ul32 *prefix) {
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *c = BN_new();
	BIGNUM *s = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *b = BN_new();
	EC_POINT *r = EC_POINT_new(eCurve);

	ul32 bKey[4];
	ul32 h1[2];
	
	do {
		ul32 hash = 0, sig[2]{};

		memset(bKey, 0, 4);

		// Generate a random number c consisting of 512 bits without any constraints.
		BN_rand(c, FIELD_BITS_2003, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

		// r = generator * c
		EC_POINT_mul(eCurve, r, nullptr, generator, c, ctx);

		// x = r.x; y = r.y;
		EC_POINT_get_affine_coordinates(eCurve, r, x, y, ctx);
			
		SHA_CTX hContext;
		byte md[SHA_DIGEST_LENGTH]{}, buf[FIELD_BYTES_2003]{};

		// hash = SHA-1(79 || OS Family || r.x || r.y)
		SHA1_Init(&hContext);

		buf[0] = 0x79;

		buf[1] = (*osFamily & 0xff);
		buf[2] = (*osFamily & 0xff00) >> 8;

		SHA1_Update(&hContext, buf, 3);
		
		memset(buf, 0, FIELD_BYTES_2003);

		BN_bn2bin(x, buf);
        endiannessConvert((byte *) buf, FIELD_BYTES_2003);
		SHA1_Update(&hContext, buf, FIELD_BYTES_2003);
		
		memset(buf, 0, FIELD_BYTES_2003);

		BN_bn2bin(y, buf);
        endiannessConvert((byte *) buf, FIELD_BYTES_2003);

		SHA1_Update(&hContext, buf, FIELD_BYTES_2003);
		SHA1_Final(md, &hContext);

		hash = (md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24)) & 0x7fffffff;
			
		/* h1 = SHA-1(5D || OS Family || Hash || Prefix || 00 00) */
		SHA1_Init(&hContext);
		buf[0] = 0x5D;
		
		buf[1] = (*osFamily & 0xff);
		buf[2] = (*osFamily & 0xff00) >> 8;
		
		buf[3] = (hash & 0xff);
		buf[4] = (hash & 0xff00) >> 8;
		buf[5] = (hash & 0xff0000) >> 16;
		buf[6] = (hash & 0xff000000) >> 24;
		
		buf[7] = prefix[0] & 0xff;
		buf[8] = (prefix[0] & 0xff00) >> 8;
		
		buf[9] = 0x00;
		buf[10] = 0x00;
		SHA1_Update(&hContext, buf, 11);
		SHA1_Final(md, &hContext);

		h1[0] = md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24);
		h1[1] = (md[4] | (md[5] << 8) | (md[6] << 16) | (md[7] << 24)) >> 2;
		h1[1] &= 0x3FFFFFFF;
		printf("h1: %.8x %.8x\n", h1[1], h1[0]);
	
		/* s = ( -h1*privateKey + sqrt( (h1*privateKey)^2 + 4k ) ) / 2 */
        endiannessConvert((byte *) h1, 8);
		BN_bin2bn((byte *)h1, 8, b);
		BN_mod_mul(b, b, privateKey, order, ctx);
		BN_copy(s, b);
		BN_mod_sqr(s, s, order, ctx);
		BN_lshift(c, c, 2);
		BN_add(s, s, c);
		BN_mod_sqrt(s, s, order, ctx);
		BN_mod_sub(s, s, b, order, ctx);
		if (BN_is_odd(s)) {
			BN_add(s, s, order);
		}
		BN_rshift1(s, s);
		sig[0] = sig[1] = 0;
		BN_bn2bin(s, (byte *)sig);
        endiannessConvert((byte *)sig, BN_num_bytes(s));
		packServer(bKey, osFamily, &hash, sig, prefix);

		printf("OS family: %u\nHash: %.8x\nSig: %.8x %.8x\nPrefix: %.8x\n", *osFamily, hash, sig[1], sig[0], *prefix);
		printf("%.8x %.8x %.8x %.8x\n", bKey[3], bKey[2], bKey[1], bKey[0]);
	} while (bKey[3] >= 0x40000000);

	base24(pKey, bKey);
	
	BN_free(c);
	BN_free(s);
	BN_free(x);
	BN_free(y);
	BN_free(b);

	BN_CTX_free(ctx);
	EC_POINT_free(r);
}

bool keyServer(char *pKey) {

	// We cannot produce a valid key without knowing the private key k. The reason for this is that
	// we need the result of the function K(x; y) = kG(x; y).
	BIGNUM *privateKey = BN_new();

	// We can, however, validate any given key using the available public key: {p, a, b, G, K}.
	// genOrder the order of the generator G, a value we have to reverse -> Schoof's Algorithm.
	BIGNUM *genOrder = BN_new();

	/* Computed data */
	BN_hex2bn(&genOrder, genOrderSv);
	BN_hex2bn(&privateKey, privateKeySv);

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

	ul32 osFamily = 1280, prefix = 0;

	RAND_bytes((byte *)&prefix, 4);
	
	prefix &= 0x3ff;
	
	generateServerKey(pKey, eCurve, genPoint, genOrder, privateKey, &osFamily, &prefix);

	printProductKey(pKey);
	printf("\n\n");

	return verifyServerKey(eCurve, genPoint, pubPoint, pKey);
}
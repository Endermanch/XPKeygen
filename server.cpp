//
// Created by Andrew on 09/04/2023.
//

#include "header.h"

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

void verifyServerKey(EC_GROUP *eCurve, EC_POINT *generator, EC_POINT *public_key, char *cdKey) {
	byte key[25];
	int i, j, k;

	BN_CTX *ctx = BN_CTX_new();

	for (i = 0, k = 0; i < strlen(cdKey); i++) {
		for (j = 0; j < 24; j++) {
			if (cdKey[i] != '-' && cdKey[i] == charset[j]) {
				key[k++] = j;
				break;
			}
			assert(j < 24);
		}
		if (k >= 25) break;
	}
	
	ul32 bkey[4] = {0};
	ul32 osfamily[1], hash[1], sig[2], prefix[1];
	unbase24(bkey, key);
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
	s = BN_bin2bn((byte *)sig, 8, NULL);
	h = BN_bin2bn((byte *)h1, 8, NULL);

	EC_POINT *r = EC_POINT_new(eCurve);
	EC_POINT *t = EC_POINT_new(eCurve);
	/* r = sig*(sig*generator + h1*public_key) */
	EC_POINT_mul(eCurve, t, NULL, generator, s, ctx);
	EC_POINT_mul(eCurve, r, NULL, public_key, h, ctx);
	EC_POINT_add(eCurve, r, r, t, ctx);
	EC_POINT_mul(eCurve, r, NULL, r, s, ctx);
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
	
	if (h2[0] == hash[0]) printf("Key VALID\n");
	else printf("Key invalid\n");
	
	BN_free(s);
	BN_free(h);
	BN_free(x);
	BN_free(y);
	EC_POINT_free(r);
	EC_POINT_free(t);
	BN_CTX_free(ctx);
}

void generateServerKey(byte *pKey, EC_GROUP *eCurve, EC_POINT *generator, BIGNUM *order, BIGNUM *privateKey, ul32 *osFamily, ul32 *prefix) {
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *k = BN_new();
	BIGNUM *s = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *b = BN_new();
	EC_POINT *r = EC_POINT_new(eCurve);

	ul32 bkey[4];
	byte buf[FIELD_BYTES_2003], md[20];
	ul32 h1[2];
	ul32 hash[1], sig[2];
	
	SHA_CTX h_ctx;
	
	for (;;) {
		/* r = k*generator */
		BN_rand(k, FIELD_BITS_2003, -1, 0);
		EC_POINT_mul(eCurve, r, NULL, generator, k, ctx);
		EC_POINT_get_affine_coordinates(eCurve, r, x, y, ctx);
			
		/* hash = SHA-1(79 || OS Family || r.x || r.y) */
		SHA1_Init(&h_ctx);
		buf[0] = 0x79;
		buf[1] = osFamily[0] & 0xff;
		buf[2] = (osFamily[0] & 0xff00) >> 8;
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
		hash[0] = (md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24)) & 0x7fffffff;
			
		/* h1 = SHA-1(5D || OS Family || Hash || Prefix || 00 00) */
		SHA1_Init(&h_ctx);
		buf[0] = 0x5d;
		buf[1] = osFamily[0] & 0xff;
		buf[2] = (osFamily[0] & 0xff00) >> 8;
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
	
		/* s = ( -h1*privateKey + sqrt( (h1*privateKey)^2 + 4k ) ) / 2 */
        endiannessConvert((byte *) h1, 8);
		BN_bin2bn((byte *)h1, 8, b);
		BN_mod_mul(b, b, privateKey, order, ctx);
		BN_copy(s, b);
		BN_mod_sqr(s, s, order, ctx);
		BN_lshift(k, k, 2);
		BN_add(s, s, k);
		BN_mod_sqrt(s, s, order, ctx);
		BN_mod_sub(s, s, b, order, ctx);
		if (BN_is_odd(s)) {
			BN_add(s, s, order);
		}
		BN_rshift1(s, s);
		sig[0] = sig[1] = 0;
		BN_bn2bin(s, (byte *)sig);
        endiannessConvert((byte *) sig, BN_num_bytes(s));
		if (sig[1] < 0x40000000) break;
	}
    packServer(bkey, osFamily, hash, sig, prefix);
	printf("OS family: %u\nHash: %.8x\nSig: %.8x %.8x\nPrefix: %.8x\n", osFamily[0], hash[0], sig[1], sig[0], prefix[0]);
	printf("%.8x %.8x %.8x %.8x\n", bkey[3], bkey[2], bkey[1], bkey[0]);
	base24(pKey, bkey);
	
	BN_free(k);
	BN_free(s);
	BN_free(x);
	BN_free(y);
	BN_free(b);
	EC_POINT_free(r);

	BN_CTX_free(ctx);
	
}
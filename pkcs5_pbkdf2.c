/*	$OpenBSD: pkcs5_pbkdf2.c,v 1.4 2013/06/03 21:07:02 tedu Exp $	*/

/*-
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <string.h>
#include <limits.h>
#include <stdlib.h>
//#include <util.h>

#include "sha1.h"

/*
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
 * Code based on IEEE Std 802.11-2007, Annex H.4.2.
 */
int
pkcs5_pbkdf2(const char *pass, size_t pass_len, const uint8_t *salt, size_t salt_len,
    uint8_t *key, size_t key_len, unsigned int rounds)
{
	uint8_t *asalt, obuf[SHA1_DIGEST_LENGTH];
	uint8_t d1[SHA1_DIGEST_LENGTH], d2[SHA1_DIGEST_LENGTH];
	unsigned int i, j;
	unsigned int count;
	size_t r;

	if (rounds < 1 || key_len == 0)
		return -1;
	if (salt_len == 0 || salt_len > SIZE_MAX - 4)
		return -1;
	if ((asalt = malloc(salt_len + 4)) == NULL)
		return -1;

	memcpy(asalt, salt, salt_len);

	for (count = 1; key_len > 0; count++) {
		asalt[salt_len + 0] = (count >> 24) & 0xff;
		asalt[salt_len + 1] = (count >> 16) & 0xff;
		asalt[salt_len + 2] = (count >> 8) & 0xff;
		asalt[salt_len + 3] = count & 0xff;
		SHA1Hmac((const uint8_t *) pass, pass_len, asalt, salt_len + 4, d1);
		memcpy(obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			SHA1Hmac((const uint8_t *) pass, pass_len, d1, sizeof(d1), d2);
			memcpy(d1, d2, sizeof(d1));
			for (j = 0; j < sizeof(obuf); j++)
				obuf[j] ^= d1[j];
		}

		r = MIN(key_len, SHA1_DIGEST_LENGTH);
		memcpy(key, obuf, r);
		key += r;
		key_len -= r;
	};
	bzero(asalt, salt_len + 4);
	free(asalt);
	bzero(d1, sizeof(d1));
	bzero(d2, sizeof(d2));
	bzero(obuf, sizeof(obuf));

	return 0;
}


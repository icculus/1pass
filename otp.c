#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sha1.h"
#include "otp.h"

static int base32_decode(const char *src, const int srclen, uint8_t *dst, const int dstlen)
{
    const int len = srclen == -1 ? strlen((const char *) src) : srclen;
    int retval = 0;
    uint32_t accum = 0;
    int shifter = 0;
    int i;

    for (i = 0; i < len; i++) {
        const uint8_t ch = (uint8_t) src[i];
        uint8_t val;

        if ((ch >= 'A') && (ch <= 'Z')) {
            val = ch - 'A';
        } else if ((ch >= '2') && (ch <= '7')) {
            val = (ch - '2') + 26;
        } else if (ch == '=') {
            val = 0;

        /* these are illegal in base32, but GAuth keys might have them. */
        } else if (ch == ' ') {
            continue;  /* skip these. */
        } else if ((ch >= 'a') && (ch <= 'z')) {
            val = ch - 'a'; /* treat like uppercase. */

        } else {
            return -1;  /* invalid string. */
        }

        accum = (accum << 5) | ((uint32_t) val);
        shifter += 5;
        if (shifter >= 8) {
            if (retval > dstlen) {
                return -1;  /* dst too small */
            }
            dst[retval] = (uint8_t) ((accum >> (shifter - 8)) & 0xFF);
            retval++;
            shifter -= 8;
        }
    }

    if (shifter > 0) {
        if (retval > dstlen) {
            return -1;  /* dst too small */
        }
        dst[retval] = (uint8_t) (accum & 0xFF);
        retval++;
    }

    return retval;
}

int totp(const char *base32_secret, char *dst, int dstlen)
{
    uint8_t decoded[64];
    int decodedlen;
    uint64_t secs;
    uint8_t timebytes[8];
    unsigned char digest[SHA1_DIGEST_LENGTH];
    uint8_t *bytes;
    uint32_t val;

    decodedlen = base32_decode(base32_secret, -1, decoded, sizeof (decoded));
    if (decodedlen == -1) {
        return -1;
    }

    secs = ((uint64_t) time(NULL)) / 30;
    for (int i = 0; i < 8; i++) {
        timebytes[i] = (uint8_t) (secs >> ((7-i) * 8));
    }

    SHA1Hmac(decoded, decodedlen, timebytes, 8, digest);

    bytes = (uint8_t *) (digest + (digest[SHA1_DIGEST_LENGTH-1] & 0xF));
    val = (((uint32_t) bytes[0]) << 24) | (((uint32_t) bytes[1]) << 16) |
          (((uint32_t) bytes[2]) << 8) | (((uint32_t) bytes[3]));
    val &= 0x7FFFFFFF; /* drop most significant bit. */
    val %= 1000000;  /* make it six digits long. */

    snprintf(dst, dstlen, "%06u", (unsigned int) val);
    return 0;
}

/* end of otp.c ... */


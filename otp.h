#ifndef _OTP_H_
#define _OTP_H_

int totp(const char *base32_secret, char *dst, int dstlen);

#endif

/* end of otp.h ... */


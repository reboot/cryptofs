/*
 * Copyright (C) 1999-2002 Hiroyuki Yamamoto
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <glib.h>
#include <ctype.h>
#include <string.h>

#include "base64.h"

static const gchar base64char[64] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";

static const gchar base64val[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, -1,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

#define BASE64VAL(c)	(isascii(c) ? base64val[(gint)(c)] : -1)

gint base64_encode(gchar *out, const gchar *in, gint inlen)
{
	const guchar *inp = (const guchar *) in;
	gchar *outp = out;

	while (inlen >= 3) {
		*outp++ = base64char[(inp[0] >> 2) & 0x3f];
		*outp++ = base64char[((inp[0] & 0x03) << 4) |
				     ((inp[1] >> 4) & 0x0f)];
		*outp++ = base64char[((inp[1] & 0x0f) << 2) |
				     ((inp[2] >> 6) & 0x03)];
		*outp++ = base64char[inp[2] & 0x3f];

		inp += 3;
		inlen -= 3;
	}

	if (inlen > 0) {
		*outp++ = base64char[(inp[0] >> 2) & 0x3f];
		if (inlen == 1) {
			*outp++ = base64char[(inp[0] & 0x03) << 4];
			*outp++ = '=';
		} else {
			*outp++ = base64char[((inp[0] & 0x03) << 4) |
					     ((inp[1] >> 4) & 0x0f)];
			*outp++ = base64char[((inp[1] & 0x0f) << 2)];
		}
		*outp++ = '=';
	}

	*outp = '\0';
	return outp - out;
}

gint base64_decode(gchar *out, const gchar *in, gint inlen)
{
	const guchar *inp = (const guchar *) in;
	gchar *outp = out;
	gchar buf[4];

	if (inlen < 0)
		inlen = G_MAXINT;

	while (inlen >= 4 && *inp != '\0') {
		buf[0] = *inp++;
		inlen--;
		if (BASE64VAL(buf[0]) == -1) break;

		buf[1] = *inp++;
		inlen--;
		if (BASE64VAL(buf[1]) == -1) break;

		buf[2] = *inp++;
		inlen--;
		if (buf[2] != '=' && BASE64VAL(buf[2]) == -1) break;

		buf[3] = *inp++;
		inlen--;
		if (buf[3] != '=' && BASE64VAL(buf[3]) == -1) break;

		*outp++ = ((BASE64VAL(buf[0]) << 2) & 0xfc) |
			  ((BASE64VAL(buf[1]) >> 4) & 0x03);
		if (buf[2] != '=') {
			*outp++ = ((BASE64VAL(buf[1]) & 0x0f) << 4) |
				  ((BASE64VAL(buf[2]) >> 2) & 0x0f);
			if (buf[3] != '=') {
				*outp++ = ((BASE64VAL(buf[2]) & 0x03) << 6) |
					   (BASE64VAL(buf[3]) & 0x3f);
			}
		}
	}

	return outp - out;
}

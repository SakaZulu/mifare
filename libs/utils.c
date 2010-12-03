/*
 * Copyright (c) 2010, Anugrah Redja Kusuma <anugrah.redja@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"

ssize_t full_read(int fd, void *buf, size_t size)
{
	uint8_t *p = buf;
	size_t left = size, nb;
	while (left > 0)
	{
		nb = read(fd, p, left);
		if (nb <= 0)
			break;
		p += nb;
		left -= nb;
	}
	return size - left;
}

ssize_t full_write(int fd, const void *buf, size_t size)
{
	const uint8_t *p = buf;
	size_t left = size, nb;
	while (left > 0)
	{
		nb = write(fd, p, left);
		if (nb <= 0)
			break;
		p += nb;
		left -= nb;
	}
	return size - left;
}

/**
 * Parse hex string into a buffer (byte array).
 *
 * Byte array will be filled left to right, and will be padded with 0 if 
 * there's no more string. Note: single digit hex string won't be parsed.
 *
 * Returns the number of bytes actually parsed.
 */
int parse_hex(const char *hex, void *buf, int size)
{
	uint8_t b = 0;
	int i, total = 0, len = strlen(hex) & ~1; /* make len even */
	if (len > size * 2)
		len = size * 2;
	memset(buf, 0, size);
	for (i = 0; i < len; i++)
	{
		uint8_t c = tolower(hex[len - i - 1]);
		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'a' && c <= 'f')
			c -= 'a' - 10;
		else
			break;

		b = (b << 4) | c;
		
		if ((i & 1))
			((uint8_t *) buf)[total++] = b;
	}
	return total;
}

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
#include "utils.h"

ssize_t full_read(int fildes, void *buf, size_t size)
{
	uint8_t *p = buf;
	size_t left = size, nb;
	while (left > 0)
	{
		nb = read(fildes, p, left);
		if (nb <= 0)
			break;
		p += nb;
		left -= nb;
	}
	return size - left;
}

ssize_t full_write(int fildes, const void *buf, size_t size)
{
	const uint8_t *p = buf;
	size_t left = size, nb;
	while (left > 0)
	{
		nb = write(fildes, p, left);
		if (nb <= 0)
			break;
		p += nb;
		left -= nb;
	}
	return size - left;
}

void print_bytes(const char *label, const void *buf, int len)
{
	int i;
	printf("%s:", label);
	for (i = 0; i < len; i++)
		printf(" %02x", ((uint8_t *) buf)[i]);
	printf("\n");
}

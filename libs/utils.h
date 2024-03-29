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

#ifndef _UTILS_H_
#define _UTILS_H_

ssize_t full_read(int fd, void *buf, size_t size);
ssize_t full_write(int fd, const void *buf, size_t size);

int parse_hex(const char *hex, void *buf, int size);

#define DUMP(s, buf, off, size) { \
	int i; printf("%s", s); \
	for (i = 0; i < size; i++) { \
		if (i > 0) printf(" "); \
		printf("%02x", ((uint8_t *) buf)[off + i]); \
	} \
	puts(""); }

#define ERROR(fmt, args...) { fprintf(stderr, fmt "\n", ##args); exit(1); }

#endif

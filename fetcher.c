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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "acr120.h"

#define TTY_DEV "/dev/ttyUSB0"

void dispatch(acr120_tag_t *tag, uint8_t *data)
{
	char serial[21], sdata[33], *p;

	int i;
	p = serial;
	for (i = 0; i < tag->size; i++)
		p += sprintf(p, "%02x", tag->serial[i]);

	p = sdata;
	for (i = 0; i < ACR120_BLOCK_SIZE; i++)
		p += sprintf(p, "%02x", data[i]);

	printf("cmd %s %s\n", serial, sdata);
}

int main()
{
	acr120_tag_t tag, last_tag;
	int i;

	int handle = acr120_open(TTY_DEV, 0, 0);
	if (handle < 0)
	{
		perror(TTY_DEV);
		return 1;
	}

	acr120_write_user_port(handle, 1);

	for (;;)
	{
		memset(&tag, 0, sizeof(tag));
		int ret = acr120_select(handle, &tag);
		if (ret != 0 && ret != ACR120_ERROR_NO_TAG)
			break;

		if (memcmp(&tag, &last_tag, sizeof(tag)) == 0)
				usleep(200000);
		else
		{
			if (ret != ACR120_ERROR_NO_TAG)
			{
				uint8_t block1[ACR120_BLOCK_SIZE];
				uint8_t key = 0;
				if (acr120_login(handle, 0, ACR120_KEY_TYPE_MASTER_A, &key) < 0)
					continue;
				if (acr120_read_block(handle, 1, block1) < 0)
					continue;

				dispatch(&tag, block1);

				int flip = 0;
				for (i = 0; i < 1; i++)
				{
					acr120_write_user_port(handle, 2 | flip);
					usleep(100000 / 1);
					flip ^= 1;
				}
				acr120_write_user_port(handle, 1);
				usleep(100000);
			}
			memcpy(&last_tag, &tag, sizeof(tag));
		}
	}

	acr120_close(handle);

	return 0;
}

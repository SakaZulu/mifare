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
#include "mifare.h"
#include "acr120s.h"
#include "mf1rw.h"

#define TTY_DEV "/dev/ttyUSB0"
#define PROG "cmd"

void dispatch(mifare_tag_t *tag, uint8_t *data)
{
	char serial[21], sdata[33], *p;
	char cmd[256];

	int i;
	p = serial;
	for (i = 0; i < tag->size; i++)
		p += sprintf(p, "%02x", tag->serial[i]);

	p = sdata;
	for (i = 0; i < MIFARE_BLOCK_SIZE; i++)
		p += sprintf(p, "%02x", data[i]);

	sprintf(cmd, "%s %s %s", PROG, serial, sdata);
	puts(cmd);
}

#define MAX_TAG 16

int main()
{
	mifare_tag_t tags[MAX_TAG], last_tags[MAX_TAG];
	mifare_dev_t dev;
	int i, j, count, last_count;

	dev.device = TTY_DEV;
	dev.baud = 0;
	dev.sid = 0;
	
	mifare_ops = &acr120s_ops;
	int handle = mifare_open(&dev);
	if (handle < 0)
	{
		mifare_ops = &mf1rw_ops;
		handle = mifare_open(&dev);
		if (handle < 0)
		{
			fprintf(stderr, "No device at %s.\n", dev.device);
			return 1;
		}
	}

	if (mifare_ops == &acr120s_ops)
		acr120s_write_user_port(handle, 1);

	count = 0;
	for (;; usleep(200000))
	{
		last_count = count;
		memcpy(last_tags, tags, count * sizeof(mifare_tag_t));

		count = MAX_TAG;
		if (mifare_detect(handle, tags, &count))
			break;

		for (i = 0; i < count; i++)
		{
			for (j = 0; j < last_count; j++)
				if (memcmp(&tags[i], &last_tags[j], sizeof(mifare_tag_t)) == 0)
					break;
				
			/* New tag detected */
			if (j >= last_count)
			{
				uint8_t block[MIFARE_BLOCK_SIZE];
				uint8_t key[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

				if (mifare_select(handle, &tags[i]))
					continue;
				if (mifare_login(handle, 0, 0, key))
					continue;
				if (mifare_read_block(handle, 1, block))
					continue;

				dispatch(&tags[i], block);

				mifare_beep(handle, 50);
			}
		}
	}

	mifare_close(handle);

	return 0;
}

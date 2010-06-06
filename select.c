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

	int detected = 0;
	printf("Continuously select card. Press Ctrl+C to abort.\n");
	for (;;)
	{
		memset(&tag, 0, sizeof(tag));
		acr120_select(handle, &tag);
		if (memcmp(&tag, &last_tag, sizeof(tag)) != 0)
		{
			if (tag.size == 0)
			{
				detected = 0;
				acr120_write_user_port(handle, 0);
				printf("No card detected.");
				printf("          \r");
			}
			else
			{
				detected = 1;
				acr120_write_user_port(handle, 3);
				printf("            \rSerial: ");
				for (i = 0; i < tag.size; i++)
					printf("%02x", tag.serial[i]);
				printf("          \r");
			}
			fflush(stdout);
			memcpy(&last_tag, &tag, sizeof(tag));

			usleep(100000);
			if (detected)
				acr120_write_user_port(handle, 1);
			usleep(100000);
		}
		else
		{
				usleep(200000);
		}
	}

	acr120_close(handle);

	return 0;
}

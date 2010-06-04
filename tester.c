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
#include "acr120.h"

int g_key_type = -1;
int g_key[ACR120_KEY_SIZE];

void usage()
{
	printf("Usage: tester <command> ...\n");
	printf("Available commands:\n");
	exit(1);
}

void need_param(const char *s, int count)
{
	printf("Need %d additional parameter for `%s'\n");
	exit(1);
}

int parse_hex(const char *hex, uint8_t *key, int size)
{
	uint8_t *k = &key[size - 1];
	int i, digit = 0;
	memset(key, 0, size);
	for (i = strlen(hex) - 1; i >= 0; i--)
	{
		char c = tolower(hex[i]);
		if (c >= '0' && c <= '9')
		{
			*k |= (c - '0') << 4;
			digit++;
		}
		else if (c >= 'a' && c <= 'f')
		{
			*k |= (c - 'a' + 10) << 4;
			digit++;
		}
		else
			continue;

		if (digit < size * 2)
		{
			if ((digit & 1) == 0)
				k--;
			else
				*k >>= 4;
		}
	}
	return digit;
}

void do_read(int argc, char **argv)
{
	if (argv[0] == 0)
		usage();

	if (!strcmp(argv[0], "block"))
	{
		if (argv[1]
	}
	else if (!strcmp(argv[0], "value"))
	{
	}
	else if (!strcmp(argv[0], "eeprom"))
	{
	}
	else if (!strcmp(argv[0], "port"))
	{
	}
	else if (!strcmp(argv[0], "reg"))
	{
	}
	else
		usage();
}

int main (int argc, char **argv)
{
	/* Skip program name */
	argc--;
	argv++;

	int i;
	for (i = 0; i < argc;)
	{
		int skip = 0;
		if (!strcmp(argv[i], "-akey"))
		{
			if (!argv[i + 1])
				usage_param(argv[i]);

			skip = 2;
			g_key_type = ACR120_KEY_TYPE_A;
			parse_hex(agv[i + 1], g_key, ACR120_KEY_SIZE);
		}
		else if (!strcmp(argv[i], "-bkey"))
		{
			if (!argv[i + 1])
				usage_param(argv[i]);

			skip = 2;
			g_key_type = ACR120_KEY_TYPE_B;
			parse_hex(agv[i + 1], g_key, ACR120_KEY_SIZE);
		}
		else if (!strcmp(argv[i], "-amkey"))
		{
			if (!argv[i + 1])
				usage_param(argv[i]);

			skip = 2;
			g_key_type = ACR120_KEY_TYPE_MASTER_A;
			g_key[0] = atoi(argv[i + 1]);
		}
		else if (!strcmp(argv[i], "-bmkey"))
		{
			if (!argv[i + 1])
				usage_param(argv[i]);

			skip = 2;
			g_key_type = ACR120_KEY_TYPE_MASTER_B;
			g_key[0] = atoi(argv[i + 1]);
		}

		if (skip == 0)
			i++;
		else
		{
			int j;
			argc -= skip;
			for (j = i; j <= argc; j++)
				argv[i] = argv[i + skip];
		}
	}

	if (argv[0] == 0)
		usage();
	
	if (!strcmp(argv[0], "read"))
		do_read(argc - 1, argv + 1);
	else if (!strcmp(argv[0], "write"))
		do_write(argc - 1, argv + 1);
	else
		usage();
}

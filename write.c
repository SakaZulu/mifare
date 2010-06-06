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
#include <ctype.h>
#include <stdlib.h>
#include "acr120.h"

#define TTY_DEV "/dev/ttyUSB0"

void usage()
{
	printf("Usage: write block <block> <val> key <a|b|ea|eb> <key>\n");
	printf("       write value <block> <val> key <a|b|ea|eb> <key>\n");
	printf("       write eeprom <reg> <val>\n");
	printf("       write master <reg> <key>\n");
	printf("       write port <val>\n");
	exit(1);
}

void parse_hex(const char *hex, unsigned char *key, int size)
{
	unsigned char *k = &key[size - 1];
	int i, digit = 0;
	memset(key, 0, size);
	for (i = strlen(hex) - 1; i >= 0; i--)
	{
		char c = tolower(hex[i]);
		if (c >= '0' && c <= '9')
			*k |= (c - '0') << 4;
		else if (c >= 'a' && c <= 'f')
			*k |= (c - 'a' + 10) << 4;
		else
			continue;

		if ((++digit & 1) == 0)
			k--;
		else
			*k >>= 4;
	}
}

int main(int argc, char **argv)
{
	int i, ret, type = 0, handle, block = 0;
	unsigned char key[ACR120_KEY_SIZE], data[ACR120_BLOCK_SIZE];
	long value;

	if (argc == 1)
		usage();
	else if (!strcmp(argv[1], "block") || !strcmp(argv[1], "value"))
	{
		if (argc != 7)
			usage();
		if (strcmp(argv[4], "key"))
			usage();

		if (!strcmp(argv[5], "a"))
		{
			type = ACR120_KEY_TYPE_A;
			parse_hex(argv[6], key, ACR120_KEY_SIZE);
		}
		else if (!strcmp(argv[5], "b"))
		{
			type = ACR120_KEY_TYPE_B;
			parse_hex(argv[6], key, ACR120_KEY_SIZE);
		}
		else if (!strcmp(argv[5], "ma"))
		{
			type = ACR120_KEY_TYPE_MASTER_A;
			key[0] = atoi(argv[6]);
		}
		else if (!strcmp(argv[5], "mb"))
		{
			type = ACR120_KEY_TYPE_MASTER_B;
			key[0] = atoi(argv[6]);
		}
		else
			usage();

		block = atoi(argv[2]);
	}
	else if (!strcmp(argv[1], "eeprom"))
	{
		if (argc != 4)
			usage();

		block = atoi(argv[2]);
	}
	else if (!strcmp(argv[1], "master"))
	{
		if (argc != 3)
			usage();

		block = atoi(argv[2]); 
	}
	else if (!strcmp(argv[1], "port"))
	{
		if (argc != 3)
			usage();
	}
	else
		usage();

	handle = acr120_open(TTY_DEV, 0, 0);
	if (handle < 0)
	{
		perror(TTY_DEV);
		return 1;
	}

	if (!strcmp(argv[1], "block") || !strcmp(argv[1], "value"))
	{
		acr120_tag_t tag;

		if (acr120_select(handle, &tag) < 0)
		{
			printf("No card detected.\n");
			return 1;
		}

		printf("Serial: ");
		for (i = 0; i < tag.size; i++)
			printf("%02x", tag.serial[i]);
		printf("\n");

		int sector = block / ACR120_BLOCK_PER_SECTOR;
		if ((ret = acr120_login(handle, sector, type, key)) < 0)
		{
			printf("Login failed (-%c)\n", -ret);
			return 1;
		}
	
		if (!strcmp(argv[1], "block"))
		{
			parse_hex(argv[3], data, ACR120_BLOCK_SIZE);
			if ((ret = acr120_write_block(handle, block, data)) < 0)
			{
				printf("Write block failed (-%c)\n", -ret);
				return 1;
			}
			
			printf("Block[%d]:", block);
			for (i = 0; i < 16; i++)
				printf(" %02x", (unsigned char) data[i]);
			printf("\n");
		}
		else
		{
			value = atoi(argv[3]);
			if ((ret = acr120_write_value(handle, block, value)) < 0)
			{
				printf("Write value failed (-%c)\n", -ret);
				return 1;
			}

			printf ("Value[%d]: %ld (%08lx)\n", block, value, value);
		}
	}
	else if (!strcmp(argv[1], "eeprom"))
	{
		unsigned char val = atoi(argv[3]);
		if ((ret = acr120_write_eeprom(handle, block, val)) < 0)
		{
			printf("Write failed (-%c)\n", -ret);
			return 1;
		}

		printf("Reg[%d] = %d (0x%02x)\n", block, val, val);
	}
	else if (!strcmp(argv[1], "master"))
	{
		parse_hex(argv[3], key, ACR120_KEY_SIZE);
		if ((ret = acr120_write_master_key(handle, block, key)) < 0)
		{
			printf("Write master key failed (-%c)\n", -ret);
			return 1;
		}

		printf("Master[%d]:", block);
		for (i = 0; i < ACR120_KEY_SIZE; i++)
			printf(" %02x", (unsigned char) key[i]);
		printf("\n");
	}
	else
	{
		unsigned char val = atoi(argv[2]);
		if ((ret = acr120_write_user_port(handle, val)) < 0)
		{
			printf("Write failed (-%c)\n", -ret);
			return 1;
		}

		printf("User Port = %d (0x%02x)\n", ret, ret);
	}

	acr120_close(handle);

	return 0;
}

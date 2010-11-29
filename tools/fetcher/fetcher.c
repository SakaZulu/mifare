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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <expat.h>
#include "mifare.h"
#include "acr120s.h"
#include "mf1rw.h"
#include "utils.h"

struct dict
{
	char *key;
	int value;
};

enum
{
	DEVICE_TYPE_ACR120S,
	DEVICE_TYPE_MF1RW
};

static struct dict device_type_dict[] =
{
	{ "acr120s", DEVICE_TYPE_ACR120S },
	{ "mf1rw", DEVICE_TYPE_MF1RW },
	{ 0, 0 }
};

static struct dict device_baud_dict[] =
{
	{ "9600", B9600 },
	{ "19200", B19200 },
	{ "38400", B38400 },
	{ "57600", B57600 },
	{ "115200", B115200 },
	{ 0, 0 }
};

struct device
{
	char *id;
	char *dev;
	int baud;
	int type;

	int has_id;
	int has_dev;
	int has_baud;
	int has_type;

	struct device *next;
};

enum
{
	KEY_TYPE_A,
	KEY_TYPE_B
};

struct dict key_type_dict[] = 
{
	{ "a", KEY_TYPE_A },
	{ "b", KEY_TYPE_B },
	{ 0, 0 }
};

struct key
{
	int sector;
	int type;
	unsigned char bytes[6];
	int eeprom;
	
	int has_sector;
	int has_type;
	int has_bytes;
	int has_eeprom;

	struct key *next;
};

enum
{
	ITEM_TYPE_ID,     /* Device ID */
	ITEM_TYPE_UID,    /* Card UID */
	ITEM_TYPE_STRING, /* Zero terminated string */
	ITEM_TYPE_BYTES,  /* Raw bytes */
	ITEM_TYPE_VALUE,  /* Value block */
};

struct dict item_type_dict[] =
{
	{ "id", ITEM_TYPE_ID },
	{ "uid", ITEM_TYPE_UID },
	{ "string", ITEM_TYPE_STRING },
	{ "bytes", ITEM_TYPE_BYTES },
	{ "value", ITEM_TYPE_VALUE },
	{ 0, 0 }
};

struct item
{
	int type;
  int block;
  int offset;
  int size;

	int has_type;
	int has_block;
	int has_offset;
	int has_size;

	struct item *next;
};

struct config
{
	struct device *devices;
	struct key *keys;
	struct item *items;
	char *cmd;
	int item_count;
} config;

#define BUFFER_SIZE 4096

struct config_ctx
{
	char *parent;
	struct device *last_device;
	struct key *last_key;
	struct item *last_item;
	int depth;
};

int lookup(const char *key, struct dict *dict, int *result)
{
	for (; dict->key; dict++)
		if (!strcmp(dict->key, key))
		{
			*result = dict->value;
			return 1;
		}
	return 0;
}

void parse_hex(const char *hex, void *key, int size)
{
	char *k = &((char *) key)[size - 1];
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

void start_handler(void *data, const char *name, const char **atts)
{
	struct config_ctx *ctx = (struct config_ctx *) data;
	ctx->depth++;
	int i = 0;
	switch (ctx->depth)
	{
		case 1:
			if (strcmp(name, "config"))
				goto error_tag;
			break;

		case 2:
			if (!strcmp(name, "exec"))
			{
				for (i = 0; atts[i]; i += 2)
				{
					if (!strcmp(atts[i], "cmd"))
					{
						config.cmd = strdup(atts[i + 1]);
						break;
					}
					else
						goto error_attr;
				}
				if (!atts[i])
				{
					fprintf(stderr, "Expecting 'cmd' attribute for 'exec' tag.\n");
					exit(1);
				}
			}
			else if (strcmp(name, "devices") &&	strcmp(name, "keys") &&
					strcmp(name, "items") && strcmp(name, "exec"))
				goto error_tag;
			free(ctx->parent);
			ctx->parent = strdup(name);
			break;

		case 3:
			if (!strcmp(name, "device") && !strcmp(ctx->parent, "devices"))
			{
				struct device *device = calloc(1, sizeof(*device));
				int i;
				for (i = 0; atts[i]; i += 2)
				{
					if (!strcmp(atts[i], "id"))
					{
						device->id = strdup(atts[i + 1]);
						device->has_id = 1;
					}
					else if (!strcmp(atts[i], "dev"))
					{
						device->dev = strdup(atts[i + 1]);
						device->has_dev = 1;
					}
					else if (!strcmp(atts[i], "baud"))
					{
						if (!lookup(atts[i + 1], device_baud_dict, &device->baud))
							goto error_value;
						device->has_baud = 1;
					}
					else if (!strcmp(atts[i], "type"))
					{
						if (!lookup(atts[i + 1], device_type_dict, &device->type))
							goto error_value;
						device->has_type = 1;
					}
					else
						goto error_attr;
				}
				if (!device->has_id || !device->has_dev || !device->has_baud || !device->has_type)
				{
					fprintf(stderr, "Required attribute for 'device' tag is missing.\n");
					exit(1);
				}
				if (ctx->last_device == 0)
					config.devices = device;
				else
					ctx->last_device->next = device;
				ctx->last_device = device;
			}
			else if (!strcmp(name, "key") && !strcmp(ctx->parent, "keys"))
			{
				struct key *key = calloc(1, sizeof(*key));
				int i;
				for (i = 0; atts[i]; i += 2)
				{
					if (!strcmp(atts[i], "sector"))
					{
						key->sector = atoi(atts[i + 1]);
						key->has_sector = 1;
					}
					else if (!strcmp(atts[i], "type"))
					{
						if (!lookup(atts[i + 1], key_type_dict, &key->type))
							goto error_value;
						key->has_type = 1;
					}
					else if (!strcmp(atts[i], "bytes"))
					{
						parse_hex(atts[i + 1], key->bytes, 6);
						key->has_bytes = 1;
					}
					else if (!strcmp(atts[i], "eeprom"))
					{
						key->eeprom = atoi(atts[i  +1]);
						key->has_eeprom = 1;
					}
					else
						goto error_attr;
				}
				if (!(key->has_bytes ^ key->has_eeprom))
				{
					fprintf(stderr, "Key bytes and key eeprom cannot co-exists.\n");
					exit(1);
				}
				if (!key->has_sector || !key->has_type)
				{
					fprintf(stderr, "Required attribute for 'key' tag is missing.\n");
					exit(1);
				}
				if (ctx->last_key == 0)
					config.keys = key;
				else
					ctx->last_key->next = key;
				ctx->last_key= key;
			}
			else if (!strcmp(name, "item") && !strcmp(ctx->parent, "items"))
			{
				struct item *item = calloc(1, sizeof(*item));
				int i;
				item->offset = 0;
				item->size = 16;
				for (i = 0; atts[i]; i += 2)
				{
					if (!strcmp(atts[i], "type"))
					{
						if (!lookup(atts[i + 1], item_type_dict, &item->type))
						{
							fprintf(stderr, "Invalid item type '%s'.\n", atts[i + 1]);
							exit(1);
						}
						item->has_type = 1;
					}
					else if (!strcmp(atts[i], "block"))
					{
						item->block = atoi(atts[i + 1]);
						item->has_block = 1;

					}
					else if (!strcmp(atts[i], "offset"))
					{
						item->offset = atoi(atts[i + 1]);
						item->has_offset = 1;
					}
					else if (!strcmp(atts[i], "size"))
					{
						item->size = atoi(atts[i + 1]);
						item->has_size = 1;
					}
					else
						goto error_attr;
				}
				config.item_count++;
				if (ctx->last_item == 0)
					config.items = item;
				else
					ctx->last_item->next = item;
				ctx->last_item = item;
			}
			else
				goto error_tag;
			break;

		default:
			goto error_tag;
	}
	return;

error_tag:
	free(ctx->parent);
	fprintf(stderr, "Invalid tag '%s'.\n", name);
	exit(1);

error_attr:
	free(ctx->parent);
	fprintf(stderr, "Invalid attribute '%s'.\n", atts[i]);
	exit(1);

error_value:
	free(ctx->parent);
	fprintf(stderr, "Invalid attribute's value '%s'.\n", atts[i + 1]);
	exit(1);
}

void end_handler(void *data, const char *name)
{
	struct config_ctx *ctx = (struct config_ctx *) data;
	ctx->depth--;
}

void read_config()
{
	FILE *fp = fopen("config.example", "r");
	struct config_ctx ctx;
	if (fp == 0)
	{
		fprintf(stderr, "Config file not found.\n");
		exit(1);
	}
	memset(&config, 0, sizeof(config));
	memset(&ctx, 0, sizeof(ctx));
	XML_Parser parser = XML_ParserCreate(0);
	XML_SetUserData(parser, &ctx);
	XML_SetElementHandler(parser, start_handler, end_handler);
	for (;;)
	{
		size_t bytes_read;
		void *buf = XML_GetBuffer(parser, BUFFER_SIZE);
		bytes_read = fread(buf, 1, BUFFER_SIZE, fp);
		if (bytes_read < 0)
		{
			fclose(fp);
			XML_ParserFree(parser);
			fprintf(stderr, "Error reading file.\n");
			exit(1);
		}
		if (!XML_ParseBuffer(parser, bytes_read, bytes_read == 0))
		{
			fclose(fp);
			XML_ParserFree(parser);
			fprintf(stderr, "Error parsing file.\n");
			exit(1);
		}
		if (bytes_read == 0)
			break;
	}
	free(ctx.parent);
	fclose(fp);
	XML_ParserFree(parser);
}

void daemonize()
{
	pid_t pid, sid;

	pid = fork();
	if (pid < 0)
		exit(1);
	if (pid > 0)
		exit(0);

	umask(0);

	sid = setsid();
	if (sid < 0)
		exit(1);

	if (chdir("/") < 0)
		exit(1);

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

int block_to_sector(int block)
{
	return block / 4;
}

struct key *get_key(int sector)
{
	struct key *key;
	for (key = config.keys; key; key = key->next)
		if (key->sector == sector)
			return key;
	return 0;
}

void fetch(int handle, struct device *device, mifare_tag_t *tag)
{
	int last_block = -1;
	int last_sector = -1;
	uint8_t block[MIFARE_BLOCK_SIZE];
	char **argv = malloc((config.item_count + 2) * sizeof(*argv));
	struct item *item;
	int i;
					
	argv[0] = config.cmd;
	for (i = 1; i <= config.item_count; i++)
		argv[i] = 0;
	argv[config.item_count + 1] = 0;

	if (mifare_select(handle, tag))
	{
		syslog(LOG_INFO, "Cannot select card");
		goto invalid;
	}

	i = 0;
	for (item = config.items; item; item = item->next)
	{
		i++;
		if (item->type == ITEM_TYPE_ID)
			argv[i] = strdup(device->id);
		else if (item->type == ITEM_TYPE_UID)
		{
			argv[i] = malloc(tag->size * 2 + 1);
			char *p = argv[i];
			int j;
			for (j = 0; j < tag->size; j++)
				p += sprintf(p, "%02x", tag->serial[j]);
		}
		else
		{
			int sector = block_to_sector(item->block);
			if (last_sector != sector)
			{
				last_sector = sector;
				struct key *key = get_key(sector);
				if (key->has_bytes)
				{
					if (mifare_login(handle, sector, key->type, key->bytes))
					{
						syslog(LOG_INFO, "Cannot login to card");
						goto invalid;
					}
				}
				else if (key->has_eeprom)
				{
					if (mifare_login_stored(handle, sector, key->type, key->eeprom))
					{
						syslog(LOG_INFO, "Cannot login to card");
						goto invalid;
					}
				}
				else
					goto invalid;
			}

			if (item->type == ITEM_TYPE_VALUE)
			{
				int32_t value;
				if (mifare_read_value(handle, item->block, &value))
				{
					syslog(LOG_INFO, "Cannot read value");
					goto invalid;
				}
				argv[i] = (char *) malloc(12);
				sprintf(argv[i], "%d", value);
			}
			else
			{
				if (last_block != item->block)
				{
					if (mifare_read_block(handle, item->block, block))
					{
						syslog(LOG_INFO, "Cannot read block");
						goto invalid;
					}
					last_block = item->block;
				}
				if (item->type == ITEM_TYPE_BYTES)
				{
					argv[i] = (char *) malloc(item->size * 2 + 1);
					char *p = argv[i];
					int j;
					for (j = 0; j < item->size; j++)
						p += sprintf(p, "%02x", block[item->offset + j]);
				}
				else if (item->type == ITEM_TYPE_STRING)
				{
					argv[i] = (char *) malloc(17);
					strncpy(argv[i], (char *) &block[item->offset], item->size);
				}
				else
					goto invalid;
			}
		}
	}
	
	mifare_beep(handle, 50);

	int len = 0;
	for (i = 0; argv[i]; i++)
		len += strlen(argv[i]) + 3;
	char *b = (char *) malloc(len);
	char *p = b;
	p += sprintf(p, "'%s'", argv[0]);
	for (i = 1; argv[i]; i++)
		p += sprintf(p, " '%s'", argv[i]);
	*p = 0;

	pid_t pid;
	pid = fork();
	if (pid < 0)
		exit(1);

	if (pid == 0)
	{
		syslog(LOG_INFO, "Executing: %s", b);
		execvp(argv[0], argv);
		syslog(LOG_INFO, "Execute command error");
		exit(1);
	}

	free(b);
	wait(0);

	for (i = 1; i < config.item_count; i++)
		if (argv[i])
			free(argv[i]);
	free(argv);
	return;

invalid:
	for (i = 1; i < config.item_count; i++)
		if (argv[i])
			free(argv[i]);
	free(argv);

	syslog(LOG_INFO, "Invalid card at %s (%s) with UID %02x%02x%02x%02x",
			device->dev, device->id, tag->serial[0], tag->serial[1],
			tag->serial[2], tag->serial[3]);
	
	mifare_beep(handle, 50);
	mifare_beep(handle, 50);
}

#define MAX_TAG 4

void start_device(struct device *device)
{
	mifare_tag_t tags[MAX_TAG], last_tags[MAX_TAG];
	mifare_dev_t dev;
	int count, last_count;
	int i, j, handle;

	daemonize();
	dev.device = device->dev;
	dev.baud = device->baud;
	dev.sid = 0;
	switch (device->type)
	{
		case DEVICE_TYPE_ACR120S: 
			mifare_ops = &acr120s_ops; 
			break;
		case DEVICE_TYPE_MF1RW:
			mifare_ops = &mf1rw_ops;
			break;
		default:
			return;
	}

	int error = 0;
	for (;;)
	{
		handle = mifare_open(&dev);
		if (handle < 0)
		{
			if (!error)
			{
				syslog(LOG_INFO, "Waiting device at %s (%s)...",
						device->dev, device->id);
				error = 1;	
			}
			sleep(1);
			continue;
		}
		error = 0;

		syslog(LOG_INFO, "Device found at %s (%s)...",
				device->dev, device->id);

		for (;; usleep(200000))
		{
			last_count = count;
			memcpy(last_tags, tags, count * sizeof(mifare_tag_t));

			count = MAX_TAG;
			if (mifare_detect(handle, tags, &count))
				break;

			puts("1");

			for (i = 0; i < count; i++)
			{
				for (j = 0; j < last_count; j++)
					if (memcmp(&tags[i], &last_tags[j], sizeof(mifare_tag_t)) == 0)
						break;

				/* New tag detected */
				if (j >= last_count)
					fetch(handle, device, &tags[i]);
			}
		}
	}
}

int main()
{
	read_config();
	struct device *dev;
	for (dev = config.devices; dev; dev = dev->next)
		start_device(dev);
	return 0;
}

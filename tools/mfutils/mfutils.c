#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <expat.h>
#include "mifare.h"
#include "acr120s.h"
#include "mf1rw.h"
#include "utils.h"
#include "id.h"

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

struct device
{
	char *dev;
	int baud;
	int type;
};

struct config
{
	struct device dev;
	struct key *keys;
	unsigned char id[4];
	int has_id;
	int wait;
	mifare_tag_t tag;

	id_desc_t id_desc;
	int has_id_sector;
	int has_id_aes_key;
	int has_id_magic;
} config;

struct config_ctx
{
	char *parent;
	struct key *last_key;
	int depth;
} config_ctx;

int g_handle;

struct dict
{
	char *key;
	int value;
};

enum
{
	DEVICE_TYPE_NONE,
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

static struct dict key_type_dict[] =
{
	{ "a", MIFARE_KEY_TYPE_A },
	{ "b", MIFARE_KEY_TYPE_B }
};

int my_parse_hex(const char *hex, void *buf, int size)
{
	int r = parse_hex(hex, buf, size);
	if (r != size)
		ERROR("Invalid %d byte(s) hex string `%s'", size, hex);
	return r;
}

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

void usage() __attribute__ ((noreturn));
void usage()
{
	printf("mfutils - Mifare Classic card and reader utilities\n"
			"Usage: mfutils <switches> <command> <argument>\n"
			"\n"
			"Switches:\n"
			"  -d <dev>   Serial device file\n"
			"  -b <baud>  Serial baud rate\n"
			"  -t <type>  Device type (Supported: acr120s, mf1rw)\n"
			"  -w <sec>   Retry for specified time if card is not detected\n"
			"  -ka <key>  Key type A\n"
			"  -kb <key>  Key type B\n"
			"  -ea <num>  Key type A from EEPROM\n"
			"  -eb <num>  Key type B from EEPROM\n"
			"  -id <id>   Do operation only if card ID is match\n"
			"\n"
			"Commands:\n"
			"  ru                  Read Card UID\n"
			"  rb <block>          Read block\n"
			"  rv <block>          Read value\n"
			"  wb <block> <value>  Write block\n"
			"  wv <block> <value>  Write value\n"
			"  wk <num> <key>      Write key to EEPROM\n"
			"  bp                  Buzzer sound\n"
			"  ra <sector>         Read access bit of a sector\n"
			"  wa <sector> <bits> <keya> <keyb>  Write access bit of a sector\n"
			"\n"
			"Application specific commands:\n"
			"  id_init <id>         Initialize sector to be used in ID application\n"
			"  id_read              Read id\n"
			"  id_batch_init <file> Batch initialize ID application\n"
			"\n"
			"  purse_init         Initialize sector to be used in Purse applicaton\n"
			"  purse_read         Read purse value\n"
			"  purse_inc <value>  Increment purse\n"
			"  purse_dec <value>  Decrement purse\n"
			);
	exit(1);
}

void do_ru(char **args);
void do_rb(char **args);
void do_rv(char **args);
void do_wb(char **args);
void do_wv(char **args);
void do_wk(char **args);
void do_iv(char **args);
void do_dv(char **args);
void do_bp(char **args);
void do_ra(char **args);
void do_wa(char **args);
void do_id_init(char **args);
void do_id_read(char **args);
void do_id_batch_init(char **args);

struct handler
{
	char *cmd;
	void (*handler)(char **args);
	int params;
};

struct handler cmds[] =
{
	{ "ru", do_ru, 0 },
	{ "rb", do_rb, 1 },
	{ "rv", do_rv, 1 },
	{ "wb", do_wb, 2 },
	{ "wv", do_wv, 2 },
	{ "wk", do_wk, 2 },
	{ "iv", do_iv, 2 },
	{ "dv", do_dv, 2 },
	{ "bp", do_bp, 0 },
	{ "ra", do_ra, 1 },
	{ "wa", do_wa, 4 },

	{ "id_init", do_id_init, 1 },
	{ "id_read", do_id_read, 0 },
	{ "id_batch_init", do_id_batch_init, 1 },

	{ 0, 0, 0 }
};

void do_open()
{
	static int opened = 0;
	if (!opened)
	{
		if (config.dev.dev == 0)
			ERROR("Device not specified");
		if (config.dev.baud == 0)
			ERROR("Baud rate not specified");
		if (config.dev.type == DEVICE_TYPE_NONE)
			ERROR("Device type not specified");

		mifare_dev_t dev;
		dev.device = config.dev.dev;
		dev.baud = config.dev.baud;
		dev.sid = 0;
		dev.ops = 0;
		if (config.dev.type == DEVICE_TYPE_ACR120S)
			dev.ops = &acr120s_ops;
		else if (config.dev.type == DEVICE_TYPE_MF1RW)
			dev.ops = &mf1rw_ops;

				g_handle = mifare_open(&dev);
		if (g_handle < 0)
			ERROR("Device not found at `%s'", config.dev.dev);

		opened = 1;
	}
}

struct key *get_key(int sector)
{
	struct key *k;
	for (k = config.keys; k; k = k->next)
		if (k->sector == sector)
			return k;
	return config.keys;
}

void do_detect()
{
	time_t wait_until = time(0) + config.wait;
	int count = 1;
	int res = mifare_detect(g_handle, &config.tag, &count);
	while ((res || count == 0) && time(0) < wait_until)
	{
		count = 1;
		res = mifare_detect(g_handle, &config.tag, &count);
	}
	if (res || count == 0)
		ERROR("Card not detected");

	if (config.has_id)
		memcpy(config.tag.serial, config.id, 4);
	else
		/* Make sure sequent selected card is the same */
		memcpy(config.id, config.tag.serial, 4);
}

void do_select()
{
	if (mifare_select(g_handle, &config.tag))
		ERROR("Cannot select card");
}

void do_login(int sector)
{
	static int last_sector = -1;
	if (last_sector != sector)
	{
		do_detect();
		do_select();
		struct key *k = get_key(sector);
		if (!(k->has_eeprom ^ k->has_bytes))
			ERROR("Bytes key or EEPROM key must be specified exclusively");
		int res;
		if (k->has_bytes)
			res = mifare_login(g_handle, sector, k->type, k->bytes);
		else
			res = mifare_login_stored(g_handle, sector, k->type, k->eeprom);
		if (res)
			ERROR("Cannot login to sector");

		last_sector = sector;
	}
}

void do_ru(char **args)
{
	uint8_t *b = config.tag.serial;
	do_open();
	do_detect();
	printf("%02x%02x%02x%02x\n", b[0], b[1], b[2], b[3]);
}

void do_rb(char **args)
{
	int block = atoi(args[0]);
	uint8_t buf[MIFARE_BLOCK_SIZE];
	do_open();
	do_login(block / 4);
	if (mifare_read_block(g_handle, block, buf))
		ERROR("Cannot read block");

	int i;
	for (i = 0; i < MIFARE_BLOCK_SIZE; i++)
		printf("%02x", buf[i]);
	puts("");
}

void do_rv(char **args)
{
	int block = atoi(args[0]);
	int32_t value;
	do_open();
	do_login(block / 4);
	if (mifare_read_value(g_handle, block, &value))
		ERROR("Cannot read value");
	printf("%d\n", value);
}

void do_wb(char **args)
{
	int block = atoi(args[0]);
	uint8_t buf[MIFARE_BLOCK_SIZE];
	my_parse_hex(args[1], buf, MIFARE_BLOCK_SIZE);
	do_open();
	do_login(block / 4);
	if (mifare_write_block(g_handle, block, buf))
		ERROR("Cannot write block");
}

void do_wv(char **args)
{
	int block = atoi(args[0]);
	int value = atoi(args[1]);
	do_open();
	do_login(block / 4);
	if (mifare_write_value(g_handle, block, value))
		ERROR("Cannot write value");
}

void do_wk(char **args)
{
	int reg = atoi(args[0]);
	uint8_t key[6];
	my_parse_hex(args[1], key, 6);
	do_open();
	if (mifare_write_key(g_handle, reg, key))
		ERROR("Cannot write key");
	printf("%02x%02x%02x%02x%02x%02x\n",
			key[0], key[1], key[2],
			key[3], key[4], key[5]);
	fprintf(stderr, "Key written to index %d", reg);
}

void do_iv(char **args)
{
	int block = atoi(args[0]);
	int value = atoi(args[1]);
	do_open();
	do_login(block / 4);
	if (mifare_inc_value(g_handle, block, value))
		ERROR("Cannot increment value");
}

void do_dv(char **args)
{
	int block = atoi(args[0]);
	int value = atoi(args[1]);
	do_open();
	do_login(block / 4);
	if (mifare_dec_value(g_handle, block, value))
		ERROR("Cannot decrement value");
}

void do_bp(char **args)
{
	do_open();
	mifare_beep(g_handle, 50);
}

void do_ra(char **args)
{
	int sector = atoi(args[0]);
	int block = sector * 4;
	uint8_t buf[MIFARE_BLOCK_SIZE];
	do_open();
	do_login(sector);
	if (mifare_read_block(g_handle, block + 3, buf))
		ERROR("Cannot read block");

	uint8_t c1, c2, c3, nc1, nc2, nc3;
	uint8_t c11, c12, c13, c14;
	uint8_t c21, c22, c23, c24;
	uint8_t c31, c32, c33, c34;
	c1 = buf[7] >> 4;
	c2 = buf[8] & 15;
	c3 = buf[8] >> 4;
	nc1 = ~buf[6] & 15;
	nc2 = (~buf[6] >> 4) & 15;
	nc3 = ~buf[7] & 15;
	if (c1 != nc1 || c2 != nc2 || c3 != nc3)
		ERROR("Invalid access bits");

	c11 = (c1 >> 0) & 1;
	c12 = (c1 >> 1) & 1;
	c13 = (c1 >> 2) & 1;
	c14 = (c1 >> 3) & 1;

	c21 = (c2 >> 0) & 1;
	c22 = (c2 >> 1) & 1;
	c23 = (c2 >> 2) & 1;
	c24 = (c2 >> 3) & 1;

	c31 = (c3 >> 0) & 1;
	c32 = (c3 >> 1) & 1;
	c33 = (c3 >> 2) & 1;
	c34 = (c3 >> 3) & 1;

	printf("Sector %d: %d%d%d %d%d%d %d%d%d %d%d%d (%d%d%d%d)\n",
			sector,
			c11, c21, c31,
			c12, c22, c32,
			c13, c23, c33,
			c14, c24, c34,
			c11 << 2 | c21 << 1 | c31,
			c12 << 2 | c22 << 1 | c32,
			c13 << 2 | c23 << 1 | c33,
			c14 << 2 | c24 << 1 | c34);
}

void do_wa(char **args)
{
	uint8_t buf[16];
	int sector = atoi(args[0]);
	int block = sector * 4 + 3;
	uint8_t a[4];
	uint8_t c1, c2, c3;
	if (strlen(args[1]) != 4)
		ERROR("Invalid access bits `%s'", args[1]);
	int i;
	for (i = 0; i < 4; i++)
	{
		if (args[1][i] < '0' || args[1][i] > '7')
			ERROR("Invalid access bits `%s'", args[1]);
		a[i] = args[1][i] - '0';
	}
	do_open();
	do_login(sector);
	if (mifare_read_block(g_handle, block, buf))
		ERROR("Cannot read block");

	c1 = 
		((a[0] >> 2) & 1) << 0 | 
		((a[1] >> 2) & 1) << 1 |
	 	((a[2] >> 2) & 1) << 2 |
		((a[3] >> 2) & 1) << 3;
	c2 = 
		((a[0] >> 1) & 1) << 0 | 
		((a[1] >> 1) & 1) << 1 |
	 	((a[2] >> 1) & 1) << 2 |
		((a[3] >> 1) & 1) << 3;
	c3 = 
		((a[0] >> 0) & 1) << 0 | 
		((a[1] >> 0) & 1) << 1 |
	 	((a[2] >> 0) & 1) << 2 |
		((a[3] >> 0) & 1) << 3;

	buf[6] = (~c2 & 15) << 4 | (~c1 & 15);
	buf[7] = (c1 & 15) << 4 | (~c3 & 15);
	buf[8] = (c3 & 15) << 4 | (c2 & 15);

	my_parse_hex(args[2], &buf[0], 6);
	my_parse_hex(args[3], &buf[10], 6);

	for (i = 0; i < 16; i++)
		printf("%02x", buf[i]);
	printf("\n");

	if (mifare_write_block(g_handle, block, buf))
		ERROR("Cannot read block");
}

void do_id_init(char **args)
{
	char id[12];
	if (!config.has_id_sector)
		ERROR("ID sector not specified");
	if (!config.has_id_magic)
		ERROR("ID magic not specified");
	if (!config.has_id_aes_key)
		ERROR("ID AES key not specified");
	struct key *k = get_key(config.id_desc.sector);
	if (k == 0)
		ERROR("Key for sector %d not found", config.id_desc.sector);
	memcpy(config.id_desc.key, k->bytes, 6);
	config.id_desc.key_type = k->type;
	do_open();
	do_detect();
	strncpy(id, args[0], 12);
	int ret = id_init(g_handle, &config.id_desc, &config.tag, id, 0);
	if (ret)
		ERROR("id_init() error: %d", ret);
}

void do_id_read(char **args)
{
	if (!config.has_id_sector)
		ERROR("ID sector not specified");
	if (!config.has_id_magic)
		ERROR("ID magic not specified");
	if (!config.has_id_aes_key)
		ERROR("ID AES key not specified");
	struct key *k = get_key(config.id_desc.sector);
	if (k == 0)
		ERROR("Key for sector %d not found", config.id_desc.sector);
	memcpy(config.id_desc.key, k->bytes, 6);
	config.id_desc.key_type = k->type;
	do_open();
	do_detect();
	char id[13];
	id[12] = 0;
	int32_t counter = 0;
	int ret = id_read(g_handle, &config.id_desc, &config.tag, id, &counter);
	uint8_t *p = config.tag.serial;
  if (ret == 0)
		printf("%02x%02x%02x%02x %d %s\n", p[0], p[1], p[2], p[3], -counter, id);
	else
		ERROR("id_read() error: %d", ret);
}

void do_id_batch_init(char **args)
{
	if (!config.has_id_sector)
		ERROR("ID sector not specified");
	if (!config.has_id_magic)
		ERROR("ID magic not specified");
	if (!config.has_id_aes_key)
		ERROR("ID AES key not specified");
	struct key *k = get_key(config.id_desc.sector);
	if (k == 0)
		ERROR("Key for sector %d not found", config.id_desc.sector);

	FILE *fp = fopen(args[0], "r");
	if (!fp)
		ERROR("File not found: %s", args[0]);

	char id[13];
	uint8_t last_uid[4];
	memset(id, 0, sizeof(id));
	memset(last_uid, 0, 4);
	while (fgets(id, 12, fp) != NULL)
	{
		int len = strlen(id);
		if (id[len - 1] == '\n')
			id[len -1] = 0;
		memcpy(config.id_desc.key, k->bytes, 6);
		config.id_desc.key_type = k->type;
		do_open();
		for (;;)
		{
			do_detect();
			if (memcmp(last_uid, config.tag.serial, 4) == 0)
				usleep(200000);
			else
				break;
		}
		int ret = id_init(g_handle, &config.id_desc, &config.tag, id, 0);
		if (ret)
			ERROR("id_init() error: %d", ret);

		uint8_t *p = config.tag.serial;
		printf("%02x%02x%02x%02x %s\n", p[0], p[1], p[2], p[3], id);
		mifare_beep(g_handle, 50);

		memset(id, 0, sizeof(id));
		memcpy(last_uid, config.tag.serial, 4);
	}
	fclose(fp);
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
				goto invalid_tag;
			break;

		case 2:
			if (!strcmp(name, "device"))
			{
				int i;
				for (i = 0; atts[i]; i += 2)
				{
					if (!strcmp(atts[i], "dev"))
					{
						config.dev.dev = strdup(atts[i + 1]);
					}
					else if (!strcmp(atts[i], "baud"))
					{
						if (!lookup(atts[i + 1], device_baud_dict, &config.dev.baud))
							goto invalid_value;
					}
					else if (!strcmp(atts[i], "type"))
					{
						if (!lookup(atts[i + 1], device_type_dict, &config.dev.type))
							goto invalid_value;
					}
					else
						goto invalid_attr;
				}
			}
			else if (!strcmp(name, "key"))
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
							goto invalid_value;
						key->has_type = 1;
					}
					else if (!strcmp(atts[i], "bytes"))
					{
						my_parse_hex(atts[i + 1], key->bytes, 6);
						key->has_bytes = 1;
					}
					else if (!strcmp(atts[i], "eeprom"))
					{
						key->eeprom = atoi(atts[i  +1]);
						key->has_eeprom = 1;
					}
					else
						goto invalid_attr;
				}
				if (!(key->has_bytes ^ key->has_eeprom))
					ERROR("Key bytes and key eeprom cannot co-exists");
				if (!key->has_sector || !key->has_type)
					ERROR("Required attribute for 'key' tag is missing");
				if (ctx->last_key == 0)
					config.keys = key;
				else
					ctx->last_key->next = key;
				ctx->last_key= key;
			}
			else if (!strcmp(name, "id"))
			{
				int i;
				for (i = 0; atts[i]; i += 2)
				{
					if (!strcmp(atts[i], "sector"))
					{
						config.id_desc.sector = atoi(atts[i + 1]);
						config.has_id_sector = 1;
					}
					else if (!strcmp(atts[i], "magic"))
					{
						my_parse_hex(atts[i + 1], config.id_desc.magic, 4);
						config.has_id_magic = 1;
					}
					else if (!strcmp(atts[i], "aes"))
					{
						my_parse_hex(atts[i + 1], config.id_desc.aes_key, 32);
						config.has_id_aes_key = 1;
					}
					else
						goto invalid_attr;
				}
			}
			else if (!strcmp(name, "purse"))
			{
				if (!strcmp(atts[i], "sector"))
				{
				}
				else
					goto invalid_attr;
			}
			else
				goto invalid_tag;
			break;

		default:
			goto invalid_tag;
	}
	return;

invalid_tag:
	free(ctx->parent);
	ERROR("Invalid tag `%s'", name);

invalid_attr:
	free(ctx->parent);
	ERROR("Invalid attribute `%s'", atts[i]);

invalid_value:
	free(ctx->parent);
	ERROR("Invalid attribute's value `%s'", atts[i + 1]);
}

void end_handler(void *data, const char *name)
{
	struct config_ctx *ctx = (struct config_ctx *) data;
	ctx->depth--;
}

#define BUFFER_SIZE 4096

void read_config(const char *cfg)
{
	FILE *fp = fopen(cfg, "r");
	if (fp == 0)
		ERROR("Config file not found: %s", cfg);
	XML_Parser parser = XML_ParserCreate(0);
	XML_SetUserData(parser, &config_ctx);
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
			ERROR("Error reading file");
		}
		if (!XML_ParseBuffer(parser, bytes_read, bytes_read == 0))
		{
			fclose(fp);
			XML_ParserFree(parser);
			ERROR("Error parsing file");
		}
		if (bytes_read == 0)
			break;
	}
	fclose(fp);
	XML_ParserFree(parser);
}

void parse_arg(int argc, char **argv)
{
	char **args = malloc(argc * sizeof(*args));
	int i, j, len = argc - 1;
	for (i = 0; i < len; i++)
		args[i] = argv[i + 1];
	args[len] = 0;
	memset(&config_ctx, 0, sizeof(config_ctx));

	/* Parse switches.
	 * Make sure switch parameter args[i +1] always available */
	for (i = 0; i < len - 1; i++)
	{
		struct key *key = 0;
		if (!strcmp(args[i], "-d"))
			config.dev.dev = args[i + 1];
		else if (!strcmp(args[i], "-b"))
		{
			if (!lookup(args[i + 1], device_baud_dict, &config.dev.baud))
				ERROR("Invalid baud rate `%s'", args[i + 1]);
		}
		else if (!strcmp(args[i], "-t"))
		{
			if (!lookup(args[i + 1], device_type_dict, &config.dev.type))
				ERROR("Invalid device type `%s'", args[i + 1]);
		}
		else if (!strcmp(args[i], "-w"))
			config.wait = atoi(args[i + 1]);
		else if (!strcmp(args[i], "-c"))
			read_config(args[i + 1]);
		else if (!strcmp(args[i], "-ka"))
		{
			key = calloc(1, sizeof(*key));
			key->type = MIFARE_KEY_TYPE_A;
			key->has_bytes = 1;
			my_parse_hex(args[i + 1], key->bytes, 6);
		}
		else if (!strcmp(args[i], "-kb"))
		{
			key = calloc(1, sizeof(*key));
			key->type = MIFARE_KEY_TYPE_B;
			key->has_bytes = 1;
			my_parse_hex(args[i + 1], key->bytes, 6);
		}
		else if (!strcmp(args[i], "-ea"))
		{
			key = calloc(1, sizeof(*key));
			key->type = MIFARE_KEY_TYPE_A;
			key->has_eeprom = 1;
			key->eeprom = atoi(args[i + 1]);
		}
		else if (!strcmp(args[i], "-eb"))
		{
			key = calloc(1, sizeof(*key));
			key->type = MIFARE_KEY_TYPE_B;
			key->has_eeprom = 1;
			key->eeprom = atoi(args[i + 1]);
		}
		else if (!strcmp(args[i], "-id"))
		{
			config.has_id = 1;
			my_parse_hex(args[i + 1], config.id, 4);
		}
		else if (args[i][0] == '-')
			usage();
		else
			continue;
		args[i++] = 0;
		args[i] = 0;
		if (key != 0)
		{
			if (config_ctx.last_key == 0)
				config.keys = key;
			else
				config_ctx.last_key->next = key;
			config_ctx.last_key = key;
		}
	}

	j = 0;
	for (i = 0; i < len; i++)
		if (args[i] != 0)
			args[j++] = args[i];
	len = j;
	args[len] = 0;

	if (len == 0 || args[len - 1][0] == '-')
		usage();

	for (i = 0; i < len;)
	{
		struct handler *h;
		for (h = cmds; h->cmd; h++)
			if (!strcmp(args[i], h->cmd))
				break;
		if (h->cmd == 0)
			ERROR("Invalid command `%s'", args[i]);
		if (h->params > len - i - 1)
			ERROR("Command '%s' needs %d parameter(s)", args[i], h->params);

		h->handler(args + i + 1);
		i += h->params + 1;
	}

	free(args);
	mifare_close(g_handle);
}

int main(int argc, char **argv)
{
	parse_arg(argc, argv);
	return 0;
}

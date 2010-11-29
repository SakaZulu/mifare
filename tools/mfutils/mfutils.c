#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include "mifare.h"
#include "acr120s.h"
#include "mf1rw.h"

struct config
{
	char *dev;
	int baud;
	int dev_type;
	unsigned char id[4];
	int key_type;
	unsigned char bytes[6];
	int eeprom;
	int wait;
	mifare_tag_t tag;

	int has_id;
	int has_bytes;
	int has_eeprom;
} config;

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
	uint8_t *k = &((uint8_t *) key)[size - 1];
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
			);
	exit(1);
}

void error(char *fmt, ...) __attribute__ ((noreturn));
void error(char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	exit(1);
}

void do_ru(char **argv);
void do_rb(char **argv);
void do_rv(char **argv);
void do_wb(char **argv);
void do_wv(char **argv);
void do_wk(char **argv);
void do_iv(char **argv);
void do_dv(char **argv);
void do_bp(char **argv);

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
	{ 0, 0, 0 }
};

void do_open()
{
	static int opened = 0;
	if (!opened)
	{
		if (config.dev == 0)
			error("Device not specified\n");
		if (config.baud == 0)
			error("Baud rate not specified\n");
		if (config.dev_type == DEVICE_TYPE_NONE)
			error("Device type not specified\n");

		if (config.dev_type == DEVICE_TYPE_ACR120S)
			mifare_ops = &acr120s_ops;
		else if (config.dev_type == DEVICE_TYPE_MF1RW)
			mifare_ops = &mf1rw_ops;

		mifare_dev_t dev;
		dev.device = config.dev;
		dev.baud = config.baud;
		dev.sid = 0;

		g_handle = mifare_open(&dev);
		if (g_handle < 0)
			error("Device not found at '%s'\n", config.dev);

		opened = 1;
	}
}

void do_select()
{
	static int selected = 0;
	int count = 1;
	int res;
	if (!selected)
	{
		time_t wait_until = time(0) + config.wait;
		res = mifare_detect(g_handle, &config.tag, &count);
		while ((res || count == 0) && time(0) < wait_until)
		{
			count = 1;
			res = mifare_detect(g_handle, &config.tag, &count);
		}
		if (res || count == 0)
			error("Card not detected\n");

		if (config.has_id)
			memcpy(config.tag.serial, config.id, 4);

		if (mifare_select(g_handle, &config.tag))
			error("Cannot select card\n");

		selected = 1;
	}
}

void do_login(int sector)
{
	static int logged_in = 0;
	if (!logged_in)
	{
		if (!(config.has_eeprom ^ config.has_bytes))
			error("Bytes key or EEPROM key must be specified exclusively\n");
		int res;
		if (config.has_bytes)
			res = mifare_login(g_handle, sector, config.key_type, config.bytes);
		else
			res = mifare_login_stored(g_handle, sector, config.key_type, config.eeprom);
		if (res)
			error("Cannot login to sector\n");

		logged_in = 1;
	}
}

void do_ru(char **args)
{
	uint8_t *b = config.tag.serial;
	do_open();
	do_select();
	printf("%02x%02x%02x%02x\n", b[0], b[1], b[2], b[3]);
}

void do_rb(char **args)
{
	int block = atoi(args[0]);
	uint8_t buf[MIFARE_BLOCK_SIZE];
	do_open();
	do_select();
	do_login(block / 4);
	if (mifare_read_block(g_handle, block, buf))
		error("Cannot read block\n");

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
	do_select();
	do_login(block / 4);
	if (mifare_read_value(g_handle, block, &value))
		error("Cannot read value\n");
	printf("%d\n", value);
}

void do_wb(char **args)
{
	int block = atoi(args[0]);
	uint8_t buf[MIFARE_BLOCK_SIZE];
	parse_hex(args[1], buf, MIFARE_BLOCK_SIZE);
	do_open();
	do_select();
	do_login(block / 4);
	if (mifare_write_block(g_handle, block, buf))
		error("Cannot write block\n");
}

void do_wv(char **args)
{
	int block = atoi(args[0]);
	int value = atoi(args[1]);
	do_open();
	do_select();
	do_login(block / 4);
	if (mifare_write_value(g_handle, block, value))
		error("Cannot write value\n");
}

void do_wk(char **args)
{
	int reg = atoi(args[0]);
	uint8_t key[6];
	parse_hex(args[1], key, 6);
	do_open();
	if (mifare_write_key(g_handle, reg, key))
		error("Cannot write key\n");
	printf("%02x%02x%02x%02x%02x%02x\n",
			key[0], key[1], key[2],
			key[3], key[4], key[5]);
	fprintf(stderr, "Key written to index %d\n", reg);
}

void do_iv(char **args)
{
	int block = atoi(args[0]);
	int value = atoi(args[1]);
	do_open();
	do_select();
	do_login(block / 4);
	if (mifare_inc_value(g_handle, block, value))
		error("Cannot increment value");
}

void do_dv(char **args)
{
	int block = atoi(args[0]);
	int value = atoi(args[1]);
	do_open();
	do_select();
	do_login(block / 4);
	if (mifare_dec_value(g_handle, block, value))
		error("Cannot decrement value");
}

void do_bp(char **args)
{
	do_open();
	mifare_beep(g_handle, 50);
}

void parse_arg(int argc, char **argv)
{
	char **args = malloc(argc * sizeof(*args));
	int i, j, len = argc - 1;
	for (i = 0; i < len; i++)
		args[i] = argv[i + 1];
	args[len] = 0;

	/* Parse switches.
	 * Make sure switch parameter args[i +1] always available */
	for (i = 0; i < len - 1; i++)
	{
		if (!strcmp(args[i], "-d"))
			config.dev = args[i + 1];
		else if (!strcmp(args[i], "-b"))
		{
			if (!lookup(args[i + 1], device_baud_dict, &config.baud))
				error("Invalid baud rate '%s'\n", args[i + 1]);
		}
		else if (!strcmp(args[i], "-t"))
		{
			if (!lookup(args[i + 1], device_type_dict, &config.dev_type))
				error("Invalid device type '%s'\n", args[i + 1]);
		}
		else if (!strcmp(args[i], "-w"))
		{
			config.wait = atoi(args[i + 1]);
		}
		else if (!strcmp(args[i], "-ka"))
		{
			config.key_type = MIFARE_KEY_TYPE_A;
			config.has_bytes = 1;
			parse_hex(args[i + 1], config.bytes, 6);
		}
		else if (!strcmp(args[i], "-kb"))
		{
			config.key_type = MIFARE_KEY_TYPE_B;
			config.has_bytes = 1;
			parse_hex(args[i + 1], config.bytes, 6);
		}
		else if (!strcmp(args[i], "-ea"))
		{
			config.key_type = MIFARE_KEY_TYPE_A;
			config.has_eeprom = 1;
			config.eeprom = atoi(args[i + 1]);
		}
		else if (!strcmp(args[i], "-eb"))
		{
			config.key_type = MIFARE_KEY_TYPE_B;
			config.has_eeprom = 1;
			config.eeprom = atoi(args[i + 1]);
		}
		else if (!strcmp(args[i], "-id"))
		{
			config.has_id = 1;
			parse_hex(args[i + 1], config.id, 4);
		}
		else if (args[i][0] == '-')
			usage();
		else
			continue;
		args[i++] = 0;
		args[i] = 0;
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
			error("Invalid command '%s'\n", args[i]);
		if (h->params > len - i - 1)
			error("Command '%s' needs %d parameter(s)", args[i], h->params);

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

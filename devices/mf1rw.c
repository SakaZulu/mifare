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

/*
 * Device information:
 * http://rhombus.com.cn
 * Search for RHMMF1RW
 *
 * Protocol description:
 * http://rhombus.com.cn/en/drivers/rw_protocol_eng.pdf
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "mf1rw.h"
#include "utils.h"

static const uint8_t STX = 0x02;
static const uint8_t ETX = 0x03;
static const uint8_t ACK = 0x06;

#define MAX_CMD_SIZE 26

#define DEBUG 1

#if DEBUG
	#define DPRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
	#define DPRINTF
#endif

#define MAX_HANDLE 8

#define SEQ(p)    (((uint8_t *)(p))[0])
#define CMD(p)    (((uint8_t *)(p))[1])
#define RES(p)    CMD(p)
#define LEN(p)    (((uint8_t *)(p))[2])
#define DATA(p,i) (((uint8_t *)(p))[3 + (i)])
#define BCC(p)    DATA(p, LEN(p))

enum
{
	CMD_Request     = 0x41,
	CMD_Anticoll    = 0x42,
	CMD_Anticoll2   = 0x71,
	CMD_Select      = 0x43,
	CMD_Auth        = 0x44,
	CMD_Auth2       = 0x72,
	CMD_AuthKey     = 0x73,
	CMD_Halt        = 0x45,
	CMD_Read        = 0x46,
	CMD_Write       = 0x47,
	CMD_Increment   = 0x48,
	CMD_Decrement   = 0x49,
	CMD_Restore     = 0x4A,
	CMD_Transfer    = 0x4B,
	CMD_Value       = 0x70,
	CMD_LoadKey     = 0x4C,
	CMD_Reset       = 0x4E,
	CMD_Set_LED_Bit = 0x50,
	CMD_Clr_LED_Bit = 0x51,
	CMD_Config      = 0x52,
	CMD_Check_Write = 0x53,
	CMD_Buzzer      = 0x60,
	CMD_Close       = 0x3F,
	CMD_Read_E2     = 0x61,
	CMD_Write_E2    = 0x62,
};

struct mf1rw_context
{
	int fd;
	struct termios oldtio;
};

static struct mf1rw_context context[MAX_HANDLE];

static inline struct mf1rw_context *get_context(int handle)
{
	if ((unsigned) handle >= MAX_HANDLE || !context[handle].fd)
		return 0;
	
	return &context[handle];
}

static uint8_t calc_bcc(void *block)
{
	uint8_t bcc;
	int i;
	bcc = SEQ(block) ^ CMD(block) ^ LEN(block);
	for (i = 0; i < LEN(block); i++)
		bcc ^= DATA(block, i);
	return bcc;
}

static inline void cmd_init(uint8_t *f, uint8_t cmd)
{
	SEQ(f) = 0;
	CMD(f) = cmd;
	LEN(f) = 0;
}

static inline void cmd_byte(uint8_t *f, uint8_t byte)
{
	DATA(f, LEN(f)) = byte;
	LEN(f)++;
}

static inline void cmd_bytes(uint8_t *f, const void *buf, int len)
{
	uint8_t *p = &DATA(f, LEN(f));
	memcpy(p, buf, len);
	LEN(f) += len;
}

static inline void cmd_done(uint8_t *f)
{
	BCC(f) = calc_bcc(f);
}

static inline int32_t get_value(void *p)
{
	uint8_t *v = p;
	return v[0] | v[1] << 8 | v[2] << 16 | v[3] << 24;
}

static int write_cmd(struct mf1rw_context *ctx, void *cmd)
{
	uint8_t cc;

	if (write(ctx->fd, &STX, 1) != 1)
		return -1;

	if (read(ctx->fd, &cc, 1) != 1 || cc != ACK)
		return -1;

	if (full_write(ctx->fd, cmd, LEN(cmd) + 4) < 0)
		return -1;

	if (write(ctx->fd, &ETX, 1) != 1)
		return -1;

	return 0;
}

static int read_result(struct mf1rw_context *ctx, void *res)
{
	uint8_t cc;

	if (read(ctx->fd, &cc, 1) != 1 || cc != STX)
		return -1;

	if (write(ctx->fd, &ACK, 1) != 1)
		return -1;

	if (full_read(ctx->fd, res, 3) < 0)
		return -1;

	cc = LEN(res) + 1;
	if (full_read(ctx->fd, &DATA(res, 0), cc) < 0)
		return -1;

	if (read(ctx->fd, &cc, 1) != 1 || cc != ETX)
		return -1;

	if (calc_bcc(res) != BCC(res))
		return -1;

	return 0;
}

static int exec_cmd(struct mf1rw_context *ctx, void *cmd, void *res)
{
	if (write_cmd(ctx, cmd) < 0)
		return -1;

	return read_result(ctx, res);
}

int mf1rw_open(const char *dev)
{
	struct termios oldtio, newtio;
	struct mf1rw_context *ctx;
	int handle, fd;

	/* Search available new handle */
	for (handle = 0; handle < MAX_HANDLE; handle++)
	{
		ctx = &context[handle];
		if (ctx->fd == 0)
			break;
	}
	if (handle >= MAX_HANDLE)
		return -1;

	/* Open device */
	fd = open(dev, O_RDWR | O_NOCTTY);
	if (fd < 0)
		return -1;

	/* Save current port setting */
	tcgetattr(fd, &oldtio);

	memset(&newtio, 0, sizeof(newtio));
	newtio.c_cflag = B9600 | CS8 | CLOCAL | CREAD;
	newtio.c_iflag = IGNPAR;
	newtio.c_oflag = 0;
	newtio.c_lflag = 0;

	/* Read return when a single byte of data received */
	newtio.c_cc[VTIME] = 10; /* Timeout in 0.3 second */
	newtio.c_cc[VMIN] = 0;

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &newtio);

	ctx->fd = fd;
	memcpy(&ctx->oldtio, &oldtio, sizeof(oldtio));

	/* Is device available */
	if (mf1rw_reset(handle, 0) < 0)
	{
		mf1rw_close(handle);
		return -1;
	}

	return handle;
}

int mf1rw_close(int handle)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	/* Restore original termios */
	tcsetattr(ctx->fd, TCSANOW, &ctx->oldtio);

	close(ctx->fd);
	ctx->fd = 0;

	return 0;
}

int mf1rw_request(int handle, uint8_t all, uint16_t *tag_type)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Request);
	cmd_byte(f, all & 1);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	if (RES(f) == 0)
		*tag_type = DATA(f, 0) | DATA(f, 1) << 8;

	return -RES(f);
}

int mf1rw_anticoll(int handle, void *serial)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Anticoll);
	cmd_byte(f, 0);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	if (RES(f) == 0)
		memcpy(serial, &DATA(f, 0), 4);

	return -RES(f);
}

int mf1rw_anticoll2(int handle, uint8_t anti_coll, void *serial)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Anticoll2);
	cmd_byte(f, anti_coll & 1);
	cmd_byte(f, 0);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	if (RES(f) == 0)
		memcpy(serial, &DATA(f, 0), 4);

	return -RES(f);
}

int mf1rw_select(int handle, const void *serial, uint8_t *capacity)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Select);
	cmd_bytes(f, serial, 4);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	if (RES(f) == 0)
		*capacity = DATA(f, 0);

	return -RES(f);
}

int mf1rw_auth(int handle, uint8_t mode, uint8_t sector)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Auth);
	cmd_byte(f, mode & 1);
	cmd_byte(f, sector & 15);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_auth2(int handle, uint8_t mode, uint8_t sector, uint8_t key)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Auth2);
	cmd_byte(f, mode & 1);
	cmd_byte(f, sector & 15);
	cmd_byte(f, key);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_auth_key(int handle, uint8_t mode, uint8_t sector, const void *key)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_AuthKey);
	cmd_byte(f, mode & 1);
	cmd_byte(f, sector & 15);
	cmd_bytes(f, key, 6);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_halt(int handle)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Halt);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_read_block(int handle, uint8_t block, void *data)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Read);
	cmd_byte(f, block);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	if (RES(f) == 0)
		memcpy(data, &DATA(f, 0), LEN(f));

	return -RES(f);
}

int mf1rw_write_block(int handle, uint8_t block, const void *data)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Write);
	cmd_byte(f, block);
	cmd_bytes(f, data, 16);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_inc_value(int handle, uint8_t block, int32_t value)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Increment);
	cmd_byte(f, block);
	cmd_byte(f, value & 255);
	cmd_byte(f, (value >> 8) & 255);
	cmd_byte(f, (value >> 16) & 255);
	cmd_byte(f, (value >> 24) & 255);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}
int mf1rw_dec_value(int handle, uint8_t block, int32_t value)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Decrement);
	cmd_byte(f, block);
	cmd_byte(f, value & 255);
	cmd_byte(f, (value >> 8) & 255);
	cmd_byte(f, (value >> 16) & 255);
	cmd_byte(f, (value >> 24) & 255);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_restore(int handle, uint8_t block)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Restore);
	cmd_byte(f, block);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_transfer(int handle, uint8_t block)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Transfer);
	cmd_byte(f, block);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_load_key(int handle, uint8_t mode, uint8_t sector, const void *key)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_LoadKey);
	cmd_byte(f, mode & 1);
	cmd_byte(f, sector & 15);
	cmd_bytes(f, key, 6);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_reset(int handle, uint8_t msec)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Reset);
	cmd_byte(f, msec);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_standby(int handle)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Close);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_config(int handle)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Config);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_set_led(int handle, int turn_on)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, turn_on ? CMD_Set_LED_Bit : CMD_Clr_LED_Bit);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_check_write(int handle, const void *serial, uint8_t mode, 
		uint8_t block, const void *data)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Check_Write);
	cmd_bytes(f, serial, 4);
	cmd_byte(f, mode);
	cmd_byte(f, block);
	cmd_bytes(f, data, 16);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_buzzer(int handle, uint8_t active, uint8_t inactive, 
		uint8_t repeat)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Buzzer);
	cmd_byte(f, 0);
	cmd_byte(f, active);
	cmd_byte(f, inactive);
	cmd_byte(f, repeat);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_read_eeprom(int handle, uint8_t addr, uint8_t len, uint8_t *data)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Read_E2);
	cmd_byte(f, addr);
	cmd_byte(f, len);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	if (RES(f) == 0)
		memcpy(data, &DATA(f, 0), LEN(f));

	return -RES(f);
}

int mf1rw_write_eeprom(int handle, uint8_t addr, uint8_t len, uint8_t *data)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Write_E2);
	cmd_byte(f, addr);
	cmd_byte(f, len);
	cmd_bytes(f, data, len);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

int mf1rw_value(int handle, uint8_t mode, uint8_t block, int32_t value,
		uint8_t transfer_block)
{
	struct mf1rw_context *ctx = get_context(handle);
	if (ctx == 0) return -1;

	if (mode != MF1RW_VALUE_MODE_DECREMENT &&
			mode != MF1RW_VALUE_MODE_INCREMENT &&
			mode != MF1RW_VALUE_MODE_RESTORE)
		return -1;

	uint8_t f[MAX_CMD_SIZE];

	cmd_init(f, CMD_Value);
	cmd_byte(f, mode);
	cmd_byte(f, block);
	if (mode != MF1RW_VALUE_MODE_RESTORE)
	{
		cmd_byte(f, value & 255);
		cmd_byte(f, (value >> 8) & 255);
		cmd_byte(f, (value >> 16) & 255);
		cmd_byte(f, (value >> 24) & 255);
	}
	cmd_byte(f, transfer_block);
	cmd_done(f);

	if (exec_cmd(ctx, f, f) != 0)
		return -1;

	return -RES(f);
}

/***************************
 * Adapter for mifare_ops_t
 ***************************/

static int _mf1rw_open(mifare_dev_t *dev)
{
	return mf1rw_open(dev->device);
}

static int _mf1rw_close(int handle)
{
	return mf1rw_close(handle);
}

static int _mf1rw_detect(int handle, mifare_tag_t *tags, int *count)
{
	uint16_t tag_type;

	if (*count <= 0)
		return 0;

	*count = 0;
	if (mf1rw_request(handle, 0, &tag_type))
		return 0;
	
	if (mf1rw_anticoll(handle, tags[0].serial))
		return 0;

	*count = 1;
	tags[0].type = 0;
	tags[0].size = 4;
	
	return 0;
}

static int _mf1rw_select(int handle, mifare_tag_t *tag)
{
	uint8_t capacity;
	return mf1rw_select(handle, tag->serial, &capacity);
}

static int _mf1rw_login(int handle, uint8_t sector, int type, const void *key)
{
	return mf1rw_auth_key(handle, sector, type, key);
}

static int _mf1rw_login_stored(int handle, uint8_t sector, int type, int key_no)
{
	return mf1rw_auth2(handle, sector, type, key_no);
}

static int _mf1rw_read_block(int handle, uint8_t block, void *data)
{
	return mf1rw_read_block(handle, block, data);
}

static int _mf1rw_write_block(int handle, uint8_t block, void *data)
{
	return mf1rw_write_block(handle, block, data);
}

static int _mf1rw_read_value(int handle, uint8_t block, int32_t *value)
{
	return -1;
}

static int _mf1rw_write_value(int handle, uint8_t block, int32_t value)
{
	return -1;
}

static int _mf1rw_inc_value(int handle, uint8_t block, int32_t value)
{
	return mf1rw_inc_value(handle, block, value);
}

static int _mf1rw_dec_value(int handle, uint8_t block, int32_t value)
{
	return mf1rw_dec_value(handle, block, value);
}

static int _mf1rw_copy_value(int handle, uint8_t from, uint8_t to)
{
	return -1;
}

static int _mf1rw_beep(int handle, int msec)
{
	mf1rw_buzzer(handle, msec / 15, msec / 15, 1); 
	return 0;
}

mifare_ops_t mf1rw_ops =
{
	.open = _mf1rw_open,
	.close = _mf1rw_close,
	
	.detect = _mf1rw_detect,
	.select = _mf1rw_select,

	.login = _mf1rw_login,
	.login_stored = _mf1rw_login_stored,

	.read_block = _mf1rw_read_block,
	.write_block = _mf1rw_write_block,

	.read_value = _mf1rw_read_value,
	.write_value = _mf1rw_write_value,

	.inc_value = _mf1rw_inc_value,
	.dec_value = _mf1rw_dec_value,
	.copy_value = _mf1rw_copy_value,

	.beep = _mf1rw_beep,
};

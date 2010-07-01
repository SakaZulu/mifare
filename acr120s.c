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
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "acr120s.h"
#include "utils.h"

#define STX 0x02
#define ETX 0x03

#define SID(p)        (((uint8_t *)(p))[1])
#define LEN(p)        (((uint8_t *)(p))[2])
#define DATA(p,i)     (((uint8_t *)(p))[3 + i])
#define BCC(p)        (DATA(p, LEN(p)))
#define FRAME_SIZE(p) (LEN(p) + 5)

#define DEBUG 1

#if DEBUG
	#define DPRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
	#define DPRINTF
#endif

#define MAX_HANDLE 8

#define CFG_GET_EXTENDED_ID(v) (((v) >> 2) & 1)

struct acr120s_context
{
	int fd;
	uint8_t cfg;
	uint8_t sid;
	struct termios oldtio;
};

static struct acr120s_context context[MAX_HANDLE];

static inline struct acr120s_context *get_context(int handle)
{
	if ((unsigned) handle >= MAX_HANDLE || !context[handle].fd)
		return 0;
	
	return &context[handle];
}

static inline void frame_init(void *f, uint8_t sid)
{
	*((uint8_t *) f) = STX;
	SID(f) = sid;
	LEN(f) = 0;
}

static inline void frame_byte(void *f, uint8_t byte)
{
	DATA(f, LEN(f)) = byte;
	LEN(f)++;
}

static inline void frame_value(void *f, int32_t value)
{
	int32_t *p = (int32_t *) &DATA(f, LEN(f));
	*p = htonl(value);
	LEN(f) += 4;
}

static inline void frame_bytes(uint8_t *f, const void *buf, int len)
{
	memcpy(&DATA(f, LEN(f)), buf, len);
	LEN(f) += len;
}

static inline int32_t get_value(void *p)
{
	return ntohl(*((uint32_t *) p));
}

static inline uint8_t calc_bcc(void *f)
{
	uint8_t bcc;
	int i;
	bcc = SID(f) ^ LEN(f);
	for (i = 0; i < LEN(f); i++)
		bcc ^= DATA(f, i);
	return bcc;
}

static inline void frame_done(uint8_t *f)
{
	BCC(f) = calc_bcc(f);
	DATA(f, LEN(f) + 1) = ETX;
}

static int write_frame(struct acr120s_context *ctx, void *f)
{
	if (full_write(ctx->fd, f, FRAME_SIZE(f)) != FRAME_SIZE(f))
		return -1;
	return FRAME_SIZE(f);
}

static int read_frame(struct acr120s_context *ctx, void *f)
{
	/* Read Header */
	if (full_read(ctx->fd, f, 3) != 3)
		return -1;

	if (((uint8_t *) f)[0] != STX)
		return -1;

	/* Read data */
	if (full_read(ctx->fd, &DATA(f, 0), LEN(f) + 2) != LEN(f) + 2)
		return -1;

	if (BCC(f) != calc_bcc(f))
		return -1;

	if (DATA(f, LEN(f) + 1) != ETX)
		return -1;

	return FRAME_SIZE(f);
}

int acr120s_open(const char *dev, int baud, uint8_t sid)
{
	struct termios oldtio, newtio;
	struct acr120s_context *ctx;
	int handle, fd;
	int bauds[5] = { B9600, B19200, B38400, B57600, B115200 };
	int i;

	/* Auto detect baud-rate */
	if (baud == 0)
	{
		int ret;
		for (i = 0; i < 5; i++)
			if ((ret = acr120s_open(dev, bauds[i], sid)) >= 0)
				return ret;
		return ret;
	}
	else
	{
		for (i = 0; i < 5; i++)
			if (bauds[i] == baud)
				break;

		/* Invalid baud rate */
		if (i > 5)
			return -1;
	}

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
	newtio.c_cflag = baud | CS8 | CLOCAL | CREAD;
	newtio.c_iflag = IGNPAR;
	newtio.c_oflag = 0;
	newtio.c_lflag = 0;

	/* Read return when a single byte of data received */
	newtio.c_cc[VTIME] = 2; /* Timeout in 0.2 second */
	newtio.c_cc[VMIN] = 0;

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &newtio);

	ctx->fd = fd;
	memcpy(&ctx->oldtio, &oldtio, sizeof(oldtio));

	/* Set or scan Station ID */
	if (acr120s_set_station_id(handle, sid) < 0)
	{
		acr120s_close(handle);
		return -1;
	}

	/* Read Protocol Configuration Register */
	if (acr120s_read_eeprom(handle, 5, &ctx->cfg) < 0)
	{
		acr120s_close(handle);
		return -1;
	}

	return handle;
}

int acr120s_close(int handle)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	/* Restore original termios */
	tcsetattr(ctx->fd, TCSANOW, &ctx->oldtio);

	close(ctx->fd);
	ctx->fd = 0;

	return 0;
}

int acr120s_reset(int handle)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'x');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	usleep(120000);
	return 0;
}

int acr120s_select(int handle, mifare_tag_t *tag)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 's');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) == 1)
		return -DATA(f, 0);

	if (CFG_GET_EXTENDED_ID(ctx->cfg))
	{
		tag->type = DATA(f, 0);
		tag->size = LEN(f) - 1;
		memcpy(tag->serial, &DATA(f, 1), tag->size);
	}
	else
	{
		tag->type = ACR120S_TAG_TYPE_UNKNOWN;
		tag->size = LEN(f);
		memcpy(tag->serial, &DATA(f, 0), tag->size);
	}

	return 0;
}

int acr120s_list_tag(int handle, mifare_tag_t *tags, int *tag_count)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	int i;

	frame_init(f, ctx->sid);
	frame_byte(f, 'm');
	frame_byte(f, '\r');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	for (i = 0;; i++)
	{
		if (read_frame(ctx, f) < 0)
			return -1;

		if (LEN(f) == 1)
		{
			if (DATA(f, 0) != i)
				DPRINTF("Tag count %d, should be %d.\n", DATA(f, 0), i);
			break;
		}

		if (i < *tag_count)
		{
			mifare_tag_t *tag = &tags[i];
			memset(tag, 0, sizeof(*tag));
			if (CFG_GET_EXTENDED_ID(ctx->cfg))
			{
				tag->type = DATA(f, 0);
				tag->size = LEN(f) - 1;
				memcpy(tag->serial, &DATA(f, 1), tag->size);
			}
			else
			{
				tag->type = ACR120S_TAG_TYPE_UNKNOWN;
				tag->size = LEN(f);
				memcpy(tag->serial, &DATA(f, 0), tag->size);
			}
		}
	}

	if (i > *tag_count)
		i = *tag_count;

	*tag_count = i;

	return 0;
}

int acr120s_multi_select(int handle, mifare_tag_t *tag)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	if (tag->size != 4 && tag->size != 7 && tag->size != 10)
		return -1;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'm');
	frame_bytes(f, tag->serial, tag->size);
	frame_byte(f, '\r');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) == 1)
		return -DATA(f, 0);

	return 0;
}

int acr120s_login(int handle, uint8_t sector, int key_type, const void *key)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'l');
	frame_byte(f, sector);

	switch (key_type)
	{
		case ACR120S_KEY_TYPE_A:
			frame_byte(f, 0xaa);
			frame_bytes(f, key, ACR120S_KEY_SIZE);
			break;

		case ACR120S_KEY_TYPE_B:
			frame_byte(f, 0xbb);
			frame_bytes(f, key, ACR120S_KEY_SIZE);
			break;

		case ACR120S_KEY_TYPE_TRANSPORT_A:
			frame_byte(f, 0xaa);
			break;

		case ACR120S_KEY_TYPE_TRANSPORT_B:
			frame_byte(f, 0xbb);
			break;

		case ACR120S_KEY_TYPE_TRANSPORT_F:
			frame_byte(f, 0xff);
			break;

		case ACR120S_KEY_TYPE_MASTER_A:
			frame_byte(f, 0x10 + ((char *) key)[0]);
			break;

		case ACR120S_KEY_TYPE_MASTER_B:
			frame_byte(f, 0x30 + ((char *) key)[0]);
			break;

		default:
			DPRINTF("%s: unknown key_type %02x\n", 
					__FUNCTION__, key_type);
			return -1;
	}

	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (DATA(f, 0) != 'L')
		return -DATA(f, 0);

	return 0;
}

int acr120s_read_block(int handle, uint8_t block, void *data)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'r');
	frame_byte(f, block & 0x3f);
	frame_done(f);
	
	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) == 1)
		return -DATA(f, 0);

	memcpy(data, &DATA(f, 0), 16);
	return 0;
}

int acr120s_read_value(int handle, uint8_t block, int32_t *value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'r');
	frame_byte(f, 'v');
	frame_byte(f,  block & 0x3f);
	frame_done(f);
	
	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) == 1)
		return -DATA(f, 0);

	*value = get_value(&DATA(f, 0));
	return 0;
}

int acr120s_read_eeprom(int handle, uint8_t reg, uint8_t *value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'r');
	frame_byte(f, 'e');
	frame_byte(f, reg);
	frame_done(f);
	
	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	*value = DATA(f, 0);
	return 0;
}

int acr120s_read_llreg(int handle, uint8_t reg, uint8_t *value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'z');
	frame_byte(f, 'r');
	frame_byte(f, reg);
	frame_done(f);
	
	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	*value = DATA(f, 0);
	return 0;
}

int acr120s_write_block(int handle, uint8_t block, void *data)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'w');
	frame_byte(f, block & 0x3f);
	frame_bytes(f, data, ACR120S_BLOCK_SIZE);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) == 1)
		return -DATA(f, 0);
		
	return 0;
}

int acr120s_write_value(int handle, uint8_t block, int32_t value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'w');
	frame_byte(f, 'v');
	frame_byte(f, block & 0x3f);
	frame_value(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) == 1)
		return -DATA(f, 0);
		
	return 0;
}

int acr120s_write_eeprom(int handle, uint8_t reg, uint8_t value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'w');
	frame_byte(f, 'e');
	frame_byte(f, reg);
	frame_byte(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	return 0;
}

int acr120s_write_llreg(int handle, uint8_t reg, uint8_t value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'z');
	frame_byte(f, 'w');
	frame_byte(f, reg);
	frame_byte(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	return 0;
}


int acr120s_write_master_key(int handle, uint8_t index, void *key)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'w');
	frame_byte(f, 'm');
	frame_byte(f, index & 0x1f);
	frame_bytes(f, key, ACR120S_KEY_SIZE);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) == 1)
		return -DATA(f, 0);

	return 0;
}

int acr120s_write_user_port(int handle, uint8_t value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'p');
	frame_byte(f, 'w');
	frame_byte(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) != 1)
		return -1;

	return 0;
}

int acr120s_flip_user_port(int handle, uint8_t value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'p');
	frame_byte(f, 'f');
	frame_byte(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;
	
	if (LEN(f) != 1)
		return -1;
	
	return 0;
}

int acr120s_inc_value(int handle, uint8_t block, int32_t value, int32_t *result)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, '+');
	frame_byte(f, block & 0x3f);
	frame_value(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;
	
	if (LEN(f) == 1)
		return -DATA(f, 0);

	if (result != 0)
		*result = get_value(&DATA(f, 0));

	return 0;
}

int acr120s_dec_value(int handle, uint8_t block, int32_t value, int32_t *result)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, '-');
	frame_byte(f, block & 0x3f);
	frame_value(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;
	
	if (LEN(f) == 1)
		return -DATA(f, 0);

	if (result != 0)
		*result = get_value(&DATA(f, 0));

	return 0;
}

int acr120s_copy_value(int handle, uint8_t from, uint8_t to, int32_t *value)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, '=');
	frame_byte(f, from & 0x3f);
	frame_byte(f, to & 0x3f);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;
	
	if (LEN(f) == 1)
		return -DATA(f, 0);

	if (value != 0)
		*value = get_value(&DATA(f, 0));

	return 0;
}

int acr120s_power_on(int handle)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'p');
	frame_byte(f, 'o');
	frame_byte(f, 'n');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	return 0;
}

int acr120s_power_off(int handle)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'p');
	frame_byte(f, 'o');
	frame_byte(f, 'f');
	frame_byte(f, 'f');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	return 0;
}

int acr120s_get_station_id(int handle, uint8_t *sid)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	*sid = ctx->sid;
	return 0;
}

int acr120s_set_station_id(int handle, uint8_t sid)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	if (sid == 0)
	{
		uint8_t f[ACR120S_MAX_FRAME_SIZE];

		frame_init(f, 0xff);
		frame_byte(f, 'g');
		frame_done(f);

		if (write_frame(ctx, f) < 0)
			return -1;

		if (read_frame(ctx, f) < 0)
			return -1;

		sid = DATA(f, 0);
	}

	ctx->sid = sid;
	return sid;
}

int acr120s_transmit_frame(int handle, uint8_t option,
		void *data, uint8_t data_len,
		void *reply, uint8_t *reply_len)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	if (data_len > 34) /* Maximum supported user frame */
		return -1;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 't');
	frame_byte(f, data_len);
	frame_byte(f, option);
	frame_bytes(f, data, data_len);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (LEN(f) == 1)
		return -DATA(f, 0);

	*reply_len = LEN(f) - 1;
	memcpy(reply, &DATA(f, + 1), *reply_len);

	return 0;
}

int acr120s_get_firmware_version(int handle, char *version)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	int len;

	frame_init(f, ctx->sid);
	frame_byte(f, 'z');
	frame_byte(f, 'v');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	len = LEN(f);
	if (len >= ACR120S_FIRMWARE_STR_SIZE)
		len = ACR120S_FIRMWARE_STR_SIZE - 1;

	memcpy(version, &DATA(f, 0), len);
	version[len] = 0;

	return 0;
}


int acr120s_set_frame_waiting_index(int handle, uint8_t fwi)
{
	struct acr120s_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120S_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120S_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'z');
	frame_byte(f, 'f');
	frame_byte(f, fwi);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	return 0;
}

/***************************
 * Adapter for mifare_ops_t
 ***************************/

static int _acr120s_open(mifare_dev_t *dev)
{
	return acr120s_open(dev->device, dev->baud, dev->sid);
}

static int _acr120s_close(int handle)
{
	return acr120s_close(handle);
}

static int _acr120s_detect(int handle, mifare_tag_t *tags, int *count)
{
	return acr120s_list_tag(handle, tags, count);
}

static int _acr120s_select(int handle, mifare_tag_t *tag)
{
	return acr120s_multi_select(handle, tag);
}

static int _acr120s_login(int handle, uint8_t sector, int type, const void *key)
{
	return acr120s_login(handle, sector, 
			type == 0 ? 
			ACR120S_KEY_TYPE_A :
			ACR120S_KEY_TYPE_B, key);
}

static int _acr120s_login_stored(int handle, uint8_t sector, int type, int key_no)
{
	uint8_t k = key_no;
	return acr120s_login(handle, sector,
			type == 0 ?
			ACR120S_KEY_TYPE_MASTER_A :
			ACR120S_KEY_TYPE_MASTER_B, &k);
}

static int _acr120s_read_block(int handle, uint8_t block, void *data)
{
	return acr120s_read_block(handle, block, data);
}

static int _acr120s_write_block(int handle, uint8_t block, void *data)
{
	return acr120s_write_block(handle, block, data);
}

static int _acr120s_read_value(int handle, uint8_t block, int32_t *value)
{
	return acr120s_read_value(handle, block, value);
}

static int _acr120s_write_value(int handle, uint8_t block, int32_t value)
{
	return acr120s_write_value(handle, block, value);
}

static int _acr120s_inc_value(int handle, uint8_t block, int32_t value)
{
	return acr120s_inc_value(handle, block, value, 0);
}

static int _acr120s_dec_value(int handle, uint8_t block, int32_t value)
{
	return acr120s_dec_value(handle, block, value, 0);
}

static int _acr120s_copy_value(int handle, uint8_t from, uint8_t to)
{
	return acr120s_copy_value(handle, from, to, 0);
}

static int _acr120s_beep(int handle, int msec)
{
	acr120s_write_user_port(handle, 2);
	usleep(msec * 1000);
	acr120s_write_user_port(handle, 1);
	return 0;
}

mifare_ops_t acr120s_ops =
{
	.open = _acr120s_open,
	.close = _acr120s_close,
	
	.detect = _acr120s_detect,
	.select = _acr120s_select,

	.login = _acr120s_login,
	.login_stored = _acr120s_login_stored,

	.read_block = _acr120s_read_block,
	.write_block = _acr120s_write_block,

	.read_value = _acr120s_read_value,
	.write_value = _acr120s_write_value,

	.inc_value = _acr120s_inc_value,
	.dec_value = _acr120s_dec_value,
	.copy_value = _acr120s_copy_value,

	.beep = _acr120s_beep,
};

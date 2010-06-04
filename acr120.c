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
#include "acr120.h"

#define STX 0x02
#define ETX 0x03

#define STX_POS 0
#define SID_POS 1
#define LEN_POS 2
#define DATA_POS 3

#define DEBUG 1

#if DEBUG
	#define DPRINTF(...) fprintf(stderr, __VA_ARGS__)
#else
	#define DPRINTF
#endif

#define MAX_HANDLE 8

#define CFG_GET_EXTENDED_ID(v) (((v) >> 2) & 1)

struct acr120_context
{
	int fd;
	uint8_t cfg;
	uint8_t sid;
	struct termios oldtio;
};

static struct acr120_context context[MAX_HANDLE];

static inline struct acr120_context *get_context(int handle)
{
	if ((unsigned) handle >= MAX_HANDLE || !context[handle].fd)
		return 0;
	
	return &context[handle];
}

static inline void frame_init(uint8_t *f, uint8_t sid)
{
	f[SID_POS] = sid;
	f[LEN_POS] = 0;
}

static inline void frame_byte(uint8_t *f, uint8_t byte)
{
	f[DATA_POS + f[LEN_POS]] = byte;
	f[LEN_POS]++;
}

static inline void frame_value(uint8_t *f, int32_t value)
{
	int32_t *p = (int32_t *) &f[DATA_POS + f[LEN_POS]];
	*p = htonl(value);
	f[LEN_POS] += 4;
}

static inline void frame_bytes(uint8_t *f, const void *buf, int len)
{
	uint8_t *p = &f[DATA_POS + f[LEN_POS]];
	memcpy(p, buf, len);
	f[LEN_POS] += len;
}

static inline int32_t get_value(void *p)
{
	return ntohl(*((uint32_t *) p));
}

static inline void frame_done(uint8_t *f)
{
	int i, bcc_pos = DATA_POS + f[LEN_POS]; 

	f[STX_POS] = STX;

	f[bcc_pos] = 0;
	for (i = SID_POS; i < bcc_pos; i++)
		f[bcc_pos] ^= f[i];

	f[bcc_pos + 1] = ETX;
}

#if 0
static void print_bytes(const char *label, uint8_t *buf, int len)
{
	int i;
	DPRINTF("%s:", label);
	for (i = 0; i < len; i++)
		DPRINTF(" %02x", buf[i]);
	DPRINTF("\n");
}
#endif

static int write_frame(struct acr120_context *ctx, void *f)
{
	uint8_t *p = f;
	int size = p[LEN_POS] + ACR120_FRAME_OVERHEAD;
	int left = size;
	int res;

	while (left > 0)
	{
		res = write(ctx->fd, p, left);
		if (res <= 0)
			return -1;
		p += res;
		left -= res;
	}

	return size;
}

static int read_frame(struct acr120_context *ctx, void *f)
{
	uint8_t cc, bcc, *p, len;
	int size;
	int i;

	for (;;)
	{
		p = f;
		bcc = 0;

		/* Read STX */
		for (;;)
		{
			if (read(ctx->fd, &cc, 1) != 1)
				return -1;
			if (cc == STX)
				break;
		}
		*p++ = cc;

		/* Read Station ID */
		if (read(ctx->fd, &cc, 1) != 1)
			return -1;
		*p++ = cc;
		bcc ^= cc;

		/* Read data length */
		if (read(ctx->fd, &cc, 1) != 1)
			return -1;
		len = cc;
		*p++ = cc;
		bcc ^= cc;

		/* Read data */
		while (len > 0)
		{
			cc = read(ctx->fd, p, len);
			if (cc == 0)
				return -1;

			for (i = 0; i < cc; i++)
				bcc ^= p[i];

			len -= cc;
			p += cc;
		}

		/* Read BCC */
		if (read(ctx->fd, &cc, 1) != 1)
			return -1;
		if (cc != bcc)
		{
			DPRINTF("Received bad BCC, 0x%02x should be 0x%02x.\n",
					cc, bcc);
			continue; /* Bad BCC, restart packet read */
		}
		*p++ = cc;

		/* Read ETX */
		if (read(ctx->fd, &cc, 1) != 1)
			return -1;
		if (cc != ETX)
		{
			DPRINTF("Frame not ended with ETX.\n");
			continue; /* Bad ETX, restart packet read */
		}
		*p++ = cc;
		
		size = p - (uint8_t *) f;
		break;
	}

	return size;
}

int acr120_open(const char *dev, int baud, uint8_t sid)
{
	struct termios oldtio, newtio;
	struct acr120_context *ctx;
	int handle, fd;

	/* Auto detect baud-rate */
	if (baud == 0)
	{
		int bauds[5] = { B9600, B19200, B38400, B57600, B115200 };
		int i, ret;
		for (i = 0; i < 5; i++)
			if ((ret = acr120_open(dev, bauds[i], sid)) >= 0)
				return ret;
		return ret;
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
	if (acr120_set_station_id(handle, sid) < 0)
	{
		acr120_close(handle);
		return -1;
	}

	/* Read Protocol Configuration Register */
	if (acr120_read_eeprom(handle, 5, &ctx->cfg) < 0)
	{
		acr120_close(handle);
		return -1;
	}

	return handle;
}

int acr120_close(int handle)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	/* Restore original termios */
	tcsetattr(ctx->fd, TCSANOW, &ctx->oldtio);

	close(ctx->fd);
	ctx->fd = 0;

	return 0;
}

int acr120_reset(int handle)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'x');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	usleep(120000);
	return 0;
}

int acr120_select(int handle, acr120_tag_t *tag)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 's');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	if (CFG_GET_EXTENDED_ID(ctx->cfg))
	{
		tag->type = f[DATA_POS];
		tag->size = f[LEN_POS] - 1;
		memcpy(tag->serial, &f[DATA_POS + 1], tag->size);
	}
	else
	{
		tag->type = ACR120_TAG_TYPE_UNKNOWN;
		tag->size = f[LEN_POS];
		memcpy(tag->serial, &f[DATA_POS], tag->size);
	}

	return 0;
}

int acr120_list_tag(int handle, acr120_tag_t *tags, int *tag_count)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
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

		if (f[LEN_POS] == 1)
		{
			if (f[DATA_POS] != i)
				DPRINTF("Tag count %d, should be %d.\n", f[DATA_POS], i);
			break;
		}

		if (i < *tag_count)
		{
			acr120_tag_t *tag = &tags[i];
			if (CFG_GET_EXTENDED_ID(ctx->cfg))
			{
				tag->type = f[DATA_POS];
				tag->size = f[LEN_POS] - 1;
				memcpy(tag->serial, &f[DATA_POS + 1], tag->size);
			}
			else
			{
				tag->type = ACR120_TAG_TYPE_UNKNOWN;
				tag->size = f[LEN_POS];
				memcpy(tag->serial, &f[DATA_POS], tag->size);
			}
		}
	}

	if (i > *tag_count)
		i = *tag_count;

	*tag_count = i;

	return 0;
}

int acr120_multi_select(int handle, acr120_tag_t *tag)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	if (tag->size != 4 && tag->size != 7 && tag->size != 10)
		return -1;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'm');
	frame_bytes(f, tag->serial, tag->size);
	frame_byte(f, '\r');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	if (CFG_GET_EXTENDED_ID(ctx->cfg))
	{
		tag->type = f[DATA_POS];
		tag->size = f[LEN_POS] - 1;
		memcpy(tag->serial, &f[DATA_POS + 1], tag->size);
	}
	else
	{
		tag->type = ACR120_TAG_TYPE_UNKNOWN;
		tag->size = f[LEN_POS];
		memcpy(tag->serial, &f[DATA_POS], tag->size);
	}

	return 0;
}

int acr120_login(int handle, uint8_t sector, int key_type, const void *key)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'l');
	frame_byte(f, sector);

	switch (key_type)
	{
		case ACR120_KEY_TYPE_A:
			frame_byte(f, 0xaa);
			frame_bytes(f, key, ACR120_KEY_SIZE);
			break;

		case ACR120_KEY_TYPE_B:
			frame_byte(f, 0xbb);
			frame_bytes(f, key, ACR120_KEY_SIZE);
			break;

		case ACR120_KEY_TYPE_TRANSPORT_A:
			frame_byte(f, 0xaa);
			break;

		case ACR120_KEY_TYPE_TRANSPORT_B:
			frame_byte(f, 0xbb);
			break;

		case ACR120_KEY_TYPE_TRANSPORT_F:
			frame_byte(f, 0xff);
			break;

		case ACR120_KEY_TYPE_MASTER_A:
			frame_byte(f, 0x10 + ((char *) key)[0]);
			break;

		case ACR120_KEY_TYPE_MASTER_B:
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

	if (f[DATA_POS] != 'L')
		return -f[DATA_POS];

	return 0;
}

int acr120_read_block(int handle, uint8_t block, void *data)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'r');
	frame_byte(f, block & 0x3f);
	frame_done(f);
	
	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	memcpy(data, &f[DATA_POS], 16);
	return 0;
}

int acr120_read_value(int handle, uint8_t block, int32_t *value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'r');
	frame_byte(f, 'v');
	frame_byte(f,  block & 0x3f);
	frame_done(f);
	
	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	*value = get_value(&f[DATA_POS]);
	return 0;
}

int acr120_read_eeprom(int handle, uint8_t reg, uint8_t *value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'r');
	frame_byte(f, 'e');
	frame_byte(f, reg);
	frame_done(f);
	
	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	*value = f[DATA_POS];
	return 0;
}

int acr120_read_llreg(int handle, uint8_t reg, uint8_t *value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'z');
	frame_byte(f, 'r');
	frame_byte(f, reg);
	frame_done(f);
	
	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	*value = f[DATA_POS];
	return 0;
}

int acr120_write_block(int handle, uint8_t block, void *data)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

	frame_init(f, ctx->sid);
	frame_byte(f, 'w');
	frame_byte(f, block & 0x3f);
	frame_bytes(f, data, ACR120_BLOCK_SIZE);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (f[LEN_POS] == 1)
		return -f[DATA_POS];
		
	return 0;
}

int acr120_write_value(int handle, uint8_t block, int32_t value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

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

	if (f[LEN_POS] == 1)
		return -f[DATA_POS];
		
	return 0;
}

int acr120_write_eeprom(int handle, uint8_t reg, uint8_t value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
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

int acr120_write_llreg(int handle, uint8_t reg, uint8_t value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
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


int acr120_write_master_key(int handle, uint8_t index, void *key)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'w');
	frame_byte(f, 'm');
	frame_byte(f, index & 0x1f);
	frame_bytes(f, key, ACR120_KEY_SIZE);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	return 0;
}

int acr120_write_user_port(int handle, uint8_t value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'p');
	frame_byte(f, 'w');
	frame_byte(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	if (f[LEN_POS] != 1)
		return -1;

	return 0;
}

int acr120_flip_user_port(int handle, uint8_t value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, 'p');
	frame_byte(f, 'f');
	frame_byte(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;
	
	if (f[LEN_POS] != 1)
		return -1;
	
	return 0;
}

int acr120_inc_value(int handle, uint8_t block, int32_t value, int32_t *result)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, '+');
	frame_byte(f, block & 0x3f);
	frame_value(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;
	
	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	if (result != 0)
		*result = get_value(&f[DATA_POS]);

	return 0;
}

int acr120_dec_value(int handle, uint8_t block, int32_t value, int32_t *result)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, '-');
	frame_byte(f, block & 0x3f);
	frame_value(f, value);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;
	
	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	if (result != 0)
		*result = get_value(&f[DATA_POS]);

	return 0;
}

int acr120_copy_value(int handle, uint8_t from, uint8_t to, int32_t *value)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
	frame_init(f, ctx->sid);
	frame_byte(f, '=');
	frame_byte(f, from & 0x3f);
	frame_byte(f, to & 0x3f);
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;
	
	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	if (value != 0)
		*value = get_value(&f[DATA_POS]);

	return 0;
}

int acr120_power_on(int handle)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
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

int acr120_power_off(int handle)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
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

int acr120_get_station_id(int handle, uint8_t *sid)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	*sid = ctx->sid;
	return 0;
}

int acr120_set_station_id(int handle, uint8_t sid)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	if (sid == 0)
	{
		uint8_t f[ACR120_MAX_FRAME_SIZE];

		frame_init(f, 0xff);
		frame_byte(f, 'g');
		frame_done(f);

		if (write_frame(ctx, f) < 0)
			return -1;

		if (read_frame(ctx, f) < 0)
			return -1;

		sid = f[DATA_POS];
	}

	ctx->sid = sid;
	return sid;
}

int acr120_transmit_frame(int handle, uint8_t option,
		void *data, uint8_t data_len,
		void *reply, uint8_t *reply_len)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	if (data_len > 34) /* Maximum supported user frame */
		return -1;

	uint8_t f[ACR120_MAX_FRAME_SIZE];

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

	if (f[LEN_POS] == 1)
		return -f[DATA_POS];

	*reply_len = f[LEN_POS] - 1;
	memcpy(reply, &f[DATA_POS + 1], *reply_len);

	return 0;
}

int acr120_get_firmware_version(int handle, char *version)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	int len;

	frame_init(f, ctx->sid);
	frame_byte(f, 'z');
	frame_byte(f, 'v');
	frame_done(f);

	if (write_frame(ctx, f) < 0)
		return -1;

	if (read_frame(ctx, f) < 0)
		return -1;

	len = f[LEN_POS];
	if (len >= ACR120_FIRMWARE_STR_SIZE)
		len = ACR120_FIRMWARE_STR_SIZE - 1;

	memcpy(version, &f[DATA_POS], len);
	version[len] = 0;

	return 0;
}


int acr120_set_frame_waiting_index(int handle, uint8_t fwi)
{
	struct acr120_context *ctx = get_context(handle);
	if (ctx == 0) return ACR120_ERROR_INVALID_HANDLE;

	uint8_t f[ACR120_MAX_FRAME_SIZE];
	
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

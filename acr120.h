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

#ifndef _ACR120_H_
#define _ACR120_H_

#include <termios.h>
#include <unistd.h>
#include <stdint.h>

enum
{
	ACR120_KEY_TYPE_A           = 0x0a,
	ACR120_KEY_TYPE_B           = 0x0b,
	ACR120_KEY_TYPE_TRANSPORT_A = 0xaa,
	ACR120_KEY_TYPE_TRANSPORT_B = 0xbb,
	ACR120_KEY_TYPE_TRANSPORT_F = 0xff,
	ACR120_KEY_TYPE_MASTER_A    = 0x10,
	ACR120_KEY_TYPE_MASTER_B    = 0x30,
};

enum
{
	ACR120_TAG_TYPE_UNKNOWN            = 0x00, /* Extended ID bit not set */
	ACR120_TAG_TYPE_MIFARE_LIGHT       = 0x01,
	ACR120_TAG_TYPE_MIFARE_1K          = 0x02,
	ACR120_TAG_TYPE_MIFARE_4K          = 0x03,
	ACR120_TAG_TYPE_MIFARE_DESFIRE     = 0x04,
	ACR120_TAG_TYPE_MIFARE_ULTRALIGHT  = 0x05,
	ACR120_TAG_TYPE_JCOP30             = 0x06,
	ACR120_TAG_TYPE_SHANGHAI_TRANSPORT = 0x07,
	ACR120_TAG_TYPE_MPCOS_COMBI        = 0x08,
	ACR120_TAG_TYE_ISO_TYPE_B          = 0x80,
};

enum
{
	ACR120_ERROR_INVALID_HANDLE     = -'H',

	ACR120_ERROR_NO_TAG             = -'N',
	ACR120_ERROR_LOGIN_FAILED       = -'F',
	ACR120_ERROR_INVALID_KEY_FORMAT = -'E',
	ACR120_ERROR_NO_VALUE_BLOCK     = -'I',
	ACR120_ERROR_FAILED             = -'F',
	ACR120_ERROR_INTERRUPTED        = -'X',
	ACR120_ERROR_NOT_MATCHED        = -'U',
};

enum
{
	ACR120_MAX_SERIAL_SIZE  =  10,
	ACR120_VALUE_SIZE       =   4,
	ACR120_KEY_SIZE         =   6,
	ACR120_BLOCK_SIZE       =  16,
	ACR120_BLOCK_PER_SECTOR =   4,
	ACR120_MAX_TAG          =  17,
	ACR120_FRAME_OVERHEAD   =   5,
	ACR120_MAX_FRAME_SIZE   = 260, /* 255 + 5 (overhead) */
};

enum
{
	ACR120_TX_PARITY_ENABLE  = 1 << 0,
	ACR120_TX_PARITY_ODD     = 1 << 1,
	ACR120_TX_CRC_GENERATE   = 1 << 2,
	ACR120_TX_CRC_CHECK      = 1 << 3,
	ACR120_TX_CRYPTO_DISABLE = 1 << 4,
};

#define ACR120_TX_BIT_FRAMING(x) ((x) << 5)

typedef struct
{
	uint8_t type;
	uint8_t serial[ACR120_MAX_SERIAL_SIZE];
	uint8_t size;
} acr120_tag_t;

/* @param dev TTY device (e.g: /dev/ttyS0, /dev/ttyUSB0)
 * @param baud Baudrate, one of: B9600, B19200, B38400, B57600, B115200
 * @param sid ACR120S Station ID, or 0 for autodetect
 *
 * @return Handle of ACR120S session, or < 0 if error
 */
int acr120_open(const char *dev, int baud, uint8_t sid);
int acr120_close(int handle);

int acr120_reset(int handle);

int acr120_select(int handle, acr120_tag_t *tag);
int acr120_list_tag(int handle, acr120_tag_t *tags, int *tag_count);
int acr120_multi_select(int handle, acr120_tag_t *tag);

int acr120_login(int handle, uint8_t sector, int key_type, const void *key);

int acr120_read_block(int handle, uint8_t block, void *data);
int acr120_read_value(int handle, uint8_t block, int32_t *value);
int acr120_read_eeprom(int handle, uint8_t reg, uint8_t *value);

int acr120_write_block(int handle, uint8_t block, void *data);
int acr120_write_value(int handle, uint8_t block, int32_t value);
int acr120_write_eeprom(int handle, uint8_t reg, uint8_t value);
int acr120_write_master_key(int handle, uint8_t index, void *key);

int acr120_write_user_port(int handle, uint8_t value);
int acr120_flip_user_port(int handle, uint8_t value);

int acr120_inc_value(int handle, uint8_t block, int32_t value, int32_t *result);
int acr120_dec_value(int handle, uint8_t block, int32_t value, int32_t *result);
int acr120_copy_value(int handle, uint8_t from, uint8_t to, int32_t *value);

int acr120_power_on(int handle);
int acr120_power_off(int handle);

int acr120_get_station_id(int handle, uint8_t *sid);
int acr120_set_station_id(int handle, uint8_t sid);

int acr120_transmit_frame(int handle, uint8_t option,
		void *data, uint8_t data_len,
		void *reply, uint8_t *reply_len);

#endif

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

#ifndef _ACR120S_H_
#define _ACR120S_H_

#include <termios.h>
#include <unistd.h>
#include <stdint.h>
#include "mifare.h"

enum
{
	ACR120S_KEY_TYPE_A           = 0x0a,
	ACR120S_KEY_TYPE_B           = 0x0b,
	ACR120S_KEY_TYPE_TRANSPORT_A = 0xaa,
	ACR120S_KEY_TYPE_TRANSPORT_B = 0xbb,
	ACR120S_KEY_TYPE_TRANSPORT_F = 0xff,
	ACR120S_KEY_TYPE_MASTER_A    = 0x10,
	ACR120S_KEY_TYPE_MASTER_B    = 0x30,
};

enum
{
	ACR120S_TAG_TYPE_UNKNOWN            = 0x00, /* Extended ID bit not set */
	ACR120S_TAG_TYPE_MIFARE_LIGHT       = 0x01,
	ACR120S_TAG_TYPE_MIFARE_1K          = 0x02,
	ACR120S_TAG_TYPE_MIFARE_4K          = 0x03,
	ACR120S_TAG_TYPE_MIFARE_DESFIRE     = 0x04,
	ACR120S_TAG_TYPE_MIFARE_ULTRALIGHT  = 0x05,
	ACR120S_TAG_TYPE_JCOP30             = 0x06,
	ACR120S_TAG_TYPE_SHANGHAI_TRANSPORT = 0x07,
	ACR120S_TAG_TYPE_MPCOS_COMBI        = 0x08,
	ACR120S_TAG_TYE_ISO_TYPE_B          = 0x80,
};

enum
{
	ACR120S_ERROR_INVALID_HANDLE     = -'H',

	ACR120S_ERROR_NO_TAG             = -'N',
	ACR120S_ERROR_LOGIN_FAILED       = -'F',
	ACR120S_ERROR_INVALID_KEY_FORMAT = -'E',
	ACR120S_ERROR_NO_VALUE_BLOCK     = -'I',
	ACR120S_ERROR_FAILED             = -'F',
	ACR120S_ERROR_INTERRUPTED        = -'X',
	ACR120S_ERROR_NOT_MATCHED        = -'U',
};

enum
{
	ACR120S_FIRMWARE_STR_SIZE =  20, /* Actually: "ACR120 x.xx" + 0 = 12 bytes */
	ACR120S_MAX_SERIAL_SIZE   =  10,
	ACR120S_VALUE_SIZE        =   4,
	ACR120S_KEY_SIZE          =   6,
	ACR120S_BLOCK_SIZE        =  16,
	ACR120S_BLOCK_PER_SECTOR  =   4,
	ACR120S_MAX_TAG           =  17,
	ACR120S_MAX_FRAME_SIZE    = 260, /* 255 + 5 (overhead) */
};

int acr120s_open(const char *dev, int baud, uint8_t sid);
int acr120s_close(int handle);

int acr120s_reset(int handle);

int acr120s_select(int handle, mifare_tag_t *tag);
int acr120s_list_tag(int handle, mifare_tag_t *tags, int *tag_count);
int acr120s_multi_select(int handle, mifare_tag_t *tag);

int acr120s_login(int handle, uint8_t sector, int key_type, const void *key);

int acr120s_read_block(int handle, uint8_t block, void *data);
int acr120s_read_value(int handle, uint8_t block, int32_t *value);
int acr120s_read_eeprom(int handle, uint8_t reg, uint8_t *value);
int acr120s_read_llreg(int handle, uint8_t reg, uint8_t *value);

int acr120s_write_block(int handle, uint8_t block, const void *data);
int acr120s_write_value(int handle, uint8_t block, int32_t value);
int acr120s_write_eeprom(int handle, uint8_t reg, uint8_t value);
int acr120s_write_llreg(int handle, uint8_t reg, uint8_t value);
int acr120s_write_master_key(int handle, uint8_t index, const void *key);

int acr120s_write_user_port(int handle, uint8_t value);
int acr120s_flip_user_port(int handle, uint8_t value);

int acr120s_inc_value(int handle, uint8_t block, int32_t value, int32_t *result);
int acr120s_dec_value(int handle, uint8_t block, int32_t value, int32_t *result);
int acr120s_copy_value(int handle, uint8_t from, uint8_t to, int32_t *value);

int acr120s_power_on(int handle);
int acr120s_power_off(int handle);

int acr120s_get_station_id(int handle, uint8_t *sid);
int acr120s_set_station_id(int handle, uint8_t sid);

int acr120s_transmit_frame(int handle, uint8_t option,
		void *data, uint8_t data_len,
		void *reply, uint8_t *reply_len);

int acr120s_get_firmware_version(int handle, char *version);
int acr120s_set_frame_waiting_index(int handle, uint8_t fwi);

extern mifare_ops_t acr120s_ops;

#endif

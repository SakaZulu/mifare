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

#ifndef _MF1RW_H_
#define _MF1RW_H_

#include <termios.h>
#include <unistd.h>
#include <stdint.h>
#include "mifare.h"

enum
{
	MF1RW_COMM_OK       = 0,
	MF1RW_OK            = 0,
	MF1RW_NOTAGERR      = -1,
	MF1RW_CRCERR        = -2,
	MF1RW_EMPTY         = -3,
	MF1RW_AUTHERR       = -4,
	MF1RW_PARITYERR     = -5,
	MF1RW_CODEERR       = -6,
	MF1RW_SENDERR       = -8,
	MF1RW_KEYERR        = -9,
	MF1RW_NOTAUTHERR    = -10,
	MF1RW_BITCOUNTERR   = -11,
	MF1RW_BYTECOUNTERR  = -12,
	MF1RW_TRANSERR      = -14,
	MF1RW_WRITEERR      = -15,
	MF1RW_INCRERR       = -16,
	MF1RW_DECRERR       = -17,
	MF1RW_READERR       = -18,
	MF1RW_COLLERR       = -24,
	MF1RW_ACCESSTIMEOUT = -27,
	MF1RW_COMM_ERR      = -255,
};

enum
{
	MF1RW_REQ_MODE_NO_HALTED = 0,
	MF1RW_REQ_MODE_ALL       = 1,
};

enum
{
	MF1RW_VALUE_MODE_DECREMENT = 0xc0,
	MF1RW_VALUE_MODE_INCREMENT = 0xc1,
	MF1RW_VALUE_MODE_RESTORE   = 0xc2,
};

int mf1rw_open(const char *dev);
int mf1rw_close(int handle);

int mf1rw_request(int handle, uint8_t mode, uint16_t *tag_type);

int mf1rw_anticoll(int handle, void *serial);
int mf1rw_anticoll2(int handle, uint8_t anti_coll, void *serial);

int mf1rw_select(int handle, const void *serial, uint8_t *capacity);

int mf1rw_auth(int handle, uint8_t mode, uint8_t sector);
int mf1rw_auth2(int handle, uint8_t mode, uint8_t sector, uint8_t key);
int mf1rw_auth_key(int handle, uint8_t mode, uint8_t sector, const void *key);

int mf1rw_halt(int handle);

int mf1rw_read_block(int handle, uint8_t block, void *data);
int mf1rw_write_block(int handle, uint8_t block, const void *data);

int mf1rw_inc_value(int handle, uint8_t block, int32_t value);
int mf1rw_dec_value(int handle, uint8_t block, int32_t value);

int mf1rw_restore(int handle, uint8_t block);
int mf1rw_transfer(int handle, uint8_t block);

int mf1rw_load_key(int handle, uint8_t mode, uint8_t sector, const void *key);

int mf1rw_reset(int handle, uint8_t msec);

int mf1rw_standby(int handle);
int mf1rw_config(int handle);

int mf1rw_set_led(int handle, int turn_on);

int mf1rw_check_write(int handle, const void *serial, uint8_t mode, 
		uint8_t block, const void *data);

int mf1rw_buzzer(int handle, uint8_t active, uint8_t inactive,
		uint8_t repeat);

int mf1rw_read_eeprom(int handle, uint8_t addr, uint8_t len, uint8_t *data);
int mf1rw_write_eeprom(int handle, uint8_t addr, uint8_t len, uint8_t *data);

int mf1rw_value(int handle, uint8_t mode, uint8_t block, int32_t value,
		uint8_t transfer_block);

extern mifare_ops_t mf1rw_ops;

#endif

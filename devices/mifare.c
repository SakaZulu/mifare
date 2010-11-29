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

#include "mifare.h"

mifare_ops_t *mifare_ops = 0;

int mifare_open(mifare_dev_t *dev)
{
	if (mifare_ops && mifare_ops->open)
		return mifare_ops->open(dev);
	return -1;
}

int mifare_close(int handle)
{
	if (mifare_ops && mifare_ops->close)
		return mifare_ops->close(handle);
	return -1;
}

int mifare_detect(int handle, mifare_tag_t *tags, int *count)
{
	if (mifare_ops && mifare_ops->detect)
		return mifare_ops->detect(handle, tags, count);
	return -1;
}

int mifare_select(int handle, mifare_tag_t *tag)
{
	if (mifare_ops && mifare_ops->select)
		return mifare_ops->select(handle, tag);
	return -1;
}

int mifare_login(int handle, uint8_t sector, int type, const void *key)
{
	if (mifare_ops && mifare_ops->login)
		return mifare_ops->login(handle, sector, type, key);
	return -1;
}

int mifare_login_stored(int handle, uint8_t sector, int type, int key_no)
{
	if (mifare_ops && mifare_ops->login_stored)
		return mifare_ops->login_stored(handle, sector, type, key_no);
	return -1;
}

int mifare_read_block(int handle, uint8_t block, void *data)
{

	if (mifare_ops && mifare_ops->read_block)
		return mifare_ops->read_block(handle, block, data);
	return -1;
}

int mifare_write_block(int handle, uint8_t block, void *data)
{
	if (mifare_ops && mifare_ops->write_block)
		return mifare_ops->write_block(handle, block, data);
	return -1;
}

int mifare_read_value(int handle, uint8_t block, int32_t *value)
{
	if (mifare_ops && mifare_ops->read_value)
		return mifare_ops->read_value(handle, block, value);
	return -1;
}

int mifare_write_value(int handle, uint8_t block, int32_t value)
{
	if (mifare_ops && mifare_ops->write_value)
		return mifare_ops->write_value(handle, block, value);
	return -1;
}

int mifare_inc_value(int handle, uint8_t block, int32_t value)
{
	if (mifare_ops && mifare_ops->inc_value)
		return mifare_ops->inc_value(handle, block, value);
	return -1;
}

int mifare_dec_value(int handle, uint8_t block, int32_t value)
{
	if (mifare_ops && mifare_ops->dec_value)
		return mifare_ops->dec_value(handle, block, value);
	return -1;
}

int mifare_copy_value(int handle, uint8_t from, uint8_t to)
{

	if (mifare_ops && mifare_ops->copy_value)
		return mifare_ops->copy_value(handle, from, to);
	return -1;
}

int mifare_beep(int handle, int msec)
{
	if (mifare_ops && mifare_ops->beep)
		return mifare_ops->beep(handle, msec);
	return -1;
}

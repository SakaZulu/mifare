#include <string.h>
#include "purse.h"
#include "aes256.h"

static void endecrypt(mifare_tag_t *tag, purse_desc_t *desc, int which,
		uint8_t *buf)
{
	/* Generate per card key */
	uint8_t aes_key[32];
	int i;
	memcpy(aes_key, desc->aes_key, 32);
	for (i = 0; i < 32; i++)
		aes_key[i] ^= tag->serial[i & 3] ^ (which ? 1 : 0);

	/* Encrypt buffer */
	aes256_context aes;
	aes256_init(&aes, aes_key);
	aes256_encrypt_ecb(&aes, buf);
	aes256_done(&aes);
}

static int purse_crypt(int handle, mifare_tag_t *tag, purse_desc_t *desc,
	 	int which, int32_t value, int32_t counter, int32_t prev)
{
	/* Prepare buffer for digest */
	uint8_t buf[16];
	memcpy(buf, desc->magic, 4);
	buf[4] = value >> 24;
	buf[5] = value >> 16;
	buf[6] = value >> 8;
	buf[7] = value;
	buf[8] = counter >> 24;
	buf[9] = counter >> 16;
	buf[10] = counter >> 8;
	buf[11] = counter;
	buf[12] = prev >> 24;
	buf[13] = prev >> 16;
	buf[14] = prev >> 8;
	buf[15] = prev;

	endecrypt(tag, desc, which, buf);

	int block = desc->sector * 4;
	if (mifare_write_block(handle, which ? block + 1: block, buf))
		return PURSE_ERROR_WRITE_BLOCK;

	return PURSE_OK;
}

static int is_valid(purse_desc_t *desc, uint8_t *buf)
{
	if (memcmp(buf, desc->magic, 4) != 0)
		return 0;
	return 1;
}

static int purse_verify(int handle, mifare_tag_t *tag, purse_desc_t *desc,
		int32_t *value, int32_t *counter)
{
	int block = desc->sector * 4;

	uint8_t buf1[16], buf2[16];
	int ok1, ok2;
	int32_t val1, val2, cnt1, cnt2, cnt3, prv1, prv2;

	if (mifare_select(handle, tag))
		return PURSE_ERROR_SELECT;
	if (mifare_login(handle, desc->sector, desc->key_type, desc->key))
		return PURSE_ERROR_LOGIN;
	if (mifare_read_block(handle, block + 0, buf1))
		return PURSE_ERROR_READ_BLOCK;
	if (mifare_read_block(handle, block + 1, buf2))
		return PURSE_ERROR_READ_BLOCK;
	if (mifare_read_value(handle, block + 2, &cnt3))
		return PURSE_ERROR_READ_VALUE;

	endecrypt(tag, desc, 0, buf1);
	endecrypt(tag, desc, 1, buf2);

	ok1 = is_valid(desc, buf1);
	ok2 = is_valid(desc, buf2);

	if (!ok1 && !ok2)
		return PURSE_ERROR_INVALID;

	val1 = buf1[4] | buf1[5] << 8 | buf1[6] << 16 | buf1[7] << 24;
	val2 = buf2[4] | buf2[5] << 8 | buf2[6] << 16 | buf2[7] << 24;
	
	cnt1 = buf1[8] | buf1[9] << 8 | buf1[10] << 16 | buf1[11] << 24;
	cnt2 = buf2[8] | buf2[9] << 8 | buf2[10] << 16 | buf2[11] << 24;

	prv1 = buf1[12] | buf1[13] << 8 | buf1[14] << 16 | buf1[15] << 24;
	prv2 = buf2[12] | buf2[13] << 8 | buf2[14] << 16 | buf2[15] << 24;

	if (!((ok2 && cnt2 == cnt3) || 
				(ok1 && cnt1 + 1 == cnt3) || 
				(ok1 && ok2 && cnt1 == cnt2)))
		return PURSE_ERROR_INVALID;


	if (ok1 && ok2 && cnt1 == cnt2 && val1 == val2 && prv1 == prv2 && cnt2 == cnt3)
	{
		/* Sate 0 & 6 */
		*value = val1;
		*counter = cnt1;
		return PURSE_OK;
	}
	
	int last_block;
	int32_t new_cnt = cnt3, new_val, new_prv;
	if (ok2 && cnt2 == cnt3)
	{
		last_block = 1; /* State 1 & 2 */
		new_val = val2;
		new_prv = prv2;
	}
	else if (ok1 && cnt1 == cnt3 - 1)
	{
		last_block = 2; /* State 3 & 4 */
		new_val = prv1;
		new_prv = prv1;
	}
	else if (ok1 && ok2 && cnt1 == cnt2 && val1 == val2 && prv1 == prv2)
	{
		last_block = 2; /* State 5 */
		new_val = prv1;
		new_prv = prv1;
	}
	else
		return PURSE_ERROR_INVALID;

	int ret;
	if (last_block >= 2)
	{
		ret = purse_crypt(handle, tag, desc, 1, new_val, new_cnt, new_prv);
		if (ret != PURSE_OK)
			return ret;
	}

	ret = purse_crypt(handle, tag, desc, 0, new_val, new_cnt, new_prv);
	if (ret != PURSE_OK)
		return ret;

	*value = new_val;
	*counter = new_cnt;
	return PURSE_OK;
}

int purse_init(int handle, mifare_tag_t *tag, purse_desc_t *desc)
{
	int block = desc->sector * 4;
	int ret;

	if (mifare_select(handle, tag))
		return PURSE_ERROR_SELECT;
	if (mifare_login(handle, desc->sector, desc->key_type, desc->key))
		return PURSE_ERROR_LOGIN;
	
	ret = purse_crypt(handle, tag, desc, 0, 0, 0, 0);
	if (ret != PURSE_OK)
		return ret;

	ret = purse_crypt(handle, tag, desc, 1, 0, 0, 0);
	if (ret != PURSE_OK)
		return ret;

	if (mifare_write_value(handle, block + 2,  0))
		return PURSE_ERROR_WRITE_VALUE;

	return PURSE_OK;
}

int purse_inc(int handle, mifare_tag_t *tag, purse_desc_t *desc,
		int32_t inc_value, int32_t *result, int32_t *counter)
{
	int block = desc->sector * 4;
	int ret;

	ret = purse_verify(handle, tag, desc, result, counter);
	if (ret != PURSE_OK)
		return ret;
	
	int32_t prv = *result;
	*result += inc_value;
	*counter = *counter - 1;

	ret = purse_crypt(handle, tag, desc, 0, *result, *counter, prv);
	if (ret != PURSE_OK)
		return ret;

	ret = purse_crypt(handle, tag, desc, 1, *result, *counter, prv);
	if (ret != PURSE_OK)
		return ret;

	if (mifare_dec_value(handle, block + 2, 1))
		return PURSE_ERROR_INC_VALUE;

	return PURSE_OK;
}

int purse_dec(int handle, mifare_tag_t *tag, purse_desc_t *desc,
		int32_t dec_value, int32_t *result, int32_t *counter)
{
	int block = desc->sector * 4;
	int ret;

	ret = purse_verify(handle, tag, desc, result, counter);
	if (ret != PURSE_OK)
		return ret;

	int32_t prv = *result;
	*result -= dec_value;
	*counter = *counter - 1;

	ret = purse_crypt(handle, tag, desc, 0, *result, *counter, prv);
	if (ret != PURSE_OK)
		return ret;

	ret = purse_crypt(handle, tag, desc, 1, *result, *counter, prv);
	if (ret != PURSE_OK)
		return ret;

	if (mifare_dec_value(handle, block + 2, 1))
		return PURSE_ERROR_INC_VALUE;

	return PURSE_OK;
}

int purse_read(int handle, mifare_tag_t *tag, purse_desc_t *desc,
		int32_t *value, int32_t *counter)
{
	return purse_verify(handle, tag, desc, value, counter);
}

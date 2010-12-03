#include <string.h>
#include "id.h"
#include "aes256.h"

int id_init(int handle, const id_desc_t *desc, mifare_tag_t *tag,
		const void *id, int32_t counter)
{
	int i, block = desc->sector * 4;

	/* Generate per card key */
	uint8_t aes_key[32];
	memcpy(aes_key, desc->aes_key, 32);
	for (i = 0; i < 32; i++)
		aes_key[i] ^= tag->serial[i & 3];

	/* Prepare buffer */
	uint8_t buf[16];
	memcpy(buf, desc->magic, 4);
	memcpy(&buf[4], id, 12);

	/* Encrypt buffer */
	aes256_context aes;
	aes256_init(&aes, aes_key);
	aes256_encrypt_ecb(&aes, buf);
	aes256_done(&aes);

	if (mifare_select(handle, tag))
		return ID_ERROR_SELECT;
	if (mifare_login(handle, desc->sector, desc->key_type, desc->key))
		return ID_ERROR_LOGIN;
	if (mifare_write_block(handle, block + 1,  buf))
		return ID_ERROR_WRITE_BLOCK;
	if (mifare_write_value(handle, block + 2, 0))
		return ID_ERROR_WRITE_VALUE;

	return ID_OK;
}

int id_read(int handle, const id_desc_t *desc, mifare_tag_t *tag,
		void *id, int32_t *counter)
{
	int i, block = desc->sector * 4;

	/* Generate per card key */
	uint8_t aes_key[32];
	memcpy(aes_key, desc->aes_key, 32);
	for (i = 0; i < 32; i++)
		aes_key[i] ^= tag->serial[i & 3];

	uint8_t buf[16];

	if (mifare_select(handle, tag))
		return ID_ERROR_SELECT;
	if (mifare_login(handle, desc->sector, desc->key_type, desc->key))
		return ID_ERROR_LOGIN;
	if (mifare_read_block(handle, block + 1, buf))
		return ID_ERROR_READ_BLOCK;

	/* Decrypt block */
	aes256_context ctx;
	aes256_init(&ctx, aes_key);
	aes256_decrypt_ecb(&ctx, buf);
	aes256_done(&ctx);

	if (memcmp(buf, desc->magic, 4) != 0)
		return ID_ERROR_INVALID_MAGIC;
	if (mifare_dec_value(handle, block + 2, 1))
		return ID_ERROR_DEC_VALUE;
	if (mifare_read_value(handle, block + 2, counter))
		return ID_ERROR_READ_VALUE;

	memcpy(id, &buf[4], 12);

	return ID_OK;
}

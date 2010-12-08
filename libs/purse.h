#ifndef _PURSE_H_
#define _PUSRE_H_

#include "mifare.h"

enum
{
	PURSE_OK                =  0,
	PURSE_ERROR_SELECT      = -1,
	PURSE_ERROR_LOGIN       = -2,
	PURSE_ERROR_WRITE_VALUE = -3,
	PURSE_ERROR_WRITE_BLOCK = -4,
	PURSE_ERROR_READ_VALUE  = -5,
	PURSE_ERROR_READ_BLOCK  = -6,
	PURSE_ERROR_INVALID     = -7,
	PURSE_ERROR_INC_VALUE   = -8,
	PURSE_ERROR_DEC_VALUE   = -9,
};

typedef struct purse_desc
{
	int sector;
	uint8_t key[6];
	int key_type;
	uint8_t magic[4];
	uint8_t aes_key[32];
} purse_desc_t;

int purse_init(int handle, mifare_tag_t *tag, purse_desc_t *desc);
int purse_inc(int handle, mifare_tag_t *tag, purse_desc_t *desc,
		int32_t inc_value, int32_t *result, int32_t *counter);
int purse_dec(int handle, mifare_tag_t *tag, purse_desc_t *desc,
		int32_t dec_value, int32_t *result, int32_t *counter);
int purse_read(int handle, mifare_tag_t *tag, purse_desc_t *desc,
		int32_t *value, int32_t *counter);

#endif

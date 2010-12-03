#ifndef _ID_H_
#define _ID_H_

/**
 * Structure for ID application.
 *
 * Needed sector: 1
 *
 * Block 0: unused (fill with random data)
 * Block 1: AES(Key ^ (UID * 4), 4 bytes magic + 12 bytes ID), read only
 * Block 2: Usage counter, read & decrement only
 * Block 3: Access bits
 */

#include "mifare.h"

#define ID_MAX_SIZE 12

enum
{
	ID_OK                  =  0,
	ID_ERROR_SELECT        = -1,
	ID_ERROR_LOGIN         = -2,
	ID_ERROR_WRITE_BLOCK   = -3,
	ID_ERROR_WRITE_VALUE   = -4,
	ID_ERROR_READ_BLOCK    = -5,
	ID_ERROR_READ_VALUE    = -6,
	ID_ERROR_DEC_VALUE     = -7,
	ID_ERROR_INVALID_MAGIC = -8,
};

typedef struct id_desc
{
	int sector;          /* Sector to put our ID into */
	uint8_t key[6];      /* Key for login to sector */
	int key_type;        /* Key type: 0 => key A, 1 => key B */
	uint8_t magic[4];    /* Application magic number, first 4 bytes of block 1 */
	uint8_t aes_key[32]; /* AES key to encrpyt/decrypt block 1 */
} id_desc_t;

int id_init(int handle, const id_desc_t *desc, mifare_tag_t *tag,
		const void *id, int32_t counter);
int id_read(int handle, const id_desc_t *desc, mifare_tag_t *tag,
		void *id, int32_t *counter);

#endif

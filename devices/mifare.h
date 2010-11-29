#ifndef _MIFARE_H_
#define _MIFARE_H_

#include <stdint.h>

typedef struct
{
	char *device;
	int baud;
	int sid;
} mifare_dev_t;

enum 
{
	MIFARE_KEY_TYPE_A,
	MIFARE_KEY_TYPE_B
};

#define MIFARE_MAX_SERIAL_SIZE 10
#define MIFARE_BLOCK_SIZE      16

typedef struct
{
	uint8_t type;
	uint8_t serial[MIFARE_MAX_SERIAL_SIZE];
	uint8_t size;
} mifare_tag_t;

typedef struct
{
	int (*open)(mifare_dev_t *dev);
	int (*close)(int handle);
	
	int (*detect)(int handle, mifare_tag_t *tags, int *count);
	int (*select)(int handle, mifare_tag_t *tag);

	int (*login)(int handle, uint8_t sector, int key_type, const void *key);
	int (*login_stored)(int handle, uint8_t sector, int key_type, int key_no);

	int (*read_block)(int handle, uint8_t block, void *data);
	int (*write_block)(int handle, uint8_t block, void *data);

	int (*read_value)(int handle, uint8_t block, int32_t *value);
	int (*write_value)(int handle, uint8_t block, int32_t value);

	int (*inc_value)(int handle, uint8_t block, int32_t value);
	int (*dec_value)(int handle, uint8_t block, int32_t value);
	int (*copy_value)(int handle, uint8_t from, uint8_t to);

	int (*write_key)(int handle, int num, const void *key);

	int (*beep)(int handle, int msec);

} mifare_ops_t;

extern mifare_ops_t *mifare_ops;

int mifare_open(mifare_dev_t *dev);
int mifare_close(int handle);

int mifare_detect(int handle, mifare_tag_t *tags, int *count);
int mifare_select(int handle, mifare_tag_t *tag);

int mifare_login(int handle, uint8_t sector, int type, const void *key);
int mifare_login_stored(int handle, uint8_t sector, int type, int key_no);

int mifare_read_block(int handle, uint8_t block, void *data);
int mifare_write_block(int handle, uint8_t block, void *data);

int mifare_read_value(int handle, uint8_t block, int32_t *value);
int mifare_write_value(int handle, uint8_t block, int32_t value);

int mifare_inc_value(int handle, uint8_t block, int32_t value);
int mifare_dec_value(int handle, uint8_t block, int32_t value);
int mifare_copy_value(int handle, uint8_t from, uint8_t to);

int mifare_write_key(int handle, int num, const void *key);

int mifare_beep(int handle, int msec);

#endif

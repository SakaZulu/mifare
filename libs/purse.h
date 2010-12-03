#ifndef _PURSE_H_
#define _PUSRE_H_

#include "mifare.h"

typedef struct purse_desc
{
	int sector1;
	int sector2;
	char key1[6];
	char key2[6];
	int key_type1;
	int key_type2;
} purse_desc_t;

int init_purse(int handle, mifare_tag_t *tag, purse_desc_t *desc);

#endif

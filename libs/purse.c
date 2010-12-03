#include "purse.h"

int init_purse(int handle, mifare_tag_t *tag, purse_desc_t *desc)
{
	if (mifare_select(handle, tag))
		return 1;

	mifare_login(handle, desc->sector1, desc->key_type1, desc->key1);
	mifare_write
}

#endif

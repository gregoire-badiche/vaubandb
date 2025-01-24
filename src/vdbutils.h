#ifndef VDB_UTILS
#define VDB_UTILS

#include "vdbconsts.h"

vdb_status_t buffer_eq(uint8_t *buffer_1, uint8_t *buffer_2, uint32_t size);

vdb_status_t aes_kdf(vdb_t *db, uint8_t *key, uint32_t key_size, uint8_t *derived_key);

#endif
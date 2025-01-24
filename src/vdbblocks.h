#ifndef VDB_BLOCKS
#define VDB_BLOCKS

#include "vdbconsts.h"

vdb_status_t decrypt_block(vdb_t *db, uint32_t block_padding, uint8_t **result_buffer);

vdb_status_t get_block_size(vdb_t *db, uint32_t padding, uint32_t *size);

vdb_status_t check_block_hash(vdb_t *db, uint32_t block_padding);

vdb_status_t check_db_hash(vdb_t *db);

#endif
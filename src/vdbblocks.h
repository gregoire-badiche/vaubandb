#ifndef VDB_BLOCKS
#define VDB_BLOCKS

#include "vdbconsts.h"

status_t read_data(vdb_t *db, uint32_t padding, uint32_t size, uint8_t *result);

status_t check_db_integrity(vdb_t *db);

#endif
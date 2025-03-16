#ifndef VDB_DATA
#define VDB_DATA

#include "vdbblocks.h"

void read_chunk(vdb_t *db, uint32_t padding, uint32_t size, uint8_t *chunk);

void write_chunk(vdb_t *db, uint32_t padding, uint32_t size, uint8_t *chunk);

void write_item(vdb_t *db, vdb_item_t item_type, void *item, uint32_t padding);

void read_item(vdb_t *db, vdb_item_t item, uint32_t padding);

#endif
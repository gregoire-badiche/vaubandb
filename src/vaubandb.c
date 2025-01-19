#include <stdlib.h>
#include "vaubandb.h"

vdb_t *create_vdb(vdb_stream_t stream)
{
    uint8_t read_size = 0;

    vdb_t *db = (vdb_t *)calloc(1, sizeof(vdb_t));
    db->stream = stream;

    uint8_t *reading = (uint8_t *)malloc(VDB_HEADER_SIZE);
    if (stream.read(0, VDB_HEADER_SIZE, reading) == vdb_error)
        return NULL;

    uint32_t signature = *((uint32_t *)(reading + read_size));
    read_size += sizeof(uint32_t);
    // Little-endian devices only :(
    if (signature != VDB_FILE_SIGNATURE)
        return NULL;

    // Only version 0.1 supported!!
    uint32_t version = *((uint32_t *)(reading + read_size));
    read_size += sizeof(uint32_t);
    if (version != 0x00000001)
        return NULL;
    
    for (uint8_t i = 0; i < VDB_SALT_SIZE; i++)
    {
        db->salt[i] = *(reading + read_size);
        read_size += sizeof(uint8_t);
    }

    db->kdf_rounds = *((uint64_t *)(reading + read_size));
    read_size += sizeof(uint64_t);

    for (uint8_t i = 0; i < VDB_IV_SIZE; i++)
    {
        db->iv[i] = *(reading + read_size);
        read_size += sizeof(uint8_t);
    }

    db->has_compression = *(reading + read_size);
    read_size += sizeof(uint8_t);

    db->block_size = *((uint32_t *)(reading + read_size));
    read_size += sizeof(uint32_t);

    db->block_stream_start = *((uint32_t *)(reading + read_size));
    read_size += sizeof(uint32_t);

    db->n_blocks = *((uint32_t *)(reading + read_size));
    read_size += sizeof(uint32_t);
}

void delete_vdb(vdb_t *db)
{
}

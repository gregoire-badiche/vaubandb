#include <stdlib.h>
#include "vaubandb.h"

uint8_t buffer_eq(uint8_t *buffer_1, uint8_t *buffer_2, uint32_t size);

uint8_t buffer_eq(uint8_t *buffer_1, uint8_t *buffer_2, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++)
    {
        if (buffer_1[i] != buffer_2[i])
            return 0;
    }
    return 1;
}

vdb_t *load_vdb(vdb_stream_t stream, vdb_crypto_fn_t crypto)
{
    uint8_t read_size = 0;

    vdb_t *db = (vdb_t *)calloc(1, sizeof(vdb_t));
    db->stream = stream;
    db->crypto = crypto;

    uint8_t *reading = (uint8_t *)malloc(VDB_TOT_HEADER_SIZE);
    if (stream.read(0, VDB_TOT_HEADER_SIZE, reading) == vdb_error)
        return NULL;

    uint32_t signature = *((uint32_t *)(reading + read_size));
    read_size += sizeof(uint32_t);
    // Little-endian devices only :(
    if (signature != VDB_FILE_SIGNATURE)
    {
        free(db);
        free(reading);
        return NULL;
    }

    // Only version 0.1 supported!!
    uint32_t version = *((uint32_t *)(reading + read_size));
    read_size += sizeof(uint32_t);
    if (version != 0x00000001)
    {
        free(db);
        free(reading);
        return NULL;
    }
    
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

    if (*((uint32_t *)(reading + read_size)) != 0)
    {
        free(db);
        free(reading);
        return NULL;
    }

    read_size += sizeof(uint32_t);

    uint8_t *header_hash_read = ((uint8_t *)(reading + read_size));
    uint8_t *header_hash_computed = (uint8_t *)malloc(sizeof(uint8_t) * 32);

    crypto.sha_256(VDB_HEADER_SIZE, read_size, header_hash_computed);

    if (buffer_eq(header_hash_read, header_hash_computed, 32) == 0)
    {
        free(db);
        free(reading);
        free(header_hash_computed);
        return NULL;
    }

    db->locked = 1;

    free(reading);
    free(header_hash_computed);
    return db;
}

void delete_vdb(vdb_t **db)
{
    free(*db);
    *db = NULL;
}

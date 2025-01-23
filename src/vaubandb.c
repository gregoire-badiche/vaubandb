#include <stdlib.h>
#include "vaubandb.h"

vdb_status_t buffer_eq(uint8_t *buffer_1, uint8_t *buffer_2, uint32_t size);

vdb_status_t decrypt_block(vdb_t *db, uint32_t block_padding, uint8_t **result_buffer);

vdb_status_t check_block_index(vdb_t *db, uint32_t block_padding);

vdb_status_t buffer_eq(uint8_t *buffer_1, uint8_t *buffer_2, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++)
    {
        if (buffer_1[i] != buffer_2[i])
            return vdb_error;
    }
    return vdb_success;
}

vdb_status_t load_vdb(vdb_stream_t stream, vdb_crypto_fn_t crypto, vdb_t **result_db)
{
    uint8_t read_size = 0;

    vdb_t *db = (vdb_t *)calloc(1, sizeof(vdb_t));
    vdb_header_t *header = (vdb_header_t *)malloc(sizeof(vdb_header_t));

    if (db == NULL || header == NULL)
        return vdb_malloc_error;

    if (stream.read(0, VDB_TOT_HEADER_SIZE, (uint8_t)header) == vdb_couldnt_read)
    {
        free(db);
        free(header);
        return vdb_couldnt_read;
    }

    uint8_t hash_computed[32];

    crypto.sha_256(VDB_HEADER_SIZE, header, hash_computed);

    if (buffer_eq(hash_computed, header->hash, 32) == vdb_error)
    {
        free(db);
        free(header);
        return vdb_hash_error;
    }

    db->stream = stream;
    db->crypto = crypto;
    db->header = header;
    db->locked = 1;

    *result_db = db;

    return vdb_success;
}

vdb_status_t check_block_index(vdb_t *db, uint32_t block_padding)
{
    //! POSSIBLE INTEGER OVERFLOW
    uint32_t block_size = db->header->block_size + sizeof(uint8_t) * 32 + sizeof(uint32_t); // HMAC (256) + size (32)
    if ((block_padding - VDB_BLOCK_STREAM_START) % block_size == 0)
        return vdb_success;
    return vdb_error;
}

vdb_status_t unlock_vdb(vdb_t *db, char *passphrase)
{
}

vdb_status_t check_block_hmac(vdb_t *db, uint32_t block_padding)
{
    if (db->locked)
        return vdb_error;

    if (check_block_index(db, block_padding) == vdb_error)
        return vdb_couldnt_read;

    uint8_t hmac_read[32];

    if (db->stream.read(block_padding, sizeof(uint8_t) * 32, hmac_read) == vdb_couldnt_read)
    {
        free(hmac_read);
        return vdb_couldnt_read;
    }

    uint32_t block_size;

    block_padding += sizeof(uint8_t) * 32;

    if (db->stream.read(block_padding, sizeof(uint32_t), &block_padding) == vdb_couldnt_read)
    {
        free(hmac_read);
        return vdb_couldnt_read;
    }

    block_padding += sizeof(uint32_t);

    uint8_t *reading = (uint8_t *)malloc(block_size * sizeof(uint32_t));

    if (reading == NULL)
    {
        return vdb_malloc_error;
    }

    if (db->stream.read(block_padding, block_size, reading) == vdb_couldnt_read)
    {
        free(reading);
        return vdb_couldnt_read;
    }

    uint8_t hmac_computed[32];

    db->crypto.hmac_sha_256(32, db->key, block_size, reading, hmac_computed);

    free(reading);

    if (buffer_eq(hmac_computed, hmac_read, 32) == vdb_success)
    {
        return vdb_success;
    }
    else
    {
        return vdb_hash_error;
    }
}

vdb_status_t decrypt_block(vdb_t *db, uint32_t block_padding, uint8_t **result_buffer)
{
    vdb_status_t res = check_block_hmac(db, block_padding);
    if (res != vdb_success)
        return res;

    block_padding += sizeof(uint8_t) * 32 + sizeof(uint32_t);

    
}

void delete_vdb(vdb_t **db)
{
    free((*db)->header);
    free(*db);
    *db = NULL;
}

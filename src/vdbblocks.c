#include <stdlib.h>
#include "vdbblocks.h"

vdb_status_t get_block_hash(vdb_t *db, uint32_t padding, uint8_t *hash);

vdb_status_t get_block_data(vdb_t *db, uint32_t padding, uint32_t size, uint8_t *encrypted_data);

vdb_status_t check_block_index(vdb_t *db, uint32_t block_padding);

vdb_status_t check_block_index(vdb_t *db, uint32_t block_padding)
{
    //! POSSIBLE INTEGER OVERFLOW
    uint32_t block_size = db->header->block_size + sizeof(uint8_t) * 32 + sizeof(uint32_t); // HMAC (256) + size (32)
    if ((block_padding - VDB_BLOCK_STREAM_START) % block_size == 0)
        return vdb_success;
    return vdb_error;
}

vdb_status_t check_block_hash(vdb_t *db, uint32_t block_padding)
{
    if (check_block_index(db, block_padding) == vdb_error)
        return vdb_couldnt_read;

    uint8_t hmac_read[32];

    if (get_block_hash(db, block_padding, hmac_read) == vdb_couldnt_read)
    {
        free(hmac_read);
        return vdb_couldnt_read;
    }

    uint32_t block_size;

    if (get_block_size(db, block_padding, &block_size) == vdb_couldnt_read)
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

    db->crypto.hmac_sha_256(db->crypto_data, 32, db->key, block_size, reading, hmac_computed);

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
    vdb_status_t res = check_block_hash(db, block_padding);
    if (res != vdb_success)
        return res;

    uint32_t block_size;

    res = get_block_size(db, block_padding, &block_size);
    if (res != vdb_success)
        return res;

    uint8_t *encrypted_data = (uint8_t *)malloc(block_size);
    if (encrypted_data == NULL)
        return vdb_malloc_error;

    res = get_block_data(db, block_padding, block_size, encrypted_data);
    if (res != vdb_success)
    {
        free(encrypted_data);
        return res;
    }

    uint8_t *decrypted_data = (uint8_t *)malloc(block_size);
    db->crypto.chacha20(db->crypto_data, db->key, block_size, encrypted_data, decrypted_data);

    *result_buffer = decrypted_data;
}

vdb_status_t check_db_hash(vdb_t *db)
{
    uint32_t padding = VDB_BLOCK_STREAM_START;
    uint32_t block_size = 1;
    uint32_t block_counter = 0;
    uint32_t wrong_hash_counter = 0;
    vdb_status_t res;

    while (block_size != 0)
    {
        get_block_size(db, padding, &block_size);
        res = check_block_hash(db, padding);
        padding += VDB_BLOCK_HEADER_SIZE + block_size;
        if (res != vdb_success)
        {
            wrong_hash_counter++;
        }
        block_counter++;
    }

    if (wrong_hash_counter == 0)
        return vdb_success;
    if (wrong_hash_counter == block_counter)
        return vdb_couldnt_read;
    return vdb_hash_error;
}

vdb_status_t get_block_size(vdb_t *db, uint32_t padding, uint32_t *size)
{
    return db->stream.read(padding + 32, sizeof(uint32_t), (uint8_t *)size);
}

vdb_status_t get_block_hash(vdb_t *db, uint32_t padding, uint8_t *hash)
{
    return db->stream.read(padding, sizeof(uint8_t) * 32, hash);
}

vdb_status_t get_block_data(vdb_t *db, uint32_t padding, uint32_t size, uint8_t *encrypted_data)
{
    return db->stream.read(padding + VDB_BLOCK_HEADER_SIZE, size, encrypted_data);
}

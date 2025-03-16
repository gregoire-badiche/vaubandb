#include <stdlib.h>
#include "vdbblocks.h"

// uint8_t check_block_padding(vdb_t *db, uint32_t block_padding);

// uint32_t get_block_index(vdb_t *db, uint32_t padding);

// void compute_block_key(vdb_t *db, uint32_t block_padding, uint8_t *key);

// uint8_t check_block_padding(vdb_t *db, uint32_t block_padding)
// {
//     //! POSSIBLE INTEGER OVERFLOW
//     uint32_t block_size = db->header->block_size + sizeof(uint8_t) * 32 + sizeof(uint32_t); // HMAC (256) + size (32)
//     if ((block_padding - VDB_BLOCK_STREAM_START) % block_size == 0)
//         return 1;

//     return 0;
// }

// uint32_t get_block_index(vdb_t *db, uint32_t padding)
// {
//     padding -= VDB_BLOCK_STREAM_START;
//     return (uint32_t)(padding / db->header->block_size);
// }

// void compute_block_key(vdb_t *db, vdb, uint8_t *key)
// {
//     uint8_t first_hash[64 + 32];
//     uint8_t first_hash_data[65];

//     for (uint8_t i = 0; i < 32; i++)
//     {
//         first_hash_data[i] = db->header->salt[i];
//         first_hash_data[i + 32] = db->key;
//     }
//     first_hash_data[64] = 0x01;

//     db->crypto.sha_512(db->crypto_data, 65, first_hash_data, first_hash + 32);

//     *((uint32_t *)first_hash) = get_block_index(db, block_padding);

//     db->crypto.sha_512(db->crypto_data, 64 + 32, first_hash, key);

//     return;
// }

// status_t check_block_hash(vdb_t *db, uint32_t block_padding)
// {
//     if(!check_block_padding(db, block_padding))
//         return error;

//     uint8_t hmac_read[32];

//     status_t res = get_block_hash(db, block_padding, hmac_read);

//     if (res != success)
//     {
//         return res;
//     }

//     int32_t block_size = get_block_size(db, block_padding);
    
//     if (block_size < 0) // Error reading the block size !
//     {
//         return error;
//     }

//     block_padding += sizeof(uint32_t);

//     uint8_t *reading = (uint8_t *)malloc(block_size * sizeof(uint32_t));

//     if (reading == NULL)
//     {
//         free(hmac_read);
//         free(reading);
//         return malloc_error;
//     }

//     res = db->stream.read(block_padding, block_size, reading);

//     if (res != success) {
//         free(reading);
//         return res;
//     }

//     uint8_t block_key[64];

//     compute_block_key(db, block_padding, block_key);

//     uint8_t hmac_computed[32];

//     db->crypto.hmac_sha_256(db->crypto_data, 64, block_key, block_size, reading, hmac_computed);

//     free(reading);

//     if(buffer_eq(hmac_computed, hmac_read, 32))
//     {
//         return success;
//     }
//     else
//     {
//         return error;
//     }
// }

// status_t decrypt_block(vdb_t *db, uint32_t block_padding, uint8_t **result_buffer)
// {
//     status_t res = check_block_hash(db, block_padding);
    
//     if (res != success)
//         return res;

//     uint32_t block_size = get_block_size(db, block_padding);

//     uint8_t *encrypted_data = (uint8_t *)malloc(block_size);
//     if (encrypted_data == NULL)
//         return malloc_error;

//     status_t res = get_block_data(db, block_padding, block_size, encrypted_data);
    
//     if (res != success)
//     {
//         free(encrypted_data);
//         return res;
//     }

//     uint8_t *decrypted_data = (uint8_t *)malloc(block_size);
//     db->crypto.chacha20(db->crypto_data, db->content_key, block_size, encrypted_data, decrypted_data);

//     *result_buffer = decrypted_data;

//     free(encrypted_data);
    
//     return success;
// }

// status_t check_db_hash(vdb_t *db)
// {
//     uint32_t padding = VDB_BLOCK_STREAM_START;
//     uint32_t block_size = 1;
//     status_t res;

//     do
//     {
//         block_size = get_block_size(db, padding);
//         if (block_size < 0)
//             return error;
//         res = check_block_hash(db, padding);
//         padding += VDB_BLOCK_HEADER_SIZE + block_size;
//         if (res != success)
//             return res;
//     } while (block_size != 0);

//     return success;
// }

// uint32_t get_block_size(vdb_t *db, uint32_t padding)
// {
//     uint32_t size;
//     status_t res = db->stream.read(padding + 32, sizeof(uint32_t), (uint8_t *)(&size));
    
//     if (res != success)
//         return res;
    
//     return size;
// }

// status_t get_block_hash(vdb_t *db, uint32_t padding, uint8_t *hash)
// {
//     db->stream.read(padding, sizeof(uint8_t) * 32, hash);
//     return;
// }

// status_t get_block_data(vdb_t *db, uint32_t padding, uint32_t size, uint8_t *encrypted_data)
// {
//     db->stream.read(padding + VDB_BLOCK_HEADER_SIZE, size, encrypted_data);
//     return success;
// }

status_t decrypt_block(vdb_t *db, vdb_encrypted_block_t *block, uint8_t *result);

uint8_t check_block_hash(vdb_t *db, vdb_encrypted_block_t *block);

status_t read_data(vdb_t *db, uint32_t padding, uint32_t size, uint8_t *result)
{
    if (db->locked)
        return error;
    
    vdb_encrypted_block_t block;
    uint32_t n_bits_wrote = 0;
    while (n_bits_wrote < size)
    {
        status_t res = db->stream.read(padding, sizeof(block), &block);
        if (res != success)
            return res;
        
        res = decrypt_block(db, &block, result);
    }
}

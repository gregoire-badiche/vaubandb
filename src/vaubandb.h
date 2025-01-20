#ifndef VAUBANDB_H
#define VAUBANDB_H

#include <stdint.h>

#define DEFAULT_BLOCK_SIZE 0x100000
#define VDB_HEADER_SIZE 93
#define VDB_TOT_HEADER_SIZE 93
#define VDB_FILE_SIGNATURE 0x76617562
#define VDB_SALT_SIZE 32
#define VDB_IV_SIZE 12

typedef enum
{
    vdb_success,
    vdb_error
} vdb_error_t;

typedef struct
{
    vdb_error_t (*read)(uint32_t start, uint32_t size, uint8_t *bytes);
    vdb_error_t (*write)(uint32_t start, uint32_t size, uint8_t *bytes);
} vdb_stream_t;

typedef struct
{
    void (*aes_256)();
    void (*sha_256)(uint32_t size, uint8_t *data, uint8_t *hash);
    void (*chacha20)();
    void (*hmac_sha_256)();
} vdb_crypto_fn_t;

typedef struct
{
    vdb_stream_t stream;
    vdb_crypto_fn_t crypto;
    uint8_t salt[32];
    uint64_t kdf_rounds;
    uint8_t iv[12];
    uint8_t has_compression;
    uint32_t block_size;
    uint32_t block_stream_start;
    uint32_t n_blocks;
    uint8_t locked;
    uint8_t key[32];
    uint64_t unlock_time;
} vdb_t;

typedef enum
{
    entry,
    folder
} vdb_item_t;

vdb_t *load_vdb(vdb_stream_t stream, vdb_crypto_fn_t crypto);

void delete_vdb(vdb_t **db);

#endif

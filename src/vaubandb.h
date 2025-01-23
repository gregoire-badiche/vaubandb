#ifndef VAUBANDB_H
#define VAUBANDB_H

#include <stdint.h>

#define DEFAULT_BLOCK_SIZE 0x100000
#define VDB_HEADER_SIZE 93
#define VDB_TOT_HEADER_SIZE 93
#define VDB_BLOCK_STREAM_START VDB_TOT_HEADER_SIZE
#define VDB_FILE_SIGNATURE 0x76617562
#define VDB_SALT_SIZE 32
#define VDB_IV_SIZE 12

#pragma pack(push, 1) // Ensure structure data packing

typedef enum
{
    vdb_success,
    vdb_error,
    vdb_couldnt_read,
    vdb_hash_error,
    vdb_malloc_error,
} vdb_status_t;

typedef struct
{
    vdb_status_t (*read)(uint32_t start, uint32_t size, uint8_t *bytes);
    vdb_status_t (*write)(uint32_t start, uint32_t size, uint8_t *bytes);
} vdb_stream_t;

typedef struct
{
    void (*aes_256)();
    void (*sha_256)(uint32_t size, uint8_t *data, uint8_t *hash);
    void (*chacha20)();
    void (*hmac_sha_256)(uint32_t key_size, uint8_t *key, uint32_t data_size, uint8_t *data, uint8_t *hash);
} vdb_crypto_fn_t;

typedef struct
{
    uint32_t file_signature;
    uint32_t format_version;
    int8_t salt[32];
    uint32_t kdf_rounds;
    int8_t iv[12];
    uint8_t has_compression;
    uint32_t block_size;
    uint32_t n_blocks;
    uint32_t end_of_header;
    int8_t hash[32];
} vdb_header_t;

typedef struct
{
    vdb_header_t *header;
    vdb_crypto_fn_t crypto;
    vdb_stream_t stream;
    uint8_t locked;
    uint8_t key[32];
    uint64_t unlock_time;
} vdb_t;

typedef enum
{
    entry,
    folder
} vdb_item_t;

vdb_status_t load_vdb(vdb_stream_t stream, vdb_crypto_fn_t crypto, vdb_t **result_db);

vdb_status_t unlock_vdb(vdb_t *db, char *passphrase);

void delete_vdb(vdb_t **db);

#endif

#ifndef VDB_CONSTS
#define VDB_CONSTS

#include <stdint.h>

#define BLOCK_DATA_SIZE 0x100000
#define VDB_HEADER_SIZE 72
#define VDB_TOT_HEADER_SIZE 104
#define VDB_BLOCK_STREAM_START VDB_TOT_HEADER_SIZE
#define VDB_BLOCK_HEADER_SIZE 36
#define VDB_FILE_SIGNATURE 0x76617562
#define VDB_SALT_SIZE 32
#define VDB_IV_SIZE 12

#pragma pack(push, 1) // Ensure structure data packing

typedef enum
{
    success,
    error,
    couldnt_read,
    hash_error,
    malloc_error,
    password_error
} status_t;

static status_t vdb_errno = success;
static char *vdb_last_error_message;

typedef struct
{
    status_t (*read)(uint32_t start, uint32_t size, uint8_t *bytes);
    status_t (*write)(uint32_t start, uint32_t size, uint8_t *bytes);
} vdb_stream_t;

typedef struct
{
    void *(*gen_crypto_data)();
    void (*aes_256_set_key)(void *crypto_data, uint32_t size, uint8_t *key);
    void (*aes_256)(void *crypto_data, uint32_t size, uint8_t *data, uint8_t *result);
    void (*sha_256)(void *crypto_data ,uint32_t size, uint8_t *data, uint8_t *hash);
    void (*sha_512)(void *crypto_data ,uint32_t size, uint8_t *data, uint8_t *hash);
    void (*chacha20)(void *crypto_data, uint8_t *key, uint32_t data_size, uint8_t *encrypted_data, uint8_t *decrypted_data);
    void (*hmac_sha_256)(void *crypto_data, uint32_t key_size, uint8_t *key, uint32_t data_size, uint8_t *data, uint8_t *hash);
} vdb_crypto_fn_t;

typedef struct
{
    uint32_t file_signature;
    uint32_t format_version;
    int8_t salt[32];
    uint32_t kdf_rounds;
    int8_t iv[12];
    uint32_t has_compression;
    uint32_t block_size;
    uint32_t n_blocks;
    uint32_t end_of_header;
    int8_t hash[32];
    int8_t hmac[32];
} vdb_header_t;

typedef struct
{
    uint8_t hash[32];
    uint8_t data[BLOCK_DATA_SIZE];
} vdb_encrypted_block_t;

typedef struct
{
    vdb_header_t *header;
    vdb_crypto_fn_t crypto;
    void *crypto_data;
    vdb_stream_t stream;
    uint8_t locked;
    uint8_t key[32];
    uint8_t content_key[32];
    uint64_t unlock_time;
} vdb_t;

typedef enum
{
    entry,
    folder
} vdb_item_t;

#endif
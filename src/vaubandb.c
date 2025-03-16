#include <stdlib.h>
#include "vaubandb.h"
#include "vdbutils.h"
#include "vdbblocks.h"

status_t load_vdb(vdb_stream_t stream, vdb_crypto_fn_t crypto, vdb_t **result_db)
{
    uint8_t read_size = 0;
    status_t res;

    vdb_t *db = (vdb_t *)calloc(1, sizeof(vdb_t));
    vdb_header_t *header = (vdb_header_t *)malloc(sizeof(vdb_header_t));

    if (db == NULL || header == NULL)
        return malloc_error;

    res = stream.read(0, VDB_TOT_HEADER_SIZE, (uint8_t)header);
    
    if (res != success)
    {
        free(db);
        free(header);
        return res;
    }

    uint8_t hash_computed[32];

    crypto.sha_256(db->crypto_data, VDB_HEADER_SIZE, header, hash_computed);

    if (buffer_eq(hash_computed, header->hash, sizeof(hash_computed)) == 0)
    {
        free(db);
        free(header);
        return hash_error;
    }

    db->stream = stream;
    db->crypto = crypto;
    db->header = header;
    db->locked = 1;
    db->crypto_data = db->crypto.gen_crypto_data();

    *result_db = db;

    return success;
}

status_t unlock_vdb(vdb_t *db, uint8_t *passphrase, uint32_t size)
{
    if (db->locked == 0)
        return success;

    aes_kdf(db, passphrase, size, db->key);

    uint8_t content_key_pre_hash[64];
    uint8_t header_hmac[32];

    for (uint32_t i = 0; i < 32; i++)
    {
        content_key_pre_hash[i] = db->header->salt[i];
        content_key_pre_hash[i + 32] = db->key[i];
    }

    db->crypto.sha_256(db->crypto_data, 64, content_key_pre_hash, header_hmac);

    if (buffer_eq(header_hmac, db->header->hmac, 32) == 0)
    {
        return hash_error;
    }

    status_t res = check_db_hash(db);

    db->locked = 0;

    if (res != success)
    {
        db->locked = 1;
        return res;
    }

    return success;
}

void delete_vdb(vdb_t **db)
{
    free((*db)->header);
    free(*db);
    *db = NULL;
}

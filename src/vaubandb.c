#include <stdlib.h>
#include "vaubandb.h"
#include "vdbutils.h"
#include "vdbblocks.h"

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

    crypto.sha_256(db->crypto_data, VDB_HEADER_SIZE, header, hash_computed);

    if (buffer_eq(hash_computed, header->hash, sizeof(hash_computed)) == vdb_error)
    {
        free(db);
        free(header);
        return vdb_hash_error;
    }

    db->stream = stream;
    db->crypto = crypto;
    db->header = header;
    db->locked = 1;
    db->crypto_data = db->crypto.gen_crypto_data();

    *result_db = db;

    return vdb_success;
}

vdb_status_t unlock_vdb(vdb_t *db, uint8_t *passphrase, uint32_t size)
{
    if (db->locked == 0)
        return vdb_success;

    vdb_status_t _ = aes_kdf(db, passphrase, size, db->key);

    uint32_t n_blocks_corrupted = 0;

}

void delete_vdb(vdb_t **db)
{
    free((*db)->header);
    free(*db);
    *db = NULL;
}

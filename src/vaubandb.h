#ifndef VAUBANDB
#define VAUBANDB

#include "vdbconsts.h"

vdb_status_t load_vdb(vdb_stream_t stream, vdb_crypto_fn_t crypto, vdb_t **result_db);

vdb_status_t unlock_vdb(vdb_t *db, uint8_t *passphrase, uint32_t size);

void delete_vdb(vdb_t **db);

#endif

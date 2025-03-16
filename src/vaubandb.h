#ifndef VAUBANDB
#define VAUBANDB

#include "vdbconsts.h"

status_t load_vdb(vdb_stream_t stream, vdb_crypto_fn_t crypto, vdb_t **result_db);

status_t unlock_vdb(vdb_t *db, uint8_t *passphrase, uint32_t size);

void delete_vdb(vdb_t **db);

#endif

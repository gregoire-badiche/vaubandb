#include "vdbutils.h"

uint8_t buffer_eq(uint8_t *buffer_1, uint8_t *buffer_2, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++)
    {
        if (buffer_1[i] != buffer_2[i])
            return 0;
    }
    return 1;
}

void aes_kdf(vdb_t *db, uint8_t *password, uint32_t password_size, uint8_t *derived_key)
{
    int8_t hash[32];

    db->crypto.sha_256(db->crypto_data, password_size, password, hash);

    db->crypto.aes_256_set_key(db->crypto_data, 32, db->header->salt);

    for (uint32_t i = 0; i < db->header->kdf_rounds; i++)
    {
        db->crypto.aes_256(db->crypto_data, 32, hash, hash);
    }

    for (uint32_t i = 0; i < 32; i++)
    {
        derived_key[i] = hash;
    }

    return;
}

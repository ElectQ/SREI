#ifndef SREI_RESOLVE_H
#define SREI_RESOLVE_H

#include <stdint.h>

#define ROTR32(value, shift) (((uint32_t)(value) >> (shift)) | ((uint32_t)(value) << (32 - (shift))))

static inline uint32_t srei_hash_name(const char *name)
{
    uint32_t hash = 0;
    const unsigned char *p = (const unsigned char *)name;

    do {
        hash = ROTR32(hash, 13);
        hash += *p;
        p++;
    } while (*(p - 1) != 0);

    return hash;
}

#endif

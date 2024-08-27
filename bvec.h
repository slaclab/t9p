
#pragma once

#include <stdint.h>
#include <stdlib.h>

typedef struct bvec32 {
    uint32_t* bits;
    uint32_t bit_count;
} bvec32_t;

static void bvec32_init(struct bvec32* bv, uint32_t count) {
    bv->bit_count = count;
    bv->bits = (uint32_t*)calloc((count + 31) / 32, sizeof(uint32_t));
}

static void bvec32_set(struct bvec32* bv, uint32_t bit, int value) {
    if (bit >= bv->bit_count)
        return;
    uint32_t* v = &bv->bits[bit>>5];
    *v = value ? *v | (1 << (bit & 0x1F)) : *v & ~(1<<(bit & 0x1F));
}

static void bvec32_set_pattern(struct bvec32* bv, uint32_t pattern) {
    for (int i = 0; i < bv->bit_count >> 5; ++i)
        bv->bits[i] = pattern;
}

static int bvec32_get(struct bvec32* bv, uint32_t bit) {
    if (bit > bv->bit_count)
        return 0;
    return (bv->bits[bit>>5] >> (bit & 0x1F)) & 0x1;
}

static void bvec32_destroy(struct bvec32* bv) {
    free(bv->bits);
    bv->bits = 0;
    bv->bit_count = 0;
}

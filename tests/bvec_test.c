
#include "../bvec.h"
#include <assert.h>

int main(int argc, char** argv) {
    bvec32_t bv;
    bvec32_init(&bv, 63);

    bvec32_set(&bv, 0, 1);
    bvec32_set(&bv, 62, 1);
    bvec32_set(&bv, 32, 1);
    bvec32_set(&bv, 31, 1);
    assert(bvec32_get(&bv, 0) == 1);
    assert(bvec32_get(&bv, 62) == 1);
    assert(bvec32_get(&bv, 32) == 1);
    assert(bvec32_get(&bv, 31) == 1);
    bvec32_set(&bv, 32, 0);
    assert(bvec32_get(&bv, 32) == 0);
    bvec32_set(&bv, 32, 1);
    assert(bvec32_get(&bv, 32) == 1);

    bvec32_destroy(&bv);
}

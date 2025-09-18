/**
* ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: t9p platform implementation using the POSIX API
 * ----------------------------------------------------------------------------
 * This file is part of 't9p'. It is subject to the license terms in the
 * LICENSE.txt file found in the top-level directory of this distribution,
 * and at:
 *    https://confluence.slac.stanford.edu/display/ppareg/LICENSE.html.
 * No part of 't9p', including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE.txt file.
 * ----------------------------------------------------------------------------
 **/
#include "t9p_platform.h"

#include <malloc.h>

#include <stdlib.h>
#include <string.h>

#ifdef __rtems__
#include <rtems/score/protectedheap.h>
#endif

#if defined(__RTEMS_MAJOR__) && __RTEMS_MAJOR__ < 7
extern Heap_Control* RTEMS_Malloc_Heap;

static size_t
t9p__malloc_usable_size(void* ptr)
{
  if (!ptr) return 0;

  size_t sz = 0;
  _Protected_heap_Get_block_size(RTEMS_Malloc_Heap, ptr, &sz);

  return sz;
}
#define malloc_usable_size t9p__malloc_usable_size
#endif

void*
#if defined(__GNUC__) || defined(__clang__)
__attribute__((malloc, alloc_size(1)))
#endif
t9p_malloc(size_t size)
{
  void* ptr = malloc(size);
#ifndef NO_MEMTRACK
  atomic_add_u32(&g_t9p_memtrack_ctx.total_allocd_bytes, malloc_usable_size(ptr));
  atomic_add_u32(&g_t9p_memtrack_ctx.total_allocd_bytes_requested, size);
  atomic_add_u32(&g_t9p_memtrack_ctx.total_alloc_calls, 1);
#endif
  return ptr;
}

void*
#if defined(__GNUC__) || defined(__clang__)
__attribute__((malloc, alloc_size(1, 2)))
#endif
t9p_calloc(size_t nmeb, size_t size)
{
  void* ptr = calloc(nmeb, size);
#ifndef NO_MEMTRACK
  atomic_add_u32(&g_t9p_memtrack_ctx.total_allocd_bytes, malloc_usable_size(ptr));
  atomic_add_u32(&g_t9p_memtrack_ctx.total_allocd_bytes_requested, nmeb * size);
  atomic_add_u32(&g_t9p_memtrack_ctx.total_alloc_calls, 1);
#endif
  return ptr;
}

void*
#if defined(__GNUC__) || defined(__clang__)
__attribute__((malloc, alloc_size(1)))
#ifndef __rtems__
__attribute__((alloc_align(2)))
#endif
#endif
t9p_aligned_zmalloc(size_t size, size_t align)
{
  void* ptr = NULL;
  posix_memalign(&ptr, align, size);
  if (ptr)
    memset(ptr, 0, size);
#ifndef NO_MEMTRACK
  atomic_add_u32(&g_t9p_memtrack_ctx.total_allocd_bytes, malloc_usable_size(ptr));
  atomic_add_u32(&g_t9p_memtrack_ctx.total_allocd_bytes_requested, size);
  atomic_add_u32(&g_t9p_memtrack_ctx.total_alloc_calls, 1);
#endif
  return ptr;
}

void
t9p_free(void* ptr)
{
  atomic_add_u32(&g_t9p_memtrack_ctx.total_freed_bytes, malloc_usable_size(ptr));
  atomic_add_u32(&g_t9p_memtrack_ctx.total_free_calls, 1);
  free(ptr);
}

#ifndef NO_MEMTRACK

t9p_memtrack_ctx_t g_t9p_memtrack_ctx = {
  0, 0, 0, 0, 0
};

void*
#if defined(__GNUC__) || defined(__clang__)
__attribute__((malloc, alloc_size(1), nonnull(2)))
#endif
t9p_malloc_ctx(size_t size, t9p_memtrack_ctx_t* ctx)
{
  void* ptr = t9p_malloc(size);
  if (ctx != &g_t9p_memtrack_ctx) {
    atomic_add_u32(&ctx->total_allocd_bytes, malloc_usable_size(ptr));
    atomic_add_u32(&ctx->total_allocd_bytes_requested, size);
    atomic_add_u32(&ctx->total_alloc_calls, 1);
  }
  return ptr;
}

void*
#if defined(__GNUC__) || defined(__clang__)
__attribute__((malloc, alloc_size(1, 2), nonnull(3)))
#endif
t9p_calloc_ctx(size_t nmemb, size_t size, t9p_memtrack_ctx_t* ctx)
{
  void* ptr = t9p_calloc(nmemb, size);
  if (ctx != &g_t9p_memtrack_ctx) {
    atomic_add_u32(&ctx->total_allocd_bytes, malloc_usable_size(ptr));
    atomic_add_u32(&ctx->total_allocd_bytes_requested, nmemb * size);
    atomic_add_u32(&ctx->total_alloc_calls, 1);
  }
  return ptr;
}

void*
#if defined(__GNUC__) || defined(__clang__)
__attribute__((malloc, alloc_size(1), nonnull(3)))
#ifndef __rtems__
__attribute__((alloc_align(2)))
#endif
#endif
t9p_aligned_zmalloc_ctx(size_t size, size_t align, t9p_memtrack_ctx_t* ctx)
{
  void* ptr = t9p_aligned_zmalloc(size, align);
  if (ctx != &g_t9p_memtrack_ctx) {
    atomic_add_u32(&ctx->total_allocd_bytes, malloc_usable_size(ptr));
    atomic_add_u32(&ctx->total_allocd_bytes_requested, size);
    atomic_add_u32(&ctx->total_alloc_calls, 1);
  }
  return ptr;
}

void
#if defined(__GNUC__) || defined(__clang__)
__attribute__((nonnull(2)))
#endif
t9p_free_ctx(void* ptr, t9p_memtrack_ctx_t* ctx)
{
  if (ctx != &g_t9p_memtrack_ctx) {
    atomic_add_u32(&ctx->total_freed_bytes, malloc_usable_size(ptr));
    atomic_add_u32(&ctx->total_free_calls, 1);
  }
  t9p_free(ptr);
}

#endif

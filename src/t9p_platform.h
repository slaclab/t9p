/**
 * ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: Common platform abstraction defintiions
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
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>

#ifdef __rtems__
#include <rtems.h>
#endif

#define T9P_TARGET_POSIX 0
#define T9P_TARGET_RTEMS4 1

/** Make your target selections here! */
#ifdef __linux__
# define T9P_TARGET T9P_TARGET_POSIX
#elif defined(__rtems__)
# define T9P_TARGET T9P_TARGET_RTEMS4
#endif

/** Alignment checking */
#ifdef NDEBUG
# define ASSERT_ALIGNED(_addr, _align)
#else
# define ASSERT_ALIGNED(_addr, _align) do {        \
    assert(((uintptr_t)(_addr)) % (_align) == 0); \
  } while (0)
#endif

#if defined(__GNUC__) || defined(__clang__)

#define CC_MFENCE asm volatile ("" : : : "memory")

#ifdef __powerpc__
# define MFENCE asm volatile ("lwsync" : : : "memory")
#elif defined(__i386__)
# define MFENCE asm volatile ("mfence" : : : "memory") /* not really needed on x86... */
#elif defined(__m68k__)
/* nop performs full pipeline synchronization on CF */
# define MFENCE asm volatile ("nop" : : : "memory")
#else
# define MFENCE asm volatile ("" : : : "memory")
#endif
/**
 * NOTE: The Coldfire ISA-A does not support atomic instructions. Instead, we
 * either skip any form of synchronization (i.e. for load32, since it is
 * inherently atomic) or we just disable interrupts and do our business.
 */

static inline uint32_t
atomic_load_u32(uint32_t* p)
{
  ASSERT_ALIGNED(p, 4);
#if __mcoldfire__ == 1
  return *p;
#else
  return __atomic_load_n(p, __ATOMIC_SEQ_CST);
#endif
}

static inline void
atomic_store_u32(uint32_t* p, uint32_t val)
{
  ASSERT_ALIGNED(p, 4);
#if __mcoldfire__ == 1
  *p = val;
#else
  __atomic_store_n(p, val, __ATOMIC_SEQ_CST);
#endif
}

static inline int
atomic_compare_exchange_u32(uint32_t* p, uint32_t expected, uint32_t newval)
{
  ASSERT_ALIGNED(p, 4);
#if __mcoldfire__ == 1
  rtems_interrupt_level l;
  int r = 0;
  rtems_interrupt_disable(l);
  if (*p == expected)
    r = 1, *p = newval;
  rtems_interrupt_enable(l);
  return r;
#else
  return __atomic_compare_exchange(p, &expected, &newval, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
#endif
}

static inline uint32_t
atomic_add_u32(uint32_t* p, uint32_t v)
{
  ASSERT_ALIGNED(p, 4);
#if __mcoldfire__ == 1
  uint32_t r;
  rtems_interrupt_level l;
  rtems_interrupt_disable(l);
  (*p) += v;
  r = *p;
  rtems_interrupt_enable(l);
  return r;
#else
  return __atomic_add_fetch(p, v, __ATOMIC_SEQ_CST);
#endif
}

static inline uint32_t
atomic_sub_u32(uint32_t* p, uint32_t v)
{
  ASSERT_ALIGNED(p, 4);
#if __mcoldfire__ == 1
  uint32_t r;
  rtems_interrupt_level l;
  rtems_interrupt_disable(l);
  (*p) -= v;
  r = *p;
  rtems_interrupt_enable(l);
  return r;
#else
  return __atomic_sub_fetch(p, v, __ATOMIC_SEQ_CST);
#endif
}

#endif

/** Generic thread API */

enum t9p_thread_prio;

typedef void* (*thread_proc_t)(void*);
typedef struct _thread_s thread_t;

extern thread_t* thread_create(thread_proc_t proc, void* param, enum t9p_thread_prio prio);
extern void thread_join(thread_t* thr);
extern void thread_destroy(thread_t* thread);

/** Generic mutex API */

typedef struct _mutex_s mutex_t;
extern mutex_t* mutex_create();
extern void mutex_lock(mutex_t* mut);
extern void mutex_unlock(mutex_t* mut);
extern void mutex_destroy(mutex_t* mut);

/** Generic event API */

typedef struct _event_s event_t;
extern event_t* event_create();
extern int event_wait(event_t* ev, uint64_t timeout_ms);
extern void event_signal(event_t* ev);
extern void event_destroy(event_t* ev);

/** Generic message queue API */

typedef struct _msg_queue_s msg_queue_t;
extern msg_queue_t* msg_queue_create(const char* id, size_t msgSize, size_t maxMsgs);
extern void msg_queue_destroy(msg_queue_t* q);
extern int msg_queue_send(msg_queue_t* q, const void* data, size_t size);
extern int msg_queue_recv(msg_queue_t* q, void* data, size_t* size);

/** Dynamic memory helpers */
extern void* t9p_malloc(size_t size);
extern void* t9p_calloc(size_t nmeb, size_t size);
extern void* t9p_aligned_zmalloc(size_t size, size_t align);
extern void t9p_free(void* ptr);

#ifndef T9P_NO_MEMTRACK
typedef struct t9p_memtrack_ctx
{
  uint32_t total_allocd_bytes;
  uint32_t total_allocd_bytes_requested;
  uint32_t total_freed_bytes;
  uint32_t total_alloc_calls;
  uint32_t total_free_calls;
} t9p_memtrack_ctx_t;

#define T9P_MEMTRACK_CTX(name) static t9p_memtrack_ctx_t name = {0, 0, 0, 0, 0}

extern t9p_memtrack_ctx_t g_t9p_memtrack_ctx;

extern void* t9p_malloc_ctx(size_t size, t9p_memtrack_ctx_t* ctx);
extern void* t9p_calloc_ctx(size_t nmemb, size_t size, t9p_memtrack_ctx_t* ctx);
extern void* t9p_aligned_zmalloc_ctx(size_t size, size_t align, t9p_memtrack_ctx_t* ctx);
extern void t9p_free_ctx(void* ptr, t9p_memtrack_ctx_t* ctx);
#else
#define T9P_MEMTRACK_CTX(name)
#define t9p_malloc_ctx(size, ctx) t9p_malloc(size)
#define t9p_calloc_ctx(nmemb, size, ctx) t9p_calloc(nmemb, size)
#define t9p_aligned_zmalloc_ctx(size, align, ctx) t9p_aligned_zmalloc(size, align)
#define t9p_free_ctx(ptr, ctx) t9p_free(ptr)
#endif

/** Safe wrapper around gethostbyname/getaddrinfo */
extern int gethostbyname_inet(const char* name, in_addr_t* outaddr);
#pragma once

#include <stdint.h>
#include <stddef.h>

#define T9P_TARGET_POSIX 0
#define T9P_TARGET_RTEMS4 1

/** Make your target selections here! */
#ifdef __linux__
#define T9P_TARGET T9P_TARGET_POSIX
#elif defined(__rtems__)
#define T9P_TARGETT9P_TARGET_RTEMS4
#endif

#if defined(__GNUC__) || defined(__clang__)
typedef uint32_t atomic_uint32_t;

inline uint32_t atomic_load32(atomic_uint32_t* p) {
    return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}

inline void atomic_store32(atomic_uint32_t* p, uint32_t val) {
    __atomic_store_n(p, val, __ATOMIC_SEQ_CST);
}

inline int atomic_compare_exchange32(atomic_uint32_t* p, uint32_t expected, uint32_t newval) {
    return __atomic_compare_exchange(p, &expected, &newval, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}
#endif

/** Generic thread API */

typedef void*(*thread_proc_t)(void*);
typedef struct _thread_s thread_t;

extern thread_t* thread_create(thread_proc_t proc, void* param);
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

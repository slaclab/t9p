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

/** Generic thread API */

typedef void*(*thread_proc_t)(void*);
typedef struct _thread_s thread_t;

extern thread_t* create_thread(thread_proc_t proc, void* param);
extern void thread_join(thread_t* thr);
extern void destroy_thread(thread_t* thread);

/** Generic mutex API */

typedef struct _mutex_s mutex_t;
extern mutex_t* create_mutex();
extern void lock_mutex(mutex_t* mut);
extern void unlock_mutex(mutex_t* mut);
extern void destroy_mutex(mutex_t* mut);

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
/**
 * T9P platform implementation using pthreads
 */

#include "t9p_platform.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <mqueue.h>

struct _thread_s {
    pthread_t thread;
    pthread_attr_t attr;
};

struct _mutex_s {
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
};

thread_t* create_thread(thread_proc_t proc, void* param) {
    thread_t* p = malloc(sizeof(struct _thread_s));
    if (!p)
        return NULL;

    if (pthread_attr_init(&p->attr) != 0) {
        free(p);
        return NULL;
    }
    // TODO: set priority properly

    if (pthread_create(&p->thread, &p->attr, proc, param) != 0) {
        pthread_attr_destroy(&p->attr);
        free(p);
        return NULL;
    }

    return p;
}

void thread_join(thread_t* thr) {
    pthread_join(thr->thread, NULL);
    thr->thread = 0;
}

void destroy_thread(thread_t* thread) {
    if (thread->thread)
        pthread_join(thread->thread, NULL);
    pthread_attr_destroy(&thread->attr);
    free(thread);
}

mutex_t* create_mutex() {
    mutex_t* m = malloc(sizeof(mutex_t));
    
    if (pthread_mutexattr_init(&m->attr) != 0) {
        free(m);
        return NULL;
    }

    if (pthread_mutex_init(&m->mutex, &m->attr) != 0) {
        pthread_mutexattr_destroy(&m->attr);
        free(m);
        return NULL;
    }

    return m;
}

void lock_mutex(mutex_t* mut) {
    pthread_mutex_lock(&mut->mutex);
}

void unlock_mutex(mutex_t* mut) {
    pthread_mutex_unlock(&mut->mutex);
}

void destroy_mutex(mutex_t* mut) {
    pthread_mutexattr_destroy(&mut->attr);
    pthread_mutex_destroy(&mut->mutex);
    free(mut);
}

struct _event_s {
    pthread_cond_t cond;
    pthread_condattr_t condattr;
    pthread_mutex_t mutex;
    pthread_mutexattr_t mutexattr;
};

event_t* event_create() {
    event_t* ev = malloc(sizeof(event_t));
    memset(ev, 0, sizeof *ev);
    pthread_condattr_init(&ev->condattr);
    pthread_cond_init(&ev->cond, &ev->condattr);
    pthread_mutexattr_init(&ev->mutexattr);
    pthread_mutex_init(&ev->mutex, &ev->mutexattr);
    return ev;
}

void event_wait(event_t* ev, uint64_t timeout_ms) {
    struct timespec tv = {};
    clock_gettime(CLOCK_MONOTONIC, &tv);
    tv.tv_nsec += (timeout_ms % 1000) * 1e6;
    tv.tv_sec += timeout_ms / 1000;

    pthread_mutex_lock(&ev->mutex);
    pthread_cond_timedwait(&ev->cond, &ev->mutex, &tv);
    pthread_mutex_unlock(&ev->mutex); // Dont need to hold this mutex
}

void event_signal(event_t* ev) {
    pthread_cond_broadcast(&ev->cond);
}

extern void event_destroy(event_t* ev) {
    if (!ev) return;
    pthread_cond_destroy(&ev->cond);
    pthread_condattr_destroy(&ev->condattr);
    pthread_mutex_destroy(&ev->mutex);
    pthread_mutexattr_destroy(&ev->mutexattr);
    free(ev);
}

struct _msg_queue_s {
    mqd_t id;
};

msg_queue_t* msg_queue_create(const char* id) {
    msg_queue_t* q = malloc(sizeof(msg_queue_t));
    q->id = mq_open(id, O_CREAT);
    if (q->id < 0) {
        free(q);
        return NULL;
    }
    return q;
}

void msg_queue_destroy(msg_queue_t* q) {
    if (!q) return;
    mq_close(q->id);
    free(q);
}

int msg_queue_send(msg_queue_t* q, const void* data, size_t size) {
    return mq_send(q->id, data, size, 0);
}

int msg_queue_recv(msg_queue_t* q, void* data, size_t* size) {
    unsigned int prio;
    ssize_t l = mq_receive(q->id, data, *size, &prio);
    if (l < 0)
        return l;
    *size = l;
    return 0;
}
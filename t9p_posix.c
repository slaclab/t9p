/**
 * T9P platform implementation using pthreads
 */

#include "t9p_platform.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <mqueue.h>
#include <errno.h>
#include <stdio.h>
#include <sys/msg.h>
#include <assert.h>


struct _thread_s {
    pthread_t thread;
    pthread_attr_t attr;
};

struct _mutex_s {
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
};

thread_t* thread_create(thread_proc_t proc, void* param) {
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

void thread_destroy(thread_t* thread) {
    if (thread->thread)
        pthread_join(thread->thread, NULL);
    pthread_attr_destroy(&thread->attr);
    free(thread);
}

mutex_t* mutex_create() {
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

void mutex_lock(mutex_t* mut) {
    pthread_mutex_lock(&mut->mutex);
}

void mutex_unlock(mutex_t* mut) {
    pthread_mutex_unlock(&mut->mutex);
}

void mutex_destroy(mutex_t* mut) {
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

int event_wait(event_t* ev, uint64_t timeout_ms) {
    struct timespec tv = {};
    clock_gettime(CLOCK_REALTIME, &tv);
    tv.tv_nsec += (timeout_ms % 1000) * 1e6;
    tv.tv_nsec %= 1000000000;
    tv.tv_sec += (timeout_ms / 1000) + (tv.tv_nsec / 1000000);

    //fprintf(stderr, "Wait event %p\n", ev);

    pthread_mutex_lock(&ev->mutex);
    int r = 0;
    do {
    } while ((r = pthread_cond_timedwait(&ev->cond, &ev->mutex, &tv)) != 0 && (r == EAGAIN || r == EINTR));

    pthread_mutex_unlock(&ev->mutex); // Dont need to hold this mutex

    return r;
}

void event_signal(event_t* ev) {
    //printf("Signal event %p\n", ev);
    pthread_mutex_lock(&ev->mutex);
    pthread_cond_broadcast(&ev->cond);
    pthread_mutex_unlock(&ev->mutex);
}

extern void event_destroy(event_t* ev) {
    if (!ev) return;
    pthread_cond_destroy(&ev->cond);
    pthread_condattr_destroy(&ev->condattr);
    pthread_mutex_destroy(&ev->mutex);
    pthread_mutexattr_destroy(&ev->mutexattr);
    free(ev);
}

// Really dumb message queue because POSIX message queues don't cut the mustard...

struct msg {
    size_t sz;
    struct msg* next;
    char data[];
};

struct _msg_queue_s {
    //mqd_t id;
    int id;

    //event_t* ev;
    mutex_t* mut;

    struct msg* fh;
    struct msg* q;
    size_t msize;
};

msg_queue_t* msg_queue_create(const char* id, size_t msgSize, size_t maxMsgs) {
    msg_queue_t* q = malloc(sizeof(msg_queue_t));

    q->fh = q->q = 0;

    for (int i = 0; i < maxMsgs; ++i) {
        struct msg* m = calloc(1, msgSize + sizeof(struct msg));
        m->next = q->fh;
        q->fh = m;
    }

    q->msize = msgSize;
    //q->ev = event_create();
    q->mut = mutex_create();
    return q;
}

void msg_queue_destroy(msg_queue_t* q) {
    if (!q) return;
    for (struct msg*m = q->q; m;) {
        struct msg* n = m->next;
        free(m);
        m = n;
    }

    for (struct msg*m = q->fh; m;) {
        struct msg* n = m->next;
        free(m);
        m = n;
    }
    free(q);
}

int msg_queue_send(msg_queue_t* q, const void* data, size_t size) {
    assert(size <= q->msize);
    //pthread_mutex_lock(&q->ev->mutex);
    mutex_lock(q->mut);

    struct msg* p = q->fh;
    if (!p) {
        //pthread_mutex_unlock(&q->ev->mutex);
        mutex_unlock(q->mut);
        return -1;
    }

    q->fh = p->next;

    struct msg* m;
    for (m = q->q; m && m->next; m = m->next)
        ;
    p->next = NULL;
    if (!m)
        q->q = p;
    else
        m->next = p;

    p->sz = size;
    memcpy(p->data, data, size);

    mutex_unlock(q->mut);

//    pthread_mutex_unlock(&q->ev->mutex);
//
//    event_signal(q->ev);

    return 0;
}

int msg_queue_recv(msg_queue_t* q, void* data, size_t* size) {

    struct msg* p = NULL;
    //pthread_mutex_lock(&q->ev->mutex);
    mutex_lock(q->mut);

    p = q->q;

    //pthread_mutex_unlock(&q->ev->mutex);

    if (p) {
        q->q = p->next;
        p->next = q->fh;
        q->fh = p;
        memcpy(data, p->data, *size < p->sz ? *size : p->sz);
        *size = p->sz;
        mutex_unlock(q->mut);
        return 0;
    }
    mutex_unlock(q->mut);
    return -1;
}

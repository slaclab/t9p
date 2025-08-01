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
#include "t9p.h"

#include <assert.h>
#include <errno.h>
#include <mqueue.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>

struct _thread_s
{
  pthread_t thread;
  pthread_attr_t attr;
};

struct _mutex_s
{
  pthread_mutex_t mutex;
  pthread_mutexattr_t attr;
};

#ifdef __rtems__
/* All SCHED_ types have prio 1-254 on RTEMS */
static const int prio_to_posix[T9P_THREAD_PRIO_COUNT] =
{
  50,  /* low */
  120, /* med */
  250  /* max */
};
#else
static const int prio_to_posix[T9P_THREAD_PRIO_COUNT] =
{
  20, /* low */
  50, /* med */
  90  /* max */
};
#endif

thread_t*
thread_create(thread_proc_t proc, void* param, enum t9p_thread_prio prio)
{
  thread_t* p = t9p_malloc(sizeof(struct _thread_s));
  if (!p)
    return NULL;

  if (pthread_attr_init(&p->attr) != 0) {
    t9p_free(p);
    return NULL;
  }

#ifdef __rtems__
  struct sched_param sp = {
    .sched_priority = prio_to_posix[prio]
  };
  pthread_attr_setschedparam(&p->attr, &sp);
  pthread_attr_setschedpolicy(&p->attr, SCHED_OTHER);
#endif

  assert(proc);

  if (pthread_create(&p->thread, &p->attr, proc, param) != 0) {
    pthread_attr_destroy(&p->attr);
    t9p_free(p);
    return NULL;
  }

  return p;
}

void
thread_join(thread_t* thr)
{
  pthread_join(thr->thread, NULL);
  thr->thread = 0;
}

void
thread_destroy(thread_t* thread)
{
  if (thread->thread)
    pthread_join(thread->thread, NULL);
  pthread_attr_destroy(&thread->attr);
  t9p_free(thread);
}

mutex_t*
mutex_create(void)
{
  mutex_t* m = t9p_malloc(sizeof(mutex_t));

  if (pthread_mutexattr_init(&m->attr) != 0) {
    t9p_free(m);
    return NULL;
  }

  if (pthread_mutex_init(&m->mutex, &m->attr) != 0) {
    pthread_mutexattr_destroy(&m->attr);
    t9p_free(m);
    return NULL;
  }

  return m;
}

void
mutex_lock(mutex_t* mut)
{
  pthread_mutex_lock(&mut->mutex);
}

void
mutex_unlock(mutex_t* mut)
{
  pthread_mutex_unlock(&mut->mutex);
}

void
mutex_destroy(mutex_t* mut)
{
  pthread_mutexattr_destroy(&mut->attr);
  pthread_mutex_destroy(&mut->mutex);
  t9p_free(mut);
}

struct _event_s
{
  pthread_cond_t cond;
  pthread_condattr_t condattr;
  pthread_mutex_t mutex;
  pthread_mutexattr_t mutexattr;
};

event_t*
event_create(void)
{
  event_t* ev = t9p_malloc(sizeof(event_t));
  memset(ev, 0, sizeof *ev);
  pthread_condattr_init(&ev->condattr);
  pthread_cond_init(&ev->cond, &ev->condattr);
  pthread_mutexattr_init(&ev->mutexattr);
  pthread_mutex_init(&ev->mutex, &ev->mutexattr);
  return ev;
}

int
event_wait(event_t* ev, uint32_t timeout_ms)
{
  struct timespec tv = {};
  if (timeout_ms != UINT32_MAX) {
    clock_gettime(CLOCK_REALTIME, &tv);
    uint64_t ns = tv.tv_nsec + timeout_ms * 1e6;
    tv.tv_nsec = ns % 1000000000ULL;
    tv.tv_sec += (ns / 1000000000ULL);
  }
  
  pthread_mutex_lock(&ev->mutex);
  int r = 0;
  do {
    if (timeout_ms != UINT32_MAX)
      r = pthread_cond_timedwait(&ev->cond, &ev->mutex, &tv);
    else
      r = pthread_cond_wait(&ev->cond, &ev->mutex);
  } while (r == EAGAIN || r == EINTR);

  pthread_mutex_unlock(&ev->mutex); // Dont need to hold this mutex

  return r;
}

void
event_signal(event_t* ev)
{
  pthread_mutex_lock(&ev->mutex);
  pthread_cond_broadcast(&ev->cond);
  pthread_mutex_unlock(&ev->mutex);
}

void
event_destroy(event_t* ev)
{
  if (!ev)
    return;
  pthread_cond_destroy(&ev->cond);
  pthread_condattr_destroy(&ev->condattr);
  pthread_mutex_destroy(&ev->mutex);
  pthread_mutexattr_destroy(&ev->mutexattr);
  t9p_free(ev);
}

#ifdef __rtems__

/* Message queue using the RTEMS score API */

struct _msg_queue_s
{
  rtems_name name;
  rtems_id queue;
  size_t msgSize;
};

msg_queue_t*
msg_queue_create(const char* id, size_t msgSize, size_t maxMsgs)
{
  msg_queue_t* q = t9p_calloc(1, sizeof(msg_queue_t));
  q->name = rtems_build_name(id[0], id[1], id[2], id[3]);
  q->msgSize = msgSize;
  rtems_status_code status =
    rtems_message_queue_create(q->name, maxMsgs, msgSize, RTEMS_FIFO, &q->queue);
  if (status != RTEMS_SUCCESSFUL) {
    printf("Queue create failed: %d\n", status);
    t9p_free(q);
    return NULL;
  }
  return q;
}

void
msg_queue_destroy(msg_queue_t* q)
{
  rtems_message_queue_delete(q->queue);
  t9p_free(q);
}

int
msg_queue_send(msg_queue_t* q, const void* data, size_t size)
{
  assert(size == q->msgSize);
  return rtems_message_queue_send(q->queue, data, size) == RTEMS_SUCCESSFUL ? 0 : -1;
}

int
msg_queue_recv(msg_queue_t* q, void* data, size_t* size)
{
  assert(*size == q->msgSize);
  return 
    rtems_message_queue_receive(q->queue, data, size, RTEMS_NO_WAIT, 0) == RTEMS_SUCCESSFUL?0:-1;
}

#else /* __rtems__ */

/** Really dumb message queue because POSIX message queues don't quite cut the mustard... */

struct msg
{
  size_t sz;
  struct msg* next;
  char data[];
};

struct _msg_queue_s
{
  int id;

  mutex_t* mut;

  struct msg* fh;
  struct msg* q;
  size_t msize;
};

msg_queue_t*
msg_queue_create(const char* id, size_t msgSize, size_t maxMsgs)
{
  msg_queue_t* q = t9p_malloc(sizeof(msg_queue_t));

  q->fh = q->q = 0;

  for (int i = 0; i < maxMsgs; ++i) {
    struct msg* m = t9p_calloc(1, msgSize + sizeof(struct msg));
    m->next = q->fh;
    q->fh = m;
  }

  q->msize = msgSize;
  q->mut = mutex_create();
  return q;
}

void
msg_queue_destroy(msg_queue_t* q)
{
  if (!q)
    return;
  for (struct msg* m = q->q; m;) {
    struct msg* n = m->next;
    t9p_free(m);
    m = n;
  }

  for (struct msg* m = q->fh; m;) {
    struct msg* n = m->next;
    t9p_free(m);
    m = n;
  }
  t9p_free(q);
}

int
msg_queue_send(msg_queue_t* q, const void* data, size_t size)
{
  assert(size <= q->msize);
  mutex_lock(q->mut);

  struct msg* p = q->fh;
  if (!p) {
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

  return 0;
}

int
msg_queue_recv(msg_queue_t* q, void* data, size_t* size)
{
  struct msg* p = NULL;
  mutex_lock(q->mut);

  p = q->q;

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

#endif

int
gethostbyname_inet(const char* name, in_addr_t* outaddr)
{
  static mutex_t* mutex;
  if (!mutex) {
    mutex = mutex_create(); /* needed to guard unsafe gethostbyname calls... */
  }

  int ret = 0;

  mutex_lock(mutex);

  struct hostent* ent = gethostbyname(name);  
  if (ent && ent->h_addr_list && *ent->h_addr_list) {
    switch (ent->h_addrtype) {
    case AF_INET:
      *outaddr = *(in_addr_t*)ent->h_addr_list[0];
      break;
    default:
      ret = -1;
      break;
    }
  }
  else
    ret = -1;

  mutex_unlock(mutex);
  return ret;
}
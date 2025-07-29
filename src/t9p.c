/**
 * ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: Core implementation of 9P2000.L and t9p's public API.
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

/** Feature flags */
#define HAVE_TCP 1

#include "t9p_platform.h"

#ifdef __rtems__
/* Required for MSG_PEEK */
#define __BSD_VISIBLE 1
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <dirent.h>
#include <stdbool.h>
#include <ctype.h>
#include <netdb.h>

#include <unistd.h>
#ifdef __linux__
#include <linux/limits.h>
#elif defined(__rtems__)
#include <rtems/score/cpuopts.h>
#if __RTEMS_MAJOR__ >= 6
#include <sys/limits.h>
#include <rtems/rtems/types.h>
#include <rtems/rtems/tasks.h>
#include <rtems/rtems/event.h>
#include <rtems/rtems/clock.h>
#else
#include <sched.h>
#endif
#else
#define PATH_MAX 256
#endif

#if HAVE_TCP
#if __RTEMS_MAJOR__ < 5
#include "netinet/in_systm.h"
#endif
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include "t9p.h"
#include "t9proto.h"

/* FIXME: This is a workaround for some diod wierdness. For some reason it assumes
 * that I/O requests (Twrite, Rread) are 24 bytes, even though they are less. This leads
 * to diod rejecting writes w/count 4073 with msize=4096, even though it really shouldn't.
 * REMOVE ME when fixed in upstream. */
#define DIOD_IOHDRSZ 24

#define T9P_TARGET_VERSION "9P2000.L"

#define MAX_PATH_COMPONENTS 256

#define MAX_TAGS 512
#define MAX_TRANSACTIONS 512

#define DEFAULT_MAX_FILES 256
#define DEFAULT_SEND_TIMEO 3000
#define DEFAULT_RECV_TIMEO 60000

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define ERRLOG(...) fprintf(stderr, __VA_ARGS__)
#define LOG(_context, _level, ...)                                                                 \
  if (_context && _context->opts.log_level <= _level) {                                            \
    fprintf(stderr, __VA_ARGS__);                                                                  \
  }

#define TRACE(_context, ...) LOG(_context, T9P_LOG_TRACE, __VA_ARGS__)
#define INFO(_context, ...) LOG(_context, T9P_LOG_INFO, __VA_ARGS__)
#define DEBUG(_context, ...) LOG(_context, T9P_LOG_DEBUG, __VA_ARGS__)
#define WARN(_context, ...) LOG(_context, T9P_LOG_WARN, __VA_ARGS__)
#define ERROR(_context, ...) LOG(_context, T9P_LOG_WARN, __VA_ARGS__)

#ifdef __rtems__
#define T9P_WAKE_EVENT RTEMS_EVENT_31
#define T9P_NODE_EVENT RTEMS_EVENT_30
#endif

/** POSIX-style events are only used on Linux */
#ifndef __rtems__
#define USE_POSIX_EVENTS
#endif

struct trans_pool
{
  struct trans_node* freehead;
  struct trans_node* deadhead;
  mutex_t* guard;
  uint32_t total;
  msg_queue_t* queue;
  event_t* recv_ev;
};

struct T9P_ALIGNED(4) t9p_context
{
  uint32_t thr_run;
  uint32_t serial;    /**< Serial number of the context. Must match fid, otherwise triggers recovery */
  bool broken;        /**< Indicates if the pipe was broken or not */

  void* conn;
  t9p_transport_t trans;
  char mntpoint[PATH_MAX];
  char addr[PATH_MAX];
  char apath[PATH_MAX];
  t9p_opts_t opts;
  struct t9p_handle_node* root;
  uint32_t msize;

  /** file handle list */
  mutex_t* fhl_mutex;
  int fhl_max;
  int fhl_count;

  /** I/O thread */
  thread_t* io_thread;
  event_t* recv_event; /**< Signaled when a new packet has been received */
  mutex_t* socket_lock;

  struct trans_pool trans_pool;

  struct t9p_handle_node* fhl; /**< Flat array of file handles, allocated in a contiguous block */
  struct t9p_handle_node* fhl_free; /**< LL of free file handles */
  
  struct t9p_stats stats;
  
#ifdef __rtems__
  rtems_id rtems_thr_ident;   /**< Used to wake the I/O thread when more data is ready */
#endif
};

#define T9P_HANDLE_ACTIVE 0x1
#define T9P_HANDLE_QID_VALID 0x2
#define T9P_HANDLE_FID_VALID 0x4

struct t9p_string
{
  uint32_t rc;
  uint16_t len;
  char string[];
};

/** 36 bytes; let's keep it close to that.
  * DEFAULT_MAX_FILES = 256, so we allocate 9216 bytes on context create */
struct t9p_handle
{
  struct t9p_string* str; /**< Path of the file */
  int32_t fid;         /**< Also the index into the fh table in t9p_context */
  uint32_t serial;     /**< Serial number. Must match context. Used for recovery */
  uint32_t iounit;     /**< Returned by Rlopen after the file is opened */
  uint32_t obits;      /**< Flags used to open the file. used for recovery */
  uint16_t valid_mask; /**< Determines what is and isn't valid */
  qid_t qid;           /**< qid of this object. Only valid if valid_mask says so */
};

struct t9p_handle_node
{
  struct t9p_handle_node* next;
  struct t9p_handle h;
};

/********************************************************************/
/*                                                                  */
/*                     P R O T O T Y P E S                          */
/*                                                                  */
/********************************************************************/

static int t9p__version_handshake(struct t9p_context* context);
static int t9p__attach_root(struct t9p_context* c);
static int t9p__send(struct t9p_context* c, const void* data, size_t sz, int flags);
static void t9p__perror(struct t9p_context* c, const char* msg, struct TRcommon* err);
static int t9p__iserror(struct TRcommon* err);
static int t9p__clunk_sync(struct t9p_context* c, int fid);
static int t9p__is_fid_rw(t9p_handle_t h, int write);
static const char* t9p__strerror(int e);
static void t9p__discard(struct t9p_context* c, struct TRcommon* com);

/** String methods */
T9P_NODISCARD static struct t9p_string* t9p__string_release(struct t9p_string* str);
static void t9p__string_acquire(struct t9p_string* str);
T9P_NODISCARD static struct t9p_string* t9p__string_new_path(const char* dname, const char* fname);
T9P_NODISCARD static struct t9p_string* t9p__string_copy(struct t9p_string* str);

/** t9p_context 'methods' */
T9P_NODISCARD static struct t9p_handle_node* t9p__alloc_handle(
  struct t9p_context* c,
  t9p_handle_t parent,
  const char* fname
);
T9P_NODISCARD static struct t9p_handle_node* _copy_handle(struct t9p_context* c, t9p_handle_t h);
static void t9p__release_handle(struct t9p_context* c, struct t9p_handle_node* h);
static void t9p__release_handle_by_fid(struct t9p_context* c, t9p_handle_t h);
static int t9p__maybe_recover(struct t9p_context* c, t9p_handle_t h);
static struct t9p_handle_node* t9p__handle_by_fid(struct t9p_context* c, t9p_handle_t h);

static void* t9p__thread_proc(void* param);

/** Safe strcpy that ensures dest is NULL terminated */
void
strNcpy(char* dest, const char* src, size_t dmax)
{
  if (!dmax || !dest)
    return;
  if (!src)
    dest[0] = 0;
  strncpy(dest, src, dmax);
  dest[dmax - 1] = 0;
}
#define strncpy strNcpy

#ifdef __rtems__
static rtems_interval
t9p__rt_ms_to_ticks(uint32_t ms)
{
  rtems_interval i = ms * rtems_clock_get_ticks_per_second() / 1000;
  if (!i) i = 1;
  return i;
}
#endif

static bool
ip_in_dot_format(const char* ip)
{
  int dots = 0, seq = 0;
  for (const char* s = ip; *s; ++s) {
    if (*s == '.') {
      if (seq == 0) return false; /* .. is invalid */
      ++dots, seq = 0;
      continue;
    }
    if (*s > '9' || *s < '0')
      return false; /* any non-numeric char that isn't '.' is invalid */
    ++seq;
    if (seq > 3)
      return false; /* more than 3 nums is invalid */
  }
  return dots == 3; /* needs exactly 3 dots */
}

/********************************************************************/
/*                                                                  */
/*            T R A N S A C T I O N        P O O L                  */
/*                                                                  */
/********************************************************************/

struct trans;
struct trans_pool;
struct trans_node;

struct trans_node* tr_enqueue(
  struct t9p_context* ctx,
  struct trans_pool* q,
  struct trans_node* tr
);
static void tr_release(struct trans_pool* q, struct trans_node* tn);
static void tr_signal(struct trans_node* n);
static int tr_wait(struct trans_node* n, int timeo);
static int tr_recv_now(struct t9p_context* c, struct trans_node* n);
static int tr_send_now(struct t9p_context* c, struct trans_node* n);

#define TR_FLAGS_NONE 0x0

struct trans {
  uint32_t ttype;    /**< Transmission type */
  uint32_t flags;    /**< Flags */
  const void *data;  /**< Outgoing data */
  size_t size;       /**< Outgoing data size */
  void *rdata;       /**< Buffer to hold incoming data */
  size_t rsize;      /**< Incoming data buffer size */
  const void *hdata; /**< Optional; header data pointer. If not NULL,
                          this is ent before this->data is.
                          This is used to avoid unnecessary copies */
  size_t hsize;      /**< Optional; header data size */
  int32_t status;    /**< Combined status/length variable. If < 0, this represents
                     an error condition. If >= 0, it's the number of bytes
                     written to rdata. */
  uint32_t rtype;    /**< 9p meta; result message type. Set to 0 to accept any. */
  void *rheader;     /**< Optional; pointer to 'header' recv data */
  size_t rheadersz;  /**< Optional; size of the the recv 'header' buf. This should be the number
                          of bytes *expected* for the header. i.e. sizeof(Rread) */
};

struct trans_node
{
  struct trans tr;

  uint8_t sent;   /**< Set once we've been sent */
#if __rtems__
  rtems_id task;  /**< Originator of the request. Used with rtems_event_send */
#else
  event_t* event; /**< Signaled when the response to this is receieved */
#endif
  uint16_t tag;   /**< Tag for this transaction node; For now, each node will have its
                       own associated tag. Somewhat sucks, but good enough for now. */

  struct trans_node* next;
};

/**
 * Init the transaction queue
 */
int
tr_pool_init(struct trans_pool* q, uint32_t num)
{
  memset(q, 0, sizeof(*q));

  q->queue = msg_queue_create("T9PQ", sizeof(struct trans_node*), MAX_TRANSACTIONS);
  if (!q->queue)
    return -1;

  if (!(q->recv_ev = event_create())) {
    msg_queue_destroy(q->queue);
    return -1;
  }

  if (!(q->guard = mutex_create())) {
    msg_queue_destroy(q->queue);
    event_destroy(q->recv_ev);
    return -1;
  }

  mutex_lock(q->guard);

  int tag = 0;

  /** Allocate nodes */
  for (int i = 0; i < num; ++i) {
    struct trans_node* on = q->freehead;
    q->freehead = t9p_calloc(1, sizeof(*on));
  #ifdef USE_POSIX_EVENTS
    q->freehead->event = event_create();
  #endif
    q->freehead->next = on;
    q->freehead->tag = tag++;
  }
  q->total = num;

  mutex_unlock(q->guard);
  return 0;
}

/**
 * Destroy the transaction queue
 */
void
tr_pool_destroy(struct trans_pool* q)
{
  mutex_lock(q->guard);

  /** Free the nodes */
  for (struct trans_node* n = q->freehead; n;) {
    struct trans_node* b = n->next;
  #ifdef USE_POSIX_EVENTS
    event_destroy(n->event);
  #endif
    t9p_free(n);
    n = b;
  }

  msg_queue_destroy(q->queue);

  mutex_unlock(q->guard);
  mutex_destroy(q->guard);
  event_destroy(q->recv_ev);
}

/**
 * Grab a free node from the transaction node pool, returns NULL if none are available.
 */
struct trans_node*
tr_get_node(struct trans_pool* q)
{
  mutex_lock(q->guard);

  if (!q->freehead) {
    /** Out of space in the trans queue */
    mutex_unlock(q->guard);
    return NULL;
  }

  /** Extract node from the free list */
  struct trans_node* us = q->freehead;
  q->freehead = us->next;

  /** Copy in data */
  us->next = NULL;
  memset(&us->tr, 0, sizeof(us->tr));

  mutex_unlock(q->guard);

  return us;
}

/**
 * Enqueue transaction. Returns the node in the queue for this transaction. On failure, this will
 * return NULL. Failure will occur in two situations:
 *  1. No remaining free transactions in the pool
 *  2. No remaining space in the message queue
 */
struct trans_node*
tr_enqueue(struct t9p_context* c, struct trans_pool* q, struct trans_node* us)
{
#if __rtems__
  us->task = rtems_task_self();
#endif

  /** Send it to the I/O thread */
  if (msg_queue_send(q->queue, &us, sizeof(us)) < 0) {
    printf("Error while sending to message queue\n");
    tr_release(q, us);
    return NULL;
  }

#ifdef __rtems__
  rtems_event_send(c->rtems_thr_ident, T9P_WAKE_EVENT);
#else
  /** Wake worker thread */
  event_signal(q->recv_ev);
#endif
  return us;
}

/**
 * Release a node back into the transaction pool.
 */
void
tr_release(struct trans_pool* q, struct trans_node* tn)
{
  mutex_lock(q->guard);

  tn->next = q->freehead;
  q->freehead = tn;
  memset(&tn->tr, 0, sizeof(tn->tr));

  mutex_unlock(q->guard);
}

/**
 * Submits a new transaction to the worker thread.
 * Only call this if you're running in threaded mode!
 * \returns < 0 on error
 */
static int
tr_send_recv_worker(struct t9p_context* c, struct trans_node* n, bool* send_ok)
{
  int r;
  n = tr_enqueue(c, &c->trans_pool, n);
  if (n == NULL)
    return -ENOMEM;

  /** Wait until serviced (or timeout) */
  if ((r = tr_wait(n, c->opts.recv_timeo)) != 0) {
    /** Add the timed out node to the dead list. It is now the I/O thread's responsibility to
      * release the node and discard its data. */
    mutex_lock(c->trans_pool.guard);
    n->next = c->trans_pool.deadhead;
    c->trans_pool.deadhead = n;
    mutex_unlock(c->trans_pool.guard);

    *send_ok = n->sent;

    printf("event_wait: %s\n", t9p__strerror(r));
    return r;
  }

  *send_ok = true;

  return 0;
}

/**
 * Single-threaded mode send-recv. Acquires the socket lock and pumps the socket itself.
 */
static int
tr_send_recv_now(struct t9p_context* c, struct trans_node* n, bool* send_ok)
{
  int r;

  mutex_lock(c->socket_lock);

  /* Attempt to send packet data */
  if ((r = tr_send_now(c, n)) < 0) {
    mutex_unlock(c->socket_lock);
    *send_ok = false;
    return r;
  }

  *send_ok = true;

  /* Attempt to read the result */
  r = tr_recv_now(c, n);

  mutex_unlock(c->socket_lock);
  return r;
}

/**
 * Enqueues the node into the queue and waits for it to be servied
 * This will release the node back into the pool on error, or after the node is serviced.
 * \param c Context
 * \param n Node
 * \param tr Transaction description, copied into n->tr before sending
 * \param send_ok Output variable to receive the send status. May be NULL
 * \return < 0 on error
 */
static int
tr_send_recv(struct t9p_context* c, struct trans_node* n, struct trans* tr, bool* send_ok)
{
  int r = 0;
  bool sent = false;
  n->tr = *tr;

  send_ok = send_ok ? send_ok : &sent;

  switch (c->opts.mode) {
  case T9P_THREAD_MODE_NONE:
    if ((r = tr_send_recv_now(c, n, send_ok)) < 0)
      return r;
    break;
  case T9P_THREAD_MODE_WORKER:
    if ((r = tr_send_recv_worker(c, n, send_ok)) < 0)
      return r;
    break;
  }

  uint32_t status = n->tr.status;
  tr_release(&c->trans_pool, n); /** Release the transaction back into the pool */
  return status;
}

/**
 * Signal a node's event. Shorthand to avoid code duplication.
 */
static void
tr_signal(struct trans_node* n)
{
#ifdef USE_POSIX_EVENTS
  event_signal(n->event);
#else
  int r = rtems_event_send(n->task, T9P_NODE_EVENT);
  if (r != RTEMS_SUCCESSFUL)
    assert(0);
#endif
}

/**
 * Waits on a node's event for the specified timeout time.
 * \returns 0 on success, error val on failure
 */
static int
tr_wait(struct trans_node* n, int timeout)
{
#ifdef USE_POSIX_EVENTS
  return event_wait(n->event, timeout);
#else
  rtems_event_set es;
  rtems_status_code r = rtems_event_receive(T9P_NODE_EVENT, RTEMS_EVENT_ALL | RTEMS_WAIT,
    t9p__rt_ms_to_ticks(timeout), &es);
  return r == RTEMS_SUCCESSFUL ? 0 : -ETIMEDOUT;
#endif
}

static int
t9p__send(struct t9p_context* c, const void* data, size_t sz, int flags)
{
  return c->trans.send(c->conn, data, sz, flags);
}

/** Synchronously recv a type of packet, or Rerror. Includes timeout */
static ssize_t
t9p__recv_type(struct t9p_context* c, void* data, size_t sz, int flags, uint8_t type, uint16_t tag, struct TRcommon* ocom)
{
  ssize_t n;
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int timeoutMs = c->opts.recv_timeo;
  while (1) {
    char comb[sizeof(struct TRcommon)] = {0};
    n = c->trans.recv(c->conn, comb, sizeof(comb), T9P_RECV_PEEK);
    if (n >= sizeof(struct TRcommon)) {
      struct TRcommon com;
      if (decode_TRcommon(&com, comb, n) < 0) {
        ERROR(c, "decode_TRcommon failed\n");
        continue;
      }
      /** Check for mismatched tag */
      else if (com.tag != tag) {
        ERROR(c, "Discarding mismatched tag. %d expected, got %d\n", tag, com.tag);
      }
      /** Return if we have recv'ed the correct type, or Rlerror/Rerror */
      else if (com.type == type || com.type == T9P_TYPE_Rlerror || com.type == T9P_TYPE_Rerror) {
        *ocom = com;
        return c->trans.recv(c->conn, data, MIN(sz, com.size), 0);;
      }
      else {
        t9p__discard(c, &com);
      }
    }

    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    int diffMs = ((tp.tv_sec - start.tv_sec) * 1000) + ((tp.tv_nsec - start.tv_nsec) / 1000000);
    if (diffMs >= timeoutMs)
      break;
    usleep(1000);
  }
  return -ETIMEDOUT;
}

static void
t9p__perror(struct t9p_context* c, const char* msg, struct TRcommon* err)
{
  if (err->type == T9P_TYPE_Rlerror) {
    ERROR(c, "%s: %s\n", msg, t9p__strerror(((struct Rlerror*)err)->ecode));
  } else if (err->tag == T9P_TYPE_Rerror) {
    struct Rerror* re = (struct Rerror*)err;
    char buf[1024];
    memcpy(buf, re->ename, MIN(re->ename_len, sizeof(buf) - 1));
    buf[re->ename_len] = 0;
    ERROR(c, "%s: %s\n", msg, buf);
  }
}

static const char*
t9p__strerror(int err)
{
  return strerror(err < 0 ? -err : err);
}

static int
t9p__iserror(struct TRcommon* err)
{
  return err->type == T9P_TYPE_Rerror || err->type == T9P_TYPE_Rlerror;
}

static int
t9p__version_handshake(struct t9p_context* c)
{
  const uint8_t version[] = T9P_TARGET_VERSION;

  char buf[1024];
  int sendSize = encode_Tversion(
    buf,
    sizeof(buf),
    T9P_NOTAG,
    c->opts.msize,
    sizeof(version) - 1,
    version
  );
  if (sendSize < 0) {
    ERROR(c, "Tversion packed encode failed\n");
    return -1;
  }

  if (t9p__send(c, buf, sendSize, 0) < 0) {
    ERROR(c, "Tversion handshake failed: I/O error\n");
    return -1;
  }

  /** Listen for the return message */
  struct TRcommon com;
  ssize_t read = t9p__recv_type(c, buf, sizeof(buf) - 1, 0, T9P_TYPE_Rversion, T9P_NOTAG, &com);
  if (read < 0) {
    ERROR(c, "Rversion handshake failed: %s\n", strerror(errno));
    return -1;
  }

  if (t9p__iserror(&com)) {
    ERROR(c, "Rversion handshake failed\n");
    return -1;
  }

  struct Rversion* rv = NULL;
  if (decode_Rversion(&rv, buf, read) < 0) {
    ERROR(c, "Rversion handshake failed: failed to decode packet\n");
    return -1;
  }

  if (memcmp(rv->version, version, MIN(sizeof(version) - 1, rv->version_len))) {
    char vstr[256] = {0};
    memcpy(vstr, rv->version, MIN(rv->version_len, sizeof(vstr) - 1));
    ERROR(
      c, "Rversion handshake failed: version mismatch, requested '%s', got '%s'\n", version, vstr
    );
    t9p_free(rv);
    return -1;
  }

  c->msize = rv->msize;

  DEBUG(c, "Using %s with msize %lu\n", version, rv->msize);
  t9p_free(rv);
  return 0;
}

static int
t9p__attach_root(struct t9p_context* c)
{
  char packetBuf[4096];
  int len;
  uint16_t tag = 0;
  uint32_t uid = *c->opts.user ? T9P_NOUID : c->opts.uid;

  struct t9p_handle_node* h = c->root ? c->root : t9p__alloc_handle(c, NULL, c->apath);
  if (!h) {
    ERROR(c, "Rattach failed: unable to allocate handle\n");
    goto error;
  }

  if ((len = encode_Tattach(
         packetBuf,
         sizeof(packetBuf),
         tag,
         h->h.fid,
         T9P_NOFID,
         strlen(c->opts.user),
         (const uint8_t*)c->opts.user,
         strlen(c->apath),
         (const uint8_t*)c->apath,
         uid
       )) < 0) {
    ERROR(c, "Tattach root failed: unable to encode packet\n");
    goto error;
  }

  if (t9p__send(c, packetBuf, len, 0) < 0) {
    ERROR(c, "Tattach root failed: unable to send\n");
    goto error;
  }

  struct TRcommon com;
  ssize_t read = t9p__recv_type(c, packetBuf, sizeof(packetBuf), 0, T9P_TYPE_Rattach, tag, &com);
  if (read < 0) {
    ERROR(c, "Rattach failed: read timeout\n");
    goto error;
  }

  if (t9p__iserror(&com)) {
    ERROR(c, "Rattach failed");
    goto error;
  }

  struct Rattach ra;
  if (decode_Rattach(&ra, packetBuf, read) < 0) {
    ERROR(c, "Rattach failed: unable to decode packet\n");
    goto error;
  }

  h->h.qid = ra.qid;
  h->h.valid_mask |= T9P_HANDLE_FID_VALID | T9P_HANDLE_QID_VALID | T9P_HANDLE_ACTIVE;

  c->root = h;
  return 0;

error:
  t9p__release_handle(c, h);
  return -1;
}

static int
t9p__clunk_sync(struct t9p_context* c, int fid)
{
  char buf[128];

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l;
  if ((l = encode_Tclunk(buf, sizeof(buf), n->tag, fid)) < 0) {
    ERROR(c, "Failed to encode Tclunk\n");
    tr_release(&c->trans_pool, n);
    return -EPROTO;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tclunk,
    .data = buf,
    .size = l,
    .rtype = T9P_TYPE_Rclunk,
    .rsize = sizeof(buf),
    .rdata = buf,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tclunk failed\n", __FUNCTION__);
    return l;
  }
  return 0;
}

/**
 * Releases the string, decrementing the ref count.
 * If the ref count is 0 after decrementing, the string is destroyed
 * and this function returns NULL. Otherwise, it returns the parameter
 * you passed in.
 */
T9P_NODISCARD static struct t9p_string*
t9p__string_release(struct t9p_string* str)
{
  uint32_t r = atomic_sub_u32(&str->rc,1);
  if (r == 0) {
    t9p_free(str);
    return NULL;
  }
  /** we've likely underflowed and this is a bug! */
  else if (r == UINT32_MAX) {
    assert(0);
  }
  return str;
}

static void
t9p__string_acquire(struct t9p_string* str)
{
  atomic_add_u32(&str->rc, 1);
}

/**
 * Allocate new ref counted string
 * Always starts with a rc of 1, do not addref to this!
 */
T9P_NODISCARD static struct t9p_string*
t9p__string_new_path(const char* dname, const char* fname)
{
  const size_t dl = strlen(dname);
  const size_t fl = strlen(fname);
  
  const size_t tl = dl + fl + 2; /* +1 for NUL, +1 for path sep */
  struct t9p_string* s = t9p_calloc(sizeof(struct t9p_string) + tl, 1);
  s->len = tl;
  s->rc = 1; /* always start with 1 ref */
  strNcpy(s->string, dname, dl+1);
  s->string[dl] = '/';
  strNcpy(s->string + dl + 1, fname, fl+1);
  return s;
}

/**
 * "copies" the string. Just increments refcount and returns it.
 */
T9P_NODISCARD static struct t9p_string*
t9p__string_copy(struct t9p_string* str)
{
  t9p__string_acquire(str);
  return str;
}

/********************************************************************/
/*                                                                  */
/*                      P U B L I C    A P I                        */
/*                                                                  */
/********************************************************************/

void
t9p_opts_init(struct t9p_opts* opts)
{
  memset(opts, 0, sizeof(*opts));
#ifdef __mcoldfire__
  opts->msize = 4096; /* Coldfire works better with smaller msize */
#else
  opts->msize = 65536;
#endif
  opts->queue_size = T9P_PACKET_QUEUE_SIZE;
  opts->max_fids = DEFAULT_MAX_FILES;
  opts->send_timeo = DEFAULT_SEND_TIMEO;
  opts->recv_timeo = DEFAULT_RECV_TIMEO;
  opts->prio = T9P_THREAD_PRIO_MED;
  opts->mode = T9P_THREAD_MODE_NONE;
}

t9p_context_t*
t9p_init(
  t9p_transport_t* transport, const t9p_opts_t* opts, const char* apath, const char* addr,
  const char* mntpoint
)
{
  /** Validate transport to prevent misuse **/
  assert(transport);
  assert(transport->connect);
  assert(transport->disconnect);
  assert(transport->recv);
  assert(transport->send);
  assert(transport->init);
  assert(transport->shutdown);
  assert(transport->getsock);
  assert(transport->reconnect);
  assert(opts);

  t9p_context_t* c = t9p_aligned_zmalloc(sizeof(struct t9p_context), T9P_ALIGNOF(struct t9p_context));
  strNcpy(c->mntpoint, mntpoint, sizeof(c->mntpoint));
  strNcpy(c->addr, addr, sizeof(c->addr));
  strNcpy(c->apath, apath, sizeof(c->apath));
  c->trans = *transport;
  c->opts = *opts;

  /** Init transport layer */
  if (!(c->conn = transport->init(c))) {
    ERRLOG("Transport init failed\n");
    goto error_pre_fhl;
  }

  /** Attempt to connect */
  if (transport->connect(c->conn, addr) < 0) {
    ERRLOG("Connection to %s failed\n", addr);
    goto error_pre_fhl;
  }

  /** Init file handle list */
  c->fhl = t9p_calloc(sizeof(struct t9p_handle_node), opts->max_fids);
  c->fhl_max = opts->max_fids;
  c->fhl_count = 0;
  c->fhl_free = NULL;
  for (int i = 0; i < c->fhl_max; ++i) {
    struct t9p_handle_node* n = &c->fhl[i];
    n->next = c->fhl_free;
    n->h.fid = i;
    c->fhl_free = n;
  }

  if (!(c->fhl_mutex = mutex_create())) {
    ERRLOG("Unable to create fhl_mutex\n");
    goto error_pre_fhl;
  }

  if (!(c->socket_lock = mutex_create())) {
    ERRLOG("Unable to create socket_lock\n");
    goto error_pre_fhl;
  }

  if (!(c->recv_event = event_create())) {
    ERRLOG("Unable to create event\n");
    goto error_post_fhl;
  }

  if (tr_pool_init(&c->trans_pool, MAX_TRANSACTIONS) < 0) {
    ERRLOG("Unable to create transaction pool\n");
    goto error_post_fhl;
  }

  mutex_lock(c->socket_lock);

  /** Perform the version handshake */
  if (t9p__version_handshake(c) < 0) {
    ERRLOG("Connection to %s failed\n", addr);
    transport->disconnect(c->conn);
    transport->shutdown(c->conn);
    mutex_unlock(c->socket_lock);
    goto error_post_pool;
  }

  /** Attach to the root fs */
  if (t9p__attach_root(c) < 0) {
    ERRLOG("Connected to %s failed\n", addr);
    transport->disconnect(c->conn);
    transport->shutdown(c->conn);
    mutex_unlock(c->socket_lock);
    goto error_post_pool;
  }

  mutex_unlock(c->socket_lock);

  /** Kick off thread */
  if (opts->mode == T9P_THREAD_MODE_WORKER) {
    c->thr_run = 1;
    if (!(c->io_thread = thread_create(t9p__thread_proc, c, c->opts.prio))) {
      t9p_shutdown(c);
      return NULL;
    }
  }

  return c;

error_post_pool:
  tr_pool_destroy(&c->trans_pool);
error_post_fhl:
  mutex_destroy(c->socket_lock);
  mutex_destroy(c->fhl_mutex);
  event_destroy(c->recv_event);
error_pre_fhl:
  t9p_free(c);
  return NULL;
}

void
t9p_shutdown(t9p_context_t* c)
{
  /** Clunk all active file handles */
  mutex_lock(c->fhl_mutex);
  for (int i = 0; i < c->fhl_max; ++i)
    if (c->fhl[i].h.valid_mask & T9P_HANDLE_FID_VALID)
      t9p__clunk_sync(c, c->fhl[i].h.fid);
  mutex_unlock(c->fhl_mutex);

  if (c->io_thread) {
    /** Kill off the thread */
    c->thr_run = 0;
    thread_join(c->io_thread);
  }

  /** Disconnect and shutdown the transport layer */
  c->trans.disconnect(c->conn);
  c->trans.shutdown(c->conn);

  t9p_free(c->fhl);

  mutex_destroy(c->fhl_mutex);
  event_destroy(c->recv_event);
  t9p_free(c);
}

static int
t9p__open_handle_internal(t9p_context_t* c, t9p_handle_t parent, const char* path, t9p_handle_t myhandle, t9p_handle_t* outhandle)
{
  TRACE(c, "t9p_open_handle(p=%p,path=%s)\n", parent, path);
  char p[T9P_PATH_MAX];
  strNcpy(p, path, sizeof(p));
  *outhandle = NULL;

  /** Default parent is the root handle */
  if (!parent)
    parent = t9p_get_root(c);

  int nwcount = 0;
  char* comps[MAX_PATH_COMPONENTS];

  /** If we start with a slash, strip it off. Files are assumed to be relative to root already */
  while (*path == '/')
    ++path;

  /** Split path into components for walk */
  char* sp = NULL;
  for (char* s = strtok_r(p, "/", &sp); s && *s; s = strtok_r(NULL, "/", &sp)) {
    comps[nwcount++] = s;
  }

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n) {
    ERROR(c, "%s: out of nodes\n", __FUNCTION__);
    return -ENOMEM;
  }

  struct t9p_handle_node* fh = myhandle ? t9p__handle_by_fid(c, myhandle)
    : t9p__alloc_handle(c, parent, path);
  
  if (!fh) {
    ERROR(c, "%s: out of handles\n", __FUNCTION__);
    return -ENOMEM;
  }

  char packet[1024];
  int l = 0;
  if ((l = encode_Twalk(
         packet, sizeof(packet), n->tag, parent->fid, fh->h.fid, nwcount, (const char* const*)comps
       )) < 0) {
    ERROR(c, "%s(%s): unable to encode Twalk\n", __FUNCTION__, path);
    tr_release(&c->trans_pool, n);
    goto error;
  }

  /** Build transaction to send */
  struct trans tr = {
    .ttype = T9P_TYPE_Twalk,
    .data = packet,
    .size = l,
    .rtype = T9P_TYPE_Rwalk,
    .rdata = packet,
    .rsize = sizeof(packet),
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s(%s): Twalk: %s\n", __FUNCTION__, path, t9p__strerror(l));
    goto error;
  }

  struct Rwalk rw;
  qid_t* qids = NULL;
  if ((l = decode_Rwalk(&rw, packet, l, &qids)) < 0) {
    ERROR(c, "%s: Rwalk decode failed\n", __FUNCTION__);
    goto error;
  }

  /** If the number of comps we requested earlier doesn't match the number of qids we have,
    * we have failed to open the full path. Just clunk and return error */
  if (nwcount != rw.nwqid) {
    t9p__clunk_sync(c, fh->h.fid);
    t9p_free(qids);
    goto error;
  }

  /** We have cloned the fid */
  if (rw.nwqid == 0)
    fh->h.qid = parent->qid;
  else
    fh->h.qid = qids[rw.nwqid - 1];
  fh->h.valid_mask |= T9P_HANDLE_FID_VALID | T9P_HANDLE_QID_VALID;
  t9p_free(qids);

  *outhandle = &fh->h;
  return 0;
error:
  if (!myhandle) /* only release handles we create */
    t9p__release_handle(c, fh);
  return -l;
}

t9p_handle_t
t9p_open_handle(t9p_context_t* c, t9p_handle_t parent, const char* path)
{
  if (t9p__maybe_recover(c, parent) < 0)
    return NULL;

  t9p_handle_t h;
  if (t9p__open_handle_internal(c, parent, path, NULL, &h) < 0)
    return NULL;
  return h;
}

void
t9p_close_handle(t9p_context_t* c, t9p_handle_t h)
{
  TRACE(c, "t9p_close_handle(h=%p)\n", h);
  if (!h)
    return;

  if (!(h->valid_mask & T9P_HANDLE_ACTIVE))
    return;
  /** Clunk it if the FID is valid */
  if (h->valid_mask & T9P_HANDLE_FID_VALID)
    t9p__clunk_sync(c, h->fid);
  t9p__release_handle(c, &c->fhl[h->fid]);
}

t9p_handle_t
t9p_get_root(t9p_context_t* c)
{
  return &c->root->h;
}

int
t9p_is_root(t9p_context_t* c, t9p_handle_t h)
{
  return c->root->h.fid == h->fid;
}

int
t9p_attach(t9p_context_t* c, const char* apath, t9p_handle_t afid, t9p_handle_t* outhandle)
{
  TRACE(c, "t9p_attach(c=%p,path=%s,outhandle=%p)\n", c, apath, outhandle);

  char packet[512];
  ssize_t l = 0;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  struct t9p_handle_node* h = t9p__alloc_handle(c, afid, apath);
  if (!h) {
    tr_release(&c->trans_pool, n);
    return -ENOMEM;
  }

  l = encode_Tattach(packet, sizeof(packet), n->tag, h->h.fid, afid ? afid->fid : T9P_NOFID,
                     strlen(c->opts.user), (const uint8_t*)c->opts.user,
                     strlen(apath), (const uint8_t*)apath, c->opts.uid);

  if (l < 0) {
    ERROR(c, "%s: unable to encode Tattach\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    t9p__release_handle(c, h);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tattach,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rattach,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tattach failed: %s\n", __FUNCTION__, t9p__strerror(l));
    t9p__release_handle(c, h);
    return l;
  }

  struct Rattach ra;
  if ((l = decode_Rattach(&ra, packet, l)) < 0) {
    ERROR(c, "%s: Rattach decode failed", __FUNCTION__);
    t9p__release_handle(c, h);
    return -EPROTO;
  }

  if (outhandle)
    *outhandle = &h->h;

  return 0;
}

int
t9p_open(t9p_context_t* c, t9p_handle_t h, uint32_t mode)
{
  TRACE(c, "t9p_open(c=%p,h=%p,mode=0x%X)\n", c, h, (unsigned)mode);
  if (t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  /** File already open, just return success */
  if (h->iounit != 0)
    return 0;

  char packet[128];

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l = 0;
  if ((l = encode_Tlopen(packet, sizeof(packet), n->tag, h->fid, mode)) < 0) {
    ERROR(c, "%s: unable to encode Tlopen\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tlopen,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rlopen,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tlopen: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  struct Rlopen rl;
  if (decode_Rlopen(&rl, packet, l) < 0) {
    ERROR(c, "%s: Malformed Rlopen\n", __FUNCTION__);
    return -EPROTO;
  }

  h->qid = rl.qid;
  h->valid_mask |= T9P_HANDLE_QID_VALID;
  h->iounit = rl.iounit;
  h->obits = mode;
  /** If the server is telling us 'whatever', iounit becomes a derivative of msize.
    * We cannot exceed msize even if iounit is 0. */
  if (h->iounit == 0) {
    h->iounit = MIN(c->msize - sizeof(struct Twrite), c->msize - sizeof(struct Rread));
  }

  return 0;
}

void
t9p_close(t9p_handle_t handle)
{
  /* Nothing to do on 9p */
}

static ssize_t
t9p_read_internal(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, void* outbuffer)
{
  char packet[128];
  char rheader[sizeof(struct Rread)];
  int status = 0;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l;
  if ((l = encode_Tread(packet, sizeof(packet), n->tag, h->fid, offset, num)) < 0) {
    ERROR(c, "%s: could not encode Tread\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tread,
    .data = packet,
    .size = l,
    .rdata = outbuffer,
    .rsize = num,
    .rtype = T9P_TYPE_Rread,
    .rheader = rheader,
    .rheadersz = sizeof(struct Rread)
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tread: %s\n", __FUNCTION__, t9p__strerror(l));
    status = l;
    goto error;
  }

  struct Rread rr;
  if (decode_Rread(&rr, rheader, l) < 0) {
    ERROR(c, "%s: unable to decode Rread\n", __FUNCTION__);
    status = -EPROTO;
    goto error;
  }

  return MIN(num, rr.count);

error:
  return status;
}

ssize_t
t9p_read(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, void* outbuffer)
{
  TRACE(c, "t9p_read(h=%p,off=%" PRIu64 ",num=%u,out=%p)\n", h, offset, (unsigned)num, outbuffer);
  if (t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  if (!t9p__is_fid_rw(h, 0))
    return -EACCES;

  const size_t maxRd = c->msize - DIOD_IOHDRSZ; /* See FIXME note at #define */
  uint64_t off = 0;
  char* buf = outbuffer;
  while (num > 0) {
    const size_t toRd = MIN(num, maxRd);
    ssize_t r = t9p_read_internal(c, h, offset + off, toRd, buf);
    if (r < 0)
      return r;
    else if (r == 0) /* end of file */
      return off;

    off += r;
    buf += r;
    if (r > num) num = 0; /* paranoia! should never happen */
    else num -= r;
  }

  return off;
}

static ssize_t
t9p_write_internal(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, const void* inbuffer)
{
  char packet[128];

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l;
  if ((l = encode_Twrite(packet, sizeof(packet), n->tag, h->fid, offset, num)) < 0) {
    ERROR(c, "%s: unable to encode Twrite\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Twrite,
    .hdata = packet,
    .hsize = l,
    .data = inbuffer,
    .size = num,
    .rtype = T9P_TYPE_Rwrite,
    .rdata = packet,
    .rsize = sizeof(packet)
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Twrite: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  struct Rwrite rw;
  if (decode_Rwrite(&rw, packet, l) < 0) {
    ERROR(c, "%s: failed to decode Rwrite\n", __FUNCTION__);
    return -EPROTO;
  }

  return rw.count;
}

ssize_t
t9p_write(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, const void* inbuffer)
{
  TRACE(c, "t9p_write(h=%p,off=%" PRIu64 ",num=%u,in=%p)\n", h, offset, (unsigned)num, inbuffer);
  if (t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  if (!t9p__is_fid_rw(h, 1))
    return -EACCES;

  const ssize_t maxWr = c->msize - DIOD_IOHDRSZ; /* See FIXME note at #define */
  const char* buf = inbuffer;
  uint64_t off = 0;
  while (num > 0) {
    const ssize_t toWrite = MIN(num, maxWr);
    ssize_t r = t9p_write_internal(c, h, offset + off, toWrite, buf);
    if (r < 0)
      return r;

    off += r;
    buf += r;
    if (r > num) num = 0; /* paranoia! should never happen */
    else num -= r;
  }

  return off;
}

int
t9p_getattr(t9p_context_t* c, t9p_handle_t h, struct t9p_getattr* attr, uint64_t mask)
{
  TRACE(c, "t9p_getattr(h=%p,mask=%" PRIx64 ")\n", h, mask);
  char packet[256];

  if (!t9p_is_valid(h))
    return -EBADF;

  if (t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l;
  if ((l = encode_Tgetattr(packet, sizeof(packet), n->tag, h->fid, mask)) < 0) {
    ERROR(c, "%s: failed to encode Tgetattr\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tgetattr,
    .data = packet,
    .size = l,
    .rtype = T9P_TYPE_Rgetattr,
    .rdata = packet,
    .rsize = sizeof(packet),
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tgetattr: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  struct Rgetattr rg;
  if (decode_Rgetattr(&rg, packet, l) < 0) {
    ERROR(c, "%s: failed to decode Rgetattr\n", __FUNCTION__);
    return -EPROTO;
  }

  attr->valid = rg.valid;
  attr->qid = rg.qid;
  attr->mode = rg.mode;
  attr->uid = rg.uid;
  attr->gid = rg.gid;
  attr->nlink = rg.nlink;
  attr->rdev = rg.rdev;
  attr->fsize = rg.fsize;
  attr->blksize = rg.blksize;
  attr->blocks = rg.blocks;
  attr->atime_sec = rg.atime_sec;
  attr->atime_nsec = rg.atime_nsec;
  attr->mtime_sec = rg.mtime_sec;
  attr->mtime_nsec = rg.mtime_nsec;
  attr->ctime_sec = rg.ctime_sec;
  attr->ctime_nsec = rg.ctime_nsec;
  attr->btime_sec = rg.btime_sec;
  attr->btime_nsec = rg.btime_nsec;
  attr->gen = rg.gen;
  attr->data_version = rg.data_version;
  return 0;
}

int
t9p_create(
  t9p_context_t* c, t9p_handle_t* newhandle, t9p_handle_t parent, const char* name, uint32_t mode,
  uint32_t gid, uint32_t flags
)
{
  TRACE(c, "t9p_create(parent=%p,nh=%p,name=%s,mode=0x%X,gid=%d,flags=0x%X)\n", parent, newhandle,
    name, (unsigned)mode, (unsigned)gid, (unsigned)flags);

  if (t9p__maybe_recover(c, parent) < 0)
    return -EBADF;

  char packet[512];

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  /** If parent is NULL, parent is root */
  if (!t9p_is_valid(parent))
    parent = t9p_get_root(c);

  /** Use default gid if none provided */
  if (gid == T9P_NOGID)
    gid = c->opts.gid;

  /** Duplicate fid of parent */
  t9p_handle_t h;
  if (t9p_dup(c, parent, &h) < 0)
    return -EBADF;

  int l;
  if ((l = encode_Tlcreate(packet, sizeof(packet), n->tag, h->fid, name, flags, mode, gid)) < 0) {
    ERROR(c, "%s: failed to encode Tlcreate\n", __FUNCTION__);
    t9p_close_handle(c, h);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tlcreate,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rlcreate
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tlcreate: %s\n", __FUNCTION__, t9p__strerror(l));
    t9p_close_handle(c, h);
    return l;
  }

  struct Rlcreate rl;
  if (decode_Rlcreate(&rl, packet, l) < 0) {
    ERROR(c, "%s: Rlcreate decode failed\n", __FUNCTION__);
    t9p_close_handle(c, h);
    return -EPROTO;
  }

  if (newhandle) {
    h->iounit = rl.iounit;
    /** If the server is telling us 'whatever', provide our own length */
    if (h->iounit == 0)
      h->iounit = UINT32_MAX;
    *newhandle = h;
  }
  /** Immediately clunk if the handle is not needed */
  else {
    t9p_close_handle(c, h);
  }

  return 0;
}

ssize_t
t9p_stat_size(t9p_context_t* c, t9p_handle_t h)
{
  struct t9p_getattr ga = {0};
  ssize_t l = t9p_getattr(c, h, &ga, T9P_GETATTR_SIZE);
  if (l < 0)
    return l;
  return ga.fsize;
}

int
t9p_dup(t9p_context_t* c, t9p_handle_t todup, t9p_handle_t* outhandle)
{
  assert(c);
  TRACE(c, "t9p_dup(todup=%p,out=%p)\n", todup, outhandle);
  char packet[128];

  *outhandle = NULL;
  if (!t9p_is_valid(todup))
    return -EBADF;

  if (t9p__maybe_recover(c, todup) < 0)
    return -EBADF;

  struct t9p_handle_node* h = _copy_handle(c, todup);
  if (!h) {
    ERROR(c, "%s: unable to alloc new handle\n", __FUNCTION__);
    return -ENOMEM;
  }

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l;
  if ((l = encode_Twalk(packet, sizeof(packet), n->tag, todup->fid, h->h.fid, 0, NULL)) < 0) {
    ERROR(c, "%s: failed to encode Twalk\n", __FUNCTION__);
    t9p__release_handle(c, h);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Twalk,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rwalk,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Twalk: %s\n", __FUNCTION__, t9p__strerror(l));
    t9p__release_handle(c, h);
    return -EIO;
  }

  struct Rwalk rw;
  qid_t* qid = NULL;
  if (decode_Rwalk(&rw, packet, l, &qid) < 0) {
    t9p__release_handle(c, h);
    return -EPROTO;
  }

  if (rw.nwqid > 0)
    h->h.qid = qid[rw.nwqid - 1];
  else
    h->h.qid = todup->qid;
  h->h.valid_mask |= T9P_HANDLE_FID_VALID | T9P_HANDLE_QID_VALID;
  *outhandle = &h->h;
  return 0;
}

int
t9p_remove(t9p_context_t* c, t9p_handle_t h)
{
  TRACE(c, "t9p_remove(h=%p)\n", h);
  char packet[128];
  bool send_ok;

  if (!t9p_is_valid(h))
    return -EBADF;
  if (t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l;
  if ((l = encode_Tremove(packet, sizeof(packet), n->tag, h->fid)) < 0) {
    ERROR(c, "%s: unable to encode Tremove\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tremove,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rremove
  };

  if ((l = tr_send_recv(c, n, &tr, &send_ok)) < 0) {
    ERROR(c, "%s: Tremove: %s\n", __FUNCTION__, t9p__strerror(l));
    /* Tremove is basically a clunk with the side effect of removing a file. This will clunk
     * even if we get Rlerror back from the server. If the send was OK and the server should
     * have received our Tremove, release the fid */
    if (send_ok)
      t9p__release_handle_by_fid(c, h);
    return l;
  }

  t9p__release_handle_by_fid(c, h);

  return 0;
#if 0
  n = tr_enqueue(c, &c->trans_pool, n);
  if (!n) {
    ERROR(c, "%s: unable to queue\n", __FUNCTION__);
    return -EIO;
  }

#warning FIXME: This logic is broken for non-threaded mode

  /** FIXME: We should only release the FID if we get back either Rerror or Rlerror from the server.
   * It is true that Tremove will clunk even on Rlerror, but we need to make sure that the server
   * *actually* gets our Tremove... With TCP transport, this probably doesn't matter too much. */

  /** Tremove is basically just a clunk with the side effect of removing a file. This will clunk
   * even if the remove fails */
  t9p__release_handle_by_fid(c, h);

  if (tr_wait(n, c->opts.recv_timeo) != 0) {
    ERROR(c, "%s: timed out\n", __FUNCTION__);
    tr_release(&c->trans_pool, n); // FIXME:!!!!!!!!!!! USE AFTER FREE IN WORKER THREAD
    return 0; /** TODO: Returning -1 here and releasing the file handle would be inconsistent with
                 the other error cases */
  }

  tr_release(&c->trans_pool, n);
#endif

  return 0;
}

int
t9p_fsync(t9p_context_t* c, t9p_handle_t file, uint32_t datasync)
{
  TRACE(c, "t9p_fsync(h=%p)\n", file);
  char packet[128];
  if (!t9p_is_valid(file) || t9p__maybe_recover(c, file) < 0)
    return -EBADF;
  if (!t9p_is_open(file))
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l;
  if ((l = encode_Tfsync(packet, sizeof(packet), n->tag, file->fid, datasync)) < 0) {
    ERROR(c, "%s: Unable to encode Tfsync\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tfsync,
    .data = packet,
    .size = l,
    .rtype = T9P_TYPE_Rfsync,
    .rdata = packet,
    .rsize = sizeof(packet)
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tfsync: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  return 0;
}

int
t9p_mkdir(
  t9p_context_t* c, t9p_handle_t parent, const char* name, uint32_t mode, uint32_t gid,
  qid_t* outqid
)
{
  TRACE(c, "t9p_mkdir(p=%p,name=%s,mode=0x%X,gid=%d)\n", parent, name, (unsigned)mode, 
    (unsigned)gid);

  char packet[512];

  if (!t9p_is_valid(parent))
    return -EBADF;
  if (t9p__maybe_recover(c, parent) < 0)
    return -EBADF;

  if (gid == T9P_NOGID) {
    gid = c->opts.gid;
  }

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  int l;
  if ((l = encode_Tmkdir(packet, sizeof(packet), n->tag, parent->fid, name, mode, gid)) < 0) {
    ERROR(c, "%s: Unable to encode Tmkdir\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tmkdir,
    .data = packet,
    .size = l,
    .rtype = T9P_TYPE_Rmkdir,
    .rdata = packet,
    .rsize = sizeof(packet),
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tmkdir: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  if (outqid) {
    struct Rmkdir rm;
    if (decode_Rmkdir(&rm, packet, l) < 0) {
      ERROR(c, "%s: failed to decode Rmkdir\n", __FUNCTION__);
      return -EPROTO;
    }
    *outqid = rm.qid;
  }

  return 0;
}

int
t9p_statfs(t9p_context_t* c, t9p_handle_t h, struct t9p_statfs* statfs)
{
  TRACE(c, "t9p_statfs(h=%p,st=%p)\n", h, statfs);
  char packet[256];
  int l;

  if (!t9p_is_valid(h))
    return -EBADF;
  if (t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  if ((l = encode_Tstatfs(packet, sizeof(packet), n->tag, h->fid)) < 0) {
    ERROR(c, "%s: Unable to encode Tstatfs\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tstatfs,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rstatfs,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tstatfs: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  struct Rstatfs rs;
  if (decode_Rstatfs(&rs, packet, l) < 0) {
    ERROR(c, "%s: failed to decode Rstatfs\n", __FUNCTION__);
    return -EPROTO;
  }

  statfs->bavail = rs.bavail;
  statfs->bfree = rs.bfree;
  statfs->blocks = rs.blocks;
  statfs->fsid = rs.fsid;
  statfs->ffree = rs.ffree;
  statfs->namelen = rs.namelen;
  statfs->files = rs.files;
  statfs->type = rs.type;
  statfs->bsize = rs.bsize;

  return 0;
}

int
t9p_readlink(t9p_context_t* c, t9p_handle_t h, char* outPath, size_t outPathSize)
{
  TRACE(c, "t9p_readlink(h=%p,op=%p,os=%zu)\n", h, outPath, outPathSize);
  char packet[512];
  int l;

  if (!t9p_is_valid(h))
    return -EBADF;
  if (t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  if ((l = encode_Treadlink(packet, sizeof(packet), n->tag, h->fid)) < 0) {
    ERROR(c, "%s: Unable to encode Treadlink\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Treadlink,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rreadlink,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Treadlink: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  struct Rreadlink rl;
  if (decode_Rreadlink(&rl, outPath, outPathSize, packet, l) < 0) {
    ERROR(c, "%s: failed to decode Rreadlink\n", __FUNCTION__);
    return -EPROTO;
  }

  return 0;
}

int
t9p_symlink(
  t9p_context_t* c, t9p_handle_t dir, const char* dst, const char* src, uint32_t gid, qid_t* oqid
)
{
  TRACE(c, "t9p_symlink(d=%p,dst=%s,src=%s,gid=%d,oqid=%p)\n", dir, dst, src, (unsigned)gid, oqid);
  char packet[768];
  int l;

  if (!t9p_is_valid(dir))
    dir = t9p_get_root(c);

  if (t9p__maybe_recover(c, dir) < 0)
    return -EBADF;

  if (gid == T9P_NOGID)
    gid = c->opts.gid;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  if ((l = encode_Tsymlink(packet, sizeof(packet), n->tag, dir->fid, dst, src, gid)) < 0) {
    ERROR(c, "%s: Unable to encode Tsymlink\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tsymlink,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rsymlink,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tsymlink: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  struct Rsymlink sl;
  if ((decode_Rsymlink(&sl, packet, l)) < 0) {
    ERROR(c, "%s: Failed to decode Rsymlink\n", __FUNCTION__);
    return -EPROTO;
  }

  if (oqid)
    *oqid = sl.qid;

  return 0;
}

struct _t9p_parse_dir_param
{
  struct t9p_dir_info** prev;
  struct t9p_dir_info** head;
  uint64_t* offset;
};

/**
 * Used with decode_Rreaddir.
 */
static void
_t9p_parse_dir_callback(void* param, struct Rreaddir_dir dir, const char* name)
{
  struct _t9p_parse_dir_param* dp = param;
  struct t9p_dir_info* di = t9p_calloc(sizeof(struct t9p_dir_info) + dir.namelen + 1, 1);
  di->qid = dir.qid;
  di->type = dir.type;

  memcpy(di->name, name, dir.namelen);
  di->name[dir.namelen] = 0;

  /** Set the previous node to us */
  if (*dp->prev)
    (*dp->prev)->next = di;
  *dp->prev = di;

  /** Set head */
  if (!*dp->head)
    *dp->head = di;

  /** Record the offset of this record; needed for additional Treaddir calls */
  *dp->offset = dir.offset;
}

int
t9p_readdir(t9p_context_t* c, t9p_handle_t dir, t9p_dir_info_t** outdirs)
{
  char packet[512];
  int l, status = 0;
  *outdirs = NULL;
  t9p_dir_info_t *prev = NULL, *head = NULL;

  /** fid must be valid AND open */
  if (!t9p_is_valid(dir) || !t9p_is_open(dir))
    return -EBADF;

  if (t9p__maybe_recover(c, dir) < 0)
    return -EBADF;

  /** Only work on dirs.. */
  if (!(dir->qid.type & T9P_QID_DIR))
    return -ENOTDIR;

  /** Treaddir is a bit of a strange call. count does not refer to the number of records returned,
   *  but instead refers to the number of bytes returned. In some ways this is better than the
   * number of records because we can constrain the number of bytes better than arbitrary length
   * records. Count will always be our packet buffer size minus the Rreaddir header size. Offset is
   * adjusted accordingly.
   */
  const uint32_t count = sizeof(packet) - sizeof(struct Rreaddir);
  uint64_t offset = 0;
  for (int i = 0; i < 999; ++i) {

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) {
      status = -ENOMEM;
      goto error;
    }

    if ((l = encode_Treaddir(packet, sizeof(packet), n->tag, dir->fid, offset, count)) < 0) {
      ERROR(c, "%s: Unable to encode Treaddir\n", __FUNCTION__);
      status = -EINVAL;
      tr_release(&c->trans_pool, n);
      goto error;
    }

    struct trans tr = {
      .ttype = T9P_TYPE_Treaddir,
      .data = packet,
      .size = l,
      .rdata = packet,
      .rsize = sizeof(packet),
      .rtype = T9P_TYPE_Rreaddir
    };

    if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
      ERROR(c, "%s: Treaddir: %s\n", __FUNCTION__, t9p__strerror(l));
      status = l;
      goto error;
    }

    /** NOTE: offset and prev will be set by _t9p_parse_dir_callback */
    struct _t9p_parse_dir_param dp = {
      .prev = &prev,
      .head = &head,
      .offset = &offset
    };

    struct Rreaddir rd;
    if ((decode_Rreaddir(&rd, packet, l, _t9p_parse_dir_callback, &dp)) < 0) {
      ERROR(c, "%s: Failed to decode Rreaddir\n", __FUNCTION__);
      status = -EPROTO;
      goto error;
    }

    /** Rreaddir returns count = 0 or offset = -1 when no more data is available to be read */
    if (rd.count == 0 || offset == (uint64_t)-1)
      break;
  }

  *outdirs = head;
  return 0;
error:
  for (t9p_dir_info_t* d = *outdirs; d;) {
    t9p_dir_info_t* dn = d->next;
    t9p_free(d);
    d = dn;
  }
  return status;
}

struct _t9p_parse_dir_dirents_param
{
  ssize_t* i;
  ssize_t totalWanted;
  uint64_t* offset;
  void* buffer;
};

/**
 * Used with decode_Rreaddir in t9p_scandir
 */
static void
_t9p_parse_dir_callback_dirents(void* param, struct Rreaddir_dir dir, const char* name)
{
  struct _t9p_parse_dir_dirents_param* dp = param;

  /** Skip if we're out of dirents */
  if (*dp->i >= dp->totalWanted)
    return;

  struct dirent* de = ((struct dirent*)dp->buffer) + *dp->i;
  de->d_reclen = sizeof(*de);
#if __RTEMS_MAJOR__ >= 6
  de->d_type = dir.type;
  de->d_fileno = *dp->i;
#endif
  de->d_off = sizeof(struct dirent) * *dp->i;
  size_t nl = MIN(dir.namelen, sizeof(de->d_name)-1);
#ifdef __rtems__
  de->d_namlen = nl;
#endif
  memcpy(de->d_name, name, nl);
  de->d_name[nl] = 0;

  /** Record offset for subsequent calls */
  *dp->offset = dir.offset;

  ++(*dp->i);
}

ssize_t 
t9p_readdir_dirents(t9p_context_t* c, t9p_handle_t dir, t9p_scandir_ctx_t* ctx,
  void* buffer, size_t bufsize)
{
  char packet[512];
  int l, status = 0;

  if (bufsize < sizeof(struct dirent))
    return -1;

  /** fid must be valid AND open */
  if (!t9p_is_valid(dir) || !t9p_is_open(dir))
    return -EBADF;

  if (t9p__maybe_recover(c, dir) < 0)
    return -EBADF;

  /** Only work on dirs.. */
  if (!(dir->qid.type & T9P_QID_DIR))
    return -ENOTDIR;

  const ssize_t numEnts = bufsize / sizeof(struct dirent);

  /** Number of entries read per transaction is fixed */
  const uint32_t count = sizeof(packet) - sizeof(struct Rreaddir);

  ssize_t i;
  for (i = 0; i < numEnts;) {

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) {
      status = -ENOMEM;
      goto error;
    }

    if ((l = encode_Treaddir(packet, sizeof(packet), n->tag, dir->fid, ctx->offset, count)) < 0) {
      ERROR(c, "%s: Unable to encode Treaddir\n", __FUNCTION__);
      status = -EINVAL;
      tr_release(&c->trans_pool, n);
      goto error;
    }

    struct trans tr = {
      .ttype = T9P_TYPE_Treaddir,
      .data = packet,
      .size = l,
      .rdata = packet,
      .rsize = sizeof(packet),
      .rtype = T9P_TYPE_Rreaddir
    };

    if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
      ERROR(c, "%s: Treaddir: %s\n", __FUNCTION__, t9p__strerror(l));
      status = l;
      goto error;
    }

    /** NOTE: offset and prev will be set by _t9p_parse_dir_callback */
    struct _t9p_parse_dir_dirents_param dp = {
      .i = &i,
      .totalWanted = numEnts,
      .offset = &ctx->offset,
      .buffer = buffer,
    };

    struct Rreaddir rd;
    if ((decode_Rreaddir(&rd, packet, l, _t9p_parse_dir_callback_dirents, &dp)) < 0) {
      ERROR(c, "%s: Failed to decode Rreaddir\n", __FUNCTION__);
      status = -EPROTO;
      goto error;
    }

    /** Rreaddir returns count = 0 or offset = -1 when no more data is available to be read */
    if (rd.count == 0 || ctx->offset == (uint64_t)-1)
      break;
  }

  return i * sizeof(struct dirent);
error:
  return status;
}

int
t9p_unlinkat(t9p_context_t* c, t9p_handle_t dir, const char* file, uint32_t flags)
{
  char packet[512];
  ssize_t l;

  if (!t9p_is_valid(dir))
    return -EBADF;

  if (t9p__maybe_recover(c, dir) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  if ((l = encode_Tunlinkat(packet, sizeof(packet), n->tag, dir->fid, file, flags)) < 0) {
    ERROR(c, "%s: Unable to encode Tunlinkat\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tunlinkat,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Runlinkat,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tunlinkat: %s\n", __FUNCTION__, t9p__strerror(-l));
    return l;
  }

  struct Runlinkat ru;
  if (decode_Runlinkat(&ru, packet, l) < 0) {
    ERROR(c, "%s: failed to decode Runlinkat\n", __FUNCTION__);
    return -EPROTO;
  }

  return 0;
}

int
t9p_renameat(
  t9p_context_t* c, t9p_handle_t olddirfid, const char* oldname, t9p_handle_t newdirfid,
  const char* newname
)
{
  char packet[768];
  ssize_t l;

  if (!t9p_is_valid(olddirfid) || !t9p_is_valid(newdirfid))
    return -EBADF;

  if (t9p__maybe_recover(c, olddirfid) < 0 || t9p__maybe_recover(c, newdirfid) < 0)
    return -EBADF;

  if (!t9p_is_dir(olddirfid) || !t9p_is_dir(newdirfid))
    return -ENOTDIR;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  if ((l = encode_Trenameat(
         packet, sizeof(packet), n->tag, olddirfid->fid, oldname, newdirfid->fid, newname
       )) < 0) {
    ERROR(c, "%s: Unable to encode Trenameat\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Trenameat,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rrenameat,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Trenameat: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  struct Rrenameat ru;
  if (decode_Rrenameat(&ru, packet, l) < 0) {
    ERROR(c, "%s: failed to decode Rrenameat\n", __FUNCTION__);
    return -EPROTO;
  }

  return 0;
}

int
t9p_setattr(t9p_context_t* c, t9p_handle_t h, uint32_t mask, const struct t9p_setattr* attr)
{
  char packet[256];
  ssize_t l;

  if (!t9p_is_valid(h))
    return -EBADF;

  if (t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  if ((l = encode_Tsetattr(packet, sizeof(packet), n->tag, h->fid, mask, attr)) < 0) {
    ERROR(c, "%s: Unable to encode Tsetattr\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -EINVAL;
  }

  struct trans tr = {
    .ttype = T9P_TYPE_Tsetattr,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rsetattr,
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tsetattr: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  struct Rsetattr rs;
  if (decode_Rsetattr(&rs, packet, l) < 0) {
    ERROR(c, "%s: failed to decode Rsetattr\n", __FUNCTION__);
    return -EPROTO;
  }

  return 0;
}

int
t9p_rename(t9p_context_t* c, t9p_handle_t dir, t9p_handle_t h, const char* newname)
{
  char packet[512];
  ssize_t l;

  if (!t9p_is_valid(dir) || !t9p_is_valid(h))
    return -EBADF;

  if (t9p__maybe_recover(c, dir) < 0 || t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  if ((l = encode_Trename(packet, sizeof(packet), n->tag, h->fid, dir->fid, newname)) < 0) {
    ERROR(c, "%s: unable to encode Trename\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -1;
  }
  
  struct trans tr = {
    .ttype = T9P_TYPE_Trename,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rrename
  };

  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Trename: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }

  /* Update the file path for the node */
  (void)t9p__string_release(h->str);
  h->str = t9p__string_new_path(dir ? dir->str->string : "", newname);

  return 0;
}

int
t9p_link(t9p_context_t* c, t9p_handle_t dir, t9p_handle_t h, const char* target)
{
  char packet[512];
  ssize_t l = 0;

  if (!t9p_is_valid(dir) || !t9p_is_valid(h))
    return -EBADF;

  if (t9p__maybe_recover(c, dir) < 0 || t9p__maybe_recover(c, h) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;
  
  if ((l = encode_Tlink(packet, sizeof(packet), n->tag, dir->fid, h->fid, target)) < 0) {
    ERROR(c, "%s: unable to encode Tlink\n", __FUNCTION__);
    tr_release(&c->trans_pool, n);
    return -1;
  }
  
  struct trans tr = {
    .ttype = T9P_TYPE_Tlink,
    .data = packet,
    .size = l,
    .rdata = packet,
    .rsize = sizeof(packet),
    .rtype = T9P_TYPE_Rlink
  };
  
  if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
    ERROR(c, "%s: Tlink: %s\n", __FUNCTION__, t9p__strerror(l));
    return l;
  }
  return 0;
}

int
t9p_mknod(t9p_context_t* c, t9p_handle_t dir, const char* name, uint32_t mode, uint32_t major,
  uint32_t minor, uint32_t gid, qid_t* outqid)
{
  char packet[512];
  ssize_t l = 0;

  if (!t9p_is_valid(dir))
    return -EBADF;

  if (t9p__maybe_recover(c, dir) < 0)
    return -EBADF;

  struct trans_node* n = tr_get_node(&c->trans_pool);
  if (!n)
    return -ENOMEM;

  if ((l = encode_Tmknod(packet, sizeof(packet), n->tag, dir->fid, name, mode, major, minor, gid)) < 0) {
      ERROR(c, "%s: unable to encode Tmknod\n", __FUNCTION__);
      tr_release(&c->trans_pool, n);
      return -1;
    }
  
    struct trans tr = {
      .ttype = T9P_TYPE_Tmknod,
      .data = packet,
      .size = l,
      .rdata = packet,
      .rsize = sizeof(packet),
      .rtype = T9P_TYPE_Rmknod
    };

    if ((l = tr_send_recv(c, n, &tr, NULL)) < 0) {
      ERROR(c, "%s: Tmknod: %s\n", __FUNCTION__, t9p__strerror(l));
      return l;
    }
    return 0;
}

int
t9p_truncate(t9p_context_t* c, t9p_handle_t h, uint64_t size)
{
  if (!t9p_is_file(h))
    return -EBADF; /** FIXME: what error to use here?? */

  struct t9p_setattr sa = {
    .size = size,
  };
  return t9p_setattr(c, h, T9P_SETATTR_SIZE, &sa);
}

int
t9p_chown(t9p_context_t* c, t9p_handle_t h, uint32_t uid, uint32_t gid)
{
  uint32_t mask = 0;
  if (uid != T9P_NOUID)
    mask |= T9P_SETATTR_UID;
  if (gid != T9P_NOGID)
    mask |= T9P_SETATTR_GID;

  if (!mask)
    return 0; /** No-op */

  struct t9p_setattr sa = {.uid = uid, .gid = gid};
  return t9p_setattr(c, h, mask, &sa);
}

int
t9p_touch(t9p_context_t* c, t9p_handle_t h, int mtime, int atime, int ctime)
{
  struct t9p_setattr sa = {0};
  int mask = 0;
  if (mtime)
    mask |= T9P_SETATTR_MTIME;
  if (atime)
    mask |= T9P_SETATTR_ATIME;
  if (ctime)
    mask |= T9P_SETATTR_CTIME;

  return t9p_setattr(c, h, mask, &sa);
}

int
t9p_chmod(t9p_context_t* c, t9p_handle_t h, mode_t mode)
{
  struct t9p_setattr sa = {.mode = mode};
  return t9p_setattr(c, h, T9P_SETATTR_MODE, &sa);
}

struct t9p_stats
t9p_get_stats(t9p_context_t* c)
{
  return c->stats;
}

uint32_t
t9p_get_iounit(t9p_handle_t h)
{
  return h->iounit;
}

int
t9p_is_open(t9p_handle_t h)
{
  return h->iounit != 0;
}

int
t9p_is_valid(t9p_handle_t h)
{
  return !!(h->valid_mask & T9P_HANDLE_ACTIVE);
}

qid_t
t9p_get_qid(t9p_handle_t h)
{
  if (h->valid_mask & T9P_HANDLE_QID_VALID)
    return h->qid;
  qid_t inval = {0};
  return inval;
}

uint32_t
t9p_get_fid(t9p_handle_t h)
{
  if (h->valid_mask & T9P_HANDLE_FID_VALID)
    return h->fid;
  return ~0U;
}

uint32_t
t9p_get_msize(t9p_context_t* c)
{
  return c->msize;
}

void
t9p_free_dirs(t9p_dir_info_t* head)
{
  if (!head)
    return;
  for (t9p_dir_info_t* d = head; d;) {
    t9p_dir_info_t* dn = d->next;
    t9p_free(d);
    d = dn;
  }
}

int
t9p_is_dir(t9p_handle_t h)
{
  qid_t q = t9p_get_qid(h);
  if ((q.type & T9P_QID_DIR) == T9P_QID_DIR)
    return 1;
  if ((q.type & T9P_QID_MOUNT) == T9P_QID_MOUNT)
    return 1;
  return 0;
}

void
t9p_get_parent_dir(const char* file_or_dir, char* outbuf, size_t outsize)
{
  strNcpy(outbuf, file_or_dir, outsize);
  char* s = strrchr(outbuf, '/');
  if (!s) {
    strNcpy(outbuf, "/", outsize);
    return;
  }

  while (s >= outbuf && *s == '/')
    *(s--) = 0;

  if (outbuf[0] == 0)
    outbuf[0] = '/';
}

void
t9p_get_basename(const char* file_or_dir, char* outbuf, size_t outsize)
{
  const char* last = strrchr(file_or_dir, '/');
  if (!last)
    strNcpy(outbuf, file_or_dir, outsize);
  else
    strNcpy(outbuf, last + 1, outsize);
}

void
t9p_set_log_level(t9p_context_t* c, t9p_log_t level)
{
  c->opts.log_level = level;
}

int
t9p_get_log_level(t9p_context_t* c)
{
  return c->opts.log_level;
}

t9p_opts_t
t9p_get_opts(t9p_context_t* c)
{
  return c->opts;
}

/********************************************************************/
/*                                                                  */
/*                C O N T E X T       M E T H O D S                 */
/*                                                                  */
/********************************************************************/

/** Alloc a new handle, locks fid table */
static struct t9p_handle_node*
t9p__alloc_handle(struct t9p_context* c, t9p_handle_t parent, const char* fname)
{
  mutex_lock(c->fhl_mutex);
  struct t9p_handle_node* n = c->fhl_free;
  if (!n) {
    mutex_unlock(c->fhl_mutex);
    return NULL;
  }
  /** Unlink from free list */
  c->fhl_free = n->next;
  n->next = NULL;

  /** Mark used */
  n->h.valid_mask = T9P_HANDLE_ACTIVE;

  bool is_parent_root = !parent || t9p_is_root(c, parent);

  /** If given a file name, associate it with the handle */
  if (fname)
    n->h.str = t9p__string_new_path(is_parent_root ? "" : parent->str->string, fname);

  mutex_unlock(c->fhl_mutex);
  return n;
}

/**
 * Perform a 'copy' operation on the handle. Doesn't do much besides alloc
 * a new handle and copy the string to it. Nothing else changes.
 */
static struct t9p_handle_node*
_copy_handle(struct t9p_context* c, t9p_handle_t h)
{
  struct t9p_handle_node* n = t9p__alloc_handle(c, NULL, NULL);
  if (!n)
    return NULL;
  n->h.str = t9p__string_copy(h->str);
  return n;
}

/** Release a handle for reuse */
static void
t9p__release_handle(struct t9p_context* c, struct t9p_handle_node* h)
{
  mutex_lock(c->fhl_mutex);

  /** Release the string */
  h->h.str = t9p__string_release(h->h.str);

  /** Clear data, but preserve fid */
  memset(&h->h.qid, 0, sizeof(h->h.qid));
  h->h.iounit = 0;
  h->h.valid_mask = 0;

  /** Link into free list */
  h->next = NULL;
  h->next = c->fhl_free;
  c->fhl_free = h;

  mutex_unlock(c->fhl_mutex);
}

static void
t9p__release_handle_by_fid(struct t9p_context* c, t9p_handle_t h)
{
  t9p__release_handle(c, &c->fhl[h->fid]);
}

static struct t9p_handle_node*
t9p__handle_by_fid(struct t9p_context* c, t9p_handle_t h)
{
  return &c->fhl[h->fid];
}

/**
 * Recovers a handle if its serial != context serial
 */
static int
t9p__maybe_recover(struct t9p_context* c, t9p_handle_t h)
{
  /* No recovery needed */
  if (!h || c->serial == h->serial || t9p_is_root(c, h))
    return 0;

  /* Also no recovery needed, just update serial to current value */
  if (!(h->valid_mask & T9P_HANDLE_ACTIVE)) {
    h->serial = c->serial;
    return 0;
  }

  /* if the connection is still broken, we can't recover yet. But let's start to get our
   * ducks in a row. Clear the valid flags */
  h->valid_mask = T9P_HANDLE_ACTIVE;
  if (c->broken)
    return 0;

  h->serial = c->serial;

  int r;
  t9p_handle_t unused;
  if ((r = t9p__open_handle_internal(c, NULL, h->str->string, h, &unused)) < 0) {
    ERROR(c, "_recover_handle_if_needed: Recovery of fid %d failed: %s\n", 
      (int)h->fid, t9p__strerror(r));
    return -1;
  }

  /* Open again if it was open previously */
  if (h->iounit) {
    if ((r = t9p_open(c, h, h->obits)) < 0) {
      ERROR(c, "_recover_handle_if_needed: Recovery of fid %d failed due to open error: %s\n",
        (int)h->fid, t9p__strerror(r));
      /** FIXME: AAAAAA clunk the fid!!!! */
    }
  }

  LOG(c, T9P_LOG_TRACE, "_recover_handle_if_needed: Successfully recovered fid %d\n", (int)h->fid);

  return 0;
}

/** Can we read/write to a fid? */
static int
t9p__is_fid_rw(t9p_handle_t h, int write)
{
  if (!t9p_is_open(h))
    return 0;
  return (
    h->qid.type != T9P_QID_MOUNT && h->qid.type != T9P_QID_DIR && h->qid.type != T9P_QID_AUTH &&
    (write ? 1 : h->qid.type != T9P_QID_APPEND)
  );
}

static void
t9p__discard(struct t9p_context* c, struct TRcommon* com)
{
  ssize_t r;

  /* Blocking mode */
  if (c->opts.mode == T9P_THREAD_MODE_NONE) {
    char buf[256];

    ssize_t rem = com ? com->size : SSIZE_MAX;
    ssize_t tries = 10;
    while (rem > 0) {
      r = c->trans.recv(c->conn, buf, MIN(rem, sizeof(buf)), T9P_RECV_PEEK | T9P_RECV_DONTWAIT);
      if (r == -EAGAIN && --tries > 0)
        continue;
      if (r <= 0)
        return;
      r = c->trans.recv(c->conn, buf, MIN(rem, sizeof(buf)), 0);
      if (r <= 0)
        return;
    }
  }
  /* Nonblock mode */
  else if (c->opts.mode == T9P_THREAD_MODE_WORKER) {
    char buf[256];
    ssize_t left = com ? com->size : SSIZE_MAX;
    ssize_t tries = 20;
    while (left > 0) {
      r = c->trans.recv(c->conn, buf, MIN(sizeof(buf), left), T9P_RECV_DONTWAIT);
      if (r == -EAGAIN && --tries > 0)
        continue;
      if (r <= 0)
        return;
      left -= r;
    }
  }
}

#ifdef __rtems__

#ifdef RTEMS_LEGACY_STACK
struct rtems_wake_io_arg
{
  rtems_id task;
};

static void
t9p__rtems_wake_io(struct socket* sock, void* a)
{
  struct rtems_wake_io_arg* arg = a;
  rtems_event_send(arg->task, T9P_WAKE_EVENT);
}
#endif

static void*
t9p__config_rtems_socket(int sock)
{
#ifdef RTEMS_LEGACY_STACK
  struct rtems_wake_io_arg* arg = t9p_calloc(sizeof(struct rtems_wake_io_arg), 1);
  arg->task = rtems_task_self();

  struct sockwakeup sow = {
    .sw_pfn = t9p__rtems_wake_io,
    .sw_arg = arg
  };

  if (0 != setsockopt(sock, SOL_SOCKET, SO_RCVWAKEUP, &sow, sizeof(sow))) {
    perror("t9p_tcp_init: failed to set SO_RCVWAKEUP on socket");
    printf("Non-fatal error, continuing anyway...\n");
    t9p_free(arg);
    return NULL;
  }

  return arg;
#else
  return NULL;
#endif
}

#define SLEEP_DURATION_MS 1

static rtems_interval
t9p__get_wait_duration(void)
{
  static rtems_interval rti = 0; 
  if (rti == 0)
    rti = (rtems_clock_get_ticks_per_second() * 1000LL * SLEEP_DURATION_MS) / 1000000LL;
  if (rti == 0)
    rti = 1;
  return rti;
}

#endif

/** Handle tasks when the connection is broken */
static void
t9p__conn_broken(t9p_context_t* c)
{
  if (c->broken)
    return; /* already handled the error case */

  c->broken = 1;

  /* Report broken only once */
  ERROR(c, "t9p: Connection to %s broken, attempting to recover...\n", c->addr);
}

/**
 * Called periodically to attempt a reconnect, if required
 * Returns -1 for connect failure
 */
static int
t9p__try_reconnect(t9p_context_t* c)
{
  LOG(c, T9P_LOG_WARN, "Attempting to re-establish connection with server...\n");
  if (c->trans.reconnect(c->conn, c->addr) < 0)
    return -1;

  /* Attach to root again, requires we hold the socket lock */
  if (t9p__attach_root(c) < 0)
    return -1;

  LOG(c, T9P_LOG_TRACE, "Connection with server re-established!\n");
  c->serial++;
  MFENCE;
  c->broken = 0;
  return 0;
}

/** TODO: we can probably devise some way of recovering these without timing 
  * them out, but that's probably more work than it's worth. Losing connection
  * to the 9P server is an exceptionally rare case, especially since we have
  * reliable transport with TCP */
static void
t9p__timeout_all(struct trans_node** nodes, size_t num)
{
  for (int i = 0; i < num; ++i) {
    if (!nodes[i]) continue;
    nodes[i]->tr.status = -ETIMEDOUT;
    tr_signal(nodes[i]);
    nodes[i] = NULL;
  }
}

/** Worker thread implementation. Handles sending of new packets, receiving
  * and servicing requests. Also handles connection recovery
  */
static void*
t9p__thread_proc(void* param)
{
  t9p_context_t* c = param;

  struct trans_node** requests = t9p_calloc(MAX_TAGS, sizeof(struct trans_node*));

#ifdef __rtems__
  c->rtems_thr_ident = rtems_task_self();

  int leSock = c->trans.getsock(c->conn);
  void* rarg = NULL;
  if (leSock >= 0) {
    rarg = t9p__config_rtems_socket(leSock);
  }
#endif

  while (c->thr_run) {
    struct trans_node* node = NULL;
    size_t size = sizeof(node);
    ssize_t l, nread;

    /* Timeout all active nodes if we lost connection */
    if (c->broken)
      t9p__timeout_all(requests, MAX_TAGS);

    /* Attempt a reconnect periodically */
    int do_sleep = 1;
    while (c->broken) {
      mutex_lock(c->socket_lock);
      if (t9p__try_reconnect(c) == 0) {
        mutex_unlock(c->socket_lock);
        break;
      }
      mutex_unlock(c->socket_lock);
      sleep(do_sleep);
      do_sleep = (do_sleep << 1) & 0x7F; /* back off a bit, but limit to 64 */
    }

    mutex_lock(c->socket_lock);

    /** Send pending transactions */
    while (msg_queue_recv(c->trans_pool.queue, &node, &size) == 0) {
      assert(size == sizeof(node));
      if (!node) {
        ERROR(c, "Got NULL node\n");
        continue;
      }

      assert(node->tag < MAX_TAGS);

      /** Trace level logging for sent packets */
      if (c->opts.log_level <= T9P_LOG_TRACE) {
        if (node->tr.hdata) {
          struct TRcommon com;
          (void)decode_TRcommon(&com, node->tr.hdata, node->tr.hsize);
          fprintf(stderr,
            "send: (header) type=%d(%s), len=%u, tag=%d\n",
            com.type, t9p_type_string(com.type), (unsigned)com.size, com.tag
          );
        }
        else if (node->tr.data) {
          struct TRcommon com;
          (void)decode_TRcommon(&com, node->tr.data, node->tr.size);
          fprintf(stderr,
            "send: type=%d(%s), len=%u, tag=%d\n",
            com.type, t9p_type_string(com.type), (unsigned)com.size, com.tag
          );
        }
      }

      atomic_add_u32(&c->stats.msg_counts[node->tr.ttype], 1);
      atomic_add_u32(&c->stats.total_bytes_send, node->tr.hsize + node->tr.size);
      atomic_add_u32(&c->stats.send_cnt, 1);

      /** Send any header data first */
      if (node->tr.hdata && (l = c->trans.send(c->conn, node->tr.hdata, node->tr.hsize, 0)) < 0) {
        atomic_add_u32(&c->stats.send_errs, 1);
        if (l == -EAGAIN) {
          continue; /** Just try again next iteration */
        }
        if (l == -EPIPE || l == -ECONNRESET)
          t9p__conn_broken(c);
        else
          ERROR(c, "send: Failed to send header data: %s\n", t9p__strerror(l));
        continue;
      }

      /** Send "body" data */
      if ((l = c->trans.send(c->conn, node->tr.data, node->tr.size, 0)) < 0) {
        atomic_add_u32(&c->stats.send_errs, 1);
        ERROR(c, "send: Failed to send data: %s\n", t9p__strerror(l));
        continue;
      }

      node->sent = 1;
      assert(!requests[node->tag]);
      requests[node->tag] = node;
    }

    char hdr[sizeof(struct TRcommon)] = {0};

    /** Recv pending transactions */
    while ((l = c->trans.recv(c->conn, hdr, sizeof(hdr), T9P_RECV_PEEK|T9P_RECV_DONTWAIT)) > 0) {
      atomic_add_u32(&c->stats.recv_cnt, 1);

      /** Decode common header to understand what we're working with */
      struct TRcommon com = {0};
      if (decode_TRcommon(&com, hdr, l) < 0) {
        ERROR(c, "recv: Unable to decode common header; discarding!\n");
        c->trans.recv(c->conn, hdr, l, 0); /** Discard */
        atomic_add_u32(&c->stats.recv_errs, 1);
        continue;
      }

      if (c->opts.log_level <= T9P_LOG_TRACE) {
        fprintf(stderr, "recv: type=%d(%s), tag=%d, size=%u\n",
          com.type, t9p_type_string(com.type), com.tag, (unsigned)com.size);
      }

      atomic_add_u32(&c->stats.total_bytes_recv, com.size);

      /** Check if tag is out of range */
      if (com.tag >= MAX_TAGS) {
        ERROR(c, "recv: Unexpected tag '%d'; discarding!\n", com.tag);
        t9p__discard(c, &com);
        atomic_add_u32(&c->stats.recv_errs, 1);
        continue;
      }

      /** Check if the type is invalid */
      if (com.type >= T9P_TYPE_Tmax) {
        ERROR(c, "recv: Out of range type (%d); discarding!\n", com.type);
        t9p__discard(c, &com);
        atomic_add_u32(&c->stats.recv_errs, 1);
        continue;
      }

      /** Lookup the node in the request list */
      struct trans_node* n = requests[com.tag];
      if (!n) {
        ERROR(c, "recv: Tag '%d' not found in request list; discarding!\n", com.tag);
        t9p__discard(c, &com);
        atomic_add_u32(&c->stats.recv_errs, 1);
        continue;
      }
      
      /** Track count of messages recv'ed */
      atomic_add_u32(&c->stats.msg_counts[com.type], 1);

      /** Handle error responses */
      if (com.type == T9P_TYPE_Rlerror) {
        char buf[sizeof(struct Rlerror)];
        /** Read the whole Rlerror packet, no discard necessary after this */
        l = c->trans.recv(c->conn, buf, MIN(sizeof(buf), com.size), 0);
        if (l < sizeof(struct Rlerror)) {
          ERROR(c, "recv: Short Rlerror\n");
          atomic_add_u32(&c->stats.recv_errs, 1);
          continue;
        }

        struct Rlerror err = {0};
        if (decode_Rlerror(&err, buf, l) < 0)
          err.ecode = -1;

        atomic_add_u32(&c->stats.recv_errs, 1);
        n->tr.status = err.ecode < 0 ? err.ecode : -err.ecode;

        if (n->tr.rdata)
          memcpy(n->tr.rdata, buf, MIN(sizeof(buf), n->tr.rsize));
        requests[n->tag] = NULL;
        tr_signal(n);
        continue;
      }

      /** Check for type mismatch and discard if there is one */
      if (n->tr.rtype != 0 && com.type != n->tr.rtype) {
        ERROR(c, "recv: Expected msg type '%u' but got '%d'; discarding!\n", (unsigned)n->tr.rtype, com.type);
        t9p__discard(c, &com);
        n->tr.status = -1;
        requests[n->tag] = NULL;
        atomic_add_u32(&c->stats.recv_errs, 1);
        tr_signal(n);
        continue;
      }

      nread = 0;

      /** Read into header space if there is any */
      if (n->tr.rheader) {
        l = c->trans.recv(c->conn, n->tr.rheader, MIN(n->tr.rheadersz, com.size), 0);
        /** Check if any data was recieved, substract from the remaining packet size */
        if (l > 0) {
          if (l > com.size) com.size = 0;
          else com.size -= l;
          nread += l;
        }
        else {
          ERROR(c, "recv: failed to read\n");
          goto recv_done;
        }
      }

      /** Check if the header data covers everything */
      if (!com.size)
        goto recv_done;

      /** No result data space? well, discard... */
      if (!n->tr.rdata || n->tr.rsize == 0)
        t9p__discard(c, &com);
      else {
        l = c->trans.recv(c->conn, n->tr.rdata, MIN(n->tr.rsize, com.size), 0);
        nread += l;
      }

    recv_done:
      /** Set status accordingly */
      n->tr.status = l < 0 ? -errno : nread;

      requests[n->tag] = NULL;
      tr_signal(n);
      continue;
    }

    /** Check for broken pipe, dispatch handling code */
    if (l == -EPIPE || l == -ECONNRESET) {
      t9p__conn_broken(c);
    }

    mutex_unlock(c->socket_lock);

    /** Cleanup timed out nodes */
    mutex_lock(c->trans_pool.guard);
    for (struct trans_node* n = c->trans_pool.deadhead; n;) {
      /** Purge from requests list */
      if (requests[n->tag] == n)
        requests[n->tag] = NULL;

      struct trans_node* nn = n->next;
      n->next = c->trans_pool.freehead;
      c->trans_pool.freehead = n;
      n = nn;
    }
    c->trans_pool.deadhead = NULL;
    mutex_unlock(c->trans_pool.guard);

  #ifdef __rtems__
    rtems_event_set es;
    rtems_event_receive(T9P_WAKE_EVENT, RTEMS_EVENT_ANY | RTEMS_WAIT, t9p__get_wait_duration(), &es);
  #else
    usleep(1000);
  #endif
  }

#if __rtems__
  if (rarg)
    t9p_free(rarg);
#endif

  t9p_free(requests);
  return NULL;
}

static int
tr_send_now(struct t9p_context* c, struct trans_node* n)
{
  ssize_t l;

  /* Debugging */
  if (c->opts.log_level <= T9P_LOG_TRACE) {
    struct TRcommon com = {0};
    if (n->tr.hdata && decode_TRcommon(&com, n->tr.hdata, n->tr.hsize) < 0)
      goto log_done;
    else if (n->tr.data && decode_TRcommon(&com, n->tr.data, n->tr.size) < 0)
      goto log_done;

    fprintf(stderr, "send: type=%d, tag=%d, size=%lu\n",
      com.type, com.tag, (unsigned long)com.size);
  }
log_done:

  /* Send header data, if any */
  if (n->tr.hdata) {
    if ((l = c->trans.send(c->conn, n->tr.hdata, n->tr.hsize, 0)) < 0) {
      atomic_add_u32(&c->stats.send_errs, 1);
      ERROR(c, "send: %s\n", strerror(-l));
      return -1;
    }
    atomic_add_u32(&c->stats.send_cnt, 1);
    atomic_add_u32(&c->stats.total_bytes_send, n->tr.hsize);
  }

  /* Send main body */
  if (n->tr.data) {
    if ((l = c->trans.send(c->conn, n->tr.data, n->tr.size, 0)) < 0) {
      atomic_add_u32(&c->stats.send_errs, 1);
      ERROR(c, "send: %s\n", strerror(-l));
      return -1;
    }
    atomic_add_u32(&c->stats.send_cnt, 1);
    atomic_add_u32(&c->stats.total_bytes_send, n->tr.size);
  }
  return 0;
}

static int
tr_recv_now(struct t9p_context* c, struct trans_node* n)
{
  ssize_t l, nr = 0;
  char hdr[sizeof(struct TRcommon)];

  while ((l = c->trans.recv(c->conn, hdr, sizeof(hdr), T9P_RECV_PEEK)) > 0) {
    atomic_add_u32(&c->stats.recv_cnt, 1);

    /* Decode the header */
    struct TRcommon com;
    if (decode_TRcommon(&com, hdr, l) < 0) {
      ERROR(c, "recv: TRcommon decode failed\n");
      t9p__discard(c, NULL);
      return -1;
    }

    if (c->opts.log_level <= T9P_LOG_TRACE) {
      fprintf(stderr, "recv: type=%d, tag=%d, size=%lu\n",
        com.type, com.tag, (unsigned long)com.size);
    }

    /* Check for mismatched tag */
    if (com.tag != n->tag) {
      ERROR(c, "recv: mismatched tag. %d vs %d\n", com.tag, n->tag);
      t9p__discard(c, &com);
      atomic_add_u32(&c->stats.recv_errs, 1);
      return -1;
    }

    atomic_add_u32(&c->stats.total_bytes_recv, com.size);

    /* Handle Rlerror specifically */
    if (com.type == T9P_TYPE_Rlerror) {
      atomic_add_u32(&c->stats.recv_errs, 1);

      n->tr.status = -1;

      /* Read entire Rlerror message */
      char buf[sizeof(struct Rlerror)];
      struct Rlerror err;
      if ((l = c->trans.recv(c->conn, buf, com.size, 0)) < sizeof(struct Rlerror)) {
        ERROR(c, "recv: error reading Rlerror\n");
      }
      else if (decode_Rlerror(&err, buf, l) < 0) {
        ERROR(c, "recv: error decoding Rlerror. tag=%d, sz=%lu\n", com.tag, 
          (unsigned long)com.size);
      }
      else {
        n->tr.status = -err.ecode;
      }
      return -1;
    }

    /* Check for mismatched type */
    if (com.type != n->tr.rtype) {
      ERROR(c, "recv: mismatched type. %d vs %d.\n", com.type, (int)n->tr.rtype);
      t9p__discard(c, &com);
      atomic_add_u32(&c->stats.recv_errs, 1);
      return -1;
    }

    /* Read into rheader, if any */
    if (n->tr.rheader && n->tr.rheadersz) {
      l = c->trans.recv(c->conn, n->tr.rheader, MIN(com.size, n->tr.rheadersz), 0);
      if (l < 0) {
        n->tr.status = l;
        atomic_add_u32(&c->stats.recv_errs, 1);
        return -1;
      }
      if (l > com.size) com.size = 0;
      else com.size -= l;
      nr += l;
    }

    /* Check if any remaining */
    if (!com.size)
      goto recv_done;

    /* Read into resulting area, if any */
    if (n->tr.rdata) {
      size_t off = 0;
      while (com.size != 0) {
        l = c->trans.recv(c->conn, (uint8_t*)n->tr.rdata + off, MIN(com.size, n->tr.rsize), 0);
        if (l < 0) {
          n->tr.status = l;
          atomic_add_u32(&c->stats.recv_errs, 1);
          return -1;
        }
        nr += l;
        off += l;
        if (l > com.size) com.size = 0;
        else com.size -= l;
      }
    }

  recv_done:
    n->tr.status = nr;
    return 0;
  }
  return 0;
}

/********************************************************************/
/*                                                                  */
/*                   T C P     T R A N S P O R T                    */
/*                                                                  */
/********************************************************************/

#if HAVE_TCP

struct tcp_context
{
  int sock;
  bool nonblock;
};

static int
t9p__tcp_newsock()
{
  int sock;
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    perror("socket");
    return -1;
  }

#ifndef __rtems__
  /* Keep connections alive.
   * Disabled for RTEMS because this causes a pretty bad mbuf cluster
   * leak in my testing. Probably not an issue with libbsd stack though */
  int o = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &o, sizeof(o)) < 0) {
    perror("setsockopt");
  }
#endif
  
#ifdef __linux__
  /** On Linux, set recv timeout */
  struct timeval to;
  to.tv_usec = 1000;
  to.tv_sec = 0;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to)) < 0) {
    perror("setsockopt(SO_RECVTIMEO)");
    close(sock);
    return -1;
  }
#endif
  return sock;
}

void*
t9p_tcp_init(t9p_context_t* c)
{
  struct tcp_context* ctx = t9p_calloc(1, sizeof(struct tcp_context));

  ctx->nonblock = c->opts.mode == T9P_THREAD_MODE_WORKER;

  if ((ctx->sock = t9p__tcp_newsock()) < 0) {
    t9p_free(ctx);
    return NULL;
  }
  return ctx;
}

int
t9p_tcp_disconnect(void* context)
{
  struct tcp_context* ctx = context;

#if 1
  if (shutdown(ctx->sock, SHUT_RDWR) < 0) {
#else
  if (connect(ctx->sock, &s, sizeof(s)) < 0) {
#endif
    fprintf(stderr, "Disconnect failed: %s\n", t9p__strerror(errno));
    return -1;
  }

  close(ctx->sock);

  return 0;
}

int
t9p_tcp_connect(void* context, const char* addr_or_file)
{
  struct tcp_context* ctx = context;

  char a[256];
  strNcpy(a, addr_or_file, sizeof(a));

  char* paddr = strtok(a, ":");
  char* pport = strtok(NULL, ":");

  struct sockaddr_in addr = {0};

  /* needs resolve first */
  if (!ip_in_dot_format(paddr)) {
    if (gethostbyname_inet(paddr, &addr.sin_addr.s_addr) < 0) {
      fprintf(stderr, "Cannot resolve addr '%s'\n", paddr);
      return -1;
    }
    fprintf(stderr, "%s\n", inet_ntoa(addr.sin_addr));
    addr.sin_family = AF_INET;
  }
  else {
    addr.sin_addr.s_addr = inet_addr(paddr);
    addr.sin_family = AF_INET;
  }

  if (pport)
    addr.sin_port = htons(atoi(pport));
  else
    addr.sin_port = htons(T9P_DEFAULT_PORT);

  if (connect(ctx->sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Connect failed to %s: %s\n", addr_or_file, t9p__strerror(errno));
    return -1;
  }

  return 0;
}

int
t9p_tcp_reconnect(void* context, const char* addr_or_file)
{
  struct tcp_context* ctx = context;

  shutdown(ctx->sock, SHUT_RDWR);
  close(ctx->sock);

  if ((ctx->sock = t9p__tcp_newsock()) < 0) {
    return -1;
  }

  return t9p_tcp_connect(context, addr_or_file);
}

void
t9p_tcp_shutdown(void* context)
{
  struct tcp_context* ctx = context;
  close(ctx->sock);
  t9p_free(context);
}

ssize_t
t9p_tcp_send(void* context, const void* data, size_t len, int flags)
{
  struct tcp_context* pc = context;
  return send(pc->sock, data, len, flags);
}

ssize_t
t9p_tcp_recv(void* context, void* data, size_t len, int flags)
{
  int rflags = 0;
  if (flags & T9P_RECV_PEEK)
    rflags |= MSG_PEEK;
  if (flags & T9P_RECV_DONTWAIT)
    rflags |= MSG_DONTWAIT;

  struct tcp_context* pc = context;

  /* Simple logic for blocking mode. Nonblock needs some funny business */
  if (!pc->nonblock) {
    ssize_t r = recv(pc->sock, data, len, rflags);
    if (r < 0)
      r = -errno;
    return r;
  }

  ssize_t off = 0, rem = len, l = 0;

  /* Read as much as we can at first */
  l = recv(pc->sock, data, len, rflags);
  if (l < 0 && errno != EAGAIN)
    return -errno;
  off += l;
  rem -= l;

  if (rem <= 0)
    return off;

  int tries = (flags & T9P_RECV_ALL) ? 50 : 3;

  fd_set fds;

  /* Nonblock recv is finnicky, especially on slow hardware lik the Coldfire MPUs.
   * Often times responses are split between TCP segments that are received and
   * processed at different times by the networking stack. Sometimes we'll
   * receive a header, immediately followed by '0' until the networking stack
   * actually manages to deliver data. We'll use select() to wait for data */
  do {
    /* 50ms timeout */
    struct timeval timeout = {
      .tv_sec = (flags & T9P_RECV_ALL) ? 5 : 0,
      .tv_usec = 50000
    };

    FD_ZERO(&fds);
    FD_SET(pc->sock, &fds);

    int r;
    if ((r = select(1, &fds, NULL, NULL, &timeout)) < 0) {
      if (r < 0)
        return -errno; /* Bail... */
      break;
    }

    l = recv(pc->sock, (uint8_t*)data + off, rem, rflags);
    if (l < 0) {
      if (errno == EAGAIN)
        continue; /* Really? */
      return -errno;
    }
    if (!l)
      break;
    rem -= l;
    off += l;
  } while(rem > 0 && --tries > 0);

  return off;
}

int
t9p_tcp_getsock(void* context)
{
  struct tcp_context* c = context;
  return c->sock;
}

int t9p_tcp_data_avail(void* context)
{
  struct tcp_context* c = context;
  fd_set fs;
  FD_ZERO(&fs);
  FD_SET(c->sock, &fs);

  struct timeval to = {0};
  select(1, &fs, NULL, NULL, &to);
  return !!FD_ISSET(c->sock, &fs);
}

#endif

int
t9p_init_tcp_transport(t9p_transport_t* tp)
{
#if HAVE_TCP
  tp->init = t9p_tcp_init;
  tp->shutdown = t9p_tcp_shutdown;
  tp->connect = t9p_tcp_connect;
  tp->recv = t9p_tcp_recv;
  tp->send = t9p_tcp_send;
  tp->disconnect = t9p_tcp_disconnect;
  tp->getsock = t9p_tcp_getsock;
  tp->reconnect = t9p_tcp_reconnect;
  tp->avail = t9p_tcp_data_avail;
  return 0;
#else
  return -1;
#endif
}

/** Feature flags */
#define HAVE_TCP    1
#define HAVE_UDP    1

#include "t9p_platform.h"

#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#include <unistd.h>
#ifdef __linux__
#include <linux/limits.h>
#elif defined(__rtems__)
#include <sys/limits.h>
#include <rtems/version.h>
#else
#define PATH_MAX 256
#endif

#if HAVE_TCP || HAVE_UDP
#if __RTEMS_MAJOR__ < 5
#include "netinet/in_systm.h"
#endif
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#endif

#include "t9p.h"
#include "t9proto.h"

//#define DO_TRACE

#define T9P_TARGET_VERSION "9P2000.L"

#define PACKET_BUF_SIZE 8192

#define MAX_PATH_COMPONENTS 256

#define MAX_TAGS 1024
#define MAX_TRANSACTIONS 512

#define DEFAULT_MAX_FILES 256
#define DEFAULT_SEND_TIMEO 3000
#define DEFAULT_RECV_TIMEO 3000

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#define ERRLOG(...) fprintf(stderr, __VA_ARGS__)
#define LOG(_context, _level, ...) if (_context && _context->opts.log_level <= _level) {    \
    fprintf(stderr, __VA_ARGS__); \
}
#define INFO(_context, ...) LOG(_context, T9P_LOG_INFO, __VA_ARGS__)
#define DEBUG(_context, ...) LOG(_context, T9P_LOG_DEBUG, __VA_ARGS__)
#define WARN(_context, ...) LOG(_context, T9P_LOG_WARN, __VA_ARGS__)
#define ERROR(_context, ...) LOG(_context, T9P_LOG_WARN, __VA_ARGS__)

struct trans_pool {
    struct trans_node* freehead;
    mutex_t* guard;
    uint32_t total;
    msg_queue_t* queue;
    event_t* recv_ev;
};

struct t9p_context {
    void* conn;
    t9p_transport_t trans;
    char mntpoint[PATH_MAX];
    char addr[PATH_MAX];
    char apath[PATH_MAX];
    t9p_opts_t opts;
    struct t9p_handle_node* root;

    /** file handle list */
    mutex_t* fhl_mutex;
    int fhl_max;
    int fhl_count;

    /** I/O thread */
    thread_t* io_thread;
    event_t* recv_event;                    /**< Signaled when a new packet has been received */
    int thr_run;
    mutex_t* socket_lock;

    struct trans_pool trans_pool;

    struct t9p_handle_node* fhl;            /**< Flat array of file handles, allocated in a contiguous block */
    struct t9p_handle_node* fhl_free;       /**< LL of free file handles */
};

#define T9P_HANDLE_ACTIVE 0x1
#define T9P_HANDLE_QID_VALID 0x2
#define T9P_HANDLE_FID_VALID 0x4

struct t9p_handle {
    int32_t fid;                    /**< Also the index into the fh table in t9p_context */
    uint32_t valid_mask;            /**< Determines what is and isn't valid */
    qid_t qid;                      /**< qid of this object. Only valid if valid_mask says so */
    uint32_t iounit;                /**< Returned by Rlopen after the file is opened */
};

struct t9p_handle_node {
    struct t9p_handle_node* next;
    struct t9p_handle_node* prev;
    struct t9p_handle h;
    int active;
};

struct t9p_requestor {
    uint16_t tag;
};

/********************************************************************/
/*                                                                  */
/*                     P R O T O T Y P E S                          */
/*                                                                  */
/********************************************************************/

static int _version_handshake(struct t9p_context* context);
static int _attach_root(struct t9p_context* c);
static int _send(struct t9p_context* c, const void* data, size_t sz, int flags);
static void _perror(struct t9p_context* c, const char* msg, struct TRcommon* err);
static int _iserror(struct TRcommon* err);
static int _clunk_sync(struct t9p_context* c, int fid);
static int _can_rw_fid(t9p_handle_t h, int write);

/** t9p_context 'methods' */
static struct t9p_handle_node* _alloc_handle(struct t9p_context* c);
static void _release_handle(struct t9p_context* c, struct t9p_handle_node* h);
static void _release_handle_by_fid(struct t9p_context* c, t9p_handle_t h);

static void* _t9p_thread_proc(void* param);

/** Safe strcpy that ensures dest is NULL terminated */
void strNcpy(char* dest, const char* src, size_t dmax) {
    if (!dmax || !dest) return;
    if (!src) dest[0] = 0;
    strncpy(dest, src, dmax);
    dest[dmax-1] = 0;
}
#define strncpy strNcpy

/********************************************************************/
/*                                                                  */
/*            T R A N S A C T I O N        P O O L                  */
/*                                                                  */
/********************************************************************/

struct trans;
struct trans_pool;
struct trans_node;

struct trans_node* tr_enqueue(struct trans_pool* q, struct trans_node* tr);
void tr_release(struct trans_pool* q, struct trans_node* tn);

#define TR_FLAGS_NONE       0x0

struct trans {
    uint32_t flags;         /**< Flags */
    
    const void* data;       /**< Outgoing data */
    size_t size;            /**< Outgoing data size */

    void* rdata;            /**< Buffer to hold incoming data */
    size_t rsize;           /**< Incoming data buffer size */

    const void* hdata;      /**< Optional; header data pointer. If not NULL, this is ent before
                                 this->data is. This is used to avoid unnecessary copies */
    size_t hsize;           /**< Optional; header data size */

    int32_t status;         /**< Combined status/length variable. If < 0, this represents an
                                 error condition. If >= 0, it's the number of bytes written to rdata. */

    /** 9p meta info */
    uint32_t rtype;         /**< Result message type. Set to 0 to accept any. */
};

struct trans_node {
    struct trans tr;

    uint8_t sent;                   /**< Set once we've been sent */
    event_t* event;                 /**< Signaled when the response to this is receieved */
    uint16_t tag;                   /**< Tag for this transaction node; For now, each node will have its
                                         own associated tag. Somewhat sucks, but good enough for now. */
    
    struct trans_node* next;
};

/**
 * Init the transaction queue
 */
int tr_pool_init(struct trans_pool* q, uint32_t num) {
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
        q->freehead = calloc(1, sizeof(*on));
        q->freehead->event = event_create();
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
void tr_pool_destroy(struct trans_pool* q) {
    mutex_lock(q->guard);

    /** Free the nodes */
    for (struct trans_node* n = q->freehead; n;) {
        struct trans_node* b = n->next;
        event_destroy(n->event);
        free(n);
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
struct trans_node* tr_get_node(struct trans_pool* q) {
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
struct trans_node* tr_enqueue(struct trans_pool* q, struct trans_node* us) {
    /** Send it to the I/O thread */
    if (msg_queue_send(q->queue, &us, sizeof(us)) < 0) {
        printf("Error while sending to message queue\n");
        tr_release(q, us);
        return NULL;
    }

    /** Wake worker thread */
    event_signal(q->recv_ev);
    return us;
}

/**
 * Release a node back into the transaction pool.
 */
void tr_release(struct trans_pool* q, struct trans_node* tn) {
    mutex_lock(q->guard);

    tn->next = q->freehead;
    q->freehead = tn;

    mutex_unlock(q->guard);
}

/**
 * Enqueues the node into the queue and waits for it to be servied
 * This will release the node back into the pool on error, or after the node is serviced.
 * \param c Context
 * \param n Node
 * \param tr Transaction description, copied into n->tr before sending
 * \return < 0 on error
 */
static int tr_send_recv(struct t9p_context* c, struct trans_node* n, struct trans* tr) {
    int r = 0;
    n->tr = *tr;

    n = tr_enqueue(&c->trans_pool, n);
    if (n == NULL) {
        //tr_release(&c->trans_pool, n);
        return -ENOMEM;
    }

    /** Wait until serviced (or timeout) */
    if ((r = event_wait(n->event, c->opts.recv_timeo)) != 0) {
        /** FIXME: If we release this node (as we should...), the thread may still have it queued up,
          * leading to a use-after-free scenario. Maybe I need to add a flag to trans_node to indicate that it should 
          * be automatically released by the thread? */
        //tr_release(&c->trans_pool, n);
        printf("event_wait: %s\n", strerror(r));
        return -1;
    }

    uint32_t status = n->tr.status;
    tr_release(&c->trans_pool, n); /** Release the transaction back into the pool */
    return status;
}

static int _send(struct t9p_context* c, const void* data, size_t sz, int flags) {
    return c->trans.send(c->conn, data, sz, flags);
}

/** Synchronously recv a type of packet, or Rerror. Includes timeout */
static ssize_t _recv_type(struct t9p_context* c, void* data, size_t sz, int flags, uint8_t type, uint16_t tag) {
    ssize_t n;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int timeoutMs = c->opts.recv_timeo;
    while (1) {
        n = c->trans.recv(c->conn, data, sz, 0);
        if (n >= sizeof(struct TRcommon)) {
            struct TRcommon* com = data;
            if (com->type == type || ((com->type == T9P_TYPE_Rlerror || com->type == T9P_TYPE_Rerror) && com->tag == tag))
                return n;
        }

        struct timespec tp;
        clock_gettime(CLOCK_MONOTONIC, &tp);
        int diffMs = ((tp.tv_sec - start.tv_sec) * 1000) + ((tp.tv_nsec - start.tv_nsec) / 1000000);
        if (diffMs >= timeoutMs)
            break;
    }
    return -ETIMEDOUT;
}

static void _perror(struct t9p_context* c, const char* msg, struct TRcommon* err) {
    if (err->type == T9P_TYPE_Rlerror) {
        ERROR(c, "%s: %s\n", msg, strerror(((struct Rlerror*)err)->ecode));
    }
    else if (err->tag == T9P_TYPE_Rerror) {
        struct Rerror* re = (struct Rerror*)err;
        char buf[1024];
        memcpy(buf, re->ename, MIN(re->ename_len, sizeof(buf)-1));
        buf[re->ename_len] = 0;
        ERROR(c, "%s: %s\n", msg, buf);
    }
}

static const char* _strerror(int err) {
    return strerror(err < 0 ? -err : err);
}

static int _iserror(struct TRcommon* err) {
    return err->type == T9P_TYPE_Rerror || err->type == T9P_TYPE_Rlerror;
}

static int _version_handshake(struct t9p_context* c) {
    const uint8_t version[] = T9P_TARGET_VERSION;

    char buf[1024];
    int sendSize = encode_Tversion(buf, sizeof(buf), T9P_NOTAG, MAX(c->opts.max_read_data_size, c->opts.max_write_data_size), sizeof(version)-1, version);
    if (sendSize < 0) {
        ERROR(c, "Tversion packed encode failed\n");
        return -1;
    }

    if (_send(c, buf, sendSize, 0) < 0) {
        ERROR(c, "Tversion handshake failed: I/O error\n");
        return -1;
    }

    /** Listen for the return message */
    ssize_t read = _recv_type(c, buf, sizeof(buf)-1, 0, T9P_TYPE_Rversion, 0);
    if (read < 0) {
        ERROR(c, "Rversion handshake failed: read timeout\n");
        return -1;
    }

    struct TRcommon* tr = (struct TRcommon*)buf;
    if (tr->type != T9P_TYPE_Rversion) {
        ERROR(c, "Rversion handshake failed: unexpected packet type %d\n", tr->type);
        return -1;
    }

    struct Rversion* rv = NULL;
    if (decode_Rversion(&rv, buf, read) < 0) {
        ERROR(c, "Rversion handshake failed: failed to decode packet\n");
        return -1;
    }

    if (memcmp(rv->version, version, MIN(sizeof(version)-1, rv->version_len))) {
        char vstr[256] = {0};
        memcpy(vstr, rv->version, MIN(rv->version_len, sizeof(vstr)-1));
        ERROR(c, "Rversion handshake failed: version mismatch, requested '%s', got '%s'\n", version, vstr);
        free(rv);
        return -1;
    }

    DEBUG(c, "Rversion handshake complete for version %s\n", version);
    free(rv);
    return 0;
}

static int _attach_root(struct t9p_context* c) {
    char packetBuf[4096];
    int len;
    uint16_t tag = 0;
    uint32_t uid = *c->opts.user ? T9P_NOUID : c->opts.uid;

    struct t9p_handle_node* h = _alloc_handle(c);
    if (!h) {
        ERROR(c, "Rattach failed: unable to allocate handle\n");
        goto error;
    }

    if ((len = encode_Tattach(packetBuf, sizeof(packetBuf), tag, h->h.fid, T9P_NOFID, strlen(c->opts.user), (const uint8_t*)c->opts.user, strlen(c->apath), (const uint8_t*)c->apath, uid)) < 0) {
        ERROR(c, "Tattach root failed: unable to encode packet\n");
        goto error;
    }

    if (_send(c, packetBuf, len, 0) < 0) {
        ERROR(c, "Tattach root failed: unable to send\n");
        goto error;
    }

    ssize_t read = _recv_type(c, packetBuf, sizeof(packetBuf), 0, T9P_TYPE_Rattach, tag);
    if (read < 0) {
        ERROR(c, "Rattach failed: read timeout\n");
        goto error;
    }

    struct TRcommon* com = (struct TRcommon*)packetBuf;
    if (_iserror(com)) {
        _perror(c, "Rattach failed", com);
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
    _release_handle(c, h);
    return -1;
}

static int _clunk_sync(struct t9p_context* c, int fid) {
    char buf[1024];

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -1;

    int l;
    if ((l = encode_Tclunk(buf, sizeof(buf), n->tag, fid)) < 0) {
        ERROR(c, "Failed to encode Tclunk\n");
        tr_release(&c->trans_pool, n);
        return -1;
    }

    struct trans tr = {
        .data = buf,
        .size = l,
        .rtype = T9P_TYPE_Rclunk,
        .rsize = sizeof(buf),
        .rdata = buf,
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: Tclunk failed\n", __FUNCTION__);
        return l;
    }

    if (l < sizeof(struct TRcommon)) {
        ERROR(c, "%s: Tclunk failed: short packet\n", __FUNCTION__);
        return -1;
    }

    struct TRcommon* tc = (struct TRcommon*)buf;
    if (_iserror(tc)) {
        _perror(c, "Rclunk failed", tc);
        return -1;
    }
    return 0;
}

/********************************************************************/
/*                                                                  */
/*                      P U B L I C    A P I                        */
/*                                                                  */
/********************************************************************/

void t9p_opts_init(struct t9p_opts* opts) {
    memset(opts, 0, sizeof(*opts));
    opts->max_read_data_size = (1<<20); /** 1M */
    opts->max_write_data_size = (1<<20); /** 1M */
    opts->queue_size = T9P_PACKET_QUEUE_SIZE;
    opts->max_fids = DEFAULT_MAX_FILES;
    opts->send_timeo = DEFAULT_SEND_TIMEO;
    opts->recv_timeo = DEFAULT_RECV_TIMEO;
}

t9p_context_t* t9p_init(t9p_transport_t* transport, const t9p_opts_t* opts, const char* apath, const char* addr, const char* mntpoint) {
    /** Validate transport to prevent misuse **/
    assert(transport);
    assert(transport->connect);
    assert(transport->disconnect);
    assert(transport->recv);
    assert(transport->send);
    assert(transport->init);
    assert(transport->shutdown);
    assert(opts);
    
    t9p_context_t* c = calloc(1, sizeof(t9p_context_t));
    strNcpy(c->mntpoint, mntpoint, sizeof(c->mntpoint));
    strNcpy(c->addr, addr, sizeof(c->addr));
    strNcpy(c->apath, apath, sizeof(c->apath));
    c->trans = *transport;
    c->opts = *opts;

    /** Init transport layer */
    if (!(c->conn = transport->init())) {
        ERRLOG("Transport init failed\n");
        goto error_pre_fhl;
    }

    /** Attempt to connect */
    if (transport->connect(c->conn, addr) < 0) {
        ERRLOG("Connection to %s failed\n", addr);
        goto error_pre_fhl;
    }

    /** Init file handle list */
    c->fhl = malloc(sizeof(struct t9p_handle_node) * opts->max_fids);
    c->fhl_max = opts->max_fids;
    c->fhl_count = 0;
    c->fhl_free = NULL;
    struct t9p_handle_node* prev = NULL;
    for (int i = 0; i < c->fhl_max; ++i) {
        struct t9p_handle_node* n = &c->fhl[i];
        n->next = c->fhl_free;
        n->prev = prev;
        n->h.fid = i;
        c->fhl_free = n;
        prev = c->fhl_free;
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
    if (_version_handshake(c) < 0) {
        ERRLOG("Connection to %s failed\n", addr);
        transport->disconnect(c->conn);
        transport->shutdown(c->conn);
        mutex_unlock(c->socket_lock);
        goto error_post_pool;
    }

    /** Attach to the root fs */
    if (_attach_root(c) < 0) {
        ERRLOG("Connected to %s failed\n", addr);
        transport->disconnect(c->conn);
        transport->shutdown(c->conn);
        mutex_unlock(c->socket_lock);
        goto error_post_pool;
    }

    mutex_unlock(c->socket_lock);

    c->thr_run = 1;

    /** Kick off thread */
    if (!(c->io_thread = thread_create(_t9p_thread_proc, c))) {
        t9p_shutdown(c);
        return NULL;
    }

    return c;

error_post_pool:
    tr_pool_destroy(&c->trans_pool);
error_post_fhl:
    mutex_destroy(c->socket_lock);
    mutex_destroy(c->fhl_mutex);
    event_destroy(c->recv_event);
error_pre_fhl:
    free(c);
    return NULL;
}

void t9p_shutdown(t9p_context_t* c) {
    /** Clunk all active file handles */
    mutex_lock(c->fhl_mutex);
    for (int i = 0; i < c->fhl_max; ++i)
        if (c->fhl[i].h.valid_mask & T9P_HANDLE_FID_VALID)
            _clunk_sync(c, c->fhl[i].h.fid);
    mutex_unlock(c->fhl_mutex);

    /** Kill off the thread */
    c->thr_run = 0;
    thread_join(c->io_thread);

    /** Disconnect and shutdown the transport layer */
    c->trans.disconnect(c->conn);
    c->trans.shutdown(c->conn);

    free(c->fhl);

    mutex_destroy(c->fhl_mutex);
    event_destroy(c->recv_event);
    free(c);
}

t9p_handle_t t9p_open_handle(t9p_context_t* c, t9p_handle_t parent, const char* path) {
    char p[T9P_PATH_MAX];
    strNcpy(p, path, sizeof(p));
    int status = 0;

    /** Default parent is the root handle */
    if (!parent)
        parent = t9p_get_root(c);

    int nwcount = 0;
    char* comps[MAX_PATH_COMPONENTS];

    /** Split path into components for walk */
    char* sp = NULL;
    for (char* s = strtok_r(p, "/", &sp); s && *s; s = strtok_r(NULL, "/", &sp)) {
        comps[nwcount++] = s;
    }

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return NULL;

    struct t9p_handle_node* fh = _alloc_handle(c);
    if (!fh) {
        return NULL;
    }

    char packet[PACKET_BUF_SIZE];
    int l = 0;
    if ((l = encode_Twalk(packet, sizeof(packet), n->tag, parent->fid, fh->h.fid, nwcount, (const char* const*)comps)) < 0) {
        ERROR(c, "%s: unable to encode Twalk\n", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        goto error;
    }

    /** Build transaction to send */
    struct trans tr = {
        .data = packet,
        .size = l,
        .rtype = T9P_TYPE_Rwalk,
        .rdata = packet,
        .rsize = sizeof(packet),
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: Twalk send/recv failed: %s\n", __FUNCTION__, strerror(l));
        goto error;
    }

    struct Rwalk rw;
    qid_t* qids = NULL;
    if (decode_Rwalk(&rw, packet, l, &qids) < 0) {
        ERROR(c, "%s: Rwalk decode failed\n", __FUNCTION__);
        goto error;
    }

    fh->h.qid = qids[rw.nwqid-1];
    fh->h.valid_mask |= T9P_HANDLE_FID_VALID | T9P_HANDLE_QID_VALID;
    free(qids);

    return &fh->h;
error:
    _release_handle(c, fh);
    return NULL;
}

void t9p_close_handle(t9p_context_t* c, t9p_handle_t h) {
    if (!h)
        return;

    if (!(h->valid_mask & T9P_HANDLE_ACTIVE))
        return;
    /** Clunk it if the FID is valid */
    if (h->valid_mask & T9P_HANDLE_FID_VALID)
        _clunk_sync(c, h->fid);
    _release_handle(c, &c->fhl[h->fid]);
}

t9p_handle_t t9p_get_root(t9p_context_t* c) {
    return &c->root->h;
}

int t9p_open(t9p_context_t* c, t9p_handle_t h, uint32_t mode) {
    char packet[PACKET_BUF_SIZE];

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    int l = 0;
    if ((l = encode_Tlopen(packet, sizeof(packet), n->tag, h->fid, mode)) < 0) {
        ERROR(c, "%s: unable to encode Tlopen", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rlopen,
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: Tlopen failed\n", __FUNCTION__);
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
    /** If the server is telling us 'whatever', provide our own length */
    if (h->iounit == 0)
        h->iounit = UINT32_MAX;

    return 0;
}

void t9p_close(t9p_handle_t handle) {
    handle->iounit = 0;
}

ssize_t t9p_read(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, void* outbuffer) {
    char packet[PACKET_BUF_SIZE];
    int status = 0;

    if (!_can_rw_fid(h, 0))
        return -EPERM;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    int l;
    if ((l = encode_Tread(packet, sizeof(packet), n->tag, h->fid, offset, num)) < 0) {
        ERROR(c, "%s: could not encode Tread\n", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    /** TODO: This needs a refactor */
    size_t recvSize = sizeof(struct Rread) + num;
    void* recvData = malloc(recvSize);

    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = recvData,
        .rsize = recvSize,
        .rtype = T9P_TYPE_Rread,
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        status = l;
        goto error;
    }

    struct Rread rr;
    if (decode_Rread(&rr, recvData, l) < 0) {
        ERROR(c, "%s: unable to decode Rread\n", __FUNCTION__);
        status = -EPROTO;
        goto error;
    }

    memcpy(outbuffer, ((uint8_t*)recvData)+sizeof(struct Rread), MIN(num, rr.count));
    free(recvData);
    return MIN(num, rr.count);

error:
    free(recvData);
    return status;
}

ssize_t t9p_write(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, const void* inbuffer) {
    char packet[PACKET_BUF_SIZE];

    if (!_can_rw_fid(h, 1))
        return -1;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    int l;
    if ((l = encode_Twrite(packet, sizeof(packet), n->tag, h->fid, offset, num)) < 0) {
        ERROR(c, "%s: unable to encode Twrite\n", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    struct trans tr = {
        .hdata = packet,
        .hsize = l,
        .data = inbuffer,
        .size = num,
        .rtype = T9P_TYPE_Rwrite,
        .rdata = packet,
        .rsize = sizeof(packet)
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: Twrite failed: %s\n", __FUNCTION__, _strerror(l));
        return l;
    }

    struct Rwrite rw;
    if (decode_Rwrite(&rw, packet, l) < 0) {
        ERROR(c, "%s: failed to decode Rwrite\n", __FUNCTION__);
        return -EPROTO;
    }

    return rw.count;
}


int t9p_getattr(t9p_context_t* c, t9p_handle_t h, struct t9p_attr* attr, uint64_t mask) {
    char packet[PACKET_BUF_SIZE];

    if (!t9p_is_valid(h))
        return -EBADF;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    int l;
    if ((l = encode_Tgetattr(packet, sizeof(packet), n->tag, h->fid, mask)) < 0) {
        ERROR(c, "%s: failed to encode Tgetattr\n", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rtype = T9P_TYPE_Rgetattr,
        .rdata = packet,
        .rsize = sizeof(packet),
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: Tgetattr failed\n", __FUNCTION__);
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

int t9p_create(t9p_context_t* c, t9p_handle_t* newhandle, t9p_handle_t parent, const char* name, uint32_t mode, uint32_t gid, uint32_t flags) {
    char packet[PACKET_BUF_SIZE];

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    /** If parent is NULL, parent is root */
    if (!t9p_is_valid(parent))
        parent = t9p_get_root(c);

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
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rlcreate
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: Tlcreate failed: %s\n", __FUNCTION__, strerror(l));
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

int t9p_dup(t9p_context_t* c, t9p_handle_t todup, t9p_handle_t* outhandle) {
    char packet[PACKET_BUF_SIZE];

    *outhandle = NULL;
    if (!t9p_is_valid(todup))
        return -EBADF;

    struct t9p_handle_node* h = _alloc_handle(c);
    if (!h) {
        ERROR(c, "%s: unable to alloc new handle\n", __FUNCTION__);
        return -ENOMEM;
    }

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    int l;
    if ((l=encode_Twalk(packet, sizeof(packet), n->tag, todup->fid, h->h.fid, 0, NULL)) < 0) {
        ERROR(c, "%s: failed to encode Twalk\n", __FUNCTION__);
        _release_handle(c, h);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rwalk,
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        _release_handle(c, h);
        return -EIO;
    }

    struct Rwalk rw;
    qid_t* qid = NULL;
    if (decode_Rwalk(&rw, packet, l, &qid) < 0) {
        _release_handle(c, h);
        return -EPROTO;
    }

    h->h.qid = qid[rw.nwqid-1];
    h->h.valid_mask |= T9P_HANDLE_FID_VALID | T9P_HANDLE_QID_VALID;
    *outhandle = &h->h;
    return 0;
}

int t9p_remove(t9p_context_t* c, t9p_handle_t h) {
    char packet[PACKET_BUF_SIZE];
    if (!t9p_is_valid(h))
        return -EBADF;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    int l;
    if ((l = encode_Tremove(packet, sizeof(packet), n->tag, h->fid)) < 0) {
        ERROR(c, "%s: unable to encode Tremove\n", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rremove
    };
    n->tr = tr;

    n = tr_enqueue(&c->trans_pool, n);
    if (!n) {
        ERROR(c, "%s: unable to queue\n", __FUNCTION__);
        return -EIO;
    }

    /** FIXME: We should only release the FID if we get back either Rerror or Rlerror from the server.
      * It is true that Tremove will clunk even on Rlerror, but we need to make sure that the server *actually* gets 
      * our Tremove... With TCP transport, this probably doesn't matter too much. */

    /** Tremove is basically just a clunk with the side effect of removing a file. This will clunk even if the remove fails */
    _release_handle_by_fid(c, h);

    if (event_wait(n->event, c->opts.recv_timeo) != 0) {
        ERROR(c, "%s: timed out\n", __FUNCTION__);
        tr_release(&c->trans_pool, n); // FIXME:!!!!!!!!!!! USE AFTER FREE IN WORKER THREAD
        return 0; /** TODO: Returning -1 here and releasing the file handle would be inconsistent with the other error cases */
    }

    tr_release(&c->trans_pool, n);

    return 0;
}

int t9p_fsync(t9p_context_t* c, t9p_handle_t file) {
    char packet[PACKET_BUF_SIZE];
    if (!t9p_is_open(file))
        return -EBADF;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    int l;
    if ((l = encode_Tfsync(packet, sizeof(packet), n->tag, file->fid)) < 0) {
        ERROR(c, "%s: Unable to encode Tfsync\n", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rtype = T9P_TYPE_Rfsync,
        .rdata = packet,
        .rsize = sizeof(packet)
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        return l;
    }

    return 0;
}

int t9p_mkdir(t9p_context_t* c, t9p_handle_t parent, const char* name, uint32_t mode, uint32_t gid, qid_t* outqid) {
    char packet[PACKET_BUF_SIZE];
    if (!t9p_is_valid(parent))
        return -1;

    if (gid == T9P_NOGID) {
        gid = c->opts.gid;
    }

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    int l;
    if ((l = encode_Tmkdir(packet, sizeof(packet), n->tag, parent->fid, name, mode, gid)) < 0) {
        ERROR(c, "%s: Unable to encode Tmkdir\n", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rtype = T9P_TYPE_Rmkdir,
        .rdata = packet,
        .rsize = sizeof(packet),
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
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

int t9p_statfs(t9p_context_t* c, t9p_handle_t h, struct t9p_statfs* statfs) {
    char packet[PACKET_BUF_SIZE];
    int l;
    if (!t9p_is_valid(h))
        return -EBADF;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    if ((l = encode_Tstatfs(packet, sizeof(packet), n->tag, h->fid)) < 0) {
        ERROR(c, "%s: Unable to encode Tstatfs\n", __FUNCTION__);
        tr_release(&c->trans_pool, n);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rstatfs,
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
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

int t9p_readlink(t9p_context_t* c, t9p_handle_t h, char* outPath, size_t outPathSize) {
    char packet[PACKET_BUF_SIZE];
    int l;
    if (!t9p_is_valid(h))
        return -EBADF;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    if ((l = encode_Treadlink(packet, sizeof(packet), n->tag, h->fid)) < 0) {
        ERROR(c, "%s: Unable to encode Treadlink\n", __FUNCTION__);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rreadlink,
    };

    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: send failed: %s\n", __FUNCTION__, strerror(l));
        return l;
    }

    struct Rreadlink rl;
    if (decode_Rreadlink(&rl, outPath, outPathSize, packet, l) < 0) {
        ERROR(c, "%s: failed to decode Rreadlink\n", __FUNCTION__);
        return -EPROTO;
    }

    return 0;
}

int t9p_symlink(t9p_context_t* c, t9p_handle_t dir, const char* dst, const char* src, uint32_t gid, qid_t* oqid) {
    char packet[PACKET_BUF_SIZE];
    int l;
    if (!t9p_is_valid(dir))
        dir = t9p_get_root(c);

    if (gid == T9P_NOGID)
        gid = c->opts.gid;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    if ((l = encode_Tsymlink(packet, sizeof(packet), n->tag, dir->fid, dst, src, gid)) < 0) {
        ERROR(c, "%s: Unable to encode Tsymlink\n", __FUNCTION__);
        return -EINVAL;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rsymlink,
    };
    if ((l = tr_send_recv(c, n, &tr)) < 0) {
        ERROR(c, "%s: send failed: %s\n", __FUNCTION__, _strerror(l));
        return l;
    }

    struct Rsymlink sl;
    if ((decode_Rsymlink(&sl, packet, l)) < 0) {
        ERROR(c, "%s: Failed to decode Rsymlink\n", __FUNCTION__);
        return -EPROTO;
    }

    if (oqid) *oqid = sl.qid;

    return 0;
}

struct _t9p_parse_dir_param {
    struct t9p_dir_info** prev;
    struct t9p_dir_info** head;
    uint64_t* offset;
};

/**
 * Used with decode_Rreaddir.
 */
static void _t9p_parse_dir_callback(void* param, struct Rreaddir_dir dir, const char* name) {
    struct _t9p_parse_dir_param* dp = param;
    struct t9p_dir_info* di = calloc(sizeof(struct t9p_dir_info) + dir.namelen + 1, 1);
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

int t9p_readdir(t9p_context_t* c, t9p_handle_t dir, t9p_dir_info_t** outdirs) {
    char packet[PACKET_BUF_SIZE];
    int l, status = 0;
    *outdirs = NULL;
    t9p_dir_info_t* prev = NULL, *head = NULL;

    /** fid must be valid AND open */
    if (!t9p_is_valid(dir) || !t9p_is_open(dir))
        return -EBADF;
    
    /** Only work on dirs.. */
    if (!(dir->qid.type & T9P_QID_DIR))
        return -ENOTDIR;

    struct trans_node* n = tr_get_node(&c->trans_pool);
    if (!n) return -ENOMEM;

    /** Treaddir is a bit of a strange call. count does not refer to the number of records returned,
     *  but instead refers to the number of bytes returned. In some ways this is better than the number
     *  of records because we can constrain the number of bytes better than arbitrary length records.
     *  Count will always be our packet buffer size minus the Rreaddir header size. Offset is adjusted
     *  accordingly.
     */
    const uint32_t count = sizeof(packet) - sizeof(struct Rreaddir);
    uint64_t offset = 0;
    for (int i = 0; i < 999; ++i) {

        if ((l = encode_Treaddir(packet, sizeof(packet), n->tag, dir->fid, offset, count)) < 0) {
            ERROR(c, "%s: Unable to encode Treaddir\n", __FUNCTION__);
            status = -EINVAL;
            goto error;
        }

        struct trans tr = {
            .data = packet,
            .size = l,
            .rdata = packet,
            .rsize = sizeof(packet),
            .rtype = T9P_TYPE_Rreaddir
        };

        if ((l = tr_send_recv(c, n, &tr)) < 0) {
            ERROR(c, "%s: send failed: %s\n", __FUNCTION__, _strerror(l));
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
        free(d);
        d = dn;
    }
    return status;
}

int t9p_unlinkat(t9p_context_t* c, t9p_handle_t dir, const char* file) {
    
}

uint32_t t9p_get_iounit(t9p_handle_t h) {
    return h->iounit;
}

int t9p_is_open(t9p_handle_t h) {
    return h->iounit != 0;
}

int t9p_is_valid(t9p_handle_t h) {
    return !!(h->valid_mask & T9P_HANDLE_ACTIVE);
}

qid_t t9p_get_qid(t9p_handle_t h) {
    if (h->valid_mask & T9P_HANDLE_QID_VALID)
        return h->qid;
    qid_t inval = {0};
    return inval;
}

void t9p_free_dirs(t9p_dir_info_t* head) {
    if (!head) return;
    for (t9p_dir_info_t* d = head; d;) {
        t9p_dir_info_t* dn = d->next;
        free(d);
        d = dn;
    }
}

/********************************************************************/
/*                                                                  */
/*                C O N T E X T       M E T H O D S                 */
/*                                                                  */
/********************************************************************/

/** Alloc a new handle, locks fid table */
static struct t9p_handle_node* _alloc_handle(struct t9p_context* c) {
    mutex_lock(c->fhl_mutex);
    struct t9p_handle_node* n = c->fhl_free;
    if (!n) {
        mutex_unlock(c->fhl_mutex);
        return NULL;
    }
    /** Unlink from free list */
    c->fhl_free = n->next;
    n->prev = n->next = NULL;

    /** Mark used */
    n->h.valid_mask = T9P_HANDLE_ACTIVE;

    mutex_unlock(c->fhl_mutex);
    return n;
}

/** Release a handle for reuse */
static void _release_handle(struct t9p_context* c, struct t9p_handle_node* h) {
    mutex_lock(c->fhl_mutex);

    /** Clear data, but preserve fid */
    memset(&h->h.qid, 0, sizeof(h->h.qid));
    h->h.iounit = 0;
    h->h.valid_mask = 0;

    /** Link into free list */
    h->next = h->prev = NULL;
    h->next = c->fhl_free;
    c->fhl_free = h;

    mutex_unlock(c->fhl_mutex);
}

static void _release_handle_by_fid(struct t9p_context* c, t9p_handle_t h) {
    _release_handle(c, &c->fhl[h->fid]);
}

/** Can we read/write to a fid? */
static int _can_rw_fid(t9p_handle_t h, int write) {
    if (!t9p_is_open(h))
        return 0;
    return (h->qid.type != T9P_QID_MOUNT && h->qid.type != T9P_QID_DIR && h->qid.type != T9P_QID_AUTH
        && (write ? 1 : h->qid.type != T9P_QID_APPEND));
}

static void _discard(struct t9p_context* c, struct TRcommon* com) {
    char buf[256];
    ssize_t left = com->size;
    while (left > 0) {
        size_t r = MIN(sizeof(buf), left);
        if (c->trans.recv(c->conn, buf, r, 0) == -1)
            return;
        left -= r;
    }
}

static void* _t9p_thread_proc(void* param) {
    t9p_context_t* c = param;

    struct trans_node** requests = calloc(MAX_TAGS, sizeof(struct trans_node*));

    while (c->thr_run) {
        struct trans_node* node = NULL;
        size_t size = sizeof(node);
        ssize_t l;

        mutex_lock(c->socket_lock);

        /** Send pending transactions */
        while (msg_queue_recv(c->trans_pool.queue, &node, &size) == 0) {
            assert(size == sizeof(node));
            if (!node) {
                ERROR(c, "Got NULL node\n");
                continue;
            }

            if (c->opts.log_level <= T9P_LOG_TRACE) {
                if (node->tr.hdata)
                    printf("send: (header) type=%d, len=%d, tag=%d\n", ((struct TRcommon*)node->tr.hdata)->type, ((struct TRcommon*)node->tr.hdata)->size, ((struct TRcommon*)node->tr.hdata)->tag);
                if (node->tr.data)
                    printf("send: type=%d, len=%d, tag=%d\n", ((struct TRcommon*)node->tr.data)->type, ((struct TRcommon*)node->tr.data)->size, ((struct TRcommon*)node->tr.data)->tag);
            }

            /** Send any header data first */
            if (node->tr.hdata && (l = c->trans.send(c->conn, node->tr.hdata, node->tr.hsize, 0)) < 0) {
                if (errno == EAGAIN) {
                    continue; /** Just try again next iteration */
                }
                ERROR(c, "send: Failed to send header data: %s\n", strerror(errno));
                continue;
            }

            /** Send "body" data */
            if ((l = c->trans.send(c->conn, node->tr.data, node->tr.size, 0)) < 0) {
                ERROR(c, "send: Failed to send data: %s\n", strerror(errno));
                continue;
            }

            node->sent = 1;
            assert(!requests[node->tag]);
            requests[node->tag] = node;
        }

        char buf[256] = {0};

        /** Recv pending transactions */
        while ((l = c->trans.recv(c->conn, buf, sizeof(buf), T9P_RECV_PEEK)) > 0) {
            struct TRcommon com = {0};
            if (decode_TRcommon(&com, buf, l) < 0) {
                ERROR(c, "recv: Unable to decode common header; discarding!\n");
                c->trans.recv(c->conn, buf, sizeof(buf), 0); /** Discard */
                continue;
            }

            if (c->opts.log_level <= T9P_LOG_TRACE) {
                printf("recv: type=%d, tag=%d, size=%d\n", com.type, com.tag, com.size);
            }

            if (com.tag >= MAX_TAGS) {
                ERROR(c, "recv: Unexpected tag '%d'; discarding!\n", com.tag);
                _discard(c, &com);
                continue;
            }

            struct trans_node* n = requests[com.tag];
            if (!n) {
                ERROR(c, "recv: Tag '%d' not found in request list; discarding!\n", com.tag);
                _discard(c, &com);
                continue;
            }

            /** Handle error responses */
            if (com.type == T9P_TYPE_Rlerror) {
                struct Rlerror err = {0};
                if (decode_Rlerror(&err, buf, l) < 0)
                    err.ecode = -1;

                n->tr.status = err.ecode < 0 ? err.ecode : -err.ecode;
                
                if (n->tr.rdata)
                    memcpy(n->tr.rdata, &err, MIN(sizeof(err), n->tr.rsize));
                _discard(c, &com);
                event_signal(n->event);
                requests[n->tag] = NULL;
                continue;
            }

            /** Check for type mismatch and discard if there is one */
            if (n->tr.rtype != 0 && com.type != n->tr.rtype) {
                ERROR(c, "recv: Expected msg type '%d' but got '%d'; discarding!\n", n->tr.rtype, com.type);
                _discard(c, &com);
                n->tr.status = -1;
                event_signal(n->event);
                requests[n->tag] = NULL;
                continue;
            }

            /** No result data space? well, discard... */
            if (!n->tr.rdata || n->tr.rsize == 0)
                _discard(c, &com);
            else {
                /** Read off what we can */
                l = c->trans.recv(c->conn, n->tr.rdata, MIN(n->tr.rsize, com.size), 0);
                if (l > 0) {
                    ssize_t rem = com.size - l;

                    /** Discard the rest */
                    while (rem > 0) {
                        ssize_t r = c->trans.recv(c->conn, buf, MIN(sizeof(buf), rem), 0);
                        if (r <= 0)
                            break;
                        rem -= r;
                    }

                    if (rem > 0)
                        ERROR(c, "recv: Partial discard\n" );
                }
            }
            
            /** Set status accordingly */
            n->tr.status = l < 0 ? -errno : l;

            event_signal(n->event);
            requests[n->tag] = NULL;
            continue;
        }

        mutex_unlock(c->socket_lock);

        /** Interruptible sleep */
        event_wait(c->trans_pool.recv_ev, 1000);
        //usleep(1000);
    }

    free(requests);
    return NULL;
}

/********************************************************************/
/*                                                                  */
/*                   T C P     T R A N S P O R T                    */
/*                                                                  */
/********************************************************************/

#if HAVE_TCP

struct tcp_context {
    int sock;
};

void* t9p_tcp_init() {
    struct tcp_context* ctx = calloc(1, sizeof(struct tcp_context));
    ctx->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ctx->sock < 0) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

int t9p_tcp_disconnect(void* context) {
    struct tcp_context* ctx = context;
    
#if 1
    if (shutdown(ctx->sock, SHUT_RDWR) < 0) {
#else
    if (connect(ctx->sock, &s, sizeof(s)) < 0) {
#endif
        fprintf(stderr, "Disconnect failed: %s\n", strerror(errno));
        return -1;
    }

    close(ctx->sock);

    return 0;
}

int t9p_tcp_connect(void* context, const char* addr_or_file) {
    struct tcp_context* ctx = context;

    char a[256];
    strNcpy(a, addr_or_file, sizeof(a));

    char* paddr = strtok(a, ":");
    char* pport = strtok(NULL, ":");

    struct sockaddr_in addr = {0};
    addr.sin_addr.s_addr = inet_addr(paddr);
    addr.sin_family = AF_INET;
    if (pport)
        addr.sin_port = htons(atoi(pport));
    else
        addr.sin_port = htons(T9P_DEFAULT_PORT);

    if (connect(ctx->sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Connect failed to %s: %s\n", addr_or_file, strerror(errno));
        return -1;
    }

#if __RTEMS_MAJOR__ < 5
    /** Nonblock for RTEMS legacy networking */
    int noblock = 1;
    assert(ioctl(ctx->sock, FIONBIO, &noblock) == 0);
#else
    /** Set nonblock */
    if (fcntl(ctx->sock, F_SETFL, O_NONBLOCK) < 0) {
        perror("Failed to set O_NONBLOCK on socket");
        close(ctx->sock);
        return 1;
    }
#endif

    return 0;
}

void t9p_tcp_shutdown(void* context) {
    struct tcp_context* ctx = context;
    close(ctx->sock);
    free(context);
}

ssize_t t9p_tcp_send(void* context, const void* data, size_t len, int flags) {
    struct tcp_context* pc = context;
    return send(pc->sock, data, len, flags);
}

ssize_t t9p_tcp_recv(void* context, void* data, size_t len, int flags) {
    int rflags = 0;
    if (flags & T9P_RECV_PEEK)
        rflags |= MSG_PEEK | MSG_DONTWAIT;

    struct tcp_context* pc = context;
    /** Read behavior instead of peek */
    //if (flags & T9P_RECV_READ)
    //    return read(pc->sock, data, len);
    //else
        return recv(pc->sock, data, len, rflags);
}

#endif

int t9p_init_tcp_transport(t9p_transport_t* tp) {
#if HAVE_TCP
    tp->init = t9p_tcp_init;
    tp->shutdown = t9p_tcp_shutdown;
    tp->connect = t9p_tcp_connect;
    tp->recv = t9p_tcp_recv;
    tp->send = t9p_tcp_send;
    tp->disconnect = t9p_tcp_disconnect;
    return 0;
#else
    return -1;
#endif
}

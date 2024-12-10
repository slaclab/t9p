/** Feature flags */
#define HAVE_TCP    1
#define HAVE_UDP    1

#include "t9p_platform.h"

#include <getopt.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <byteswap.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#include <unistd.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#define PATH_MAX 256
#endif

#if HAVE_TCP || HAVE_UDP
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#endif

#include "t9p.h"
#include "t9proto.h"

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

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BSWAP32(x) bswap_32(x)
#define BSWAP16(x) bswap_16(x)
#define BSWAP64(x) bswap_64(x)
#else
#define BSWAP32(x) (x)
#define BSWAP16(x) (x)
#define BSWAP64(x) (x)
#endif

struct trans_pool {
    struct trans_node* freehead;
    mutex_t* guard;
    uint32_t total;
    msg_queue_t* queue;
};

struct t9p_context {
    void* conn;
    t9p_transport_t* trans;
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

static int _mktag(struct t9p_context* c);
static void _release_tag(struct t9p_context* c, int tag);

static void* _t9p_thread_proc(void* param);

static void _free_node_list(struct t9p_handle_node* head);

/********************************************************************/
/*                                                                  */
/*            T R A N S A C T I O N        P O O L                  */
/*                                                                  */
/********************************************************************/

struct trans;
struct trans_pool;
struct trans_node;

struct trans_node* trans_enqueue(struct trans_pool* q, struct trans* tr);
void trans_release(struct trans_pool* q, struct trans_node* tn);

struct trans {
    uint32_t flags;         /**< Flags */
    
    const void* data;       /**< Outgoing data */
    size_t size;            /**< Outgoing data size */

    void* rdata;            /**< Buffer to hold incoming data */
    size_t rsize;           /**< Incoming data buffer size */

    const void* hdata;      /**< Optional; header data pointer. If not NULL, this is ent before
                                 this->data is. This is used to avoid unnecessary copies */
    size_t hsize;           /**< Optional; header data size */

    int32_t* status;        /**< Pointer to combined status/length variable. If < 0, this represents an
                                 error condition. If >= 0, it's the number of bytes written to rdata. */

    /** 9p meta info */
    uint32_t rtype;         /**< Result message type. Set to 0 to accept any. */
    uint16_t tag;           /**< Transaction tag */
};

struct trans_node {
    struct trans tr;

    uint8_t sent;                   /**< Set once we've been sent */
    event_t* event;                 /**< Signaled when the response to this is receieved */
    
    struct trans_node* next;
};

/**
 * Init the transaction queue
 */
int trans_pool_init(struct trans_pool* q, uint32_t num) {
    memset(q, 0, sizeof(*q));

    q->queue = msg_queue_create("/tmp/TPOOL", sizeof(struct trans_node*), MAX_TRANSACTIONS);
    if (!q->queue)
        return -1;

    if (!(q->guard = create_mutex())) {
        msg_queue_destroy(q->queue);
        return -1;
    }

    lock_mutex(q->guard);

    /** Allocate nodes */
    for (int i = 0; i < num; ++i) {
        struct trans_node* on = q->freehead;
        q->freehead = calloc(1, sizeof(*on));
        q->freehead->event = event_create();
        q->freehead->next = on;
    }
    q->total = num;

    unlock_mutex(q->guard);
    return 0;
}

/**
 * Destroy the transaction queue
 */
void trans_pool_destroy(struct trans_pool* q) {
    lock_mutex(q->guard);

    /** Free both lists */
    for (struct trans_node* n = q->freehead; n;) {
        struct trans_node* b = n->next;
        event_destroy(b->event);
        free(n);
        n = b;
    }

    msg_queue_destroy(q->queue);

    unlock_mutex(q->guard);
    destroy_mutex(q->guard);
}

/**
 * Enqueue transaction. Returns the node in the queue for this transaction. On failure, this will
 * return NULL. Failure will occur in two situations:
 *  1. No remaining free transactions in the pool
 *  2. No remaining space in the message queue
 */
struct trans_node* trans_enqueue(struct trans_pool* q, struct trans* tr) {
    lock_mutex(q->guard);

    if (!q->freehead) {
        /** Out of space in the trans queue */
        unlock_mutex(q->guard);
        return NULL;
    }

    /** Extract node from the free list */
    struct trans_node* us = q->freehead;
    q->freehead = us->next;

    /** Copy in data */
    us->next = NULL;
    us->tr = *tr;

    unlock_mutex(q->guard);

    /** Send it to the I/O thread */
    if (msg_queue_send(q->queue, &us, sizeof(us)) < 0) {
        trans_release(q, us);
        return NULL;
    }

    return us;
}

/**
 * Release a node back into the transaction pool.
 */
void trans_release(struct trans_pool* q, struct trans_node* tn) {
    lock_mutex(q->guard);

    tn->next = q->freehead;
    q->freehead = tn;

    unlock_mutex(q->guard);
}

/** Safe strcpy that ensures dest is NULL terminated */
void strNcpy(char* dest, const char* src, size_t dmax) {
    if (!dmax || !dest) return;
    if (!src) dest[0] = 0;
    strncpy(dest, src, dmax);
    dest[dmax-1] = 0;
}
#define strncpy strNcpy


void t9p_opts_init(struct t9p_opts* opts) {
    memset(opts, 0, sizeof(*opts));
    opts->max_read_data_size = (2<<20); /** 1M */
    opts->max_write_data_size = (2<<20); /** 1M */
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
    c->trans = transport;
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

    if (!(c->fhl_mutex = create_mutex())) {
        ERRLOG("Unable to create fhl_mutex\n");
        goto error_pre_fhl;
    }

    if (!(c->socket_lock = create_mutex())) {
        ERRLOG("Unable to create socket_lock\n");
        goto error_pre_fhl;
    }

    if (!(c->recv_event = event_create())) {
        ERRLOG("Unable to create event\n");
        goto error_post_fhl;
    }

    if (trans_pool_init(&c->trans_pool, MAX_TRANSACTIONS) < 0) {
        ERRLOG("Unable to create transaction pool\n");
        goto error_post_fhl;
    }

    /** Perform the version handshake */
    if (_version_handshake(c) < 0) {
        ERRLOG("Connection to %s failed\n", addr);
        transport->disconnect(c->conn);
        transport->shutdown(c->conn);
        goto error_post_pool;
    }

    /** Attach to the root fs */
    if (_attach_root(c) < 0) {
        ERRLOG("Connected to %s failed\n", addr);
        transport->disconnect(c->conn);
        transport->shutdown(c->conn);
        goto error_post_pool;
    }

    c->thr_run = 1;

    /** Kick off thread */
    if (!(c->io_thread = create_thread(_t9p_thread_proc, c))) {
        t9p_shutdown(c);
        return NULL;
    }

    return c;

error_post_pool:
    trans_pool_destroy(&c->trans_pool);
error_post_fhl:
    destroy_mutex(c->socket_lock);
    destroy_mutex(c->fhl_mutex);
    event_destroy(c->recv_event);
    _free_node_list(c->fhl_free);
    //_free_node_list(c->fhl_list);
error_pre_fhl:
    free(c);
    return NULL;
}

void t9p_shutdown(t9p_context_t* c) {
    /** Clunk all active file handles */
    lock_mutex(c->fhl_mutex);
    for (int i = 0; i < c->fhl_max; ++i)
        if (c->fhl[i].h.valid_mask & T9P_HANDLE_FID_VALID)
            _clunk_sync(c, c->fhl[i].h.fid);
    unlock_mutex(c->fhl_mutex);

    /** Disconnect and shutdown the transport layer */
    c->trans->disconnect(c->conn);
    c->trans->shutdown(c->conn);

    _free_node_list(c->fhl_free);
    //_free_node_list(c->fhl_list);

    free(c->fhl);

    /** Kill off the thread */
    c->thr_run = 0;
    thread_join(c->io_thread);

    destroy_mutex(c->fhl_mutex);
    event_destroy(c->recv_event);
    free(c);
}

static int tr_send_recv(struct t9p_context* c, struct trans* tr) {
    int r = 0, status = 0;
    tr->status = &status; /** We always want to capture this */

    struct trans_node* n = trans_enqueue(&c->trans_pool, tr);
    if (n == NULL) {
        tr->status = NULL;
        return -1;
    }

    /** Wait until serviced (or timeout) */
    if ((r = event_wait(n->event, c->opts.recv_timeo)) != 0) {
        tr->status = NULL;
        return -1;
    }
    tr->status = NULL;
    trans_release(&c->trans_pool, n); /** Release the transaction back into the pool */
    return status;
}

static int tr_send(struct t9p_context* c, struct trans* tr) {
    int r = 0;

    struct trans_node* n = trans_enqueue(&c->trans_pool, tr);
    if (n == NULL) {
        return -1;
    }

    return 0;
}

static int _send(struct t9p_context* c, const void* data, size_t sz, int flags) {
    return c->trans->send(c->conn, data, sz, flags);
}

/** Synchronously recv a type of packet, or Rerror. Includes timeout */
static ssize_t _recv_type(struct t9p_context* c, void* data, size_t sz, int flags, uint8_t type, uint16_t tag) {
    ssize_t n;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int timeoutMs = c->opts.recv_timeo;
    while (1) {
        n = c->trans->recv(c->conn, data, sz, 0);
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

static int _iserror(struct TRcommon* err) {
    return err->type == T9P_TYPE_Rerror || err->type == T9P_TYPE_Rlerror;
}

static int _version_handshake(struct t9p_context* c) {
    const uint8_t version[] = "9P2000.L";

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
    uint16_t tag = _mktag(c);
    int l;
    if ((l = encode_Tclunk(buf, sizeof(buf), tag, fid)) < 0) {
        ERROR(c, "Failed to encode Tclunk\n");
        return -1;
    }

    struct trans tr = {
        .data = buf,
        .size = l,
        .rtype = T9P_TYPE_Rclunk,
        .rsize = sizeof(buf),
        .rdata = buf,
        .tag = tag
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: Tclunk failed\n", __FUNCTION__);
        return -1;
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

t9p_handle_t t9p_open_handle(t9p_context_t* c, t9p_handle_t parent, const char* path) {
    char p[T9P_PATH_MAX];
    strNcpy(p, path, sizeof(p));

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

    uint16_t tag = _mktag(c);

    struct t9p_handle_node* fh = _alloc_handle(c);
    if (!fh) {
        return NULL;
    }

    char packet[PACKET_BUF_SIZE];
    int l = 0;
    if ((l = encode_Twalk(packet, sizeof(packet), tag, parent->fid, fh->h.fid, nwcount, (const char* const*)comps)) < 0) {
        ERROR(c, "%s: unable to encode Twalk\n", __FUNCTION__);
        goto error;
    }

    /** Build transaction to send */
    struct trans tr = {
        .data = packet,
        .size = l,
        .tag = tag,
        .rtype = T9P_TYPE_Rwalk,
        .rdata = packet,
        .rsize = sizeof(packet),
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
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
    uint16_t tag = _mktag(c);
    int l = 0;
    if ((l = encode_Tlopen(packet, sizeof(packet), tag, h->fid, mode)) < 0) {
        ERROR(c, "%s: unable to encode Tlopen", __FUNCTION__);
        return -1;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .tag = tag,
        .rtype = T9P_TYPE_Rlopen,
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: Tlopen failed\n", __FUNCTION__);
        return -1;
    }

    struct Rlopen rl;
    if (decode_Rlopen(&rl, packet, l) < 0) {
        ERROR(c, "%s: Malformed Rlopen\n", __FUNCTION__);
        return -1;
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

    if (!_can_rw_fid(h, 0))
        return -1;

    uint16_t tag = _mktag(c);

    int l;
    if ((l = encode_Tread(packet, sizeof(packet), tag, h->fid, offset, num)) < 0) {
        ERROR(c, "%s: could not encode Tread\n", __FUNCTION__);
        return -1;
    }

    /** TODO: This needs a refactor */
    size_t recvSize = sizeof(struct Rread) + num;
    void* recvData = malloc(recvSize);

    struct trans tr = {
        .tag = tag,
        .data = packet,
        .size = l,
        .rdata = recvData,
        .rsize = recvSize,
        .rtype = T9P_TYPE_Rread,
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        goto error;
    }

    struct Rread rr;
    if (decode_Rread(&rr, recvData, l) < 0) {
        ERROR(c, "%s: unable to decode Rread\n", __FUNCTION__);
        goto error;
    }

    memcpy(outbuffer, ((uint8_t*)recvData)+sizeof(struct Rread), MIN(num, rr.count));
    free(recvData);
    return MIN(num, rr.count);

error:
    free(recvData);
    return -1;
}

ssize_t t9p_write(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, const void* inbuffer) {
    char packet[PACKET_BUF_SIZE];

    if (!_can_rw_fid(h, 1))
        return -1;

    uint16_t tag = _mktag(c);

    int l;
    if ((l = encode_Twrite(packet, sizeof(packet), tag, h->fid, offset, num)) < 0) {
        ERROR(c, "%s: unable to encode Twrite\n", __FUNCTION__);
        return -1;
    }

    struct trans tr = {
        .hdata = packet,
        .hsize = l,
        .data = inbuffer,
        .size = num,
        .tag = tag,
        .rtype = T9P_TYPE_Rwrite,
        .rdata = packet,
        .rsize = sizeof(packet)
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: Twrite failed\n", __FUNCTION__);
        return -1;
    }

    struct Rwrite rw;
    if (decode_Rwrite(&rw, packet, l) < 0) {
        ERROR(c, "%s: failed to decode Rwrite\n", __FUNCTION__);
        return -1;
    }

    return rw.count;
}


int t9p_getattr(t9p_context_t* c, t9p_handle_t h, struct t9p_attr* attr, uint64_t mask) {
    char packet[PACKET_BUF_SIZE];

    if (!t9p_is_valid(h))
        return -1;

    uint16_t tag = _mktag(c);

    int l;
    if ((l = encode_Tgetattr(packet, sizeof(packet), tag, h->fid, mask)) < 0) {
        ERROR(c, "%s: failed to encode Tgetattr\n", __FUNCTION__);
        return -1;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rtype = T9P_TYPE_Rgetattr,
        .rdata = packet,
        .rsize = sizeof(packet),
        .tag = tag
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: Tgetattr failed\n", __FUNCTION__);
        return -1;
    }

    struct Rgetattr rg;
    if (decode_Rgetattr(&rg, packet, l) < 0) {
        ERROR(c, "%s: failed to decode Rgetattr\n", __FUNCTION__);
        return -1;
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

    uint16_t tag = _mktag(c);

    /** If parent is NULL, parent is root */
    if (!t9p_is_valid(parent))
        parent = t9p_get_root(c);

    /** Duplicate fid of parent */
    t9p_handle_t h = t9p_dup(c, parent);
    if (!h)
        return -1;

    int l;
    if ((l = encode_Tlcreate(packet, sizeof(packet), tag, h->fid, name, flags, mode, gid)) < 0) {
        ERROR(c, "%s: failed to encode Tlcreate\n", __FUNCTION__);
        t9p_close_handle(c, h);
        return -1;
    }
    
    struct trans tr = {
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .tag = tag,
        .rtype = T9P_TYPE_Rlcreate
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: Tlcreate failed\n", __FUNCTION__);
        t9p_close_handle(c, h);
        return -1;
    }

    struct Rlcreate rl;
    if (decode_Rlcreate(&rl, packet, l) < 0) {
        ERROR(c, "%s: Rlcreate decode failed\n", __FUNCTION__);
        t9p_close_handle(c, h);
        return -1;
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

t9p_handle_t t9p_dup(t9p_context_t* c, t9p_handle_t todup) {
    char packet[PACKET_BUF_SIZE];

    if (!t9p_is_valid(todup))
        return NULL;

    struct t9p_handle_node* h = _alloc_handle(c);
    if (!h) {
        ERROR(c, "%s: unable to alloc new handle\n", __FUNCTION__);
        return NULL;
    }

    uint16_t tag = _mktag(c);
    int l;
    if ((l=encode_Twalk(packet, sizeof(packet), tag, todup->fid, h->h.fid, 0, NULL)) < 0) {
        ERROR(c, "%s: failed to encode Twalk\n", __FUNCTION__);
        _release_handle(c, h);
        return NULL;
    }

    struct trans tr = {
        .tag = tag,
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rwalk,
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        _release_handle(c, h);
        return NULL;
    }

    struct Rwalk rw;
    qid_t* qid = NULL;
    if (decode_Rwalk(&rw, packet, l, &qid) < 0) {
        _release_handle(c, h);
        return NULL;
    }

    h->h.qid = qid[rw.nwqid-1];
    h->h.valid_mask |= T9P_HANDLE_FID_VALID | T9P_HANDLE_QID_VALID;
    return &h->h;
}

int t9p_remove(t9p_context_t* c, t9p_handle_t h) {
    char packet[PACKET_BUF_SIZE];
    if (!t9p_is_valid(h))
        return -1;

    uint16_t tag = _mktag(c);
    int l;
    if ((l = encode_Tremove(packet, sizeof(packet), tag, h->fid)) < 0) {
        ERROR(c, "%s: unable to encode Tremove\n", __FUNCTION__);
        return -1;
    }

    int status;
    struct trans tr = {
        .tag = tag,
        .data = packet,
        .size = l,
        .rdata = packet,
        .rsize = sizeof(packet),
        .rtype = T9P_TYPE_Rremove,
        .status = &status
    };

    struct trans_node* n = trans_enqueue(&c->trans_pool, &tr);
    if (!n) {
        ERROR(c, "%s: unable to queue\n", __FUNCTION__);
        return -1;
    }

    /** Tremove is basically just a clunk with the side effect of removing a file. This will clunk even if the remove fails */
    _release_handle_by_fid(c, h);

    if (event_wait(n->event, c->opts.recv_timeo) != 0) {
        ERROR(c, "%s: timed out\n", __FUNCTION__);
        return 0; /** TODO: Returning -1 here and releasing the file handle would be inconsistent with the other error cases */
    }

    trans_release(&c->trans_pool, n);

    return 0;
}

int t9p_fsync(t9p_context_t* c, t9p_handle_t file) {
    char packet[PACKET_BUF_SIZE];
    if (!t9p_is_open(file))
        return -1;

    uint16_t tag = _mktag(c);
    int l;
    if ((l = encode_Tfsync(packet, sizeof(packet), tag, file->fid)) < 0) {
        ERROR(c, "%s: Unable to encode Tfsync\n", __FUNCTION__);
        return -1;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rtype = T9P_TYPE_Rfsync,
        .tag = tag,
        .rdata = packet,
        .rsize = sizeof(packet)
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

int t9p_mkdir(t9p_context_t* c, t9p_handle_t parent, const char* name, uint32_t mode, uint32_t gid, qid_t* outqid) {
    char packet[PACKET_BUF_SIZE];
    if (!t9p_is_valid(parent))
        return -1;

    uint16_t tag = _mktag(c);

    if (gid == T9P_NOGID) {
        gid = c->opts.gid;
    }

    int l;
    if ((l = encode_Tmkdir(packet, sizeof(packet), tag, parent->fid, name, mode, gid)) < 0) {
        ERROR(c, "%s: Unable to encode Tmkdir\n", __FUNCTION__);
        return -1;
    }

    struct trans tr = {
        .data = packet,
        .size = l,
        .rtype = T9P_TYPE_Rmkdir,
        .rdata = packet,
        .rsize = sizeof(packet),
        .tag = tag
    };

    if ((l = tr_send_recv(c, &tr)) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        return -1;
    }

    if (outqid) {
        struct Rmkdir rm;
        if (decode_Rmkdir(&rm, packet, l) < 0) {
            ERROR(c, "%s: failed to decode Rmkdir\n", __FUNCTION__);
            return -1;
        }
        *outqid = rm.qid;
    }

    return 0;
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

/********************************************************************/
/*                                                                  */
/*                C O N T E X T       M E T H O D S                 */
/*                                                                  */
/********************************************************************/

/** Alloc a new handle, locks fid table */
static struct t9p_handle_node* _alloc_handle(struct t9p_context* c) {
    lock_mutex(c->fhl_mutex);
    struct t9p_handle_node* n = c->fhl_free;
    if (!n) {
        unlock_mutex(c->fhl_mutex);
        return NULL;
    }
    /** Unlink from free list */
    c->fhl_free = n->next;
    n->prev = n->next = NULL;

    /** Mark used */
    n->h.valid_mask |= T9P_HANDLE_ACTIVE;

    unlock_mutex(c->fhl_mutex);
    return n;
}

/** Release a handle for reuse */
static void _release_handle(struct t9p_context* c, struct t9p_handle_node* h) {
    lock_mutex(c->fhl_mutex);

    /** Clear data, but preserve fid */
    memset(&h->h.qid, 0, sizeof(h->h.qid));
    h->h.iounit = 0;
    h->h.valid_mask = 0;

    /** Link into free list */
    h->next = h->prev = NULL;
    h->next = c->fhl_free;
    c->fhl_free = h;

    unlock_mutex(c->fhl_mutex);
}

static void _release_handle_by_fid(struct t9p_context* c, t9p_handle_t h) {
    _release_handle(c, &c->fhl[h->fid]);
}

static int _mktag(struct t9p_context* c) {
    return 0; // TODO:!!!!!
}

static void _release_tag(struct t9p_context* c, int tag) {

}


static void _free_node_list(struct t9p_handle_node* head) {
    //for (struct t9p_handle_node* n = head; n;) {
    //    struct t9p_handle_node* nn = n->next;
    //    free(n);
    //    n = nn;
    //}
}

/** Can we read/write to a fid? */
static int _can_rw_fid(t9p_handle_t h, int write) {
    if (!t9p_is_open(h))
        return 0;
    return (h->qid.type != T9P_QID_MOUNT && h->qid.type != T9P_QID_DIR && h->qid.type != T9P_QID_AUTH
        && (write ? 1 : h->qid.type != T9P_QID_APPEND));
}

static void* _t9p_thread_proc(void* param) {
    t9p_context_t* c = param;

    static struct trans_node* requests[MAX_TAGS] = {0};

    while (c->thr_run) {
        struct trans_node* node = NULL;
        size_t size;
        ssize_t l;

        /** Send pending transactions */
        while (msg_queue_recv(c->trans_pool.queue, &node, &size) == 0) {
            assert(size == sizeof(node));
            if (!node) {
                ERROR(c, "Got NULL node\n");
                continue;
            }

            /** Send any header data first */
            if (node->tr.hdata && (l = c->trans->send(c->conn, node->tr.hdata, node->tr.hsize, 0)) < 0) {
                ERROR(c, "send: Failed to send header data: %s\n", strerror(l));
                continue;
            }

            /** Send "body" data */
            printf("send %p %ld\n", node->tr.data, node->tr.size);
            if ((l = c->trans->send(c->conn, node->tr.data, node->tr.size, 0)) < 0) {
                ERROR(c, "send: Failed to send data: %s\n", strerror(errno));
                continue;
            }

            node->sent = 1;
            requests[node->tr.tag] = node;
        }

        union {
            char buf[128];
            struct TRcommon com;
            struct Rlerror err;
        } data;

        /** Recv pending transactions */
        while ((l = c->trans->recv(c->conn, data.buf, sizeof(data.buf), T9P_RECV_PEEK)) > 0) {
            printf("recv: type=%d, tag=%d, size=%d\n", data.com.type, data.com.tag, data.com.size);
            if (data.com.tag >= MAX_TAGS) {
                ERROR(c, "recv: Unexpected tag '%d'; discarding!\n", data.com.tag);
                c->trans->recv(c, data.buf, sizeof(data.buf), 0); /** Discard */
                continue;
            }

            if (l < sizeof(struct TRcommon))
                continue;

            struct trans_node* n = requests[data.com.tag];
            if (!n) {
                ERROR(c, "recv: Tag '%d' not found in request list; discarding!\n", data.com.tag);
                continue;
            }

            /** Handle error responses */
            if (data.com.type == T9P_TYPE_Rlerror) {
                if (n->tr.status)
                    *n->tr.status = data.err.ecode < 0 ? data.err.ecode : -data.err.ecode;
                if (n->tr.rdata)
                    memcpy(n->tr.rdata, &data.err, MIN(sizeof(data.err), n->tr.rsize));
                c->trans->recv(c->conn, data.buf, sizeof(data.buf), 0); /** Discard */
                event_signal(n->event);
                requests[n->tr.tag] = NULL;
                continue;
            }

            /** Check for type mismatch and discard if there is one */
            if (n->tr.rtype != 0 && data.com.type != n->tr.rtype) {
                ERROR(c, "recv: Expected msg type '%d' but got '%d'; discarding!\n", n->tr.rtype, data.com.type);
                c->trans->recv(c->conn, data.buf, sizeof(data.buf), 0); /** Discard */
                if (n->tr.status)
                    *n->tr.status = -1;
                event_signal(n->event);
                requests[n->tr.tag] = NULL;
                continue;
            }

            /** Finally, service the request */
            l = c->trans->recv(c->conn, n->tr.rdata ? n->tr.rdata : data.buf, n->tr.rdata ? n->tr.rsize : sizeof(data.buf), 0);
            if (n->tr.status)
                *n->tr.status = l < 0 ? -errno : l;
            event_signal(n->event);
            requests[n->tr.tag] = NULL;
            
        }
    }

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

    /** Set this after connect to avoid EAGAIN there */
    int noblock = 1;
    assert(ioctl(ctx->sock, FIONBIO, &noblock) == 0);

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
        rflags |= MSG_PEEK;
    if (flags & T9P_RECV_NOWAIT)
        rflags |= MSG_DONTWAIT;

    struct tcp_context* pc = context;
    /** Read behavior instead of peek */
    if (flags & T9P_RECV_READ)
        return read(pc->sock, data, len);
    else
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

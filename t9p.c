/** Feature flags */
#define HAVE_TCP    1
#define HAVE_UDP    1

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
#endif

#include "t9p.h"
#include "t9proto.h"

#define MAX_FILES_DEFAULT 256

#define PACKET_BUF_SIZE 8192

#define MAX_PATH_COMPONENTS 256

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

static int _version_handshake(struct t9p_context* context);
static int _attach_root(struct t9p_context* c);
static int _send(struct t9p_context* c, const void* data, size_t sz, int flags, int retries);
static ssize_t _recv(struct t9p_context* c, void* data, size_t sz, int flags);
static void _perror(struct t9p_context* c, struct TRcommon* err);
static int _iserror(struct TRcommon* err);
static int _clunk_sync(struct t9p_context* c, int fid);

struct t9p_context {
    void* conn;
    t9p_transport_t* trans;
    char mntpoint[PATH_MAX];
    char addr[PATH_MAX];
    char apath[PATH_MAX];
    t9p_opts_t opts;
    struct t9p_handle_node* root;

    /** file handle list */
    pthread_mutex_t fhl_mutex;
    pthread_mutexattr_t fhl_mutexattr;
    int fhl_max;
    int fhl_count;
    //struct t9p_handle* fhl;

    struct t9p_handle_node* fhl;
    //struct t9p_handle_node* fhl_list;
    struct t9p_handle_node* fhl_free;
    //qid_t* qid;
};

/** t9p_context 'methods' */
static struct t9p_handle_node* _alloc_handle(struct t9p_context* c);
static void _release_handle(struct t9p_context* c, struct t9p_handle_node* h);

static int _mktag(struct t9p_context* c);
static void _release_tag(struct t9p_context* c, int tag);

static void _free_node_list(struct t9p_handle_node* head);

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

struct queue_node {
    struct queue_node* next;
    void* data;                     /**< Heap allocated data */
    uint32_t tag;                   /**< Transaction tag */
};

struct packet_queue {
    struct queue_node* head;        /**< Head of the in-flight list */
    struct queue_node* freehead;    /**< Head of the free list */
    uint32_t total;                 /**< Total number of nodes */
    uint32_t used;                  /**< Used node count */
};

void packet_queue_init(struct packet_queue* p, uint32_t nodes) {
    memset(p, 0, sizeof(*p));
    for (uint32_t i = 0; i < nodes; ++i) {
        struct queue_node* n = calloc(1, sizeof(struct queue_node));
        n->next = p->freehead;
        p->freehead = n;
    }
}

void packet_queue_destroy(struct packet_queue* p) {
    for (struct queue_node* n = p->freehead; n;) {
        struct queue_node* nn = n->next;
        free(n);
        n = nn;
    }
    p->freehead = NULL;
    for (struct queue_node* n = p->head; n;) {
        struct queue_node* nn = n->next;
        free(n);
        n = nn;
    }
    p->head = NULL;
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
    opts->max_fids = MAX_FILES_DEFAULT;
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

    pthread_mutexattr_init(&c->fhl_mutexattr);
    pthread_mutex_init(&c->fhl_mutex, &c->fhl_mutexattr);

    /** Perform the version handshake */
    if (_version_handshake(c) < 0) {
        ERRLOG("Connection to %s failed\n", addr);
        transport->disconnect(c->conn);
        transport->shutdown(c->conn);
        goto error_post_fhl;
    }

    /** Attach to the root fs */
    if (_attach_root(c) < 0) {
        ERRLOG("Connected to %s failed\n", addr);
        transport->disconnect(c->conn);
        transport->shutdown(c->conn);
        goto error_post_fhl;
    }

    return c;

error_post_fhl:
    pthread_mutexattr_destroy(&c->fhl_mutexattr);
    pthread_mutex_destroy(&c->fhl_mutex);
    _free_node_list(c->fhl_free);
    //_free_node_list(c->fhl_list);
error_pre_fhl:
    free(c);
    return NULL;
}

void t9p_shutdown(t9p_context_t* c) {
    /** Clunk all active file handles */
    pthread_mutex_lock(&c->fhl_mutex);
    for (int i = 0; i < c->fhl_max; ++i)
        if (c->fhl[i].h.valid_mask & T9P_HANDLE_FID_VALID)
            _clunk_sync(c, c->fhl[i].h.fid);
    pthread_mutex_unlock(&c->fhl_mutex);

    c->trans->disconnect(c->conn);
    c->trans->shutdown(c->conn);

    _free_node_list(c->fhl_free);
    //_free_node_list(c->fhl_list);

    free(c->fhl);

    pthread_mutex_destroy(&c->fhl_mutex);
    pthread_mutexattr_destroy(&c->fhl_mutexattr);
    free(c);
}

static int _send(struct t9p_context* c, const void* data, size_t sz, int flags, int retries) {
    int tries = 10;
    while (tries-- > 0) {
        int ret;
        if ((ret = c->trans->send(c->conn, data, sz, flags)) < 0) {
            if (ret != -EAGAIN) {
                return -1;
            }
        }
        else {
            return ret;
        }
    }
    return -1;
}

static ssize_t _recv(struct t9p_context* c, void* data, size_t sz, int flags) {
    ssize_t n;
    int timeoutMs = c->opts.recv_timeo;
    while ((n = c->trans->recv(c->conn, data, sz, MSG_DONTWAIT)) < 0 && timeoutMs >= 0) {
        usleep(1000);
        timeoutMs--;
    }
    return n;
}

/** Synchronously recv a type of packet, or Rerror. Includes timeout */
static ssize_t _recv_type(struct t9p_context* c, void* data, size_t sz, int flags, uint8_t type, uint16_t tag) {
    ssize_t n;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int timeoutMs = c->opts.recv_timeo;
    while (1) {
        n = c->trans->recv(c->conn, data, sz, MSG_DONTWAIT);
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

/** Recv + handle error */
static ssize_t _recv_type_handle_error(struct t9p_context* c, void* data, size_t sz, int flags, uint8_t type, uint16_t tag) {
    ssize_t ret;
    if ((ret=_recv_type(c, data, sz, flags, type, tag)) < 0) {
        ERROR(c, "%s: recv failed: %s\n", t9p_type_string(type), strerror(-ret));
        return -1;
    }

    if (ret < sizeof(struct TRcommon)) {
        ERROR(c, "%s: short packet\n", t9p_type_string(type));
        return -1;
    }

    if (_iserror(data)) {
        ERROR(c, "%s: error response:", t9p_type_string(type));
        _perror(c, data);
        return -1;
    }

    return ret;
}

static void _perror(struct t9p_context* c, struct TRcommon* err) {
    if (err->type == T9P_TYPE_Rlerror) {
        ERROR(c, "%s\n", strerror(((struct Rlerror*)err)->ecode));
    }
    else if (err->tag == T9P_TYPE_Rerror) {
        struct Rerror* re = (struct Rerror*)err;
        char buf[1024];
        memcpy(buf, re->ename, MIN(re->ename_len, sizeof(buf)-1));
        buf[re->ename_len] = 0;
        ERROR(c, "%s\n", buf);
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

    if (_send(c, buf, sendSize, 0, 10) < 0) {
        ERROR(c, "Tversion handshake failed: I/O error\n");
        return -1;
    }

    /** Listen for the return message */
    ssize_t read = _recv(c, buf, sizeof(buf)-1, 0);
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

    if (_send(c, packetBuf, len, 0, 10) < 0) {
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
        ERROR(c, "Rattach failed: ");
        _perror(c, com);
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
    uint16_t tag = 0;
    int l;
    if ((l = encode_Tclunk(buf, sizeof(buf), tag, fid)) < 0) {
        ERROR(c, "Failed to encode Tclunk\n");
        return -1;
    }

    if (_send(c, buf, l, 0, 1) < 0) {
        ERROR(c, "Tclunk failed: unable to send\n");
        return -1;
    }

    ssize_t read = _recv_type(c, buf, sizeof(buf), 0, T9P_TYPE_Rclunk, tag);
    if (read < 0) {
        ERROR(c, "Rclunk failed: timeout\n");
        return -1;
    }

    struct TRcommon* tc = (struct TRcommon*)buf;
    if (_iserror(tc)) {
        ERROR(c, "Rclunk failed: ");
        _perror(c, tc);
        return -1;
    }
    return 0;
}

/********************** t9p public api **********************/

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
    int len = 0;
    if ((len = encode_Twalk(packet, sizeof(packet), tag, parent->fid, fh->h.fid, nwcount, (const char* const*)comps)) < 0) {
        ERROR(c, "%s: unable to encode Twalk\n", __FUNCTION__);
        goto error;
    }

    if (_send(c, packet, len, 0, 1) < 0) {
        ERROR(c, "%s: Twalk send failed\n", __FUNCTION__);
        goto error;
    }

    ssize_t l = _recv_type_handle_error(c, packet, sizeof(packet), 0, T9P_TYPE_Rwalk, tag);
    if (l < 0) {
        goto error;
    }

    struct Rwalk rw;
    qid_t* qids = NULL;
    if (decode_Rwalk(&rw, packet, sizeof(packet), &qids) < 0) {
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
    int len = 0;
    if ((len = encode_Tlopen(packet, sizeof(packet), tag, h->fid, mode)) < 0) {
        ERROR(c, "%s: unable to encode Tlopen", __FUNCTION__);
        return -1;
    }

    if (_send(c, packet, len, 0, 1) < 0) {
        ERROR(c, "%s: Tlopen send failed\n", __FUNCTION__);
        return -1;
    }

    if ((len = _recv_type_handle_error(c, packet, sizeof(packet), 0, T9P_TYPE_Rlopen, tag)) < 0) {
        return -1;
    }

    struct Rlopen rl;
    if (decode_Rlopen(&rl, packet, len) < 0) {
        ERROR(c, "%s: Malformed Rlopen\n", __FUNCTION__);
        return -1;
    }

    h->qid = rl.qid;
    h->valid_mask |= T9P_HANDLE_QID_VALID;
    h->iounit = rl.iounit;

    return 0;
}

void t9p_close(t9p_handle_t handle) {
    handle->iounit = 0;
}

ssize_t t9p_read(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, void* outbuffer) {
    char packet[PACKET_BUF_SIZE];
    uint16_t tag = _mktag(c);

    int l;
    if ((l = encode_Tread(packet, sizeof(packet), tag, h->fid, offset, num)) < 0) {
        ERROR(c, "%s: could not encode Tread\n", __FUNCTION__);
        return -1;
    }

    if (_send(c, packet, l, 0, 1) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        return -1;
    }

    /** TODO: This needs a refactor */
    size_t recvSize = sizeof(struct Rread) + num;
    void* recvData = malloc(recvSize);

    ssize_t len;
    if ((len=_recv_type_handle_error(c, recvData, recvSize, 0, T9P_TYPE_Rread, tag)) < 0) {
        return -1;
    }

    struct Rread rr;
    if (decode_Rread(&rr, recvData, len) < 0) {
        ERROR(c, "%s: unable to decode Rread\n", __FUNCTION__);
        return -1;
    }

    memcpy(outbuffer, ((uint8_t*)recvData)+sizeof(struct Rread), MIN(num, rr.count));
    free(recvData);
    return MIN(num, rr.count);
}

ssize_t t9p_write(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, const void* inbuffer) {
    char packet[PACKET_BUF_SIZE];
    uint16_t tag = _mktag(c);

    int l;
    if ((l = encode_Twrite(packet, sizeof(packet), tag, h->fid, offset, num)) < 0) {
        ERROR(c, "%s: unable to encode Twrite\n", __FUNCTION__);
        return -1;
    }

    if (_send(c, packet, l, 0, 1) < 0) {
        ERROR(c, "%s: failed to send Twrite header\n", __FUNCTION__);
        return -1;
    }

    if (_send(c, inbuffer, num, 0, 1) < 0) {
        /** TODO: Tflush */
        ERROR(c, "%s: failed to send buffer\n", __FUNCTION__);
        return -1;
    }

    ssize_t len;
    if ((len=_recv_type_handle_error(c, packet, sizeof(packet), 0, T9P_TYPE_Rwrite, tag)) < 0) {
        ERROR(c, "%s: no Rwrite received\n", __FUNCTION__);
        return -1;
    }

    struct Rwrite rw;
    if (decode_Rwrite(&rw, packet, len) < 0) {
        ERROR(c, "%s: failed to decode Rwrite\n", __FUNCTION__);
        return -1;
    }

    return rw.count;
}


int t9p_getattr(t9p_context_t* c, t9p_handle_t h, struct t9p_attr* attr, uint64_t mask) {
    char packet[PACKET_BUF_SIZE];
    uint16_t tag = _mktag(c);

    int l;
    if ((l = encode_Tgetattr(packet, sizeof(packet), tag, h->fid, mask)) < 0) {
        ERROR(c, "%s: failed to encode Tgetattr\n", __FUNCTION__);
        return -1;
    }

    if (_send(c, packet, l, 0, 1) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        return -1;
    }

    ssize_t len;
    if ((len=_recv_type_handle_error(c, packet, sizeof(packet), 0, T9P_TYPE_Rgetattr, tag)) < 0) {
        ERROR(c, "%s: no Rgetattr recv'ed\n", __FUNCTION__);
        return -1;
    }

    struct Rgetattr rg;
    if (decode_Rgetattr(&rg, packet, len) < 0) {
        ERROR(c, "%s: failed to decode Rgetattr\n", __FUNCTION__);
        return -1;
    }

    O_RDONLY;

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

    if (_send(c, packet, l, 0, 1) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        return -1;
    }

    ssize_t len;
    if ((len=_recv_type_handle_error(c, packet, sizeof(packet), 0, T9P_TYPE_Rlcreate, tag)) < 0) {
        t9p_close_handle(c, h);
        return -1;
    }

    struct Rlcreate rl;
    if (decode_Rlcreate(&rl, packet, len) < 0) {
        ERROR(c, "%s: Rlcreate decode failed\n", __FUNCTION__);
        t9p_close_handle(c, h);
        return -1;
    }

    if (newhandle) {
        h->iounit = rl.iounit;
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

    if (_send(c, packet, l, 0, 1) < 0) {
        ERROR(c, "%s: send failed\n", __FUNCTION__);
        _release_handle(c, h);
        return NULL;
    }

    ssize_t len;
    if ((len=_recv_type_handle_error(c, packet, sizeof(packet), 0, T9P_TYPE_Rwalk, tag)) < 0) {
        _release_handle(c, h);
        return NULL;
    }

    struct Rwalk rw;
    qid_t* qid = NULL;
    if (decode_Rwalk(&rw, packet, len, &qid) < 0) {
        _release_handle(c, h);
        return NULL;
    }

    h->h.qid = qid[rw.nwqid-1];
    h->h.valid_mask |= T9P_HANDLE_FID_VALID | T9P_HANDLE_QID_VALID;
    return &h->h;
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

/********************** t9p_context methods **********************/

/** Alloc a new handle, locks fid table */
static struct t9p_handle_node* _alloc_handle(struct t9p_context* c) {
    pthread_mutex_lock(&c->fhl_mutex);
    struct t9p_handle_node* n = c->fhl_free;
    if (!n) {
        pthread_mutex_unlock(&c->fhl_mutex);
        return NULL;
    }
    /** Unlink from free list */
    c->fhl_free = n->next;
    n->prev = n->next = NULL;

    /** Mark used */
    n->h.valid_mask |= T9P_HANDLE_ACTIVE;

    /** Link into the active list */
    //struct t9p_handle_node* p = c->fhl_list;
    //n->next = p;
    //c->fhl_list = n;
    pthread_mutex_unlock(&c->fhl_mutex);
    return n;
}

/** Release a handle for reuse */
static void _release_handle(struct t9p_context* c, struct t9p_handle_node* h) {
    pthread_mutex_lock(&c->fhl_mutex);

    /** Clear data, but preserve fid */
    memset(&h->h.qid, 0, sizeof(h->h.qid));
    h->h.iounit = 0;
    h->h.valid_mask = 0;

    /** Unlink from active list */
    //if (h->prev)
    //    h->prev->next = h->next;
    //if (c->fhl_list == h)
    //    c->fhl_list = h->next;

    /** Link into free list */
    h->next = h->prev = NULL;
    h->next = c->fhl_free;
    c->fhl_free = h;

    pthread_mutex_unlock(&c->fhl_mutex);
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

/********************** TCP transport layer **********************/

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
        return recv(pc->sock, data, len, flags);
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

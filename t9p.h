#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default packet queue size */
#define T9P_PACKET_QUEUE_SIZE 1024

#define T9P_DEFAULT_PORT 10002

#define T9P_PATH_MAX PATH_MAX

/** Flags for Topen */
#define T9P_OREAD 0
#define T9P_OWRITE 1
#define T9P_ORDWR 2
#define T9P_OEXEC 3
#define T9P_OTRUNC 0x10
#define T9P_ORCLOSE 0x40

#define T9P_OEXCL 0x1000

/**
 * Transport flags
 */
#define T9P_RECV_PEEK 0x1           /**< Read a message, but leave it in the queue. See MSG_PEEK. Incompatible with T9P_RECV_READ */
#define T9P_RECV_READ 0x2           /**< Read part of a message and leave it in the queue. Similar to peek, except that this advances the read position.
                                         Incompatible with T9P_RECV_PEEK */
#define T9P_RECV_NOWAIT 0x4         /**< Don't block */

/**
 * Transport methods.
 */
typedef void*(*t9p_init_t)();
typedef void(*t9p_shutdown_t)(void* /*context*/);
typedef int(*t9p_connect_t)(void* /*context*/, const char* /*addr_or_file*/);
/** Disconnect method, return 0 for success */
typedef int(*t9p_disconnect_t)(void* /*context*/);
typedef ssize_t(*t9p_send_t)(void* /*context*/, const void* /*data*/, size_t /*len*/, int /*flags*/);
typedef ssize_t(*t9p_recv_t)(void* /*context*/, void* /*data*/, size_t /*len*/, int /*flags*/);

/**
 * Transport interface.
 * this abstracts out some platform specific behavior (i.e. socket creation/read/write). This must be provided by
 * users of the library.
 */
typedef struct t9p_transport {
    t9p_init_t init;
    t9p_shutdown_t shutdown;
    t9p_connect_t connect;
    t9p_disconnect_t disconnect;
    t9p_send_t send;
    t9p_recv_t recv;
} t9p_transport_t;

typedef struct t9p_context t9p_context_t;

/**< Generic handle to a t9p file, directory or symlink */
typedef struct t9p_handle* t9p_handle_t;

/**< Logging levels */
enum t9p_log {
    T9P_LOG_DEBUG = -1,
    T9P_LOG_INFO = 0,
    T9P_LOG_WARN,
    T9P_LOG_ERR,
};

typedef struct t9p_opts {
    uint32_t max_write_data_size;       /**< Max amount of data that can be transferred in a write packet */
    uint32_t max_read_data_size;        /**< Max amount of data that can be transferred in a read packet */
    uint32_t queue_size;                /**< Packet queue size. Must be power of two! */
    int log_level;                      /**< Logging level (See t9p_log enum) */
    uint32_t uid;                       /**< UID to use */
    char user[128];                     /**< Username to use. If provided, it will be used instead of uid */
    int max_fids;                       /**< Max number of open file IDs (1 will be consumed for root) */
    int send_timeo;                     /**< Send timeout, in ms */
    int recv_timeo;                     /**< Recv timeout, in ms */
} t9p_opts_t;

/**
 * \brief Init the options table with sensible defaults
 */
void t9p_opts_init(struct t9p_opts* opts);

t9p_context_t* t9p_init(t9p_transport_t* transport, const t9p_opts_t* opts, const char* apath, const char* addr, const char* mntpoint);
void t9p_shutdown(t9p_context_t* context);

t9p_handle_t t9p_open_handle(t9p_context_t* c, t9p_handle_t parent, const char* path);
void t9p_close_handle(t9p_context_t* c, t9p_handle_t h);

int t9p_open(t9p_context_t* c, t9p_handle_t h, uint32_t mode);
void t9p_close(t9p_handle_t handle);

ssize_t t9p_read(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, void* outbuffer);
ssize_t t9p_write(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, const void* inbuffer);

t9p_handle_t t9p_get_root(t9p_context_t* c);

/**
 * TCP transport layer. Returns -1 if unsupported, otherwise fills out `tp`
 */
int t9p_init_tcp_transport(t9p_transport_t* tp);

#ifdef __cplusplus
}
#endif
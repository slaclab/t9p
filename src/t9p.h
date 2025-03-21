#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "t9proto.h"

#ifdef __cplusplus
extern "C"
{
#endif

/** Default packet queue size */
#define T9P_PACKET_QUEUE_SIZE 1024

#define T9P_DEFAULT_PORT 10002

#define T9P_PATH_MAX PATH_MAX

#define T9P_NOGID (~0U)

/** Flags for Tlopen (these match Linux O_XXX bits)*/
typedef enum t9p_open_flags
{
  T9P_OREADONLY = 00000000,
  T9P_OWRITEONLY = 00000001,
  T9P_ORDWR = 00000002,
  T9P_ONOACCESS = 00000003,
  T9P_OCREATE = 00000100,
  T9P_OEXCL = 00000200,
  T9P_ONOCTTY = 00000400,
  T9P_OTRUNC = 00001000,
  T9P_OAPPEND = 00002000,
  T9P_ONONBLOCK = 00004000,
  T9P_ODSYNC = 00010000,
  T9P_OFASYNC = 00020000,
  T9P_ODIRECT = 00040000,
  T9P_OLARGEFILE = 00100000,
  T9P_ODIRECTORY = 00200000,
  T9P_ONOFOLLOW = 00400000,
  T9P_ONOATIME = 01000000,
  T9P_OCLOEXEC = 02000000,
  T9P_OSYNC = 04000000,
} t9p_open_flags_t;

/** QID types */
typedef enum t9p_qid_type
{
  T9P_QID_DIR = 0x80,    /**< Directory */
  T9P_QID_APPEND = 0x40, /**< File is append only */
  T9P_QID_EXCL = 0x20,   /**< Exclusive; only one handle at a time */
  T9P_QID_MOUNT = 0x10,  /**< Mount point */
  T9P_QID_AUTH = 0x8,    /**< Auth file */
  T9P_QID_MP = 0x4,      /**< Non-backed up file */
  T9P_QID_SYMLINK = 0x2, /**< Symbolic link */
  T9P_QID_LINK = 0x1,    /**< Hard link */
  T9P_QID_FILE = 0x0,    /**< Normal file */
} t9p_qid_type_t;

/**
 * Transport flags
 */
#define T9P_RECV_PEEK                                                                              \
  0x1 /**< Read a message, but leave it in the queue. See MSG_PEEK. Incompatible with              \
         T9P_RECV_READ */
#define T9P_RECV_READ                                                                              \
  0x2 /**< Read part of a message and leave it in the queue. Similar to peek, except that this     \
         advances the read position. Incompatible with T9P_RECV_PEEK */

/**
 * Transport methods.
 */
typedef void* (*t9p_init_t)();
typedef void (*t9p_shutdown_t)(void* /*context*/);
typedef int (*t9p_connect_t)(void* /*context*/, const char* /*addr_or_file*/);
/** Disconnect method, return 0 for success */
typedef int (*t9p_disconnect_t)(void* /*context*/);
typedef ssize_t (*t9p_send_t)(
  void* /*context*/, const void* /*data*/, size_t /*len*/, int /*flags*/
);
typedef ssize_t (*t9p_recv_t)(void* /*context*/, void* /*data*/, size_t /*len*/, int /*flags*/);

/**
 * Transport interface.
 * this abstracts out some platform specific behavior (i.e. socket creation/read/write). This must
 * be provided by users of the library.
 */
typedef struct t9p_transport
{
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
typedef enum t9p_log
{
  T9P_LOG_TRACE = -2,
  T9P_LOG_DEBUG,
  T9P_LOG_INFO = 0,
  T9P_LOG_WARN,
  T9P_LOG_ERR,
} t9p_log_t;

typedef struct t9p_opts
{
  uint32_t max_write_data_size; /**< Max amount of data that can be transferred in a write packet */
  uint32_t max_read_data_size;  /**< Max amount of data that can be transferred in a read packet */
  uint32_t queue_size;          /**< Packet queue size. Must be power of two! */
  int log_level;                /**< Logging level (See t9p_log enum) */
  uint32_t uid;                 /**< UID to use */
  char user[128];               /**< Username to use. If provided, it will be used instead of uid */
  int max_fids;                 /**< Max number of open file IDs (1 will be consumed for root) */
  int send_timeo;               /**< Send timeout, in ms */
  int recv_timeo;               /**< Recv timeout, in ms */
  uint32_t gid;                 /**< Default gid, used when NOGID is passed to functions */
} t9p_opts_t;

/** Flags for t9p_getattr */
typedef enum t9p_getattr_mask
{
  T9P_GETATTR_MODE = 0x00000001ULL,
  T9P_GETATTR_NLINK = 0x00000002ULL,
  T9P_GETATTR_UID = 0x00000004ULL,
  T9P_GETATTR_GID = 0x00000008ULL,
  T9P_GETATTR_RDEV = 0x00000010ULL,
  T9P_GETATTR_ATIME = 0x00000020ULL,
  T9P_GETATTR_MTIME = 0x00000040ULL,
  T9P_GETATTR_CTIME = 0x00000080ULL,
  T9P_GETATTR_INO = 0x00000100ULL,
  T9P_GETATTR_SIZE = 0x00000200ULL,
  T9P_GETATTR_BLOCKS = 0x00000400ULL,
  T9P_GETATTR_BTIME = 0x00000800ULL,
  T9P_GETATTR_GEN = 0x00001000ULL,
  T9P_GETATTR_DATA_VERSION = 0x00002000ULL,
  T9P_GETATTR_BASIC = 0x000007ffULL,
  T9P_GETATTR_ALL = 0x00003fffULL,
} t9p_getattr_mask_t;

/**
 * \brief File attributes, used with t9p_getattr
 */
typedef struct t9p_getattr
{
  uint32_t valid;
  qid_t qid;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint64_t nlink;
  uint64_t rdev;
  uint64_t fsize;
  uint64_t blksize;
  uint64_t blocks;
  uint64_t atime_sec;
  uint64_t atime_nsec;
  uint64_t mtime_sec;
  uint64_t mtime_nsec;
  uint64_t ctime_sec;
  uint64_t ctime_nsec;
  uint64_t btime_sec;
  uint64_t btime_nsec;
  uint64_t gen;
  uint64_t data_version;
} t9p_getattr_t;

/**
 * \brief Flags for t9p_setattr
 */
typedef enum t9p_setattr_mask
{
  T9P_SETATTR_MODE = 0x1UL,
  T9P_SETATTR_UID = 0x2UL,
  T9P_SETATTR_GID = 0x4UL,
  T9P_SETATTR_SIZE = 0x8UL,
  T9P_SETATTR_ATIME = 0x10UL,
  T9P_SETATTR_MTIME = 0x20UL,
  T9P_SETATTR_CTIME = 0x40UL,
  T9P_SETATTR_ATIME_SET = 0x80UL,
  T9P_SETATTR_MTIME_SET = 0x100UL,
} t9p_setattr_mask_t;

/**
 * \brief File attributes for t9p_setattr
 */
typedef struct t9p_setattr
{
  uint64_t valid;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint64_t size;
  uint64_t atime_sec;
  uint64_t atime_nsec;
  uint64_t mtime_sec;
  uint64_t mtime_nsec;
} t9p_setattr_t;

/**
 * \brief File system stats, used with t9p_statfs
 */
typedef struct t9p_statfs
{
  uint32_t type;
  uint32_t bsize;
  uint64_t blocks;
  uint64_t bfree;
  uint64_t bavail;
  uint64_t files;
  uint64_t ffree;
  uint64_t fsid;
  uint32_t namelen;
} t9p_statfs_t;

typedef struct t9p_dir_info
{
  struct t9p_dir_info* next;
  qid_t qid;
  uint8_t type;
  char name[];
} t9p_dir_info_t;

/**
 * Flags for use with t9p_unlinkat.
 */
typedef enum t9p_unlinkat_flags
{
  T9P_AT_REMOVEDIR = 0x200,
} t9p_unlinkat_flags_t;

/**
 * \brief Init the options table with sensible defaults
 */
void t9p_opts_init(struct t9p_opts* opts);

/**
 * Init a t9p context
 * \param transport Pointer to a transport structure, defining the transport operations
 * \param opts Pointer to options @see t9p_opts_t
 * \param apath Remote path
 * \param addr IP address of the server, with port
 * \param mntpoint Mount point
 * \returns Context pointer, or NULL if there was an error during connection
 */
t9p_context_t* t9p_init(
  t9p_transport_t* transport, const t9p_opts_t* opts, const char* apath, const char* addr,
  const char* mntpoint
);

/**
 * Shutdown a t9p context. This will clunk all fids, disconnect and shutdown transport, and free the
 * context pointer. Do not use `context` after this method is called
 * \param context Context pointer
 */
void t9p_shutdown(t9p_context_t* context);

t9p_handle_t t9p_open_handle(t9p_context_t* c, t9p_handle_t parent, const char* path);

/**
 * \brief Closes a handle
 * Unlike t9p_close, this will actually clunk the file handle allowing it to be reused for a
 * different file.
 * \param c Context
 * \param h Handle
 */
void t9p_close_handle(t9p_context_t* c, t9p_handle_t h);

/**
 * \brief Opens a file for writing
 * \param c Context
 * \param h File handle
 * \param mode Mode (i.e. T9P_OREAD, T9P_OWRITE, etc.)
 */
int t9p_open(t9p_context_t* c, t9p_handle_t h, uint32_t mode);

/**
 * \brief Closes a file handle
 * This will not clunk the fid. In reality, this does almost nothing
 */
void t9p_close(t9p_handle_t handle);

/**
 * Read data from a file handle
 * \param c Context
 * \param h File handle
 * \param offset Offset within the file, in bytes
 * \param num Number of bytes to read
 * \param outbuffer Buffer to hold the data
 * \returns Number of bytes read, or a negative error code
 */
ssize_t t9p_read(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, void* outbuffer);

/**
 * Write data to a file
 * \param c Context
 * \param h File handle
 * \param offset Offset within the file, in bytes
 * \param num Number of bytes to write
 * \param inbuffer Buffer
 * \returns Number of bytes written, or a negative error code
 */
ssize_t
t9p_write(t9p_context_t* c, t9p_handle_t h, uint64_t offset, uint32_t num, const void* inbuffer);

/**
 * Creates a new file under a directory
 * \param c Context
 * \param newhandle Output parameter to hold the new file handle. If NULL, the new fid will be
 * clunked immediately
 * \param parent Parent directory fid. NULL for root
 * \param name Name of the new file
 * \param mode Mode of the file (i.e. 0777)
 * \param gid GID of the owner (or T9P_NOGID)
 * \param flags Additional flags
 */
int t9p_create(
  t9p_context_t* c, t9p_handle_t* newhandle, t9p_handle_t parent, const char* name, uint32_t mode,
  uint32_t gid, uint32_t flags
);

/**
 * Creates a new directory under parent
 * \param c context
 * \param parent Handle to the parent directory
 * \param name Name of the new directory
 * \param mode Mode (i.e. 0777 for o+rwx/g+rwx/u+rwx)
 * \param gid GID of the owner (or T9P_NOGID)
 * \param outqid [Optional] parameter to hold the qid of the new dir
 * \return < 0 on error
 */
int t9p_mkdir(
  t9p_context_t* c, t9p_handle_t parent, const char* name, uint32_t mode, uint32_t gid,
  qid_t* outqid
);

/**
 * Perform an fsync operation on the file. The file must be open already, if not, it will error
 * \param c context
 * \param file File to fsync
 * \return < 0 on error
 */
int t9p_fsync(t9p_context_t* c, t9p_handle_t file);

/**
 * Duplicates a file handle
 * \param c Context
 * \param todup File handle to duplicated
 * \param handle Output parameter holding the parameter
 * \returns < 0 on error
 */
int t9p_dup(t9p_context_t* c, t9p_handle_t todup, t9p_handle_t* outhandle);

/**
 * Performs a getattr on the specified file handle
 * \param c Context
 * \param h File handle
 * \param attr Output buffer to hold the attr info
 * \param mask Attribute mask, @see T9P_GETATTR_XXX macros
 */
int t9p_getattr(t9p_context_t* c, t9p_handle_t h, struct t9p_getattr* attr, uint64_t mask);

/**
 * Performs a getattr on the specified file, returning the size. Shorthand for a getattr call.
 * \param c Context
 * \param h File handle
 * \returns File size, or < 0 on error
 */
ssize_t t9p_stat_size(t9p_context_t* c, t9p_handle_t h);

/**
 * Performs a statfs operation with Tstatfs/Rstatfs. Much like statfs(2) on Linux
 * \param c context
 * \param h Handle to a file on the filesystem that we want to query
 * \param statfs Result buffer to hold statfs info
 * \return < 0 on error
 */
int t9p_statfs(t9p_context_t* c, t9p_handle_t h, struct t9p_statfs* statfs);

/**
 * Reads the target of the symlink pointed to by h. If h is not a symlink, this returns error.
 * \param c Context
 * \param h Handle to the symlink
 * \param outPath Buffer to hold the symlink target
 * \param outPathSize Size of the aforementioned buffer
 * \return < 0 on error
 */
int t9p_readlink(t9p_context_t* c, t9p_handle_t h, char* outPath, size_t outPathSize);

/**
 * Creates a symlink to src at dst
 * \param c Context
 * \param dir Handle to the directory to create the symlink in
 * \param dst Name of the actual symlink
 * \param src Source of the symlink, i.e. where it points to
 * \param gid GID of the new symlink
 * \param oquid [Optional] output parameter holding the QID of the new symlink
 */
int t9p_symlink(
  t9p_context_t* c, t9p_handle_t dir, const char* dst, const char* src, uint32_t gid, qid_t* oqid
);

/**
 * Gets a list of all files in a directory
 * \param c Context
 * \param dir Handle of the directory. This must be opened with at least O_READ with t9p_open!
 * \param dirs Output pointer holding a linked list of directories. Free with t9p_free_dirs @see
 * t9p_dir_info_t
 * \return < 0 on error
 */
int t9p_readdir(t9p_context_t* c, t9p_handle_t dir, t9p_dir_info_t** dirs);

/**
 * \brief Frees a list of directories returned by t9p_readdir
 */
void t9p_free_dirs(t9p_dir_info_t* head);

/**
 * Unlinks a file or directory.
 * According to diod's docs, if the server returns -ENOTSUPP you should fallback to
 * the more widely supported Tremove.
 * \param c Context
 * \param dir Parent directory containing the file/directory
 * \param file File/directory to unlink
 * \param flags Flags. @see t9p_unlinkat_flags
 * \returns < 0 on error
 */
int t9p_unlinkat(t9p_context_t* c, t9p_handle_t dir, const char* file, uint32_t flags);

/**
 * Renames a file or directory
 * Similar to unlinkat, if this returns -ENOTSUPP, use the other rename call instead
 * \param c Context
 * \param olddirfid Old directory's FID
 * \param oldname Old file name
 * \param newdirfid New directory's FID
 * \param newname New file's name
 * \returns < 0 on error
 */
int t9p_renameat(
  t9p_context_t* c, t9p_handle_t olddirfid, const char* oldname, t9p_handle_t newdirfid,
  const char* newname
);

/**
 * Returns the file handle associated with the root
 * \param c Context
 */
t9p_handle_t t9p_get_root(t9p_context_t* c);

/**
 * Returns the IO size for an opened handle. If it's not opened, or the handle is invalid, then this
 * will return 0
 * \param h A valid file handle
 */
uint32_t t9p_get_iounit(t9p_handle_t h);

/**
 * Returns the QID of the opened handle
 * \param h A valid file handle
 */
qid_t t9p_get_qid(t9p_handle_t h);

/**
 * Remove the object referred to by fid, and clunk fid.
 * This will *always* clunk the fid pointed to by h, even if the remove fails on the server
 * \param c Context
 * \param h File handle. After this operation, this handle will be clunked
 */
int t9p_remove(t9p_context_t* c, t9p_handle_t h);

/**
 * Set file attributes
 * \param c Context
 * \param h File handle to set attributes on
 * \param mask File attributes mask @see t9p_setattr_mask
 * \param attr Attributes to set @see t9p_setattr
 * \returns < 0 on error
 */
int t9p_setattr(t9p_context_t* c, t9p_handle_t h, uint32_t mask, const struct t9p_setattr* attr);

/**
 * Performs a truncate operation on the file. This is functionally similar to ftruncate(2)
 * This expands to a setattr call. Fails if h is NOT a file!
 * \param c Context
 * \param h File handle to truncate (does not need to be open?)
 * \param size Size, in bytes, to truncate at
 * \returns < 0 on error
 */
int t9p_truncate(t9p_context_t* c, t9p_handle_t h, uint64_t size);

/**
 * Performs a chown operation on the handle.
 * This expands to a setattr call
 * \param c Context
 * \param h File handle
 * \param uid user ID to own the handle. If T9P_NOUID is supplied, we skip the uid chown
 * \param gid group ID to own the handle. If T9P_NOGID is supplied, we skip the gid chown
 * \returns < 0 on error
 */
int t9p_chown(t9p_context_t* c, t9p_handle_t h, uint32_t uid, uint32_t gid);

/**
 * Sets the modification time of the handle to the current time on the server.
 * Same as running `touch myfile` on the server.
 * This expands to a setattr call
 * \param c Context
 * \param h File handle
 * \param mtime If set to 1, we set mtime
 * \param atime If set to 1, we set atime
 * \param ctime If set to 1, we set ctime
 * \returns < 0 on error
 */
int t9p_touch(t9p_context_t* c, t9p_handle_t h, int mtime, int atime, int ctime);

/**
 * Performs a chmod operation on the handle.
 * This expands to a setattr call with the mode mask. @see t9p_setattr
 * \param c Context
 * \param h Handle
 * \param mode Linux mode bits (i.e. 0777)
 * \returns < 0 on error
 */
int t9p_chmod(t9p_context_t* c, t9p_handle_t h, mode_t mode);

/** Returns TRUE if open for I/O, FALSE otherwise */
int t9p_is_open(t9p_handle_t h);

/** Returns TRUE if the handle is valid, FALSE otherwise */
int t9p_is_valid(t9p_handle_t h);

/** Returns TRUE if the handle is a directory, FALSE otherwise */
int t9p_is_dir(t9p_handle_t h);

/** Returns TRUE if the handle is a file, FALSE otherwise */
static inline int
t9p_is_file(t9p_handle_t h)
{
  return !t9p_is_dir(h);
}

/** Returns TRUE if the handle is a symlink, FALSE otherwise */
static inline int
t9p_is_symlink(t9p_handle_t h)
{
  return !!(t9p_get_qid(h).type == T9P_QID_SYMLINK);
}

/** Returns TRUE if the handle is a hard link, FALSE otherwise */
static inline int
t9p_is_link(t9p_handle_t h)
{
  return !!(t9p_get_qid(h).type == T9P_QID_LINK);
}

/**
 * TCP transport layer. Returns -1 if unsupported, otherwise fills out `tp`
 */
int t9p_init_tcp_transport(t9p_transport_t* tp);

/**
 * \brief Sets the current log level of the context
 * \param c Context
 * \param level Logging level
 */
void t9p_set_log_level(t9p_context_t* c, t9p_log_t level);

/**
 * \brief Gets the current log level of the conext
 */
int t9p_get_log_level(t9p_context_t* c);

/**
 * \brief Utility function to return the parent of the directory.
 * This only operates on a string, and it effectively strips the last chunk after the last pathsep
 */
void t9p_get_parent_dir(const char* file_or_dir, char* outbuf, size_t outsize);

void t9p_get_basename(const char* file_or_dir, char* outbuf, size_t outsize);

#ifdef __cplusplus
}
#endif

#define _T9P_NO_POSIX_MQ
#include "t9p_rtems.h"
#include "t9p.h"
#include "t9p_platform.h"

#include <rtems.h>
#include <rtems/libio.h>
#include <rtems/libio_.h>
#include <stdlib.h>
#include <inttypes.h>
#if __RTEMS_MAJOR__ < 5
#include <rtems/posix/mutex.h>
#endif

#if __RTEMS_MAJOR__ >= 6
#include <rtems/thread.h>
#endif

#ifdef HAVE_CEXPSH
#include <cexpsh.h>
#endif

#include "t9p_posix.c"

//#define DO_TRACE
#ifdef DO_TRACE
#define TRACE(...) do { \
  printf("%s(", __FUNCTION__); \
  printf(__VA_ARGS__); \
  printf(")\n"); \
} while(0);
#else
#define TRACE(...)
#endif

typedef struct t9p_rtems_ctx_node {
  struct t9p_rtems_ctx_node* next;
  struct t9p_context* c;
  char* apath;
  char* mntpt;
  char* ip;
} t9p_rtems_ctx_node_t;

static mutex_t* s_ctx_mutex;
static t9p_rtems_ctx_node_t* s_ctxts = NULL; 

/**************************************************************************************
 * File System Operations
 **************************************************************************************/

static int t9p_rtems_fsmount_me(rtems_filesystem_mount_table_entry_t* mt_entry, const void* data);

/** RTEMS 6+ Prototypes */
#if __RTEMS_MAJOR__ >= 6

static void t9p_rtems_fs_unmountme(rtems_filesystem_mount_table_entry_t* mt_entry);

static void t9p_rtems_fs_freenode(const rtems_filesystem_location_info_t* loc);

static void t9p_rtems_fs_evalpath(rtems_filesystem_eval_path_context_t* ctx);

static int t9p_rtems_fs_symlink(
  const rtems_filesystem_location_info_t* parentloc,
  const char* name,
  size_t namelen,
  const char* target
);

static long t9p_rtems_fs_readlink(
  const rtems_filesystem_location_info_t* loc,
  char* buf,
  size_t bufsize
);

static void t9p_rtems_fs_lock(const rtems_filesystem_mount_table_entry_t* mt_entry);
static void t9p_rtems_fs_unlock(const rtems_filesystem_mount_table_entry_t* mt_entry);

static int t9p_rtems_fs_rename(
  const rtems_filesystem_location_info_t*,
  const rtems_filesystem_location_info_t*,
  const rtems_filesystem_location_info_t*,
  const char*,
  size_t
);

static int t9p_rtems_fs_link(
  const rtems_filesystem_location_info_t*,
  const rtems_filesystem_location_info_t*,
  const char*,
  size_t
);

static int t9p_rtems_fs_mknod(
  const rtems_filesystem_location_info_t* parentloc,
  const char* name,
  size_t namelen,
  mode_t mode,
  dev_t dev
);

static int t9p_rtems_fs_chown(
  const rtems_filesystem_location_info_t* loc,
  uid_t owner,
  gid_t group
);

static int t9p_rtems_fs_utimens(
  const rtems_filesystem_location_info_t* loc,
  struct timespec times[2]
);

#else

static int t9p_rtems_fs_unmountme(rtems_filesystem_mount_table_entry_t* mt_entry);

static int t9p_rtems_fs_freenode(rtems_filesystem_location_info_t* loc);

static int t9p_rtems_fs_symlink(
  rtems_filesystem_location_info_t* parentloc,
  const char *link_name,
  const char *node_name
);

static int t9p_rtems_fs_readlink(
  rtems_filesystem_location_info_t* loc,
  char* buf,
  size_t bufsize
);

static void t9p_rtems_fs_lock(const rtems_filesystem_mount_table_entry_t* mt_entry);
static void t9p_rtems_fs_unlock(const rtems_filesystem_mount_table_entry_t* mt_entry);

static int t9p_rtems_fs_rename(
  rtems_filesystem_location_info_t *old_parent_loc,
  rtems_filesystem_location_info_t *old_loc,
  rtems_filesystem_location_info_t *new_parent_loc, const char *name
);

static int t9p_rtems_fs_link(
  rtems_filesystem_location_info_t *to_loc,
  rtems_filesystem_location_info_t *parent_loc,
  const char *name
);

static int t9p_rtems_fs_mknod(
  const char *path,
  mode_t mode,
  dev_t dev,
  rtems_filesystem_location_info_t* pathloc
);

static int t9p_rtems_fs_chown(
  rtems_filesystem_location_info_t* loc,
  uid_t owner,
  gid_t group
);

static int t9p_rtems_fs_utimens(
  rtems_filesystem_location_info_t* loc,
  time_t atime,
  time_t mtime
);

static int t9p_rtems_fs_eval_link(
  rtems_filesystem_location_info_t *pathloc,
  int flags
);

static int t9p_rtems_fs_evalpath(
  const char *pathname,
  size_t pathnamelen,
  int flags,
  rtems_filesystem_location_info_t *pathloc
);

static int t9p_rtems_fs_eval_for_make(
  const char                       *path,
  rtems_filesystem_location_info_t *pathloc,
  const char                      **name
);

static int t9p_rtems_fs_node_type(
  rtems_filesystem_location_info_t *pathloc
);

#endif // RTEMS_MAJOR >= 6

static int t9p_rtems_fs_mount(rtems_filesystem_mount_table_entry_t* mt_entry);
static int t9p_rtems_fs_unmount(rtems_filesystem_mount_table_entry_t* mt_entry);
static int t9p_rtems_fs_rmnod(
  const rtems_filesystem_location_info_t* parentloc, const rtems_filesystem_location_info_t* loc
);
static bool t9p_rtems_fs_are_nodes_equal(
  const rtems_filesystem_location_info_t* a, const rtems_filesystem_location_info_t* b
);
static int t9p_rtems_fs_clonenode(rtems_filesystem_location_info_t* loc);
static int t9p_rtems_fs_fchmod(const rtems_filesystem_location_info_t* loc, mode_t mode);

static const struct _rtems_filesystem_operations_table t9p_fs_ops = {
  .link_h = t9p_rtems_fs_link,                       /*rtems_filesystem_link_t*/
  .mknod_h = t9p_rtems_fs_mknod,                     /*rtems_filesystem_mknod_t*/
  .chown_h = t9p_rtems_fs_chown,                     /*rtems_filesystem_chown_t*/
  .freenod_h = t9p_rtems_fs_freenode,                /*rtems_filesystem_freenode_t*/
  .mount_h = t9p_rtems_fs_mount,                     /*rtems_filesystem_mount_t*/
  .unmount_h = t9p_rtems_fs_unmount,                 /*rtems_filesystem_unmount_t*/
  .fsunmount_me_h = t9p_rtems_fs_unmountme,          /*rtems_filesystem_fsunmount_me_t*/
  .symlink_h = t9p_rtems_fs_symlink,                 /*rtems_filesystem_symlink_t*/
  .readlink_h = t9p_rtems_fs_readlink,               /*rtems_filesystem_readlink_t*/
  .rename_h = t9p_rtems_fs_rename,                   /*rtems_filesystem_rename_t*/
  .statvfs_h = NULL,                                 /*rtems_filesystem_statvfs_t*/
#if __RTEMS_MAJOR__ >= 6
  .are_nodes_equal_h = t9p_rtems_fs_are_nodes_equal, /*rtems_filesystem_are_nodes_equal_t*/
  .fchmod_h = t9p_rtems_fs_fchmod,                   /*rtems_filesystem_fchmod_t*/
  .clonenod_h = t9p_rtems_fs_clonenode,              /*rtems_filesystem_clonenode_t*/
  .rmnod_h = t9p_rtems_fs_rmnod,                     /*rtems_filesystem_rmnod_t*/
  .lock_h = t9p_rtems_fs_lock,                       /*rtems_filesystem_mt_entry_lock_t*/
  .unlock_h = t9p_rtems_fs_unlock,                   /*rtems_filesystem_mt_entry_unlock_t*/
  .eval_path_h = t9p_rtems_fs_evalpath,              /*rtems_filesystem_eval_path_t*/
  .utimens_h = t9p_rtems_fs_utimens,                /*rtems_filesystem_utimens_t*/
#else
  .evalpath_h = t9p_rtems_fs_evalpath,              /*rtems_filesystem_eval_path_t*/
  .evalformake_h = t9p_rtems_fs_eval_for_make,
  .utime_h = t9p_rtems_fs_utimens,
  .node_type_h = t9p_rtems_fs_node_type,
#endif
};

static const rtems_filesystem_limits_and_options_t t9p_fs_opts = {
  .link_max = 128,               /* count */
  .max_canon = 1024,             /* max formatted input line size */
  .max_input = 1024,             /* max input line size */
  .name_max = 1024,              /* max name length */
  .path_max = 1024,              /* max path */
  .pipe_buf = 4096,              /* pipe buffer size */
  .posix_async_io = 0,           /* async IO supported on fs, 0=no, 1=yes */
  .posix_chown_restrictions = 1, /* can chown: 0=no, 1=yes */
  .posix_no_trunc = 1,           /* error on names > max name, 0=no, 1=yes */
  .posix_prio_io = 0,            /* priority IO, 0=no, 1=yes */
  .posix_sync_io = 1,            /* file can be sync'ed, 0=no, 1=yes */
  .posix_vdisable = 0,           /* special char processing, 0=no, 1=yes */
};

typedef struct t9p_rtems_node
{
  t9p_context_t* c;
  t9p_handle_t h;
  ssize_t size;
} t9p_rtems_node_t;

typedef struct t9p_rtems_fs_info
{
  t9p_context_t* c;
  t9p_rtems_mount_opts_t opts;
  pthread_mutex_t mutex;
  pthread_mutexattr_t mutattr;
  char mntpt[PATH_MAX];
} t9p_rtems_fs_info_t;

/**************************************************************************************
 * File Operations
 *************************************************************************************/

static int t9p_rtems_file_close(rtems_libio_t* iop);
static ssize_t t9p_rtems_file_read(rtems_libio_t* iop, void* buffer, size_t count);
static ssize_t t9p_rtems_file_write(rtems_libio_t* iop, const void* buffer, size_t count);
static off_t t9p_rtems_file_lseek(rtems_libio_t* iop, off_t offset, int whence);
#if __RTEMS_MAJOR__ >= 6
static int t9p_rtems_file_fstat(const rtems_filesystem_location_info_t* loc, struct stat* buf);
static int t9p_rtems_file_open(rtems_libio_t* iop, const char* path, int oflag, mode_t mode);
#else
static int t9p_rtems_file_fstat(rtems_filesystem_location_info_t* loc, struct stat* buf);
static int t9p_rtems_file_open(rtems_libio_t* iop, const char* path, uint32_t oflag, mode_t mode);
static int t9p_rtems_file_fcntl(int p, rtems_libio_t* iop);
static int t9p_rtems_file_rmnod(rtems_filesystem_location_info_t *parent_loc,
  rtems_filesystem_location_info_t *pathloc);
static int t9p_rtems_file_fchmod(rtems_filesystem_location_info_t *pathloc, mode_t mode);
static int t9p_rtems_file_fpathconf(rtems_libio_t *pathloc, int mode);
#endif
static int t9p_rtems_file_ftruncate(rtems_libio_t* iop, off_t length);
static int t9p_rtems_file_fsync(rtems_libio_t* iop);
static int t9p_rtems_file_ioctl(rtems_libio_t* iop, unsigned long req, void* buffer);

static const rtems_filesystem_file_handlers_r t9p_file_ops = {
  .open_h = t9p_rtems_file_open,           /*rtems_filesystem_open_t */
  .close_h = t9p_rtems_file_close,         /*rtems_filesystem_close_t */
  .read_h = t9p_rtems_file_read,           /*rtems_filesystem_read_t */
  .write_h = t9p_rtems_file_write,         /*rtems_filesystem_write_t */
  .ioctl_h = t9p_rtems_file_ioctl,         /*rtems_filesystem_ioctl_t */
  .lseek_h = t9p_rtems_file_lseek,         /*rtems_filesystem_lseek_t */
  .fstat_h = t9p_rtems_file_fstat,         /*rtems_filesystem_fstat_t */
  .ftruncate_h = t9p_rtems_file_ftruncate, /*rtems_filesystem_ftruncate_t */
  .fsync_h = t9p_rtems_file_fsync,         /*rtems_filesystem_fsync_t */
  .fdatasync_h = t9p_rtems_file_fsync,     /*rtems_filesystem_fdatasync_t */
#if __RTEMS_MAJOR__ >= 6
  .fcntl_h = rtems_filesystem_default_fcntl,
  .poll_h = rtems_filesystem_default_poll,
  .kqfilter_h = rtems_filesystem_default_kqfilter,
  .readv_h = rtems_filesystem_default_readv,
  .writev_h = rtems_filesystem_default_writev,
  .mmap_h = rtems_filesystem_default_mmap,
#else
  .fcntl_h = t9p_rtems_file_fcntl,
  .rmnod_h = t9p_rtems_file_rmnod,
  .fchmod_h = t9p_rtems_file_fchmod,
  .fpathconf_h = t9p_rtems_file_fpathconf,
#endif
};

static ssize_t t9p_rtems_dir_read(rtems_libio_t* iop, void* buffer, size_t count);
static int t9p_rtems_dir_fstat(const rtems_filesystem_location_info_t* loc, struct stat* buf);
#if __RTEMS_MAJOR__ >= 6
static int t9p_rtems_dir_open(rtems_libio_t* iop, const char* path, int oflag, mode_t mode);
#else
static int t9p_rtems_dir_open(rtems_libio_t* iop, const char* path, uint32_t oflag, mode_t mode);
#endif

static const rtems_filesystem_file_handlers_r t9p_dir_ops = {
  .open_h = t9p_rtems_dir_open,
  .read_h = t9p_rtems_dir_read,
  .ioctl_h = t9p_rtems_file_ioctl,
  .fstat_h = t9p_rtems_file_fstat,
#if __RTEMS_MAJOR__ >= 6
  .write_h = rtems_filesystem_default_write,
  .lseek_h = rtems_filesystem_default_lseek_directory,
  .close_h = rtems_filesystem_default_close,
  .ftruncate_h = rtems_filesystem_default_ftruncate_directory,
  .fsync_h = rtems_filesystem_default_fsync_or_fdatasync_success,
  .fdatasync_h = rtems_filesystem_default_fsync_or_fdatasync_success,
  .fcntl_h = rtems_filesystem_default_fcntl,
  .poll_h = rtems_filesystem_default_poll,
  .kqfilter_h = rtems_filesystem_default_kqfilter,
  .readv_h = rtems_filesystem_default_readv,
  .writev_h = rtems_filesystem_default_writev,
  .mmap_h = rtems_filesystem_default_mmap,
#else
  /** Default the rest to NULL */
#endif
};

/**************************************************************************************
 * Public API
 **************************************************************************************/

int
t9p_rtems_register(void)
{
  s_ctx_mutex = mutex_create();
  return rtems_filesystem_register(RTEMS_FILESYSTEM_TYPE_9P, t9p_rtems_fsmount_me);
}

/** For Cexpsh
  * Roughly match the nfsMount syntax: p9Mount(uid_gid_at_host, server_path, mntpt)
  * USAGE:
  * p9Mount("16626.2211@134.79.217.70", "/scratch/lorelli/dummy-diod-fs", "/test")
  */
int
p9Mount(const char* ip, const char* srvpath, const char* mntpt)
{
  char opts[128];
  *opts = 0;

  const char* p = strpbrk(ip, "@");
  if (p) {
    char uid[32], gid[32];
    sscanf(ip, "%[^.].%[^@]%*s", uid, gid);
    snprintf(opts, sizeof(opts), "uid=%s,gid=%s", uid, gid);
  }

  /** Ensure the mount point actually exists */
  struct stat st;
  if (stat(mntpt, &st) < 0) {
    if (mkdir(mntpt, 0777) < 0) {
      printf("Unable to create %s: %s\n", mntpt, strerror(errno));
      return -1;
    }
  }

  printf("Mounting %s at %s with opts '%s'\n", srvpath, mntpt, opts);

  char mnt[512];
  snprintf(mnt, sizeof(mnt), "%s:%s", p+1, srvpath);
  printf("mnt=%s, mtpt=%s\n", mnt, mntpt);

  int r = mount(mnt, mntpt, RTEMS_FILESYSTEM_TYPE_9P, 0, opts);
  if (r < 0) {
    perror("Mount failed");
    return -1;
  }
  return 0;
}

#ifdef HAVE_CEXP
CEXP_HELP_TAB_BEGIN(p9Mount)
	HELP(
"Mount a 9P file system.\n"
"Paramters:\n"
" ip - String in the format [UID.GID@]IP[:PORT], where\n"
"      UID is the user ID number, GID is the GID number.\n"
"      Port is optional and defaults to 10002\n",
" srvpath - Path to the export on the server.\n"
"           Sometimes called 'apath' in 9P-speak\n",
" mntpt - Mount point locally. Will be created with 0777 perms\n"
"         if it does not exist already\n"
	int, p9Mount,  (const char* ip, const char* srvpath, const char* mntpt)
	),
CEXP_HELP_TAB_END
#endif

int
p9Stats()
{
  mutex_lock(s_ctx_mutex);
  int n = 0;
  for (t9p_rtems_ctx_node_t* c = s_ctxts; c; c = c->next, n++) {
    t9p_opts_t opts = t9p_get_opts(c->c);
    t9p_stats_t stats = t9p_get_stats(c->c);
    printf("%s\n", c->ip);
    printf("  apath=%s,mntpt=%s,uid=%d,gid=%d\n", c->apath, c->mntpt,
      (int)opts.uid, (int)opts.gid);
    printf("   bytesSend=%u bytesRecv=%u\n", (unsigned)stats.total_bytes_recv,
      (unsigned)stats.total_bytes_recv);
    printf("   sendCnt=%u, sendErrCnt=%u\n", (unsigned)stats.send_cnt,
      (unsigned)stats.send_errs);
    printf("   recvCnt=%u, recvErrCnt=%u\n\n", (unsigned)stats.recv_cnt,
    (unsigned)stats.recv_errs);
  }
  mutex_unlock(s_ctx_mutex);

  printf("\n%d total 9P mounts\n", n);
  return 0;
}

#ifdef HAVE_CEXP
CEXP_HELP_TAB_BEGIN(p9Stats)
	HELP(
"Display stats about all 9P mounts\n"
	int, p9Stats,  ()
	),
CEXP_HELP_TAB_END
#endif

#define WR_FLAGS (S_IWUSR | S_IWGRP | S_IWOTH)
#define RD_FLAGS (S_IRUSR | S_IRGRP | S_IROTH)
#define EX_FLAGS (S_IXUSR | S_IXGRP | S_IXOTH)

static int
rtems_mode_to_t9p(mode_t mode)
{
  int m = 0;

  if ((mode & WR_FLAGS) && (mode & RD_FLAGS))
    m = T9P_ORDWR;
  else if (mode & WR_FLAGS)
    m = T9P_OWRITEONLY;
  else if (mode & RD_FLAGS)
    m = T9P_OREADONLY;
  else
    m = T9P_ONOACCESS;
  return m;
}

static int
min(int x, int y)
{
  return x < y ? x : y;
}

/**************************************************************************************
 * FS ops implementation
 **************************************************************************************/

static t9p_rtems_node_t*
t9p_rtems_fs_get_node(const rtems_filesystem_location_info_t* loc)
{
  return loc->node_access;
}

static t9p_rtems_node_t*
t9p_rtems_iop_get_node(const rtems_libio_t* iop)
{
  return iop->pathinfo.node_access;
}

static t9p_context_t*
t9p_rtems_iop_get_ctx(const rtems_libio_t* iop)
{
  return ((t9p_rtems_fs_info_t*)iop->pathinfo.mt_entry->fs_info)->c;
}

static t9p_rtems_node_t*
t9p_rtems_iop_clone_node(const t9p_rtems_node_t* old, int dupFid)
{
  t9p_rtems_node_t* n = calloc(sizeof(t9p_rtems_node_t), 1);
  *n = *old;

  /** Duplicate fid too */
  if (dupFid) {
    if (t9p_dup(n->c, old->h, &n->h) < 0) {
      free(n);
      return NULL;
    }
    n->size = -1;
  }

  return n;
}

static int
t9p_rtems_fsmount_me(rtems_filesystem_mount_table_entry_t* mt_entry, const void* data)
{
  TRACE("mt_entry=%p, data=%p", mt_entry, data);
  if (!data) {
    errno = EINVAL;
    return -1;
  }

  char buf[1024];
  buf[0] = 0;
  if (data)
    strncpy(buf, (const char*)data, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;

  char* apath = mt_entry->dev;
  char ip[128] = {0};
  char user[128] = {0};
  char path[256] = {0};
  int port = 10002, uid = T9P_NOUID, gid = T9P_NOGID;

  /** Parse source (in format IP:[PORT:]/path/on/server) */
  char* sip = strtok(mt_entry->dev, ":");
  if (sip)
    strcpy(ip, sip);

  /** Next will be port or apath */
  char* sportOrPath = strtok(NULL, ":");
  if (sportOrPath && *sportOrPath != '/') {
    port = atoi(sportOrPath);
    apath = strtok(NULL, ":");
  } else {
    apath = sportOrPath;
  }

  /** No apath is invalid */
  if (!apath) {
    printf("No apath provided, mount must be in format IP:[PORT:]/path/on/server\n");
    errno = EINVAL;
    return -1;
  }

  for (char* r = strtok(buf, ","); r; r = strtok(NULL, ",")) {
    if (!strncmp(r, "port", strlen("port"))) {
      const char* p = strpbrk(r, "=");
      if (p)
        port = atoi(p + 1);
    } else if (!strncmp(r, "ip", strlen("ip"))) {
      const char* p = strpbrk(r, "=");
      if (p)
        strcpy(ip, p + 1);
    } else if (!strncmp(r, "uid", strlen("uid"))) {
      const char* p = strpbrk(r, "=");
      if (p)
        uid = atoi(p + 1);
    } else if (!strncmp(r, "gid", strlen("gid"))) {
      const char* p = strpbrk(r, "=");
      if (p)
        gid = atoi(p + 1);
    } else if (!strncmp(r, "user", strlen("user"))) {
      const char* p = strpbrk(r, "=");
      if (p)
        strcpy(user, p + 1);
    }
  }

#if __RTEMS_MAJOR__ >= 6
  mt_entry->ops = &t9p_fs_ops;
  mt_entry->pathconf_limits_and_options = &t9p_fs_opts;
#else
  mt_entry->mt_fs_root.ops = &t9p_fs_ops;
  mt_entry->pathconf_limits_and_options = t9p_fs_opts;
#endif
  /** Configure FS info and opts */
  mt_entry->fs_info = calloc(sizeof(t9p_rtems_fs_info_t), 1);
  t9p_rtems_fs_info_t* fi = mt_entry->fs_info;

  pthread_mutexattr_init(&fi->mutattr);
  pthread_mutexattr_settype(&fi->mutattr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&fi->mutex, &fi->mutattr);
  
  t9p_opts_init(&fi->opts.opts);
  fi->opts.opts.gid = gid;
  fi->opts.opts.uid = uid;
  fi->opts.transport = T9P_RTEMS_TRANS_TCP;
  fi->opts.opts.log_level = T9P_LOG_DEBUG;
  strcpy(fi->opts.ip, ip);
  strcpy(fi->opts.opts.user, user);

  /** Init the 9p FS */
  t9p_transport_t t;

  switch (fi->opts.transport) {
  case T9P_RTEMS_TRANS_TCP:
    if (t9p_init_tcp_transport(&t) < 0) {
      errno = EPROTO;
      return -1;
    }
    break;
  default:
    errno = EINVAL;
    return -1;
  }

  printf("target=%s, ip=%s, apath=%s\n", mt_entry->target, ip, apath);

  fi->c = t9p_init(&t, &fi->opts.opts, apath, ip, mt_entry->target);
  if (fi->c == NULL)
    return -1;

  printf("Mounted 9P %s:%s at %s\n", ip, apath, mt_entry->target);

  /** Global list, just for debugging ... */
  mutex_lock(s_ctx_mutex);
  t9p_rtems_ctx_node_t* cn = calloc(1, sizeof(t9p_rtems_ctx_node_t));
  cn->next = s_ctxts;
  cn->c = fi->c;
  cn->apath = strdup(apath);
  cn->mntpt = strdup(mt_entry->target);
  cn->ip = strdup(ip);
  s_ctxts = cn;
  mutex_unlock(s_ctx_mutex);

  /** Setup root node info */
  t9p_rtems_node_t* root = calloc(sizeof(t9p_rtems_node_t), 1);
  root->c = fi->c;
  root->size = -1;
  root->h = t9p_get_root(fi->c);
#if __RTEMS_MAJOR__ >= 6
  mt_entry->mt_fs_root->location.node_access = root;
  mt_entry->mt_fs_root->location.handlers = &t9p_dir_ops;
  mt_entry->mt_fs_root->reference_count++;
#else
  mt_entry->mt_fs_root.node_access = root;
  mt_entry->mt_fs_root.handlers = &t9p_dir_ops;
  mt_entry->mt_fs_root.ops = &t9p_fs_ops;
  //mt_entry->mt_fs_root->reference_count++; // FIXME:???
#endif
  return 0;
}

#if __RTEMS_MAJOR__ >= 6
static void
t9p_rtems_fs_unmountme(rtems_filesystem_mount_table_entry_t* mt_entry)
#else
static int
t9p_rtems_fs_unmountme(rtems_filesystem_mount_table_entry_t* mt_entry)
#endif
{
  TRACE("mt_entry=%p", mt_entry);
  t9p_rtems_fs_info_t* fi = mt_entry->fs_info;

  /** Remove from context list */
  mutex_lock(s_ctx_mutex);
  for (t9p_rtems_ctx_node_t* c = s_ctxts, *p = NULL; c; c = c->next) {
    if (c->c != fi->c) {
      p = c;
     continue;
    }

    free(c->ip);
    free(c->apath);
    free(c->mntpt);
    if (p)
      p->next = c->next;
    free(c);
    break;
  }
  mutex_unlock(s_ctx_mutex);

  pthread_mutex_destroy(&fi->mutex);
  pthread_mutexattr_destroy(&fi->mutattr);
  t9p_shutdown(fi->c);
}

static void
t9p_rtems_fs_lock(const rtems_filesystem_mount_table_entry_t* mt_entry)
{
  TRACE("mt_entry=%p", mt_entry);
  t9p_rtems_fs_info_t* fi = mt_entry->fs_info;
  pthread_mutex_lock(&fi->mutex);
}

static void
t9p_rtems_fs_unlock(const rtems_filesystem_mount_table_entry_t* mt_entry)
{
  TRACE("mt_entry=%p", mt_entry);
  t9p_rtems_fs_info_t* fi = mt_entry->fs_info;
  pthread_mutex_unlock(&fi->mutex);
}

#if __RTEMS_MAJOR__ >= 6
/**
 * Transform a path into its final form based on the root node, starting node and a path string
 * describing the new location.
 * 9P lets us do this trivially with Twalk/Rwalk
 */
static void
t9p_rtems_fs_evalpath(rtems_filesystem_eval_path_context_t* ctx)
{
  TRACE("ctx=%p", ctx);
  rtems_filesystem_location_info_t* current = rtems_filesystem_eval_path_get_currentloc(ctx);

  t9p_rtems_node_t* n = current->node_access;

  /** Attempt the open the new location with the current as parent */
  t9p_handle_t h = t9p_open_handle(n->c, n->h, ctx->path);
  if (h == NULL) {
    rtems_filesystem_eval_path_error(ctx, -1);
    return;
  }

  /** Create a new node for the new location. We're supposed to reuse currentloc here. */
  t9p_rtems_node_t* e = calloc(sizeof(t9p_rtems_node_t), 1);
  current->node_access = e;
  e->c = n->c;
  e->h = h;
  e->size = -1;

  /** Configure handlers */
  if (t9p_is_dir(h)) {
    current->handlers = &t9p_dir_ops;
  } else {
    current->handlers = &t9p_file_ops;
  }

  rtems_filesystem_eval_path_clear_path(ctx);
}
#endif

#if __RTEMS_MAJOR__ <= 4

static int
t9p_rtems_fs_eval_link(
  rtems_filesystem_location_info_t *pathloc,
  int flags
)
{
  TRACE("pathloc=%p, flags=%d", pathloc, flags);
}

/**
 * TODO: RTEMS4:
 *  - Handle special case where RTEMS may do path/to/file.xyz/.. to get the parent dir
 */

/**
 * Evalpath notes
 * - When entering eval path, clone the node
 */

static int
t9p_rtems_fs_evalpath(
  const char *pathname,
  size_t pathnamelen,
  int flags,
  rtems_filesystem_location_info_t *pathloc
)
{
  TRACE("pathname=%s,pathnamelen=%zu,flags=%d,pathloc=%p", pathname, pathnamelen,
    flags, pathloc);

  if (!rtems_libio_is_valid_perms(flags)) {
    TRACE("E: EIO");
    errno = EIO;
    return -1;
  }

  t9p_rtems_node_t* p = t9p_rtems_iop_clone_node(pathloc->node_access, 0);
  pathloc->node_access = p;

  /** Strip mount point from the start of the path... */
  const size_t tl = strlen(pathloc->mt_entry->target);
  if (!strncmp(pathloc->mt_entry->target, pathname, tl)) {
    pathname += tl;
    if (*pathname == '/')
      pathname++;
  }

  t9p_handle_t nh = t9p_open_handle(p->c, p->h, pathname);
  if (nh == NULL) {
    TRACE("E: ENOENT");
    errno = ENOENT;
    return -1;
  }

  p->h = nh;
  p->size = -1;

  pathloc->ops = &t9p_fs_ops;
  if (t9p_is_dir(p->h)) {
    pathloc->handlers = &t9p_dir_ops;
    TRACE("handlers=dir_ops");
  }
  else {
    pathloc->handlers = &t9p_file_ops;
    TRACE("handlers=file_ops");
  }

  return 0;
}

static int
t9p_rtems_fs_eval_for_make(
  const char                       *path,
  rtems_filesystem_location_info_t *pathloc,
  const char                      **name
)
{
  TRACE("path=%s, pathloc=%p, name=%p", path, pathloc, name);
  int r;
  *name = strrchr(path, '/');
  if (!*name)
    *name = path;

  t9p_rtems_node_t* nn = t9p_rtems_iop_clone_node(pathloc->node_access, 0);
  pathloc->node_access = nn;

  t9p_handle_t h = t9p_open_handle(nn->c, nn->h, path);
  if (h == NULL) {
    /** Create a new file if one does not exist (plus inherit gid) */
    if ((r = t9p_create(nn->c, &h, nn->h, path, 0644, T9P_NOGID, 0)) < 0) {
      errno = -r;
      free(nn);
      return -1;
    }
  }

  nn->h = h;
  nn->size = -1;

  pathloc->handlers = &t9p_file_ops;
  pathloc->ops = &t9p_fs_ops;

  return 0;
}

static int
t9p_rtems_file_rmnod(rtems_filesystem_location_info_t *parent_loc,
  rtems_filesystem_location_info_t *pathloc)
{
  TRACE("parentloc=%p,pathloc=%p", parent_loc, pathloc);
  /** TODO: Im lazy */
  return -1;
}

static int
t9p_rtems_file_fchmod(rtems_filesystem_location_info_t *pathloc, mode_t mode)
{
  TRACE("pathloc=%p,mode=%u", pathloc, (unsigned)mode);
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(pathloc);
  int r;
  if ((r = t9p_chmod(n->c, n->h, mode)) < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static int
t9p_rtems_file_fpathconf(rtems_libio_t *pathloc, int name)
{
  TRACE("pathloc=%p,name=%d", pathloc, name);
  return -1;
}

static int
t9p_rtems_file_fcntl(int p, rtems_libio_t* iop)
{
  TRACE("p=%d,iop=%p", p, iop);
  return -1;
}

static int
t9p_rtems_fs_node_type(rtems_filesystem_location_info_t *pathloc)
{
  TRACE("pathloc=%p", pathloc);
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(pathloc);
  if (t9p_is_dir(n->h)) {
    return RTEMS_FILESYSTEM_DIRECTORY;
  }
  else {
    return 0; /** ??? this means regular??? */
  }
}

#endif // __RTEMS_MAJOR__ < 6

static int
t9p_rtems_fs_mount(rtems_filesystem_mount_table_entry_t* mt_entry)
{
  TRACE("mt_entry=%p", mt_entry);
  return -1;
}

static int
t9p_rtems_fs_unmount(rtems_filesystem_mount_table_entry_t* mt_entry)
{
  TRACE("mt_entry=%p", mt_entry);
  return -1;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_symlink(
  const rtems_filesystem_location_info_t* parentloc, const char* name, size_t namelen,
  const char* target
)
#else
static int
t9p_rtems_fs_symlink(
  rtems_filesystem_location_info_t* parentloc,
  const char *name,
  const char *target
)
#endif
{
  TRACE("parentloc=%p, name=%s, target=%s", parentloc, name, target);
  t9p_rtems_fs_info_t* fi = parentloc->mt_entry->fs_info;
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(parentloc);
  int r = t9p_symlink(fi->c, n->h, target, name, T9P_NOGID, NULL);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_utimens(const rtems_filesystem_location_info_t* loc, struct timespec times[2])
#else
static int
t9p_rtems_fs_utimens(rtems_filesystem_location_info_t* loc, time_t atime, time_t mtime)
#endif
{
  TRACE("loc=%p", loc);
  return -1;
}

static int
t9p_rtems_fs_rmnod(
  const rtems_filesystem_location_info_t* parentloc, const rtems_filesystem_location_info_t* loc
)
{
  TRACE("parentloc=%p, loc=%p", parentloc, loc);
  return -1;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_mknod(
  const rtems_filesystem_location_info_t* parentloc,
  const char* name,
  size_t namelen,
  mode_t mode,
  dev_t dev
)
#else
static int t9p_rtems_fs_mknod(
  const char *name,
  mode_t mode,
  dev_t dev,
  rtems_filesystem_location_info_t* parentloc
)
#endif
{
  TRACE("parentloc=%p, name=%s, mode=%u, dev=%llu", parentloc, name, (unsigned)mode, dev);
  t9p_rtems_fs_info_t* fi = parentloc->mt_entry->fs_info;
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(parentloc);
  /** This operation will immediately clunk the new fid */
  int r = t9p_create(fi->c, NULL, n->h, name, mode, T9P_NOGID, 0);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static bool
t9p_rtems_fs_are_nodes_equal(
  const rtems_filesystem_location_info_t* a, const rtems_filesystem_location_info_t* b
)
{
  TRACE("a=%p, b=%p", a, b);
  qid_t qa = t9p_get_qid(((t9p_rtems_node_t*)a->node_access)->h);
  qid_t qb = t9p_get_qid(((t9p_rtems_node_t*)b->node_access)->h);
  return !memcmp(&qa, &qb, sizeof(qb));
}

#if __RTEMS_MAJOR__ >= 6
static void
t9p_rtems_fs_freenode(const rtems_filesystem_location_info_t* loc)
#else
static int
t9p_rtems_fs_freenode(rtems_filesystem_location_info_t* loc)
#endif
{
  TRACE("loc=%p", loc);
  t9p_rtems_fs_info_t* fi = loc->mt_entry->fs_info;
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);
  t9p_close_handle(fi->c, n->h);
  n->h = NULL;
  n->c = NULL;
  free(n);
}

static int
t9p_rtems_fs_clonenode(rtems_filesystem_location_info_t* loc)
{
  TRACE("loc=%p", loc);

  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);

  /** Duplicate the existing node to avoid double frees.
    * FIXME: We could use ref counting here instead!! */
  t9p_rtems_node_t* nn = calloc(sizeof(t9p_rtems_node_t), 1);
  *nn = *n;
  loc->node_access = nn;

  t9p_handle_t nh;
  int r;
  if ((r = t9p_dup(n->c, nn->h, &nh)) < 0) {
    errno = -r;
    return -1;
  }
  nn->h = nh;
  nn->size = -1;
  return 0;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_link(
  const rtems_filesystem_location_info_t* parentloc,
  const rtems_filesystem_location_info_t* targetloc,
  const char* name,
  size_t namelen
)
#else
static int t9p_rtems_fs_link(
  rtems_filesystem_location_info_t  *targetloc,
  rtems_filesystem_location_info_t  *parentloc,
  const char                        *name
)
#endif
{
  TRACE("parentloc=%p, targetloc=%p, name=%s", parentloc, targetloc, name);
  return -1;
}

#if __RTEMS_MAJOR__ >= 6
static long
t9p_rtems_fs_readlink(const rtems_filesystem_location_info_t* loc, char* buf, size_t bufsize)
#else
static int
t9p_rtems_fs_readlink(rtems_filesystem_location_info_t* loc, char* buf, size_t bufsize)
#endif
{
  TRACE("loc=%p, buf=%p, bufsz=%zu", loc, buf, bufsize);
  t9p_rtems_fs_info_t* fi = loc->mt_entry->fs_info;
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);

  int r = t9p_readlink(fi->c, n->h, buf, bufsize);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_rename(
  const rtems_filesystem_location_info_t* oldparentloc,
  const rtems_filesystem_location_info_t* oldloc,
  const rtems_filesystem_location_info_t* newparentloc, const char* name, size_t namelen
)
#else
static int
t9p_rtems_fs_rename(
  rtems_filesystem_location_info_t *oldparentloc,
  rtems_filesystem_location_info_t *oldloc,
  rtems_filesystem_location_info_t *newparentloc, const char *name
)
#endif
{
  TRACE("oldparentloc=%p, oldloc=%p, newparentloc=%p, name=%s", oldparentloc,
    oldloc, newparentloc, name);
  return -1;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_chown(const rtems_filesystem_location_info_t* loc, uid_t owner, gid_t group)
#else
static int
t9p_rtems_fs_chown(rtems_filesystem_location_info_t* loc, uid_t owner, gid_t group)
#endif
{
  TRACE("loc=%p, owner=%d, group=%d", loc, owner, group);
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);
  int r = t9p_chown(n->c, n->h, owner, group);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static int
t9p_rtems_fs_fchmod(const rtems_filesystem_location_info_t* loc, mode_t mode)
{
  TRACE("loc=%p, mode=%d", loc, (unsigned)mode);
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);
  int r = t9p_chmod(n->c, n->h, mode);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static ssize_t
t9p_rtems_dir_read(rtems_libio_t* iop, void* buffer, size_t count)
{
  TRACE("iop=%p, buffer=%p, count=%zu", iop, buffer, count);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);

  t9p_scandir_ctx_t sc = {.offset = iop->offset};
  ssize_t bytesTrans = t9p_readdir_dirents(n->c, n->h, &sc, buffer, count);
  if (bytesTrans < 0) {
    errno = -bytesTrans;
    return -1;
  }
  iop->offset = sc.offset;
  return bytesTrans;
}

static int
t9p_rtems_dir_fstat(const rtems_filesystem_location_info_t* loc, struct stat* buf)
{
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);
  return -1;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_dir_open(rtems_libio_t* iop, const char* path, int oflag, mode_t mode)
#else
static int
t9p_rtems_dir_open(rtems_libio_t* iop, const char* path, uint32_t oflag, mode_t mode)
#endif
{
  TRACE("iop=%p, path=%s, oflag=0x%X, mode=0x%X", iop, path, (unsigned)oflag, (unsigned)mode);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);

  if (t9p_open(n->c, n->h, T9P_OREADONLY) < 0)
    return -1;
  return 0;
}

/**************************************************************************************
 * File handlers
 **************************************************************************************/

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_file_open(rtems_libio_t* iop, const char* path, int oflag, mode_t mode)
#else
static int
t9p_rtems_file_open(rtems_libio_t* iop, const char* path, uint32_t oflag, mode_t mode)
#endif
{
  TRACE("iop=%p, path=%s, oflag=0x%X, mode=0%o", iop, path, (unsigned)oflag, (unsigned)mode);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  int r = t9p_open(n->c, n->h, rtems_mode_to_t9p(mode));
  if (r < 0) {
    TRACE("E: %d (%s)\n", -r, strerror(-r));
    errno = -r;
    return -1;
  }

  struct t9p_getattr ta;
  if ((r = t9p_getattr(n->c, n->h, &ta, T9P_GETATTR_ALL)) < 0) {
    t9p_close(n->h);
    TRACE("E: %d (%s)\n", -r, strerror(-r));
    errno = -r;
    return -1;
  }
  n->size = ta.fsize;

  #if 0
  if (S_ISDIR(ta.mode)) {
    iop->handlers = &t9p_dir_ops;
  }
  else {
    iop->handlers = &t9p_file_ops;
  }
  #endif

  return 0;
}

static int
t9p_rtems_file_close(rtems_libio_t* iop)
{
  TRACE("iop=%p", iop);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  t9p_close(n->h);
  return 0;
}

static ssize_t
t9p_rtems_file_read(rtems_libio_t* iop, void* buffer, size_t count)
{
  TRACE("iop=%p,buffer=%p,count=%zu,iop->off=%llu", iop, buffer, count, iop->offset);
  ssize_t off = iop->offset;
  uint8_t* p = buffer;
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);

  n->size = t9p_stat_size(n->c, n->h);
  /** Need to truncate this because 9p will give us nothing if we ask for too much 
    *... I think. TODO: verify */
  if (count > n->size)
    count = n->size;

  /** Break reads into pieces in case iounit is smaller than the requested read size */
  const size_t iounit = t9p_get_iounit(n->h);
  ssize_t rem = count, ret = 0;
  while (rem > 0) {
    const ssize_t toRead = min(iounit, rem < count ? rem : count);
    ret = t9p_read(n->c, n->h, off, toRead, p);
    if (ret < 0) {
      errno = -ret;
      return -1;
    }
    rem -= ret;
    p += ret;
    /** RTEMS 4.X is funny about this; it handles the offset itself. */
  #if __RTEMS_MAJOR__ >= 6
    iop->offset += ret;
  #endif
    off += ret;

    /** Likely end of file */
    if (ret != toRead)
      break;
  }
  return (uintptr_t)p - (uintptr_t)buffer;
}

static ssize_t
t9p_rtems_file_write(rtems_libio_t* iop, const void* buffer, size_t count)
{
  TRACE("iop=%p, buffer=%p, count=%zu", iop, buffer, count);
  const uint8_t* p = buffer;
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);

  /** Break writes into pieces in case iounit is smaller than the requested write size */
  const size_t iounit = t9p_get_iounit(n->h);
  ssize_t rem = count, ret = 0;
  while (rem > 0) {
    ssize_t toWrite = min(iounit, rem < count ? rem : count);
    ret = t9p_write(n->c, n->h, iop->offset, toWrite, p);
    if (ret < 0) {
      errno = -ret;
      return -1;
    }
    rem -= ret;
    p += ret;
    /** RTEMS 4.X tracks the offset for us */
  #if __RTEMS_MAJOR__ >= 6
    iop->offset += ret;
  #endif

    /** Should we update size from the server? */
    if (iop->offset >= n->size)
      n->size = iop->offset+1;
  }
  return count;
}

static off_t
t9p_rtems_file_lseek(rtems_libio_t* iop, off_t offset, int whence)
{
  TRACE("iop=%p, off=%llu, whence=%d", iop, offset, whence);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  n->size = t9p_stat_size(n->c, n->h);

  switch (whence) {
  case SEEK_SET:
    iop->offset = offset;
    break;
  case SEEK_CUR:
    iop->offset += offset;
    break;
  case SEEK_END:
    iop->offset = n->size-1;
    break;
  }

  if (iop->offset >= n->size) iop->offset = n->size-1;
  if (iop->offset < 0) iop->offset = 0;
  return iop->offset;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_file_fstat(const rtems_filesystem_location_info_t* loc, struct stat* buf)
#else
static int
t9p_rtems_file_fstat(rtems_filesystem_location_info_t* loc, struct stat* buf)
#endif
{
  TRACE("loc=%p, buf=%p", loc, buf);
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);

  struct t9p_getattr ta;
  int r = t9p_getattr(n->c, n->h, &ta, T9P_GETATTR_ALL);
  if (r < 0) {
    errno = -r;
    return -1;
  }

  buf->st_dev = 0;
  buf->st_ino = t9p_get_qid(n->h).path;
  buf->st_mode = ta.mode;
  buf->st_nlink = ta.nlink;
  buf->st_uid = ta.uid;
  buf->st_gid = ta.gid;
  buf->st_rdev = ta.rdev;
  buf->st_size = ta.fsize;
  buf->st_atim.tv_sec = ta.atime_sec;
  buf->st_atim.tv_nsec = ta.atime_nsec;
  buf->st_mtim.tv_sec = ta.mtime_sec;
  buf->st_mtim.tv_nsec = ta.mtime_nsec;
  buf->st_ctim.tv_sec = ta.ctime_sec;
  buf->st_ctim.tv_nsec = ta.ctime_nsec;
  buf->st_blksize = ta.blksize;
  buf->st_blocks = ta.blocks;
  return 0;
}

static int
t9p_rtems_file_ftruncate(rtems_libio_t* iop, off_t length)
{
  TRACE("iop=%p, length=%llu", iop, length);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);

  int r = t9p_truncate(n->c, n->h, length);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static int
t9p_rtems_file_fsync(rtems_libio_t* iop)
{
  TRACE("iop=%p", iop);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  int r = t9p_fsync(n->c, n->h);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}


static int
t9p_rtems_file_ioctl(rtems_libio_t* iop, unsigned long req, void* buffer)
{
  TRACE("iop=%p, req=%lu, buf=%p", iop, req, buffer);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  if (!buffer) {
    errno = EINVAL;
    return -1;
  }

  int* ll = buffer;
  uint32_t* u = buffer;

  switch (req)
  {
  case T9P_RTEMS_IOCTL_GET_FID:
  case T9P_RTEMS_IOCTL_GET_FID_COUNT:
    break;
  case T9P_RTEMS_IOCTL_GET_IOUNIT:
    *u = t9p_get_iounit(n->h);
    break;
  case T9P_RTEMS_IOCTL_GET_LOG_LEVEL:
    *ll = t9p_get_log_level(n->c);
    break;
  }
  return 0;
}

#if 1
struct _msg_queue_s
{
  rtems_name name;
  rtems_id queue;
  size_t msgSize;
};

msg_queue_t*
msg_queue_create(const char* id, size_t msgSize, size_t maxMsgs)
{
  msg_queue_t* q = calloc(1, sizeof(msg_queue_t));
  q->name = rtems_build_name(id[0], id[1], id[2], id[3]);
  q->msgSize = msgSize;
  rtems_status_code status =
    rtems_message_queue_create(q->name, maxMsgs, msgSize, RTEMS_FIFO, &q->queue);
  if (status != RTEMS_SUCCESSFUL) {
    printf("Queue create failed: %d\n", status);
    free(q);
    return NULL;
  }
  return q;
}

void
msg_queue_destroy(msg_queue_t* q)
{
  rtems_message_queue_delete(q->queue);
  free(q);
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
  return rtems_message_queue_receive(q->queue, data, size, RTEMS_NO_WAIT, 0) == RTEMS_SUCCESSFUL
           ? 0
           : -1;
}

#endif
#define _T9P_NO_POSIX_MQ
#include "t9p_rtems.h"
#include "t9p.h"
#include "t9p_platform.h"

#include <rtems.h>
#include <rtems/libio.h>
#include <rtems/libio_.h>
#include <rtems/thread.h>
#include <stdlib.h>

#include "t9p_posix.c"

#define DO_TRACE
#ifdef DO_TRACE
#define TRACE(...) do { \
  printf("%s(", __FUNCTION__); \
  printf(__VA_ARGS__); \
  printf(")\n"); \
} while(0);
#else
#define TRACE(...)
#endif

#if 0
/* the file handlers table */
static
struct _rtems_filesystem_file_handlers_r nfs_file_file_handlers = {
                nfs_file_open,                  /* OPTIONAL; may be NULL */
                nfs_file_close,                 /* OPTIONAL; may be NULL */
                nfs_file_read,                  /* OPTIONAL; may be NULL */
                nfs_file_write,                 /* OPTIONAL; may be NULL */
                nfs_file_ioctl,                 /* OPTIONAL; may be NULL */
                nfs_file_lseek,                 /* OPTIONAL; may be NULL */
                nfs_fstat,                              /* OPTIONAL; may be NULL */
                nfs_fchmod,                             /* OPTIONAL; may be NULL */
                nfs_file_ftruncate,             /* OPTIONAL; may be NULL */
                nfs_file_fpathconf,             /* OPTIONAL; may be NULL - UNUSED */
                nfs_file_fsync,                 /* OPTIONAL; may be NULL */
                nfs_file_fdatasync,             /* OPTIONAL; may be NULL */
                nfs_file_fcntl,                 /* OPTIONAL; may be NULL */
                nfs_unlink,                             /* OPTIONAL; may be NULL */
};

/* the directory handlers table */
static
struct _rtems_filesystem_file_handlers_r nfs_dir_file_handlers = {
                nfs_dir_open,                   /* OPTIONAL; may be NULL */
                nfs_dir_close,                  /* OPTIONAL; may be NULL */
                nfs_dir_read,                   /* OPTIONAL; may be NULL */
                nfs_dir_write,                  /* OPTIONAL; may be NULL */
                nfs_dir_ioctl,                  /* OPTIONAL; may be NULL */
                nfs_dir_lseek,                  /* OPTIONAL; may be NULL */
                nfs_fstat,                              /* OPTIONAL; may be NULL */
                nfs_fchmod,                             /* OPTIONAL; may be NULL */
                nfs_dir_ftruncate,              /* OPTIONAL; may be NULL */
                nfs_dir_fpathconf,              /* OPTIONAL; may be NULL - UNUSED */
                nfs_dir_fsync,                  /* OPTIONAL; may be NULL */
                nfs_dir_fdatasync,              /* OPTIONAL; may be NULL */
                nfs_dir_fcntl,                  /* OPTIONAL; may be NULL */
                nfs_dir_rmnod,                          /* OPTIONAL; may be NULL */
};

/* the link handlers table */
static
struct _rtems_filesystem_file_handlers_r nfs_link_file_handlers = {
                nfs_link_open,                  /* OPTIONAL; may be NULL */
                nfs_link_close,                 /* OPTIONAL; may be NULL */
                nfs_link_read,                  /* OPTIONAL; may be NULL */
                nfs_link_write,                 /* OPTIONAL; may be NULL */
                nfs_link_ioctl,                 /* OPTIONAL; may be NULL */
                nfs_link_lseek,                 /* OPTIONAL; may be NULL */
                nfs_fstat,                              /* OPTIONAL; may be NULL */
                nfs_fchmod,                             /* OPTIONAL; may be NULL */
                nfs_link_ftruncate,             /* OPTIONAL; may be NULL */
                nfs_link_fpathconf,             /* OPTIONAL; may be NULL - UNUSED */
                nfs_link_fsync,                 /* OPTIONAL; may be NULL */
                nfs_link_fdatasync,             /* OPTIONAL; may be NULL */
                nfs_link_fcntl,                 /* OPTIONAL; may be NULL */
                nfs_unlink,                             /* OPTIONAL; may be NULL */
};

#endif

/**************************************************************************************
 * File System Operations
 **************************************************************************************/

static int t9p_rtems_fsmount_me(rtems_filesystem_mount_table_entry_t* mt_entry, const void* data);
static void t9p_rtems_fs_unmountme(rtems_filesystem_mount_table_entry_t* mt_entry);

static void t9p_rtems_fs_evalpath(rtems_filesystem_eval_path_context_t* ctx);
static int t9p_rtems_fs_mount(rtems_filesystem_mount_table_entry_t* mt_entry);
static int t9p_rtems_fs_unmount(rtems_filesystem_mount_table_entry_t* mt_entry);
static int t9p_rtems_fs_symlink(
  const rtems_filesystem_location_info_t* parentloc, const char* name, size_t namelen,
  const char* target
);
static int
t9p_rtems_fs_utimenfs(const rtems_filesystem_location_info_t* loc, struct timespec times[2]);
static int t9p_rtems_fs_rmnod(
  const rtems_filesystem_location_info_t* parentloc, const rtems_filesystem_location_info_t* loc
);
static int t9p_rtems_fs_mknod(
  const rtems_filesystem_location_info_t* parentloc, const char* name, size_t namelen, mode_t mode,
  dev_t dev
);
static bool t9p_rtems_fs_are_nodes_equal(
  const rtems_filesystem_location_info_t* a, const rtems_filesystem_location_info_t* b
);
static void t9p_rtems_fs_freenode(const rtems_filesystem_location_info_t* loc);
static int t9p_rtems_fs_clonenode(rtems_filesystem_location_info_t* loc);
static int t9p_rtems_fs_link(
  const rtems_filesystem_location_info_t*, const rtems_filesystem_location_info_t*, const char*,
  size_t
);
static long
t9p_rtems_fs_readlink(const rtems_filesystem_location_info_t* loc, char* buf, size_t bufsize);
static int t9p_rtems_fs_rename(
  const rtems_filesystem_location_info_t*, const rtems_filesystem_location_info_t*,
  const rtems_filesystem_location_info_t*, const char*, size_t
);
static int
t9p_rtems_fs_chown(const rtems_filesystem_location_info_t* loc, uid_t owner, gid_t group);
static int t9p_rtems_fs_fchmod(const rtems_filesystem_location_info_t* loc, mode_t mode);
static bool t9p_rtems_fs_is_dir(rtems_filesystem_eval_path_context_t* ctx, void* data);
static rtems_filesystem_eval_path_generic_status t9p_rtems_eval_path_token(
  rtems_filesystem_eval_path_context_t* ctx, void* arg, const char* token, size_t tokenlen
);
static void t9p_rtems_fs_lock(const rtems_filesystem_mount_table_entry_t* mt_entry);
static void t9p_rtems_fs_unlock(const rtems_filesystem_mount_table_entry_t* mt_entry);

static const struct _rtems_filesystem_operations_table t9p_fs_ops = {
  .lock_h = t9p_rtems_fs_lock,                       /*rtems_filesystem_mt_entry_lock_t*/
  .unlock_h = t9p_rtems_fs_unlock,                   /*rtems_filesystem_mt_entry_unlock_t*/
  .eval_path_h = t9p_rtems_fs_evalpath,              /*rtems_filesystem_eval_path_t*/
  .link_h = t9p_rtems_fs_link,                       /*rtems_filesystem_link_t*/
  .are_nodes_equal_h = t9p_rtems_fs_are_nodes_equal, /*rtems_filesystem_are_nodes_equal_t*/
  .mknod_h = t9p_rtems_fs_mknod,                     /*rtems_filesystem_mknod_t*/
  .rmnod_h = t9p_rtems_fs_rmnod,                     /*rtems_filesystem_rmnod_t*/
  .fchmod_h = t9p_rtems_fs_fchmod,                   /*rtems_filesystem_fchmod_t*/
  .chown_h = t9p_rtems_fs_chown,                     /*rtems_filesystem_chown_t*/
  .clonenod_h = t9p_rtems_fs_clonenode,              /*rtems_filesystem_clonenode_t*/
  .freenod_h = t9p_rtems_fs_freenode,                /*rtems_filesystem_freenode_t*/
  .mount_h = t9p_rtems_fs_mount,                     /*rtems_filesystem_mount_t*/
  .unmount_h = t9p_rtems_fs_unmount,                 /*rtems_filesystem_unmount_t*/
  .fsunmount_me_h = t9p_rtems_fs_unmountme,          /*rtems_filesystem_fsunmount_me_t*/
  .utimens_h = t9p_rtems_fs_utimenfs,                /*rtems_filesystem_utimens_t*/
  .symlink_h = t9p_rtems_fs_symlink,                 /*rtems_filesystem_symlink_t*/
  .readlink_h = t9p_rtems_fs_readlink,               /*rtems_filesystem_readlink_t*/
  .rename_h = t9p_rtems_fs_rename,                   /*rtems_filesystem_rename_t*/
  .statvfs_h = NULL,                                 /*rtems_filesystem_statvfs_t*/
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

static const rtems_filesystem_eval_path_generic_config t9p_eval_path_cfg = {
  .is_directory = t9p_rtems_fs_is_dir,
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
  rtems_recursive_mutex mutex;
} t9p_rtems_fs_info_t;

/**************************************************************************************
 * File Operations
 *************************************************************************************/

static int t9p_rtems_file_open(rtems_libio_t* iop, const char* path, int oflag, mode_t mode);
static int t9p_rtems_file_close(rtems_libio_t* iop);
static ssize_t t9p_rtems_file_read(rtems_libio_t* iop, void* buffer, size_t count);
static ssize_t t9p_rtems_file_write(rtems_libio_t* iop, const void* buffer, size_t count);
static off_t t9p_rtems_file_lseek(rtems_libio_t* iop, off_t offset, int whence);
static int t9p_rtems_file_fstat(const rtems_filesystem_location_info_t* loc, struct stat* buf);
static int t9p_rtems_file_ftruncate(rtems_libio_t* iop, off_t length);
static int t9p_rtems_file_fsync(rtems_libio_t* iop);
static int t9p_rtems_file_ioctl(rtems_libio_t* iop, unsigned long req, void* buffer);

static rtems_filesystem_file_handlers_r t9p_file_ops = {
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
  .fcntl_h = NULL,                         /*rtems_filesystem_fcntl_t */
  .poll_h = NULL,                          /*rtems_filesystem_poll_t */
  .kqfilter_h = NULL,                      /*rtems_filesystem_kqfilter_t */
  .readv_h = NULL,                         /*rtems_filesystem_readv_t */
  .writev_h = NULL,                        /*rtems_filesystem_writev_t */
  .mmap_h = NULL,                          /*rtems_filesystem_mmap_t */
};

static rtems_filesystem_file_handlers_r t9p_dir_ops = {
  .open_h = NULL,      /*rtems_filesystem_open_t */
  .close_h = NULL,     /*rtems_filesystem_close_t */
  .read_h = NULL,      /*rtems_filesystem_read_t */
  .write_h = NULL,     /*rtems_filesystem_write_t */
  .ioctl_h = t9p_rtems_file_ioctl,     /*rtems_filesystem_ioctl_t */
  .lseek_h = NULL,     /*rtems_filesystem_lseek_t */
  .fstat_h = NULL,     /*rtems_filesystem_fstat_t */
  .ftruncate_h = NULL, /*rtems_filesystem_ftruncate_t */
  .fsync_h = NULL,     /*rtems_filesystem_fsync_t */
  .fdatasync_h = NULL, /*rtems_filesystem_fdatasync_t */
  .fcntl_h = NULL,     /*rtems_filesystem_fcntl_t */
  .poll_h = NULL,      /*rtems_filesystem_poll_t */
  .kqfilter_h = NULL,  /*rtems_filesystem_kqfilter_t */
  .readv_h = NULL,     /*rtems_filesystem_readv_t */
  .writev_h = NULL,    /*rtems_filesystem_writev_t */
  .mmap_h = NULL,      /*rtems_filesystem_mmap_t */
};

/**************************************************************************************
 * Public API
 **************************************************************************************/

int
t9p_rtems_register()
{
  rtems_filesystem_fsmount_me_t mnt;
  return rtems_filesystem_register(RTEMS_FILESYSTEM_TYPE_9P, t9p_rtems_fsmount_me);
}

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

static int
t9p_rtems_fsmount_me(rtems_filesystem_mount_table_entry_t* mt_entry, const void* data)
{
  /*
mount -t 9p -o uid=1000,gid=1000,ip=10.0.2.2:10002,port=10002,user=jeremy
/home/jeremy/dev/lw9p/tests/fs /test
  */
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

  mt_entry->ops = &t9p_fs_ops;
  mt_entry->pathconf_limits_and_options = &t9p_fs_opts;

  /** Configure FS info and opts */
  mt_entry->fs_info = calloc(sizeof(t9p_rtems_fs_info_t), 1);
  t9p_rtems_fs_info_t* fi = mt_entry->fs_info;
  rtems_recursive_mutex_init(&fi->mutex, "9PMUTEX");
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

  fi->c = t9p_init(&t, &fi->opts.opts, apath, ip, mt_entry->target);
  if (fi->c == NULL)
    return -1;

  /** Setup root node info */
  t9p_rtems_node_t* root = calloc(sizeof(t9p_rtems_node_t), 1);
  root->c = fi->c;
  root->size = -1;
  root->h = t9p_get_root(fi->c);
  mt_entry->mt_fs_root->location.node_access = root;
  mt_entry->mt_fs_root->location.handlers = &t9p_dir_ops;
  mt_entry->mt_fs_root->reference_count++;

  return 0;
}

static void
t9p_rtems_fs_unmountme(rtems_filesystem_mount_table_entry_t* mt_entry)
{
  t9p_rtems_fs_info_t* fi = mt_entry->fs_info;
  rtems_recursive_mutex_destroy(&fi->mutex);
  t9p_shutdown(fi->c);
}

static bool
t9p_rtems_fs_is_dir(rtems_filesystem_eval_path_context_t* ctx, void* data)
{
  TRACE("ctx=%p,data=%p", ctx, data);
  return false;
}

static void
t9p_rtems_fs_lock(const rtems_filesystem_mount_table_entry_t* mt_entry)
{
  TRACE("mt_entry=%p", mt_entry);
  t9p_rtems_fs_info_t* fi = mt_entry->fs_info;
  rtems_recursive_mutex_lock(&fi->mutex);
}

static void
t9p_rtems_fs_unlock(const rtems_filesystem_mount_table_entry_t* mt_entry)
{
  TRACE("mt_entry=%p", mt_entry);
  t9p_rtems_fs_info_t* fi = mt_entry->fs_info;
  rtems_recursive_mutex_unlock(&fi->mutex);
}

static rtems_filesystem_eval_path_generic_status
t9p_rtems_eval_path_token(
  rtems_filesystem_eval_path_context_t* ctx, void* arg, const char* token, size_t tokenlen
)
{
  TRACE("ctx=%p, arg=%p, token=%s, tokenlen=%zu", ctx, arg, token, tokenlen);
  t9p_rtems_node_t* node = arg;
  rtems_filesystem_location_info_t* currloc = rtems_filesystem_eval_path_get_currentloc(ctx);

  if (rtems_filesystem_is_current_directory(token, tokenlen)) {
    rtems_filesystem_eval_path_clear_token(ctx);
    return RTEMS_FILESYSTEM_EVAL_PATH_GENERIC_DONE;
  }

  t9p_handle_t nh = t9p_open_handle(node->c, node->h, token);
  if (nh == NULL) {
    return RTEMS_FILESYSTEM_EVAL_PATH_GENERIC_NO_ENTRY;
  }

  /** Follow symlinks if request */
  if (t9p_is_symlink(nh) && ctx->flags & RTEMS_FS_FOLLOW_SYM_LINK) {
  }

  /** Configure handlers */
  if (t9p_is_dir(nh)) {
    currloc->handlers = &t9p_dir_ops;
  } else {
    currloc->handlers = &t9p_file_ops;
  }

  currloc->node_access = calloc(sizeof(t9p_rtems_node_t), 1);
  t9p_rtems_node_t* nn = currloc->node_access;
  nn->c = node->c;
  nn->h = nh;
  nn->size = -1;

  t9p_close_handle(node->c, node->h);

  return RTEMS_FILESYSTEM_EVAL_PATH_GENERIC_CONTINUE;
}

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

  t9p_handle_t h = t9p_open_handle(n->c, n->h, ctx->path);
  if (h == NULL) {
    rtems_filesystem_eval_path_error(ctx, -1);
    return;
  }

  current->node_access = calloc(sizeof(t9p_rtems_node_t), 1);
  t9p_rtems_node_t* nn = current->node_access;
  if (nn->h)
    t9p_close_handle(nn->c, nn->h);
  nn->c = n->c;
  nn->h = h;
  nn->size = -1;

  /** Configure handlers */
  if (t9p_is_dir(h)) {
    current->handlers = &t9p_dir_ops;
  } else {
    current->handlers = &t9p_file_ops;
  }

  rtems_filesystem_eval_path_clear_path(ctx);
}

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

static int
t9p_rtems_fs_symlink(
  const rtems_filesystem_location_info_t* parentloc, const char* name, size_t namelen,
  const char* target
)
{
  TRACE("parentloc=%p, name=%s, nl=%zu, target=%s", parentloc, name, namelen, target);
  t9p_rtems_fs_info_t* fi = parentloc->mt_entry->fs_info;
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(parentloc);
  int r = t9p_symlink(fi->c, n->h, target, name, T9P_NOGID, NULL);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static int
t9p_rtems_fs_utimenfs(const rtems_filesystem_location_info_t* loc, struct timespec times[2])
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

static int
t9p_rtems_fs_mknod(
  const rtems_filesystem_location_info_t* parentloc, const char* name, size_t namelen, mode_t mode,
  dev_t dev
)
{
  TRACE("parentloc=%p, name=%s, nl=%zu, mode=%u, dev=%llu", parentloc, name, namelen, mode, dev);
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

static void
t9p_rtems_fs_freenode(const rtems_filesystem_location_info_t* loc)
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
  t9p_rtems_fs_info_t* fi = loc->mt_entry->fs_info;
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);

  t9p_handle_t nh;
  int r;
  if ((r = t9p_dup(n->c, n->h, &nh)) < 0) {
    errno = -r;
    return -1;
  }
  n->h = nh;
  n->size = -1;
  return 0;
}

static int
t9p_rtems_fs_link(
  const rtems_filesystem_location_info_t* parentloc,
  const rtems_filesystem_location_info_t* targetloc, const char* name, size_t namelen
)
{
  TRACE("parentloc=%p, targetloc=%p, name=%s, namelen=%zu", parentloc, targetloc, name, namelen);
  return -1;
}

static long
t9p_rtems_fs_readlink(const rtems_filesystem_location_info_t* loc, char* buf, size_t bufsize)
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

static int
t9p_rtems_fs_rename(
  const rtems_filesystem_location_info_t* oldparentloc,
  const rtems_filesystem_location_info_t* oldloc,
  const rtems_filesystem_location_info_t* newparentloc, const char* name, size_t namelen
)
{
  TRACE("oldparentloc=%p, oldloc=%p, newparentloc=%p, name=%s, namelen=%zu", oldparentloc,
    oldloc, newparentloc, name, namelen);
  return -1;
}

static int
t9p_rtems_fs_chown(const rtems_filesystem_location_info_t* loc, uid_t owner, gid_t group)
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
  TRACE("loc=%p, mode=%d", loc, mode);
  t9p_rtems_node_t* n = t9p_rtems_fs_get_node(loc);
  int r = t9p_chmod(n->c, n->h, mode);
  if (r < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

/**************************************************************************************
 * File handlers
 **************************************************************************************/

static int
t9p_rtems_file_open(rtems_libio_t* iop, const char* path, int oflag, mode_t mode)
{
  TRACE("iop=%p, path=%s, oflag=0x%X, mode=0x%X", iop, path, oflag, mode);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  int r = t9p_open(n->c, n->h, rtems_mode_to_t9p(mode));
  if (r < 0) {
    errno = -r;
    return -1;
  }

  struct t9p_getattr ta;
  if ((r = t9p_getattr(n->c, n->h, &ta, T9P_GETATTR_ALL)) < 0) {
    t9p_close(n->h);
    errno = -r;
    return -1;
  }
  n->size = ta.fsize;
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
  TRACE("iop=%p, buffer=%p, count=%zu", iop, buffer, count);
  uint8_t* p = buffer;
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);

  n->size = t9p_stat_size(n->c, n->h);
  if (count > n->size)
    count = n->size;

  /** Break reads into pieces in case iounit is smaller than the requested read size */
  const size_t iounit = t9p_get_iounit(n->h);
  ssize_t rem = count, ret = 0;
  while (rem > 0) {
    const ssize_t toRead = min(iounit, rem < count ? rem : count);
    ret = t9p_read(n->c, n->h, iop->offset, toRead, p);
    if (ret < 0) {
      errno = -ret;
      return -1;
    }
    rem -= ret;
    p += ret, iop->offset += ret;

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
    p += ret, iop->offset += ret;

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

static int
t9p_rtems_file_fstat(const rtems_filesystem_location_info_t* loc, struct stat* buf)
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
    rtems_set_errno_and_return_minus_one(EINVAL);
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
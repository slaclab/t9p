/**
 * ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: RTEMS platform-specific code + file system ops implementation.
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

#define _T9P_NO_POSIX_MQ
#include "t9p_rtems.h"
#include "t9p.h"
#include "t9p_platform.h"

#include <rtems.h>
#include <rtems/libio.h>
#include <rtems/libio_.h>
#include <rtems/seterr.h>
#include <rtems/error.h>
#include <rtems/malloc.h>
#include <stdlib.h>
#include <inttypes.h>
#include <fcntl.h>

#include <rtems/score/protectedheap.h>
#include <rtems/score/wkspace.h>

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

#define TESTING

#define TRACE(...) \
  if (s_do_trace) { \
  fprintf(stderr,"%s(", __FUNCTION__); \
  fprintf(stderr,__VA_ARGS__); \
  fprintf(stderr,")\n"); \
}

#define ENSURE(_x)    \
  if (!(_x)) {        \
    rtems_panic("%s:%u CHECK FAILED: %s\n", __FILE__, __LINE__, #_x); \
  }

#if __RTEMS_MAJOR__ == 4

#define HEAP_CHECK() \
  do { \
    fprintf(stderr, "%s:%u\n", __FILE__, __LINE__); \
    Heap_Information_block info; \
    _Protected_heap_Get_information(&_Workspace_Area, &info); \
  } while(0)

#else

#define HEAP_CHECK()

#endif

static int s_do_trace = 0;

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

static int t9p_rtems_fs_statvfs(
  const rtems_filesystem_location_info_t *loc,
  struct statvfs *buf
);

static int t9p_rtems_fs_rmnod(
  const rtems_filesystem_location_info_t* parentloc,
  const rtems_filesystem_location_info_t* loc
);

static bool t9p_rtems_fs_are_nodes_equal(
  const rtems_filesystem_location_info_t* a,
  const rtems_filesystem_location_info_t* b
);

static int t9p_rtems_fs_clonenode(rtems_filesystem_location_info_t* loc);
static int t9p_rtems_fs_fchmod(const rtems_filesystem_location_info_t* loc, mode_t mode);

static void t9p_rtems_fs_lock(const rtems_filesystem_mount_table_entry_t* mt_entry);
static void t9p_rtems_fs_unlock(const rtems_filesystem_mount_table_entry_t* mt_entry);

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

static int t9p_rtems_fs_unlink(
  rtems_filesystem_location_info_t *parentloc,
  rtems_filesystem_location_info_t *pathloc
);

static int t9p_rtems_fs_statvfs(
  rtems_filesystem_location_info_t *loc,
  struct statvfs *buf
);

#endif // RTEMS_MAJOR >= 6

static int t9p_rtems_fs_mount(rtems_filesystem_mount_table_entry_t* mt_entry);
static int t9p_rtems_fs_unmount(rtems_filesystem_mount_table_entry_t* mt_entry);

static const struct _rtems_filesystem_operations_table t9p_fs_ops = {
  .link_h = t9p_rtems_fs_link,
  .mknod_h = t9p_rtems_fs_mknod,
  .chown_h = t9p_rtems_fs_chown,
  .freenod_h = t9p_rtems_fs_freenode,
  .mount_h = t9p_rtems_fs_mount,
  .unmount_h = t9p_rtems_fs_unmount,
  .fsunmount_me_h = t9p_rtems_fs_unmountme,
  .symlink_h = t9p_rtems_fs_symlink,
  .readlink_h = t9p_rtems_fs_readlink,
  .rename_h = t9p_rtems_fs_rename,
  .statvfs_h = t9p_rtems_fs_statvfs,
#if __RTEMS_MAJOR__ >= 6
  .are_nodes_equal_h = t9p_rtems_fs_are_nodes_equal,
  .fchmod_h = t9p_rtems_fs_fchmod,
  .clonenod_h = t9p_rtems_fs_clonenode,
  .rmnod_h = t9p_rtems_fs_rmnod,
  .lock_h = t9p_rtems_fs_lock,
  .unlock_h = t9p_rtems_fs_unlock,
  .eval_path_h = t9p_rtems_fs_evalpath,
  .utimens_h = t9p_rtems_fs_utimens,
#else
  .evalpath_h = t9p_rtems_fs_evalpath,
  .evalformake_h = t9p_rtems_fs_eval_for_make,
  .utime_h = t9p_rtems_fs_utimens,
  .node_type_h = t9p_rtems_fs_node_type,
  .unlink_h = t9p_rtems_fs_unlink,
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

/**
 * Holds per-node info. These should be unique per each individiual fsloc/iop node
 */
typedef struct t9p_rtems_node
{
  t9p_context_t* c;
  t9p_handle_t h;
} t9p_rtems_node_t;

/**
 * Global structure defining fs info for the entire mount.
 */
typedef struct t9p_rtems_fs_info
{
  t9p_context_t* c;
  t9p_rtems_mount_opts_t opts;
  pthread_mutex_t mutex;
  pthread_mutexattr_t mutattr;
  char mntpt[PATH_MAX];
  char apath[PATH_MAX];
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
/*static int t9p_rtems_file_fcntl(int p, rtems_libio_t* iop);*/
static int t9p_rtems_file_fchmod(rtems_filesystem_location_info_t *pathloc, mode_t mode);
/*static int t9p_rtems_file_fpathconf(rtems_libio_t *pathloc, int mode);*/

static int t9p_rtems_file_rmnod(
  rtems_filesystem_location_info_t *parent_loc,
  rtems_filesystem_location_info_t *pathloc
);

#endif
static int t9p_rtems_file_ftruncate(rtems_libio_t* iop, off_t length);
static int t9p_rtems_file_fsync(rtems_libio_t* iop);
static int t9p_rtems_file_ioctl(rtems_libio_t* iop, unsigned long req, void* buffer);

static const rtems_filesystem_file_handlers_r t9p_file_ops = {
  .open_h = t9p_rtems_file_open,
  .close_h = t9p_rtems_file_close,
  .read_h = t9p_rtems_file_read,
  .write_h = t9p_rtems_file_write,
  .ioctl_h = t9p_rtems_file_ioctl,
  .lseek_h = t9p_rtems_file_lseek,
  .fstat_h = t9p_rtems_file_fstat,
  .ftruncate_h = t9p_rtems_file_ftruncate,
  .fsync_h = t9p_rtems_file_fsync,
  .fdatasync_h = t9p_rtems_file_fsync,
#if __RTEMS_MAJOR__ >= 6
  .fcntl_h = rtems_filesystem_default_fcntl,
  .poll_h = rtems_filesystem_default_poll,
  .kqfilter_h = rtems_filesystem_default_kqfilter,
  .readv_h = rtems_filesystem_default_readv,
  .writev_h = rtems_filesystem_default_writev,
  .mmap_h = rtems_filesystem_default_mmap,
#else
  .rmnod_h = t9p_rtems_file_rmnod,
  .fchmod_h = t9p_rtems_file_fchmod,
  /** Leave these NULL until you implement them!! I learned the hard way. */
  /**.fcntl_h = t9p_rtems_file_fcntl,*/
  /**.fpathconf_h = t9p_rtems_file_fpathconf,*/
#endif
};

static ssize_t t9p_rtems_dir_read(rtems_libio_t* iop, void* buffer, size_t count);
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
  .rmnod_h = t9p_rtems_file_rmnod,    /** Can share the same logic as file rm */
  /** Default the rest to NULL */
#endif
};

/**************************************************************************************
 * Public API
 **************************************************************************************/

int
t9p_rtems_register(void)
{
  return rtems_filesystem_register(RTEMS_FILESYSTEM_TYPE_9P, t9p_rtems_fsmount_me);
}

/** For Cexpsh
  * Roughly match the nfsMount syntax: p9Mount(uid_gid_at_host, server_path, mntpt)
  * USAGE:
  * p9Mount("16626.2211@134.79.217.70", "/scratch/lorelli/dummy-diod-fs", "/test", ...)
  */
int
p9Mount(const char* ip, const char* srvpath, const char* mntpt, const char* otheropts)
{
  char opts[128];
  *opts = 0;

  const char* p = strpbrk(ip, "@");
  if (p) {
    char uid[32], gid[32];
    sscanf(ip, "%[^.].%[^@]%*s", uid, gid);
    snprintf(opts, sizeof(opts), "uid=%s,gid=%s", uid, gid);
  }

  if (*opts && otheropts) {
    strcat(opts, ",");
    strcat(opts, otheropts);
  }
  
  /* Check if they want to enable tracing */
  if (strstr(otheropts, "trace")) {
    s_do_trace = 1;
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
" otheropts - Options string to be concatenated to the internal options string\n"
"             for example, passing 'trace' to other opts will enable tracing mode\n"
	int, p9Mount,  (const char* ip, const char* srvpath, const char* mntpt, const char* otheropts)
	),
CEXP_HELP_TAB_END
#endif

static bool
t9p_iterate_fs_stats(const rtems_filesystem_mount_table_entry_t* mt_entry, void* p)
{
  if (strcmp(mt_entry->type, RTEMS_FILESYSTEM_TYPE_9P))
    return false;

  int* n = p;
  struct t9p_rtems_fs_info* fsi = mt_entry->fs_info;

  t9p_opts_t opts = t9p_get_opts(fsi->c);
  t9p_stats_t stats = t9p_get_stats(fsi->c);
  printf("%s\n", fsi->opts.ip);
  printf("  apath=%s,mntpt=%s,uid=%d,gid=%d\n", fsi->apath, mt_entry->target,
    (int)opts.uid, (int)opts.gid);
  printf("   msize=%u\n", (unsigned)t9p_get_msize(fsi->c));
  printf("   bytesSent=%u (%.2fM) bytesRecv=%u (%.2fM)\n",
    (unsigned)stats.total_bytes_send, stats.total_bytes_send / 1000000.f,
    (unsigned)stats.total_bytes_recv, stats.total_bytes_recv / 1000000.f);
  printf("   sendCnt=%u, sendErrCnt=%u\n", (unsigned)stats.send_cnt,
    (unsigned)stats.send_errs);
  printf("   recvCnt=%u, recvErrCnt=%u\n\n", (unsigned)stats.recv_cnt,
  (unsigned)stats.recv_errs);

  (*n)++;
  return false;
}

int
p9Stats()
{
  int n = 0;
  rtems_filesystem_mount_iterate(t9p_iterate_fs_stats, &n);
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

void
p9SetTrace(int doTrace)
{
  printf("9p tracing %s\n", doTrace ? "enabled" : "disabled");
  s_do_trace = doTrace;
}

#ifdef HAVE_CEXP
CEXP_HELP_TAB_BEGIN(p9SetTrace)
	HELP(
"Enable or disable tracing\n"
	void, p9SetTrace,  ()
	),
CEXP_HELP_TAB_END
#endif

/**************************************************************************************
 * Utilities
 **************************************************************************************/

#define WR_FLAGS (S_IWUSR | S_IWGRP | S_IWOTH)
#define RD_FLAGS (S_IRUSR | S_IRGRP | S_IROTH)
#define EX_FLAGS (S_IXUSR | S_IXGRP | S_IXOTH)

static int
rtems_oflag_to_t9p(uint32_t oflag)
{
  if ((oflag & O_RDWR) == O_RDWR)
    return T9P_ORDWR;
  if ((oflag & O_WRONLY) == O_WRONLY)
    return T9P_OWRITEONLY;
  return T9P_OREADONLY;
}

static int
min(int x, int y)
{
  return x < y ? x : y;
}

static t9p_rtems_node_t*
t9p_rtems_loc_get_node(const rtems_filesystem_location_info_t* loc)
{
  if (!loc) return NULL;
  return loc->node_access;
}

static t9p_rtems_node_t*
t9p_rtems_iop_get_node(const rtems_libio_t* iop)
{
  if (!iop) return NULL;
  return iop->file_info;
}

t9p_rtems_node_t*
t9p_rtems_loc_get_root_node(const rtems_filesystem_location_info_t* loc)
{
#if __RTEMS_MAJOR__ <= 4
  return loc->mt_entry->mt_fs_root.node_access;
#else
  return loc->mt_entry->mt_fs_root->location.node_access;
#endif
}

t9p_rtems_fs_info_t*
t9p_rtems_loc_get_fsinfo(const rtems_filesystem_location_info_t* loc)
{
  return loc->mt_entry->fs_info;
}

static t9p_rtems_node_t*
t9p_rtems_clone_node(const t9p_rtems_node_t* old, int dupFid)
{
  t9p_rtems_node_t* n = calloc(sizeof(t9p_rtems_node_t), 1);
  *n = *old;

  /** Duplicate fid too */
  if (dupFid) {
    if (t9p_dup(n->c, old->h, &n->h) < 0) {
      free(n);
      return NULL;
    }
  }

  return n;
}

static void
copyNStr(char* dst, size_t dstSize, const char* src, size_t num) {
  size_t tocopy = min(dstSize-1, num);
  strncpy(dst, src, tocopy);
  dst[tocopy] = 0;
}

/**************************************************************************************
 * FS ops implementation
 **************************************************************************************/

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
  int uid = T9P_NOUID, gid = T9P_NOGID;
  int msize = 65536;

  /** Parse source (in format IP:[PORT:]/path/on/server) */
  char* sip = strtok(mt_entry->dev, ":");
  if (sip)
    strcpy(ip, sip);

  /** Next will be port or apath */
  char* sportOrPath = strtok(NULL, ":");
  if (sportOrPath && *sportOrPath != '/') {
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

  int loglevel = T9P_LOG_DEBUG;
  for (char* r = strtok(buf, ","); r; r = strtok(NULL, ",")) {
    if (!strncmp(r, "ip", strlen("ip"))) {
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
    } else if (!strncmp(r, "msize", strlen("msize"))) {
      const char* p = strpbrk(r, "=");
      if (p)
        msize = atoi(p + 1);
    } else if (!strncmp(r, "user", strlen("user"))) {
      const char* p = strpbrk(r, "=");
      if (p)
        strcpy(user, p + 1);
    } else if (!strcmp(r, "trace")) {
      loglevel = T9P_LOG_TRACE;
    }
  }

  if (msize <= 0) {
    fprintf(stderr, "Invalid msize\n");
    errno = EINVAL;
    return -1;
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
  fi->opts.opts.log_level = loglevel;
  fi->opts.opts.msize = msize;
  strcpy(fi->opts.ip, ip);
  strcpy(fi->opts.opts.user, user);
  strcpy(fi->apath, apath);

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

  printf("Mounted 9P %s:%s at %s\n", ip, apath, mt_entry->target);

  /** Setup root node info */
  t9p_rtems_node_t* root = calloc(sizeof(t9p_rtems_node_t), 1);
  root->c = fi->c;
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

  pthread_mutex_destroy(&fi->mutex);
  pthread_mutexattr_destroy(&fi->mutattr);
  t9p_shutdown(fi->c);
  
#if __RTEMS_MAJOR__ <= 4
  return 0;
#endif
}

#if __RTEMS_MAJOR__ >= 6

/***********************************************************************
 * RTEMS 6 FS Ops
 ***********************************************************************/

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

static int
t9p_rtems_fs_rmnod(
  const rtems_filesystem_location_info_t* parentloc,
  const rtems_filesystem_location_info_t* loc
)
{
  TRACE("parentloc=%p, loc=%p", parentloc, loc);

  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(loc);
  ENSURE(n != NULL);
  if (!n)
    rtems_set_errno_and_return_minus_one(EBADF);

  int r;
  if ((r = t9p_remove(n->c, n->h)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  n->h = NULL; /** fid got clunked by Tremove */
  return 0;
}

static bool
t9p_rtems_fs_are_nodes_equal(
  const rtems_filesystem_location_info_t* a,
  const rtems_filesystem_location_info_t* b
)
{
  TRACE("a=%p, b=%p", a, b);
  ENSURE(a->node_access != NULL);
  ENSURE(b->node_access != NULL);
  qid_t qa = t9p_get_qid(((t9p_rtems_node_t*)a->node_access)->h);
  qid_t qb = t9p_get_qid(((t9p_rtems_node_t*)b->node_access)->h);
  return !memcmp(&qa, &qb, sizeof(qb));
}

static int
t9p_rtems_fs_fchmod(const rtems_filesystem_location_info_t* loc, mode_t mode)
{
  TRACE("loc=%p, mode=%d", loc, (unsigned)mode);
  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(loc);

  ENSURE(n != NULL);

  int r;
  if ((r = t9p_chmod(n->c, n->h, mode)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  return 0;
}

static int
t9p_rtems_fs_clonenode(rtems_filesystem_location_info_t* loc)
{
  TRACE("loc=%p", loc);

  const t9p_rtems_node_t* n = t9p_rtems_loc_get_node(loc);

  ENSURE(n != NULL);
  
  /** Duplicate the existing node to avoid double frees.
    * TODO: Ref counting? */
  t9p_rtems_node_t* newnode = calloc(sizeof(t9p_rtems_node_t), 1);
  *newnode = *n;

  t9p_handle_t newhandle;
  int r;
  if ((r = t9p_dup(n->c, n->h, &newhandle)) < 0) {
    errno = -r;
    free(newnode);
    return -1;
  }
  newnode->h = newhandle;

  loc->node_access = newnode;

  return 0;
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

/**
 * TODO: RTEMS4:
 *  - Handle special case where RTEMS may do path/to/file.xyz/.. to get the parent dir
 */

/**
 * rtems_filesystem_eval_path
 * Transform a path defined by pathname/pathnamelen into a final location.
 * Pathloc should be modified to point at this location.
 */
static int
t9p_rtems_fs_evalpath(
  const char *inpathname,
  size_t pathnamelen,
  int flags,
  rtems_filesystem_location_info_t *pathloc
)
{
  TRACE("pathname=%s,pathnamelen=%zu,flags=%d,pathloc=%p", inpathname, pathnamelen,
    flags, pathloc);

  if (!rtems_libio_is_valid_perms(flags)) {
    TRACE("E: EIO");
    errno = EIO;
    return -1;
  }

  /** inpathname is actually a bounded string... Let's make a NULL terminated copy
    * of it to make things easier */
  char pathbuf[PATH_MAX];
  pathbuf[0] = 0;
  copyNStr(pathbuf, sizeof(pathbuf), inpathname, pathnamelen);
  const char* pathname = pathbuf;

  t9p_rtems_node_t* realnode = t9p_rtems_loc_get_node(pathloc);
  ENSURE(realnode != NULL);

  /** Walk downwards, starting with the parent node */
  t9p_handle_t nh = t9p_open_handle(realnode->c, realnode->h, pathname);
  if (nh == NULL) {
    TRACE("E: ENOENT");
    errno = ENOENT;
    return -1;
  }

  /** Make a new node for pathloc, to replace the parent's */
  t9p_rtems_node_t* p = t9p_rtems_clone_node(pathloc->node_access, 0);
  p->h = nh;
  pathloc->node_access = p;

  /** NOTE: Do not need to free the old node_access */

  pathloc->ops = &t9p_fs_ops;
  if (t9p_is_dir(nh)) {
    pathloc->handlers = &t9p_dir_ops;
    TRACE("handlers=dir_ops");
  }
  else {
    pathloc->handlers = &t9p_file_ops;
    TRACE("handlers=file_ops");
  }

  return 0;
}

/**
 * From RTEMS src:
 *  The following routine evaluate path for a new node to be created.
 *  pathloc is returned with a pointer to the parent of the new node.
 *  name is returned with a pointer to the first character in the
 *  new node name.  The parent node is verified to be a directory.
 */
static int
t9p_rtems_fs_eval_for_make(
  const char                       *path,
  rtems_filesystem_location_info_t *pathloc,
  const char                      **name
)
{
  TRACE("path=%s, pathloc=%p, name=%p", path, pathloc, name);

  /** Determine the name of the file */
  *name = strrchr(path, '/');
  if (!*name)
    *name = path;
  else
    (*name)++; /** Skip past the '/' */

  t9p_rtems_node_t* node = t9p_rtems_loc_get_node(pathloc);
  ENSURE(node != NULL);

  /** Determine parent dir */
  char parentPath[PATH_MAX];
  t9p_get_parent_dir(path, parentPath, sizeof(parentPath));

  TRACE("parentPath=%s", parentPath);

  /** Open handle to the parent dir */
  t9p_handle_t nh = t9p_open_handle(node->c, node->h, parentPath);
  if (nh == NULL) {
    return -1;
  }

  /** Allocate new node */
  t9p_rtems_node_t* newnode = t9p_rtems_clone_node(node, 0);
  newnode->h = nh;

  pathloc->ops = &t9p_fs_ops;
  pathloc->node_access = newnode;

  return 0;
}

/**
 * Remove the file pointed to by pathloc. parentloc is the parent's location.
 */
static int
t9p_rtems_file_rmnod(
  rtems_filesystem_location_info_t *parentloc,
  rtems_filesystem_location_info_t *pathloc
)
{
  TRACE("parentloc=%p,pathloc=%p", parentloc, pathloc);

  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(pathloc);
  if (!n)
    rtems_set_errno_and_return_minus_one(EBADF);

  /** Remove will always clunk the fid. This is not ideal, as the higher level fs code will
    * explicitly call freenode on the node after this. For now I think it's safe to clunk
    * and just clear out the n->h. In freenode, we'll check for validity first.
    * TODO: Re-evaluate me at some point!
    */
  int r = t9p_remove(n->c, n->h);
  n->h = NULL;
  if (r < 0)
    rtems_set_errno_and_return_minus_one(-r);

  return 0;
}

static int
t9p_rtems_file_fchmod(
  rtems_filesystem_location_info_t *pathloc,
  mode_t mode
)
{
  TRACE("pathloc=%p,mode=%u", pathloc, (unsigned)mode);
  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(pathloc);
  ENSURE(n != NULL);

  int r;
  if ((r = t9p_chmod(n->c, n->h, mode)) < 0) {
    errno = -r;
    return -1;
  }
  return 0;
}

static int
t9p_rtems_fs_node_type(rtems_filesystem_location_info_t *pathloc)
{
  TRACE("pathloc=%p", pathloc);
  const t9p_rtems_node_t* n = t9p_rtems_loc_get_node(pathloc);
  ENSURE(n != NULL);

  if (t9p_is_dir(n->h)) {
    return RTEMS_FILESYSTEM_DIRECTORY;
  }
  else {
    return RTEMS_FILESYSTEM_MEMORY_FILE; /** TODO: This means regular...right? */
  }
}

static int 
t9p_rtems_fs_unlink(
  rtems_filesystem_location_info_t *parentloc,
  rtems_filesystem_location_info_t *pathloc
)
{
  TRACE("parentloc=%p,pathloc=%p", parentloc, pathloc);

  t9p_rtems_node_t* node = t9p_rtems_loc_get_node(pathloc);
  ENSURE(node != NULL);

  if (!node)
    rtems_set_errno_and_return_minus_one(EIO);

  int r;
  if ((r = t9p_remove(node->c, node->h)) < 0)
    rtems_set_errno_and_return_minus_one(-r);

  /** Same situation as noted in rmnod. Tremove always clunks, so we need
    * to null out this handle. An alternative would be to duplicate the fid,
    * so we can keep a copy of it around for freenode. However, I think it's
    * generally a bad idea to have a use-after-unlink situation anyway.
    * This should be OK.
    */
  node->h = NULL;
  return 0;
}

#endif // __RTEMS_MAJOR__ < 6

static int
t9p_rtems_fs_mount(rtems_filesystem_mount_table_entry_t* mt_entry)
{
  TRACE("mt_entry=%p", mt_entry);
  errno = ENOTSUP;
  return -1;
}

static int
t9p_rtems_fs_unmount(rtems_filesystem_mount_table_entry_t* mt_entry)
{
  TRACE("mt_entry=%p", mt_entry);
  errno = ENOTSUP;
  return -1;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_symlink(
  const rtems_filesystem_location_info_t* parentloc,
  const char* name,
  size_t namelen,
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
  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(parentloc);
  ENSURE(n != NULL);
  ENSURE(fi != NULL);

  int r;
  if ((r = t9p_symlink(fi->c, n->h, target, name, T9P_NOGID, NULL)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
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
  t9p_rtems_fs_info_t* fi = t9p_rtems_loc_get_fsinfo(parentloc);
  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(parentloc);

  ENSURE(n != NULL);
  ENSURE(fi != NULL);

  int r;
  if (S_ISREG(mode)) {
    /** This operation will immediately clunk the new fid */
    if ((r = t9p_create(fi->c, NULL, n->h, name, mode, T9P_NOGID, 0)) < 0)
      rtems_set_errno_and_return_minus_one(-r);
  }
  /** Use mkdir for dirs. No fid is allocated for mkdir */
  else if (S_ISDIR(mode)) {
    if ((r = t9p_mkdir(n->c, n->h, name, mode, T9P_NOGID, NULL)) < 0)
      rtems_set_errno_and_return_minus_one(-r);
  }
  /** Other file types not supported via mknod */
  else
    rtems_set_errno_and_return_minus_one(ENOTSUP);

  return 0;
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
  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(loc);

  if (t9p_rtems_loc_get_root_node(loc) == n) {
    printf("%s: Tried to free root node??\n", __FUNCTION__);
  #if __RTEMS_MAJOR__ <= 4
    return -1;
  #else
    return;
  #endif
  }

  /** Funky; see comment in t9p_rtems_fs_rmnod. We may have clunked the fid elsewhere */
  if (n->h)
    t9p_close_handle(n->c, n->h);

  n->h = NULL;
  n->c = NULL;
  loc->node_access = NULL;
  free(n);
  
#if __RTEMS_MAJOR__ <= 4
  return 0;
#endif
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

  t9p_rtems_node_t* tgtnode = t9p_rtems_loc_get_node(targetloc);
  t9p_rtems_node_t* parnode = t9p_rtems_loc_get_node(parentloc);

  ENSURE(parnode != NULL);
  ENSURE(tgtnode != NULL);
  
  int r;
  if ((r = t9p_link(tgtnode->c, parnode->h, tgtnode->h, name)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  return 0;
}

#if __RTEMS_MAJOR__ >= 6
static long
t9p_rtems_fs_readlink(
  const rtems_filesystem_location_info_t* loc,
  char* buf,
  size_t bufsize
)
#else
static int
t9p_rtems_fs_readlink(
  rtems_filesystem_location_info_t* loc,
  char* buf,
  size_t bufsize
)
#endif
{
  TRACE("loc=%p, buf=%p, bufsz=%zu", loc, buf, bufsize);
  t9p_rtems_fs_info_t* fi = loc->mt_entry->fs_info;
  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(loc);

  ENSURE(n != NULL);
  ENSURE(fi != NULL);

  int r;
  if ((r = t9p_readlink(fi->c, n->h, buf, bufsize)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  return 0;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_rename(
  const rtems_filesystem_location_info_t* oldparentloc,
  const rtems_filesystem_location_info_t* oldloc,
  const rtems_filesystem_location_info_t* newparentloc,
  const char* name,
  size_t namelen
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

  const t9p_rtems_node_t* oldparnode = t9p_rtems_loc_get_node(oldparentloc);
  const t9p_rtems_node_t* oldnode = t9p_rtems_loc_get_node(oldloc);
  const t9p_rtems_node_t* newparnode = t9p_rtems_loc_get_node(newparentloc);

  ENSURE(oldparnode);
  ENSURE(oldnode);
  ENSURE(newparnode);

  if (!oldparnode || !oldnode || !newparnode)
    rtems_set_errno_and_return_minus_one(EIO);

  int r;
  if ((r = t9p_rename(oldnode->c, newparnode->h, oldnode->h, name)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  return 0;
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
  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(loc);

  ENSURE(n != NULL);

  int r;
  if ((r = t9p_chown(n->c, n->h, owner, group)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  return 0;
}

static ssize_t
t9p_rtems_dir_read(rtems_libio_t* iop, void* buffer, size_t count)
{
  TRACE("iop=%p, buffer=%p, count=%zu", iop, buffer, count);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);

  ENSURE(n != NULL);

  t9p_scandir_ctx_t sc = {.offset = iop->offset};
  ssize_t bytesTrans = t9p_readdir_dirents(n->c, n->h, &sc, buffer, count);
  if (bytesTrans < 0)
    rtems_set_errno_and_return_minus_one(-bytesTrans);
  iop->offset = sc.offset;
  return bytesTrans;
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

  ENSURE(n != NULL);

  int r;
  if ((r = t9p_open(n->c, n->h, T9P_OREADONLY)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  return 0;
}

#if __RTEMS_MAJOR__ >= 6
static int
t9p_rtems_fs_statvfs(const rtems_filesystem_location_info_t *loc, struct statvfs *buf)
#else
static int
t9p_rtems_fs_statvfs(rtems_filesystem_location_info_t *loc, struct statvfs *buf)
#endif
{
  TRACE("loc=%p,buf=%p", loc, buf);

  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(loc);
  ENSURE(n != NULL);

  struct t9p_statfs stat;
  int r;
  if ((r = t9p_statfs(n->c, n->h, &stat)) < 0)
    rtems_set_errno_and_return_minus_one(-r);

  buf->f_bsize = stat.bsize;
  buf->f_frsize = stat.bsize; /** TODO: Is this correct? glibc does this if driver
                                * returns 0 for this field */
  buf->f_blocks = stat.blocks;
  buf->f_bfree = stat.bfree;
  buf->f_bavail = stat.bavail;
  buf->f_files = stat.files;
  buf->f_ffree = stat.ffree;
  buf->f_favail = stat.ffree - stat.files;
  buf->f_fsid = stat.fsid;
  buf->f_flag = 0; /** TODO: Set this properly */
  buf->f_namemax = stat.namelen;
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
  ENSURE(n != NULL);

  int r = t9p_open(n->c, n->h, rtems_oflag_to_t9p(oflag));
  if (r < 0) {
    TRACE("E: %d (%s)\n", -r, strerror(-r));
    rtems_set_errno_and_return_minus_one(-r);
  }

  return 0;
}

static int
t9p_rtems_file_close(rtems_libio_t* iop)
{
  TRACE("iop=%p", iop);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  ENSURE(n != NULL);
  t9p_close(n->h);
  return 0;
}

static ssize_t
t9p_rtems_file_read(rtems_libio_t* iop, void* buffer, size_t count)
{
  TRACE("iop=%p,buffer=%p,count=%zu,iop->off=%lld", iop, buffer, count, iop->offset);
  ssize_t off = iop->offset;
  uint8_t* p = buffer;
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  ENSURE(n != NULL);

  /** Break reads into pieces in case iounit is smaller than the requested read size */
  const size_t iounit = t9p_get_iounit(n->h);
  ssize_t rem = count, ret = 0;
  while (rem > 0) {
    const uint32_t toRead = min(iounit, rem);
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

  TRACE("read num=%lu", (uintptr_t)p - (uintptr_t)buffer);
  return (uintptr_t)p - (uintptr_t)buffer;
}

static ssize_t
t9p_rtems_file_write(rtems_libio_t* iop, const void* buffer, size_t count)
{
  TRACE("iop=%p, buffer=%p, count=%zu", iop, buffer, count);
  const uint8_t* p = buffer;
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  ENSURE(n != NULL);

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
  }
  return count;
}

static off_t
t9p_rtems_file_lseek(rtems_libio_t* iop, off_t offset, int whence)
{
  TRACE("iop=%p, off=%lld, whence=%d", iop, offset, whence);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  ENSURE(n != NULL);

  if (whence == SEEK_END) {
    iop->offset = t9p_stat_size(n->c, n->h);
  }

  /** FIXME: Why doesn't higher-level lseek handle this? am I doing something wrong? */
  //if (iop->offset < 0)
  //  rtems_set_errno_and_return_minus_one(EINVAL);

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
  t9p_rtems_node_t* n = t9p_rtems_loc_get_node(loc);
  ENSURE(n != NULL);

  struct t9p_getattr ta;
  int r;
  if ((r = t9p_getattr(n->c, n->h, &ta, T9P_GETATTR_ALL)) < 0)
    rtems_set_errno_and_return_minus_one(-r);

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
  buf->st_blksize = 4096;
  buf->st_blocks = ta.blocks;
  return 0;
}

static int
t9p_rtems_file_ftruncate(rtems_libio_t* iop, off_t length)
{
  TRACE("iop=%p, length=%llu", iop, length);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  ENSURE(n != NULL);

  int r;
  if ((r = t9p_truncate(n->c, n->h, length)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  return 0;
}

static int
t9p_rtems_file_fsync(rtems_libio_t* iop)
{
  TRACE("iop=%p", iop);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  ENSURE(n != NULL);

  int r;
  if ((r = t9p_fsync(n->c, n->h, 0)) < 0)
    rtems_set_errno_and_return_minus_one(-r);
  return 0;
}

static int
t9p_rtems_file_ioctl(rtems_libio_t* iop, unsigned long req, void* buffer)
{
  TRACE("iop=%p, req=%lu, buf=%p", iop, req, buffer);
  t9p_rtems_node_t* n = t9p_rtems_iop_get_node(iop);
  ENSURE(n != NULL);

  if (!buffer)
    rtems_set_errno_and_return_minus_one(EINVAL);

  int* ll = buffer;
  uint32_t* u = buffer;
  void** pp = buffer;
  qid_t* q = buffer;

  switch (req)
  {
  case T9P_RTEMS_IOCTL_GET_FID:
    *u = t9p_get_fid(n->h);
    break;
  case T9P_RTEMS_IOCTL_GET_FID_COUNT:
    break;
  case T9P_RTEMS_IOCTL_GET_IOUNIT:
    *u = t9p_get_iounit(n->h);
    break;
  case T9P_RTEMS_IOCTL_GET_LOG_LEVEL:
    *ll = t9p_get_log_level(n->c);
    break;
  case T9P_RTEMS_IOCTL_GET_CONTEXT:
    *pp = n->c;
    break;
  case T9P_RTEMS_IOCTL_GET_QID:
    *q = t9p_get_qid(n->h);
    break;
  default:
    return -1;
  }
  return 0;
}

/**************************************************************************************
 * Platform abstraction
 **************************************************************************************/

void*
aligned_zmalloc(size_t size, size_t align)
{
  void* ptr = NULL;
  rtems_memalign(&ptr, align, size);
  if (ptr)
    memset(ptr, 0, size);
  return ptr;
}

#ifdef _T9P_NO_POSIX_MQ

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
  return 
    rtems_message_queue_receive(q->queue, data, size, RTEMS_NO_WAIT, 0) == RTEMS_SUCCESSFUL?0:-1;
}

#endif

#if defined(TESTING) && defined(HAVE_GESYS)

/** This is so evil.. */
#include "../tests/t9p_automated_test.c"

#endif

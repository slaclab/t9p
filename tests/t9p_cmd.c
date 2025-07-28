/**
 * ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: Command-line utility for interacting with 9P. For debugging!
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
#include "t9p.h"
#include "t9p_platform.h"

#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#ifdef __linux__
#include <md5.h>
#endif

#ifdef __linux__
#include <linux/limits.h>
#else
#undef PATH_MAX
#define PATH_MAX 256
#endif

#ifdef HAVE_READLINE
#include <readline/history.h>
#include <readline/readline.h>
#endif

struct t9p_context* ctx;
int run = 1;
static char ipAddr[256];
static char mntpt[256];
static char remotePath[256];
static char user[256];
static char prompt[512];
static int uid;

static void
usage()
{
  printf("t9p -u user -a apath -m mntpt ip\n");
  exit(1);
}

static int
check_connection()
{
  if (ctx != NULL)
    return 1;
  printf("Not connected; use 'connect' first\n");
  return 0;
}

void
ls(int argc, const char* const* argv)
{
  if (argc < 2) {
    printf("usage: ls <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("unable to open %s\n", argv[1]);
    return;
  }

  if (t9p_open(ctx, h, T9P_OREADONLY) < 0) {
    printf("unable to open!\n");
    return;
  }

  t9p_dir_info_t* dirs;
  if (t9p_readdir(ctx, h, &dirs) < 0) {
    printf("ls failed\n");
  } else {
    for (t9p_dir_info_t* d = dirs; d; d = d->next) {
      printf(" %s%s\n", d->name, d->qid.type == T9P_QID_DIR ? "/" : "");
    }
  }

  t9p_close_handle(ctx, h);
}

void
hopen_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: hopen <path>\n");
    return;
  }

  if (!t9p_open_handle(ctx, NULL, argv[1])) {
    printf("Unable to open %s\n", argv[1]);
  } else {
    printf("Opened %s\n", argv[1]);
  }
}

void
exit_cmd(int argc, const char* const* argv)
{
  run = 0;
}

void
cat_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: cat <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("unable to open handle for %s\n", argv[1]);
    return;
  }

  if (t9p_open(ctx, h, T9P_OREADONLY) < 0) {
    printf("unable to open %s\n", argv[1]);
  } else {
    ssize_t sz = t9p_stat_size(ctx, h);
    off_t off = 0;
    while (sz > 0) {
      char buf[128] = {0};
      ssize_t l;
      if ((l = t9p_read(ctx, h, off, sizeof(buf)-1, buf)) < 0) {
        printf("unable to read %s\n", argv[1]);
        goto end;
      }
      buf[sizeof(buf)-1] = 0;
      fputs(buf, stdout);
      sz -= l, off += l;
    }
  }
end:
  t9p_close_handle(ctx, h);
}

void
md5_cmd(int argc, const char* const* argv)
{
#ifdef __linux__
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: md5 <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("unable to open handle for %s\n", argv[1]);
    return;
  }

  MD5_CTX mdc;
  MD5Init(&mdc);

  if (t9p_open(ctx, h, T9P_OREADONLY) < 0) {
    printf("unable to open %s\n", argv[1]);
  } else {
    ssize_t sz = t9p_stat_size(ctx, h);
    off_t off = 0;
    while (sz > 0) {
      char buf[128] = {0};
      ssize_t l;
      if ((l = t9p_read(ctx, h, off, sizeof(buf)-1, buf)) < 0) {
        printf("unable to read %s\n", argv[1]);
        goto end;
      }
      MD5Update(&mdc, (unsigned char*)buf, l);
      buf[sizeof(buf)-1] = 0;
      fputs(buf, stdout);
      sz -= l, off += l;
    }
    unsigned char digest[16];
    char hex[64];
    printf("\nmd5: %s\n", MD5End(&mdc, hex));
  }
end:
  t9p_close_handle(ctx, h);
#endif
}

void
create_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: create <path>\n");
    return;
  }

  char dir[PATH_MAX];
  const char* name;
  strcpy(dir, argv[1]);
  char* d = strrchr(dir, '/');
  if (d) {
    name = d + 1;
    *d = 0;
  } else {
    dir[0] = 0;
    name = argv[1];
  }

  t9p_handle_t parent = t9p_open_handle(ctx, NULL, dir);
  if (!parent) {
    printf("Unable to open dir %s\n", dir);
    return;
  }

  t9p_handle_t h;
  if (t9p_create(ctx, &h, parent, name, 0777, 1000, 0) < 0) {
    printf("Create failed\n");
  }
  t9p_close_handle(ctx, h);
  t9p_close_handle(ctx, parent);
}

void
mkdir_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: mkdir <path>\n");
    return;
  }

  char dir[PATH_MAX];
  const char* name;
  strcpy(dir, argv[1]);
  char* d = strrchr(dir, '/');
  if (d) {
    name = d + 1;
    *d = 0;
  } else {
    dir[0] = 0;
    name = argv[1];
  }

  t9p_handle_t parent = t9p_open_handle(ctx, NULL, dir);
  if (!parent) {
    printf("Unable to open dir %s\n", dir);
    return;
  }

  if (t9p_mkdir(ctx, parent, name, 0777, 1000, NULL) < 0) {
    printf("mkdir failed\n");
  }
  t9p_close_handle(ctx, parent);
}

void
getattr_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: getattr <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("open %s failed\n", argv[1]);
    return;
  }

  struct t9p_getattr a;
  if (t9p_getattr(ctx, h, &a, T9P_GETATTR_ALL) < 0) {
    printf("getattr failed\n");
  } else {
    printf(" mode:          %d\n", (int)a.mode);
    printf(" uid:           %d\n", (int)a.uid);
    printf(" gid:           %d\n", (int)a.gid);
    printf(" nlink:         %" PRIu64 "\n", a.nlink);
    printf(" rdev:          %" PRIu64 "\n", a.rdev);
    printf(" fsize:         %" PRIu64 "\n", a.fsize);
    printf(" blksize:       %" PRIu64 "\n", a.blksize);
    printf(" blocks:        %" PRIu64 "\n", a.blocks);
    printf(" atime_sec:     %" PRIu64 "\n", a.atime_sec);
    printf(" atime_nsec:    %" PRIu64 "\n", a.atime_nsec);
    printf(" mtime_sec:     %" PRIu64 "\n", a.mtime_sec);
    printf(" mtime_nsec:    %" PRIu64 "\n", a.mtime_nsec);
    printf(" ctime_sec:     %" PRIu64 "\n", a.ctime_sec);
    printf(" ctime_nsec:    %" PRIu64 "\n", a.ctime_nsec);
    printf(" btime_sec:     %" PRIu64 "\n", a.btime_sec);
    printf(" btime_nsec:    %" PRIu64 "\n", a.btime_nsec);
    printf(" gen:           %" PRIu64 "\n", a.gen);
    printf(" data_version:  %" PRIu64 "\n", a.data_version);
  }

  t9p_close_handle(ctx, h);
}

void
touch_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: touch <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("failed to open %s\n", argv[1]);
    return;
  }

  if (t9p_touch(ctx, h, 1, 1, 0) < 0) {
    printf("failed to touch file\n");
  }

  t9p_close_handle(ctx, h);
}

void
truncate_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 3) {
    printf("usage: truncate <path> <size>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("failed to open %s\n", argv[1]);
    return;
  }

  int r;
  if ((r = t9p_truncate(ctx, h, atoi(argv[2]))) < 0) {
    printf("failed to truncate %s at %s: %s\n", argv[1], argv[2], strerror(-r));
    return;
  }

  t9p_close_handle(ctx, h);
}

void
put_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 3) {
    printf("usage: put <path> <data_str>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("unable to open handle for %s\n", argv[1]);
    return;
  }

  if (t9p_open(ctx, h, T9P_ORDWR | T9P_OTRUNC) < 0) {
    printf("unable to open %s for write\n", argv[1]);
  } else {
    ssize_t c;
    if ((c = t9p_write(ctx, h, 0, strlen(argv[2]), argv[2])) < 0) {
      printf("unable to write %s\n", argv[1]);
    }
    printf("wrote %ld bytes\n", c);
  }

  t9p_close_handle(ctx, h);
}

void
mv_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 3) {
    printf("usage: mv <oldpath> <newpath>\n");
    return;
  }

  char oparent[1024];
  t9p_get_parent_dir(argv[1], oparent, sizeof(oparent));
  char ofile[1024];
  t9p_get_basename(argv[1], ofile, sizeof(ofile));

  char nparent[1024];
  t9p_get_parent_dir(argv[2], nparent, sizeof(nparent));
  char nfile[1024];
  t9p_get_basename(argv[2], nfile, sizeof(nfile));

  t9p_handle_t odirh, ndirh;
  if ((odirh = t9p_open_handle(ctx, NULL, oparent)) == NULL) {
    printf("unable to open %s\n", oparent);
    return;
  }

  if ((ndirh = t9p_open_handle(ctx, NULL, nparent)) == NULL) {
    printf("unable to open %s\n", nparent);
    t9p_close_handle(ctx, odirh);
    return;
  }

  int r = t9p_renameat(ctx, odirh, ofile, ndirh, nfile);
  if (r < 0) {
    printf("failed to rename: %s\n", strerror(-r));
  }

  t9p_close_handle(ctx, odirh);
  t9p_close_handle(ctx, ndirh);
}

void
unlink_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: unlink <path>\n");
    return;
  }

  char parent[1024];
  t9p_get_parent_dir(argv[1], parent, sizeof(parent));
  char file[1024];
  t9p_get_basename(argv[1], file, sizeof(file));

  t9p_handle_t h = t9p_open_handle(ctx, NULL, parent);
  if (!h) {
    printf("unable to find parent %s\n", parent);
    return;
  }

  int r;
  if ((r = t9p_unlinkat(ctx, h, file, T9P_AT_REMOVEDIR)) < 0) {
    printf("unable to unlink %s/%s: %s\n", parent, file, strerror(r));
    return;
  }

  t9p_close_handle(ctx, h);
  printf("removing %s/%s\n", parent, file);
}

void
rm_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: rm <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("unable to hopen for %s\n", argv[1]);
    return;
  }

  if (t9p_remove(ctx, h) == 0)
    printf("Removed %s\n", argv[1]);
}

void
statfs_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: statfs <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("unable to open handle for %s\n", argv[1]);
    return;
  }

  struct t9p_statfs statfs;
  if (t9p_statfs(ctx, h, &statfs) < 0) {
    printf("unable to statfs\n");
    return;
  }

  printf("bavail:  %" PRIu64 "\n", statfs.bavail);
  printf("bfree:   %" PRIu64 "\n", statfs.bfree);
  printf("blocks:  %" PRIu64 "\n", statfs.blocks);
  printf("fsid:    %" PRIu64 "\n", statfs.fsid);
  printf("ffree:   %" PRIu64 "\n", statfs.ffree);
  printf("namelen: %d\n", (int)statfs.namelen);
  printf("files:   %" PRIu64 "\n", statfs.files);
  printf("type:    %d\n", (int)statfs.type);
  printf("bsize:   %d\n", (int)statfs.bsize);

  t9p_close_handle(ctx, h);
}

static void
readlink_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: statfs <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("unable to open handle for %s\n", argv[1]);
    return;
  }

  char path[PATH_MAX];
  if (t9p_readlink(ctx, h, path, sizeof(path)) < 0) {
    printf("readlink failed\n");
  } else {
    printf("%s\n", path);
  }

  t9p_close_handle(ctx, h);
}

static void
lsdirent_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 2) {
    printf("usage: lsdirent <path>\n");
    return;
  }

  t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
  if (!h) {
    printf("hopen failed for %s\n", argv[1]);
    return;
  }

  t9p_open(ctx, h, T9P_OREADONLY);

  struct dirent buf[64];

  t9p_scandir_ctx_t sc = {0};
  ssize_t bread = t9p_readdir_dirents(ctx, h, &sc, buf, sizeof(buf));
  for (int i = 0; i < bread; i += sizeof(struct dirent)) {
    printf("  %s\n", buf[i/sizeof(struct dirent)].d_name);
  }

  t9p_close_handle(ctx, h);
}

static void
symlink_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;

  if (argc < 3) {
    printf("usage: symlink <to> <from>\n");
    return;
  }

  if (t9p_symlink(ctx, t9p_get_root(ctx), argv[1], argv[2], T9P_NOGID, NULL) < 0) {
    printf("symlink failed\n");
  }
}

static void
link_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;
  
  if (argc < 3) {
    printf("usage: link <to> <from>\n");
    return;
  }
  
  char tod[256];
  t9p_get_parent_dir(argv[1], tod, sizeof(tod));
  char base[256];
  t9p_get_basename(argv[1], base, sizeof(base));
  
  t9p_handle_t dh = t9p_open_handle(ctx, NULL, tod);
  if (!dh) {
    printf("%s not exist!\n", tod);
    return;
  }
  
  t9p_handle_t target = t9p_open_handle(ctx, NULL, argv[2]);
  if (!target) {
    printf("%s not exist!\n", argv[2]);
    t9p_close_handle(ctx, dh);
    return;
  }
  
  t9p_link(ctx, dh, target, base);
  
  t9p_close_handle(ctx, target);
  t9p_close_handle(ctx, dh);
}

static void
rename_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;
  
  if (argc < 3) {
    printf("usage: rename <old> <new>\n");
    return;
  }
  
  char tod[256];
  t9p_get_parent_dir(argv[2], tod, sizeof(tod));
  char base[256];
  t9p_get_basename(argv[2], base, sizeof(base));
  
  t9p_handle_t dh = t9p_open_handle(ctx, NULL, tod);
  if (!dh) {
    printf("%s not exist!\n", tod);
    return;
  }
  
  t9p_handle_t src = t9p_open_handle(ctx, NULL, argv[1]);
  if (!src) {
    printf("%s not exist!\n", argv[1]);
    t9p_close_handle(ctx, dh);
    return;
  }
  
  t9p_rename(ctx, dh, src, base);
  
  t9p_close_handle(ctx, src);
  t9p_close_handle(ctx, dh);
}

void help_cmd(int argc, const char* const* argv);

static int
do_init()
{
  t9p_transport_t trans;
  if (t9p_init_tcp_transport(&trans) < 0) {
    printf("tcp unsupported\n");
    return -1;
  }

  t9p_opts_t opts;
  t9p_opts_init(&opts);
  opts.log_level = T9P_LOG_DEBUG;
  opts.uid = uid;
  strcpy(opts.user, user);

  ctx = t9p_init(&trans, &opts, remotePath, ipAddr, mntpt);
  if (!ctx) {
    printf("t9p init failed, exiting...\n");
    return -1;
  }

  return 0;
}

static void
connect_cmd(int argc, const char* const* argv)
{
  if (argc < 5) {
    printf("usage: connect ip remotePath mntpt user\n");
    return;
  }

  strcpy(ipAddr, argv[1]);
  strcpy(remotePath, argv[2]);
  strcpy(mntpt, argv[3]);
  strcpy(user, argv[4]);

  if (do_init() < 0) {
    printf("error while initting\n");
  }

  snprintf(prompt, sizeof(prompt), "%s> ", ipAddr);
}

static void
stats_cmd(int argc, const char* const* argv)
{
  if (!check_connection())
    return;
  
  struct t9p_stats st = t9p_get_stats(ctx);
  printf("send_cnt: %d\n", (int)st.send_cnt);
  printf("send_errs: %d\n", (int)st.send_errs);
  printf("recv_cnt: %d\n", (int)st.recv_cnt);
  printf("recv_errs: %d\n", (int)st.recv_errs);
  printf("total_bytes_sent: %llu\n", (unsigned long long)st.total_bytes_send);
  printf("total_bytes_recv: %llu\n", (unsigned long long)st.total_bytes_recv);
  printf("message counts:\n");
  for (int i = 0; i < T9P_TYPE_Tmax; ++i) {
    const char* n = t9p_type_string(i);
    if (n)
      printf(" %s: %d\n", n, (int)st.msg_counts[i]);
  }
}

struct command
{
  const char* name;
  void (*func)(int argc, const char* const* argv);
};

struct command COMMANDS[] = {
  {"connect", connect_cmd},
  {"hopen", hopen_cmd},
  {"exit", exit_cmd},
  {"cat", cat_cmd},
  {"put", put_cmd},
  {"getattr", getattr_cmd},
  {"create", create_cmd},
  {"rm", rm_cmd},
  {"mkdir", mkdir_cmd},
  {"statfs", statfs_cmd},
  {"readlink", readlink_cmd},
  {"symlink", symlink_cmd},
  {"ls", ls},
  {"unlink", unlink_cmd},
  {"mv", mv_cmd},
  {"touch", touch_cmd},
  {"truncate", truncate_cmd},
  {"lsdir", lsdirent_cmd},
  {"link", link_cmd},
  {"rename", rename_cmd},
  {"stats", stats_cmd},
  {"md5", md5_cmd},
  {"help", help_cmd},
  {0, 0}
};

void
help_cmd(int argc, const char* const* argv)
{
  for (int i = 0; i < (sizeof(COMMANDS) / sizeof(COMMANDS[0])) - 1; ++i)
    printf("%s\n", COMMANDS[i].name);
}

#ifndef HAVE_READLINE
static char*
readline(const char* prompt)
{
  printf("%s", prompt);
  fflush(stdout);
  char* buf = malloc(1024);
  buf[0] = 0;
  do {
    fgets(buf, 1024, stdin);
    usleep(1000);
  } while (buf[0] == 0);
  return buf;
}
#endif

int
main(int argc, char** argv)
{
  int opt;
  while ((opt = getopt(argc, argv, "hu:a:m:i:")) != -1) {
    switch (opt) {
    case 'u':
      strcpy(user, optarg);
      break;
    case 'a':
      strcpy(remotePath, optarg);
      break;
    case 'm':
      strcpy(mntpt, optarg);
      break;
    case 'i':
      uid = atoi(optarg);
      break;
    case 'h':
      usage();
      break;
    default:
      break;
    }
  }

  if (optind < argc)
    strcpy(ipAddr, argv[optind]);

  if (*ipAddr && do_init() < 0)
    return -1;

  if (!*ipAddr)
    printf("Use the connect command to begin\n");

#ifdef HAVE_READLINE
  rl_initialize();
#endif

  snprintf(prompt, sizeof(prompt), "%s> ", ipAddr);

  char* ptr = NULL;

  while (run && (ptr = readline(prompt)) != NULL) {
    if (!ptr)
      continue;
#ifdef HAVE_READLINE
    add_history(ptr);
#endif
    const char* comps[256] = {0};
    int n = 0;
    for (char* c = ptr; *c; c++) {
      if (*c == '"' || *c == '\'') {
        comps[n++] = ++c;
        while (*c && *c != '"' && *c != '\'')
          c++;
        *c = 0;
        if (*c)
          c++;
      } else if (!isspace(*c)) {
        comps[n++] = c;
        while (*c && !isspace(*c))
          c++;
        *c = 0;
      } else {
        *c = 0;
      }
    }

    if (n > 0) {
      int found = 0;
      for (struct command* cmd = COMMANDS; cmd->name; cmd++) {
        if (!strcmp(cmd->name, comps[0])) {
          cmd->func(n, comps);
          found = 1;
          break;
        }
      }

      if (!found) {
        printf("No such command '%s'\n", comps[0]);
      }
    }

    free(ptr);
    ptr = NULL;
  }

#ifndef T9P_NO_MEMTRACK
  /* malloc and co. will reserve more space than necessary, don't rely on exact values */
  printf(
    "Allocations: %d (%u bytes total, %u bytes requested)\n",
    atomic_load_u32(&g_t9p_memtrack_ctx.total_alloc_calls),
    atomic_load_u32(&g_t9p_memtrack_ctx.total_allocd_bytes),
    atomic_load_u32(&g_t9p_memtrack_ctx.total_allocd_bytes_requested)
  );
  printf(
    "Frees:       %d (%u bytes total)\n",
    atomic_load_u32(&g_t9p_memtrack_ctx.total_free_calls),
    atomic_load_u32(&g_t9p_memtrack_ctx.total_freed_bytes)
  );
#endif

  if (ctx)
    t9p_shutdown(ctx);
}
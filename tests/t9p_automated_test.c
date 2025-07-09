/**
 * ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: Automated test code for RTEMS (and other platforms...)
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
#include <stdio.h>
#include <rtems.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>

#if __RTEMS_MAJOR__ >= 6
#include <sys/limits.h>
#else
#include <rtems.h>
#include <rtems/system.h>
#include <rtems/libcsupport.h>
#endif

#include <rtems/score/heap.h>
#include <rtems/score/wkspace.h>
#include <rtems/score/apimutex.h>
#include <rtems/score/protectedheap.h>

#include "t9p.h"
#include "../src/t9p_platform.h"

#define CHECK(_x, ...) \
  if ((r = (_x)(__VA_ARGS__)) < 0) { \
    printf("*** %s:%u: %s: %s\n", __FUNCTION__, __LINE__, #_x , strerror(errno)); \
    ++fails; \
  }

static void
result_banner(int f)
{
  printf("*********************************************\n");
  if (f != 0)
    printf(" TEST FAILURE DETECTED!!!!\n");
  else
    printf(" TESTS PASSED\n");
  printf("*********************************************\n");
}

static int
file_exists(const char* path)
{
  struct stat st;
  if (stat(path, &st) < 0)
    return 0;
  return 1;
}

static double
time_now()
{
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return tp.tv_sec + tp.tv_nsec / 1e9;
}

static int
run_hog(void* param)
{
  int fails = 0;
  ssize_t l;
  const char* path = param;
  int fd = open(path, O_RDWR | O_CREAT, 0644);

  if (fd < 0) {
    printf("ERROR: could not open %s: %s\n", path, strerror(errno));
    return -1;
  }
  
  int goofy[64];
  int og[64];
  for (int i = 0; i < sizeof(goofy) / 4; ++i) {
    goofy[i] = i*i;
  }
  memcpy(og, goofy, sizeof(goofy));

  for (int i = 0; i < 32; ++i) {
    size_t l;
    if ((l = write(fd, goofy, sizeof(goofy))) != sizeof(goofy))
      printf("ERR: only wrote %ld out of %ld bytes\n", l, sizeof(goofy));
    printf("Wrote %ld bytes\n", sizeof(goofy));
  }

  if ((l = lseek(fd, 0, SEEK_SET)) < 0) {
    perror("lseek failed");
  }

  for (int i = 0; i < 32; ++i) {
    if ((l = read(fd, goofy, sizeof(goofy))) != sizeof(goofy))
      printf("ERR: only read %ld out of %ld bytes\n", l, sizeof(goofy));
    for (int x = 0; x < sizeof(og)/4; ++x) {
      if (goofy[x] != og[x]) {
        printf("  mismatch!! got '0x%X' expect '0x%X'\n", goofy[x], og[x]);
      }
    }
    printf("Read %ld bytes\n", sizeof(goofy));
  }

  close(fd);

  result_banner(fails);

  return 0;
}

int
t9p_run_trunc_test(const char* path)
{
  int r;
  if (!path) {
    printf("USAGE: t9p_run_trunc_test PATH\n");
    return -1;
  }

  printf("===============> TRUNC TEST <===============\n");

  int fails = 0;

  int fd = open(path, O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    perror("*** open failed");
    fails++;
  }
  else {
    char buf[200];
    if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
      perror("*** write failed");
      fails++;
    }
    close(fd);
  }

  CHECK(truncate, path, 128);
  
  struct stat st = {0};
  
  CHECK(stat, path, &st);

  if (st.st_size != 128) {
    printf("*** truncate failed."
      "wanted trunc at %d bytes, but stat says %lld\n", 128, st.st_size);
    fails++;
  }

  fd = open(path, O_TRUNC | O_RDWR);
  if (fd < 0) {
    perror("*** open with O_TRUNC failed");
    fails++;
  }
  
  CHECK(fstat, fd, &st);

  if (st.st_size != 0) {
    printf("*** O_TRUNC did not truncate?\n");
    fails++;
  }

  close(fd);

  result_banner(fails);
  return fails;
}

#define BLOCK_SIZE 512

int
t9p_run_write_perf_test(const char* path)
{
  if (!path) {
    printf("USAGE: t9p_run_write_perf_test PATH\n");
    return -1;
  }

  printf("===============> WRITE PERF TEST <===============\n");

  int fails = 0;
  int fd = open(path, O_RDWR | O_CREAT, 0644);
  if (fd < 0) {
    perror("open failed");
    result_banner(1);
    return -1;
  }

  char* buf = malloc(BLOCK_SIZE);
  for (int i = 0; i < BLOCK_SIZE; ++i) {
    buf[i] = "1234567890ABCDEF"[rand() & 0xF];
  }

  double cumWr = 0, cumRd = 0;
  double xferWr = 0, xferRd = 0;

  /** 1000 iterations of write */
  for (int j = 0; j < 100; ++j) {
    double start = time_now();

    for (int i = 0; i < 10; ++i) {
      lseek(fd, 0, SEEK_SET);
      ssize_t l = write(fd, buf, BLOCK_SIZE);
      if (l < 0) {
        fails++;
        perror("write failed");
        continue;
      }
      xferWr += l;
    }

    cumWr += time_now() - start;
    usleep(1000);

    fsync(fd);
  }

  /** 1000 iterations of read */
  for (int j = 0; j < 100; ++j) {
    double start = time_now();

    for (int i = 0; i < 10; ++i) {
      lseek(fd, 0, SEEK_SET);
      ssize_t l = read(fd, buf, BLOCK_SIZE);
      if (l < 0) {
        fails++;
        perror("read failed");
        continue;
      }
      xferRd += l;
    }

    cumRd += time_now() - start;
    usleep(1000);

    fsync(fd);
  }

  xferRd /= 1000000.;
  xferWr /= 1000000.;

  printf("Wrote %.2f MB (%.2f MB/s). Read %.2f MB (%.2f MB/s)\n", xferWr, xferWr / cumWr, xferRd, xferRd / cumRd);

  free(buf);
  close(fd);
  result_banner(fails);
  return fails;
}

static void*
t9p_threaded_write_perf_proc(void* p)
{
  printf("Starting hog...\n");
  t9p_run_write_perf_test(p);
  return NULL;
}

int
t9p_run_threaded_write_test()
{
  thread_t* threads[] = {
    thread_create(t9p_threaded_write_perf_proc, "/test/threadfile1.txt", T9P_THREAD_PRIO_LOW),
    thread_create(t9p_threaded_write_perf_proc, "/test/threadfile2.txt", T9P_THREAD_PRIO_MED),
    thread_create(t9p_threaded_write_perf_proc, "/test/threadfile3.txt", T9P_THREAD_PRIO_HIGH),
  };

  for (int i = 0; i < sizeof(threads)/sizeof(threads[0]); ++i) {
    thread_join(threads[i]);
  }

  return 0;
}

int
t9p_run_create_test(const char* path)
{
  int r;
  if (!path) {
    printf("USAGE: %s PATH\n", __FUNCTION__);
    return -1;
  }

  printf("===============> CREATE TEST <===============\n");

  int fails = 0;

  struct stat st;
  if (stat(path, &st) >= 0)
    CHECK(unlink, path);

  int fd = open(path, O_RDWR | O_CREAT, 0644);
  if (fd < 0) {
    perror("*** open failed");
    ++fails;
  }

  /** Check mode */
  CHECK(stat, path, &st);
  if (st.st_mode != 0644) {
    printf("*** Mode mistmatch. Expected %o, got %o\n", 0644, (unsigned)st.st_mode);
    ++fails;
  }

  close(fd);

  CHECK(stat, path, &st);

  result_banner(fails);
  return fails;
}

int
t9p_run_rename_test(const char* path)
{
  int r;
  if (!path) {
    printf("USAGE: %s PATH\n", __FUNCTION__);
    return -1;
  }
  printf("===============> RENAME TEST <===============\n");
  printf("path=%s\n", path);

  int fails = 0;

  /** Create the test file if it doesn't exist yet */
  struct stat st;
  if (stat(path, &st) < 0) {
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
      perror("*** failed to create test file");
      ++fails;
    }
    
    CHECK(write, fd, "hello world", strlen("hello world"));

    close(fd);
  }

  char newname[256];
  snprintf(newname, sizeof(newname), "%s.1", path);

  /** Rename! */
  CHECK(rename, path, newname);

  /** Remove it */
  CHECK(unlink, newname);

  result_banner(fails);
  return fails;
}

int
t9p_run_chmod_chown_test(const char* path)
{
  int r, fails = 0;
  if (!path) {
    printf("USAGE: %s PATH\n", path);
    return -1;
  }

  printf("===============> CHMOD/CHOWN TEST <===============\n");

  /** Create file if it doesnt exist already */
  struct stat st;
  if (stat(path, &st) < 0) {
    CHECK(creat, path, 0644);
  }

  CHECK(chmod, path, 0777);

  CHECK(stat, path, &st);
  if ((st.st_mode & 0777) != 0777) {
    printf("*** expected %o mode, got %o\n", 0777, (unsigned)(st.st_mode&0777));
    fails++;
  }

  CHECK(chmod, path, 0444);

  CHECK(stat, path, &st);
  if ((st.st_mode & 0777) != 0444) {
    printf("*** expected %o mode, got %o\n", 0444, (unsigned)(st.st_mode&0777));
    ++fails;
  }
  
  /** Make it writable for the next test in the list */
  CHECK(chmod, path, 0644);

#if 0 /** Not really a good way to test this in a portable manner */
  if (chown(path, 8412, 2211) < 0) {
    perror("*** chown failed");
    ++fails;
  }

  if (stat(path, &st) < 0) {
    perror("*** stat");
    ++fails;
  }
  else {
    if (st.st_uid != 8412) {
      printf("*** Expected uid=%d, got uid=%d\n", 8412, st.st_uid);
      ++fails;
    }
    if (st.st_gid != 2211) {
      printf("*** Expected gid=%d, got gid=%d\n", 2211, st.st_gid);
      ++fails;
    }
  }
#endif

  result_banner(fails);
  return fails;
}

int
t9p_run_dir_test(const char* path)
{
  if (!path) {
    printf("USAGE: %s PATH\n", __FUNCTION__);
    return -1;
  }

  int fails = 0, r;

  printf("===============> DIR TEST <===============\n");

  char dirPath[PATH_MAX];
  snprintf(dirPath, sizeof(dirPath), "%s/mydir", path);

  char filePath[PATH_MAX];
  snprintf(filePath, sizeof(filePath), "%s/myfile.txt", dirPath);

  if (file_exists(filePath))
    CHECK(unlink, filePath);

  /** Remove pre-existing dir or file */
  struct stat st;
  if (stat(dirPath, &st) >= 0) {
    if (S_ISDIR(st.st_mode)) {
      CHECK(rmdir, path);
    }
    else {
      CHECK(unlink, dirPath);
    }
  }

  CHECK(mkdir, dirPath, 0777);

  /** Create in the subdir */
  CHECK(creat, filePath, 0644);

  /** Attempt to actually do I/O */
  int fd = open(filePath, O_TRUNC | O_RDWR);
  if (fd < 0) {
    perror("*** open failed");
    ++fails;
  }
  else {
    char tow[] = "hello world";
    if (write(fd, tow, sizeof(tow)-1) < 0) {
      perror("*** write failed");
      ++fails;
    }

    lseek(fd, 0, SEEK_SET);

    char newb[128] = {0};
    ssize_t l;
    if ((l=read(fd, newb, sizeof(newb))) < 0) {
      perror("*** read failed");
      ++fails;
    }

    if (strcmp(newb, tow)) {
      printf("*** data mismatch!\n");
      ++fails;
    }

    close(fd);
  }
  
  CHECK(unlink, filePath);
  CHECK(rmdir, dirPath);

  result_banner(fails);
  return fails;
}

int
t9p_run_chdir_test(const char* path)
{
  int fails = 0, r;
  if (!path) {
    printf("USAGE: %s PATH\n", __FUNCTION__);
    return -1;
  }

  printf("===============> CHDIR TEST <===============\n");
  
  char dirPath[PATH_MAX];
  snprintf(dirPath, sizeof(dirPath), "%s/testdir", path);
  
  char filePath[PATH_MAX];
  snprintf(filePath, sizeof(filePath), "%s/myfile.txt", dirPath);
  
  if (!file_exists(dirPath))
    CHECK(mkdir, dirPath, 0777);
  
  CHECK(chdir, dirPath);
  
  if (file_exists("myfile.txt"))
    CHECK(unlink, "myfile.txt");

  CHECK(creat, "myfile.txt", 0777);
  if (!file_exists(filePath)) {
    printf("*** %s not found!\n", filePath);
    fails++;
  }

  /** Cleanup */
  CHECK(unlink, "myfile.txt");
  CHECK(chdir, path);
  CHECK(rmdir, dirPath);

  result_banner(fails);
  return fails;
}


int
run_c_api_test(const char* path)
{
  if (!path) {
    printf("USAGE: run_c_api_test PATH\n");
    return -1;
  }

  char srcF[256], dstF[256];
  snprintf(srcF, sizeof(srcF), "%s/myfile.1", path);
  snprintf(dstF, sizeof(dstF), "%s/myfile.2", path);

  unlink(srcF);
  unlink(dstF);

  FILE* fp = fopen(srcF, "wb");
  assert(fp);
  for (int i = 0; i < 65536; ++i) {
    fputc("0123456789abcdef"[rand() & 0xF], fp);
  }
  fclose(fp);
  
  int fd = open(srcF, O_RDONLY);
  assert(fd >= 0);
  
  fp = fdopen(fd, "rb");
  assert(fp);
  
  fclose(fp);
  
  fd = open(dstF, O_TRUNC | O_RDWR | O_CREAT, 0644);
  assert(fd >= 0);
  
  fp = fdopen(fd, "wb");
  assert(fp);
  
  fclose(fp);

  unlink(dstF);
  return 0;
}

int
run_auto_test(int iters)
{
  extern rtems_id RTEMS_Malloc_Heap;
  Heap_Information_block sib;
  rtems_region_get_information(RTEMS_Malloc_Heap, &sib);

  run_c_api_test("/test");

  t9p_run_threaded_write_test();

  int ok = 1;
  if (t9p_run_trunc_test("/test/myfile.txt") != 0)
    ok = 0;

  if (t9p_run_write_perf_test("/test/myfile.txt") != 0)
    ok = 0;

  if (t9p_run_chmod_chown_test("/test/myfile.txt") != 0)
    ok = 0;

  if (t9p_run_rename_test("/test/myfile.txt") != 0)
    ok = 0;

  if (t9p_run_dir_test("/test") != 0)
    ok = 0;

  if (t9p_run_chdir_test("/test") != 0)
    ok = 0;

  Heap_Information_block eib;
  rtems_region_get_information(RTEMS_Malloc_Heap, &eib);

  printf("Mem use at start: %.2fK/%.2fK\n", (sib.Used.total) / 1024.f, (sib.Used.total + sib.Free.total) / 1024.f);
  printf("Mem use at end: %.2fK/%2.fK\n", (eib.Used.total) / 1024.f, (eib.Used.total + eib.Free.total) / 1024.f);

  _Heap_Get_information(&_Workspace_Area, &sib);
  printf("Workspace usage: %2.fK/%.2fK\n", sib.Used.total / 1024.f, (sib.Used.total+sib.Free.total) / 1024.f);

  return ok ? 0 : -1;
}
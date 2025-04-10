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

#ifdef HAVE_CEXP
#include <cexpsh.h>
#endif

static void
result_banner(int f)
{
  printf("*******************************************\n");
  if (f != 0)
    printf(" TEST FAILURE DETECTED!!!!\n");
  else
    printf(" TESTS PASSED\n");
  printf("*******************************************\n");
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

void
t9p_run_trunc_test(const char* path)
{
  if (!path) {
    printf("USAGE: t9p_run_trunc_test PATH\n");
    return;
  }
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

  if (truncate("path", 128) < 0) {
    perror("*** truncate failed");
    fails++;
  }

  struct stat st = {0};
  if (stat("path", &st) < 0) {
    perror("*** stat failed");
    fails++;
  }

  if (st.st_size != 128) {
    printf("*** truncate failed."
      "wanted trunc at %d bytes, but stat says %lld\n", 128, st.st_size);
    fails++;
  }

  fd = open("path", O_TRUNC | O_RDWR);
  if (fd < 0) {
    perror("*** open with O_TRUNC failed");
    fails++;
  }

  if (fstat(fd, &st) < 0) {
    perror("*** fstat failed");
    fails++;
  }
  if (st.st_size != 0) {
    printf("*** O_TRUNC did not truncate?\n");
    fails++;
  }

  close(fd);

  result_banner(fails);
}

#ifdef HAVE_CEXP
CEXP_HELP_TAB_BEGIN(t9p_run_trunc_test)
	HELP(
"Run O_TRUNC/ftruncate/truncate unit test\n"
	void, t9p_run_trunc_test,  (const char* path)
	),
CEXP_HELP_TAB_END
#endif


#define BLOCK_SIZE 16384

void
t9p_run_write_perf_test(const char* path)
{
  if (!path) {
    printf("USAGE: t9p_run_write_perf_test PATH\n");
    return;
  }

  int fails = 0;
  int fd = open(path, O_RDWR | O_CREAT, 0644);
  if (fd < 0) {
    perror("open failed");
    result_banner(1);
    return;
  }

  char* buf = malloc(BLOCK_SIZE);
  for (int i = 0; i < BLOCK_SIZE; ++i) {
    buf[i] = "1234567890ABCDEF"[rand() & 0xF];
  }

  double xfer = 0;
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  for (int i = 0; i < 1000; ++i) {
    lseek(fd, 0, SEEK_SET);
    ssize_t l = write(fd, buf, BLOCK_SIZE);
    if (l < 0) {
      fails++;
      perror("write failed");
      continue;
    }
    xfer += l;
  }

  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);

  double dend = (double)end.tv_sec + (end.tv_nsec / 1e9);
  double dstart = start.tv_sec + (start.tv_nsec / 1e9);
  double elapsed = dend-dstart;

  printf("Transferred %.2f MiB in %.2f seconds (%.2f MiB/s)\n", xfer / (1024. * 1024.), elapsed,
    (xfer/(1024.*1024.)) / elapsed);


  free(buf);
  close(fd);
  result_banner(fails);
}

#ifdef HAVE_CEXP
CEXP_HELP_TAB_BEGIN(t9p_run_write_perf_test)
	HELP(
"Run write performance unit test\n"
	void, t9p_run_write_perf_test,  (const char* path)
	),
CEXP_HELP_TAB_END
#endif

int
run_auto_test(int iters)
{
  t9p_run_trunc_test("/test/myfile.txt");

  //for (int i = 0; i < iters; ++i)
  //  if (run_hog() < 0)
  //    return -1;

  t9p_run_write_perf_test("/test/myfile.txt");

  return 0;
}
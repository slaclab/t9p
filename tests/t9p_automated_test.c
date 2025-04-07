/**
 * Automatest test code for RTEMS
 */

#include <stdio.h>
#include <rtems.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

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
run_hog(void)
{
  int fails = 0;
  ssize_t l;
  const char* path = "/test/myfile.txt";
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

static void
do_trunc(void)
{
  int fails = 0;

  int fd = open("/test/myfile.txt", O_CREAT | O_RDWR, 0644);
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

  if (truncate("/test/myfile.txt", 128) < 0) {
    perror("*** truncate failed");
    fails++;
  }

  struct stat st = {0};
  if (stat("/test/myfile.txt", &st) < 0) {
    perror("*** stat failed");
    fails++;
  }

  if (st.st_size != 128) {
    printf("*** truncate failed."
      "wanted trunc at %d bytes, but stat says %lld\n", 128, st.st_size);
    fails++;
  }

  fd = open("/test/myfile.txt", O_TRUNC | O_RDWR);
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

int
run_auto_test(int iters)
{
  do_trunc();

  for (int i = 0; i < iters; ++i)
    if (run_hog() < 0)
      return -1;

  return 0;
}
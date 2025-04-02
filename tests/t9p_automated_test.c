/**
 * Automatest test code for RTEMS
 */

#include <stdio.h>
#include <rtems.h>

static int
run_hog(void)
{
  const char* path = "/test/myfile.txt";
  FILE* fp = fopen(path, "wb");

  if (!fp) {
    printf("ERROR: could not fopen %s\n", path);
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
    if ((l = fwrite(goofy, 1, sizeof(goofy), fp)) != sizeof(goofy))
      printf("ERR: only wrote %ld out of %ld blocks\n", l, sizeof(goofy));
    printf("Wrote %ld bytes\n", sizeof(goofy));
  }

  for (int i = 0; i < 32; ++i) {
    size_t l;
    if ((l = fread(goofy, 1, sizeof(goofy), fp)) != sizeof(goofy))
      printf("ERR: only read %ld out of %ld blocks\n", l, sizeof(goofy));
    if (memcmp(goofy, og, sizeof(og)) != 0) {
      printf("ERR: mismatch!\n");
    }
    printf("Read %ld bytes\n", sizeof(goofy));
  }

  fclose(fp);
  return 0;
}

int
run_auto_test(int iters)
{
  for (int i = 0; i < iters; ++i)
    if (run_hog() < 0)
      return -1;
  return 0;
}
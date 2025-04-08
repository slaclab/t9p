/** Cexpsh init code */

#include "t9p_rtems.h"

void
_cexpModuleInitialize(void *mod)
{
  t9p_rtems_register();
}

int
_cexpModuleFinalize(void *mod)
{
  return 0;
}

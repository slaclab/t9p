
# Common configuration
set(RTEMS_ARCH "powerpc")
set(RTEMS_VERSION 4)
set(RTEMS_BSP "mvme3100")
set(RTEMS_BSP_CFLAGS "-mcpu=powerpc -msoft-float -D__ppc_generic -O2 -g -Wimplicit-function-declaration -Wstrict-prototypes -Wnested-externs -DRTEMS_LEGACY_STACK=1")
include ("${CMAKE_CURRENT_LIST_DIR}/rtems.cmake")

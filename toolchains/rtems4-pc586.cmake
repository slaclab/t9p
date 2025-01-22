
# Common configuration
set(RTEMS_ARCH "i386")
set(RTEMS_VERSION 4)
set(RTEMS_BSP "ps586")
set(RTEMS_BSP_CFLAGS "-march=pentium -O2 -g -Wall -Wimplicit-function-declaration -Wstrict-prototypes -Wnested-externs -DRTEMS_LEGACY_STACK=1")
include ("${CMAKE_CURRENT_LIST_DIR}/rtems.cmake")

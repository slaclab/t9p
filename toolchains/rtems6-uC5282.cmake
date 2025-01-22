
# Common configuration
set(RTEMS_ARCH "m68k")
set(RTEMS_VERSION 6)
set(RTEMS_BSP "uC5282")
set(RTEMS_BSP_CFLAGS "-mcpu=5282 -DRTEMS_LIBBSD_STACK=1")
include ("${CMAKE_CURRENT_LIST_DIR}/rtems.cmake")

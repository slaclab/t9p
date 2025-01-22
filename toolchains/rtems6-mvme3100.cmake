
# Common configuration
set(RTEMS_ARCH "powerpc")
set(RTEMS_VERSION 6)
set(RTEMS_BSP "mvme3100")
set(RTEMS_BSP_CFLAGS "-mcpu=powerpc -msoft-float -DRTEMS_LIBBSD_STACK=1")
include ("${CMAKE_CURRENT_LIST_DIR}/rtems.cmake")

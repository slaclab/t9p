
# Common configuration
set(RTEMS_ARCH "powerpc")
set(RTEMS_VERSION 6)
set(RTEMS_BSP "psim")
set(RTEMS_BSP_CFLAGS "-Dppc603e -meabi -mcpu=603e -msdata=sysv -DRTEMS_LIBBSD_STACK=1")
include ("${CMAKE_CURRENT_LIST_DIR}/rtems.cmake")

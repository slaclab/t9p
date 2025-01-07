
# Common configuration
set(RTEMS_ARCH "powerpc")
set(RTEMS_VERSION 6)
set(RTEMS_BSP "beatnik")
set(RTEMS_BSP_CFLAGS "-mcpu=7400")
include ("${CMAKE_CURRENT_LIST_DIR}/rtems.cmake")

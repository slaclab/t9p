
# Common configuration
set(RTEMS_ARCH "arm")
set(RTEMS_VERSION 6)
set(RTEMS_BSP "xilinx_zynq_a9_qemu")
set(RTEMS_BSP_CFLAGS "-march=armv7-a -mthumb -mfpu=neon -mfloat-abi=hard -mtune=cortex-a9 -DRTEMS_LIBBSD_STACK=1")
include ("${CMAKE_CURRENT_LIST_DIR}/rtems.cmake")

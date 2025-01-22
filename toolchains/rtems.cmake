set(CMAKE_SYSTEM_NAME "RTEMS")
set(CMAKE_SYSTEM_PROCESSOR "powerpc")

set(CMAKE_CROSSCOMPILING ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (NOT DEFINED RTEMS_VERSION)
    message(WARNING "RTEMS_VERSION not set, defaulting to 6.0")
    set(RTEMS_VERSION 6)
endif()

# RTEMS 4.X doesn't use a version prefix on the tool, i.e. powerpc-rtems-gcc instead of powerpc-rtems6-gcc
if (NOT DEFINED RTEMS_TOOL_VERSION AND NOT "${RTEMS_VERSION}" STREQUAL "4")
    set(RTEMS_TOOL_VERSION "${RTEMS_VERSION}")
endif()

if (NOT DEFINED RTEMS_ARCH)
    message(FATAL_ERROR "RTEMS_ARCH must be provided by the including toolchain file")
endif()

#
# Compiler configuration
#
set(CMAKE_C_COMPILER "${RTEMS_ARCH}-rtems${RTEMS_TOOL_VERSION}-gcc")
set(CMAKE_CXX_COMPILER "${RTEMS_ARCH}-rtems${RTEMS_TOOL_VERSION}-g++")
set(CMAKE_LINKER "${RTEMS_ARCH}-rtems${RTEMS_TOOL_VERSION}-ld")
set(CMAKE_AR "${RTEMS_ARCH}-rtems${RTEMS_TOOL_VERSION}-ar")
if (DEFINED RTEMS_TOP)
    if (NOT DEFINED HOST_DIR)
        if (EXISTS "${RTEMS_TOP}/host/linux-x86_64")
            set(HOST_DIR "linux-x86_64")
        elseif (EXISTS "${RTEMS_TOP}/host/amd64_linux26")
            set(HOST_DIR "amd64_linux26")
        else()
            message(FATAL_ERROR "Unable to determine HOST_DIR")
        endif()
    endif()

    set(CMAKE_C_COMPILER "${RTEMS_TOP}/host/${HOST_DIR}/bin/${CMAKE_C_COMPILER}")
    set(CMAKE_CXX_COMPILER "${RTEMS_TOP}/host/${HOST_DIR}/bin/${CMAKE_CXX_COMPILER}")
    set(CMAKE_LINKER "${RTEMS_TOP}/host/${HOST_DIR}/bin/${CMAKE_LINKER}")
    set(CMAKE_AR "${RTEMS_TOP}/host/${HOST_DIR}/bin/${CMAKE_AR}")
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# When testing ${CMAKE_C[XX]_COMPILER} functionality, don't try to link a test application
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

#
# BSP specific compiler flags
#
set(RTEMS_CFLAGS "${RTEMS_BSP_CFLAGS} -ffunction-sections -fdata-sections -O2 -g -isystem${RTEMS_TOP}/target/rtems/${RTEMS_ARCH}-rtems${RTEMS_TOOL_VERSION}/${RTEMS_BSP}/lib/include")
set(RTEMS_LDFLAGS "-qrtems -Wl,--gc-sections -B${RTEMS_TOP}/target/rtems/${RTEMS_ARCH}-rtems${RTEMS_TOOL_VERSION}/${RTEMS_BSP}/lib")

set(CMAKE_C_FLAGS "${RTEMS_CFLAGS}")
set(CMAKE_CXX_FLAGS "${RTEMS_CFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${RTEMS_LDFLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${RTEMS_LDFLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${RTEMS_LDFLAGS}")

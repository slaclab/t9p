cmake_minimum_required(VERSION 3.10)
project(t9p C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_VERBOSE_MAKEFILE ON)

option(T9P_NO_MEMTRACK "Disable tracking allocations and frees" OFF)

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "RTEMS")
    include(rtems-tools/cmake/rtems.cmake)
    rtems_cmake_init()
endif()

set(T9P_SOURCES
    "src/t9p.c"
    "src/t9p_mem.c"
    "src/t9proto.c"
    "src/t9p_posix.c"
)

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "RTEMS")
    set(T9P_PLATFORM_SOURCES
        "src/t9p_rtems.c"
    )
endif()

# Main t9p library
add_library(
    t9p STATIC
    ${T9P_SOURCES}
)

set(WARN_FLAGS
    "-Wreturn-type -Werror=return-type -Wno-strict-prototypes -Werror=implicit-function-declaration"
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g2 ${WARN_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g2")

if(T9P_NO_MEMTRACK)
    target_compile_definitions(t9p PUBLIC T9P_NO_MEMTRACK)
endif()

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "RTEMS")
    execute_process(COMMAND id -u OUTPUT_VARIABLE RTEMS_TEST_UID OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND id -g OUTPUT_VARIABLE RTEMS_TEST_GID OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(RTEMS_TEST_PATH "${CMAKE_CURRENT_LIST_DIR}")

    configure_file(tests/rtems_test_cfg.h.in ${CMAKE_CURRENT_BINARY_DIR}/rtems_test_cfg.h)

    # RTEMS test code
    add_executable(
        t9p_rtems_test
        "tests/t9p_rtems_test.c"
        "tests/t9p_cmd.c"
        "tests/t9p_automated_test.c"
        ${T9P_PLATFORM_SOURCES}
    )

    target_link_libraries(
        t9p_rtems_test PRIVATE
        t9p
        rtemsbsp
        rtemscpu
        m
    )

    if ("${RTEMS_NETWORK_STACK}" STREQUAL "BSD")
        target_link_libraries(
            t9p_rtems_test PRIVATE

            bsd
            debugger
            m
        )
    endif()

    target_include_directories(
        t9p_rtems_test PRIVATE
        "src"
        "${CMAKE_CURRENT_BINARY_DIR}"
    )
else()
    # Threaded test executable
    add_executable(
        t9p_threaded_test
        "tests/t9p_threaded_test.c"
        ${T9P_PLATFORM_SOURCES}
    )

    target_link_libraries(
        t9p_threaded_test PRIVATE t9p
    )

    target_include_directories(
        t9p_threaded_test PRIVATE
        "src"
    )

    # Interactive test
    add_executable(
        t9p_cmd
        "tests/t9p_cmd.c"
        ${T9P_PLATFORM_SOURCES}
    )

    target_include_directories(
        t9p_cmd PRIVATE
        "src"
    )

    if ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
        target_link_libraries(t9p_cmd PRIVATE readline)
        target_compile_definitions(t9p_cmd PRIVATE HAVE_READLINE)
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
    endif()

    target_link_libraries(
        t9p_cmd PRIVATE t9p md
    )
endif()

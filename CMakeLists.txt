cmake_minimum_required(VERSION 3.10)
project(t9p C)

set(CMAKE_C_STANDARD 99)

set(T9P_SOURCES
    "src/t9p.c"
    "src/t9proto.c"
)

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "RTEMS")
    set(T9P_PLATFORM_SOURCES
        "src/t9p_rtems.c"
    )
else()
    set(T9P_PLATFORM_SOURCES
        "src/t9p_posix.c"
    )
endif()

# Main t9p library
add_library(
    t9p STATIC
    ${T9P_SOURCES}
)

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "RTEMS")
    # RTEMS test code
    add_executable(
        t9p_rtems_test
        "tests/t9p_rtems_test.c"
        "tests/t9p_cmd.c"
        ${T9P_PLATFORM_SOURCES}
    )

    target_link_libraries(
        t9p_rtems_test PRIVATE
        t9p
        rtemsbsp
        rtemscpu
        bsd
        debugger
        m
    )

    target_include_directories(
        t9p_rtems_test PRIVATE
        "src"
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

    target_link_libraries(
        t9p_cmd PRIVATE t9p readline
    )
endif()

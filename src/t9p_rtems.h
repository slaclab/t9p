/**
 * Public definitions for RTEMS implementation of t9p
 */

#pragma once

#include "t9p.h"

#define RTEMS_FILESYSTEM_TYPE_9P "9p"

typedef enum t9p_rtems_trans {
    t9p_rtems_trans_tcp = 0,
} t9p_rtems_trans_t;

typedef struct t9p_rtems_mount_opts {
    t9p_opts_t opts;
    char remotePath[512];
    char ip[128];
    t9p_rtems_trans_t transport;
} t9p_rtems_mount_opts_t;

/**
 * \brief Registers the t9p file system
 */
int t9p_rtems_register();

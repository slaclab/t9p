/**
 * Public definitions for RTEMS implementation of t9p
 */

#pragma once

#include "t9p.h"

#define RTEMS_FILESYSTEM_TYPE_9P "9p"

typedef enum t9p_rtems_trans
{
  T9P_RTEMS_TRANS_TCP = 0,
} t9p_rtems_trans_t;

typedef enum t9p_rtems_ioctl
{
  T9P_RTEMS_IOCTL_GET_LOG_LEVEL = 0,
  T9P_RTEMS_IOCTL_SET_LOG_LEVEL,
  T9P_RTEMS_IOCTL_GET_IOUNIT,
  T9P_RTEMS_IOCTL_GET_FID,
  T9P_RTEMS_IOCTL_GET_FID_COUNT, 
} t9p_rtems_ioctl_t;

typedef struct t9p_rtems_mount_opts
{
  t9p_opts_t opts;
  char remotePath[512];
  char ip[128];
  t9p_rtems_trans_t transport;
} t9p_rtems_mount_opts_t;

/**
 * \brief Registers the t9p file system
 */
int t9p_rtems_register();

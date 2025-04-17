/**
 * ----------------------------------------------------------------------------
 * Company    : SLAC National Accelerator Laboratory
 * ----------------------------------------------------------------------------
 * Description: Public definitions for t9p's RTEMS support
 * ----------------------------------------------------------------------------
 * This file is part of 't9p'. It is subject to the license terms in the
 * LICENSE.txt file found in the top-level directory of this distribution,
 * and at:
 *    https://confluence.slac.stanford.edu/display/ppareg/LICENSE.html.
 * No part of 't9p', including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE.txt file.
 * ----------------------------------------------------------------------------
 **/
#pragma once

#include "t9p.h"

#define RTEMS_FILESYSTEM_TYPE_9P "9p"

typedef enum t9p_rtems_trans
{
  T9P_RTEMS_TRANS_TCP = 0,
} t9p_rtems_trans_t;

typedef enum t9p_rtems_ioctl
{
  T9P_RTEMS_IOCTL_GET_LOG_LEVEL = 0,/** int */
  T9P_RTEMS_IOCTL_SET_LOG_LEVEL,    /** int */
  T9P_RTEMS_IOCTL_GET_IOUNIT,       /** uint32_t */
  T9P_RTEMS_IOCTL_GET_FID,          /** uint32_t */
  T9P_RTEMS_IOCTL_GET_FID_COUNT,    /** int */
  T9P_RTEMS_IOCTL_GET_CONTEXT,      /** void* */
  T9P_RTEMS_IOCTL_GET_QID,          /** qid_t */
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

/**
 * Black box printf (direct printing to serial console)
 */
int bb_printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

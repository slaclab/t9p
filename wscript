#!/usr/bin/env python3
# ----------------------------------------------------------------------------
# Company    : SLAC National Accelerator Laboratory
# ----------------------------------------------------------------------------
# Description : Waf build script
# ----------------------------------------------------------------------------
# This file is part of the t9p package. It is subject to
# the license terms in the LICENSE.txt file found in the top-level directory
# of this distribution and at:
#    https://confluence.slac.stanford.edu/display/ppareg/LICENSE.html.
# No part of the t9p package, including this file, may be
# copied, modified, propagated, or distributed except according to the terms
# contained in the LICENSE.txt file.
# ----------------------------------------------------------------------------

from rtems_waf import rtems
import os

# Configuration header for test applications
CONFIGURE = f"""
#pragma once

#define RTEMS_TEST_UID "{os.getuid()}"
#define RTEMS_TEST_GID "{os.getgid()}"
#define RTEMS_TEST_PATH "{os.path.abspath(os.path.dirname(os.getcwd()))}"
"""


def init(ctx):
    # RTEMS 4 lacks the version suffix after "rtems"
    if ctx.options.rtems_version == "4":
        ctx.options.rtems_version = ""
    rtems.init(ctx, version=ctx.options.rtems_version, long_commands=True)

def configure(conf):
    def bsp_configure(conf, ab):
        s = ab.split("-")
        # This define is omitted from the RTEMS4 pkgconfig files for some reason.
        if s[0] in ["powerpc"] and conf.options.rtems_version == "":
            conf.env.DEFINES += ['__ppc_generic']

    rtems.configure(conf, bsp_configure=bsp_configure)
    with open(conf.path.make_node("build/rtems_test_cfg.h").abspath(), "w") as f:
        f.write(CONFIGURE)

def options(opt):
    rtems.options(opt)

def build(bld):
    rtems.build(bld)

    bld.env.CFLAGS += [
        "-std=gnu99",
        "-g",
        "-Wreturn-type",
        "-Werror=return-type",
        "-Wno-strict-prototypes",
        "-Werror=implicit-function-declaration",
    ]

    bld.env.INCLUDES += ["src", "build"]

    if bld.env.RTEMS_NETWORKING == "Yes":
        bld.env.DEFINES += ["RTEMS_LEGACY_STACK"]
    else:
        bld.log("No networking support on this BSP")
        return

    bld(
        features="c cstlib",
        target="t9p",
        source=[
            "src/t9p.c",
            "src/t9p_mem.c",
            "src/t9proto.c",
            "src/t9p_posix.c",
            "src/t9p_rtems.c",
        ]
    )
    
    bld(
        features="c cprogram",
        target="t9p_rtems_test",
        source=[
            "tests/t9p_rtems_test.c",
            "tests/t9p_cmd.c",
            "tests/t9p_automated_test.c",
        ],
        use=[
            "t9p",
            "m",
            "c",
            "rtemsbsp",
            "rtemscpu",
        ]
    )
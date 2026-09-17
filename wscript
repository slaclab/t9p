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
from waflib.Build import BuildContext
import os

# Configuration header for test applications
CONFIGURE = f"""
#pragma once

#define RTEMS_TEST_UID "{os.getuid()}"
#define RTEMS_TEST_GID "{os.getgid()}"
#define RTEMS_TEST_PATH "{os.path.abspath(os.getcwd())}"
"""

def init(ctx):
    # RTEMS 4 lacks the version suffix after "rtems"
    if ctx.options.rtems_version == "4":
        ctx.options.rtems_version = ""
    if ctx.options.rtems_version == None:
        ctx.options.rtems_version = ""

    rtems.init(ctx, version=ctx.options.rtems_version, long_commands=True)

    from waflib.Build import BuildContext, CleanContext, \
        InstallContext, UninstallContext
    import waflib.Options

    # Create a build context for Linux
    class LinuxBuildContext(BuildContext):
        cmd = 'build-linux'
        fun = 'build_linux'
        variant = 'linux'

    # Create dummy contexts for Linux that just call into default behavior
    for t in [CleanContext, InstallContext, UninstallContext]:
        target = t.__name__.lower().replace('context', '') + '-linux'
        class context(t):
            cmd = target
            def execute(self):
                super().execute()

def configure(conf):
    # SLAC-style rtems_top configuration
    if conf.options.rtems_top is not None:
        if conf.options.rtems_version is None:
            conf.options.rtems_version = "7"
        conf.options.rtems_path = f'{conf.options.rtems_top}/target/rtems'
        conf.options.rtems_tools = f'{conf.options.rtems_top}/host/linux-x86_64'

    def bsp_configure(conf, ab):
        s = ab.split("-")
        # This define is omitted from the RTEMS4 pkgconfig files for some reason.
        if s[0] in ["powerpc"] and conf.options.rtems_version == "":
            conf.env.DEFINES += ['__ppc_generic']

    # Avoid configuring for RTEMS if we have no parameters pointing us at it
    if conf.options.rtems_top is not None or conf.options.rtems_tools is not None or conf.options.rtems_path is not None:
        rtems.configure(conf, bsp_configure=bsp_configure)
        conf.env.NO_RTEMS = False
    else:
        conf.env.NO_RTEMS = True

    with open(conf.path.make_node("build/rtems_test_cfg.h").abspath(), "w") as f:
        f.write(CONFIGURE)

    # Env for host builds
    env = conf.env.derive()
    conf.setenv('linux', env)
    conf.load('gcc')
    conf.load('g++')
    conf.load('gas')
    conf.setenv('', env)

def options(opt):
    rtems.options(opt)
    opt.add_option('--rtems-top', type=str, help='If set, uses the SLAC deployment style where rtems-tools and rtems are automatically detected')

def do_build(bld, is_cross):
    if is_cross:
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
    elif is_cross: # RTEMS_NETWORKING obviously doesnt need to be set for Linux builds
        print("No networking support on this BSP")
        return

    src = [
        "src/t9p.c",
        "src/t9p_mem.c",
        "src/t9proto.c",
        "src/t9p_posix.c",
    ]

    if is_cross:
        src += ["src/t9p_rtems.c"]

    bld(
        features="c cstlib",
        target="t9p",
        source=src
    )

    # RTEMS specific tests
    if is_cross:
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
        
    # Linux tests
    if not is_cross:
        bld(
            features="c cprogram",
            target="t9p_threaded_test",
            source=["tests/t9p_threaded_test.c"],
            use=["t9p"]
        )
        
        bld(
            features="c cprogram",
            target="t9p_cmd",
            source=["tests/t9p_cmd.c"],
            use=["t9p", "readline"]
        )
    
def build(bld):
    do_build(bld, True)

def build_linux(bld):
    do_build(bld, False)

def clean_linux(bld):
    clean(bld)

def install_linux(bld):
    install(bld)

def uninstall_linux(bld):
    uninstall(bld)

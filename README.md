# t9p

t9p is a relatively small (originally tiny) 9p2000.L client supporting RTEMS and Linux.
This client was designed with older RTEMS systems in mind (single core, <=512M memory, PowerPC or m68k).

t9p has been tested on the following platforms:
- Linux x86\_64
- mvme6100 (PowerPC G4, 512MB memory) RTEMS 4.10.2
- mvme3100 (PowerPC e500, 256MB memory) RTEMS 4.10.2
- uC5282 (Coldfire [m68k] V2, 16MB memory) RTEMS 4.10.2
- pc686 (i386 in Qemu) RTEMS 4.10.2

## Building

A C99 compliant compiler and a Python interpreter are required.

### Integrating with Other Projects

t9p's source files require no special compiler flags to build, so they can be trivially included in other projects.

Platform specific source files will need to be excluded manually (i.e. do not build `t9p_rtems.c` if you are targeting Linux).

### Building for RTEMS

`waf` is the preferred method for configuring and building t9p.

For RTEMS 7:
```sh
./waf configure --rtems="$HOME/dev/rtems/7.0/target/rtems" --rtems-tools="$HOME/dev/rtems/7.0/host/linux-x86_64" --rtems-version=7
```

For RTEMS 4:
```sh
./waf configure --rtems="$HOME/dev/rtems/4.10.2/target/rtems_p5" --rtems-tools="$HOME/dev/rtems/4.10.2/host/amd64_linux26" --rtems-version=4
```

**NOTE: You must create an empty directory `share/rtems` in your RTEMS prefix for waf to work with RTEMS 4.**

To compile, simply run:
```sh
./waf
```

And to install:
```sh
./waf install
```

### Building for Linux

When configuring for RTEMS, there will be a `build-linux` target available that will build the binaries for Linux:
```sh
./waf build-linux
```

If you're only interested in building for Linux, all arguments can be omitted from configure:
```sh
./waf configure
./waf build-linux
```

### Running the RTEMS Tests

Tests can be run under QEMU using the rtems-test.sh script.

For RTEMS 7:
```sh
./tests/rtems-test.sh -t i386-rtems7-pc686
```

and RTEMS 4 (which has no version suffix):
```sh
./tests/rtems-test.sh -t i386-rtems-pc686
```

**NOTE: you will need qemu-system-i386 to be installed and available in your PATH.**

## Target Environment

This client has been tested on the following targets:
- linux-x86_64
- linux-powerpc (testing only)
- RTEMS4/6-mvme3100 (PowerPC, soft FP)
- RTEMS4/6-mvme6100 (PowerPC, hard FP, altivec)
- RTEMS4/6-uC5282 (m68k, Coldfire ISA-A)

We will also need to test the client on:
- RTEMS4-svgm (PowerPC, soft FP [for VGM-1D] and hard+altivec [for VGM5])

Compilers:
- GCC 4.8.5 (RTEMS 4)
- GCC 13.2.0 (RTEMS 6)
- whatever else you are building with on host system

## Testing

### Targets

- Host system (linux-x86_64)
- qemu-powerpc-static (user-space Linux PowerPC emulation)
- rtems4-pc586 (QEMU)
- rtems6-pc686-qemu (QEMU)
- Actual hardware (mvme-3100, 6100, uC5282, svgm)

### Test Applications

- t9p_cmd: interactive cli for interacting with 9p
- t9p_threaded_test: threaded validation and performance testing
- t9p_rtems_test: Combines an automated test with t9p_cmd on RTEMS target

### Running Tests

1. Run ./tests/mktree.sh to create a test file system tree
2. Run ./tests/diod.sh in a new terminal
3. Run ./tests/t9p.sh, t9p-threaded.sh or rtems-test.sh

### Testing on Hardware

Integrated ssrlApps/GeSys build at: /sdf/group/cds/sw/epics/users/lorelli/rtems/4.10.2/src/ssrlApps

Set your nvram config to point at this image:
- mvme3100: /sdf/group/cds/sw/epics/users/lorelli/rtems/4.10.2/target/rtems_p5/ssrlApps_p4/powerpc-rtems/mvme3100/bin/rtems.ralf
- mvme6100: /sdf/group/cds/sw/epics/users/lorelli/rtems/4.10.2/target/rtems_p5/ssrlApps_p4/powerpc-rtems/beatnik/bin/rtems.ralf
- uC5282: TODO

t9p.obj gets loaded automatically on boot.

Mounting example:
```
p9Mount("16626.2211@134.79.217.70", "/scratch/lorelli/dummy-diod-fs", "/test")
```
Must be mounted with correct uid/gid. IP required right now, that needs fixing.

## Development Guidelines

- Use C99, plus GNU extensions (but don't do anything crazy with the GNU extensions)
- Generally follow the formatting guidelines
- Leave plenty of comments
- Validate your changes with manual testing before committing them
- Open issues for bugs+improvements

## Supported Calls

| Call | Implemented? | Notes |
|---|---|---|
| version       | Y |   |
| flush         |   |   |
| walk          | Y |   |
| read          | Y |   |
| write         | Y |   |
| clunk         | Y |   |
| remove        | Y |   |
| attach        | Y |   |
| auth          |   |   |
| statfs        | Y |   |
| lopen         | Y |   |
| lcreate       | Y |   |
| symlink       | Y |   |
| mknod         | Y |   |
| rename        | Y |   |
| readlink      | Y |   |
| getattr       | Y |   |
| setattr       | Y | trunc, chmod, chown, etc. wrappers too  |
| xattrwalk     |   |   |
| xattrcreate   |   |   |
| readdir       | Y |   |
| fsync         | Y |   |
| lock          |   |   |
| getlock       |   |   |
| link          | Y |   |
| mkdir         | Y |   |
| renameat      | Y |   |
| unlinkat      | Y |   |

The xattr calls are likely not going to be implemented, as they are not needed for the primary use-case of this client.

Implementation percentage: 22/28 (78%)

## Copyright Notice:
            
COPYRIGHT © SLAC National Accelerator Laboratory. All rights reserved. 
This work is supported [in part] by the U.S. Department of Energy, Office of Basic Energy Sciences under contract DE-AC02-76SF00515.

## Usage Restrictions:

Neither the name of the Leland Stanford Junior University, SLAC National Accelerator Laboratory, U.S. Department of Energy 
nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

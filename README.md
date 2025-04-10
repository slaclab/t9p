# t9p

t9p is a tiny 9p client that implements most of 9p.2000L

## Status

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

## Building

Including t9p in a different application may be done in a variety of different ways. You can opt to build and install the t9p libraries
to your system's library dir, or you can include the .c files directly in your project.

The .c files require no special defines or include directories to compile, and can be included as-is. Platform specific code is toggled on or off
using built-in compiler defines.


### Configuring

A makefile is provided that can automatically configure for all targets.
```sh
make -f Makefile.conf configure
```

If the RTEMS_TOP environment variable is set to the top of your RTEMS 6 install, Makefile.conf will automatically determine the available targets
and configure for those.

The build-cmake directory will contain all of the build subdirs. It is safe to delete.

### Building All


The makefile can also build all targets:
```sh
make -f Makefile.conf build
```

### Configuring Manually


#### Linux

```sh
cmake . -Bbuild
make -C build -j$(nproc)
```

Alternatively, you can use Makefile.conf (this will configure for all available targets):
```sh
make -f Makefile.conf configure
```

Makefile.conf will generate `build-cmake/build-linux-x86_64` for Linux.

#### RTEMS 6

Example shown is RTEMS6-pc686-qemu target.
```sh
cmake . -Bbuild-cmake/build-rtems6-pc686-qemu -DCMAKE_TOOLCHAIN_FILE=rtems-tools/toolchains/rtems6-pc686-qemu.cmake -DRTEMS_TOP=$HOME/dev/rtems/6.0
make -C build-cmake/build-rtems6-pc686-qemu -j$(nproc)
```

Running in QEMU is done with this script:
```sh
./tests/rtems-test.sh -t rtems6-pc686-qemu
```

NOTE: you will need qemu-system-i386 to be installed and available in your PATH.


#### RTEMS 4


Configuring for RTEMS 4.X is similar:
```sh
cmake . -Bbuild-cmake/build-rtems4-pc586 -DCMAKE_TOOLCHAIN_FILE=rtems-tools/toolchains/rtems4-pc586.cmake -DRTEMS_TOP=path/to/your/rtems/4.10.2
make -C build-cmake/build-rtems4-pc586
```

Running in QEMU can be done by the following script:

```sh
./tests/rtems-test.sh -t rtems4-pc586
```

NOTE: you will need qemu-system-i386 to be installed and available in your PATH.

## Target Environment

This needs to run on the following targets:
- linux-x86_64
- linux-powerpc (testing only)
- RTEMS4/6-mvme3100 (PowerPC, soft FP)
- RTEMS4/6-mvme6100 (PowerPC, hard FP, altivec)
- RTEMS4-svgm (PowerPC, soft FP and hard+altivec)
- RTEMS4/6-uC5282 (m68k)

Compilers:
- GCC 4.8.5 (RTEMS 4)
- GCC 13.2.0 (RTEMS 6)
- whatever else you are building with on host system

Important things to note:
- Must be endian-safe
- Must not rely on Linux-specific syscalls, if avoidable 
- Must not rely on RTEMS-specific syscalls, if avoidable

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

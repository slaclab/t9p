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
| mknod         |   |   |
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


Implementation percentage: 21/28 (75%)

## Building

Including t9p in a different application may be done in a variety of different ways. You can opt to build and install the t9p libraries
to your system's library dir, or you can include the .c files directly in your project.

The .c files require no special defines or include directories to compile, and can be included as-is. Platform specific code is toggled on or off
using built-in compiler defines.


### Configuring

A makefile is provided that can automatically configure for all targets.
```
make configure
```

This assumes you have RTEMS 6 available locally, as the RTEMS_TOP environment variable must be provided. This makefile needs some serious improvement though.

The build-cmake directory will contain all of the build subdirs. It is safe to delete.

### Building All


The makefile can also build all targets:
```
make build
```

### Configuring Manually


#### Linux
```
cmake . -Bbuild
make -C build -j$(nproc)
```

#### RTEMS

Example shown is RTEMS6-pc686-qemu target.
```
cmake . -Bbuild-rtems6-pc686-qemu -DCMAKE_TOOLCHAIN_FILE=rtems-tools/toolchains/rtems6-pc686-qemu.cmake -DRTEMS_TOP=$HOME/dev/rtems/6.0
make -C build-rtems6-pc686-qemu -j$(nproc)
```

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

## Development Guidelines

- Use C99, plus GNU extensions (but don't do anything crazy with the GNU extensions)
- Generally follow the formatting guidelines
- Leave plenty of comments
- Validate your changes with manual testing before committing them
- Open issues for bugs+improvements

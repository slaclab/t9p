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
| rename        |   |   |
| readlink      | Y |   |
| getattr       | Y |   |
| setattr       | Y | trunc, chmod, chown, etc. wrappers too  |
| xattrwalk     |   |   |
| xattrcreate   |   |   |
| readdir       | Y |   |
| fsync         | Y |   |
| lock          |   |   |
| getlock       |   |   |
| link          |   |   |
| mkdir         | Y |   |
| renameat      | Y |   |
| unlinkat      | Y |   |


Implementation percentage: 19/28 (67%)

## Building

Including t9p in a different application may be done in a variety of different ways. You can opt to build and install the t9p libraries
to your system's library dir, or you can include the .c files directly in your project.

The .c files require no special defines or include directories to compile, and can be included as-is. Platform specific code is toggled on or off
using built-in compiler defines.

### Linux

```
cmake . -Bbuild -GNinja
ninja -C build
```

### RTEMS

```
cmake . -Bbuild -GNinja -DCMAKE_TOOLCHAIN_FILE=toolchains/rtems6-xilinx_zynq_a9_qemu.cmake -DRTEMS_TOP=$HOME/dev/rtems/6.0
ninja -C build
```

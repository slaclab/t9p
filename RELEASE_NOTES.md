# Release Notes

## 0.10.0 Series

### 0.10.0 - XX-XX-20XX

* Fixed performance issue related to Nagle's algorithm on RTEMS 4.X's legacy networking stack
    * `TCP_NODELAY` is now toggled when needed to improve write and read performance.
* Added `prio=N` and `timeo=N` options to `mount(2)`
    * `prio` configures task priority, and `timeo` configures timeout duration.
* Improved logging
* Avoid allocating POSIX condition variables and mutexes for transactions when they're not needed.
* Fixed out-of-bounds read in `p9Mount` when the `uid.gid` portion of the IP string is not provided.
* Removed CMake build support
* Added waf build support with integration for RTEMS 4
* Fixed typo in verbose logging

## 0.9.0 Series

### 0.9.0 - 09-30-2025

* Initial release of t9p for RTEMS 4.X and Linux


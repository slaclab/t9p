#pragma once


#if 0
/* the file handlers table */
static
struct _rtems_filesystem_file_handlers_r nfs_file_file_handlers = {
                nfs_file_open,                  /* OPTIONAL; may be NULL */
                nfs_file_close,                 /* OPTIONAL; may be NULL */
                nfs_file_read,                  /* OPTIONAL; may be NULL */
                nfs_file_write,                 /* OPTIONAL; may be NULL */
                nfs_file_ioctl,                 /* OPTIONAL; may be NULL */
                nfs_file_lseek,                 /* OPTIONAL; may be NULL */
                nfs_fstat,                              /* OPTIONAL; may be NULL */
                nfs_fchmod,                             /* OPTIONAL; may be NULL */
                nfs_file_ftruncate,             /* OPTIONAL; may be NULL */
                nfs_file_fpathconf,             /* OPTIONAL; may be NULL - UNUSED */
                nfs_file_fsync,                 /* OPTIONAL; may be NULL */
                nfs_file_fdatasync,             /* OPTIONAL; may be NULL */
                nfs_file_fcntl,                 /* OPTIONAL; may be NULL */
                nfs_unlink,                             /* OPTIONAL; may be NULL */
};

/* the directory handlers table */
static
struct _rtems_filesystem_file_handlers_r nfs_dir_file_handlers = {
                nfs_dir_open,                   /* OPTIONAL; may be NULL */
                nfs_dir_close,                  /* OPTIONAL; may be NULL */
                nfs_dir_read,                   /* OPTIONAL; may be NULL */
                nfs_dir_write,                  /* OPTIONAL; may be NULL */
                nfs_dir_ioctl,                  /* OPTIONAL; may be NULL */
                nfs_dir_lseek,                  /* OPTIONAL; may be NULL */
                nfs_fstat,                              /* OPTIONAL; may be NULL */
                nfs_fchmod,                             /* OPTIONAL; may be NULL */
                nfs_dir_ftruncate,              /* OPTIONAL; may be NULL */
                nfs_dir_fpathconf,              /* OPTIONAL; may be NULL - UNUSED */
                nfs_dir_fsync,                  /* OPTIONAL; may be NULL */
                nfs_dir_fdatasync,              /* OPTIONAL; may be NULL */
                nfs_dir_fcntl,                  /* OPTIONAL; may be NULL */
                nfs_dir_rmnod,                          /* OPTIONAL; may be NULL */
};

/* the link handlers table */
static
struct _rtems_filesystem_file_handlers_r nfs_link_file_handlers = {
                nfs_link_open,                  /* OPTIONAL; may be NULL */
                nfs_link_close,                 /* OPTIONAL; may be NULL */
                nfs_link_read,                  /* OPTIONAL; may be NULL */
                nfs_link_write,                 /* OPTIONAL; may be NULL */
                nfs_link_ioctl,                 /* OPTIONAL; may be NULL */
                nfs_link_lseek,                 /* OPTIONAL; may be NULL */
                nfs_fstat,                              /* OPTIONAL; may be NULL */
                nfs_fchmod,                             /* OPTIONAL; may be NULL */
                nfs_link_ftruncate,             /* OPTIONAL; may be NULL */
                nfs_link_fpathconf,             /* OPTIONAL; may be NULL - UNUSED */
                nfs_link_fsync,                 /* OPTIONAL; may be NULL */
                nfs_link_fdatasync,             /* OPTIONAL; may be NULL */
                nfs_link_fcntl,                 /* OPTIONAL; may be NULL */
                nfs_unlink,                             /* OPTIONAL; may be NULL */
};

#endif
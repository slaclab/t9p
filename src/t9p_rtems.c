
#include "t9p_platform.h"

#include <rtems.h>
#include <rtems/thread.h>
#include <stdlib.h>
#include <rtems/libio.h>

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

/** Provide our own posix message queue */
//#define _T9P_NO_POSIX_MQ
#include "t9p_posix.c"

#if 0
struct _msg_queue_s {
    rtems_name name;
    rtems_id queue;
    size_t msgSize;
};

msg_queue_t* msg_queue_create(const char* id, size_t msgSize, size_t maxMsgs) {
    msg_queue_t* q = calloc(1, sizeof(msg_queue_t));
    q->name = rtems_build_name(id[0], id[1], id[2], id[3]);
    q->msgSize = msgSize;
    rtems_status_code status = rtems_message_queue_create(q->name, maxMsgs, msgSize, RTEMS_FIFO, &q->queue);
    if (status != RTEMS_SUCCESSFUL) {
        printf("Queue create failed: %d\n", status);
        free(q);
        return NULL;
    }
    return q;
}

void msg_queue_destroy(msg_queue_t* q) {
    rtems_message_queue_delete(q->queue);
    free(q);
}

int msg_queue_send(msg_queue_t* q, const void* data, size_t size) {
    assert(size == q->msgSize);
    return rtems_message_queue_send(q->queue, data, size) == RTEMS_SUCCESSFUL ? 0 : -1;
}

int msg_queue_recv(msg_queue_t* q, void* data, size_t* size) {
    assert(*size == q->msgSize);
    return rtems_message_queue_receive(q->queue, data, size, RTEMS_NO_WAIT, 0) == RTEMS_SUCCESSFUL ? 0 : -1;
}

#endif
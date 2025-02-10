
#include "t9p.h"
#include "t9p_platform.h"

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#define FILE_SIZE 4096

t9p_context_t* ctx;
int thr_run = 0;
thread_t** threads;

static void* thread_proc(void* p);

static void usage(const char* av0) {
    printf("%s -u user -a apath -m mntpt ip -n threads -t time\n", av0);
    exit(1);
}

int main(int argc, char** argv) {
    int opt;
    char user[128] = {0};
    char mntpoint[PATH_MAX] = {0};
    char ap[PATH_MAX] = {0};
    char ip[PATH_MAX] = {0};
    int uid = 0, thread_cnt = 1;
    float time = 10;
    while ((opt = getopt(argc, argv, "hu:a:m:i:n:t:")) != -1) {
        switch(opt) {
        case 'u':
            strcpy(user, optarg);
            break;
        case 'a':
            strcpy(ap, optarg);
            break;
        case 'm':
            strcpy(mntpoint, optarg);
            break;
        case 'i':
            uid = atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            break;
        case 'n':
            thread_cnt = atoi(optarg);
            break;
        case 't':
            time = atof(optarg);
            break;
        default:
            break;
        }
    }

    if (optind < argc)
        strcpy(ip, argv[optind]);

    if (!*ap || !*mntpoint || !*ip) {
        usage(argv[0]);
    }

    printf("Attempting to mount %s:%s at %s\n", ip, ap, mntpoint);

    t9p_transport_t trans;
    if (t9p_init_tcp_transport(&trans) < 0) {
        printf("tcp unsupported\n");
        return -1;
    }

    t9p_opts_t opts;
    t9p_opts_init(&opts);
    opts.log_level = T9P_LOG_DEBUG;
    opts.uid = uid;
    strcpy(opts.user, user);
    
    ctx = t9p_init(&trans, &opts, ap, ip, mntpoint);
    if (!ctx) {
        printf("Fail\n");
        return -1;
    }

    // Generate some file data...
    char buf[FILE_SIZE];
    t9p_handle_t h = t9p_open_handle(ctx, NULL, "b.txt");
    if (!h) {
        printf("failed to write b.txt!!\n");
        abort();
    }

    ssize_t l;
    if ((l = t9p_open(ctx, h, T9P_ORDWR | T9P_OTRUNC)) < 0) {
        printf("failed to open: ret=%ld\n", l);
        abort();
    }

    for (int i = 0; i < FILE_SIZE; ++i)
        buf[i] = rand() & 0xFF;

    if ((l = t9p_write(ctx, h, 0, FILE_SIZE, buf)) != FILE_SIZE) {
        printf("write failed: ret=%ld\n", l);
        abort();
    }
    t9p_close(h);
    t9p_close_handle(ctx, h);

    int v = 1;
    __atomic_store(&thr_run, &v, __ATOMIC_RELEASE);

    thread_t** threads = calloc(thread_cnt, sizeof(thread_t*));
    for (int i = 0; i < thread_cnt; ++i) {
        threads[i] = thread_create(thread_proc, ctx);
    }

    usleep(time * 1e6);

    v = 0;
    __atomic_store(&thr_run, &v, __ATOMIC_RELEASE);

    for (int i = 0; i < thread_cnt; ++i)
        thread_join(threads[i]);

    t9p_shutdown(ctx);
}

static void* thread_proc(void* p) {
    t9p_context_t* c = p;

    static int thread_num = 1;
    int me = thread_num++;

    int n;
    while (1) {
        __atomic_load(&thr_run, &n, __ATOMIC_ACQUIRE);
        if (!n)
            break;

        ssize_t n;
        t9p_handle_t h = t9p_open_handle(c, NULL, "b.txt");
        if (!h) {
            printf("Failed to open %s\n", "b.txt");
            abort();
        }

        if ((n = t9p_open(c, h, T9P_OREAD)) < 0) {
            printf("Failed to open: %s\n", strerror(n));
            t9p_close_handle(c, h);
            abort();
            continue;
        }

        char buf[FILE_SIZE];
        if ((n=t9p_read(c, h, 0, sizeof(buf), buf)) != sizeof(buf)) {
            printf("Failed to read!! got %ld\n", n);
            t9p_close(h);
            t9p_close_handle(c, h);
            abort();
            continue;
        }

        t9p_close(h);
        t9p_close_handle(c, h);

        usleep(1000);
    }

    return NULL;
}
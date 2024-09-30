
#include "t9p.h"

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <getopt.h>
#include <linux/limits.h>
#include <stdlib.h>

struct t9p_context* ctx;
int run = 1;

static void usage() {
    printf("t9p -u user -a apath -m mntpt ip\n");
    exit(1);
}

void ls(const char* loc) {

}

void hopen_cmd(int argc, const char* const* argv) {
    if (argc < 2) {
        printf("usage: hopen <path>\n");
        return;
    }

    if (!t9p_open_handle(ctx, NULL, argv[1])) {
        printf("Unable to open %s\n", argv[1]);
    }
    else {
        printf("Opened %s\n", argv[1]);
    }
}

void exit_cmd(int argc, const char* const* argv) {
    run = 0;
}

void cat_cmd(int argc, const char* const* argv) {
    if (argc < 2) {
        printf("usage: cat <path>\n");
        return;
    }

    t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
    if (!h) {
        printf("unable to open handle for %s\n", argv[1]);
        return;
    }

    if (t9p_open(ctx, h, T9P_OREAD) < 0) {
        printf("unable to open %s\n", argv[1]);
    }
    else {
        char buf[128];
        if (t9p_read(ctx, h, 0, 128, buf) < 0) {
            printf("unable to read %s\n", argv[1]);
        }
        else {
            buf[sizeof(buf)-1] = 0;
            puts(buf);
        }
    }

    t9p_close_handle(ctx, h);
}

void create_cmd(int argc, const char* const* argv) {
    if (argc < 2) {
        printf("usage: create <path>\n");
        return;
    }

    char dir[PATH_MAX];
    const char* name;
    strcpy(dir, argv[1]);
    char* d = strrchr(dir, '/');
    if (d) {
        name = d+1;
        *d = 0;
    }
    else {
        dir[0] = 0;
        name = argv[1];
    }

    t9p_handle_t parent = t9p_open_handle(ctx, NULL, dir);
    if (!parent) {
        printf("Unable to open dir %s\n", dir);
        return;
    }

    t9p_handle_t h;
    if (t9p_create(ctx, &h, parent, name, 0777, 1000, 0) < 0) {
        printf("Create failed\n");
    }
    t9p_close_handle(ctx, h);
    t9p_close_handle(ctx, parent);
}

void getattr_cmd(int argc, const char* const* argv) {
    if (argc < 2) {
        printf("usage: getattr <path>\n");
        return;
    }

    t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
    if (!h) {
        printf("open %s failed\n", argv[1]);
        return;
    }

    struct t9p_attr a;
    if (t9p_getattr(ctx, h, &a, T9P_GETATTR_ALL) < 0) {
        printf("getattr failed\n");
    }
    else {
        char mode[4];
        printf(" mode:          %d\n", a.mode);
        printf(" uid:           %d\n", a.uid);
        printf(" gid:           %d\n", a.gid);
        printf(" nlink:         %ld\n", a.nlink);
        printf(" rdev:          %ld\n", a.rdev);
        printf(" fsize:         %ld\n", a.fsize);
        printf(" blksize:       %ld\n", a.blksize);
        printf(" blocks:        %ld\n", a.blocks);
        printf(" atime_sec:     %ld\n", a.atime_sec);
        printf(" atime_nsec:    %ld\n", a.atime_nsec);
        printf(" mtime_sec:     %ld\n", a.mtime_sec);
        printf(" mtime_nsec:    %ld\n", a.mtime_nsec);
        printf(" ctime_sec:     %ld\n", a.ctime_sec);
        printf(" ctime_nsec:    %ld\n", a.ctime_nsec);
        printf(" btime_sec:     %ld\n", a.btime_sec);
        printf(" btime_nsec:    %ld\n", a.btime_nsec);
        printf(" gen:           %ld\n", a.gen);
        printf(" data_version:  %ld\n", a.data_version);
    }

    t9p_close_handle(ctx, h);
}

void put_cmd(int argc, const char* const* argv) {
    if (argc < 3) {
        printf("usage: put <path> <data_str>\n");
        return;
    }

    t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
    if (!h) {
        printf("unable to open handle for %s\n", argv[1]);
        return;
    }

    if (t9p_open(ctx, h, T9P_OWRITE | T9P_OTRUNC) < 0) {
        printf("unable to open %s for write\n", argv[1]);
    }
    else {
        ssize_t c;
        if ((c=t9p_write(ctx, h, 0, strlen(argv[2]), argv[2])) < 0) {
            printf("unable to write %s\n", argv[1]);
        }
        printf("wrote %ld bytes\n", c);
    }

    t9p_close_handle(ctx, h);
}

void rm_cmd(int argc, const char* const* argv) {
    if (argc < 2) {
        printf("usage: rm <path>\n");
        return;
    }

    t9p_handle_t h = t9p_open_handle(ctx, NULL, argv[1]);
    if (!h) {
        printf("unable to hopen for %s\n", argv[1]);
        return;
    }

    if (t9p_remove(ctx, h) == 0)
        printf("Removed %s\n", argv[1]);
}

struct command {
    const char* name;
    void (*func)(int argc, const char* const* argv);
};

struct command COMMANDS[] = {
    {"hopen", hopen_cmd},
    {"exit", exit_cmd},
    {"cat", cat_cmd},
    {"put", put_cmd},
    {"getattr", getattr_cmd},
    {"create", create_cmd},
    {"rm", rm_cmd},
    {0,0}
};

int main(int argc, char** argv) {
    int opt;
    char user[128] = {0};
    char mntpoint[PATH_MAX] = {0};
    char ap[PATH_MAX] = {0};
    char ip[PATH_MAX] = {0};
    int uid = 0;
    while ((opt = getopt(argc, argv, "hu:a:m:i:")) != -1) {
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
            usage();
            break;
        default:
            break;
        }
    }

    if (optind < argc)
        strcpy(ip, argv[optind]);

    if (!*ap || !*mntpoint || !*ip) {
        usage();
    }

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

    rl_initialize();

    char prompt[512];
    snprintf(prompt, sizeof(prompt), "%s> ", ip);

    char* ptr = NULL;
    while(run && (ptr = readline(prompt)) != NULL) {
        if (!ptr) continue;
        add_history(ptr);
        const char* comps[256] = {0};
        int n = 0;
        for (char* c = ptr; *c; c++) {
            if (*c == '"' || *c == '\'') {
                comps[n++] = ++c;
                while(*c && *c != '"' && *c != '\'') c++;
                *c = 0;
                if (*c) c++;
            }
            else if (!isspace(*c)) {
                comps[n++] = c;
                while (*c && !isspace(*c)) c++;
                *c = 0;
            }
            else {
                *c = 0;
            }
        }

        if (n > 0) {
            int found = 0;
            for (struct command* cmd = COMMANDS; cmd->name; cmd++) {
                if (!strcmp(cmd->name, comps[0])) {
                    cmd->func(n, comps);
                    found = 1;
                    break;
                }
            }

            if (!found) {
                printf("No such command '%s'\n", comps[0]);
            }
        }

        free(ptr);
        ptr = NULL;
    }

    t9p_shutdown(ctx);
}
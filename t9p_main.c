
#include "t9p.h"

#include <stdio.h>
#include <readline/readline.h>
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

struct command {
    const char* name;
    void (*func)(int argc, const char* const* argv);
};

struct command COMMANDS[] = {
    {"hopen", hopen_cmd},
    {"exit", exit_cmd},
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

    char* ptr = NULL;
    size_t len;
    ssize_t nread;
    while(run && (nread = getline(&ptr, &len, stdin)) != -1) {
        if (!ptr) continue;
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
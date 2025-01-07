

#include <rtems.h>
#include <machine/rtems-bsd-commands.h>
#include <rtems/shell.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/** From t9p_cmd.c */
extern int main(int, char**);

/** Configure network using libbsd */
static void configure_network()
{
    char* ifcmd[] = {
        "ifconfig",
        "if0",
        "up",
        "inet",
        "10.2.0.1",
        "netmask",
        "255.255.255.0"
    };
    if (rtems_bsd_command_ifconfig(RTEMS_BSD_ARGC(ifcmd), ifcmd) != EXIT_SUCCESS) {
        printf("rtems_bsd_command_ifconfig failed\n");
    }
}

static rtems_task Init(rtems_task_argument arg)
{
    printf("** t9p RTEMS test application\n");

    /** Configue settings for stdin */
    struct termios t;
    if (tcgetattr (fileno (stdin), &t) < 0) {
        printf ("tcgetattr failed: %s\n", strerror (errno));
        return;
    }
    t.c_iflag &= ~(IXOFF | IXON | IXANY);
    if (tcsetattr (fileno (stdin), TCSANOW, &t) < 0) {
        printf ("tcsetattr failed: %s\n", strerror (errno));
        return;
    }

    /** Configure network */
    configure_network();

    /** Generate files required by the shell */
    setuid(0);
    mkdir("/etc", 0777);
    chmod("/etc", 0777);
    rtems_shell_write_file("/etc/passwd", "rtems::1:1:RTEMS Application::/:/bin/sh\n");
    chmod("/etc/passwd", 0644);
    rtems_shell_write_file("/etc/group", "rtems:x:1:rtems\n");
    chmod("/etc/group", 0644);

    printf("Press s to open shell, any other key to continue\n");
    char b;
    b = getchar();
    if (b == 's') {
        rtems_shell_init_environment();
        rtems_status_code status = rtems_shell_init("SHLL", 0, 100, "/dev/console", true, true, NULL);
        if (status != RTEMS_SUCCESSFUL) {
            printf("** Error starting RTEMS shell!\n");
            exit(1);
        }
        while (1) {
            rtems_task_wake_after(rtems_clock_get_ticks_per_second());
        }
    }

    char* args[] = {"t9p_cmd"};
    int r = main(0, args);

    if (r != 0)
        printf("*** FAILED T9P CMD ***\n");
    else
        printf("** PASSED T9P CMD ***\n");

    exit(r);
}

#define CONFIGURE_INIT
#define CONFIGURE_APPLICATION_NEEDS_CLOCK_DRIVER
#define CONFIGURE_APPLICATION_NEEDS_CONSOLE_DRIVER
#define CONFIGURE_MAXIMUM_TASKS 12
#define CONFIGURE_RTEMS_INIT_TASKS_TABLE
#define CONFIGURE_MICROSECONDS_PER_TICK 1000
#define CONFIGURE_APPLICATION_NEEDS_LIBBLOCK
#define CONFIGURE_MAXIMUM_FILE_DESCRIPTORS 64

#include <rtems/confdefs.h>

#define CONFIGURE_SHELL_COMMANDS_INIT
#define CONFIGURE_SHELL_COMMANDS_ALL

#include <rtems/shellconfig.h>

#define RTEMS_BSD_CONFIG_BSP_CONFIG
#define RTEMS_BSD_CONFIG_INIT
#define RTEMS_BSD_CONFIG_NET_IF_VLAN

#include <machine/rtems-bsd-config.h>
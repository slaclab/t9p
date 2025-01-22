
#include <sys/types.h>
#include <rtems.h>
#ifndef RTEMS_LEGACY_STACK
#include <machine/rtems-bsd-commands.h>
#include <rtems/bsd.h>
#include <rtems/bsd/iface.h>
#include <rtems/bsd/bsd.h>
#endif
#include <rtems/shell.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bsp.h>

/** From t9p_cmd.c */
extern int main(int, char**);

/** Configure network using libbsd */
static void configure_network()
{
#if defined(__i386__)
    // glorious hack to stub out useless EEPROM check
    // which takes sooooo longggg w/ QEMU
    // Writes a 'ret' instruction to immediatly return to the caller
    extern void _bsd_e1000_validate_nvm_checksum(void);
    *(char*)&_bsd_e1000_validate_nvm_checksum = 0xc3;
#endif

    rtems_bsd_setlogpriority("debug");
    if (rtems_bsd_initialize() != RTEMS_SUCCESSFUL) {
        printf("rtems_bsd_initialize() failed\n");
        exit(EXIT_FAILURE);
    }

    rtems_bsd_ifconfig_lo0();

    char* ifcmd[] = {
        "ifconfig",
        "cgem0",
        "up",
        "inet",
        "10.2.0.1",
        "netmask",
        "255.255.255.0",
        NULL
    };
    if (rtems_bsd_command_ifconfig(RTEMS_BSD_ARGC(ifcmd), ifcmd) != EXIT_SUCCESS) {
        printf("rtems_bsd_command_ifconfig failed\n");
    }

    /** Display current network configuration */
    char* cmd[] = {"ifconfig", NULL};
    rtems_bsd_command_ifconfig(1, cmd);
}

static void* POSIX_Init(void* arg)
{
    printf("** t9p RTEMS test application\n");
    fprintf(stderr, "test\n");

    /** Configue settings for stdin */
    struct termios t;
    if (tcgetattr (fileno (stdin), &t) < 0) {
        printf ("tcgetattr failed: %s\n", strerror (errno));
        return NULL;
    }
    t.c_iflag &= ~(IXOFF | IXON | IXANY);
    if (tcsetattr (fileno (stdin), TCSANOW, &t) < 0) {
        printf ("tcsetattr failed: %s\n", strerror (errno));
        return NULL;
    }

    printf("cheese\n");

    rtems_shell_init_environment();

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
        rtems_status_code status = rtems_shell_init("shell", 8192, 100, "/dev/console", false, true, NULL);
        if (status != RTEMS_SUCCESSFUL) {
            printf("** Error starting RTEMS shell: %s\n", rtems_status_text(status));
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

/* Ensure that stdio goes to serial (so it can be captured) */
//#define USE_COM1_AS_CONSOLE 1
#if defined(__i386__) && !USE_COM1_AS_CONSOLE
#include <uart.h>
#if __RTEMS_MAJOR__ > 4
#include <libchip/serial.h>
#endif

extern int BSPPrintkPort;
void bsp_predriver_hook(void)
{
#if __RTEMS_MAJOR__ > 4
    Console_Port_Minor = BSP_CONSOLE_PORT_COM1;
#else
    BSPConsolePort = BSP_CONSOLE_PORT_COM1;

#endif
    BSPPrintkPort = BSP_CONSOLE_PORT_COM1;
}
#endif


/** POSIX configuration */
#define CONFIGURE_POSIX_INIT_THREAD_TABLE
#define CONFIGURE_POSIX_INIT_THREAD_ENTRY_POINT POSIX_Init
#define CONFIGURE_POSIX_INIT_THREAD_STACK_SIZE  (64*1024)

#define CONFIGURE_MAXIMUM_PERIODS 	5
#define CONFIGURE_MICROSECONDS_PER_TICK 10000
#define CONFIGURE_MALLOC_STATISTICS     1
/* MINIMUM_STACK_SIZE == 8K */
#define CONFIGURE_EXTRA_TASK_STACKS         (4000 * RTEMS_MINIMUM_STACK_SIZE)

#define CONFIGURE_FILESYSTEM_DEVFS
#define CONFIGURE_FILESYSTEM_NFS
#define CONFIGURE_FILESYSTEM_IMFS

#define CONFIGURE_USE_IMFS_AS_BASE_FILESYSTEM

#ifndef RTEMS_LEGACY_STACK
/** libbsd config */
#define RTEMS_BSD_CONFIG_BSP_CONFIG
#define RTEMS_BSD_CONFIG_INIT
#include <machine/rtems-bsd-config.h>
#endif

/** RTEMS config */
#define CONFIGURE_APPLICATION_NEEDS_CLOCK_DRIVER
#define CONFIGURE_APPLICATION_NEEDS_SIMPLE_CONSOLE_DRIVER
#define CONFIGURE_APPLICATION_NEEDS_STUB_DRIVER
#define CONFIGURE_APPLICATION_NEEDS_ZERO_DRIVER

#define CONFIGURE_MAXIMUM_FILE_DESCRIPTORS 64
#define CONFIGURE_IMFS_ENABLE_MKFIFO    2

#define CONFIGURE_MAXIMUM_NFS_MOUNTS 		3
#define CONFIGURE_MAXIMUM_USER_EXTENSIONS 	5

#define CONFIGURE_UNLIMITED_ALLOCATION_SIZE 32
#define CONFIGURE_UNLIMITED_OBJECTS
#define CONFIGURE_UNIFIED_WORK_AREAS

#define CONFIGURE_STACK_CHECKER_ENABLED

#define CONFIGURE_APPLICATION_NEEDS_LIBBLOCK
#define CONFIGURE_BDBUF_BUFFER_MAX_SIZE (64 * 1024)
#define CONFIGURE_BDBUF_MAX_READ_AHEAD_BLOCKS 4
#define CONFIGURE_BDBUF_CACHE_MEMORY_SIZE (1 * 1024 * 1024)

#define CONFIGURE_SHELL_COMMANDS_INIT

#include <bsp/irq-info.h>

#include <rtems/netcmds-config.h>

/** Add the BSD commands we want */
#define CONFIGURE_SHELL_USER_COMMANDS \
  &bsp_interrupt_shell_command, \
  &rtems_shell_HOSTNAME_Command, \
  &rtems_shell_PING_Command, \
  &rtems_shell_ROUTE_Command, \
  &rtems_shell_NETSTAT_Command, \
  &rtems_shell_IFCONFIG_Command, \
  &rtems_shell_TCPDUMP_Command, \
  &rtems_shell_PFCTL_Command, \
  &rtems_shell_SYSCTL_Command, \
  &rtems_shell_ARP_Command, \
  &rtems_shell_VMSTAT_Command

#define CONFIGURE_SHELL_COMMANDS_ALL_NETWORKING
#define CONFIGURE_SHELL_COMMANDS_ALL

#include <rtems/shellconfig.h>

#define RTEMS_BSD_CONFIG_BSP_CONFIG
#define RTEMS_BSD_CONFIG_SERVICE_TELNETD
#define RTEMS_BSD_CONFIG_TELNETD_STACK_SIZE (16 * 1024)
#define RTEMS_BSD_CONFIG_SERVICE_FTPD
#define RTEMS_BSD_CONFIG_FIREWALL_PF

#define CONFIGURE_MAXIMUM_DRIVERS 40

//#if defined(BSP_pc386) || defined(BSP_pc686)
#define RTEMS_BSD_CONFIG_DOMAIN_PAGE_MBUFS_SIZE (64 * 1024 * 1024)
//#elif defined(BSP_qoriq_e500)
//#define RTEMS_BSD_CONFIG_DOMAIN_PAGE_MBUFS_SIZE (32 * 1024 * 1024)
//#endif

#define CONFIGURE_INIT

#include <rtems/confdefs.h>

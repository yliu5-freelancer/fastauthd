#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <glib-2.0/glib.h>
#include <gio/gio.h>
#include <syslog.h>

#include "fastauthd_oidc_dbus_service.h"
#include "fastauthd_systemd.h"

bool fastauthd_oidc_is_foreground = false;

static bool
check_dbus_daemon()
{
    GDBusConnection *connection;
    GError *error = NULL;

    connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);

    if (error != NULL) {
        printf("Error connecting to D-Bus: %s\n", error->message);
        g_error_free(error);
        return false;
    }

    if (connection) {
        printf("D-Bus is supported and running!\n");
        g_object_unref(connection);
        return true;
    }
    return false;
}
static int
fastauthd_oidc_init_run_path()
{
    const char *dir = "/var/lib/fastauthd/";
    
    return g_mkdir_with_parents(dir, 0700);
}

static int
fastauthd_oidc_init()
{
    int ret;
    GError *error = NULL;

    ret = fastauthd_oidc_init_run_path();

    return ret;
}

int
main(int argc, char *argv[])
{
    int opt;
    GMainLoop *loop;
    guint owner_id;

    while ((opt = getopt(argc, argv, "f")) != -1) {
        switch (opt) {
        case 'f':
            fastauthd_oidc_is_foreground = true;
            break;            
        default:
            printf("Usage: %s -f    --foreground\n", argv[0]);
            exit(-1);
        }
    }
    if (!fastauthd_oidc_is_foreground) {
        openlog("fastauthd-oidc", LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Starting fastauthd-oidc service ...");
    }
    loop = g_main_loop_new(NULL, FALSE);
 
    if (!check_dbus_daemon()) {
        // Using D-Bus as connection path.
        syslog(LOG_ERR, "The D-Bus service not started, fastauthd-oidc terminated.");
        return -1;
    }
    fastauthd_oidc_init();
    owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
                              "com.fastauthd.oidc",
                              G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT |
                              G_BUS_NAME_OWNER_FLAGS_REPLACE,
                              fastauthd_oidc_bus_acquired_cb,
                              fastauthd_oidc_bus_name_acquired_cb,
                              fastauthd_oidc_bus_name_lost_cb,
                              loop,
                              NULL);
    if (!fastauthd_oidc_is_foreground) {
        syslog(LOG_INFO, "The fastauthd service started.");
        notify_systemd_ready();
        notify_systemd_status("The fastauthd D-Bus service ready.");
    }
    g_main_loop_run(loop);

    // Clean up resources when service stop
    g_bus_unown_name(owner_id);
    g_main_loop_unref(loop);
    if (!fastauthd_oidc_is_foreground) {
        closelog();
    }

    return 0;
}
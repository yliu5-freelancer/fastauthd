#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <glib-2.0/glib.h>
#include <gio/gio.h>
#include <getopt.h>
#include "fastauthd_dbus_service.h"
#include "fastauthd_systemd.h"
#include "fastauthd_config.h"

#define FASTAUTHD_DBUS_NAME "com.fastauthd.broker"
bool fastauthd_is_foreground = false;
GDBusConnection *fastauthd_oidc_connection = NULL;
fastauthd_msa_config_t fastauthd_msa_config = {0};

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
fastauthd_init_run_path()
{
    const char *dir = "/var/lib/fastauthd/usersinfo";
    
    return g_mkdir_with_parents(dir, 0700);
}

static int
fastauthd_init()
{
    int ret;
    GError *error = NULL;

    ret = fastauthd_init_run_path();
    fastauthd_oidc_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error != NULL) {
       g_print("Error getting D-Bus connection: %s\n", error->message);
       g_error_free(error);
       ret = -1;
    }

    return ret;
}

static enum fastauthd_broker_type
broker_type_convert(const char *type_str)
{
    if (strcmp(type_str, "msa") == 0) {
        return FASTAUTHD_BROKER_MSA;
    } else if (strcmp(type_str, "giam") == 0) {
        return FASTAUTHD_BROKER_GIAM;
    }
    return FASTAUTHD_BROKER_UNKNOWN;
}

int
main(int argc, char *argv[])
{
    GMainLoop *loop;
    guint owner_id;
    char *config_file = NULL;
    char *config_json_data = NULL;
    int opt;
    enum fastauthd_broker_type broker_type;

    while ((opt = getopt(argc, argv, "b:c:")) != -1) {
        switch (opt) {
        case 'b':
            broker_type = broker_type_convert(optarg);
            break;
        case 'c':
            config_file = optarg;
            break;
        case 'f':
            fastauthd_is_foreground = true;
            break;            
        default:
            printf("Usage: %s -c <config.json> -f(optional)\n", argv[0]);
            exit(-1);
        }
    }

    if (!config_file) {
        config_file = FASTAUTHD_DEFCONFIG;
    }
    if (broker_type == FASTAUTHD_BROKER_MSA) {
        config_json_data = load_fastauthd_msa_config(config_file);
        if (!config_json_data) {
            printf("Error: Config file format is not correct.\n");
            exit(-1);
        }
        if (!parse_fastauthd_msa_config(config_json_data, &fastauthd_msa_config)) {
            printf("Error: Parse config file failed.\n");
            exit(-1);
        }
        if (strlen(fastauthd_msa_config.client_id) == 0 ||
            strlen(fastauthd_msa_config.tenant_id) == 0) {
            printf("Error: Client id and teeant id are not correct.\n");
            exit(-1);
        }
    }
    if (!fastauthd_is_foreground) {
        openlog("fastauthd", LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Starting fastauthd service ...");
    }

    loop = g_main_loop_new(NULL, FALSE);
 
    if (!check_dbus_daemon()) {
        // Using D-Bus as connection path.
        syslog(LOG_ERR, "The D-Bus service not started, fastauthd terminated.");
        return -1;
    }
    fastauthd_init();
    owner_id = fastauthd_start_dbus_connection_loop(loop, FASTAUTHD_DBUS_NAME,
        fastauthd_bus_acquired_cb, fastuahtd_bus_name_acquired_cb, fastauthd_bus_name_lost_cb);
    if (!fastauthd_is_foreground) {
        syslog(LOG_INFO, "The fastauthd service started.");
        notify_systemd_ready();
        notify_systemd_status("The fastauthd D-Bus service ready.");
    }
    g_main_loop_run(loop);

    // Clean up resources when service stop
    g_bus_unown_name(owner_id);
    g_main_loop_unref(loop);
    if (!fastauthd_is_foreground) {
        closelog();
    }
    return 0;
}
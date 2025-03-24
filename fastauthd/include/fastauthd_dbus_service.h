#ifndef _FASTAUTHD_DBUS_SERVICE_H
#define _FASTAUTHD_DBUS_SERVICE_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib-2.0/glib.h>
#include <gio/gio.h>
#include <syslog.h>

#define FASTAUTHD_DBUS_INTERFACE_NAME "com.fastauthd.broker.deviceflow"

void
fastauthd_bus_acquired_cb(GDBusConnection *connection,
                          const gchar     *name,
                          gpointer         user_data);
void
fastauthd_bus_name_lost_cb(GDBusConnection *connection,
                           const gchar     *name,
                           gpointer         user_data);
void
fastuahtd_bus_name_acquired_cb(GDBusConnection *connection,
                               const gchar     *name,
                               gpointer         user_data);

guint
fastauthd_start_dbus_connection_loop(GMainLoop *loop,
    const char *name,
    GBusAcquiredCallback bus_acquired_handler,
    GBusNameAcquiredCallback name_acquired_handler,
    GBusNameLostCallback name_lost_handler);

#endif
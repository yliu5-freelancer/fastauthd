#ifndef _FASTAUTHD_OIDC_DBUS_SERVICE_H
#define _FASTAUTHD_OIDC_DBUS_SERVICE_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib-2.0/glib.h>
#include <gio/gio.h>
#include <syslog.h>

void
fastauthd_oidc_bus_acquired_cb(GDBusConnection *connection,
                               const gchar     *name,
                               gpointer         user_data);

void
fastauthd_oidc_bus_name_lost_cb(GDBusConnection *connection,
                                const gchar     *name,
                                gpointer         user_data);

void
fastauthd_oidc_bus_name_acquired_cb(GDBusConnection *connection,
                                    const gchar     *name,
                                    gpointer         user_data);
#endif
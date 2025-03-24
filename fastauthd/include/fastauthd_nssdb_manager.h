#ifndef _FASTAUTHD_NSSDB_MANAGER_H
#define _FASTAUTHD_NSSDB_MANAGER_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <glib-2.0/glib.h>
#include <gio/gio.h>

extern const char *g_nssdb_path;
extern GHashTable *g_nssdb_hashtable;

extern int fastauthd_nssdb_manager_update_record(const char *username, const char *userinfo);
extern char *fastauthd_nssdb_manager_query_shadow_record_byname(const char *username);
extern char *fastauthd_nssdb_manager_query_passwd_record_byname(const char *username);
extern int fastauthd_nssdb_manager_remove_record(const char *username);

#endif
#include "fastauthd_nssdb_manager.h"
#include "fastauthd_systemd.h"
#include <linux/limits.h>
#include <cjson/cJSON.h>

const char *g_nssdb_path = NULL;
GHashTable *g_nssdb_hashtable = NULL;
extern bool fastauthd_is_foreground;

static int
fastauthd_nssdb_manager_open_passwd_db(const char *username)
{
    int fd;
    char filepath[PATH_MAX];

    gchar *filename = g_compute_checksum_for_string(G_CHECKSUM_MD5, username, -1);
    snprintf(filepath, PATH_MAX, "/var/lib/fastauthd/usersinfo/%s/passwd", filename);

    fd = open(filepath, O_RDWR);
    if (fd < 0) {
        SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_ERR, "Open user info (%s) failed.\n", filename);
        return -1;
    }

    return fd;
}

static int
fastauthd_nssdb_manager_open_shadow_db(const char *username)
{
    int fd;
    char filepath[PATH_MAX];

    gchar *filename = g_compute_checksum_for_string(G_CHECKSUM_MD5, username, -1);
    snprintf(filepath, PATH_MAX, "/var/lib/fastauthd/usersinfo/%s/shadow", filename);

    fd = open(filepath, O_RDWR);
    if (fd < 0) {
        SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_ERR, "Open user info (%s) failed.\n", filename);
        return -1;
    }

    return fd;
}

static int
fastauthd_nssdb_manager_closedb(int fd)
{
    return close(fd);
}

int
fastauthd_nssdb_manager_update_record(const char *username,
                                      const char *userinfo)
{
    return -1;
}

char *
fastauthd_nssdb_manager_query_shadow_record_byname(const char *username)
{
    int fd;
    char *json_str;
    char line[1024];
    char *token;
    cJSON *json_obj = NULL;

    fd = fastauthd_nssdb_manager_open_shadow_db(username);
    if (fd < 0) {
        SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_ERR, "Open nss db failed.\n");
        return NULL;
    }

    if (read(fd, line, sizeof(line)) <= 0) {
        fastauthd_nssdb_manager_closedb(fd);
        return NULL;
    }

    token = strtok(line, ":");
    json_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(json_obj, "username", token);
    token = strtok(NULL, ":");
    cJSON_AddStringToObject(json_obj, "password", token);
    token = strtok(NULL, ":");
    cJSON_AddNumberToObject(json_obj, "last_changed", atoi(token));
    token = strtok(NULL, ":");
    cJSON_AddNumberToObject(json_obj, "min_days", atoi(token));
    token = strtok(NULL, ":");
    cJSON_AddNumberToObject(json_obj, "max_days", atoi(token));
    token = strtok(NULL, ":");
    cJSON_AddNumberToObject(json_obj, "warn_period", atoi(token));
    token = strtok(NULL, ":");
    cJSON_AddNumberToObject(json_obj, "inactive_period", atoi(token));
    token = strtok(NULL, ":");
    cJSON_AddNumberToObject(json_obj, "expire_date", atoi(token));
    token = strtok(NULL, ":");
    cJSON_AddStringToObject(json_obj, "reserved", token ? token : "");
    json_str = cJSON_PrintUnformatted(json_obj);
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "User info in JSON format: %s\n", json_str);

    return json_str;
}

char *
fastauthd_nssdb_manager_query_passwd_record_byname(const char *username)
{
    int fd;
    char *json_str;
    char line[1024];
    char *token;
    cJSON *json_obj = NULL;

    fd = fastauthd_nssdb_manager_open_passwd_db(username);
    if (fd < 0) {
        SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_ERR, "Open nss db failed.\n");
        return NULL;
    }

    if (read(fd, line, sizeof(line)) <= 0) {
        fastauthd_nssdb_manager_closedb(fd);
        return NULL;
    }

    token = strtok(line, ":");
    json_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(json_obj, "username", token);
    token = strtok(NULL, ":");
    cJSON_AddStringToObject(json_obj, "password", token);
    token = strtok(NULL, ":");
    cJSON_AddNumberToObject(json_obj, "uid", atoi(token));
    token = strtok(NULL, ":");
    cJSON_AddNumberToObject(json_obj, "gid", atoi(token));
    token = strtok(NULL, ":");
    cJSON_AddStringToObject(json_obj, "gecos", token);
    token = strtok(NULL, ":");
    cJSON_AddStringToObject(json_obj, "home_directory", token);
    token = strtok(NULL, ":");
    cJSON_AddStringToObject(json_obj, "shell", token);
    json_str = cJSON_PrintUnformatted(json_obj);
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "User info in JSON format: %s\n", json_str);

    fastauthd_nssdb_manager_closedb(fd);

    return json_str;
}

int
fastauthd_nssdb_manager_remove_record(const char *username)
{
    return -1;
}

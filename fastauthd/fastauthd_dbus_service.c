#include "fastauthd_dbus_service.h"
#include "fastauthd_systemd.h"
#include "autogen/fastauthd_gdbus_autogen.h"
#include "fastauthd_nssdb_manager.h"
#include "fastauthd_config.h"
#include <linux/limits.h>
#include <cjson/cJSON.h>
#include <jwt.h>

static GDBusObjectManagerServer *manager = NULL;
extern bool fastauthd_is_foreground;
extern GDBusConnection *fastauthd_oidc_connection;
extern fastauthd_msa_config_t fastauthd_msa_config;

static gchar *
fastauthd_call_device_code_request_method(gchar *username, gchar *tenant_id, gchar *client_id)
{
    gchar object_path[PATH_MAX];
    GVariant *parameters = NULL, *result = NULL;
    GError *error = NULL;
    gchar *response;

    snprintf(object_path, PATH_MAX, "/deviceflow/%s", "request_device_code");
    parameters = g_variant_new("(sss)", username, tenant_id, client_id);
 
    result = g_dbus_connection_call_sync(fastauthd_oidc_connection,
       "com.fastauthd.oidc",
       "/deviceflow/request_device_code",
       "com.fastauthd.oidc.deviceflow",
       "request_device_code",
       parameters,
       NULL,
       G_DBUS_CALL_FLAGS_NONE,
       -1,
       NULL,
       &error);
    g_variant_get(result, "(s)", &response);
    if (!response) {
        return NULL;
    }
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "Response from oidc: %s", response);
    return response;
}

static gchar *
fastauthd_call_msa_auth_result_method(gchar *device_code, gchar *tenant_id, gchar *client_id)
{
    gchar object_path[PATH_MAX];
    GVariant *parameters = NULL, *result = NULL;
    GError *error = NULL;
    gchar *response;

    snprintf(object_path, PATH_MAX, "/deviceflow/%s", "query_msa_auth_result");
    parameters = g_variant_new("(sss)", device_code, tenant_id, client_id);
 
    result = g_dbus_connection_call_sync(fastauthd_oidc_connection,
       "com.fastauthd.oidc",
       "/deviceflow/query_msa_auth_result",
       "com.fastauthd.oidc.deviceflow",
       "query_msa_auth_result",
       parameters,
       NULL,
       G_DBUS_CALL_FLAGS_NONE,
       -1,
       NULL,
       &error);
    g_variant_get(result, "(s)", &response);
    if (!response) {
        return NULL;
    }
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "Response from oidc: %s", response);
    return response;
}

static gchar *
fastauthd_call_verify_user_and_group_method(gchar *username, gchar *access_token, gchar *token_type, gchar *group_id)
{
    gchar object_path[PATH_MAX];
    GVariant *parameters = NULL, *result = NULL;
    GError *error = NULL;
    gchar *response;

    snprintf(object_path, PATH_MAX, "/deviceflow/%s", "verify_user_and_group");
    parameters = g_variant_new("(ssss)", username, access_token, token_type, group_id);
 
    result = g_dbus_connection_call_sync(fastauthd_oidc_connection,
       "com.fastauthd.oidc",
       "/deviceflow/verify_user_and_group",
       "com.fastauthd.oidc.deviceflow",
       "verify_user_and_group",
       parameters,
       NULL,
       G_DBUS_CALL_FLAGS_NONE,
       -1,
       NULL,
       &error);
    g_variant_get(result, "(s)", &response);
    if (!response) {
        return NULL;
    }
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "Response from oidc: %s", response);
    return response;
}

static gboolean
fastauthd_request_device_code_method(fastauthdDeviceflow    *interface,
                                     GDBusMethodInvocation  *invocation,
                                     gpointer                user_data)
{
    GVariant *params;
    gchar *username, *tenant_id, *client_id;
    gchar *response;
    
    params = g_dbus_method_invocation_get_parameters(invocation);
    g_variant_get(params, "(s)", &username);
    tenant_id = (gchar *) fastauthd_msa_config.tenant_id;
    client_id = (gchar *) fastauthd_msa_config.client_id; 
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "Get device code request.\n");
    printf("The username, tenant_id, client_id is: %s, %s, %s\n", username, tenant_id, client_id);
    if (!(response = fastauthd_call_device_code_request_method(username, tenant_id, client_id))) {
        fastauthd_deviceflow_complete_request_device_code(interface, invocation, -1, "Request device code error.");
        return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
    fastauthd_deviceflow_complete_request_device_code(interface, invocation, 0, response);
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
fastauthd_refresh_device_code_method(fastauthdDeviceflow    *interface,
                                     GDBusMethodInvocation  *invocation,
                                     gpointer                user_data)
{
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "Get refresh device code request.\n");
    fastauthd_deviceflow_complete_refresh_device_code(interface, invocation, 0, "Complete");
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
fastauthd_query_msa_auth_result_method(fastauthdDeviceflow    *interface,
                                       GDBusMethodInvocation  *invocation,
                                       gpointer                user_data)
{
    GVariant *params;
    gchar *device_code, *tenant_id, *client_id;
    gchar *response;
    cJSON *token_json;

    params = g_dbus_method_invocation_get_parameters(invocation);
    g_variant_get(params, "(s)", &device_code);
    tenant_id = (gchar *) fastauthd_msa_config.tenant_id;
    client_id = (gchar *) fastauthd_msa_config.client_id; 
    printf("The device code, tenant_id, client_id is: %s, %s, %s\n", device_code, tenant_id, client_id);
    if (!(response = fastauthd_call_msa_auth_result_method(device_code, tenant_id, client_id))) {
        fastauthd_deviceflow_complete_query_msa_auth_result(interface, invocation, -1, "Request device code error.");
        return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
    token_json = cJSON_Parse(response);
    if (!token_json) {
        free(response);
        fastauthd_deviceflow_complete_query_msa_auth_result(interface, invocation, -1, "Request device code error.");
        return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

    cJSON *access_token_item = cJSON_GetObjectItemCaseSensitive(token_json, "access_token");
    if (!access_token_item) {
        cJSON *error_item = cJSON_GetObjectItemCaseSensitive(token_json, "error");
        if (error_item && strcmp(error_item->valuestring, "authorization_pending") == 0) {
            fastauthd_deviceflow_complete_query_msa_auth_result(interface, invocation, -2, "Error: authorization_pending");
            return G_DBUS_METHOD_INVOCATION_HANDLED;
        }
    }

    fastauthd_deviceflow_complete_query_msa_auth_result(interface, invocation, 0, response);
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
fastauthd_verify_user_and_group(fastauthdDeviceflow    *interface,
                                GDBusMethodInvocation  *invocation,
                                gpointer                user_data)
{
    GVariant *params;
    gchar *username, *access_token, *token_type, *group_id;
    jwt_t *jwt;
    const gchar *upn;
    gint result = 0;
    gchar *response;

    params = g_dbus_method_invocation_get_parameters(invocation);
    g_variant_get(params, "(sss)", &username, &access_token, &token_type);
    jwt_decode(&jwt, access_token, NULL, 0);
    upn = jwt_get_grant(jwt, "upn");
    if (strcmp(upn, username) != 0) result = -1;
    printf("The upn is: %s, username is: %s\n", upn, username);
    if (result != 0) {
        // Username is not match, return a error to PAM service
        printf("upn and username is not match\n");
    
        fastauthd_deviceflow_complete_verify_user_and_group(interface, invocation, result, "{\"error\": Verify user and group failed.\"}");
        return G_DBUS_METHOD_INVOCATION_HANDLED;
    } else {
        group_id = fastauthd_msa_config.group_id;
        if (strlen(group_id) != 0) {
            // Need to verify group.
            response = fastauthd_call_verify_user_and_group_method(username, access_token, token_type, group_id);
            printf("The response is: %s\n", response);
            
            if (!response) {
                fastauthd_deviceflow_complete_verify_user_and_group(interface, invocation, result, "{\"error\": Verify user and group failed.\"}");
                return G_DBUS_METHOD_INVOCATION_HANDLED;
            }
            cJSON *resp_json = cJSON_Parse(response);
            if (resp_json == NULL) {
                fastauthd_deviceflow_complete_verify_user_and_group(interface, invocation, result, "{\"error\": Verify user and group failed.\"}");
                return G_DBUS_METHOD_INVOCATION_HANDLED;
            }
            cJSON *group_id_obj = cJSON_GetObjectItemCaseSensitive(resp_json, "value");
            if (cJSON_IsArray(group_id_obj)) {
                int array_size = cJSON_GetArraySize(group_id_obj);
                for (int i = 0; i < array_size; i++) {
                    cJSON *item = cJSON_GetArrayItem(group_id_obj, i);
                    if (cJSON_IsString(item) && item->valuestring != NULL) {
                        if (strcmp(group_id, item->valuestring) == 0) {
                            fastauthd_deviceflow_complete_verify_user_and_group(interface, invocation, 0, response);
                            return G_DBUS_METHOD_INVOCATION_HANDLED;
                        }
                    }
                }
            }
        }
    }

    fastauthd_deviceflow_complete_verify_user_and_group(interface, invocation, -1, response);
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
fastauthd_query_nssdb_method(fastauthdDeviceflow    *interface,
                             GDBusMethodInvocation  *invocation,
                             gpointer                user_data)
{
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "Query NSS database.\n");
    gchar *passwd_json_str, *shadow_json_str, *merged_json_str;
    cJSON *passwd_json_obj, *shadow_json_obj;
    cJSON *merged_json_obj = cJSON_CreateObject();
    gchar *username;
    gchar error_string[4096];

    username = (gchar *) user_data;
    if (!username) {
        return G_DBUS_METHOD_INVOCATION_UNHANDLED;
    }
    passwd_json_str = fastauthd_nssdb_manager_query_passwd_record_byname(username);
    shadow_json_str = fastauthd_nssdb_manager_query_shadow_record_byname(username);
    if (!passwd_json_str || !shadow_json_str) {
        snprintf(error_string, sizeof(error_string), "Not found user (%s) in nss database.", username);
        fastauthd_deviceflow_complete_query_fastauthd_nssdb(interface, invocation, -1, error_string);
        return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
    passwd_json_obj = cJSON_Parse(passwd_json_str);
    shadow_json_obj = cJSON_Parse(shadow_json_str);

    cJSON_AddItemToObject(merged_json_obj, "passwd", passwd_json_obj);
    cJSON_AddItemToObject(merged_json_obj, "shadow", shadow_json_obj);

    merged_json_str = cJSON_Print(merged_json_obj);
    if (!merged_json_str) {
        snprintf(error_string, sizeof(error_string), "Unknown issue.");
        fastauthd_deviceflow_complete_query_fastauthd_nssdb(interface, invocation, -1, error_string);
        return G_DBUS_METHOD_INVOCATION_HANDLED;    
    }
    cJSON_Delete(merged_json_obj);

    fastauthd_deviceflow_complete_query_fastauthd_nssdb(interface, invocation, 0, merged_json_str);
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

void
fastauthd_bus_acquired_cb(GDBusConnection *connection,
                          const gchar     *name,
                          gpointer         user_data)
{
    const gchar *obj_paths[] = {
        "/deviceflow/request_device_code",
        "/deviceflow/refresh_device_code",
        "/deviceflow/query_fastauthd_nssdb",
        "/deviceflow/query_msa_auth_result",
        "/deviceflow/verify_user_and_group"
    };

    const gchar *method_names[] = {
        "handle-request-device-code",
        "handle-refresh-device-code",
        "handle-query-fastauthd-nssdb",
        "handle-query-msa-auth-result",
        "handle-verify-user-and-group"
    };

    gboolean (*callbacks[])(fastauthdDeviceflow *, GDBusMethodInvocation *, gpointer) = {
        fastauthd_request_device_code_method,
        fastauthd_refresh_device_code_method,
        fastauthd_query_nssdb_method,
        fastauthd_query_msa_auth_result_method,
        fastauthd_verify_user_and_group
    };

    fastauthdObjectSkeleton *obj_skeletons[5];
    fastauthdDeviceflow *deviceflows[5];
    g_autofree gchar *obj_paths_copy[5];
    GDBusInterfaceInfo *info = fastauthd_deviceflow_interface_info();
    SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "Registered D-Bus bus (%s)\n", info->name);

    manager = g_dbus_object_manager_server_new("/deviceflow");

    for (int i = 0; i < 5; i++) {
        obj_paths_copy[i] = g_strdup_printf(obj_paths[i]);
        obj_skeletons[i] = fastauthd_object_skeleton_new(obj_paths_copy[i]);
        deviceflows[i] = fastauthd_deviceflow_skeleton_new();
        fastauthd_object_skeleton_set_deviceflow(obj_skeletons[i], deviceflows[i]);
        g_signal_connect(deviceflows[i], method_names[i], G_CALLBACK(callbacks[i]), NULL);
        g_dbus_object_manager_server_export(manager, G_DBUS_OBJECT_SKELETON(obj_skeletons[i]));
        g_object_unref(deviceflows[i]);
        SYSLOG_WRAPPER(fastauthd_is_foreground, LOG_INFO, "Registered D-Bus object (%s)\n", info->methods[i]->name);
    }

    for (int i = 0; i < 5; i++) {
        g_object_unref(obj_skeletons[i]);
    }

    g_dbus_object_manager_server_set_connection(manager, connection);
}

void
fastauthd_bus_name_lost_cb(GDBusConnection *connection,
                           const gchar     *name,
                           gpointer         user_data)
{

}

void
fastuahtd_bus_name_acquired_cb(GDBusConnection *connection,
                               const gchar     *name,
                               gpointer         user_data)
{

}

guint
fastauthd_start_dbus_connection_loop(GMainLoop *loop,
                                     const char *name,
                                     GBusAcquiredCallback bus_acquired_handler,
                                     GBusNameAcquiredCallback name_acquired_handler,
                                     GBusNameLostCallback name_lost_handler)
{
    return g_bus_own_name(G_BUS_TYPE_SYSTEM,
                          "com.fastauthd.broker",
                          G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT |
                          G_BUS_NAME_OWNER_FLAGS_REPLACE,
                          bus_acquired_handler,
                          name_acquired_handler,
                          name_lost_handler,
                          loop,
                          NULL);
}

#include "fastauthd_systemd.h"
#include "fastauthd_oidc_msa.h"
#include "fastauthd_oidc_dbus_service.h"
#include "autogen/fastauthd_oidc_gdbus_autogen.h"
#include <linux/limits.h>
#include <cjson/cJSON.h>

extern bool fastauthd_oidc_is_foreground;

static GDBusObjectManagerServer *manager = NULL;

static gboolean
fastauthd_oidc_request_device_code_method(fastauthdoidcDeviceflow *interface,
                                          GDBusMethodInvocation   *invocation,
                                          gpointer                user_data)
{
    GVariant *params;
    gchar *username, *tenant_id, *client_id;
    gchar *response;

    params = (GVariant *) g_dbus_method_invocation_get_parameters(invocation);

    g_variant_get(params, "(sss)", &username, &tenant_id, &client_id);
    
    response = fastauthd_oidc_msa_device_code_get_usercode(tenant_id, client_id);
    if (!response) {
        fastauthd_oidc_deviceflow_complete_request_device_code(interface, invocation, "{\"errcode\": -1}");
        return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
    printf("The response is: %s\n", response);
    fastauthd_oidc_deviceflow_complete_request_device_code(interface, invocation, response);
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
fastauthd_oidc_refresh_device_code_method(fastauthdoidcDeviceflow    *interface,
                                          GDBusMethodInvocation  *invocation,
                                          gpointer                user_data)
{
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
fastauthd_oidc_query_msa_auth_result_method(fastauthdoidcDeviceflow *interface,
                                            GDBusMethodInvocation   *invocation,
                                            gpointer                user_data)
{
    GVariant *params;
    gchar *device_code, *tenant_id, *client_id;
    gchar *response;

    params = (GVariant *) g_dbus_method_invocation_get_parameters(invocation);
    g_variant_get(params, "(sss)", &device_code, &tenant_id, &client_id);
    printf("The device code: %s\n", device_code);
    response = fastauthd_oidc_query_msa_access_token(device_code, tenant_id, client_id);
    if (!response) {
        fastauthd_oidc_deviceflow_complete_request_device_code(interface, invocation, "{\"errcode\": -1}");
        return G_DBUS_METHOD_INVOCATION_HANDLED;
    }
    printf("The response is: %s\n", response);
    fastauthd_oidc_deviceflow_complete_request_device_code(interface, invocation, response);
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
fastauthd_oidc_verify_user_and_group_method(fastauthdoidcDeviceflow *interface,
                                            GDBusMethodInvocation   *invocation,
                                            gpointer                user_data)
{
    GVariant *params;
    gchar *username, *access_token, *token_type, *group_id;
    gchar *response;

    params = (GVariant *) g_dbus_method_invocation_get_parameters(invocation);
    g_variant_get(params, "(ssss)", &username, &access_token, &token_type, &group_id);
    response = fastauthd_oidc_msa_verify_group(username, access_token, token_type, group_id);
    printf("The response is: %s\n", response);
    fastauthd_oidc_deviceflow_complete_request_device_code(interface, invocation, response);
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

void
fastauthd_oidc_bus_acquired_cb(GDBusConnection *connection,
                               const gchar     *name,
                               gpointer         user_data)
{
    fastauthdoidcObjectSkeleton *device_code_objs[4];
    fastauthdoidcDeviceflow *device_code_flows[4];
    GDBusInterfaceInfo *info = NULL;
    
    gchar *obj_paths[] = {
        "/deviceflow/request_device_code",
        "/deviceflow/refresh_device_code",
        "/deviceflow/query_msa_auth_result",
        "/deviceflow/verify_user_and_group"
    };
    
    gboolean (*methods[])(fastauthdoidcDeviceflow *, GDBusMethodInvocation *, gpointer) = {
        fastauthd_oidc_request_device_code_method,
        fastauthd_oidc_refresh_device_code_method,
        fastauthd_oidc_query_msa_auth_result_method,
        fastauthd_oidc_verify_user_and_group_method
    };
    
    const char *method_names[] = {
        "handle-request-device-code",
        "handle-refresh-device-code",
        "handle-query-msa-auth-result",
        "handle-verify-user-and-group"
    };
    
    info = fastauthd_oidc_deviceflow_interface_info();
    SYSLOG_WRAPPER(fastauthd_oidc_is_foreground, LOG_INFO, "Registered D-Bus bus (%s)\n", info->name);
    
    manager = g_dbus_object_manager_server_new("/deviceflow");
    
    for (int i = 0; i < 4; i++) {
        device_code_objs[i] = fastauthd_oidc_object_skeleton_new(obj_paths[i]);
        device_code_flows[i] = fastauthd_oidc_deviceflow_skeleton_new();
    
        fastauthd_oidc_object_skeleton_set_deviceflow(device_code_objs[i], device_code_flows[i]);
    
        g_signal_connect(device_code_flows[i], method_names[i], G_CALLBACK(methods[i]), NULL);
    
        g_dbus_object_manager_server_export(manager, G_DBUS_OBJECT_SKELETON(device_code_objs[i]));
    
        SYSLOG_WRAPPER(fastauthd_oidc_is_foreground, LOG_INFO, "Registered D-Bus object (%s)\n", info->methods[i]->name);
    
        g_object_unref(device_code_flows[i]);
        g_object_unref(device_code_objs[i]);
    }
    
    g_dbus_object_manager_server_set_connection(manager, connection);
}

void
fastauthd_oidc_bus_name_lost_cb(GDBusConnection *connection,
                                const gchar     *name,
                                gpointer         user_data)
{

}

void
fastauthd_oidc_bus_name_acquired_cb(GDBusConnection *connection,
                                    const gchar     *name,
                                    gpointer         user_data)
{

}

#ifndef _FASTAUTHD_MSA_H
#define _FASTAUTHD_MSA_H

#include <stdbool.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <glib-2.0/glib.h>
#include <gio/gio.h>
enum msa_method_t {
    MSA_METHOD_ALL_SUPPORT,
    MSA_METHOD_DEVICECODE,
    MSA_METHOD_PKCE,
    MSA_METHOD_ROPC,
    MSA_METHOD_UNSUPPORT
};
gchar *
fastauthd_oidc_msa_device_code_get_usercode(char *tenant_id, char *client_id);
gchar *
fastauthd_oidc_query_msa_access_token(char *device_code, char *tenant_id, char *client_id);
gchar *
fastauthd_oidc_msa_verify_group(const gchar *username, const gchar *access_token, const gchar *token_type, const gchar *group_id);
// int
// msa_device_code_flow_verify(fastauthd_config_t fastauthd_config);

// int
// msa_pkce_flow_verify(fastauthd_config_t fastauthd_config);

// int
// msa_ropc_flow_verify(fastauthd_config_t fastauthd_config_t);

#endif
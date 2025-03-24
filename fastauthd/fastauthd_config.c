#include "fastauthd_config.h"

char *
load_fastauthd_msa_config(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Can not open file: %s\n", filename);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *content = (char *)malloc(length + 1);
    if (content) {
        fread(content, 1, length, file);
        content[length] = '\0';
    }
    fclose(file);
    return content;
}

bool
parse_fastauthd_msa_config(const char *json_data, fastauthd_msa_config_t *aad_config)
{
    cJSON *json = cJSON_Parse(json_data);
    cJSON *tenant_id, *client_id, *group_id, *secrets;

    if (!json) {
        printf("Error: Parsing JSON data failed.\n");
        return false;
    }
    tenant_id = cJSON_GetObjectItem(json, "tenant_id");
    client_id = cJSON_GetObjectItem(json, "client_id");
    group_id = cJSON_GetObjectItem(json, "group_id");
    secrets = cJSON_GetObjectItem(json, "secrets");
    if (cJSON_IsString(tenant_id) && tenant_id->valuestring) {
        snprintf(aad_config->tenant_id, 256, "%s", tenant_id->valuestring);
    }
    if (cJSON_IsString(client_id) && client_id->valuestring) {
        snprintf(aad_config->client_id, 256, "%s", client_id->valuestring);
    }
    if (cJSON_IsString(group_id) && group_id->valuestring) {
        snprintf(aad_config->group_id, 256, "%s", group_id->valuestring);
    }
    if (cJSON_IsString(secrets) && secrets->valuestring) {
        snprintf(aad_config->secrets, 256, "%s", secrets->valuestring);
    }
    return true;
}

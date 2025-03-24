#ifndef _FASTAUTHD_CONFIG_H
#define _FASTAUTHD_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <cjson/cJSON.h>

#define FASTAUTHD_DEFCONFIG "/etc/fastauthd/fastauthd.config"
typedef struct _fastauthd_msa_config_t {
    char tenant_id[256];
    char client_id[256];
    char group_id[256];
    char secrets[256];
} fastauthd_msa_config_t;

char *
load_fastauthd_msa_config(const char *filename);

bool
parse_fastauthd_msa_config(const char *json_data, fastauthd_msa_config_t *aad_config);

enum fastauthd_broker_type {
    FASTAUTHD_BROKER_MSA,   // Microsoft Account
    FASTAUTHD_BROKER_GIAM,  // Google Identity and Access Management
    FASTAUTHD_BROKER_UNKNOWN
};

#endif
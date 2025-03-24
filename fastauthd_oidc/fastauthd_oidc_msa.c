#include "fastauthd_oidc_msa.h"
#include "fastauthd_debug.h"
// #include "fastauthd_config.h"

#define MAX_BUFFER 4096  // Increase buffer size


// // // Function to exchange authorization code for tokens
// // void
// // exchange_code_for_token(const char *code)
// // {
// //     CURL *curl;
// //     CURLcode res;
// //     char url[1024];
// //     snprintf(url, sizeof(url), "%s/token", AUTHORITY);
    
// //     // Prepare data for the POST request
// //     char post_data[1024];
// //     snprintf(post_data, sizeof(post_data), 
// //         "client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s&scope=openid%%20profile", 
// //         CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI);
    
// //     // Prepare the curl handle
// //     curl_global_init(CURL_GLOBAL_DEFAULT);
// //     curl = curl_easy_init();
// //     if(curl) {
// //         char response[4096] = {0};
        
// //         // Set curl options
// //         curl_easy_setopt(curl, CURLOPT_URL, url);
// //         curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
// //         curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
// //         curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        
// //         // Execute the POST request
// //         res = curl_easy_perform(curl);
        
// //         if(res == CURLE_OK) {
// //             // Parse the response JSON
// //             json_error_t error;
// //             json_t *root = json_loads(response, 0, &error);
// //             if (root) {
// //                 json_t *access_token = json_object_get(root, "access_token");
// //                 json_t *id_token = json_object_get(root, "id_token");
// //                 if (access_token && id_token) {
// //                     printf("Access Token: %s\n", json_string_value(access_token));
// //                     printf("ID Token: %s\n", json_string_value(id_token));
// //                 }
// //                 json_decref(root);
// //             } else {
// //                 fprintf(stderr, "Error parsing response JSON: %s\n", error.text);
// //             }
// //         } else {
// //             fprintf(stderr, "Error with curl request: %s\n", curl_easy_strerror(res));
// //         }
        
// //         // Clean up curl handle
// //         curl_easy_cleanup(curl);
// //     }
    
// //     curl_global_cleanup();
// // }

// // // Function to redirect user to the login page
// // void redirect_to_login() {
// //     char auth_url[1024];
// //     snprintf(auth_url, sizeof(auth_url), 
// //         "%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=openid%%20profile&state=randomstate",
// //         AUTHORITY, CLIENT_ID, REDIRECT_URI);
    
// //     printf("Go to the following URL to login:\n%s\n", auth_url);
// // }

// Function to handle the response body from curl
size_t
write_callback(void *ptr,
               size_t size,
               size_t nmemb,
               char *data)
{
    size_t total_size = size * nmemb;

    if (!data || !ptr)
        return 0;
    strcat(data, ptr);
    return total_size;
}

// Function to make a POST request and get the response
char*
post_request(const char *url,
             const char *data,
             struct curl_slist *headers)
{
    CURL *curl;
    CURLcode res;
    long http_code = 0;

    char *response = (char *)malloc(MAX_BUFFER);
    if (!response) {
        DEBUGPRINT("Memory allocation failed for response buffer!\n");
        return NULL;
    }
    response[0] = '\0';
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    #ifdef DEBUG
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    #endif

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            DEBUGPRINT("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(response);  // Free the response buffer on error
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return NULL;
        }

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        DEBUGPRINT("HTTP Response Code: %ld\n", http_code);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return response;
}

// // Function to make a GET request and get the response
// char*
// get_request(const char *url,
//             struct curl_slist *headers)
// {
//     CURL *curl;
//     CURLcode res;
    
//     char *response = (char *)malloc(MAX_BUFFER);
//     if (!response) {
//         DEBUGPRINT("Memory allocation failed for response buffer!\n");
//         return NULL;
//     }
//     response[0] = '\0';
//     curl_global_init(CURL_GLOBAL_DEFAULT);
//     curl = curl_easy_init();
    
//     if(curl) {
//         curl_easy_setopt(curl, CURLOPT_URL, url);
//         curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
//         curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
//         curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

//     #ifdef DEBUG
//         curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
//     #endif 
//         res = curl_easy_perform(curl);
//         if(res != CURLE_OK) {
//             // DEBUGPRINT("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
//             free(response);  // Free the response buffer on error
//             curl_easy_cleanup(curl);
//             curl_global_cleanup();
//             return NULL;
//         }

//         curl_easy_cleanup(curl);
//     }

//     curl_global_cleanup();
//     return response;
// }


// int
// msa_device_code_flow_verify(fastauthd_config_t fastauthd_config)
// {
//     char device_code_url[512];
//     char device_code_data[512];
//     struct curl_slist *headers = NULL;
//     const char *scope = "User.Read";

//     snprintf(device_code_url, sizeof(device_code_url), "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", fastauthd_config.tenant_id);
//     snprintf(device_code_data, sizeof(device_code_data), "client_id=%s&scope=%s", fastauthd_config.client_id, scope);

//     headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

//     //  Request device code
//     char *response = post_request(device_code_url, device_code_data, headers);
//     if (!response) {
//         DEBUGPRINT("Failed to get device code\n");
//         curl_slist_free_all(headers);
//         return -1;
//     }

//     DEBUGPRINT("Response from device code request: %s\n", response);

//     // Parse the response string to JSON
//     cJSON *json_response = cJSON_Parse(response);
//     if (!json_response) {
//         DEBUGPRINT("Error parsing JSON: %s\n", response);
//         free(response);
//         curl_slist_free_all(headers);
//         return -1;
//     }

//     // Get device code, verification URL and user code
//     cJSON *device_code_item = cJSON_GetObjectItemCaseSensitive(json_response, "device_code");
//     cJSON *verification_uri_item = cJSON_GetObjectItemCaseSensitive(json_response, "verification_uri");
//     cJSON *user_code_item = cJSON_GetObjectItemCaseSensitive(json_response, "user_code");

//     if (!verification_uri_item || !user_code_item || !device_code_item) {
//         DEBUGPRINT("Invalid response format\n");
//         cJSON_Delete(json_response);
//         free(response);
//         curl_slist_free_all(headers);
//         return -1;
//     }

//     const char *device_code = device_code_item->valuestring;
//     const char *verification_uri = verification_uri_item->valuestring;
//     const char *user_code = user_code_item->valuestring;

//     printf("Open the following URL in your browser: %s\n", verification_uri);
//     printf("Enter the code: %s\n", user_code);

//     char token_url[512];
//     snprintf(token_url, sizeof(token_url), "https://login.microsoftonline.com/%s/oauth2/v2.0/token", fastauthd_config.tenant_id);

//     char token_data[512];
//     snprintf(token_data, sizeof(token_data), "client_id=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s", fastauthd_config.client_id, device_code);

//     bool authorize_pending = false;

//     while (1) {
//         // Send token request
//         char *token_response = post_request(token_url, token_data, headers);
//         if (!token_response) {
//             DEBUGPRINT("Failed to get token\n");
//             cJSON_Delete(json_response);
//             free(response);
//             curl_slist_free_all(headers);
//             return -1;
//         }

//         DEBUGPRINT("Token response: %s\n", token_response);

//         // Parse token response
//         cJSON *token_json = cJSON_Parse(token_response);
//         if (!token_json) {
//             DEBUGPRINT("Error parsing token response: %s\n", token_response);
//             free(token_response);
//             cJSON_Delete(json_response);
//             free(response);
//             curl_slist_free_all(headers); 
//             return -1;
//         }

//         // Check for access_token
//         cJSON *access_token_item = cJSON_GetObjectItemCaseSensitive(token_json, "access_token");
//         if (access_token_item) {
//             const char *access_token = access_token_item->valuestring;
//             printf("Access Token: %s\n", access_token);
//             DEBUGPRINT("Access Token: %s\n", access_token);

//             // Step 3: Use the access token to get user info
//             char graph_url[] = "https://graph.microsoft.com/v1.0/me";
//             char authorization_header[4096];
//             snprintf(authorization_header, sizeof(authorization_header), "Authorization: Bearer %s", access_token);
            
//             struct curl_slist *graph_headers = NULL;
//             graph_headers = curl_slist_append(graph_headers, authorization_header);

//             char *graph_response = get_request(graph_url, graph_headers);
//             if (!graph_response) {
//                 DEBUGPRINT("Failed to get user info\n");
//                 cJSON_Delete(token_json);
//                 free(token_response);
//                 free(graph_response);
//                 cJSON_Delete(json_response);
//                 free(response);
//                 curl_slist_free_all(headers);
//                 return -1;
//             }
//             printf("The user info: %s\n", graph_response);
//             DEBUGPRINT("User Info: %s\n", graph_response);
//             cJSON_Delete(token_json);
//             free(token_response);
//             free(graph_response);
//             break;
//         }

//         // If the token isn't ready yet, sleep and retry
//         cJSON *error_item = cJSON_GetObjectItemCaseSensitive(token_json, "error");
//         if (error_item && strcmp(error_item->valuestring, "authorization_pending") == 0) {
//             if (!authorize_pending) {
//                 printf("Waiting for user authentication...\n");
//                 authorize_pending = true;
//             }
//         } else {
//             DEBUGPRINT("Error: %s\n", token_response);
//             cJSON_Delete(token_json);
//             free(token_response);
//             break;
//         }
//         cJSON_Delete(token_json);
//         free(token_response);
//     }
//     authorize_pending = false;

//     // Clean up
//     cJSON_Delete(json_response);
//     free(response);
//     curl_slist_free_all(headers);  // Free the headers list
//     return 0;
// }

// int
// msa_pkce_flow_verify(fastauthd_config_t fastauthd_config)
// {
//     // unsupport now
//     return -1;
// }

// int
// msa_ropc_flow_verify(fastauthd_config_t fastauthd_config_t)
// {
//     // unsupport now
//     return -1;
// }
gchar *
fastauthd_oidc_query_msa_access_token(char *device_code, char *tenant_id, char *client_id)
{
    char token_url[512];
    char token_data[512];
    char *token_response;

    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    snprintf(token_url, sizeof(token_url), "https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant_id);
    snprintf(token_data, sizeof(token_data), "client_id=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s", client_id, device_code);

    token_response = post_request(token_url, token_data, headers);
    if (!token_response) {
        DEBUGPRINT("Failed to get token\n");
        curl_slist_free_all(headers);
        return NULL;
    }

    return token_response;
}

gchar *
fastauthd_oidc_msa_device_code_get_usercode(char *tenant_id, char *client_id)
{
    char device_code_url[512];
    char device_code_data[512];
    struct curl_slist *headers = NULL;
    const char *scope = "User.Read";

    snprintf(device_code_url, sizeof(device_code_url), "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", tenant_id);
    snprintf(device_code_data, sizeof(device_code_data), "client_id=%s&scope=%s", client_id, scope);

    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

    //  Request device code
    gchar *response = post_request(device_code_url, device_code_data, headers);
    if (!response) {
        DEBUGPRINT("Failed to get device code\n");
        curl_slist_free_all(headers);
        return NULL;
    }

    return response;
}

gchar *
fastauthd_oidc_msa_verify_group(const gchar *username,
                                const gchar *access_token,
                                const gchar *token_type,
                                const gchar *group_id)
{
    char graph_url[] = "https://graph.microsoft.com/v1.0/me/checkMemberGroups";
    char authorization_header[4096];
    snprintf(authorization_header, sizeof(authorization_header), "Authorization: Bearer %s", access_token);
    
    struct curl_slist *graph_headers = NULL;
    graph_headers = curl_slist_append(graph_headers, authorization_header);
    graph_headers = curl_slist_append(graph_headers, "Content-Type: application/json");

    cJSON *json_body = cJSON_CreateObject();
    cJSON *group_ids_json = cJSON_CreateArray();

    cJSON_AddItemToArray(group_ids_json, cJSON_CreateString(group_id));
    cJSON_AddItemToObject(json_body, "groupIds", group_ids_json);

    // Convert the JSON object to a string
    char *json_string = cJSON_Print(json_body);

    // Don't forget to free the memory later!
    cJSON_Delete(json_body);

    char *graph_response = post_request(graph_url, json_string, graph_headers);
    if (!graph_response) {
        DEBUGPRINT("Failed to get user info\n");
        return NULL;
    }
    return graph_response;
}
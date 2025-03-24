#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <glib-2.0/glib.h>
#include <gio/gio.h>
#include <linux/limits.h>
#include <cjson/cJSON.h>

#define PAM_LOG_ERR(pamh, ...) pam_syslog(pamh, LOG_ERR, __VA_ARGS__)
#define PAM_LOG_WARNING(pamh, ...) pam_syslog(pamh, LOG_WARNING, __VA_ARGS__)
#define PAM_LOG_NOTICE(pamh, ...) pam_syslog(pamh, LOG_NOTICE, __VA_ARGS__)
#define PAM_LOG_INFO(pamh, ...) pam_syslog(pamh, LOG_INFO, __VA_ARGS__)
#define PAM_LOG_DEBUG(pamh, ...) pam_syslog(pamh, LOG_DEBUG, __VA_ARGS__)

#define OMN_AAD_PASSWD_DBPATH "/var/cache/omnaad/passwd/passwd.db"
#define OMN_AAD_GROUP_DBPATH "/var/cache/omnaad/group/group.db"
#define OMN_AAD_SHADOW_DBPATH "/var/cache/omnaad/shadow/shadow.db"

bool pwd_nss_cache = false;
GDBusConnection *fastauthd_connection = NULL;

bool
check_nss_cache_token(pam_handle_t *pamh, const gchar *password,
                const gchar *nss_db_password)
{
	// Check the username and local password in our data base
	// Now, current database is hardcoded
   // Fetch the shadow password entry
   gchar *encrypted_password;

   // Encrypt the entered password and compare with the stored hash
   encrypted_password = crypt(password, nss_db_password);
   if (strcmp(encrypted_password, nss_db_password) == 0) {
      return true;  // Authentication succeeded
   }
	return false;
}

gchar *
generate_salt()
{
   static gchar salt[17]; // 16 characters for the salt + 1 for the null terminator
   const gchar *salt_chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
   
   memcpy(salt, "$6$", 3);
   // Seed the random number generator
   srand(time(NULL));

   // Generate a 16-character salt
   for (int i = 3; i < 16; i++) {
      salt[i] = salt_chars[rand() % (sizeof(salt_chars) - 1)];
   }
   salt[16] = '\0'; // Null-terminate the string

   return salt;
}


int
update_password_in_db(const gchar *username,
                      const gchar *new_password)
{
   struct spwd *spwd;
   gchar *encrypted_new_password;
   // Generate a salt for the new password
   gchar *salt = generate_salt();

   // Encrypt the new password using the generated salt
   encrypted_new_password = crypt(new_password, salt);
   // Update the shadow entry logic here
   spwd = getspnam(username);
   if (spwd) {
      // Logic to update the spwd structure and save it back
      // This typically involves writing the new hashed password to the relevant database
      // Note: Ensure you manage file locks or synchronization if needed
      struct spwd new_spwd;
      memset(&new_spwd, 0, sizeof(new_spwd));  // Initialize to zero

      // Fill in the new values
      new_spwd.sp_namp = strdup(username);
      new_spwd.sp_pwdp = strdup(encrypted_new_password);  // New hashed password
      new_spwd.sp_lstchg = time(NULL) / (24 * 60 * 60);  // Last change (in days)
      new_spwd.sp_min = 0;  // Minimum days between changes
      new_spwd.sp_max = 99999;  // Maximum days until password must be changed
      new_spwd.sp_warn = 7;  // Days to warn before expiration
      new_spwd.sp_inact = -1;  // Inactive period
      new_spwd.sp_expire = -1;  // Expiration date

      FILE *shadow_file = fopen(OMN_AAD_SHADOW_DBPATH, "r+");
      if (!shadow_file) {
         return PAM_SYSTEM_ERR;  // Handle file opening errors
      }

      // Read through the shadow file, looking for the user entry
      gchar line[256];
      long pos;

      while (fgets(line, sizeof(line), shadow_file)) {
         if (strstr(line, username) == line) {  // Found the line for the user
            pos = ftell(shadow_file);  // Get the current position
            fseek(shadow_file, pos - strlen(line), SEEK_SET);  // Go back to overwrite
            
            // Construct the new line for the shadow file
            fprintf(shadow_file, "%s:%s:%ld:%ld:%ld:%ld:%ld:%ld:\n",
                     new_spwd.sp_namp, new_spwd.sp_pwdp,
                     new_spwd.sp_lstchg, new_spwd.sp_min,
                     new_spwd.sp_max, new_spwd.sp_warn,
                     new_spwd.sp_inact, new_spwd.sp_expire);
            fflush(shadow_file);  // Flush the changes to the file
            break;
         }
      }

      fclose(shadow_file);  // Close the file
      return 0; // Success
   }

   return -1; // User not found
}

GVariant *
fastauthd_gdbus_call_deviceflow_method(const GVariant *params, const gchar *method, GError *error)
{
   gchar object_path[PATH_MAX];

   snprintf(object_path, PATH_MAX, "/deviceflow/%s", method);

   return g_dbus_connection_call_sync(fastauthd_connection,
      "com.fastauthd.broker",
      object_path,
      "com.fastauthd.broker.deviceflow",
      method,
      params,
      NULL,
      G_DBUS_CALL_FLAGS_NONE,
      -1,
      NULL,
      &error);
}

static int
init_fastauthd_dbus_connection()
{
   GError *error = NULL;

   fastauthd_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
   if (error != NULL) {
      g_print("Error getting D-Bus connection: %s\n", error->message);
      g_error_free(error);
      return -1;
   }
   return 0;
}

bool
request_fastauthd_query_nssdb(const gchar *username, struct spwd *spwd)
{
   GError *error = NULL;
   GVariant *result, *params;
   gint errcode;
   gchar *usrpwdinfo;

   params = g_variant_new("(s)", username);
   result = fastauthd_gdbus_call_deviceflow_method(params, "query_fastauthd_nssdb", error);
   if (error != NULL) {
      g_print("Error to send dbus message to fastauthd: %s\n", error->message);
      g_error_free(error);
      return false;
   }
   if (!result) {
      return false;
   }

   g_variant_get(result, "(is)", &errcode, &usrpwdinfo);
   if (errcode != 0 || !usrpwdinfo) {
      return false;
   }

   g_variant_unref(result);
   return true;
}

bool
request_fastauthd_device_flow_devicecode(const gchar *username, gchar **response_json)
{
   GError *error = NULL;
   GVariant *result, *params;
   gint errcode;

   params = g_variant_new("(s)", username);
   result = fastauthd_gdbus_call_deviceflow_method(params, "request_device_code", error);
   if (error != NULL) {
      g_print("Error to send dbus message to fastauthd: %s\n", error->message);
      g_error_free(error);
      return false;
   }
   if (!result) {
      return false;
   }
   g_variant_get(result, "(is)", &errcode, response_json);

   if (errcode != 0 || !response_json) {
      return false;
   }

   g_variant_unref(result);
   return true;
}

int
request_fastauthd_device_code_authresult(const gchar *device_code, gchar **access_token, gchar **token_type)
{
   GError *error = NULL;
   GVariant *result, *params;
   gint errcode;
   gchar *response;
   
   params = g_variant_new("(s)", device_code);
   result = fastauthd_gdbus_call_deviceflow_method(params, "query_msa_auth_result", error);
   if (error != NULL) {
      g_print("Error to send dbus message to fastauthd: %s\n", error->message);
      g_error_free(error);
      return -1;
   }
   if (!result) {
      return -1;
   }
   g_variant_get(result, "(is)", &errcode, &response);
   cJSON *json = cJSON_Parse(response);
   if (json == NULL) {
      printf("JSON解析失败\n");
      return -1;
   }

   *token_type = cJSON_GetObjectItemCaseSensitive(json, "token_type")->valuestring;
   *access_token = cJSON_GetObjectItemCaseSensitive(json, "access_token")->valuestring;

   cJSON_Delete(json);
   g_variant_unref(result);

   return errcode;
}

int
request_fastauthd_verify_user_and_group(const gchar *username, const gchar *access_token, const gchar *token_type)
{
   GError *error = NULL;
   GVariant *result, *params;
   gint errcode;
   gchar *response;

   params = g_variant_new("(sss)", username, access_token, token_type);
   result = fastauthd_gdbus_call_deviceflow_method(params, "verify_user_and_group", error);
   if (error != NULL) {
      g_print("Error to send dbus message to fastauthd: %s\n", error->message);
      g_error_free(error);
      return -1;
   }
   if (!result) {
      return -1;
   }
   g_variant_get(result, "(is)", &errcode, &response);
   printf("The response is: %s\n", response);
   g_variant_unref(result);
   return errcode;
}
int
request_fastauthd_update_nssdb(const gchar *username,
                              const gchar *password)
{
   return PAM_SUCCESS;
}

int
write_passwd_entry(pam_handle_t *pamh,
                   const gchar *username,
                   const gchar *password)
{
   FILE *file = fopen(OMN_AAD_PASSWD_DBPATH, "a");
   if (!file) {
      PAM_LOG_ERR(pamh, "Failed to open passwd file: %s", OMN_AAD_PASSWD_DBPATH);
      return PAM_SYSTEM_ERR;
   }

   // Write in the format: username:x:UID:GID:USER INFO:HOME:SHELL
   fprintf(file, "%s:x:1005:1005::/home/%s:/bin/bash\n", username, username);
   fclose(file);
   return PAM_SUCCESS;
}

// Function to write a user entry to the custom shadow file
int
write_shadow_entry(pam_handle_t *pamh,
                   const gchar *username,
                   const gchar *password)
{
   FILE *file;
   time_t now;
   gchar *encrypted_new_password;
   gchar *salt;
   long days_since_epoch;

   file = fopen(OMN_AAD_SHADOW_DBPATH, "a");
   if (!file) {
      PAM_LOG_ERR(pamh, "Failed to open shadow file: %s", OMN_AAD_SHADOW_DBPATH);
      return PAM_SYSTEM_ERR;
   }

   // Generate a salt for the new password
   salt = generate_salt();

   // Encrypt the new password using the generated salt
   encrypted_new_password = crypt(password, salt);

   // Get current time stamp
   time(&now);

   // Convert to days since the Unix epoch (January 1, 1970)
   days_since_epoch = now / (60 * 60 * 24);

   // Write in the format: username:encrypted_password:last_changed:...
   fprintf(file, "%s:%s:%ld:0:99999:7:::\n", username, encrypted_new_password, days_since_epoch); // Replace password with hashed password
   fclose(file);

   return PAM_SUCCESS;
}

// Function to write a user entry to the custom group file
int
write_group_entry(pam_handle_t *pamh,
                  const gchar *username)
{
   FILE *file;

   file = fopen(OMN_AAD_GROUP_DBPATH, "a");
   if (!file) {
      PAM_LOG_ERR(pamh, "Failed to open group file: %s", OMN_AAD_GROUP_DBPATH);
      return PAM_SYSTEM_ERR;
   }

   // Write in the format: groupname:x:GID:user1,user2,...
   fprintf(file, "%s:x:1005:\n", username); // Simple group with the username
   fclose(file);

   return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh,
                    int flags,
                    int argc,
                    const gchar **argv)
{
   // Initialize variables
   const gchar *username;
   int retval;

   // Get the username from PAM
   retval = pam_get_user(pamh, &username, NULL);
   if (retval != PAM_SUCCESS) {
      PAM_LOG_ERR(pamh, "Failed to get username: %s", pam_strerror(pamh, retval));
      return retval;
   }

   // You can add session setup logic here
   PAM_LOG_INFO(pamh, "Opening session for user: %s", username);

   // Return success
   return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh,
                     int flags,
                     int argc,
                     const gchar **argv)
{
    const gchar *username;
    int retval;

    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        PAM_LOG_ERR(pamh, "Failed to get username: %s", pam_strerror(pamh, retval));
        return retval;
    }

    PAM_LOG_INFO(pamh, "Closing session for user: %s", username);

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh,
               int flags,
               int argc,
               const gchar **argv )
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh,
                 int flags,
                 int argc,
                 const gchar **argv)
{
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

static int password_changed = 0;

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh,
                 int flags,
                 int argc,
                 const gchar **argv)
{
   const gchar *username;
   const gchar *old_password;
   const gchar *new_password;
   struct spwd *spwd;

   // Get the username
   if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
      return PAM_USER_UNKNOWN;
   }

   // Fetch the shadow password entry
   spwd = getspnam(username);
   if (!spwd) {
      return PAM_USER_UNKNOWN;
   }

   // Get the new password
   if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&new_password) != PAM_SUCCESS) {
      if (!new_password) {
         return PAM_SUCCESS;
      }
      return PAM_USER_UNKNOWN;
   }

   if (update_password_in_db(username, new_password) != 0) {
      return PAM_SYSTEM_ERR;  // Handle update failure
   }

   return PAM_SUCCESS;  // Password change successful
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh,
                    int flags,
                    int argc,
                    const gchar **argv)
{
	int retval;
	const gchar *username = NULL;
	const gchar *password = NULL;
   struct spwd spwd;

   init_fastauthd_dbus_connection();
	retval = pam_get_user(pamh, &username, NULL);
	if (retval != PAM_SUCCESS || !username) {
		PAM_LOG_ERR(pamh, "pam_get_user(%s) failed.\n", username);
		return retval;
	}

   pwd_nss_cache = request_fastauthd_query_nssdb(username, &spwd);
	if (pwd_nss_cache) {
		// check local password if domain user set a local password
		retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
		if (retval != PAM_SUCCESS) {
         PAM_LOG_ERR(pamh, "pam_get_authtok() failed.\n");
			return retval;
		}

		if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
			if (password == NULL || strcmp(password, "") == 0) {
            PAM_LOG_ERR(pamh, "null password is disallowed, please contact your admin.\n");
				return PAM_PERM_DENIED;
			}
		}
		if (!getpwnam(username)) {
         PAM_LOG_ERR(pamh, "User (%s) is not found.\n", username);
			return PAM_USER_UNKNOWN;
		}
		if (check_nss_cache_token(pamh, password, spwd.sp_pwdp)) {
			return PAM_SUCCESS;
		}
	} else {
		// Request device code from Microsoft IdP
      gchar *device_code_json_data, *access_token = NULL, *token_type = NULL;
      cJSON *device_code_json_obj, *device_code_item, *verify_uri_item,
            *user_code_item, *message_item;
      const gchar *device_code, *verify_uri, *user_code, *message;
      int errcode = -2;
      static int max_retry_cnt = 3;

      if (!request_fastauthd_device_flow_devicecode(username, &device_code_json_data)) {
         PAM_LOG_ERR(pamh, "Get device code failed.\n");
         return PAM_AUTH_ERR;
      }
      // Parse the response string to JSON
      device_code_json_obj = cJSON_Parse(device_code_json_data);
      if (!device_code_json_obj) {
         PAM_LOG_ERR(pamh, "Error parsing JSON: %s\n", device_code_json_data);
         free(device_code_json_data);
         return PAM_AUTH_ERR;
      }

      // Get device code, verification URL and user code
      device_code_item = cJSON_GetObjectItemCaseSensitive(device_code_json_obj, "device_code");
      verify_uri_item = cJSON_GetObjectItemCaseSensitive(device_code_json_obj, "verification_uri");
      user_code_item = cJSON_GetObjectItemCaseSensitive(device_code_json_obj, "user_code");
      message_item = cJSON_GetObjectItemCaseSensitive(device_code_json_obj, "message");

      if (!verify_uri_item || !user_code_item || !device_code_item || !message_item) {
         PAM_LOG_ERR(pamh, "Invalid response format\n");
         cJSON_Delete(device_code_json_obj);
         free(device_code_json_data);
         return PAM_AUTH_ERR;
      }

      device_code = device_code_item->valuestring;
      verify_uri = verify_uri_item->valuestring;
      user_code = user_code_item->valuestring;
      message = message_item->valuestring;

      pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, NULL, "\n1. Open the following URL in your browser: %s\n2. Enter the code : %s\n3. Please press enter if authenticate successful.\n", verify_uri, user_code);

      while (request_fastauthd_device_code_authresult(device_code, &access_token, &token_type) == -2) {
         free(access_token);
         access_token = NULL;
         sleep(3);
      }
      if (access_token) {
         if (request_fastauthd_verify_user_and_group(username, access_token, token_type) != 0) {
            return PAM_AUTH_ERR;
         }
      }
      if (!(flags & PAM_SILENT)) {
         gchar *msa_password;
         gchar *msa_retype_password;

         if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF,
                        (gchar **)&msa_password, "Set local Password: ") != PAM_SUCCESS) {
            PAM_LOG_ERR(pamh, "pam_prompt failed, reason unknown.\n");
            return PAM_SYSTEM_ERR;
         }
         do {
            if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF,
                           (gchar **)&msa_retype_password, "Re-enter local Password: ") != PAM_SUCCESS) {
               PAM_LOG_ERR(pamh, "pam_prompt failed, reason unknown.\n");
               return PAM_SYSTEM_ERR;
            }
            max_retry_cnt--;
         } while (strcmp(msa_password, msa_retype_password) != 0 && max_retry_cnt > 0);

         if (max_retry_cnt != 0) {
            return request_fastauthd_update_nssdb(username, msa_password);
         }
         return PAM_MAXTRIES;
      }
   }
	
	return PAM_AUTH_ERR;
}

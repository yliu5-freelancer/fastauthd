#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static int
fastauthd_session_worker_handler(int number_of_messages,
                              const struct pam_message **messages,
                              struct pam_response      **responses,
                              void *ptr);
const struct pam_conv conv = {
	fastauthd_session_worker_handler,
	NULL
};
pam_handle_t* pamh = NULL;
static int
fastauthd_session_worker_handler(int number_of_messages,
                              const struct pam_message **messages,
                              struct pam_response      **responses,
                              void *ptr)
{
   struct pam_response *replies;

   printf("Received %d new messages.\n", number_of_messages);
   if (number_of_messages < 0) {
            printf("Messages number error\n");
            return PAM_CONV_ERR;
   }
   replies = (struct pam_response *) calloc (number_of_messages,
                                             sizeof (struct pam_response));
   for (int i = 0; i < number_of_messages; i++) {
            char    *response;

            response = NULL;

            switch (messages[i]->msg_style) {
            case PAM_PROMPT_ECHO_ON:
   printf("ECHO ON Message: %s\n", messages[i]->msg);
   char *username = malloc(1024);
   memset(username, 0, 1024);
   if (strcmp(messages[i]->msg, "login:") == 0) {
      fgets(username, 1024, stdin);
      username[strlen(username) - 1] = '\0';
   }
   response = username;
                  break;
            case PAM_PROMPT_ECHO_OFF:
                  //response = getpass(messages[i]->msg);
   printf("ECHO OFF Message: %s\n", messages[i]->msg);
   char *password = malloc(1024);
   memset(password, 0, 1024);
   fgets(password, 1024, stdin);
   password[strlen(password) - 1] = '\0';
   response = password;
                  break;
            case PAM_TEXT_INFO:
   printf("TEXT INFO Message: %s\n", messages[i]->msg);
                  break;
            case PAM_ERROR_MSG:
                  printf("ERROR Message: %s\n", messages[i]->msg);
                  return PAM_CONV_ERR;
            case PAM_BINARY_PROMPT:
   printf("BINARY PROMPT Message: %s\n", messages[i]->msg);
                  break;
            default:
                  printf("Unknown style: %d\n", messages[i]->msg_style);
                  break;

            }
            replies[i].resp = response;
            replies[i].resp_retcode = PAM_SUCCESS;
   }
   *responses = replies;
   return PAM_SUCCESS;
}


int main(int argc, char *argv[]) {
	int retval;
	const char* user = "nobody";


	printf("PAM conversion started.\n");
	retval = pam_start("fastauthd-auth", NULL, &conv, &pamh);

	// Are the credentials correct?
	if (retval == PAM_SUCCESS) {
		retval = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
	}

	// Can the accound be used at this time?
	if (retval == PAM_SUCCESS) {
		printf("PAM authenticate success.\n");
		retval = pam_acct_mgmt(pamh, 0);
	} else {
		printf("PAM authenticate failed.\n");
		exit(-1);
	}

	// Did everything work?
	if (retval == PAM_SUCCESS) {
		printf("PAM account management success.\n");
	} else {
		printf("PAM account management failed.\n");
		goto out;
	}

	retval = pam_open_session(pamh, 0);
   	if (retval != PAM_SUCCESS) {
      		printf("pam_open_session error!");
	}

	printf("PAM session open success.\n");
out:
	// close PAM (end session)
	if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		printf("check_user: failed to release authenticator\n");
		exit(-1);
	}

	return retval == PAM_SUCCESS ? 0 : 1;
}

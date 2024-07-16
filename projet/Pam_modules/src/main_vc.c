#include <security/_pam_types.h>
#define _GNU_SOURCE
#include <curl/curl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
// #include <libpq-fe.h>
#include <postgresql/libpq-fe.h>
#include <security/pam_ext.h>

#include "../include/b64.h"
#include "../include/kc_auth.h"
#include "../include/logger.h"

// Certificate to validate the JWT against

#define TRUSTED_CERTIFICATE_PATH                                               \
  "/etc/ssl/certs/keycloak_verifiable-credentials.pem"
#define PORT 12345

void cleanup_pointer(pam_handle_t *handle, void *data, int error_status) {
  free(data);
} // Cleanup function

static int converse(pam_handle_t *pamh, int nargs,
                    const struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  logger("request pass", "just entered converse");
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    logger("request pass", "could not get item PAM_CONV");
    return retval;
  }
  logger("request pass", "could get item PAM_CONV : conving rn");
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static char *request_pass(pam_handle_t *pamh, int echocode,
                          const char *prompt) {
  // Query user for verification code
  logger("request pass", "just entered");
  const struct pam_message msg = {.msg_style = echocode, .msg = prompt};
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;
  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    logger("request pass", "Did not receive code from user");
    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
                                   const char **argv) {
  printf("pam_sm_authenticate\n");

  int pam_code, retval_code = PAM_SUCCESS;
  const char *username = NULL, *token = NULL;
  char *prompt = NULL, *grants = NULL, *hash = NULL;

  char **SD_array = NULL, **SD_json = NULL, **decoded_SD = NULL;
  int nSD_array, nSD_json, length;

  char *public_key = NULL;

  int ndisclosures = 0;
  char **parsed_sd_jwt = NULL;

  pam_code = pam_get_user(handle, &username, "USERNAME: ");
  logger("pam_sm_authenticate vc pam", username);
  if (pam_code != PAM_SUCCESS) {
    fprintf(stderr, "Can't get username");
    logger("pam_sm_authenticate vc pam", "Could not get username");
    retval_code = PAM_PERM_DENIED;
    goto cleanup;
  }

  // pam_prompt(handle, int style, char **response, const char *fmt, ...)
  /* Asking the application for a token */
  asprintf(&prompt,
           "SD-JWT Verifiable Credential based authentication.\nTo access this "
           "ressource, you have to send your SD-JWT presentation at PORT : "
           "%d.\nYou will need to disclose your username.\nContinue ? (y/N)  ",
           PORT);
  pam_code = pam_get_authtok(handle, PAM_AUTHTOK, &token, prompt);
  free(prompt);
  //return PAM_SUCCESS;
  logger("vc auth just after the prompt", token);
  // return PAM_SUCCESS;

  if (pam_code != PAM_SUCCESS || token == NULL) {
    fprintf(stderr, "Can't get user token\n");
    logger("pam_sm_authenticate vc pam", "Could not get token");
    retval_code = PAM_AUTHTOK_ERR;
    goto cleanup;
  }
  if (!(strcmp(token, "Y") == 0 || strcmp(token, "y") == 0)) {
    retval_code = PAM_TRY_AGAIN;
    printf("User denied token-based authentication\n");
    logger("pam_sm_authenticate vc pam",
           "User denied token-based authentication");
    goto cleanup;
  }
  free(token);

  // Get the token from the socket
  receive_jwt_socket((char **)&token, PORT);
  logger("auth", "inside main");
  char *token_info;
  asprintf(&token_info, "The token is %s\nThe lenght of this token is %ld",
           token, strlen(token));
  logger("token info from socket retrieved by socket : ", token_info);
  free(token_info);

  if (token == NULL || strcmp(token, "") == 0) {
    fprintf(stderr, "Null authentication token is not allowed!.");
    retval_code = PAM_BAD_ITEM;
    goto cleanup;
  }
  public_key = (char *)get_pub_key(TRUSTED_CERTIFICATE_PATH);
  logger("auth main vc", "just got certificate");
  char *full_sd_jwt = NULL;
  full_sd_jwt = strdup(token);
  parse_SD_JWT_VC(full_sd_jwt, &parsed_sd_jwt, &ndisclosures);
  if (!validate_jwt((const char **)&parsed_sd_jwt[0],
                    (const char **)&public_key)) {
    // The token is a valid token signed from a trusted source
    logger("auth main vc", "jwt is not valid");

    retval_code = PAM_PERM_DENIED;
    goto cleanup;
  }

  // Check if the username is in the disclosed claims
  if (decode_all_sd((const char **)parsed_sd_jwt, ndisclosures, &decoded_SD,
                    &length) != 1) {
    fprintf(stderr, "Could not decode the SDs\n");
    logger("auth main vc", "Could not decode the SDs");
    retval_code = PAM_PERM_DENIED;
    goto cleanup;
  };
  logger("auth main vc", "SDs decoded succesfully");

  int index;
  if (check_claim_in_disclosures((const char **)decoded_SD, length, "username",
                                 username, &index) != 1) {
    fprintf(stderr, "User not in the disclosed claims\n");
    logger("auth main vc", "User not in the disclosed claims");
    retval_code = PAM_PERM_DENIED;
    goto cleanup;
  }; // User is in the disclosed claims at the index
  logger("auth main vc", "User is inside disclosed claims");

  // Check if the claimed disclosed actually true is in the _sd
  grants = extract_grant_jwt((const char **)&parsed_sd_jwt[0], "_sd");

  json_array_2_array(&grants, &SD_array, &nSD_array);
  if (check_claim_validity((const char **)SD_array, nSD_array,
                           parsed_sd_jwt[index]) != 1) {
    //+1 because the first element is the jwt itself
    fprintf(stderr, "Claimed disclosure is not in _sd\n");
    logger("sm claim not in _sd", username);
    retval_code = PAM_PERM_DENIED;
    goto cleanup;
  }
  pam_set_item(handle, PAM_USER, username);
  logger("main vc auth","going to cleanup");
cleanup:
  if (public_key != NULL)
    free(public_key);
  if (decoded_SD != NULL)
    free(decoded_SD);
  if (hash != NULL)
    free(hash);
  if (grants != NULL)
    free(grants);
  if (SD_array != NULL)
    cleanupArray(SD_array, nSD_array);
  if (SD_json != NULL)
    cleanupArray(SD_json, nSD_json);
  if (parsed_sd_jwt != NULL) {
    cleanupArray(parsed_sd_jwt, ndisclosures);
  }
  logger("main vc auth","returning ...");
  return retval_code;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  /* This struct contains the expiry date of the account */
  printf("pam_sm_acct_mgmt\n");
  logger("pam_sm_acct_mgmt", "username to be defined");
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  printf("pam_sm_setcred\n");
  logger("pam_sm_setcred", "username to be defined");
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  /* Get the username from PAM */
  const char *username;
  pam_get_item(pamh, PAM_USER, (const void **)&username);

  logger("pam_sm_open_session", username);
  printf("Opening session for user %s...\n", username);

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {

  const char *username;
  // token based authentication, there is no session to close
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  printf("pam_sm_chauthtok \n");
  return PAM_PERM_DENIED;
}
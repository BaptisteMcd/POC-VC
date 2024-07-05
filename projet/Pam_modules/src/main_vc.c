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

#include "../include/b64.h"
#include "../include/kc_auth.h"
#include "../include/logger.h"

void cleanup_pointer(pam_handle_t *handle, void *data, int error_status) {
  free(data);
} // Cleanup function

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
                                   const char **argv) {
  logger("pam_sm_authenticate", "username to be defined");
  printf("pam_sm_authenticate\n");

  int pam_code;
  const char *username = NULL;
  const char *token = NULL;

  /* Asking the application for an  username */
  pam_code = pam_get_user(handle, &username, "USERNAME: ");
  if (pam_code != PAM_SUCCESS) {
    fprintf(stderr, "Can't get username");
    logger("pam_sm_authenticate vc pam", "Could not get username");
    return PAM_PERM_DENIED;
  }
  /* Asking the application for a token */
  pam_code =
      pam_get_authtok(handle, PAM_AUTHTOK, &token, "Authentifcation token : ");
  if (pam_code != PAM_SUCCESS) {
    fprintf(stderr, "Can't get user token");
    logger("pam_sm_authenticate vc pam", "Could not get token");
    return PAM_PERM_DENIED;
  }

  asprintf(
      (char **)&token,
      "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHd1pmZHVfeEE1TVlKbUlX"
      "bnJBZHZiRXhNTVdHZHNxZlkycW9xRlZoVlBNIn0."
      "eyJfc2QiOlsiYUlxX2x3WTdMY1NfNTM1RzhfQVp1U2x0SXBTcW53amFwVjFNd05nQkZicyIs"
      "ImRDMkljS0R1SS15WUg1S1U3Nnd0aGlURWIyR3FFZ1A3dVllek5Wb241aDAiLCJxaDNGYW5R"
      "ZlVpMjVOTWFvcGdZcGtKcDB5MlRHZlR3QWJXS3B4VlB4RUZRIl0sIl9zZF9hbGciOiJTSEEt"
      "MjU2IiwiaXNzIjoiZGlkOndlYjp0ZXN0Lm9yZyIsIm5iZiI6MTcxOTIzNDk1NSwidmN0Ijoi"
      "TmF0dXJhbFBlcnNvbkNyZWRlbnRpYWwiLCJqdGkiOiJ1cm46dXVpZDo5MWI5YWFhZC1mYTcx"
      "LTRiNmItODUzYy1hYTQ4ZGYwNDdlMGYifQ."
      "RWg2UUqluXsnrSDDkwQ0Dz6M1N3fGO9XjBZenEMIAOTbfOQwjG5eU9jDqRlysSaQ6nffBR1I"
      "G6Gx1HDq_"
      "e8yu33l192GMf6oyTI3QX7I2D4TdWWLTSNfBbxIs9jpaUMpkBmz01NBjsKFOsaz5X09wHH3C"
      "gfT3BRMiDd3Qi_iDBaNSZ5pz_ij3TD_nLIsfGikxCpPlIj8KPAIffrWczl4X5ikNh8Bj-"
      "X67YbDKZ0iHtEhU18vaGHE6YpBCY_Kl6DBGEJ_fYiN33sP5hjuRJkaNCpHYj_"
      "Ix6cqJUtZeHSIxez1Q4Jq3KMIVi5Mi5fqpai6hoNcG-mjFbm9jLI1cEh8PQ~"
      "WyJpX2dTSC1McUYydjBuRnZQTDl0ZUJnIiwgInJvbGVzIiwgW3sibmFtZXMiOiBbIkVNUExP"
      "WUVFIl0sICJ0YXJnZXQiOiAiZGlkOndlYjp0ZXN0LW1hcmtldHBsYWNlLm9yZyJ9XV0");
  // On est bon ici
  // TODO editer les fonctions pour transmettre le contenu du token d'une
  // manière ou d'une autre

  if (token == NULL || strcmp(token, "") == 0) {
    fprintf(stderr, "Null authentication token is not allowed!.");
    return PAM_PERM_DENIED;
  }

  const char *public_key =
      "-----BEGIN PUBLIC "
      "KEY-----"
      "\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1M1vl2mW0ewMctKEoCYG6+"
      "SgV9TqN+4oIt2ZLkQb1O+yWGTWuu8h2U7yZ+"
      "Dc1JfSPUd45eU1p9j3rYu5Bs2Labc6zZUYyBMjZXopv/"
      "AqIOhvuTRRg7v4yRkC6QACniLndPCkanlp/"
      "8dL98Gmm8x+"
      "oOjYf1UFbGxjGqqVxfNVZmGi9NLE6AM0e4wmBVknwWTcC3TTHDxgAxHHa0GhL1y7OYsmw9Kz"
      "1riUWlr0Az3lBclOFACbOp/"
      "cGnyHnotErw1xKVQtGOv4GIsYQZr4jIeQkoFcqbAQVOk30NjTRNgVra2JzEpMvhbm4l+"
      "WHK2OfsPfBx6OKTOmet6zJnnNC608jQIDAQAB\n-----END PUBLIC KEY-----";

  char *full_sd_jwt = NULL;
  full_sd_jwt = strdup(token);
  char *jwt = NULL;
  char **parsed_sd_jwt = NULL;
  unsigned long ndisclosures;
  parse_SD_JWT_VC(full_sd_jwt, &parsed_sd_jwt, &ndisclosures);

  if (!validate_jwt((const char **)&parsed_sd_jwt[0], &public_key)) {
    // The token is a valid token signed from a trusted source
    logger("vc the token valid", username);
    return PAM_PERM_DENIED;
  }

  char *decoded_SD = NULL;
  decoded_SD = base64_decode(parsed_sd_jwt[1]);

  char **SD_json = NULL;
  int nSD_json;
  json_array_2_array(&decoded_SD, &SD_json, &nSD_json);

  if (!is_in_array((const char **)SD_json, nSD_json, "roles")) {
    return PAM_PERM_DENIED;
  }
  if (!is_in_array((const char **)SD_json, nSD_json, "EMPLOYEE")) {
    return PAM_PERM_DENIED;
  }
  free(full_sd_jwt);
  full_sd_jwt = strdup(token);

  char *hash = NULL;
  SHA256_sum(parsed_sd_jwt[1], &hash);
  printf("Welcome, %s\n", username);

  char *grants = NULL;
  grants = extract_grant_jwt((const char **)&parsed_sd_jwt[0], "_sd");
  printf("The grants found in the jwt : %s \n", grants);

  char **SD_array = NULL;
  int nSD_array;
  json_array_2_array(&grants, &SD_array, &nSD_array);
  PrintArray(SD_array, nSD_array);

  if (check_claim_validity((const char **)SD_array, nSD_array,
                           parsed_sd_jwt[1]) != 1) {
    fprintf(stderr, "Claimed disclosure is not in _sd\n");
    logger("sm claim not in _sd", username);
    return PAM_PERM_DENIED;
  }

  // set the user env and tokens
  pam_set_item(handle, PAM_USER, username);
  //  pam_set_data(handle, "access_token", access_token, cleanup_pointer);
  //    pam_set_item(handle, PAM_AUTHTOK, access_token);

  return PAM_SUCCESS;
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

  char path_tokens[512];
  sprintf(path_tokens, "/tmp/.tokens");

  // Retrieve the previously set tokens and write them to a file
  char *access_token;
  char *id_token;
  char *refresh_token;
  pam_get_data(pamh, "access_token", (const void **)&access_token);
  pam_get_data(pamh, "id_token", (const void **)&id_token);
  pam_get_data(pamh, "refresh_token", (const void **)&refresh_token);

  write_tokens(path_tokens, access_token, id_token, refresh_token);

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
#define _GNU_SOURCE
#include <curl/curl.h>
#include <postgresql/libpq-fe.h>
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
#include "../include/b64.h"
#include "../include/kc_auth.h"
#include "../include/logger.h"
#include <security/pam_appl.h>
// #include "../src/kc_auth.c"

#define TOKEN_FILE ".token"
#define TOKEN_FIELD "sd_jwt_token"
#define TRUSTED_CERTIFICATE_PATH                                               \
  "/etc/ssl/certs/keycloak_verifiable-credentials.pem"

void cleanup_pointer(pam_handle_t *handle, void *data, int error_status) {
  free(data);
}



PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
                                   const char **argv) {
  const char *username = NULL;
  int retval_code;

  logger("auth", "just before prompr conversation");
  //request_pass(handle, PAM_TEXT_INFO, "LOL tu l'as vu ?\n");
  logger("auth", "just after prompr conversation");
  retval_code = pam_get_user(handle, &username, "USERNAME: ");
  /* Asking the application for a token */
  char *prompt = NULL, *hash = NULL;
  asprintf(&prompt,
           "Token-based authentication, file: %s, field: %s.\nYou will need to "
           "disclose your username.\nContinue ? (y/N)  ",
           TOKEN_FILE, TOKEN_FIELD);
  const char *token = NULL;
  retval_code = pam_get_authtok(handle, PAM_AUTHTOK, &token, prompt);

  // My arrays of char **
  char **SD_array = NULL, **SD_json = NULL, **decoded_SD = NULL;
  int nSD_array, nSD_json, ndecoded_SD;

  char *public_key = NULL;

  int ndisclosures = 0;
  char **parsed_sd_jwt = NULL;

  /* Asking the application for an  username */
  if (retval_code != PAM_SUCCESS) {
    fprintf(stderr, "Can't get username");
    return PAM_PERM_DENIED;
  }
  logger("pam_sm_authenticate pg pam", username);

  if (!(strcmp(token, "Y") == 0 || strcmp(token, "y") == 0)) {
    retval_code = PAM_TRY_AGAIN;
    printf("User denied token-based authentication\n");
    logger("pam vc pg", "user denied token authentication");
    goto cleanup;
  }
  free(prompt);
  // Shunt if user is postgres
  if (strcmp(username, "postgres") == 0) {
    // check password
    if (retval_code != PAM_SUCCESS) {
      fprintf(stderr, "Can't get password");
      return PAM_PERM_DENIED;
    }
    if (strcmp(token, "postgres") != 0) {
      fprintf(stderr, "Wrong password\n");
      return PAM_PERM_DENIED;
    }
    return PAM_SUCCESS;
  }
  read_token(TOKEN_FILE, (char **)&token, TOKEN_FIELD);
  if (retval_code != PAM_SUCCESS || token == NULL) {
    fprintf(stderr, "Can't get user token\n");
    logger("pam_sm_authenticate vc pam", "Could not get token");
    retval_code = PAM_AUTHTOK_ERR;
    goto cleanup;
  }

  if (token == NULL || strcmp(token, "") == 0) {
    fprintf(stderr, "Null authentication token is not allowed!.");
    retval_code = PAM_BAD_ITEM;
    goto cleanup;
  }
  public_key = (char *)get_pub_key(TRUSTED_CERTIFICATE_PATH);

  char *full_sd_jwt = NULL;
  full_sd_jwt = strdup(token);
  parse_SD_JWT_VC(full_sd_jwt, &parsed_sd_jwt, &ndisclosures);
  if (!validate_jwt((const char **)&parsed_sd_jwt[0],
                    (const char **)&public_key)) {
    // The token is a valid token signed from a trusted source
    retval_code = PAM_PERM_DENIED;
    goto cleanup;
  }

  // Check if the username is in the disclosed claims
  if (decode_all_sd((const char **)parsed_sd_jwt, ndisclosures, &decoded_SD,
                    &ndecoded_SD) != 1) {
    fprintf(stderr, "Could not decode the SDs\n");
    retval_code = PAM_PERM_DENIED;
    goto cleanup;
  };

  //  logger("auth pg jeton valide pour utilisateur : ", token_user);
  int index;
  check_claim_in_disclosures((const char **)decoded_SD, ndecoded_SD, "roles",
                             "ADMIN", &index);

  // Now we need to allows the roles for PGSQL
  char **list_roles_kc;
  int nroles_kc;

  if (!parse_role_claims((const char **)&decoded_SD[index], "names",
                         &list_roles_kc, &nroles_kc)) {
    logger("pg authenticate", "Failed to parse role claims but user is legit");
    cleanupArray(list_roles_kc, nroles_kc);
    return PAM_SUCCESS;
  }

  const char *conninfo;
  PGconn *conn;

  conninfo = "dbname = postgres user=postgres password=postgres";
  /* Crée une connexion à la base de données */
  conn = PQconnectdb(conninfo);

  /* Vérifier que la connexion au backend a été faite avec succès */
  if (PQstatus(conn) != CONNECTION_OK) {
    fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));
    logger("test conndb error", PQerrorMessage(conn));
    exit_nicely(conn);
  } // Connection to database successful
  logger("test conndb", "Connection to database ok");
  InitSearchPath(conn);

  if (!checkUserDB(conn, username)) {
    createUserDB(conn, username);
    logger("pg authenticate, created user", username);
  } // Create user if not exists
  else {
    logger("pg authenticate, user already exists", username);
  }

  char **list_roles_db;
  int nroles_db;
  // Get the roles contained in the db for the specified user
  getUserRoles(conn, username, &list_roles_db, &nroles_db);
  logger("pg authenticate", "user roles retrieved");
  assignAuthorizedRoles(conn, (const char **)list_roles_db, nroles_db,
                        (const char **)list_roles_kc, nroles_kc);

  // Cleanup
  // cleanupArray(list_roles_db, nroles_db);
  // cleanupArray(list_roles_kc, nroles_kc);
  /* ferme la connexion à la base et nettoie */

  logger("pg authenticate good allowing", username);
  printf("Welcome, %s\n", username);
  pam_set_item(handle, PAM_USER, username);
cleanup:
  PQfinish(conn);

  return retval_code;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  /* This struct contains the expiry date of the account */
  printf("pam_sm_acct_mgmt\n");
  logger("pam_sm_acct_mgmt pg pam", "username to be defined");

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  printf("pam_sm_setcred\n");
  logger("pam_sm_setcred pg pam", "username to be defined");
  // Set the credentials to share with other modules

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  const char *username;
  /* Get the username from PAM */
  pam_get_item(pamh, PAM_USER, (const void **)&username);
  printf("pam_sm_open_session for user %s \n", username);

  logger("pam_sm_open_session pg pam", username);
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {

  const char *username;

  /* Get the username from PAM */
  pam_get_item(pamh, PAM_USER, (const void **)&username);
  printf("Closing session for user %s...\n", username);
  char *access_token;
  char *id_token;
  char *refresh_token;
  pam_get_data(pamh, "access_token", (const void **)&access_token);
  pam_get_data(pamh, "id_token", (const void **)&id_token);
  pam_get_data(pamh, "refresh_token", (const void **)&refresh_token);

  if (deconnection((const char **)&access_token,
                   (const char **)&refresh_token)) {
    printf("Déconnexion réussie\n");
    logger("Déconnexion réussie", username);
  } else {
    printf("Déconnexion échouée\n");
    logger("Déconnexion échouée", username);
  }

  logger("pam_sm_close_session pg pam", username);
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  printf("pam_sm_chauthtok \n");
  const char *username;
  const char *cur_password;
  const char *new_password;
  /* We always return PAM_SUCCESS for the preliminary check */
  if (flags & PAM_PRELIM_CHECK) {
    return PAM_SUCCESS;
  }

  /* Get the username */
  pam_get_item(pamh, PAM_USER, (const void **)&username);
  logger("pam_sm_chauthtok  pg pam", username);

  /* We're not handling the PAM_CHANGE_EXPIRED_AUTHTOK specifically
   * since we do not have expiry dates for our passwords. */
  if ((flags & PAM_UPDATE_AUTHTOK) || (flags & PAM_CHANGE_EXPIRED_AUTHTOK)) {
    /* Ask the application for the password. From this module function,
     * pam_get_authtok() with item type PAM_AUTHTOK asks for the new password
     * with the retype. Therefore, to ask for the current password we must use
     * PAM_OLDAUTHTOK. */
    pam_get_authtok(pamh, PAM_OLDAUTHTOK, &cur_password,
                    "Insert current password: ");

    /* Check if the current password is correct */
    char *id_token;
    char *access_token;
    char *refresh_token;

    if (authentification_utilisateur(username, cur_password, &access_token,
                                     &id_token,
                                     &refresh_token)) // to rewrite right here
    {
      pam_get_authtok(pamh, PAM_AUTHTOK, &new_password, "New password: ");
    } else {
      return PAM_PERM_DENIED;
    }
  }
  return PAM_SUCCESS;
}

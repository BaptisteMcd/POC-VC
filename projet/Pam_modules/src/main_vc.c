#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>
//#include <libpq-fe.h>
#include <postgresql/libpq-fe.h>

#include "../include/logger.h"
#include "../include/kc_auth.h"
// #include "kc_auth.c"

void cleanup_pointer(pam_handle_t *handle, void *data, int error_status)
{
	// printf("cleanup_pointer shunt\n"); // testing
	free(data);
} // Cleanup function

void change_pass(const char *, const char *);

void change_pass(const char *username, const char *password)
{
	// TO REWRITE
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
								   const char **argv)
{
	logger("pam_sm_authenticate first pam", "username to be defined");
	printf("pam_sm_authenticate\n");

	int pam_code;
	const char *username = NULL;
	const char *password = NULL;
	/* Asking the application for an  username */
	pam_code = pam_get_user(handle, &username, "USERNAME: ");
	if (pam_code != PAM_SUCCESS)
	{
		fprintf(stderr, "Can't get username");
		return PAM_PERM_DENIED;
	}
	logger("pam_sm_authenticate", username);
	/* Asking the application for a password */
	pam_code = pam_get_authtok(handle, PAM_AUTHTOK, &password, "PASSWORD: ");
	if (pam_code != PAM_SUCCESS)
	{
		fprintf(stderr, "Can't get password");
		return PAM_PERM_DENIED;
	}

	/* Checking the PAM_DISALLOW_NULL_AUTHTOK flag: if on, we can't accept empty passwords */
	if (flags & PAM_DISALLOW_NULL_AUTHTOK)
	{
		if (password == NULL || strcmp(password, "") == 0)
		{
			fprintf(stderr,
					"Null authentication token is not allowed!.");
			return PAM_PERM_DENIED;
		}
	}

	char *access_token;
	char *id_token;
	char *refresh_token;

	if (authentification_utilisateur(username, password, &access_token, &refresh_token, &id_token))
	{ // Authenticated
		logger("sm authenticate good", username);
		printf("Welcome, %s\n", username);

		// set the user env and tokens
		pam_set_item(handle, PAM_USER, username);
		pam_set_data(handle, "access_token", access_token, cleanup_pointer);
		pam_set_data(handle, "id_token", id_token, cleanup_pointer);
		pam_set_data(handle, "refresh_token", refresh_token, cleanup_pointer);

		pam_set_item(handle, PAM_AUTHTOK, access_token);
		char *key_val;

		asprintf(&key_val, "access_token=%s", access_token);
		pam_putenv(handle, key_val);

		char *acc_from_env = (char *)pam_getenv(handle, "access_token");
		printf("access_token from env %s\n", acc_from_env);

		return PAM_SUCCESS;
	}
	else
	{ // Bad authentification
		fprintf(stderr, "Wrong username or password\n");
		logger("sm authenticate bad", username);
		return PAM_PERM_DENIED;
	}
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
								const char **argv)
{
	/* This struct contains the expiry date of the account */
	printf("pam_sm_acct_mgmt\n");
	logger("pam_sm_acct_mgmt", "username to be defined");	
	
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
							  const char **argv)
{
	printf("pam_sm_setcred\n");
	logger("pam_sm_setcred", "username to be defined");

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
								   const char **argv)
{
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
									const char **argv)
{

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

	if (deconnection((const char **)&access_token, (const char **)&refresh_token))
	{
		printf("Déconnexion réussie\n");
		logger("Déconnexion réussie", username);
	}
	else
	{
		printf("Déconnexion échouée\n");
		logger("Déconnexion échouée", username);
	}
	logger("pam_sm_close_session", username);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
								const char **argv)
{
	printf("pam_sm_chauthtok \n");
	const char *username;
	const char *cur_password;
	const char *new_password;
	/* We always return PAM_SUCCESS for the preliminary check */
	if (flags & PAM_PRELIM_CHECK)
	{
		return PAM_SUCCESS;
	}

	/* Get the username */
	pam_get_item(pamh, PAM_USER, (const void **)&username);
	logger("pam_sm_chauthtok", username);

	/* We're not handling the PAM_CHANGE_EXPIRED_AUTHTOK specifically
	 * since we do not have expiry dates for our passwords. */
	if ((flags & PAM_UPDATE_AUTHTOK) ||
		(flags & PAM_CHANGE_EXPIRED_AUTHTOK))
	{
		/* Ask the application for the password. From this module function, pam_get_authtok()
		 * with item type PAM_AUTHTOK asks for the new password with the retype. Therefore,
		 * to ask for the current password we must use PAM_OLDAUTHTOK. */
		pam_get_authtok(pamh, PAM_OLDAUTHTOK, &cur_password, "Insert current password: ");

		/* Check if the current password is correct */
		char *id_token;
		char *access_token;
		char *refresh_token;

		if (authentification_utilisateur(username, cur_password, &access_token, &id_token, &refresh_token)) // to rewrite right here
		{
			pam_get_authtok(pamh, PAM_AUTHTOK, &new_password,
							"New password: ");
			change_pass(username, new_password);
		}
		else
		{
			return PAM_PERM_DENIED;
		}
	}
	return PAM_SUCCESS;
}

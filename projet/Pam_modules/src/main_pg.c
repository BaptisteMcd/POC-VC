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
// #include <jwt.h>
#include "../include/logger.h"
#include "../include/kc_auth.h"
// #include "kc_auth.c"

#define MAX_USERFILE_SIZE 1024
#define USERSFILE "users"

void cleanup_pointer(pam_handle_t *handle, void *data, int error_status) { free(data); } // Cleanup function

void change_pass(const char *, const char *);

void change_pass(const char *username, const char *password)
{
	// TO REWRITE
	FILE *f = fopen(USERSFILE, "wr");
	char content[MAX_USERFILE_SIZE];
	int pos = 0;
	bool authenticated = false;

	int filepos = 0;

	int c;
	/* Reading the file until EOF and filling content */
	while ((c = fgetc(f)) != EOF)
	{
		content[pos++] = c;
	}

	char *userfield = strtok(content, ":");
	char *passfield = strtok(NULL, "\n");
	filepos += strlen(userfield) + strlen(passfield) + 2;
	while (1)
	{
		if (strcmp(username, userfield) == 0 &&
			strcmp(password, passfield) == 0)
		{
			authenticated = true;
			break;
		}
		userfield = strtok(NULL, ":");
		if (userfield == NULL)
			break;
		passfield = strtok(NULL, "\n");
		if (passfield == NULL)
			break;
	}
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
								   const char **argv)
{
	logger("pam_sm_authenticate", "username to be defined");
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



	char *access_token;
	char *id_token;
	char *refresh_token;

	/* Asking the application for a password */
	pam_get_data(handle, "access_token", (const void **)&access_token);
	// Get JWT from the access_token and validate its signature

	
	// // jwt_t *jwt = jwt_decode(id_token);
	// if (jwt == NULL)
	// {
	// 	fprintf(stderr, "Can't get id_token");
	// 	return PAM_PERM_DENIED;
	// }
	if (authentification_utilisateur(username, password, &access_token, &refresh_token, &id_token))
	{ // Authenticated
		logger("sm authenticate good", username);
		printf("Welcome, %s\n", username);

		// set the user env and tokens
		pam_set_item(handle, PAM_USER, username);
		pam_set_data(handle, "access_token", access_token, cleanup_pointer);
		pam_set_data(handle, "id_token", id_token, cleanup_pointer);
		pam_set_data(handle, "refresh_token", refresh_token, cleanup_pointer);

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
	logger("pam_sm_acct_mgmt pg pam", "username to be defined");

	struct tm expiry_date;
	expiry_date.tm_mday = 31;
	expiry_date.tm_mon = 12;
	expiry_date.tm_year = 2020;
	expiry_date.tm_sec = 0;
	expiry_date.tm_min = 0;
	expiry_date.tm_hour = 0;

	time_t expiry_time;
	time_t current_time;

	/* Getting time_t value for expiry_date and current date */
	expiry_time = mktime(&expiry_date);
	current_time = time(NULL);

	/* Checking the account is not expired */
	if (current_time > expiry_time)
	{
		return PAM_PERM_DENIED;
	}
	else
	{
		return PAM_SUCCESS;
	}
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
							  const char **argv)
{
	printf("pam_sm_setcred\n");
	logger("pam_sm_setcred pg pam", "username to be defined");

	/* Environment variable name */
	const char *env_var_name = "USER_FULL_NAME";

	/* User full name */
	const char *name = "John Smith";

	/* String in which we write the assignment expression */
	char env_assignment[100];

	/* If application asks for establishing credentials */
	if (flags & PAM_ESTABLISH_CRED)
		/* We create the assignment USER_FULL_NAME=John Smith */
		sprintf(env_assignment, "%s=%s", env_var_name, name);
	/* If application asks to delete credentials */
	else if (flags & PAM_DELETE_CRED)
		/* We create the assignment USER_FULL_NAME, withouth equal,
		 * which deletes the environment variable */
		sprintf(env_assignment, "%s", env_var_name);

	/* In this case credentials do not have an expiry date,
	 * so we won't handle PAM_REINITIALIZE_CRED */

	pam_putenv(pamh, env_assignment);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
								   const char **argv)
{
	const char *username;
	/* Get the username from PAM */
	pam_get_item(pamh, PAM_USER, (const void **)&username);
	printf("pam_sm_open_session for user %s \n", username);

	logger("pam_sm_open_session pg pam", username);
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


	logger("pam_sm_close_session pg pam", username);
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
	logger("pam_sm_chauthtok  pg pam", username);

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

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

void cleanup_pointer(pam_handle_t *handle, void *data, int error_status)
{
	// printf("cleanup_pointer shunt\n");
	// free(data);
} // Cleanup function

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
	logger("pam_sm_authenticate pg pam", username);

	// Récupération des jetons
	char path_tokens[512];
	// sprintf(path_tokens, "/home/%s/.tokens", username);
	sprintf(path_tokens, "/tmp/.tokens"); // testing

	FILE *pTokensFile = fopen(path_tokens, "r");
	if (pTokensFile == NULL)
	{
		printf("Erreur lors de l'ouverture du fichier .tokens\n");
		logger("test", "Erreur lors de l'ouverture du fichier .tokens");
		return PAM_PERM_DENIED;
	}

	logger("pam_sm_authenticate pTokensFile", "pTokensFile");
	char *access_token;
	char *id_token;
	char *refresh_token;
	read_tokens("/tmp/.tokens", &access_token, &id_token, &refresh_token);
	fclose(pTokensFile);
	if (access_token == NULL || id_token == NULL || refresh_token == NULL)
	{
		printf("Erreur lors de la lecture des tokens\n");
		logger("test", "Erreur lors de la lecture des tokens");
		return PAM_PERM_DENIED;
	}
	logger("pg auth", "success dans la récupération des jetons");

	// Clé publique à partir du serveur Keycloak
	char *pubkey;
	bool success_getting_pk = getpubkey(&pubkey);
	if (!success_getting_pk)
	{
		printf("Clé publique non récupérée\n");
		logger("pg auth", "clé publique non récupérée");
	}
	logger("pg auth", "Clé publique récupérée dans le main\n");

	// Validation du jeton
	char *claim = "resource_access";
	char *token_user;
	logger("Auth token", "Going into token validation");
	bool succes_token_validation = validate_token((const char **)&access_token, (const char **)&pubkey, &claim, &token_user);
	
	return PAM_SUCCESS;
	logger("Auth token", "Token in validation");

	if (!succes_token_validation)
	{
		logger("Auth token", "TOKEN NOT VALIDATED");
		return PAM_PERM_DENIED;
	}
	logger("auth pg", token_user);
	return PAM_SUCCESS;

	if (verif_existance_utilisateur(username, (const char **)&access_token))
	{
		printf("Utilisateur trouvé\n");
		logger("test", "verif user fonctionnelle");
	}
	else
	{
		printf("Utilisateur non trouvé\n");
		logger("test", "verif user non fonctionnelle");
	}
	if (true)
	{ // Authenticated
		logger("sm authenticate good", username);
		printf("Welcome, %s\n", username);

		// set the user env and tokens
		pam_set_item(handle, PAM_USER, username);

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
	// Set the credentials to share with other modules

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

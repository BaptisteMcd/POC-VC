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
#include "../include/logger.h"
#include "../include/kc_auth.h"

void cleanup_pointer(pam_handle_t *handle, void *data, int error_status)
{
	free(data);
} 

void change_pass(const char *, const char *);

void change_pass(const char *username, const char *password)
{
	// TO REWRITE ?
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
								   const char **argv)
{
	int pam_code;
	const char *username = NULL;
	const char *password = NULL;

	char *access_token;
	char *id_token;
	char *refresh_token;

	char *pubkey;
	char *client_access_token;
	char *client_id_token;

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

	sprintf(path_tokens, "/tmp/.tokens"); // sprintf(path_tokens, "/home/%s/.tokens", username);
	FILE *pTokensFile = fopen(path_tokens, "r");
	if (pTokensFile == NULL)
	{
		printf("Erreur lors de l'ouverture du fichier .tokens\n");
		logger("test", "Erreur lors de l'ouverture du fichier .tokens");
		return PAM_AUTHINFO_UNAVAIL;
	}

	read_tokens("/tmp/.tokens", &access_token, &id_token, &refresh_token);
	fclose(pTokensFile);
	if (access_token == NULL || id_token == NULL || refresh_token == NULL)
	{
		printf("Erreur lors de la lecture des tokens\n");
		logger("test", "Erreur lors de la lecture des tokens");
		return PAM_AUTHINFO_UNAVAIL;
	}
	logger("pg auth", "success dans la récupération des jetons");

	bool success_getting_pk = getpubkey(&pubkey);
	if (!success_getting_pk)
	{ // Public key not retrieved
		printf("Clé publique non récupérée\n");
		logger("pg auth", "clé publique non récupérée");
	}
	logger("pg auth", "Clé publique récupérée dans le main\n");

	char *claim = "resource_access";
	char *token_user;
	bool succes_token_validation = validate_token((const char **)&access_token, (const char **)&pubkey, &claim, &token_user);
	if (!succes_token_validation)
	{ // Le jeton n'a pas été validé
		logger("Auth token", "TOKEN NOT VALIDATED");
		return PAM_PERM_DENIED;
	}
	logger("auth pg jeton valide pour utilisateur : ", token_user);

	if (strcmp(token_user, username) != 0)
	{ // Le jeton ne correspond pas au nom de utilisateur
		logger("auth pg", "username of linux session and token_user are different");
		return PAM_PERM_DENIED;
	}
	logger("auth pg", "username of linux session and token_user are the same");

	if (!jeton_client("openid", &client_access_token, &client_id_token))
	{ // Failed to retrieve client token
		logger("pg auth", "Failed to retrieve client token");
		return PAM_AUTHINFO_UNAVAIL;
	}

	if (!verif_existance_utilisateur(username, (const char **)&client_access_token))
	{ // Bad authentification
		fprintf(stderr, "Wrong username or password\n");
		logger("pg authenticate bad utilisateur non trouvé", username);
		return PAM_USER_UNKNOWN;

	} // Good authentification


	// Now we need to allows the roles for PGSQL

	logger("pg authenticate good", username);
	printf("Welcome, %s\n", username);
	pam_set_item(handle, PAM_USER, username);
	return PAM_SUCCESS;
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

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
#include "logger.c"
#include "kc_auth.c"

#define MAX_USERFILE_SIZE 1024
#define USERSFILE "users"

bool auth_user(const char *, const char *);
void change_pass(const char *, const char *);
/**
 * @brief R
 *
 * @param user
 * @param password
 */
bool auth_user(const char *user, const char *password)
{
	FILE *f = fopen(USERSFILE, "r");
	char content[MAX_USERFILE_SIZE];
	int pos = 0;
	bool authenticated = false;
	int c;
	/* Reading the file until EOF and filling content */
	while ((c = fgetc(f)) != EOF)
	{
		content[pos++] = c;
	}

	char *userfield = strtok(content, ":");
	char *passfield = strtok(NULL, "\n");

	while (1)
	{
		if (strcmp(user, userfield) == 0 &&
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
	return authenticated;
}

void change_pass(const char *username, const char *password)
{
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

bool KC_auth(const char *user, const char *pass)
{

	CURL *curl;
	CURLcode res;
	curl = curl_easy_init();
	FILE *devnull = fopen("/dev/null", "w+");

	if (curl)
	{
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
		curl_easy_setopt(curl, CURLOPT_URL, "http://172.30.6.16:8080/realms/DevRealm/protocol/openid-connect/token");
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
		struct curl_slist *headers = NULL;
		headers = curl_slist_append(headers, "Accept: */*");
		headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
		headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
		headers = curl_slist_append(headers, "User-Agent: python-requests/2.31.0");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		// char *data;// = "client_id=Client-test&client_secret=gf5V17TzXFDFWqnxOjPY4px4dw6KPHNQ&username=firstuser&password=test&grant_type=password&scope=openid";
		char *post_data;
		asprintf(&post_data, "client_id=Client-test&client_secret=Z717yEXBXJMD490AckHFYSrY7PPSp8ym&username=%s&password=%s&grant_type=password&scope=openid", user, pass);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

		curl_easy_setopt(curl, CURLOPT_WRITEDATA, devnull);// ne pas print les données reçues

		res = curl_easy_perform(curl);
		curl_slist_free_all(headers);
		free(post_data);
	}

	fclose(devnull);
	curl_easy_cleanup(curl);

	long response_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	// printf((int) response_code);
	printf("%ld :", response_code);
	if (response_code == 200)
	{
		// Succeeded
		return 1;
	}
	else
	{
		// Failed
		return 0;
	}
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
								   const char **argv)
{
	logger("pam_sm_authenticate", "username to be defined");
	printf("pam_sm_authenticate");

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

	/* Asking the application for a password */
	pam_code =
		pam_get_authtok(handle, PAM_AUTHTOK, &password, "PASSWORD: ");
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

	/*Auth user reads a file with usernames and passwords and returns true if username
	 * and password are correct. Obviously, you must not save clear text passwords */
	//
	bool result = authentification_utilisateur(username, password);
	if (result)
	{
		logger("sm authenticate good", username);
		logger("sm authenticate good the password", password);
		pam_putenv(handle, "USER_FULL_NAME_2=first");
		printf("Welcome, %s\n", username);
		
		return PAM_SUCCESS;
	}
	else
	{
		int retval;
		logger("sm authenticate bad password before", password);
		fprintf(stderr, "Wrong username or password");
		logger("sm authenticate bad", username);
		logger("sm authenticate bad password after", password);

		return PAM_PERM_DENIED;
	}
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
								const char **argv)
{
	/* This struct contains the expiry date of the account */
	logger("pam_sm_acct_mgmt", "username to be defined");

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
	logger("pam_sm_setcred", "username to be defined");

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
	char dir_path[512];

	/* Get the username from PAM */
	pam_get_item(pamh, PAM_USER, (const void **)&username);
	logger("pam_sm_open_session", username);

	/* Creating directory path string */
	sprintf(dir_path, "/home/%s", username);

	mkdir(dir_path, 0770);
	printf("made directory for user");

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
									const char **argv)
{

	const char *username;
	char dir_path[512];

	/* Get the username from PAM */
	pam_get_item(pamh, PAM_USER, (const void **)&username);
	logger("pam_sm_close_session", username);

	/* Creating directory path string */
	sprintf(dir_path, "/home/%s", username);

	rmdir(dir_path);
	printf("removed directory for user");

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
								const char **argv)
{
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
		pam_get_authtok(pamh, PAM_OLDAUTHTOK, &cur_password,
						"Insert current password: ");

		if (auth_user(username, cur_password))
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

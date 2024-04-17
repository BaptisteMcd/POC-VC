/*
 * libnss_pool.c
 * Author: Marcin Stolarek (stolarek.marcin@gmail.com)
 */
#include <pthread.h>

static pthread_mutex_t NSS_HTTP_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#define NSS_HTTP_LOCK()    do { pthread_mutex_lock(&NSS_HTTP_MUTEX); } while (0)
#define NSS_HTTP_UNLOCK()  do { pthread_mutex_unlock(&NSS_HTTP_MUTEX); } while (0)

#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
// #include "kc_auth.h"

// This defines the maximal size of the pool stored in /etc/pool-passwd
#define MAX_POOL_SIZE 20	

// poolPasswd file
#define POOLPASSWD "/etc/pool-passwd"
// GET /admin/realms/{realm}/users



enum nss_status
_nss_pool_getpwnam_r(const char *name,
					 struct passwd *p,
					 char *buffer,
					 size_t buflen,
					 int *errnop)
{
	printf("_nss_pool_getpwnam_r\n");
	NSS_HTTP_LOCK();
	
	bool found = false;
	bool reponse = false;

	char *access_token = NULL;
	char *id_token = NULL;
	
	printf("User found\n");
	//create user if not in system 
	printf("Added user with name :%s:\n", name);

	char * name_64 = malloc(sizeof(char) * 64);
	name_64 = strncpy(name_64, name, 64);
	char * argv[3];
	argv[0] = "/usr/sbin/useradd";
	argv[1] = name_64;
	argv[2] =  NULL;
	//execvp("/usr/sbin/useradd", argv);
	char * cmd;
	asprintf(&cmd, "/usr/sbin/useradd %s", name);
	system(cmd);
	NSS_HTTP_UNLOCK();
	return NSS_STATUS_SUCCESS;

	/*
	reponse = jeton_client("openid", &access_token, &id_token);
	int return_value = 0;
	if (reponse)
	{
		found = verif_existance_utilisateur(name, (const char **)&access_token);
		if (found)
		{
			printf("User found\n");
			//create user if not in system 
			printf("Added user\n");
			system("whoami");

			char * name_64 = malloc(sizeof(char) * 64);
			name_64 = strncpy(name_64, name, 64);
			char * argv[3];
			argv[0] = "useradd";
			argv[1] = name_64;
			argv[2] =  NULL;
			execvp("/usr/sbin/useradd", argv);
			return_value = NSS_STATUS_SUCCESS;
		}
		else
		{
			printf("User not found\n");
			return_value = NSS_STATUS_TRYAGAIN;
		}
	}
	else
	{
		printf("Error while getting token\n");
		return_value = NSS_STATUS_UNAVAIL;
	}
	free(access_token);
	free(id_token);
	return return_value;
	
	return NSS_STATUS_NOTFOUND;*/
}

enum nss_status
_nss_pool_getpwuid_r(uid_t uid, struct passwd *p,
					 char *buf, size_t buflen, struct passwd **result)
{
	printf("_nss_pool_getpwuid_r");

	FILE *fd, *log;
	struct passwd *it;
	fd = fopen(POOLPASSWD, "r");
	if (fd == NULL)
	{
		return NSS_STATUS_NOTFOUND;
	}
	log = fopen("/tmp/debugUid", "w+");
	setbuf(log, NULL);
	while ((it = fgetpwent(fd)) != NULL)
	{
		fprintf(log, "%s\n", it->pw_name);
		if (it->pw_uid == uid)
		{
			*p = *it;
			fclose(log);
			fclose(fd);
			return NSS_STATUS_SUCCESS;
		}
	}

	fclose(log);
	fclose(fd);
	return NSS_STATUS_NOTFOUND;
}
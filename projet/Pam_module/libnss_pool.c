/*
 * libnss_pool.c
 * Author: Marcin Stolarek (stolarek.marcin@gmail.com)
*/

#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//This defines the maximal size of the pool stored in /etc/pool-passwd
#define MAX_POOL_SIZE 20

//poolPasswd file
#define POOLPASSWD "/etc/pool-passwd"
// GET /admin/realms/{realm}/users

enum nss_status
_nss_pool_getpwnam_r( const char *name, 
	   	     struct passwd *p, 
	             char *buffer, 
	             size_t buflen, 
	             int *errnop)
{
	printf("_nss_pool_getpwnam_r\n");
	printf("COURTCIRCUITAGE ...\n");
	return NSS_STATUS_SUCCESS;


	
}

enum nss_status
_nss_pool_getpwuid_r(uid_t uid, struct passwd *p,
            char *buf, size_t buflen, struct passwd **result)
{
	printf("_nss_pool_getpwuid_r");

	FILE * fd, * log;
	struct passwd *it;
	fd=fopen(POOLPASSWD,"r");
	if(fd==NULL) {
		return NSS_STATUS_NOTFOUND;
	}
	log=fopen("/tmp/debugUid","w+");
	setbuf(log,NULL);
	while( (it=fgetpwent(fd)) != NULL) {
			fprintf(log,"%s\n",it->pw_name);
			if(it->pw_uid==uid) {
				*p=*it;
				fclose(log);
				fclose(fd);
				return NSS_STATUS_SUCCESS;
			}
	}
		
	fclose(log);
	fclose(fd);
	return NSS_STATUS_NOTFOUND;
}
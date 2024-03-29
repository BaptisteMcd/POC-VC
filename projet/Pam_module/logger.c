#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// #define LOG_FILE_PATH "/var/log/audit/audit.log" // Erreurs de droits + resets des droits à la déconnexion
#define LOG_FILE_PATH "/tmp/audit.log"
void logger(const char* tag, const char* message) {
    time_t now;
    time(&now);
   	FILE *pAuditLogFile;
	pAuditLogFile=fopen(LOG_FILE_PATH, "a"); // a mode so only append
	if(pAuditLogFile==NULL) {
		perror("Error opening file.");
	}else{
		fprintf(pAuditLogFile,"%.19s [%s]: %s\n", ctime(&now), tag, message);
	}
    	fclose(pAuditLogFile);
}
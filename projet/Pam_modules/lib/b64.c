#define _GNU_SOURCE
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/b64.h"
#include "../lib/jwt.h"

void PrintArray(char **array, int n) {
  for (int i = 0; i < n; i++) {
    printf("PrintArray element n%d : %s\n", i, array[i]);
  }
}

/***********************************************************
 * Base64 library implementation                            *
 * @author Ahmed Elzoughby                                  *
 * @date July 23, 2017                                      *
 ***********************************************************/

char base46_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
                     'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                     'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
                     'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                     's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2',
                     '3', '4', '5', '6', '7', '8', '9', '+', '/'};
char *base64_decode(char *cipher) {

  char counts = 0;
  char buffer[4];
  char *plain = malloc(strlen(cipher) * 3 / 4);
  int i = 0, p = 0;

  for (i = 0; cipher[i] != '\0'; i++) {
    char k;
    for (k = 0; k < 64 && base46_map[k] != cipher[i]; k++)
      ;
    buffer[counts++] = k;
    if (counts == 4) {
      plain[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
      if (buffer[2] != 64)
        plain[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
      if (buffer[3] != 64)
        plain[p++] = (buffer[2] << 6) + buffer[3];
      counts = 0;
    }
  }
  plain[p] = '\0'; /* string padding character */
  return plain;
}

bool parse_SD_JWT_VC(char *raw_sd_jwt, char ***sd_jwt,
                     unsigned long *nelemenents) {
  const char *tilde = "~";
  char retval = 1;
  unsigned long nparsed = 0;

  char *toke = strtok(raw_sd_jwt, tilde);
  while (toke != NULL) {
    *sd_jwt = realloc(*sd_jwt, (nparsed + 1) * sizeof(char *));
    if (*sd_jwt == NULL) {
      printf("Failed realloc of parsed pointer");
      retval = -1;
      goto exit;
    }
    asprintf(&(*sd_jwt)[nparsed], "%s", toke);
    nparsed = nparsed + 1;
    toke = strtok(NULL, tilde); // NULL after subsequents calls
  }
  *nelemenents = nparsed;
  // Successfull
  // jwt is now our 1st element and the rest are disclosures
  // everything is already allocated
exit:
  return retval;
}

const bool validate_jwt(const char **p_token, const char **p_public_key) {
  bool success = 1;

  // Validate token
  jwt_t *jwt = NULL;
  jwt_alg_t opt_alg = JWT_ALG_RS256;
  jwt_valid_t *jwt_valid;
  int ret = 0;
  /* Setup validation */
  ret = jwt_valid_new(&jwt_valid, opt_alg);

  if (ret != 0 || jwt_valid == NULL) {
    fprintf(stderr, "failed to allocate jwt_valid\n");
    success = 0;
    goto finish_valid;
  }

  jwt_valid_set_headers(jwt_valid, 1);
  jwt_valid_set_now(jwt_valid, time(NULL));

  ret = jwt_decode(&jwt, *p_token, NULL, 0);

  if (jwt == NULL) { // working access and id but not refresh
    fprintf(stderr, "Could not decode token\n");
    success = 0;
    goto finish;
  } else if (ret != 0) { // working access and id but not refresh
    fprintf(stderr, "Signature not verified\n");
    success = 0;
    goto finish;
  }

  if (jwt_validate(jwt, jwt_valid) != 0) { // token decoded successfully!
    jwt_dump_fp(jwt, stderr, 1);
    goto finish;
  }
  success = 0;

finish:
  jwt_free(jwt);
finish_valid:
  jwt_valid_free(jwt_valid);
  return success;
}
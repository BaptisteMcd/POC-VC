#define _GNU_SOURCE
#include "../include/logger.h"
#include <arpa/inet.h>
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../include/b64.h"
#include "../lib/jwt.h"

#define BUFFER_SIZE 1500 // 64 KB

bool receive_jwt_socket(char **jwt, unsigned short port) {
  int server_fd, new_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);
  char buffer[BUFFER_SIZE];
  int retval = 0;
  logger("Socket", "Starting socket\n");
  // Create socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    logger("Socket", "Socket failed\n");
    return 0;
  }

  // Bind to the port
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    logger("Socket", "Bind failed\n");
    goto error_socket;
  }
  logger("Socket", "Binded to port\n");

  // Listen for incoming connections
  if (listen(server_fd, 3) < 0) {
    logger("Socket", "Listen failed\n");
    perror("listen");
    goto error_server;
  }

  // Accept an incoming connection
  if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                           (socklen_t *)&addrlen)) < 0) {
    perror("accept");
    goto error_server;
  }
  // accepted a conn
  logger("Socket", "Accepted a connection\n");
  // Initialize a buffer to accumulate the incoming JWT
  char *jwt_buffer = malloc(BUFFER_SIZE);
  if (jwt_buffer == NULL) {
    perror("malloc failed");
    goto error_server;
  }
  jwt_buffer[0] = '\0';
  logger("Socket", "Buffer initialized\n");

  // Read data from the socket
  int total_read = 0;
  int valread;
  while ((valread = read(new_socket, buffer, BUFFER_SIZE - 1)) > 0) {
    buffer[valread] = '\0'; // Null-terminate the received data
    total_read += valread;
    jwt_buffer = realloc(jwt_buffer, total_read + 1);
    if (jwt_buffer == NULL) {
      perror("realloc failed");
      goto error_server;
    }

    logger("Socket", "Data read from socket\n");
    logger("Socket", buffer);
    strcat(jwt_buffer, buffer);
    break;
  }
  logger("Socket", "Data read from socket\n");
  if (valread < 0) {
    logger("Socket", "valread <0 \n");
    perror("read");
    free(jwt_buffer);
    goto error_server;

  }
  logger("Socket", "valread >=0 \n");
  // Assign the accumulated JWT to the output parameter
  *jwt = jwt_buffer;

  logger("socket print *jwt", *jwt);
  retval = 1;

error_server:
  close(server_fd);
error_socket:
  close(new_socket);
  logger("Socket", "Closed socket, returning to main\n");
  return retval;
}

void PrintArray(char **array, int n) {
  for (int i = 0; i < n; i++) {
    printf("PrintArray element n%d : %s\n", i, array[i]);
  }
}

bool parse_SD_JWT_VC(char *raw_sd_jwt, char ***sd_jwt, int *nelemenents) {
  const char *tilde = "~"; /* Tilde is the Separator of
  SD-JWT~Disclosure1~Disclosure2~... See
  */
  char retval = 1;
  int nparsed = 0;

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

int base64_url_safe_decode(const char *base64_input, char **output,
                           int *length) {
  BIO *b64, *bmem;
  int padding = (4 - strlen(base64_input) % 4) % 4;

  char *buffer = malloc(strlen(base64_input) + padding + 1);
  if (buffer == NULL) {
    return 0;
  }
  strcpy(buffer, base64_input);
  for (int i = 0; i < padding; ++i) {
    strcat(buffer, "=");
  }

  int buffer_length = strlen(buffer);
  *output = malloc(buffer_length + 1);
  if (*output == NULL) {
    free(buffer);
    return 0;
  }

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(buffer, buffer_length);
  bmem = BIO_push(b64, bmem);

  *length = BIO_read(bmem, *output, buffer_length);
  (*output)[*length] = '\0';

  BIO_free_all(bmem);
  free(buffer);

  return *length > 0;
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
  ret = jwt_decode(&jwt, *p_token, (const unsigned char *)*p_public_key,
                   (int)strlen((const char *)*p_public_key));

  if (jwt == NULL) { // working access and id but not refresh
    fprintf(stderr, "Could not decode token\n");
    printf("token wrong");
    success = 0;
    goto finish;
  } else if (ret != 0) { // working access and id but not refresh
    fprintf(stderr, "Signature not verified\n");
    printf("signature wrong");
    success = 0;
    goto finish;
  }

  if (jwt_validate(jwt, jwt_valid) != 0) { // token decoded successfully!
    fprintf(stderr, "Signature verified\n");
    jwt_dump_fp(jwt, stderr, 1);
    goto finish;
  }

finish:
  jwt_free(jwt);
finish_valid:
  jwt_valid_free(jwt_valid);
  return success;
}

bool decode_all_sd(const char **parsed_sd_jwt, const int ndisclosures,
                   char ***decoded_SD, int *length) {
  bool success = 1;
  for (int i = 1; i < ndisclosures; i = i + 1) {
    char *decoded = NULL;
    int len;
    base64_url_safe_decode(parsed_sd_jwt[i], &decoded, &len);
    if (decoded == NULL) {
      success = 0;
      goto finish;
    }
    *decoded_SD = realloc(*decoded_SD, (i) * sizeof(char *));
    if (*decoded_SD == NULL) {
      success = 0;
      goto finish;
    }
    (*decoded_SD)[i - 1] = decoded;
  }
  *length = ndisclosures - 1;
finish:
  return success;
}

char *extract_grant_jwt(const char **p_token, const char *grant) {
  jwt_t *jwt = NULL;
  jwt_alg_t opt_alg = JWT_ALG_RS256;
  jwt_valid_t *jwt_valid;
  int ret = 0;

  /* Setup validation */
  ret = jwt_valid_new(&jwt_valid, opt_alg);

  if (ret != 0 || jwt_valid == NULL) {
    fprintf(stderr, "failed to allocate jwt_valid\n");
    goto finish_valid;
  }

  jwt_valid_set_headers(jwt_valid, 1);
  jwt_valid_set_now(jwt_valid, time(NULL));

  ret = jwt_decode(&jwt, *p_token, NULL, 0);

  if (jwt == NULL || ret != 0) { // working access and id but not refresh
    fprintf(stderr, "Could not decode token\n");
    goto finish;
  }

  char *retval = NULL;
  retval = jwt_get_grants_json(jwt, grant);

finish:
  jwt_free(jwt);
finish_valid:
  jwt_valid_free(jwt_valid);
  return retval;
}

bool json_array_2_array(char **json_array, char ***array, int *narray) {
  char *token;
  int i = 0;
  *narray = 0;

  token = strtok(*json_array, "\"");
  while (token != NULL) {
    if (i % 2 == 1) { // string
      *array = realloc(*array, (*narray + 1) * sizeof(char *));
      if (*array == NULL) {
        printf("Failed realloc of parsed pointer");
        return false;
      }
      if (asprintf(&(*array)[*narray], "%s", token) == -1) {
        return false;
      }; // adding string to array

      *narray = *narray + 1;
    }
    i = i + 1;
    token = strtok(NULL, "\"");
  }
  return true;
}

void base64_url_safe_encode(const unsigned char *input, int length,
                            char *output) {
  // Base64 encode
  int out_len = EVP_EncodeBlock((unsigned char *)output, input, length);

  // Replace + with -, / with _, and remove = padding characters
  for (int i = 0; i < out_len; i++) {
    if (output[i] == '+') {
      output[i] = '-';
    } else if (output[i] == '/') {
      output[i] = '_';
    } else if (output[i] == '=') {
      output[i] = '\0';
      break;
    }
  }
}

bool SHA256_sum(const char *raw_text, char **base64_output) {
  // Calculate the SHA-256 hash

  unsigned char hash[SHA256_DIGEST_LENGTH];
  *base64_output =
      malloc(sizeof(char) * EVP_ENCODE_LENGTH(SHA256_DIGEST_LENGTH));
  if (*base64_output == NULL) {
    return 0;
  }
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, raw_text, strlen(raw_text));
  SHA256_Final(hash, &sha256);

  // Convert the hash to a URL-safe Base64 encoded string
  base64_url_safe_encode(hash, SHA256_DIGEST_LENGTH, *base64_output);
  return 1;
}

bool check_claim_validity(const char **sd_array, const int nsd_array,
                          const char *claim) {
  char *hash = NULL;
  SHA256_sum(claim, &hash);
  for (int i = 0; i < nsd_array; i = i + 1) {
    if (strcmp((const char *)hash, sd_array[i]) == 0) {
      return true;
    }
  }
  return false;
}

bool is_in_array(const char **array, const int narray, const char *claim) {
  for (int i = 0; i < narray; i = i + 1) {
    if (strcmp((const char *)claim, array[i]) == 0) {
      return true;
    }
  }
  return false;
}

bool check_claim_in_disclosures(const char **array, const int narray,
                                const char *claim, const char *value,
                                int *index) {
  for (int i = 0; i < narray; i = i + 1) {
    if (strstr((const char *)array[i], claim) != NULL) {
      if (strstr((const char *)array[i], value) != NULL) {
        *index = i;
        return true;
      } else {
        return false;
      }
    }
  }
  return false;
}

char *get_pub_key(const char *filepath) {
  BIO *bio = NULL;
  X509 *cert = NULL;
  EVP_PKEY *pkey = NULL;
  BIO *pub_bio = NULL;
  BUF_MEM *pub_key_mem = NULL;
  char *output = NULL;

  OpenSSL_add_all_algorithms();

  bio = BIO_new(BIO_s_file());
  if (bio == NULL) {
    fprintf(stderr, "Failed to create BIO\n");
    goto cleanup;
  }

  if (BIO_read_filename(bio, filepath) <= 0) {
    fprintf(stderr, "Failed to read certificate file\n");
    goto cleanup;
  }

  // Load the certificate
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
  if (cert == NULL) {
    fprintf(stderr, "Failed to load certificate\n");
    goto cleanup;
  }

  pkey = X509_get_pubkey(cert);
  if (pkey == NULL) {
    fprintf(stderr, "Failed to extract public key\n");
    goto cleanup;
  }

  // Create a new BIO to hold the public key
  pub_bio = BIO_new(BIO_s_mem());
  if (pub_bio == NULL) {
    fprintf(stderr, "Failed to create BIO for public key\n");
    goto cleanup;
  }
  if (!PEM_write_bio_PUBKEY(pub_bio, pkey)) {
    fprintf(stderr, "Failed to write public key to BIO\n");
    goto cleanup;
  }

  // Get the data from the BIO
  BIO_get_mem_ptr(pub_bio, &pub_key_mem);
  if (pub_key_mem == NULL) {
    fprintf(stderr, "Failed to get public key data from BIO\n");
    goto cleanup;
  }

  output = (char *)malloc(pub_key_mem->length + 1);
  if (output == NULL) {
    fprintf(stderr, "Failed to allocate memory for public key\n");
    goto cleanup;
  }

  // Copy the public key to the output buffer
  memcpy(output, pub_key_mem->data, pub_key_mem->length);
  output[pub_key_mem->length] = '\0'; // Null-terminate the output buffer

cleanup:
  if (pub_bio)
    BIO_free(pub_bio);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (cert)
    X509_free(cert);
  if (bio)
    BIO_free_all(bio);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  return output;
}
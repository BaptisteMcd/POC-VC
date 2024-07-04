// #include <cinttypes>
#define _GNU_SOURCE
// #include "../include/jsmn.h"
#include "../include/kc_auth.h"
#include "../include/b64.h"
// #include "../src/kc_auth.c"
//  #include <libpq-fe.h>
#include <postgresql/libpq-fe.h>
#include <stdbool.h>
// #include <stdexcept>

#include <assert.h>
#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {

  char full_sd_jwt[] =
      "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHd1pmZHVfeEE1TVlKbUlX"
      "bnJBZHZiRXhNTVdHZHNxZlkycW9xRlZoVlBNIn0."
      "eyJfc2QiOlsiYUlxX2x3WTdMY1NfNTM1RzhfQVp1U2x0SXBTcW53amFwVjFNd05nQkZicyIs"
      "ImRDMkljS0R1SS15WUg1S1U3Nnd0aGlURWIyR3FFZ1A3dVllek5Wb241aDAiLCJxaDNGYW5R"
      "ZlVpMjVOTWFvcGdZcGtKcDB5MlRHZlR3QWJXS3B4VlB4RUZRIl0sIl9zZF9hbGciOiJTSEEt"
      "MjU2IiwiaXNzIjoiZGlkOndlYjp0ZXN0Lm9yZyIsIm5iZiI6MTcxOTIzNDk1NSwidmN0Ijoi"
      "TmF0dXJhbFBlcnNvbkNyZWRlbnRpYWwiLCJqdGkiOiJ1cm46dXVpZDo5MWI5YWFhZC1mYTcx"
      "LTRiNmItODUzYy1hYTQ4ZGYwNDdlMGYifQ."
      "RWg2UUqluXsnrSDDkwQ0Dz6M1N3fGO9XjBZenEMIAOTbfOQwjG5eU9jDqRlysSaQ6nffBR1I"
      "G6Gx1HDq_"
      "e8yu33l192GMf6oyTI3QX7I2D4TdWWLTSNfBbxIs9jpaUMpkBmz01NBjsKFOsaz5X09wHH3C"
      "gfT3BRMiDd3Qi_iDBaNSZ5pz_ij3TD_nLIsfGikxCpPlIj8KPAIffrWczl4X5ikNh8Bj-"
      "X67YbDKZ0iHtEhU18vaGHE6YpBCY_Kl6DBGEJ_fYiN33sP5hjuRJkaNCpHYj_"
      "Ix6cqJUtZeHSIxez1Q4Jq3KMIVi5Mi5fqpai6hoNcG-mjFbm9jLI1cEh8PQ~"
      "WyJpX2dTSC1McUYydjBuRnZQTDl0ZUJnIiwgInJvbGVzIiwgW3sibmFtZXMiOiBbIkVNUExP"
      "WUVFIl0sICJ0YXJnZXQiOiAiZGlkOndlYjp0ZXN0LW1hcmtldHBsYWNlLm9yZyJ9XV0~"
      "WyI5THJCcmJfcnNpZjlJQU1YWU02U3d3IiwgImlkIiwgImRpZDprZXk6ejZNa2hhU2FmMWFj"
      "eFhkaHNvQzNVZ3hSQm9LMXdrTFVCaDZMcTRCblB1VmN0RG9zIl0~"
      "WyJBLUxZcFBYTEsyUk5ObmVzSklyXzlBIiwgImVtYWlsIiwgInRvdG9AdG90by5uZXQiXQ~";

  char *jwt = NULL;
  char **parsed_sd_jwt = NULL;
  unsigned long ndisclosures;
  parse_SD_JWT_VC(full_sd_jwt, &parsed_sd_jwt, &ndisclosures);

  // printf("Voici le jwt : %s \n", jwt);
  printf("Addresses of the parsed SD-JWT : %p\n", *parsed_sd_jwt);
  printf("Voici les chaines de char du tableau : \n");
  PrintArray(parsed_sd_jwt, ndisclosures);
  // assert(ndisclosures == 4);

  printf("First disclosure Decoded : %s \n", base64_decode(parsed_sd_jwt[1]));

  const char *jwttocheck =
      "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHd1pmZHVfeEE1TVlKbUlX"
      "bnJBZHZiRXhNTVdHZHNxZlkycW9xRlZoVlBNIn0."
      "eyJfc2QiOlsiYUlxX2x3WTdMY1NfNTM1RzhfQVp1U2x0SXBTcW53amFwVjFNd05nQkZicyIs"
      "ImRDMkljS0R1SS15WUg1S1U3Nnd0aGlURWIyR3FFZ1A3dVllek5Wb241aDAiLCJxaDNGYW5R"
      "ZlVpMjVOTWFvcGdZcGtKcDB5MlRHZlR3QWJXS3B4VlB4RUZRIl0sIl9zZF9hbGciOiJTSEEt"
      "MjU2IiwiaXNzIjoiZGlkOndlYjp0ZXN0Lm9yZyIsIm5iZiI6MTcxOTIzNDk1NSwidmN0Ijoi"
      "TmF0dXJhbFBlcnNvbkNyZWRlbnRpYWwiLCJqdGkiOiJ1cm46dXVpZDo5MWI5YWFhZC1mYTcx"
      "LTRiNmItODUzYy1hYTQ4ZGYwNDdlMGYifQ."
      "RWg2UUqluXsnrSDDkwQ0Dz6M1N3fGO9XjBZenEMIAOTbfOQwjG5eU9jDqRlysSaQ6nffBR1I"
      "G6Gx1HDq_"
      "e8yu33l192GMf6oyTI3QX7I2D4TdWWLTSNfBbxIs9jpaUMpkBmz01NBjsKFOsaz5X09wHH3C"
      "gfT3BRMiDd3Qi_iDBaNSZ5pz_ij3TD_nLIsfGikxCpPlIj8KPAIffrWczl4X5ikNh8Bj-"
      "X67YbDKZ0iHtEhU18vaGHE6YpBCY_Kl6DBGEJ_fYiN33sP5hjuRJkaNCpHYj_"
      "Ix6cqJUtZeHSIxez1Q4Jq3KMIVi5Mi5fqpai6hoNcG-mjFbm9jLI1cEh8PQ";

  const char *token =
      "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHd1pmZHVfeEE1TVlKbUlX"
      "bnJBZHZiRXhNTVdHZHNxZlkycW9xRlZoVlBNIn0."
      "eyJfc2QiOlsiYUlxX2x3WTdMY1NfNTM1RzhfQVp1U2x0SXBTcW53amFwVjFNd05nQkZicyIs"
      "ImRDMkljS0R1SS15WUg1S1U3Nnd0aGlURWIyR3FFZ1A3dVllek5Wb241aDAiLCJxaDNGYW5R"
      "ZlVpMjVOTWFvcGdZcGtKcDB5MlRHZlR3QWJXS3B4VlB4RUZRIl0sIl9zZF9hbGciOiJTSEEt"
      "MjU2IiwiaXNzIjoiZGlkOndlYjp0ZXN0Lm9yZyIsIm5iZiI6MTcxOTIzNDk1NSwidmN0Ijoi"
      "TmF0dXJhbFBlcnNvbkNyZWRlbnRpYWwiLCJqdGkiOiJ1cm46dXVpZDo5MWI5YWFhZC1mYTcx"
      "LTRiNmItODUzYy1hYTQ4ZGYwNDdlMGYifQ."
      "RWg2UUqluXsnrSDDkwQ0Dz6M1N3fGO9XjBZenEMIAOTbfOQwjG5eU9jDqRlysSaQ6nffBR1I"
      "G6Gx1HDq_"
      "e8yu33l192GMf6oyTI3QX7I2D4TdWWLTSNfBbxIs9jpaUMpkBmz01NBjsKFOsaz5X09wHH3C"
      "gfT3BRMiDd3Qi_iDBaNSZ5pz_ij3TD_nLIsfGikxCpPlIj8KPAIffrWczl4X5ikNh8Bj-"
      "X67YbDKZ0iHtEhU18vaGHE6YpBCY_Kl6DBGEJ_fYiN33sP5hjuRJkaNCpHYj_"
      "Ix6cqJUtZeHSIxez1Q4Jq3KMIVi5Mi5fqpai6hoNcG-mjFbm9jLI1cEh8PQ";

  // pubkey must be in PEM format
  const char *public_key =
      "-----BEGIN PUBLIC "
      "KEY-----"
      "\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1M1vl2mW0ewMctKEoCYG6+"
      "SgV9TqN+4oIt2ZLkQb1O+yWGTWuu8h2U7yZ+"
      "Dc1JfSPUd45eU1p9j3rYu5Bs2Labc6zZUYyBMjZXopv/"
      "AqIOhvuTRRg7v4yRkC6QACniLndPCkanlp/"
      "8dL98Gmm8x+"
      "oOjYf1UFbGxjGqqVxfNVZmGi9NLE6AM0e4wmBVknwWTcC3TTHDxgAxHHa0GhL1y7OYsmw9Kz"
      "1riUWlr0Az3lBclOFACbOp/"
      "cGnyHnotErw1xKVQtGOv4GIsYQZr4jIeQkoFcqbAQVOk30NjTRNgVra2JzEpMvhbm4l+"
      "WHK2OfsPfBx6OKTOmet6zJnnNC608jQIDAQAB\n-----END PUBLIC KEY-----";
  bool valid;

  printf("\nAvant validation le jeton : %s\n la clée publique : %s\n",
         parsed_sd_jwt[0], public_key);
  valid = validate_jwt((const char **)&parsed_sd_jwt[0], &public_key);
  assert(valid == 1);
  printf("Le jeton est %s.\n", valid ? " validé" : "non validé");

  char *grants = NULL;
  grants = extract_grant_jwt((const char **)&parsed_sd_jwt[0], "_sd");
  assert(grants != NULL);
  printf("The grants found in the jwt : %s \n", grants);

  char **SD_array = NULL;
  int nSD_array;
  valid = json_array_2_array(&grants, &SD_array, &nSD_array);
  assert((valid = true && nSD_array == 3));
  PrintArray(SD_array, nSD_array);

  // the disclosure claimed
  const char *SD_input =
      "WyJpX2dTSC1McUYydjBuRnZQTDl0ZUJnIiwgInJvbGVzIiwgW3sibmFtZXMiOiBbIkVNUExP"
      "WUVFIl0sICJ0YXJnZXQiOiAiZGlkOndlYjp0ZXN0LW1hcmtldHBsYWNlLm9yZyJ9XV0";

  // Print the hash
  char *hash = NULL;
  assert(SHA256_sum(SD_input, &hash) == 1);
  printf("URL-safe Base64 encoded hash: %s\n", hash);

  printf("Comparaison found to 2nd sd signed hash %s \n",
         strcmp((const char *)hash, SD_array[1]) == 0
             ? "same, the disclosure is valid"
             : "differs disclosure isn't valid");
  valid = check_claim_validity((const char **)SD_array, nSD_array, SD_input);
  assert(valid == 1);
  // TODO : free()
  return 0;
}
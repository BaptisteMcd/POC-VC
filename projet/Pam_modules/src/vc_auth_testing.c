// #include <cinttypes>
#define _GNU_SOURCE
// #include "../include/jsmn.h"
#include "../include/kc_auth.h"
#include "../lib/b64.h"
// #include "../src/kc_auth.c"
//  #include <libpq-fe.h>
#include <postgresql/libpq-fe.h>
#include <stdbool.h>
// #include <stdexcept>

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
  //assert(ndisclosures == 4);

  printf("First disclosure Decoded : %s \n",base64_decode(parsed_sd_jwt[1]));


  const char * certificate = "-----BEGIN CERTIFICATE-----MIIE/jCCA+agAwIBAgISA6pEpAokqYJAJqQPgnCnsHAsMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMzEyMjQwNTQxMzFaFw0yNDAzMjMwNTQxMzBaMCMxITAfBgNVBAMTGGNvbnN1bWVyLmRvbWUuZml3YXJlLmRldjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANTNb5dpltHsDHLShKAmBuvkoFfU6jfuKCLdmS5EG9Tvslhk1rrvIdlO8mfg3NSX0j1HeOXlNafY962LuQbNi2m3Os2VGMgTI2V6Kb/wKiDob7k0UYO7+MkZAukAAp4i53TwpGp5af/HS/fBppvMfqDo2H9VBWxsYxqqlcXzVWZhovTSxOgDNHuMJgVZJ8Fk3At00xw8YAMRx2tBoS9cuzmLJsPSs9a4lFpa9AM95QXJThQAmzqf3Bp8h56LRK8NcSlULRjr+BiLGEGa+IyHkJKBXKmwEFTpN9DY00TYFa2ticxKTL4W5uJflhytjn7D3wcejikzpnresyZ5zQutPI0CAwEAAaOCAhswggIXMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUxOKFQ5oAbX4U5ixy4ofvajMkTdAwHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wIwYDVR0RBBwwGoIYY29uc3VtZXIuZG9tZS5maXdhcmUuZGV2MBMGA1UdIAQMMAowCAYGZ4EMAQIBMIIBBQYKKwYBBAHWeQIEAgSB9gSB8wDxAHcASLDja9qmRzQP5WoC+p0w6xxSActW3SyB2bu/qznYhHMAAAGMmo6vgQAABAMASDBGAiEAzJ0YhzMGyKKrkD66BAJQkWOqQS4E32X9jYvVL/XjqR4CIQCtrHjnCE7LdIBhESY873ctjvd3izH/F+OeoLocfP/p8wB2AHb/iD8KtvuVUcJhzPWHujS0pM27KdxoQgqf5mdMWjp0AAABjJqOsBQAAAQDAEcwRQIhALZ8CQK+/Rj8p0krq96y68KED2qN9VWEA/diHmc3BSPkAiBhmZRBIDYZ3+BwiYQXLmWB34Uc8RCvsEHBHLVsLWJtizANBgkqhkiG9w0BAQsFAAOCAQEAn/2qNjtU0v1fQbTnFgrOzvCDnruhWSgqC7t9/vAv+mK5t/KEIwMfDAXiaNXofn8me5nXXsfGSxhqNfXpBBfzGA6MEM3Rfqd+D2ie5+oWtNY+5Tdoi/jdaww07ZiiFsFPPfPgHZ6LbU/jDP4J0VwwYt30+FWMkKecsXKOCt+VUB3tgo0PY3DQOsbmSt9rFAIv8LHa8mQ/ikF+sk07BP+CfAjPz/4Rg8AR8A9mtqKMlD3AvvMLxVga/KgEEaB4vGrcK1liBFZF6/RRwExeXn0nErcHYGiqeiyYD8sI07QCRv2bv0LYkmEKqB/RxgTWMkltTQUFjUD55Dy1/4UTXtM9yg==-----END CERTIFICATE-----";
 const char * jwttocheck = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJHd1pmZHVfeEE1TVlKbUlXbnJBZHZiRXhNTVdHZHNxZlkycW9xRlZoVlBNIn0.eyJfc2QiOlsiYUlxX2x3WTdMY1NfNTM1RzhfQVp1U2x0SXBTcW53amFwVjFNd05nQkZicyIsImRDMkljS0R1SS15WUg1S1U3Nnd0aGlURWIyR3FFZ1A3dVllek5Wb241aDAiLCJxaDNGYW5RZlVpMjVOTWFvcGdZcGtKcDB5MlRHZlR3QWJXS3B4VlB4RUZRIl0sIl9zZF9hbGciOiJTSEEtMjU2IiwiaXNzIjoiZGlkOndlYjp0ZXN0Lm9yZyIsIm5iZiI6MTcxOTIzNDk1NSwidmN0IjoiTmF0dXJhbFBlcnNvbkNyZWRlbnRpYWwiLCJqdGkiOiJ1cm46dXVpZDo5MWI5YWFhZC1mYTcxLTRiNmItODUzYy1hYTQ4ZGYwNDdlMGYifQ.RWg2UUqluXsnrSDDkwQ0Dz6M1N3fGO9XjBZenEMIAOTbfOQwjG5eU9jDqRlysSaQ6nffBR1IG6Gx1HDq_e8yu33l192GMf6oyTI3QX7I2D4TdWWLTSNfBbxIs9jpaUMpkBmz01NBjsKFOsaz5X09wHH3CgfT3BRMiDd3Qi_iDBaNSZ5pz_ij3TD_nLIsfGikxCpPlIj8KPAIffrWczl4X5ikNh8Bj-X67YbDKZ0iHtEhU18vaGHE6YpBCY_Kl6DBGEJ_fYiN33sP5hjuRJkaNCpHYj_Ix6cqJUtZeHSIxez1Q4Jq3KMIVi5Mi5fqpai6hoNcG-mjFbm9jLI1cEh8PQ";

  bool valid;
  validate_jwt((const char **) &jwttocheck, &certificate);
  
  
  // TODO : free()
  return 0;
}
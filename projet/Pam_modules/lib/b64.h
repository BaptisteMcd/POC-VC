#ifndef _BASE64_H_d_
#define _BASE64_H_d_

void PrintArray(char **array, int n);
char *base64_decode(char *cipher);
const bool validate_jwt(const char **p_token, const char **p_public_key);
bool parse_SD_JWT_VC(char *raw_sd_jwt, char ***sd_jwt,
                     unsigned long *nelemenents);
char *extract_grant_jwt(const char **p_token, const char *grant);

// Check if one claim is true in a set of Selective disclosure digests check claim in b64 format
bool check_claim_validity(const char **sd_array,const int nsd_array, const char *claim);
bool json_array_2_array(char **json_array, char ***array, int *narray);
void base64_url_safe_encode(const unsigned char *input, int length,
                            char *output);
bool SHA256_sum(const char * raw_text, char ** base64_output);

#endif /* _BASE64_H_d_ */
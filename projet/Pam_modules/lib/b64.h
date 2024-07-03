#ifndef _BASE64_H_d_
#define _BASE64_H_d_

void PrintArray(char **array, int n);
char* base64_decode(char* cipher);
const bool validate_jwt(const char **p_token, const char **p_public_key);
bool parse_SD_JWT_VC(char *raw_sd_jwt, char *** sd_jwt, unsigned long *nelemenents);

#endif /* _BASE64_H_d_ */

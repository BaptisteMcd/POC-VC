#ifndef _BASE64_H_d_
#define _BASE64_H_d_

/**
 * Fonction to print an array of char *
 * @param array the array to print
 * @param n number of elements in the array
 */
void PrintArray(char **array, int n);

/**
 * Fonction to decode base64
 * @param cipher the base64 string to decode
 * @return the decoded string
 */
char *base64_decode(char *cipher);

/**
 * Fonction to validate a JWT token
 * @param p_token pointer on a char * representing the token
 * @param p_public_key pointer on a char * representing the public key
 * @return true if token is valid false otherwise
 */
const bool validate_jwt(const char **p_token, const char **p_public_key);

/**
 * Fonction Parse a Selective Disclosure JWT
 * @param[in] raw_sd_jwt the raw jwt to parse
 * @param[out] sd_jwt pointer on a char ** jwt + disclosures
 * @param[out] nelemenents pointer on the number of elements in the array (jwt +
 * disclosures)
 */
bool parse_SD_JWT_VC(char *raw_sd_jwt, char ***sd_jwt,
                     unsigned long *nelemenents);

/**
 * Fonction to extract a grant from a jwt
 * @param[in] p_token pointer on a char * representing the token
 * @param[in] grant the grant to extract
 * @return the extracted grant as a string
 */
char *extract_grant_jwt(const char **p_token, const char *grant);

/**
 * Fonction to extract a claim from a jwt
 * @param[in] json_array the json array to parse
 * @param[out] array the array to fill
 * @param[out] narray the number of elements in the array
 */
bool json_array_2_array(char **json_array, char ***array, int *narray);

/**
 * Check if one claim is inside a set of disclosed claims
 * @param[in] sd_array the array of disclosed claims
 * @param[in] nsd_array the number of disclosed claims
 * @param[in] claim the claim to check
 * @return true if the claim is inside the disclosed claims, false otherwise
 */
bool check_claim_validity(const char **sd_array, const int nsd_array,
                          const char *claim);

/**
 * Function to convert the hash to a URL-safe Base64 string
 * @param input the hash to convert
 * @param length the length of the hash
 * @param output the output string
 */
void base64_url_safe_encode(const unsigned char *input, int length,
                            char *output);

/**
 * Function to calculate the SHA256 hash of a string
    * @param raw_text the string to hash
    * @param base64_output the output string
    * @return true if the hash is calculated, false otherwise
 */
bool SHA256_sum(const char *raw_text, char **base64_output);

#endif /* _BASE64_H_d_ */

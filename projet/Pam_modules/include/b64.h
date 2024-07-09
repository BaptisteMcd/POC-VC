/** @file b64.h
 * @brief My utils to manipulate b64 data and validate SD-JWT tokens
 * @author Baptiste Marchand
 */
#include <stdbool.h>
#include <stddef.h>
#ifndef _BASE64_H_d_
#define _BASE64_H_d_

/**
 * Fonction to print an array of char *
 * @param[in] array the array to print
 * @param[in] n number of elements in the array
 */
void PrintArray(char **array, int n);

/** 
* Fonction to decode a base64 string
* @param[in] base64_input the base64 string to decode
* @param[out] output the decoded string
* @param[out] length the length of the decoded string
*/
int base64_url_safe_decode(const char *base64_input, char **output, int *length);

/**
 * Fonction to validate a JWT token
 * @param[in] p_token pointer on a char * representing the token
 * @param[in] p_public_key pointer on a char * representing the public key
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
                     int *nelemenents);

/**
 * Fonction to extract a grant from a jwt
 * @param[in] p_token pointer on a char * representing the token
 * @param[in] grant the grant to extract
 * @return the extracted grant as a string
 */
char *extract_grant_jwt(const char **p_token, const char *grant);

/**
 * Fonction to convert claim json array as a string into a real c array (char
 * **)
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
 * @param[in] input the hash to convert
 * @param[in] length the length of the hash
 * @param[out] output the output string
 */
void base64_url_safe_encode(const unsigned char *input, int length,
                            char *output);

/**
 * Function to calculate the SHA256 hash of a string
 * @param[in] raw_text the string to hash
 * @param[out] base64_output the output string
 * @return true if the hash is calculated, false otherwise
 */
bool SHA256_sum(const char *raw_text, char **base64_output);

/**
 * Function check if string is inside an array
 * @param[in] array the array to check
 * @param[in] narray the number of elements in the array
 * @param[in] claim the claim to check
 *@return true if the claim is inside the array, false otherwise
 */
bool is_in_array(const char **array, const int narray, const char *claim);

/**
* Function to retrieve the public key from a file
* @param[in] filepath the path to the file containing the public key
* @return char * public key, needs to be freed
*/ char *get_pub_key(const char *filepath);

/**
* Function to check the username disclosure is in a set of disclosed claims
* @param[in] array the array of disclosed claims 
* @param[in] narray the number of disclosed claims
* @param[in] username the username to check
* @param[out] index the index of the corresponding SD claim in the array
 */
bool user_in_disclosures(const char **array, const int narray, const char *username, int * index);

/**
* Function to decode all base 64 disclosure of a VCP
* @param[in] parsed_sd_jwt the parsed jwt token
* @param[in] ndisclosures the number of disclosures
* @param[out] decoded_SD the decoded SDs
* @param[out] length the number of decoded SDs
 */
bool decode_all_sd(const char **parsed_sd_jwt, const int ndisclosures, char ***decoded_SD, int *length);
#endif /* _BASE64_H_d_ */
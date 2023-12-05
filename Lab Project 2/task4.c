/*task 4*/
#include <stdio.h>
#include <openssl/bn.h>
#include<string.h>
/*function to display the singature */
void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}
int main() {
const char *input_string = "I owe you $3000.";
    char hex_string[2 * strlen(input_string) + 1]; // Twice the length for hexadecimal representation + 1 for null terminator

    for (int i = 0; i < strlen(input_string); ++i) {
        sprintf(hex_string + 2 * i, "%02X", input_string[i]);
    }
    printf("Hexadecimal representation: %s\n", hex_string);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *message = BN_new();
    /*message given we convert it from hex to bn*/
    BN_hex2bn(&message, hex_string);
    /*n value given we convert it to bn*/
    BIGNUM *N = BN_new();
    BN_hex2bn(&N, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    /* private key is given convert it to bn*/
    BIGNUM *D = BN_new();
    BN_hex2bn(&D, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BIGNUM *signature = BN_new();
    /* In rsa method signing is done using the private key on the message as follows */
    BN_mod_exp(signature, message, D, N, ctx);
    /*signature printed here*/
    printBN("signature:",signature);
    // free space
    BN_free(message);
    BN_free(N);
    BN_free(D);
    BN_free(signature);
    BN_CTX_free(ctx);
    return 0;
}
	


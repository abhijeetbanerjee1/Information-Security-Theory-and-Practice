/* Task 3 */
#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *cipher_text = BN_new();
    /*cipher_text given we convert it from hex to bn*/
    BN_hex2bn(&cipher_text, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    /*n value given we convert it to bn*/
    BIGNUM *N = BN_new();
    BN_hex2bn(&N, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    /* private key is given convert it to bn*/
    BIGNUM *D = BN_new();
    BN_hex2bn(&D, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BIGNUM *decrypt_message = BN_new();
    BN_mod_exp(decrypt_message, cipher_text, D, N, ctx);
    char *message_hex = BN_bn2hex(decrypt_message);
     /*find length of the hex message*/
    int length = strlen(message_hex);
    /*function to change the hex message to ascii value to read it*/
    char *message_in_ascii = OPENSSL_malloc(length / 2);
    for (int i = 0, j = 0; i < length; i += 2, j++) {
        sscanf(message_hex + i, "%2hhx", &message_in_ascii[j]);
    }
   	message_in_ascii[length / 2] = '\0';
    printf("Decrypted message (ASCII): %s\n", message_in_ascii);
    // free space
    BN_free(cipher_text);
    BN_free(N);
    BN_free(D);
    BN_free(decrypt_message);
    BN_CTX_free(ctx);
    OPENSSL_free(message_hex);
    OPENSSL_free(message_in_ascii);
    return 0;
}
	


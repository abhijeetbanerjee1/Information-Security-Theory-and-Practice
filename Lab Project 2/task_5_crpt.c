#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>
int main() {
    char *M = "4C61756E63682061206D697373696C652E";
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *signature_crpt = BN_new();
    BIGNUM *decrypted = BN_new();
    
    // Set the public key values
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    // Set the corrupted signature
    BN_hex2bn(&signature_crpt, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

    // Decrypting the corrupted signature
    BN_mod_exp(decrypted, signature_crpt, e, n, ctx);
    
    // Convert the decrypted BIGNUM to a hex string
    char *hex_str = BN_bn2hex(decrypted);
    printf("Corrupted Signature in hex: %s\n", hex_str);

    printf("Verifying the Signature...\n");

    // Verifying the corrupeted Signature by comparing it to the original Message
    if (strcmp(M, hex_str) == 0){
	printf("The Signature is valid.\n");
	}
    else{
	printf("The Signature is NOT valid.\n");
	}
    return 0;
}

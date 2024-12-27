#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
   /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
   char *number_str = BN_bn2hex(a);
   printf("%s %s\n", msg, number_str);
   OPENSSL_free(number_str);
}

int main ()
{
  BN_CTX *ctx = BN_CTX_new();
	 
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *M = BN_new(); 
  BIGNUM *msg1 = BN_new();
  BIGNUM *sign1 = BN_new();
  BIGNUM *msg2 = BN_new();
  BIGNUM *sign2 = BN_new();


  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); 
  BN_hex2bn(&e, "010001" );
  BN_hex2bn(&M, "4c61756e63682061206d697373696c652e");
  BN_hex2bn(&sign1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
  BN_hex2bn(&sign2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  
  BN_mod_exp(msg1, sign1, e, n, ctx);
  BN_mod_exp(msg2, sign2, e, n, ctx);
  
  printf("Verification of original signature: ");
  if (BN_cmp(msg1, M) == 0){
	  printf("Signature is valid.\n");
  }
  else {
	  printf("Signature is invalid.\n");
  }

  printf("Verification of corrupted signature: ");
  if (BN_cmp(msg2, M) == 0){
          printf("Signature is valid.\n");
  }
  else {
          printf("Signature is invalid.\n");
  }


  return 0;
}


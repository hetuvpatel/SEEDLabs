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
  BIGNUM *d = BN_new(); 
  BIGNUM *msg1 = BN_new();
  BIGNUM *sign1 = BN_new();
  BIGNUM *msg2 = BN_new();
  BIGNUM *sign2 = BN_new();


  BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5"); 
  BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D" );
  BN_hex2bn(&msg1, "49206f776520796f752024323030302e");
  BN_hex2bn(&msg2, "49206f776520796f752024333030302e");
  
  BN_mod_exp(sign1, msg1, d, n, ctx);
  BN_mod_exp(sign2, msg2, d, n, ctx);

  printBN("Signature for \"I owe you $2000.\": ", sign1);
  printBN("Signature for \"I owe you $3000.\": ", sign2);

  return 0;
}


#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string */
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    // Declare variables
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *S = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *m = BN_new();

    // Initialize n, e, S, and b
    BN_hex2bn(&n, "B6E02FC22406C86D045FD7EF0A6406B27D22266516AE42409BCEDC9F9F76073EC330558719B94F940E5A941F5556B4C2022AAFD098EE0B40D7C4D03B72C8149EEF90B111A9AED2C8B8433AD90B0BD5D595F540AFC81DED4D9C5F57B786506899F58ADAD2C7051FA897C9DCA4B182842DC6ADA59CC71982A6850F5E44582A378FFD35F10B0827325AF5BB8B9EA4BD51D027E2DD3B4233A30528C4BB28CC9AAC2B230D78C67BE65E71B74A3E08FB81B71616A19D23124DE5D79208AC75A49CBACD17B21E4435657F532539D11C0A9A631B199274680A37C2C25248CB395AA2B6E15DC1DDA020B821A293266F144A2141C7ED6D9BF2482FF303F5A26892532F5EE3");
    BN_set_word(e, 65537);
    BN_hex2bn(&S, "5202fd1feb29b64ebc10dd6efb14bef3f1ffca4a546b8ac401a292052a619c928788b2b9d879f369af3f422550d80199b617038889cfb764d0f2d28565a3083c39c648466796d7a57a89ceb28c155dabe38663cf25e71db50ebbbba7894afb72635f801f2c4082168d804e3921a6097362e0319b181d73311ebd73752c8ea1e749b2f78d6836732c8b8071f095c08a7c13cf3d5ae1dbb001173347fbb9a55550e18afff00fa8d7acd7bb9e841cd6d0d56876fa611449227036bde5661280a64c071b6f629aa360c2f1871ca0f8099984e320e458d42e46dd56b5206e986100bdcc5d03940185dc8fb6d65b08c52a89725f660e2e72abb8178e15c2aea65d91ae");
    BN_hex2bn(&b, "3975378b556db0fa31785d22bfe7a72b06d44c099a6524ed1172cbff1d125568");

    // Decrypt the signature S using public key: m = S^e mod n
    BN_mod_exp(m, S, e, n, ctx);

    // Print original and decrypted messages
    printBN("Expected Message (original) = ", b);
    printBN("Decrypted Message (from signature) = ", m);

    // Verify signature by comparing expected message to decrypted message
    
    char *b_hex = BN_bn2hex(b);
    char *m_hex = BN_bn2hex(m);

    if (strstr(m_hex, b_hex) != NULL) {
	    printf("Signature: VALID\n");
    } else {
	    printf("Signature: INVALID\n");
    }
    

    // Clean up
    BN_free(n);
    BN_free(e);
    BN_free(S);
    BN_free(b);
    BN_free(m);
    BN_CTX_free(ctx);

    return 0;
}


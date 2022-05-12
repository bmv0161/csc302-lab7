#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}
void keygen(BIGNUM *p, BIGNUM *q, BIGNUM *e, BIGNUM *d, BIGNUM *n);
void encrypt(char *text, BIGNUM *e, BIGNUM *n, BIGNUM *c);
void decrypt(BIGNUM *c, BIGNUM *d, BIGNUM *n);
void sign(char *text, BIGNUM *d, BIGNUM *n, BIGNUM *s, BIGNUM *m);
void validate(BIGNUM *s, BIGNUM *e, BIGNUM *m, BIGNUM *n);
void charToASCII(char *text, char *ascii);

int main(int argc, char *argv[]) {
    //initializing values 
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *m = BN_new();
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    //generate private key
    keygen(p, q, e, d, n);
    printf("\n");
    //hex value encryption
    /*
    if(argc == 2) {
        char text[32];
        snprintf(text, 32, "%s", argv[1]);
        encrypt(text, e, n, c);
    } else {
    */
    encrypt("4120746f702073656372657421", e, n, c);
    //}
    //hex value decryption
    //BN_hex2bn(&c, argv[1]);
    //printBN("c = ", c);
    decrypt(c, d, n);
    printf("\n");
    
    //Signature creation
    if(argc == 2) {
        sign(argv[1], d, n, s, m);
    } else {
        sign("I owe you $2000.", d, n, s, m);
    }
    
    /*
    //Signature validation
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    
    char *text = "Launch a missile.";
    BN_bin2bn(text, strlen(text), m);
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F181161"); 
    */
    validate(s, e, m, n);
}

void keygen(BIGNUM *p, BIGNUM *q, BIGNUM *e, BIGNUM *d, BIGNUM *n) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *o = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *k = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();
    BN_one(one);
    //calculate n
    BN_mul(n, p, q, ctx);
    //calculate o
    BN_sub(p, p, one);
    BN_sub(q, q, one);
    BN_mul(o, p, q, ctx);
    //printBN("o = ", o);
    
    //calculate d
    //unsigned int dec_e = atoi(BN_bn2dec(e));
    for(unsigned int i = 0; i < UINT_MAX; i++) {
        char str[10];
        snprintf(str, sizeof(str), "%d", i);
        BN_dec2bn(&k, str);

        BN_mul(temp1, k, o, ctx);
        BN_add(temp1, temp1, one);
        BN_mod(temp2, temp1, e, ctx);
        //BN_mod_add(temp2, temp1, one, e, ctx);
        
        if(BN_is_zero(temp2)) {
            BN_div(d, temp2, temp1, e, ctx);
            break;
        }
    }
    printf("private key (d, n):\n");
    printBN("d = ", d);
    printBN("n = ", n);
}
void encrypt(char *text, BIGNUM *e, BIGNUM *n, BIGNUM *c) {
    BIGNUM *m = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    BN_hex2bn(&m, text);
    BN_mod_exp(c, m, e, n, ctx);
    printBN("Cipher Text: ", c);
}
void decrypt(BIGNUM *c, BIGNUM *d, BIGNUM *n) {
    BIGNUM *m = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    BN_mod_exp(m, c, d, n, ctx);
    printBN("Decrypted Text: ", m);
}
void sign(char *text, BIGNUM *d, BIGNUM *n, BIGNUM *s, BIGNUM *m) {
    BN_CTX *ctx = BN_CTX_new();

    printf("Original: %s\n", text);
    BN_bin2bn(text, strlen(text), m);
    printBN("m = ", m);
    BN_mod_exp(s, m, d, n, ctx);
    
    unsigned char sig[BN_num_bytes(s)];   
    BN_bn2bin(s, sig);
    printBN("Hex Signature: ", s);
    printf("Bin Signature: %s\n", sig);
}
void validate(BIGNUM *s, BIGNUM *e, BIGNUM *m, BIGNUM *n) {
    BIGNUM *m1 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *temp1 = BN_new(); 
    char temp2[strlen(BN_bn2hex(m)) / 2 + 1];
    long int len = sizeof(temp2);
    
    BN_mod_exp(m1, s, e, n, ctx);
    //printBN("Original: ", m);
    //BN_signed_bn2bin(m,temp2);
    //printf("Bin Original: %s\n", temp2);
    //printBN("Hex Original: ", m);
    //printBN("Validation: ", m1);
    BN_bn2bin(m1,temp2);
    temp2[len-1] = '\0';
    printf("Bin Validation: %s\n", temp2);
    printBN("Hex Validation: ", m1);

    BN_sub(temp1, m, m1);
    if(BN_is_zero(temp1)) {
        printf("Signature validated\n");
    } else {
        printf("Signature invalid\n");
    }
}

void charToASCII(char *text, char* msg) {
    int length = strlen(text);
    int n = 0;
    for(int i = 0; i < length; i++) {
        n += sprintf(&msg[n], "%d", (int)text[i]);
    }
    //printf("\n%s\n", msg);
}

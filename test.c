#include<stdio.h>
#include<string.h>
# include  "openssl/bio.h"
# include  "openssl/ssl.h"
# include  "openssl/err.h"
# include  "openssl/sha.h"
# include  "openssl/aes.h"
# include  "openssl/evp.h"
# include  "openssl/rand.h"

int calc_sha512(char *path, char output[65]) {

    FILE *file = fopen(path, "rb");
    if(!file)
        return -1;

    unsigned char hash[SHA512_DIGEST_LENGTH];

    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    const int bufSize = 32768;
    char *buffer = malloc(bufSize);
    int bytesRead = 0;
    if(!buffer)
        return -1;
    
    while((bytesRead = fread(buffer, 1, bufSize, file))) {
        SHA512_Update(&sha512, buffer, bytesRead);
    }

    SHA512_Final(hash, &sha512);

    for (int i = 0; i<SHA512_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    output[64] = 0;
    fclose(file);
    free(buffer);
    return 0;
}

void PBKDF2_HMAC_SHA_512(const char* pass, int passlen, const unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)  {
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations, EVP_sha384(), outputBytes, digest);

    printf("PBKDF2 result : ");
    for (i = 0; i < sizeof(digest); i++)
    {
        printf("%02x", digest[i]);
        binResult[i] = digest[i];
    };
    printf("\n");
}

void encrypt(FILE *ifp, FILE *ofp) {

    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    fseek(ifp, 0L, SEEK_SET);

    int outlen1 = 0, outlen2 = 0;

    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize*2);
    unsigned char ckey[] = "thisisabadkey";
    unsigned char ivec[] = "dontusethisinput";

    fread(indata, sizeof(char), fsize, ifp);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), ckey, ivec);
    EVP_EncryptUpdate(ctx, outdata, &outlen1, indata, fsize);
    EVP_EncryptFinal(ctx, outdata+outlen1, &outlen2);
    fwrite(outdata, sizeof(char), outlen1+outlen2, ofp);
    printf("Encryption done\n");
}

int main(int argc, char** argv) {
    printf("Hello world of openssl\n");

    char output[65];
    const char *pass = "hello";
    const unsigned char *salt = "KCl";
    uint32_t outputBytes = 64;
    char hexResult[2*outputBytes+1];
    uint8_t binResult[outputBytes+1];
    calc_sha512("hello.txt", output);
    PBKDF2_HMAC_SHA_512(pass, 5, salt, 3, 4096, outputBytes, hexResult, binResult);

    FILE *fIN, *fOUT;
    fIN = fopen("hello.txt", "rb");
    fOUT = fopen("hello.txt.uf", "wb");
    
    encrypt(fIN, fOUT);
    calc_sha512("hello.txt.uf", output);
    return 0;
}
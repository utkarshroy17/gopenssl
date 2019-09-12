#include<stdio.h>
#include<string.h>
# include  "openssl/bio.h"
# include  "openssl/ssl.h"
# include  "openssl/hmac.h"
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

    printf("File hash : ");
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

void encrypt(FILE *ifp, FILE *ofp, char key[129], unsigned char *digest) {

    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    fseek(ifp, 0L, SEEK_SET);

    int outlen1 = 0, outlen2 = 0;

    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize*2);
    unsigned char iv[32];

    if(!RAND_bytes(iv, sizeof(iv))) {
        printf("Error in generating IV\n");
        return;
    }

    fread(indata, sizeof(char), fsize, ifp);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
    EVP_EncryptUpdate(ctx, outdata, &outlen1, indata, fsize);
    EVP_EncryptFinal(ctx, outdata+outlen1, &outlen2);
    fwrite(outdata, sizeof(char), outlen1+outlen2, ofp);

    printf("AES : ");
    for(int i = 0; i<strlen(outdata); i++) {
        printf("%02x", outdata[i]);
    }

    printf("\nSuccessfully encrypted testfile\n");

    digest = HMAC(EVP_sha512(), key, strlen(key), outdata, strlen(outdata), NULL, NULL);

    printf("HMAC : ");
    for(int i = 0; i<strlen(digest); i++) {
        printf("%02x", digest[i]);
    }

    printf("\n");
}

void decrypt(FILE *ifp, FILE *ofp, char key[129], unsigned char *digest) {
    
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    //set back to normal
    fseek(ifp, 0L, SEEK_SET);

    int outLen1 = 0; int outLen2 = 0;
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize);
    unsigned char iv[32];
    unsigned char *decrypt_hmac;

    decrypt_hmac = HMAC(EVP_sha512(), key, strlen(key), outdata, strlen(outdata), NULL, NULL);

    printf("decryption HMAC : ");
    for(int i = 0; i<strlen(decrypt_hmac); i++) {
        printf("%02x", decrypt_hmac[i]);
    }

    printf("\n");

    if(!RAND_bytes(iv, sizeof(iv))) {
        printf("Error in generating IV\n");
        return;
    }

    fread(indata,sizeof(char),fsize, ifp);//Read Entire File

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx,EVP_aes_256_cbc(),key,iv);
    EVP_DecryptUpdate(ctx,outdata,&outLen1,indata,fsize);
    EVP_DecryptFinal(ctx,outdata + outLen1,&outLen2);

    printf("AES decryption : ");
    for(int i = 0; i<strlen(outdata); i++) {
        printf("%02x", outdata[i]);
    }
    printf("\nSuccessfully decrpyted testfile\n");
    fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);
}

int main(int argc, char** argv) {
    printf("Hello world of openssl\n");

    char output[65];
    const char *pass = "hello";
    const unsigned char *salt = "KCl";
    uint32_t outputBytes = 64;
    char hexResult[129];
    uint8_t binResult[65];
    calc_sha512("hello.txt", output);
    PBKDF2_HMAC_SHA_512(pass, 5, salt, 3, 4096, outputBytes, hexResult, binResult);

    FILE *fIN, *fOUT;
    unsigned char *digest;
    fIN = fopen("hello.txt", "rb");
    fOUT = fopen("hello.txt.uf", "wb");
    encrypt(fIN, fOUT, hexResult, digest);
    fclose(fIN);
    fclose(fOUT);

    calc_sha512("hello.txt.uf", output);
    
    unsigned char *concat = strcat(hexResult, digest);

    printf("Concatenated string : ");
    for(int i = 0; i<strlen(hexResult); i++) {
        printf("%02x", hexResult[i]);
    }

    printf("\n");

    fIN = fopen("hello.txt.uf", "rb");
    fOUT = fopen("hello_new.txt", "wb");
    decrypt(fIN, fOUT, hexResult, digest);
    fclose(fIN);
    fclose(fOUT);
    return 0;
}
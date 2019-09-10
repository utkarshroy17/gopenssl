#include<stdio.h>
#include<string.h>
# include  "openssl/bio.h"
# include  "openssl/ssl.h"
# include  "openssl/err.h"
# include  "openssl/sha.h"
# include  "openssl/aes.h"
# include  "openssl/rand.h"

int main(int argc, char** argv) {
    printf("Hello world of openssl\n");

    unsigned char hash[SHA512_DIGEST_LENGTH];
    calc_sha512("hello.txt", hash);
    char password[256];
    printf("Password : ");
    scanf("%s", password);
    

    printf("Creating SHA512\n");
    SHA512(password, strlen(password), hash);

    printf("SHA512 created\n");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    // SSL_load_error_strings();
    // ERR_load_BIO_strings();
    // OpenSSL_add_all_algorithms();
    // printf("Initialization done\n");
    // BIO * bio;
    // bio = BIO_new_connect("www.ibm.com:80");

    // if (bio == NULL) {
    //     printf("Connection failed\n");
    //     return 0;
    // }

    // if (BIO_do_connect(bio) <= 0) {
    //     printf("Failed connection\n");
    //     return 0;
    // }

    // // void * buf;
    // // if (BIO_write(bio, buf, 10) <= 0) {
    // //     if (!BIO_should_retry(bio)) {
    // //         printf("Failed writing");
    // //     }
    // // }
    
    // // int x = BIO_read(bio, buf, 10);
    // // if (x == 0) {
    // //     printf("Reading failed\n");
    // //     return 0;
    // // } 

    // // printf("x = %d", x);

    // printf("Connection successful\n");

    // BIO_reset(bio);
    // BIO_free_all(bio);

    // SSL_CTX ctx = SSL_CTX_new(SSLv23_client_method());
    // SSL ssl;
    return 0;
}
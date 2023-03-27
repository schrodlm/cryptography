#include <openssl/types.h>
#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

//enveloped data - high-level interface for cryptographic functions
#include <openssl/evp.h>

//functions for generating randomness suitable for cryptography
#include <openssl/rand.h>

#endif /* __PROGTEST__ */

#define DIGEST_NAME "sha512"

int findHash (int bits, char ** message, char ** hash) {
    /* TODO: Your code here */


    /*
    Já bych chtěl asi udělat postup druhou stranou, jelikož vím, jak má vypadat hash (mám počet 0, kteér budou na jeho počátku)
    -> chtěl bych tedy prvně nejspíše vytvořit hash a ten pak dešifrovat
     */

    //object holds digestion intermediate state and other data related to the operation
    EVP_MD_CTX *mdctx;

    //structure that represents a message digest algorithm in OpenSSL's EVP library
    const EVP_MD *md;

    char mess1[] = "Test Message\n";
    char mess2[] = "Hello World\n";

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname(DIGEST_NAME);
    if(!md){
      std::cout << "Unknown message digest " << DIGEST_NAME << std::endl;
      return 0;
    }

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx,md, NULL);
    EVP_DigestUpdate(mdctx,mess1, strlen(mess1));
    EVP_DigestUpdate(mdctx,mess2, strlen(mess2));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    EVP_MD_CTX_destroy(mdctx);

    std::cout << "Digest " << DIGEST_NAME << " is: " << std::endl;

    for(unsigned int i = 0; i < md_len; i++){
      //printf("%02x", md_value[i]);
      std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
    }
    std::cout << std::endl;

    EVP_cleanup();
    return 1;


}

int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    /* TODO or use dummy implementation */
    return 1;
}

#ifndef __PROGTEST__

int checkHash(int bits, char * hexString) {
    // DIY
}

int main (void) {
    char * message, * hash;

    findHash(0,&message, &hash);

//    assert(findHash(0, &message, &hash) == 1);
//    assert(message && hash && checkHash(0, hash));
//    free(message);
//    free(hash);
//    assert(findHash(1, &message, &hash) == 1);
//    assert(message && hash && checkHash(1, hash));
//    free(message);
//    free(hash);
//    assert(findHash(2, &message, &hash) == 1);
//    assert(message && hash && checkHash(2, hash));
//    free(message);
//    free(hash);
//    assert(findHash(3, &message, &hash) == 1);
//    assert(message && hash && checkHash(3, hash));
//    free(message);
//    free(hash);
//    assert(findHash(-1, &message, &hash) == 0);
//    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */


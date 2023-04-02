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

// enveloped data - high-level interface for cryptographic functions
#include <openssl/evp.h>

// functions for generating randomness suitable for cryptography
#include <openssl/rand.h>

#endif /* __PROGTEST__ */

#define DIGEST_NAME "sha512"
#define MESS_LENGTH 20

bool checkStrings(const char* lhs, const char* rhs)
{
  if(strlen(lhs) != strlen(rhs)) return false;

  for(size_t i = 0; i < strlen(lhs); i++)
  {
    if(lhs[i]!= rhs[i]) return false;
  }

  return true;
}

bool checkHash(int bits, unsigned char ct[EVP_MAX_MD_SIZE])
{

  // ct[i] by mělo být 8 bitů
  int toTransform = ceil(bits / 8.0);

  for (int i = 0; i < toTransform; i++)
  {
    int step = 7;
    while (step >= 0)
    {
      // check if nth bit is zero, if not return false
      // std::cout << (ct[i] >> step) << std::endl;
      if (!((ct[i] >> step) == 0))
        return false;

      step--;
      if (--bits == 0)
        break;
    }
  }

  return true;
}

int findHash(int bits, char **message, char **hash)
{
  // wrong input handling
  if (bits < 0 || bits > 512)
  {
    return 0;
  }

  // object holds digestion intermediate state and other data related to the operation
  EVP_MD_CTX *mdctx;

  // structure that represents a message digest algorithm in OpenSSL's EVP library
  const EVP_MD *md;

  if (message == NULL || hash == NULL)
  {
    std::cout << "Error: Failed to allocate memory for message/hash." << std::endl;
    return 0;
  }

  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname(DIGEST_NAME);
  if (!md)
  {
    std::cout << "Unknown message digest " << DIGEST_NAME << std::endl;
    return 0;
  }

  unsigned char open_text[MESS_LENGTH];

  do
  {
    // Creating SHA-512 message
    mdctx = EVP_MD_CTX_create();

    if (!RAND_bytes(open_text, MESS_LENGTH))
    {
      std::cout << "RAND_bytes failed" << std::endl;
    }
     //open_text[MESS_LENGTH] = '\0';

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, open_text, MESS_LENGTH);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    EVP_MD_CTX_destroy(mdctx);

    // Add NULL byte
   

  } while (!checkHash(bits, md_value));

  std::ostringstream oss;

  // fill oss with text message in hexadecimal format
  for (unsigned int i = 0; i < MESS_LENGTH; i++)
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(open_text[i]);

  std::string message_const = oss.str();

  // allocate memory for message output value
  *message = (char *)malloc(sizeof(char) * 2 * (MESS_LENGTH + 1));
  OPENSSL_strlcpy(*message, message_const.c_str(), sizeof(char) * message_const.size()+1);

  // empty ostringstream buffer
  oss.str("");

  // fill oss with hash message in hexadecimal format
  for (unsigned int i = 0; i < md_len; i++)
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);

  std::string hash_const = oss.str();
  // allocate memory for hash output value
  *hash = (char *)malloc(sizeof(char) * 2 * (EVP_MAX_MD_SIZE + 1));
  OPENSSL_strlcpy(*hash, hash_const.c_str(), sizeof(char) * hash_const.size()+1);

  EVP_cleanup();

    std::cout << *message << std::endl;
    std::cout << *hash  << std::endl;
    // std::cout << strlen(*message) <<std::endl;
    // std::cout << strlen(*hash) <<std::endl;
    // std::cout << hash_const.size() << std::endl;
    // std::cout << message_const.size() << std::endl;

    // if(checkStrings(*message, message_const.c_str())) std::cout << "Messages are the same" <<std::endl;
    // if(checkStrings(*hash, hash_const.c_str())) std::cout << "Hashes are the same" <<std::endl;


  return 1;
}

int findHashEx(int bits, char **message, char **hash, const char *hashFunction)
{
  /* TODO or use dummy implementation */
  return 1;
}

#ifndef __PROGTEST__

int checkBits(int bits, char *hexString)
{
    //std::cout<<"checkHash got hash: "<<hexString<<std::endl;
    int bigSteps = bits/4;
    for(int i = 0; i< bigSteps; i++){ //kontrola celych bajtu hexStringu 
        if(hexString[i] != '0') 
            return 0;
    }

    //tady je potreba prekonvertovat 8bit char do "4bit" hexadecima
    char testedChar = hexString[bigSteps];
    if(hexString[bigSteps] >= '0' && hexString[bigSteps] <= '9')
        testedChar -= '0';
    else if(hexString[bigSteps] >= 'a' && hexString[bigSteps] <= 'f')
        testedChar -= 'a'-10;
    else if(hexString[bigSteps] >= 'A' && hexString[bigSteps] <= 'F') //tohle by snad ale nemelo byt potreba, hexadecimalni zapis mame v tomhle reseni jen lowercase
        testedChar -= 'A'-10;
    int smallSteps = bits -bigSteps*4;
    for(int i = 0; i<smallSteps; i++){
        //int bitmask = pow(2,3-i); // kontrola casti bajtu pomoci bitove masky
        int bitmask = 1 << (3-i); // kontrola pomoci bitove masky... rychlejsi nez pow ig
        if((bitmask & testedChar) != 0){
            //std::cout<<"bitmask true on bit "<< i<< " of char "<<testedChar<<std::endl;
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    char *message, *hash;

    assert(findHash(0, &message, &hash) == 1);
    assert(message && hash && checkBits(0, hash));
    free(message);
    free(hash);
    assert(findHash(1, &message, &hash) == 1);
    assert(message && hash && checkBits(1, hash));
    free(message);
    free(hash);
    assert(findHash(2, &message, &hash) == 1);
    assert(message && hash && checkBits(2, hash));
    free(message);
    free(hash);
    assert(findHash(3, &message, &hash) == 1);
    assert(message && hash && checkBits(3, hash));
    free(message);
    free(hash);
    assert(findHash(-1, &message, &hash) == 0);
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */


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

#include <openssl/evp.h>
#include <openssl/rand.h>

#endif /* __PROGTEST__ */
#define MESS_LENGTH 20

bool checkBytes(unsigned char* message);

std::string string_to_hex(const std::string& input)
{
  static const char hex_digits[] = "0123456789ABCDEF";

  std::string output;
  output.reserve(input.length() * 2);
  for (unsigned char c : input)
    {
    output.push_back(hex_digits[c >> 4]);
    output.push_back(hex_digits[c & 15]);
  }
  return output; // je to string, automaticky prida /0 na konec
}

int findHash (int bits, char ** message, char ** hash) {
  using namespace std;
  OpenSSL_add_all_digests();
  unsigned int length; //vysledna delka hashe
  unsigned char* internalHash = (unsigned char*)malloc( sizeof(char) * ( EVP_MAX_MD_SIZE) );
  //char* internalHashHex = (char*)malloc( sizeof(char) * ( EVP_MAX_MD_SIZE) );
  //char* hexOutput = ( char*)malloc( sizeof(char) * ( MESS_LENGTH+1) );
  char* internalHashHex;
  char* hexOutput;
  //unsigned char internalHash[EVP_MAX_MD_SIZE];
  //unsigned char* internalHash = new unsigned char[EVP_MAX_MD_SIZE];
  const EVP_MD* type = EVP_get_digestbyname("sha512");
  /* TODO: Your code here */
  if(bits < 0 || bits > 512){
    return 0;
  }
  unsigned char text [MESS_LENGTH + 1];

  if(!RAND_bytes(text, MESS_LENGTH)){
    std::cout<<"RAND_bytes failed"<<std::endl;
  }
  if(!checkBytes(text)){
    //continue and repeat cycle  -  try to generate new ones
  }
    else{
    text[MESS_LENGTH] = 0;
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_new(); // create context for hashing
  if (ctx == NULL){
    //continue;
    std::cout<<"context is null"<<std::endl;
    return 2;
  }
  if (!EVP_DigestInit_ex(ctx, type, NULL)){ // context setup for our hash type
    std::cout<<"error 3"<<std::endl;
    return 3;
  }

  if (!EVP_DigestUpdate(ctx, text, MESS_LENGTH)){ // feed the message in
    std::cout<<"error 4"<<std::endl;
    return 4;
  }

  if (!EVP_DigestFinal_ex(ctx, internalHash, &length)){ // get the hash
    std::cout<<"error 5"<<std::endl;
    return 5;
  }
  EVP_MD_CTX_free(ctx); // destroy the context



  for (const unsigned char* p = text; *p; ++p)
    {
    printf("%x", *p);
  }
  printf("\n");
  for(int i=0; i<MESS_LENGTH; ++i)
    std::cout<<std::hex<<(int)text[i];
  std::cout<<std::endl;
  string hex((const char*)&(text[0]), MESS_LENGTH+1);
  std::cout<<string_to_hex(hex)<<std::endl;

  hexOutput = strdup(string_to_hex(hex).c_str());


  printf("Hash textu \"%s\" je: ", text);
  for (unsigned int i = 0; i < length; i++)
    printf("%02x", internalHash[i]);
  printf("\n");

  std::cout<<"hexa message"<<hexOutput<<std::endl;

  string hexHash((const char*)internalHash, length);

  internalHashHex = strdup(string_to_hex(hexHash).c_str());

  *hash = internalHashHex; // TOHLE FUNGUJE
  *message = hexOutput;
  /**hash = (char*) internalHashHex; // TOHLE FUNGUJE
    *message = hexOutput;*/

  std::cout<<"HASH:"<<*hash<<std::endl; //potrebuju prekonvertovat do hexadecimalniho formatu
  std::cout<<"MESSAGE:"<<*message<<std::endl;

  /*for(int i=0; i<EVP_MAX_MD_SIZE; i++){
        free(&internalHash[i]);
    }*/
  /*free(internalHash);
    free(hexOutput);
    free(internalHashHex);*/
  free(internalHash);
  return 1;


  //https://www.nayuki.io/res/lowest-sha512-value-by-brute-force/lowest-sha512.c
  //https://www.nayuki.io/page/lowest-sha512-value-by-brute-force
  //vymysleni zpravy
  //rand bytes
  //zkontrolovat, zda neni nekde nulovy bajt, pouze na konci, tam musi byt
  //konverze do hexidecimalni podoby -  neni nutny jen  abcd1234, hexadecilamni podoba vezme cokoliv 0-255 - tzn jakykoliv byte
  //pak bud muzeme pricitat jednicky - zase pozor na nulove byty, nebo pouzit rand bytes znova
  //vygenerovani hashe
  //zkontrolovani hashe
  //znova na zacatek
  }

  int findHashEx (int bits, char ** message, char ** hash, const char * hashFunction) {
    /* TODO or use dummy implementation */
    return 1;
  }

#ifndef __PROGTEST__

  int checkHash(int bits, char * hexString) {
    // DIY
    std::cout<<"checkHash got hash: "<<hexString<<std::endl;
    std::cout<<"BITS: "<<bits<<std::endl;
    int bigSteps = bits/8;
    std::cout<<"big steps "<< bigSteps<<std::endl;
    for(int i = 0; i< bigSteps; i++){
      if(hexString[i] != 0)
        return 0;
    }
    int smallSteps = bits %8;
    std::cout<<"small steps "<< smallSteps<<std::endl;
    char controlledByte = hexString[bigSteps];
    //bitove posunout o x a zkontrolovat zda == 0
    //smallSteps = 3 -> posun o 5
    std::cout<<"controlled char begore: "<<" dec:"<<std::dec<<(short)controlledByte<<std::endl;
    controlledByte = controlledByte >> (8-smallSteps);
    std::cout<<"controlled char after:"<<std::dec<<(char)controlledByte<<std::endl;
    if(controlledByte != 0)
      return 0;
    return 1;


  }

  bool checkBytes(unsigned char* message){
    for(int i = 0; i< MESS_LENGTH; i++){
      if(message[i] == 0)
        return false;
    }
    return true;
  }

  int main (void) {
    char * message, * hash;
    assert(findHash(0, &message, &hash) == 1);
    //assert(message && hash && checkHash(0, hash));

    std::cout<<"GOT HASH";
    for(int i = 0; i< strlen(hash); i++){
      std::cout<<hash[i];
    }
    std::cout<<std::endl;
    std::cout<<"GOT MESSAGE";
    for(int i = 0; i< strlen(message); i++){
      std::cout<<message[i];
    }
    std::cout<<std::endl;
    free(message);
    free(hash);
    /*assert(findHash(1, &message, &hash) == 1);
    std::cout<<"GOT HASH"<<*hash<<std::endl;
    assert(message && hash && checkHash(1, hash));

    free(message);
    free(hash);
    /*assert(findHash(2, &message, &hash) == 1);
    assert(message && hash && checkHash(2, hash));
    free(message);
    free(hash);
    assert(findHash(3, &message, &hash) == 1);
    assert(message && hash && checkHash(3, hash));
    free(message);
    free(hash);
    assert(findHash(-1, &message, &hash) == 0);*/
    return EXIT_SUCCESS;
  }
#endif /* __PROGTEST__ */

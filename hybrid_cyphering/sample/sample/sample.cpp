#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

#define BUFF_LEN 1024

bool writeToFile(const void *data, const size_t data_length, FILE *out_file)
{

    // length of ciphered key
    if (fwrite(data, 1, data_length, out_file) != data_length)
    {
        std::cerr << "Error: Could not write encrypted data to output file" << std::endl;
        return false;
    }
    return true;
}

void printKeys(const std::unique_ptr<uint8_t[]> &encrypted_symmetric_key, const int rsa_size, const std::unique_ptr<uint8_t[]> &symmetric_key, const size_t symmetric_key_length)
{

    std::cout << "Symmetric key:" << std::endl;
    for (int i = 0; i < (int)symmetric_key_length; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(symmetric_key[i]);
    }
    std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "RSA-encrypted symmetric key:" << std::endl;
    for (int i = 0; i < (int)rsa_size; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(encrypted_symmetric_key[i]);
    }
    std::cout << std::dec << std::setw(0) << std::endl;
    std::cout << std::endl;

    std::cout << "Size of symmetric:" << symmetric_key_length << std::endl;
    std::cout << "Size RSA:" << rsa_size << std::endl;
    std::cout << std::endl;
}

// Destruktor funkce
//=================================================

void ctx_destructor(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

void rsa_destructor(RSA *rsa)
{
    RSA_free(rsa);
}
void file_closer(FILE *file)
{
    if (file)
    {
        fclose(file);
    }
}

class File
{
public:
    File(FILE* _file, std::string _path){
        file = _file;
        path = _path;
    }

    ~File(){
        fclose(file);
        std::remove(path.c_str());
    }

    FILE *file;
    std::string path;
};

/**
 * Loads up public key from a file
 */
unique_ptr<RSA, decltype(&rsa_destructor)> loadPublicKey(const std::string &public_key_file)
{
    FILE *file = fopen(public_key_file.c_str(), "r");
    if (file == nullptr)
    {
        std::cerr << "Error opening public key file: " << public_key_file << std::endl;
        return std::unique_ptr<RSA, decltype(&rsa_destructor)>(nullptr, rsa_destructor);
    }

    RSA *rsa = PEM_read_RSA_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (rsa == nullptr)
    {
        std::cerr << "Error loading public key" << std::endl;
    }

    return std::unique_ptr<RSA, decltype(&rsa_destructor)>(rsa, rsa_destructor);
}
/**
 * Loads up private key from a file
 */
unique_ptr<RSA, decltype(&rsa_destructor)> loadPrivateKey(const std::string &private_key_file)
{
    FILE *file = fopen(private_key_file.c_str(), "r");
    if (!file)
    {
        return std::unique_ptr<RSA, decltype(&rsa_destructor)>(nullptr, rsa_destructor);
    }

    RSA *rsa = PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return std::unique_ptr<RSA, decltype(&rsa_destructor)>(rsa, rsa_destructor);
}

/**
 * Encrypts provided symmetric key
 */
std::unique_ptr<uint8_t[]> encryptSymmetricKey(const unique_ptr<RSA, decltype(&rsa_destructor)> &rsa, const int rsa_size, const std::unique_ptr<uint8_t[]> &symmetric_key, const size_t symmetric_key_length)
{
    // std::vector<unsigned char> encrypted_key(rsa_size);
    std::unique_ptr<uint8_t[]> encrypted_key = std::make_unique<uint8_t[]>(rsa_size);

    int result = RSA_public_encrypt(symmetric_key_length, symmetric_key.get(), encrypted_key.get(), rsa.get(), RSA_PKCS1_PADDING);

    if (result == -1)
    {
        std::cerr << "Error encrypting symmetric key" << std::endl;
        encrypted_key = nullptr;
    }

    return encrypted_key;
}

/**
*   Funkce vygeneruje symetrický (sdílený) klíč a inicializační vektor (dále IV), který bude vstupem do symetrické šifry symmetricCipher.
    Touto šifrou, klíčem a IV zašifrujete data v inFile.
    Klíč k symetrické šifře zašifrujete asymetrickou šifrou (RSA) pomocí veřejného klíče uloženého v publicKeyFile.


    - EVP_PKEY_encrypt / decrypt -> slouží k šifrování  krtkých zpráv (např klíče)

    -načtení klíče
        EVP_PKEY * pubkey;
        fp = fopen(....);
        pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL); //No password protection of the key itself
        EVP_PKEY_free(pubkey);

    - smazání souboru
        std::remove (filename)



*/
bool seal(const char *inFile, const char *outFile, const char *publicKeyFile, const char *symmetricCipher)
{
    // error handling
    if (!inFile || !outFile || !publicKeyFile || !symmetricCipher)
        return false;

    OpenSSL_add_all_ciphers();

    // INITIALIZE CIPHER OBJECT
    // we do not need to free this cipher object because it is managed internally by OpenSSL
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(symmetricCipher);
    if (cipher == NULL)
    {
        std::cerr << "Cipher name was not given or doesn't exist" << std::endl;
        return false;
    }

    const size_t symmetric_key_length = EVP_CIPHER_key_length(cipher);
    const size_t iv_length = EVP_CIPHER_iv_length(cipher);

    std::unique_ptr<uint8_t[]> symmetric_iv = std::make_unique<uint8_t[]>(iv_length);
    std::unique_ptr<uint8_t[]> symmetric_key = std::make_unique<uint8_t[]>(symmetric_key_length);

    //==================================================================================
    // INITIALIZING IV AND KEY TO SYMMETRIC CIPHER
    //==================================================================================

    // CREATING KEY TO SYMMETRIC CIPHER
    if (RAND_bytes(symmetric_key.get(), symmetric_key_length) != 1)
    {
        std::cerr << "Function failed to initialize key for a given cipher" << std::endl;
        return false;
    }

    // CREATING IV TO SYMMETRIC CIPHER
    //  provided cipher needs IV vector so I need to check if provided IV is the right size
    if (iv_length > 0)
    {
        if (RAND_bytes(symmetric_iv.get(), iv_length) != 1)
        {
            std::cerr << "Function failed to initialize key for a given cipher" << std::endl;
            return false;
        }
    }
    //==================================================================================
    //  CIPHERING THE KEY USING RSA
    //==================================================================================
    // RSA* rsa = loadPublicKey(publicKeyFile);
    unique_ptr<RSA, decltype(&rsa_destructor)> rsa = loadPublicKey(publicKeyFile);
    if (!rsa)
        return false;

    const size_t rsa_size = RSA_size(rsa.get());
    std::unique_ptr<uint8_t[]> encrypted_symmetric_key = encryptSymmetricKey(rsa, rsa_size, symmetric_key, symmetric_key_length);

    if (!encrypted_symmetric_key)
    {
        std::cout << "Encrypted symmetric key is null";
        return false;
    }

    // DEBUG
    printKeys(encrypted_symmetric_key, rsa_size, symmetric_key, symmetric_key_length);

    //==================================================================================
    // ADDING METADATA TO OUR OUTPUT DATA FILE
    // Structure:
    //  4 B - NID (id of used symmetric cipher)
    //  4 B - length of ciphered key
    //  ? B - RSA-ciphered key
    //  ? B - IV length
    //==================================================================================

    const size_t nid_reserved_bytes = 4;
    const size_t rsa_encrypted_key_reserved_bytes = 4;

    // open output file
    // FILE *out_file = fopen(outFile, "wb");
    std::unique_ptr<FILE, decltype(&file_closer)> out_file(fopen(outFile, "wb"), &file_closer);
    if (out_file == NULL)
    {
        std::cerr << "Could not open the output file: " << outFile << std::endl;
        return false;
    }
    // WRITING METADATA TO FILE

    // id of used symmetric cipher
    int nid = EVP_CIPHER_nid(cipher);
    if (!writeToFile(&nid, nid_reserved_bytes, out_file.get()))
        return false;

    // length of ciphered key
    if (!writeToFile(&rsa_size, rsa_encrypted_key_reserved_bytes, out_file.get()))
        return false;

    // rsa encrypted key
    if (!writeToFile(encrypted_symmetric_key.get(), rsa_size, out_file.get()))
        return false;

    // IV (only if symmetric cipher we used also used IV)
    if (iv_length > 0)
    {
        if (!writeToFile(symmetric_iv.get(), iv_length, out_file.get()))
            return false;
    }

    // DEBUG
    std::cout << "IV: ";
    for (int i = 0; i < (int)iv_length; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(symmetric_iv[i]);
    }
    std::cout << std::endl;

    //==================================================================================
    // WRITING ENCRYPTED INPUT DATA INTO OUTPUT FILE
    //==================================================================================

    std::unique_ptr<FILE, decltype(&file_closer)> in_file(fopen(inFile, "rb"), &file_closer);
    if (in_file == NULL)
    {
        std::cerr << "Could not open the output file: " << inFile << std::endl;
        return false;
    }

    std::unique_ptr<uint8_t[]> in_buffer = std::make_unique<uint8_t[]>(BUFF_LEN);
    std::unique_ptr<uint8_t[]> out_buffer = std::make_unique<uint8_t[]>(BUFF_LEN);

    int in_buff_len;
    int out_buff_len;

    unique_ptr<EVP_CIPHER_CTX, decltype(&ctx_destructor)> ctx = unique_ptr<EVP_CIPHER_CTX, decltype(&ctx_destructor)>(EVP_CIPHER_CTX_new(), &ctx_destructor);

    if (EVP_EncryptInit_ex(ctx.get(), cipher, NULL, symmetric_key.get(), (symmetric_key_length > 0) ? symmetric_iv.get() : NULL) != 1)
    {
        std::cerr << "Cipher Initialization failed" << std::endl;
        return false;
    }

    while ((in_buff_len = fread(in_buffer.get(), 1, BUFF_LEN, in_file.get())) > 0)
    {
        if (EVP_CipherUpdate(ctx.get(), out_buffer.get(), &out_buff_len, in_buffer.get(), in_buff_len) != 1)
        {
            std::cerr << "Failed to update encryption" << std::endl;
            return false;
        }

        if (fwrite(out_buffer.get(), 1, out_buff_len, out_file.get()) != (size_t)out_buff_len)
        {
            std::cerr << "Error: Could not write encrypted data to output file" << std::endl;
            return false;
        }
    }

    if (ferror(in_file.get()) || !feof(in_file.get()) || in_buff_len < 0)
    {
        std::cerr << "Error in input file" << std::endl;

        return false;
    }

    if (EVP_CipherFinal_ex(ctx.get(), out_buffer.get(), &out_buff_len) != 1)
    {
        std::cerr << "Failed final encryption" << std::endl;
        return false;
    }

    if (fwrite(out_buffer.get(), 1, out_buff_len, out_file.get()) != (size_t)out_buff_len)
    {
        std::cerr << "Error: Could not write encrypted data to output file" << std::endl;
        return false;
    };

    std::cout << "-----------------------" << std::endl;
    return true;
}
/**
 * Open a file encrypted by the seal() function and extracts metadata and using private key will decrypt the original message
 * using hibrid ciphering
 */
bool open(const char *inFile, const char *outFile, const char *privateKeyFile)
{
    // error handling
    if (!inFile || !outFile || !privateKeyFile)
        return false;

    OpenSSL_add_all_ciphers();

    // Open input file
    std::unique_ptr<FILE, decltype(&file_closer)> in_file(fopen(inFile, "rb"), &file_closer);
    if (in_file == NULL)
    {
        std::cerr << "Could not open the output file: " << inFile << std::endl;
        return false;
    }

    //==================================================================================
    // READING METADATA FROM OUR INPUT FILE
    // Structure:
    //  4 B - NID (id of used symmetric cipher)
    //  4 B - length of ciphered key
    //  ? B - RSA-ciphered key
    //  ? B - IV
    //==================================================================================
    const int nid_byte_size = 4;
    const int ciphered_key_byte_size = 4;

    int nid;
    int ciphered_key_length;

    // reading NID of the cipher and how much bytes were preserved for RSA-ciphered key
    if (fread(&nid, 1, nid_byte_size, in_file.get()) != nid_byte_size)
        return false;
    if (fread(&ciphered_key_length, 1, ciphered_key_byte_size, in_file.get()) != ciphered_key_byte_size)
        return false;

    std::cout << std::dec << std::setw(0) << std::endl;
    std::cout << "NID: " << nid << endl;
    std::cout << "ciphered_key_length:" << ciphered_key_length << endl;
    std::cout << std::endl;

    // getting cipher by its NID
    const EVP_CIPHER *cipher = EVP_get_cipherbynid(nid);
    if (cipher == NULL)
    {
        std::cerr << "Cipher NID was not given or doesn't exist" << std::endl;
        return false;
    }

    // getting sizes of key and IV
    const size_t symmetric_key_length = EVP_CIPHER_key_length(cipher);
    const size_t iv_length = EVP_CIPHER_iv_length(cipher);

    // reading encrypted symmetric key
    std::unique_ptr<uint8_t[]> encrypted_symmetric_key = std::make_unique<uint8_t[]>(ciphered_key_length);
    if (fread(encrypted_symmetric_key.get(), 1, ciphered_key_length, in_file.get()) != (size_t)ciphered_key_length)
        return false;

    // reading IV (only if necessary)
    std::unique_ptr<uint8_t[]> iv = std::make_unique<uint8_t[]>(iv_length);
    if (iv_length > 0)
    {
        if (fread(iv.get(), 1, iv_length, in_file.get()) != iv_length)
            return false;
    }

    std::cout << "RSA-encrypted symmetric key:" << std::endl;
    for (int i = 0; i < (int)ciphered_key_length; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(encrypted_symmetric_key[i]);
    }

    std::cout << std::endl;

    std::cout << "IV: ";
    for (int i = 0; i < (int)iv_length; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(iv[i]);
    }
    std::cout << std::endl;

    //==================================================================================
    // DECRYPT THE KEY WITH RSA PRIVATE KEY
    //==================================================================================
    unique_ptr<RSA, decltype(&rsa_destructor)> rsa = loadPrivateKey(privateKeyFile);

    if (!rsa)
    {
        std::cerr << "Error loading private key: " << privateKeyFile << std::endl;
        return false;
    }

    std::unique_ptr<uint8_t[]> symmetric_key = std::make_unique<uint8_t[]>(symmetric_key_length);

    int decryptedMessageLength = RSA_private_decrypt(
        ciphered_key_length,
        encrypted_symmetric_key.get(),
        symmetric_key.get(),
        rsa.get(),
        RSA_PKCS1_PADDING);

    if (decryptedMessageLength == -1)
    {
        std::cerr << "Error decrypting message: " << std::endl;
        return 1;
    }

    //==================================================================================
    // DECRYPT THE DATA WITH NOW ENCRYPTED KEY
    //==================================================================================

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(BUFF_LEN);
    std::unique_ptr<uint8_t[]> ciphertext = std::make_unique<uint8_t[]>(BUFF_LEN);

    int buffer_len;
    int ciphertext_len;

    // open output file
    //  Open input file
    std::unique_ptr<FILE, decltype(&file_closer)> out_file(fopen(outFile, "wb"), &file_closer);
    if (in_file == NULL)
    {
        std::cerr << "Could not open the output file: " << inFile << std::endl;
        return false;
    }

    unique_ptr<EVP_CIPHER_CTX, decltype(&ctx_destructor)> ctx = unique_ptr<EVP_CIPHER_CTX, decltype(&ctx_destructor)>(EVP_CIPHER_CTX_new(), &ctx_destructor);

    if (EVP_DecryptInit_ex(ctx.get(), cipher, NULL, symmetric_key.get(), (iv_length > 0) ? iv.get() : NULL) != 1)
    {
        std::cerr << "Failed to initialize encryption" << std::endl;
        return false;
    }

    while ((buffer_len = fread(buffer.get(), 1, BUFF_LEN, in_file.get())) > 0)
    {
        if (EVP_CipherUpdate(ctx.get(), ciphertext.get(), &ciphertext_len, buffer.get(), buffer_len) != 1)
        {
            std::cerr << "Failed to update encryption" << std::endl;
            return false;
        }

        if (fwrite(ciphertext.get(), 1, ciphertext_len, out_file.get()) != (size_t)ciphertext_len)
        {
            std::cerr << "Error: Could not write encrypted data to output file" << std::endl;
            return false;
        }
    }

    if (ferror(in_file.get()) || !feof(in_file.get()) || buffer_len < 0)
    {
        std::cerr << "Error in input file" << std::endl;
        return false;
    }

    if (EVP_CipherFinal_ex(ctx.get(), ciphertext.get(), &ciphertext_len) != 1)
    {
        std::cerr << "Failed final encryption" << std::endl;
        return false;
    }

    if (fwrite(ciphertext.get(), 1, ciphertext_len, out_file.get()) != (size_t)ciphertext_len)
    {
        std::cerr << "Error: Could not write encrypted data to output file" << std::endl;
        return false;
    };
    std::cout << "Cipher finished successfully!" << std::endl;
    std::cout << "---------------------------------" << std::endl;

    return true;
}

#ifndef __PROGTEST__

int main(void)
{
    // assert(seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));
    // assert(open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem"));

    // assert(open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem"));

    seal("OT.txt", "sealed.bin", "PublicKey.pem", "aes-128-cbc");
    open("sealed.bin", "test.txt", "PrivateKey.pem");
    return 0;
}

#endif /* __PROGTEST__ */

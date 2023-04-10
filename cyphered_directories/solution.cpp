#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * @brief Block cipher configuration
 * 
 */
struct crypto_config
{
	const char *m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif /* _PROGTEST_ */

bool blockCipherGeneric(const std::string &in_filename, const std::string &out_filename, crypto_config &config, bool isEncrypt);

/**
 * @brief Header size of a TGA Image file (only the main header) 
 * 
 */
#define HEADER_SIZE 18

//===============================================================================================
// HELPING FUNCTIONS DECLARATIONS
//===============================================================================================
void cipherExitFree(FILE *in_file, FILE *out_file, EVP_CIPHER_CTX *ctx);
void print_key(bool wasChanged, crypto_config &config);
void print_iv(int type, crypto_config &config);


/**
 * @brief Encrypts provided TGA file into output TGA file
 * 
 * @param in_filename  	- input TGA
 * @param out_filename 	- output TGA
 * @param config 		- cipher configuration
 * @return true 		- encryption was succesful
 * @return false 		- encryption failed
 */
bool encrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config)
{
	return blockCipherGeneric(in_filename, out_filename, config, true);
}

/**
 * @brief Decrypts provided TGA file into output TGA file
 * 
 * @param in_filename 	- input TGA
 * @param out_filename 	- output TGA
 * @param config 		- cipher configuration
 * @return true 		- decryption was succesful
 * @return false 		- decryption failed
 */
bool decrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config)
{
	return blockCipherGeneric(in_filename, out_filename, config, false);
}

/**
 * @brief This function is able to encrypt or decrypt TGA file with ANY block cipher based on provided input, it behaves a little different for each encryption 
 * and decryption.
 * 
 * For encryption if wrong IV/key is provided (based on provided block cipher), new IV/key will be generated.
 * For decryption if wrong IV/key is provided function will fail.
 * 
 * 
 * @param in_filename 
 * @param out_filename 
 * @param config 
 * @param isEncrypt 
 * @return true 
 * @return false 
 */
bool blockCipherGeneric(const std::string &in_filename, const std::string &out_filename, crypto_config &config, bool isEncrypt)
{
	OpenSSL_add_all_ciphers();
	// INITIALIZE CIPHER OBJECT
	const EVP_CIPHER *cipher = EVP_get_cipherbyname(config.m_crypto_function);
	if (cipher == NULL)
	{
		std::cerr << "Cipher name was not given or doesn't exist" << std::endl;
		return false;
	}

	const size_t cipher_key_length = EVP_CIPHER_key_length(cipher);
	//===============================================================================================
	// KEY CHECK
	//===============================================================================================
	// checking if key size is appropriate for given cipher and if not generate appropriate one
	if (config.m_key_len != cipher_key_length || !config.m_key)
	{
		// if we are decrypting and cipher key doesnt match - we exit
		if (!isEncrypt)
			return false;

		// generate new key
		std::unique_ptr<uint8_t[]> new_key_ptr = std::make_unique<uint8_t[]>(cipher_key_length);

		if (RAND_bytes(new_key_ptr.get(), cipher_key_length) != 1)
		{
			std::cerr << "Function failed to initialize key for a given cipher" << std::endl;
			return false;
		}

		// move that newly allocated appropriate key to the config
		config.m_key = std::move(new_key_ptr);
		config.m_key_len = cipher_key_length;

		// DEBUG
		print_key(true, config);
	}
	//DEBUG
	else
		print_key(false, config);

	//===============================================================================================
	// IV VECTOR CHECK
	//===============================================================================================

	const size_t cipher_iv_length = EVP_CIPHER_iv_length(cipher);

	// provided cipher needs IV vector so I need to check if provided IV is the right size
	if (cipher_iv_length > 0)
	{
		// it is not so I need to generate appropriate one
		if (config.m_IV_len != cipher_iv_length || !config.m_IV)
		{
			// if we are decrypting and cipher IV doesnt match - we exit
			if (!isEncrypt)
				return false;

			std::unique_ptr<uint8_t[]> new_iv = std::make_unique<uint8_t[]>(cipher_iv_length);

			if (RAND_bytes(new_iv.get(), cipher_iv_length) != 1)
			{
				std::cerr << "Function failed to initialize key for a given cipher" << std::endl;
				return false;
			}

			// move that newly allocated appropriate key to the config
			config.m_IV = std::move(new_iv);
			config.m_IV_len = cipher_iv_length;

			// DEBUG
			print_iv(0, config);
		}
		// else
		print_iv(1, config);
	}
	// provided cipher doesnt need IV vector
	else
	{
		print_iv(2, config);
	}
	std::cout << "---------------------------------" << std::endl;

	//===============================================================================================
	// GENERATING ENCRYPTION INTO OUTPUT FILE BY BLOCK SIZE
	//===============================================================================================

	const int block_size = EVP_CIPHER_block_size(cipher);

	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(block_size);
	std::unique_ptr<uint8_t[]> ciphertext = std::make_unique<uint8_t[]>(block_size);

	int buffer_len;
	int ciphertext_len;

	FILE *in_file = fopen(in_filename.c_str(), "rb");

	if (in_file == NULL)
	{
		std::cerr << "Could not open the input file: " << in_filename << std::endl;
		return false;
	}

	FILE *out_file = fopen(out_filename.c_str(), "wb");

	if (out_file == NULL)
	{
		std::cerr << "Could not open the output file: " << out_filename << std::endl;
		fclose(in_file);
		return false;
	}

	// COPY HEADER FROM INPUT TO OUTPUT FILE
	unsigned char header_buffer[HEADER_SIZE];
	size_t header_bytes_read = fread(header_buffer, 1, HEADER_SIZE, in_file);

	if (header_bytes_read > 17)
	{
		fwrite(header_buffer, 1, header_bytes_read, out_file);
	}
	else
	{
		std::cerr << "Error while copying header." << std::endl;
		fclose(in_file);
		fclose(out_file);
		return false;
	}

	// Cipher context
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	// TODO: Have to check the 18 bytes if it is really a TGA HEADER

	// Initialize cipher ( there is is decided if it encryption or decryption will be applied)
	if (EVP_CipherInit_ex(ctx, cipher, NULL, config.m_key.get(), (cipher_iv_length > 0) ? config.m_IV.get() : NULL, isEncrypt) != 1)
	{
		std::cerr << "Failed to initialize encryption" << std::endl;
		cipherExitFree(in_file, out_file, ctx);
		return false;
	}

	while ((buffer_len = fread(buffer.get(), 1, block_size, in_file)) > 0)
	{
		if (EVP_CipherUpdate(ctx, ciphertext.get(), &ciphertext_len, buffer.get(), buffer_len) != 1)
		{
			std::cerr << "Failed to update encryption" << std::endl;
			cipherExitFree(in_file, out_file, ctx);
			return false;
		}

		if (fwrite(ciphertext.get(), 1, ciphertext_len, out_file) != (size_t) ciphertext_len)
		{
			std::cerr << "Error: Could not write encrypted data to output file" << std::endl;
			cipherExitFree(in_file, out_file, ctx);
			return false;
		}
	}

	if (ferror(in_file))
	{
		std::cerr << "Failed in input file" << std::endl;
		cipherExitFree(in_file, out_file, ctx);

		return false;
	}
	else if (!feof(in_file))
	{
		std::cerr << "Error: Unexpected end of file while reading input file " << in_filename << std::endl;
		return false;
	}
	if (buffer_len < 0)
	{
		std::cerr << "Error: Failed to read input file " << in_filename << std::endl;
		return false;
	}

	if (EVP_CipherFinal_ex(ctx, ciphertext.get(), &ciphertext_len) != 1)
	{
		std::cerr << "Failed final encryption" << std::endl;
		cipherExitFree(in_file, out_file, ctx);
		return false;
	}

	if (fwrite(ciphertext.get(), 1, ciphertext_len, out_file) != (size_t) ciphertext_len)
	{
		std::cerr << "Error: Could not write encrypted data to output file" << std::endl;
		cipherExitFree(in_file, out_file, ctx);
		return false;
	};

	cipherExitFree(in_file, out_file, ctx);

	std::cout << "Cipher finished successfully!" <<std::endl;
	std::cout << "---------------------------------" << std::endl;

	return true;
}

//===============================================================================================
// HELPING FUNCTIONS
//===============================================================================================

/**
 * @brief Frees memory of a file iterators and context of a cipher
 * 
 * @param in_file  	- file
 * @param out_file 	- file
 * @param ctx 		- cipher context
 */
void cipherExitFree(FILE *in_file, FILE *out_file, EVP_CIPHER_CTX *ctx)
{

	fclose(in_file);
	fclose(out_file);
	EVP_CIPHER_CTX_free(ctx);
}

/**
 * @brief Compares two files by their binary content
 * 
 * @param name1 	- path to the first file 
 * @param name2  	- path to the second file
 * @return true  	- files are the same
 * @return false  	- files are different
 */
bool compare_files(const char *name1, const char *name2)
{
	std::ifstream f1(name1, std::ifstream::binary | std::ifstream::ate);
	std::ifstream f2(name2, std::ifstream::binary | std::ifstream::ate);

	if (f1.fail() || f2.fail())
	{
		return false; // file problem
	}

	if (f1.tellg() != f2.tellg())
	{
		return false; // size mismatch
	}

	// seek back to beginning and use std::equal to compare contents
	f1.seekg(0, std::ifstream::beg);
	f2.seekg(0, std::ifstream::beg);
	return std::equal(std::istreambuf_iterator<char>(f1.rdbuf()),
					  std::istreambuf_iterator<char>(),
					  std::istreambuf_iterator<char>(f2.rdbuf()));
}

//HELPING DEBUG FUNCTIONS

/**
 * @brief Will print key and information if generating new key was neccessary
 * 
 * @param wasChanged - generating new key was neccessary
 * @param config  - config of a cipher
 */
void print_key(bool wasChanged, crypto_config &config)
{
	if (wasChanged)
	{
		std::cout << "New key was generated!" << std::endl;
	}

	else
	{
		std::cout << "Key was okay!" << std::endl;
	}

	std::cout << "Contents of the key: " << std::endl;

	for (int i = 0; i < (int)config.m_key_len; i++)
	{
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(config.m_key[i]);
	}
	std::cout << std::endl;
}

/**
 * @brief Will print IV and information if generating new IV was neccessary
 * 
 * @param type - 	- 0 -> New IV vector needed to be generated 
 * 					- 1 -> Original IV was good
 * 					- 2 -> Provided cipher doesn't need IV 
 * @param config - config of a cipher
 */
void print_iv(int type, crypto_config &config)
{
	if (type == 0)
	{
		std::cout << "New IV vector was generated!" << std::endl;
	}

	else if (type == 1)
	{
		std::cout << "IV Vector was okay!" << std::endl;
	}

	else
	{
		std::cout << "Cipher does not need IV vector!" << std::endl;
		return;
	}

	std::cout << "Contents of the IV vector: " << std::endl;

	for (int i = 0; i < (int)config.m_IV_len; i++)
	{
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(config.m_IV[i]);
	}
	std::cout << std::endl;
}

#ifndef __PROGTEST__

int main(void)
{

	crypto_config config{nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	encrypt_data("original_image.TGA", "aes-ecb.tga", config);
	//decrypt_data("homer_AES_ECB1.TGA", "test.TGA", config);

	config.m_crypto_function = "AES-128-CBC";
	encrypt_data("original_image.tga", "aes-cbc.tga", config);

}

#endif /* _PROGTEST_ */

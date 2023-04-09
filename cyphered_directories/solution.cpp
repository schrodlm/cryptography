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

struct crypto_config
{
	const char *m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

// debug functions
// void print_key(bool wasChanged, crypto_config &config);
// void print_iv(int type, crypto_config &config);

#endif /* _PROGTEST_ */

bool genericCipher(const std::string &in_filename, const std::string &out_filename, crypto_config &config, bool isEncrypt);

#define HEADER_SIZE 18

//===============================================================================================
// HELPING FUNCTIONS DECLARATIONS
//===============================================================================================
void cipherExitFree(FILE *in_file, FILE *out_file, EVP_CIPHER_CTX *ctx);

bool encrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config)
{
	return genericCipher(in_filename, out_filename, config, true);
}

bool decrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config)
{
	return genericCipher(in_filename, out_filename, config, false);
}

bool genericCipher(const std::string &in_filename, const std::string &out_filename, crypto_config &config, bool isEncrypt)
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
		// print_key(true, config);
	}
	// DEBUG
	// else
	// 	print_key(false, config);

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
			// print_iv(0, config);
		}
		// else
		// 	print_iv(1, config);
	}
	// provided cipher doesnt need IV vector
	// else
	// {
	// 	print_iv(2, config);
	// }

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

	// Initialize cipher
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

	return true;
}
//===============================================================================================
// HELPING FUNCTIONS
//===============================================================================================
void cipherExitFree(FILE *in_file, FILE *out_file, EVP_CIPHER_CTX *ctx)
{

	fclose(in_file);
	fclose(out_file);
	EVP_CIPHER_CTX_free(ctx);
}

#ifndef __PROGTEST__

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

int main(void)
{
	// // CONFIG 1
	// //====================================

	// crypto_config config{nullptr, nullptr, nullptr, 0, 0};

	// // ECB mode
	// config.m_crypto_function = "AES-128-ECB";
	// config.m_key = std::make_unique<uint8_t[]>(16);
	// memset(config.m_key.get(), 0, 16);
	// config.m_key_len = 16;

	// encrypt_data("homer-simpson.TGA", "homer_AES_ECB1.TGA", config);
	// decrypt_data("homer_AES_ECB1.TGA", "test.TGA", config);

	// // CONFIG 2
	// //====================================

	// crypto_config config2{nullptr, nullptr, nullptr, 0, 0};

	// // ECB mode
	// config2.m_crypto_function = "AES-128-ECB";
	// config2.m_key = std::make_unique<uint8_t[]>(6);
	// memset(config2.m_key.get(), 0, 6);
	// config2.m_key_len = 6;

	// encrypt_data("homer-simpson.TGA", "homer_AES_ECB.TGA", config2);

	// // CONFIG 3
	// //====================================
	// crypto_config config3{nullptr, nullptr, nullptr, 0, 0};

	// config3.m_crypto_function = "AES-128-CBC";
	// config3.m_IV = std::make_unique<uint8_t[]>(17);
	// config3.m_IV_len = 17;
	// memset(config3.m_IV.get(), 0, 17);

	// encrypt_data("homer-simpson.TGA", "homer_AES_CBC.TGA", config3);

	//=====================================================================
	//=====================================================================
	//=====================================================================

	crypto_config config{nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	// assert(compare_files("out_file.TGA", "out_file.TGA"));

	assert(encrypt_data("homer-simpson.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "homer-simpson_enc_ecb.TGA"));

	assert(decrypt_data("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "homer-simpson.TGA"));

	assert(encrypt_data("UCM8.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "UCM8_enc_ecb.TGA"));

	assert(decrypt_data("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "UCM8.TGA"));

	assert(encrypt_data("image_1.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "ref_1_enc_ecb.TGA"));

	assert(encrypt_data("image_2.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "ref_2_enc_ecb.TGA"));

	assert(decrypt_data("image_3_enc_ecb.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "ref_3_dec_ecb.TGA"));

	assert(decrypt_data("image_4_enc_ecb.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "ref_4_dec_ecb.TGA"));

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert(encrypt_data("UCM8.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "UCM8_enc_cbc.TGA"));

	assert(decrypt_data("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "UCM8.TGA"));

	assert(encrypt_data("homer-simpson.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "homer-simpson_enc_cbc.TGA"));

	assert(decrypt_data("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "homer-simpson.TGA"));

	assert(encrypt_data("image_1.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "ref_5_enc_cbc.TGA"));

	assert(encrypt_data("image_2.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "ref_6_enc_cbc.TGA"));

	assert(decrypt_data("image_7_enc_cbc.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "ref_7_dec_cbc.TGA"));

	assert(decrypt_data("image_8_enc_cbc.TGA", "out_file.TGA", config) &&
		   compare_files("out_file.TGA", "ref_8_dec_cbc.TGA"));
	return 0;
}

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

#endif /* _PROGTEST_ */

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

using namespace std;

struct crypto_config
{
	const char *m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif /* _PROGTEST_ */

bool encrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config)
{
	// soubor si mám pry otevirat po částech
	/**
	 * Vstupní a výstupní soubory mohou být velké, větší než je velikost dostupné paměti.
	 * Obecně se proto při práci se soubory snažíme data zpracovávat průběžně.
	 * Není rozumné celý vstupní soubor načíst do paměti a pak jej v paměti zpracovávat.
	 * Poslední test kontroluje paměťové nároky Vašeho řešení. Selže, pokud se pokusíte udržovat v paměti najednou celé soubory nebo jejich velké části.
	 */

	// -> u toho plyne, že by nejspíš bylo nejlepší zpracovávat soubor přesně po blocích

	/*

		Před tímto bych měl asi ještě obejít tu hlavičku (prvních 18 bytu)

	 ===== Encryption process ====
		1. Generate random initialization vector (IV)
			- musím checkovat jestli ho šifra potřebuje, pokud ano, čeknout jestli je ten poskytnutý dost dlouhý
			  když ne tak vygenerovat novej
			- zjistit velikost IV -  EVP_CIPHER_iv_length(cipher)


		2. Initialize encryption key and context
		- zjistit veliksot klíče - EVP_CIPHER_key_length(cipher)


	*/

	const EVP_CIPHER *cipher = EVP_get_cipherbyname(config.m_crypto_function);
	if (cipher == NULL)
	{
		std::cerr << "Cipher name was not given or doesn't exist" << std::endl;
		return 0;
	}

	const size_t cipher_key_length = EVP_CIPHER_key_length(cipher);

	// checking if key size is appropriate for given cipher and if not generate appropriate one
	if (config.m_key_len != cipher_key_length)
	{
		// generate new key
		std::unique_ptr<uint8_t[]> new_key_ptr = std::make_unique<uint8_t[]>(cipher_key_length);

		if (RAND_bytes(new_key_ptr.get(), cipher_key_length) != 1)
		{
			std::cerr << "Function failed to initialize key for a given cipher" << std::endl;
		}

		// move that newly allocated appropriate key to the config
		config.m_key = std::move(new_key_ptr);
		config.m_key_len = cipher_key_length;

		std::cout << "New key was generated!" << std::endl;
		std::cout << "Contents of the key: " << std::endl;
		for (int i = 0; i < (int)cipher_key_length; i++)
		{
			std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(config.m_key[i]);
		}
	std::cout << std::endl;

		return 0;
	}

	std::cout << "Key was okay!" << std::endl;
	std::cout << "Contents of the key: " << std::endl;

	for (int i = 0; i < (int)cipher_key_length; i++)
	{
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(config.m_key[i]);
	}
	std::cout << std::endl;
	return 0;
}

bool decrypt_data(const std::string &in_filename, const std::string &out_filename, crypto_config &config)
{
	return true;
}

#ifndef __PROGTEST__

bool compare_files(const char *name1, const char *name2)
{
	return true;
}

int main(void)
{
	crypto_config config{nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	encrypt_data("fdfd", "fdfd", config);

	crypto_config config2{nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(6);
	memset(config.m_key.get(), 0, 6);
	config.m_key_len = 6;

	encrypt_data("fdfd", "fdfd", config);

	// assert(encrypt_data("homer-simpson.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "homer-simpson_enc_ecb.TGA"));

	// assert(decrypt_data("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "homer-simpson.TGA"));

	// assert(encrypt_data("UCM8.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "UCM8_enc_ecb.TGA"));

	// assert(decrypt_data("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "UCM8.TGA"));

	// assert(encrypt_data("image_1.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "ref_1_enc_ecb.TGA"));

	// assert(encrypt_data("image_2.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "ref_2_enc_ecb.TGA"));

	// assert(decrypt_data("image_3_enc_ecb.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "ref_3_dec_ecb.TGA"));

	// assert(decrypt_data("image_4_enc_ecb.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "ref_4_dec_ecb.TGA"));

	// // CBC mode
	// config.m_crypto_function = "AES-128-CBC";
	// config.m_IV = std::make_unique<uint8_t[]>(16);
	// config.m_IV_len = 16;
	// memset(config.m_IV.get(), 0, 16);

	// assert(encrypt_data("UCM8.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "UCM8_enc_cbc.TGA"));

	// assert(decrypt_data("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "UCM8.TGA"));

	// assert(encrypt_data("homer-simpson.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "homer-simpson_enc_cbc.TGA"));

	// assert(decrypt_data("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "homer-simpson.TGA"));

	// assert(encrypt_data("image_1.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "ref_5_enc_cbc.TGA"));

	// assert(encrypt_data("image_2.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "ref_6_enc_cbc.TGA"));

	// assert(decrypt_data("image_7_enc_cbc.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "ref_7_dec_cbc.TGA"));

	// assert(decrypt_data("image_8_enc_cbc.TGA", "out_file.TGA", config) &&
	// 	   compare_files("out_file.TGA", "ref_8_dec_cbc.TGA"));
	// return 0;
}

#endif /* _PROGTEST_ */

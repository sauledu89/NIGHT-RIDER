/**
 * @file CryptoHelper.cpp
 * @brief Implementación de utilidades criptográficas con OpenSSL.
 *
 * @details
 * Este archivo contiene las definiciones de las funciones declaradas en `CryptoHelper.h`,
 * centradas en criptografía híbrida:
 *
 * - Generación de claves RSA (2048 bits) con OpenSSL.
 * - Exportación/importación de claves en formato PEM.
 * - Generación de claves AES-256 aleatorias.
 * - Cifrado/descifrado de claves AES con RSA y padding OAEP.
 * - Cifrado/descifrado de mensajes con AES-256 en modo CBC (Cipher Block Chaining).
 *
 * @note Requiere la instalación y vinculación de OpenSSL (`libcrypto`, `libssl`).
 */

#include "CryptoHelper.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "openssl/evp.h"

 /**
  * @brief Constructor: inicializa punteros a claves RSA en nullptr y la clave AES a 0s.
  */
CryptoHelper::CryptoHelper() : rsaKeyPair(nullptr), peerPublicKey(nullptr) {
	std::memset(&aesKey, 0, sizeof(aesKey));
}

/**
 * @brief Destructor: libera memoria de claves RSA asignadas.
 */
CryptoHelper::~CryptoHelper() {
	if (rsaKeyPair) {
		RSA_free(rsaKeyPair);
	}
	if (peerPublicKey) {
		RSA_free(peerPublicKey);
	}
}

/**
 * @brief Genera un nuevo par de claves RSA (2048 bits).
 *
 * @note Internamente usa `RSA_generate_key_ex` con exponente `RSA_F4` (65537).
 */
void CryptoHelper::GenerateRSAKeys() {
	BIGNUM* bn = BN_new();
	BN_set_word(bn, RSA_F4);  // exponente público usual
	rsaKeyPair = RSA_new();
	RSA_generate_key_ex(rsaKeyPair, 2048, bn, nullptr);
	BN_free(bn);
}

/**
 * @brief Devuelve la clave pública RSA propia en formato PEM (como string).
 *
 * @return String PEM que puede ser enviado a otro peer.
 */
std::string CryptoHelper::GetPublicKeyString() const {
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(bio, rsaKeyPair);
	char* buffer = nullptr;
	size_t length = BIO_get_mem_data(bio, &buffer);
	std::string publicKey(buffer, length);
	BIO_free(bio);
	return publicKey;
}

/**
 * @brief Carga la clave pública del peer desde un string PEM.
 *
 * @param pemKey Clave pública codificada en formato PEM.
 * @throws std::runtime_error si el parseo del PEM falla.
 */
void CryptoHelper::LoadPeerPublicKey(const std::string& pemKey) {
	BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
	peerPublicKey = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (!peerPublicKey) {
		throw std::runtime_error("Failed to load peer public key: "
			+ std::string(ERR_error_string(ERR_get_error(), nullptr)));
	}
}

/**
 * @brief Genera una clave AES-256 (32 bytes) aleatoria.
 */
void CryptoHelper::GenerateAESKey() {
	RAND_bytes(aesKey, sizeof(aesKey));
}

/**
 * @brief Cifra la clave AES con la clave pública del peer (RSA-OAEP).
 *
 * @return Vector de bytes con la clave AES cifrada.
 * @throws std::runtime_error si la clave pública del peer no ha sido cargada.
 */
std::vector<unsigned char> CryptoHelper::EncryptAESKeyWithPeer() {
	if (!peerPublicKey) {
		throw std::runtime_error("Peer public key is not loaded.");
	}
	std::vector<unsigned char> encryptedKey(256);  // 2048 bits = 256 bytes
	int result = RSA_public_encrypt(sizeof(aesKey),
		aesKey,
		encryptedKey.data(),
		peerPublicKey,
		RSA_PKCS1_OAEP_PADDING);
	encryptedKey.resize(result);
	return encryptedKey;
}

/**
 * @brief Descifra una clave AES previamente cifrada con la RSA propia.
 *
 * @param encryptedKey Vector con la clave cifrada (256 bytes).
 * @note El resultado se guarda en `aesKey`.
 */
void CryptoHelper::DecryptAESKey(const std::vector<unsigned char>& encryptedKey) {
	RSA_private_decrypt(encryptedKey.size(),
		encryptedKey.data(),
		aesKey,
		rsaKeyPair,
		RSA_PKCS1_OAEP_PADDING);
}

/**
 * @brief Cifra un mensaje con AES-256 en modo CBC y genera un IV aleatorio.
 *
 * @param plaintext Texto plano a cifrar.
 * @param outIV Vector donde se almacenará el IV generado (16 bytes).
 * @return Vector de bytes con el mensaje cifrado.
 *
 * @note Usa EVP (alta abstracción de OpenSSL) para seguridad y flexibilidad.
 */
std::vector<unsigned char> CryptoHelper::AESEncrypt(const std::string& plaintext,
	std::vector<unsigned char>& outIV) {
	outIV.resize(AES_BLOCK_SIZE);
	RAND_bytes(outIV.data(), AES_BLOCK_SIZE);

	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	std::vector<unsigned char> out(plaintext.size() + AES_BLOCK_SIZE); // espacio para padding
	int outlen1 = 0, outlen2 = 0;

	EVP_EncryptInit_ex(ctx, cipher, nullptr, aesKey, outIV.data());
	EVP_EncryptUpdate(ctx,
		out.data(), &outlen1,
		reinterpret_cast<const unsigned char*>(plaintext.data()),
		static_cast<int>(plaintext.size()));
	EVP_EncryptFinal_ex(ctx, out.data() + outlen1, &outlen2);

	out.resize(outlen1 + outlen2);
	EVP_CIPHER_CTX_free(ctx);
	return out;
}

/**
 * @brief Descifra un mensaje previamente cifrado con AES-256-CBC.
 *
 * @param ciphertext Vector de bytes con el mensaje cifrado.
 * @param iv IV utilizado durante el cifrado (16 bytes).
 * @return Texto plano original. Devuelve cadena vacía si falla el descifrado.
 */
std::string CryptoHelper::AESDecrypt(const std::vector<unsigned char>& ciphertext,
	const std::vector<unsigned char>& iv) {
	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	std::vector<unsigned char> out(ciphertext.size());
	int outlen1 = 0, outlen2 = 0;

	EVP_DecryptInit_ex(ctx, cipher, nullptr, aesKey, iv.data());
	EVP_DecryptUpdate(ctx,
		out.data(), &outlen1,
		ciphertext.data(),
		static_cast<int>(ciphertext.size()));
	if (EVP_DecryptFinal_ex(ctx, out.data() + outlen1, &outlen2) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return {}; // Descifrado fallido: padding, clave o IV incorrectos
	}

	out.resize(outlen1 + outlen2);
	EVP_CIPHER_CTX_free(ctx);
	return std::string(reinterpret_cast<char*>(out.data()), out.size());
}

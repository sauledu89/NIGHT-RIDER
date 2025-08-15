/**
 * @file CryptoHelper.h
 * @brief Utilidades criptográficas basadas en OpenSSL: RSA y AES-256-CBC.
 *
 * @details
 * Esta clase proporciona soporte para cifrado seguro en aplicaciones cliente-servidor.
 * Incluye funciones para generar claves, exportar/importar en formato PEM, y cifrar/descifrar
 * tanto mensajes como claves de sesión.
 *
 * - 🔐 RSA: clave pública/privada de 2048 bits.
 * - 🔒 AES-256: cifrado de datos con CBC y vector de inicialización (IV).
 *
 * @note Todas las operaciones están diseñadas para usarse con strings en UTF-8.
 * @warning Es crucial liberar memoria de claves RSA para evitar fugas.
 */

#pragma once
#include "Prerequisites.h"
#include "openssl/rsa.h"
#include "openssl/aes.h"

 /**
  * @class CryptoHelper
  * @brief Manejador criptográfico para RSA y AES-256-CBC con OpenSSL.
  *
  * Esta clase es ideal para estudiantes que desean comprender cómo implementar
  * cifrado híbrido en redes seguras. Divide claramente responsabilidades de RSA y AES.
  *
  * @par Funcionalidades clave:
  * - Generación y gestión de claves RSA.
  * - Exportación/importación en formato PEM.
  * - Cifrado de la clave AES usando RSA.
  * - Cifrado y descifrado de mensajes usando AES-256 en modo CBC.
  */
class CryptoHelper {
public:
    /// @brief Constructor por defecto. Inicializa punteros y clave AES.
    CryptoHelper();

    /// @brief Destructor: libera recursos asignados por OpenSSL (claves RSA).
    ~CryptoHelper();

    // ====================== RSA ======================

    /**
     * @brief Genera un nuevo par de claves RSA de 2048 bits.
     *
     * @post El par generado se almacena internamente en @ref rsaKeyPair.
     * @throws std::runtime_error si ocurre un fallo en la generación.
     *
     * @note Este paso es obligatorio antes de exportar o usar la clave privada.
     */
    void GenerateRSAKeys();

    /**
     * @brief Obtiene la clave pública RSA como string PEM.
     * @return Clave pública codificada en formato PEM.
     * @pre Se debe haber llamado a @ref GenerateRSAKeys().
     *
     * @note Este string puede enviarse al peer para intercambio de claves.
     */
    std::string GetPublicKeyString() const;

    /**
     * @brief Carga la clave pública del peer desde un string PEM.
     * @param pemKey Cadena en formato PEM con la clave pública del peer.
     *
     * @throws std::runtime_error si el string PEM no es válido.
     * @post Se puede usar para cifrar la clave AES con @ref EncryptAESKeyWithPeer().
     */
    void LoadPeerPublicKey(const std::string& pemKey);

    // ====================== AES ======================

    /**
     * @brief Genera una clave AES-256 (32 bytes aleatorios).
     *
     * @post La clave queda almacenada en el arreglo interno @ref aesKey.
     *
     * @note Este paso es esencial antes de cifrar mensajes o exportar la clave.
     */
    void GenerateAESKey();

    /**
     * @brief Cifra la clave AES con la clave pública del peer (RSA).
     * @return Vector de bytes con la clave AES cifrada.
     *
     * @pre Debe haberse llamado antes a @ref LoadPeerPublicKey().
     * @note Esta clave cifrada puede enviarse al servidor para establecer el canal.
     */
    std::vector<unsigned char> EncryptAESKeyWithPeer();

    /**
     * @brief Descifra la clave AES cifrada recibida del cliente.
     * @param encryptedKey Vector de bytes con la clave AES cifrada (RSA).
     *
     * @pre La clave privada RSA debe estar disponible (ver @ref GenerateRSAKeys()).
     * @post La clave AES se guarda en @ref aesKey y se puede usar en AESDecrypt().
     */
    void DecryptAESKey(const std::vector<unsigned char>& encryptedKey);

    /**
     * @brief Cifra un mensaje de texto plano usando AES-256 en modo CBC.
     * @param plaintext Mensaje a cifrar.
     * @param outIV Vector donde se almacenará el IV usado.
     * @return Texto cifrado como vector de bytes.
     *
     * @pre La clave AES debe estar ya generada o cargada.
     * @note Se genera un nuevo IV aleatorio en cada llamada.
     */
    std::vector<unsigned char> AESEncrypt(const std::string& plaintext,
        std::vector<unsigned char>& outIV);

    /**
     * @brief Descifra un mensaje previamente cifrado con AES-256-CBC.
     * @param ciphertext Texto cifrado como vector de bytes.
     * @param iv Vector con el IV usado en el cifrado original.
     * @return Texto plano descifrado.
     *
     * @pre La clave AES debe estar ya establecida (vía generación o descifrado).
     */
    std::string AESDecrypt(const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& iv);

private:
    RSA* rsaKeyPair;            ///< Par de claves RSA (privada/pública).
    RSA* peerPublicKey;         ///< Clave pública RSA del otro participante.
    unsigned char aesKey[32];   ///< Clave AES-256: 32 bytes (256 bits).
};

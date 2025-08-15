/**
 * @file Client.h
 * @brief Cliente TCP con cifrado híbrido: handshake RSA y mensajería AES.
 *
 * @details
 * Este archivo define la clase `Client`, que implementa un cliente TCP seguro.
 * Su función principal es conectarse a un servidor, intercambiar claves mediante RSA
 * y luego establecer un canal de comunicación cifrado con AES.
 *
 * Ideal para proyectos que buscan aplicar seguridad en redes mediante criptografía híbrida.
 *
 * @note Codificación sugerida: UTF-8 (sin BOM) para evitar problemas de consola.
 * @warning Algunas operaciones de red pueden ser bloqueantes si no se manejan apropiadamente.
 */

#pragma once
#include "NetworkHelper.h"
#include "CryptoHelper.h"
#include "Prerequisites.h"

 /**
  * @class Client
  * @brief Cliente TCP seguro con intercambio de claves y cifrado simétrico.
  *
  * Esta clase encapsula todo lo necesario para establecer una conexión segura:
  * conexión TCP, intercambio de claves RSA, envío seguro de clave AES, y comunicación cifrada.
  *
  * @par Flujo de uso típico:
  * 1. Crear un objeto con `Client(ip, port)`.
  * 2. Llamar a `Connect()` para iniciar la conexión TCP.
  * 3. Llamar a `ExchangeKeys()` para recibir la clave pública del servidor.
  * 4. Usar `SendAESKeyEncrypted()` para enviar clave/IV cifrados con RSA.
  * 5. Enviar y recibir mensajes con `SendEncryptedMessageLoop()` y `StartReceiveLoop()`.
  *
  * @note Esta clase es ideal para experimentar con criptografía en red.
  */
class Client {
public:
    /// @brief Constructor por defecto. No realiza ninguna conexión automáticamente.
    Client() = default;

    /**
     * @brief Constructor que inicializa IP y puerto.
     * @param ip Dirección IP del servidor (ej. "127.0.0.1").
     * @param port Puerto TCP para la conexión (ej. 5000).
     *
     * @note No establece conexión hasta llamar a @ref Connect().
     */
    Client(const std::string& ip, int port);

    /// @brief Destructor: cierra el socket y limpia recursos.
    ~Client();

    /**
     * @brief Establece la conexión TCP con el servidor.
     * @return `true` si la conexión fue exitosa, `false` en caso de error.
     *
     * @post El socket queda listo para intercambiar claves.
     */
    bool Connect();

    /**
     * @brief Realiza el intercambio de claves RSA.
     *
     * @details
     * - Recibe la clave pública RSA del servidor.
     * - (Opcional) Enviar clave pública del cliente si fuera bidireccional.
     * - Genera clave e IV para sesión AES.
     *
     * @pre Debe haberse llamado previamente a @ref Connect().
     */
    void ExchangeKeys();

    /**
     * @brief Cifra y envía la clave de sesión AES usando RSA.
     *
     * @details
     * La clave e IV AES se cifran con la clave pública del servidor y se envían.
     * Esto permite al servidor establecer una sesión segura.
     *
     * @pre Se debe haber ejecutado @ref ExchangeKeys().
     */
    void SendAESKeyEncrypted();

    /**
     * @brief Cifra un mensaje con AES y lo envía.
     * @param message Texto en claro que se desea enviar de forma segura.
     *
     * @note Utiliza @ref CryptoHelper para cifrado y @ref NetworkHelper para envío.
     * @pre Debe existir una sesión AES ya establecida (ver @ref SendAESKeyEncrypted()).
     */
    void SendEncryptedMessage(const std::string& message);

    /**
     * @brief Bucle de envío interactivo: mensajes por consola cifrados con AES.
     *
     * @details
     * Lee mensajes desde la consola, los cifra y los envía. Finaliza al recibir EOF
     * o comando de salida. Ideal para pruebas o chat en vivo.
     *
     * @warning Es una función bloqueante (espera input indefinidamente).
     */
    void SendEncryptedMessageLoop();

    /**
     * @brief Bucle completo de chat (envío + recepción).
     *
     * @details
     * Combina lectura de consola, cifrado, envío, y recepción de mensajes
     * desde el servidor (según implementación).
     *
     * @note Útil para pruebas rápidas de comunicación bidireccional.
     */
    void StartChatLoop();

    /**
     * @brief Bucle de recepción de mensajes cifrados desde el servidor.
     *
     * @details
     * Extrae mensajes de la red, los descifra y los muestra por consola.
     * Termina si se cierra el socket o hay error.
     *
     * @warning Se recomienda ejecutar en un hilo separado.
     */
    void StartReceiveLoop();

private:
    /** @brief Dirección IP o hostname del servidor. */
    std::string m_ip;

    /** @brief Puerto TCP para conexión. */
    int m_port;

    /** @brief Descriptor de socket del servidor (válido tras @ref Connect()). */
    SOCKET m_serverSock;

    /** @brief Manejador de operaciones de red (timeouts, framing, envío/recepción). */
    NetworkHelper m_net;

    /** @brief Manejador criptográfico para RSA/AES. */
    CryptoHelper m_crypto;
};

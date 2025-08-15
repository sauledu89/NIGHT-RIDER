/**
 * @file Client.h
 * @brief Cliente TCP con cifrado h�brido: handshake RSA y mensajer�a AES.
 *
 * @details
 * Este archivo define la clase `Client`, que implementa un cliente TCP seguro.
 * Su funci�n principal es conectarse a un servidor, intercambiar claves mediante RSA
 * y luego establecer un canal de comunicaci�n cifrado con AES.
 *
 * Ideal para proyectos que buscan aplicar seguridad en redes mediante criptograf�a h�brida.
 *
 * @note Codificaci�n sugerida: UTF-8 (sin BOM) para evitar problemas de consola.
 * @warning Algunas operaciones de red pueden ser bloqueantes si no se manejan apropiadamente.
 */

#pragma once
#include "NetworkHelper.h"
#include "CryptoHelper.h"
#include "Prerequisites.h"

 /**
  * @class Client
  * @brief Cliente TCP seguro con intercambio de claves y cifrado sim�trico.
  *
  * Esta clase encapsula todo lo necesario para establecer una conexi�n segura:
  * conexi�n TCP, intercambio de claves RSA, env�o seguro de clave AES, y comunicaci�n cifrada.
  *
  * @par Flujo de uso t�pico:
  * 1. Crear un objeto con `Client(ip, port)`.
  * 2. Llamar a `Connect()` para iniciar la conexi�n TCP.
  * 3. Llamar a `ExchangeKeys()` para recibir la clave p�blica del servidor.
  * 4. Usar `SendAESKeyEncrypted()` para enviar clave/IV cifrados con RSA.
  * 5. Enviar y recibir mensajes con `SendEncryptedMessageLoop()` y `StartReceiveLoop()`.
  *
  * @note Esta clase es ideal para experimentar con criptograf�a en red.
  */
class Client {
public:
    /// @brief Constructor por defecto. No realiza ninguna conexi�n autom�ticamente.
    Client() = default;

    /**
     * @brief Constructor que inicializa IP y puerto.
     * @param ip Direcci�n IP del servidor (ej. "127.0.0.1").
     * @param port Puerto TCP para la conexi�n (ej. 5000).
     *
     * @note No establece conexi�n hasta llamar a @ref Connect().
     */
    Client(const std::string& ip, int port);

    /// @brief Destructor: cierra el socket y limpia recursos.
    ~Client();

    /**
     * @brief Establece la conexi�n TCP con el servidor.
     * @return `true` si la conexi�n fue exitosa, `false` en caso de error.
     *
     * @post El socket queda listo para intercambiar claves.
     */
    bool Connect();

    /**
     * @brief Realiza el intercambio de claves RSA.
     *
     * @details
     * - Recibe la clave p�blica RSA del servidor.
     * - (Opcional) Enviar clave p�blica del cliente si fuera bidireccional.
     * - Genera clave e IV para sesi�n AES.
     *
     * @pre Debe haberse llamado previamente a @ref Connect().
     */
    void ExchangeKeys();

    /**
     * @brief Cifra y env�a la clave de sesi�n AES usando RSA.
     *
     * @details
     * La clave e IV AES se cifran con la clave p�blica del servidor y se env�an.
     * Esto permite al servidor establecer una sesi�n segura.
     *
     * @pre Se debe haber ejecutado @ref ExchangeKeys().
     */
    void SendAESKeyEncrypted();

    /**
     * @brief Cifra un mensaje con AES y lo env�a.
     * @param message Texto en claro que se desea enviar de forma segura.
     *
     * @note Utiliza @ref CryptoHelper para cifrado y @ref NetworkHelper para env�o.
     * @pre Debe existir una sesi�n AES ya establecida (ver @ref SendAESKeyEncrypted()).
     */
    void SendEncryptedMessage(const std::string& message);

    /**
     * @brief Bucle de env�o interactivo: mensajes por consola cifrados con AES.
     *
     * @details
     * Lee mensajes desde la consola, los cifra y los env�a. Finaliza al recibir EOF
     * o comando de salida. Ideal para pruebas o chat en vivo.
     *
     * @warning Es una funci�n bloqueante (espera input indefinidamente).
     */
    void SendEncryptedMessageLoop();

    /**
     * @brief Bucle completo de chat (env�o + recepci�n).
     *
     * @details
     * Combina lectura de consola, cifrado, env�o, y recepci�n de mensajes
     * desde el servidor (seg�n implementaci�n).
     *
     * @note �til para pruebas r�pidas de comunicaci�n bidireccional.
     */
    void StartChatLoop();

    /**
     * @brief Bucle de recepci�n de mensajes cifrados desde el servidor.
     *
     * @details
     * Extrae mensajes de la red, los descifra y los muestra por consola.
     * Termina si se cierra el socket o hay error.
     *
     * @warning Se recomienda ejecutar en un hilo separado.
     */
    void StartReceiveLoop();

private:
    /** @brief Direcci�n IP o hostname del servidor. */
    std::string m_ip;

    /** @brief Puerto TCP para conexi�n. */
    int m_port;

    /** @brief Descriptor de socket del servidor (v�lido tras @ref Connect()). */
    SOCKET m_serverSock;

    /** @brief Manejador de operaciones de red (timeouts, framing, env�o/recepci�n). */
    NetworkHelper m_net;

    /** @brief Manejador criptogr�fico para RSA/AES. */
    CryptoHelper m_crypto;
};

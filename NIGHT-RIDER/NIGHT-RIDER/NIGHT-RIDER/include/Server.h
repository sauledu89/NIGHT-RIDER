/**
 * @file Server.h
 * @brief Servidor TCP con handshake RSA y comunicaci�n cifrada con AES.
 *
 * @details
 * Esta clase representa un servidor de red que utiliza un esquema de cifrado h�brido (RSA para intercambio de claves y AES-256-CBC para la sesi�n).
 *
 * - Inicia un socket TCP en un puerto dado.
 * - Acepta una conexi�n entrante.
 * - Intercambia claves p�blicas RSA.
 * - Recibe una clave AES cifrada con la RSA del servidor.
 * - Usa esa clave para mantener un canal cifrado con AES.
 * - Permite intercambiar mensajes en un chat seguro con env�o y recepci�n simult�neos.
 *
 * @note Depende de @ref NetworkHelper para la red y @ref CryptoHelper para la criptograf�a.
 */

#pragma once
#include "NetworkHelper.h"
#include "CryptoHelper.h"
#include "Prerequisites.h"

 /**
  * @class Server
  * @brief Clase que representa un servidor TCP seguro con cifrado h�brido RSA/AES.
  *
  * Dise�ada para demostrar comunicaci�n segura punto a punto. Facilita la implementaci�n de un servidor b�sico
  * que puede recibir y enviar mensajes cifrados con AES tras un intercambio inicial de claves RSA.
  *
  * @par Flujo t�pico de uso:
  * 1. Construir la instancia con `Server(port)`.
  * 2. Llamar a `Start()` para iniciar el servidor.
  * 3. Llamar a `WaitForClient()` para aceptar un cliente y negociar claves.
  * 4. Usar `StartChatLoop()` para mantener la comunicaci�n bidireccional segura.
  *
  * @warning Los m�todos de env�o/recepci�n son bloqueantes. Usar hilos para ejecuci�n concurrente.
  */
class Server {
public:
    /// @brief Constructor por defecto (no configura ni inicia el servidor).
    Server() = default;

    /**
     * @brief Constructor que inicializa el servidor con un puerto espec�fico.
     * @param port Puerto TCP en el que el servidor escuchar� conexiones.
     */
    Server(int port);

    /// @brief Destructor que libera recursos, cierra sockets activos y detiene hilos.
    ~Server();

    /**
     * @brief Inicia el servidor en el puerto especificado.
     * @return `true` si se inici� correctamente, `false` si hubo un error.
     * @post El servidor estar� listo para aceptar clientes mediante @ref WaitForClient().
     */
    bool Start();

    /**
     * @brief Acepta un cliente y realiza el handshake criptogr�fico.
     *
     * @details
     * 1. Acepta una conexi�n entrante.
     * 2. Env�a la clave p�blica RSA del servidor.
     * 3. Recibe la clave p�blica del cliente.
     * 4. Recibe la clave AES cifrada y la descifra con la clave privada del servidor.
     *
     * @pre `Start()` debe haberse llamado antes.
     */
    void WaitForClient();

    /**
     * @brief Recibe y muestra un mensaje cifrado del cliente.
     * @note �til para pruebas aisladas. No se usa en modo de chat continuo.
     */
    void ReceiveEncryptedMessage();

    /**
     * @brief Bucle continuo para recepci�n de mensajes cifrados desde el cliente.
     *
     * @details
     * - Escucha mensajes encriptados.
     * - Descifra y muestra los mensajes en consola.
     *
     * @warning Es una operaci�n bloqueante. Ejecutar en un hilo si se necesita simultaneidad.
     */
    void StartReceiveLoop();

    /**
     * @brief Bucle continuo para env�o de mensajes cifrados al cliente.
     *
     * @details
     * - Toma la entrada desde consola.
     * - Cifra con AES-256 y env�a al cliente.
     * - Finaliza si el mensaje es `/exit`.
     */
    void SendEncryptedMessageLoop();

    /**
     * @brief Bucle de chat completo (env�o y recepci�n en paralelo).
     *
     * @details
     * - Inicia un hilo para la recepci�n de mensajes.
     * - El hilo principal gestiona el env�o.
     * - Finaliza al cerrar el canal o recibir `/exit`.
     */
    void StartChatLoop();

private:
    int m_port;                            ///< Puerto TCP en el que escucha el servidor.
    SOCKET m_clientSock;                   ///< Socket del cliente conectado.
    NetworkHelper m_net;                   ///< Utilidad para comunicaci�n TCP.
    CryptoHelper m_crypto;                 ///< Utilidad para operaciones RSA y AES.
    std::thread m_rxThread;                ///< Hilo para la recepci�n de mensajes.
    std::atomic<bool> m_running{ false };  ///< Bandera para controlar la ejecuci�n del bucle de chat.
};

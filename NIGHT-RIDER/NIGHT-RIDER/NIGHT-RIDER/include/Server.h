/**
 * @file Server.h
 * @brief Servidor TCP con handshake RSA y comunicación cifrada con AES.
 *
 * @details
 * Esta clase representa un servidor de red que utiliza un esquema de cifrado híbrido (RSA para intercambio de claves y AES-256-CBC para la sesión).
 *
 * - Inicia un socket TCP en un puerto dado.
 * - Acepta una conexión entrante.
 * - Intercambia claves públicas RSA.
 * - Recibe una clave AES cifrada con la RSA del servidor.
 * - Usa esa clave para mantener un canal cifrado con AES.
 * - Permite intercambiar mensajes en un chat seguro con envío y recepción simultáneos.
 *
 * @note Depende de @ref NetworkHelper para la red y @ref CryptoHelper para la criptografía.
 */

#pragma once
#include "NetworkHelper.h"
#include "CryptoHelper.h"
#include "Prerequisites.h"

 /**
  * @class Server
  * @brief Clase que representa un servidor TCP seguro con cifrado híbrido RSA/AES.
  *
  * Diseñada para demostrar comunicación segura punto a punto. Facilita la implementación de un servidor básico
  * que puede recibir y enviar mensajes cifrados con AES tras un intercambio inicial de claves RSA.
  *
  * @par Flujo típico de uso:
  * 1. Construir la instancia con `Server(port)`.
  * 2. Llamar a `Start()` para iniciar el servidor.
  * 3. Llamar a `WaitForClient()` para aceptar un cliente y negociar claves.
  * 4. Usar `StartChatLoop()` para mantener la comunicación bidireccional segura.
  *
  * @warning Los métodos de envío/recepción son bloqueantes. Usar hilos para ejecución concurrente.
  */
class Server {
public:
    /// @brief Constructor por defecto (no configura ni inicia el servidor).
    Server() = default;

    /**
     * @brief Constructor que inicializa el servidor con un puerto específico.
     * @param port Puerto TCP en el que el servidor escuchará conexiones.
     */
    Server(int port);

    /// @brief Destructor que libera recursos, cierra sockets activos y detiene hilos.
    ~Server();

    /**
     * @brief Inicia el servidor en el puerto especificado.
     * @return `true` si se inició correctamente, `false` si hubo un error.
     * @post El servidor estará listo para aceptar clientes mediante @ref WaitForClient().
     */
    bool Start();

    /**
     * @brief Acepta un cliente y realiza el handshake criptográfico.
     *
     * @details
     * 1. Acepta una conexión entrante.
     * 2. Envía la clave pública RSA del servidor.
     * 3. Recibe la clave pública del cliente.
     * 4. Recibe la clave AES cifrada y la descifra con la clave privada del servidor.
     *
     * @pre `Start()` debe haberse llamado antes.
     */
    void WaitForClient();

    /**
     * @brief Recibe y muestra un mensaje cifrado del cliente.
     * @note Útil para pruebas aisladas. No se usa en modo de chat continuo.
     */
    void ReceiveEncryptedMessage();

    /**
     * @brief Bucle continuo para recepción de mensajes cifrados desde el cliente.
     *
     * @details
     * - Escucha mensajes encriptados.
     * - Descifra y muestra los mensajes en consola.
     *
     * @warning Es una operación bloqueante. Ejecutar en un hilo si se necesita simultaneidad.
     */
    void StartReceiveLoop();

    /**
     * @brief Bucle continuo para envío de mensajes cifrados al cliente.
     *
     * @details
     * - Toma la entrada desde consola.
     * - Cifra con AES-256 y envía al cliente.
     * - Finaliza si el mensaje es `/exit`.
     */
    void SendEncryptedMessageLoop();

    /**
     * @brief Bucle de chat completo (envío y recepción en paralelo).
     *
     * @details
     * - Inicia un hilo para la recepción de mensajes.
     * - El hilo principal gestiona el envío.
     * - Finaliza al cerrar el canal o recibir `/exit`.
     */
    void StartChatLoop();

private:
    int m_port;                            ///< Puerto TCP en el que escucha el servidor.
    SOCKET m_clientSock;                   ///< Socket del cliente conectado.
    NetworkHelper m_net;                   ///< Utilidad para comunicación TCP.
    CryptoHelper m_crypto;                 ///< Utilidad para operaciones RSA y AES.
    std::thread m_rxThread;                ///< Hilo para la recepción de mensajes.
    std::atomic<bool> m_running{ false };  ///< Bandera para controlar la ejecución del bucle de chat.
};

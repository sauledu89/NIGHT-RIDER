/**
 * @file NetworkHelper.h
 * @brief Utilidad para manejo de sockets TCP: cliente y servidor.
 *
 * @details
 * Esta clase proporciona una abstracci�n sencilla sobre la API de Winsock2.
 * Permite crear servidores TCP, aceptar conexiones, conectarse como cliente,
 * y enviar/recibir datos en formato texto o binario con control de tama�o.
 *
 * @note Se debe inicializar Winsock previamente con `WSAStartup()` en el programa principal.
 * @warning Las funciones son bloqueantes por defecto. Usar select o modo no bloqueante si se requiere.
 */

#pragma once
#include "Prerequisites.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

 /**
  * @class NetworkHelper
  * @brief Clase de soporte para operaciones b�sicas con sockets TCP.
  *
  * Ideal para proyectos que requieren comunicaci�n entre cliente y servidor.
  * Proporciona funciones reutilizables para enviar y recibir datos con precisi�n.
  *
  * @par Funciones clave:
  * - Iniciar servidor y aceptar clientes.
  * - Conectarse a un servidor remoto.
  * - Enviar/recibir texto y binarios con control de tama�o.
  * - Cierre seguro de sockets.
  */
class NetworkHelper {
public:
    /// @brief Constructor por defecto. Inicializa estado interno.
    NetworkHelper();

    /// @brief Destructor. Libera recursos y limpia si es necesario.
    ~NetworkHelper();

    // ====================== Servidor ======================

    /**
     * @brief Inicia un servidor TCP en el puerto dado.
     * @param port Puerto donde se escuchar�n conexiones.
     * @return `true` si se inicia correctamente, `false` en caso de error.
     *
     * @post Se asigna y configura @ref m_serverSocket para escuchar conexiones.
     */
    bool StartServer(int port);

    /**
     * @brief Acepta una conexi�n entrante en el socket del servidor.
     * @return Descriptor de socket del cliente, o `INVALID_SOCKET` si falla.
     *
     * @pre Se debe haber iniciado el servidor con @ref StartServer().
     */
    SOCKET AcceptClient();

    // ====================== Cliente ======================

    /**
     * @brief Conecta a un servidor TCP remoto.
     * @param ip Direcci�n IP del servidor (ej. "127.0.0.1").
     * @param port Puerto del servidor (ej. 5000).
     * @return `true` si se conecta correctamente, `false` en caso de error.
     */
    bool ConnectToServer(const std::string& ip, int port);

    // ====================== Env�o ======================

    /**
     * @brief Env�a una cadena de texto al socket.
     * @param socket Socket v�lido (cliente o servidor).
     * @param data Texto a enviar.
     * @return `true` si se env�a exitosamente, `false` si ocurre un error.
     */
    bool SendData(SOCKET socket, const std::string& data);

    /**
     * @brief Env�a datos binarios por el socket.
     * @param socket Socket v�lido.
     * @param data Vector de bytes a enviar (por ejemplo, claves).
     * @return `true` si se env�an todos los datos, `false` en error.
     */
    bool SendData(SOCKET socket, const std::vector<unsigned char>& data);

    /**
     * @brief Env�a exactamente `len` bytes desde un buffer.
     * @param s Socket v�lido.
     * @param data Puntero al buffer.
     * @param len N�mero de bytes a enviar.
     * @return `true` si se env�an todos los bytes, `false` si ocurre error.
     *
     * @note �til para garantizar la entrega completa de mensajes binarios.
     */
    bool SendAll(SOCKET s, const unsigned char* data, int len);

    // ====================== Recepci�n ======================

    /**
     * @brief Recibe una cadena de texto desde el socket.
     * @param socket Socket v�lido.
     * @return Texto recibido. Cadena vac�a si hubo error o cierre.
     */
    std::string ReceiveData(SOCKET socket);

    /**
     * @brief Recibe datos binarios desde el socket.
     * @param socket Socket v�lido.
     * @param size N�mero de bytes a recibir. Si es 0, se reciben hasta cierre.
     * @return Vector con los datos recibidos.
     */
    std::vector<unsigned char> ReceiveDataBinary(SOCKET socket, int size = 0);

    /**
     * @brief Recibe exactamente `len` bytes y los guarda en el buffer dado.
     * @param s Socket v�lido.
     * @param out Buffer donde se almacenar�n los bytes recibidos.
     * @param len N�mero exacto de bytes esperados.
     * @return `true` si se reciben todos, `false` si falla.
     */
    bool ReceiveExact(SOCKET s, unsigned char* out, int len);

    // ====================== Utilidad ======================

    /**
     * @brief Cierra un socket de forma segura.
     * @param socket Descriptor del socket a cerrar.
     */
    void close(SOCKET socket);

public:
    SOCKET m_serverSocket = -1;  ///< Socket del servidor (escucha). -1 si no est� activo.

private:
    bool m_initialized;          ///< Indica si Winsock fue inicializado correctamente.
};

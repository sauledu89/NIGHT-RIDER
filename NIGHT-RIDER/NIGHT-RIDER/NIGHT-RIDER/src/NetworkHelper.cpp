/**
 * @file NetworkHelper.cpp
 * @brief Implementación de utilidades de red para cliente y servidor TCP.
 *
 * @details
 * Este módulo encapsula funciones esenciales para trabajar con sockets en Windows usando Winsock2.
 * Las funcionalidades incluyen:
 *
 * - Inicialización de la biblioteca Winsock (`WSAStartup`).
 * - Creación y configuración de sockets TCP.
 * - Modo servidor: escucha y acepta clientes.
 * - Modo cliente: se conecta a un servidor.
 * - Envío/recepción de datos en modo texto y binario.
 * - Funciones auxiliares para asegurar envío y recepción exacta de bytes.
 *
 * @note Pensado para ser multiplataforma solo con modificaciones menores si se sustituye Winsock.
 */

#include "NetworkHelper.h"

 /**
  * @brief Constructor. Inicializa Winsock.
  */
NetworkHelper::NetworkHelper() : m_serverSocket(INVALID_SOCKET), m_initialized(false) {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
    }
    else {
        m_initialized = true;
    }
}

/**
 * @brief Destructor. Libera recursos y limpia Winsock.
 */
NetworkHelper::~NetworkHelper() {
    if (m_serverSocket != INVALID_SOCKET) {
        closesocket(m_serverSocket);
    }

    if (m_initialized) {
        WSACleanup();
    }
}

/**
 * @brief Inicia un servidor TCP que escucha en el puerto especificado.
 * @param port Puerto TCP donde se aceptarán conexiones.
 * @return `true` si el servidor se inicia correctamente.
 */
bool NetworkHelper::StartServer(int port) {
    m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_serverSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        return false;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Error binding socket: " << WSAGetLastError() << std::endl;
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }

    if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Error listening on socket: " << WSAGetLastError() << std::endl;
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }

    std::cout << "Server started on port " << port << std::endl;
    return true;
}

/**
 * @brief Acepta una conexión entrante del cliente.
 * @return Socket del cliente aceptado, o `INVALID_SOCKET` si falla.
 */
SOCKET NetworkHelper::AcceptClient() {
    SOCKET clientSocket = accept(m_serverSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Error accepting client: " << WSAGetLastError() << std::endl;
        return INVALID_SOCKET;
    }
    std::cout << "Client connected." << std::endl;
    return clientSocket;
}

/**
 * @brief Conecta a un servidor remoto en IP y puerto dados.
 * @param ip Dirección IP del servidor.
 * @param port Puerto al que conectarse.
 * @return `true` si la conexión fue exitosa.
 */
bool NetworkHelper::ConnectToServer(const std::string& ip, int port) {
    m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_serverSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        return false;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddress.sin_addr);

    if (connect(m_serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }

    std::cout << "Connected to server at " << ip << ":" << port << std::endl;
    return true;
}

/**
 * @brief Envía una cadena de texto por el socket.
 * @param socket Socket conectado.
 * @param data Texto a enviar.
 * @return `true` si el envío fue exitoso.
 */
bool NetworkHelper::SendData(SOCKET socket, const std::string& data) {
    return send(socket, data.c_str(), static_cast<int>(data.size()), 0) != SOCKET_ERROR;
}

/**
 * @brief Envía un vector binario por el socket.
 * @param socket Socket conectado.
 * @param data Datos binarios.
 * @return `true` si se envían todos los datos.
 */
bool NetworkHelper::SendData(SOCKET socket, const std::vector<unsigned char>& data) {
    return SendAll(socket, data.data(), static_cast<int>(data.size()));
}

/**
 * @brief Recibe una cadena de texto desde el socket.
 * @param socket Socket conectado.
 * @return Cadena recibida. Puede estar vacía si hay error.
 */
std::string NetworkHelper::ReceiveData(SOCKET socket) {
    char buffer[4096] = {};
    int len = recv(socket, buffer, sizeof(buffer), 0);
    return std::string(buffer, len);
}

/**
 * @brief Recibe una cantidad exacta de bytes desde el socket.
 * @param socket Socket conectado.
 * @param size Número de bytes a recibir.
 * @return Vector con los datos recibidos. Vacío si falla.
 */
std::vector<unsigned char> NetworkHelper::ReceiveDataBinary(SOCKET socket, int size) {
    std::vector<unsigned char> buf(size);
    if (!ReceiveExact(socket, buf.data(), size)) return {};
    return buf;
}

/**
 * @brief Cierra un socket de manera segura.
 * @param socket Socket a cerrar.
 */
void NetworkHelper::close(SOCKET socket) {
    closesocket(socket);
}

/**
 * @brief Envía exactamente `len` bytes desde un buffer.
 * @param s Socket conectado.
 * @param data Puntero al buffer.
 * @param len Cantidad de bytes a enviar.
 * @return `true` si se envían todos los bytes, `false` en error.
 */
bool NetworkHelper::SendAll(SOCKET s, const unsigned char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, (const char*)data + sent, len - sent, 0);
        if (n == SOCKET_ERROR) return false;
        sent += n;
    }
    return true;
}

/**
 * @brief Recibe exactamente `len` bytes y los almacena en el buffer dado.
 * @param s Socket conectado.
 * @param out Puntero al buffer de destino.
 * @param len Número de bytes esperados.
 * @return `true` si se reciben todos los bytes, `false` si ocurre un error.
 */
bool NetworkHelper::ReceiveExact(SOCKET s, unsigned char* out, int len) {
    int recvd = 0;
    while (recvd < len) {
        int n = recv(s, (char*)out + recvd, len - recvd, 0);
        if (n <= 0) return false;
        recvd += n;
    }
    return true;
}

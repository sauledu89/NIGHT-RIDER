/**
 * @file Server.cpp
 * @brief Implementación del servidor TCP con cifrado híbrido RSA/AES.
 *
 * @details
 * Este archivo contiene la lógica principal del servidor seguro. Sus responsabilidades incluyen:
 *
 * - Inicializar un servidor TCP y aceptar una conexión entrante.
 * - Intercambiar claves públicas RSA con el cliente.
 * - Recibir y descifrar la clave AES cifrada.
 * - Establecer un canal simétrico con AES-256-CBC.
 * - Enviar y recibir mensajes cifrados mediante sockets.
 * - Gestionar hilos para mantener la comunicación bidireccional en paralelo.
 *
 * @note Usa `NetworkHelper` para comunicación y `CryptoHelper` para manejo de claves y cifrado.
 */

#include "Server.h"

 /**
  * @brief Constructor. Inicializa puerto y genera claves RSA.
  * @param port Puerto TCP en el que el servidor escuchará.
  */
Server::Server(int port) : m_port(port), m_clientSock(-1) {
	m_crypto.GenerateRSAKeys(); // Genera par RSA
}

/**
 * @brief Destructor. Cierra la conexión si aún está activa.
 */
Server::~Server() {
	if (m_clientSock != -1) {
		m_net.close(m_clientSock);
	}
}

/**
 * @brief Inicia el servidor TCP.
 * @return `true` si el servidor pudo iniciarse correctamente.
 */
bool Server::Start() {
	std::cout << "[Server] Iniciando servidor en el puerto " << m_port << "...\n";
	return m_net.StartServer(m_port);
}

/**
 * @brief Espera una conexión entrante y realiza el intercambio de claves.
 *
 * @details
 * 1. Acepta un cliente.
 * 2. Envía clave pública del servidor.
 * 3. Recibe clave pública del cliente.
 * 4. Recibe la clave AES cifrada (RSA).
 * 5. Descifra y almacena la clave AES para la sesión.
 */
void Server::WaitForClient() {
	std::cout << "[Server] Esperando conexión de un cliente...\n";

	m_clientSock = m_net.AcceptClient();
	if (m_clientSock == INVALID_SOCKET) {
		std::cerr << "[Server] No se pudo aceptar cliente.\n";
		return;
	}
	std::cout << "[Server] Cliente conectado.\n";

	std::string serverPubKey = m_crypto.GetPublicKeyString();
	m_net.SendData(m_clientSock, serverPubKey);

	std::string clientPubKey = m_net.ReceiveData(m_clientSock);
	m_crypto.LoadPeerPublicKey(clientPubKey);

	std::vector<unsigned char> encryptedAESKey = m_net.ReceiveDataBinary(m_clientSock, 256);
	m_crypto.DecryptAESKey(encryptedAESKey);

	std::cout << "[Server] Clave AES intercambiada exitosamente.\n";
}

/**
 * @brief (Alternativo) Recibe y muestra un solo mensaje cifrado.
 * @warning No se usa en el flujo principal (ver @ref StartReceiveLoop).
 */
void Server::ReceiveEncryptedMessage() {
	std::vector<unsigned char> iv = m_net.ReceiveDataBinary(m_clientSock, 16);
	std::vector<unsigned char> encryptedMsg = m_net.ReceiveDataBinary(m_clientSock, 128);
	std::string msg = m_crypto.AESDecrypt(encryptedMsg, iv);
	std::cout << "[Server] Mensaje recibido: " << msg << "\n";
}

/**
 * @brief Bucle de recepción de mensajes cifrados desde el cliente.
 *
 * @details
 * - Espera el IV (16 bytes), el tamaño del mensaje (4 bytes) y el ciphertext.
 * - Descifra y muestra el mensaje.
 * - Finaliza si la conexión se pierde.
 */
void Server::StartReceiveLoop() {
	while (true) {
		auto iv = m_net.ReceiveDataBinary(m_clientSock, 16);
		if (iv.empty()) {
			std::cout << "\n[Server] Conexión cerrada por el cliente.\n";
			break;
		}

		auto len4 = m_net.ReceiveDataBinary(m_clientSock, 4);
		if (len4.size() != 4) {
			std::cout << "[Server] Error al recibir tamaño.\n";
			break;
		}
		uint32_t nlen = 0;
		std::memcpy(&nlen, len4.data(), 4);
		uint32_t clen = ntohl(nlen); // tamaño real

		auto cipher = m_net.ReceiveDataBinary(m_clientSock, static_cast<int>(clen));
		if (cipher.empty()) {
			std::cout << "[Server] Error al recibir datos.\n";
			break;
		}

		std::string plain = m_crypto.AESDecrypt(cipher, iv);
		std::cout << "\n[Cliente]: " << plain << "\nServidor: ";
		std::cout.flush();
	}
}

/**
 * @brief Bucle de envío de mensajes cifrados al cliente.
 *
 * @details
 * - Cifra cada mensaje con AES-256-CBC.
 * - Envía: IV (16 bytes), tamaño (4 bytes), y mensaje cifrado.
 * - Termina si el usuario escribe `/exit`.
 */
void Server::SendEncryptedMessageLoop() {
	std::string msg;
	while (true) {
		std::cout << "Servidor: ";
		std::getline(std::cin, msg);
		if (msg == "/exit") break;

		std::vector<unsigned char> iv;
		auto cipher = m_crypto.AESEncrypt(msg, iv);

		m_net.SendData(m_clientSock, iv);

		uint32_t clen = static_cast<uint32_t>(cipher.size());
		uint32_t nlen = htonl(clen);
		std::vector<unsigned char> len4(
			reinterpret_cast<unsigned char*>(&nlen),
			reinterpret_cast<unsigned char*>(&nlen) + 4
		);
		m_net.SendData(m_clientSock, len4);
		m_net.SendData(m_clientSock, cipher);
	}
	std::cout << "[Server] Saliendo del chat.\n";
}

/**
 * @brief Inicia el chat cifrado bidireccional con el cliente.
 *
 * @details
 * - Lanza un hilo para recepción.
 * - El hilo principal gestiona la entrada del usuario y envío de mensajes.
 * - Finaliza correctamente al cerrar el canal.
 */
void Server::StartChatLoop() {
	std::thread recvThread([&]() {
		StartReceiveLoop();
		});

	SendEncryptedMessageLoop();

	if (recvThread.joinable())
		recvThread.join();
}

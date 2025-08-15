/**
 * @file Client.cpp
 * @brief Implementaci�n del cliente TCP con cifrado h�brido RSA/AES.
 *
* @details
* Este m�dulo contiene la l�gica que permite a un cliente:
* - Conectarse a un servidor remoto v�a TCP.
* - Intercambiar claves p�blicas (RSA).
* - Enviar una clave AES cifrada con la RSA del servidor.
* - Cifrar mensajes con AES-256-CBC y enviarlos al servidor.
* - Recibir mensajes cifrados del servidor y descifrarlos.
*
* Tambi�n incluye un bucle de chat interactivo con env�o y recepci�n en paralelo mediante hilos.
*/

#include "Client.h"

 /**
  * @brief Constructor que inicializa IP, puerto y claves.
  *
  * @details
  * Genera autom�ticamente el par RSA del cliente y su clave AES para sesi�n.
  *
  * @param ip Direcci�n IP del servidor.
  * @param port Puerto TCP del servidor.
  */
Client::Client(const std::string& ip, int port)
	: m_ip(ip), m_port(port), m_serverSock(INVALID_SOCKET) {
	m_crypto.GenerateRSAKeys();  // Par RSA propio
	m_crypto.GenerateAESKey();   // Clave AES de sesi�n
}

/**
 * @brief Destructor que cierra el socket si est� abierto.
 */
Client::~Client() {
	if (m_serverSock != INVALID_SOCKET) {
		m_net.close(m_serverSock);
	}
}

/**
 * @brief Establece conexi�n TCP con el servidor.
 *
 * @return `true` si la conexi�n fue exitosa, `false` si fall�.
 */
bool Client::Connect() {
	std::cout << "[Client] Conectando al servidor " << m_ip << ":" << m_port << "...\n";
	bool connected = m_net.ConnectToServer(m_ip, m_port);
	if (connected) {
		m_serverSock = m_net.m_serverSocket;
		std::cout << "[Client] Conexi�n establecida.\n";
	}
	else {
		std::cerr << "[Client] Error al conectar.\n";
	}
	return connected;
}

/**
 * @brief Intercambia claves RSA con el servidor.
 *
 * @details
 * - Recibe primero la clave p�blica del servidor.
 * - Luego, env�a la clave p�blica del cliente.
 */
void Client::ExchangeKeys() {
	std::string serverPubKey = m_net.ReceiveData(m_serverSock);
	m_crypto.LoadPeerPublicKey(serverPubKey);
	std::cout << "[Client] Clave p�blica del servidor recibida.\n";

	std::string clientPubKey = m_crypto.GetPublicKeyString();
	m_net.SendData(m_serverSock, clientPubKey);
	std::cout << "[Client] Clave p�blica del cliente enviada.\n";
}

/**
 * @brief Env�a la clave AES cifrada con la RSA del servidor.
 */
void Client::SendAESKeyEncrypted() {
	std::vector<unsigned char> encryptedAES = m_crypto.EncryptAESKeyWithPeer();
	m_net.SendData(m_serverSock, encryptedAES);
	std::cout << "[Client] Clave AES cifrada y enviada al servidor.\n";
}

/**
 * @brief Cifra y env�a un mensaje con AES-256-CBC.
 * @param message Texto plano a cifrar.
 */
void Client::SendEncryptedMessage(const std::string& message) {
	std::vector<unsigned char> iv;
	auto cipher = m_crypto.AESEncrypt(message, iv);

	// 1. Enviar IV (16 bytes)
	m_net.SendData(m_serverSock, iv);

	// 2. Enviar tama�o del ciphertext (4 bytes, big-endian)
	uint32_t clen = static_cast<uint32_t>(cipher.size());
	uint32_t nlen = htonl(clen);
	std::vector<unsigned char> len4(reinterpret_cast<unsigned char*>(&nlen),
		reinterpret_cast<unsigned char*>(&nlen) + 4);
	m_net.SendData(m_serverSock, len4);

	// 3. Enviar el ciphertext
	m_net.SendData(m_serverSock, cipher);
}

/**
 * @brief Bucle interactivo de env�o de mensajes cifrados.
 *
 * @details
 * Lee entradas por consola, las cifra y las env�a.
 * Finaliza si el usuario escribe `/exit`.
 */
void Client::SendEncryptedMessageLoop() {
	std::string msg;
	while (true) {
		std::cout << "Cliente: ";
		std::getline(std::cin, msg);
		if (msg == "/exit") break;

		std::vector<unsigned char> iv;
		auto cipher = m_crypto.AESEncrypt(msg, iv);

		m_net.SendData(m_serverSock, iv);

		uint32_t clen = static_cast<uint32_t>(cipher.size());
		uint32_t nlen = htonl(clen);
		std::vector<unsigned char> len4(reinterpret_cast<unsigned char*>(&nlen),
			reinterpret_cast<unsigned char*>(&nlen) + 4);
		m_net.SendData(m_serverSock, len4);
		m_net.SendData(m_serverSock, cipher);
	}
}

/**
 * @brief Bucle de recepci�n de mensajes cifrados desde el servidor.
 *
 * @details
 * - Recibe IV, tama�o, y ciphertext.
 * - Descifra y muestra el mensaje.
 * - Finaliza si hay error o desconexi�n.
 */
void Client::StartReceiveLoop() {
	while (true) {
		auto iv = m_net.ReceiveDataBinary(m_serverSock, 16);
		if (iv.empty()) {
			std::cout << "\n[Client] Conexi�n cerrada por el servidor.\n";
			break;
		}

		auto len4 = m_net.ReceiveDataBinary(m_serverSock, 4);
		if (len4.size() != 4) {
			std::cout << "[Client] Error al recibir tama�o.\n";
			break;
		}
		uint32_t nlen = 0;
		std::memcpy(&nlen, len4.data(), 4);
		uint32_t clen = ntohl(nlen);

		auto cipher = m_net.ReceiveDataBinary(m_serverSock, static_cast<int>(clen));
		if (cipher.empty()) {
			std::cout << "[Client] Error al recibir datos.\n";
			break;
		}

		std::string plain = m_crypto.AESDecrypt(cipher, iv);
		std::cout << "\n[Servidor]: " << plain << "\nCliente: ";
		std::cout.flush();
	}
	std::cout << "[Client] ReceiveLoop terminado.\n";
}

/**
 * @brief Inicia el chat cliente con env�o y recepci�n en paralelo.
 *
 * @details
 * Lanza un hilo para recepci�n mientras el hilo principal gestiona el env�o.
 * Espera a que el hilo de recepci�n finalice al salir del bucle.
 */
void Client::StartChatLoop() {
	std::thread recvThread([&]() {
		StartReceiveLoop();
		});

	SendEncryptedMessageLoop();

	if (recvThread.joinable())
		recvThread.join();
}

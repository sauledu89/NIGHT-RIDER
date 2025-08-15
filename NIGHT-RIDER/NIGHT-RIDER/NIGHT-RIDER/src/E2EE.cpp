/**
 * @file main.cpp
 * @brief Punto de entrada para la aplicaci�n de chat cifrado RSA/AES.
 *
 * @details
 * Este archivo inicializa y ejecuta la aplicaci�n en modo **servidor** o **cliente**,
 * dependiendo de los argumentos proporcionados por l�nea de comandos o por entrada del usuario.
 *
 * - En **modo servidor**:
 *    - Escucha conexiones en un puerto espec�fico.
 *    - Realiza intercambio de claves p�blicas RSA.
 *    - Recibe la clave AES cifrada desde el cliente.
 *    - Entra en el bucle de chat bidireccional cifrado.
 *
 * - En **modo cliente**:
 *    - Se conecta a la IP y puerto del servidor.
 *    - Realiza el intercambio de claves p�blicas.
 *    - Env�a la clave AES cifrada.
 *    - Inicia un bucle de chat cifrado con hilos.
 *
 * @note La l�gica de red y cifrado est� delegada en las clases `Server` y `Client`.
 * @warning Requiere que el puerto est� disponible en la red y que las bibliotecas est�n correctamente configuradas.
 */

#include "Prerequisites.h"
#include "Server.h"
#include "Client.h"

 /**
  * @brief Ejecuta la l�gica del servidor.
  *
  * @param port Puerto TCP donde el servidor escuchar�.
  */
static void runServer(int port) {
    Server s(port);
    if (!s.Start()) {
        std::cerr << "[Main] No se pudo iniciar el servidor.\n";
        return;
    }
    s.WaitForClient();       // Espera e intercambia claves
    s.StartChatLoop();       // Chat en paralelo
}

/**
 * @brief Ejecuta la l�gica del cliente.
 *
 * @param ip Direcci�n IP del servidor al que conectarse.
 * @param port Puerto TCP del servidor.
 */
static void runClient(const std::string& ip, int port) {
    Client c(ip, port);
    if (!c.Connect()) {
        std::cerr << "[Main] No se pudo conectar.\n";
        return;
    }

    c.ExchangeKeys();          // Recibe/enviar claves RSA
    c.SendAESKeyEncrypted();   // Env�a clave AES cifrada

    c.StartChatLoop();         // Chat en paralelo
}

/**
 * @brief Funci�n principal de la aplicaci�n.
 *
 * @param argc N�mero de argumentos desde l�nea de comandos.
 * @param argv Vector de argumentos (modo, IP, puerto).
 * @return `0` si finaliza correctamente, `1` si hubo error de uso.
 */
int main(int argc, char** argv) {
    std::string mode, ip;
    int port = 0;

    // === Modo por argumentos ===
    if (argc >= 2) {
        mode = argv[1];

        if (mode == "server") {
            port = (argc >= 3) ? std::stoi(argv[2]) : 12345;
        }
        else if (mode == "client") {
            if (argc < 4) {
                std::cerr << "Uso: E2EE client <ip> <port>\n";
                return 1;
            }
            ip = argv[2];
            port = std::stoi(argv[3]);
        }
        else {
            std::cerr << "Modo no reconocido. Usa: server | client\n";
            return 1;
        }
    }

    // === Modo interactivo (sin argumentos) ===
    else {
        std::cout << "Modo (server/client): ";
        std::cin >> mode;

        if (mode == "server") {
            std::cout << "Puerto: ";
            std::cin >> port;
        }
        else if (mode == "client") {
            std::cout << "IP: ";
            std::cin >> ip;
            std::cout << "Puerto: ";
            std::cin >> port;
        }
        else {
            std::cerr << "Modo no reconocido.\n";
            return 1;
        }

        // Limpieza del buffer de entrada
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    // === Ejecuci�n del modo seleccionado ===
    if (mode == "server") runServer(port);
    else runClient(ip, port);

    return 0;
}

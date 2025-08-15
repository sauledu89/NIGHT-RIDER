/**
 * @file main.cpp
 * @brief Punto de entrada para la aplicación de chat cifrado RSA/AES.
 *
 * @details
 * Este archivo inicializa y ejecuta la aplicación en modo **servidor** o **cliente**,
 * dependiendo de los argumentos proporcionados por línea de comandos o por entrada del usuario.
 *
 * - En **modo servidor**:
 *    - Escucha conexiones en un puerto específico.
 *    - Realiza intercambio de claves públicas RSA.
 *    - Recibe la clave AES cifrada desde el cliente.
 *    - Entra en el bucle de chat bidireccional cifrado.
 *
 * - En **modo cliente**:
 *    - Se conecta a la IP y puerto del servidor.
 *    - Realiza el intercambio de claves públicas.
 *    - Envía la clave AES cifrada.
 *    - Inicia un bucle de chat cifrado con hilos.
 *
 * @note La lógica de red y cifrado está delegada en las clases `Server` y `Client`.
 * @warning Requiere que el puerto esté disponible en la red y que las bibliotecas estén correctamente configuradas.
 */

#include "Prerequisites.h"
#include "Server.h"
#include "Client.h"

 /**
  * @brief Ejecuta la lógica del servidor.
  *
  * @param port Puerto TCP donde el servidor escuchará.
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
 * @brief Ejecuta la lógica del cliente.
 *
 * @param ip Dirección IP del servidor al que conectarse.
 * @param port Puerto TCP del servidor.
 */
static void runClient(const std::string& ip, int port) {
    Client c(ip, port);
    if (!c.Connect()) {
        std::cerr << "[Main] No se pudo conectar.\n";
        return;
    }

    c.ExchangeKeys();          // Recibe/enviar claves RSA
    c.SendAESKeyEncrypted();   // Envía clave AES cifrada

    c.StartChatLoop();         // Chat en paralelo
}

/**
 * @brief Función principal de la aplicación.
 *
 * @param argc Número de argumentos desde línea de comandos.
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

    // === Ejecución del modo seleccionado ===
    if (mode == "server") runServer(port);
    else runClient(ip, port);

    return 0;
}

# 🔐 Chat TCP con Cifrado Híbrido RSA/AES

## 📌 Descripción
Este proyecto es parte de mi aprendizaje en **desarrollo de software para videojuegos** y redes.  
Implementa un **chat cliente-servidor** en **C++** usando **TCP** y un sistema de **cifrado híbrido**:

- 🔑 **RSA-2048** para intercambiar de forma segura la clave de sesión.
- 🔐 **AES-256-CBC** para cifrar los mensajes que se envían en tiempo real.

El objetivo principal es entender cómo funciona la comunicación segura y cómo podría aplicarse en contextos de videojuegos (por ejemplo, para proteger datos de jugadores o chats dentro de un juego).

---

## 🚀 Características
- Conexión TCP entre cliente y servidor.
- Generación de un par de claves RSA (2048 bits) por cada instancia.
- Intercambio de claves públicas.
- Envío de clave AES cifrada con la clave pública del receptor.
- Mensajes cifrados y descifrados en tiempo real con AES-256-CBC.
- Chat en paralelo (envío y recepción simultánea).
- Compatible con **Windows** (Winsock2 + OpenSSL).

---

## 📂 Estructura del Proyecto
├── Client.h / Client.cpp # Lógica del cliente
├── Server.h / Server.cpp # Lógica del servidor
├── NetworkHelper.h / .cpp # Funciones de red TCP
├── CryptoHelper.h / .cpp # Funciones de cifrado RSA/AES
├── Prerequisites.h # Includes y defines comunes
├── main.cpp # Punto de entrada
└── README.md # Documentación

yaml
Copiar
Editar

---

## 🛠️ Requisitos
- Compilador **C++17** o superior.
- **Windows** con soporte Winsock2.
- **OpenSSL** instalado y configurado.

Ejemplo de instalación con **vcpkg**:
```bash

<img width="1919" height="1074" alt="image" src="https://github.com/user-attachments/assets/f32038ce-2b16-4a9e-aed2-426472e78000" />

vcpkg install openssl:x64-windows

/**
 * @file Prerequisites.h
 * @brief Inclusiones y definiciones comunes para todo el proyecto.
 *
 * @details
 * Este archivo sirve como cabecera común para importar las bibliotecas estándar
 * necesarias en múltiples módulos del sistema. Reduce la redundancia de includes
 * y garantiza compatibilidad y portabilidad mínima.
 *
 * También define una macro útil para evitar conflictos comunes con macros de Windows.
 */

#pragma once  ///< Garantiza que este archivo se incluya solo una vez por unidad de compilación.

 /**
  * @def NOMINMAX
  * @brief Evita que Windows defina macros `min` y `max`.
  *
  * @details
  * Windows.h define `min` y `max` como macros, lo que puede interferir
  * con las funciones estándar `std::min` y `std::max` de C++.
  * Esta macro previene esa colisión.
  */
#define NOMINMAX

  // ===================== Bibliotecas estándar =====================

#include <string>       ///< Para manipulación de cadenas de texto (std::string).
#include <vector>       ///< Para uso de arreglos dinámicos (std::vector).
#include <iostream>     ///< Para entrada/salida estándar (std::cout, std::cin, etc.).
#include <cstring>      ///< Para funciones C de manipulación de memoria (memcpy, strcmp...).
#include <limits>       ///< Para obtener los límites de tipos numéricos (std::numeric_limits).
#include <thread>       ///< Para manejo de múltiples hilos de ejecución (std::thread).


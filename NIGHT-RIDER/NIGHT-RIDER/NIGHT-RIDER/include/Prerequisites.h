/**
 * @file Prerequisites.h
 * @brief Inclusiones y definiciones comunes para todo el proyecto.
 *
 * @details
 * Este archivo sirve como cabecera com�n para importar las bibliotecas est�ndar
 * necesarias en m�ltiples m�dulos del sistema. Reduce la redundancia de includes
 * y garantiza compatibilidad y portabilidad m�nima.
 *
 * Tambi�n define una macro �til para evitar conflictos comunes con macros de Windows.
 */

#pragma once  ///< Garantiza que este archivo se incluya solo una vez por unidad de compilaci�n.

 /**
  * @def NOMINMAX
  * @brief Evita que Windows defina macros `min` y `max`.
  *
  * @details
  * Windows.h define `min` y `max` como macros, lo que puede interferir
  * con las funciones est�ndar `std::min` y `std::max` de C++.
  * Esta macro previene esa colisi�n.
  */
#define NOMINMAX

  // ===================== Bibliotecas est�ndar =====================

#include <string>       ///< Para manipulaci�n de cadenas de texto (std::string).
#include <vector>       ///< Para uso de arreglos din�micos (std::vector).
#include <iostream>     ///< Para entrada/salida est�ndar (std::cout, std::cin, etc.).
#include <cstring>      ///< Para funciones C de manipulaci�n de memoria (memcpy, strcmp...).
#include <limits>       ///< Para obtener los l�mites de tipos num�ricos (std::numeric_limits).
#include <thread>       ///< Para manejo de m�ltiples hilos de ejecuci�n (std::thread).


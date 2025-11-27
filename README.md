# Introducción-a-la-Criptografia
IMPLEMENTACIÓN DE RSA Y CIFRADO HÍBRIDO EN PYTHON

Este proyecto es una implementación académica y funcional de un sistema criptográfico completo. Combina la creación manual del algoritmo RSA (desde la generación de números primos) con estándares modernos de cifrado simétrico (AES) para lograr un esquema de Cifrado Híbrido.

CARACTERÍSTICAS PRINCIPALES

El código se divide en cuatro módulos lógicos que operan secuencialmente:

Generación de Claves (Miller-Rabin)

Implementación del test de primalidad Miller-Rabin para certificar números primos con alta probabilidad.

Generación de dos números primos grandes (512 bits) usando entropía segura (secrets).

Cálculo de las claves pública (N, e) y privada (N, d) necesarias para RSA.

RSA con Padding (PKCS#1 v1.5)

Implementación manual de RSA.

Mecanismo de Padding: Antes de cifrar, se añade un relleno aleatorio no nulo a los mensajes. Esto evita ataques algebraicos y asegura que el mismo mensaje cifrado dos veces produzca textos cifrados diferentes.

Funciones para "agregar_padding" y "quitar_padding" trabajando a nivel de bytes.

Firma Digital

Uso de SHA-256 para generar un hash del mensaje original.

Cifrado del hash con la Clave Privada para crear una firma digital.

Verificación de la firma descifrándola con la Clave Pública y comparando los hashes.

Cifrado Híbrido de Archivos (Imágenes)
Simulación de un entorno real eficiente:

Cifrado Simétrico (AES-GCM): Se cifra una imagen ("Unal.png") usando una clave aleatoria de sesión AES-256. Esto es rápido y eficiente para datos pesados.

Intercambio de Claves (RSA): La clave AES se cifra usando la clave pública RSA (con padding).

Integridad: Se firma digitalmente la clave AES para garantizar su autenticidad.

Descifrado: El script demuestra el proceso inverso: recuperar la clave AES usando RSA privado y luego descifrar la imagen.

REQUISITOS

El proyecto utiliza librerías nativas de Python y algunas dependencias externas para operaciones matemáticas y AES.

Comando de instalación:
pip install sympy cryptography

secrets & random: Para generación de entropía.

sympy: Para el cálculo del inverso modular (mod_inverse).

cryptography: Para la implementación robusta de AES-GCM.

hashlib: Para SHA-256.

EJECUCIÓN

El script ejecuta automáticamente un flujo de prueba completo:

1) Genera primos y calcula claves.

2) Cifra y descifra un mensaje de texto corto.

3) Cifra una imagen local "Unal.png" y guarda los resultados binarios ("imagen_cifrada.bin").

4) Descifra los archivos y recupera la imagen original como "imagen_descifrada.png".

import RSA,Firmas_digitales
from RSA import *
from Firmas_digitales import * 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Funciones RSA base
def rsa_encrypt_int(m_int, e, N):
    return pow(m_int, e, N)

def rsa_decrypt_int(c_int, d, N):
    return pow(c_int, d, N)

# ====== LECTURA DE IMAGEN (Simulada o Real) ======
try:
    with open("Unal.png", "rb") as f:
        img_bytes = f.read()
except FileNotFoundError:
    # Creamos bytes falsos si no existe la imagen para que el código corra
    print("Aviso: 'Unal.png' no encontrada, usando datos de prueba.")
    img_bytes = os.urandom(1024)

# ====== GENERAR CLAVE AES ======
aes_key = os.urandom(32)   # AES-256 (32 bytes)
iv = os.urandom(12)        # IV GCM

# ====== CIFRAR IMAGEN CON AES-GCM ======
backend = default_backend()
encryptor = Cipher(
    algorithms.AES(aes_key),
    modes.GCM(iv),
    backend=backend
).encryptor()

cipher_img = encryptor.update(img_bytes) + encryptor.finalize()
tag = encryptor.tag

# ====== CIFRAR CLAVE AES CON TU RSA (AHORA CON PADDING) ======

# 1. Convertimos la clave AES (bytes) a un entero PADEADO
aes_key_padded_int = agregar_padding(aes_key, N)

# 2. Ciframos ese entero con RSA
cipher_key_int = rsa_encrypt_int(aes_key_padded_int, e, N)


# ==========================================
# FIRMA DIGITAL DE LA CLAVE AES
# ==========================================

# Hash de la clave AES
hash_aes = hashlib.sha256(aes_key).digest()
hash_aes_int = int.from_bytes(hash_aes, "big")

# Firma: hash^d mod N
firma_aes = pow(hash_aes_int, d, N)

# Guardamos la firma en base64 (mucho más presentable)
firma_aes_bytes = firma_aes.to_bytes(n_bytes, "big")
firma_aes_b64 = base64.b64encode(firma_aes_bytes).decode()

print("Firma AES (base64):", firma_aes_b64)


# Guardar todo
with open("imagen_cifrada.bin", "wb") as f:
    f.write(iv + tag + cipher_img)
with open("clave_cifrada_rsa.txt", "w") as f:
    f.write(str(cipher_key_int))

print("Imagen y clave AES cifradas correctamente.")

# ====== LEER ARCHIVO CIFRADO ======
with open("imagen_cifrada.bin", "rb") as f:
    data = f.read()
iv = data[:12]
tag = data[12:28]
cipher_img = data[28:]

# ====== DESCIFRAR CLAVE AES CON RSA ======
with open("clave_cifrada_rsa.txt") as f:
    cipher_key_int_leida = int(f.read())

# 1. Descifrado matemático RSA
aes_key_padded_recuperada = rsa_decrypt_int(cipher_key_int_leida, d, N)

# 2. Quitar padding para obtener la clave AES original de 32 bytes
try:
    aes_key_recuperada = quitar_padding(aes_key_padded_recuperada, N)
except ValueError as err:
    print(f"Error descifrando clave AES: {err}")
    aes_key_recuperada = b'\x00' * 32

# ====== DESCIFRAR IMAGEN ======
try:
    decryptor = Cipher(
        algorithms.AES(aes_key_recuperada),
        modes.GCM(iv, tag),
        backend=default_backend
    ).decryptor()

    img_dec = decryptor.update(cipher_img) + decryptor.finalize()

    with open("imagen_descifrada.png", "wb") as f:
        f.write(img_dec)
    print("Imagen descifrada correctamente (AES key recuperada vía RSA con Padding).")
except Exception as e:
    print(f"Error al descifrar imagen: {e}")


# ====== VERIFICAR FIRMA  ======
hash_verificado = verificar_firma(firma_aes_b64, e, N)

if hash_verificado == hash_aes_int:
    print("Firma AES VERIFICADA ✔️")
else:
    print("Firma AES inválida ❌")

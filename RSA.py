# ==========================================
# BLOQUE 1: Miller-Rabin y Generación de Primos
# ==========================================
import random
import secrets

def MillerRabin(N, k):
  if N == 2 or N == 3: return True
  if N % 2 == 0: return False

  t = N - 1
  s = 0
  while True:  # Descomponemos N de la forma 2^s * d + 1
    if t % 2 == 0:
      t = t // 2
      s += 1
    else:
      d = t
      break
  for i in range(k):
    a = random.randrange(2, N - 1)
    primo = False
    if 1 == pow(a, d, N):
      primo = True
    else:
      r = 0
      while r <= s and not primo:
        x = 2**r * d
        if (N - 1) == pow(a, x, N):
          primo = True
        r += 1
    if not primo:
      return False
  return True

# Generamos primos aleatorios
primos = []
while True:
  # 512 bits es aceptable para pruebas académicas,
  # pero para prod real se recomienda 1024 (para RSA-2048)
  p = secrets.randbits(512)
  p |= 1
  if MillerRabin(p, 40):
    primos.append(p)
    if len(primos) > 1:
      break
print("Primos generados.")

# ==========================================
# BLOQUE 2: Implementación RSA con PADDING
# ==========================================
from math import gcd
from sympy import mod_inverse
import secrets

p, q = primos[0], primos[1]
N = p * q # Número público
totn = (p - 1) * (q - 1) # Función totiente
e = 65537 # Estándar público

if gcd(e, totn) > 1:
    print("Es necesario generar un nuevo par de primos p,q")
else:
    d = mod_inverse(e, totn) # Cálculo del inverso privado

print(f"N = {N}\ne = {e}\nd = {d}")


# Estructura: 0x00 || 0x02 || Relleno_Aleatorio || 0x00 || Mensaje

def agregar_padding(mensaje_bytes, n_modulus):
    """
    Añade padding PKCS#1 v1.5 para cifrado.
    """
    k = (n_modulus.bit_length() + 7) // 8 # Longitud de N en bytes
    m_len = len(mensaje_bytes)

    # El mensaje no puede ser mayor que k - 11 bytes (seguridad)
    if m_len > k - 11:
        raise ValueError("El mensaje es muy largo para este tamaño de clave RSA")

    # Calcular longitud necesaria del relleno (Padding String)
    ps_len = k - m_len - 3

    # Generar bytes aleatorios no nulos
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.randbits(8)
        if b != 0: # El padding no puede contener ceros
            ps.append(b)


    bloque_padding = b'\x00\x02' + ps + b'\x00' + mensaje_bytes
    return int.from_bytes(bloque_padding, byteorder="big")

def quitar_padding(entero_descifrado, n_modulus):
    """
    Elimina el padding PKCS#1 v1.5 después de descifrar.
    """
    k = (n_modulus.bit_length() + 7) // 8
    # Convertimos el entero recuperado a bytes
    bloque_bytes = entero_descifrado.to_bytes(k, byteorder="big")

    if bloque_bytes[0] != 0 or bloque_bytes[1] != 2:
        raise ValueError("Error de decodificación: Padding inválido")

    # Buscar el separador 0x00 que divide el padding del mensaje
    # Empezamos a buscar desde el índice 2
    try:
        idx_separador = bloque_bytes.index(b'\x00', 2)
    except ValueError:
        raise ValueError("Error: No se encontró separador de mensaje")

    return bloque_bytes[idx_separador + 1:]


 #--- PRUEBA CON MENSAJE DE TEXTO ---

mensaje = "Este es un mensaje pequeño con fines académicos"
msg_bytes = mensaje.encode("utf-8")

print(f"\nMensaje original: {mensaje}")

# 1. Aplicamos Padding y convertimos a entero
m_padded_int = agregar_padding(msg_bytes, N)
print("Mensaje con padding: ", m_padded_int)

# 2. Ciframos (Raw RSA)
c = pow(m_padded_int, e, N)
print(f"Cifrado (int): {c}")

# 3. Desciframos (Raw RSA)
m2_padded_int = pow(c, d, N)

# 4. Quitamos Padding
try:
    msg_bytes_recuperado = quitar_padding(m2_padded_int, N)
    mensaje_recuperado = msg_bytes_recuperado.decode("utf-8")
    print(f"Mensaje Recuperado: {mensaje_recuperado}")
except Exception as err:
    print(f"Fallo al recuperar mensaje: {err}")

import RSA
from RSA import * 

# ==========================================
# VERIFICACIÓN FIRMA DIGITAL
# ==========================================


# ==========================================
# BLOQUE 3: Firma Digital (Hash)
# ==========================================

import hashlib
import base64
hash_bytes = hashlib.sha256(msg_bytes).digest() #( Hashing del mensaje)
hash_entero = int.from_bytes(hash_bytes,"big")

firma = pow(hash_entero, d, N) # Firma digital (se cifra el hashing con la clave privada del emisor)

n_bytes = (N.bit_length() + 7) // 8
fir_bytes = firma.to_bytes(n_bytes, "big") # Se pasa la firma a bytes

fir_b64 = base64.b64encode(fir_bytes).decode()
print("Firma en base 64: ", fir_b64) # Se convierte la firma en base 64


def verificar_firma(firma,e,N):
  firma = base64.b64decode(firma)
  firma = int.from_bytes(firma, byteorder="big")
  return pow(firma,e,N) # Desencriptamos la firma

v = verificar_firma(fir_b64,e,N)

if v == hash_entero:
    print(f"\nVerificación de firma (Hash coincide): {v == hash_entero}")
else:
    print("El Hash NO coincide")

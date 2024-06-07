"""
Este es un ejemplo de uso para encriptar y desencriptar mensajes usando la llave del cliente (K_C)
Se puede eliminar o ajustar según sus necesidades...
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Función para cifrar un mensaje
def encrypt_message(key, message):
    iv = os.urandom(16)  # Generar un vector de inicialización (IV) aleatorio
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) 
    encryptor = cipher.encryptor()
    
    # Añadir padding al mensaje para que su longitud sea múltiplo de 16 bytes
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()
    
    # Cifrar el mensaje
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv + encrypted_message  # Concatenar IV y mensaje cifrado

# Función para descifrar un mensaje
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:16]  # Extraer el IV del inicio del mensaje cifrado
    encrypted_message = encrypted_message[16:]  # El resto es el mensaje cifrado
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Descifrar el mensaje
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Eliminar el padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message

def read_client_key(directory):
    with open(directory, 'rb') as file:
        key = file.read()
    return key


client_key = read_client_key("./K_C.key")
client_key_AS = read_client_key("../AS/K_C.key")

# Mensaje a cifrar
message = b"hola"

# Cifrar el mensaje
encrypted_message = encrypt_message(client_key, message)
print("\nMensaje cifrado:", encrypted_message)

# Descifrar el mensaje con la llave que tiene AS que debería ser el mismo que el del cliente
decrypted_message = decrypt_message(client_key_AS, encrypted_message)
print("Mensaje descifrado:", decrypted_message.decode(), "\n")

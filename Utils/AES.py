from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Función para cifrar un mensaje
def aes_encrypt_message(key: bytes, message: bytes) -> bytes:
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
def aes_decrypt_message(key : bytes, encrypted_message : bytes) -> bytes:
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


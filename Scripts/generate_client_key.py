"""
Este archivo se encarga de crear una llave del cliente...

Cada usuario (cliente) tiene una clave secreta derivada de su contraseña. 
Esta clave secreta se almacena en el servidor de autenticación (AS) y se 
usa para cifrar y descifrar los mensajes entre el cliente y el AS.

"""

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

directories = {
    "AS": "../AS",
    "Client": "../Client"
}

def generate_client_secret(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def storage_client_key(directory, name, key):
    with open(os.path.join(directory, f"{name}.key"), 'wb') as file:
        file.write(key)

# Generar sal y clave secreta del cliente
salt = os.urandom(16)
client_password = "password1234"
client_secret = generate_client_secret(client_password, salt)

# Crear directorios si no existen y guardar clave y sal
for dir in directories.values():
    os.makedirs(dir, exist_ok=True)

storage_client_key(directories["Client"], "K_C", client_secret)
storage_client_key(directories["AS"], "K_C", client_secret)

print("Clave guardada exitosamente en cliente y servidor de autenticación.")

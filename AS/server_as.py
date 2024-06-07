import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

# Función para desencriptar la llave secreta compartida recibida del TGS usando su propia llave privada
def decrypt_key(message_data):
    with open('./as_private_key.key', 'rb') as f: # Lectura de su propia llave privada
        sa_private_key_data = f.read()
        sa_private_key = serialization.load_pem_private_key(
            sa_private_key_data,
            password=None,
            backend=default_backend()
        )

    decrypted_key = sa_private_key.decrypt( # Desencripta usando su llave privada
        message_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Llave secreta del servidor TGS:", decrypted_key.hex())
    return decrypted_key


def storage_key(secret_key):
    with open("./K_TGS.key", 'wb') as f:
        f.write(secret_key)


def handle_client(conn):
    with conn:
        message_type = conn.recv(1)  # Leer el primer byte para determinar el tipo de mensaje
        message_data = conn.recv(4096)

    if message_type == b'K':  # Mensaje de clave del servidor TGS
        print("Recibido mensaje de clave del servidor TGS")
        secret_key = decrypt_key(message_data)
        storage_key(secret_key)
        print("Llave secreta guardada en AS\n\n")
        
    elif message_type == b'C':  # Mensaje del cliente
        print("Recibido mensaje del cliente:", message_data.decode())

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 8000))
    server.listen()
    print("Servidor de Autenticación (SA) iniciado y esperando conexiones...\n")
    
    while True:
        conn, addr = server.accept()
        print(f"Conexión establecida desde {addr}")
        handle_client(conn)
        conn.close()

if __name__ == "__main__":
    start_server()

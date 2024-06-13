from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import socket, os, sys
sys.path.append('../Simulacion-Sistema-Kerberos')
from DTOS.dtos import *

# Función encargada de generar la llave secreta
def generate_aes_keys(directory, name):
    secret_key = os.urandom(24)  # 24 bytes = 192 bits

    with open(os.path.join(directory, f"{name}.key"), 'wb') as f:
        f.write(secret_key)

    print("\nLlave segreta generada: ", name, directory)

# Función para preparar la llave secreta generada del SS para que este se envíe al TGS usando la llave pública del TGS
def prepare_encrypted_key(tgs_key_path, as_key_path):
    # Lectura de la llave secreta
    with open(tgs_key_path, 'rb') as f:
        tgs_secret_key = f.read()

    print("Llave secreta del servidor TGS:", tgs_secret_key.hex())

    # Lectura de la llave pública del TGS
    with open(as_key_path, 'rb') as f:
        as_key_bytes  = f.read()

    # Cargar la clave pública del TGS
    as_public_key = serialization.load_pem_public_key(
        as_key_bytes,
        backend=default_backend()
    )

    # Cifrar la clave secreta usando la clave pública del TGS
    encrypted_secret_key = as_public_key.encrypt(
        tgs_secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_secret_key


def send_key_to_tgs(tgs_key_path, as_key_path):
    # Preparar la llave encriptada
    encrypted_key = prepare_encrypted_key(tgs_key_path, as_key_path)
    
    # Enviar la llave al servidor TGS
    server_address = ('localhost', 8001)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)
        ss_to_tgs = SS_To_TGS(encrypted_key)
        s.sendall(ss_to_tgs.to_bytes())
        print("Llave enviada al servidor TGS desde SS\n")


generate_aes_keys("../SS", "K_S")
send_key_to_tgs('../SS/K_S.key', '../TGS/tgs_public_key.pem')
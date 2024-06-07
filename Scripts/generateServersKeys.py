"""
Este archivo es el que generará las respectivas llaves públicas y privadas de cada servidor:
* AS
* TGS
* SS

Porque se usará la llave pública de x servidor para pasarle la llave secreta (privada) compartida 
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Diccionario de las ubicaciones de los servidores
directories = {
    "AS": "./AS",
    "TGS": "./TGS",
    "SS": "./SS",
    "Client": "./Client"
}


# Función para generar las llaves públicas y privadas de cada uno de los servidores con el algoritmo RSA
def generate_rsa_keys(directory, name):
    private_key_tgs = rsa.generate_private_key( 
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Obtener la clave pública a partir de la clave privada
    public_key_tgs = private_key_tgs.public_key()

    # Serializar la clave privada en formato PEM
    private_key_pem_tgs = private_key_tgs.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializar la clave pública en formato PEM
    public_key_pem_tgs = public_key_tgs.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(os.path.join(directory, f"{name}_private_key.key"), 'wb') as f:
        f.write(private_key_pem_tgs)

    with open(os.path.join(directory, f"{name}_public_key.pem"), 'wb') as f:
        f.write(public_key_pem_tgs)
    
    print("Key pair for", name)


for dir in directories.values():
    if not os.path.exists(dir):
        os.makedirs(dir)

# Generar llaves RSA para AS, TGS, SS y Cliente (llave pública y privada de cada servere)
generate_rsa_keys(directories["AS"], "as")
generate_rsa_keys(directories["TGS"], "tgs")
generate_rsa_keys(directories["SS"], "ss")
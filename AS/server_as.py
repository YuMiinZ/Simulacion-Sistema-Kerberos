import socket, json
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import sys
sys.path.append('../Simulacion-Sistema-Kerberos')
from DTOS.dtos import *
from Utils.AES import *
from Utils.utils import *

users = {
    1 : {
        "authorized": True
    },
    2 : {
        "authorized": False
    }
}

# Función para desencriptar la llave secreta compartida recibida del TGS usando su propia llave privada
def decrypt_key(message_data):
    with open('AS/as_private_key.key', 'rb') as f: # Lectura de su propia llave privada
        sa_private_key_data = f.read()
        sa_private_key = load_pem_private_key(
            sa_private_key_data,
            password=None,
            backend=default_backend()
        )

    decrypted_key = sa_private_key.decrypt( # Desencripta usando su llave privada
        message_data,
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    print("Llave secreta del servidor TGS:", decrypted_key.hex())
    return decrypted_key


def storage_key(secret_key):
    with open("AS/K_TGS.key", 'wb') as f:
        f.write(secret_key)


def handle_from_client(parsed_data, addr) -> str:
    user_id = parsed_data["user_id"]

    if not user_id in users:
        error = AS_To_Client()
        error.error = "desde as : Usuario no encontrado"
        return error.to_json()
    
    user = users[user_id]

    if not user["authorized"]:
        error = AS_To_Client()
        error.error = "desde as : Usuario no autorizado"
        return error.to_json()
    
    k_c = read_key("AS/K_C.key")

    client_tgs_key = create_session_key()

    msg_a = Msg_A(client_tgs_key)

    msg_a_encrypted = aes_encrypt_message(k_c, msg_a.to_bytes())

    client_id  = 1 # ??? ¿de dónde sale este valor?
    # el profe explico que es de una base de datos, pero en este caso se hardcodea

    validity = 5 # segundos

    msg_b = Msg_B(client_tgs_key, client_id, addr, validity)

    k_tgs = read_key("AS/K_TGS.key")

    msg_b_encrypted = aes_encrypt_message(k_tgs, msg_b.to_bytes())

    return AS_To_Client(msg_a_encrypted, msg_b_encrypted).to_json()


def handle_client(conn, addr):
    try:
        message_data = conn.recv(4096)
        message_data_decoded = message_data.decode()
        # convierte el json a un diccionario
        parsed_data = json.loads(message_data_decoded)

        if parsed_data["source"] == 'TGS':  # Mensaje de clave del servidor TGS
            tgs_to_as = TGS_To_AS.from_json(parsed_data)
            print("Recibido mensaje de clave del servidor TGS")
            secret_key = decrypt_key(tgs_to_as.encrypted_key)
            storage_key(secret_key)
            print("Llave secreta guardada en AS\n\n")
            return "llave secreta fue guardada en AS\n"
            
        elif parsed_data["source"] == 'client':  # Mensaje del cliente
            return handle_from_client(parsed_data, addr)

    except Exception as e:
        error = AS_To_Client()
        error.error = f"desde as : {e}"
        return error.to_json()
    
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 8000))
    server.listen()
    print("Servidor de Autenticación (SA) iniciado y esperando conexiones...\n")
    
    while True:
        conn, addr = server.accept()
        print(f"Conexión establecida desde {addr}")
        responseStr = handle_client(conn, addr)
        conn.sendall(responseStr.encode())
        conn.close()

if __name__ == "__main__":
    start_server()

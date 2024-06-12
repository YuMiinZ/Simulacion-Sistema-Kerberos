import socket, json, datetime as dt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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

def handle_from_client(parsed_data, addr) -> str:

    user_id = parsed_data["user_id"]

    if not user_id in users:
        return Error("Usuario no autorizado").to_json()
    
    k_c = read_key("AS/K_C.key")

    client_tgs_key = create_session_key()

    msg_a = Msg_A(client_tgs_key)

    msg_a_encrypted = aes_encrypt_message(k_c, msg_a.to_bytes())

    client_id  = 1 # ??? ¿de dónde sale este valor?

    ahora = dt.datetime.now()
    # esta hora que se suma agregarla a un configurable
    diferencia = dt.timedelta(hours=1)
    ttl = ahora + diferencia

    msg_b = Msg_B(client_tgs_key, client_id, addr, ttl)

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
            print("Recibido mensaje de clave del servidor TGS")
            secret_key = decrypt_key(message_data)
            storage_key(secret_key)
            print("Llave secreta guardada en AS\n\n")
            
        elif parsed_data["source"] == 'client':  # Mensaje del cliente
            return handle_from_client(parsed_data, addr)

    except Exception as e:
        print(f"Error al procesar el mensaje: {e}")
        return json.dumps({"error": str(e)})

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

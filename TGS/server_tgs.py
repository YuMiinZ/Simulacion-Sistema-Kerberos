import socket, os, json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

import sys
sys.path.append('../Simulacion-Sistema-Kerberos')
from DTOS.dtos import *
from Utils.AES import *
from Utils.utils import *

def decrypt_key(message_data):
    with open('./tgs_private_key.key', 'rb') as f:
        sa_private_key_data = f.read()
        sa_private_key = serialization.load_pem_private_key(
            sa_private_key_data,
            password=None,
            backend=default_backend()
        )

    decrypted_key = sa_private_key.decrypt(
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
    with open(os.path.join("./", f"K_TGS.key"), 'wb') as f:
        f.write(secret_key)

def handle_from_client(parsed_data, addr) -> str:
    print("Recibido mensaje del cliente:", parsed_data)

    client_to_tgs = Client_To_TGS.from_json(parsed_data)

    msg_b_encrypted = client_to_tgs.msg_c.msg_b

    k_tgs = read_key("TGS/K_TGS.key")

    # Desencriptar el mensaje B

    msg_b_decrypted = aes_decrypt_message(k_tgs, msg_b_encrypted)

    msg_b = Msg_B.from_json(msg_b_decrypted)

    # con msg_b.client_tgs_key desencripto el mensaje d

    msg_d_decrypted = aes_decrypt_message(msg_b.client_tgs_key, client_to_tgs.msg_d)

    msg_d = MsgD.from_json(msg_d_decrypted)

    # comparar id client en mensaje B Y D

    if msg_b.client_id != msg_d.client_id:
        return Error("ID de cliente no coincide en mensaje B y D").to_json()
    
    # !!! acá no sé de donde se extrae el client_id, addr y ttl
    msg_e = Msg_E(create_session_key(), msg_b.client_id, msg_b.address, msg_b.ttl)

    msg_f = Msg_F(msg_e.client_server_key)

    k_s = read_key("TGS/K_S.key") # ahorita no está en el folder pero algo así seria    

    msg_e_encrypted = aes_encrypt_message(k_s, msg_e.to_bytes())

    msg_f_encrypted = aes_encrypt_message(msg_b.client_tgs_key, msg_f.to_bytes())

    return TGS_To_Client(msg_e_encrypted, msg_f_encrypted).to_json()

def handle_client(conn, addr) -> str:
   
    try:

        message_data = conn.recv(4096)
        message_data_decoded = message_data.decode()
        # convierte el json a un diccionario
        parsed_data = json.loads(message_data_decoded)

        # TODO : adapt this
        if parsed_data["source"] == 'SS':  # Mensaje de clave del servidor SS

            print("Recibido mensaje de clave del servidor SS")
            secret_key = decrypt_key(parsed_data["encrypted_key"])
            storage_key(secret_key)
            print("Llave secreta guardada en TGS\n\n")

        elif parsed_data["source"] == 'client':  # Mensaje del cliente
            return handle_from_client(parsed_data, addr)

    except Exception as e:
        print(f"Error al procesar el mensaje: {e}")
        error = TGS_To_Client()
        error.error = f"from tgs : {e}"
        return error.to_json()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 8001))
    server.listen()
    print("Servidor Ticket Granting Service (TGS) iniciado y esperando conexiones...\n")
    
    while True:
        conn, addr = server.accept()
        print(f"Conexión establecida desde {addr}")
        responseStr = handle_client(conn, addr)
        conn.sendall(responseStr.encode())
        conn.close()

if __name__ == "__main__":
    start_server()

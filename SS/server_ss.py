import socket, sys
sys.path.append('../Simulacion-Sistema-Kerberos')
from DTOS.dtos import *
from Utils.AES import *
from Utils.utils import *

def handle_from_client(parsed_data) -> str:
    client_to_ss = Client_To_SS.from_json(parsed_data)

    msg_e_encrypted = client_to_ss.msg_e

    k_s = read_key("SS/K_S.key")

    msg_e_decrypted = aes_decrypt_message(k_s, msg_e_encrypted)

    msg_e = Msg_E.from_json(msg_e_decrypted)

    msg_g_encrypted = client_to_ss.msg_g

    msg_g_decrypted = aes_decrypt_message(msg_e.client_server_key, msg_g_encrypted)

    msg_g = Msg_G.from_json(msg_g_decrypted)

    if not msg_g.client_id == msg_e.client_id :
        ss_to_client = SS_To_Client()
        ss_to_client.error = "ID de cliente no coincide en mensaje G y E"
        return ss_to_client.to_json()
    
    msg_h = Msg_H(msg_e.ttl)

    msg_h_encrypted = aes_encrypt_message(msg_e.client_server_key, msg_h.to_bytes())

    return SS_To_Client(msg_h_encrypted).to_json()

def handle_service(parsed_data) -> str:
    request_service = Request_Service.from_json(parsed_data)
    response_service = Response_Service()
    if request_service.service_name == "sumas":
        response_service.resultado = "servicio de sumas"
    elif request_service.service_name == "restas":
        response_service.resultado = "servicio de restas"
    elif request_service.service_name == "multiplicaciones":
        response_service.resultado = "servicio de multiplicaciones"
    else:
        response_service.error = "Servicio no encontrado"
    return response_service.to_json()

def handle_client(conn) -> str:
    try:

        message_data = conn.recv(4096)
        message_data_decoded = message_data.decode()
        # convierte el json a un diccionario
        parsed_data = json.loads(message_data_decoded)

        if parsed_data["source"] == 'client':  # Mensaje del cliente
            return handle_from_client(parsed_data)
        elif parsed_data["source"] == 'servicio':
            return handle_service(parsed_data)

    except Exception as e:
        print(f"Error al procesar el mensaje: {e}")
        error = SS_To_Client()
        error.error = f"from tgs : {e}"
        return error.to_json()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 8002))
    server.listen()
    print("Servidor de Servidios (SS) iniciado y esperando conexiones...\n")
    
    while True:
        conn, addr = server.accept()
        print(f"Conexión establecida desde {addr}\n")
        responseStr = handle_client(conn, addr)
        conn.sendall(responseStr.encode())
        conn.close()

if __name__ == "__main__":
    start_server()

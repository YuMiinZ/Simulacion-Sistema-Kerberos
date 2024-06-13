"""
Este es un ejemplo de uso para encriptar y desencriptar mensajes usando la llave del cliente (K_C)
Se puede eliminar o ajustar según sus necesidades...
"""

import socket, datetime as dt
from datetime import datetime
import sys
sys.path.append('../Simulacion-Sistema-Kerberos')
from DTOS.dtos import *
from Utils.AES import *
from Utils.utils import *
from typing import Tuple

class Cliente:
    def __init__(self, cliente_id:int, ):
        self.client_id = cliente_id
        self.servers = {
            "as": ('localhost', 8000),
            "tgs": ('localhost', 8001),
            "ss": ('localhost', 8002)
        }

    def send_to_server(self, server_address, message:str):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(server_address)
            client_socket.sendall(message.encode())
            response = client_socket.recv(1024)
            return response.decode()
        
    def programa_1(self, user_id:int) -> AS_To_Client:
        # crea el primer mensaje hacia el AS
        client_to_as = Client_To_AS(user_id)
        # lo envía al servidor AS
        response_from_as = self.send_to_server(self.servers["as"], client_to_as.to_json())
        # parsea el response
        as_to_client = AS_To_Client.from_json(response_from_as)
        if as_to_client.error:
            raise Exception(as_to_client.error)
        
        return as_to_client
    
    def programa_2(self, as_to_client: AS_To_Client, service_name : str) -> Tuple[Client_To_TGS, datetime, Msg_A]:
         # acá utilizo el K_C.key para desencriptar la session key
        k_c = read_key("Client/K_C.key")
        # TODO : hacer un ejemplo donde k_c del cliente y del AS sean diferentes
        msg_a_decrypted = aes_decrypt_message(k_c, as_to_client.msg_a)
        msg_a = Msg_A.from_json(msg_a_decrypted)

        # ??? ¿qué se hace con el service_name?
        msg_c = MsgC(service_name, as_to_client.msg_b)

        ahora = dt.datetime.now()
        # esta hora que se suma agregarla a un configurable
        delta_una_hora = dt.timedelta(hours=1)
        nueva_fecha_hora = ahora + delta_una_hora

        # ??? ¿es correcto obtener el client_id de esta manera?
        msg_d = MsgD(self.client_id, nueva_fecha_hora)

        encrypted_message_d = aes_encrypt_message(msg_a.client_tgs_key, msg_d.to_bytes())

        return Client_To_TGS(msg_c, encrypted_message_d), nueva_fecha_hora, msg_a
    
    def programa_3(self, client_to_tgs: Client_To_TGS) -> TGS_To_Client:
        responseFromTGS = self.send_to_server(self.servers["tgs"], client_to_tgs.to_json())

        tgs_to_client = TGS_To_Client.from_json(responseFromTGS)

        if tgs_to_client.error:
            raise Exception(tgs_to_client.error)

        return tgs_to_client
    
    def programa_4 (self, msg_a: Msg_A, tgs_to_client: TGS_To_Client, nueva_fecha_hora: datetime) -> Tuple[Client_To_SS, Msg_F, Msg_G]:
        msg_f_decrypted = aes_decrypt_message(msg_a.client_tgs_key, tgs_to_client.msg_f)

        msg_f = Msg_F.from_json(msg_f_decrypted)

        msg_e_encrypted = tgs_to_client.msg_e

        # ??? no estoy seguro de este nueva_fecha_hora, de donde voy tomando el ttl y el client_id?
        # no sé si se guarda en una base de datos
        msg_g = Msg_G(self.client_id, nueva_fecha_hora)

        msg_g_encrypted = aes_encrypt_message(msg_f.client_server_key, msg_g.to_bytes())

        return Client_To_SS(msg_e_encrypted, msg_g_encrypted), msg_f, msg_g
    
    def programa_5 (self, client_to_server: Client_To_SS,) -> SS_To_Client :
        response_from_server = self.send_to_server(self.servers["ss"], client_to_server.to_json())

        ss_to_client = SS_To_Client.from_json(response_from_server)

        if ss_to_client.error:
            raise Exception(ss_to_client.error)
        
        return ss_to_client
    
    def programa_6 (self, msg_g: Msg_G, msg_f: Msg_F, ss_to_client : SS_To_Client) -> bool:

        msg_h_encrypted = aes_decrypt_message(msg_f.client_server_key, ss_to_client.msg_h)

        msg_h = Msg_H.from_json(msg_h_encrypted)

        # verifica que los ttl sean iguales
        # TODO: revisar porque g viene como datetime y h como stirng
        h_datetime = datetime.strptime(msg_h.ttl, '%Y-%m-%dT%H:%M:%S.%f')
        return msg_g.ttl == h_datetime
    
    def programa_7 (self, nombre_del_servicio : str) -> Response_Service:
        request_service = Request_Service(nombre_del_servicio)

        response_from_server = self.send_to_server(self.servers["ss"], request_service.to_json())

        response_service = Response_Service.from_json(response_from_server)

        if response_service.error:
            raise Exception(response_service.error)
        
        return response_service

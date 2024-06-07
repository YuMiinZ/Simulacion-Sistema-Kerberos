"""
Este es un archivo de prueba de la comunicación del cliente a x servidor...
Se puede eliminar el archivo
"""

import socket

def send_to_server(server_address, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(server_address)
        client_socket.sendall(message.encode())
        response = client_socket.recv(1024)
        print(f"Respuesta del servidor: {response.decode()}")

if __name__ == "__main__":
    # Enviar datos al servidor de autenticación (SA)
    print("Enviando al SA...")
    send_to_server(('localhost', 8000), "Mensaje para SA")

    # Enviar datos al servidor de otorgamiento de boletos (TGS)
    print("Enviando al TGS...")
    send_to_server(('localhost', 8001), "Mensaje para TGS")

    # Enviar datos al servidor de servicios (SS)
    print("Enviando al SS...")
    send_to_server(('localhost', 8002), "Mensaje para SS")

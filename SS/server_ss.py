import socket

def handle_client(conn):
    # Recibir datos del cliente
    data = conn.recv(4096)
    print(f"SS recibió: {data.decode()}")


    # Enviar respuesta al cliente
    conn.sendall(b'Recibido por SS\n\n')

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 8002))
    server.listen()
    print("Servidor de Servidios (SS) iniciado y esperando conexiones...\n")
    
    while True:
        conn, addr = server.accept()
        print(f"Conexión establecida desde {addr}\n")
        handle_client(conn)
        conn.close()

if __name__ == "__main__":
    start_server()

import sys
sys.path.append('Simulacion-Sistema-Kerberos')
from Client.client import Cliente

# acá llamar todos los servicios
print("\n Simulación de Kerberos")
while True :
    try:
        user_id = int(input("Ingrese su ID de usuario: "))

        service_name = input("Ingrese el nombre del servicio: ")

        password = input("Ingrese su contraseña: ")

        cliente = Cliente(user_id)

        as_to_client = cliente.programa_1(user_id)

        client_to_tgs, nueva_fecha_hora = cliente.programa_2(as_to_client, service_name)

        tgs_to_client = cliente.programa_3(client_to_tgs)

        client_to_server, msg_f, msg_g = cliente.programa_4(as_to_client.msg_a, tgs_to_client, nueva_fecha_hora)

        done = cliente.programa_5(client_to_server, msg_f, msg_g)


    except Exception as e:
        print(f"Error al procesar el mensaje: {e}")
    



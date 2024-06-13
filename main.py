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

        client_to_tgs, nueva_fecha_hora, msg_a = cliente.programa_2(as_to_client, service_name)

        tgs_to_client = cliente.programa_3(client_to_tgs)

        client_to_ss, msg_f, msg_g = cliente.programa_4(msg_a, tgs_to_client, nueva_fecha_hora)

        ss_to_client = cliente.programa_5(client_to_ss)

        puede_confiar = cliente.programa_6(msg_g, msg_f, ss_to_client)

        if not puede_confiar:
            raise Exception("No se puede confiar en el servidor de servicios")
        
        resultado = cliente.programa_7(service_name)

        print(f"Resultado del servicio {service_name}: {resultado.resultado}")
        # TODO : no terminar el ciclo
        # TODO : permiter seguir solicitando servicios y que valide el ttl del request

    except Exception as e:
        print(f"Error al procesar el mensaje: {e}")
    



from client import *
from Utils.AES import *
from Utils.utils import *

client_key = read_key("Client/K_C.key")
client_key_AS = read_key("AS/K_C.key")

# Mensaje a cifrar
message = b"hola"

# Cifrar el mensaje
encrypted_message = aes_encrypt_message(client_key, message)
print("\nMensaje cifrado:", encrypted_message)

# Descifrar el mensaje con la llave que tiene AS que debería ser el mismo que el del cliente
decrypted_message = aes_decrypt_message(client_key_AS, encrypted_message)
print("Mensaje descifrado:", decrypted_message.decode(), "\n")

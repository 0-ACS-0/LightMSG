import socket
import ssl

HOST = '192.168.1.38'  # o la IP donde corre tu servidor
PORT = 2002         # puerto del servidor

context = ssl.create_default_context()

# Si tu certificado es autofirmado, puede que tengas que saltarte la verificación del certificado:
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def tls_client():
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            print(f"Conectado a {HOST}:{PORT} con TLS")
            
            # Enviar el mensaje como bytes
            ch = 'a'

            try:
                ssock.sendall(ch.encode('utf-8'))
            except Exception as e:
                print(f"Error enviando datos: {e}")

            # Condición para detener el cliente

            while ch != 'q':
                ch = input("q para cerrar cliente: ")
            
            # Cierre limpio:
            try:
                ssock.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                print(f"Error durante shutdown: {e}")
            ssock.close()

if __name__ == "__main__":
    tls_client()

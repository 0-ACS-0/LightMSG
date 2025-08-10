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
            

            # Bucle de envío de datos:
            ch = 'a'
            while ch != "exit":
                ch = input("Texto a enviar ('exit' para salir): ")
                ssock.sendall(ch.encode('utf-8'))
            # Cierre limpio:
            try:
                ssock.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                print(f"Error durante shutdown: {e}")
            ssock.close()

if __name__ == "__main__":
    tls_client()

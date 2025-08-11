import socket, ssl, threading
import time

class ClientConn:
    def __init__(self, host : str, port : int) -> None:
        self.server_host = host
        self.server_port = port

        self.context = None

        self.client_sock = None
        self.client_ssock = None

        self.is_connected = False

        self.rcv_buffer = None
        self.rcv_thread = None
        self.snd_buffer = None


    def tls_client_connect(self) -> bool:
        try:
            # Creación del contexto TLS:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

            # Creación del socket TCP/IP:
            self.client_sock = socket.create_connection(
                (self.server_host, self.server_port))

            # Se aplica la capa TLS al socket TCP/IP:
            self.client_ssock = self.context.wrap_socket(
                self.client_sock, 
                server_hostname=self.server_host)

            # Flag de conexión activa y retorno:
            self.is_connected = True
            return True

        except Exception as e:
            # Error al realizar la conexión:
            print(f"[ClientConn - Err]: Error de conexión con el servidor: {e}")
            self.client_sock = None
            self.client_ssock = None
            self.is_connected = False
            return False

    def tls_client_disconnect(self) -> bool:
        try:
            # Desconexión controlada con el servidor:
            if self.client_ssock:
                self.client_ssock.shutdown(socket.SHUT_RDWR)
                self.client_ssock.close()
                self.client_ssock = None
            
            if self.client_sock:
                self.client_sock.close()
                self.client_sock = None
            
            self.is_connected = False
            return True

        except Exception as e:
            # Error al realizar la desconexión:
            print(f"[ClientConn - Err]: Error de desconexión con el servidor: {e}")
            return False
        pass

    def tls_client_send(self, msg : str) -> bool:
        # Comprobación de conexión activa:
        if not self.is_connected:
            print(f"[ClientConn - Err]: No se ha podido enviar el mensaje -> No hay conexión con el servidor!")
            return False
        
        try:
            # Envío del mensaje y guardado en el buffer de envío del cliente:
            self.snd_buffer = msg
            self.client_ssock.sendall(self.snd_buffer.encode('utf-8'))
            return True

        except Exception as e:
            # Error en el envío del mensaje:
            print(f"[ClientConn - Err]: Error al enviar datos, cerrando conexión...: {e}")
            self.tls_client_disconnect()
            return False


    def _tls_client_rcv_th(self, callback):
        # Bucle de lectura de datos:
        while self.is_connected:
            try:
                data = self.client_ssock.recv(4096)
                if data:
                    self.rcv_buffer = data.decode('utf-8')
                    callback(self.rcv_buffer)
                else:
                    print(f"[ClientConn - Warn]: El servidor ha cerrado la conexión, finalizando cliente...")
                    self.tls_client_disconnect()
                    break

            except Exception as e:
                print(f"[ClientConn - Err]: Error de recepción de datos, cerrando conexión...: {e}")
                self.tls_client_disconnect()
                break
        
    def tls_client_start_receiving(self, callback):
        self.rcv_thread = threading.Thread(
            target=self._tls_client_rcv_th,
            args=(callback,), 
            daemon=True)
        self.rcv_thread.start()


if __name__ == '__main__':
    ######                                                          ######
    ## FUNCIONES PRIVADAS DE PRUEBA (CHAT INTERACTIVO -> ECHO ACTIVADO) ##
    #####                                                           ######
    import readline
    import sys

    def receive_callback(rcv_buffer: str) -> None:
        # Almacenaje de la línea prompt del usuario:
        line = readline.get_line_buffer()

        # Borrado y escritura del mensaje recibido en esa misma línea:
        sys.stdout.write('\r')                      
        sys.stdout.write('\033[K')                  
        print(f"<< {rcv_buffer}")

        # Reescritura del prompt de usuario en la siguiente línea:                  
        sys.stdout.write(f">> {line}")    
        sys.stdout.flush()


    def send_loop() -> None:
        while True:
            # Prompt de entrada de texto:
            msg = input(">> ")

            # Caso desconexión forzada por el servidor:
            if not client.is_connected:
                return

            # Condición de salida de aplicación:
            if msg.lower() == "exit":
                return

            # Envío de mensaje al servidor:
            if not client.tls_client_send(msg):
                print(f"Error de envío de datos del cliente.")
                exit(1)

    ######                     ######
    ## Lógica del chat interactivo ##
    #####                      ######
    try:
        client = ClientConn('192.168.1.38', 2020)
        if not client.tls_client_connect():
            print(f"Error de conexión del cliente.")
            exit(1)
        
        client.tls_client_start_receiving(receive_callback)

        send_loop()

    except KeyboardInterrupt:
        print(f"Interrupción por teclado, cerrando conexión...")

    finally:
        if client.tls_client_disconnect():
            print(f"Cliente desconectado.")


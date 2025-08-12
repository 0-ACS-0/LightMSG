import socket, ssl, threading
import time

class ClientConn:
    def __init__(self, host : str, port : int, rcv_buf_len : int, snd_buf_len : int) -> None:
        # Atributos de conexión:
        self._server_host = host
        self._server_port = port
        self._context = None
        self._client_sock = None
        self._client_ssock = None
        self._is_connected = False

        # Atributos de datos:
        self._rcv_buffer = None
        self._rcv_buffer_len = rcv_buf_len
        self._rcv_thread = None
        self._snd_buffer = None
        self._snd_buffer_len = snd_buf_len


    def tls_client_connect(self) -> bool:
        try:
            # Creación del contexto TLS:
            self._context = ssl.create_default_context()
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_NONE

            # Creación del socket TCP/IP:
            self._client_sock = socket.create_connection(
                (self._server_host, self._server_port))

            # Se aplica la capa TLS al socket TCP/IP:
            self._client_ssock = self._context.wrap_socket(
                self._client_sock, 
                server_hostname=self._server_host)

            # Flag de conexión activa y retorno:
            self._is_connected = True

            print(f"[ClientConn - Info]: Conectado al servidor {self._server_host}:{self._server_port}!")
            return True

        except Exception as e:
            # Error al realizar la conexión:
            print(f"[ClientConn - Err]: Error de conexión con el servidor. -> {e}")
            self._client_sock = None
            self._client_ssock = None
            self._is_connected = False
            return False

    def tls_client_disconnect(self) -> bool:
        try:
            # Desconexión controlada con el servidor:
            self._is_connected = False

            if self._client_ssock:
                self._client_ssock.shutdown(socket.SHUT_RDWR)
                self._client_ssock.close()
                self._client_ssock = None
            
            if self._client_sock:
                self._client_sock.close()
                self._client_sock = None

            

            return True

        except Exception as e:
            # Error al realizar la desconexión:
            print(f"[ClientConn - Err]: Error de desconexión con el servidor. -> {e}")
            return False
        pass

    def tls_client_send(self, msg : str) -> bool:
        # Comprobación de conexión activa:
        if not self._is_connected:
            print(f"[ClientConn - Err]SEND: No se ha podido enviar el mensaje. -> No hay conexión con el servidor!")
            return False
        
        if len(msg) > self._snd_buffer_len:
            print(f"[ClientConn - Err]: No se ha podido enviar el mensaje. -> La longitud excede el máximo configurado!")
 
        try:
            # Envío del mensaje y guardado en el buffer de envío del cliente:
            self._snd_buffer = msg
            self._client_ssock.sendall(self._snd_buffer.encode('utf-8'))
            return True

        except Exception as e:
            # Error en el envío del mensaje:
            print(f"[ClientConn - Err]: Error al enviar datos, cerrando conexión...-> {e}")
            self.tls_client_disconnect()
            return False

    def tls_client_start_receiving(self, callback):
        self._rcv_thread = threading.Thread(
            target=self._tls_client_rcv_th,
            args=(callback,), 
            daemon=True)
        self._rcv_thread.start()

    def _tls_client_rcv_th(self, callback):
        # Bucle de lectura de datos:
        while self._is_connected:
            try:
                data = self._client_ssock.recv(self._rcv_buffer_len)
                if data:
                    self._rcv_buffer = data.decode('utf-8')
                    callback(self._rcv_buffer)
                else:
                    print(f"[ClientConn - Warn]: El servidor ha cerrado la conexión, finalizando cliente...")
                    self.tls_client_disconnect()
                    break

            except Exception as e:
                print(f"[ClientConn - Err]: Error de recepción de datos, cerrando conexión...-> {e}")
                self.tls_client_disconnect()
                break

    @property
    def rcv_buffer(self) -> str:
        return self._rcv_buffer

    @property
    def is_connected(self) -> bool:
        return self._is_connected


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
        client = ClientConn('10.228.210.160', 2020, 4096, 4096)
        if not client.tls_client_connect():
            exit(1)
        
        client.tls_client_start_receiving(receive_callback)

        send_loop()

    except KeyboardInterrupt:
        print(f"Interrupción por teclado, cerrando conexión...")

    finally:
        client.tls_client_disconnect()


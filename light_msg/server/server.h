#ifndef _SERVER_HEADER
#define _SERVER_HEADER


/* ---------------------------------------------------------------- */
/* ---- Librerías ------------------------------------------------- */
// Estándar:
#include <stdio.h>          // printf(), perror()
#include <errno.h>          // errno, perror()
#include <unistd.h>         // close(), read(), write()
#include <stdlib.h>         // malloc(), free(), exit()
#include <string.h>         // memset(), memcpy()
#include <stdint.h>         // uint8_t, int8_t
#include <stdbool.h>        // bool, true, false

// Hilos:
#include <pthread.h>        // pthread_t, pthread_create()

// Conectores (red):
#include <sys/socket.h>     // socket(), bind(), accept()
#include <netinet/in.h>     // struct sockaddr_in
#include <arpa/inet.h>      // inet_pton(), htons()
#include <fcntl.h>          // 0_NONBLOCK

// Eventos de notificación E/S:
#include <sys/epoll.h>      // epoll_create1(), epoll_ctl(), epoll_wait()

// OpenSSL (TLS):
#include <openssl/ssl.h>    // SSL, SSL_CTX, SSL_accept()
#include <openssl/err.h>    // ERR_print_errors_fp()

// Señales:
#include <signal.h>         // signal(), sigaction()

// Timer:
#include <time.h>           // time_t, cloc()
/* ---------------------------------------------------------------- */
/* ---------------------------------------------------------------- */



/* ---------------------------------------------------------------- */
/* ---- Definiciones/Macros --------------------------------------- */
#define DEFAULT_LOG_PATH                    "./logs"
#define DEFAULT_LOG_FILE                    "server"
#define DEFAULT_LOG_FILE_SIZE               10000000
#define DEFAULT_LOG_MIN_LVL                 0
#define MAX_LOG_ROUTE_LEN                   255
#define LOG_RESERVED_FORMAT_LEN             128
#define MAX_LOG_MSG_LEN                     512
#define LOG_LEVEL2STR(l)                    (l == 0) ? "[DEBUG]"    : \
                                            (l == 1) ? "[INFO]"     : \
                                            (l == 2) ? "[WARNING]"  : \
                                            "[ERROR]"

#define DEFAULT_CONN_CERT_PATH              "./certs/cert.pem"
#define DEFAULT_CONN_KEY_PATH               "./certs/key.pem"
#define DEFAULT_CONN_PORT                   4433
#define MIN_CONN_PORT_NUMBER                1000

#define DEFAULT_NUM_WORKERS                 8
#define DEFAULT_CLIENT_READ_BUFFER_SIZE     8192
#define DEFAULT_CLIENT_WRITE_BUFFER_SIZE    8192
#define DEFAULT_CLIENT_TIMEOUT              1200
#define DEFAULT_CLIENT_CAPACITY_BLOCK       10

#define MAX_EPOLL_EVENTS                    64
#define MAX_WORKER_CLIENT_NUM               200


/* ---------------------------------------------------------------- */
/* ---------------------------------------------------------------- */





/* ---------------------------------------------------------------- */
/* ---- Enumeraciones --------------------------------------------- */
// Estado del logger del servidor:
enum server_logger_state{
    LOGGER_ERR,
    LOGGER_OK,
};

// Niveles de gravedad del log:
enum server_logger_level{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERR
};

// Estado del cliente:
enum server_client_state{
    CLIENT_STATE_STANDBY,
    CLIENT_STATE_ESTABLISH,
    CLIENT_STATE_CLOSING,
    CLIENT_STATE_CLOSED
};

// Estado del servidor:
enum server_state {
    SERVER_STATE_INITIALIZED,     
    SERVER_STATE_RUNNING,         
    SERVER_STATE_STOPPING,        
    SERVER_STATE_STOPPED,         
    SERVER_STATE_DESTROYED        
};

/* ---------------------------------------------------------------- */
/* ---------------------------------------------------------------- */




/* ---------------------------------------------------------------- */
/* ---- Estructuras de datos -------------------------------------- */
// Estructura con la ruta al directorio de logs y fichero:
struct server_logger{
    // Ruta al directorio y archivo de logs:
    char * log_path;
    char * log_file;

    // Índice de fichero logger:
    size_t log_index;

    // Bloqueo para evitar escritura al log de manera concurrente:
    pthread_mutex_t log_lock;

    // Descriptor del archivo log:
    FILE * log_fd;

    // Nivel mínimo del logger:
    enum server_logger_level log_min_lvl;

    // Control de tamaño de los archivos:
    size_t log_max_size;
    size_t log_current_size;

    // Estado del loger:
    enum server_logger_state state;
};

// Estructura de datos de configuración del logger:
struct server_logger_conf{
    // Rutas configuradas:
    char * log_path;
    char * log_file;

    // Nivel mínimo configurado:
    enum server_logger_level log_min_lvl;

    // Tamaño máximo de fichero configurado:
    size_t log_max_size;
};

// Estructura con los datos de conexión del servidor:
struct server_conn{
    // Datos de conexión del servidor:
    int fd;
    int port;
    struct sockaddr_in addr;

    // Contexto de la capa TLS:
    const SSL_METHOD * ssl_method;
    SSL_CTX * ssl_ctx;

    // Ruta al certificado y clave del servidor para TLS:
    char * cert_path;
    char * key_path; 
};

// Estructura de configuración de la estructura de conexión del servidor:
struct server_conn_conf{
    // Datos de conexión:
    int port;

    // Rutas a certificado y clave del servidor:
    char * cert_path;
    char * key_path;
};

// Estructura con los datos del cliente conectado:
struct server_client_conn{
    // Datos de conexión del cliente conectado:
    int fd;
    struct sockaddr_in addr;

    // Capa TLS del cliente conectado:
    SSL * ssl;

    // Buffer de datos del cliente (lecutra/escritura):
    char * read_buffer;
    pthread_mutex_t * read_lock;
    size_t read_len;
    size_t read_off;

    char * write_buffer;
    pthread_mutex_t * write_lock;
    size_t write_len;
    size_t write_off;

    // Estado del cliente:
    enum server_client_state state;

    // Timeout:
    time_t last_action_time;
};

// Estructura con el contexto de trabajo para el hilo de gestión de clientes.
struct server_client_ctx{
    struct server_worker * server_worker;
    struct server_logger * server_logger;
    enum server_state * server_state;
    size_t thread_index;
};

// Estructura con los datos de los hilos:
struct server_worker{
    // Número de hilos:
    int num_workers;

    // Referencia a cada hilo y eventos de e/s:
    pthread_mutex_t realloc_lock;
    pthread_t main_thread;
    pthread_t * thread;
    int * epoll_fd;

    // Referencia a los clientes conectados por hilo:
    struct server_client_conn ** client;
    struct server_client_ctx * client_ctx;
    size_t * client_count;
    size_t * client_capacity;
    size_t client_capacity_block;

    // Tamaño de buffers y timeout:
    size_t client_read_buffer_size;
    size_t client_write_buffer_size;
    time_t client_timeout;

    // Funciones a realizar sobre los datos de los clientes:
    void (*on_client_connect)(void * args);
    void (*on_client_disconnect)(void * args);
    void (*on_client_timeout)(void * args);
    void (*on_client_rcv)(void * args);
    void (*on_client_snd)(void * args);
};

// Estructura con los datos de configuración de los hilos:
struct server_worker_conf{
    // Configuración de número de hilos:
    int num_workers;

    // Configuración del bloque de capacidad mínimo de clientes por hilo:
    size_t client_capacity_block;

    // Configuración de tamaño de buffers y timeout:
    size_t client_read_buffer_size;
    size_t client_write_buffer_size;
    time_t client_timeout;

    // Configuración de las funciones de procesado de datos de los clientes:
    void (*on_client_connect)(void * args);
    void (*on_client_disconnect)(void * args);
    void (*on_client_timeout)(void * args);
    void (*on_client_rcv)(void * args);
    void (*on_client_snd)(void * args);
};

// Estructura global del servidor:
struct server{
    struct server_logger logger;
    struct server_conn conn;
    struct server_worker worker;

    enum server_state state;
};

// Estructura global de configuración del servidor:
struct server_conf{
    struct server_logger_conf logger_conf;
    struct server_conn_conf conn_conf;
    struct server_worker_conf worker_conf;
};
/* ---------------------------------------------------------------- */
/* ---------------------------------------------------------------- */




/* ---------------------------------------------------------------- */
/* ---- Tipos de datos -------------------------------------------- */
typedef struct server server_t;
typedef server_t * server_pt;
typedef struct server_conf server_conf_t;
typedef server_conf_t * server_conf_pt;
/* ---------------------------------------------------------------- */
/* ---------------------------------------------------------------- */




/* ---------------------------------------------------------------- */
/* ---- Prototipo de las funciones -------------------------------- */
server_pt server_init(server_conf_pt server_conf);
bool server_open(server_pt server);
bool server_close(server_pt server);
bool server_deinit(server_pt * server);
bool server_broadcast(server_pt server, const char * data, size_t len);
/* ---------------------------------------------------------------- */
/* ---------------------------------------------------------------- */





#endif
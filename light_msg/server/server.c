#include "server.h"
#include <netinet/in.h>
#include <string.h>


/* -------------------------------------------------------------------------------------------------------------------------------- */
/* ---- Prototipo de funciones estáticas ------------------------------------------------------------------------------------------ */
// ==== Logger ==== //
static bool _server_logger_init(struct server_logger * logger);
static void _server_logger_deinit(struct server_logger * logger);
static void _server_logger_conf(struct server_logger * logger, struct server_logger_conf * logger_conf);
static void _server_log(struct server_logger * logger, enum server_logger_level log_level, const char * log_msg_fmt, ...);

// ==== Conn ==== //
static void _server_conn_conf(struct server_conn * conn, struct server_conn_conf * conn_conf);
static bool _server_conn_init(struct server_conn * conn);
static void _server_conn_deinit(struct server_conn * conn);

// ==== Worker ==== //
static bool _server_worker_conf(struct server_worker * worker, struct server_worker_conf * worker_conf, struct server_logger * server_logger, enum server_state * server_state);
static void _server_worker_deinit(struct server_worker * worker);
static bool _server_worker_launch(server_pt server);
static void _server_worker_wait_land(struct server_worker * worker);
/* -------------------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------------------- */




/* -------------------------------------------------------------------------------------------------------------------------------- */
/* ---- Implementación de funciones públicas -------------------------------------------------------------------------------------- */
/*
    @brief Función para inicializar el servidor.

    @param server_conf_pt server_conf: Estructura con toda la configuración del servidor.

    @retval server_pt: Referencia al servidor.
*/
server_pt server_init(server_conf_pt server_conf){
    // Validación de estructura de configuración válida:
    if (!server_conf) return NULL;

    // Reserva de memoria para la estructura global del servidor:
    server_pt server = (server_pt)malloc(sizeof(server_t));
    if (!server) return NULL;

    bool err = false;

    // Inicialización y configuración del logger del servidor:
    err |= _server_logger_init(&server->logger);
    _server_logger_conf(&server->logger, &server_conf->logger_conf);

    // Inicialización y configuración de datos de conexión del servidor:
    _server_conn_conf(&server->conn, &server_conf->conn_conf);
    err |= _server_conn_init(&server->conn);

    // Inicialización y configuración del worker del servidor:
    err |= _server_worker_conf(&server->worker, &server_conf->worker_conf, &server->logger, &server->state);

    // Comprobación de errores de inicialización internos:
    if (err){
        _server_logger_deinit(&server->logger);
        _server_conn_deinit(&server->conn);
        free(server);
        return NULL;
    }

    // Estado de servidor inicializado:
    _server_log(&server->logger, LOG_DEBUG, "Servidor inicializado correctamente en (%p).", server);
    server->state = SERVER_STATE_INITIALIZED;
    return server;
}

/*
    @brief Función para comenzar los hilos de gestión del servidor, aceptando conexiones.

    @param server_pt server: Referencia al servidor (debe estar previamente inicializado).

    @retval true: Ha ocurrido un error.
    @retval false: No han ocurrido errores.
*/
bool server_open(server_pt server){
    // Comprobación de servidor válido:
    if (!server) return true;
    if ((server->state != SERVER_STATE_INITIALIZED) && (server->state != SERVER_STATE_STOPPED)) return true;

    // Lanzamiento de hilos de recepción y gestión de clientes:
    server->state = SERVER_STATE_RUNNING;
    if(_server_worker_launch(server)){
        _server_log(&server->logger, LOG_WARN, "No ha sido posible abrir correctamente el servidor.");
        server->state = SERVER_STATE_INITIALIZED;
        return true;
    }

    _server_log(&server->logger, LOG_INFO, "Servidor abierto correctamente.");
    return false;
}

/*
    @brief Función para finalizar los hilos de gestión del servidor, cerrando conexiones.

    @param server_pt server: Referencia al servidor (debe estar previamente inicializado).

    @retval true: Ha ocurrido un error.
    @retval false: No han ocurrido errores.
*/
bool server_close(server_pt server){
    // Comprobación de servidor válido:
    if (!server) return true;
    if (server->state != SERVER_STATE_RUNNING) return true;

    // Detención de los hilos:
    server->state = SERVER_STATE_STOPPING;
    _server_log(&server->logger, LOG_DEBUG, "Cerrando el servidor...");
    _server_worker_wait_land(&server->worker);
    _server_log(&server->logger, LOG_INFO, "Servidor cerrado correctamente.");
    server->state = SERVER_STATE_STOPPED;

    return false;
}

/*
    @brief Función para liberar la memoria del servidor por completo.
    @note El servidor debe estar completamente detenido para liberar la memoria, evitando así fugas
    en hilos que no hayan terminado su ejecución.

    @param server_pt server: Referencia al servidor.

    @retval true: Ha ocurrido un error.
    @retval false: No han ocurrido errores.
*/
bool server_deinit(server_pt * server){
    // Comprobación de servidor válido:
    if ((!server) || (!(*server))) return true;
    if (((*server)->state != SERVER_STATE_STOPPED) && ((*server)->state != SERVER_STATE_INITIALIZED)) return true;

    _server_log(&(*server)->logger, LOG_INFO, "Servidor desinicializado.");

    // Desinicialización del worker:
    _server_worker_deinit(&(*server)->worker);

    // Desinicialización de datos de conexión del servidor:
    _server_conn_deinit(&(*server)->conn);

    // Desinicialización del logger del servidor:
    _server_logger_deinit(&(*server)->logger);

    // Liberación de memoria del servidor:
    free(*server);
    *server = NULL;

    return false;
}
/* -------------------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------------------- */




/* -------------------------------------------------------------------------------------------------------------------------------- */
/* ---- Implementación de funciones estáticas ------------------------------------------------------------------------------------- */

// ================================================================ //
// Logger del servidor.
// ================================================================ //
static void __server_log_genname(struct server_logger * logger, char * buffer, size_t buffer_len);
static void __server_log_rotfile(struct server_logger * logger);

/*
    @brief Función para inicializara con valores por defecto el logger del servidor.

    @param struct server_logger * logger: Referencia al logger del servidor.

    @retval true: Error en la inicialización del logger.
    @retval false: No han ocurrido errores.
*/
static bool _server_logger_init(struct server_logger * logger){
    // Comprobación de referencia a logger válida:
    if (!logger) return true;

    // Inicialización de valores por defecto del logger:
    logger->log_fd = NULL;
    logger->log_index = 0;
    logger->log_current_size = 0;
    logger->log_max_size = DEFAULT_LOG_FILE_SIZE;
    logger->log_min_lvl = DEFAULT_LOG_MIN_LVL;
    logger->log_path = strdup(DEFAULT_LOG_PATH);
    logger->log_file = strdup(DEFAULT_LOG_FILE);
    if (pthread_mutex_init(&logger->log_lock, NULL) != 0){
        logger->state = LOGGER_ERR;
        return true;
    }

    logger->state = LOGGER_OK;
    return false;
}

/*
    @brief Función para deinicializar el logger del servidor de manera segura.

    @param sturct server_logger * logger: Referencia al logger del servidor.

    @retval None
*/
static void _server_logger_deinit(struct server_logger * logger){
    // Comprobación de referencia válida:
    if (!logger) return;

    // Si hay un fichero abierto, se cierra:
    if (logger->log_fd){
        fclose(logger->log_fd);
        logger->log_fd = NULL;
    }

    // Se libera la memoria de la ruta y nombre de ficheros log:
    if (logger->log_path){
        free(logger->log_path);
        logger->log_path = NULL;
    }

    if (logger->log_file){
        free(logger->log_file);
        logger->log_file = NULL;
    }

    // Se libera el mutex:
    pthread_mutex_destroy(&logger->log_lock);

    // Se establece el estado de error para evitar su uso:
    logger->state = LOGGER_ERR;
}

/*
    @brief Función para configurar los parámetros básicos del logger del servidor.
    @note: Pensada para ser usada tras inicializar el logger!

    @param struct server_logger * logger: Referencia al logger del servidor.
    @param struct server_logger_conf logger_conf: Estructura de datos con la configuración deseada.

    @retval None.
*/
static void _server_logger_conf(struct server_logger * logger, struct server_logger_conf * logger_conf){
    // Comprobación de estructuras válidas:
    if (!logger) return;
    if (!logger_conf) return;

    // Estado válido para configuración:
    if (logger->state == LOGGER_ERR) return;

    // Lock para evitar problemas:
    pthread_mutex_lock(&logger->log_lock);

    // Configuración de miembros configurables:
    if (logger_conf->log_path){
        if (logger->log_path) free(logger->log_path);
        logger->log_path = NULL;
        logger->log_path = strdup(logger_conf->log_path);
    }
    if (logger_conf->log_file){
        if (logger->log_file) free(logger->log_file);
        logger->log_file = NULL;
        logger->log_file = strdup(logger_conf->log_file);
    } 
    if (logger_conf->log_max_size) logger->log_max_size = logger_conf->log_max_size;
    logger->log_min_lvl = logger_conf->log_min_lvl;

    // Liberación del lock:
    pthread_mutex_unlock(&logger->log_lock);
}


/*
    @brief Función para registrar mensajes y datos en archivos de log dedicados al servidor.

    @param struct server_logger * logger: Referencia al logger del servidor.
    @param enum server_logger_level log_level: Nivel al que se escribirá el log.
    @param const char * log_msg_fmt: Mensaje y formato del que se desea hacer loggin.
    @param ...: Número variable de argumentos, usados en conjunto con log_msg_fmt.

    @retval None.
*/
static void _server_log(struct server_logger * logger, enum server_logger_level log_level, const char * log_msg_fmt, ...){
    // Si el logger es inválido se ignora la llamada:
    if (!logger) return;
    if (logger->state != LOGGER_OK) return;

    // Si alguna ruta no es válida se ignora la llamada:
    if (!logger->log_path) return;
    if (!logger->log_file) return;

    // Si el nivel es inferior al mínimo se ignora la llamada:
    if (log_level < logger->log_min_lvl) return;

    // Si el puntero al mensaje de log es inválido se ignora la llamada:
    if (!log_msg_fmt) return;

    // Mensaje formateado:
    char log_msg[MAX_LOG_MSG_LEN];
    va_list args;
    va_start(args, log_msg_fmt);
    vsnprintf(log_msg, sizeof(log_msg), log_msg_fmt, args);
    va_end(args);

    // Si la longitud excede un máximo se ignora la llamada:
    if (strlen(log_msg) > MAX_LOG_MSG_LEN - LOG_RESERVED_FORMAT_LEN) return;

    // Comienzo de operación -> Lock:
    pthread_mutex_lock(&logger->log_lock);

    // Mensaje completo (fecha, hora, nivel y mensaje):
    char timestr[32];
    time_t actual_time = time(NULL);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&actual_time));

    char fullmsg[LOG_RESERVED_FORMAT_LEN + MAX_LOG_MSG_LEN];
    snprintf(fullmsg, sizeof(fullmsg), "[%s]%s: %s", timestr, LOG_LEVEL2STR(log_level), log_msg);

    // Caso de primera escritura del servidor al log:
    if (!logger->log_fd){
        char fullpath[MAX_LOG_ROUTE_LEN];
        __server_log_genname(logger, fullpath, sizeof(fullpath));
        logger->log_fd = fopen(fullpath, "a");
        if (!logger->log_fd){
            pthread_mutex_unlock(&logger->log_lock);
            return;
        }
    }

    // Caso archivo > 10MB (rotación):
    logger->log_current_size += strlen(fullmsg);
    if (logger->log_current_size > logger->log_max_size){
        __server_log_rotfile(logger);
        if (!logger->log_fd){
            pthread_mutex_unlock(&logger->log_lock);
            return;
        }
    }

    // Escritura en archivo log:
    fprintf(logger->log_fd, "%s\n", fullmsg);
    fflush(logger->log_fd);

    // Fin de operación -> Unlock:
    pthread_mutex_unlock(&logger->log_lock);
}

/*
    @brief Función dedicada al logger del servidor para formatear el nombre del archivo del siguiente modo:
    -> ruta/archivo_XXXXYYZZRRRRRR_I.log /  [XXXX]: Año [YY]: Mes [ZZ]: Día 
                                            [I]: Índice de archivo

    @param struct server_logger * logger: Referencia al logger del servidor.
    @param char * buffer: Referencia al buffer que almacenará la ruta completa.
    @param size_t buffer_len: Longitud máxima de la ruta.

    @retval None.
*/
static void __server_log_genname(struct server_logger * logger, char * buffer, size_t buffer_len){
    // Lectura de la fecha local:
    time_t localdate = time(NULL);
    struct tm * tm_info = localtime(&localdate);

    // Bucle para evitar colisiones en los nombres de archivos:
    size_t attempt = 0;
    const size_t max_attempts = 10000;
    while (attempt < max_attempts){
        // Escritura del nombre completo en el buffer:
        snprintf(buffer, buffer_len, 
        "%s/%s_%04d%02d%02d_%ld.log",
        logger->log_path,
        logger->log_file,
        tm_info->tm_year + 1900,
        tm_info->tm_mon + 1,
        tm_info->tm_mday,
        logger->log_index
        ); 

        // Comprobación de existencia del nombre:
        if (access(buffer, F_OK) != 0) return;
        logger->log_index++;
        attempt++;
    }

    // En caso de error, se establece un buffer nulo:
    memset(buffer, '\0', buffer_len);
}

/*
    @brief Función para rotar de archivo log abierto de manera segura, incrementando en 1 el índice del archivo.

    @param struct server_logger * logger: Referencia al logger del servidor.

    @retval None.
*/
static void __server_log_rotfile(struct server_logger * logger){
    // Se cierra el archivo anterior (si está abierto):
    if (logger->log_fd) fclose(logger->log_fd);

    // Se incrementa el índice de archivo y se reinicia el contador de tamaño de archivo:
    logger->log_index++;
    logger->log_current_size = 0;

    // Se abre el archivo de log y se almacena su referencia:
    char fullpath[MAX_LOG_ROUTE_LEN];
    __server_log_genname(logger, fullpath, sizeof(fullpath));
    logger->log_fd = fopen(fullpath, "a");
}

// ================================================================ //
// Conexión del servidor.
// ================================================================ //
/*
    @brief Función para configurar puerto y rutas a certificado y clave del servidor.
    @note Obligatoria antes de _server_conn_init().

    @param struct server_conn * conn: Referencia a la estructura de conexión del servidor.
    @param struct server_conn_conf * conn_conf: Referencia a la estructura de configuración de conexión.

    @retval None.
*/
static void _server_conn_conf(struct server_conn * conn, struct server_conn_conf * conn_conf){
    // Comprobación de estructuras válidas:
    if (!conn) return;
    if (!conn_conf) return;

    // Asignación del puerto del servidor configurado (o puerto por defecto):
    conn->port = (conn_conf->port >= MIN_CONN_PORT_NUMBER) ? conn_conf->port : DEFAULT_CONN_PORT;

    // Asignación de las rutas completas hacia el certificad y clave privada del servidor:
    if (conn_conf->cert_path)
        conn->cert_path = strdup(conn_conf->cert_path);
    else 
        conn->cert_path = strdup(DEFAULT_CONN_CERT_PATH);


    if (conn_conf->key_path)
        conn->key_path = strdup(conn_conf->key_path);
    else
        conn->key_path = strdup(DEFAULT_CONN_KEY_PATH);
}

/*
    @brief Función para inicializar el servidor (socket tcp/ip y capa tls).

    @param struct server_conn * conn: Estructura de datos de la conexión del servidor.

    @retval true: Error en la inicialización del servidor.
    @retval false: No han ocurrido errores.
*/
static bool _server_conn_init(struct server_conn * conn){
    // Comprobación de etructura de conexión válida:
    if (!conn) return true;
    if (conn->port < MIN_CONN_PORT_NUMBER) return true;
    if (!conn->cert_path) return true;
    if (!conn->key_path) return true;

    // Creación del socket TCP:
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd < 0) return true;

    // Socket en modo no bloqueante:
    int flags = fcntl(conn->fd, F_GETFL, 0);
    if (flags < 0) return true;
    if (fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK) < 0) return true;

    // Reusar dirección (evita esperar la liberación del puerto cuando el servidor se reinicia):
    int opt = 1;
    setsockopt(conn->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Asigna la estructura de conexión con los datos de dirección y puerto:
    memset(&conn->addr, 0, sizeof(conn->addr));
    conn->addr.sin_addr.s_addr = INADDR_ANY;
    conn->addr.sin_port = htons(conn->port);
    conn->addr.sin_family = AF_INET;

    // Se une la estructura de conexión con el socket:
    if(bind(conn->fd, (struct sockaddr *)&conn->addr, sizeof(conn->addr)) < 0){
        close(conn->fd);
        return true;
    }

    // Se establece el socket en escucha:
    if(listen(conn->fd, SOMAXCONN) < 0){
        close(conn->fd);
        return true;
    }

    // Inicialización de la capa TLS:
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Establecimiento del método de cifrado y creación del contexto del servidor:
    conn->ssl_method = TLS_server_method();
    conn->ssl_ctx = SSL_CTX_new(conn->ssl_method);
    if (!conn->ssl_ctx){
        close(conn->fd);
        return true;
    }

    // Carga de certificado y clave:
    if (SSL_CTX_use_certificate_file(conn->ssl_ctx, conn->cert_path, SSL_FILETYPE_PEM) <= 0 ||
    SSL_CTX_use_PrivateKey_file(conn->ssl_ctx, conn->key_path, SSL_FILETYPE_PEM) <= 0 ||
    !SSL_CTX_check_private_key(conn->ssl_ctx)){
        SSL_CTX_free(conn->ssl_ctx);
        close(conn->fd);
        return true;
    }

    return false;
}

/*
    @brief Función para deinicializar la estructura de conexión del servidor y liberar memoria reservada en la estructura.

    @param struct server_conn * conn: Referencia a la estructura de conexión del servidor.

    @retval None.
*/
static void _server_conn_deinit(struct server_conn * conn){
    // Comprobación de estructura válida:
    if (!conn) return;

    // Liberación del contexto tls y cierre del socket:
    if (conn->ssl_ctx) SSL_CTX_free(conn->ssl_ctx);
    if (conn->fd >= 0) close(conn->fd);

    // Liberación de memoria de las rutas de certificado y clave:
    if (conn->cert_path){
        free(conn->cert_path);
        conn->cert_path = NULL;
    }
    if (conn->key_path){
        free(conn->key_path);
        conn->key_path = NULL;
    }  
}

// ================================================================ //
// Worker.
// ================================================================ //
static void * __server_main_worker(void * arg);
static void * __server_cli_worker(void * arg);

/*
    @brief Función para crear y configurar parámetros básicos de los hilos de trabajo del servidor.
    @note Esta función sirve como inicializadora de los worker y sus miembros, su uso es obligatorio.

    @param struct server_workers * workers: Referencia a la estructura de datos de los hilos del servidor.
    @param struct server_workers * workers_conf: Referencia a los datos de configuración.

    @retval true: Error en la inicialización de workers del servidor.
    @retval false: No han ocurrido errores.
*/
static bool _server_worker_conf(struct server_worker * worker, struct server_worker_conf * worker_conf, struct server_logger * server_logger, enum server_state * server_state){
    // Comprobación de estructuras válidas:
    if (worker == NULL) return true;
    if (worker_conf == NULL) return true;

    // Se aseguran que los punteros sean inválidos:
    worker->client_ctx = NULL;
    worker->client_capacity = NULL;
    worker->client_count = NULL;
    worker->client = NULL;
    worker->epoll_fd = NULL;
    worker->thread = NULL;

    // Asignación de valores configurados (o por defecto si no se dan - miembros estáticos):
    worker->num_workers = (worker_conf->num_workers > 0) ? worker_conf->num_workers : DEFAULT_NUM_WORKERS;
    worker->client_capacity_block = (worker_conf->client_capacity_block > 0) ? worker_conf->client_capacity_block : DEFAULT_CLIENT_CAPACITY_BLOCK;
    worker->client_read_buffer_size = (worker_conf->client_read_buffer_size > 0) ? worker_conf->client_read_buffer_size : DEFAULT_CLIENT_READ_BUFFER_SIZE;
    worker->client_write_buffer_size = (worker_conf->client_write_buffer_size > 0) ? worker_conf->client_write_buffer_size : DEFAULT_CLIENT_WRITE_BUFFER_SIZE;
    worker->client_timeout = (worker_conf->client_timeout > 0) ? worker_conf->client_timeout : DEFAULT_CLIENT_TIMEOUT;
    worker->on_client_rcv = worker_conf->on_client_rcv;
    worker->on_client_snd = worker->on_client_snd;

    // Asignación de valores configurados (o por defecto - miembros dinámicos):
    worker->client_ctx = malloc(sizeof(struct server_client_ctx) * worker->num_workers);
    if (!worker->client_ctx) return true;

    worker->client_capacity = calloc(worker->num_workers, sizeof(size_t));
    if (!worker->client_capacity){
        _server_worker_deinit(worker);
        return true;
    }

    worker->client_count = calloc(worker->num_workers, sizeof(size_t));
    if (!worker->client_count){
        _server_worker_deinit(worker);
        return true;
    }

    worker->client = calloc(worker->num_workers, sizeof(struct server_client_conn *));
    if (!worker->client){
        _server_worker_deinit(worker);
        return true;
    }

    for (size_t i = 0; i < worker->num_workers; i++){
        worker->client[i] = calloc(worker->client_capacity_block, sizeof(struct server_client_conn));
        worker->client_capacity[i] = worker->client_capacity_block;
        worker->client_ctx[i].server_worker = worker;
        worker->client_ctx[i].server_logger = server_logger;
        worker->client_ctx[i].server_state = server_state;
        worker->client_ctx[i].client_index = i;
        if (worker->client[i]) continue;
        _server_worker_deinit(worker);
        return true;
    }

    worker->epoll_fd = calloc(worker->num_workers, sizeof(int));
    if (!worker->epoll_fd){
        _server_worker_deinit(worker);
        return true;
    }
    for (size_t i = 0; i < worker->num_workers; i++){
        worker->epoll_fd[i] = -1;
    }

    for (size_t i = 0; i < worker->num_workers; i++){
        worker->epoll_fd[i] = epoll_create1(0);
        if (worker->epoll_fd[i] == -1){
            _server_worker_deinit(worker);
            return true;
        }
    }

    worker->thread = calloc(worker->num_workers, sizeof(pthread_t));
    if (!worker->thread){
        _server_worker_deinit(worker);
        return true;
    }



    return false;
}

/*
    @brief Función para desinicializar y liberar la memoria usada por los hilos del servidor.
    @note: Los hilos deben ser detenidos previamente a la llamada de este servidor!

    @param struct server_worker * worker: Referencia a la estructura global de los hilos.

    @retval None.
*/
static void _server_worker_deinit(struct server_worker * worker){
    // Comprobación de referencia válida:
    if (worker == NULL) return;

    // Liberación de memoria:
    for (size_t i = 0; i < worker->num_workers; i++){
        if (worker->epoll_fd && (worker->epoll_fd[i] != -1)){
            close(worker->epoll_fd[i]);
            worker->epoll_fd[i] = -1;
        }

        if (worker->client[i]) free(worker->client[i]);
        worker->client[i] = NULL;
    }
    if (worker->client_ctx) free(worker->client_ctx);
    worker->client_ctx = NULL;
    if (worker->client_count) free(worker->client_count);
    worker->client_count = NULL;
    if (worker->client_capacity) free(worker->client_capacity);
    worker->client_capacity = NULL;
    if (worker->client) free(worker->client);
    worker->client = NULL; 
    if (worker->epoll_fd) free(worker->epoll_fd);
    worker->epoll_fd = NULL;
    if (worker->thread) free(worker->thread);
    worker->thread = NULL;
}

/*
    @brief Función para lanzar la ejecución (no bloqueante) de los hilos del servidor.

    @param struct server_worker * worker: Referencia al worker que gestionará los hilos del servidor.

    @retval true: Error en la inicialización de workers del servidor.
    @retval false: No han ocurrido errores.
*/
static bool _server_worker_launch(server_pt server){
    // Comprobación de worker válido:
    if (!server) return true;

    struct server_worker * worker = &server->worker;
    struct server_logger * logger = &server->logger;

    // Lanzamiento de los hilos que gestionan los clientes:
    for (size_t i = 0; i < worker->num_workers; i++){

        if(pthread_create(&worker->thread[i], NULL, __server_cli_worker, (void *)&worker->client_ctx[i]) == 0) continue;
        _server_log(logger, LOG_ERR, "No se han podido lanzar los hilos de gestión de clientes.");
        for (ssize_t j = (ssize_t)i-1; j >= 0; j--){
            pthread_cancel(worker->thread[j]);
            pthread_join(worker->thread[j],NULL);
        }
        return true;
    }

    // Lanzamiento del hilo que gestiona las conexiones:
    if(pthread_create(&worker->main_thread, NULL, __server_main_worker, (void *)server) != 0){
        _server_log(logger, LOG_ERR, "No se ha podido lanzar el hilo principal del servidor de gestión de conexiones.");
        for (size_t i = 0; i < worker->num_workers; i++){
            pthread_cancel(worker->thread[i]);
            pthread_join(worker->thread[i], NULL);
        }
        return true;
    }

    return false;
}

/*
    @brief Función para esperar la detención de los hilos del servidor.
    @note Bloquea la ejecución del hilo que lo llama, y está pensado para ser llamado antes de liberar
    recursos como seguridad adicional. 
    @note Para la detención de los hilos, se deberá cambiar el estado del servidor de SERVER_STATE_RUNNING a SERVER_STATE_CLOSING, de
    manera externa a esta función. En caso de que no se de, esta función bloqueará el flujo de ejecución de manera indefinida, 
    previniendo la ejecución de código que pueda ser peligroso para los hilos en ejecución.

    @param struct server_worker * worker: Referencia al worker del servidor.

    @retval None.
*/
static void _server_worker_wait_land(struct server_worker * worker){
    // Comprobación de referencia válida:
    if (!worker) return;

    // Se espera al fin de ejecución de los hilos del servidor:
    for (size_t i = 0; i < worker->num_workers; i++){
        pthread_join(worker->thread[i], NULL);
    }

    pthread_join(worker->main_thread, NULL);
}

// ================================================================ //
// Hilos de gestión del servidor.
// ================================================================ //
static bool ___server_cli_init(struct server_client_conn * client, size_t read_buffer_len, size_t write_buffer_len);
static void ___server_cli_deinit(struct server_client_conn * client);
static void ___server_cli_close(struct server_client_conn * client_conn, int epoll_fd, size_t * count);
static void ___server_cli_check_timeout(time_t current_time, struct server_worker * worker, int epoll_fd, struct server_client_ctx * client_ctx, struct server_client_conn * clients);

/*
    @brief Esta función es el hilo principal del servidor, gestiona las conexiones con los clientes y su distribución en los hilos de gestión de clientes.

    @param void * arg: Referencia a la estructura general del servidor, es decir, un server_pt.

    @retval NULL.
*/
static void * __server_main_worker(void * arg){
    // Comprobación de argumento válido:
    if (!arg) return NULL;

    // Estructuras principales del servidor:
    server_pt server = (server_pt)arg;
    struct server_logger * logger = &server->logger;
    struct server_conn * conn = &server->conn;
    struct server_worker * worker = &server->worker;

    // Estructura genérica de la conexión del cliente:
    struct server_client_conn client;
    socklen_t client_len = sizeof(client.addr);

    // Bucle principal:
    while (server->state == SERVER_STATE_RUNNING){
        // Se crean los buffers y mutex de un cliente nuevo (en la estructura local client de manera temporal, tras una conexión estas referencias se copian a las estructuras
        // internas de los hilos de gestión de clientes).
        if (___server_cli_init(&client, worker->client_read_buffer_size, worker->client_write_buffer_size)) continue;

        // Se acepta la conexión en la capa TCP:
        client.fd = accept(conn->fd, (struct sockaddr *)&client.addr, &client_len);
        if (client.fd < 0){
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) usleep(10000);
            ___server_cli_deinit(&client);
            continue;
        }

        // Se establece el socket del cliente como no bloqueante:
        if (fcntl(client.fd, F_SETFL, O_NONBLOCK) < 0){
            close(client.fd);
            ___server_cli_deinit(&client);
            continue;
        }

        // Capa TLS para el cliente:
        client.ssl = SSL_new(conn->ssl_ctx);
        if(!client.ssl){
            close(client.fd);
            ___server_cli_deinit(&client);
            continue;
        }

        SSL_set_fd(client.ssl, client.fd);
        if (SSL_accept(client.ssl) <= 0){
            SSL_free(client.ssl);
            close(client.fd);
            ___server_cli_deinit(&client);
            continue;
        }

        // Distribución de la carga del cliente a los hilos de gestión de cliente:
        size_t th_index = 0;
        for (size_t i = 0; i < worker->num_workers - 1; i++){
            // Se encuentra el hilo con menor carga de clientes:
            if (worker->client_count[i+1] < worker->client_count[th_index]) th_index = i;
        }

        if (worker->client_count[th_index] == worker->client_capacity[th_index]){
            // Se comprueba que el número de clientes no excede el máximo permitido:
            if ((worker->client_capacity[th_index] + worker->client_capacity_block) >= MAX_WORKER_CLIENT_NUM){
                SSL_shutdown(client.ssl);
                SSL_free(client.ssl);
                close(client.fd);
                ___server_cli_deinit(&client);
                continue;
            }

            // Se comprueba que haya suficiente capacidad, y se incrementa en caso contrario:
            void * temp = realloc(worker->client[th_index], sizeof(struct server_client_conn) * (worker->client_capacity[th_index] + worker->client_capacity_block));
            if (!temp){
                SSL_shutdown(client.ssl);
                SSL_free(client.ssl);
                close(client.fd);
                ___server_cli_deinit(&client);
                continue;
            }
            worker->client[th_index] = temp;
            worker->client_capacity[th_index] += worker->client_capacity_block;
        }

        size_t pos_index = 0;
        for (size_t i = 0; i < worker->client_capacity[th_index]; i++){
            // En el hilo seleccionado, se copia el cliente en el primer slot libre de clientes del hilo:
            if (worker->client[th_index][i].state != CLIENT_STATE_STANDBY) continue;
            pos_index = i;
            worker->client[th_index][i] = client;
            worker->client[th_index][i].state = CLIENT_STATE_ESTABLISH;
            worker->client_count[th_index]++;
            break;
        }

        struct epoll_event event;
        event.events = EPOLLIN;
        event.data.ptr = &worker->client[th_index][pos_index];
        if(epoll_ctl(worker->epoll_fd[th_index], EPOLL_CTL_ADD, client.fd, &event) == -1){
            // Se añade el tipo de eventos a escuchar y el descriptor socket al epoll del hilo. (La estructura event es copiada internamente en la función ctl).
            ___server_cli_close(&worker->client[th_index][pos_index], worker->epoll_fd[th_index], &worker->client_count[th_index]);
            continue;
        }

        // Loggin e impresión de datos del cliente conectado:
        char ip_str[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, &client.addr.sin_addr, ip_str, sizeof(ip_str)) == NULL) ip_str[0] = '?';
        int port = ntohs(client.addr.sin_port);
        _server_log(logger, LOG_INFO, "Cliente conectado: %s:%d", ip_str, port);
    }

    return NULL;
}

/*
    @brief Esta función rerpresenta un hilo gestor de clientes del servidor, encargado de gestionar los eventos de estos (lectura y escritura).

    @param void * arg: Referencia a la estructura server_client_ctx del hilo.

    @retval NULL.
*/
static void * __server_cli_worker(void * arg){
    // Comprobación de argumento válido:
    if (!arg) return NULL;

    // Estructura del contexto del cliente asignado al hilo:
    struct server_client_ctx * client_ctx = (struct server_client_ctx *)arg;
    struct server_logger * client_logger = client_ctx->server_logger;
    struct server_worker * worker = client_ctx->server_worker;
    struct server_client_conn * clients = worker->client[client_ctx->client_index];

    int epoll_fd = worker->epoll_fd[client_ctx->client_index];
    struct epoll_event events[MAX_EPOLL_EVENTS];

    while (*client_ctx->server_state == SERVER_STATE_RUNNING){
        // Escucha de eventos en los sockets clientes asignados al hilo:
        int nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, 1000);
        if ((nfds < 0) && (errno == EINTR)) continue;

        // Verificación de los timeouts de los clientes tras un evento:
        time_t current_time = time(NULL);
        ___server_cli_check_timeout(current_time, worker, epoll_fd, client_ctx, clients);

        // Gestión de los eventos capturados en los sockets para lectura de datos:
        for (size_t i = 0; i < nfds; i++){
            struct server_client_conn * client = (struct server_client_conn *)events[i].data.ptr;
            if (!client || (client->state != CLIENT_STATE_ESTABLISH)) continue;

            char ip_str[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, &client->addr.sin_addr, ip_str, sizeof(ip_str)) == NULL) ip_str[0] = '?';
            int port = ntohs(client->addr.sin_port);

            // Lectura de datos del cliente:
            if (events[i].events & EPOLLIN){
                pthread_mutex_lock(client->read_lock);
                int rb = SSL_read(client->ssl, client->read_buffer + client->read_off, worker->client_read_buffer_size - client->read_off);
                
                if (rb > 0){
                    // Caso recepción de datos:
                    client->read_len += rb;
                    client->last_action_time = current_time;

                    // Procesado de los datos leídos:
                    worker->on_client_rcv(client);      // TODO: Desacoplar procesamiento del hilo (ahora, esta función es bloqueante)

                    // Log de debug para registrar la lectura de datos del cliente:
                    _server_log(client_logger, LOG_DEBUG, "Lectura - Se han leído datos del cliente %s:%d", ip_str, port);

                    // Liberación del mutex de lectura:
                    pthread_mutex_unlock(client->read_lock);
                } else if ((rb == 0) || (SSL_get_error(client->ssl, rb) == SSL_ERROR_ZERO_RETURN)){
                    // Log de info para registrar la desconexión de un cliente:
                    _server_log(client_logger, LOG_INFO, "Lectura - Se ha desconectado el cliente %s:%d", ip_str, port);

                    // Caso cierre de conexión por parte del cliente:
                    pthread_mutex_unlock(client->read_lock);
                    ___server_cli_close(client, epoll_fd, &worker->client_count[client_ctx->client_index]);
                } else {
                    // Caso error en la comunicación con el cliente:
                    int ssl_err = SSL_get_error(client->ssl, rb);
                    if ((ssl_err != SSL_ERROR_WANT_READ) && (ssl_err != SSL_ERROR_WANT_WRITE)){
                        // Log de advertencia para registrar un error en un cliente:
                        _server_log(client_logger, LOG_WARN, "Lectura - Se ha producido un error en el cliente %s:%d", ip_str, port);

                        pthread_mutex_unlock(client->read_lock);
                        ___server_cli_close(client, epoll_fd, &worker->client_count[client_ctx->client_index]);
                    }
                }
            }


            // Escritura de datos del cliente:
            if ((client->write_len > 0) && (events[i].events & EPOLLOUT)){
                pthread_mutex_lock(client->write_lock);
                int wb = SSL_write(client->ssl, client->write_buffer + client->write_off, client->write_len - client->write_off);

                if (wb > 0){
                    // Caso escritura de datos:
                    client->write_off += wb;
                    if (client->write_off == client->write_len){
                        // Caso toda la respuesta enviada:
                        client->write_off = 0;
                        client->write_len = 0;

                        struct epoll_event ev = {.events = EPOLLIN, .data.ptr = client};
                       
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev) == -1){
                            // Log de advertencia para registrar un error en el cliente:
                            _server_log(client_logger, LOG_WARN, "Escritura - Se ha producido un error en el cliente %s:%d", ip_str, port);

                            pthread_mutex_unlock(client->write_lock);
                            ___server_cli_close(client, epoll_fd, &worker->client_count[client_ctx->client_index]);
                        }   

                        // Log de debug para registrar la escritura en un cliente:
                        _server_log(client_logger, LOG_DEBUG, "Escritura - Se han escrito datos al cliente %s:%d", ip_str, port);
                    }
                    client->last_action_time = current_time;

                    // Liberación del mutex de escritura:
                    pthread_mutex_unlock(client->write_lock);
                } else {
                    // Caso error en la comunicación con el cliente:
                    int ssl_err = SSL_get_error(client->ssl, wb);
                    if ((ssl_err != SSL_ERROR_WANT_READ) && (ssl_err != SSL_ERROR_WANT_WRITE)){
                        // Log de advertencia para registrar un error en el cliente:
                        _server_log(client_logger, LOG_WARN, "Escritura - Se ha producido un error en el cliente %s:%d", ip_str, port);

                        pthread_mutex_unlock(client->write_lock);
                        ___server_cli_close(client, epoll_fd, &worker->client_count[client_ctx->client_index]);
                    }
                }
            }

        }
    }

    // Cierre completo de los clientes conectados al hilo:
    for (size_t i = 0; i < worker->client_capacity[client_ctx->client_index]; i++){
        ___server_cli_close(&clients[i], epoll_fd, &worker->client_count[client_ctx->client_index]);
    }

    return NULL;
}

// ================================================================ //
// Funciones auxiliares para los clientes.
// ================================================================ //
/*
    @brief Función para alojar memoria e inicializar a 0's la estructura de un cliente.
    @note: Pensada para inicializar la estructura de un cliente previamente a su conexión, dentro del hilo principal del servidor.

    @param struct server_client_conn * client: Referencia a la estructura de conexión del cliente.
    @param size_t read_buffer_len: Longitud del buffer de lectura del cliente.
    @param size_t write_buffer_len: Longitud del buffer de escritura del cliente.

    @retval true: Han ocurrido errores durante la inicialización.
    @retval false: No han ocurrido errores.
*/
static bool ___server_cli_init(struct server_client_conn * client, size_t read_buffer_len, size_t write_buffer_len){
    // Comprobación de referencia a referencia válida:
    if (!client) return true;

    // Alojamiento de memoria para los buffers del nuevo cliente a conectarse:
    client->read_buffer = calloc(read_buffer_len, sizeof(char));
    if (!client->read_buffer) return true;
    client->write_buffer = calloc(write_buffer_len, sizeof(char));
    if (!client->write_buffer){
        free(client->read_buffer);
        return true;
    }

    // Alojamiento de memoria de los locks de los buffers:
    client->read_lock = malloc(sizeof(pthread_mutex_t));
    if (!client->read_lock){
        free(client->read_buffer);
        free(client->write_buffer);
        return true;
    }

    client->write_lock = malloc(sizeof(pthread_mutex_t));
    if (!client->write_lock){
        free(client->read_buffer);
        free(client->write_buffer);
        free(client->read_lock);
        return true; 
    }

    // Inicialización de los locks de los buffers:
    int err = 0;
    err += pthread_mutex_init(client->read_lock, NULL);
    err += pthread_mutex_init(client->write_lock, NULL);

    if (err != 0){
        free(client->read_buffer);
        free(client->write_buffer);
        pthread_mutex_destroy(client->read_lock);
        free(client->read_lock);
        pthread_mutex_destroy(client->write_lock);
        free(client->write_lock);
        return true;         
    }

    // Reset de los campos del cliente:
    client->read_len = 0;
    client->read_off = 0;
    client->write_len = 0;
    client->write_off = 0;
    client->state = CLIENT_STATE_STANDBY;
    client->last_action_time = time(NULL);

    return false;
}

/*
    @brief Función para liberar correctamente la estructura de un cliente.
    @note Esta función no considera una conexión activa con el cliente, solo libera recursos de memoria.

    @param struct server_client_conn * client: Referencia a la estructura de conexión de un cliente.

    @retval None.
*/
static void ___server_cli_deinit(struct server_client_conn * client){
    // Comprobación de referencia válida:
    if (!client) return;

    // Liberación de recursos de la estructura del cliente:
    free(client->read_buffer);
    client->read_buffer = NULL;
    free(client->write_buffer);
    client->write_buffer = NULL;
    pthread_mutex_destroy(client->read_lock);
    free(client->read_lock);
    client->read_lock = NULL;
    pthread_mutex_destroy(client->write_lock);
    free(client->write_lock);
    client->write_lock = NULL;
}

/*
    @brief Función para cerrar correctamente la conexión de un cliente conectado.
    @note Esta función es una ampliación de "deinit" que asume la conexión del cliente.
    @note Libera los recursos en memoria reservados para el cliente pero no la estructura en sí.

    @param struct server_client_conn * client_conn: Referencia a la estructura de conexión del cliente.
    @param int epoll_fd: Descriptor de archivo de la estructura epoll del hilo que maneja el cliente a cerrar.
    @param size_t * count: Referencia al contador de clientes conectados por hilo al que pertenece el cliente.

    @retval None.
*/
static void ___server_cli_close(struct server_client_conn * client_conn, int epoll_fd, size_t * count){
    // Se compruba que los parámetros sean válidos:
    if (!client_conn || !count) return;
    if (client_conn->state != CLIENT_STATE_ESTABLISH) return;

    // Cierre completo y seguro del cliente:
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_conn->fd, NULL);

    if (client_conn->ssl){
        SSL_shutdown(client_conn->ssl);
        SSL_free(client_conn->ssl);
    }

    close(client_conn->fd);

    ___server_cli_deinit(client_conn);

    client_conn->state = CLIENT_STATE_STANDBY;
    (*count)--;
}

/*
    @brief Función para verificar los timeout de los clientes de un hilo gestor de clientes.

    @param struct server_worker * worker: Referencia al worker del servidor.
    @param int epoll_fd: Descriptor de archivo del epoll del hilo gestor.
    @param struct server_client_ctx * client_ctx: Referencia al contexto de clientes del hilo gestor.
    @param struct server_client_conn * clients: Referencia al array de clientes del hilo gestor.

    @retval None.
*/
static void ___server_cli_check_timeout(time_t current_time, struct server_worker * worker, int epoll_fd, struct server_client_ctx * client_ctx, struct server_client_conn * clients){
    // Verificación de los timeouts:
    for (size_t i = 0; i < worker->client_capacity[client_ctx->client_index]; i++){
        struct server_client_conn * temp_client = &clients[i];
        if (temp_client->state != CLIENT_STATE_ESTABLISH) continue;
        if (difftime(current_time, temp_client->last_action_time) <= worker->client_timeout) continue;
        ___server_cli_close(temp_client, epoll_fd, &worker->client_count[client_ctx->client_index]);
    }
}
/* -------------------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------------------- */

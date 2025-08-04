#include "server.h"




/* -------------------------------------------------------------------------------------------------------------------------------- */
/* ---- Prototipo de funciones estáticas ------------------------------------------------------------------------------------------ */
// ==== Logger ==== //
static bool _server_logger_init(struct server_logger * logger);
static void _server_logger_deinit(struct server_logger * logger);
static void _server_logger_conf(struct server_logger * logger, struct server_logger_conf * logger_conf);
static void _server_log(struct server_logger * logger, enum server_logger_level log_level, const char * log_msg);

// ==== TCP/IP + TLS ==== //
/* -------------------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------------------- */




/* -------------------------------------------------------------------------------------------------------------------------------- */
/* ---- Implementación de funciones públicas -------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------------------- */




/* -------------------------------------------------------------------------------------------------------------------------------- */
/* ---- Implementación de funciones estáticas ------------------------------------------------------------------------------------- */

// ================================================================ //
// Logger del servidor
// ================================================================ //
static void __server_log_genname(struct server_logger * logger, char * buffer, size_t buffer_len);
static void __server_log_rotfile(struct server_logger * logger);

/*
    @brief Función para inicializara con valores por defecto el logger del servidor.

    @param struct server_logger * logger: Referencia al logger del servidor.

    @retval true: Error en la inicialización del logger
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

    @param struct server_logger * logger: Referencia al logger del servidor.
    @param struct server_logger_conf logger_conf: Estructura de datos con la configuración deseada.

    @retval None.
*/
static void _server_logger_conf(struct server_logger * logger, struct server_logger_conf * logger_conf){
    // Comprobación de estructuras válidas:
    if (!logger) return;
    if (!logger_conf) return;

    // Configuración de miembros configurables:
    if (logger_conf->log_path){
        if (logger->log_path) free(logger->log_path);
        logger->log_path = strdup(logger_conf->log_path);
    }
    if (logger_conf->log_file){
        if (logger->log_file) free(logger->log_file);
        logger->log_file = strdup(logger_conf->log_file);
    } 
    if (logger_conf->log_max_size) logger->log_max_size = logger_conf->log_max_size;
    logger->log_min_lvl = logger_conf->log_min_lvl;
}


/*
    @brief Función para registrar mensajes y datos en archivos de log dedicados al servidor.

    @param struct server_logger * logger: Referencia al logger del servidor.
    @param enum server_logger_level log_level: Nivel al que se escribirá el log.
    @param const char * log_msg: Mensaje que incluirá el log.

    @retval None.
*/
static void _server_log(struct server_logger * logger, enum server_logger_level log_level, const char * log_msg){
    // Si el logger es inválido se ignora la llamada:
    if (!logger) return;
    if (logger->state != LOGGER_OK) return;

    // Si alguna ruta no es válida se ignora la llamada:
    if (!logger->log_path) return;
    if (!logger->log_file) return;

    // Si el nivel es inferior al mínimo se ignora la llamada:
    if (log_level < logger->log_min_lvl) return;

    // Si el puntero al mensaje de log es inválido se ignora la llamada:
    if (!log_msg) return;

    // Si la longitud excede un máximo se ignora la llamada:
    if (strlen(log_msg) > MAX_LOG_MSG_LEN - LOG_RESERVED_FORMAT_LEN) return;

    // Comienzo de operación -> Lock:
    pthread_mutex_lock(&logger->log_lock);

    // Mensaje completo (fecha, hora, nivel y mensaje):
    char timestr[32];
    time_t actual_time = time(NULL);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&actual_time));

    char fullmsg[MAX_LOG_MSG_LEN];
    snprintf(fullmsg, sizeof(fullmsg), "[%s][%s]: %s", timestr, LOG_LEVEL2STR(log_level), log_msg);

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
// TCP/IP + TLS: Creación y gestión de conexiones.
// ================================================================ //

/* -------------------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------------------- */

#include "server.h"
#include <stdio.h>

int main(int argc, char ** argv){

    server_pt server = server_init(&(server_conf_t){
        .logger_conf.log_max_size = 8000,
        .logger_conf.log_min_lvl = 1,
        .logger_conf.log_path = "./logs",
        .logger_conf.log_file = "server",

        .conn_conf.port = 2002,
        .conn_conf.cert_path = "./certs/cert.pem",
        .conn_conf.key_path = "./certs/key.pem",

        .worker_conf.num_workers = 4,
        .worker_conf.client_capacity_block = 2,
        .worker_conf.client_read_buffer_size = 2000,
        .worker_conf.client_write_buffer_size = 2000,
        .worker_conf.client_timeout = 600
    });

    printf("Servidor creado en (%p)\n", server);
    server_open(server);
    printf("Servidor abierto!\n");

    char ch = 'a';
    while(ch != 'q'){
        printf("Pulsa 'q' para cerrar: ");
        ch = fgetc(stdin);
    }

    server_close(server);
    printf("Servidor cerrado!\n");

    server_deinit(&server);

    return 0;
}

/*
    @
*/
void rcvfn_echo(void * args){
    printf("%s\n", (char *)args);
}
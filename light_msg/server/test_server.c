#include "server.h"
#include <stdio.h>

server_pt server;

void at_rcv(void * args){
    // Comprobaciones de seguridad:
    client_pt client = (client_pt)args;

    // Broadcast a todos los clientes conectados:
    server_broadcast(server, client->read_buffer, client->read_len, NULL);
}

int main(int argc, char ** argv){

    server = server_init(&(server_conf_t){
        .logger_conf.log_max_size = 8000000,
        .logger_conf.log_min_lvl = 0,
        .logger_conf.log_path = "./logs",
        .logger_conf.log_file = "server",

        .conn_conf.port = 2020,
        .conn_conf.cert_path = "./certs/cert.pem",
        .conn_conf.key_path = "./certs/key.pem",

        .worker_conf.num_workers = 8,
        .worker_conf.client_capacity_block = 20,
        .worker_conf.client_read_buffer_size = 4096,
        .worker_conf.client_write_buffer_size = 4096,
        .worker_conf.client_timeout = 60,
        .worker_conf.on_client_rcv = at_rcv,
    });

    server_open(server);

    printf("\nPulsa 'enter' para cerrar el servidor.\n");
    fgetc(stdin);

    server_close(server);
    server_deinit(&server);

    return 0;
}
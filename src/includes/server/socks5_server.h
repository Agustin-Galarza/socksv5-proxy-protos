#ifndef SOCKS5SV_H_
#define SOCKS5SV_H_

#include "utils/netutils.h"
#include "utils/selector.h"

#define MAX_CLIENTS_AMOUNT 500

bool socks5_init_server(size_t max_clients);
void socks5_close_server();

const struct fd_handler* get_socks5_server_handlers();

extern struct socks5_server_data socks5_server_data;

uint16_t socks5_get_historic_connections();
uint16_t socks5_get_concurrent_connections();
uint16_t socks5_get_bytes_sent();

/**
 * Actualiza el tamaño del buffer para la comunicación de los clientes.
 * Devuelve true si el valor fue actualizado, false en caso contrario.
*/
bool socks5_update_client_buffer_size(uint16_t new_size);

#endif

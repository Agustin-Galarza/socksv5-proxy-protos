#ifndef SOCKS5SV_H_
#define SOCKS5SV_H_

#include "utils/netutils.h"
#include "utils/selector.h"

bool socks5_init_server();
void socks5_close_server();

const struct fd_handler* get_socks5_server_handlers();

struct socks5_server_data
{
    size_t max_clients;
    size_t client_count;
} socks5_server_data;

#endif

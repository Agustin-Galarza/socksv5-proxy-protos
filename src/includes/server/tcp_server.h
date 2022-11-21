#ifndef TCPSV_H_
#define TCPSV_H_
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/parser/args.h" // struct users

#define SERVER_MAX_USERS 500

enum ip_version
{
    IPV4 = 0,
    IPV6
};

struct server_config
{
    size_t max_clients;

    char* socks5_addr;
    uint16_t port;

    char* admin_addr;
    uint16_t admin_port;

    int initial_connections;
    struct users users[SERVER_MAX_USERS];
};

// returns TRUE on error, FALSE, otherwhise
bool run_server(struct server_config* config);

#endif

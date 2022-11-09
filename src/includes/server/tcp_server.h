#ifndef TCPSV_H_
#define TCPSV_H_
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "parser/args.h" // struct users

#define SERVER_MAX_USERS 500

enum ip_version
{
    IPV4 = 0,
    IPV6
};

struct server_config
{
    size_t max_clients;
    uint16_t port;
    uint16_t admin_port;
    enum ip_version version;
    int initial_connections;
    const char* logs_filename;
    struct users users[SERVER_MAX_USERS]; // todo: make list
};

// returns TRUE on error, FALSE, otherwhise
bool run_server(struct server_config* config);

#endif

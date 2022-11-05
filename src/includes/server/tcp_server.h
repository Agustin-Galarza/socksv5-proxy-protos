#ifndef TCPSV_H_
#define TCPSV_H_
#include <stdbool.h>
#include <stddef.h>

enum ip_version
{
    IPV4 = 0,
    IPV6
};

struct server_config
{
    size_t max_clients;
    const char* port;
    enum ip_version version;
    int initial_connections;
    const char* logs_filename;
};

// returns TRUE on error, FALSE, otherwhise
bool run_server(struct server_config* config);

#endif

#ifndef __CONF_H__
#define __CONF_H__

#include <stdio.h>

#include "tcp_client_util.h"
#include <string.h>
#include <stdbool.h>

#define TOKEN_ENV_VAR   "TOKEN"
#define COMMAND_ARGUMENTS "127.0.0.1"
#define CONF_ARGUMENTS  ":hL:P:"
#define ARGUMENTS   CONF_ARGUMENTS COMMAND_ARGUMENTS

#define IP_V4 1
#define DOMAINNAME 3
#define IP_V6 4

typedef struct tcp_conf {
    char * addr;
    unsigned short port;
    int version;
} tcp_conf;

typedef enum CMD
{
    CONNECT,
    BIND,
    UDP_ASSOCIATE,
} CMD;

typedef struct n_conf {
    CMD cmd;
    int version;
    int rsv;
    int atyp;
    char* dest_addr;
    char* dest_port;
} n_conf;

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * tcp-conf con defaults o la seleccion humana.
 */
bool parse_conf(const int argc, char **argv, struct tcp_conf* tcp_conf);
bool n_parse_conf(const int argc, char **argv, struct n_conf* n_conf);

#endif

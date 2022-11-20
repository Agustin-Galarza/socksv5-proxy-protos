#ifndef __CONF_H__
#define __CONF_H__

#include <stdio.h>

#include "tcp_client_util.h"

#define TOKEN_ENV_VAR   "TOKEN"
//CAP, STATS, USERS, BUFFSIZE, SET-BUFFISZE, ADD-USER
#define COMMAND_ARGUMENTS "0123:4:5:"
#define CONF_ARGUMENTS  ":hvL:P:"
#define ARGUMENTS   CONF_ARGUMENTS COMMAND_ARGUMENTS

typedef struct tcp_conf {
    const char * addr;
    const char * port;
    int version;
} tcp_conf;

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * tcp-conf con defaults o la seleccion humana.
 */
bool parse_conf(const int argc, char **argv, struct tcp_conf* tcp_conf);

#endif

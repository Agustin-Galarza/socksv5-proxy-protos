#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>

#include "utils/parser/args.h"

static unsigned short
port(const char* s) {
    char* end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
       || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
       || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

void
user(char* s, struct users* user) {
    char* p = strchr(s, ':');
    if (p == NULL) {
        fprintf(stderr, "password not found\n");
        exit(1);
    }
    else {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
    }

}

static void
version(void) {
    fprintf(stderr, "socks5d version 1.0\n"
                    "ITBA Protocolos de Comunicación 2022/2 -- Grupo 4\n"
                    "MIT License\n"
    "Copyright (c) 2022 Protocolos de Comunicación - 2022:Group 4\n");
}

static void
usage(const char* progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -l               Specify address where SOCKS server will listen. By default it listens in all interfaces.\n"
        "   -L               Specify address where admin server will listen. Default is localhost.\n"
        "   -P <conf port>   Puerto entrante conexiones admin\n"
        "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
        "   -v               Imprime información sobre la versión versión y termina.\n"
        "\n",
        progname);
    exit(1);
}

void
parse_args(const int argc, char** argv, struct socks5args* args) {
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socks_host = NULL;
    args->socks_port = 1080;
    args->admin_host = "localhost";
    args->admin_port = 8080;

    int c;
    int nusers = 0;

    while (true) {
        c = getopt(argc, argv, "hp:P:l:L:u:v");
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage(argv[0]);
            break;
        case 'l':
            args->socks_host = optarg;
            break;
        case 'L':
            args->admin_host = optarg;
            break;
        case 'p':
            args->socks_port = port(optarg);
            break;
        case 'P':
            args->admin_port = port(optarg);
            break;
        case 'u':
            if (nusers >= MAX_USERS) {
                fprintf(stderr, "maximun number of command line users reached: %d.\n", MAX_USERS);
                exit(1);
            }
            else {
                user(optarg, args->users + nusers);
                nusers++;
            }
            break;
        case 'v':
            version();
            exit(0);
            break;
        default:
            fprintf(stderr, "unknown argument %d.\n", c);
            exit(1);
        }

    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}

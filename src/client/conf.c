#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h> 
#include <errno.h>

#include "client/conf.h"
#include "client/tcp_client_util.h"

static void
version(void) {
    fprintf(stderr, "Cliente de administración\n"
                    "ITBA Protocolos de Comunicación 2023/1 -- Grupo X\n"
                    "LICENCIA\n");
}

static unsigned short
port(const char *s) {
    char *end     = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s|| '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

static CMD cmd(const char *s) {
    
    const int cmd = atoi(s);

    if (cmd != CONNECT && cmd != BIND && cmd != UDP_ASSOCIATE) {
        fprintf(stderr, "CMD should be:\n \t%d\n \t%d\n \t%d\n", CONNECT, BIND, UDP_ASSOCIATE );
        exit(1);
        return 1;
    }
    return cmd;
}
static void
usage(const char* progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Help.\n"
            "   -L               Specify address to connect. REQUIRED\n"
            "   -P               Specify port to connect.\n"
            "   [-4 | -6]        Specify ip version use.\n"
            "\n",
            progname);
    exit(1);
}

static void
n_usage(const char* progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Help.\n"
            "   -C               Specify CMD. REQUIRED\n"
            "   -A               Specify ATYP. REQUIRED\n"
            "   -a     Specify destination address. REQUIRED\n"
            "   -p     Specify destination port. REQUIRED\n"
            "\n",
            progname);
    exit(1);
}

bool parse_conf(const int argc, char** argv, struct tcp_conf* args) {
    memset(args, 0, sizeof(*args));

    args->addr = NULL;
    args->port = 8080;


    int c;

    while (true) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hL:P:46", NULL, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'L':
                args->addr = optarg;
                break;
            case 'P':
                printf("Connecting to port %s\n", optarg);
                args->port = port(optarg);
                break;
            case '4':
                args->version=4;
                break;
            case '6':
                args->version=6;
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
    return true;
}

bool n_parse_conf(const int argc, char** argv, struct n_conf* args) {
    memset(args, 0, sizeof(*args));

    args->rsv = 0;
    args->dest_port = 8080;


    int c;

    while (true) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hC:A:a:p:", NULL, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                n_usage(argv[0]);
                break;
            case 'C':
                args->cmd = cmd(optarg);
                break;
            case 'A':
                args->atyp = optarg;
                break;
            case 'a':
                args->dest_addr=optarg;
                break;
            case 'p':
                args->dest_port=port(optarg);
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
    return true;
}
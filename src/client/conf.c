#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "client/conf.h"
#include "client/tcp_client_util.h"

static void
version(void) {
    fprintf(stderr, "Cliente de administración\n"
                    "ITBA Protocolos de Comunicación 2023/1 -- Grupo X\n"
                    "LICENCIA\n");
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

bool parse_conf(const int argc, char** argv, struct tcp_conf* tcp_conf) {
    int c;
    opterr = 0, optind = 0;
    while (-1 != (c = getopt(argc, argv, ARGUMENTS))) {
        switch (c) {
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'L':
            if (*optarg == '-') {
                fprintf(stderr, "Option -L requires an argument.\n");
                return false;
            }
            tcp_conf->addr = optarg;
            break;
        case 'P':
            if (*optarg == '-') {
                fprintf(stderr, "Option -P requires an argument.\n");
                return false;
            }
            tcp_conf->port = optarg;
            break;
        case '4':
            tcp_conf->version =4;
        case '6':
            tcp_conf->version =6;
        default:
            fprintf(stderr, "Unknown argument %c.\n", optopt);
            return false;
        }
    }
    if (optind - argc < 1) {
        fprintf(stderr, "Invalid argument: ");
        while (optind - argc < 1) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        usage(argv[0]);
        return false;
    }
    return true;
}

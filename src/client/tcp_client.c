#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#include "utils/logger/logger.h"
#include "client/tcp_client_util.h"
#include "client/conf.h"

int main(int argc, char* argv[]) {
    int exit_status = 0;
    char* err_msg, * success_msg = "OK!\n";
    tcp_conf conf = {
        .addr = "127.0.0.1", // default address
        .port = "8080", // default port
        .token = NULL, // default token
        .sock = 0,
    };

    if (!parse_conf(argc, argv, &conf)) {
        err_msg = "Error parsing configuration from arguments";
        exit_status = 1;
        goto finally;
    }

    if ((conf.sock = tcpClientSocket(conf.addr, conf.port)) < 0) {
        err_msg = "Error creating sock with server";
        exit_status = 1;
        goto finally;
    }

    log_debug("----------------------------");
    log_debug("CONNECTING TO SERVER");

    if (!read_hello(conf.sock)) {
        err_msg = "Error in server greeting";
        exit_status = 1;
        goto finally;
    }

    log_debug("----------------------------");
    log_debug("");

    log_debug("----------------------------");
    log_debug("AUTHENTICATING WITH TOKEN");
    if (!authenticate(conf.sock, conf.token)) {
        err_msg = "Could not authenticate in server";
        exit_status = 1;
        goto finally;
    }

    log_debug("----------------------------");
    log_debug("");

    int c;
    opterr = 0, optind = 0;
    while (-1 != (c = getopt(argc, argv, ARGUMENTS))) {
        switch (c) {
        case '0':
            capabilities(conf.sock);
            break;
        case '1':
            stats(conf.sock);
            break;
        case '2':
            users(conf.sock);
            break;
        case '3':
            buffsize(conf.sock);
            break;
        case '4':
            if (*optarg == '-') {
                err_msg = "Option -4 requires an argument.\nError parsing configuration from arguments";
                exit_status = 1;
                goto finally;
            }
            set_buffsize(conf.sock, optarg);
            break;
        case '5':
            if (*optarg == '-') {
                err_msg = "Option -5 requires an argument.\nError parsing configuration from arguments";
                exit_status = 1;
                goto finally;
            }
            add_user(conf.sock, optarg);
            break;
        }
    }

    log_info(success_msg);

    finally:
    if (exit_status) log_error("%s\n", err_msg);
    if (errno) perror("");
    close(conf.sock);
    return exit_status;
}

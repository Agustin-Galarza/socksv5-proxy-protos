#include <stdio.h>
#include <string.h>

#include "utils/logger/logger.h"
#include "utils/buffer.h"
#include "server/tcp_server.h"
#include "utils/parser/args.h"

#ifdef DEFAULT_FILE_NAME
#undef DEFAULT_FILE_NAME
#define DEFAULT_FILE_NAME "logs/logger.log"
#endif

int main(int argc, char** argv) {
    struct logger_init_args logger_args = {
        .logs_enabled = true,
        .stderr_enabled = true,
        .level_config = {
            DEFAULT_ERROR_CONFIG,  // ERROR
            DEFAULT_DEBUG_CONFIG,  // DEBUG
            DEFAULT_INFO_CONFIG,   // INFO
            DEFAULT_WARNING_CONFIG // WARNING
        } };
    logger_init(&logger_args);
    atexit(logger_cleanup);

    struct socks5args socks5_args;
    parse_args(argc, argv, &socks5_args);

    struct server_config config_args;
    config_args.initial_connections = 3;
    config_args.max_clients = 500;
    config_args.port = socks5_args.socks_port;
    config_args.admin_port = socks5_args.mng_port;
    config_args.version = IPV4;
    config_args.logs_filename = "logs/server_logs.log";
    memcpy(config_args.users, socks5_args.users, MAX_USERS * sizeof(struct users));

    if (run_server(&config_args)) {
        log_error("Error while running server");
        exit(1);
    }

    return 0;
}
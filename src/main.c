#include <stdio.h>
#include <string.h>

#include "logger/logger.h"
#include "utils/buffer.h"
#include "server/tcp_server.h"

#ifdef DEFAULT_FILE_NAME
#undef DEFAULT_FILE_NAME
#define DEFAULT_FILE_NAME "logs/logger.log"
#endif

int main(int argc, char **argv)
{
    struct logger_init_args args = {
        .logs_enabled = true,
        .stderr_enabled = true,
        .level_config = {
            DEFAULT_ERROR_CONFIG,  // ERROR
            DEFAULT_DEBUG_CONFIG,  // DEBUG
            DEFAULT_INFO_CONFIG,   // INFO
            DEFAULT_WARNING_CONFIG // WARNING
        }};
    logger_init(&args);
    atexit(logger_cleanup);

    struct server_config config_args;
    config_args.initial_connections = 3;
    config_args.max_clients = 400;
    config_args.port = "8080";
    config_args.version = IPV4;
    config_args.logs_filename = "logs/server_logs.log";

    if (run_server(&config_args))
    {
        log_error("Error while running server");
        exit(1);
    }

    return 0;
}
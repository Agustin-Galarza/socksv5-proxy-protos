#include<stdio.h>

#include "printer.h"
#include "logger.h"

#define do_nothing(X) _Generic( (X), int: do_nothing_i, char**: do_nothing_ss, default: do_nothing_ss )(X)

#ifdef DEFAULT_FILE_NAME
#undef DEFAULT_FILE_NAME
#define DEFAULT_FILE_NAME "logs/logger.log"
#endif

int main(int argc, char** argv) {
    struct logger_init_args args = {
        .logs_enabled = true,
        .stderr_enabled = true,
        .level_config = {
            DEFAULT_ERROR_CONFIG_WITH_FILE,   // ERROR
            DEFAULT_DEBUG_CONFIG,   // DEBUG
            DEFAULT_INFO_CONFIG_WITH_FILE,    // INFO
            DEFAULT_WARNING_CONFIG  // WARNING
        }
    };
    logger_init(&args);
    atexit(logger_cleanup);

    log_info("Hello, this is my info");
    log_debug("Reached here");

    print_something();

    printf("Hello World!\n");

    return 0;
}
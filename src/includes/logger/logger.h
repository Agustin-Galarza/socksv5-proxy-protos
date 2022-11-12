#ifndef LOGGER_H_
#define LOGGER_H_
#include <stdlib.h>
#include <stdbool.h>

#define MAX_FILE_NAME_SIZE 50

///// Colors
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define YELLOW "\033[1;33m"
#define BLUE "\033[0;34m"
#define CYAN "\033[0;36m"
#define LIGHT_BLUE "\033[1;34m"
#define NO_COLOR "\033[0m"
/////////////////////////

#define DEFAULT_FILE_NAME "logger.log" // redefine this value to change the default location.

#define DEFAULT_CONFIG                                     \
    {                                                      \
        .enabled = true, .color = NO_COLOR, .filename = "" \
    }
#define DEFAULT_ERROR_CONFIG                          \
    {                                                 \
        .enabled = true, .color = RED, .filename = "" \
    }
#define DEFAULT_DEBUG_CONFIG                            \
    {                                                   \
        .enabled = true, .color = GREEN, .filename = "" \
    }
#define DEFAULT_INFO_CONFIG                            \
    {                                                  \
        .enabled = true, .color = CYAN, .filename = "" \
    }
#define DEFAULT_WARNING_CONFIG                           \
    {                                                    \
        .enabled = true, .color = YELLOW, .filename = "" \
    }

#define DEFAULT_CONFIG_WITH_FILE                                          \
    {                                                                     \
        .enabled = true, .color = NO_COLOR, .filename = DEFAULT_FILE_NAME \
    }
#define DEFAULT_ERROR_CONFIG_WITH_FILE                               \
    {                                                                \
        .enabled = true, .color = RED, .filename = DEFAULT_FILE_NAME \
    }
#define DEFAULT_DEBUG_CONFIG_WITH_FILE                                 \
    {                                                                  \
        .enabled = true, .color = GREEN, .filename = DEFAULT_FILE_NAME \
    }
#define DEFAULT_INFO_CONFIG_WITH_FILE                                 \
    {                                                                 \
        .enabled = true, .color = CYAN, .filename = DEFAULT_FILE_NAME \
    }
#define DEFAULT_WARNING_CONFIG_WITH_FILE                                \
    {                                                                   \
        .enabled = true, .color = YELLOW, .filename = DEFAULT_FILE_NAME \
    }

typedef enum level
{
    ERROR,
    DEBUG,
    INFO,
    WARNING
} log_level;

struct log_level_config
{
    bool enabled;
    char color[11];
    char filename[MAX_FILE_NAME_SIZE]; // relative or absolute path to log file for this level. Note that the logger does not create directories so this value must represent a valid path.
};

struct logger_init_args
{
    bool logs_enabled;
    bool stderr_enabled;
    struct log_level_config level_config[4];
};

//! All functions return true on error, false on success

void logger_init(struct logger_init_args* args);
void logger_cleanup();
bool log_info(const char* fmt_msg, ...);
bool log_error(const char* fmt_msg, ...);
bool log_warning(const char* fmt_msg, ...);
bool log_debug(const char* fmt_msg, ...);
bool is_level_enabled(log_level level);
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "logger.h"

#define FILE_APPEND_CREATE "a"

#define MAX_LOG_SIZE 256

struct log_level_status
{
    bool enabled;
    char name[10];
    char color[11];
    char filename[MAX_FILE_NAME_SIZE];
};

struct logger_status
{
    bool is_logger_enabled;
    bool is_stderr_enabled;
    struct log_level_status level[4];
} status;

char _log_entry_fmt[] = "[%s] - %s\n"; // [level_tag] - message

char log_buffer[MAX_LOG_SIZE];

void logger_init(struct logger_init_args *args)
{
    status.is_logger_enabled = args->logs_enabled;
    if (!status.is_logger_enabled)
        return;
    status.is_stderr_enabled = args->stderr_enabled;

    for (int i = 0; i < 4; i++)
    {
        status.level[i].enabled = args->level_config[i].enabled;

        if (args->level_config[i].color[0] != 0)
        {
            strncpy(status.level[i].color, args->level_config[i].color, 11);
        }
        else
        {
            strcpy(status.level[i].color, NO_COLOR);
        }

        if (args->level_config[i].filename[0] != 0)
        {
            strncpy(status.level[i].filename, args->level_config[i].filename, MAX_FILE_NAME_SIZE);
        }
        else
        {
            status.level[i].filename[0] = 0;
        }
    }
    // Setup names by default
    strcpy(status.level[ERROR].name, "ERROR");
    strcpy(status.level[DEBUG].name, "DEBUG");
    strcpy(status.level[INFO].name, "INFO");
    strcpy(status.level[WARNING].name, "WARNING");

    return;
}

bool is_file_enabled(LogLevel level)
{
    return status.level[level].filename[0] != 0;
}

bool is_level_enabled(LogLevel level)
{
    return status.level[level].enabled;
}

bool _log_file(LogLevel level, char *fmt_msg, va_list argp)
{
    if (!is_file_enabled(level))
        return false;

    char *filename = status.level[level].filename;
    char *levelname = status.level[level].name;

    FILE *file = fopen(filename, FILE_APPEND_CREATE);
    if (file == NULL)
    {
        perror("Error while opening file");
        return true;
    }

    if (sprintf(log_buffer, _log_entry_fmt, levelname, fmt_msg) < 0)
    {
        perror("Error building log entry");
        fclose(file);
        return true;
    }

    if (vfprintf(file, log_buffer, argp) < 0)
    {
        perror("Error writing into file");
        fclose(file);
        return true;
    }

    fclose(file);

    return false;
}

bool _log_stderr(LogLevel level, char *fmt, va_list argp)
{
    if (!status.is_stderr_enabled)
        return false;

    char *levelname = status.level[level].name;
    char *color = status.level[level].color;

    if (fputs(color, stderr) == EOF)
    {
        perror("Error while adding color to console");
        return true;
    }

    if (sprintf(log_buffer, _log_entry_fmt, levelname, fmt) < 0)
    {
        perror("Error building log entry");
        return true;
    }

    if (vfprintf(stderr, log_buffer, argp) < 0)
    {
        perror("Error while logging into console");
        return true;
    }

    if (fputs(NO_COLOR, stderr) == EOF)
    {
        perror("Error while adding color to console\n");
        return true;
    }

    return false;
}

void set_context(LogLevel level)
{
    // nop
}

bool log_info(char *fmt_msg, ...)
{
    if (!is_level_enabled(INFO))
        return false;
    va_list argp;
    va_start(argp, fmt_msg);

    if (_log_stderr(INFO, fmt_msg, argp))
    {
        va_end(argp);
        return true;
    }
    // Restart the argument pointer because it was used by _log_stderr
    va_start(argp, fmt_msg);

    if (_log_file(INFO, fmt_msg, argp))
    {
        va_end(argp);

        return true;
    }
    va_end(argp);
    return false;
}
bool log_error(char *fmt_msg, ...)
{
    if (!is_level_enabled(ERROR))
        return false;
    va_list argp;
    va_start(argp, fmt_msg);

    if (_log_stderr(ERROR, fmt_msg, argp))
    {
        va_end(argp);

        return true;
    }
    // Restart the argument pointer because it was used by _log_stderr
    va_start(argp, fmt_msg);

    if (_log_file(ERROR, fmt_msg, argp))
    {
        va_end(argp);
        return true;
    }
    va_end(argp);
    return false;
}
bool log_warning(char *fmt_msg, ...)
{
    if (!is_level_enabled(WARNING))
        return false;
    va_list argp;
    va_start(argp, fmt_msg);

    if (_log_stderr(WARNING, fmt_msg, argp))
    {
        va_end(argp);
        return true;
    }

    // Restart the argument pointer because it was used by _log_stderr
    va_start(argp, fmt_msg);

    if (_log_file(WARNING, fmt_msg, argp))
    {
        va_end(argp);
        return true;
    }
    va_end(argp);
    return false;
}
bool log_debug(char *fmt_msg, ...)
{
    if (!is_level_enabled(DEBUG))
        return false;
    va_list argp;
    va_start(argp, fmt_msg);

    if (_log_stderr(DEBUG, fmt_msg, argp))
    {
        va_end(argp);
        return true;
    }
    // Restart the argument pointer because it was used by _log_stderr
    va_start(argp, fmt_msg);

    if (_log_file(DEBUG, fmt_msg, argp))
    {
        va_end(argp);
        return true;
    }
    va_end(argp);
    return false;
}

void logger_cleanup()
{
    // no mallocs yet ;D
}
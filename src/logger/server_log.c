#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "logger/server_log.h"
#include "logger/logger.h"

bool write_server_log(const char *log_msg_fmt, ...)
{
    va_list argp;
    va_start(argp, log_msg_fmt);

    size_t remaining_size = 0;
    uint8_t *write_ptr = buffer_write_ptr(logs_file_data.buff, &remaining_size);
    size_t chars_written = vsnprintf((char *)write_ptr, remaining_size, log_msg_fmt, argp);
    if (chars_written < 0)
    {
        va_end(argp);
        return true;
    }
    buffer_write_adv(logs_file_data.buff, chars_written);

    va_end(argp);
    return false;
}

bool flush_logs()
{
    struct buffer *logs_buffer = logs_file_data.buff;
    FILE *logs_file = logs_file_data.stream;
    size_t max_read = 0;
    uint8_t *msg = buffer_read_ptr(logs_buffer, &max_read);
    if (max_read != 0)
    {
        ssize_t chars_written = fprintf(logs_file, "%s\n", msg);
        fflush(logs_file);

        if (chars_written < 0)
            return true;

        if ((size_t)chars_written < max_read)
        {
            // mark the read chars from buffer to keep reading from it.
            buffer_read_adv(logs_buffer, chars_written);
        }
        else
        {
            buffer_reset(logs_buffer);
        }
    }
    return false;
}

bool init_server_logger(const char *filename)
{
    errno = 0;
    logs_file_data.stream = fopen(filename, LOGS_FILE_MODE);
    if (logs_file_data.stream == NULL)
    {
        log_error("Could not initialize log file: %s", strerror(errno));
        return true;
    }
    logs_file_data.buff = malloc(sizeof(struct buffer));
    if (logs_file_data.buff == NULL)
    {
        log_error("Could not allocate space for buffer");
        return true;
    }
    buffer_init(logs_file_data.buff, LOGS_BUFFER_SIZE, malloc(LOGS_BUFFER_SIZE));
    return false;
}

void free_server_logger()
{
    flush_logs(); // try to flush logs before closing
    free(logs_file_data.buff->data);
    free(logs_file_data.buff);
    fclose(logs_file_data.stream);
}
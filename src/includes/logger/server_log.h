#ifndef SERVER_LOG_H_
#define SERVER_LOG_H_
#include <stdio.h>
#include <stdbool.h>

#include "utils/buffer.h"

#define LOGS_BUFFER_SIZE 1024
#define LOGS_FILE_MODE "a"

struct logs_file_data
{
    FILE* stream;
    struct buffer* buff;
};

bool init_server_logger(const char* filename);
struct logs_file_data get_file_data();
bool write_server_log(const char* log_msg_fmt, ...);
bool flush_logs();
void free_server_logger();

#endif

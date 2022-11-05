#include <string.h>

#include "parser/client_parser.h"

enum command parse_client_message(void* msg, size_t msg_size, int client_socket) {
    if (strncmp(msg, "close\n", msg_size) == 0)
    {
        return CLOSE;
    }
    return ECHO;
}

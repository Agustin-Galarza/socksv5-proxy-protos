#ifndef CLIENT_PARSER_H_
#define CLIENT_PARSER_H_

#include <stddef.h>

enum command
{
    CLOSE = 0,
    ECHO
};

// Parses msg and returns an action to perform. Returns -1 on error
enum command parse_client_message(void *msg,
                                  size_t msg_size,
                                  int client_socket);
#endif
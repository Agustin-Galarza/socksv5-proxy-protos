#ifndef TCPCLIENTUTIL_H_
#define TCPCLIENTUTIL_H_

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <netdb.h>

#define MAX_RESPONSE_LEN 512
#define EOL "\r\n"
#define EOM EOL "." EOL

typedef enum {
    CMD_CAP = 0,
    CMD_TOKEN,
    CMD_STATS,
    CMD_USERS,
    CMD_BUFFSIZE,
    CMD_SET_BUFFSIZE,
    CMD_ADD_USER,
    CMD_SIZE,
} Commands;

// Create and connect a new TCP client socket
int tcpClientSocket(const char *server, const char *service);
bool read_hello(int sock);

bool authenticate(int sock, const char *token);
bool capabilities(int sock);
bool stats(int sock);
bool users(int sock);
bool buffsize(int sock);
bool set_buffsize(int sock, const char * size);
bool add_user(int sock, const char *username_password);

#endif

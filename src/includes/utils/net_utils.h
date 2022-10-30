#ifndef NET_UTILS_H_
#define NET_UTILS_H_
#include <sys/socket.h>

struct sockaddr get_socket_addr(int socket_descriptor);

#endif
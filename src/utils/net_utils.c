#include "utils/net_utils.h"

struct sockaddr get_socket_addr(int socket_descriptor) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct sockaddr* sock_addr_ptr = (struct sockaddr*)&client_addr;
    // close connection to client
    getpeername(socket_descriptor, sock_addr_ptr, &client_addr_len);
    return *sock_addr_ptr;
}
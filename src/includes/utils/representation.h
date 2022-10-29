#ifndef REPRESENTATION_H_
#define REPRESENTATION_H_

#include <sys/socket.h>

// reads addr_info struct and writes the address in addr_str and also returns it
char *print_address_info(struct addrinfo *addr_info, char addr_str[]);
// reads address struct and writes its value in addr_str and also returns it
char *print_address(struct sockaddr *address, char *addr_str);
char *print_address_from_descriptor(int socket_descriptor, char *addr_str);

#endif
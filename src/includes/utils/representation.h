#ifndef REPRESENTATION_H_
#define REPRESENTATION_H_

#include <sys/socket.h>
#define TIME_FMT_STR_MAX_SIZE 128

// reads addr_info struct and writes the address in addr_str and also returns it
char* print_address_info(struct addrinfo* addr_info, char addr_str[]);
// reads address struct and writes its value in addr_str and also returns it
char* print_address(struct sockaddr* address, char* addr_str);
char* print_address_from_descriptor(int socket_descriptor, char* addr_str);
/**
 * Creates representation of current date and time and writes it in addr_str and also returns it.
 * The returned string is guaranteed to be smaller or equal to TIME_FMT_STR_MAX_SIZE
 * On error the return value is an empty string.
 */
char* get_datetime_string(char* datetime_str);
#endif
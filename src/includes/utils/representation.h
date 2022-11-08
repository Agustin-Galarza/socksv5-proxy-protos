#ifndef REPRESENTATION_H_
#define REPRESENTATION_H_

#include <sys/socket.h>
#include <netdb.h>

#include "utils/netutils.h" // MAX_PORT_STR_LEN
#define TIME_FMT_STR_MAX_SIZE 128

#define ADDR_STR_MAX_SIZE 128


/**
 * Representación de una dirección IP, la cuál puede representarse como IPv4 o IPv6,
 * donde se representa como un entero, o como un FQDN que se encuentra expresado
 * como string.
 */
enum address_type {
    IPV4_ADDR,
    IPV6_ADDR,
    FQDN_ADDR
};
struct address_representation {
    enum address_type type;
    char* hostname;
    char port[MAX_PORT_STR_LEN];
};

// reads addr_info struct and writes the address in addr_str and also returns it
char* print_address_info(struct addrinfo* addr_info, char addr_str[]);
// reads address struct and writes its value in addr_str and also returns it
char* print_address(struct sockaddr* address, char* addr_str);
char* print_address_from_descriptor(int socket_descriptor, char* addr_str);
char* print_address_from_repr(struct address_representation* addr, char* addr_str);
/**
 * Creates representation of current date and time and writes it in addr_str and also returns it.
 * The returned string is guaranteed to be smaller or equal to TIME_FMT_STR_MAX_SIZE
 * On error the return value is an empty string.
 */
char* get_datetime_string(char* datetime_str);
#endif

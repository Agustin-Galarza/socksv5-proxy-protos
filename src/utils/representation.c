#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "utils/representation.h"
#include "utils/net_utils.h"

char* print_address_info(struct addrinfo* aip, char addr[]) {
    char buffer[INET6_ADDRSTRLEN];
    const char* addr_aux;
    if (aip->ai_family == AF_INET)
    {
        struct sockaddr_in* sinp;
        sinp = (struct sockaddr_in*)aip->ai_addr;
        addr_aux = inet_ntop(AF_INET, &sinp->sin_addr, buffer, INET_ADDRSTRLEN);
        if (addr_aux == NULL)
            addr_aux = "unknown";
        strcpy(addr, addr_aux);
        if (sinp->sin_port != 0)
        {
            sprintf(addr + strlen(addr), ": %d", ntohs(sinp->sin_port));
        }
    }
    else if (aip->ai_family == AF_INET6)
    {
        struct sockaddr_in6* sinp;
        sinp = (struct sockaddr_in6*)aip->ai_addr;
        addr_aux = inet_ntop(AF_INET6, &sinp->sin6_addr, buffer, INET6_ADDRSTRLEN);
        if (addr_aux == NULL)
            addr_aux = "unknown";
        strcpy(addr, addr_aux);
        if (sinp->sin6_port != 0)
            sprintf(addr + strlen(addr), ": %d", ntohs(sinp->sin6_port));
    }
    else
        strcpy(addr, "unknown");
    return addr;
}

char*
print_address(struct sockaddr* address, char* addr_str) {

    void* numericAddress;

    in_port_t port;

    switch (address->sa_family)
    {
    case AF_INET:
        numericAddress = &((struct sockaddr_in*)address)->sin_addr;
        port = ntohs(((struct sockaddr_in*)address)->sin_port);
        break;
    case AF_INET6:
        numericAddress = &((struct sockaddr_in6*)address)->sin6_addr;
        port = ntohs(((struct sockaddr_in6*)address)->sin6_port);
        break;
    default:
        strcpy(addr_str, "[unknown type]"); // Unhandled type
        return addr_str;
    }
    // Convert binary to printable address
    if (inet_ntop(address->sa_family, numericAddress, addr_str, INET6_ADDRSTRLEN) == NULL)
        strcpy(addr_str, "[invalid address]");
    else
    {
        if (port != 0)
            sprintf(addr_str + strlen(addr_str), ":%u", port);
    }
    return addr_str;
}

char* print_address_from_descriptor(int socket_descriptor, char* addr_str) {
    struct sockaddr addr = get_socket_addr(socket_descriptor);
    return print_address(&addr, addr_str);
}

char* get_datetime_string(char* datetime_str) {
    time_t t = time(NULL);
    // localtime return a pointer to a static resource so it must NOT be freed
    struct tm* tm = localtime(&t);
    // Writes time into format like 'Thu Apr 14 22:39:03 2016'
    // see https://stackoverflow.com/questions/1442116/how-to-get-the-date-and-time-values-in-a-c-program
    if (strftime(datetime_str, TIME_FMT_STR_MAX_SIZE, "%c", tm) == 0)
        datetime_str[0] = '\0';

    return datetime_str;
}
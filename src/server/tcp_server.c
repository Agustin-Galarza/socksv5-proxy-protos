#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>


#include "server/tcp_server.h"
#include "utils/logger/logger.h"
#include "utils/buffer.h"
#include "utils/representation.h"
#include "utils/selector.h"
#include "utils/netutils.h"
#include "utils/parser/negotiation.h"
#include "utils/parser/request.h"
#include "server/socks5_server.h"
#include "server/admin_server.h"

/*********************************
|          Definitions          |
*********************************/

#define IPV4_HOST_ADDR "127.0.0.1"

#define IPV6_HOST_ADDR "::"

#define LOGS_BUFFER_SIZE 256

struct socket_descriptors {
    socket_descriptor ipv4_fd;
    socket_descriptor ipv6_fd;
};

struct server_sockets {
    struct socket_descriptors socks5;
    struct socket_descriptors admin;
};

/**************************************
|          Global Variables          |
**************************************/

/**
 * @brief defines if the server should keep running
 */
bool server_active = true;

/*******************************************
|          Function declarations          |
*******************************************/

void handle_sig_kill(int signum);

struct server_sockets
    server_init(struct server_config* config);

bool start_listening(socket_descriptor socket, int max_connections);

socket_descriptor
setup_passive_socket(struct sockaddr* sockaddr_ptr, size_t sockaddr_size);

void close_sockets(struct server_sockets sockets);

void admin_server_handle_read(struct selector_key* key);

/**********************************************
|          Function Implementations          |
**********************************************/


bool run_server(struct server_config* config) {
    /************* Variables and Init *************/
    signal(SIGINT, handle_sig_kill);
    signal(SIGKILL, handle_sig_kill);
    signal(SIGTERM, handle_sig_kill);

    bool error = false;

    fd_selector selector = NULL;
    struct server_sockets sockets;
    memset(&sockets, NO_SOCKET, sizeof(sockets));

    const struct selector_init init_args = {
        .select_timeout = {
            .tv_nsec = 0,
            .tv_sec = 10,
        },
        .signal = SIGALRM,
    };

    // Starting server
    sockets = server_init(config);

    if (sockets.socks5.ipv4_fd == NO_SOCKET) {
        log_error("Could not initialize server");
        error = true;
        goto end;
    }

    /************* Algorithm *************/

    char port_str[MAX_PORT_STR_LEN];
    port_itoa(config->port, port_str);

    // Set all sockets to listen
    if (start_listening(sockets.socks5.ipv4_fd, config->max_clients)) {
        error = true;
        goto end;
    }
    if (start_listening(sockets.socks5.ipv6_fd, config->max_clients)) {
        error = true;
        goto end;
    }
    if (start_listening(sockets.admin.ipv4_fd, config->max_clients)) {
        error = true;
        goto end;
    }
    if (start_listening(sockets.admin.ipv6_fd, config->max_clients)) {
        error = true;
        goto end;
    }

    log_info("Server waiting for connections on port %s", port_str);


    // inicializamos el selector
    if (selector_init(&init_args)) {
        log_error("Could not initialize selector library");

        error = true;
        goto end;
    }

    selector = selector_new(config->max_clients);
    if (selector == NULL) {
        log_error("Could not create new selector");

        error = true;
        goto end;
    }

    selector_status status = selector_register(selector, sockets.socks5.ipv4_fd, get_socks5_server_handlers(), OP_READ, &socks5_server_data);
    if (status != SELECTOR_SUCCESS) {
        log_error("Could not register socks5 IPv4 socket");

        error = true;
        goto end;
    }

    status = selector_register(selector, sockets.socks5.ipv6_fd, get_socks5_server_handlers(), OP_READ, &socks5_server_data);
    if (status != SELECTOR_SUCCESS) {
        log_error("Could not register socks5 IPv6 socket");

        error = true;
        goto end;
    }

    status = selector_register(selector, sockets.admin.ipv4_fd, get_admin_server_handlers(), OP_READ, &admin_server_data);
    if (status != SELECTOR_SUCCESS) {
        log_error("Could not register admin IPv4 socket");

        error = true;
        goto end;
    }

    status = selector_register(selector, sockets.admin.ipv6_fd, get_admin_server_handlers(), OP_READ, &admin_server_data);
    if (status != SELECTOR_SUCCESS) {
        log_error("Could not register admin IPv6 socket");

        error = true;
        goto end;
    }

    /** Loop del servidor **/

    for (; server_active;) {
        errno = 0;
        status = selector_select(selector);
        if (status != SELECTOR_SUCCESS) {
            log_error(
                "Problems while executing selector: %s%s%s",
                selector_error(status),
                status == SELECTOR_IO ? " - " : "",
                status == SELECTOR_IO ? strerror(errno) : "");
            goto end;
        }
    }

end:
    selector_destroy(selector);
    selector_close();
    close_sockets(sockets);
    socks5_close_server();

    return error;
}

//TODO: remove
static void print_user(struct user_list_user* usr) {
    log_debug("- %s:%s", usr->username, usr->password);
}

struct server_sockets
    server_init(struct server_config* config) {
    struct server_sockets sockets;
    memset(&sockets, NO_SOCKET, sizeof(sockets));

    // Run initialization scripts
    if (socks5_init_server(config->max_clients)) {
        log_error("Could not initialize socks5 server");
        return sockets;
    }

    user_list_t* users = user_list_init(MAX_CLIENTS_AMOUNT);
    for (int i = 0;config->users[i].name != NULL;i++) {
        user_list_add(users, config->users[i].name, config->users[i].pass);
    }
    log_debug("Initial Users:");
    user_list_for_each(users, print_user);

    if (admin_server_init(users)) {
        log_error("Could not initialize admin server");
        return sockets;
    }

    // Socks5 IPv4
    struct sockaddr_in socks5_ipv4_sockaddr;
    memset(&socks5_ipv4_sockaddr, 0, sizeof(socks5_ipv4_sockaddr));
    socks5_ipv4_sockaddr.sin_family = AF_INET;
    socks5_ipv4_sockaddr.sin_port = htons(config->port);
    socks5_ipv4_sockaddr.sin_addr.s_addr = inet_addr(IPV4_HOST_ADDR);

    sockets.socks5.ipv4_fd = setup_passive_socket((struct sockaddr*)&socks5_ipv4_sockaddr, sizeof(socks5_ipv4_sockaddr));
    if (sockets.socks5.ipv4_fd == NO_SOCKET) {
        log_error("Could not create socks5 IPv4 socket");

        return sockets;
    }

    // Socks5 IPv6
    struct sockaddr_in6 socks5_ipv6_sockaddr;
    socks5_ipv6_sockaddr.sin6_family = AF_INET6;
    socks5_ipv6_sockaddr.sin6_port = htons(config->port);
    socks5_ipv6_sockaddr.sin6_addr = in6addr_loopback;

    sockets.socks5.ipv6_fd = setup_passive_socket((struct sockaddr*)&socks5_ipv6_sockaddr, sizeof(socks5_ipv6_sockaddr));
    if (sockets.socks5.ipv6_fd == NO_SOCKET) {
        log_error("Could not create socks5 IPv6 socket");

        return sockets;
    }

    // Admin IPv4
    struct sockaddr_in admin_ipv4_sockaddr;
    memset(&admin_ipv4_sockaddr, 0, sizeof(admin_ipv4_sockaddr));
    admin_ipv4_sockaddr.sin_family = AF_INET;
    admin_ipv4_sockaddr.sin_port = htons(config->admin_port);
    admin_ipv4_sockaddr.sin_addr.s_addr = inet_addr(IPV4_HOST_ADDR);

    sockets.admin.ipv4_fd = setup_passive_socket((struct sockaddr*)&admin_ipv4_sockaddr, sizeof(admin_ipv4_sockaddr));
    if (sockets.admin.ipv4_fd == NO_SOCKET) {
        log_error("Could not create admin IPv4 socket");

        return sockets;
    }

    // Admin IPv6
    struct sockaddr_in6 admin_ipv6_sockaddr;
    admin_ipv6_sockaddr.sin6_family = AF_INET6;
    admin_ipv6_sockaddr.sin6_port = htons(config->admin_port);
    admin_ipv6_sockaddr.sin6_addr = in6addr_loopback;
    // inet_pton(AF_INET6, IPV6_HOST_ADDR, &admin_ipv6_sockaddr.sin6_addr);

    sockets.admin.ipv6_fd = setup_passive_socket((struct sockaddr*)&admin_ipv6_sockaddr, sizeof(admin_ipv6_sockaddr));
    if (sockets.admin.ipv6_fd == NO_SOCKET) {
        log_error("Could not create admin IPv6 socket");

        return sockets;
    }

    return sockets;
}

socket_descriptor
setup_passive_socket(struct sockaddr* sockaddr_ptr, size_t sockaddr_size) {
    errno = 0;

    socket_descriptor socket_fd = socket(sockaddr_ptr->sa_family, SOCK_STREAM, IPPROTO_TCP);

    if (socket_fd == NO_SOCKET) {
        char addr_buffer[ADDR_STR_MAX_SIZE];
        log_error("Could not create socket on %s: %s",
            print_address(sockaddr_ptr, addr_buffer),
            strerror(errno));
        return NO_SOCKET;
    }

    int reuseaddr_option_value = true;
    if (
        setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            (char*)&reuseaddr_option_value,
            sizeof(reuseaddr_option_value)) < 0) {
        log_error("Could not configure socket: %s", strerror(errno));

        close(socket_fd);
        return NO_SOCKET;
    }

    if (bind(socket_fd, sockaddr_ptr, sockaddr_size) != 0) {
        char addr_str[ADDR_STR_MAX_SIZE];
        log_error("Could not bind socket to %s: %s", print_address(sockaddr_ptr, addr_str), strerror(errno));

        close(socket_fd);
        return NO_SOCKET;
    }

    return socket_fd;
}

void handle_sig_kill(int signum) {
    char datetime_str[TIME_FMT_STR_MAX_SIZE];
    get_datetime_string(datetime_str);

    char log_msg[LOGS_BUFFER_SIZE];

#ifdef __GLIBC__ 
    snprintf(log_msg, LOGS_BUFFER_SIZE, "Server abruptly stopped on %s by %s", get_datetime_string(datetime_str), strsignal(signum));
#endif

    log_warning(log_msg);

    socks5_close_server();
    admin_server_close();

    server_active = false;
}


bool start_listening(socket_descriptor socket, int max_connections) {
    if (listen(socket, max_connections) != 0) {
        char addr_str[ADDR_STR_MAX_SIZE];
        log_error("Could not listen on %s: %s", print_address_from_descriptor(socket, addr_str), strerror(errno));

        return true;
    }

    if (selector_fd_set_nio(socket) == -1) {
        log_error("Could not handle server socket flags: %s", strerror(errno));

        return true;
    }

    return false;
}

void close_sockets(struct server_sockets sockets) {
    if (sockets.socks5.ipv4_fd >= 0)
        close(sockets.socks5.ipv4_fd);
    if (sockets.socks5.ipv6_fd >= 0)
        close(sockets.socks5.ipv4_fd);
    if (sockets.admin.ipv4_fd >= 0)
        close(sockets.socks5.ipv4_fd);
    if (sockets.admin.ipv6_fd >= 0)
        close(sockets.socks5.ipv4_fd);
}


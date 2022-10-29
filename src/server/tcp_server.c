
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "server/tcp_server.h"
#include "logger/logger.h"
#include "utils/buffer.h"
#include "utils/representation.h"
/**
 * @brief tcp server that waits pasively on a given port and for each incoming requests starts a new active conection. The server then performs a series of tasks based on the sent command via tcp.
 *
 * This is a
 *
 */

#define NO_SOCKET -1

#define CLIENT_BUFFER_SIZE 1024

#define CLOSE_CLIENT_BUFFERS                          \
    {                                                 \
        for (int i = 0; i < config->max_clients; i++) \
        {                                             \
            buffer_close(client_buffers[i]);          \
        }                                             \
        free(client_buffers);                         \
    }

#define CLOSE_CLIENT_SOCKETS                          \
    {                                                 \
        for (int i = 0; i < config->max_clients; i++) \
        {                                             \
            if (client_sockets[i] > 0)                \
                close(client_sockets[i]);             \
        }                                             \
        free(client_sockets);                         \
    }

typedef int socket_descriptor;

socket_descriptor
create_passive_socket(struct server_config *config);

// returns max socket descripor on success
socket_descriptor
config_socket_descriptors(fd_set *read_fd_set_ptr,
                          socket_descriptor server_socket,
                          socket_descriptor *client_sockets,
                          size_t clients_ammount);

socket_descriptor
handle_new_connection(socket_descriptor server_socket);

bool run_server(struct server_config *config)
{
    // Create all buffers to store client message data
    struct buffer **client_buffers = malloc(sizeof(struct buffer *) * config->max_clients);
    for (int i = 0; i < config->max_clients; i++)
    {
        client_buffers[i] = buffer_init(CLIENT_BUFFER_SIZE);
    }
    // set up descriptors and fd of clients
    fd_set read_fd_set;
    size_t client_sockets_alloc_size = sizeof(socket_descriptor *) * config->max_clients;
    socket_descriptor *client_sockets = malloc(client_sockets_alloc_size); // init client sockets descriptors array and set everything to 0
    memset(client_sockets, 0, client_sockets_alloc_size);

    size_t client_count = 0;

    socket_descriptor server_socket = create_passive_socket(config);

    if (server_socket == NO_SOCKET)
    {
        CLOSE_CLIENT_BUFFERS
        return true; // TODO: define return on error
    }

    // listen(server_socket);
    if (listen(server_socket, config->initial_connections) != 0)
    {
        log_error("Could not listen to port %s: %s", config->port, strerror(errno));

        close(server_socket);
        CLOSE_CLIENT_BUFFERS
        return true;
    }

    log_info("Server waiting for connections on port %s", config->port);

    bool server_active = true;

    for (; server_active;)
    {
        // configure descriptors
        socket_descriptor max_socket_descriptor =
            config_socket_descriptors(&read_fd_set, server_socket, client_sockets, config->max_clients);

        // TODO: add read fds, timeout and signal management
        if (pselect(max_socket_descriptor + 1, &read_fd_set, NULL, NULL, NULL, NULL) < 0 && errno != EINTR)
        {
            log_error("Error while waiting for activity");

            close(server_socket);
            CLOSE_CLIENT_SOCKETS
            CLOSE_CLIENT_BUFFERS
            return true;
        }

        if (FD_ISSET(server_socket, &read_fd_set))
        {
            if (client_count == config->max_clients)
            {
                // there's no more capacity for new connections
            }
            else
            {
                socket_descriptor new_client = handle_new_connection(server_socket);

                if (new_client > 0)
                {

                    // add new client to array
                    for (int i = 0; i < config->max_clients; i++)
                    {
                        if (client_sockets[i] == 0)
                        {
                            client_sockets[i] = new_client;
                            break;
                        }
                    }
                    client_count++;
                }
            }
        }

        for (int i = 0; i < config->max_clients; i++)
        {
            socket_descriptor client_socket = client_sockets[i];
            if (!FD_ISSET(client_socket, &read_fd_set))
                continue;

            int ammount_read = read(client_socket,
                                    buffer_get_data(client_buffers[i]),
                                    buffer_get_remaining_size(client_buffers[i]));
            if (ammount_read < 0)
            {
                log_error("Could not read from client with descriptor %d", client_socket);

                CLOSE_CLIENT_BUFFERS
                CLOSE_CLIENT_SOCKETS
                close(server_socket);
                return true;
            }

            if (ammount_read == 0)
            {
                // close connection to client
                char addr_buf[200]; // TODO:remove magic number
                log_info("Closing connection to %s", print_address_from_descriptor(client_socket, addr_buf));

                close(client_socket);
                client_sockets[i] = 0;
            }
            else
            {
                // TODO: do something with message
                char *msg = buffer_get_data(client_buffers[i]);
                msg[ammount_read] = '\0';
                char addr_buf[200]; // TODO:remove magic number
                log_info("New message from %s: %s",
                         print_address_from_descriptor(client_socket, addr_buf),
                         msg);
                buffer_clear(client_buffers[i]);
            }
        }
    }
    CLOSE_CLIENT_BUFFERS
    CLOSE_CLIENT_SOCKETS
    close(server_socket);
    return false;
}

socket_descriptor create_passive_socket(struct server_config *config)
{
    errno = 0;

    struct addrinfo addr_config;
    memset(&addr_config, '\0', sizeof(addr_config));
    addr_config.ai_family = config->version == IPV4 ? AF_INET : AF_INET6;
    addr_config.ai_flags = AI_PASSIVE;
    addr_config.ai_protocol = IPPROTO_TCP;
    addr_config.ai_socktype = SOCK_STREAM;

    struct addrinfo *addr_list;

    if (getaddrinfo(NULL, config->port, &addr_config, &addr_list) != 0)
    {
        log_error("Could not parse server config: %s", strerror(errno));

        freeaddrinfo(addr_list); // TODO: define cleanup management
        return NO_SOCKET;
    }
    if (addr_list == NULL)
    {
        log_error("Could not get address for server: %s", strerror(errno));

        freeaddrinfo(addr_list);
        return NO_SOCKET;
    }

    socket_descriptor server_socket = socket(addr_list->ai_family, addr_list->ai_socktype, addr_list->ai_protocol);

    if (server_socket == NO_SOCKET)
    {
        char addr_buffer[200];
        log_error("Could not create socket on %s: %s", print_address_info(addr_list, addr_buffer), strerror(errno));

        freeaddrinfo(addr_list);
        return NO_SOCKET;
    }

    // set master socket to allow multiple connections , this is just a good habit, it will work without this
    int reuseaddr_option_value = true;
    if (
        setsockopt(
            server_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            (char *)&reuseaddr_option_value,
            sizeof(reuseaddr_option_value)) < 0)
    {
        log_error("Could not configure socket: %s", strerror(errno));

        freeaddrinfo(addr_list);
        close(server_socket);
        return NO_SOCKET;
    }

    if (bind(server_socket, addr_list->ai_addr, addr_list->ai_addrlen) != 0)
    {
        log_error("Could not bind socket: %s", strerror(errno));

        freeaddrinfo(addr_list);
        close(server_socket);
        return NO_SOCKET;
    }

    freeaddrinfo(addr_list);
    return server_socket;
}

socket_descriptor
config_socket_descriptors(fd_set *read_fd_set_ptr,
                          socket_descriptor server_socket,
                          socket_descriptor *client_sockets,
                          size_t clients_ammount)
{
    socket_descriptor max_socket_desc;
    FD_ZERO(read_fd_set_ptr);

    FD_SET(server_socket, read_fd_set_ptr);
    max_socket_desc = server_socket;

    for (int i = 0; i < clients_ammount; i++)
    {
        socket_descriptor client_socket = client_sockets[i];

        if (client_socket > 0)
            FD_SET(client_socket, read_fd_set_ptr);

        if (client_socket > max_socket_desc)
            max_socket_desc = client_socket;
    }

    return max_socket_desc;
}

socket_descriptor
handle_new_connection(socket_descriptor server_socket)
{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    socket_descriptor new_connection = accept(server_socket,
                                              (struct sockaddr *)&client_addr,
                                              &client_addr_len);
    if (new_connection < 0)
    {
        log_error("New connection refused: %s", strerror(errno));
        return -1;
    }
    char addr_buf[200]; // TODO: remove magic number
    log_info("New connection to %s", print_address((struct sockaddr *)&client_addr, addr_buf));

    return new_connection;
}
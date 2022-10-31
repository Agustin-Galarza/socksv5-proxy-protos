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
#include <stdarg.h>

#include "server/tcp_server.h"
#include "logger/logger.h"
#include "utils/buffer.h"
#include "utils/representation.h"

/*********************************
|          Definitions          |
*********************************/

#define NO_SOCKET -1

#define ADDR_BUF_SIZE 128

#define CLIENT_BUFFER_SIZE 1024

#define LOGS_FILE_MODE "a"

#define LOGS_BUFFER_SIZE 1024

typedef int socket_descriptor;

enum command
{
    CLOSE = 0,
    ECHO
};

/**************************************
|          Global Variables          |
**************************************/

/**
 * @brief pointer to the file for logging user activity
 */
FILE *logs_file;
/**
 * @brief buffer to store all the user activity logs
 */
struct buffer *logs_buffer;
/**
 * @brief defines if the server should keep running
 */
bool server_active = true;

/*******************************************
|          Function declarations          |
*******************************************/

void handle_sig_kill(int signum);

socket_descriptor
create_passive_socket(struct server_config *config);

// returns max socket descripor on success
socket_descriptor
config_socket_descriptors(fd_set *read_fd_set_ptr,
                          fd_set *write_fd_set_ptr,
                          socket_descriptor server_socket,
                          socket_descriptor *client_sockets,
                          int logs_file_fd,
                          size_t clients_ammount);

socket_descriptor
handle_new_connection(socket_descriptor server_socket);

bool flush_logs();

bool add_new_client_log(socket_descriptor client_fd);

bool add_disconnected_client_log(socket_descriptor client_fd);

// Parses msg and returns an action to perform. Returns -1 on error
enum command parse_client_message(char *msg,
                                  size_t msg_size,
                                  socket_descriptor client_socket);

bool write_to_client(socket_descriptor client_socket, struct buffer *client_buffer);

bool write_server_log(const char *log_msg_fmt, ...);

/**********************************************
|          Function Implementations          |
**********************************************/

bool run_server(struct server_config *config)
{
    signal(SIGINT, handle_sig_kill);
    signal(SIGKILL, handle_sig_kill);
    signal(SIGTERM, handle_sig_kill);

    bool error = false;
    // Create all buffers to store client message data
    struct buffer **client_buffers = malloc(sizeof(struct buffer *) * config->max_clients);
    for (size_t i = 0; i < config->max_clients; i++)
    {
        client_buffers[i] = buffer_init(CLIENT_BUFFER_SIZE);
    }
    // set up descriptors and fd of clients
    fd_set read_fd_set;
    fd_set write_fd_set;
    size_t client_sockets_alloc_size = sizeof(socket_descriptor *) * config->max_clients;
    socket_descriptor *client_sockets = malloc(client_sockets_alloc_size); // init client sockets descriptors array and set everything to 0
    memset(client_sockets, 0, client_sockets_alloc_size);

    // prepare and open logs file
    logs_file = fopen(config->logs_filename, LOGS_FILE_MODE);
    int logs_file_fd = fileno(logs_file);
    logs_buffer = buffer_init(LOGS_BUFFER_SIZE);

    size_t client_count = 0;

    // Starting server
    char *time_msg = malloc(TIME_FMT_STR_MAX_SIZE);
    get_datetime_string(time_msg);
    if (write_server_log("Starting server on %s\n", time_msg))
    {
        log_error("Could not write server log");
        error = true;
        goto close_after_logs_buffer;
    }
    free(time_msg);

    socket_descriptor server_socket = create_passive_socket(config);

    if (server_socket == NO_SOCKET)
    {
        error = true;
        goto close_after_logs_buffer;
    }

    if (listen(server_socket, config->initial_connections) != 0)
    {
        log_error("Could not listen to port %s: %s", config->port, strerror(errno));

        error = true;
        goto close_after_server_socket;
    }

    log_info("Server waiting for connections on port %s", config->port);

    for (; server_active;)
    {
        // configure descriptors
        socket_descriptor max_socket_descriptor =
            config_socket_descriptors(&read_fd_set, &write_fd_set, server_socket, client_sockets, logs_file_fd, config->max_clients);

        // TODO: add timeout and signal management
        if (pselect(max_socket_descriptor + 1, &read_fd_set, &write_fd_set, NULL, NULL, NULL) < 0 && errno != EINTR)
        {
            log_error("Error while waiting for activity");

            error = true;
            goto close_after_server_socket;
        }

        if (FD_ISSET(server_socket, &read_fd_set))
        {
            if (client_count == config->max_clients)
            {
                // there's no more capacity for new connections
                log_warning("Refused new connection, max capacity of clients reached");
            }
            else
            {
                socket_descriptor new_client = handle_new_connection(server_socket);

                if (new_client > 0)
                {
                    // log new client. Write message into buffer to write when file is ready
                    if (add_new_client_log(new_client))
                    {
                        log_error("Could not generate new client log");

                        error = true;
                        goto close_after_server_socket;
                    }
                    // add new client to array
                    for (size_t i = 0; i < config->max_clients; i++)
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

        if (FD_ISSET(logs_file_fd, &write_fd_set))
        {
            if (flush_logs())
            {
                log_error("Could not write into logs file");

                error = true;
                goto close_after_server_socket;
            }
        }

        // manage client activity
        for (size_t i = 0; i < config->max_clients; i++)
        {
            socket_descriptor client_socket = client_sockets[i];
            struct buffer *client_buffer = client_buffers[i];

            if (FD_ISSET(client_socket, &read_fd_set))
            {
                // read client message
                char *msg = buffer_get_to_write(client_buffer);
                int ammount_read = read(client_socket,
                                        msg,
                                        buffer_get_remaining_write_size(client_buffer));
                if (ammount_read < 0)
                {
                    log_error("Could not read from client with descriptor %d", client_socket);

                    error = true;
                    goto close_after_server_socket;
                }

                if (ammount_read == 0)
                {
                    // close connection to client
                    char addr_buf[ADDR_BUF_SIZE];
                    log_info("Closing connection to %s", print_address_from_descriptor(client_socket, addr_buf));

                    add_disconnected_client_log(client_socket);

                    buffer_clear(client_buffer);
                    close(client_socket);
                    FD_CLR(client_socket, &write_fd_set);
                    client_sockets[i] = 0;
                    client_count--;
                }
                else
                {
                    buffer_mark_written(client_buffer, ammount_read);
                    msg[ammount_read] = '\0';

                    char addr_buf[ADDR_BUF_SIZE];
                    log_info("New message from %s: %s",
                             print_address_from_descriptor(client_socket, addr_buf),
                             msg);

                    switch (parse_client_message(msg, ammount_read, client_socket))
                    {
                    case CLOSE:
                        server_active = false;
                        char datetime_str[TIME_FMT_STR_MAX_SIZE];
                        char addr_str[ADDR_BUF_SIZE];

                        log_info("Stopping server on %s by order of %s",
                                 get_datetime_string(datetime_str),
                                 print_address_from_descriptor(client_socket, addr_str));
                        write_server_log("Stopping server on %s by order of %s",
                                         get_datetime_string(datetime_str),
                                         print_address_from_descriptor(client_socket, addr_str));
                        break;
                    case ECHO:

                        break;
                    default:
                        // Error
                        error = true;
                        goto close_after_server_socket;
                        break;
                    }
                }
            }
            if (FD_ISSET(client_socket, &write_fd_set))
            {
                if (write_to_client(client_socket, client_buffer))
                {
                    log_error("Could not write to client with descriptor %d", client_socket);

                    error = true;
                    goto close_after_server_socket;
                }
            }
        }
    }

close_after_server_socket:
    close(server_socket);
close_after_logs_buffer:
    flush_logs(); // try to flush logs before closing
    buffer_close(logs_buffer);
close_after_logs_file:
    fclose(logs_file);
close_after_client_sockets:
    for (size_t i = 0; i < config->max_clients; i++)
    {
        if (client_sockets[i] > 0)
            close(client_sockets[i]);
    }
    free(client_sockets);
close_after_client_buffers:
    for (size_t i = 0; i < config->max_clients; i++)
    {
        buffer_close(client_buffers[i]);
    }
    free(client_buffers);
    return error;
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
                          fd_set *write_fd_set_ptr,
                          socket_descriptor server_socket,
                          socket_descriptor *client_sockets,
                          int logs_file_fd,
                          size_t clients_ammount)
{
    socket_descriptor max_socket_desc;
    FD_ZERO(read_fd_set_ptr);
    FD_ZERO(write_fd_set_ptr);

    FD_SET(server_socket, read_fd_set_ptr);
    FD_SET(server_socket, write_fd_set_ptr);

    FD_SET(logs_file_fd, write_fd_set_ptr);

    max_socket_desc = server_socket > logs_file_fd ? server_socket : logs_file_fd;

    for (size_t i = 0; i < clients_ammount; i++)
    {
        socket_descriptor client_socket = client_sockets[i];

        if (client_socket > 0)
        {
            FD_SET(client_socket, read_fd_set_ptr);
            FD_SET(client_socket, write_fd_set_ptr);
        }

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
    char addr_buf[ADDR_BUF_SIZE];
    log_info("New connection to %s", print_address((struct sockaddr *)&client_addr, addr_buf));

    return new_connection;
}

bool add_new_client_log(socket_descriptor client_fd)
{
    char client_address_str[ADDR_BUF_SIZE];
    char time_fmt_str[TIME_FMT_STR_MAX_SIZE];

    print_address_from_descriptor(client_fd, client_address_str);

    get_datetime_string(time_fmt_str);
    if (time_fmt_str[0] == '\0')
    {
        log_error("Error while trying to generate datetime string");
        return true;
    }

    if (write_server_log("New connection from %s on %s\n", client_address_str, time_fmt_str))
    {
        return true;
    }

    return false;
}

bool add_disconnected_client_log(socket_descriptor client_fd)
{
    char client_address_str[ADDR_BUF_SIZE];
    char time_fmt_str[TIME_FMT_STR_MAX_SIZE];

    print_address_from_descriptor(client_fd, client_address_str);

    get_datetime_string(time_fmt_str);
    if (time_fmt_str[0] == '\0')
    {
        log_error("Error while trying to generate datetime string");
        return true;
    }

    if (write_server_log("Client %s disconnected on %s\n", client_address_str, time_fmt_str))
    {
        return true;
    }

    return false;
}

bool flush_logs()
{
    char *msg = buffer_get_to_read(logs_buffer);
    ssize_t msg_size = strlen(msg);
    if (msg_size != 0)
    {
        ssize_t chars_written = fprintf(logs_file, "%s\n", msg);
        fflush(logs_file);

        if (chars_written < 0)
            return true;

        if (chars_written < msg_size)
        {
            // mark the read chars from buffer to keep reading from it.
            buffer_mark_read(logs_buffer, chars_written);
        }
        else
        {
            buffer_clear(logs_buffer);
        }
    }
    return false;
}

enum command parse_client_message(char *msg, size_t msg_size, socket_descriptor client_socket)
{
    if (strncmp(msg, "close\n", msg_size) == 0)
    {
        return CLOSE;
    }
    return ECHO;
}

bool write_to_client(socket_descriptor client_socket, struct buffer *client_buffer)
{
    char *msg = buffer_get_to_read(client_buffer);
    ssize_t msg_size = strlen(msg);
    if (msg_size != 0)
    {
        ssize_t chars_written = send(client_socket, msg, msg_size, 0);
        if (chars_written == -1)
            return true;

        if (chars_written < msg_size)
        {
            buffer_mark_read(client_buffer, chars_written);
        }
        else
        {
            buffer_clear(client_buffer);
        }
    }
    return false;
}

void handle_sig_kill(int signum)
{
    char datetime_str[TIME_FMT_STR_MAX_SIZE];
    get_datetime_string(datetime_str);

    char log_msg[LOGS_BUFFER_SIZE];
    snprintf(log_msg, LOGS_BUFFER_SIZE, "Server abruptly stopped on %s by %s", get_datetime_string(datetime_str), strsignal(signum));

    log_warning(log_msg);
    fprintf(logs_file, "%s\n", log_msg);
    fflush(logs_file);

    server_active = false;
}

bool write_server_log(const char *log_msg_fmt, ...)
{
    va_list argp;
    va_start(argp, log_msg_fmt);

    size_t remaining_size = buffer_get_remaining_write_size(logs_buffer);

    size_t chars_written = vsnprintf(buffer_get_to_write(logs_buffer), remaining_size, log_msg_fmt, argp);
    if (chars_written < 0)
    {
        va_end(argp);
        return true;
    }
    buffer_mark_written(logs_buffer, chars_written);

    va_end(argp);
    return false;
}
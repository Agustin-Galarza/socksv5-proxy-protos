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

#include "server/tcp_server.h"
#include "logger/logger.h"
#include "utils/buffer.h"
#include "utils/representation.h"
#include "utils/selector.h"
#include "logger/server_log.h"
#include "parser/client_parser.h"

/*********************************
|          Definitions          |
*********************************/

#define NO_SOCKET -1

#define ADDR_BUF_SIZE 128

#define CLIENT_BUFFER_SIZE 1024

typedef int socket_descriptor;

/**
 *              --------
 * Client =====| Proxy |====== Remote
 *             -------
 *    ---->  |write_buffer| ----->
 *   <----  |read_buffer|  <-----
 */
struct client_data
{
    // Buffer used to write from Client to Remote
    struct buffer *write_buffer;
    // Buffer used to wrte from Remote to Client
    struct buffer *read_buffer;
};

/**************************************
|          Global Variables          |
**************************************/

/**
 * @brief defines if the server should keep running
 */
bool server_active = true;

struct server_data
{
    size_t max_clients;
    socket_descriptor fd;
    size_t client_count;
} server_data;

/*******************************************
|          Function declarations          |
*******************************************/

void handle_sig_kill(int signum);

socket_descriptor
server_init(struct server_config *config);

/**
 * @brief accepts new connection and returns the new client's socket descriptor
 */
socket_descriptor
accept_new_connection(socket_descriptor server_socket);

bool add_new_client_log(socket_descriptor client_fd);

bool add_disconnected_client_log(socket_descriptor client_fd);

bool write_to_client(socket_descriptor client_socket, struct buffer *client_buffer);

struct client_data *
generate_new_client_data();

void free_client_data(struct client_data *data);

bool add_new_client(socket_descriptor client, fd_selector selector);

// Event Handlers
void server_handle_read(struct selector_key *key);

void handle_file_write(struct selector_key *key);

void client_handle_read(struct selector_key *key);

void client_handle_write(struct selector_key *key);

void client_handle_close(struct selector_key *key);

struct fd_handler client_handlers = {
    .handle_read = client_handle_read,
    .handle_write = client_handle_write,
    .handle_block = NULL,
    .handle_close = client_handle_close,
};

/**********************************************
|          Function Implementations          |
**********************************************/

bool run_server(struct server_config *config)
{
    signal(SIGINT, handle_sig_kill);
    signal(SIGKILL, handle_sig_kill);
    signal(SIGTERM, handle_sig_kill);

    bool error = false;

    fd_selector selector;

    // prepare and open logs file
    if (init_server_logger(config->logs_filename))
    {
        log_error("Error initializing logs file");
        return true;
    }
    int logs_file_fd = fileno(logs_file_data.stream);

#define END goto close_after_logs_file

    // Starting server
    char *time_msg = malloc(TIME_FMT_STR_MAX_SIZE);
    get_datetime_string(time_msg);
    if (write_server_log("Starting server on %s\n", time_msg))
    {
        log_error("Could not write server log");
        error = true;
        END;
    }
    free(time_msg);

    socket_descriptor server_socket = server_init(config);

    if (server_socket == NO_SOCKET)
    {
        log_error("Could not initialize server");
        error = true;
        END;
    }

#undef END
#define END goto close_after_server_socket

    if (listen(server_socket, config->initial_connections) != 0)
    {
        log_error("Could not listen to port %s: %s", config->port, strerror(errno));

        error = true;
        END;
    }

    log_info("Server waiting for connections on port %s", config->port);

    if (selector_fd_set_nio(server_socket) == -1)
    {
        log_error("Could not handle server socket flags: %s", strerror(errno));
        error = true;
        END;
    }

    // inicializamos el selector
    const struct selector_init init_args = {
        .select_timeout = {
            .tv_nsec = 0,
            .tv_sec = 10,
        },
        .signal = SIGALRM,
    };

    if (selector_init(&init_args))
    {
        log_error("Could not initialize selector library");

        error = true;
        END;
    }

#undef END
#define END goto close_after_selector_init

    selector = selector_new(config->max_clients);
    if (selector == NULL)
    {
        log_error("Could not create new selector");

        error = true;
        END;
    }

#undef END
#define END goto close_after_selector

    // en un principio registramos sólo al servidor
    const struct fd_handler server_handlers = {
        .handle_read = server_handle_read,
        .handle_write = NULL,
        .handle_close = NULL,
    };

    selector_status status = selector_register(selector, server_socket, &server_handlers, OP_READ, &server_data);
    if (status != SELECTOR_SUCCESS)
    {
        log_error("Could not register server socket");

        error = true;
        END;
    }

    const struct fd_handler logs_file_handlers = {
        .handle_read = NULL,
        .handle_write = handle_file_write,
        .handle_close = NULL,
        .handle_block = NULL,
    };

    status = selector_register(selector, logs_file_fd, &logs_file_handlers, OP_WRITE, &logs_file_data);
    if (status != SELECTOR_SUCCESS)
    {
        log_error("Could not register logs file");

        error = true;
        END;
    }

    for (; server_active;)
    {
        errno = 0;
        status = selector_select(selector);
        if (status != SELECTOR_SUCCESS)
        {
            log_error(
                "Problems while executing selector: %s%s%s",
                selector_error(status),
                status == SELECTOR_IO ? " - " : "",
                status == SELECTOR_IO ? strerror(errno) : "");
            END;
        }
    }

close_after_selector_init:
    selector_destroy(selector);
close_after_selector:
    selector_close();
close_after_server_socket:
    close(server_socket);
close_after_logs_file:
    free_server_logger();

    return error;
}

socket_descriptor server_init(struct server_config *config)
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

        freeaddrinfo(addr_list);
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

    server_data.client_count = 0;
    server_data.max_clients = config->max_clients;
    server_data.fd = server_socket;
    freeaddrinfo(addr_list);
    return server_socket;
}

socket_descriptor
accept_new_connection(socket_descriptor server_socket)
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

bool write_to_client(socket_descriptor client_socket, struct buffer *client_buffer)
{
    size_t max_read = 0;
    uint8_t *msg = buffer_read_ptr(client_buffer, &max_read);
    if (max_read != 0)
    {
        ssize_t chars_written = send(client_socket, msg, max_read, 0);
        if (chars_written == -1)
            return true;

        if ((size_t)chars_written < max_read)
        {
            buffer_read_adv(client_buffer, chars_written);
        }
        else
        {
            buffer_reset(client_buffer);
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
    fprintf(logs_file_data.stream, "%s\n", log_msg);
    fflush(logs_file_data.stream);

    server_active = false;
}

struct client_data *generate_new_client_data()
{
    struct client_data *data = malloc(sizeof(struct client_data));

    data->read_buffer = malloc(sizeof(struct buffer));
    buffer_init(data->read_buffer, CLIENT_BUFFER_SIZE, malloc(CLIENT_BUFFER_SIZE));

    data->write_buffer = malloc(sizeof(struct buffer));
    buffer_init(data->write_buffer, CLIENT_BUFFER_SIZE, malloc(CLIENT_BUFFER_SIZE));

    return data;
}

void free_client_data(struct client_data *data)
{
    if (data == NULL)
        return;

    if (data->read_buffer != NULL)
    {
        free(data->read_buffer->data);
        free(data->read_buffer);
    }
    if (data->write_buffer != NULL)
    {
        free(data->write_buffer->data);
        free(data->write_buffer);
    }
    free(data);
}

bool add_new_client(socket_descriptor client, fd_selector selector)
{
    // TODO: manage states: we should only want to read from a client after it's connected. Then we'll handle reads and writes as every connection changes states.
    // At first we read from the client, then we re-write the string to the client
    if (selector_register(selector, client, &client_handlers, OP_READ, generate_new_client_data()))
    {
        return true;
    }
    server_data.client_count++;
    return false;
}

void server_handle_read(struct selector_key *key)
{
    struct server_data *data = key->data;
    socket_descriptor server_socket = key->fd;
    fd_selector selector = key->s;

    if (data->client_count == data->max_clients)
    {
        // there's no more capacity for new connections
        log_warning("Refused new connection, max capacity of clients reached");
    }
    else
    {
        socket_descriptor new_client = accept_new_connection(server_socket);

        if (new_client > 0)
        {
            // log new client. Write message into buffer to write when file is ready
            if (add_new_client_log(new_client))
            {
                log_error("Could not generate new client log");
                return;
            }
            // add new client to array
            if (add_new_client(new_client, selector))
            {
                log_error("Could not register client");
                return;
            }
        }
    }
}

void handle_file_write(struct selector_key *key)
{
    if (flush_logs())
    {
        log_error("Could not write into logs file");
    }
}

void client_handle_read(struct selector_key *key)
{
    fd_selector selector = key->s;

    socket_descriptor client = key->fd;
    struct buffer *client_buffer = ((struct client_data *)key->data)->write_buffer;

    char addr_str[ADDR_BUF_SIZE];
    print_address_from_descriptor(client, addr_str);

    size_t max_write = 0;
    uint8_t *msg = buffer_write_ptr(client_buffer, &max_write);

    if (max_write == 0)
        return;
    int ammount_read = read(client, msg, max_write);
    switch (ammount_read)
    {
    case -1:
        log_error("Could not read from client %s", addr_str);
        return;
    case 0:
        log_info("Closing connection to %s", addr_str);
        add_disconnected_client_log(client);

        selector_unregister_fd(selector, client);
        break;
    default:
        buffer_write_adv(client_buffer, ammount_read);
        msg[ammount_read] = '\0';

        log_info("New message from %s: %s", addr_str, msg);
        struct buffer *echo_buffer;
        switch (parse_client_message(msg, ammount_read, client))
        {
        case CLOSE:
            server_active = false;
            char datetime_str[TIME_FMT_STR_MAX_SIZE];

            log_info("Stopping server on %s by order of %s",
                     get_datetime_string(datetime_str),
                     print_address_from_descriptor(client, addr_str));
            write_server_log("Stopping server on %s by order of %s",
                             get_datetime_string(datetime_str),
                             print_address_from_descriptor(client, addr_str));
            break;
        case ECHO:
            // TODO: keep list of clients
            // Pass message into write buffer and set socket to write
            echo_buffer = ((struct client_data *)key->data)->read_buffer;
            size_t max_echo_write = 0;
            uint8_t *echo_msg = buffer_write_ptr(echo_buffer, &max_echo_write);

            strncpy((char *)echo_msg, (char *)msg, max_echo_write);
            size_t ammount_written = (size_t)ammount_read <= max_echo_write ? ammount_read : max_echo_write;
            buffer_write_adv(echo_buffer, ammount_written);

            buffer_reset(client_buffer);

            selector_set_interest(selector, client, OP_WRITE);
            break;
        default:
            // Error
            return;
        }
        break;
    }
}

void client_handle_write(struct selector_key *key)
{
    fd_selector selector = key->s;

    socket_descriptor client = key->fd;
    struct buffer *client_buffer = ((struct client_data *)key->data)->read_buffer;

    // TODO: check if write was completed
    write_to_client(client, client_buffer);

    selector_set_interest(selector, client, OP_READ);
}

void client_handle_close(struct selector_key *key)
{
    free_client_data((struct client_data *)key->data);
    close(key->fd);
    server_data.client_count--;
}
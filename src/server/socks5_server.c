#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "server/socks5_server.h"
#include "logger/logger.h"
#include "utils/representation.h"
#include "parser/negociation.h"
#include "parser/request.h"

/*********************************
|          Definitions          |
*********************************/

#define MAX_CLIENTS_AMOUNT 500

#define CLIENT_BUFFER_SIZE 1024

/*
 *  Estados de la maquina de estados.
 *  RESOLVE_ADDRESS: Resolviendo consulta DNS
 *  CONNECTING: Estableciendo conexion con el servidor
 *  COPY: Copiando del buffer de entrada al de salida del cliente
 *
 * Algoritmo:
 *  Proxy TCP
   a. crear socket pasivo
   (SP) READ si tengo capacidad para atender nuevos clientes

   b. aceptar la conexión (accept)

   g. (C) CONNECT - creo socket activo a Origin - configurar no bloqueante
   connect(127.0.0.1 9090)
   subscribir(WRITE)
   write -> check estado de la conexión

   i. COPY
*/
enum connection_state {
    NEGOCIATING,
    RESOLVE_ADDRESS,
    CONNECTING,
    COPY
};

/**
 * Representación de una conexión del Proxy.
 * Toda la información se maneja desde el cliente
 *
 *              --------
 * Client =====| Proxy |====== Origin
 *             -------
 *    ---->  |write_buffer| ----->
 *   <----  |read_buffer|  <-----
 */
struct client_data
{
    socket_descriptor client;
    // Buffer used to write from Client to Origin
    struct buffer* write_buffer;
    // Buffer used to wrte from Origin to Client
    struct buffer* read_buffer;
    enum connection_state state;

    socket_descriptor origin;
    struct address_representation* origin_address_repr;

    /**
     * Lista de direcciones resueltas en base a origin_address_repr
     * Solo tiene contenido si el cliente se encuentra en el estado
     * RESOLVE_ADDRESS
     */
    struct addrinfo* resolved_addresses_list;
    struct addrinfo* current_connection_trial;
    // struct sockaddr* origin_address;
    // socklen_t origin_address_len;
    fd_selector selector;

    struct negociation_parser* negociation_parser;
    struct request_parser* request_parser;

    /**
     * Representación legible del cliente para usar en logs y registros:
     *  client_host:port
     */
    char* client_str;
    // cantidad de referencias para saber cuando hacer free del struct
    uint8_t references;
};

/**************************************
|          Global Variables          |
**************************************/

/*
 * Clientes del servidor
*/
struct client_data** clients;

/*
*   Direccion de todos los sockets activos
*/

struct address_representation origin_global_address = {
    .type = FQDN_ADDR,
    .hostname = "localhost",
    .port = "9090",
};



/*******************************************
|          Function declarations          |
*******************************************/

void socks5_server_handle_read(struct selector_key* key);
const struct fd_handler
socks5_server_handlers = {
        .handle_read = socks5_server_handle_read,
        .handle_write = NULL,
        .handle_close = NULL,
};

/**
 * @brief accepts new connection and returns the new client's socket descriptor
 */
socket_descriptor
accept_new_connection(socket_descriptor server_socket);

bool write_to_client(socket_descriptor client_socket, struct buffer* client_buffer);

bool socks5_close_connection(struct client_data* client);

struct client_data*
    socks5_generate_new_client_data(socket_descriptor client, fd_selector selector);

void socks5_free_client_data(struct client_data* data);

bool read_new_request_from_client(struct client_data* data);

bool socks5_add_new_client(socket_descriptor client, fd_selector selector);

/**
 *  Revisa la intención de conexión indicada por el cliente en el campo
 * origin_address_repr y resuelve su dirección IP para luego poder conectarse.
 * Deja en el cliente la lista de posibles direcciones
 */
void* socks5_resolve_origin_address(void* client_data);

socket_descriptor socks5_try_connect(struct client_data* client);

// Event Handlers

void socks5_client_handle_read(struct selector_key* key);

void socks5_client_handle_write(struct selector_key* key);

void socks5_connect_client(struct selector_key* key);

int free_addrinfo_on_error(struct addrinfo* addrinfo, char* message);

void client_handle_close(struct selector_key* key);

static void get_targets(socket_descriptor source_descriptor,
                struct client_data* data,
                struct buffer** target_buffer,
                socket_descriptor* target_descriptor);

static const struct fd_handler
socks5_client_handlers = {
    .handle_read = socks5_client_handle_read,
    .handle_write = socks5_client_handle_write,
    .handle_block = socks5_connect_client,
    .handle_close = client_handle_close,
};

/**********************************************
|          Function Implementations          |
**********************************************/

bool socks5_init_server() {
    clients = malloc(MAX_CLIENTS_AMOUNT * sizeof(struct client_data*));
    return false;
}

void socks5_close_server() {
    if (clients != NULL) {
        free(clients);
        clients = NULL;
    }
}

const struct fd_handler* get_socks5_server_handlers() {
    return &socks5_server_handlers;
}

void socks5_server_handle_read(struct selector_key* key) {
    struct socks5_server_data* data = key->data;
    socket_descriptor server_socket = key->fd;
    fd_selector selector = key->s;

    if (data->client_count == data->max_clients) {
        // there's no more capacity for new connections
        log_warning("Refused new connection, max capacity of clients reached");
    }
    else {
        socket_descriptor new_client = accept_new_connection(server_socket);

        if (new_client > 0) {
            if (socks5_add_new_client(new_client, selector)) {
                log_error("Could not register client");
                return;
            }
        }
    }
}

socket_descriptor
accept_new_connection(socket_descriptor server_socket) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    socket_descriptor new_connection = accept(server_socket,
        (struct sockaddr*)&client_addr,
        &client_addr_len);
    if (new_connection < 0) {
        log_error("New connection refused: %s", strerror(errno));
        return -1;
    }
    char addr_buf[ADDR_STR_MAX_SIZE];
    log_info("New connection to %s", print_address((struct sockaddr*)&client_addr, addr_buf));

    return new_connection;
}

bool write_to_client(socket_descriptor client_socket, struct buffer* client_buffer) {
    if (!buffer_can_read(client_buffer)) return false;
    size_t max_read = 0;
    uint8_t* msg = buffer_read_ptr(client_buffer, &max_read);
    ssize_t chars_written = send(client_socket, msg, max_read, 0);
    if (chars_written == -1)
        return true;

    if ((size_t)chars_written < max_read) {
        buffer_read_adv(client_buffer, chars_written);
    }
    else {
        buffer_reset(client_buffer);
    }

    return false;
}

bool socks5_close_connection(struct client_data* client) {
    bool error = false;

    fd_selector selector = client->selector;
    socket_descriptor client_descriptor = client->client;
    socket_descriptor origin_descriptor = client->origin;

    log_info("Closing connection of client %s", client->client_str);
    // add_disconnected_client_log(client);

    char* client_str_copy = malloc(strlen(client->client_str) + 1);
    strcpy(client_str_copy, client->client_str);

    selector_status status;
    if ((status = selector_unregister_fd(selector, client_descriptor)) != SELECTOR_SUCCESS) {
        log_error("Could not close connection with client endpoint from %s: %s", client_str_copy, selector_error(status));

        error = true;
        goto close_connection_end;
    }
    if ((status = selector_unregister_fd(selector, origin_descriptor)) != SELECTOR_SUCCESS) {
        log_error("Could not close connection with origin endpoint from %s: %s", client_str_copy, selector_error(status));

        error = true;
        goto close_connection_end;
    }

close_connection_end:
    free(client_str_copy);
    return error;
}

struct client_data* socks5_generate_new_client_data(socket_descriptor client, fd_selector selector) {
    struct client_data* data = malloc(sizeof(struct client_data));

    data->read_buffer = malloc(sizeof(struct buffer));
    buffer_init(data->read_buffer, CLIENT_BUFFER_SIZE, malloc(CLIENT_BUFFER_SIZE + 1));

    data->write_buffer = malloc(sizeof(struct buffer));
    buffer_init(data->write_buffer, CLIENT_BUFFER_SIZE, malloc(CLIENT_BUFFER_SIZE + 1));

    data->state = RESOLVE_ADDRESS;

    data->origin = NO_SOCKET;

    data->client = client;

    data->selector = selector;

    data->references = 1;

    data->resolved_addresses_list = NULL;
    data->current_connection_trial = NULL;


    data->negociation_parser = negociation_parser_init();

    data->client_str = malloc(ADDR_STR_MAX_SIZE);
    print_address_from_descriptor(data->client, data->client_str);

    return data;
}

void socks5_free_client_data(struct client_data* data) {
    if (data == NULL || data->references-- > 1)
        return;

    if (data->read_buffer != NULL) {
        free(data->read_buffer->data);
        free(data->read_buffer);
    }
    if (data->write_buffer != NULL) {
        free(data->write_buffer->data);
        free(data->write_buffer);
    }
    if (data->client_str != NULL) {
        free(data->client_str);
    }
    // if (data->origin_address != NULL)
    //     free(data->origin_address);
    // TODO: free origin_address_repr when it is allocated

    // Remove client register
    for (size_t i = 0; i < socks5_server_data.client_count; i++) {
        if (clients[i] == data) {
            for (size_t j = i + 1; j < socks5_server_data.client_count; j++)
                clients[i] = clients[j];
            clients[socks5_server_data.client_count] = NULL;
            break;
        }
    }
    free(data);
}

bool read_new_request_from_client(struct client_data* data) {
    // READ_REQUEST
    data->origin_address_repr = &origin_global_address;
    char host_addr_buff[ADDR_STR_MAX_SIZE];
    log_debug("Requested address %s for client %s",
        print_address_from_repr(data->origin_address_repr, host_addr_buff),
        data->client_str);
    /* GET_ADDR */
    data->state = RESOLVE_ADDRESS;

    pthread_t tid;
    pthread_create(&tid, NULL, socks5_resolve_origin_address, (void*)data);

    return false;
}

bool socks5_add_new_client(socket_descriptor client, fd_selector selector) {
    // TODO: manage states: we should only want to read from a client after it's connected. Then we'll handle reads and writes as every connection changes states.
    // At first we have to resolve the origin address, meanwhile the new client stays idle
    struct client_data* data = socks5_generate_new_client_data(client, selector);

    clients[socks5_server_data.client_count] = data;

    if (selector_register(selector, client, &socks5_client_handlers, OP_NOOP, data)) {
        return true;
    }
    socks5_server_data.client_count++;

    // Leo el primer mensaje del cliente 
    // TODO: Por ahora es bloqueante!

    int bytes_read = read(client, data->write_buffer->data, CLIENT_BUFFER_SIZE);
    if (bytes_read == -1) {
        log_error("Error while reading from client");
        return true;
    }
    buffer_write_adv(data->write_buffer, bytes_read);

    // Leo del cliente y parseo el mensaje de negociacion
    // Si el mensaje es invalido, cierro la conexion
    // Si el mensaje es valido, lo guardo le guardo al cliente su socket y su selector
    log_debug("Starting negociation with client %s", data->client_str);
    data->state = NEGOCIATING;
    enum negociation_results  negociation_parser_result = negociation_parser_consume(data->write_buffer, data->negociation_parser);

    if (negociation_parser_result == NEGOCIATION_PARSER_FINISH_OK)
        return read_new_request_from_client(data);

    if (negociation_parser_result == NEGOCIATION_PARSER_FINISH_ERROR) {
        log_error("Could not negociate with client %s", data->client_str);
        socks5_close_connection(data);
        return true;
    }

    if (negociation_parser_result == NEGOCIATION_PARSER_NOT_FINISH) {
        log_debug("Negociation with client %s not finished", data->client_str);
        return true;
    }
    return false;
}

void* socks5_resolve_origin_address(void* client_data) {
    struct client_data* data = client_data;
    struct address_representation* addr_repr = data->origin_address_repr;
    char* addr_name = addr_repr->hostname;
    char* port = addr_repr->port;
    struct addrinfo addr_hints;
    struct addrinfo* addr_list;

    log_debug("Resolving address for client %s", data->client_str);

    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;
    addr_hints.ai_flags = AI_NUMERICSERV;

    switch (addr_repr->type) {
    case FQDN_ADDR:
        addr_hints.ai_family = AF_UNSPEC;
        break;
    case IPV4_ADDR:
        addr_hints.ai_family = AF_INET;
        addr_hints.ai_flags |= AI_NUMERICHOST;
        break;
    case IPV6_ADDR:
        addr_hints.ai_family = AF_INET6;
        addr_hints.ai_flags |= AI_NUMERICHOST;
        break;

    default:
        // Error
        log_error("Incorrect address type for representation, trying as FQDN");
        addr_hints.ai_family = AF_UNSPEC;
        break;
    }

    int error;
    if ((error = getaddrinfo(addr_name, port, &addr_hints, &addr_list))) {
        log_error("Could not resolve address: %s", gai_strerror(error));
        selector_notify_block(data->selector, data->client);
        return NULL;
    }

    data->resolved_addresses_list = addr_list;

    data->state = CONNECTING;

    // informar al selector que terminó la resolución de address
    selector_notify_block(data->selector, data->client);

    return NULL;
}

socket_descriptor socks5_try_connect(struct client_data* client) {
    if (client->current_connection_trial == NULL) return NO_SOCKET;

    struct addrinfo* origin = client->current_connection_trial;
    // crear el socket
    socket_descriptor new_client_socket = socket(origin->ai_family, origin->ai_socktype, origin->ai_protocol);
    if (new_client_socket == NO_SOCKET) {
        free_addrinfo_on_error(origin, "Could not create socket on ");
        return NO_SOCKET;
    }
    // configurar el socket como no bloqueante
    if (selector_fd_set_nio(new_client_socket)) {
        free_addrinfo_on_error(origin, "Could not create non blocking socket on");
        return NO_SOCKET;
    };

    // connect
    int connection_status;
    if ((connect(new_client_socket, origin->ai_addr, origin->ai_addrlen) == -1) && !connection_in_proggress(errno)) {
        log_error("Error code: %d", errno);
        free_addrinfo_on_error(origin, "Could not connect to origin");
        return NO_SOCKET;
    }
    connection_status = errno;

    char local_addr_buff[ADDR_STR_MAX_SIZE];
    char origin_addr_buff[ADDR_STR_MAX_SIZE];

    print_address_from_descriptor(new_client_socket, local_addr_buff);
    print_address_info(client->current_connection_trial, origin_addr_buff);
    if (connection_in_proggress(connection_status)) {
        log_debug("Starting connection to %s from %s", origin_addr_buff, local_addr_buff);
        client->state = CONNECTING;
    }
    else {
        log_debug("Connected to %s", origin_addr_buff);
        client->state = COPY;
    }

    return new_client_socket;
}

void socks5_client_handle_read(struct selector_key* key) {
    fd_selector selector = key->s;
    socket_descriptor source_descriptor = key->fd;
    struct client_data* data = key->data;

    struct buffer* source_buffer;
    socket_descriptor target_descriptor;

    get_targets(source_descriptor, data, &source_buffer, &target_descriptor);

    if (!buffer_can_write(source_buffer)) return;

    size_t max_write = 0;

    uint8_t* source_buff_raw = buffer_write_ptr(source_buffer, &max_write);

    int ammount_read = read(source_descriptor, source_buff_raw, max_write);
    char addr_str[ADDR_STR_MAX_SIZE];
    log_debug("Read %d bytes from client %s(%s)", ammount_read, data->client_str, print_address_from_descriptor(source_descriptor, addr_str));

    switch (ammount_read) {
    case -1:
        log_error("Could not read from client %s(%s): %s", data->client_str, print_address_from_descriptor(source_descriptor, addr_str), strerror(errno));
    case 0:
        if (socks5_close_connection(data))
            return;
        break;
    default:
        buffer_write_adv(source_buffer, ammount_read);
        log_debug("Starting COPY with client %s", data->client_str);
        data->state = COPY;

        // TODO: REVISAR
        enum request_results request_parser_status = request_parser_consume(source_buffer, data->request_parser);
        if (request_parser_status == REQUEST_PARSER_FINISH_OK) {
            log_debug("Request from client %s finished", data->client_str);
            if (data->origin == -1) {
                log_debug("Client %s requested address %s", data->client_str, data->request_parser->address);
                if (socks5_resolve_origin_address(data)) {
                    log_error("Could not resolve origin address");
                    return;
                }
                selector_set_interest(selector, target_descriptor, OP_WRITE | OP_READ);

            }
            else {
                log_debug("Client %s already has origin address %s", data->client_str, data->request_parser->address);
                if (selector_set_interest(selector, target_descriptor, OP_WRITE)) {
                    log_error("Could not set interest in write for client %s", data->client_str);
                    return;
                }
            }
        }
        else if (request_parser_status == REQUEST_PARSER_NOT_FINISH) {
            log_debug("Request from client %s not finished", data->client_str);
            return;
        }
        else if (request_parser_status == REQUEST_PARSER_FINISH_ERROR) {
            log_error("Could not parse request from client %s", data->client_str);
            if (socks5_close_connection(data))
                return;
        }

        break;
    }
}

void socks5_client_handle_write(struct selector_key* key) {
    fd_selector selector = key->s;
    socket_descriptor target_descriptor = key->fd;
    struct client_data* data = key->data;

    struct buffer* target_buffer = target_descriptor == data->client ? data->read_buffer : data->write_buffer;

    char addr_str[ADDR_STR_MAX_SIZE];
    log_debug("Writing into %s", print_address_from_descriptor(target_descriptor, addr_str));

    // TODO: check if write was completed
    write_to_client(target_descriptor, target_buffer);

    if (data->state == CONNECTING) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);

        bool connected = getpeername(data->origin, (struct sockaddr*)&addr, &addr_len) == 0;

        if (!connected) {
            char addr_str[ADDR_STR_MAX_SIZE];
            log_info("Could not connect to %s", print_address_from_repr(data->origin_address_repr, addr_str));

            socks5_close_connection(data);
            return;
        }
        log_debug(" to %s", print_address_from_descriptor(data->origin, addr_str));
        selector_set_interest(selector, data->client, OP_READ);
        selector_set_interest(selector, data->origin, OP_NOOP);
        data->state = COPY;
    }
    else {
        selector_set_interest(selector, target_descriptor, OP_READ);
    }
}

void socks5_connect_client(struct selector_key* key) {
    struct client_data* data = key->data;
    struct addrinfo* addr_list = data->resolved_addresses_list;

    if (addr_list == NULL) {
        log_error("Client does not have a list of resolved addresses");
        return;
    }

    char origin_addr_buff[ADDR_STR_MAX_SIZE];

    socket_descriptor origin_local_socket = NO_SOCKET;
    for (;addr_list != NULL; addr_list = addr_list->ai_next) {
        data->current_connection_trial = addr_list;
        origin_local_socket = socks5_try_connect(data);
        if (origin_local_socket != NO_SOCKET) break;
    }
    if (origin_local_socket == NO_SOCKET) {
        log_error("Could not resolve origin address %s", print_address_info(addr_list, origin_addr_buff));
        data->current_connection_trial = NULL;
        freeaddrinfo(data->resolved_addresses_list);

        return;
    }

    data->origin = origin_local_socket;
    data->current_connection_trial = NULL;
    freeaddrinfo(data->resolved_addresses_list);
    data->resolved_addresses_list = NULL;

    fd_selector selector = key->s;
    socket_descriptor client_fd = key->fd;

    // Add origin
    data->references++;
    clients[socks5_server_data.client_count++] = data;
    selector_register(selector, origin_local_socket, &socks5_client_handlers, OP_NOOP, data);

    if (data->state == COPY) {
        selector_set_interest(selector, client_fd, OP_READ); // TODO: add consideration for READ_HELLO and WRITE_HELLO states
    }
    else {
        // conectando
        selector_set_interest(selector, origin_local_socket, OP_WRITE);
    }
}

int free_addrinfo_on_error(struct addrinfo* addrinfo, char* message) {
    char addr_buffer[200];
    log_error("%s %s: %s", message, print_address_info(addrinfo, addr_buffer), strerror(errno));
    freeaddrinfo(addrinfo);
    return true;
}

void client_handle_close(struct selector_key* key) {
    socks5_free_client_data((struct client_data*)key->data);
    close(key->fd);
    socks5_server_data.client_count--;
}

// Util
static void get_targets(socket_descriptor source_descriptor,
                struct client_data* data,
                struct buffer** target_buffer,
                socket_descriptor* target_descriptor) {
    if (source_descriptor == data->client) {
        *target_descriptor = data->origin;
        *target_buffer = data->write_buffer;
    }
    else {
        *target_descriptor = data->client;
        *target_buffer = data->read_buffer;
    }
}

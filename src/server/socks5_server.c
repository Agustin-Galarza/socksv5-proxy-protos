#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>

#include "server/socks5_server.h"
#include "utils/logger/logger.h"
#include "utils/representation.h"
#include "utils/parser/negotiation.h"
#include "utils/parser/request.h"
#include "utils/stm.h"

/*********************************
|          Definitions          |
*********************************/

#define MAX_CLIENTS_AMOUNT 500

#define CLIENT_BUFFER_SIZE 1024

#define SOCKS_VER_BYTE 0x5

#define SOCKS_RSV_BYTE 0x00

#define GET_DATA(key) (struct client_data*)key->data

#define SEND_FLAGS 0

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
    NEGOTIATING_REQ = 0,
    NEGOTIATING_RES,
    ADDRESS_REQ,
    RESOLVE_ADDRESS,
    CONNECTING,
    ADDRESS_RES,
    COPY,
    CONNECTION_DONE,
    CONNECTION_ERROR
};

enum socks5_reply_status {
    SUCCEDED = 0,
    SERVER_FAILURE,
    CONNECTION_NOT_ALLOWED,
    NETWORK_UNREACHABLE,
    HOST_UNREACHABLE,
    CONNECTION_REFUSED,
    TTL_EXPIRED,
    COMMAND_NOT_SUPPORTED,
};

struct copy_endpoint {
    socket_descriptor source;
    socket_descriptor target;
    struct buffer* r_buffer;
    struct buffer* w_buffer;
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
    socket_descriptor origin;

    // Buffer used to write from Client to Origin
    struct buffer* write_buffer;
    // Buffer used to wrte from Origin to Client
    struct buffer* read_buffer;

    //TODO: se van
    enum connection_state state;
    struct address_representation* origin_address_repr;
    ////////////////////////

    struct state_machine stm;

    /**
     * Lista de direcciones resueltas en base a origin_address_repr
     * Solo tiene contenido si el cliente se encuentra en el estado
     * RESOLVE_ADDRESS
     */
    struct addrinfo* resolved_addresses_list;
    struct addrinfo* current_connection_trial;

    struct addrinfo* addr_hint;
    char* dst_fqdn;
    char* dst_port;

    enum socks5_reply_status reply_status;

    fd_selector selector;

    struct negotiation_parser* negociation_parser;
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

static void get_targets(socket_descriptor source_descriptor,
                struct client_data* data,
                struct buffer** target_buffer,
                socket_descriptor* target_descriptor);

static struct copy_endpoint
get_endpoint(struct selector_key* key);

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

int free_addrinfo_on_error(struct addrinfo* addrinfo, char* message);

uint8_t choose_socks5_method(uint8_t methods[2]);

// Event Handlers

void socks5_client_handle_read(struct selector_key* key);

void socks5_client_handle_write(struct selector_key* key);

void socks5_handle_block(struct selector_key* key);

void socks5_client_handle_close(struct selector_key* key);

static const struct fd_handler
socks5_client_handlers = {
    .handle_read = socks5_client_handle_read,
    .handle_write = socks5_client_handle_write,
    .handle_block = socks5_handle_block,
    .handle_close = socks5_client_handle_close,
};

/*** Funciones para cada estado ***/
// NEGOTIATIING_REQ
static void negotiating_req_init(const unsigned state, struct selector_key* key);
static void negotiating_req_close(const unsigned state, struct selector_key* key);
static unsigned read_hello(struct selector_key* key);

// NEGOTIATING_RES
static void negotiating_res_init(const unsigned state, struct selector_key* key);
static void negotiating_res_close(const unsigned state, struct selector_key* key);
static unsigned write_hello(struct selector_key* key);

// ADDRESS_REQ
static void address_req_init(const unsigned state, struct selector_key* key);
static void address_req_close(const unsigned state, struct selector_key* key);
static unsigned read_address_req(struct selector_key* key);

// RESOLVE_ADDRESS
static void resolve_addr_request(const unsigned state, struct selector_key* key);
static void resolve_addr_close(const unsigned state, struct selector_key* key);
static void* resolve_fqdn_address(void* data); // TODO: selector handler
static unsigned finish_address_resolution(struct selector_key* key);

// CONNECTING
static void start_connection(const unsigned state, struct selector_key* key);
static void connecting_close(const unsigned state, struct selector_key* key);
static unsigned check_connection_with_origin(struct selector_key* key);

// ADDRESS_RES
static void address_res_init(const unsigned state, struct selector_key* key);
static void address_res_close(const unsigned state, struct selector_key* key);
static unsigned write_address_res(struct selector_key* key);

// COPY
static void copy_init(const unsigned state, struct selector_key* key);
static void copy_close(const unsigned state, struct selector_key* key);
static unsigned copy_write(struct selector_key* key);
static unsigned copy_read(struct selector_key* key);

// DONE
static void close_connection_normally(const unsigned state, struct selector_key* key);

// ERROR
static void close_connection_error(const unsigned state, struct selector_key* key);

/*****************************
|          Estados          |
*****************************/

static const struct state_definition socks5_states[] = {
    {
        .state = NEGOTIATING_REQ,
        .on_arrival = negotiating_req_init,
        .on_departure = negotiating_req_close,
        .on_read_ready = read_hello,
    },{
        .state = NEGOTIATING_RES,
        .on_arrival = negotiating_res_init,
        .on_departure = negotiating_res_close,
        .on_write_ready = write_hello,
    },{
        .state = ADDRESS_REQ,
        .on_arrival = address_req_init,
        .on_departure = address_req_close,
        .on_read_ready = read_address_req,
    },{
        .state = RESOLVE_ADDRESS,
        .on_arrival = resolve_addr_request,
        .on_departure = resolve_addr_close,
        .on_block_ready = finish_address_resolution,
    },{
        .state = CONNECTING,
        .on_arrival = start_connection,
        .on_departure = connecting_close,
        .on_write_ready = check_connection_with_origin,
    },{
        .state = ADDRESS_RES,
        .on_arrival = address_res_init,
        .on_departure = address_res_close,
        .on_write_ready = write_address_res
    },{
        .state = COPY,
        .on_arrival = copy_init,
        .on_departure = copy_close,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
    },{
        .state = CONNECTION_DONE,
        .on_arrival = close_connection_normally,
    },{
        .state = CONNECTION_ERROR,
        .on_arrival = close_connection_error,
    },
};


/**********************************************
|          Function Implementations          |
**********************************************/

bool socks5_init_server() {
    clients = calloc(MAX_CLIENTS_AMOUNT, sizeof(struct client_data*));
    return false;
}

void socks5_close_server() {
    if (clients != NULL) {
        for (int i = 0; i < MAX_CLIENTS_AMOUNT; i++) {
            if (clients[i] != NULL) {
                struct selector_key key = {
                    .s = clients[i]->selector,
                    .fd = clients[i]->client,
                    .data = clients[i]
                };
                socks5_client_handle_close(&key);
                if (clients[i]->origin > 0) {
                    key.fd = clients[i]->origin;
                    socks5_client_handle_close(&key);
                }
            }
        }
        free(clients);
        clients = NULL;
    }
}

const struct fd_handler* get_socks5_server_handlers() {
    return &socks5_server_handlers;
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

static struct copy_endpoint
get_endpoint(struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    if (key->fd == client->client) {
        struct copy_endpoint endpoint = {
            .source = client->client,
            .w_buffer = client->write_buffer,
            .r_buffer = client->read_buffer,
            .target = client->origin
        };
        return endpoint;
    }
    struct copy_endpoint endpoint = {
            .source = client->origin,
            .w_buffer = client->read_buffer,
            .r_buffer = client->write_buffer,
            .target = client->client
    };
    return endpoint;
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
    ssize_t chars_written = send(client_socket, msg, max_read, SEND_FLAGS);
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

    data->stm.initial = NEGOTIATING_REQ;
    data->stm.states = socks5_states;
    data->stm.current = socks5_states;
    data->stm.max_state = CONNECTION_ERROR;
    stm_init(&data->stm);

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

    if (selector_register(selector, client, &socks5_client_handlers, OP_READ, data) != SELECTOR_SUCCESS) {
        return true;
    }
    socks5_server_data.client_count++;
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
    if (!connection_in_proggress(connection_status)) {
        log_error("Error connecting to %s: %s", origin_addr_buff, strerror(connection_status));
        return NO_SOCKET;
    }
    log_debug("Starting connection to %s from %s", origin_addr_buff, local_addr_buff);

    return new_client_socket;
}

int free_addrinfo_on_error(struct addrinfo* addrinfo, char* message) {
    char addr_buffer[200];
    log_error("%s %s: %s", message, print_address_info(addrinfo, addr_buffer), strerror(errno));
    freeaddrinfo(addrinfo);
    return true;
}

void socks5_client_handle_read(struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    stm_handler_read(&client->stm, key);
}

void socks5_client_handle_write(struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    stm_handler_write(&client->stm, key);
}

void socks5_handle_block(struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    stm_handler_block(&client->stm, key);
}

void socks5_client_handle_close(struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    stm_handler_close(&client->stm, key);
}

static void
negotiating_req_init(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    log_debug("Waiting for hello");


    selector_set_interest(key->s, client->client, OP_READ);

}

static void
negotiating_req_close(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);

}

static unsigned
read_hello(struct selector_key* key) {
    // Todo: quizás checkear si el fd es del cliente
    struct client_data* client = GET_DATA(key);

    client->negociation_parser = negotiation_parser_init();
    if (client->negociation_parser == NULL) {
        // Todo: error
        log_error("Could not initiate negotiation parser");
        return CONNECTION_ERROR;
    }

    int bytes_read = read(key->fd, client->write_buffer->data, CLIENT_BUFFER_SIZE);

    if (bytes_read == 0)
        return CONNECTION_DONE;

    if (bytes_read == -1) {
        log_error("Error while reading hello from client");
        return CONNECTION_ERROR;
    }
    buffer_write_adv(client->write_buffer, bytes_read);

    // Leo del cliente y parseo el mensaje de negociacion
    // Si el mensaje es invalido, cierro la conexion
    // Si el mensaje es valido, lo guardo le guardo al cliente su socket y su selector
    log_debug("Starting negociation with client %s", client->client_str);
    client->state = NEGOTIATING_REQ;
    enum negotiation_results  negociation_parser_result = negotiation_parser_consume(client->write_buffer, client->negociation_parser);

    switch (negociation_parser_result) {
    case NEGOTIATION_PARSER_FINISH_ERROR:
        log_error("Could not negociate with client %s", client->client_str);
        return CONNECTION_ERROR;

    case NEGOTIATION_PARSER_FINISH_OK:
        return NEGOTIATING_RES;

    default:
        log_debug("Negociation with client %s not finished", client->client_str);
    }

    return NEGOTIATING_REQ;
}

static void
negotiating_res_init(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);

    log_debug("Sending hello");

    // Elegir el método de entre los que nos dió el usuario
    uint8_t used_method = NO_ACCEPTABLE_METHODS;
    if (client->negociation_parser->methods[1] == NO_ACCEPTABLE_METHODS) {
        used_method = client->negociation_parser->methods[0];
    }
    else {
        used_method = choose_socks5_method(client->negociation_parser->methods);
    }

    buffer_reset(client->write_buffer);
    buffer_write(client->write_buffer, SOCKS_VER_BYTE);
    buffer_write(client->write_buffer, used_method);

    selector_set_interest(key->s, client->client, OP_WRITE);
}

static unsigned write_hello(struct selector_key* key) {
    errno = 0;
    struct client_data* client = GET_DATA(key);

    size_t bytes_to_send;
    uint8_t* res_buf = buffer_read_ptr(client->write_buffer, &bytes_to_send);

    int send_status = send(key->fd, res_buf, bytes_to_send, SEND_FLAGS);

    if (send_status < 0) {
        log_error("Could not send hello response to %s [Reason:%s]", client->client_str, strerror(errno));
        return CONNECTION_ERROR;
    }
    size_t bytes_sent = (size_t)send_status;
    buffer_read_adv(client->write_buffer, bytes_sent);

    if (bytes_sent == bytes_to_send)
        return ADDRESS_REQ;

    return NEGOTIATING_RES;
}

static void
negotiating_res_close(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);

    negotiation_parser_free(client->negociation_parser);
}

static void address_req_init(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);

    log_debug("Requesting address from client");

    client->request_parser = request_parser_init();

    selector_set_interest(key->s, client->client, OP_READ);
}

static void address_req_close(const unsigned state, struct selector_key* key) {
    // struct client_data* client = GET_DATA(key);

    // request_parser_free(client->request_parser);
}

static unsigned read_address_req(struct selector_key* key) {
    errno = 0;
    struct client_data* client = GET_DATA(key);

    if (!buffer_can_write(client->write_buffer))
        return ADDRESS_REQ;

    size_t max_read_bytes, bytes_read;
    uint8_t* buffer_raw = buffer_write_ptr(client->write_buffer, &max_read_bytes);
    int read_status = read(client->client, buffer_raw, max_read_bytes);
    switch (read_status) {
    case -1:
        log_error("Could not read request from client %s [Reason: %s]", client->client_str, strerror(errno));
        return CONNECTION_ERROR;
        break;
    case 0:
        return CONNECTION_DONE;
    default:
        bytes_read = (size_t)read_status;
        buffer_write_adv(client->write_buffer, bytes_read);

        enum request_results request_parser_status = request_parser_consume(client->write_buffer, client->request_parser);

        if (request_parser_status == REQUEST_PARSER_FINISH_ERROR) {
            log_error("Could not parse request from client %s", client->client_str);
            return CONNECTION_ERROR;
        }

        if (request_parser_status == REQUEST_PARSER_FINISH_OK) {
            log_debug("Request from client %s finished", client->client_str);
            log_debug("Client %s requested address %s", client->client_str, client->request_parser->address);
            return RESOLVE_ADDRESS;
        }
    }

    log_debug("Request from client %s not finished", client->client_str);

    return ADDRESS_REQ;
}

static void resolve_addr_request(const unsigned state, struct selector_key* key) {
    errno = 0;
    struct client_data* client = GET_DATA(key);

    log_debug("Starting address resolution");

    socklen_t addr_len;
    struct sockaddr_in* addr_in;
    struct sockaddr_in6* addr_in6;
    switch (client->request_parser->address_type) {
    case REQUEST_ADDRESS_TYPE_IPV4:
        client->resolved_addresses_list = malloc(sizeof(struct addrinfo));
        client->resolved_addresses_list->ai_family = AF_INET;

        client->resolved_addresses_list->ai_socktype = SOCK_STREAM;
        client->resolved_addresses_list->ai_protocol = IPPROTO_TCP;

        addr_len = sizeof(struct sockaddr_in);
        client->resolved_addresses_list->ai_addrlen = addr_len;
        addr_in = malloc(addr_len); // TODO: free this
        memset(addr_in, 0, addr_len);
        addr_in->sin_family = AF_INET;
        addr_in->sin_port = (in_port_t)*client->request_parser->port;
        addr_in->sin_addr.s_addr = (in_addr_t)*client->request_parser->address;

        client->resolved_addresses_list->ai_addr = (struct sockaddr*)addr_in;

        // Aunque no haya tarea bloqueante, se avisa del fin de una para pasar
        // al siguiente estado.
        selector_notify_block(key->s, client->client);
        break;

    case REQUEST_ADDRESS_TYPE_IPV6:
        client->resolved_addresses_list = malloc(sizeof(struct addrinfo));
        client->resolved_addresses_list->ai_family = AF_INET6;

        client->resolved_addresses_list->ai_socktype = SOCK_STREAM;
        client->resolved_addresses_list->ai_protocol = IPPROTO_TCP;

        addr_len = sizeof(struct sockaddr_in6);
        client->resolved_addresses_list->ai_addrlen = addr_len;
        addr_in6 = malloc(addr_len); // TODO: free this
        memset(addr_in6, 0, addr_len);
        addr_in6->sin6_family = AF_INET6;
        addr_in6->sin6_port = (in_port_t)*client->request_parser->port;
        memcpy(
            addr_in6->sin6_addr.s6_addr,
            client->request_parser->address,
            client->request_parser->address_length
        );

        client->resolved_addresses_list->ai_addr = (struct sockaddr*)addr_in6;

        // Aunque no haya tarea bloqueante, se avisa del fin de una para pasar
        // al siguiente estado.
        selector_notify_block(key->s, client->client);
        break;

    case REQUEST_ADDRESS_TYPE_DOMAINNAME:
        client->addr_hint = malloc(sizeof(struct addrinfo));
        client->dst_fqdn = malloc(client->request_parser->address_length + 1);
        client->dst_port = malloc(MAX_PORT_STR_LEN + 1);

        client->addr_hint->ai_family = AF_UNSPEC;
        client->addr_hint->ai_socktype = SOCK_STREAM;
        client->addr_hint->ai_protocol = IPPROTO_TCP;
        client->addr_hint->ai_flags = AI_NUMERICSERV;

        memcpy(
            client->dst_fqdn,
            client->request_parser->address,
            client->request_parser->address_length
        );
        client->dst_fqdn[client->request_parser->address_length] = '\0';

        port_itoa(htons(*((uint16_t*)client->request_parser->port)), client->dst_port);

        resolve_fqdn_address(client);
        break;
    default:
        // Invalid type
        log_error("Invalid address type for client request: %d", client->request_parser->address_type);
        // resolved_adresses_list en client es NULL por lo que se termina en error 

        // Aunque no haya tarea bloqueante, se avisa del fin de una para pasar
        // al siguiente estado.
        selector_notify_block(key->s, client->client);
        break;
    }
}

static void* resolve_fqdn_address(void* data) {
    struct client_data* client = data;
    if (client->addr_hint == NULL || client->dst_fqdn == NULL || client->dst_port == NULL)
        return NULL;

    struct addrinfo* addr_list;

    int error;
    if ((error = getaddrinfo(client->dst_fqdn, client->dst_port, client->addr_hint, &addr_list))) {
        log_error("Could not resolve address: %s", gai_strerror(error));
        client->resolved_addresses_list = NULL;
        goto resolve_fqdn_address_end;
    }

    client->resolved_addresses_list = addr_list;

resolve_fqdn_address_end:
    free(client->addr_hint);
    free(client->dst_fqdn);
    free(client->dst_port);
    client->addr_hint = NULL;
    client->dst_fqdn = NULL;
    client->dst_port = NULL;
    selector_notify_block(client->selector, client->client);
    return client->resolved_addresses_list;
}

static void resolve_addr_close(const unsigned state, struct selector_key* key) {

}

static unsigned finish_address_resolution(struct selector_key* key) {
    struct client_data* client = GET_DATA(key);

    if (client->resolved_addresses_list == NULL)
        return CONNECTION_ERROR;

    return CONNECTING;
}

static void start_connection(const unsigned state, struct selector_key* key) {
    struct client_data* data = key->data;
    struct addrinfo* addr_list = data->resolved_addresses_list;

    log_debug("Trying to connect with client");

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

        close_connection_error(CONNECTION_ERROR, key);
        return;
    }

    data->origin = origin_local_socket;

    fd_selector selector = key->s;

    // Add origin
    data->references++;
    clients[socks5_server_data.client_count++] = data;
    selector_register(selector, origin_local_socket, &socks5_client_handlers, OP_NOOP, data);
    selector_set_interest(selector, origin_local_socket, OP_WRITE);
}

static void connecting_close(const unsigned state, struct selector_key* key) {

}

static unsigned check_connection_with_origin(struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    char addr_str[ADDR_STR_MAX_SIZE];

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    bool connected = getpeername(client->origin, (struct sockaddr*)&addr, &addr_len) == 0;

    if (!connected) {
        log_info("Could not connect to %s", print_address_info(client->current_connection_trial, addr_str));

        return CONNECTION_ERROR;
    }

    print_address_from_descriptor(client->origin, addr_str);
    log_debug("Connected to %s", print_address_from_descriptor(client->origin, addr_str));

    selector_set_interest(key->s, client->client, OP_READ);
    selector_set_interest(key->s, client->origin, OP_NOOP);
    client->reply_status = SUCCEDED; //TODO: handle error statuses too
    return ADDRESS_RES;
}

static void address_res_init(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);

    log_debug("Sending response to client");

    buffer_reset(client->write_buffer);
    buffer_write(client->write_buffer, SOCKS_VER_BYTE);
    buffer_write(client->write_buffer, client->reply_status);
    buffer_write(client->write_buffer, SOCKS_RSV_BYTE);
    if (client->reply_status != SUCCEDED) {
        buffer_write(client->write_buffer, REQUEST_ADDRESS_TYPE_DOMAINNAME);
        buffer_write(client->write_buffer, 0x0);
        buffer_write(client->write_buffer, 0x00);

        goto address_res_init_end; //TODO: close connection
    }
    buffer_write(client->write_buffer, client->request_parser->address_type);

    size_t max_write_size;
    uint8_t* raw_buff = buffer_write_ptr(client->write_buffer, &max_write_size);

    void* addr;
    size_t addr_len;
    void* port;
    if (client->current_connection_trial->ai_family == AF_INET) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)client->current_connection_trial->ai_addr;
        assert(MAX_IPV4_LENGTH + MAX_PORT_LENGTH < max_write_size);
        addr = &addr_in->sin_addr;
        addr_len = MAX_IPV4_LENGTH;
        port = &addr_in->sin_port;
    }
    else {
        struct sockaddr_in6* addr_in = (struct sockaddr_in6*)client->current_connection_trial->ai_addr;
        assert(MAX_IPV6_LENGTH + MAX_PORT_LENGTH < max_write_size);
        addr = &addr_in->sin6_addr;
        addr_len = MAX_IPV6_LENGTH;
        port = &addr_in->sin6_port;
    }
    memcpy(raw_buff, addr, addr_len);
    memcpy(raw_buff, port, MAX_PORT_LENGTH);
    buffer_write_adv(client->write_buffer, addr_len + MAX_PORT_LENGTH);

address_res_init_end:
    selector_set_interest(key->s, client->client, OP_WRITE);
}

static void address_res_close(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);

    request_parser_free(client->request_parser);
    freeaddrinfo(client->resolved_addresses_list);
    client->resolved_addresses_list = NULL;
    client->current_connection_trial = NULL;
}

static unsigned write_address_res(struct selector_key* key) {
    errno = 0;
    struct client_data* client = GET_DATA(key);

    size_t bytes_to_send;
    uint8_t* res_buf = buffer_read_ptr(client->write_buffer, &bytes_to_send);

    int send_status = send(key->fd, res_buf, bytes_to_send, SEND_FLAGS);

    if (send_status < 0) {
        log_error("Could not send hello response to %s [Reason:%s]", client->client_str, strerror(errno));
        return CONNECTION_ERROR;
    }
    size_t bytes_sent = (size_t)send_status;
    buffer_read_adv(client->write_buffer, bytes_sent);

    if (bytes_sent == bytes_to_send)
        return COPY;

    return ADDRESS_RES;
}

static void copy_init(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);

    fd_selector selector = key->s;

    buffer_reset(client->write_buffer);
    buffer_reset(client->read_buffer);

    //TODO: compute interests
    selector_set_interest(selector, client->client, OP_READ | OP_WRITE);
    selector_set_interest(selector, client->origin, OP_READ | OP_WRITE);
}

static void copy_close(const unsigned state, struct selector_key* key) {

}

static unsigned copy_write(struct selector_key* key) {
    socket_descriptor target_descriptor = key->fd;
    struct client_data* data = key->data;

    struct buffer* target_buffer = target_descriptor == data->client ? data->read_buffer : data->write_buffer;

    // char addr_str[ADDR_STR_MAX_SIZE];
    // log_debug("Writing into %s", print_address_from_descriptor(target_descriptor, addr_str));

    // TODO: check if write was completed
    if (write_to_client(target_descriptor, target_buffer)) {
        log_error("Could not write to client");

        return CONNECTION_ERROR;
    }


    //TODO: compute interests
    return COPY;
}

static unsigned copy_read(struct selector_key* key) {
    fd_selector selector = key->s;
    struct client_data* data = key->data;

    struct copy_endpoint endpoint = get_endpoint(key);

    size_t max_write;

    uint8_t* source_buff_raw = buffer_write_ptr(endpoint.w_buffer, &max_write);

    int ammount_read = read(endpoint.source, source_buff_raw, max_write);
    char addr_str[ADDR_STR_MAX_SIZE];
    log_debug("Read %d bytes from client %s(%s)", ammount_read, data->client_str, print_address_from_descriptor(endpoint.source, addr_str));

    switch (ammount_read) {
    case -1:
        log_error("Could not read from client %s(%s): %s", data->client_str, print_address_from_descriptor(endpoint.source, addr_str), strerror(errno));
        return CONNECTION_ERROR;
    case 0:
        return CONNECTION_DONE;
    default:
        buffer_write_adv(endpoint.w_buffer, ammount_read);

        //TODO: compute interests
        return COPY;
    }
}


static void close_connection_normally(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    socks5_close_connection(client);
}

static void close_connection_error(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    log_error("Error");
    socks5_close_connection(client);
}

uint8_t choose_socks5_method(uint8_t methods[2]) {
    //TODO: de momento no implementamos autenticación, así que sólo podemos soportar este método
    if (methods[0] == USERNAME_PASSWORD && methods[1] == USERNAME_PASSWORD)
        return NO_ACCEPTABLE_METHODS;
    return NO_AUTENTICATION;
}
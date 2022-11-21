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
#include "utils/parser/pop3_parser.h"
#include "utils/user_list.h"
#include "server/admin_server.h"
#include "utils/parser/auth_negociation.h"

/*********************************
|          Definitions          |
*********************************/

#define SOCKS_VER_BYTE 0x5
#define SOCKS_AUTH_VER_BYTE 0x01

#define SOCKS_RSV_BYTE 0x00

#define GET_DATA(key) ((struct client_data*)key->data)

#define JOIN_PORT_ARRAY(port_arr) *((uint16_t*)port_arr)

#define ORIGIN_SV_DEFAULT_STR "origin server (unresolved)"

#define CAN_READ(duplex) (duplex & OP_READ)
#define CAN_WRITE(duplex) (duplex & OP_WRITE)
#define SHTDWN_READ(duplex) (duplex & ~OP_READ)
#define SHTDWN_WRITE(duplex) (duplex & ~OP_WRITE)

#define POP3_PORT 110

#define MAX_NULL_TERMINATED_STRING_SIZE 256

enum connection_state {
    NEGOTIATING_REQ = 0,
    NEGOTIATING_RES,
    AUTHENTICATION_READ,
    AUTHENTICATION_WRITE,
    ADDRESS_REQ,
    RESOLVE_ADDRESS,
    CONNECTING,
    ADDRESS_RES,
    SNIFF,
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
    ADDRESS_TYPE_NOT_SUPPORTED
};

enum metric_index {
    HISTORIC_CONNECTIONS,
    CONCURRENT_CONNECTIONS,
    BYTES_SENT
};

struct server_metric {
    enum metric_index index;
    uint16_t value;
};

static struct socks5_server_metrics
{
    uint16_t historic_connections;
    uint16_t concurrent_connections;
    uint32_t bytes_sent;
} server_metrics = { 0 };


enum socks5_auth_reply_status {
    SOCKS5_AUTH_SUCCESS = 0,
    SOCKS5_AUTH_FAILURE,
};

enum socks5_client_status {
    ACTIVE = 0,
    CLOSING,
    INACTIVE
};

struct negotiation_struct {
    socket_descriptor* fd;
    struct buffer* write_buffer;
    struct buffer* read_buffer;
    struct negotiation_parser* parser;
    uint8_t selected_method;
    char* to_str;
};

struct auth_struct {
    socket_descriptor* fd;
    struct buffer* write_buffer;
    struct buffer* read_buffer;
    struct auth_negociation_parser* parser;
    enum socks5_auth_reply_status status;
    char* to_str;
};


struct domainname_hint {
    struct addrinfo* addrinfo_hint;
    char* address;
    char* port;
};

struct resolved_addresses_list {
    struct addrinfo* start;
    struct addrinfo* current;
};

/**
 * - Leer la request del cliente y parsearla
 * - El resultado se guarda dentro de parser
 * - Se comienza la resolución de la dirección:
 *      - si el tipo de dirección no es DOMAINNAME se arma el struct addrinfo a mano
 *      - en cado de un DOMAINNAME se crea un nuevo hilo donde se resuelve por dns dicho nombre
 *      - la lista de todas las direcciones IP resueltas se guarda en resolved_addresses_list
 * - Una vez que se tiene la lista de direcciones se va intentando de a una para conectarse:
 *      - se crea un nuevo socket para conectarse con origin y se lo configura
 *      - se usa la función connect para intentar conectarse con origin. Como manejamos sockets no bloqueantes, connect debería devolver EINPROGRESS. Para poder ver si la conexión es exitosa hay que esperar a que el socket de origin esté listo para escribir. En ese caso checkeamos con getpeername si la conexión fue efectivamente establecida.
 *      - ante cualquier problema, ya sea para crear el socket o para concretar la conexión, se intenta con la siguiente dirección IP de la lista.
 * - Si no es posible conectarse con el origen, hay que responderle al cliente con el error correspondiente (el cual se guarda en resolution_status) y terminar la conexión.
 * - Si se logró concretar la conexión se le responde al cliente con SUCCEDED (0x00).
 * - BND. ADDRESS y BND. PORT se dejan siempre en 0
 */
 // For client
struct address_request_struct {
    socket_descriptor* fd;
    struct buffer* write_buffer;
    struct buffer* read_buffer;
    struct request_parser* parser;
    struct domainname_hint dst_hint;
    struct resolved_addresses_list* resolved_addresses_list;
    enum socks5_reply_status* resolution_status;
    fd_selector* selector;
    char* to_str;
};

// For origin
struct connecting_struct {
    socket_descriptor* fd;
    struct buffer* write_buffer;
    struct buffer* read_buffer;
    struct resolved_addresses_list* resolved_addresses_list;
    enum socks5_reply_status* resolution_status;
    char* to_str;
};

struct copy_struct {
    socket_descriptor* fd;
    struct copy_struct* target;
    struct buffer* write_buffer;
    struct buffer* read_buffer;
    fd_interest duplex;
    char* to_str;
};

struct sniff_struct {
    struct copy_struct;
    struct pop3_parser* parser;
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
    // Cliente
    socket_descriptor client_fd;

    char* client_str; //Representación legible del cliente para usar en logs y registros (: client_host:port)

    union {
        struct negotiation_struct negotiation;
        struct auth_struct auth;
        struct address_request_struct addr_req;
        struct sniff_struct sniff;
        struct copy_struct copy;
    } client;


    // Origin
    socket_descriptor origin_fd;
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;

    enum socks5_reply_status request_resolution_status;

    char* origin_str; //Representación legible del servidor de origen para usar en logs y registros (: client_host:port)

    union {
        struct connecting_struct connecting;
        struct sniff_struct sniff;
        struct copy_struct copy;
    } origin;


    // Buffers
    uint8_t* write_buff_raw;
    uint8_t* read_buff_raw;
    struct buffer* write_buffer;
    struct buffer* read_buffer;

    // Address resolution
    struct resolved_addresses_list resolved_addresses_list;

    struct state_machine stm;

    fd_selector selector;

    enum socks5_client_status status;

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

/**
 * Lista de usuarios sniffeados por el servidor
 */
static user_list_t* sniffed_users;
/**
 * Hint sobre el tipo de conexión que vamos a pedir para resolver por DNS la request del cliente
 */
static struct addrinfo addrinfo_hint = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
    .ai_protocol = IPPROTO_TCP,
    .ai_flags = AI_NUMERICSERV,
};

static uint16_t client_buffer_size = 1024;

/*******************************************
|          Function declarations          |
*******************************************/

// static struct copy_endpoint_old
// get_endpoint(struct selector_key* key);

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

bool socks5_unregister_client(struct client_data* client);

struct client_data*
    socks5_generate_new_client_data(socket_descriptor client, fd_selector selector);

void socks5_free_client_data(struct client_data* data);

bool socks5_add_new_client(socket_descriptor client, fd_selector selector);

socket_descriptor socks5_try_connect(struct client_data* client);

int free_addrinfo_on_error(struct addrinfo* addrinfo, char* message);

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

// AUTHENTICATION_READ
static void authentication_read_init(const unsigned state, struct selector_key* key);
static void authentication_read_close(const unsigned state, struct selector_key* key);
static unsigned read_authentication(struct selector_key* key);

// AUTHENTICATION WRITE
static void authentication_write_init(const unsigned state, struct selector_key* key);
static void authentication_write_close(const unsigned state, struct selector_key* key);
static unsigned write_authentication(struct selector_key* key);

// ADDRESS_REQ
static void address_req_init(const unsigned state, struct selector_key* key);
static void address_req_close(const unsigned state, struct selector_key* key);
static unsigned read_address_req(struct selector_key* key);

// RESOLVE_ADDRESS
static void resolve_addr_request(const unsigned state, struct selector_key* key);
static void resolve_addr_close(const unsigned state, struct selector_key* key);
static void* resolve_fqdn_address(void* data);
static unsigned finish_address_resolution(struct selector_key* key);

// CONNECTING
static void start_connection(const unsigned state, struct selector_key* key);
static void connecting_close(const unsigned state, struct selector_key* key);
static unsigned check_connection_with_origin(struct selector_key* key);

// ADDRESS_RES
static void address_res_init(const unsigned state, struct selector_key* key);
static void address_res_close(const unsigned state, struct selector_key* key);
static unsigned write_address_res(struct selector_key* key);

// COPY - SNIFF
static void sniff_n_copy_init(const unsigned state, struct selector_key* key);
static void sniff_n_copy_close(const unsigned state, struct selector_key* key);
static unsigned copy_write(struct selector_key* key);
static unsigned copy_read(struct selector_key* key);
static unsigned sniff_write(struct selector_key* key);
static unsigned sniff_read(struct selector_key* key);

// DONE - ERROR
static void close_connection_normally(const unsigned state, struct selector_key* key);

uint8_t choose_socks5_method(uint8_t methods[2]);

void set_interests(struct selector_key* key, struct copy_struct* ep);

struct copy_struct* get_copy_struct_ptr(struct selector_key* key);

struct sniff_struct* get_sniff_struct_ptr(struct selector_key* key);

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
        .state = AUTHENTICATION_READ,
        .on_arrival = authentication_read_init,
        .on_departure = authentication_read_close,
        .on_read_ready = read_authentication,
    },{
        .state = AUTHENTICATION_WRITE,
        .on_arrival = authentication_write_init,
        .on_departure = authentication_write_close,
        .on_write_ready = write_authentication,
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
        .state = SNIFF,
        .on_arrival = sniff_n_copy_init,
        .on_departure = sniff_n_copy_close,
        .on_read_ready = sniff_read,
        .on_write_ready = sniff_write,
    },{
        .state = COPY,
        .on_arrival = sniff_n_copy_init,
        .on_departure = sniff_n_copy_close,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
    },
    /*
    Ante un error en la ejecución del cliente:
        - se va al estado de error
        - si el cliente no está ya en estado CLOSING, el estado de error marca al cliente como CLOSING y se encarga de desregistrar los fd.
            como se está en el estado de error no se ejecuta ninguna función de cierre.
        - el estado de error cierra los fd, marca al cliente como INACTIVE y libera los recursos.

    Ante un error en la ejecución del server:
        - el servidor marca al cliente como CLOSING
        - el servidor desregistra los fd
            si el cliente está en un estado no terminal, se va a invocar su método de on_departure el cuál se va a fijar en el estado del cliente, va a realizar la rutina de cierre que sea necesaria, y luego continuará al estado de error.

    Ante un cierre normal del cliente:
        lo mismo que para el estado de error.
*/
    {
        .state = CONNECTION_DONE,
        .on_arrival = close_connection_normally,
    },{
        .state = CONNECTION_ERROR,
        .on_arrival = close_connection_normally,
    },
};


/**********************************************
|          Function Implementations          |
**********************************************/

bool socks5_init_server() {
    clients = calloc(MAX_CLIENTS_AMOUNT, sizeof(struct client_data*));
    sniffed_users = user_list_init(MAX_CLIENTS_AMOUNT);
    return false;
}

void socks5_close_server() {
    if (clients != NULL) {
        for (int i = 0; i < MAX_CLIENTS_AMOUNT; i++) {
            if (clients[i] != NULL) {
                clients[i]->status = CLOSING;
                socks5_unregister_client(clients[i]);
                clients[i] = NULL;
            }
        }
        free(clients);
        clients = NULL;
    }
    user_list_free(sniffed_users);
    sniffed_users = NULL;
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

bool socks5_unregister_client(struct client_data* data) {
    bool error = false;

    fd_selector selector = data->selector;
    socket_descriptor client_descriptor = data->client_fd;
    socket_descriptor origin_descriptor = data->origin_fd;

    log_info("Closing connection of client %s", data->client_str);

    char* client_str_copy = malloc(strlen(data->client_str) + 1);
    strcpy(client_str_copy, data->client_str);

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
    buffer_init(data->read_buffer, client_buffer_size, malloc(client_buffer_size + 1));
    data->read_buff_raw = NULL; // TODO: check if necessary

    data->write_buffer = malloc(sizeof(struct buffer));
    buffer_init(data->write_buffer, client_buffer_size, malloc(client_buffer_size + 1));
    data->write_buff_raw = NULL; // TODO: check if necessary

    data->origin_fd = NO_SOCKET;

    data->client_fd = client;

    data->selector = selector;

    data->references = 1;

    data->status = ACTIVE;

    memset(&data->client, 0, sizeof(data->client));

    memset(&data->origin, 0, sizeof(data->origin));

    data->stm.initial = NEGOTIATING_REQ;
    data->stm.states = socks5_states;
    data->stm.current = socks5_states;
    data->stm.max_state = CONNECTION_ERROR;
    stm_init(&data->stm);

    data->request_resolution_status = SUCCEDED;

    data->client_str = malloc(ADDR_STR_MAX_SIZE);
    print_address_from_descriptor(data->client_fd, data->client_str);
    data->origin_str = malloc(ADDR_STR_MAX_SIZE);
    strcpy(data->origin_str, ORIGIN_SV_DEFAULT_STR);

    return data;
}

void socks5_free_client_data(struct client_data* data) {
    log_debug("Enter freeclientdata");
    if (data == NULL || data->references-- > 1)
        return;
    log_debug("Freeing client");
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
    if (data->origin_str != NULL) {
        free(data->origin_str);
    }
    data->status = INACTIVE;

    // Remove client register
    for (size_t i = 0; i < socks5_server_data.client_count; i++) {
        if (clients[i] == data) {
            // for (size_t j = i + 1; j < socks5_server_data.client_count; j++)
            //     clients[i] = clients[j];
            // clients[socks5_server_data.client_count] = NULL;
            clients[i] = NULL;
            break;
        }
    }
    server_metrics.concurrent_connections--;
    socks5_server_data.client_count--;
    free(data);
}

bool socks5_add_new_client(socket_descriptor client, fd_selector selector) {
    // At first we have to resolve the origin address, meanwhile the new client stays idle
    struct client_data* data = socks5_generate_new_client_data(client, selector);

    clients[socks5_server_data.client_count++] = data;

    if (selector_register(selector, client, &socks5_client_handlers, OP_READ, data) != SELECTOR_SUCCESS) {
        return true;
    }
    return false;
}

socket_descriptor socks5_try_connect(struct client_data* data) {
    struct connecting_struct* origin = &data->origin.connecting;
    if (origin->resolved_addresses_list->current == NULL) return NO_SOCKET;

    struct addrinfo* origin_addr = origin->resolved_addresses_list->current;
    // crear el socket
    socket_descriptor new_client_socket = socket(origin_addr->ai_family, origin_addr->ai_socktype, origin_addr->ai_protocol);
    if (new_client_socket == NO_SOCKET) {
        free_addrinfo_on_error(origin_addr, "Could not create socket on "); //TODO: check
        return NO_SOCKET;
    }
    // configurar el socket como no bloqueante
    if (selector_fd_set_nio(new_client_socket)) {
        free_addrinfo_on_error(origin_addr, "Could not create non blocking socket on");
        return NO_SOCKET;
    };

    // connect
    int connection_status;
    if ((connect(new_client_socket, origin_addr->ai_addr, origin_addr->ai_addrlen) == -1) && !connection_in_proggress(errno)) {
        log_error("Error code: %d", errno);
        free_addrinfo_on_error(origin_addr, "Could not connect to origin");
        return NO_SOCKET;
    }
    connection_status = errno;

    char origin_addr_buff[ADDR_STR_MAX_SIZE];
    print_address_info(origin_addr, origin_addr_buff);

    if (!connection_in_proggress(connection_status)) {
        log_error("Error connecting to %s: %s", origin_addr_buff, strerror(connection_status));
        struct address_request_struct* client = &data->client.addr_req;

        switch (connection_status) {
        case EAFNOSUPPORT:
            *client->resolution_status = ADDRESS_TYPE_NOT_SUPPORTED;
            break;
        case ECONNREFUSED:
            *client->resolution_status = CONNECTION_REFUSED;
        case ENETUNREACH:
            *client->resolution_status = NETWORK_UNREACHABLE;
        default:
            *client->resolution_status = SERVER_FAILURE;
            break;
        }
        return NO_SOCKET;
    }
    log_debug("Starting connection to %s", origin_addr_buff);

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
    log_debug("Waiting for hello");
    struct negotiation_struct* client = &GET_DATA(key)->client.negotiation;

    client->fd = &GET_DATA(key)->client_fd;
    client->parser = negotiation_parser_init();
    client->selected_method = NO_ACCEPTABLE_METHODS;
    client->read_buffer = GET_DATA(key)->read_buffer;
    client->write_buffer = GET_DATA(key)->write_buffer;
    client->to_str = GET_DATA(key)->client_str;

    selector_set_interest_key(key, OP_READ);
}

static void
negotiating_req_close(const unsigned state, struct selector_key* key) {
    struct negotiation_struct* client = &GET_DATA(key)->client.negotiation;
    if (GET_DATA(key)->status == CLOSING) {
        negotiation_parser_free(client->parser);
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static unsigned
read_hello(struct selector_key* key) {
    struct negotiation_struct* client = &GET_DATA(key)->client.negotiation;

    if (client->parser == NULL) {
        // Todo: error
        log_error("Could not initiate negotiation parser");
        return CONNECTION_ERROR;
    }

    size_t max_write;
    uint8_t* buffer_raw = buffer_write_ptr(client->write_buffer, &max_write);
    int bytes_read = read(key->fd, buffer_raw, max_write);

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
    log_debug("Starting negociation with client %s", client->to_str);
    enum negotiation_results  negociation_parser_result = negotiation_parser_consume(client->write_buffer, client->parser);

    switch (negociation_parser_result) {
    case NEGOTIATION_PARSER_FINISH_ERROR:
        log_error("Could not negociate with client %s", client->to_str);
        return CONNECTION_ERROR;

    case NEGOTIATION_PARSER_FINISH_OK:
        return NEGOTIATING_RES;

    default:
        log_debug("Negociation with client %s not finished", client->to_str);
    }

    return NEGOTIATING_REQ;
}

static void
negotiating_res_init(const unsigned state, struct selector_key* key) {
    struct negotiation_struct* client = &GET_DATA(key)->client.negotiation;

    log_debug("Sending hello");

    // Elegir el método de entre los que nos dió el usuario
    client->selected_method = choose_socks5_method(client->parser->methods);

    buffer_reset(client->read_buffer);
    buffer_write(client->read_buffer, SOCKS_VER_BYTE);
    buffer_write(client->read_buffer, client->selected_method);

    selector_set_interest_key(key, OP_WRITE);
}

static unsigned write_hello(struct selector_key* key) {
    errno = 0;
    struct negotiation_struct* client = &GET_DATA(key)->client.negotiation;

    size_t bytes_to_send;
    uint8_t* buff_raw = buffer_read_ptr(client->read_buffer, &bytes_to_send);

    int send_status = send(key->fd, buff_raw, bytes_to_send, SEND_FLAGS);

    if (send_status < 0) {
        log_error("Could not send hello response to %s [Reason:%s]", client->to_str, strerror(errno));
        return CONNECTION_ERROR;
    }
    size_t bytes_sent = (size_t)send_status;
    buffer_read_adv(client->read_buffer, bytes_sent);

    if (bytes_sent == bytes_to_send) {
        if (client->selected_method == USERNAME_PASSWORD) {
            return AUTHENTICATION_READ;
        }
        if (client->selected_method == NO_AUTENTICATION) {
            return ADDRESS_REQ;
        }
        return CONNECTION_ERROR;
    }

    return NEGOTIATING_RES;
}

static void
negotiating_res_close(const unsigned state, struct selector_key* key) {
    struct negotiation_struct* client = &GET_DATA(key)->client.negotiation;

    if (client->selected_method == NO_ACCEPTABLE_METHODS)
        log_error("No supported methods for client %s", client->to_str);

    negotiation_parser_free(client->parser);

    if (GET_DATA(key)->status == CLOSING) {
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static void authentication_read_init(const unsigned state, struct selector_key* key) {
    struct auth_struct* client = &GET_DATA(key)->client.auth;

    client->fd = &GET_DATA(key)->client_fd;
    client->write_buffer = GET_DATA(key)->write_buffer;
    client->read_buffer = GET_DATA(key)->read_buffer;
    client->parser = auth_negociation_parser_init();
    client->status = SOCKS5_AUTH_FAILURE;
    client->to_str = GET_DATA(key)->client_str;

    log_debug("Authenticating client %s", client->to_str);
    selector_set_interest_key(key, OP_READ);
}

static void authentication_read_close(const unsigned state, struct selector_key* key) {
    struct auth_struct* client = &GET_DATA(key)->client.auth;
    if (GET_DATA(key)->status == CLOSING) {
        auth_negociation_parser_free(client->parser);
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static unsigned read_authentication(struct selector_key* key) {
    struct auth_struct* client = &GET_DATA(key)->client.auth;

    size_t max_write;
    uint8_t* buffer_raw = buffer_write_ptr(client->write_buffer, &max_write);
    int bytes_read = read(key->fd, buffer_raw, max_write);

    switch (bytes_read) {
    case -1:
        log_error("Error while reading authentication from %s", client->to_str);
        auth_negociation_parser_free(client->parser);
        return CONNECTION_ERROR;
    case 0:
        return CONNECTION_DONE;
    default:
        buffer_write_adv(client->write_buffer, bytes_read);

        log_debug("Reading authentication from %s", client->to_str);
        enum auth_negociation_results  negociation_parser_result = auth_negociation_parser_consume(client->parser, client->write_buffer);

        switch (negociation_parser_result) {
        case AUTH_NEGOCIATION_PARSER_ERROR:
            log_error("Could not parse credentails of client %s", client->to_str);
        case AUTH_NEGOCIATION_PARSER_FINISHED:
            return AUTHENTICATION_WRITE;
        }
        break;
    }
    return AUTHENTICATION_READ;
}

static bool authenticate_user(struct auth_negociation_parser* parser) {
    user_list_t* allowed_users = admin_server_get_allowed_users();
    char username[MAX_NULL_TERMINATED_STRING_SIZE];
    char password[MAX_NULL_TERMINATED_STRING_SIZE];
    strncpy(username, (char*)parser->username, parser->username_length);
    username[parser->username_length] = '\0';
    strncpy(password, (char*)parser->password, parser->password_length);
    password[parser->password_length] = '\0';

    return user_list_contains(allowed_users, username, password);
}

static void print_user(struct user_list_user* usr_ptr) {
    log_info("- %s", usr_ptr->username);
}

static void authentication_write_init(const unsigned state, struct selector_key* key) {
    struct auth_struct* client = &GET_DATA(key)->client.auth;

    buffer_reset(client->read_buffer);

    buffer_write(client->read_buffer, SOCKS_AUTH_VER_BYTE);
    log_debug("Result: %d", client->parser->result);
    if (client->parser->result == AUTH_NEGOCIATION_PARSER_FINISHED) {
        client->status = authenticate_user(client->parser) ? SOCKS5_AUTH_SUCCESS : AUTH_NEGOCIATION_PARSER_ERROR;
        if (client->status == AUTH_NEGOCIATION_PARSER_ERROR) {
            char username[MAX_NULL_TERMINATED_STRING_SIZE];
            strncpy(username, (char*)client->parser->username, client->parser->username_length);
            username[client->parser->username_length] = '\0';
            log_info("User %s is not a valid user", username);
            log_info("Valid users:");
            user_list_for_each(admin_server_get_allowed_users(), print_user);
        }
    }

    buffer_write(client->read_buffer, client->status);
    selector_set_interest_key(key, OP_WRITE);
}

static void authentication_write_close(const unsigned state, struct selector_key* key) {
    struct auth_struct* client = &GET_DATA(key)->client.auth;

    auth_negociation_parser_free(client->parser);

    if (GET_DATA(key)->status == CLOSING) {
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static unsigned write_authentication(struct selector_key* key) {
    errno = 0;
    struct auth_struct* client = &GET_DATA(key)->client.auth;

    size_t bytes_to_send;
    uint8_t* buff_raw = buffer_read_ptr(client->read_buffer, &bytes_to_send);

    int send_status = send(key->fd, buff_raw, bytes_to_send, SEND_FLAGS);

    if (send_status < 0) {
        log_error("Could not send auth response to %s [Reason:%s]", client->to_str, strerror(errno));
        return CONNECTION_ERROR;
    }
    size_t bytes_sent = (size_t)send_status;
    buffer_read_adv(client->read_buffer, bytes_sent);

    if (bytes_sent == bytes_to_send) {
        if (client->status == SOCKS5_AUTH_FAILURE) {
            return CONNECTION_DONE;
        }
        return ADDRESS_REQ;
    }

    return AUTHENTICATION_WRITE;
}

static void address_req_init(const unsigned state, struct selector_key* key) {
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;

    server_metrics.historic_connections++;
    server_metrics.concurrent_connections++;

    log_debug("Requesting address from client");

    client->parser = request_parser_init();
    client->fd = &GET_DATA(key)->client_fd;
    client->read_buffer = GET_DATA(key)->read_buffer;
    client->write_buffer = GET_DATA(key)->write_buffer;
    client->resolution_status = &GET_DATA(key)->request_resolution_status;
    client->to_str = GET_DATA(key)->client_str;
    client->resolved_addresses_list = &GET_DATA(key)->resolved_addresses_list;
    client->selector = &GET_DATA(key)->selector;

    selector_set_interest_key(key, OP_READ);
}

static void address_req_close(const unsigned state, struct selector_key* key) {
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;

    if (GET_DATA(key)->status == CLOSING) {
        request_parser_free(client->parser);
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static unsigned read_address_req(struct selector_key* key) {
    errno = 0;
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;

    if (!buffer_can_write(client->write_buffer))
        return ADDRESS_REQ;

    size_t max_read_bytes, bytes_read;
    uint8_t* buffer_raw = buffer_write_ptr(client->write_buffer, &max_read_bytes);
    int read_status = read(*client->fd, buffer_raw, max_read_bytes);
    switch (read_status) {
    case -1:
        log_error("Could not read request from client %s [Reason: %s]", client->to_str, strerror(errno));
        *client->resolution_status = SERVER_FAILURE;
        return ADDRESS_RES;
    case 0:
        // Si el cliente cierra la conexión de su lado, de todas formas parseo la respuesta y luego le mando el resultado
    default:
        bytes_read = (size_t)read_status;
        buffer_write_adv(client->write_buffer, bytes_read);

        enum request_results request_parser_status = request_parser_consume(client->write_buffer, client->parser);

        if (request_parser_status == REQUEST_PARSER_FINISH_ERROR) {
            log_error("Could not parse request from client %s", client->to_str);
            *client->resolution_status = SERVER_FAILURE;
            return ADDRESS_RES;
        }

        if (request_parser_status == REQUEST_PARSER_FINISH_OK) {
            log_debug("Request from client %s finished", client->to_str);
            log_debug("Client %s requested address %s", client->to_str, client->parser->address);
            return RESOLVE_ADDRESS;
        }
    }

    log_debug("Request from client %s not finished", client->to_str);

    return ADDRESS_REQ;
}

static void resolve_addr_request(const unsigned state, struct selector_key* key) {
    errno = 0;
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;

    log_debug("Starting address resolution");

    socklen_t addr_len;
    struct sockaddr_in* addr_in;
    struct sockaddr_in6* addr_in6;
    struct addrinfo* addr_info;
    switch (client->parser->address_type) {
    case REQUEST_ADDRESS_TYPE_IPV4:
        client->resolved_addresses_list->start = malloc(sizeof(struct addrinfo));
        addr_info = client->resolved_addresses_list->start;
        addr_info->ai_family = AF_INET;

        addr_info->ai_socktype = SOCK_STREAM;
        addr_info->ai_protocol = IPPROTO_TCP;

        addr_len = sizeof(struct sockaddr_in);
        addr_info->ai_addrlen = addr_len;
        addr_in = malloc(addr_len); // TODO: free this
        memset(addr_in, 0, addr_len);
        addr_in->sin_family = AF_INET;
        addr_in->sin_port = (in_port_t)*client->parser->port;
        addr_in->sin_addr.s_addr = (in_addr_t)*client->parser->address;

        addr_info->ai_addr = (struct sockaddr*)addr_in;

        // Aunque no haya tarea bloqueante, se avisa del fin de una para pasar
        // al siguiente estado.
        selector_notify_block(key->s, key->fd);
        break;

    case REQUEST_ADDRESS_TYPE_IPV6:
        client->resolved_addresses_list->start = malloc(sizeof(struct addrinfo));
        addr_info = client->resolved_addresses_list->start;
        addr_info->ai_family = AF_INET6;

        addr_info->ai_socktype = SOCK_STREAM;
        addr_info->ai_protocol = IPPROTO_TCP;

        addr_len = sizeof(struct sockaddr_in6);
        addr_info->ai_addrlen = addr_len;
        addr_in6 = malloc(addr_len);
        memset(addr_in6, 0, addr_len);
        addr_in6->sin6_family = AF_INET6;
        addr_in6->sin6_port = (in_port_t)*client->parser->port;
        memcpy(
            addr_in6->sin6_addr.s6_addr,
            client->parser->address,
            client->parser->address_length
        );

        addr_info->ai_addr = (struct sockaddr*)addr_in6;

        // Aunque no haya tarea bloqueante, se avisa del fin de una para pasar
        // al siguiente estado.
        selector_notify_block(key->s, key->fd);
        break;

    case REQUEST_ADDRESS_TYPE_DOMAINNAME:
        client->dst_hint.addrinfo_hint = &addrinfo_hint;

        client->dst_hint.address = malloc(client->parser->address_length + 1);
        memcpy(
            client->dst_hint.address,
            client->parser->address,
            client->parser->address_length
        );
        client->dst_hint.address[client->parser->address_length] = '\0';

        client->dst_hint.port = malloc(MAX_PORT_STR_LEN + 1);
        port_itoa(ntohs(JOIN_PORT_ARRAY(client->parser->port)), client->dst_hint.port);

        resolve_fqdn_address(client);
        break;
    default:
        // Invalid type
        log_error("Invalid address type for client request: %d", client->parser->address_type);
        // resolved_adresses_list en client es NULL por lo que se termina en error 

        // Aunque no haya tarea bloqueante, se avisa del fin de una para pasar
        // al siguiente estado.
        selector_notify_block(key->s, *client->fd);
        break;
    }
}

static enum socks5_reply_status resolve_status(int gai_err, int errno_err) {
    switch (gai_err) {
    case EAI_NONAME:
#ifdef __USE_GNU
    case EAI_ADDRFAMILY:
    case EAI_NODATA:
#endif
        return HOST_UNREACHABLE;
    case EAI_FAMILY:
        return ADDRESS_TYPE_NOT_SUPPORTED;
    case EAI_SERVICE:
    case EAI_SOCKTYPE:
        return CONNECTION_REFUSED;
    default:
        switch (errno_err) {
        case ENETUNREACH:
        case ENETDOWN:
            return NETWORK_UNREACHABLE;
        case EHOSTUNREACH:
        case EHOSTDOWN:
            return HOST_UNREACHABLE;
        case ENOTCONN:
        case ESHUTDOWN:
            return CONNECTION_REFUSED;
        case EAFNOSUPPORT:
            return ADDRESS_TYPE_NOT_SUPPORTED;
        }
    }
    return SERVER_FAILURE;
}

static void* resolve_fqdn_address(void* data) {
    errno = 0;
    struct address_request_struct* client = data;
    if (client->dst_hint.address == NULL || client->dst_hint.port == NULL) {
        *client->resolution_status = SERVER_FAILURE;
        return NULL;
    }

    struct addrinfo* addr_list;

    int error;
    if ((error = getaddrinfo(client->dst_hint.address, client->dst_hint.port, client->dst_hint.addrinfo_hint, &addr_list))) {
        log_error("Could not resolve address %s:%s: %s", client->dst_hint.address, client->dst_hint.port, gai_strerror(error));
        client->resolved_addresses_list->start = NULL;
        *client->resolution_status = resolve_status(error, errno);
        goto resolve_fqdn_address_end;
    }

    client->resolved_addresses_list->start = addr_list;

resolve_fqdn_address_end:
    free(client->dst_hint.address);
    free(client->dst_hint.port);
    client->dst_hint.address = NULL;
    client->dst_hint.port = NULL;
    if (selector_notify_block(*client->selector, *client->fd) != SELECTOR_SUCCESS) {
        *client->resolution_status = SERVER_FAILURE;
        return NULL;
    }
    return client->resolved_addresses_list->start;
}

static void resolve_addr_close(const unsigned state, struct selector_key* key) {
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;
    if (GET_DATA(key)->status == CLOSING) {
        request_parser_free(client->parser);
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static unsigned finish_address_resolution(struct selector_key* key) {
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;

    struct connecting_struct* origin = &GET_DATA(key)->origin.connecting;
    origin->fd = &GET_DATA(key)->origin_fd;
    origin->resolved_addresses_list = &GET_DATA(key)->resolved_addresses_list;
    origin->resolved_addresses_list->current = origin->resolved_addresses_list->start;
    origin->resolution_status = &GET_DATA(key)->request_resolution_status;
    origin->write_buffer = GET_DATA(key)->read_buffer;
    origin->read_buffer = GET_DATA(key)->write_buffer;
    origin->to_str = GET_DATA(key)->origin_str;

    if (client->resolved_addresses_list->start == NULL) {
        // Hubo un error y hay que informarlo al cliente
        return ADDRESS_RES;
    }

    return CONNECTING;
}

static void start_connection(const unsigned state, struct selector_key* key) {
    struct client_data* data = key->data;
    struct connecting_struct* origin = &GET_DATA(key)->origin.connecting;

    struct addrinfo* addr_list = origin->resolved_addresses_list->current;

    log_debug("Trying to connect with client");


    socket_descriptor origin_local_socket = NO_SOCKET;
    for (;addr_list != NULL; addr_list = addr_list->ai_next) {
        origin->resolved_addresses_list->current = addr_list;
        origin_local_socket = socks5_try_connect(data);
        if (origin_local_socket != NO_SOCKET) break;
    }
    if (origin_local_socket == NO_SOCKET) {
        char origin_addr_buff[ADDR_STR_MAX_SIZE];
        log_error("Could not resolve origin address %s", print_address_info(addr_list, origin_addr_buff));
        data->resolved_addresses_list.current = NULL;
        freeaddrinfo(origin->resolved_addresses_list->start);

        return;
    }

    *origin->fd = origin_local_socket;

    fd_selector selector = key->s;

    // Add origin
    data->references++;
    if (selector_register(selector, origin_local_socket, &socks5_client_handlers, OP_WRITE, data) != SELECTOR_SUCCESS) {
        struct address_request_struct* client = &GET_DATA(key)->client.addr_req;
        *client->resolution_status = SERVER_FAILURE;
        return;
    }
}

static void connecting_close(const unsigned state, struct selector_key* key) {
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;

    if (GET_DATA(key)->status == CLOSING) {
        request_parser_free(client->parser);
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static unsigned check_connection_with_origin(struct selector_key* key) {
    struct connecting_struct* origin = &GET_DATA(key)->origin.connecting;

    int connection_status = getpeername(*origin->fd, (struct sockaddr*)&GET_DATA(key)->origin_addr, &GET_DATA(key)->origin_addr_len) == 0;

    if (connection_status != 0) {
        log_info("Could not connect to %s", print_address_info(origin->resolved_addresses_list->current, origin->to_str));
        if (origin->resolved_addresses_list->current->ai_next != NULL) {
            origin->resolved_addresses_list->current = origin->resolved_addresses_list->current->ai_next;
            start_connection(CONNECTING, key);
            return CONNECTING;
        }
        return ADDRESS_RES;
    }

    print_address_from_descriptor(*origin->fd, origin->to_str);
    log_debug("Connected to %s", origin->to_str);

    selector_set_interest(key->s, GET_DATA(key)->client_fd, OP_READ);
    selector_set_interest(key->s, GET_DATA(key)->origin_fd, OP_NOOP);
    *origin->resolution_status = SUCCEDED;
    return ADDRESS_RES;
}

static void address_res_init(const unsigned state, struct selector_key* key) {
    struct connecting_struct* origin = &GET_DATA(key)->origin.connecting;
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;


    buffer_reset(origin->write_buffer);
    buffer_write(origin->write_buffer, SOCKS_VER_BYTE);
    buffer_write(origin->write_buffer, *origin->resolution_status);
    buffer_write(origin->write_buffer, SOCKS_RSV_BYTE);
    //mandar siempre 0 en la bnd.address, sin importar si hubo error o no
    buffer_write(origin->write_buffer, REQUEST_ADDRESS_TYPE_IPV4);
    buffer_write(origin->write_buffer, 0x00);
    buffer_write(origin->write_buffer, 0x00);
    buffer_write(origin->write_buffer, 0x00);
    buffer_write(origin->write_buffer, 0x00);

    buffer_write(origin->write_buffer, 0x00);
    buffer_write(origin->write_buffer, 0x00);

    if (*origin->resolution_status != SUCCEDED) {
        log_error("There were errors during connection");
    }

    selector_set_interest(key->s, GET_DATA(key)->client_fd, OP_WRITE);
}

static void address_res_close(const unsigned state, struct selector_key* key) {
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;

    request_parser_free(client->parser);
    freeaddrinfo(client->resolved_addresses_list->start);
    GET_DATA(key)->resolved_addresses_list.start = NULL;
    GET_DATA(key)->resolved_addresses_list.current = NULL;
    if (GET_DATA(key)->status == CLOSING) {
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static unsigned write_address_res(struct selector_key* key) {
    errno = 0;
    struct address_request_struct* client = &GET_DATA(key)->client.addr_req;

    size_t bytes_to_send;
    uint8_t* res_buf = buffer_read_ptr(client->read_buffer, &bytes_to_send);

    int send_status = send(key->fd, res_buf, bytes_to_send, SEND_FLAGS);

    if (send_status < 0) {
        log_error("Could not send request response to %s [Reason:%s]", client->to_str, strerror(errno));
        return CONNECTION_ERROR;
    }
    size_t bytes_sent = (size_t)send_status;
    buffer_read_adv(client->read_buffer, bytes_sent);

    if (bytes_sent == bytes_to_send) {
        if (*client->resolution_status != SUCCEDED)
            return CONNECTION_DONE;
        return ntohs(JOIN_PORT_ARRAY(client->parser->port)) == POP3_PORT ? SNIFF : COPY;
    }
    return ADDRESS_RES;
}

static unsigned sniff_write(struct selector_key* key) {
    struct sniff_struct* source = get_sniff_struct_ptr(key);

    size_t max_read = 0;
    uint8_t* buff_raw = buffer_read_ptr(source->read_buffer, &max_read);

    int send_status = send(*source->fd, buff_raw, max_read, SEND_FLAGS);

    if (send_status == -1) {
        log_error("Could not write into %s", source->to_str);
        return CONNECTION_ERROR;
    }

    if (*source->fd == GET_DATA(key)->origin_fd) {
        server_metrics.bytes_sent += send_status;
    }

    buffer_read_adv(source->read_buffer, send_status);

    set_interests(key, (struct copy_struct*)source);
    set_interests(key, (struct copy_struct*)source->target);
    return SNIFF;
}

static unsigned sniff_read(struct selector_key* key) {
    struct sniff_struct* source = get_sniff_struct_ptr(key);

    size_t max_write;
    uint8_t* source_buff_raw = buffer_write_ptr(source->write_buffer, &max_write);

    int ammount_read = read(*source->fd, source_buff_raw, max_write);
    switch (ammount_read) {
    case -1:
        log_error("Could not read from %s: %s", source->to_str, strerror(errno));
        return CONNECTION_ERROR;
    case 0:
        // Cuando un socket manda EOF, deja de enviar bytes
        // si ya estaba cerrado el otro canal, se cierra la conexión
        if (!CAN_WRITE(source->duplex))
            return CONNECTION_DONE;
        errno = 0;
        source->duplex = SHTDWN_READ(source->duplex);
        source->target->duplex = SHTDWN_WRITE(source->target->duplex);
        if (shutdown(*source->fd, SHUT_RD)) {
            log_error("Could not shutdown %s: %s", source->to_str, strerror(errno));
            return CONNECTION_ERROR;
        }
        if (shutdown(*source->target->fd, SHUT_WR)) {
            log_error("Could not shutdown %s: %s", source->target->to_str, strerror(errno));
            return CONNECTION_ERROR;
        }

        break;
    default:
        buffer_write_adv(source->write_buffer, ammount_read);
        if (source->parser == NULL) break;

        // Creo un buffer aparte para que consuma el sniffer
        struct buffer sniff_buffer;
        buffer_init(&sniff_buffer, ammount_read, source->write_buffer->data);
        buffer_write_adv(&sniff_buffer, ammount_read);


        enum pop3_results sniff_results =
            pop3_parser_consume(&sniff_buffer, source->parser);

        switch (sniff_results) {
        case POP3_FINISH_ERROR:
            pop3_parser_reset(source->parser);
            break;
        case POP3_FINISH_OK:
            // se detectó usuario y contraseña, guardar
            user_list_add(sniffed_users, source->parser->user, source->parser->pass);
            log_debug("Sniffed user (%s:%s)", source->parser->user, source->parser->pass);
            break;
        }
        break;
    }
    set_interests(key, (struct copy_struct*)source);
    set_interests(key, (struct copy_struct*)source->target);
    return SNIFF;
}

static void sniff_n_copy_init(const unsigned state, struct selector_key* key) {
    if (state == SNIFF) {
        log_debug("Entering sniffing mode");
    }
    struct copy_struct* client = &GET_DATA(key)->client.copy;
    struct copy_struct* origin = &GET_DATA(key)->origin.copy;

    buffer_reset(GET_DATA(key)->read_buffer);
    buffer_reset(GET_DATA(key)->write_buffer);

    client->fd = &GET_DATA(key)->client_fd;
    client->target = origin;
    client->write_buffer = GET_DATA(key)->write_buffer;
    client->read_buffer = GET_DATA(key)->read_buffer;
    client->duplex = OP_READ | OP_WRITE;
    client->to_str = GET_DATA(key)->client_str;
    if (state == SNIFF)
        ((struct sniff_struct*)client)->parser = pop3_parser_init();


    origin->fd = &GET_DATA(key)->origin_fd;
    origin->target = client;
    origin->write_buffer = GET_DATA(key)->read_buffer;
    origin->read_buffer = GET_DATA(key)->write_buffer;
    origin->duplex = OP_READ | OP_WRITE;
    origin->to_str = GET_DATA(key)->origin_str;
    // seteamos el parser de origin en NULL para identificarlo del cliente
    if (state == SNIFF)
        ((struct sniff_struct*)origin)->parser = NULL;

    // selector_set_interest(key->s, *client->fd, OP_READ);
    // selector_set_interest(key->s, *origin->fd, OP_READ);
    set_interests(key, client);
    set_interests(key, origin);
}

static void sniff_n_copy_close(const unsigned state, struct selector_key* key) {
    if (state == SNIFF && get_sniff_struct_ptr(key)->parser != NULL) {
        pop3_parser_free(get_sniff_struct_ptr(key)->parser);
    }
    if (GET_DATA(key)->status == CLOSING) {
        close_connection_normally(CONNECTION_ERROR, key);
        return;
    }
}

static unsigned copy_write(struct selector_key* key) {
    struct copy_struct* source = get_copy_struct_ptr(key);

    size_t max_read = 0;
    uint8_t* buff_raw = buffer_read_ptr(source->read_buffer, &max_read);

    int send_status = send(*source->fd, buff_raw, max_read, SEND_FLAGS);

    if (send_status == -1) {
        log_error("Could not write into %s", source->to_str);
        return CONNECTION_ERROR;
    }

    if (*source->fd == GET_DATA(key)->origin_fd) {
        server_metrics.bytes_sent += send_status;
    }

    buffer_read_adv(source->read_buffer, send_status);

    set_interests(key, source);
    set_interests(key, source->target);
    return COPY;
}

static unsigned copy_read(struct selector_key* key) {
    struct copy_struct* source = get_copy_struct_ptr(key);

    size_t max_write;
    uint8_t* source_buff_raw = buffer_write_ptr(source->write_buffer, &max_write);

    int ammount_read = read(*source->fd, source_buff_raw, max_write);
    switch (ammount_read) {
    case -1:
        log_error("Could not read from  %s: %s", source->to_str, strerror(errno));
        return CONNECTION_ERROR;
    case 0:
        // Cuando un socket manda EOF, deja de enviar bytes
        // si ya estaba cerrado el otro canal, se cierra la conexión
        if (!CAN_WRITE(source->duplex))
            return CONNECTION_DONE;
        errno = 0;
        source->duplex = SHTDWN_READ(source->duplex);
        source->target->duplex = SHTDWN_WRITE(source->target->duplex);
        if (shutdown(*source->fd, SHUT_RD)) {
            log_error("Could not shutdown %s: %s", source->to_str, strerror(errno));
            return CONNECTION_ERROR;
        }
        if (shutdown(*source->target->fd, SHUT_WR)) {
            log_error("Could not shutdown %s: %s", source->target->to_str, strerror(errno));
            return CONNECTION_ERROR;
        }

        break;
    default:
        buffer_write_adv(source->write_buffer, ammount_read);
        break;
    }
    set_interests(key, source);
    set_interests(key, source->target);
    return COPY;
}


static void close_connection_normally(const unsigned state, struct selector_key* key) {
    struct client_data* client = GET_DATA(key);
    if (state == CONNECTION_ERROR) {
        log_error("There was an error on execution for %s", client->client_str);
    }
    log_info("Closing connection of %s", client->client_str);
    if (client->status != CLOSING) {
        client->status = CLOSING;
        socks5_unregister_client(client);
        log_debug("Closing both ends of client");
        close(client->client_fd);
        if (client->origin_fd > 0) {
            close(client->origin_fd);
        }
        client->references = 1;
        socks5_free_client_data(client);
        return;
    }
    log_debug("Closing client %s", client->client_str);
    close(key->fd);
    socks5_free_client_data(client);
}

uint8_t choose_socks5_method(uint8_t methods[2]) {
    if (methods[0] == NO_ACCEPTABLE_METHODS)
        return NO_ACCEPTABLE_METHODS;
    if (methods[1] == NO_ACCEPTABLE_METHODS) {
        return methods[0];
    }
    if (methods[0] == USERNAME_PASSWORD || methods[1] == USERNAME_PASSWORD)
        return USERNAME_PASSWORD;
    return NO_AUTENTICATION;
}

void set_interests(struct selector_key* key, struct copy_struct* ep) {
    fd_interest interest = OP_NOOP;
    if (CAN_READ(ep->duplex) && buffer_can_write(ep->write_buffer)) {
        interest |= OP_READ;
    }
    if (CAN_WRITE(ep->duplex) && buffer_can_read(ep->read_buffer)) {
        interest |= OP_WRITE;
    }
    if (selector_set_interest(key->s, *ep->fd, interest) != SELECTOR_SUCCESS) {
        log_error("Could not set interests for %s", ep->to_str);
        //TODO: handle error
    }
}

struct copy_struct* get_copy_struct_ptr(struct selector_key* key) {
    return key->fd == GET_DATA(key)->client_fd ? &GET_DATA(key)->client.copy : &GET_DATA(key)->origin.copy;
}

struct sniff_struct* get_sniff_struct_ptr(struct selector_key* key) {
    return key->fd == GET_DATA(key)->client_fd ? &GET_DATA(key)->client.sniff : &GET_DATA(key)->origin.sniff;
}

uint16_t socks5_get_historic_connections() {
    return server_metrics.historic_connections;
}

uint16_t socks5_get_concurrent_connections() {
    return server_metrics.concurrent_connections;
}

uint16_t socks5_get_bytes_sent() {
    log_debug("Bytes: %ld", server_metrics.bytes_sent);
    return server_metrics.bytes_sent >> 10;
}

void socks5_update_client_buffer_size(uint16_t new_size) {
    log_debug("Client buffer updated");
    client_buffer_size = new_size;
}

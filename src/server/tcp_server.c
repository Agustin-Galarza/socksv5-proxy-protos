/**
 * TODO:
 *  manejar errores del selector || revisar flujo para ver si se manejan bien todos los errores
 */
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
#include "logger/logger.h"
#include "utils/buffer.h"
#include "utils/representation.h"
#include "utils/selector.h"
#include "logger/server_log.h"
#include "parser/client_parser.h"
#include "utils/netutils.h"
#include "parser/negociation.h"

 /*********************************
 |          Definitions          |
 *********************************/

#define NO_SOCKET -1

#define CLIENT_BUFFER_SIZE 1024

#define MAX_CLIENTS_AMOUNT 500

typedef int socket_descriptor;


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
    struct addrinfo* resolved_addresses;
    // struct sockaddr* origin_address;
    // socklen_t origin_address_len;
    fd_selector selector;

    client_parser* parser;
    struct negociation_parser* negociation_parser;

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

/**
 * @brief defines if the server should keep running
 */
bool server_active = true;
/*
 * Clientes del servidor
*/
struct client_data** clients;

struct server_data
{
    size_t max_clients;
    socket_descriptor fd;
    size_t client_count;
} server_data;

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

void handle_sig_kill(int signum);

socket_descriptor
server_init(struct server_config* config);

/**
 * @brief accepts new connection and returns the new client's socket descriptor
 */
socket_descriptor
accept_new_connection(socket_descriptor server_socket);

bool add_new_client_log(socket_descriptor client);

bool add_disconnected_client_log(struct client_data* client);

bool write_to_client(socket_descriptor client_socket, struct buffer* client_buffer);

bool close_connection(struct client_data* client);

struct client_data*
    generate_new_client_data(socket_descriptor client, fd_selector selector);

void free_client_data(struct client_data* data);

bool read_new_request_from_client(struct client_data* data);

bool add_new_client(socket_descriptor client, fd_selector selector);

/**
 *  Revisa la intención de conexión indicada por el cliente en el campo
 * origin_address_repr y resuelve su dirección IP para luego poder conectarse.
 * Deja en el cliente la lista de posibles direcciones
 */
void* resolve_origin_address(void* client_data);

socket_descriptor try_connect(struct addrinfo* origin);

// Event Handlers
void server_handle_read(struct selector_key* key);

void handle_file_write(struct selector_key* key);

void client_handle_read(struct selector_key* key);

void client_handle_write(struct selector_key* key);

void connect_client(struct selector_key* key);
int free_addrinfo_on_error(struct addrinfo* addrinfo, char* message);


void client_handle_close(struct selector_key* key);

static const struct fd_handler
client_handlers = {
    .handle_read = client_handle_read,
    .handle_write = client_handle_write,
    .handle_block = connect_client,
    .handle_close = client_handle_close,
};

static const struct fd_handler
server_handlers = {
        .handle_read = server_handle_read,
        .handle_write = NULL,
        .handle_close = NULL,
};

static const struct fd_handler
logs_file_handlers = {
        .handle_read = NULL,
        .handle_write = handle_file_write,
        .handle_close = NULL,
        .handle_block = NULL,
};

/**********************************************
|          Function Implementations          |
**********************************************/

/**
 * Proxy TCP (origin: 127.0.0.1 9090)
 *
 * - Inicializar todos los recursos a utilizar por el servidor
 *
 * - Crear el socket pasivo (SP) (IPv4) para esperar por nuevas conexiones
 *
 * - (SP): READ - si tengo capacidad para atender nuevos clientes
 *          aceptar la conexión y agregar al nuevo cliente*
 *
 * - agregar nuevo cliente:
 *      crear estructura de datos
 *      registrar al cliente en el selector
 *      cliente (C) en estado de READ_REQUEST
 *
 * - (C): READ_REQUEST - agregar al cliente la referencia al origen fijo
 *              pasar al estado RESOLVE_ADDR
 *
 * - (C): RESOLVE_ADDR - en un nuevo thread, hacer la resolución con getaddrinfo
 *          y guardar los resultados en el cliente
 *              pasar al estado de CONNECTING
 *
 * - (C): CONNECTING - iterar por la lista de resultados y conectarse al primer
 *          endpoint posible.
 *              agregar al origen (O) al cliente y registarlo en el selector
 *              pasar al estado de COPY
 *
 * - (C), (O): COPY     (Revisar diagrama de la conexión)
 *              Read socket(C) si write_buffer tiene capacidad
 *              Read socket(O) si read_buffer tiene capacidad
 *              Write socket(C) si read_buffer tiene capacidad
 *              Write socket(O) si write_buffer tiene capacidad
 *
 */
bool run_server(struct server_config* config) {
    /************* Variables and Init *************/
    signal(SIGINT, handle_sig_kill);
    signal(SIGKILL, handle_sig_kill);
    signal(SIGTERM, handle_sig_kill);

    bool error = false;

    clients = malloc(sizeof(struct client_data*) * MAX_CLIENTS_AMOUNT);

    fd_selector selector = NULL;
    socket_descriptor server_socket = NO_SOCKET;

    const struct selector_init init_args = {
        .select_timeout = {
            .tv_nsec = 0,
            .tv_sec = 10,
        },
        .signal = SIGALRM,
    };

    // prepare and open logs file
    if (init_server_logger(config->logs_filename)) {
        log_error("Error initializing logs file");
        return true;
    }
    int logs_file_fd = fileno(get_file_data().stream);

    // Starting server
    char* time_msg = malloc(TIME_FMT_STR_MAX_SIZE);
    get_datetime_string(time_msg);
    if (write_server_log("Starting server on %s\n", time_msg)) {
        log_error("Could not write server log");
        error = true;
        goto end;
    }
    free(time_msg);

    server_socket = server_init(config);

    if (server_socket == NO_SOCKET) {
        log_error("Could not initialize server");
        error = true;
        goto end;
    }

    /************* Algorithm *************/

    char port_str[MAX_PORT_STR_LEN];
    port_itoa(config->port, port_str);

    if (listen(server_socket, config->initial_connections) != 0) {
        log_error("Could not listen to port %s: %s", port_str, strerror(errno));

        error = true;
        goto end;
    }

    log_info("Server waiting for connections on port %s", port_str);

    if (selector_fd_set_nio(server_socket) == -1) {
        log_error("Could not handle server socket flags: %s", strerror(errno));
        error = true;
        goto end;
    }

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

    selector_status status = selector_register(selector, server_socket, &server_handlers, OP_READ, &server_data);
    if (status != SELECTOR_SUCCESS) {
        log_error("Could not register server socket");

        error = true;
        goto end;
    }

    // struct logs_file_data file_data = get_file_data();
    // status = selector_register(selector, logs_file_fd, &logs_file_handlers, OP_WRITE, &file_data);
    // if (status != SELECTOR_SUCCESS) {
    //     log_error("Could not register logs file");

    //     error = true;
    //     goto end;
    // }

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
    int prev_errno = errno;
    if (close(server_socket)) errno = prev_errno;
    free_server_logger();

    return error;
}

socket_descriptor server_init(struct server_config* config) {
    errno = 0;

    struct addrinfo addr_config;
    memset(&addr_config, '\0', sizeof(addr_config));
    addr_config.ai_family = config->version == IPV4 ? AF_INET : AF_INET6;
    addr_config.ai_flags = AI_PASSIVE;
    addr_config.ai_protocol = IPPROTO_TCP;
    addr_config.ai_socktype = SOCK_STREAM;

    struct addrinfo* addr_list;

    char port_str[MAX_PORT_STR_LEN];
    if (port_itoa(config->port, port_str) == NULL) {
        log_error("Could not parse port number");

        return NO_SOCKET;
    }

    if (getaddrinfo(NULL, port_str, &addr_config, &addr_list) != 0) {
        log_error("Could not parse server config: %s", strerror(errno));

        freeaddrinfo(addr_list);
        return NO_SOCKET;
    }
    if (addr_list == NULL) {
        log_error("Could not get address for server: %s", strerror(errno));

        freeaddrinfo(addr_list);
        return NO_SOCKET;
    }

    socket_descriptor server_socket = socket(addr_list->ai_family, addr_list->ai_socktype, addr_list->ai_protocol);

    if (server_socket == NO_SOCKET) {
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
            (char*)&reuseaddr_option_value,
            sizeof(reuseaddr_option_value)) < 0) {
        log_error("Could not configure socket: %s", strerror(errno));

        freeaddrinfo(addr_list);
        close(server_socket);
        return NO_SOCKET;
    }

    if (bind(server_socket, addr_list->ai_addr, addr_list->ai_addrlen) != 0) {
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

bool add_new_client_log(socket_descriptor client) {
    char time_fmt_str[TIME_FMT_STR_MAX_SIZE];
    char addr_buff[ADDR_STR_MAX_SIZE];


    get_datetime_string(time_fmt_str);
    if (time_fmt_str[0] == '\0') {
        log_error("Error while trying to generate datetime string");
        return true;
    }

    print_address_from_descriptor(client, addr_buff);
    if (write_server_log("New connection from %s on %s\n", addr_buff, time_fmt_str)) {
        return true;
    }

    return false;
}

bool add_disconnected_client_log(struct client_data* client) {
    char time_fmt_str[TIME_FMT_STR_MAX_SIZE];

    get_datetime_string(time_fmt_str);
    if (time_fmt_str[0] == '\0') {
        log_error("Error while trying to generate datetime string");
        return true;
    }

    if (write_server_log("Client %s disconnected on %s\n", client->client_str, time_fmt_str)) {
        return true;
    }

    return false;
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

void handle_sig_kill(int signum) {
    char datetime_str[TIME_FMT_STR_MAX_SIZE];
    get_datetime_string(datetime_str);

    char log_msg[LOGS_BUFFER_SIZE];

#ifdef __GLIBC__ 
    snprintf(log_msg, LOGS_BUFFER_SIZE, "Server abruptly stopped on %s by %s", get_datetime_string(datetime_str), strsignal(signum));
#endif


    log_warning(log_msg);
    fprintf(get_file_data().stream, "%s\n", log_msg);
    fflush(get_file_data().stream);

    server_active = false;
}

struct client_data* generate_new_client_data(socket_descriptor client, fd_selector selector) {
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

    data->resolved_addresses = NULL;

    data->parser = client_parser_init();

    data->negociation_parser = negociation_parser_init();

    data->client_str = malloc(ADDR_STR_MAX_SIZE);
    print_address_from_descriptor(data->client, data->client_str);
    // data->origin_address = NULL;
    // data->origin_address_repr = NULL;
    // data->origin_address_len = 0;

    return data;
}

void free_client_data(struct client_data* data) {
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
    client_parser_free(data->parser);
    negociation_parser_free(data->negociation_parser);
    // if (data->origin_address != NULL)
    //     free(data->origin_address);
    // TODO: free origin_address_repr when it is allocated

    // Remove client register
    for (size_t i = 0; i < server_data.client_count; i++) {
        if (clients[i] == data) {
            for (size_t j = i + 1; j < server_data.client_count; j++)
                clients[i] = clients[j];
            clients[server_data.client_count] = NULL;
            break;
        }
    }
    free(data);
}

bool add_new_client(socket_descriptor client, fd_selector selector) {
    // TODO: manage states: we should only want to read from a client after it's connected. Then we'll handle reads and writes as every connection changes states.
    // At first we have to resolve the origin address, meanwhile the new client stays idle
    struct client_data* data = generate_new_client_data(client, selector);

    clients[server_data.client_count] = data;

    if (selector_register(selector, client, &client_handlers, OP_NOOP, data)) {
        return true;
    }
    server_data.client_count++;

    return read_new_request_from_client(data);
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
    pthread_create(&tid, NULL, resolve_origin_address, (void*)data);

    return false;
}

void server_handle_read(struct selector_key* key) {
    struct server_data* data = key->data;
    socket_descriptor server_socket = key->fd;
    fd_selector selector = key->s;

    if (data->client_count == data->max_clients) {
        // there's no more capacity for new connections
        log_warning("Refused new connection, max capacity of clients reached");
    }
    else {
        socket_descriptor new_client = accept_new_connection(server_socket);

        if (new_client > 0) {
            // log new client. Write message into buffer to write when file is ready
            if (add_new_client_log(new_client)) {
                log_error("Could not generate new client log");
                return;
            }
            // add new client to array
            if (add_new_client(new_client, selector)) {
                log_error("Could not register client");
                return;
            }
        }
    }
}

void handle_file_write(struct selector_key* key) {
    if (flush_logs()) {
        log_error("Could not write into logs file");
    }
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

void client_handle_read(struct selector_key* key) {
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
    switch (ammount_read) {
    case -1:
        log_error("Could not read from client %s: %s", data->client_str, strerror(errno));
        return;
    case 0:
        if (close_connection(data))
            return;
        break;
    default:
        buffer_write_adv(source_buffer, ammount_read);

        // Leo del cliente y parseo el mensaje de negociacion
        // Si el mensaje es invalido, cierro la conexion
        // Si el mensaje es valido, lo guardo le guardo al cliente su socket y su selector
        log_debug("Starting negociation with client %s", data->client_str);
        data->state = NEGOCIATING;
        int negociation_parser_result = negociation_parser_consume(data->write_buffer, data->negociation_parser);

        if (negociation_parser_result == PARSER_FINISH_OK)
            selector_set_interest(selector, target_descriptor, OP_WRITE | OP_READ);

        if (negociation_parser_result == PARSER_FINISH_ERROR) {
            log_error("Could not negociate with client %s", data->client_str);
            close_connection(data);
            return;
        }

        if (negociation_parser_result == PARSER_NOT_FINISH) {
            log_debug("Negociation with client %s not finished", data->client_str);
        }

        // source_buff_raw[ammount_read] = '\0';

        // //TODO: el parseo tendría que ser únicamente del cliente al origen 
        // enum parsing_status parser_status;
        // // if parser status is WAITING, start parsing -> change status to PARSING
        // if (client_parser_get_status(data->parser) == CLNT_PARSER_WAITING) {
        //     parser_status = start_parsing(data->parser, (char*)source_buff_raw, ammount_read);
        // }
        // else {
        //     // parse msg
        //     parser_status = keep_parsing(data->parser, ammount_read);
        // }
        // buffer_reset(source_buffer);

        // // if error -> handle
        // if (parser_status == CLNT_PARSER_ERROR) {
        //     log_error("Could not parse message from client %s: %s",
        //         data->client_str,
        //         client_parser_error_str(data->parser));
        //     client_parser_reset(data->parser);
        //     return;
        // }
        // if (parser_status == CLNT_PARSER_DONE) {
        //     // if done log msg and add write to interests
        //     // print_address_from_descriptor(source_descriptor, addr_str);
        //     struct parsed_msg* msg = get_parsed_msg(data->parser);
        //     log_info("New message from %s: %s", msg->username, msg->msg);

        //     // write parsed msg into buffer
        //     // buffer_reset(source_buffer);
        //     source_buff_raw = buffer_write_ptr(source_buffer, &max_write);
        //     strncpy((char*)source_buff_raw, msg->msg, max_write);
        //     buffer_write_adv(source_buffer, strlen((char*)source_buff_raw));
        //     client_parser_reset(data->parser);

        //     selector_set_interest(selector, target_descriptor, OP_WRITE | OP_READ);
        // }
        // // if not done, keep reading and parsing
        break;
    }
}

void client_handle_write(struct selector_key* key) {
    fd_selector selector = key->s;
    socket_descriptor target_descriptor = key->fd;
    struct client_data* data = key->data;

    struct buffer* target_buffer = target_descriptor == data->client ? data->read_buffer : data->write_buffer;

    // TODO: check if write was completed
    write_to_client(target_descriptor, target_buffer);

    selector_set_interest(selector, target_descriptor, OP_READ);
}

bool close_connection(struct client_data* client) {
    fd_selector selector = client->selector;
    socket_descriptor client_descriptor = client->client;
    socket_descriptor origin_descriptor = client->origin;

    log_info("Closing connection to %s", client->client_str);
    add_disconnected_client_log(client);

    selector_status status;
    if ((status = selector_unregister_fd(selector, client_descriptor)) != SELECTOR_SUCCESS) {
        log_error("Could not close connection with client endpoint from %s: %s", client->client_str, selector_error(status));
        return true;
    }
    if ((status = selector_unregister_fd(selector, origin_descriptor)) != SELECTOR_SUCCESS) {
        log_error("Could not close connection with origin endpoint from %s: %s", client->client_str, selector_error(status));
        return true;
    }

    return false;
}

void client_handle_close(struct selector_key* key) {
    free_client_data((struct client_data*)key->data);
    close(key->fd);
    server_data.client_count--;
}





void* resolve_origin_address(void* client_data) {
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

    data->resolved_addresses = addr_list;

    data->state = CONNECTING;

    // informar al selector que terminó la resolución de address
    selector_notify_block(data->selector, data->client);

    return NULL;
}

void connect_client(struct selector_key* key) {
    struct client_data* data = key->data;
    struct addrinfo* addr_list = data->resolved_addresses;

    if (addr_list == NULL) {
        log_error("Client does not have a list of resolved addresses");
        return;
    }

    char origin_addr_buff[ADDR_STR_MAX_SIZE];
    log_info("Connecting client %s to address %s",
        data->client_str,
        print_address_info(addr_list, origin_addr_buff));
    write_server_log("Connecting client %s to address %s",
        data->client_str,
        print_address_info(addr_list, origin_addr_buff));

    socket_descriptor origin = NO_SOCKET;
    for (;addr_list != NULL; addr_list = addr_list->ai_next) {
        origin = try_connect(addr_list);
        if (origin != NO_SOCKET) break;
    }

    if (origin == NO_SOCKET) {
        log_error("Could not resolve origin address %s", origin_addr_buff);
        freeaddrinfo(data->resolved_addresses);

        return;
    }

    data->origin = origin;
    freeaddrinfo(data->resolved_addresses);
    data->resolved_addresses = NULL;

    data->state = COPY;

    fd_selector selector = key->s;
    socket_descriptor client_fd = key->fd;

    selector_set_interest(selector, client_fd, OP_READ);

    // Add origin
    data->references++;
    clients[server_data.client_count++] = data;
    selector_register(selector, origin, &client_handlers, OP_READ, data);

}

int free_addrinfo_on_error(struct addrinfo* addrinfo, char* message) {
    char addr_buffer[200];
    log_error("%s %s: %s", message, print_address_info(addrinfo, addr_buffer), strerror(errno));
    freeaddrinfo(addrinfo);
    return true;
}

//TODO: utils
bool connection_in_proggress(int connect_status) {
    return connect_status == EINPROGRESS || connect_status == EAGAIN;
}

socket_descriptor try_connect(struct addrinfo* origin) {
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
    if ((connect(new_client_socket, origin->ai_addr, origin->ai_addrlen) == NO_SOCKET) && !connection_in_proggress(errno)) {
        log_error("Error code: %d", errno);
        free_addrinfo_on_error(origin, "Could not connect to origin");
        return NO_SOCKET;
    }

    return new_client_socket;
}

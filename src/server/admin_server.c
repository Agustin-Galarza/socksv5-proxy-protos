/**
 * TODO: manejar cierre del servidor
 */
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>

#include "server/admin_server.h"
#include "server/socks5_server.h"
#include "utils/stm.h"
#include "logger/logger.h"
#include "utils/buffer.h"
#include "utils/parser/yap_parser.h"
#include "utils/parser/yap_negociation.h"
#include "utils/representation.h"

 /*********************************
 |          Definitions          |
 *********************************/

#define ADMIN_READ_BUFFER_SIZE 1024
#define ADMIN_WRITE_BUFFER_SIZE 1024

#define ADMIN_MAX_STR_REPRESENTATION_SIZE 128

#define MAX_PAYLOAD_SIZE 131072

#define NON_REGISTERED_ADMIN_STR "Unauthorized"

#define MAX_ADMINS 1

enum admin_server_state {
    ADMIN_SERVER_STATE_AUTHENTICATION_REQ = 0,
    ADMIN_SERVER_STATE_AUTHENTICATION_RES,
    ADMIN_SERVER_STATE_CMD_REQ,
    ADMIN_SERVER_STATE_CMD_RES,
    ADMIN_SERVER_STATE_DONE,
    ADMIN_SERVER_STATE_ERROR,
};

struct admin_data {
    socket_descriptor admin_fd;
    char* admin_str;

    struct yap_negociation_parser* negotiation_parser;
    struct yap_parser* cmd_parser;

    struct state_machine stm;

    fd_selector selector;

    struct buffer* read_buffer;
    struct buffer* write_buffer;
};

struct protocol_string {
    uint8_t len;
    uint8_t* value;
};

enum server_status {
    ADMIN_SERVER_STATUS_OK = 0,
    ADMIN_SERVER_STATUS_ERROR
};

/**************************************
|          Global Variables          |
**************************************/

static struct user_list_user
only_admin = {
    .username = "admin",
    .password = "admin"
};

static user_list_t* allowed_users = NULL;

static struct admin_data* admins[MAX_ADMINS] = { 0 };

static enum server_status server_status = ADMIN_SERVER_STATUS_OK;

struct admin_server_data
{
    size_t max_clients;
    size_t client_count;
} admin_server_data;

/*******************************************
|          Function declarations          |
*******************************************/

void admin_server_handle_read(struct selector_key* key);

// Event Handlers

void admin_handle_read(struct selector_key* key);

void admin_handle_write(struct selector_key* key);

void admin_handle_close(struct selector_key* key);

// CMD resolvers

/**
 * Zona de memoria donde se van a guardar los datos para enviar al admin
 * como respuesta de los comandos que solicite.
 * En general, las respuestas que envía el servidor son del tipo
 * +-----+-------+
 * | CMD | data  |
 * +-----+-------+
 *
 * donde la sección de data va a contener diferentes tipos de datos según
 * el comando que se haya solicitado (una lista de strings, un status, etc.).
 * De esta forma, payload contendrá la parte de 'data' de la respuesta, la cual
 * será completada por el handler conrrespondiente
 */
static struct payload {
    uint32_t size;
    uint8_t data[MAX_PAYLOAD_SIZE];
} payload;

static void get_all_users(void* _);
static void get_metric(void* metric);
static void add_user(void* user);
static void remove_user(void* user);
static struct config_change_request {
    fd_selector selector;
    uint8_t config_number;
    uint16_t new_value;
};
static void set_config(void* config);

// Tienen que estar en el orden del enum yap_commands (excluyendo el valor YAP_NO_COMMAND)
// Todas las funciones reciben argumentos que se arman con la función build_cmd_args, arman el resultado y lo guardan en la variable estática payload
// Los argumentos se liberan luego con free_cmd_args
static void (*cmd_handlers[])(void*) = {
get_all_users,
get_metric,
add_user,
remove_user,
set_config
};

// States

static void
authentication_req_init(const unsigned int state, struct selector_key* key);
static void
authentication_req_close(const unsigned int state, struct selector_key* key);
static unsigned read_authentication_request(struct selector_key* key);

static void
authentication_res_init(const unsigned int state, struct selector_key* key);
static void
authentication_res_close(const unsigned int state, struct selector_key* key);
static unsigned write_authentication_response(struct selector_key* key);

static void
cmd_req_init(const unsigned int state, struct selector_key* key);
static void
cmd_req_close(const unsigned int state, struct selector_key* key);
static unsigned read_cmd_request(struct selector_key* key);

static void
cmd_res_init(const unsigned int state, struct selector_key* key);
static void
cmd_res_close(const unsigned int state, struct selector_key* key);
static unsigned write_cmd_response(struct selector_key* key);

static void
close_connection(const unsigned int state, struct selector_key* key);

/*****************************
|          Estados          |
*****************************/

static const struct state_definition admin_states[] = {
    {
        .state = ADMIN_SERVER_STATE_AUTHENTICATION_REQ,
        .on_arrival = authentication_req_init,
        .on_departure = authentication_req_close,
        .on_read_ready = read_authentication_request,
    },{
        .state = ADMIN_SERVER_STATE_AUTHENTICATION_RES,
        .on_arrival = authentication_res_init,
        .on_departure = authentication_res_close,
        .on_write_ready = write_authentication_response,
    },{
        .state = ADMIN_SERVER_STATE_CMD_REQ,
        .on_arrival = cmd_req_init,
        .on_departure = cmd_req_close,
        .on_read_ready = read_cmd_request,
    },{
        .state = ADMIN_SERVER_STATE_CMD_RES,
        .on_arrival = cmd_res_init,
        .on_departure = cmd_res_close,
        .on_write_ready = write_cmd_response,
    },{
        .state = ADMIN_SERVER_STATE_DONE,
        .on_arrival = close_connection
    },{
        .state = ADMIN_SERVER_STATE_ERROR,
        .on_arrival = close_connection
    }
};

static const struct fd_handler
admin_handlers = {
    .handle_read = admin_handle_read,
    .handle_write = admin_handle_write,
    .handle_block = NULL,
    .handle_close = admin_handle_close,
};

static const struct fd_handler
admin_server_handlers = {
    .handle_read = admin_server_handle_read
};

/**********************************************
|          Function Implementations          |
**********************************************/

bool admin_server_init(user_list_t* initial_users) {
    allowed_users = initial_users;
    admin_server_data.max_clients = MAX_ADMINS;
    admin_server_data.client_count = 0;
    return false;
}

void admin_server_close() {
    server_status = ADMIN_SERVER_STATUS_ERROR;
    user_list_free(allowed_users);
    for (int i = 0; i < admin_server_data.max_clients; i++) {
        if (admins[i] != NULL) {
            selector_unregister_fd(admins[i]->selector, admins[i]->admin_fd);
            admins[i] = NULL;
        }
    }
}

const struct fd_handler* get_admin_server_handlers() {
    return &admin_server_handlers;
}

struct admin_data* admin_data_new(socket_descriptor socket, fd_selector selector) {
    struct admin_data* admin = malloc(sizeof(struct admin_data));

    admin->admin_fd = socket;
    admin->selector = selector;

    admin->negotiation_parser = yap_negociation_parser_init();

    admin->cmd_parser = yap_parser_init();

    admin->stm.initial = ADMIN_SERVER_STATE_AUTHENTICATION_REQ;
    admin->stm.max_state = ADMIN_SERVER_STATE_ERROR;
    admin->stm.current = admin_states;
    admin->stm.states = admin_states;
    stm_init(&admin->stm);

    admin->admin_str = malloc(ADMIN_MAX_STR_REPRESENTATION_SIZE);
    strcpy(admin->admin_str, NON_REGISTERED_ADMIN_STR);

    admin->write_buffer = malloc(sizeof(struct buffer));
    buffer_init(admin->write_buffer, ADMIN_WRITE_BUFFER_SIZE, malloc(ADMIN_WRITE_BUFFER_SIZE));
    admin->read_buffer = malloc(sizeof(struct buffer));
    buffer_init(admin->read_buffer, ADMIN_READ_BUFFER_SIZE, malloc(ADMIN_READ_BUFFER_SIZE));

    return admin;
}

void admin_data_free(struct admin_data* admin) {
    if (admin != NULL) {
        yap_negociation_parser_free(admin->negotiation_parser);
        yap_parser_free(admin->cmd_parser);

        if (admin->admin_str != NULL)
            free(admin->admin_str);

        if (admin->write_buffer != NULL) {
            if (admin->write_buffer->data != NULL)
                free(admin->write_buffer->data);
            free(admin->write_buffer);
        }

        if (admin->read_buffer != NULL) {
            if (admin->read_buffer->data != NULL)
                free(admin->read_buffer->data);
            free(admin->read_buffer);
        }

        for (size_t i = 0; i < admin_server_data.client_count; i++) {
            if (admins[i] == admin) {
                admins[i] = NULL;
                break;
            }
        }
        admin_server_data.client_count--;


        free(admin);
    }
}

static socket_descriptor
accept_new_connection(socket_descriptor server_socket) {
    struct sockaddr_storage admin_addr;
    socklen_t admin_addr_len = sizeof(admin_addr);

    socket_descriptor new_connection = accept(server_socket,
        (struct sockaddr*)&admin_addr,
        &admin_addr_len);
    if (new_connection < 0) {
        log_error("New connection refused: %s", strerror(errno));
        return -1;
    }
    char addr_buf[ADDR_STR_MAX_SIZE];
    // log_info("New connection to %s", print_address((struct sockaddr*)&admin_addr, addr_buf)); //TODO: new connection attempt

    return new_connection;
}


void admin_server_handle_read(struct selector_key* key) {
    struct admin_server_data* data = key->data;
    socket_descriptor server_socket = key->fd;
    fd_selector selector = key->s;

    if (data->client_count == data->max_clients) {
        // there's no more capacity for new connections
    }
    else {
        socket_descriptor new_admin = accept_new_connection(server_socket);

        if (new_admin > 0) {
            struct admin_data* admin_data = admin_data_new(new_admin, selector);
            admins[admin_server_data.client_count++] = admin_data;


            if (selector_register(selector, new_admin, &admin_handlers, OP_READ, admin_data) != SELECTOR_SUCCESS) {
                log_error("Could not register admin");
                return;
            }
        }
    }
}

void admin_handle_read(struct selector_key* key) {
    struct admin_data* admin = key->data;
    stm_handler_read(&admin->stm, key);
}

void admin_handle_write(struct selector_key* key) {
    struct admin_data* admin = key->data;
    stm_handler_write(&admin->stm, key);
}

void admin_handle_close(struct selector_key* key) {
    struct admin_data* admin = key->data;
    stm_handler_close(&admin->stm, key);
}

static void
authentication_req_init(const unsigned int state, struct selector_key* key) {

}

static void
authentication_req_close(const unsigned int state, struct selector_key* key) {
    if (server_status == ADMIN_SERVER_STATUS_ERROR) {
        close_connection(ADMIN_SERVER_STATE_ERROR, key);
    }
}

static unsigned read_authentication_request(struct selector_key* key) {
    errno = 0;
    struct admin_data* admin = key->data;

    // El buffer no debería estar inhabilitado en este estado
    if (!buffer_can_write(admin->write_buffer))
        buffer_reset(admin->write_buffer);

    size_t max_write;
    uint8_t* buff_raw = buffer_write_ptr(admin->write_buffer, &max_write);

    int read_status = read(admin->admin_fd, buff_raw, max_write);
    switch (read_status) {
    case -1:
        log_error("Could read authentication from admin: %s", strerror(errno));
        break;
    case 0:
        // No va a haber data extra para mandarle al cliente en esta etapa, por lo que se cierra el socket directamnente
        return ADMIN_SERVER_STATE_DONE;
    default:
        buffer_write_adv(admin->write_buffer, read_status);
        enum yap_negociation_result result = yap_negociation_parser_consume(admin->write_buffer, admin->negotiation_parser);
        switch (result) {
        case YAP_NEGOCIATION_ERROR:
            log_error("Could not parse authentication request");
            return ADMIN_SERVER_STATE_AUTHENTICATION_RES;
        case YAP_NEGOCIATION_SUCCESS:
            return ADMIN_SERVER_STATE_AUTHENTICATION_RES;
        default:
            break;
        }
        break;
    }
    return ADMIN_SERVER_STATE_AUTHENTICATION_REQ;
}

static bool authenticate_user(struct protocol_string* username, struct protocol_string* password) {
    return strncmp(only_admin.username, (char*)username->value, username->len) == 0 &&
        strncmp(only_admin.password, (char*)password->value, password->len) == 0;
}

static void
authentication_res_init(const unsigned int state, struct selector_key* key) {
    struct admin_data* admin = key->data;

    // buffer_reset(admin->read_buffer);
    buffer_write(admin->read_buffer, ADMIN_SERVER_VERSION);
    if (admin->negotiation_parser->status == AUTH_SUCCESS) {
        // El parseo fue correcto, ahora hay que autenticar
        struct protocol_string username = {
            .value = admin->negotiation_parser->username,
            .len = admin->negotiation_parser->username_len
        };
        struct protocol_string password = {
            .value = admin->negotiation_parser->password,
            .len = admin->negotiation_parser->password_len
        };
        admin->negotiation_parser->status = authenticate_user(&username, &password) ? AUTH_SUCCESS : AUTH_FAIL;
    }
    buffer_write(admin->read_buffer, admin->negotiation_parser->status);
    selector_set_interest(admin->selector, admin->admin_fd, OP_WRITE);
}
static void
authentication_res_close(const unsigned int state, struct selector_key* key) {
    struct admin_data* admin = key->data;

    strncpy(admin->admin_str, (char*)admin->negotiation_parser->username, admin->negotiation_parser->username_len);
    admin->admin_str[admin->negotiation_parser->username_len] = '\0';

    yap_negociation_parser_free(admin->negotiation_parser);
    admin->negotiation_parser = NULL;

    log_info("Admin Authorized: %s", admin->admin_str);

    selector_set_interest(admin->selector, admin->admin_fd, OP_READ);

    if (server_status == ADMIN_SERVER_STATUS_ERROR) {
        close_connection(ADMIN_SERVER_STATE_ERROR, key);
    }
}
static unsigned write_authentication_response(struct selector_key* key) {
    errno = 0;
    struct admin_data* admin = key->data;

    size_t bytes_to_send;
    uint8_t* res_buf = buffer_read_ptr(admin->read_buffer, &bytes_to_send);

    int send_status = send(key->fd, res_buf, bytes_to_send, SEND_FLAGS);

    if (send_status < 0) {
        log_error("Could not send authentication response to %s [Reason:%s]", admin->admin_str, strerror(errno));
        return ADMIN_SERVER_STATE_ERROR;
    }
    size_t bytes_sent = (size_t)send_status;
    buffer_read_adv(admin->read_buffer, bytes_sent);

    if (bytes_sent == bytes_to_send) {
        if (admin->negotiation_parser->status != AUTH_SUCCESS) {
            return ADMIN_SERVER_STATE_DONE;
        }
        else {
            return ADMIN_SERVER_STATE_CMD_REQ;
        }
    }
    return ADMIN_SERVER_STATE_AUTHENTICATION_RES;
}

static void
cmd_req_init(const unsigned int state, struct selector_key* key) {

}
static void
cmd_req_close(const unsigned int state, struct selector_key* key) {
    if (server_status == ADMIN_SERVER_STATUS_ERROR) {
        close_connection(ADMIN_SERVER_STATE_ERROR, key);
    }
}
static unsigned read_cmd_request(struct selector_key* key) {
    errno = 0;
    struct admin_data* admin = key->data;

    // El buffer no debería estar inhabilitado en este estado
    if (!buffer_can_write(admin->write_buffer))
        buffer_reset(admin->write_buffer);

    size_t max_write;
    uint8_t* buff_raw = buffer_write_ptr(admin->write_buffer, &max_write);

    int read_status = read(admin->admin_fd, buff_raw, max_write);
    switch (read_status) {
    case -1:
        log_error("Could read authentication from admin: %s", strerror(errno));
        break;
    case 0:
        // No va a haber data extra para mandarle al cliente en esta etapa, por lo que se cierra el socket directamnente
        if (!buffer_can_read(admin->write_buffer))
            return ADMIN_SERVER_STATE_DONE;
    default:
        buffer_write_adv(admin->write_buffer, read_status);
        enum yap_result result = yap_parser_consume(admin->write_buffer, admin->cmd_parser);
        switch (result) {
        case YAP_PARSER_ERROR:
            log_error("Could not parse command");
        case YAP_PARSER_FINISH:
            buffer_reset(admin->write_buffer);
            return ADMIN_SERVER_STATE_CMD_RES;
        default:
            break;
        }
        break;
    }
    return ADMIN_SERVER_STATE_CMD_REQ;
}

static void* build_cmd_args(fd_selector selector, struct yap_parser* parser) {
    switch (parser->command) {
    case YAP_COMMANDS_USERS:
        return NULL;

    case YAP_COMMANDS_METRICS:;
        uint8_t* metric_ptr = malloc(1);
        *metric_ptr = parser->metric;
        return metric_ptr;

    case YAP_COMMANDS_ADD_USER:
    case YAP_COMMANDS_REMOVE_USER:;
        struct user_list_user* user_ptr = malloc(sizeof(struct user_list_user));

        user_ptr->username = malloc(parser->username_length + 1);
        strncpy(user_ptr->username, parser->username, parser->username_length);
        user_ptr->username[parser->username_length] = '\0';

        user_ptr->password = malloc(parser->password_length + 1);
        strncpy(user_ptr->password, parser->password, parser->password_length);
        user_ptr->password[parser->password_length] = '\0';

        return user_ptr;

    case YAP_COMMANDS_CONFIG:;
        struct config_change_request* req = malloc(sizeof(struct config_change_request));
        req->selector = selector;
        req->config_number = parser->config;
        req->new_value = parser->config_value;
        return req;

    default:
        break;
    }
    return NULL;
}

static void free_cmd_args(enum yap_commands command, void* args) {
    if (args == NULL) return;
    switch (command) {
    case YAP_COMMANDS_METRICS:
    case YAP_COMMANDS_CONFIG:
        free(args);
        return;
    case YAP_COMMANDS_ADD_USER:
    case YAP_COMMANDS_REMOVE_USER:;
        struct user_list_user* user_ptr = args;
        if (user_ptr->username != NULL)
            free(user_ptr->username);
        if (user_ptr->password != NULL)
            free(user_ptr->password);
        free(user_ptr);
        return;
    case YAP_COMMANDS_USERS:
    default:
        break;
    }
}

static void
cmd_res_init(const unsigned int state, struct selector_key* key) {
    struct admin_data* admin = key->data;

    if (admin->cmd_parser->result == YAP_PARSER_ERROR) {
        buffer_write(admin->read_buffer, 0xFF);
        buffer_write(admin->read_buffer, 0xFF);
        goto cmd_res_init_end;
    }

    // Resolver el comando solicitado
    void* args = build_cmd_args(admin->selector, admin->cmd_parser);
    cmd_handlers[admin->cmd_parser->command - 1](args);
    free_cmd_args(admin->cmd_parser->command, args);
    // Armar el buffer de respuesta
    buffer_reset(admin->read_buffer);
    buffer_write(admin->read_buffer, admin->cmd_parser->command);
    size_t max_write;
    uint8_t* buff_raw = buffer_write_ptr(admin->read_buffer, &max_write);

    memcpy(buff_raw, payload.data, payload.size);
    buffer_write_adv(admin->read_buffer, payload.size);

    payload.size = 0;

cmd_res_init_end:
    selector_set_interest(admin->selector, admin->admin_fd, OP_WRITE);
}
static void
cmd_res_close(const unsigned int state, struct selector_key* key) {
    struct admin_data* admin = key->data;

    yap_parser_reset(admin->cmd_parser);

    selector_set_interest(admin->selector, admin->admin_fd, OP_READ);

    if (server_status == ADMIN_SERVER_STATUS_ERROR) {
        close_connection(ADMIN_SERVER_STATE_ERROR, key);
    }
}
static unsigned write_cmd_response(struct selector_key* key) {
    errno = 0;
    struct admin_data* admin = key->data;

    size_t bytes_to_send;
    uint8_t* res_buf = buffer_read_ptr(admin->read_buffer, &bytes_to_send);

    int send_status = send(key->fd, res_buf, bytes_to_send, SEND_FLAGS);

    if (send_status < 0) {
        log_error("Could not send cmd response to %s [Reason:%s]", admin->admin_str, strerror(errno));
        return ADMIN_SERVER_STATE_ERROR;
    }
    size_t bytes_sent = (size_t)send_status;
    buffer_read_adv(admin->read_buffer, bytes_sent);

    if (bytes_sent == bytes_to_send)
        return ADMIN_SERVER_STATE_CMD_REQ;

    return ADMIN_SERVER_STATE_CMD_RES;
}

static void
close_connection(const unsigned int state, struct selector_key* key) {
    struct admin_data* admin = key->data;
    if (state == ADMIN_SERVER_STATE_ERROR) {
        log_error("There was an error on execution for %s", admin->admin_str);
    }
    log_info("Closing connection of %s", admin->admin_str);
    if (server_status != ADMIN_SERVER_STATUS_ERROR) {
        if (selector_unregister_fd(admin->selector, admin->admin_fd) != SELECTOR_SUCCESS) {
            log_error("Could not unregister admin %s", admin->admin_str);
        }
    }
    close(admin->admin_fd);
    admin_data_free(admin);
}

static void get_all_users(void* _) {
    // Tamaño en bytes de la variable que contiene el tamaño de la lista de usuarios
    const uint8_t list_len_bytes = sizeof(uint32_t);

    struct buffer users_buff;
    buffer_init(&users_buff, MAX_PAYLOAD_SIZE, payload.data);
    size_t users_amount = user_list_size(allowed_users);
    // Reservo el espacio para escribir el tamaño final de la lista
    buffer_write_adv(&users_buff, list_len_bytes);

    for (int i = 0; i < users_amount; i++) {
        struct user_list_user usr = user_list_get(allowed_users, i);

        size_t aux;

        size_t username_len = strlen(usr.username);
        buffer_write(&users_buff, username_len);
        strncpy((char*)buffer_write_ptr(&users_buff, &aux), usr.username, username_len);
        buffer_write_adv(&users_buff, username_len);

        size_t password_len = strlen(usr.password);
        buffer_write(&users_buff, password_len);
        strncpy((char*)buffer_write_ptr(&users_buff, &aux), usr.password, password_len);
        buffer_write_adv(&users_buff, password_len);

    }
    size_t list_size;
    buffer_read_ptr(&users_buff, &list_size);
    payload.size = list_size;
    list_size -= list_len_bytes;
    uint32_t nlist_size = htonl(list_size);
    memcpy(payload.data, &nlist_size, list_len_bytes);
}

static void get_metric(void* metric) {
    uint8_t metric_num = *((uint8_t*)metric);
    uint16_t value;
    switch (metric_num) {
    case YAP_METRIC_HISTORICAL_CONNECTIONS:
        value = socks5_get_historic_connections();
        break;
    case YAP_METRIC_CONCURRENT_CONNECTIONS:
        value = socks5_get_concurrent_connections();
        break;
    case YAP_METRIC_BYTES_SEND:
        value = socks5_get_bytes_sent();
        break;
    }
    uint16_t nvalue = htons(value);
    *payload.data = metric_num;
    memcpy(payload.data + 1, &nvalue, sizeof(uint16_t));
    payload.size = 1 + sizeof(uint16_t);
}

#define OK_STATUS 0x00
#define MAX_USERS_REACHED_STATAUS 0x01
#define USER_ALREADY_EXISTS_STATUS 0X02
static void add_user(void* user) {
    struct user_list_user* user_ptr = user;
    payload.size = sizeof(uint8_t);
    uint8_t* status_ptr = payload.data;
    if (user_list_contains(allowed_users, user_ptr->username, user_ptr->password)) {
        *status_ptr = USER_ALREADY_EXISTS_STATUS;
    }
    else {
        *status_ptr = user_list_add(allowed_users, user_ptr->username, user_ptr->password) ? OK_STATUS : MAX_USERS_REACHED_STATAUS;
    }
}

#define USER_NOT_FOUND_STATUS 0x01
static void remove_user(void* user) {
    struct user_list_user* user_ptr = user;
    payload.size = sizeof(uint8_t);
    uint8_t* status_ptr = payload.data;
    *status_ptr = user_list_remove(allowed_users, user_ptr->username, user_ptr->password) ? OK_STATUS : USER_NOT_FOUND_STATUS;
}

#define COULD_NOT_UPDATE 0x01
static void set_config(void* config) {
    struct config_change_request* conf_req = config;
    payload.size = 0;

    struct timespec tv;
    uint8_t* write_ptr = payload.data;
    *write_ptr = conf_req->config_number;
    write_ptr++;
    payload.size++;
    switch (conf_req->config_number) {
    case YAP_CONFIG_TIMEOUTS:
        tv.tv_nsec = 0;
        tv.tv_sec = conf_req->new_value;

        selector_set_timeout(conf_req->selector, tv);
        log_info("Timeout changed to %ds", conf_req->new_value);
        *write_ptr = OK_STATUS;
        payload.size++;
        break;
    case YAP_CONFIG_BUFFER_SIZE:
        *write_ptr = socks5_update_client_buffer_size(conf_req->new_value) ? OK_STATUS : COULD_NOT_UPDATE;
        payload.size++;
        break;
    }
}

user_list_t* admin_server_get_allowed_users() {
    return allowed_users;
}

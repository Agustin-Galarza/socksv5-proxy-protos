#ifndef REQUEST_H
#define REQUEST_H

#include <stdint.h>
#include "utils/buffer.h"

#define VERSION 0x05

#define MAX_ADDRESS_LENGTH 256
#define MAX_PORT_LENGTH 2
#define MAX_IPV4_LENGTH 4
#define MAX_IPV6_LENGTH 16

// Estados finales de la request
enum request_results {
    PARSER_FINISH_ERROR = 0,
    PARSER_FINISH_OK,
    PARSER_NOT_FINISH
};

// Estados de la request
enum request_state {
    REQUEST_VERSION = 0,
    REQUEST_CMD,
    REQUEST_RSV,
    REQUEST_ADDRESS_TYPE,
    REQUEST_DESTINATION_ADDRESS,
    REQUEST_DESTINATION_PORT,
    REQUEST_DONE,
    REQUEST_ERROR
};

enum request_cmd {
    REQUEST_CMD_CONNECT = 0x01,
    REQUEST_CMD_BIND = 0x02,
    REQUEST_CMD_UDP_ASSOCIATE = 0x03
};

enum request_address_type {
    REQUEST_ADDRESS_TYPE_IPV4 = 0x01,
    REQUEST_ADDRESS_TYPE_DOMAINNAME = 0x03,
    REQUEST_ADDRESS_TYPE_IPV6 = 0x04
};

// Estructura del Parser de la request. Guardamos el estado y todos los campos que vamos leyendo

struct request_parser {
    enum request_state state;
    uint8_t version;
    enum request_cmd cmd;
    uint8_t rsv;
    enum request_address_type address_type;
    uint8_t address[MAX_ADDRESS_LENGTH];
    uint16_t address_length;
    uint8_t port[MAX_PORT_LENGTH];
    uint8_t port_length;
};



// Inicializa el parser
struct request_parser* request_parser_init();

//Free parser
void request_parser_free(struct request_parser* parser);

// Parsea un byte
enum request_state request_parser_feed(struct request_parser* parser, uint8_t byte);

// Checkea si llego al estado final
enum request_results request_parser_is_finished(struct request_parser* parser);

// Ckeckea si hay error
int request_parser_has_error(struct request_parser* parser);

// Consumo buffer. Retorna 0 si hubo error, 1 si termino la request y 2 si no termino
enum request_results request_parser_consume(buffer* buff, struct request_parser* parser);

// Reset parser
void request_parser_reset(struct request_parser* parser);


#endif
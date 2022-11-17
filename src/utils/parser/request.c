#include "parser/request.h"
#include <string.h>
#include "logger/logger.h"


struct request_parser* request_parser_init() {
    struct request_parser* parser = malloc(sizeof(struct request_parser));
    request_parser_reset(parser);
    return parser;
}

void request_parser_free(struct request_parser* parser) {
    free(parser);
}

int request_parser_has_error(struct request_parser* parser) {
    return parser->state == REQUEST_ERROR;
}

enum request_state request_parser_feed(struct request_parser* parser, uint8_t byte) {
    switch (parser->state) {
    case REQUEST_VERSION:
        if (byte == VERSION) {
            parser->version = byte;
            parser->state = REQUEST_CMD;
            log_debug("Version correcta");
        }
        else {
            parser->state = REQUEST_ERROR;
            log_debug("Version incorrecta: %d", byte);
        }
        break;
    case REQUEST_CMD:
        if (byte == REQUEST_CMD_CONNECT || byte == REQUEST_CMD_BIND || byte == REQUEST_CMD_UDP_ASSOCIATE) {
            parser->cmd = byte;
            parser->state = REQUEST_RSV;
            log_debug("Comando correcto");
        }
        else {
            parser->state = REQUEST_ERROR;
            log_debug("Comando incorrecto");
        }
        break;
    case REQUEST_RSV:
        if (byte == 0x00) {
            parser->rsv = byte;
            parser->state = REQUEST_ADDRESS_TYPE;
            log_debug("RSV correcto");
        }
        else {
            parser->state = REQUEST_ERROR;
            log_debug("RSV incorrecto");
        }
        break;
    case REQUEST_ADDRESS_TYPE:
        if (byte == REQUEST_ADDRESS_TYPE_IPV4 || byte == REQUEST_ADDRESS_TYPE_DOMAINNAME || byte == REQUEST_ADDRESS_TYPE_IPV6) {
            parser->address_type = byte;
            parser->state = REQUEST_DESTINATION_ADDRESS;
            log_debug("Address type correcto");
        }
        else {
            parser->state = REQUEST_ERROR;
            log_debug("Address type incorrecto");
        }
        break;
    case REQUEST_DESTINATION_ADDRESS:
        if (parser->address_type == REQUEST_ADDRESS_TYPE_IPV4) {
            if (parser->address_length < MAX_IPV4_LENGTH) {
                parser->address[parser->address_length] = byte;
                parser->address_length++;
                log_debug("Direccion IPv4: %d", byte);
            }
            if (parser->address_length == MAX_IPV4_LENGTH) {
                parser->state = REQUEST_DESTINATION_PORT;
                log_debug("Direccion IPv4 completa");
            }
        }
        else if (parser->address_type == REQUEST_ADDRESS_TYPE_DOMAINNAME) {
            if (parser->address_length == 0) {
                parser->address_length = byte;
                break;
            }
            else if (parser->_address_current_index < parser->address_length) {
                parser->address[parser->_address_current_index++] = byte;
                log_debug("Direccion Domain: %d", byte);
            }
            if (parser->_address_current_index == parser->address_length) {
                parser->state = REQUEST_DESTINATION_PORT;
                log_debug("Direccion Domain completa: %s", parser->address);
            }
        }
        else if (parser->address_type == REQUEST_ADDRESS_TYPE_IPV6) {
            if (parser->address_length < MAX_IPV6_LENGTH) {
                parser->address[parser->address_length] = byte;
                parser->address_length++;
                log_debug("Direccion IPv6: %d", byte);
            }
            if (parser->address_length == MAX_IPV6_LENGTH) {
                parser->state = REQUEST_DESTINATION_PORT;
                log_debug("Direccion IPv6 completa");
            }
        }
        break;
    case REQUEST_DESTINATION_PORT:
        if (parser->port_length < MAX_PORT_LENGTH) {
            parser->port[parser->port_length] = byte;
            parser->port_length++;
            log_debug("Puerto: %d", byte);
        }
        if (parser->port_length == MAX_PORT_LENGTH) {
            parser->state = REQUEST_DONE;
            log_debug("Puerto completo");
        }
        break;
    case REQUEST_ERROR:
    case REQUEST_DONE:
        break;
    }
    return parser->state;
}

enum request_results request_parser_is_finished(struct request_parser* parser) {
    return parser->state == REQUEST_DONE ? REQUEST_PARSER_FINISH_OK : REQUEST_PARSER_NOT_FINISH;
}

enum request_results request_parser_consume(buffer* buff, struct request_parser* parser) {
    while (buffer_can_read(buff)) {
        uint8_t byte = buffer_read(buff);
        request_parser_feed(parser, byte);
        if (request_parser_has_error(parser)) {
            return REQUEST_PARSER_FINISH_ERROR;
        }
        if (request_parser_is_finished(parser) == REQUEST_PARSER_FINISH_OK) {
            break;
        }
    }
    return request_parser_is_finished(parser);
}


void request_parser_reset(struct request_parser* parser) {
    parser->state = REQUEST_VERSION;
    parser->version = 0;
    parser->cmd = 0;
    parser->rsv = 0;
    parser->address_type = 0;
    parser->address_length = 0;
    parser->_address_current_index = 0;
    memset(parser->address, 0, MAX_ADDRESS_LENGTH);
    parser->port_length = 0;
    memset(parser->port, 0, MAX_PORT_LENGTH);
}

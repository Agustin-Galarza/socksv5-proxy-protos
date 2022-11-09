#include "parser/negociation.h"
#include "logger/logger.h"
#include <string.h>

struct negociation_parser* negociation_parser_init() {
    struct negociation_parser* parser = malloc(sizeof(struct negociation_parser));


    parser->state = NEGOCIATION_VERSION;
    parser->version = 0;
    parser->nmethods = 0;

    memset(parser->methods, NO_ACCEPTABLE_METHODS, ALLOWED_METHODS_AMOUNT);

    return parser;
}

void negociation_parser_free(struct negociation_parser* parser) {
    free(parser);
}

enum negociation_state negociation_paser_feed(struct negociation_parser* parser, uint8_t byte) {
    switch (parser->state) {
    case NEGOCIATION_VERSION:
        if (byte == VERSION) {
            parser->version = byte;
            parser->state = NEGOCIATION_NMETHODS;

            log_debug("Version correcta");
        }
        else {
            parser->state = NEGOCIATION_ERROR;
            log_debug("Version incorrecta: %d", byte);
        }
        break;
    case NEGOCIATION_NMETHODS:
        parser->nmethods = byte;
        parser->state = NEGOCIATION_METHODS;
        log_debug("Cantidad de metodos correcta");
        break;
    case NEGOCIATION_METHODS:
        while (parser->nmethods > 0) {
            if (byte == NO_AUTENTICATION || byte == USERNAME_PASSWORD) {
                parser->methods[parser->nmethods - 1] = byte;
                parser->nmethods--;
                log_debug("Metodo correcto");
            }
            else {
                parser->state = NEGOCIATION_ERROR;
                log_debug("Metodo incorrecto");
            }
        }

        parser->state = NEGOCIATION_DONE;
        log_debug("Metodo correcto");

        break;
    case NEGOCIATION_DONE:
        log_debug("Negociacion finalizada");
        break;
    case NEGOCIATION_ERROR:
        log_debug("Error en la negociacion");
        break;
    }
    return parser->state;
}

int negociation_parser_is_finished(struct negociation_parser* parser) {
    return parser->state == NEGOCIATION_DONE ? PARSER_FINISH_OK : PARSER_NOT_FINISH;
}

int negociation_parser_has_error(struct negociation_parser* parser) {
    return parser->state == NEGOCIATION_ERROR;
}

int negociation_parser_consume(buffer* buff, struct negociation_parser* parser) {
    while (buffer_can_read(buff)) {
        uint8_t byte = buffer_read(buff);
        negociation_paser_feed(parser, byte);
        if (negociation_parser_has_error(parser)) {
            return PARSER_FINISH_ERROR;
        }
        if (negociation_parser_is_finished(parser)) {
            break;
        }
    }
    return negociation_parser_is_finished(parser);
}

void negociation_parser_reset(struct negociation_parser* parser) {
    negociation_parser_init(parser);
}

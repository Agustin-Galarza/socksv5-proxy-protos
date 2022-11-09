#include "parser/negociation.h"
#include "logger/logger.h"

void negociation_parser_init(struct negociation_parser* parser) {
    parser->state = NEGOCIATION_VERSION;
    parser->version = 0;
    parser->nmethods = 0;
    for (int i = 0; i < ALLOWED_METHODS_AMOUNT; i++) {
        parser->methods[i] = 0;
    }
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
            log_debug("Version incorrecta");
        }
        break;
    case NEGOCIATION_NMETHODS:
        if (byte > 0 && byte <= ALLOWED_METHODS_AMOUNT) {
            parser->nmethods = byte;
            parser->state = NEGOCIATION_METHODS;
            log_debug("Cantidad de metodos correcta");
        }
        else {
            parser->state = NEGOCIATION_ERROR;
            log_debug("Cantidad de metodos incorrecta");
        }
        break;
    case NEGOCIATION_METHODS:
        for (int i = 0; i < parser->nmethods; i++) {
            if (parser->methods[i] == 0) {
                parser->methods[i] = byte;
                break;
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
    return parser->state == NEGOCIATION_DONE;
}

int negociation_parser_has_error(struct negociation_parser* parser) {
    return parser->state == NEGOCIATION_ERROR;
}

bool negociation_parser_consume(buffer* buff, struct negociation_parser* parser) {
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
    return negociation_parser_is_finished(parser) ? PARSER_FINISH_OK : PARSER_NOT_FINISH;
}
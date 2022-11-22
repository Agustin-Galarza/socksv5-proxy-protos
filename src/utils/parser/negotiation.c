#include "utils/parser/negotiation.h"
#include "utils/logger/logger.h"
#include <string.h>

struct negotiation_parser* negotiation_parser_init() {
    struct negotiation_parser* parser = malloc(sizeof(struct negotiation_parser));


    parser->state = NEGOTIATION_VERSION;
    parser->version = 0;
    parser->nmethods = 0;
    parser->valid_methods_count = 0;

    memset(parser->methods, NO_ACCEPTABLE_METHODS, ALLOWED_METHODS_AMOUNT);

    return parser;
}

void negotiation_parser_free(struct negotiation_parser* parser) {
    if (parser != NULL)
        free(parser);
}

enum negotiation_state negotiation_paser_feed(struct negotiation_parser* parser, uint8_t byte) {
    switch (parser->state) {
    case NEGOTIATION_VERSION:
        if (byte == VERSION) {
            parser->version = byte;
            parser->state = NEGOTIATION_NMETHODS;

            log_debug("Version correcta");
        }
        else {
            parser->state = NEGOTIATION_ERROR;
            log_debug("Version incorrecta: %d", byte);
        }
        break;
    case NEGOTIATION_NMETHODS:
        parser->nmethods = byte;
        parser->state = NEGOTIATION_METHODS;
        log_debug("Cantidad de metodos correcta");
        break;
    case NEGOTIATION_METHODS:
        if ((byte == NO_AUTENTICATION || byte == USERNAME_PASSWORD) && parser->valid_methods_count < 2) {
            parser->methods[parser->valid_methods_count++] = byte;
            log_debug("Metodo correcto: %d", byte);
        }
        parser->nmethods--;
        if (parser->nmethods == 0) {
            if (parser->methods[0] == NO_ACCEPTABLE_METHODS) {
                parser->state = NEGOTIATION_ERROR;
                log_debug("No se proveyeron métodos válidos");
                break;
            }
            parser->state = NEGOTIATION_DONE;
        }
        break;
    case NEGOTIATION_DONE:
        log_debug("Negociacion finalizada");
        break;
    case NEGOTIATION_ERROR:
        log_debug("Error en la negociacion");
        break;
    }
    return parser->state;
}

enum negotiation_results negotiation_parser_is_finished(struct negotiation_parser* parser) {
    return parser->state == NEGOTIATION_DONE ? NEGOTIATION_PARSER_FINISH_OK : NEGOTIATION_PARSER_NOT_FINISH;
}

int negotiation_parser_has_error(struct negotiation_parser* parser) {
    return parser->state == NEGOTIATION_ERROR;
}

enum negotiation_results negotiation_parser_consume(buffer* buff, struct negotiation_parser* parser) {
    while (buffer_can_read(buff)) {
        log_debug("Estado: %d", parser->state);
        uint8_t byte = buffer_read(buff);
        negotiation_paser_feed(parser, byte);
        if (negotiation_parser_has_error(parser)) {
            return NEGOTIATION_PARSER_FINISH_ERROR;
        }
        if (negotiation_parser_is_finished(parser) == NEGOTIATION_PARSER_FINISH_OK) {
            break;
        }
    }
    return negotiation_parser_is_finished(parser);
}

void negotiation_parser_reset(struct negotiation_parser* parser) {
    *parser = *negotiation_parser_init();
}

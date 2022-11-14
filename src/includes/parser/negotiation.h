#ifndef NEGOCIATION_H
#define NEGOCIATION_H

#include <stdint.h>

#include "utils/buffer.h"

#define ALLOWED_METHODS_AMOUNT 2
#define NO_AUTENTICATION 0x00
#define USERNAME_PASSWORD 0x02
#define NO_ACCEPTABLE_METHODS 0xFF
#define VERSION 0x05


// Estados finales de la negociacion
enum negotiation_results {
    NEGOTIATION_PARSER_FINISH_ERROR = 0,
    NEGOTIATION_PARSER_FINISH_OK,
    NEGOTIATION_PARSER_NOT_FINISH
};


// Estados de la negociación
enum negotiation_state {
    NEGOTIATION_VERSION = 0,
    NEGOTIATION_NMETHODS,
    NEGOTIATION_METHODS,
    NEGOTIATION_DONE,
    NEGOTIATION_ERROR
};

// Estructura del Parser de la negociación. Guardamos el estado y todos los campos que vamos leyendo
struct negotiation_parser {
    enum negotiation_state state;

    uint8_t version;
    uint8_t nmethods;
    uint8_t methods[ALLOWED_METHODS_AMOUNT];
};

// Inicializa el parser
struct negotiation_parser* negotiation_parser_init();

//Free parser
void negotiation_parser_free(struct negotiation_parser* parser);

// Parsea un byte
enum negotiation_state negotiation_parser_feed(struct negotiation_parser* parser, uint8_t byte);

// Checkea si llego al estado final
enum negotiation_results negotiation_parser_is_finished(struct negotiation_parser* parser);

// Ckeckea si hay error
int negotiation_parser_has_error(struct negotiation_parser* parser);

// Consumo buffer. Retorna 0 si hubo error, 1 si termino la negociación y 2 si no termino
enum negotiation_results negotiation_parser_consume(buffer* buff, struct negotiation_parser* parser);

// Reset parser
void negotiation_parser_reset(struct negotiation_parser* parser);

#endif

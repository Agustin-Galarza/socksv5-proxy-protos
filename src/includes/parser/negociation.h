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
enum negociation_results {
    NEGOCIATION_PARSER_FINISH_ERROR = 0,
    NEGOCIATION_PARSER_FINISH_OK,
    NEGOCIATION_PARSER_NOT_FINISH
};


// Estados de la negociación
enum negociation_state {
    NEGOCIATION_VERSION = 0,
    NEGOCIATION_NMETHODS,
    NEGOCIATION_METHODS,
    NEGOCIATION_DONE,
    NEGOCIATION_ERROR
};

// Estructura del Parser de la negociación. Guardamos el estado y todos los campos que vamos leyendo
struct negociation_parser {
    enum negociation_state state;

    uint8_t version;
    uint8_t nmethods;
    uint8_t methods[ALLOWED_METHODS_AMOUNT];
};

// Inicializa el parser
struct negociation_parser* negociation_parser_init();

//Free parser
void negociation_parser_free(struct negociation_parser* parser);

// Parsea un byte
enum negociation_state negociation_parser_feed(struct negociation_parser* parser, uint8_t byte);

// Checkea si llego al estado final
enum negociation_results negociation_parser_is_finished(struct negociation_parser* parser);

// Ckeckea si hay error
int negociation_parser_has_error(struct negociation_parser* parser);

// Consumo buffer. Retorna 0 si hubo error, 1 si termino la negociación y 2 si no termino
enum negociation_results negociation_parser_consume(buffer* buff, struct negociation_parser* parser);

// Reset parser
void negociation_parser_reset(struct negociation_parser* parser);

#endif

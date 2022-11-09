#ifndef NEGOCIATION_H
#define NEGOCIATION_H

#include <stdint.h>

#define ALLOWED_METHODS_AMOUNT 2
#define NO_AUTENTICATION 0x00
#define USERNAME_PASSWORD 0x02
#define VERSION 0x05


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
void negociation_parser_init(struct negociation_parser* parser);

// Parsea un byte
enum negociation_state negociation_parser_feed(struct negociation_parser* parser, uint8_t byte);

// Checkea si llego al estado final
int negociation_parser_is_finished(struct negociation_parser* parser);


#endif

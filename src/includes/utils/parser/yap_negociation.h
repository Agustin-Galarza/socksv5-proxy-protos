#ifndef YAP_NEGOCIATION_H
#define YAP_NEGOCIATION_H

#include "utils/buffer.h"
#include <stdint.h>


/*
    Parser de negociacion de nuestro protocolo YAP
    (Yet Another Protocol)

    Request de autenticacion:
    +----+-------+-------+
    |VER | UNAME | PASS  |
    +----+-------+-------+

    Donde VER es el numero de version del protocolo y debe ser: 0x01
    UNAME es el nombre de usuario MAX 255 bytes
    PASS es la contraseña MAX 255 bytes

    Response de autenticacion:
    +----+-------+
    |VER | STATUS|
    +----+-------+

    Donde VER es el numero de version del protocolo y debe ser: 0x01
    STATUS es el estado de la autenticacion y puede ser:
        0x00: Autenticacion exitosa
        0x01: Autenticacion fallida



*/

#define YAP_VERSION 0x01
#define MAX_STR_LEN 255
#define MAX_USERNAME MAX_STR_LEN
#define MAX_PASSWORD MAX_STR_LEN
#define LIMITER 0x00

enum yap_negociation_status {
    AUTH_SUCCESS = 0x00,
    AUTH_FAIL = 0x01
};

enum yap_negociation_result {
    YAP_NEGOCIATION_SUCCESS = 0,
    YAP_NEGOCIATION_ERROR = 1,
    YAP_NEGOCIATION_INCOMPLETE = 2
};


enum yap_negociation_state {
    YAP_NEGOCIATION_PARSER_VERSION,
    YAP_NEGOCIATION_PARSER_USERNAME,
    YAP_NEGOCIATION_PARSER_PASSWORD,
    YAP_NEGOCIATION_PARSER_DONE,
    YAP_NEGOCIATION_PARSER_ERROR
};

struct yap_negociation_parser {
    enum yap_negociation_state state;
    uint8_t username[MAX_USERNAME];
    uint8_t password[MAX_PASSWORD];
    int username_len;
    int username_current;
    int password_len;
    enum yap_negociation_status status;
    int password_current;
};

// Inicializa el parser
struct yap_negociation_parser* yap_negociation_parser_init();

// Parsea un byte
enum yap_negociation_result request_yap_negociation_parser_feed(struct yap_negociation_parser* parser, uint8_t byte);

// Consume un byte del buffer
enum yap_negociation_result yap_negociation_parser_consume(struct buffer* buffer, struct yap_negociation_parser* parser);

// Checkeo si llego al final
enum yap_negociation_result yap_negociation_parser_is_done(struct yap_negociation_parser* parser);

// Checkeo si hubo un error
int yap_negociation_parser_has_error(struct yap_negociation_parser* parser);

// Free parser
void yap_negociation_parser_free(struct yap_negociation_parser* parser);

// Reset parser
void yap_negociation_parser_reset(struct yap_negociation_parser* parser);

#endif

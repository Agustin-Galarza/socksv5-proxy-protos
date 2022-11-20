#ifndef AUTH_NEGOCIATION_H
#define AUTH_NEGOCIATION_H

#include <stdint.h>

#include "utils/buffer.h"

#define AUTH_VERSION 0x01

/*
    Subparser for the authentication negociation for socks5 0x02 auth method.
*/

enum auth_negociation_results {
    AUTH_NEGOCIATION_PARSER_FINISHED = 0,
    AUTH_NEGOCIATION_PARSER_ERROR = 1,
    AUTH_NEGOCIATION_PARSER_NOT_FINISHED = 2,
};

enum auth_negociation_state {
    AUTH_NEGOCIATION_VERSION = 0,
    AUTH_NEGOCIATION_ULEN = 1,
    AUTH_NEGOCIATION_USERNAME = 2,
    AUTH_NEGOCIATION_PLEN = 3,
    AUTH_NEGOCIATION_PASSWORD = 4,
    AUTH_NEGOCIATION_DONE,
};

#define AUTH_NEGOCIATION_PARSER_MAX_USERNAME_LENGTH 255
#define AUTH_NEGOCIATION_PARSER_MAX_PASSWORD_LENGTH 255

struct auth_negociation_parser {
    enum auth_negociation_state state;
    enum auth_negociation_results result;
    uint8_t version;
    uint8_t username_length;
    uint8_t password_length;
    uint8_t username_index;
    uint8_t password_index;
    uint8_t username[AUTH_NEGOCIATION_PARSER_MAX_USERNAME_LENGTH];
    uint8_t password[AUTH_NEGOCIATION_PARSER_MAX_PASSWORD_LENGTH];
};

// Inicializo el parser
struct auth_negociation_parser* auth_negociation_parser_init();

// Libero la memoria del parser
void auth_negociation_parser_free(struct auth_negociation_parser* parser);

// Parseo un byte
enum auth_negociation_results auth_negociation_parser_feed(struct auth_negociation_parser* parser, uint8_t byte);

// Parseo un buffer
enum auth_negociation_results auth_negociation_parser_consume(struct auth_negociation_parser* parser, struct buffer* buffer);

// Reset parser
void auth_negociation_parser_reset(struct auth_negociation_parser* parser);

// Checkeo si el parser termino
enum auth_negociation_results auth_negociation_parser_has_finished(struct auth_negociation_parser* parser);

#endif

#include <string.h>
#include "../../includes/utils/parser/auth_negociation.h"
#include "utils/logger/logger.h"


// Inicializo el parser
struct auth_negociation_parser* auth_negociation_parser_init() {
    struct auth_negociation_parser* parser = malloc(sizeof(struct auth_negociation_parser));
    auth_negociation_parser_reset(parser);
    return parser;
}

// Libero la memoria del parser
void auth_negociation_parser_free(struct auth_negociation_parser* parser) {
    if (parser != NULL) {
        free(parser);
    }
}

// Parseo un byte
enum auth_negociation_results auth_negociation_parser_feed(struct auth_negociation_parser* parser, uint8_t byte) {
    switch (parser->state) {
    case AUTH_NEGOCIATION_VERSION:
        if (byte == AUTH_VERSION) {
            parser->version = byte;
            parser->state = AUTH_NEGOCIATION_ULEN;
            parser->result = AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
            log_debug("Version correcta");
            return AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
        }
        else {
            parser->result = AUTH_NEGOCIATION_PARSER_ERROR;
            return AUTH_NEGOCIATION_PARSER_ERROR;
        }
        break;
    case AUTH_NEGOCIATION_ULEN:
        if (byte > 0) {
            parser->username_length = byte;
            parser->state = AUTH_NEGOCIATION_USERNAME;
            parser->result = AUTH_NEGOCIATION_PARSER_NOT_FINISHED;

            log_debug("Ulen correcta %d", byte);
            return AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
        }
        else {
            parser->result = AUTH_NEGOCIATION_PARSER_ERROR;
            return AUTH_NEGOCIATION_PARSER_ERROR;
        }
        break;
    case AUTH_NEGOCIATION_USERNAME:
        if (parser->username_index < parser->username_length) {
            parser->username[parser->username_index] = byte;
            parser->username_index++;
            log_debug("Username byte %d", byte);
            parser->result = AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
            // return AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
        }
        if (parser->username_index == parser->username_length) {
            parser->state = AUTH_NEGOCIATION_PLEN;
            log_debug("Username correcto %s", parser->username);
            parser->result = AUTH_NEGOCIATION_PARSER_NOT_FINISHED;

            return AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
        }
        break;
    case AUTH_NEGOCIATION_PLEN:
        if (byte > 0) {
            parser->password_length = byte;
            parser->state = AUTH_NEGOCIATION_PASSWORD;
            log_debug("Plen correcta %d", byte);
            parser->result = AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
            return AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
        }
        else {
            parser->result = AUTH_NEGOCIATION_PARSER_ERROR;
            return AUTH_NEGOCIATION_PARSER_ERROR;
        }
        break;
    case AUTH_NEGOCIATION_PASSWORD:
        if (parser->password_index < parser->password_length) {
            parser->password[parser->password_index] = byte;
            parser->password_index++;
            parser->result = AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
            log_debug("Password byte %d", byte);
            // return AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
        }
        if (parser->password_index == parser->password_length) {
            parser->state = AUTH_NEGOCIATION_DONE;
            parser->result = AUTH_NEGOCIATION_PARSER_FINISHED;
            log_debug("Password correcto %s", parser->password);
            return parser->result;
        }
        break;
    default:
        parser->result = AUTH_NEGOCIATION_PARSER_ERROR;
        return AUTH_NEGOCIATION_PARSER_ERROR;
        break;
    }
    return parser->result;
}

// Parseo un buffer
enum auth_negociation_results auth_negociation_parser_consume(struct auth_negociation_parser* parser, struct buffer* buffer) {
    while (buffer_can_read(buffer)) {
        enum auth_negociation_results result = auth_negociation_parser_feed(parser, buffer_read(buffer));
        if (result != AUTH_NEGOCIATION_PARSER_NOT_FINISHED) {
            return result;
        }
    }
    return auth_negociation_parser_has_finished(parser);
}

// Reset parser
void auth_negociation_parser_reset(struct auth_negociation_parser* parser) {
    parser->state = AUTH_NEGOCIATION_VERSION;
    parser->result = AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
    parser->version = 0;
    parser->username_length = 0;
    parser->password_length = 0;
    parser->username_index = 0;
    parser->password_index = 0;
    memset(parser->username, 0, AUTH_NEGOCIATION_PARSER_MAX_USERNAME_LENGTH);
    memset(parser->password, 0, AUTH_NEGOCIATION_PARSER_MAX_PASSWORD_LENGTH);
}

// Checkeo si el parser termino
enum auth_negociation_results auth_negociation_parser_has_finished(struct auth_negociation_parser* parser) {
    return parser->state == AUTH_NEGOCIATION_DONE ? AUTH_NEGOCIATION_PARSER_FINISHED : AUTH_NEGOCIATION_PARSER_NOT_FINISHED;
}


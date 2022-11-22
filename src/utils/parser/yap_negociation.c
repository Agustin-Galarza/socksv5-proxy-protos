#include "utils/parser/yap_negociation.h"
#include <string.h>
#include "utils/logger/logger.h"

// Inicializa el parser
struct yap_negociation_parser* yap_negociation_parser_init() {
    struct yap_negociation_parser* parser = (struct yap_negociation_parser*)malloc(sizeof(struct yap_negociation_parser));
    yap_negociation_parser_reset(parser);
    return parser;
}

// Parsea un byte
enum yap_negociation_result request_yap_negociation_parser_feed(struct yap_negociation_parser* parser, uint8_t byte) {
    switch (parser->state) {
    case YAP_NEGOCIATION_PARSER_VERSION:
        if (byte == YAP_VERSION) {
            parser->state = YAP_NEGOCIATION_PARSER_USERNAME;
            log_debug("YAP_NEGOCIATION_PARSER_VERSION");
            return YAP_NEGOCIATION_INCOMPLETE;
        }
        else {
            parser->state = YAP_NEGOCIATION_PARSER_ERROR;
            log_debug("YAP_NEGOCIATION_PARSER_VERSION_ERROR");
            return YAP_NEGOCIATION_ERROR;
        }
    case YAP_NEGOCIATION_PARSER_USERNAME:
        if (byte >= MAX_USERNAME) {
            log_debug("YAP_NEGOCIATION_PARSER_USERNAME_TOO_BIG");
            return YAP_NEGOCIATION_ERROR;
        }
        if (parser->username_len == 0) {
            parser->username_len = byte;
            log_debug("YAP_NEGOCIATION_PARSER_USERNAME_LEN %d", parser->username_len);
            return YAP_NEGOCIATION_INCOMPLETE;
        }
        else if (parser->username_current < parser->username_len) {
            parser->username[parser->username_current++] = byte;
            log_debug("YAP_NEGOCIATION_PARSER_USERNAME_BYTE %c", byte);
            if (parser->username_current == parser->username_len) {
                parser->username[parser->username_current] = '\0';
                log_debug("YAP_NEGOCIATION_PARSER_USERNAME %s", parser->username);
            }
            return YAP_NEGOCIATION_INCOMPLETE;
        }
    case YAP_NEGOCIATION_PARSER_PASSWORD:
        if (byte >= MAX_PASSWORD) {
            log_debug("YAP_NEGOCIATION_PARSER_PASSWORD_TOO_BIG");
            return YAP_NEGOCIATION_ERROR;
        }
        if (parser->password_len == 0) {
            parser->password_len = byte;
            log_debug("YAP_NEGOCIATION_PARSER_PASSWORD_LEN %d", parser->password_len);
            return YAP_NEGOCIATION_INCOMPLETE;
        }
        else if (parser->password_current < parser->password_len) {
            parser->password[parser->password_current++] = byte;
            log_debug("YAP_NEGOCIATION_PARSER_PASSWORD_BYTE %c", byte);
            if (parser->password_current == parser->password_len) {
                parser->password[parser->password_current] = '\0';
                log_debug("YAP_NEGOCIATION_PARSER_PASSWORD %s", parser->password);
                parser->status = AUTH_SUCCESS;
                return YAP_NEGOCIATION_SUCCESS;
            }
            return YAP_NEGOCIATION_INCOMPLETE;
        }
    case YAP_NEGOCIATION_PARSER_DONE:
        log_debug("YAP_NEGOCIATION_PARSER_DONE");
        return YAP_NEGOCIATION_SUCCESS;
    case YAP_NEGOCIATION_PARSER_ERROR:
        log_debug("YAP_NEGOCIATION_PARSER_ERROR");
        return YAP_NEGOCIATION_ERROR;
    default:
        return YAP_NEGOCIATION_ERROR;
    }
}

// Consume un byte del buffer
enum yap_negociation_result yap_negociation_parser_consume(struct buffer* buffer, struct yap_negociation_parser* parser) {
    while (buffer_can_read(buffer)) {
        uint8_t byte = buffer_read(buffer);
        enum yap_negociation_result result = request_yap_negociation_parser_feed(parser, byte);
        if (result != YAP_NEGOCIATION_INCOMPLETE) {
            return result;
        }
    }
    enum yap_negociation_result res = yap_negociation_parser_is_done(parser);
    parser->status = res == YAP_NEGOCIATION_SUCCESS ? AUTH_SUCCESS : AUTH_FAIL;
    return res;
}

// Checkeo si llego al final
enum yap_negociation_result yap_negociation_parser_is_done(struct yap_negociation_parser* parser) {
    return parser->state == YAP_NEGOCIATION_PARSER_DONE ? YAP_NEGOCIATION_SUCCESS : YAP_NEGOCIATION_INCOMPLETE;
}

// Checkeo si hubo un error
int yap_negociation_parser_has_error(struct yap_negociation_parser* parser);

// Free parser
void yap_negociation_parser_free(struct yap_negociation_parser* parser) {
    if (parser != NULL)
        free(parser);
}

// Reset parser
void yap_negociation_parser_reset(struct yap_negociation_parser* parser) {
    parser->state = YAP_NEGOCIATION_PARSER_VERSION;
    parser->username_len = 0;
    parser->password_len = 0;
    parser->username_current = 0;
    parser->password_current = 0;
    memset(parser->username, 0, MAX_USERNAME);
    memset(parser->password, 0, MAX_PASSWORD);
}
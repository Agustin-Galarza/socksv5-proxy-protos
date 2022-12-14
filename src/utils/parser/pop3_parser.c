#include <string.h>

#include "utils/parser/pop3_parser.h"
#include "utils/logger/logger.h"


struct pop3_parser* pop3_parser_init() {
    struct pop3_parser* parser = malloc(sizeof(struct pop3_parser));
    parser->buff = malloc(sizeof(struct buffer));

    buffer_init(parser->buff, MAX_POP3_LENGHT, malloc(MAX_POP3_LENGHT));
    pop3_parser_reset(parser);
    return parser;
}

void pop3_parser_reset(struct pop3_parser* parser) {
    parser->state = POP3_STATE_INIT;
    parser->user = NULL;
    parser->pass = NULL;
    parser->user_len = 0;
    parser->pass_len = 0;
}


void pop3_parser_free(struct pop3_parser* parser) {
    if (parser == NULL) return;
    if (parser->user != NULL) {
        free(parser->user);
    }
    if (parser->pass != NULL) {
        free(parser->pass);
    }
    if (parser->buff != NULL) {
        if (parser->buff->data != NULL)
            free(parser->buff->data);
        free(parser->buff);
    }
    free(parser);
}

int pop3_parser_has_error(struct pop3_parser* parser) {
    return parser->state == POP3_ERROR;
}


enum pop3_state pop3_parser_feed(struct pop3_parser* parser, uint8_t c) {
    switch (parser->state) {
    case POP3_STATE_INIT:
        if (POP_U(c)) {
            parser->state = POP3_STATE_USER_U;
            log_debug("Estado correcto U");
        }
        else {
            parser->state = POP3_STATE_INIT;
            log_debug("No se ha terminado");
        }
        break;
    case POP3_STATE_USER_U:
        if (POP_S(c)) {
            parser->state = POP3_STATE_USER_S;
            log_debug("Estado correcto S");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_USER_S:
        if (POP_E(c)) {
            parser->state = POP3_STATE_USER_E;
            log_debug("Estado correcto E");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_USER_E:
        if (POP_R(c)) {
            parser->state = POP3_STATE_USER_R;
            log_debug("Estado correcto R");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_USER_R:
        if (SPACE(c)) {
            parser->state = POP3_STATE_USER_SNIF;
            log_debug("Estado correcto SPACE");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_USER_SNIF:
        if (!CRLF_1(c)) {
            buffer_write(parser->buff, c);
            parser->user_len++;
            log_debug("Leyendo usuario");
        }
        else {
            parser->user = malloc(sizeof(char) * (parser->user_len + 1));
            memcpy(parser->user, parser->buff->data, parser->user_len);
            parser->user[parser->user_len] = '\0';
            parser->state = POP3_STATE_USER_CRLF;
            log_debug("Usuario terminado");
            buffer_reset(parser->buff);
        }
        break;
    case POP3_STATE_USER_CRLF:
        if (CRLF_2(c)) {
            parser->state = POP3_STATE_USER_OK;
            log_debug("Estado correcto /n");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_USER_OK:
        if (POP_P(c)) {
            parser->state = POP3_STATE_PASS_P;
            log_debug("Estado correcto P");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_PASS_P:
        if (POP_A(c)) {
            parser->state = POP3_STATE_PASS_A;
            log_debug("Estado correcto A");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_PASS_A:
        if (POP_S(c)) {
            parser->state = POP3_STATE_PASS_S_1;
            log_debug("Estado correcto S");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_PASS_S_1:
        if (POP_S(c)) {
            parser->state = POP3_STATE_PASS_S_2;
            log_debug("Estado correcto S");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_PASS_S_2:
        if (SPACE(c)) {
            parser->state = POP3_STATE_PASS_SNIF;
            log_debug("Estado correcto SPACE");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
        }
        break;
    case POP3_STATE_PASS_SNIF:
        if (!CRLF_1(c)) {
            buffer_write(parser->buff, c);
            parser->pass_len++;
            log_debug("Leyendo pass");
        }
        else {
            parser->pass = malloc(sizeof(char) * (parser->pass_len + 1));
            memcpy(parser->pass, parser->buff->data, parser->pass_len);
            parser->pass[parser->pass_len] = '\0';
            parser->state = POP3_STATE_PASS_CRLF;
            log_debug("Pass terminada");
            buffer_reset(parser->buff);
        }
        break;
    case POP3_STATE_PASS_CRLF:
        if (CRLF_2(c)) {
            parser->state = POP3_STATE_PASS_OK;
            buffer_reset(parser->buff);
            log_debug("Estado correcto");
        }
        else {
            parser->state = POP3_ERROR;
            log_debug("Estado incorrecto");
            break;
        }
    case POP3_STATE_PASS_OK:
        parser->state = POP3_STATE_DONE;
        break;
    case POP3_STATE_DONE:
    case POP3_ERROR:
        break;
    }
    return parser->state;
}

enum pop3_results pop3_parser_is_finished(struct pop3_parser* parser) {
    return parser->state == POP3_STATE_DONE ? POP3_FINISH_OK : POP3_NOT_FINISH;
}

enum pop3_results pop3_parser_consume(buffer* buff, struct pop3_parser* parser) {
    while (buffer_can_read(buff)) {
        uint8_t c = buffer_read(buff);
        pop3_parser_feed(parser, c);
        if (pop3_parser_has_error(parser)) {
            return POP3_FINISH_ERROR;
        }
        if (pop3_parser_is_finished(parser) == POP3_FINISH_OK) {
            break;
        }
    }
    return pop3_parser_is_finished(parser);
}


char* pop3_parser_get_user(struct pop3_parser* parser) {
    return parser->user;
}

char* pop3_parser_get_pass(struct pop3_parser* parser) {
    return parser->pass;
}


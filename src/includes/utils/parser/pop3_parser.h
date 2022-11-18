#ifndef POP3_PARSER_H
#define POP3_PARSER_H

#include "utils/buffer.h"
#include <stdint.h>

#define MAX_POP3_LENGHT 256

#define POP_U(x) x == "u" || x == "U"
#define POP_S(x) x == "s" || x == "S"
#define POP_E(x) x == "e" || x == "E"
#define POP_R(x) x == "r" || x == "R"

#define POP_P(x) x == "p" || x == "P"
#define POP_A(x) x == "a" || x == "A"
#define POP_S(x) x == "s" || x == "S"

#define CRLF_1(x) x == "\r"
#define CRLF_2(x) x == "\n"


// Estados finales del parser
enum pop3_results {
    POP3_FINISH_OK,
    POP3_FINISH_ERROR,
    POP3_NOT_FINISH
};

// Estados del parser. Solo nos importan los comandos usr y pass
enum pop3_state {
    POP3_STATE_INIT,
    POP3_STATE_USER_U,
    POP3_STATE_USER_S,
    POP3_STATE_USER_E,
    POP3_STATE_USER_R,
    POP3_STATE_USER_CRLF,
    POP3_STATE_USER_SNIF,
    POP3_STATE_USER_OK,
    POP3_STATE_PASS_P,
    POP3_STATE_PASS_A,
    POP3_STATE_PASS_S_1,
    POP3_STATE_PASS_S_2,
    POP3_STATE_PASS_CRLF,
    POP3_STATE_PASS_SNIF,
    POP3_STATE_PASS_OK,
    POP3_STATE_DONE,
    POP3_ERROR
};

// Estructura del parser
struct pop3_parser {
    enum pop3_state state;
    struct buffer* buff;
    char* user;
    int user_len;
    char* pass;
    int pass_len;
};

// Inicializa el parser
struct pop3_parser* pop3_parser_init();

// Libera la memoria del parser
void pop3_parser_free(struct pop3_parser* parser);

// Parsea un byte
enum pop3_results pop3_parser_feed(struct pop3_parser* parser, uint8_t c);

// Parsea un buffer
enum pop3_results request_parser_consume(buffer* buff, struct pop3_parser* parser);

// Devuelve el usuario
char* pop3_parser_get_user(struct pop3_parser* parser);

// Devuelve la contraseña
char* pop3_parser_get_pass(struct pop3_parser* parser);

// Checkea si llego al estado final
enum pop3_results pop3_parser_is_finished(struct pop3_parser* parser);

// Ckeckea si hay error
int request_parser_has_error(struct pop3_parser* parser);

// Resetea el parser
void pop3_parser_reset(struct pop3_parser* parser);

#endif

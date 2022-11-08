#ifndef CLIENT_PARSER_H_
#define CLIENT_PARSER_H_

#include <stddef.h>
#include <stdbool.h>

#define MAX_USRNAME_LEN 20
#define MAX_MSG_LEN 30
#define END_TOKEN '\n'
#define NEW_LINE_REPR '\\'

/**
 * Parser para un protocolo definido como
 * +------------+----------+--------+-----------+------+
 * |    VER     | Username | Sep    |   Msg     | End |
 * +----+-----+-------+------+----------+-------------+
 * |  1 (char)  | Variable |  '|'   | Variable | '\n' |
 * +----+-----+-------+------+----------+------------+
 *
 */

enum parsing_status
{
    CLNT_PARSER_WAITING = 0,
    CLNT_PARSER_PARSING,
    CLNT_PARSER_DONE,
    CLNT_PARSER_ERROR
};

struct parsed_msg {
    char* username;
    char* msg;
};

typedef struct client_parser client_parser;


client_parser* client_parser_init();

const char* client_parser_error_str(client_parser* parser);

enum parsing_status client_parser_get_status(client_parser* parser);

enum parsing_status start_parsing(client_parser* parser, char* msg, size_t msg_len);

enum parsing_status keep_parsing(client_parser* parser, size_t extra_len);

struct parsed_msg* get_parsed_msg(client_parser* parser);

void client_parser_reset(client_parser* parser);

void client_parser_free(client_parser* parser);
#endif

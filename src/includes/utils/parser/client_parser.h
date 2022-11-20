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

enum parser_state {
    VERSION_CHECK = 0,
    USERNAME_RETR,
    MSG_RETR,
    DONE,
    CONNECTION_ERROR
};

enum parser_error {
    CLNT_PARSER_OK = 0,
    CLNT_PARSER_NO_MSG,
    CLNT_PARSER_UNDEF,
    CLNT_PARSER_WRONG_VER,
    CLNT_PARSER_USRNAME_TOO_LONG,
    CLNT_PARSER_MSG_TOO_LONG,

};

struct parsed_msg {
    char* username;
    char* msg;
};

struct client_parser
{
    enum parsing_status status;
    enum parser_state state;
    char* msg;
    size_t msg_len;
    size_t curr_char;

    size_t username_index;
    size_t msg_index;

    struct parsed_msg* parsed_msg;

    enum parser_error error_status;
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

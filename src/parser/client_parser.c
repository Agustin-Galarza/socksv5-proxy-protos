#include <string.h>
#include <stdlib.h>

#include "parser/client_parser.h"

#define SEPARATION_TOKEN '|'

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

client_parser* client_parser_init() {
    client_parser* parser = malloc(sizeof(struct client_parser));

    parser->msg = NULL;
    parser->msg_len = 0;
    parser->curr_char = 0;
    parser->username_index = 0;
    parser->msg_index = 0;
    parser->status = CLNT_PARSER_WAITING;
    parser->error_status = CLNT_PARSER_OK;
    parser->state = VERSION_CHECK;
    parser->parsed_msg = malloc(sizeof(struct parsed_msg));
    parser->parsed_msg->msg = malloc(MAX_MSG_LEN + 1);
    parser->parsed_msg->username = malloc(MAX_USRNAME_LEN + 1);

    return parser;
}

const char* client_parser_error_str(client_parser* parser) {
    switch (parser->error_status) {
    case CLNT_PARSER_OK:
        return "OK";
    case CLNT_PARSER_NO_MSG:
        return "No message to parse could be found";
    case CLNT_PARSER_UNDEF:
        return "Invalid parsing state";
    case CLNT_PARSER_WRONG_VER:
        return "Wrong version";
    case CLNT_PARSER_USRNAME_TOO_LONG:
        return "Username is too long";
    case CLNT_PARSER_MSG_TOO_LONG:
        return "Message is too long";
    default:
        return "Something went wrong";
    }

}

void client_parser_free(client_parser* parser) {
    if (parser == NULL)
        return;

    if (parser->parsed_msg != NULL) {
        free(parser->parsed_msg->msg);
        free(parser->parsed_msg->username);
        free(parser->parsed_msg);
    }
    free(parser);
}

enum parsing_status client_parser_get_status(client_parser* parser) {
    return parser->status;
}

enum parsing_status start_parsing(client_parser* parser, char* msg, size_t msg_len) {
    parser->msg = msg;
    parser->state = VERSION_CHECK;
    parser->status = CLNT_PARSER_PARSING;


    return keep_parsing(parser, msg_len);
}

enum parsing_status keep_parsing(client_parser* parser, size_t extra_len) {
    if (parser->msg == NULL) {
        parser->status = CLNT_PARSER_ERROR;
        parser->error_status = CLNT_PARSER_NO_MSG;
        goto end;
    }

    if (extra_len == 0) {
        goto end;
    }
    parser->msg_len += extra_len;

    switch (parser->state) {
    case VERSION_CHECK:
        if (parser->msg[parser->curr_char++] != '5') {
            parser->status = CLNT_PARSER_ERROR;
            parser->error_status = CLNT_PARSER_WRONG_VER;
            goto end;
        }
        parser->state = USERNAME_RETR;
    case USERNAME_RETR:
        for (;parser->curr_char < parser->msg_len && parser->msg[parser->curr_char - (parser->msg_len - extra_len)] != SEPARATION_TOKEN; parser->curr_char++) {
            if (parser->username_index >= MAX_USRNAME_LEN) {
                parser->status = CLNT_PARSER_ERROR;
                parser->error_status = CLNT_PARSER_USRNAME_TOO_LONG;
                goto end;
            }
            parser->parsed_msg->username[parser->username_index] = parser->msg[parser->curr_char - (parser->msg_len - extra_len)];

            parser->username_index++;
        }
        if (parser->msg[parser->curr_char - (parser->msg_len - extra_len)] != SEPARATION_TOKEN)
            break;

        parser->curr_char++;
        parser->parsed_msg->username[parser->username_index] = '\0';
        parser->state = MSG_RETR;
    case MSG_RETR:
        for (;parser->curr_char < parser->msg_len && parser->msg[parser->curr_char - (parser->msg_len - extra_len)] != END_TOKEN; parser->curr_char++) {
            if (parser->msg_index >= MAX_MSG_LEN) {
                parser->status = CLNT_PARSER_ERROR;
                parser->error_status = CLNT_PARSER_MSG_TOO_LONG;
                goto end;
            }
            if (parser->msg[parser->curr_char - (parser->msg_len - extra_len)] == NEW_LINE_REPR) {
                parser->parsed_msg->msg[parser->msg_index] = '\n';
            }
            else {
                parser->parsed_msg->msg[parser->msg_index] = parser->msg[parser->curr_char - (parser->msg_len - extra_len)];
            }
            parser->msg_index++;
        }
        if (parser->msg[parser->curr_char - (parser->msg_len - extra_len)] != END_TOKEN)
            break;

        parser->parsed_msg->msg[parser->msg_index] = '\0';
        parser->state = DONE;
        parser->status = CLNT_PARSER_DONE;
        break;
    default:
        parser->status = CLNT_PARSER_ERROR;
        parser->error_status = CLNT_PARSER_UNDEF;
        goto end;
    }

end:
    return parser->status;


}

struct parsed_msg* get_parsed_msg(client_parser* parser) {
    return parser->parsed_msg;
}

void client_parser_reset(client_parser* parser) {
    parser->curr_char = 0;
    parser->username_index = 0;
    parser->msg_index = 0;
    parser->msg_len = 0;
    parser->msg = NULL;
    parser->status = CLNT_PARSER_WAITING;
}

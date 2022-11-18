#include "utils/parser/yap_parser.h"
#include <string.h>
#include "utils/logger/logger.h"

// Inicializa el parser
struct yap_parser* yap_parser_init() {
    struct yap_parser* parser = malloc(sizeof(struct yap_parser));
    yap_parser_reset(parser);
    return parser;
}

// Free del parser
void yap_parser_free(struct yap_parser* parser) {
    free(parser);
}

// Parsea un buffer
enum yap_result yap_parser_feed(struct yap_parser* parser, uint8_t byte) {
    switch (parser->state) {
    case YAP_STATE_COMMAND:
        if (yap_parser_is_valid_command(byte) && parser->command == YAP_NO_COMMAND) {
            parser->command = byte;
            switch (byte) {
            case YAP_COMMANDS_USERS:
                return YAP_PARSER_FINISH;
                break;
            case YAP_COMMANDS_METRICS:
                parser->state = YAP_STATE_METRIC;
                break;
            case YAP_COMMANDS_ADD_USER:
                parser->state = YAP_STATE_ADD_USER;
                break;
            case YAP_COMMANDS_REMOVE_USER:
                parser->state = YAP_STATE_REMOVE_USER;
                break;
            case YAP_COMMANDS_CONFIG:
                parser->state = YAP_STATE_CONFIG;
                break;
            default:
                break;
            }
            log_debug("Comando correcto");
            return YAP_PARSER_NOT_FINISHED;
        }
        else {
            log_error("Comando incorrecto");
            return YAP_PARSER_ERROR;
        }
        break;
    case YAP_STATE_METRIC:
        if (yap_parser_is_valid_metric(byte)) {
            parser->metric = byte;
            return YAP_PARSER_FINISH;
        }
        else {
            log_error("Metrica incorrecta");
            return YAP_PARSER_ERROR;
        }
        break;
    case YAP_STATE_ADD_USER:
        if (byte == 0) {
            parser->state = YAP_STATE_ADD_PASS;
            return YAP_PARSER_NOT_FINISHED;
        }
        else if (parser->username_length < MAX_USERNAME_LENGTH) {
            parser->username[parser->username_length] = byte;
            parser->username_length++;
            return YAP_PARSER_NOT_FINISHED;
        }
        else {
            log_error("Username demasiado largo");
            return YAP_PARSER_ERROR;
        }
        break;
    case YAP_STATE_ADD_PASS:
        if (byte == 0) {
            return YAP_PARSER_FINISH;
        }
        else if (parser->password_length < MAX_PASSWORD_LENGTH) {
            parser->password[parser->password_length] = byte;
            parser->password_length++;
            return YAP_PARSER_NOT_FINISHED;
        }
        else {
            log_error("Password demasiado larga");
            return YAP_PARSER_ERROR;
        }
        break;
    case YAP_STATE_REMOVE_USER:
        if (byte == 0) {
            return YAP_PARSER_FINISH;
        }
        else if (parser->username_length < MAX_USERNAME_LENGTH) {
            parser->username[parser->username_length] = byte;
            parser->username_length++;
            return YAP_PARSER_NOT_FINISHED;
        }
        else {
            log_error("Username demasiado largo");
            return YAP_PARSER_ERROR;
        }
        break;
    case YAP_STATE_CONFIG:
        if (yap_parser_is_valid_config(byte)) {
            parser->config = byte;
            return YAP_PARSER_FINISH;
        }
        else {
            log_error("Configuracion incorrecta");
            return YAP_PARSER_ERROR;
        }
        break;

    default:
        return YAP_PARSER_ERROR;
        break;
    }
}

// COnsume un buffer
enum yap_result yap_parser_consume(struct buffer* buffer, struct yap_parser* parser) {
    enum yap_result result = YAP_PARSER_NOT_FINISHED;
    while (buffer_can_read(buffer) && result == YAP_PARSER_NOT_FINISHED) {
        result = yap_parser_feed(parser, buffer_read(buffer));
    }
    return result;
}

// Resetea el parser
void yap_parser_reset(struct yap_parser* parser) {
    parser->state = YAP_STATE_COMMAND;
    parser->command = YAP_NO_COMMAND;
    parser->metric = 0;
    parser->username_length = 0;
    parser->password_length = 0;
    parser->config = 0;
    parser->config_value = 0;
    memset(parser->username, 0, MAX_USERNAME_LENGTH);
    memset(parser->password, 0, MAX_PASSWORD_LENGTH);
}
// Checkeo que sea un comando valido
int yap_parser_is_valid_command(uint8_t command) {
    return command >= YAP_NO_COMMAND && command <= YAP_COMMANDS_CONFIG;
}


// Checkeo que sea una metrica valida
int yap_parser_is_valid_metric(uint8_t metric) {
    return metric >= YAP_METRIC_HISTORICAL_CONNECTIONS && metric <= YAP_METRIC_BYTES_SEND;
}

// Checkeo que sea una configuracion valida
int yap_parser_is_valid_config(uint8_t config) {
    return config >= YAP_CONFIG_TIMEOUTS && config <= YAP_CONFIG_BUFFER_SIZE;
}

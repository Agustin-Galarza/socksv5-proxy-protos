#include "utils/parser/yap_parser.h"
#include <string.h>
#include "utils/logger/logger.h"
#include <netdb.h>

// Inicializa el parser
struct yap_parser* yap_parser_init() {
    struct yap_parser* parser = malloc(sizeof(struct yap_parser));
    yap_parser_reset(parser);
    return parser;
}

// Free del parser
void yap_parser_free(struct yap_parser* parser) {
    if (parser != NULL)
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
                parser->state = YAP_STATE_USER;
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
                return YAP_PARSER_ERROR;
            }
            log_debug("Comando correcto %d", byte);
            return YAP_PARSER_NOT_FINISHED;
        }
        else {
            log_error("Comando incorrecto %d", byte);
            return YAP_PARSER_ERROR;
        }
        break;
    case YAP_STATE_METRIC:
        if (yap_parser_is_valid_metric(byte)) {
            parser->metric = byte;
            return YAP_PARSER_FINISH;
        }
        else {
            log_error("Metrica incorrecta %d", byte);
            return YAP_PARSER_ERROR;
        }
        break;
    case YAP_STATE_ADD_USER:
        if (parser->username_length == 0) {
            parser->username_length = byte;
        }
        else if (parser->username_current < parser->username_length) {
            parser->username[parser->username_current++] = byte;
        }
        if (parser->username_current == parser->username_length) {
            parser->state = YAP_STATE_ADD_PASS;
            log_debug("Username completa: %s", parser->username);
            return YAP_PARSER_NOT_FINISHED;
        }
        break;
    case YAP_STATE_ADD_PASS:
        if (parser->password_length == 0) {
            parser->password_length = byte;
            return YAP_PARSER_NOT_FINISHED;
        }
        else if (parser->password_current < parser->password_length) {
            parser->password[parser->password_current++] = byte;
        }
        if (parser->password_current == parser->password_length) {
            log_debug("Password completa: %s", parser->password);
            return YAP_PARSER_FINISH;
        }
        break;
    case YAP_STATE_REMOVE_USER:
        if (parser->username_length == 0) {
            parser->username_length = byte;
        }
        else if (parser->username_current < parser->username_length) {
            parser->username[parser->username_current++] = byte;
        }
        if (parser->username_current == parser->username_length) {
            parser->state = YAP_STATE_REMOVE_PASS;
            log_debug("Username completa: %s", parser->username);
            return YAP_PARSER_NOT_FINISHED;
        }
        break;
    case YAP_STATE_REMOVE_PASS:
        if (parser->password_length == 0) {
            parser->password_length = byte;
            return YAP_PARSER_NOT_FINISHED;
        }
        else if (parser->password_current < parser->password_length) {
            parser->password[parser->password_current++] = byte;
        }
        if (parser->password_current == parser->password_length) {
            log_debug("Password completa: %s", parser->password);
            return YAP_PARSER_FINISH;
        }
        break;
    case YAP_STATE_CONFIG:
        if (yap_parser_is_valid_config(byte)) {
            parser->config = byte;
            parser->state = YAP_STATE_CONFIG_VALUE;
            log_debug("Config correcta %d", byte);
            return YAP_PARSER_NOT_FINISHED;
        }
        else {
            log_error("Configuracion incorrecta");
            return YAP_PARSER_ERROR;
        }
        break;
    case YAP_STATE_CONFIG_VALUE:
        if (parser->config_index < 2) {
            memcpy((uint8_t*)&parser->config_value + parser->config_index, &byte, 1);
            // parser->config_value = byte;
            parser->config_index++;
            log_debug("Config value correcta %d", byte);
            // return YAP_PARSER_NOT_FINISHED;
        }
        if (parser->config_index == 2) {
            parser->config_value = ntohs(parser->config_value);
            return YAP_PARSER_FINISH;
            break;
        }
        break;
    default:
        return YAP_PARSER_ERROR;
        break;
    }
    return YAP_PARSER_NOT_FINISHED;
}

// COnsume un buffer
enum yap_result yap_parser_consume(struct buffer* buffer, struct yap_parser* parser) {
    enum yap_result result = YAP_PARSER_NOT_FINISHED;
    while (buffer_can_read(buffer) && result == YAP_PARSER_NOT_FINISHED) {
        result = yap_parser_feed(parser, buffer_read(buffer));
    }
    parser->result = result;
    log_debug("Parsed complete\n");
    return result;
}

// Resetea el parser
void yap_parser_reset(struct yap_parser* parser) {
    parser->state = YAP_STATE_COMMAND;
    parser->command = YAP_NO_COMMAND;
    parser->metric = 0;
    parser->result = YAP_PARSER_NOT_FINISHED;
    parser->username_length = 0;
    parser->password_length = 0;
    parser->username_current = 0;
    parser->password_current = 0;
    parser->config = 0;
    parser->config_value = 0;
    parser->config_index = 0;
    memset(parser->username, 0, MAX_USERNAME_LENGTH);
    memset(parser->password, 0, MAX_PASSWORD_LENGTH);
}
// Checkeo que sea un comando valido
int yap_parser_is_valid_command(uint8_t command) {
    return command >= YAP_NO_COMMAND && command <= YAP_COMMANDS_CONFIG;
}


// Checkeo que sea una metrica valida
int yap_parser_is_valid_metric(uint8_t metric) {
    return metric <= YAP_METRIC_BYTES_SEND;
}

// Checkeo que sea una configuracion valida
int yap_parser_is_valid_config(uint8_t config) {
    return config <= YAP_CONFIG_BUFFER_SIZE;
}

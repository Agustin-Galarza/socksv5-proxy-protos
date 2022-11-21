#ifndef YAP_PARSER_H
#define YAP_PARSER_H

#include "utils/buffer.h"
#include <stdint.h>

/*

    Parser de la comunicacion de nuestro protocolo YAP

*/

#define MAX_USERNAME_LENGTH 125
#define MAX_PASSWORD_LENGTH 125

enum yap_metrics {
    YAP_METRIC_HISTORICAL_CONNECTIONS = 0x00,
    YAP_METRIC_CONCURRENT_CONNECTIONS = 0x01,
    YAP_METRIC_BYTES_SEND = 0x02,
};

enum yap_configs {
    YAP_CONFIG_TIMEOUTS = 0x00,
    YAP_CONFIG_BUFFER_SIZE = 0x01,
};

enum yap_commands {
    YAP_NO_COMMAND = 0x00,
    YAP_COMMANDS_USERS = 0x01, // Devuelve lista de usuarios
    YAP_COMMANDS_METRICS = 0x02, // Devuelve metrica
    YAP_COMMANDS_ADD_USER = 0x03, // Agrega un usuario
    YAP_COMMANDS_REMOVE_USER = 0x04, // Elimina un usuario
    YAP_COMMANDS_CONFIG = 0x05 // Devuelve una configuracion
};

enum yap_states {
    YAP_STATE_COMMAND,
    YAP_STATE_USER,
    YAP_STATE_METRIC,
    YAP_STATE_ADD_USER,
    YAP_STATE_ADD_PASS,
    YAP_STATE_REMOVE_USER,
    YAP_STATE_REMOVE_PASS,
    YAP_STATE_CONFIG,
    YAP_STATE_CONFIG_VALUE
};

enum yap_result {
    YAP_PARSER_FINISH = 0,
    YAP_PARSER_ERROR = 1,
    YAP_PARSER_NOT_FINISHED = 2
};

struct yap_parser {
    enum yap_states state;
    enum yap_result result;
    enum yap_commands command;
    // USERS
    // METRICS
    uint8_t metric;
    uint8_t metric_value;
    // ADD_USER and REMOVE_USER
    char username[MAX_USERNAME_LENGTH];
    uint8_t username_length;
    uint8_t username_current;
    char password[MAX_PASSWORD_LENGTH];
    uint8_t password_length;
    uint8_t password_current;
    // CONFIG
    uint8_t config;
    uint16_t config_value;
};

// Inicializa el parser
struct yap_parser* yap_parser_init();

// Free del parser
void yap_parser_free(struct yap_parser* parser);

// Parsea un buffer
enum yap_result yap_parser_feed(struct yap_parser* parser, uint8_t byte);

// COnsume un buffer
enum yap_result yap_parser_consume(struct buffer* buffer, struct yap_parser* parser);

// Resetea el parser
void yap_parser_reset(struct yap_parser* parser);

// Checkeo que sea un comando valido
int yap_parser_is_valid_command(uint8_t command);

// Checkeo que sea una metrica valida
int yap_parser_is_valid_metric(uint8_t metric);

// Checkeo que sea una configuracion valida
int yap_parser_is_valid_config(uint8_t config);

#endif

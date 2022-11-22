#ifndef TCPCLIENTUTIL_H_
#define TCPCLIENTUTIL_H_

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <netdb.h>
#include <arpa/inet.h>


#include "utils/parser/yap_parser.h"


#define CREDS_LEN 128
#define MAX_AUTH_TRIES 3
#define RECV_BUFFER_SIZE 512
#define PARAMS_LEN 64
#define NUMERIC_INPUT_LEN 32
#define USER_LIST 7
#define SUCCESS_AUTH 0
#define FAILED_AUTH 1
#define CONNECTED 0
#define TERMINATE 1
#define COMMAND_LEN 64
#define BUILTIN_TOTAL 2
#define CMD_TOTAL 5
#define METRICS_TOTAL 3
#define CONFIG_TOTAL 2


// #define LIST_USERS 1
// #define METRIC 2
// #define ADD_USER 3
// #define REMOVE_USER 4
// #define CONFIG 5

#define HISTORICAL_CONNECTIONS 0
#define CONCURRENT_CONNECTIONS 1
#define BYTES_SENT 2

#define BUFF_SIZE 256



int connect_to_ipv4(struct sockaddr_in * ipv4_address, unsigned short port , char * address);
int connect_to_ipv6(struct sockaddr_in6 * ipv6_address, unsigned short port,char * address);

int ask_credentials(uint8_t * username, uint8_t * password);
int ask_username(uint8_t * username);
int ask_password(uint8_t * password);
int ask_command(int socket, struct yap_parser * parser);
int ask_metric(uint8_t * metric);
int ask_config(uint8_t* config, uint8_t* config_value);

int send_credentials(int socket_fd, uint8_t * username, uint8_t * password);
int send_string(uint8_t socket_fd, uint8_t len, uint8_t * array);
int send_command(int sock_fd, struct yap_parser * parser);

void print_status(uint16_t status);
int print_response(struct yap_parser * parser, int socket);
void print_welcome();
int print_user_list(int socket, struct yap_parser * parser);
int print_metric(int socket, struct yap_parser * parser);
int print_config(int socket, struct yap_parser * parser);
int print_historical_connections(char* buffer);
int print_concurrent_connections(char* buffer);
int print_bytes_sent(char* buffer);
int print_user_command(int socket, struct yap_parser* parser);

int close_connection(int socket_fd);

void handle_quit(int sock_fd);
void handle_help();
void handle_metrics();
void handle_config();
void handle_input(uint8_t* input);
void clean_input(uint8_t* string);


#endif

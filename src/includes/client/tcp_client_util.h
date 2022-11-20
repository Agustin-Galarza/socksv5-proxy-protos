#ifndef TCPCLIENTUTIL_H_
#define TCPCLIENTUTIL_H_

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <netdb.h>

#include "utils/parser/yap_parser.h"

#define CREDS_LEN 128
#define MAX_AUTH_TRIES 3
#define RECV_BUFFER_SIZE 512
#define PARAMS_LEN 64
#define NUMERIC_INPUT_LEN 32
#define USER_LIST 7
#define QUERIES_TOTAL 4
#define MODIFIERS_TOTAL 2
#define SUCCESS_AUTH 0x0000
#define COMMAND_MAX_LEN 64
#define BUILTIN_TOTAL 2


#define LIST_USERS 1
#define METRIC 2
#define ADD_USER 3
#define REMOVE_USER 4
#define CONFIG 5

#define HISTORICAL_CONNECTIONS 0
#define CONCURRENT_CONNECTIONS 1
#define BYTES_SENT 2

#define BUFF_SIZE 256

char * queries[] = {"thc", "cc", "tbs", "ul"};
char * query_description[] = {
    "thc - Get Total Historical Connections",
    "cc - Get Concurrent Connections",
    "tbs - Get Total Bytes Sent",
    "ul - Get User List"
};

char * modifiers[] = {"au", "ru"};
char * modifier_description[] = {
    "au - Add User",
    "ru - Remove User"
};

int connect_to_ipv4(struct sockaddr_in * ipv4_address, unsigned short port , char * address);
int connect_to_ipv6(struct sockaddr_in6 * ipv6_address, unsigned short port,char * address);

int ask_credentials(uint8_t * username, uint8_t * password);
int ask_username(uint8_t * username);
int ask_password(uint8_t * password);

int send_credentials(int socket_fd, uint8_t * username, uint8_t * password);
int send_string(uint8_t socket_fd, uint8_t len, uint8_t * array);

void print_status(uint16_t status);
int print_response(uint8_t * cmd, struct yap_parser * parser, int socket);
void print_welcome();
int print_added_user(struct yap_parser * parser);
int print_removed_user(struct yap_parser * parser);
int print_user_list(int socket);
int print_metric(int socket);
int print_config(int socket);
int print_historical_connections(char* buffer);
int print_concurrent_connections(char* buffer);
int print_bytes_sent(char* buffer);

int close_connection(int socket_fd);

void handle_quit(int sock_fd);
void handle_help(int sock_fd);
char * builtin_names[] = {"help", "quit"};
void (*builtin[])(int) = {handle_help, handle_quit};

#endif

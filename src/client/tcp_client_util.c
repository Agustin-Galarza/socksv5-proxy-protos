#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "utils/logger/logger.h"
#include "utils/util.h"
#include "client/tcp_client_util.h"
#include "utils/representation.h"


#define TO_UINT16(p) (*((uint16_t*)p))

char* commands[] = { "ul", "m", "au", "ru", "c" };
char* cmd_description[] = {
    "ul - Get User List",
    "m  - Select from a list of metrics",
    "au - Add User",
    "ru - Remove User",
    "c  - Select from a list of configurations"
};


char* available_metrics[] = {
    "hc - Prints the number of historic connections",
    "cc - Prints the number of concurrent connections",
    "bs - Prints the number of bytes sent"
};

char* available_config[] = {
    "tout     - Sets timeout to given seconds",
    "bsize    - Sets buffer size to given size"
};

char* builtin_names[] = { "help", "quit" };
void (*builtin[])(int) = { handle_help, handle_quit };


int connect_to_ipv4(struct sockaddr_in* ipv4_address, unsigned short port, char* address) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return -1;

    memset(ipv4_address, 0, sizeof(*ipv4_address));
    ipv4_address->sin_family = AF_INET;
    ipv4_address->sin_port = htons(port);
    inet_pton(AF_INET, address, &ipv4_address->sin_addr.s_addr);

    if (connect(sock_fd, (struct sockaddr*)ipv4_address, sizeof(*ipv4_address)) < 0) {
        printf("Unable to connect IPv4\n");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

int connect_to_ipv6(struct sockaddr_in6* ipv6_address, unsigned short port, char* address) {
    int sock_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return -1;

    ipv6_address->sin6_family = AF_INET6;
    ipv6_address->sin6_flowinfo = 0;
    ipv6_address->sin6_scope_id = 0;
    inet_pton(AF_INET6, address, &ipv6_address->sin6_addr);
    ipv6_address->sin6_port = htons(port);

    if (connect(sock_fd, (struct sockaddr*)ipv6_address, sizeof(*ipv6_address)) < 0) {
        printf("Unable to connect IPv6\n");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}


int ask_credentials(uint8_t* username, uint8_t* password) {
    if (ask_username(username) < 0) {
        printf("Please enter credentials with valid format\n");
        return -1;
    }

    if (ask_password(password) < 0) {
        printf("Please enter credentials with valid format\n");
        return -1;
    }

    return 0;
}

int ask_username(uint8_t* username) {
    printf("Enter username: ");
    fflush(stdout);
    if (!fgets((char*)username, CREDS_LEN, stdin))
        return -1;

    if (*username == '\n')
        return -1;

    char* end = strchr((char*)username, '\n');
    if (end == NULL) {
        while (getc(stdin) != '\n');
        return -1;
    }
    else
        username[end - (char*)username] = 0;

    size_t len = strlen((char*)username);
    return len;
}


int ask_password(uint8_t* password) {
    printf("Enter password: ");
    fflush(stdout);
    if (!fgets((char*)password, CREDS_LEN, stdin))
        return -1;

    if (*password == '\n')
        return -1;

    char* end = strchr((char*)password, '\n');
    if (end == NULL) {
        while (getc(stdin) != '\n');
        return -1;
    }
    else
        password[end - (char*)password] = 0;

    return strlen((char*)password);
}

int ask_metric(uint8_t* metric) {
    fflush(stdout);
    if (!fgets((char*)metric, CREDS_LEN, stdin))
        return -1;

    if (*metric == '\n')
        return -1;

    for (int i = 0; i < strlen((char*)metric); i++) {
        if (metric[i] == '\n')
            metric[i] = 0;
    }

    return *metric;
}

int ask_command(int socket, struct yap_parser* parser) {
    char cmd[COMMAND_LEN];
    printf("$> ");

    yap_parser_reset(parser);

    fflush(stdout);

    if (!fgets((char*)cmd, COMMAND_LEN, stdin))
        return -1;

    char* end = strchr((char*)cmd, '\n');
    if (end == NULL) {
        printf("Invalid command\n");
        handle_help();
        while (getc(stdin) != '\n');
        return 0;
    }
    else
        cmd[end - (char*)cmd] = 0;

    for (int i = 0; i < BUILTIN_TOTAL; i++) {
        if (!strcmp(builtin_names[i], cmd)) {
            builtin[i](socket);
            return 1;
        }
    }

    uint8_t command = 0;
    for (int i = 0; i < CMD_TOTAL; i++) {
        if (strcmp(commands[i], cmd) == 0) {
            command = i + 1;
            break;
        }
    }

    if (command == 0) {
        printf("Invalid command: %s\n", cmd);
        handle_help();
        return 0;
    }

    parser->command = 0;

    enum yap_result res = yap_parser_feed(parser, command);
    return print_response(parser, socket);
}



int print_response(struct yap_parser* parser, int socket) {
    switch (parser->state) {
    case YAP_STATE_USER:
        return print_user_list(socket, parser);

    case YAP_STATE_METRIC:
        return print_metric(socket, parser);

    case YAP_STATE_ADD_USER:
        return print_user_command(socket, parser);

    case YAP_STATE_REMOVE_USER:
        return print_user_command(socket, parser);

    case YAP_STATE_CONFIG:
        return print_config(socket, parser);
    }

    return -1;
}



int print_user_command(int socket, struct yap_parser* parser) {

    struct buffer buf;
    buffer_init(&buf, BUFF_SIZE * 2 + 3, 0);

    buffer_write(&buf, &parser->command);

    uint8_t username[BUFF_SIZE];
    printf("Enter username: ");
    handle_input(username);
    uint8_t username_len = strlen((char*)username);
    buffer_write(&buf, username_len);

    for (int i = 0; i < username_len; i++)
        buffer_write(&buf, username[i]);


    uint8_t password[BUFF_SIZE];
    printf("Enter password: ");
    handle_input(password);

    uint8_t password_len = strlen((char*)password);
    buffer_write(&buf, password_len);

    for (int i = 0; i < password_len; i++)
        buffer_write(&buf, password[i]);


    send(socket, buf.data, 3 + username_len + password_len, 0);

    printf("$> ");

    return 0;
}

int print_metric(int socket, struct yap_parser* parser) {
    handle_metrics();

    uint8_t* metric = malloc(BUFF_SIZE);

    ask_metric(metric);

    if (!strcmp((char*)metric, "hc"))
        parser->metric = YAP_METRIC_HISTORICAL_CONNECTIONS;
    else if (!strcmp((char*)metric, "cc"))
        parser->metric = YAP_METRIC_CONCURRENT_CONNECTIONS;
    else if (!strcmp((char*)metric, "bs"))
        parser->metric = YAP_METRIC_BYTES_SEND;
    else
        printf("Unknown command\n");

    free(metric);

    if (send_command(socket, parser) < 0) {
        return -1;
    }

    char* buffer = malloc(BUFF_SIZE);
    size_t bytes = read(socket, buffer, BUFF_SIZE);

    printf("Buffer: %x %x %x %x %x %x\n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);

    if (bytes == 0) {
        free(buffer);
        return -1;
    }

    char* buffer_ref = buffer;
    buffer++;

    int ret = -1;
    switch (*buffer) {
    case YAP_METRIC_HISTORICAL_CONNECTIONS:
        ret = print_historical_connections(buffer + 1);
        break;

    case YAP_METRIC_CONCURRENT_CONNECTIONS:
        ret = print_concurrent_connections(buffer + 1);
        break;

    case YAP_METRIC_BYTES_SEND:
        ret = print_bytes_sent(buffer + 1);
        break;
    default:
        printf("Error getting metric\n");
    }
    free(buffer_ref);
    return ret;
}

int print_historical_connections(char* buffer) {
    uint16_t val;
    memcpy(&val, buffer, sizeof(uint16_t));
    // return printf("Historical connections: %.*d\n", 2, TO_UINT16(buffer));
    return printf("Historical connections: %d\n", ntohs(val));

}

int print_concurrent_connections(char* buffer) {
    uint16_t val;
    memcpy(&val, buffer, sizeof(uint16_t));
    return printf("Concurrent connections: %.*s\n", 2, buffer);
}

int print_bytes_sent(char* buffer) {
    uint16_t val;
    memcpy(&val, buffer, sizeof(uint16_t));
    return printf("Bytes sent: %.*s\n", 2, buffer);
}

int print_user_list(int socket, struct yap_parser * parser) {

    printf("User list:\n");

    if (send_command(socket, parser) < 0) {
        return -1;
    }

    char* buffer = malloc(BUFF_SIZE);
    size_t bytes = read(socket, buffer, BUFF_SIZE);

    if (bytes == 0) {
        free(buffer);
        return -1;
    }

    char* buffer_ref = buffer;
    buffer++;

    int ret = -1;

    char* totalSize = buffer;
    int bytesAmount = atoi(totalSize);
    buffer++;
    for (int i = 0; i < bytesAmount;) {
        char * size = buffer;
        int userSize = atoi(size);
        buffer++;

        printf("Username:\t%.*s \n", userSize, buffer);
        i += userSize;
        //Avanzo la cant de chars q escribi (username)
        buffer = (buffer + userSize);
    }

    return 0;
}

int print_config(int socket, struct yap_parser * parser) {
    handle_config();

    uint8_t * config = malloc(BUFF_SIZE);
    uint8_t * config_value = malloc(BUFF_SIZE);

    ask_config(config, config_value);

    uint16_t config_value_int = atoi((char*)config_value);

    if (!strcmp((char*)config, "tout"))
        parser->config = YAP_CONFIG_TIMEOUTS;
    else if (!strcmp((char*)config, "bsize"))
        parser->config = YAP_CONFIG_BUFFER_SIZE;
    else{
        printf("Unknown config command\n");
        free(config);
        free(config_value);
        return 0;
    }

    parser->config_value = config_value_int;


    free(config);
    free(config_value);

    if (send_command(socket, parser) < 0) {
        printf("Failed in send\n");
        return -1;
    }

    char* buffer = malloc(BUFF_SIZE);
    size_t bytes = read(socket, buffer, BUFF_SIZE);

    if (bytes == 0) {
        free(buffer);
        return -1;
    }

    char* buffer_ref = buffer;
    buffer++;

    int ret = -1;
    switch (*buffer) {          
        case YAP_CONFIG_TIMEOUTS:
            switch (buffer[1]) {
            case 0:
                printf("Timeout was updated succesfully\n");
                ret = 0;
            case 1:
                printf("Could not update timeout\n");
                ret = -1;
            }

        case YAP_CONFIG_BUFFER_SIZE:
            switch (buffer[1]) {
            case 0:
                printf("Buffer size was updated succesfully\n");
                ret = 0;
            case 1:
                printf("Could not update buffer size\n");
                ret = -1;
            }
    }
    free(buffer_ref);
    return ret;
}

int ask_config(uint8_t * config, uint8_t * config_value) {
    fflush(stdout);
    uint8_t * buffer = malloc(BUFF_SIZE);
    if (!fgets((char*)buffer, BUFF_SIZE, stdin))
        return -1;

    if (*buffer == '\n')
        return -1;

    int found_cmd = 0;
    int i;
    int arg2_start = 0;
    int arg2_end = 0;
    uint8_t * arg1 = buffer, * arg2;
    int len = strlen((char*)buffer);
    for (i = 0; i < len; i++) {
        if (buffer[i] == ' '){
            buffer[i] = 0;
            arg2 = buffer+i+1;
            arg2_start = i+1;
            found_cmd++;
        }
        if (buffer[i] == '\n'){
            buffer[i] = 0;
            arg2_end = i;
            found_cmd++;
        }
    }

    strcpy((char*)config, (char*)arg1);

    strncpy((char*) config_value, (char*) arg1+arg2_start, arg2_end-arg2_start+1);

    if (found_cmd != 2)
        printf("\nPlease send your command as <command> <value>\n\n"); 

    free(buffer);
    return *config;
}


int send_credentials(int socket_fd, uint8_t* username, uint8_t* password) {
    uint8_t ulen = strlen((char*)username);
    uint8_t plen = strlen((char*)password);
    uint8_t version = 1;

    if (send(socket_fd, &version, 1, 0) <= 0)
        return -1;

    if (send(socket_fd, &ulen, 1, 0) <= 0)
        return -1;

    if (send_string(socket_fd, ulen, username) < 0)
        return -1;

    if (send(socket_fd, &plen, 1, 0) <= 0)
        return -1;

    if (send_string(socket_fd, plen, password) < 0)
        return -1;

    return 0;
}


int send_string(uint8_t socket_fd, uint8_t len, uint8_t* array) {
    while (len > 0) {
        int ret;
        if ((ret = send(socket_fd, array, len, 0)) <= 0)
            return -1;
        len -= ret;
        array += ret;
    }
    return 0;
}

int send_command(int sock_fd, struct yap_parser* parser) {
    if (send(sock_fd, &parser->command, 1, 0) < 0)
        return -1;


    int res = -1;
    switch (parser->command) {
        case YAP_COMMANDS_USERS:
            res = 0;
            break;
        case YAP_COMMANDS_METRICS:
            res = send(sock_fd, &parser->metric, 1, 0);
            // res = send(sock_fd, &parser->metric, 1, 0);
            break;
        case YAP_COMMANDS_ADD_USER:
            res = send(sock_fd, &parser->username, parser->username_length, 0);
            if (res < 0)
                break;
            res = send(sock_fd, &parser->password, parser->password_length, 0);
            break;
        case YAP_COMMANDS_REMOVE_USER:
            res = send(sock_fd, &parser->username, parser->username_length, 0);
            if (res < 0)
                break;
            res = send(sock_fd, &parser->password, parser->password_length, 0);
            break;
        case YAP_COMMANDS_CONFIG:
            res = send(sock_fd, &parser->config, 1, 0);
            if (res < 0)
                break;
            uint16_t toSend = htons(parser->config_value);
            res = send(sock_fd, &toSend, 2, 0);
    }

    if (res < 0)
        return -1;

    return 0;
}

static int send_array(uint8_t socket_fd, uint8_t len, uint8_t* array) {
    while (len > 0) {
        int ret;
        if ((ret = send(socket_fd, array, len, 0)) <= 0)
            return -1;
        len -= ret;
        array += ret;
    }
    return 0;
}


void print_status(uint16_t status) {
    if (status == 0xC001)
        print_welcome();
    else if (status == 0x4B1D)
        printf("Invalid credentials, please try again");
    else {
        printf("Please enter valid credentials");
    }
}


int close_connection(int socket_fd) {
    printf("Closing connection...\n");
    return close(socket_fd);
}

void print_welcome() {
    printf("\n===========================================================\n");
    printf("Welcome to sock5 proxy configuration.\n\n");
    printf("Enter \"help\" in the command prompt to see the posible configuration commands.\n");
    printf("Enter \"quit\" in the command prompt to terminate the session.\n");
    printf("===========================================================\n");
}


void handle_help() {
    printf("\nList of supported commands:\n");
    for (int i = 0; i < CMD_TOTAL; i++)
        printf("%s\n", cmd_description[i]);
}

void handle_input(uint8_t* input) {
    fflush(stdin);
    fgets((char*)input, BUFF_SIZE, stdin);
    clean_input(input);
    printf("\n");
    printf("$> ");

}

void clean_input(uint8_t* string) {
    for (int i = 0; i < strlen((char*)string); i++) {
        if (string[i] == '\n')
            string[i] = 0;
    }
}

void handle_metrics() {
    printf("\nList of supported metrics:\n");
    for (int i = 0; i < METRICS_TOTAL; i++)
        printf("%s\n", available_metrics[i]);
    printf("\nSend your command as <command>\n\n");
    printf("(metric) ");
}

void handle_config() {
    printf("\nList of supported configurations:\n");
    for (int i = 0; i < CONFIG_TOTAL; i++)
        printf("%s\n", available_config[i]);
    printf("\nSend your command as <command> <value>\n\n");
    printf("(config) ");
}

void handle_quit(int sock_fd) {
    close_connection(sock_fd);
    exit(0);
}
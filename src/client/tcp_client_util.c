#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "utils/logger/logger.h"
#include "utils/util.h"
#include "client/tcp_client_util.h"

char * commands[] = {"ul", "m", "au", "ru", "c"};
char * cmd_description[] = {
    "ul - Get User List",
    "m  - Select from a list of metrics",
    "au - Add User",
    "ru - Remove User",
    "c  - Select from a list of configurations"
};

char * builtin_names[] = {"help", "quit"};
void (*builtin[])(int) = {handle_help, handle_quit};


int connect_to_ipv4(struct sockaddr_in * ipv4_address, unsigned short port , char * address){
    int sock_fd = socket(AF_INET , SOCK_STREAM , 0);
    if(sock_fd < 0)
        return -1;

    memset(ipv4_address, 0, sizeof(*ipv4_address));
    ipv4_address->sin_family = AF_INET;
    ipv4_address->sin_port = htons(port);
    inet_pton(AF_INET, address, &ipv4_address->sin_addr.s_addr);

    if(connect(sock_fd, (struct sockaddr *) ipv4_address, sizeof(*ipv4_address)) < 0){
        printf("Unable to connect IPv4\n");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

int connect_to_ipv6(struct sockaddr_in6 * ipv6_address, unsigned short port,char * address){
    int sock_fd = socket(AF_INET6, SOCK_STREAM , 0);
    if(sock_fd < 0)
        return -1;

    ipv6_address->sin6_family = AF_INET6;
    ipv6_address->sin6_flowinfo = 0;
    ipv6_address->sin6_scope_id = 0;
    inet_pton(AF_INET6, address, &ipv6_address->sin6_addr);
    ipv6_address->sin6_port= htons(port);

    if(connect(sock_fd, (struct sockaddr *) ipv6_address, sizeof(*ipv6_address)) < 0){
        printf("Unable to connect IPv6\n");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}


int ask_credentials(uint8_t * username, uint8_t * password){
    if(ask_username(username) < 0){
        printf("Please enter credentials with valid format\n");
        return -1;
    }

    if(ask_password(password) < 0){
        printf("Please enter credentials with valid format\n");
        return -1;
    }

    return 0;
}

int ask_username(uint8_t * username){
    printf("Enter username: ");
    fflush(stdout);
    if(!fgets((char *) username, CREDS_LEN, stdin))
        return -1;

    if(*username == '\n')
        return -1;
        
    char * end = strchr((char *) username, '\n');
    if(end == NULL){
        while(getc(stdin) != '\n');
        return -1;
    }
    else
        username[end-(char *) username] = 0; 

    size_t len = strlen((char *) username);
    return len;
}


int ask_password(uint8_t * password){
    printf("Enter password: ");
    fflush(stdout);
    if(!fgets((char *) password, CREDS_LEN, stdin))
        return -1;

    if(*password == '\n')
        return -1;

    char * end = strchr((char *) password, '\n');
    if(end == NULL){
        while(getc(stdin) != '\n');
        return -1;
    }
    else
        password[end-(char *) password] = 0; 

    return strlen((char *) password);
}

int ask_command(int socket, struct yap_parser * parser){
    char cmd[COMMAND_LEN];
    printf("$> ");

    fflush(stdout);

    if(!fgets((char *) cmd, COMMAND_LEN, stdin))
        return -1;

    char * end = strchr((char *) cmd, '\n');
    if(end == NULL){
        printf("Invalid command\n");
        handle_help(socket);
        while(getc(stdin) != '\n');
        return 0;
    }
    else
        cmd[end-(char *) cmd] = 0; 

    for(int i = 0; i < BUILTIN_TOTAL; i++){
        if(!strcmp(builtin_names[i], cmd)){
            builtin[i](socket);
            return 0;
        }
    }

    uint8_t command = 0;
    for(int i = 0; i < CMD_TOTAL; i++){
        if(strcmp(commands[i], cmd) == 0){
            command = i+1;
            break;
        }
    }

    if(command == 0){
        printf("Invalid command: %s\n", cmd);
        handle_help(socket);
        return 0;
    }

    parser->command = 0;

    enum yap_result res = yap_parser_feed(parser, command);
    print_response(parser, socket);


    return 0;
}



int print_response(struct yap_parser * parser, int socket){
    switch(parser->state){
        case YAP_STATE_USER:
            return print_user_list(socket);

        case YAP_STATE_METRIC:
            return print_metric(socket); 
            
        case YAP_STATE_ADD_USER:
            return print_added_user(parser);

        case YAP_STATE_REMOVE_USER:
            return print_removed_user(parser);

        case YAP_STATE_CONFIG:
            return print_config(socket);
        }
    return -1;
}

int print_added_user(struct yap_parser * parser){
    return ntohs(printf("Added user: %s\n", parser->username));
}

int print_removed_user(struct yap_parser * parser){
    return ntohs(printf("Removed user: %s\n", parser->username));
}


int print_metric(int socket){
    printf("Entered metrics\n");
    char * buffer = malloc(BUFF_SIZE);
    size_t bytes = read(socket, buffer, BUFF_SIZE);
    if (bytes == 0)
        return -1;
    buffer++;

    switch(htons(buffer[0])){
        case YAP_METRIC_HISTORICAL_CONNECTIONS:
            return ntohs(print_historical_connections(buffer));

        case YAP_METRIC_CONCURRENT_CONNECTIONS:
            return ntohs(print_concurrent_connections(buffer));

        case YAP_METRIC_BYTES_SEND:
            return ntohs(print_bytes_sent(buffer));
    }
    return -1;
}

int print_historical_connections(char* buffer){
    return printf("Historical connections: %.*s\n", 2, buffer);
}

int print_concurrent_connections(char* buffer){
    return printf("Concurrent connections: %.*s\n", 2, buffer);
}

int print_bytes_sent(char* buffer){
    return printf("Bytes sent: %.*s\n", 2, buffer);
}

int print_user_list(int socket){

    printf("Entered user list\n");

    struct yap_parser * parser = yap_parser_init();

    // enum yap_result res = yap_parser_consume(cmd, parser);
    // while(res == YAP_PARSER_NOT_FINISHED){
    //     res = yap_parser_consume(1, parser);
    // }
    

    // if (res == YAP_PARSER_ERROR){
    //     close_connection(sock);
    //     exit_status = -1;
    //     goto finish;
    // }
    char * buffer = malloc(BUFF_SIZE);

    size_t bytes = read(socket, buffer, BUFF_SIZE);

    if (bytes == 0)
        return -1;

        
    buffer++;
    char * totalSize = &buffer[0];
    int bytesAmount = atoi(totalSize);
    buffer++;
    for(int i=0; i<bytesAmount;){
        char * size = &buffer[0];
        int userSize = atoi(size);
        buffer++;

        printf("Username:\t%.*s \n", userSize, buffer);
        i+=userSize;
        //Avanzo la cant de chars q escribi (username)
        buffer = (buffer + userSize);
    }

    return 0;
}

int print_config(int socket){
    printf("Entered print config\n");
    char * buffer = malloc(BUFF_SIZE);
    size_t bytes = read(socket, buffer, BUFF_SIZE);
    if (bytes == 0)
        return -1;
    buffer++;

    switch(htons(buffer[0])){
        case YAP_CONFIG_TIMEOUTS:
            switch (buffer[1]){
                case 0:
                    return ntohs(printf("Timeout was updated succesfully\n"));
                case 1:
                    return ntohs(printf("Could not update timeout\n"));
            }

        case YAP_CONFIG_BUFFER_SIZE:
            switch (buffer[1]){
                case 0:
                    return ntohs(printf("Buffer size was updated succesfully\n"));
                case 1:
                    return ntohs(printf("Could not update buffer size\n"));
            }
    }
    return -1;
}


int send_credentials(int socket_fd, uint8_t * username, uint8_t * password){
    uint8_t ulen = strlen((char *) username);
    uint8_t plen = strlen((char *) password);
    uint8_t version = 1;

    if(send(socket_fd, &version, 1, 0) <= 0)
        return -1;

    if(send(socket_fd, &ulen, 1, 0) <= 0)
        return -1;
    
    if(send_string(socket_fd, ulen, username) < 0)
        return -1;
        
    if(send(socket_fd, &plen, 1, 0) <= 0)
        return -1;

    if(send_string(socket_fd, plen, password) < 0)
        return -1;

    return 0;
}


int send_string(uint8_t socket_fd, uint8_t len, uint8_t * array){
    while(len > 0){
        int ret;
        if((ret = send(socket_fd, array, len, 0)) <= 0)
            return -1;
        len -= ret;
        array += ret;
    } 
    return 0;
}

void print_status(uint16_t status){
    if(status == 0xC001)
        print_welcome();
    else if(status == 0x4B1D)
        printf("Invalid credentials, please try again");
    else{
        printf("Please enter valid credentials");
    }
}


int close_connection(int socket_fd){
    printf("Closing connection...\n");
    return close(socket_fd);
}

void print_welcome(){
    printf("\n===========================================================\n");
    printf("Welcome to sock5 proxy configuration.\n\n");
    printf("Enter \"help\" in the command prompt to see the posible configuration commands.\n");
    printf("Enter \"quit\" in the command prompt to terminate the session.\n");
    printf("===========================================================\n");
}


void handle_help(int sock_fd){
    printf("List of supported commands:\n");
    for(int i = 0; i < CMD_TOTAL; i++)
        printf("%s\n", cmd_description[i]);
}

void handle_quit(int sock_fd){
    close_connection(sock_fd);
    exit(0);
}
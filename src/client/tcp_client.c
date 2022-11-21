#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#include "utils/logger/logger.h"
#include "client/tcp_client_util.h"
#include "client/conf.h"

int main(int argc, char* argv[]) {
    int exit_status = 0;
    char* err_msg, * success_msg = "OK!\n";
    tcp_conf conf = {
        .port = 1080, // default port
        .version = 4, //default version
    };
    
    int tries=0;
    uint16_t status = FAILED_AUTH;
    uint8_t username[CREDS_LEN] = {0}, password[CREDS_LEN] = {0};

    struct yap_parser * parser = yap_parser_init();


    if (!parse_conf(argc, argv, &conf)) {
        err_msg = "Error parsing configuration from arguments";
        exit_status = 1;
    }

    int sock;
    struct sockaddr_in6 ipv6_address;
    struct sockaddr_in ipv4_address;
    unsigned short port = conf.port;

    if (conf.version == 6 ){
        printf("Connecting to IPv6\n");
        sock = connect_to_ipv6(&ipv6_address, port, conf.addr);
    }
    else{
        printf("Connecting to IPv4\n");
        sock = connect_to_ipv4(&ipv4_address, port, conf.addr);
    }
    
    if(sock < 0){
        exit_status = -1;
        goto finish;
    }

    printf("Successfully connected\n");

    while(status != SUCCESS_AUTH){

        //TODO mandar credenciales al servidor
        if(ask_credentials(username, password) < 0)
            continue;

        if(tries++ >= MAX_AUTH_TRIES){
            printf("Max number of tries reached\n");
            exit_status = -1;
            close_connection(sock);
            goto finish;
        }

        if(send_credentials(sock, username, password) < 0){
            close_connection(sock);
            exit_status = -1;
            goto finish;
        }

        status = SUCCESS_AUTH;

        putchar('\n');
    }

    status = CONNECTED;

    print_welcome();


    while (status == CONNECTED){

        if(ask_command(sock, parser) < 0){
            close_connection(sock);
            exit_status = -1;
            goto finish;
        }
    }

finish:    
            yap_parser_free(parser);


    return exit_status;
}
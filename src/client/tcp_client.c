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
        .addr = "127.0.0.1", // default address
        .port = "8080", // default port
        .version = 4, //default version
    };
    struct sockaddr_in6 ipv6_address;
    struct sockaddr_in ipv4_address;
    char * addr = (char *)conf.addr;
    int version = conf.version;
    unsigned short port = (unsigned short) atoi(conf.port);
    int tries=0;
    uint16_t status = 0;
    uint8_t username[CREDS_LEN] = {0}, password[CREDS_LEN] = {0};
    int sock;

    buffer * cmd = malloc(sizeof(buffer*));
    cmd->data = malloc(sizeof(uint8_t)*BUFF_SIZE);

    if (!parse_conf(argc, argv, &conf)) {
        err_msg = "Error parsing configuration from arguments";
        exit_status = 1;
    }

    if(version == 4)
        sock = connect_to_ipv4(&ipv4_address, port, addr);
    else if (version == 6 )
        sock = connect_to_ipv6(&ipv6_address, port, addr);
    else{
        printf("You should enter the version as: 4 for ipv4 or 6 for ipv6.\n");
        return -1;
    }
    
    if(sock < 0)
        return -1;


    /*
        read al socket
                primer byte cantidad de bytes a leer

    */


    while(status != SUCCESS_AUTH){

        if(ask_credentials(username, password) < 0)
            continue;

        if(tries++ >= MAX_AUTH_TRIES){
            printf("Max number of tries reached\n");
            return close_connection(sock);
        }

        if(send_credentials(sock, username, password) < 0){
            close_connection(sock);
            return -1;
        }

        struct yap_parser * parser = yap_parser_init();

        enum yap_result res = yap_parser_consume(cmd, parser);

        print_response(cmd->data, parser, sock);

        free(parser);

        putchar('\n');
    }

    free(cmd->data);
    free(cmd);

    return 0;
}
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

    int tries = 0;
    uint16_t status = FAILED_AUTH;
    uint8_t username[CREDS_LEN] = { 0 }, password[CREDS_LEN] = { 0 };

    struct yap_parser* parser = yap_parser_init();


    if (!parse_conf(argc, argv, &conf)) {
        err_msg = "Error parsing configuration from arguments";
        exit_status = 1;
    }

    int sock;
    struct sockaddr_in6 ipv6_address;
    struct sockaddr_in ipv4_address;
    unsigned short port = conf.port;

    while (status != SUCCESS_AUTH) {

        if (conf.version == 6) {
            printf("Connecting to IPv6\n");
            sock = connect_to_ipv6(&ipv6_address, port, conf.addr);
        }
        else {
            printf("Connecting to IPv4\n");
            sock = connect_to_ipv4(&ipv4_address, port, conf.addr);
        }

        if (sock < 0) {
            exit_status = -1;
            goto finish;
        }

        printf("Successfully connected\n");  // TODO: remove

        if (ask_credentials(username, password) < 0)
            continue;

        if (tries++ >= MAX_AUTH_TRIES) {
            printf("Max number of tries reached\n");
            exit_status = -1;
            close_connection(sock);
            goto finish;
        }

        if (send_credentials(sock, username, password) < 0) {
            close_connection(sock);
            exit_status = -1;
            goto finish;
        }

        const size_t server_response_size = 2;
        uint8_t buff[server_response_size];

        errno = 0;
        int bytes_read = read(sock, buff, server_response_size);
        if (bytes_read == -1) {
            fprintf(stderr, "Could not read response from server: %s", strerror(errno));
            close_connection(sock);
            exit_status = -1;
            goto finish;
        }

        status = buff[1];
        printf("Status: %d", status); // TODO: remove

        putchar('\n');
    }

    status = CONNECTED;

    print_welcome();


    while (status == CONNECTED) {

        if (ask_command(sock, parser) < 0) {
            close_connection(sock);
            exit_status = -1;
            goto finish;
        }
    }


    // SOCKS Request _ AGUS

    struct yap_negociation_parser* n_parser = yap_negociation_parser_init();
    char* buffer = malloc(BUFF_SIZE);
    uint16_t n_status = AUTH_FAIL;
    n_conf n_config = {
        .port = 1080, // default port
        .version = 5, //default version
    };

    if (!n_parse_conf(argc, argv, &n_config)) {
        err_msg = "Error parsing configuration from arguments";
        exit_status = 1;
    }
    // uint8_t buffer[BUFF_SIZE];

    // while(n_status != AUTH_SUCCESS){  
    //     int bytes_read = read(sock, buffer, BUFF_SIZE);
    //     if (bytes_read == -1) {
    //         fprintf(stderr, "Could not read response from server: %s", strerror(errno));
    //         close_connection(sock);
    //         goto finish;
    //     }

    //     n_status = buff[1];
    // }

finish:
    yap_parser_free(parser);
    negotiation_parser_free(n_parser);

    return exit_status;
}
#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#include "utils/logger/logger.h"
#include "client/tcp_client_util.h"
#include "client/conf.h"
#include "utils/parser/yap_negociation.h"

int main(int argc, char* argv[]) {
    int exit_status = 0;
    char* success_msg = "OK!\n";
    tcp_conf conf = {
        .addr = "127.0.0.1",
        .port = 8080, // default port
        .version = 4, //default version
    };

    struct negotiation_parser n_config = {
            .version = 5, //default version
    };

    int tries = 0;
    uint16_t status = FAILED_AUTH;
    uint8_t username[CREDS_LEN] = { 0 }, password[CREDS_LEN] = { 0 };

    int protocol = ask_protocol(argc, argv);


    struct yap_parser* parser = yap_parser_init();
    struct n_conf* n_parser = malloc(sizeof(struct n_conf));
    struct pop3_parser* pop3_parser = pop3_parser_init();
    struct auth_negociation_parser* auth_parser = auth_negociation_parser_init();

    int sock_fd;
    struct sockaddr_in6 ipv6_address;
    struct sockaddr_in ipv4_address;
    unsigned short port = conf.port;


    if (protocol == YAP) {
        if (!parse_conf(argc, argv, &conf)) {
            printf("Error parsing configuration from arguments");
            exit_status = 1;
            goto finish;
        }

        if (conf.version == 6) {
            printf("Connecting to IPv6\n");
            sock_fd = connect_to_ipv6(&ipv6_address, port, conf.addr);
        }
        else {
            printf("Connecting to IPv4\n");
            sock_fd = connect_to_ipv4(&ipv4_address, port, conf.addr);
        }

        if (sock_fd < 0) {
            exit_status = -1;
            goto finish;
        }

        printf("Successfully connected\n");

        while (status != SUCCESS_AUTH) {

            if (ask_credentials(username, password) < 0)
                continue;

            if (tries++ >= MAX_AUTH_TRIES) {
                printf("Max number of tries reached\n");
                exit_status = -1;
                close_connection(sock_fd);
                goto finish;
            }

            if (send_credentials(sock_fd, username, password) < 0) {
                close_connection(sock_fd);
                exit_status = -1;
                goto finish;
            }

            const size_t server_response_size = 2;
            uint8_t buff[server_response_size];

            errno = 0;
            int bytes_read = read(sock_fd, buff, server_response_size);
            if (bytes_read == -1) {
                fprintf(stderr, "Could not read response from server: %s", strerror(errno));
                close_connection(sock_fd);
                exit_status = -1;
                goto finish;
            }

            status = buff[1];
            printf("Invalid credentials. Please try again\n");

            putchar('\n');
        }

        status = CONNECTED;

        print_welcome();


        while (status == CONNECTED) {

            if (ask_command_yap(sock_fd, parser) < 0) {
                close_connection(sock_fd);
                exit_status = -1;
                goto finish;
            }
        }
    }
    else {

        if (!n_parse_conf(argc, argv, &n_config, auth_parser, &port)) {
            printf("Error parsing configuration from arguments");
            exit_status = 1;
            goto finish;
        }

        sock_fd = connect_to_ipv4(&ipv4_address, port, conf.addr);

        if (sock_fd < 0) {
            exit_status = -1;
            goto finish;
        }

        uint8_t to_send[] = { 5, 1, 2 };

        char* buff = malloc(BUFF_SIZE);

        if (send(sock_fd, &to_send, 3, 0) <= 0)
            return -1;

        size_t bytes = read(sock_fd, buff, BUFF_SIZE);

        free(buff);

        if (send_socks_credentials(sock_fd, auth_parser) < 0) {
            close_connection(sock_fd);
            exit_status = -1;
            goto finish;
        }


        status = CONNECTED;

        print_socks_welcome_msg();

        while (status == CONNECTED) {
            if (ask_command_socks(sock_fd, n_parser) < 0) {
                close_connection(sock_fd);
                exit_status = -1;
                goto finish;
            }
        }
    }

finish:
    yap_parser_free(parser);
    free(n_parser);
    pop3_parser_free(pop3_parser);
    auth_negociation_parser_free(auth_parser);

    return exit_status;
}
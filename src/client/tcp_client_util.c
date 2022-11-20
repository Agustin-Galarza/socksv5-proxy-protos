#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "utils/logger/logger.h"
#include "utils/util.h"
#include "client/tcp_client_util.h"

#define MAX_ADDR_BUFFER 128
#define BUFFSIZE MAX_RESPONSE_LEN

static char response_buf[BUFFSIZE];
static char request_buf[BUFFSIZE];
static const char* commands_format[] = {
    "CAP\r\n",
    "TOKEN %s\r\n",
    "STATS\r\n",
    "USERS\r\n",
    "BUFFSIZE\r\n",
    "SET-BUFFSIZE %s\r\n", // Server parse the number
    "ADD-USER %s\r\n",
};

static bool
finished(char* buff, bool multiline);

int tcpClientSocket(const char* host, const char* service) {
    char addrBuffer[MAX_ADDR_BUFFER];
    struct addrinfo addrCriteria;                   // Criteria for address match
    memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
    addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
    addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
    addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

    // Get address(es)
    struct addrinfo* servAddr; // Holder for returned list of server addrs
    int rtnVal = getaddrinfo(host, service, &addrCriteria, &servAddr);
    if (rtnVal != 0) {
        log_error("getaddrinfo() failed %s", gai_strerror(rtnVal));
        return -1;
    }

    int sock = -1;
    for (struct addrinfo* addr = servAddr; addr != NULL && sock == -1; addr = addr->ai_next) {
        // Create a reliable, stream socket using TCP
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock >= 0) {
            errno = 0;
            // Establish the connection to the server
            if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
                log_info("can't connect to %s: %s", printAddressPort(addr, addrBuffer), strerror(errno));
                close(sock); 	// Socket connection failed; try next address
                sock = -1;
            }
        }
        else {
            log_debug("Can't create client socket on %s", printAddressPort(addr, addrBuffer));
        }
    }

    freeaddrinfo(servAddr);
    return sock;
}

/*
 * Returns true if answer could be read.
 * Returns false if an error occured.
 */
static bool
get_response(int sock, char* buff, size_t len, bool multiline) {
    char* write_ptr = buff;
    do {
        uint8_t bytes_read = read(sock, write_ptr, len - (write_ptr - buff));
        if (bytes_read <= 0) {
            log_error("Error while reading answer");
            return false;
        }
        write_ptr += bytes_read;
        *write_ptr = '\0';
    } while (!finished(buff, multiline));
    return true;
}

// - -> error
// \r\n -> fin de linea
// \r\n.\r\n -> fin de comando

/*
 * buff is expected to hold a null terminated string
 */
static bool
finished(char* buff, bool multiline) {
    if (buff[0] == '-') //Errors are one line
        multiline = false;
    return strstr(buff, (multiline) ? EOM : EOL) != NULL;
}

bool read_hello(int sock) {
    if (!get_response(sock, response_buf, BUFFSIZE, false)) {
        return false;
    }

    if (response_buf[0] == '-') {
        return false;
    }

    log_debug("Connection successful. Server is now ready.");

    return true;
}

static bool
send_text(int sock, const char* text) {
    return send(sock, text, strlen(text), MSG_DONTWAIT) >= 0;
}

static void
simple_iteration(const char* buffer, const char* line_header) {
    char* tok = strtok(response_buf, EOL);
    tok = strtok(NULL, EOL); // All multiline responses begin with the line '+OK [...]'
    int i = 0;
    while (tok != NULL && tok[0] != '.') { // All multiline responses end with the line '.'
        log_info("%s #%d: %s\n", line_header, i++, tok);
        tok = strtok(NULL, EOL);
    }
}

bool capabilities(int sock) {
    if (!send_text(sock, commands_format[CMD_CAP])) {
        return false;
    }

    if (!get_response(sock, response_buf, BUFFSIZE, true)) {
        return false;
    }

    if (response_buf[0] == '-') {
        log_error("Error running CAP: %s\n", response_buf);
        return false;
    }

    log_info("----------------------------");

    log_info("List of capabilities:\n");
    simple_iteration(response_buf, "CAP");

    log_info("----------------------------");
    putchar('\n');

    return true;
}

bool authenticate(int sock, const char* token) {
    snprintf(request_buf, BUFFSIZE, commands_format[CMD_TOKEN], token);
    if (!send_text(sock, request_buf)) {
        return false;
    }

    if (!get_response(sock, response_buf, BUFFSIZE, false)) {
        return false;
    }

    if (response_buf[0] == '-') {
        return false;
    }

    log_info("Authentication with token: \"%s\" successful\n", token);
    return true;
}

bool stats(int sock) {
    if (!send_text(sock, commands_format[CMD_STATS])) {
        return false;
    }

    if (!get_response(sock, response_buf, BUFFSIZE, true)) {
        return false;
    }

    if (response_buf[0] == '-') {
        log_error("Error running STATS: %s\n", response_buf);
        return false;
    }

    log_info("----------------------------");

    log_info("List of statistics:\n");
    char* tok = strtok(response_buf, EOL);
    tok = strtok(NULL, EOL);
    while (tok != NULL && tok[0] != '.') {
        unsigned long long int stat = strtoull(tok + 1, NULL, 10);
        switch (tok[0]) {
        case 'B':
            log_info("Bytes transferred: %llu\n", stat);
            break;
        case 'H':
            log_info("Historical connections: %llu\n", stat);
            break;
        case 'C':
            log_info("Concurrent connections: %llu\n", stat);
            break;
        }
        tok = strtok(NULL, EOL);
    }

    log_info("----------------------------");
    putchar('\n');

    return true;
}

bool users(int sock) {
    if (!send_text(sock, commands_format[CMD_USERS])) {
        return false;
    }

    if (!get_response(sock, response_buf, BUFFSIZE, true)) {
        return false;
    }

    if (response_buf[0] == '-') {
        log_error("Error running USERS: %s\n", response_buf);
        return false;
    }

    log_info("----------------------------");

    log_info("List of users:\n");
    simple_iteration(response_buf, "USER");

    log_info("----------------------------");
    putchar('\n');

    return true;
}

bool buffsize(int sock) {
    if (!send_text(sock, commands_format[CMD_BUFFSIZE])) {
        return false;
    }

    if (!get_response(sock, response_buf, BUFFSIZE, true)) {
        return false;
    }

    if (response_buf[0] == '-') {
        log_error("Error running BUFFSIZE: %s\n", response_buf);
        return false;
    }

    log_info("----------------------------");

    char* tok = strtok(response_buf, EOL);
    tok = strtok(NULL, EOL);
    unsigned long long int buff_size = strtoull(tok, NULL, 10);
    log_info("Current size of the buffer: %llu\n", buff_size);

    log_info("----------------------------");
    putchar('\n');

    return true;
}


bool set_buffsize(int sock, const char* size) {
    snprintf(request_buf, BUFFSIZE, commands_format[CMD_SET_BUFFSIZE], size);
    if (!send_text(sock, request_buf)) {
        return false;
    }

    if (!get_response(sock, response_buf, BUFFSIZE, false)) {
        return false;
    }

    if (response_buf[0] == '-') {
        log_error("Error running SET-BUFFSIZE: %s\n", response_buf);
        return false;
    }

    log_info("----------------------------");

    log_info("Buffer size updated to %s\n", size);

    log_info("----------------------------");
    putchar('\n');

    return true;
}


bool add_user(int sock, const char* username_password) {
    snprintf(request_buf, BUFFSIZE, commands_format[CMD_ADD_USER], username_password);
    if (!send_text(sock, request_buf)) {
        return false;
    }

    if (!get_response(sock, response_buf, BUFFSIZE, false)) {
        return false;
    }

    if (response_buf[0] == '-') {
        log_error("Error running ADD-USER: %s\n", response_buf);
        return false;
    }

    log_info("----------------------------");

    log_info("Successfully added user to the list of users.\n");

    log_info("----------------------------");
    putchar('\n');

    return true;
}

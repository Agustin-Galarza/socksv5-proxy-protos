/* Basado en findsrv.c del libro de Stevens */

#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include "utils/logger/logger.h"
#include "utils/util.h"

// int
// main(int argc, char* argv[]) {
//     struct addrinfo* ailist, * aip;
//     struct addrinfo		hint;
//     int 			err;
//     char* service;
//     char* addrString;
//     char 	addr[64];

//     if (argc < 2)
//         log_error("usage: %s host [service]", argv[0]);
//     if (argc >= 3)
//         service = argv[2];
//     else
//         service = NULL;

//     addrString = argv[1];

//     memset(&hint, 0, sizeof(hint));
//     hint.ai_flags = AI_CANONNAME;
//     if ((err = getaddrinfo(addrString, service, &hint, &ailist)) != 0)
//         log_error("getaddrinfo error: %s", gai_strerror(err));
//     for (aip = ailist; aip != NULL; aip = aip->ai_next) {
//         printFlags(aip);
//         printf(" family: %s ", printFamily(aip));
//         printf(" type: %s ", printType(aip));
//         printf(" protocol %s ", printProtocol(aip));
//         printf("\n\thost %s", aip->ai_canonname ? aip->ai_canonname : "-");
//         printf("address: %s", printAddressPort(aip, addr));
//         putchar('\n');
//     }
//     freeaddrinfo(ailist);
//     return 0;
// }

#ifndef NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U
#define NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U

#include <netinet/in.h>
#include <sys/socket.h>

#include "utils/buffer.h"

#define MAX_PORT_STR_LEN 6

#define SOCKADDR_TO_HUMAN_MIN (INET6_ADDRSTRLEN + 5 + 1)
/**
 * Describe de forma humana un sockaddr:
 *
 * @param buff     el buffer de escritura
 * @param buffsize el tamaño del buffer  de escritura
 *
 * @param af    address family
 * @param addr  la dirección en si
 * @param nport puerto en network byte order
 *
 */
const char*
sockaddr_to_human(char* buff, const size_t buffsize,
                  const struct sockaddr* addr);

/**
 * Escribe n bytes de buff en fd de forma bloqueante
 *
 * Retorna 0 si se realizó sin problema y errno si hubo problemas
 */
int sock_blocking_write(const int fd, buffer* b);

/**
 * copia todo el contenido de source a dest de forma bloqueante.
 *
 * Retorna 0 si se realizó sin problema y errno si hubo problemas
 */
int sock_blocking_copy(const int source, const int dest);

/**
 * Consigue la dirección de un socket en base a su file descriptor
 */
struct sockaddr get_socket_addr(int socket_descriptor);

/**
 * Castea el número de puerto port a string en portstr y lo retorna.
 * En caso de error deja portstr como string vacío y retorna NULL
 */
char* port_itoa(uint16_t port, char portstr[MAX_PORT_STR_LEN]);

#endif

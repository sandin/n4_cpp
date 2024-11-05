#ifndef N4_CPP_SOCKET_H_
#define N4_CPP_SOCKET_H_

#include <sys/socket.h>
#include <sys/types.h>

int socket_addr_setport(struct sockaddr *sa, socklen_t salen, unsigned short port);

int socket_addr_from_ipv4(struct sockaddr_in *addr4, socklen_t *addr2_len, const char *ipv4_or_dns,
                          unsigned short port);

int64_t socket_poll_read(int s[], int n, int timeout);

int socket_setnonblock(int sock, int noblock);

int create_tcp_socket(const char *server_ip, int server_port, bool is_server = false,
                      bool nonblock = false);
int create_tcp_server_socket(const char *server_ip, int server_port, bool nonblock = false);
int create_udp_socket(const char *local_ip, int local_port, bool nonblock = false);

#endif  // N4_CPP_SOCKET_H_
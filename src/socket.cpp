
#include "socket.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>

#include "log.h"

int socket_addr_setport(struct sockaddr *sa, socklen_t salen, unsigned short port) {
  if (AF_INET == sa->sa_family) {
    struct sockaddr_in *in = (struct sockaddr_in *)sa;
    assert(sizeof(struct sockaddr_in) == salen);
    in->sin_port = htons(port);
  } else {
    assert(0);
    return -1;
  }

  return 0;
}

int socket_addr_from_ipv4(struct sockaddr_in *addr4, socklen_t *addr2_len, const char *ipv4_or_dns,
                          unsigned short port) {
  int r;
  char portstr[16];
  struct addrinfo hints, *addr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  //	hints.ai_flags = AI_ADDRCONFIG;
  snprintf(portstr, sizeof(portstr), "%u", (unsigned int)port);
  r = getaddrinfo(ipv4_or_dns, portstr, &hints, &addr);
  if (0 != r) return r;

  // fixed ios getaddrinfo don't set port if node is ipv4 address
  socket_addr_setport(addr->ai_addr, (socklen_t)addr->ai_addrlen, port);
  assert(sizeof(struct sockaddr_in) == addr->ai_addrlen);
  memcpy(addr4, addr->ai_addr, addr->ai_addrlen);
  *addr2_len = addr->ai_addrlen;
  freeaddrinfo(addr);
  return 0;
}

int64_t socket_poll_read(int s[], int n, int timeout) {
  int i;
  int64_t r;

  int j;
  struct pollfd fds[64];
  assert(n <= 64);
  for (j = i = 0; i < n && i < 64; i++) {
    if (-1 == s[i]) continue;
    fds[j].fd = s[i];
    fds[j].events = POLLIN;
    fds[j].revents = 0;
    j++;
  }

  r = poll(fds, j, timeout);
  while (-1 == r && (EINTR == errno || EAGAIN == errno)) r = poll(fds, j, timeout);

  for (r = i = 0; i < n && i < 64; i++) {
    if (-1 == s[i]) continue;
    if (fds[i].revents & POLLIN) r |= (int64_t)1 << i;
  }

  return r;
}

int socket_setnonblock(int sock, int noblock) {
  // http://stackoverflow.com/questions/1150635/unix-nonblocking-i-o-o-nonblock-vs-fionbio
  // Prior to standardization there was ioctl(...FIONBIO...) and fcntl(...O_NDELAY...) ...
  // POSIX addressed this with the introduction of O_NONBLOCK.
  int flags = fcntl(sock, F_GETFL, 0);
  return fcntl(sock, F_SETFL, noblock ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
  // return ioctl(sock, FIONBIO, &noblock);
}

int create_tcp_socket(const char *server_ip, int server_port, bool is_server, bool nonblock) {
  struct sockaddr_in sa;
  int fd;
  int opt;

  // Creating socket file descriptor
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    N4_LOG_E("socket creation failed errno=%s(%d)\n", strerror(errno), errno);
    return -1;
  }
  opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(int));
  if (nonblock) {
    socket_setnonblock(fd, 1);
  }

  // Filling socket information
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;  // IPv4
  sa.sin_addr.s_addr = inet_addr(server_ip);
  sa.sin_port = htons((unsigned short)server_port);

  if (is_server) {
    // bind the socket with the server address
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
      N4_LOG_E("bind failed, addr=%s:%d errno=%s(%d)\n", server_ip, server_port, strerror(errno),
               errno);
      close(fd);
      return -1;
    }
    if (listen(fd, 5) < 0) {
      N4_LOG_E("listen failed, addr=%s:%d errno=%s(%d)\n", server_ip, server_port, strerror(errno),
               errno);
      close(fd);
      return -1;
    }
    N4_LOG_D("[TCP] server listen at: %s:%d\n", server_ip, server_port);
  } else {
    // connect the socket with the server address
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
      N4_LOG_E("connect failed, addr=%s:%d errno=%s(%d)\n", server_ip, server_port, strerror(errno),
               errno);
      close(fd);
      return -1;
    }
    N4_LOG_D("[TCP] connect to server: %s:%d\n", server_ip, server_port);
  }
  return fd;
}

int create_tcp_server_socket(const char *server_ip, int server_port, bool nonblock) {
  return create_tcp_socket(server_ip, server_port, true, nonblock);
}

int create_udp_socket(const char *local_ip, int local_port, bool nonblock) {
  struct sockaddr_in sa;
  int fd;
  int opt;

  // Creating socket file descriptor
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket creation failed");
    return -1;
  }
  opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(int));
  if (nonblock) {
    socket_setnonblock(fd, 1);
  }

  // Filling socket information
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;                   // IPv4
  sa.sin_addr.s_addr = inet_addr(local_ip);  // or INADDR_ANY
  sa.sin_port = htons((unsigned short)local_port);

  // Bind the socket with the local port
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind failed");
    close(fd);
    return -1;
  }
  N4_LOG_D("[UDP] bind sockfd: %d to local address: %s:%d\n", fd, local_ip, local_port);
  return fd;
}
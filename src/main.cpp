#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "n4/n4.h"

using namespace n4;

#define USAGE            \
  "Usage: n4"            \
  " -c: client mode"     \
  " -s: server mode"     \
  " -h <server_ip>"      \
  " -p <server_port>"    \
  " -b <src_port_start>" \
  " -n <src_port_count>" \
  " -o <peer_port_offset>\n"

int server_main(const PunchParams& params) {
  int ret = 0;
  while (1) {
    ret = serve(params);
    if (ret != 0) {
      break;
    }
  }
  return ret;
}

int client_main(const PunchParams& params) {
  PunchResult result;
  int ret = punch(params, &result);
  if (ret == 0) {
    struct sockaddr_in local_sa;
    memset(&local_sa, 0, sizeof(local_sa));
    socklen_t local_sa_len = sizeof(local_sa);
    if (getsockname(result.local_sockfd, (struct sockaddr*)&local_sa, &local_sa_len) < 0) {
      printf("Error: can not get local sock name\n");
      return -1;
    }

    char* local_ip = inet_ntoa(local_sa.sin_addr);
    uint16_t local_port = ntohs(local_sa.sin_port);
    char* peer_ip = inet_ntoa(((struct sockaddr_in*)&result.peer_socksa)->sin_addr);
    uint16_t peer_port = ntohs(((struct sockaddr_in*)&result.peer_socksa)->sin_port);
    printf("punch successed, fd=%d, local_ip=%s, local_port=%d, peer_ip=%s, peer_port=%d\n",
           result.local_sockfd, local_ip, local_port, peer_ip, peer_port);
  } else {
    printf("punch failed, errno=%d\n", ret);
  }
  return ret;
}

int main(int argc, char** argv) {
  PunchParams params{.server_host = "127.0.0.1",
                     .server_port = 1721,
                     .src_port_start = 30000,
                     .src_port_count = 25,
                     .peer_port_offset = 20,
                     .timeout_ms = 3 * 60 * 1000};
  int opt;
  bool client_mode = false;
  bool server_mode = false;
  while ((opt = getopt(argc, argv, "sch:p:b:n:o:")) != -1) {
    switch (opt) {
      case 's':
        server_mode = true;
        break;
      case 'c':
        client_mode = true;
        break;
      case 'h':
        if (strlen(optarg) < sizeof(params.server_host)) {
          strcpy(params.server_host, optarg);
        }
        break;
      case 'p':
        params.server_port = atoi(optarg);
        break;
      case 'b':
        params.src_port_start = atoi(optarg);
        break;
      case 'n':
        params.src_port_count = atoi(optarg);
        break;
      case 'o':
        params.peer_port_offset = atoi(optarg);
        break;
      default: /* '?' */
        fprintf(stderr, USAGE);
        exit(EXIT_FAILURE);
    }
  }

  if (server_mode) {
    return server_main(params);
  } else {
    return client_main(params);
  }
}
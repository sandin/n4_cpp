#ifndef N4_CPP_N4_H_
#define N4_CPP_N4_H_

#include <sys/socket.h>
#include <sys/types.h>

#include <cstdint>

namespace n4 {

struct PunchParams {
  char server_host[256];
  int server_port;
  int src_port_start;
  int src_port_count;
  int peer_port_offset;
  uint64_t timeout_ms;
};

struct PunchResult {
  int local_sockfd;
  struct sockaddr peer_socksa;
  socklen_t peer_socksa_len;
};

int punch(const PunchParams& params, PunchResult* result);

int serve(const PunchParams& params);

}  // namespace n4

#endif  // N4_CPP_N4_H_
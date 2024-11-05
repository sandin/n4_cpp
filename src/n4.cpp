#include "n4/n4.h"

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

#include <atomic>
#include <thread>
#include <vector>

#include "log.h"
#include "socket.h"

namespace n4 {

constexpr uint32_t kMaxClient = 128;

constexpr uint8_t kIdent[6] = {'n', '4', 'n', '4', 'n', '4'};
constexpr uint8_t kCmdInvalid = 0x01;
constexpr uint8_t kCmdHello = 0x01;
constexpr uint8_t kCmdReady = 0x02;
constexpr uint8_t kCmdExchange = 0x03;
constexpr uint8_t kCmdPeerInfo = 0x04;
constexpr uint8_t kCmdPunch = 0x05;

class N4Packet {
 public:
  N4Packet(int cmd = kCmdInvalid) : cmd_(cmd) {}

  virtual ~N4Packet() {}

  virtual bool Serialize(char* buffer, size_t buffer_size) const {
    assert(buffer_size >= 8);
    memcpy(buffer, &cmd_, sizeof(cmd_));                // 1 byte
    memcpy(buffer + 1, &reserved_, sizeof(reserved_));  // 1 byte
    memcpy(buffer + 2, &payload_, sizeof(payload_));    // 6 bytes
    return true;
  }

  virtual bool Deserialize(char* buffer, size_t buffer_size) {
    assert(buffer_size >= 8);
    cmd_ = *((uint8_t*)buffer);
    reserved_ = *((uint8_t*)buffer + 1);
    memcpy(&payload_[0], buffer + 2, sizeof(payload_));
    return true;
  }

  uint8_t* GetPayloadPtr() { return &payload_[0]; }
  size_t GetPayloadSize() { return sizeof(payload_); }
  int GetCmd() const { return cmd_; }
  void SetCmd(int cmd) { cmd_ = cmd; }

 protected:
  uint8_t cmd_;
  uint8_t reserved_ = 0;
  uint8_t payload_[6] = {};
};

class PeerInfoPacket : public N4Packet {
 public:
  PeerInfoPacket() : N4Packet(kCmdPeerInfo) {}

  virtual bool Deserialize(char* buffer, size_t buffer_size) override {
    if (!N4Packet::Deserialize(buffer, buffer_size)) {
      return false;
    }
    if (cmd_ != kCmdPeerInfo) {
      return false;
    }

    struct in_addr ip_addr;
    ip_addr.s_addr = *(uint32_t*)&payload_[0];
    char* ip_str = inet_ntoa(ip_addr);
    strcpy(ip_, ip_str);

    port_ = ntohs(*(uint16_t*)&payload_[4]);
    return true;
  }

  const char* GetIp() const { return &ip_[0]; }
  uint16_t GetPort() const { return port_; }

  void SetPeerInfo(struct sockaddr* socksa, socklen_t socksa_len) {
    struct sockaddr_in* sa = (struct sockaddr_in*)socksa;
    uint32_t addr = (uint32_t)sa->sin_addr.s_addr;
    memcpy(&payload_[0], &addr, sizeof(addr));  // big endian
    char* ip = inet_ntoa(sa->sin_addr);
    strcpy(ip_, ip);

    uint16_t port = (uint16_t)sa->sin_port;
    memcpy(&payload_[4], &port, sizeof(port));  // big endian
    port_ = ntohs(port);
  }

 private:
  char ip_[256] = {0};
  uint16_t port_;
};

inline uint64_t now_ts() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

inline in_addr_t get_addr_from_fd(int fd) {
  struct sockaddr socksa;
  socklen_t socksa_len = sizeof(socksa);
  if (getpeername(fd, &socksa, &socksa_len) < 0) {
    N4_LOG_E("getpeername failed errno=%s(%d)\n", strerror(errno), errno);
  }
  return ((struct sockaddr_in*)&socksa)->sin_addr.s_addr;
}

int punch(const PunchParams& params, PunchResult* result) {
  int ret;
  int sockfd;             // tcp port
  std::vector<int> pool;  // udp ports
  int local_sockfd = -1;  // peer sockfd (readable)

  uint64_t start_ts = now_ts();
  char buf[8];
  int i = 0;
  int port = params.src_port_start;
  while (true) {
    N4_LOG_D("===============\n");
    N4_LOG_D("punch, i=%d\n", i++);
    if (now_ts() - start_ts > params.timeout_ms) {
      ret = -2;  // timeout
      break;
    }

    // init sock
    sockfd = create_tcp_socket(params.server_host, params.server_port);
    if (sockfd < 0) {
      return -1;
    }

    int fd;
    const char* local_host = "0.0.0.0";
    for (int i = 0; i < params.src_port_count; ++i) {
      fd = create_udp_socket(local_host, port, true /* nonblock */);
      if (fd < 0) {
        continue;
      }
      pool.emplace_back(fd);
      port++;
    }
    assert(pool.size() > 0);

    {
      N4Packet packet(kCmdHello);
      memcpy(packet.GetPayloadPtr(), &kIdent, sizeof(kIdent));
      packet.Serialize(&buf[0], sizeof(buf));

      if (send(sockfd, &buf[0], sizeof(buf), 0) < 0) {
        N4_LOG_E("send failed errno=%s(%d)\n", strerror(errno), errno);
        ret = -errno;
        goto close_all_socks;
      }

      N4_LOG_D("[TCP] Server <== Hello\n");
      hexdump(&buf[0], sizeof(buf), 0);
    }

    {
      N4Packet packet;
      int n = recv(sockfd, &buf[0], sizeof(buf), 0);
      if (n < 0) {
        N4_LOG_E("send failed errno=%s(%d)\n", strerror(errno), errno);
        ret = -errno;
        goto close_all_socks;
      }
      assert(n > 0);
      if (!packet.Deserialize(&buf[0], n) || packet.GetCmd() != kCmdReady) {
        N4_LOG_E("unexpected message\n");
        ret = -1;
        goto close_all_socks;
      }

      N4_LOG_D("[TCP] Server ==> Ready\n");
      hexdump(&buf[0], sizeof(buf), 0);
    }

    {
      N4Packet packet(kCmdExchange);
      memcpy(packet.GetPayloadPtr(), &kIdent, sizeof(kIdent));
      packet.Serialize(&buf[0], sizeof(buf));

      struct sockaddr socksa;
      socklen_t socksa_len;
      socket_addr_from_ipv4((struct sockaddr_in*)&socksa, &socksa_len, params.server_host,
                            params.server_port);
      for (int i = 0; i < 3; ++i) {
        if (sendto(pool[0], &buf[0], sizeof(buf), 0, &socksa, socksa_len) < 0) {
          N4_LOG_E("sendto failed errno=%s(%d)\n", strerror(errno), errno);
          ret = -errno;
          goto close_all_socks;
        }
      }

      N4_LOG_D("[UDP] Server <== Exchange\n");
      hexdump(&buf[0], sizeof(buf), 0);
    }

    const char* peer_ip;
    uint16_t peer_port;
    {
      PeerInfoPacket peerInfoPacket;
      ret = recv(sockfd, &buf[0], sizeof(buf), 0);
      if (ret < 0) {
        N4_LOG_E("send failed errno=%s(%d)\n", strerror(errno), errno);
        ret = -errno;
        goto close_all_socks;
      }
      if (!peerInfoPacket.Deserialize(&buf[0], ret)) {
        N4_LOG_E("unexpected message\n");
        ret = -1;
        goto close_all_socks;
      }

      peer_ip = peerInfoPacket.GetIp();
      peer_port = peerInfoPacket.GetPort();
      N4_LOG_D("[TCP] Server ==> PeerInfo: %s:%d\n", peer_ip, peer_port);
      hexdump(&buf[0], sizeof(buf), 0);
    }

    {
      N4Packet packet(kCmdPunch);
      memcpy(packet.GetPayloadPtr(), &kIdent, sizeof(kIdent));
      packet.Serialize(&buf[0], sizeof(buf));

      struct sockaddr socksa;
      socklen_t socksa_len;
      socket_addr_from_ipv4((struct sockaddr_in*)&socksa, &socksa_len, peer_ip, peer_port);
      for (int i = 0; i < 5; ++i) {
        for (auto sockfd : pool) {
          if (sendto(sockfd, &buf[0], sizeof(buf), 0, &socksa, socksa_len) < 0) {
            N4_LOG_E("sendto failed errno=%s(%d)\n", strerror(errno), errno);
            // goto close_all_socks;
          }
        }
      }

      N4_LOG_D("[UDP] Peer <== Punch\n");
      hexdump(&buf[0], sizeof(buf), 0);
    }

    {
      int fds[pool.size()];
      memcpy(fds, pool.data(), pool.size() * sizeof(int));
      while (1) {
        ret = socket_poll_read(fds, sizeof(fds) / sizeof(int), 10 * 1000 /* 10s */);
        if (ret > 0) {
          for (int i = 0; i < 64; ++i) {
            if (ret & ((int64_t)1 << i)) {
              local_sockfd = fds[i];  // first readable sock
              break;
            }
          }
        }
        if (local_sockfd < 0) {
          break;  // punch failed, try again!
        }

        struct sockaddr socksa;
        socklen_t socksa_len = sizeof(socksa);
        int n = recvfrom(local_sockfd, &buf, sizeof(buf), 0, &socksa, &socksa_len);
        if (n <= 0) {
          N4_LOG_E("recvfrom failed errno=%s(%d)\n", strerror(errno), errno);
          break;
        }

        N4Packet packet;
        if (!packet.Deserialize(&buf[0], n) || packet.GetCmd() != kCmdPunch) {
          N4_LOG_E("unexpected message\n");
          break;
        }
        N4_LOG_D("[UDP] Peer ==> Punch\n");
        hexdump(&buf[0], n, 0);

        char* recv_peer_ip = inet_ntoa(((struct sockaddr_in*)&socksa)->sin_addr);
        if (strcmp(recv_peer_ip, peer_ip) == 0) {
          result->local_sockfd = local_sockfd;
          memcpy(&result->peer_socksa, &socksa, socksa_len);
          result->peer_socksa_len = socksa_len;
          ret = 0;  // punch successed!
          goto close_all_socks;
        }
      }
    }

    close(sockfd);
    sockfd = -1;
    for (auto fd : pool) {
      if (fd > 0) {
        close(fd);
      }
    }
    pool.resize(0);
  }  // end of switch

close_all_socks:
  if (sockfd != -1) {
    close(sockfd);
  }
  for (auto fd : pool) {
    if (fd != local_sockfd) {
      close(fd);
    }
  }
  return ret;
}

int serve(const PunchParams& params) {
  int r;
  int sockfd, usockfd;
  int peer_sockfds[2] = {-1, -1};
  int peer_sockfds_sz = 0;
  int peer_sockstate[2] = {0, 0};
  int timeout = 3 * 60 * 1000;
  int nfds = 0, current_size = 0, i, j;
  bool close_conn, compress_array;
  char buf[8];

  // init socks
  sockfd = create_tcp_server_socket(params.server_host, params.server_port, true /* nonblock */);
  if (sockfd < 0) {
    return -1;
  }
  usockfd = create_udp_socket(params.server_host, params.server_port, true /* nonblock */);
  if (usockfd < 0) {
    return -1;
  }

  // init poll
  struct pollfd fds[kMaxClient];
  memset(fds, 0, sizeof(fds));
  fds[0].fd = sockfd;
  fds[0].events = POLLIN;
  fds[1].fd = usockfd;
  fds[1].events = POLLIN;
  nfds = 2;  // 1 TCP + 1 UDP

  // main loop
  while (1) {
    r = poll(fds, nfds, timeout);
    while (-1 == r && (EINTR == errno || EAGAIN == errno)) r = poll(fds, nfds, timeout);
    if (r < 0) {
      N4_LOG_E("poll failed errno=%s(%d)\n", strerror(errno), errno);
      break;
    }

    current_size = nfds;
    for (i = 0; i < current_size; ++i) {
      if (fds[i].revents == 0) {
        continue;
      }

      if (fds[i].fd == sockfd) {  // TCP server socket
        int client_sockfd;
        do {
          client_sockfd = accept(sockfd, NULL, NULL);
          if (client_sockfd < 0) {
            if (errno != EWOULDBLOCK) {
              N4_LOG_E("accept() failed errno=%s(%d)\n", strerror(errno), errno);
              goto server_exit;
            }
            break;
          }

          N4_LOG_I("[TCP] new incoming connection, fd=%d\n", client_sockfd);
          if (nfds < kMaxClient) {
            socket_setnonblock(client_sockfd, 1);
            fds[nfds].fd = client_sockfd;
            fds[nfds].events = POLLIN;
            nfds++;
          } else {
            close(client_sockfd);
          }
        } while (client_sockfd != -1);
      } else if (fds[i].fd == usockfd) {  // UDP socket
        struct sockaddr socksa;
        socklen_t socksa_len = sizeof(socksa);
        do {
          r = recvfrom(fds[i].fd, &buf, sizeof(buf), 0, &socksa, &socksa_len);
          // N4_LOG_D("[UDP] recvfrom() r=%d\n", r);
          if (r <= 0) {
            N4_LOG_E("recvfrom failed errno=%s(%d)\n", strerror(errno), errno);
            break;
          }

          N4Packet packet;
          if (!packet.Deserialize(&buf[0], r) || packet.GetCmd() != kCmdExchange) {
            N4_LOG_E("unexpected message\n");
            break;
          }
          N4_LOG_D("[UDP] recvfrom ==> Exchange\n");
          hexdump(&buf[0], r, 0);

          in_addr_t udp_addr = ((struct sockaddr_in*)&socksa)->sin_addr.s_addr;
          N4_LOG_D("[UDP] ip=%s\n", inet_ntoa(((struct sockaddr_in*)&socksa)->sin_addr));
          in_port_t udp_port = ((struct sockaddr_in*)&socksa)->sin_port;

          int peer_tcp_sockfd_idx = -1;
          int other_peer_tcp_sockfd = -1;
          struct sockaddr tcp_socksa;
          socklen_t tcp_socksa_len = sizeof(tcp_socksa);
          for (i = 0; i < peer_sockfds_sz; ++i) {
            if (peer_sockfds[i] != -1) {
              if (getpeername(peer_sockfds[i], &tcp_socksa, &tcp_socksa_len) < 0) {
                N4_LOG_E("getpeername failed errno=%s(%d)\n", strerror(errno), errno);
                continue;
              }
              N4_LOG_D("[TCP] %d peer ip=%s\n", i,
                       inet_ntoa(((struct sockaddr_in*)&tcp_socksa)->sin_addr));
              if (((struct sockaddr_in*)&tcp_socksa)->sin_addr.s_addr == udp_addr) {
                peer_tcp_sockfd_idx = i;
                // break;
              }
            }
          }
          if (peer_tcp_sockfd_idx == -1) {
            continue;
          }
          int idx = peer_tcp_sockfd_idx == 0 ? 1 : 0;
          if (peer_sockstate[idx] == 0) {
            other_peer_tcp_sockfd = peer_sockfds[idx];

            PeerInfoPacket peerinfo_packet;
            peerinfo_packet.SetPeerInfo(&socksa, socksa_len);
            peerinfo_packet.Serialize(&buf[0], sizeof(buf));
            r = send(other_peer_tcp_sockfd, &buf[0], sizeof(buf), 0);
            if (r < 0) {
              N4_LOG_E("send() failed errno=%s(%d)\n", strerror(errno), errno);
              close_conn = true;
              break;
            }
            N4_LOG_D("[TCP] send <== PeerInfo: %s:%d\n", peerinfo_packet.GetIp(),
                     peerinfo_packet.GetPort());
            hexdump(&buf[0], sizeof(buf), 0);
            peer_sockstate[idx] = 1;
          }

          int cnt = 0;
          for (i = 0; i < peer_sockfds_sz; ++i) {
            if (peer_sockstate[i] == 1) {
              ++cnt;
            }
          }
          if (cnt == 2) {
            goto server_exit;  // shutdown the server
          }
        } while (1);
      } else {  // TCP client socket
        close_conn = false;
        do {
          r = recv(fds[i].fd, buf, sizeof(buf), 0);
          // N4_LOG_D("[TCP] recv() r=%d\n", r);
          if (r < 0) {
            if (errno != EWOULDBLOCK) {
              N4_LOG_E("recv() failed errno=%s(%d)\n", strerror(errno), errno);
              close_conn = true;
            }
            break;
          }
          if (r == 0) {
            N4_LOG_E("connection closed by client\n");
            close_conn = true;
            break;
          }
          N4_LOG_D("[TCP] recv ==> Hello\n");
          hexdump(&buf[0], r, 0);

          N4Packet hello_packet;
          if (!hello_packet.Deserialize(&buf[0], r)) {
            N4_LOG_E("unexpected message\n");
            close_conn = true;
            break;
          }
          if (hello_packet.GetCmd() != kCmdHello ||
              memcmp(hello_packet.GetPayloadPtr(), &kIdent, sizeof(kIdent)) != 0) {
            N4_LOG_E("unexpected message\n");
            close_conn = true;
            break;
          }

          if (peer_sockfds_sz < 2) {
            peer_sockfds[peer_sockfds_sz] = fds[i].fd;
            ++peer_sockfds_sz;
            N4_LOG_D("[TCP] add new peer, current peer size: %d\n", peer_sockfds_sz);
          }

          if (peer_sockfds_sz == 2) {
            for (j = 0; j < peer_sockfds_sz; ++j) {
              N4Packet ready_packet{kCmdReady};
              ready_packet.Serialize(&buf[0], sizeof(buf));
              r = send(peer_sockfds[j], &buf[0], sizeof(buf), 0);
              if (r < 0) {
                N4_LOG_E("send() failed errno=%s(%d)\n", strerror(errno), errno);
                close_conn = true;
                break;
              }
              N4_LOG_D("[TCP] send <== Ready\n");
              hexdump(&buf[0], sizeof(buf), 0);
            }
          }
        } while (1);

        if (close_conn) {
          close(fds[i].fd);
          fds[i].fd = -1;
          compress_array = true;
        }
      }
    }  // End of loop through fds

    if (compress_array) {
      compress_array = false;
      for (i = 0; i < nfds; i++) {
        if (fds[i].fd == -1) {
          for (j = i; j < nfds - 1; j++) {
            fds[j].fd = fds[j + 1].fd;
          }
          i--;
          nfds--;
        }
      }
    }
  }  // end of main loop

server_exit:
  for (i = 0; i < nfds; ++i) {
    if (fds[i].fd != -1) {
      close(fds[i].fd);
    }
  }
  return 0;
}

}  // namespace n4
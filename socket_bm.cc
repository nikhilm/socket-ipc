#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <string>

#include <benchmark/benchmark.h>

static void BM_SocketPairWrite(benchmark::State& state) {
    uint64_t written = 0;
    int fds[2];
    int ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
    if (ret == -1) {
        state.SkipWithError(strerrordesc_np(errno));
        return;
    }

    for (auto _ : state) {
        const int data_size = state.range(0);
        std::string data(data_size, 'X');
        int w = write(fds[0], data.c_str(), data_size);
        if (w == -1) {
            state.SkipWithError(strerrordesc_np(errno));
            goto fail;
        }
        written += w;

        char *buf = new char[data_size];
        int r = read(fds[1], buf, data_size);
        delete buf;
        if (r == -1) {
            state.SkipWithError(strerrordesc_np(errno));
            goto fail;
        } else if (r < data_size) {
            state.SkipWithError("did not read all the data");
            goto fail;
        }
    }

fail:
    close(fds[0]);
    close(fds[1]);
    state.SetBytesProcessed(written);
}
BENCHMARK(BM_SocketPairWrite)->Arg(512)->Arg(1024)->Arg(4096)->Arg(8192)->Arg(16384)->Arg(32768)->Iterations(100);

static void BM_UDPWrite(benchmark::State& state) {
    uint64_t written = 0;

    const uint16_t port = 7667;
    const char* group = "239.255.255.250";

    struct sockaddr_in send_addr{};
    struct sockaddr_in recv_addr{};
    struct ip_mreq mreq{};
    
    int send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_fd < 0) {
        // state.SkipWithError(strerrordesc_np(errno));
        state.SkipWithError("send socket creation failed");
        return;
    }

    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = inet_addr(group);
    send_addr.sin_port = htons(port);

    int recv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_fd < 0) {
        // state.SkipWithError(strerrordesc_np(errno));
        state.SkipWithError("recv socket creation failed");
        close(send_fd);
        return;
    }
    const unsigned int yes = 1;
    if (setsockopt(recv_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof(yes)) < 0) {
        state.SkipWithError("Setting REUSEADDR on recv socket failed");
        goto fail;
    }

    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    recv_addr.sin_port = htons(port);
    if (bind(recv_fd, (struct sockaddr *) &recv_addr, sizeof(recv_addr)) < 0) {
        state.SkipWithError("binding to recv addr failed");
        goto fail;
    }

    mreq.imr_multiaddr.s_addr = inet_addr(group);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(recv_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &mreq, sizeof(mreq)) < 0) {
        state.SkipWithError("joining multicast group failed");
        goto fail;
    }


    for (auto _ : state) {
        const int data_size = state.range(0);
        std::string data(data_size, 'X');
        int w = sendto(send_fd, data.c_str(), data.size(), 0, (struct sockaddr*) &send_addr, sizeof(send_addr));
        if (w == -1) {
            state.SkipWithError(strerrordesc_np(errno));
            goto fail;
        }
        written += w;

        /*
        char *buf = new char[data_size];
        socklen_t addrlen = sizeof(recv_addr);
        int r = recvfrom(recv_fd, buf, data_size, 0, (struct sockaddr*) &recv_addr, &addrlen);
        delete buf;
        if (r == -1) {
            state.SkipWithError(strerrordesc_np(errno));
            goto fail;
        } else if (r < data_size) {
            state.SkipWithError("did not read all the data");
            goto fail;
        }
        */
    }

fail:
    close(send_fd);
    close(recv_fd);
    state.SetBytesProcessed(written);
}

BENCHMARK(BM_UDPWrite)->Arg(512)->Arg(1024)->Arg(4096)->Arg(8192)->Arg(16384)->Arg(32768)->Iterations(100);

// TODO: Then a benchmark that does this using threads & select.

BENCHMARK_MAIN();

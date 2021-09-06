#include <cstring>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <string>

#include <benchmark/benchmark.h>

static void BM_UnixSingleWrite(benchmark::State& state) {
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
BENCHMARK(BM_UnixSingleWrite)->Arg(512)->Arg(1024)->Arg(4096)->Arg(8192)->Arg(16384)->Arg(32768);

static void BM_UDPWrite(benchmark::State& state) {
    uint64_t written = 0;

    const uint16_t port = 7667;
    const char* group = "239.255.76.67";

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
    }

fail:
    close(send_fd);
    close(recv_fd);
    state.SetBytesProcessed(written);
}

BENCHMARK(BM_UDPWrite)->Arg(512)->Arg(1024)->Arg(4096)->Arg(8192)->Arg(16384)->Arg(32768);

static void BM_UnixMultiWrite(benchmark::State& state) {
    const size_t N_PAIRS = 10;
    uint64_t written = 0;
    // (send, recv)
    std::vector<std::pair<int, int>> fds(N_PAIRS);
    bool errored = false;
    std::generate(fds.begin(), fds.end(), [&]() {
        int fds_init[2];
        int ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, fds_init);
        if (ret == -1) {
            state.SkipWithError(strerrordesc_np(errno));
            errored = true;
            return std::pair(-1, -1);
        }
        return std::pair(fds_init[0], fds_init[1]);
    });
    if (errored) {
        return;
    }

    for (auto _ : state) {
        const int data_size = state.range(0);
        std::string data(data_size, 'X');
        for (auto fd_pair : fds) {
            int w = write(fd_pair.first, data.c_str(), data_size);
            if (w == -1) {
                state.SkipWithError(strerrordesc_np(errno));
                goto fail;
            }
            written += w;

            char *buf = new char[data_size];
            int r = read(fd_pair.second, buf, data_size);
            delete buf;
            if (r == -1) {
                state.SkipWithError(strerrordesc_np(errno));
                goto fail;
            } else if (r < data_size) {
                state.SkipWithError("did not read all the data");
                goto fail;
            }
        }
    }

fail:
    for (auto fd_pair : fds) {
        close(fd_pair.first);
        close(fd_pair.second);
    }
    state.SetBytesProcessed(written);
}
BENCHMARK(BM_UnixMultiWrite)->Arg(512)->Arg(1024)->Arg(4096)->Arg(8192)->Arg(16384)->Arg(32768);

static void BM_UnixMultiSplice(benchmark::State& state) {
    const size_t N_PAIRS = 10;
    uint64_t written = 0;
    // (send, recv)
    std::vector<std::pair<int, int>> fds(N_PAIRS);
    bool errored = false;
    std::generate(fds.begin(), fds.end(), [&]() {
        int fds_init[2];
        int ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, fds_init);
        if (ret == -1) {
            state.SkipWithError(strerrordesc_np(errno));
            errored = true;
            return std::pair(-1, -1);
        }
        return std::pair(fds_init[0], fds_init[1]);
    });
    if (errored) {
        for (auto fd_pair : fds) {
            if (fd_pair.first >= 0) {
                close(fd_pair.first);
            }
            if (fd_pair.second >= 0) {
                close(fd_pair.second);
            }
        }
        return;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        state.SkipWithError("pipe creation failed");
        goto fail;
    }

    int pipefd2[2];
    if (pipe(pipefd2) < 0) {
        state.SkipWithError("pipe fd2 creation failed");
        goto fail;
    }

    for (auto _ : state) {
        const int data_size = state.range(0);
        std::string data(data_size, 'X');
        // First copy from userspace into the kernel buffer.
        struct iovec iov{};
        iov.iov_base = const_cast<char*>(data.c_str());
        iov.iov_len = data.size();
        if (vmsplice(pipefd[1], &iov, 1, 0) < data_size) {
            state.SkipWithError("Did not write all data in vmsplice");
            goto fail;
        }

        for (int i = 0; i < fds.size(); ++i) {
            auto fd_pair = fds[i];
            // Need to tee because splice will consume the data.
            // But don't do it on the last write, otherwise we will never clear pipefd and future writes will block.
            int splice_from = pipefd[0];
            if (i < (fds.size() - 1)) {
                if (tee(pipefd[0], pipefd2[1], data_size, 0) < data_size) {
                    state.SkipWithError("tee failed");
                    goto fail;
                }
                splice_from = pipefd2[0];
            }

            // Splice into every domain socket.
            int w = splice(splice_from, nullptr, fd_pair.first, nullptr, data_size, 0);
            if (w < data_size) {
                state.SkipWithError("Did not write all data in splice");
                // state.SkipWithError(strerrordesc_np(errno));
                goto fail;
            }
            written += w;

            char *buf = new char[data_size];
            int read_bytes = 0;
            while (true) {
                int r = read(fd_pair.second, buf, data_size);
                if (r == -1) {
                    state.SkipWithError(strerrordesc_np(errno));
                    goto fail;
                }
                read_bytes += r;
                if (read_bytes == data_size) {
                    break;
                }
            }
            delete buf;
        }
    }

fail:
    close(pipefd[0]);
    close(pipefd[1]);
    close(pipefd2[0]);
    close(pipefd2[1]);
    for (auto fd_pair : fds) {
        close(fd_pair.first);
        close(fd_pair.second);
    }
    state.SetBytesProcessed(written);
}
BENCHMARK(BM_UnixMultiSplice)->Arg(512)->Arg(1024)->Arg(4096)->Arg(8192)->Arg(16384)->Arg(32768);


BENCHMARK_MAIN();

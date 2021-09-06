#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

#include <benchmark/benchmark.h>

static void BM_SocketPairWrite(benchmark::State& state) {
    int fds[2];
    int ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
    if (ret == -1) {
        state.SkipWithError(strerrordesc_np(errno));
        return;
    }

    uint64_t written = 0;
    for (auto _ : state) {
        std::string data(state.range(0), 'X');
        int w = write(fds[0], data.c_str(), data.size());
        if (w == -1) {
            state.SkipWithError(strerrordesc_np(errno));
            goto fail;
        }
        written += w;

        char *buf = new char[state.range(0)];
        int r = read(fds[1], buf, state.range(0));
        delete buf;
        if (r == -1) {
            state.SkipWithError(strerrordesc_np(errno));
            goto fail;
        }
    }

fail:
    close(fds[0]);
    close(fds[1]);
    state.SetBytesProcessed(written);
}
BENCHMARK(BM_SocketPairWrite)->Arg(512)->Arg(1024)->Arg(4096)->Arg(8192)->Arg(16384)->Arg(32768);

static void BM_UDPWrite(benchmark::State& state) {
    // TODO: Create a UDP sender and receiver bound to loopback and write.
}

// TODO: Then a benchmark that does this using threads & select.

BENCHMARK_MAIN();
